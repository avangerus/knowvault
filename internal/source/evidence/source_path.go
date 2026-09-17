package evidence

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// The ingest pipeline seals either a FILE locator or a connector identity.
// Old code-source fixtures also use a plain path. Decode the stored identity;
// never invent a file name from an opaque object id or from the source text.
func sourceExternalPath(value string) (string, error) {
	if value == "" || !utf8.ValidString(value) {
		return "", ErrNotFound
	}
	if !strings.HasPrefix(strings.TrimSpace(value), "{") {
		return value, nil
	}
	var identity struct {
		ConnectionID string `json:"connection_id"`
		Kind         string `json:"kind"`
		RelativePath string `json:"relative_path"`
		ExternalID   string `json:"external_id"`
	}
	if err := jsonv2.Unmarshal([]byte(value), &identity, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || identity.ConnectionID == "" || identity.Kind == "" {
		return "", ErrNotFound
	}
	if identity.Kind == "FILE" && identity.RelativePath != "" && identity.ExternalID == "" {
		return identity.RelativePath, nil
	}
	if identity.Kind != "FILE" && identity.ExternalID != "" && identity.RelativePath == "" {
		return identity.ExternalID, nil
	}
	return "", ErrNotFound
}

// sourcePostgreSQLQueryDisplay validates the sealed identity shape emitted by
// the PostgreSQL query ingester and turns it into a content-free display
// value. Row identity values are deliberately parsed only for schema
// validation; they are never rendered as a path or returned to a caller. The
// opaque segment is the already tenant-bound, HMAC-keyed
// source_object.external_object_id_digest supplied by the caller.
func sourcePostgreSQLQueryDisplay(value, opaqueID string) (string, error) {
	identity, err := parsePostgreSQLQueryIdentity(value)
	if err != nil || !sourceHMACDigestPattern.MatchString(opaqueID) {
		return "", ErrNotFound
	}
	return sourcePostgreSQLQueryDisplayFromIdentity(identity, opaqueID)
}

func sourcePostgreSQLQueryDisplayFromIdentity(identity postgresqlQueryExternalIdentity, opaqueID string) (string, error) {
	if identity.Kind != "POSTGRESQL_QUERY_IDENTITY" || !validProjectionLineage(identity.LineageID) ||
		!validPostgreSQLIdentityValues(identity.IdentityValues) || !sourceHMACDigestPattern.MatchString(opaqueID) {
		return "", ErrNotFound
	}
	return "postgresql-query/" + url.PathEscape(identity.LineageID) + "/" + url.PathEscape(opaqueID), nil
}

func parsePostgreSQLQueryIdentity(value string) (postgresqlQueryExternalIdentity, error) {
	if value == "" || !utf8.ValidString(value) {
		return postgresqlQueryExternalIdentity{}, ErrNotFound
	}
	raw := []byte(value)
	canonical := jsontext.Value(append([]byte(nil), raw...))
	if err := canonical.Canonicalize(); err != nil || !bytes.Equal(raw, []byte(canonical)) {
		return postgresqlQueryExternalIdentity{}, ErrNotFound
	}
	var identity postgresqlQueryExternalIdentity
	if err := jsonv2.Unmarshal(raw, &identity, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return postgresqlQueryExternalIdentity{}, ErrNotFound
	}
	if identity.Kind != "POSTGRESQL_QUERY_IDENTITY" || !validProjectionLineage(identity.LineageID) ||
		!validPostgreSQLIdentityValues(identity.IdentityValues) {
		return postgresqlQueryExternalIdentity{}, ErrNotFound
	}
	return identity, nil
}

func validatePostgreSQLQueryCanonicalLocator(value, expectedConnectionID, expectedLineageID, expectedOpaqueID string) error {
	if !validProjectionLineage(expectedConnectionID) || !validProjectionLineage(expectedLineageID) ||
		!sourceHMACDigestPattern.MatchString(expectedOpaqueID) || value == "" || !utf8.ValidString(value) {
		return ErrNotFound
	}
	raw := []byte(value)
	canonical := jsontext.Value(append([]byte(nil), raw...))
	if err := canonical.Canonicalize(); err != nil || !bytes.Equal(raw, []byte(canonical)) {
		return ErrNotFound
	}
	var locator postgresqlQueryCanonicalLocator
	if err := jsonv2.Unmarshal(raw, &locator, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return ErrNotFound
	}
	if locator.Kind != "POSTGRESQL_QUERY_ROW" || locator.ConnectionID != expectedConnectionID ||
		locator.LineageID != expectedLineageID || locator.Revision < 1 || locator.EntityIdentityDigest != expectedOpaqueID {
		return ErrNotFound
	}
	return nil
}

type postgresqlQueryExternalIdentity struct {
	Kind           string                       `json:"kind"`
	LineageID      string                       `json:"projection_lineage_id"`
	IdentityValues []postgresqlquery.ValueEntry `json:"identity_values"`
}

type postgresqlQueryCanonicalLocator struct {
	ConnectionID         string `json:"connection_id"`
	Kind                 string `json:"kind"`
	LineageID            string `json:"projection_lineage_id"`
	Revision             int64  `json:"projection_revision"`
	EntityIdentityDigest string `json:"entity_identity_digest"`
}

var sourceHMACDigestPattern = regexp.MustCompile(`^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$`)

func validProjectionLineage(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validPostgreSQLIdentityValues(values []postgresqlquery.ValueEntry) bool {
	if len(values) == 0 || len(values) > 256 {
		return false
	}
	previousOrdinal := 0
	for _, value := range values {
		if value.Ordinal <= previousOrdinal || value.Ordinal > 256 || !validPostgreSQLTypeFingerprint(value.TypeFingerprint) || value.ValueTag == "NULL" {
			return false
		}
		// A non-NULL SQL JSON/JSONB value may itself be the JSON literal null;
		// jsonv2 consequently decodes that embedded value as a nil interface.
		// Scalar SQL identity values never have a nil Value after producer
		// canonicalization.
		if value.Value == nil && value.LogicalType != postgresqlquery.TypeJSON && value.LogicalType != postgresqlquery.TypeJSONB {
			return false
		}
		if !validPostgreSQLValueTag(value.LogicalType, value.ValueTag, value.Value) {
			return false
		}
		previousOrdinal = value.Ordinal
	}
	return true
}

func validPostgreSQLTypeFingerprint(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func validPostgreSQLValueTag(logicalType postgresqlquery.LogicalType, valueTag string, value any) bool {
	if logicalType == postgresqlquery.TypeJSON || logicalType == postgresqlquery.TypeJSONB {
		return valueTag == string(logicalType)
	}
	want := map[postgresqlquery.LogicalType]string{
		postgresqlquery.TypeBool:        "BOOL",
		postgresqlquery.TypeInt:         "INT",
		postgresqlquery.TypeNumeric:     "NUMERIC",
		postgresqlquery.TypeUUID:        "UUID",
		postgresqlquery.TypeDate:        "DATE",
		postgresqlquery.TypeTimestamp:   "TIMESTAMP_LOCAL",
		postgresqlquery.TypeTimestamptz: "TIMESTAMPTZ_UTC",
		postgresqlquery.TypeText:        "TEXT",
	}[logicalType]
	if want == "" || valueTag != want {
		return false
	}
	if logicalType == postgresqlquery.TypeBool {
		_, ok := value.(bool)
		return ok
	}
	_, ok := value.(string)
	return ok
}
