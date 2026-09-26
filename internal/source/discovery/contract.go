// Package discovery owns the pre-registration PostgreSQL catalog probe. It
// only accepts source-owned connection coordinates, keeps the probe on the
// worker side and stores the bounded metadata as an encrypted artifact.
package discovery

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

const (
	// MetadataSchemaVersion identifies the encrypted catalog payload. It is
	// private to the worker/result owner until a later API projection is approved.
	MetadataSchemaVersion = "source-discovery-metadata-v1"
	// ResultSchemaVersion identifies the stable fields used to derive result_hash.
	ResultSchemaVersion = "source-discovery-result-v1"
	resultSucceeded     = "SUCCEEDED"
	resultNeedsReview   = "NEEDS_INTERPRETATION"
)

var errMetadataInvalid = errors.New("source discovery metadata invalid")

// Metadata is the complete bounded catalog observation sealed under the
// SOURCE_DISCOVERY_RESULT owner. It contains server catalog metadata only;
// the API and model gateway receive no raw artifact bytes in this slice.
type Metadata struct {
	SchemaVersion      string                          `json:"schema_version"`
	ConnectionID       string                          `json:"connection_id"`
	ConnectionRevision int64                           `json:"connection_revision"`
	DatabaseOID        uint32                          `json:"database_oid"`
	DatabaseName       string                          `json:"database_name"`
	PrivilegeDigest    string                          `json:"privilege_digest"`
	Views              []postgresqlquery.ViewDiscovery `json:"views"`
}

func (metadata Metadata) validate(maxViews int) bool {
	return maxViews >= 1 && maxViews <= 1024 && metadata.SchemaVersion == MetadataSchemaVersion && validOpaque(metadata.ConnectionID) &&
		metadata.ConnectionRevision >= 1 && metadata.DatabaseOID >= 1 &&
		validCatalogText(metadata.DatabaseName, 128) && validSHA256(metadata.PrivilegeDigest) &&
		metadata.Views != nil && len(metadata.Views) <= maxViews
}

// Validate reports whether an encrypted metadata payload contains only the
// bounded source-owned fields accepted by this worker package.
func (metadata Metadata) Validate(maxViews int) bool { return metadata.validate(maxViews) }

func marshalMetadata(metadata Metadata, maxViews int) ([]byte, error) {
	if !metadata.validate(maxViews) {
		return nil, errMetadataInvalid
	}
	raw, err := jsonv2.Marshal(metadata)
	if err != nil {
		return nil, errMetadataInvalid
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, errMetadataInvalid
	}
	return append([]byte(nil), canonical...), nil
}

type resultHashInput struct {
	SchemaVersion         string `json:"schema_version"`
	OrganizationID        string `json:"organization_id"`
	ActorPrincipalID      string `json:"actor_principal_id"`
	RequestID             string `json:"request_id"`
	ResultID              string `json:"result_id"`
	ConnectionID          string `json:"connection_id"`
	ConnectionRevision    int64  `json:"connection_revision"`
	TrustProfileHash      string `json:"trust_profile_hash"`
	SecurityEpoch         int64  `json:"security_epoch"`
	DatabaseIdentityHash  string `json:"database_identity_hash"`
	PrivilegeDigest       string `json:"privilege_digest"`
	Status                string `json:"status"`
	ViewCount             int    `json:"view_count"`
	PreparedViewCount     int    `json:"prepared_view_count"`
	NeedsViewCount        int    `json:"needs_interpretation_view_count"`
	MetadataPlaintextHash string `json:"metadata_plaintext_hash"`
}

func resultHash(input resultHashInput) (string, error) {
	if input.SchemaVersion != ResultSchemaVersion || !validOpaque(input.OrganizationID) ||
		!validOpaque(input.ActorPrincipalID) || !validGeneratedID(input.RequestID, "sdrq_") ||
		!validGeneratedID(input.ResultID, "sdr_") || !validGeneratedID(input.ConnectionID, "conn_") ||
		input.ConnectionRevision < 1 || !validSHA256(input.TrustProfileHash) || input.SecurityEpoch < 1 ||
		!validSHA256(input.DatabaseIdentityHash) || !validSHA256(input.PrivilegeDigest) ||
		(input.Status != resultSucceeded && input.Status != resultNeedsReview) ||
		input.ViewCount < 0 || input.ViewCount > 1024 || input.PreparedViewCount < 0 ||
		input.NeedsViewCount < 0 || input.PreparedViewCount+input.NeedsViewCount != input.ViewCount ||
		(input.Status == resultSucceeded && input.NeedsViewCount != 0) || !validSHA256(input.MetadataPlaintextHash) {
		return "", errMetadataInvalid
	}
	raw, err := canon.CanonicalJSON(input)
	if err != nil {
		return "", errMetadataInvalid
	}
	return canon.Hash(raw), nil
}

func databaseIdentityHash(oid uint32, name string) (string, error) {
	if oid < 1 || !validCatalogText(name, 128) {
		return "", errMetadataInvalid
	}
	raw, err := canon.CanonicalJSON(struct {
		OID  uint32 `json:"oid"`
		Name string `json:"name"`
	}{OID: oid, Name: name})
	if err != nil {
		return "", errMetadataInvalid
	}
	return canon.Hash(raw), nil
}

func validGeneratedID(value, prefix string) bool {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if len(value) != len(prefix)+26 || !strings.HasPrefix(value, prefix) || len(prefix) == 0 || value[len(prefix)] < '0' || value[len(prefix)] > '7' {
		return false
	}
	for _, symbol := range value[len(prefix)+1:] {
		if !strings.ContainsRune(alphabet, symbol) {
			return false
		}
	}
	return true
}

func validGeneratedCredential(value string) bool { return validGeneratedID(value, "cred_") }

func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validCatalogText(value string, maxBytes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 && character != '\n' && character != '\t' {
			return false
		}
	}
	return true
}
