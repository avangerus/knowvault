package repository

// B2.3a: pure normalization boundary for one persisted governed-exposure
// artifact.
//
// public.governed_query_exposed_schema keeps, per revision, exactly what the
// governed-query registration wrote for one source connection: the revision
// ordinal, the exposed-schema inventory as jsonb (objects_json) and the
// content hash of that inventory (revision_hash). This file owns the pure
// read-side normalization of that single artifact. It decodes the full
// exposed-schema wire, re-derives the artifact hash over the whole decoded
// inventory, and projects only the fields an approved analytic projection
// needs: the revision, the full artifact hash, the one selected relation and
// that relation's column names.
//
// It grants no authority and performs no I/O. No context, SQL, database,
// connection, network, clock, model, transport, credential or mutable
// package/global state participates, and nothing here constructs an
// authorization token or a JSON projection. Every refusal is content-free:
// CodePersistence for a malformed artifact, hash, identifier, bound or
// duplicate, and CodeNotFound when the artifact simply holds no object with
// the requested identity. Both always come with the true zero result.

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/workspace"
)

const (
	// maxGovernedExposureArtifactBytes is the fixed pre-decode cap on the
	// scanned jsonb text. An exposed-schema artifact is a bounded operator
	// inventory, so anything larger is refused before a decoder sees it: the
	// cap must hold even while decoding is the expensive part.
	maxGovernedExposureArtifactBytes = 8 << 20

	// Inventory bounds of the persisted artifact. They mirror the existing
	// registration validator exactly (governedquery.ExposedSchema.Validate):
	// 1..32 objects and 1..64 columns per object. Exposure narrows what the
	// dedicated role already sees, so an empty or oversized inventory is not a
	// decodable artifact at all.
	maxGovernedExposureObjects = 32
	maxGovernedExposureColumns = 64

	// Prose bounds of the two operator-written free-text members, mirroring
	// the same validator: a description is required and bounded to 512 runes,
	// a unit is optional (the wire omits it with omitempty) and bounded to 64.
	maxGovernedExposureDescriptionRunes = 512
	maxGovernedExposureUnitRunes        = 64

	// governedExposureIdentifierBytes is the 63-byte limit of an unquoted
	// PostgreSQL identifier (NAMEDATALEN-1).
	governedExposureIdentifierBytes = 63
)

// governedExposureColumn and governedExposureObject mirror the persisted
// exposed-schema wire member for member. They are private because they exist
// only to decode already-trusted server bytes inside this package; the exact
// JSON member names, and the unit omitempty, are what make the re-derived
// canonical hash byte-identical to the registration hash
// (canon.Hash(canon.CanonicalJSON(schema.Objects)) in the registration path).
// The registration parallelism covers the wire and the hash convention only.
// Identifier acceptance is deliberately wider than registration's validator:
// see validGovernedExposureIdentifier.
type governedExposureColumn struct {
	Name        string `json:"name"`
	DataType    string `json:"data_type"`
	Description string `json:"description"`
	Unit        string `json:"unit,omitempty"`
}

type governedExposureObject struct {
	SchemaName  string                   `json:"schema_name"`
	TableName   string                   `json:"table_name"`
	Description string                   `json:"description"`
	Columns     []governedExposureColumn `json:"columns"`
}

// governedExposureFacts is the closed result of one verified decode. It
// carries only the revision, the full-artifact hash, the selected
// schema/relation identity and that relation's detached column names. There is
// deliberately no exported type, constructor or JSON projection: the value is
// read by this package's own loaders and never crosses a transport boundary.
type governedExposureFacts struct {
	revision     int64
	artifactHash string
	schemaName   string
	relationName string
	columns      []string
}

// decodeGovernedExposure normalizes one persisted governed-exposure artifact.
//
// objectsJSON is the scanned objects_json jsonb text, revision and
// revisionHash are the sibling persisted columns, and schemaName/relationName
// are the exact case-sensitive identity of the one relation the caller wants
// projected. The whole decoded artifact participates in the hash, never only
// the selected relation: every other object, and every description, data type
// and unit, is part of what makes the artifact what it is. Array order is
// preserved, so reordering objects or columns changes the hash.
//
// A malformed artifact, hash, identifier, bound or duplicate returns zero
// facts and CodePersistence. An artifact that is well formed and hash-verified
// but holds no object with the requested identity returns zero facts and
// CodeNotFound. Duplicate matching identity cannot survive the uniqueness
// requirement and is CodePersistence.
func decodeGovernedExposure(
	objectsJSON []byte,
	revision int64,
	revisionHash string,
	schemaName string,
	relationName string,
) (governedExposureFacts, error) {
	if len(objectsJSON) == 0 || len(objectsJSON) > maxGovernedExposureArtifactBytes {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	if revision < 1 || revision > maxSafeInteger {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	// The persisted hash is the exact canonical lowercase form registration
	// writes (canon.Hash), so an alias, an uppercase digest or a non-sha256
	// form is malformed rather than a mere mismatch.
	if !workspace.IsConfigurationHash(revisionHash) {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	if !validGovernedExposureIdentifier(schemaName) || !validGovernedExposureIdentifier(relationName) {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}

	var objects []governedExposureObject
	if err := jsonv2.Unmarshal(objectsJSON, &objects,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	if len(objects) == 0 || len(objects) > maxGovernedExposureObjects {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	identities := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		identity, ok := validGovernedExposureObject(object)
		if !ok {
			return governedExposureFacts{}, &Error{code: CodePersistence}
		}
		if _, duplicate := identities[identity]; duplicate {
			return governedExposureFacts{}, &Error{code: CodePersistence}
		}
		identities[identity] = struct{}{}
	}

	// Re-derive the hash from the decoded artifact. The decoded jsonb bytes are
	// never hashed: PostgreSQL may re-render the stored document, so the hash
	// must come from the canonical form of the decoded value — the same
	// convention registration persists.
	canonical, err := canon.CanonicalJSON(objects)
	if err != nil {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}
	artifactHash := canon.Hash(canonical)
	if artifactHash != revisionHash {
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}

	matches := 0
	selected := 0
	for index, object := range objects {
		if object.SchemaName != schemaName || object.TableName != relationName {
			continue
		}
		if matches == 0 {
			selected = index
		}
		matches++
	}
	switch {
	case matches == 0:
		return governedExposureFacts{}, &Error{code: CodeNotFound}
	case matches > 1:
		// The artifact-wide identity uniqueness check above already refuses a
		// duplicated schema/table pair. Keeping the selection rule closed on
		// its own means a future weakening of that check still cannot make
		// "exactly one object" ambiguous.
		return governedExposureFacts{}, &Error{code: CodePersistence}
	}

	// Detach: the returned names are this call's own slice, never a view of the
	// decoded artifact or of another result.
	columns := make([]string, len(objects[selected].Columns))
	for index, column := range objects[selected].Columns {
		columns[index] = column.Name
	}
	return governedExposureFacts{
		revision: revision,
		// artifactHash already equals revisionHash; the re-derived value is
		// returned so the facts carry the hash of the content that was decoded.
		artifactHash: artifactHash,
		schemaName:   schemaName,
		relationName: relationName,
		columns:      columns,
	}, nil
}

// validGovernedExposureObject validates one decoded object and returns its
// artifact-wide identity. Identity is the schema/table pair; neither member
// can contain the separator, so distinct pairs cannot collide.
func validGovernedExposureObject(object governedExposureObject) (string, bool) {
	if !validGovernedExposureIdentifier(object.SchemaName) || !validGovernedExposureIdentifier(object.TableName) {
		return "", false
	}
	if !validGovernedExposureProse(object.Description, maxGovernedExposureDescriptionRunes) {
		return "", false
	}
	if len(object.Columns) == 0 || len(object.Columns) > maxGovernedExposureColumns {
		return "", false
	}
	seen := make(map[string]struct{}, len(object.Columns))
	for _, column := range object.Columns {
		if !validGovernedExposureIdentifier(column.Name) || column.DataType == "" ||
			!validGovernedExposureProse(column.Description, maxGovernedExposureDescriptionRunes) ||
			(column.Unit != "" && !validGovernedExposureProse(column.Unit, maxGovernedExposureUnitRunes)) {
			return "", false
		}
		if _, duplicate := seen[column.Name]; duplicate {
			return "", false
		}
		seen[column.Name] = struct{}{}
	}
	return object.SchemaName + "." + object.TableName, true
}

// validGovernedExposureIdentifier accepts exactly the case-sensitive, unquoted
// PostgreSQL identifier shape typed analytics already validates schema,
// relation and column names with (^[A-Za-z_][A-Za-z0-9_$]{0,62}$, the pattern
// analytic.SourceProjectionSpec.Valid and analyticsource's column set use): an
// ASCII letter or underscore followed by at most 62 more letters, digits,
// underscores or dollar signs. Nothing is trimmed, case-folded or quoted, so
// "Facts", "facts" and `"facts"` stay three distinct identities.
//
// This is deliberately not the registration validator
// (governedquery.validIdentifier), which accepts only lowercase letters,
// digits and underscores: the read side follows the typed-analytics contract,
// so uppercase and dollar signs are accepted here even though that registration
// path could never have written them.
func validGovernedExposureIdentifier(value string) bool {
	if len(value) == 0 || len(value) > governedExposureIdentifierBytes {
		return false
	}
	for index, character := range value {
		switch {
		case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character == '_':
			continue
		case character >= '0' && character <= '9' && index > 0, character == '$' && index > 0:
			continue
		default:
			return false
		}
	}
	return true
}

// validGovernedExposureProse mirrors the registration validator's prose rule
// (governedquery.validProse): a required non-empty value bounded to maxRunes
// runes, where every control character except a newline is refused. A unit is
// checked only when the operator wrote one, because the wire omits an absent
// unit.
func validGovernedExposureProse(value string, maxRunes int) bool {
	if value == "" {
		return false
	}
	count := 0
	for _, character := range value {
		if character < 0x20 && character != '\n' {
			return false
		}
		count++
		if count > maxRunes {
			return false
		}
	}
	return true
}
