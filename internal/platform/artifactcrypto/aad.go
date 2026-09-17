package artifactcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// wrappedDEKSchemaVersion binds the wrap-layer AAD. It is distinct from the
// artifact AADSchemaVersion so a wrapped DEK can never be authenticated as an
// artifact envelope or vice versa.
const wrappedDEKSchemaVersion = "encrypted-artifact-wrapped-dek-v1"

// artifactAAD builds the canonical JCS bytes bound into the artifact AES-256-GCM
// operation. It is recomputed on open from the trusted owner tuple, never taken
// from the stored envelope or an API argument, so ciphertext moved between
// tenants, rows, columns or resource types fails GCM authentication.
func artifactAAD(owner OwnerIdentity) ([]byte, error) {
	if !owner.valid() {
		return nil, &Error{code: CodeInvalidOwner}
	}
	return canonicalJSON(struct {
		Field          string `json:"field"`
		OrganizationID string `json:"organization_id"`
		OwnerColumn    string `json:"owner_column"`
		OwnerTable     string `json:"owner_table"`
		ResourceID     string `json:"resource_id"`
		ResourceType   string `json:"resource_type"`
		SchemaVersion  string `json:"schema_version"`
	}{
		Field:          owner.field,
		OrganizationID: owner.organizationID,
		OwnerColumn:    owner.ownerColumn,
		OwnerTable:     owner.ownerTable,
		ResourceID:     owner.resourceID,
		ResourceType:   owner.resourceType,
		SchemaVersion:  AADSchemaVersion,
	})
}

// wrapAAD builds the canonical JCS bytes bound into the DEK-wrapping operation.
// It binds the full owner tuple plus the exact KEK reference and version so a
// wrapped DEK moved to another artifact, column, tenant, key reference or key
// version fails wrap authentication.
func wrapAAD(owner OwnerIdentity, kekReference string, kekVersion int64) ([]byte, error) {
	if !owner.valid() || kekReference == "" || kekVersion < 1 {
		return nil, &Error{code: CodeWrapFailed}
	}
	return canonicalJSON(struct {
		Field          string `json:"field"`
		KEKReference   string `json:"kek_reference"`
		KEKVersion     int64  `json:"kek_version"`
		OrganizationID string `json:"organization_id"`
		OwnerColumn    string `json:"owner_column"`
		OwnerTable     string `json:"owner_table"`
		ResourceID     string `json:"resource_id"`
		ResourceType   string `json:"resource_type"`
		SchemaVersion  string `json:"schema_version"`
	}{
		Field:          owner.field,
		KEKReference:   kekReference,
		KEKVersion:     kekVersion,
		OrganizationID: owner.organizationID,
		OwnerColumn:    owner.ownerColumn,
		OwnerTable:     owner.ownerTable,
		ResourceID:     owner.resourceID,
		ResourceType:   owner.resourceType,
		SchemaVersion:  wrappedDEKSchemaVersion,
	})
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		return nil, &Error{code: CodeSealFailed}
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, &Error{code: CodeSealFailed}
	}
	return []byte(canonical), nil
}

// hashDigest formats a SHA-256 digest as the canonical sha256:<lowercase hex>
// string accepted by app.stage2_sha256_is_valid.
func hashDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
