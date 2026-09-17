package postgresqlquery

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// IdentityDigest derives the stable SourceObject identity from only the
// declared identity columns and the immutable database/projection lineage.
// Projection revision and contract hash are deliberately excluded so a
// byte-identical compatible revision reuses the same entity.
func IdentityDigest(key []byte, keyVersion int, projection Projection, row Row) (string, error) {
	if len(key) == 0 || keyVersion < 1 {
		return "", &Error{code: CodeInvalidValue}
	}
	if err := projection.Validate(); err != nil {
		return "", err
	}
	identityOrdinals := make(map[int]struct{})
	for _, column := range projection.Columns {
		for _, role := range column.Roles {
			if role == RoleIdentity {
				identityOrdinals[column.Ordinal] = struct{}{}
			}
		}
	}
	entries := make([]ValueEntry, 0, len(identityOrdinals))
	for _, entry := range row.Values {
		if _, ok := identityOrdinals[entry.Ordinal]; ok {
			if entry.ValueTag == "NULL" {
				return "", &Error{code: CodeInvalidValue}
			}
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ordinal < entries[j].Ordinal })
	if len(entries) != len(identityOrdinals) {
		return "", &Error{code: CodeInvalidValue}
	}
	payload, err := canon.CanonicalJSON(struct {
		ConnectionID     string       `json:"connection_id"`
		DatabaseIdentity string       `json:"database_identity"`
		LineageID        string       `json:"projection_lineage_id"`
		IdentityValues   []ValueEntry `json:"identity_values"`
	}{
		ConnectionID: projection.ConnectionID, DatabaseIdentity: projection.DatabaseIdentity,
		LineageID: projection.LineageID, IdentityValues: entries,
	})
	if err != nil {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	return canon.HMACDigest(key, keyVersion, payload), nil
}

// SnapshotSetHash is independent of result-row order. Every row hash is
// sorted before hashing, so a database view that changes only its physical
// order does not mint a new SourceVersion.
func SnapshotSetHash(rows []Row) (string, error) {
	values := make([]string, len(rows))
	for index, row := range rows {
		if len(row.Canonical) == 0 || row.Hash == "" {
			return "", &Error{code: CodeInvalidValue}
		}
		values[index] = row.Hash
	}
	sort.Strings(values)
	canonical, err := canon.CanonicalJSON(values)
	if err != nil {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
