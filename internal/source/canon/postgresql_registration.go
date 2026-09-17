package canon

// PostgreSQL query source registration plaintexts. These values are sealed in
// the same owner branches as folder sources; the shape is deliberately free of
// SQL text, credentials and row data. The projection contract is represented by
// its immutable hash and canonical column descriptor bytes.

import "encoding/json"

func PostgreSQLQueryScopeIdentityBytes(connectionID, databaseIdentity, lineageID string, revision int64) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion      string `json:"schema_version"`
		SourceType         string `json:"source_type"`
		ConnectionID       string `json:"connection_id"`
		DatabaseIdentity   string `json:"database_identity"`
		LineageID          string `json:"lineage_id"`
		ProjectionRevision int64  `json:"projection_revision"`
	}{
		"source-postgresql-query-identity-v1", "POSTGRESQL_QUERY", connectionID,
		databaseIdentity, lineageID, revision,
	})
}

func PostgreSQLQueryTrustBytes(connectionID, databaseIdentity, lineageID string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion    string `json:"schema_version"`
		SourceType       string `json:"source_type"`
		ConnectionID     string `json:"connection_id"`
		DatabaseIdentity string `json:"database_identity"`
		LineageID        string `json:"lineage_id"`
	}{"source-postgresql-query-trust-v1", "POSTGRESQL_QUERY", connectionID, databaseIdentity, lineageID})
}

// PostgreSQLQueryScopeConfigBytes accepts already-canonical column JSON. It
// embeds it as raw JSON so the resulting JCS remains byte-for-byte stable.
func PostgreSQLQueryScopeConfigBytes(databaseIdentity, lineageID string, revision int64,
	schemaName, relationName, relationKind, contractHash, columnsJSON, emptyPolicy string,
	maxRows, maxColumns, maxFieldBytes, maxRowBytes, maxTotalBytes, statementTimeoutMS int64) ([]byte, error) {
	var columns json.RawMessage = []byte(columnsJSON)
	return canonicalJSON(struct {
		SchemaVersion       string          `json:"schema_version"`
		SourceType          string          `json:"source_type"`
		DatabaseIdentity    string          `json:"database_identity"`
		LineageID           string          `json:"lineage_id"`
		ProjectionRevision  int64           `json:"projection_revision"`
		SchemaName          string          `json:"schema_name"`
		RelationName        string          `json:"relation_name"`
		RelationKind        string          `json:"relation_kind"`
		ContractHash        string          `json:"contract_hash"`
		Columns             json.RawMessage `json:"columns"`
		EmptySnapshotPolicy string          `json:"empty_snapshot_policy"`
		MaxRows             int64           `json:"max_rows"`
		MaxColumns          int64           `json:"max_columns"`
		MaxFieldBytes       int64           `json:"max_field_bytes"`
		MaxRowBytes         int64           `json:"max_row_bytes"`
		MaxTotalBytes       int64           `json:"max_total_bytes"`
		StatementTimeoutMS  int64           `json:"statement_timeout_ms"`
	}{
		"source-postgresql-query-config-v1", "POSTGRESQL_QUERY", databaseIdentity, lineageID,
		revision, schemaName, relationName, relationKind, contractHash, columns, emptyPolicy,
		maxRows, maxColumns, maxFieldBytes, maxRowBytes, maxTotalBytes, statementTimeoutMS,
	})
}
