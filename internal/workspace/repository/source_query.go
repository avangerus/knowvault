package repository

// source_query.go is S3 card 2's read boundary behind ADR-0097's
// knowvault_source_sql tool. It resolves one enabled PostgreSQL source of the
// caller's workspace to exactly what the agent may name and nothing more:
//
//   - the immutable relation scope already registered for the source (the
//     exclusion-narrowed projections of migration 000110/000115), and
//   - the optional opaque reference to the source's own QUERY credential
//     (migration 000116), which is never the ingestion credential.
//
// Like the source schema read, it goes through sourceMetadataRead, the shared
// admission-before-data boundary, so authorization, cross-tenant invisibility,
// the content-free CodeNotFound and the source.metadata.read.* audit journal
// are identical to the other source metadata reads; the kind is SOURCE_SQL.
// It opens no external database and composes no SQL against it.

import (
	"context"
	"encoding/json"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const sourceSQLRead = "SOURCE_SQL"

// SourceQueryRelation is one registered relation of the source scope plus the
// projected columns the agent may name.
type SourceQueryRelation struct {
	Schema  string
	Table   string
	Columns []string
}

// SourceQuerySource is the exact server-owned scope of one enabled source.
// QueryCredentialReference is empty when the connection has no separate query
// credential; ScopeRevision is the source scope revision the attempt is
// audited against; DatabaseIdentity is the projection's immutable "pgdb:…".
type SourceQuerySource struct {
	SourceID                 string
	ScopeRevision            int64
	DatabaseIdentity         string
	QueryCredentialReference string
	Relations                []SourceQueryRelation
}

// SourceQuery resolves one enabled source's registered relation scope and the
// optional query credential reference. An unknown, foreign, disabled or
// non-member source, or one with no registered relation, is the same
// content-free CodeNotFound every other source metadata read returns.
func (store *Store) SourceQuery(ctx context.Context, access database.AccessContext, workspaceID, sourceID string) (SourceQuerySource, error) {
	if store == nil || store.database == nil || store.audit == nil || access.Validate() != nil ||
		!validID(workspaceID) || !validID(sourceID) {
		return SourceQuerySource{}, &Error{code: CodeRequestInvalid}
	}
	var result SourceQuerySource
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceSQLRead, func() error {
		var readErr error
		result, readErr = store.sourceQuery(ctx, access, workspaceID, sourceID)
		return readErr
	})
	if err != nil {
		return SourceQuerySource{}, err
	}
	return result, nil
}

func (store *Store) sourceQuery(ctx context.Context, access database.AccessContext, workspaceID, sourceID string) (SourceQuerySource, error) {
	result := SourceQuerySource{SourceID: sourceID}
	notFound := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT projection.schema_name, projection.relation_name, projection.columns_json,
			       scope_revision.revision, projection.database_identity,
			       connection_revision.query_credential_reference
			FROM app.workspace_source_status_v3($1) AS status
			JOIN public.source_scope_revision AS scope_revision
			  ON scope_revision.organization_id = $2
			 AND scope_revision.source_scope_id = status.source_scope_id
			 AND scope_revision.revision = status.source_scope_revision
			 AND scope_revision.connection_id = status.connection_id
			 AND scope_revision.source_type = 'POSTGRESQL_QUERY'
			JOIN public.postgresql_query_projection AS projection
			  ON projection.organization_id = scope_revision.organization_id
			 AND projection.source_scope_id = scope_revision.source_scope_id
			 AND projection.source_scope_revision = scope_revision.revision
			 AND projection.connection_id = scope_revision.connection_id
			LEFT JOIN public.source_connection_revision AS connection_revision
			  ON connection_revision.organization_id = scope_revision.organization_id
			 AND connection_revision.connection_id = scope_revision.connection_id
			 AND connection_revision.revision = scope_revision.connection_revision
			WHERE status.enabled AND status.connection_id = $3
			ORDER BY projection.schema_name, projection.relation_name`,
			workspaceID, access.OrganizationID, sourceID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var relation SourceQueryRelation
			var columnsRaw []byte
			var credentialReference *string
			if scanErr := rows.Scan(&relation.Schema, &relation.Table, &columnsRaw,
				&result.ScopeRevision, &result.DatabaseIdentity, &credentialReference); scanErr != nil {
				return scanErr
			}
			columns, decodeErr := sourceQueryColumns(columnsRaw)
			if decodeErr != nil {
				return decodeErr
			}
			relation.Columns = columns
			result.Relations = append(result.Relations, relation)
			if credentialReference != nil {
				result.QueryCredentialReference = *credentialReference
			}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		if len(result.Relations) == 0 {
			notFound = true
		}
		return nil
	})
	if err != nil {
		return SourceQuerySource{}, &Error{code: CodePersistence, cause: err}
	}
	if notFound {
		return SourceQuerySource{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// sourceQueryColumns decodes the projection's own columns_json. The projection
// is already exclusion-narrowed at registration, so a column the administrator
// excluded is simply absent from the scope the agent can name.
func sourceQueryColumns(columnsRaw []byte) ([]string, error) {
	var projected []sourceSchemaProjectionColumn
	if err := json.Unmarshal(columnsRaw, &projected); err != nil {
		return nil, err
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].Ordinal < projected[j].Ordinal })
	columns := make([]string, 0, len(projected))
	for _, column := range projected {
		columns = append(columns, column.Name)
	}
	return columns, nil
}
