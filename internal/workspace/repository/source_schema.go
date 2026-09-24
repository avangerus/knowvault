package repository

// source_schema.go is S3 card 1's read boundary behind ADR-0097's
// knowvault_source_schema tool. It answers from exactly the data an earlier
// registration already persisted -- the enabled workspace source bindings, the
// immutable postgresql_query_projection rows and the display-only
// postgresql_query_relation_catalog companion from migration 000114 -- so the
// tool never opens the external source database and never re-derives a schema.
//
// Authorization, cross-tenant invisibility and the content-free denial are not
// re-implemented here: both reads go through sourceMetadataRead, the same
// admission-before-data boundary ListSources and ConfirmationContext already
// use, so a foreign, unknown, disabled or non-member source collapses to the
// identical CodeNotFound and every read is journalled with the existing
// source.metadata.read.* vocabulary (kind SOURCE_SCHEMA_LIST / SOURCE_SCHEMA).
//
// Columns come from the projection's own columns_json, so a column the
// administrator excluded at registration (already absent from the projection)
// can never be listed. Display metadata -- native type name, relation/column
// comments and pg_class.reltuples -- is merged from the catalog row when it
// exists and gracefully falls back to the projection's logical type with no
// comment for a hand-registered scope that has no discovery catalog.

import (
	"context"
	"encoding/json"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	sourceSchemaListRead = "SOURCE_SCHEMA_LIST"
	sourceSchemaRead     = "SOURCE_SCHEMA"
)

// SourceSchemaSource is one enabled PostgreSQL source connection of a
// workspace: the connection id the source tools name, its display name and the
// number of registered projections (tables) currently bound to the workspace.
type SourceSchemaSource struct {
	ID         string
	Name       string
	TableCount int
}

// SourceSchemaColumn is one projected column. Type is the native PostgreSQL
// type name observed at discovery, or the projection's logical type when no
// catalog row exists. PrimaryKey mirrors the projection's IDENTITY role, so a
// view's entity key and a table's declared key are both reported.
type SourceSchemaColumn struct {
	Name       string
	Type       string
	Nullable   bool
	PrimaryKey bool
	Note       string
}

// SourceSchemaTable is one registered relation of a source.
type SourceSchemaTable struct {
	Schema      string
	Name        string
	Kind        string
	RowEstimate int64
	Note        string
	Columns     []SourceSchemaColumn
}

// SourceSchema is one page of a source's relations. DatabaseIdentity is the
// projection's immutable database identity ("pgdb:…"), empty only when the
// source has no readable relation at all.
type SourceSchema struct {
	SourceID         string
	DatabaseIdentity string
	Tables           []SourceSchemaTable
	HasMore          bool
}

// ListSourceSchemas lists the enabled PostgreSQL sources of one workspace: one
// entry per enabled source connection with a registered projection, ordered by
// display name then connection id.
func (store *Store) ListSourceSchemas(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceSchemaSource, error) {
	if store == nil || store.database == nil || store.audit == nil || access.Validate() != nil || !validID(workspaceID) {
		return nil, &Error{code: CodeRequestInvalid}
	}
	var result []SourceSchemaSource
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceSchemaListRead, func() error {
		var readErr error
		result, readErr = store.listSourceSchemas(ctx, access, workspaceID)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (store *Store) listSourceSchemas(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceSchemaSource, error) {
	result := []SourceSchemaSource{}
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT status.connection_id, status.connection_name, count(*)::bigint
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
			WHERE status.enabled
			GROUP BY status.connection_id, status.connection_name
			ORDER BY status.connection_name, status.connection_id`, workspaceID, access.OrganizationID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var source SourceSchemaSource
			if scanErr := rows.Scan(&source.ID, &source.Name, &source.TableCount); scanErr != nil {
				return scanErr
			}
			result = append(result, source)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return result, nil
}

// SourceSchema reads one page of the relations registered for one enabled
// PostgreSQL source of a workspace. An unknown, foreign, disabled or
// non-member source is CodeNotFound with no content, exactly like the other
// source metadata reads; a table filter that matches nothing is an empty
// successful page, not a denial. When table is non-empty it must already be a
// validated "schema.name".
func (store *Store) SourceSchema(ctx context.Context, access database.AccessContext, workspaceID, sourceID, table string, offset, limit int) (SourceSchema, error) {
	if store == nil || store.database == nil || store.audit == nil || access.Validate() != nil || !validID(workspaceID) ||
		!validID(sourceID) || offset < 0 || limit < 1 || limit > maxSourceSchemaPage {
		return SourceSchema{}, &Error{code: CodeRequestInvalid}
	}
	var result SourceSchema
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceSchemaRead, func() error {
		var readErr error
		result, readErr = store.sourceSchema(ctx, access, workspaceID, sourceID, table, offset, limit)
		return readErr
	})
	if err != nil {
		return SourceSchema{}, err
	}
	return result, nil
}

// maxSourceSchemaPage bounds one page of relations. It mirrors the tool's own
// 50-relation maximum so the repository and the transport cannot disagree.
const maxSourceSchemaPage = 50

func (store *Store) sourceSchema(ctx context.Context, access database.AccessContext, workspaceID, sourceID, table string, offset, limit int) (SourceSchema, error) {
	schemaName, relationName := sourceSchemaSelector(table)
	result := SourceSchema{SourceID: sourceID}
	notFound := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		var relationCount int64
		var databaseIdentity *string
		if queryErr := transaction.QueryRow(transactionContext, `
			SELECT count(*), min(projection.database_identity)
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
			WHERE status.enabled AND status.connection_id = $3`, workspaceID, access.OrganizationID, sourceID).Scan(&relationCount, &databaseIdentity); queryErr != nil {
			return queryErr
		}
		if relationCount == 0 {
			notFound = true
			return nil
		}
		if databaseIdentity != nil {
			result.DatabaseIdentity = *databaseIdentity
		}
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT projection.schema_name, projection.relation_name, projection.relation_kind,
			       projection.columns_json, catalog.relation_comment,
			       catalog.approx_row_count, catalog.columns_catalog
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
			LEFT JOIN public.postgresql_query_relation_catalog AS catalog
			  ON catalog.organization_id = projection.organization_id
			 AND catalog.source_scope_id = projection.source_scope_id
			 AND catalog.source_scope_revision = projection.source_scope_revision
			WHERE status.enabled AND status.connection_id = $3
			  AND ($4 = '' OR (projection.schema_name = $4 AND projection.relation_name = $5))
			ORDER BY projection.schema_name, projection.relation_name
			LIMIT $6 OFFSET $7`,
			workspaceID, access.OrganizationID, sourceID, schemaName, relationName, limit+1, offset)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var relation SourceSchemaTable
			// relationComment and approxRowCount are nullable because the
			// catalog row is optional (a hand-registered scope has none);
			// columnsCatalog stays nil in that case.
			var columnsRaw []byte
			var relationComment *string
			var approxRowCount *int64
			var columnsCatalog []byte
			if scanErr := rows.Scan(&relation.Schema, &relation.Name, &relation.Kind,
				&columnsRaw, &relationComment, &approxRowCount, &columnsCatalog); scanErr != nil {
				return scanErr
			}
			relation.RowEstimate = -1
			if approxRowCount != nil {
				relation.RowEstimate = *approxRowCount
			}
			if relationComment != nil {
				relation.Note = *relationComment
			}
			columns, decodeErr := sourceSchemaColumns(columnsRaw, columnsCatalog)
			if decodeErr != nil {
				return decodeErr
			}
			relation.Columns = columns
			result.Tables = append(result.Tables, relation)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		result.HasMore = len(result.Tables) > limit
		if result.HasMore {
			result.Tables = result.Tables[:limit]
		}
		return nil
	})
	if err != nil {
		return SourceSchema{}, &Error{code: CodePersistence, cause: err}
	}
	if notFound {
		return SourceSchema{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// sourceSchemaSelector splits a validated "schema.name" selector. An empty
// selector means "every relation"; the transport refuses anything that is not
// exactly one validated identifier on each side of the dot before this runs.
func sourceSchemaSelector(table string) (string, string) {
	for index := 0; index < len(table); index++ {
		if table[index] == '.' {
			return table[:index], table[index+1:]
		}
	}
	return "", ""
}

type sourceSchemaProjectionColumn struct {
	Ordinal     int      `json:"ordinal"`
	Name        string   `json:"name"`
	LogicalType string   `json:"logical_type"`
	Roles       []string `json:"roles"`
	Nullable    bool     `json:"nullable"`
}

type sourceSchemaCatalogColumn struct {
	Name       string `json:"name"`
	TypeName   string `json:"type_name"`
	Comment    string `json:"comment"`
	PrimaryKey bool   `json:"primary_key"`
}

// sourceSchemaColumns builds the reported column list from the projection's
// own columns_json (the exclusion-narrowed contract) merged with the optional
// discovery catalog. A catalog entry whose name is not in the projection is
// ignored, so even a corrupt or stale catalog row can never widen the contract.
func sourceSchemaColumns(columnsRaw, columnsCatalog []byte) ([]SourceSchemaColumn, error) {
	var projected []sourceSchemaProjectionColumn
	if err := json.Unmarshal(columnsRaw, &projected); err != nil {
		return nil, err
	}
	catalog := make(map[string]sourceSchemaCatalogColumn)
	if len(columnsCatalog) > 0 {
		var entries []sourceSchemaCatalogColumn
		if err := json.Unmarshal(columnsCatalog, &entries); err != nil {
			return nil, err
		}
		for _, entry := range entries {
			catalog[entry.Name] = entry
		}
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].Ordinal < projected[j].Ordinal })
	columns := make([]SourceSchemaColumn, 0, len(projected))
	for _, column := range projected {
		result := SourceSchemaColumn{Name: column.Name, Type: column.LogicalType, Nullable: column.Nullable}
		for _, role := range column.Roles {
			if role == "IDENTITY" {
				result.PrimaryKey = true
				break
			}
		}
		if entry, ok := catalog[column.Name]; ok {
			if entry.TypeName != "" {
				result.Type = entry.TypeName
			}
			result.Note = entry.Comment
			if entry.PrimaryKey {
				result.PrimaryKey = true
			}
		}
		columns = append(columns, result)
	}
	return columns, nil
}
