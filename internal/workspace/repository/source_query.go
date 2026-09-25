package repository

// source_query.go is S3 card 2's read boundary behind ADR-0097's
// knowvault_source_sql tool, hardened by card 2c. It resolves one enabled
// PostgreSQL source of the caller's workspace to exactly what the agent may
// name and nothing more:
//
//   - the immutable relation scope already registered for the source (the
//     exclusion-narrowed projections of migration 000110/000115);
//   - the optional opaque reference to the source's own QUERY credential
//     (migration 000116/000117), which is never the ingestion credential;
//   - the source's live activation/trust facts, so the execution boundary can
//     refuse a pending-activation or untrusted source with the content-free
//     not-found; and
//   - the stored least-privilege proof (migration 000118) bound to the exact
//     (connection revision, query credential revision, projection) pair.
//
// Every row of one call must share one scope, one scope revision and one
// connection revision. PostgreSQL's join already pins one scope revision; the
// Go side detects a workspace that bound the same connection twice (two scope
// rows) and folds it into the same content-free not-found instead of silently
// mixing two scopes.
//
// Like the source schema read, it goes through sourceMetadataRead, the shared
// admission-before-data boundary, so authorization, cross-tenant invisibility,
// the content-free CodeNotFound and the source.metadata.read.* audit journal
// are identical to the other source metadata reads; the kind is SOURCE_SQL.
// It opens no external database and composes no SQL against it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// SourceQueryVerification is the stored least-privilege proof for one source
// connection. It is content-free: a projection hash and a role digest, never a
// relation, a column or a secret.
type SourceQueryVerification struct {
	ConnectionRevision int64
	CredentialRevision int64
	ScopeHash          string
	RoleDigest         string
}

// SourceQuerySource is the exact server-owned scope of one enabled source.
// QueryCredentialReference is empty when the connection has no separate query
// credential; ScopeRevision is the source scope revision the attempt is
// audited against; DatabaseIdentity is the projection's immutable "pgdb:…".
// ConnectionRevision and QueryCredentialRevision are the two halves of the
// card's verification pair; ActivationStatus and TrustVerified are the source
// state gates the execution boundary enforces.
type SourceQuerySource struct {
	SourceID                 string
	SourceScopeID            string
	ScopeRevision            int64
	ConnectionRevision       int64
	DatabaseIdentity         string
	QueryCredentialReference string
	QueryCredentialRevision  int64
	// IngestionCredentialReference is the exact connection revision's
	// ingestion credential reference. It is read only so the owner control can
	// refuse a query credential that equals it before the database trigger
	// (migration 000118) refuses it too; it is never disclosed to a caller.
	IngestionCredentialReference string
	ActivationStatus             string
	TrustVerified                bool
	Relations                    []SourceQueryRelation
	Verification                 SourceQueryVerification
}

// ScopeHash is the content-free hash of the registered projection. It is
// computed server-side from the stored projection, never from a request, so a
// projection change invalidates a stored proof even without a revision bump.
func (source SourceQuerySource) ScopeHash() string {
	return sourceQueryScopeHash(source.Relations)
}

// RoleProven reports whether the stored verification row still matches this
// exact (connection revision, credential revision, projection) pair. Card S3.2d
// makes this a content-free evidence predicate only: the execution path
// re-runs the least-privilege proof inside the statement's own transaction and
// never consults this row to authorize anything, so a stale or forged row
// cannot let a statement run.
func (source SourceQuerySource) RoleProven() bool {
	return source.Verification.ConnectionRevision == source.ConnectionRevision &&
		source.Verification.CredentialRevision == source.QueryCredentialRevision &&
		source.Verification.CredentialRevision > 0 &&
		source.Verification.ScopeHash == source.ScopeHash() &&
		source.Verification.RoleDigest != ""
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
	var result SourceQuerySource
	var notFound bool
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		var readErr error
		result, notFound, readErr = readSourceQueryRelations(transactionContext, transaction, access.OrganizationID, workspaceID, sourceID)
		return readErr
	})
	if err != nil {
		return SourceQuerySource{}, &Error{code: CodePersistence, cause: err}
	}
	if notFound {
		return SourceQuerySource{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// readSourceQueryRelations is the shared relation-scope read behind the tool
// boundary and the owner-gated credential control. It runs on the caller's
// already-authorized transaction and never authorizes anything itself.
func readSourceQueryRelations(ctx context.Context, transaction database.Transaction, organizationID, workspaceID, sourceID string) (SourceQuerySource, bool, error) {
	result := SourceQuerySource{SourceID: sourceID}
	rows, queryErr := transaction.Query(ctx, `
		SELECT status.source_scope_id, status.source_scope_revision, scope_revision.connection_revision,
		       projection.schema_name, projection.relation_name, projection.columns_json,
		       projection.database_identity, status.activation_status, status.trust_verified,
		       connection_revision.credential_reference,
		       query_credential.credential_reference, query_credential.revision,
		       verification.connection_revision, verification.credential_revision,
		       verification.scope_hash, verification.role_digest
		FROM app.workspace_source_status_v3($1) AS status
		JOIN public.source_scope_revision AS scope_revision
		  ON scope_revision.organization_id = $2
		 AND scope_revision.source_scope_id = status.source_scope_id
		 AND scope_revision.revision = status.source_scope_revision
		 AND scope_revision.connection_id = status.connection_id
		 AND scope_revision.source_type = 'POSTGRESQL_QUERY'
		JOIN public.source_connection_revision AS connection_revision
		  ON connection_revision.organization_id = scope_revision.organization_id
		 AND connection_revision.connection_id = scope_revision.connection_id
		 AND connection_revision.revision = scope_revision.connection_revision
		JOIN public.postgresql_query_projection AS projection
		  ON projection.organization_id = scope_revision.organization_id
		 AND projection.source_scope_id = scope_revision.source_scope_id
		 AND projection.source_scope_revision = scope_revision.revision
		 AND projection.connection_id = scope_revision.connection_id
		LEFT JOIN public.source_query_credential AS query_credential
		  ON query_credential.organization_id = scope_revision.organization_id
		 AND query_credential.connection_id = scope_revision.connection_id
		LEFT JOIN public.source_query_credential_verification AS verification
		  ON verification.organization_id = scope_revision.organization_id
		 AND verification.connection_id = scope_revision.connection_id
		WHERE status.enabled AND status.connection_id = $3
		ORDER BY projection.schema_name, projection.relation_name`,
		workspaceID, organizationID, sourceID)
	if queryErr != nil {
		return SourceQuerySource{}, false, queryErr
	}
	defer rows.Close()
	scopeSeen := false
	for rows.Next() {
		var scopeID string
		var scopeRevision, connectionRevision int64
		var relation SourceQueryRelation
		var columnsRaw []byte
		var credentialReference *string
		var credentialRevision *int64
		var verifiedConnectionRevision, verifiedCredentialRevision *int64
		var verifiedScopeHash, verifiedRoleDigest *string
		if scanErr := rows.Scan(&scopeID, &scopeRevision, &connectionRevision,
			&relation.Schema, &relation.Table, &columnsRaw,
			&result.DatabaseIdentity, &result.ActivationStatus, &result.TrustVerified,
			&result.IngestionCredentialReference,
			&credentialReference, &credentialRevision,
			&verifiedConnectionRevision, &verifiedCredentialRevision,
			&verifiedScopeHash, &verifiedRoleDigest); scanErr != nil {
			return SourceQuerySource{}, false, scanErr
		}
		// Every row of one call must share one scope, one revision and one
		// connection revision; a workspace that bound the same connection more
		// than once is the same content-free not-found rather than a silent
		// merge of two scopes.
		if !scopeSeen {
			scopeSeen = true
			result.SourceScopeID = scopeID
			result.ScopeRevision = scopeRevision
			result.ConnectionRevision = connectionRevision
		} else if !sourceQueryScopeMatches(result, scopeID, scopeRevision, connectionRevision) {
			return SourceQuerySource{}, true, nil
		}
		columns, decodeErr := sourceQueryColumns(columnsRaw)
		if decodeErr != nil {
			return SourceQuerySource{}, false, decodeErr
		}
		relation.Columns = columns
		result.Relations = append(result.Relations, relation)
		if credentialReference != nil {
			result.QueryCredentialReference = *credentialReference
		}
		if credentialRevision != nil {
			result.QueryCredentialRevision = *credentialRevision
		}
		if verifiedConnectionRevision != nil && verifiedCredentialRevision != nil &&
			verifiedScopeHash != nil && verifiedRoleDigest != nil {
			result.Verification = SourceQueryVerification{
				ConnectionRevision: *verifiedConnectionRevision,
				CredentialRevision: *verifiedCredentialRevision,
				ScopeHash:          *verifiedScopeHash,
				RoleDigest:         *verifiedRoleDigest,
			}
		}
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return SourceQuerySource{}, false, rowsErr
	}
	if len(result.Relations) == 0 {
		return SourceQuerySource{}, true, nil
	}
	return result, false, nil
}

// sourceQueryScopeMatches reports whether one more projection row belongs to the
// same scope, scope revision and connection revision as the first row of the
// call. A workspace that bound the same connection through two scopes produces
// rows that fail this check, and the whole read collapses into the content-free
// not-found instead of merging two scopes.
func sourceQueryScopeMatches(source SourceQuerySource, scopeID string, scopeRevision, connectionRevision int64) bool {
	return source.SourceScopeID == scopeID && source.ScopeRevision == scopeRevision &&
		source.ConnectionRevision == connectionRevision
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

// sourceQueryScopeHash is the canonical content-free hash of a registered
// projection. It is computed from the stored, server-owned relation list (never
// from a request), so two servers derive the same value for the same scope and
// a projection change without a revision bump still invalidates a proof.
func sourceQueryScopeHash(relations []SourceQueryRelation) string {
	canonical := struct {
		Format    string     `json:"format"`
		Relations [][]string `json:"relations"`
	}{Format: "postgresql-query-scope-v1"}
	for _, relation := range relations {
		entry := append([]string{relation.Schema, relation.Table}, relation.Columns...)
		canonical.Relations = append(canonical.Relations, entry)
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
