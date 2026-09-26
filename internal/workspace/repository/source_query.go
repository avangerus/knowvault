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
// projected columns the agent may name. QueryOnly marks S3 card 4's query-only
// registration: the relation is addressable by SQL but its rows are never
// indexed.
type SourceQueryRelation struct {
	Schema    string
	Table     string
	Columns   []string
	QueryOnly bool
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
		       verification.scope_hash, verification.role_digest,
		       projection.query_only
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
	var scanned []sourceQueryRow
	for rows.Next() {
		var row sourceQueryRow
		var columnsRaw []byte
		if scanErr := rows.Scan(&row.scopeID, &row.scopeRevision, &row.connectionRevision,
			&row.relation.Schema, &row.relation.Table, &columnsRaw,
			&row.databaseIdentity, &row.activationStatus, &row.trustVerified,
			&row.ingestionCredentialReference,
			&row.credentialReference, &row.credentialRevision,
			&row.verifiedConnectionRevision, &row.verifiedCredentialRevision,
			&row.verifiedScopeHash, &row.verifiedRoleDigest, &row.relation.QueryOnly); scanErr != nil {
			return SourceQuerySource{}, false, scanErr
		}
		columns, decodeErr := sourceQueryColumns(columnsRaw)
		if decodeErr != nil {
			return SourceQuerySource{}, false, decodeErr
		}
		row.relation.Columns = columns
		scanned = append(scanned, row)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return SourceQuerySource{}, false, rowsErr
	}
	result, merged := mergeSourceQueryRows(sourceID, scanned)
	if !merged {
		return SourceQuerySource{}, true, nil
	}
	return result, false, nil
}

// sourceQueryRow is one registered relation of one enabled scope on the
// requested connection, as read by readSourceQueryRelations.
type sourceQueryRow struct {
	scopeID                      string
	scopeRevision                int64
	connectionRevision           int64
	relation                     SourceQueryRelation
	databaseIdentity             string
	activationStatus             string
	trustVerified                bool
	ingestionCredentialReference string
	credentialReference          *string
	credentialRevision           *int64
	verifiedConnectionRevision   *int64
	verifiedCredentialRevision   *int64
	verifiedScopeHash            *string
	verifiedRoleDigest           *string
}

// mergeSourceQueryRows folds the relations of every scope the workspace has
// enabled on one connection into the one source the agent queries. The
// registration flow registers each table as its own scope, so a database with
// several registered tables is several scopes on one connection; the query
// role is one per connection and its least-privilege proof covers exactly the
// union of their projections, so the union is the source's scope.
//
// The fold is refused (content-free not-found) when the rows do not describe
// one database at one connection revision, when one scope appears at two
// revisions, or when two scopes register the same relation. The merged source
// is READY and trusted only when every one of its scopes is, so SQL never runs
// while part of the registered set is still pending or revoked. ScopeRevision,
// the exposed-schema revision the attempt is audited and re-authorized
// against, is the sum of the scope revisions: it equals the scope revision for
// a single scope and changes whenever a scope is added, removed or revised.
func mergeSourceQueryRows(sourceID string, rows []sourceQueryRow) (SourceQuerySource, bool) {
	if len(rows) == 0 {
		return SourceQuerySource{}, false
	}
	first := rows[0]
	result := SourceQuerySource{
		SourceID: sourceID, SourceScopeID: first.scopeID, ConnectionRevision: first.connectionRevision,
		DatabaseIdentity: first.databaseIdentity, IngestionCredentialReference: first.ingestionCredentialReference,
		ActivationStatus: sourceActivationReadyState, TrustVerified: true,
	}
	scopeRevisions := map[string]int64{}
	relations := map[[2]string]bool{}
	for _, row := range rows {
		if row.connectionRevision != first.connectionRevision || row.databaseIdentity != first.databaseIdentity {
			return SourceQuerySource{}, false
		}
		if revision, seen := scopeRevisions[row.scopeID]; seen && revision != row.scopeRevision {
			return SourceQuerySource{}, false
		} else if !seen {
			scopeRevisions[row.scopeID] = row.scopeRevision
			result.ScopeRevision += row.scopeRevision
		}
		key := [2]string{row.relation.Schema, row.relation.Table}
		if relations[key] {
			return SourceQuerySource{}, false
		}
		relations[key] = true
		if row.activationStatus != sourceActivationReadyState && result.ActivationStatus == sourceActivationReadyState {
			result.ActivationStatus = row.activationStatus
		}
		if !row.trustVerified {
			result.TrustVerified = false
		}
		result.Relations = append(result.Relations, row.relation)
		if row.credentialReference != nil {
			result.QueryCredentialReference = *row.credentialReference
		}
		if row.credentialRevision != nil {
			result.QueryCredentialRevision = *row.credentialRevision
		}
		if row.verifiedConnectionRevision != nil && row.verifiedCredentialRevision != nil &&
			row.verifiedScopeHash != nil && row.verifiedRoleDigest != nil {
			result.Verification = SourceQueryVerification{
				ConnectionRevision: *row.verifiedConnectionRevision,
				CredentialRevision: *row.verifiedCredentialRevision,
				ScopeHash:          *row.verifiedScopeHash,
				RoleDigest:         *row.verifiedRoleDigest,
			}
		}
	}
	return result, true
}

// sourceActivationReadyState is the only activation state of a scope on which
// the merged source counts as READY.
const sourceActivationReadyState = "READY"

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
