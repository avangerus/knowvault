package repository

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace"
)

// authorityColumn is the private wire shape of one entry in the persisted
// columns_json document. It exists only to decode already-trusted server
// contract bytes inside the read transaction; it is never returned.
type authorityColumn struct {
	Ordinal         int                         `json:"ordinal"`
	Name            string                      `json:"name"`
	TypeFingerprint string                      `json:"type_fingerprint"`
	LogicalType     postgresqlquery.LogicalType `json:"logical_type"`
	Roles           []postgresqlquery.Role      `json:"roles"`
	Nullable        bool                        `json:"nullable"`
	Precision       int                         `json:"precision"`
	Scale           int                         `json:"scale"`
	MaxBytes        int                         `json:"max_bytes"`
}

// PostgreSQLAuthorityRequest carries the immutable identity of one workspace
// source scope revision for which an authority decision is requested.
type PostgreSQLAuthorityRequest struct {
	WorkspaceID         string
	WorkspaceSourceID   string
	SourceScopeID       string
	ScopeConfigHash     string
	AccessMode          string
	SourceScopeRevision int64
}

// PostgreSQLAuthorityResult carries the resolved authority decision. All
// fields are private so that callers can only observe the resolved values
// through the accessor methods.
type PostgreSQLAuthorityResult struct {
	workspaceID         string
	workspaceRevision   int64
	workspaceConfigHash string
	workspaceSourceID   string
	sourceScopeID       string
	sourceScopeRevision int64
	scopeConfigHash     string
	accessMode          string
	projection          postgresqlquery.Projection
	limits              postgresqlquery.Limits
}

// postgreSQLExecutionAuthority is the private, in-process execution envelope.
// Credential material and the exact connection revision never cross the
// public authority result boundary.
type postgreSQLExecutionAuthority struct {
	result              PostgreSQLAuthorityResult
	connectionID        string
	connectionRevision  int64
	credentialReference string
}

func (r PostgreSQLAuthorityResult) WorkspaceID() string { return r.workspaceID }

func (r PostgreSQLAuthorityResult) WorkspaceRevision() int64 { return r.workspaceRevision }

func (r PostgreSQLAuthorityResult) WorkspaceConfigurationHash() string {
	return r.workspaceConfigHash
}

func (r PostgreSQLAuthorityResult) WorkspaceSourceID() string { return r.workspaceSourceID }

func (r PostgreSQLAuthorityResult) SourceScopeID() string { return r.sourceScopeID }

func (r PostgreSQLAuthorityResult) SourceScopeRevision() int64 { return r.sourceScopeRevision }

func (r PostgreSQLAuthorityResult) ScopeConfigHash() string { return r.scopeConfigHash }

func (r PostgreSQLAuthorityResult) AccessMode() string { return r.accessMode }

// Projection returns an independent copy of the resolved projection. A nil
// Columns slice is preserved as the true zero value so that an unresolved
// result stays strictly zero; a non-nil slice, and every column Roles slice
// within it, is newly allocated on every call.
func (r PostgreSQLAuthorityResult) Projection() postgresqlquery.Projection {
	projection := r.projection
	if r.projection.Columns == nil {
		return projection
	}
	projection.Columns = make([]postgresqlquery.Column, len(r.projection.Columns))
	for i, column := range r.projection.Columns {
		column.Roles = make([]postgresqlquery.Role, len(column.Roles))
		copy(column.Roles, r.projection.Columns[i].Roles)
		projection.Columns[i] = column
	}
	return projection
}

func (r PostgreSQLAuthorityResult) Limits() postgresqlquery.Limits { return r.limits }

// MarshalJSON renders the authority result as an opaque empty JSON object so
// that no private source authority value can leak through generic JSON logging.
func (PostgreSQLAuthorityResult) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

// ResolvePostgreSQLAuthority resolves the authority decision for one exact
// workspace source scope revision through the admission boundary. It validates
// the request and the caller's access context, then performs a single read that
// authenticates the caller, loads the current workspace snapshot, authorizes
// the workspace.ask operation, exact-compares the stored current configuration
// hash against the recomputed one, and resolves the exact current confirmed
// PostgreSQL projection and server-owned limits through the source query.
func (store *Store) ResolvePostgreSQLAuthority(ctx context.Context, access database.AccessContext, request PostgreSQLAuthorityRequest) (PostgreSQLAuthorityResult, error) {
	authority, err := store.resolvePostgreSQLExecutionAuthority(ctx, access, request)
	if err != nil {
		return PostgreSQLAuthorityResult{}, err
	}
	return authority.result, nil
}

// resolvePostgreSQLExecutionAuthority resolves the public authority decision
// and the exact private connector target in the same final admission SELECT.
func (store *Store) resolvePostgreSQLExecutionAuthority(ctx context.Context, access database.AccessContext, request PostgreSQLAuthorityRequest) (postgreSQLExecutionAuthority, error) {
	if store == nil || store.database == nil || ctx == nil || access.Validate() != nil {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeRequestInvalid}
	}
	if !validID(request.WorkspaceID) || !validID(request.WorkspaceSourceID) || !validID(request.SourceScopeID) {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeRequestInvalid}
	}
	if request.SourceScopeRevision <= 0 {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeRequestInvalid}
	}
	if !workspace.IsConfigurationHash(request.ScopeConfigHash) {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeRequestInvalid}
	}
	if request.AccessMode != authorityAccessModeManaged {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeRequestInvalid}
	}
	denied := false
	notFound := false
	persistence := false
	resolved := false
	result := postgreSQLExecutionAuthority{}
	readErr := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, storedHash, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, request.WorkspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		membership := currentMembership(snapshot, access.PrincipalID)
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceAsk,
			Subject:   subject,
			Workspace: policy.Workspace{
				OrganizationID: snapshot.OrganizationID,
				ID:             snapshot.ID,
				Status:         policy.WorkspaceStatus(snapshot.Status),
			},
			Membership: membership,
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		recomputedHash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil {
			persistence = true
			return nil
		}
		if recomputedHash != storedHash {
			persistence = true
			return nil
		}
		var (
			scannedWorkspaceSourceID   string
			scannedSourceScopeID       string
			scannedScopeRevision       int64
			scannedAccessMode          string
			scannedScopeConfigHash     string
			scannedConnectionID        string
			scannedConnectionRevision  int64
			scannedCredentialReference string
			scannedDatabaseIdentity    string
			scannedLineageID           string
			scannedProjectionRevision  int64
			scannedContractHash        string
			scannedSchemaName          string
			scannedRelationName        string
			scannedRelationKind        string
			scannedColumnsRaw          string
			scannedEmptyPolicy         string
			scannedMaxRows             int64
			scannedMaxColumns          int
			scannedMaxFieldBytes       int64
			scannedMaxRowBytes         int64
			scannedMaxTotalBytes       int64
			scannedTimeoutMS           int64
		)
		scanErr := transaction.QueryRow(transactionContext, `
			SELECT status.workspace_source_id, status.source_scope_id,
			       status.source_scope_revision, status.access_mode, status.scope_config_hash,
			       status.connection_id, execution_connection.revision,
			       execution_connection.credential_reference,
			       projection.database_identity, projection.lineage_id,
			       projection.projection_revision, projection.contract_hash,
			       projection.schema_name, projection.relation_name,
			       projection.relation_kind, projection.columns_json,
			       projection.empty_snapshot_policy,
			       projection.max_rows, projection.max_columns,
			       projection.max_field_bytes, projection.max_row_bytes,
			       projection.max_total_bytes, projection.statement_timeout_ms
			  FROM app.workspace_source_status_v3($1) AS status
			  JOIN public.organization AS admission_organization
			    ON admission_organization.id=$2
			   AND admission_organization.status='ACTIVE'
			  JOIN public.principal AS admission_principal
			    ON admission_principal.organization_id=$2
			   AND admission_principal.id=$10
			   AND admission_principal.status='ACTIVE'
			  JOIN public.workspace AS current_workspace
			    ON current_workspace.organization_id=$2 AND current_workspace.id=$1
			   AND current_workspace.current_revision=$9
			  JOIN public.workspace_revision AS current_revision
			    ON current_revision.organization_id=current_workspace.organization_id
			   AND current_revision.workspace_id=current_workspace.id
			   AND current_revision.revision=current_workspace.current_revision
			   AND current_revision.configuration_hash=$8
			  JOIN public.workspace_revision_source AS binding
			    ON binding.organization_id=current_workspace.organization_id
			   AND binding.workspace_id=current_workspace.id
			   AND binding.workspace_revision=current_workspace.current_revision
			   AND binding.workspace_source_id=status.workspace_source_id
			   AND binding.source_scope_id=status.source_scope_id
			   AND binding.source_scope_revision=status.source_scope_revision
			   AND binding.scope_config_hash=status.scope_config_hash
			   AND binding.access_mode=status.access_mode
			   AND binding.workspace_configuration_hash=current_revision.configuration_hash
			   AND binding.enabled
			  JOIN public.source_scope AS scope
			    ON scope.organization_id=$2 AND scope.id=status.source_scope_id
			   AND scope.active_revision=status.source_scope_revision
			  JOIN public.source_scope_revision AS scope_revision
			    ON scope_revision.organization_id=$2
			   AND scope_revision.source_scope_id=status.source_scope_id
			   AND scope_revision.revision=status.source_scope_revision
			   AND scope_revision.connection_id=status.connection_id
			   AND scope_revision.scope_config_hash=status.scope_config_hash
			  JOIN public.source_connection_revision AS execution_connection
			    ON execution_connection.organization_id=$2
			   AND execution_connection.connection_id=scope_revision.connection_id
			   AND execution_connection.revision=scope_revision.connection_revision
			   AND execution_connection.connector_type='POSTGRESQL_QUERY'
			  JOIN public.source_scope_activation AS activation
			    ON activation.organization_id=$2
			   AND activation.source_scope_id=status.source_scope_id
			   AND activation.source_scope_revision=status.source_scope_revision
			   AND activation.revision=1
			  JOIN public.postgresql_query_projection AS projection
			    ON projection.organization_id=$2
			   AND projection.source_scope_id=status.source_scope_id
			   AND projection.source_scope_revision=status.source_scope_revision
			   AND projection.connection_id=status.connection_id
			 WHERE status.workspace_source_id=$3
			   AND status.source_scope_id=$4
			   AND status.source_scope_revision=$5
			   AND status.scope_config_hash=$6
			   AND status.access_mode=$7
			   AND status.enabled
			   AND status.activation_status='READY'
			   AND status.trust_verified
			   AND scope_revision.source_type='POSTGRESQL_QUERY'
			   AND scope_revision.scope_contract_version='postgresql-query-v1'
			   AND activation.status='READY'
			   AND projection.status='ACTIVE'
			   AND projection.contract_version='postgresql-query-value-v1'
			   AND app.workspace_source_confirmation_live($1,$3,$4,$5,$6,$7)`,
			request.WorkspaceID, access.OrganizationID, request.WorkspaceSourceID,
			request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash,
			request.AccessMode, storedHash, snapshot.Revision, access.PrincipalID,
		).Scan(
			&scannedWorkspaceSourceID, &scannedSourceScopeID,
			&scannedScopeRevision, &scannedAccessMode, &scannedScopeConfigHash,
			&scannedConnectionID, &scannedConnectionRevision,
			&scannedCredentialReference,
			&scannedDatabaseIdentity, &scannedLineageID,
			&scannedProjectionRevision, &scannedContractHash,
			&scannedSchemaName, &scannedRelationName,
			&scannedRelationKind, &scannedColumnsRaw,
			&scannedEmptyPolicy,
			&scannedMaxRows, &scannedMaxColumns,
			&scannedMaxFieldBytes, &scannedMaxRowBytes,
			&scannedMaxTotalBytes, &scannedTimeoutMS,
		)
		if database.IsNotFound(scanErr) {
			notFound = true
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		if scannedWorkspaceSourceID != request.WorkspaceSourceID ||
			scannedSourceScopeID != request.SourceScopeID ||
			scannedScopeRevision != request.SourceScopeRevision ||
			scannedScopeConfigHash != request.ScopeConfigHash ||
			scannedAccessMode != request.AccessMode {
			notFound = true
			return nil
		}
		if scannedConnectionRevision <= 0 || !validAuthorityCredentialReference(scannedCredentialReference) {
			persistence = true
			return nil
		}
		var decoded []authorityColumn
		if decodeErr := jsonv2.Unmarshal(jsontext.Value(scannedColumnsRaw), &decoded,
			jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); decodeErr != nil {
			persistence = true
			return nil
		}
		columns := make([]postgresqlquery.Column, len(decoded))
		for i, entry := range decoded {
			roles := make([]postgresqlquery.Role, len(entry.Roles))
			copy(roles, entry.Roles)
			columns[i] = postgresqlquery.Column{
				Ordinal:         entry.Ordinal,
				Name:            entry.Name,
				TypeFingerprint: entry.TypeFingerprint,
				LogicalType:     entry.LogicalType,
				Roles:           roles,
				Nullable:        entry.Nullable,
				Precision:       entry.Precision,
				Scale:           entry.Scale,
				MaxBytes:        entry.MaxBytes,
			}
		}
		projection := postgresqlquery.Projection{
			ConnectionID:        scannedConnectionID,
			DatabaseIdentity:    scannedDatabaseIdentity,
			LineageID:           scannedLineageID,
			Revision:            scannedProjectionRevision,
			ContractHash:        scannedContractHash,
			SchemaName:          scannedSchemaName,
			RelationName:        scannedRelationName,
			RelationKind:        scannedRelationKind,
			Columns:             columns,
			EmptySnapshotPolicy: scannedEmptyPolicy,
		}
		if projection.Validate() != nil {
			persistence = true
			return nil
		}
		limits := postgresqlquery.Limits{
			MaxRows:            int(scannedMaxRows),
			MaxColumns:         scannedMaxColumns,
			MaxFieldBytes:      int(scannedMaxFieldBytes),
			MaxRowBytes:        int(scannedMaxRowBytes),
			MaxTotalBytes:      int(scannedMaxTotalBytes),
			StatementTimeout:   time.Duration(scannedTimeoutMS) * time.Millisecond,
			TransactionTimeout: time.Duration(scannedTimeoutMS+120000) * time.Millisecond,
		}
		if limits.Validate() != nil {
			persistence = true
			return nil
		}
		result = postgreSQLExecutionAuthority{
			result: PostgreSQLAuthorityResult{
				workspaceID:         request.WorkspaceID,
				workspaceRevision:   snapshot.Revision,
				workspaceConfigHash: storedHash,
				workspaceSourceID:   scannedWorkspaceSourceID,
				sourceScopeID:       scannedSourceScopeID,
				sourceScopeRevision: scannedScopeRevision,
				scopeConfigHash:     scannedScopeConfigHash,
				accessMode:          scannedAccessMode,
				projection:          projection,
				limits:              limits,
			},
			connectionID:        scannedConnectionID,
			connectionRevision:  scannedConnectionRevision,
			credentialReference: scannedCredentialReference,
		}
		resolved = true
		return nil
	})
	if readErr != nil {
		return postgreSQLExecutionAuthority{}, &Error{code: CodePersistence}
	}
	if persistence {
		return postgreSQLExecutionAuthority{}, &Error{code: CodePersistence}
	}
	if denied || notFound || !resolved {
		return postgreSQLExecutionAuthority{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

func validAuthorityCredentialReference(value string) bool {
	const (
		prefix   = "cred_"
		alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	)
	if len(value) != len(prefix)+26 || !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := value[len(prefix):]
	if encoded[0] < '0' || encoded[0] > '7' {
		return false
	}
	for _, symbol := range encoded[1:] {
		if !strings.ContainsRune(alphabet, symbol) {
			return false
		}
	}
	return true
}
