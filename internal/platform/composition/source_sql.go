package composition

// source_sql.go is ADR-0097's production implementation of the optional
// SourceSQLProvider capability behind the knowvault_source_sql knowledge tool
// (S3 card 2). It is the only server-side wiring that turns one workspace
// source into one agent-authored governed read, and it adds no second way to
// send SQL to a customer database:
//
//   - the relation scope and the optional query credential reference come from
//     the workspace repository's sourceMetadataRead boundary, so the
//     authorization, the content-free code-not-found and the SOURCE_SQL audit
//     are the existing ones;
//   - the DSN is resolved from the mounted secret provider only at execution
//     time and is never logged, echoed or persisted;
//   - the statement executes through governedquery.ExecuteScoped, the one
//     governed-execution entry point (static pre-check, read-only transaction,
//     statement timeout, EXPLAIN cost cap, row/byte cap, plan scope walk); and
//   - the content-free attempt (source id, sql hash, cost, row count, result
//     digest, outcome) is appended before any row is disclosed, and a failed
//     append returns no rows.

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// newSourceServiceWithSQL composes the production source facade with the
// optional agent-authored SQL capability. The mounted source trust bundle is
// the capability gate: without it the base facade is returned unchanged, so
// knowvault_source_sql keeps failing closed as SERVICE_UNAVAILABLE rather than
// advertising a capability the deployment cannot serve.
func newSourceServiceWithSQL(base sourceServiceFacade, workspaces *workspacerepository.Store,
	auditor *audit.Store, resolver *secretmount.Provider) workspaceapi.SourceService {
	if workspaces == nil || auditor == nil || resolver == nil {
		return base
	}
	bundle, err := trustbundle.LoadSourceMounted()
	if err != nil {
		return base
	}
	roots, rootsErr := bundle.DatabaseRoots()
	if rootsErr != nil {
		return base
	}
	return sourceServiceFacadeWithSQL{sourceServiceFacade: base, sourceSQL: sourceSQLExecutor{
		workspaces: workspaces, auditor: auditor, resolver: resolver, roots: roots,
		limits: sourceSQLServerLimits(), now: time.Now,
	}}
}

// sourceQueryCredentialResolver is the deployment boundary for a source's
// separate query credential. It resolves one opaque reference to a DSN from
// protected mounted material at execution time and never from a request.
type sourceQueryCredentialResolver interface {
	ResolveReference(context.Context, string) (string, error)
}

// sourceQueryTrustRoots is the mounted CA bundle for source connections. It is
// the interface governedquery.Config.TrustRoots already requires, accepted as
// the narrow capability so a caller cannot share or mutate a pool.
type sourceQueryTrustRoots interface {
	NewCertPool() (*x509.CertPool, error)
}

// sourceSQLAuditor is the append-only audit boundary. The production
// *audit.Store satisfies it; a nil auditor means "no journal wired", which the
// executor treats as a failed write rather than silently disclosing unaudited
// rows, because ADR-0097 §4 makes the audit record a condition of disclosure.
type sourceSQLAuditor interface {
	Append(context.Context, database.AccessContext, audit.EventInput) (audit.Event, error)
}

// sourceSQLServerLimits are the server-owned bounds of every agent-authored
// read. They are never request fields, so no caller can widen them.
func sourceSQLServerLimits() governedquery.Limits {
	return governedquery.Limits{
		StatementTimeout: 30 * time.Second,
		MaxRows:          1000,
		MaxResultBytes:   4 << 20,
		MaxCostEstimate:  1_000_000,
	}
}

type sourceSQLExecutor struct {
	workspaces *workspacerepository.Store
	auditor    sourceSQLAuditor
	resolver   sourceQueryCredentialResolver
	roots      sourceQueryTrustRoots
	limits     governedquery.Limits
	now        func() time.Time
}

var _ workspaceapi.SourceSQLProvider = sourceSQLExecutor{}

// SourceSQL executes one agent-authored statement against one enabled source
// of the caller's workspace. Every refusal is the closed SourceSQLRefusal the
// agent can react to; an authorization failure keeps the repository's
// content-free CodeNotFound so the transports render their single not-found.
func (executor sourceSQLExecutor) SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {
	if executor.workspaces == nil || executor.resolver == nil || executor.roots == nil || executor.auditor == nil ||
		ctx == nil || ctx.Err() != nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeDatabaseRejected)}
	}
	target, err := executor.workspaces.SourceQuery(ctx, access, workspaceID, request.SourceID)
	if err != nil {
		return workspaceapi.SourceSQLResult{}, err
	}
	if target.QueryCredentialReference == "" {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeSourceSQLNotConfigured)}
	}
	dsn, err := executor.resolver.ResolveReference(ctx, target.QueryCredentialReference)
	if err != nil || dsn == "" {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeDatabaseRejected)}
	}
	// The DSN is copied into the validated config and then dropped; it is never
	// logged, echoed to the caller or persisted.
	roots, err := executor.roots.NewCertPool()
	if err != nil || roots == nil || len(roots.Subjects()) == 0 {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeDatabaseRejected)}
	}
	limits := executor.limits
	config := governedquery.Config{
		ConnectionID: target.SourceID, DatabaseIdentity: target.DatabaseIdentity, WorkspaceID: workspaceID,
		DSN: dsn, TrustRoots: roots, Limits: limits,
	}
	result, attempt, execErr := governedquery.ExecuteScoped(ctx, config, governedquery.ScopedParams{
		SQLText: request.SQL, Purpose: request.Purpose, Schema: governedquery.ScopedSchema{Relations: sourceSQLRelations(target)},
	})
	code := sourceSQLRefusalCode(execErr)
	if auditErr := executor.auditAttempt(ctx, access, workspaceID, target, attempt, code); auditErr != nil {
		// ADR-0097 §4: no row, no digest and no attempt id is disclosed unless
		// the content-free attempt durably landed. This is a plain error (not a
		// closed refusal) so every transport answers its content-free
		// service-unavailable rather than pretending the statement was refused.
		return workspaceapi.SourceSQLResult{}, errors.New("SOURCE_SQL_AUDIT_UNAVAILABLE")
	}
	if execErr != nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: code}
	}
	attemptID, idErr := ids.New("gqat")
	if idErr != nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeDatabaseRejected)}
	}
	return workspaceapi.SourceSQLResult{
		Format: "postgres-text-table-v1", SourceID: target.SourceID,
		ExposedSchemaRevision: target.ScopeRevision,
		Columns:               result.Columns, Rows: result.Rows, RowCount: result.RowCount,
		AttemptID: attemptID, SQLHash: attempt.SQLHash, ResultDigest: attempt.ResultDigest,
		DatabaseIdentity:   target.DatabaseIdentity,
		ExecutionStartedAt: result.ExecutionStartedAt, ExecutionCompletedAt: result.ExecutionCompletedAt,
	}, nil
}

// auditAttempt appends exactly one content-free source.governed_query_attempted
// event per execution. A refusal that never reached execution still carries its
// sql hash and outcome; the connection id is always the source id and the
// revision is the source scope revision, so an operator can join the attempt to
// the exact scope the agent was allowed to read.
func (executor sourceSQLExecutor) auditAttempt(ctx context.Context, access database.AccessContext, workspaceID string, target workspacerepository.SourceQuerySource, attempt governedquery.Attempt, refusalCode string) error {
	if executor.auditor == nil {
		return errors.New("source sql audit unavailable")
	}
	eventID, err := ids.New("gqae")
	if err != nil {
		return err
	}
	workspace := workspaceID
	principal := access.PrincipalID
	sqlHash := attempt.SQLHash
	if sqlHash == "" {
		// A refusal that happened before the hash was computed (an invalid
		// scope) still needs a content-free resource id; hash the closed code
		// rather than the SQL text.
		sqlHash = "sha256:" + zeroSHA256
	}
	outcome := string(attempt.Outcome)
	if outcome == "" {
		outcome = string(governedquery.OutcomeRejectedStatic)
	}
	revision := target.ScopeRevision
	if revision < 1 {
		revision = 1
	}
	connection := target.SourceID
	outcomeValue := outcome
	metadata := audit.Metadata{
		GovernedQueryConnectionID: &connection, GovernedQueryExposedSchemaRevision: &revision,
		GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcomeValue,
	}
	auditOutcome := audit.OutcomeFailed
	var errorCode *string
	if refusalCode == "" {
		auditOutcome = audit.OutcomeSuccess
		cost := int64(attempt.CostEstimate)
		rows := int64(attempt.RowCount)
		digest := attempt.ResultDigest
		metadata.GovernedQueryCostEstimate = &cost
		metadata.GovernedQueryRowCount = &rows
		metadata.GovernedQueryResultDigest = &digest
	} else {
		code := refusalCode
		errorCode = &code
	}
	_, err = executor.auditor.Append(ctx, access, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal, Action: audit.ActionGovernedQueryAttempted,
		ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: access.RequestID, Outcome: auditOutcome, ErrorCode: errorCode,
		Metadata: metadata, OccurredAt: executor.now().UTC(),
	})
	return err
}

// zeroSHA256 is the canonical all-zero sha256 body used only as the
// content-free resource id of a refusal that never computed a SQL hash.
const zeroSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

// sourceSQLRelations converts the repository's scope into the governedquery
// scope type.
func sourceSQLRelations(target workspacerepository.SourceQuerySource) []governedquery.ScopedRelation {
	relations := make([]governedquery.ScopedRelation, 0, len(target.Relations))
	for _, relation := range target.Relations {
		relations = append(relations, governedquery.ScopedRelation{
			Schema: relation.Schema, Table: relation.Table, Columns: append([]string(nil), relation.Columns...),
		})
	}
	return relations
}

// sourceSQLRefusalCode maps the governed executor's typed error onto the closed
// ADR-0097 vocabulary. A success is the empty string.
func sourceSQLRefusalCode(err error) string {
	if err == nil {
		return ""
	}
	code := governedquery.CodeOf(err)
	switch code {
	case governedquery.CodeSQLRejectedStatic, governedquery.CodeRelationNotInSource, governedquery.CodeCostLimit,
		governedquery.CodeRowLimit, governedquery.CodeTimeout, governedquery.CodeDatabaseRejected,
		governedquery.CodeSourceSQLNotConfigured:
		return string(code)
	default:
		return string(governedquery.CodeDatabaseRejected)
	}
}

// SetSourceQueryCredential is S3 card 2b's owner-only control over one source
// connection's SQL query credential (ADR-0097). It sets the opaque mounted
// reference (or clears it when reference is empty) only after all three card
// checks pass: the reference resolves, a read-only connection reaches the
// source's own database identity, and the role cannot read a column excluded
// from the registered tables. Every failure is a closed
// workspaceapi.SourceQueryCredentialRefusal and nothing is written.
func (executor sourceSQLExecutor) SetSourceQueryCredential(ctx context.Context, access database.AccessContext, workspaceID, connectionID, credentialReference string) error {
	if executor.workspaces == nil || executor.resolver == nil || executor.roots == nil || ctx == nil || ctx.Err() != nil {
		return &workspaceapi.SourceQueryCredentialRefusal{Code: string(governedquery.CodeQueryCredentialRejected)}
	}
	// The owner-gated target read is deliberately first: a non-owner, an
	// unknown workspace and a foreign connection all resolve to the
	// repository's content-free CodeNotFound before any mounted credential is
	// touched or any external connection is opened.
	target, err := executor.workspaces.SourceQueryCredentialTarget(ctx, access, workspaceID, connectionID)
	if err != nil {
		return err
	}
	if credentialReference != "" {
		dsn, resolveErr := executor.resolver.ResolveReference(ctx, credentialReference)
		if resolveErr != nil || dsn == "" {
			return &workspaceapi.SourceQueryCredentialRefusal{Code: workspaceapi.SourceQueryCredentialUnresolved}
		}
		roots, rootsErr := executor.roots.NewCertPool()
		if rootsErr != nil || roots == nil || len(roots.Subjects()) == 0 {
			return &workspaceapi.SourceQueryCredentialRefusal{Code: string(governedquery.CodeQueryCredentialRejected)}
		}
		config := governedquery.Config{
			ConnectionID: target.SourceID, DatabaseIdentity: target.DatabaseIdentity, WorkspaceID: workspaceID,
			DSN: dsn, TrustRoots: roots, Limits: executor.limits,
		}
		if verifyErr := governedquery.VerifyQueryCredential(ctx, config, governedquery.QueryCredentialParams{
			Relations: sourceSQLRelations(target),
		}); verifyErr != nil {
			return &workspaceapi.SourceQueryCredentialRefusal{Code: sourceQueryCredentialRefusalCode(verifyErr)}
		}
	}
	// The repository re-checks the OWNER inside its write and appends the one
	// content-free audit event in the same transaction.
	return executor.workspaces.SetSourceQueryCredential(ctx, access, workspaceID, connectionID, credentialReference)
}

// sourceQueryCredentialRefusalCode keeps only the card's closed check
// vocabulary; every other governed error folds into the connection-rejected
// code so a driver message can never reach the operator.
func sourceQueryCredentialRefusalCode(err error) string {
	switch governedquery.CodeOf(err) {
	case governedquery.CodeQueryCredentialDatabaseMismatch:
		return string(governedquery.CodeQueryCredentialDatabaseMismatch)
	case governedquery.CodeQueryCredentialColumnPrivilege:
		return string(governedquery.CodeQueryCredentialColumnPrivilege)
	default:
		return string(governedquery.CodeQueryCredentialRejected)
	}
}

// ReauthorizeSourceSQLAttempt is the read-time check for one stored
// agent-authored SQL receipt: it re-reads the source through the same
// owner/member source-metadata boundary the tool itself authorizes with, so a
// caller who has lost access to the source (or a scope revision that has moved)
// can no longer disclose the receipt. It opens no external connection and
// carries no SQL, row or credential.
func (executor sourceSQLExecutor) ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error {
	if executor.workspaces == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_UNAVAILABLE")
	}
	target, err := executor.workspaces.SourceQuery(ctx, access, workspaceID, disclosure.ConnectionID)
	if err != nil {
		return err
	}
	if target.SourceID != disclosure.ConnectionID || target.ScopeRevision != disclosure.ExposedSchemaRevision ||
		target.DatabaseIdentity == "" {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_MISMATCH")
	}
	return nil
}
