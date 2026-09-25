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
		limits: sourceSQLServerLimits(), now: time.Now, limiter: newSourceSQLLimiter(),
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

// sourceSQLWorkspace is the narrow workspace-repository capability the SQL
// executor needs. The production *workspacerepository.Store satisfies it. It is
// an interface on purpose: the executor's audit, source-state, load-limit and
// refusal behavior can then be proven with a closed fake, without a database,
// while production still passes the real store.
type sourceSQLWorkspace interface {
	SourceQuery(context.Context, database.AccessContext, string, string) (workspacerepository.SourceQuerySource, error)
	RecordSourceQueryVerification(context.Context, database.AccessContext, string, string, int64, int64, string, string) error
	SourceQueryCredentialTarget(context.Context, database.AccessContext, string, string) (workspacerepository.SourceQuerySource, error)
	SetSourceQueryCredential(context.Context, database.AccessContext, string, string, string) error
}

type sourceSQLExecutor struct {
	workspaces sourceSQLWorkspace
	auditor    sourceSQLAuditor
	resolver   sourceQueryCredentialResolver
	roots      sourceQueryTrustRoots
	limits     governedquery.Limits
	now        func() time.Time
	// limiter is S3 card 2c's shared load limit (2 concurrent per source, 20
	// per minute per principal). It is server-owned and shared by MCP, REST and
	// chat because all three dispatch through this one executor.
	limiter *sourceSQLLimiter
}

var _ workspaceapi.SourceSQLProvider = sourceSQLExecutor{}

// sourceActivationReady is the only source activation state on which SQL may
// run (card S3.2c §3). DRAFT, SYNCING, FAILED and REVOKED are all not-found.
const sourceActivationReady = "READY"

// SourceSQL executes one agent-authored statement against one enabled source
// of the caller's workspace. Every refusal is the closed SourceSQLRefusal the
// agent can react to; an authorization failure keeps the repository's
// content-free CodeNotFound so the transports render their single not-found.
//
// Card S3.2c adds four guarantees to the card 2 path:
//
//   - SQL runs only on a source whose activation is READY and whose trust is
//     verified; otherwise the content-free not-found, never a refusal oracle;
//   - server-owned load limits are enforced before any external connection,
//     shared by MCP, REST and chat because all three dispatch here;
//   - the least-privilege role proof is reused only for the exact
//     (connection revision, credential revision, projection) pair and is
//     stored after a fresh proof; and
//   - every attempt that passed authorization appends exactly one audit event,
//     including the not-configured, credential-resolution and load-limit
//     refusals, the returned attempt_id is that event's id, and the audit
//     write is detached from client cancellation.
func (executor sourceSQLExecutor) SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {
	if executor.workspaces == nil || executor.resolver == nil || executor.roots == nil || executor.auditor == nil ||
		ctx == nil || ctx.Err() != nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: string(governedquery.CodeDatabaseRejected)}
	}
	target, err := executor.workspaces.SourceQuery(ctx, access, workspaceID, request.SourceID)
	if err != nil {
		// Authorization itself failed (unknown, foreign, disabled or
		// non-member): the attempt never passed authorization, so it is not
		// audited and the repository's content-free CodeNotFound travels
		// unchanged.
		return workspaceapi.SourceSQLResult{}, err
	}
	// Card S3.2c §3: a pending-activation or untrusted source is the same
	// content-free not-found as an unknown source.
	if target.ActivationStatus != sourceActivationReady || !target.TrustVerified {
		return workspaceapi.SourceSQLResult{}, workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	}

	// Card S3.2c §2: the server-owned load limits refuse before any credential
	// is resolved and before any external connection is opened.
	release, limitCode := executor.limiter.acquire(target.SourceID, access.PrincipalID)
	if limitCode != "" {
		return executor.refuseAudited(ctx, access, workspaceID, target, request, governedquery.Attempt{}, limitCode)
	}
	defer release()

	attempt := governedquery.Attempt{}
	code := ""
	var result governedquery.QueryResult
	if target.QueryCredentialReference == "" {
		code = string(governedquery.CodeSourceSQLNotConfigured)
	} else if dsn, resolveErr := executor.resolver.ResolveReference(ctx, target.QueryCredentialReference); resolveErr != nil || dsn == "" {
		// The reference is the one stored for this exact organization and
		// connection (the repository read is org- and workspace-scoped), so a
		// foreign organization's reference can never be the one resolved here.
		code = string(governedquery.CodeDatabaseRejected)
	} else if roots, rootsErr := executor.roots.NewCertPool(); rootsErr != nil || roots == nil || len(roots.Subjects()) == 0 {
		code = string(governedquery.CodeDatabaseRejected)
	} else {
		config := governedquery.Config{
			ConnectionID: target.SourceID, DatabaseIdentity: target.DatabaseIdentity, WorkspaceID: workspaceID,
			DSN: dsn, TrustRoots: roots, Limits: executor.limits,
			// RoleProven is server-owned: it is set only from the stored proof
			// row that still matches this connection revision, credential
			// revision and projection. The safe zero value re-proves the role.
			RoleProven: target.RoleProven(),
		}
		var execErr error
		result, attempt, execErr = governedquery.ExecuteScoped(ctx, config, governedquery.ScopedParams{
			SQLText: request.SQL, Purpose: request.Purpose, Schema: governedquery.ScopedSchema{Relations: sourceSQLRelations(target)},
		})
		code = sourceSQLRefusalCode(execErr)
		if execErr == nil && attempt.RoleVerificationDigest != "" {
			// Remember the proof for exactly this pair. A failed cache write is
			// not a data disclosure: the next call simply re-proves the role.
			_ = executor.workspaces.RecordSourceQueryVerification(ctx, access, workspaceID, target.SourceID,
				target.ConnectionRevision, target.QueryCredentialRevision, target.ScopeHash(), attempt.RoleVerificationDigest)
		}
	}

	eventID, auditErr := executor.auditAttempt(ctx, access, workspaceID, target, request.Purpose, attempt, code)
	if auditErr != nil {
		// ADR-0097 §4: no row, no digest and no attempt id is disclosed unless
		// the content-free attempt durably landed. This is a plain error (not a
		// closed refusal) so every transport answers its content-free
		// service-unavailable rather than pretending the statement was refused.
		return workspaceapi.SourceSQLResult{}, errors.New("SOURCE_SQL_AUDIT_UNAVAILABLE")
	}
	if code != "" {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: code}
	}
	return workspaceapi.SourceSQLResult{
		Format: "postgres-text-table-v1", SourceID: target.SourceID,
		ExposedSchemaRevision: target.ScopeRevision,
		Columns:               result.Columns, Rows: result.Rows, RowCount: result.RowCount,
		// The attempt id is exactly the audited event's id (card S3.2c §4).
		AttemptID: eventID, SQLHash: attempt.SQLHash, ResultDigest: attempt.ResultDigest,
		DatabaseIdentity:   target.DatabaseIdentity,
		ExecutionStartedAt: result.ExecutionStartedAt, ExecutionCompletedAt: result.ExecutionCompletedAt,
	}, nil
}

// refuseAudited renders one closed load-limit refusal after appending its
// content-free audit event, so an over-limit call is still provable. An
// unauditable refusal becomes the plain service-unavailable error.
func (executor sourceSQLExecutor) refuseAudited(ctx context.Context, access database.AccessContext, workspaceID string,
	target workspacerepository.SourceQuerySource, request workspaceapi.SourceSQLRequest, attempt governedquery.Attempt, code string) (workspaceapi.SourceSQLResult, error) {
	if _, auditErr := executor.auditAttempt(ctx, access, workspaceID, target, request.Purpose, attempt, code); auditErr != nil {
		return workspaceapi.SourceSQLResult{}, errors.New("SOURCE_SQL_AUDIT_UNAVAILABLE")
	}
	return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: code}
}

// auditAttempt appends exactly one content-free source.governed_query_attempted
// event per authorized attempt and returns the event id, which is the attempt
// id the caller is given (card S3.2c §4). A refusal that never reached
// execution still carries its closed code; the connection id is always the
// source id and the revision is the source scope revision, so an operator can
// join the attempt to the exact scope the agent was allowed to read.
//
// The append runs on a context detached from the client request, so a client
// that cancels after execution can no longer suppress the audit record. The
// bounded purpose note is recorded as its own closed metadata field and never
// as SQL text.
func (executor sourceSQLExecutor) auditAttempt(ctx context.Context, access database.AccessContext, workspaceID string, target workspacerepository.SourceQuerySource, purpose string, attempt governedquery.Attempt, refusalCode string) (string, error) {
	if executor.auditor == nil {
		return "", errors.New("source sql audit unavailable")
	}
	eventID, err := ids.New("gqat")
	if err != nil {
		return "", err
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
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
	if purpose != "" {
		metadata.GovernedQueryPurpose = &purpose
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
	_, err = executor.auditor.Append(auditContext, access, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal, Action: audit.ActionGovernedQueryAttempted,
		ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: access.RequestID, Outcome: auditOutcome, ErrorCode: errorCode,
		Metadata: metadata, OccurredAt: executor.now().UTC(),
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
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
		governedquery.CodeSourceSQLNotConfigured, governedquery.CodeSourceSQLRateLimited,
		governedquery.CodeSourceSQLConcurrencyLimited:
		return string(code)
	default:
		return string(governedquery.CodeDatabaseRejected)
	}
}

// SetSourceQueryCredential is the owner-only control over one source
// connection's SQL query credential (ADR-0097). It sets the opaque mounted
// reference (or clears it when reference is empty) only after the candidate
// passes every check: the reference is not the ingestion credential and
// resolves, a read-only connection reaches the source's own database identity,
// and the role passes the full least-privilege proof (card S3.2c) — the role
// rules, the excluded columns and the projectable ones. Every failure is a
// closed workspaceapi.SourceQueryCredentialRefusal naming the failed rule, and
// nothing is written.
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
	if credentialReference != "" && credentialReference == target.IngestionCredentialReference {
		// The database trigger of migration 000118 refuses this too; the
		// pre-check only names the rule before an external connection is opened.
		return &workspaceapi.SourceQueryCredentialRefusal{Code: workspaceapi.SourceQueryCredentialIngestionReference}
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

// sourceQueryCredentialRefusalCode keeps the card's closed check vocabulary;
// every other governed error folds into the connection-rejected code so a
// driver message can never reach the operator. Card 2c adds one code per
// least-privilege rule, so the OWNER is told exactly which rule failed.
func sourceQueryCredentialRefusalCode(err error) string {
	switch code := governedquery.CodeOf(err); code {
	case governedquery.CodeQueryCredentialDatabaseMismatch,
		governedquery.CodeQueryCredentialColumnPrivilege,
		governedquery.CodeQueryRoleMissingSelect,
		governedquery.CodeQueryRoleExtraRelation,
		governedquery.CodeQueryRoleWritePrivilege,
		governedquery.CodeQueryRoleElevatedAttribute,
		governedquery.CodeQueryRoleMembership,
		governedquery.CodeQueryRoleSecurityDefiner,
		governedquery.CodeQueryRoleRemoteExecution:
		return string(code)
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
