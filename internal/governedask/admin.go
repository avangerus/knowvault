package governedask

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"log/slog"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// authorize applies the same current-workspace-membership policy check every
// other workspace-scoped mutation/read uses (mirrors question.Service.start).
func (service *Service) authorize(ctx context.Context, access database.AccessContext, workspaceID string, operation policy.Operation) error {
	var (
		organizationStatus, workspaceStatus, principalStatus, role string
		principalRevision                                          int64
	)
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT organization.status, workspace.status, principal.status, principal.session_revision,
			       COALESCE(member.role, '')
			  FROM public.organization
			  JOIN public.workspace ON workspace.organization_id = organization.id AND workspace.id = $2
			  JOIN public.principal ON principal.organization_id = organization.id AND principal.id = $3
			  LEFT JOIN public.workspace_member member
			    ON member.organization_id = workspace.organization_id AND member.workspace_id = workspace.id
			   AND member.principal_id = principal.id AND member.removed_at IS NULL
			 WHERE organization.id = $1
		`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(
			&organizationStatus, &workspaceStatus, &principalStatus, &principalRevision, &role)
	})
	if err != nil {
		if database.IsNotFound(err) {
			return &Error{code: CodeDenied}
		}
		return &Error{code: CodePersistence, cause: err}
	}
	decision := policy.EvaluateWorkspace(policy.Request{
		Operation: operation,
		Subject: policy.Subject{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
			Status: policy.PrincipalStatus(principalStatus), SessionRevision: principalRevision},
		Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: workspaceID, Status: policy.WorkspaceStatus(workspaceStatus)},
		Membership: policy.Membership{Present: role != "", Role: policy.WorkspaceRole(role)},
	})
	if organizationStatus != "ACTIVE" || !decision.Allowed {
		return &Error{code: CodeDenied}
	}
	return nil
}

// ensureWorkspaceBindingTx creates the connection row if this is the very
// first workspace ever to touch this connection, then opts workspaceID into
// public.governed_query_workspace_binding if it has not already opted in.
// It never changes an existing binding's live_queries_enabled: opting a
// workspace into visibility of a connection/schema it did not previously see
// must not silently turn live queries on for it (AGG-2 keeps that a separate,
// explicit SetLiveQueries call, default off).
func (service *Service) ensureWorkspaceBindingTx(txCtx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string) error {
	if _, err := tx.Exec(txCtx, `
		INSERT INTO public.governed_query_connection
		    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (organization_id, id) DO NOTHING
	`, access.OrganizationID, service.config.ConnectionID, workspaceID, service.config.DatabaseIdentity, access.PrincipalID); err != nil {
		return err
	}
	_, err := tx.Exec(txCtx, `
		INSERT INTO public.governed_query_workspace_binding
		    (organization_id, connection_id, workspace_id, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (organization_id, connection_id, workspace_id) DO NOTHING
	`, access.OrganizationID, service.config.ConnectionID, workspaceID, access.PrincipalID)
	return err
}

// ensureWorkspaceBinding is ensureWorkspaceBindingTx wrapped in its own
// write transaction, for callers (the schema-replay path) that are not
// already inside one.
func (service *Service) ensureWorkspaceBinding(ctx context.Context, access database.AccessContext, workspaceID string) error {
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return service.ensureWorkspaceBindingTx(txCtx, tx, access, workspaceID)
	})
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// liveQueriesEnabled is the per-workspace opt-in (AGG-2): a connection may be
// bound to any number of workspaces, each with its own independent toggle in
// public.governed_query_workspace_binding, so enabling live queries in one
// workspace never enables them in another that shares the same source
// connection.
func (service *Service) liveQueriesEnabled(ctx context.Context, access database.AccessContext, workspaceID string) (bool, error) {
	var enabled bool
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT live_queries_enabled FROM public.governed_query_workspace_binding
			 WHERE organization_id = $1 AND connection_id = $2 AND workspace_id = $3
		`, access.OrganizationID, service.config.ConnectionID, workspaceID).Scan(&enabled)
	})
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, &Error{code: CodePersistence, cause: err}
	}
	return enabled, nil
}

// loadExposedSchema reads the connection's own exposed schema. The exposed
// schema is a property of the connection (the source), not of one workspace
// (AGG-2): any workspace that has opted this connection into its own
// governed_query_workspace_binding row may see it -- membership/role in that
// workspace is checked separately by authorize.
func (service *Service) loadExposedSchema(ctx context.Context, access database.AccessContext, workspaceID string) (*governedquery.ExposedSchema, int64, error) {
	var (
		revision    int64
		objectsJSON []byte
	)
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT s.revision, s.objects_json
			  FROM public.governed_query_exposed_schema s
			  JOIN public.governed_query_workspace_binding b
			    ON b.organization_id = s.organization_id AND b.connection_id = s.connection_id
			 WHERE s.organization_id = $1 AND s.connection_id = $2 AND b.workspace_id = $3
			 ORDER BY s.revision DESC LIMIT 1
		`, access.OrganizationID, service.config.ConnectionID, workspaceID).Scan(&revision, &objectsJSON)
	})
	if database.IsNotFound(err) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, &Error{code: CodePersistence, cause: err}
	}
	var objects []governedquery.ExposedObject
	if err := jsonv2.Unmarshal(objectsJSON, &objects); err != nil {
		return nil, 0, &Error{code: CodePersistence, cause: err}
	}
	schema := governedquery.ExposedSchema{Revision: revision, Objects: objects}
	if err := schema.Validate(); err != nil {
		return nil, 0, &Error{code: CodePersistence, cause: err}
	}
	return &schema, revision, nil
}

// SetLiveQueries is the "flag of the source, live queries allowed, default
// off" toggle ADR-0089 §6/owner decision 10 requires, per WORKSPACE (AGG-2):
// the connection/exposed schema belong to the source, not to one workspace,
// so any workspace with sufficient role here may opt itself in independently
// of every other workspace that shares this same connection. It also acts as
// the minimal typed registration of the mounted connection into this
// workspace's control plane (the full ADR-0078 POSTGRESQL_QUERY registration
// surface is a separate slice, V1-A; see the connection's own doc comment).
func (service *Service) SetLiveQueries(ctx context.Context, access database.AccessContext, workspaceID, connectionID string, enabled bool) error {
	if service == nil || !service.enabled {
		return &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceManageSources); err != nil {
		return err
	}
	if connectionID != service.config.ConnectionID {
		return &Error{code: CodeConnectionUnavailable}
	}
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		// The connection row is created once, by whichever workspace opts in
		// first; its own workspace_id/live_queries_enabled columns are legacy
		// history from before AGG-2 and are never updated again here -- every
		// workspace's actual opt-in state lives only in the binding row below.
		if _, execErr := tx.Exec(txCtx, `
			INSERT INTO public.governed_query_connection
			    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $5)
			ON CONFLICT (organization_id, id) DO NOTHING
		`, access.OrganizationID, service.config.ConnectionID, workspaceID, service.config.DatabaseIdentity, access.PrincipalID); execErr != nil {
			return execErr
		}
		_, execErr := tx.Exec(txCtx, `
			INSERT INTO public.governed_query_workspace_binding
			    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $5)
			ON CONFLICT (organization_id, connection_id, workspace_id) DO UPDATE
			   SET live_queries_enabled = EXCLUDED.live_queries_enabled, updated_by = EXCLUDED.updated_by, updated_at = transaction_timestamp()
		`, access.OrganizationID, service.config.ConnectionID, workspaceID, enabled, access.PrincipalID)
		return execErr
	})
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// RegisterExposedSchema cross-validates the operator's requested exposed
// objects against the dedicated role's own information_schema and stores a
// new immutable revision (ADR-0089 §1). The schema itself belongs to the
// connection, not to the registering workspace (AGG-2); registering it also
// opts the calling workspace into the connection's workspace_binding table
// (live queries stay off until a separate SetLiveQueries(true)), so any other
// workspace this same source is bound to may register or see the schema
// independently, through its own membership/role, without disturbing this one.
func (service *Service) RegisterExposedSchema(ctx context.Context, access database.AccessContext, workspaceID, connectionID string, objects []governedquery.ExposedObject) (int64, error) {
	if service == nil || !service.enabled {
		return 0, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return 0, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceManageSources); err != nil {
		return 0, err
	}
	if connectionID != service.config.ConnectionID {
		return 0, &Error{code: CodeConnectionUnavailable}
	}
	var nextRevision int64
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var current int64
		scanErr := tx.QueryRow(txCtx, `
			SELECT COALESCE(MAX(revision), 0) FROM public.governed_query_exposed_schema
			 WHERE organization_id = $1 AND connection_id = $2
		`, access.OrganizationID, service.config.ConnectionID).Scan(&current)
		nextRevision = current + 1
		return scanErr
	})
	if err != nil {
		return 0, &Error{code: CodePersistence, cause: err}
	}
	schema, err := governedquery.DiscoverExposedSchema(ctx, service.config, nextRevision, objects)
	if err != nil {
		// A malformed operator request is not "the schema is unavailable".
		// Collapsing both onto CodeSchemaUnavailable answered a rejected
		// annotation with 409 GOVERNED_QUERY_UNAVAILABLE -- the same content-free
		// code the capability-absent path uses -- so an operator could not tell
		// "fix your request" from "this deployment has no governed query", and
		// neither can be told from the server's own logs without
		// DiagnosticClass. The refusal stays content-free either way: no schema,
		// table or column name is echoed.
		if governedquery.CodeOf(err) == governedquery.CodeInvalid {
			return 0, &Error{code: CodeRequestInvalid, cause: err}
		}
		return 0, &Error{code: CodeSchemaUnavailable, cause: err}
	}
	objectsJSON, err := canon.CanonicalJSON(schema.Objects)
	if err != nil {
		return 0, &Error{code: CodePersistence, cause: err}
	}
	revisionHash := canon.Hash(objectsJSON)
	// An exposed schema is content-identified: 000068 pins
	// UNIQUE (organization_id, connection_id, revision_hash) precisely so the
	// same operator-narrowed inventory cannot exist twice under two revision
	// numbers. Re-submitting the identical schema — what an operator does on
	// every redeploy, and what the acceptance does on every run — is therefore
	// a replay, and it must converge on the revision that already holds that
	// content. Inserting blindly turned it into an unhandled unique violation
	// answered as 503 SERVICE_UNAVAILABLE, so the governed-query surface could
	// be registered exactly once in the lifetime of a connection.
	var existingRevision int64
	replayErr := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT revision FROM public.governed_query_exposed_schema
			 WHERE organization_id = $1 AND connection_id = $2 AND revision_hash = $3
		`, access.OrganizationID, service.config.ConnectionID, revisionHash).Scan(&existingRevision)
	})
	if replayErr != nil && !database.IsNotFound(replayErr) {
		return 0, &Error{code: CodePersistence, cause: replayErr}
	}
	if replayErr == nil {
		// A replay of already-registered content still must opt THIS workspace
		// into the connection's workspace_binding (AGG-2): a second workspace
		// re-registering the same source's schema for the first time is exactly
		// how it becomes able to see it and later call SetLiveQueries(true).
		if bindErr := service.ensureWorkspaceBinding(ctx, access, workspaceID); bindErr != nil {
			return 0, bindErr
		}
		return existingRevision, nil
	}
	err = service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if execErr := service.ensureWorkspaceBindingTx(txCtx, tx, access, workspaceID); execErr != nil {
			return execErr
		}
		_, execErr := tx.Exec(txCtx, `
			INSERT INTO public.governed_query_exposed_schema
			    (organization_id, connection_id, revision, objects_json, revision_hash, created_by)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (organization_id, connection_id, revision_hash) DO NOTHING
		`, access.OrganizationID, service.config.ConnectionID, nextRevision, jsontext.Value(objectsJSON), revisionHash, access.PrincipalID)
		return execErr
	})
	if err != nil {
		return 0, &Error{code: CodePersistence, cause: err}
	}
	// A concurrent registration of the same content wins the ON CONFLICT above;
	// read back the revision that actually holds this content so the caller
	// never receives a revision number that does not exist.
	if readBackErr := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT revision FROM public.governed_query_exposed_schema
			 WHERE organization_id = $1 AND connection_id = $2 AND revision_hash = $3
		`, access.OrganizationID, service.config.ConnectionID, revisionHash).Scan(&existingRevision)
	}); readBackErr != nil {
		return 0, &Error{code: CodePersistence, cause: readBackErr}
	}
	return existingRevision, nil
}

// recordExecutedAttempt persists the exact statement one successful governed
// query actually ran, under a server-owned attempt id. It is the only writer
// of governed_query_attempt.sql_text, and its input is Execute's own accepted
// candidate -- never a request body. Promotion later dereferences this row, so
// the ADR-0089 §5 "save the query that worked" command needs no SQL input
// field at all (PRODUCT_CONSTITUTION.md §7).
func (service *Service) recordExecutedAttempt(ctx context.Context, access database.AccessContext, workspaceID string, revision int64, sqlText, sqlHash string, rowCount int) (string, error) {
	attemptID, idErr := newAttemptID()
	if idErr != nil {
		return "", &Error{code: CodePersistence, cause: idErr}
	}
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(txCtx, `
			INSERT INTO public.governed_query_attempt
			    (organization_id, id, connection_id, workspace_id, exposed_schema_revision,
			     sql_hash, sql_text, row_count, executed_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, access.OrganizationID, attemptID, service.config.ConnectionID, workspaceID, revision,
			sqlHash, sqlText, rowCount, access.PrincipalID)
		return execErr
	})
	if err != nil {
		return "", &Error{code: CodePersistence, cause: err}
	}
	return attemptID, nil
}

// loadExecutedAttempt reads one executed attempt of THIS connection and
// workspace. A missing, foreign-workspace or foreign-connection attempt is
// indistinguishable in the answer: all three map to the same content-free
// refusal an invalid request gets.
func (service *Service) loadExecutedAttempt(ctx context.Context, access database.AccessContext, workspaceID, attemptID string) (governedquery.ExecutedAttempt, error) {
	var attempt governedquery.ExecutedAttempt
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT id, connection_id, exposed_schema_revision, sql_hash, sql_text
			  FROM public.governed_query_attempt
			 WHERE organization_id = $1 AND id = $2 AND connection_id = $3 AND workspace_id = $4
		`, access.OrganizationID, attemptID, service.config.ConnectionID, workspaceID).Scan(
			&attempt.AttemptID, &attempt.ConnectionID, &attempt.ExposedSchemaRevision,
			&attempt.SQLHash, &attempt.SQLText)
	})
	if database.IsNotFound(err) {
		return governedquery.ExecutedAttempt{}, &Error{code: CodeRequestInvalid}
	}
	if err != nil {
		return governedquery.ExecutedAttempt{}, &Error{code: CodePersistence, cause: err}
	}
	return attempt, nil
}

// Promote is the typed "save as projection" hook (ADR-0089 §5). Its input is
// the identity of an attempt that already ran plus the SQL hash the operator
// was shown -- never SQL text. The real ADR-0078 registration integration is
// a separate slice (V1-A); see governedquery.PromoteToProjection's own doc
// comment.
func (service *Service) Promote(ctx context.Context, access database.AccessContext, workspaceID, connectionID, attemptID, expectedSQLHash string) (governedquery.PromotionResult, error) {
	if service == nil || !service.enabled {
		return governedquery.PromotionResult{}, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(attemptID) ||
		!validSQLHash(expectedSQLHash) {
		return governedquery.PromotionResult{}, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceManageSources); err != nil {
		return governedquery.PromotionResult{}, err
	}
	if connectionID != service.config.ConnectionID {
		return governedquery.PromotionResult{}, &Error{code: CodeConnectionUnavailable}
	}
	attempt, err := service.loadExecutedAttempt(ctx, access, workspaceID, attemptID)
	if err != nil {
		return governedquery.PromotionResult{}, err
	}
	result, promoteErr := governedquery.PromoteToProjection(ctx, governedquery.PromotionRequest{
		ConnectionID: service.config.ConnectionID, PrincipalID: access.PrincipalID,
		ExpectedSQLHash: expectedSQLHash, Attempt: attempt,
	})
	if promoteErr != nil {
		return governedquery.PromotionResult{}, &Error{code: CodeRequestInvalid, cause: promoteErr}
	}
	// Promoting the same attempt twice is the operator pressing the button
	// twice, not a second projection: 000074 pins one promotion per attempt
	// and this converges on the row that already holds it.
	promotionErr := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		id, idErr := newPromotionID()
		if idErr != nil {
			return idErr
		}
		_, execErr := tx.Exec(txCtx, `
			INSERT INTO public.governed_query_promotion
			    (organization_id, id, connection_id, sql_hash, status, promoted_by, attempt_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (organization_id, attempt_id) DO NOTHING
		`, access.OrganizationID, id, service.config.ConnectionID, result.SQLHash, string(result.Status),
			access.PrincipalID, result.AttemptID)
		return execErr
	})
	if promotionErr != nil {
		return governedquery.PromotionResult{}, &Error{code: CodePersistence, cause: promotionErr}
	}
	return result, nil
}

// auditAttempt appends exactly one content-free source.governed_query_attempted
// event per attempt (ADR-0089 §4). Every branch of Ask calls it exactly once,
// before any success branch may disclose rows: its returned error is the
// caller's own signal that the mandatory audit record did not durably land,
// and Ask must turn that into a refusal with zero bytes of content rather
// than let a successful SQL execution reach the client unaudited (FIX-1 #1).
// A nil auditor (no journal wired at all) is a deliberate deployment choice,
// not a failed write, so it returns nil rather than blocking every call.
func (service *Service) auditAttempt(ctx context.Context, access database.AccessContext, workspaceID string, revision int64, sqlHash, outcome string, cost *float64, rows *int, digest *string) error {
	if service == nil || service.auditor == nil {
		return nil
	}
	eventID, idErr := newPromotionID()
	if idErr != nil {
		return idErr
	}
	if sqlHash == "" {
		sqlHash = canon.Hash([]byte(outcome + ":" + workspaceID))
	}
	if revision < 1 {
		revision = 1
	}
	connectionID := service.config.ConnectionID
	var costValue *int64
	if cost != nil {
		rounded := int64(*cost)
		costValue = &rounded
	}
	var rowValue *int64
	if rows != nil {
		converted := int64(*rows)
		rowValue = &converted
	}
	outcomeValue := outcome
	auditOutcome := outcomeToAuditOutcome(outcome)
	// The common event validator requires ErrorCode set on every non-SUCCESS
	// outcome; the closed governed-query outcome vocabulary itself is already
	// a valid ErrorCode shape (uppercase, digits, underscore), so every
	// rejection kind names itself as its own error code.
	var errorCode *string
	if auditOutcome != audit.OutcomeSuccess {
		errorCode = &outcomeValue
	}
	// The audit store binds an event to the request that caused it: an append
	// whose RequestID is not the caller's own request id is rejected as an
	// invalid event before it ever reaches the database. This event carried a
	// freshly minted id instead, so ADR-0089 §4's "every attempt is audited"
	// silently produced nothing at all — the append error was discarded here and
	// the journal simply never had a governed-query attempt in it.
	if _, auditErr := service.auditor.Append(ctx, access, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()), ActorPrincipalID: &access.PrincipalID,
		Action: audit.ActionGovernedQueryAttempted, ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: access.RequestID, Outcome: auditOutcome, ErrorCode: errorCode,
		Metadata: audit.Metadata{
			GovernedQueryConnectionID: &connectionID, GovernedQueryExposedSchemaRevision: &revision,
			GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcomeValue,
			GovernedQueryCostEstimate: costValue, GovernedQueryRowCount: rowValue, GovernedQueryResultDigest: digest,
		},
		OccurredAt: service.now(),
	}); auditErr != nil {
		// Never silent again: a governed attempt that cannot be journalled is a
		// content-free warning an operator can act on, not an invisible gap --
		// and, per FIX-1 #1, the caller's own refusal, never just a log line.
		slog.Warn("governed query attempt not audited", "component", "knowvault-server",
			"request_id", access.RequestID, "error_code", audit.CodeOf(auditErr))
		return auditErr
	}
	return nil
}

func outcomeToAuditOutcome(outcome string) audit.Outcome {
	if outcome == audit.GovernedQueryOutcomeSucceeded {
		return audit.OutcomeSuccess
	}
	return audit.OutcomeDenied
}

func newPromotionID() (string, error) {
	return ids.New("gqid")
}

func newAttemptID() (string, error) {
	return ids.New("gqat")
}

// validSQLHash is the closed shape of the content-free hash the operator
// confirms. It is checked before any database round trip, so a malformed
// reference never reaches the attempt store.
func validSQLHash(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}
