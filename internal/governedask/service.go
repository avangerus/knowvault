// Package governedask is the workspace-facing orchestration for ADR-0089's
// governed model-authored SQL path. It never holds the dedicated
// governed-execution role's connection capability itself and never
// constructs SQL text: it loads the current exposed-schema revision, asks
// the Model Gateway for a candidate SQL claim over that bounded schema text,
// and hands the exact untrusted candidate to
// internal/source/postgresqlquery/governedquery.Execute -- the one package
// permitted to run it. This package is the "server-owned Question authority"
// ADR-0089 §2 describes for this narrower ad hoc path; it is deliberately
// independent of internal/question's retrieval/candidate pipeline because a
// governed query has no pre-ingested Evidence to select from.
package governedask

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

type ErrorCode string

const (
	CodeUnavailable           ErrorCode = "GOVERNED_ASK_UNAVAILABLE"
	CodeRequestInvalid        ErrorCode = "GOVERNED_ASK_REQUEST_INVALID"
	CodeDenied                ErrorCode = "GOVERNED_ASK_DENIED"
	CodeLiveQueriesOff        ErrorCode = "GOVERNED_ASK_LIVE_QUERIES_DISABLED"
	CodeSchemaUnavailable     ErrorCode = "GOVERNED_ASK_SCHEMA_UNAVAILABLE"
	CodeConnectionUnavailable ErrorCode = "GOVERNED_ASK_CONNECTION_UNAVAILABLE"
	CodeGenerationFailed      ErrorCode = "GOVERNED_ASK_GENERATION_FAILED"
	CodeExecutionFailed       ErrorCode = "GOVERNED_ASK_EXECUTION_FAILED"
	CodePersistence           ErrorCode = "GOVERNED_ASK_PERSISTENCE_FAILED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// DiagnosticClass is the content-free operator diagnosis for one governed-ask
// failure. Every capability, schema and connection refusal deliberately
// answers the caller with the single opaque code GOVERNED_QUERY_UNAVAILABLE so
// a caller can never probe which tables the operator exposed or whether the
// dedicated role exists (ADR-0089 §6). That is right for the transport and
// useless for the operator, who otherwise cannot tell "live queries are off"
// from "the dedicated role could not be dialled". This helper reports only the
// wrapped governedquery code, the SQLSTATE or the Go type of the cause --
// never SQL text, a DSN, a schema/table name, a row or a model answer -- and
// is the value the server logs beside the request id.
func DiagnosticClass(err error) string {
	if err == nil {
		return ""
	}
	var governedError *governedquery.Error
	if errors.As(err, &governedError) {
		// The governedquery codes already carry their own GOVERNED_QUERY_ prefix.
		return string(governedquery.CodeOf(governedError))
	}
	var gatewayError *modelgateway.Error
	if errors.As(err, &gatewayError) {
		// Likewise MODEL_GATEWAY_*: "the model step failed" is not actionable,
		// "the runtime is unreachable" versus "the model's plan did not validate
		// against the required schema" is.
		return string(modelgateway.CodeOf(gatewayError))
	}
	if state := database.SQLStateCode(err); state != "" {
		if constraint := database.SQLConstraintName(err); constraint != "" {
			return "SQLSTATE_" + state + "_CONSTRAINT_" + constraint
		}
		return "SQLSTATE_" + state
	}
	if errors.Is(err, context.Canceled) {
		return "CONTEXT_CANCELED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "CONTEXT_DEADLINE_EXCEEDED"
	}
	var typed *Error
	if errors.As(err, &typed) {
		if typed.cause == nil {
			return "NO_CAUSE"
		}
		return "CAUSE_TYPE_" + fmt.Sprintf("%T", typed.cause)
	}
	return "ERROR_TYPE_" + fmt.Sprintf("%T", err)
}

const (
	// The instructions and the schema below are deliberately as explicit as
	// internal/question's generation contract. The ClaimPlan shape the Model
	// Gateway validates is exact (claim_id ^C[1-9][0-9]*$, section_id
	// ^S[1-9][0-9]*$, per-kind null/empty rules), and a schema that only listed
	// REQUIRED KEY NAMES left the model to guess those: every governed ask on
	// the acceptance stand came back MODEL_GATEWAY_RESPONSE_INVALID after both
	// bounded attempts. Naming the exact field shapes is the contract the
	// gateway already enforces, not a relaxation of it.
	askSystemInstructions = "Produce exactly one SQL SELECT query (one statement, with no trailing semicolon " +
		"and no DDL/DML) to answer the user's question, using only the tables and columns " +
		"described in the supplied Evidence fragments. Fully qualify every table or view " +
		"as schema_name.table_name exactly as given in Evidence; unqualified object names are prohibited. " +
		"The response must be strictly a ClaimPlan JSON object without any " +
		"other text or markdown: the top-level object contains exactly schema_version, claims and sections, " +
		"and no additional or punctuation-named members are allowed (for example a member named \".\"); " +
		"schema_version=\"1.4\", claims is an array of exactly one claim with " +
		"claim_id=\"C1\", sections is an array of exactly one section with section_id=\"S1\", title=null, and " +
		"ordered_claim_ids=[\"C1\"]. Claim field rules by kind: " +
		"FACT: text is the exact SQL query text (a nonempty string without markdown or explanation), " +
		"unknown_reason is exactly null, evidence_ids is a nonempty array of identifiers for the schema fragments used, " +
		"supporting_claim_ids is exactly []; " +
		"UNKNOWN: text MUST be null (JSON null), unknown_reason=\"NO_RELEVANT_EVIDENCE\", " +
		"evidence_ids is exactly [], and supporting_claim_ids is exactly []. " +
		"If the question requires a table or column outside the supplied schema, return a claim with kind=UNKNOWN."
	askOutputSchema = `{"type":"object","additionalProperties":false,"required":["schema_version","claims","sections"],"properties":{` +
		`"schema_version":{"const":"1.4"},` +
		`"claims":{"type":"array","minItems":1,"maxItems":1,"items":{"type":"object","additionalProperties":false,"required":["claim_id","text","kind","unknown_reason","evidence_ids","supporting_claim_ids"],` +
		`"properties":{"claim_id":{"type":"string","pattern":"^C[1-9][0-9]*$"},"text":{"type":["string","null"]},"kind":{"enum":["FACT","UNKNOWN"]},` +
		`"unknown_reason":{"type":["string","null"],"enum":[null,"NO_RELEVANT_EVIDENCE"]},` +
		`"evidence_ids":{"type":"array","items":{"type":"string"}},"supporting_claim_ids":{"type":"array","items":{"type":"string"}}}}},` +
		`"sections":{"type":"array","minItems":1,"maxItems":1,"items":{"type":"object","additionalProperties":false,"required":["section_id","title","ordered_claim_ids"],` +
		`"properties":{"section_id":{"type":"string","pattern":"^S[1-9][0-9]*$"},"title":{"type":["string","null"]},"ordered_claim_ids":{"type":"array","items":{"type":"string"}}}}}}}`
	askMaxOutputTokens = 4096
	// askMaxAttempts bounds how many times one question may be re-composed when
	// the model produces a schema-valid statement the exposed schema or the
	// dedicated read-only role refuses (ADR-0080 bounded retries). It is a
	// server-owned constant; no request may widen it.
	askMaxAttempts = 2
)

// auditAppender is the narrow slice of *audit.Store governedask actually
// calls: one durable, tenant-scoped append per attempt. Declaring it here
// (rather than depending on the concrete *audit.Store) lets a unit test
// substitute a fake that returns a controlled error, so auditAttempt's own
// fail-closed handling can be exercised without a live database (INT-2 #4).
// *audit.Store already has exactly this method set, so accepting the
// interface in New below does not change behavior for either production
// caller (internal/platform/composition/runtime.go,
// tests/integration/postgres) -- both already pass a *audit.Store.
type auditAppender interface {
	Append(ctx context.Context, access database.AccessContext, input audit.EventInput) (audit.Event, error)
}

// Service is capability-gated: EnableGovernedQueryConfig must receive a valid
// mounted Config before preset and administration methods expose behavior.
// Ask additionally requires the model adapter wired by EnableGovernedQuery,
// mirroring question.Service's capability-absent-by-default shape.
type Service struct {
	db      *database.Store
	auditor auditAppender
	config  governedquery.Config
	enabled bool
	adapter *modelgateway.LabAdapter
	now     func() time.Time
}

func New(db *database.Store, auditor auditAppender) (*Service, error) {
	if db == nil || auditor == nil {
		return nil, errors.New("governedask requires a database store and audit store")
	}
	return &Service{db: db, auditor: auditor, now: time.Now}, nil
}

// EnableGovernedQuery wires the mounted ADR-0089 connection capability and
// the Model Gateway adapter used to compose candidate SQL. Composition calls
// this only when both a valid governedquery mount and a Model Gateway
// adapter exist; absent that call, every method below fails closed with
// CodeUnavailable before touching a database or the model.
func (service *Service) EnableGovernedQuery(config governedquery.Config, adapter *modelgateway.LabAdapter) {
	if service == nil || config.Validate() != nil || adapter == nil {
		return
	}
	service.config = config
	service.enabled = true
	service.adapter = adapter
}

// EnableGovernedQueryConfig mounts the database capability without requiring
// a text-generation model. This is sufficient for administrator-approved SQL
// presets, whose statement is selected by id and never composed during a run.
// EnableGovernedQuery may subsequently add the optional ad-hoc ask adapter.
func (service *Service) EnableGovernedQueryConfig(config governedquery.Config) {
	if service == nil || config.Validate() != nil {
		return
	}
	service.config = config
	service.enabled = true
}

// PresetOnly reports the operator-mounted policy for the MCP transport. The
// service remains the authority for this decision: request data cannot turn
// an ad-hoc query back on. A service that has not accepted a valid mount keeps
// the legacy false value and exposes no closed-mode claim.
func (service *Service) PresetOnly() bool {
	return service != nil && service.enabled && service.config.PresetOnly
}

// AskResult is the user-facing, non-content-free answer ADR-0089 §4 requires:
// the exact SQL executed and its result table are shown to the user alongside
// the model's answer.
type AskResult struct {
	// AttemptID is the server-owned identity of the executed attempt. It is
	// the ONLY handle :promote accepts (with the hash below): the operator
	// saves a query that ran, by reference, never by posting SQL text back
	// (PRODUCT_CONSTITUTION.md §7, ADR-0089 §5).
	AttemptID             string      `json:"attempt_id"`
	SQL                   string      `json:"sql"`
	SQLHash               string      `json:"sql_hash"`
	Columns               []string    `json:"columns"`
	Rows                  [][]*string `json:"rows"`
	RowCount              int         `json:"row_count"`
	CostEstimate          float64     `json:"cost_estimate"`
	Answer                string      `json:"answer"`
	ConnectionID          string      `json:"connection_id"`
	DatabaseIdentity      string      `json:"database_identity"`
	ExposedSchemaRevision int64       `json:"exposed_schema_revision"`
	ResultFormat          string      `json:"result_format"`
	ResultDigest          string      `json:"result_digest"`
	ExecutionStartedAt    time.Time   `json:"execution_started_at"`
	ExecutionCompletedAt  time.Time   `json:"execution_completed_at"`
}

// Ask is the single production entry point for ADR-0089's ad hoc governed
// query. It fails closed before any model call when the connection is
// unknown, live queries are disabled, or no exposed schema is registered.
func (service *Service) Ask(ctx context.Context, access database.AccessContext, workspaceID, connectionID, question string) (AskResult, error) {
	if service == nil || !service.enabled || service.adapter == nil {
		return AskResult{}, &Error{code: CodeUnavailable}
	}
	// AGG-2: the connection's mounted config.WorkspaceID is no longer the
	// access gate -- a connection belongs to its source, not to one
	// workspace, and any workspace may ask once it has its own opted-in
	// governed_query_workspace_binding row (checked below by
	// liveQueriesEnabled) and ordinary workspace membership/role
	// (checked by authorize, right after this validation).
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || question == "" || len(question) > 4000 {
		return AskResult{}, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return AskResult{}, err
	}
	// Outcome 2 (audit before data): the single admission event for this
	// governed ask is persisted here, before liveQueriesEnabled,
	// loadExposedSchema, the Model Gateway call or governedquery.Execute reads
	// or executes anything. It records the effective actor kind
	// (HUMAN | SERVICE) and the access decision (SUCCESS = admitted). If it
	// cannot be recorded, Ask fails closed with the existing audit-failure
	// error and a zero AskResult and no governed read or execution happens.
	// The existing source.governed_query_attempted outcome events below are
	// unchanged, so a governed query that fails after admission leaves
	// admission plus an outcome, never admission alone.
	return service.withAdmission(ctx, access, workspaceID, func() (AskResult, error) {
		if connectionID != service.config.ConnectionID {
			if err := service.auditAttempt(ctx, access, workspaceID, 0, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil); err != nil {
				return AskResult{}, &Error{code: CodeUnavailable, cause: err}
			}
			return AskResult{}, &Error{code: CodeConnectionUnavailable}
		}
		return service.askAdmitted(ctx, access, workspaceID, question)
	})
}

// askAdmitted is Ask()'s governed body: it runs only after the mandatory
// admission event is durable and performs every governed read and execution.
func (service *Service) askAdmitted(ctx context.Context, access database.AccessContext, workspaceID, question string) (AskResult, error) {
	liveQueriesEnabled, err := service.liveQueriesEnabled(ctx, access, workspaceID)
	if err != nil {
		return AskResult{}, err
	}
	if !liveQueriesEnabled {
		service.auditAttempt(ctx, access, workspaceID, 0, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
		return AskResult{}, &Error{code: CodeLiveQueriesOff}
	}
	schema, revision, err := service.loadExposedSchema(ctx, access, workspaceID)
	if err != nil {
		return AskResult{}, err
	}
	if schema == nil {
		service.auditAttempt(ctx, access, workspaceID, 0, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
		return AskResult{}, &Error{code: CodeSchemaUnavailable}
	}

	evidence, err := schemaEvidence(*schema)
	if err != nil {
		return AskResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	// A model answer that is schema-valid but not executable against the
	// exposed schema (a column the model invented, a shape the read-only role
	// or the EXPLAIN cost gate refuses) is a model outcome, not a system
	// failure, and it made this route fail intermittently on questions it could
	// answer. ADR-0080's bounded-retry discipline applies to the whole
	// compose-and-execute step, not only to the JSON-shape retry inside
	// GenerateBounded: compose again, at most askMaxAttempts times.
	//
	// Nothing about the security boundary is retried away. Every attempt is
	// composed from the same exposed schema, executed by the same dedicated
	// read-only role under the same transaction, timeout, row and cost bounds,
	// and audited content-free in its own right, so a refusal stays a refusal:
	// exhausting the attempts returns exactly the last typed failure.
	var lastErr error
	for attemptNumber := 1; attemptNumber <= askMaxAttempts; attemptNumber++ {
		plan, genErr := service.adapter.GenerateBounded(ctx, question, askSystemInstructions, []byte(askOutputSchema),
			evidence, askMaxOutputTokens, func(modelgateway.AttemptResult) {})
		if genErr != nil {
			service.auditAttempt(ctx, access, workspaceID, revision, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			lastErr = &Error{code: CodeGenerationFailed, cause: genErr}
			continue
		}
		sqlText, ok := candidateSQL(plan)
		if !ok {
			service.auditAttempt(ctx, access, workspaceID, revision, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			lastErr = &Error{code: CodeGenerationFailed}
			continue
		}

		result, attempt, execErr := governedquery.Execute(ctx, service.config, governedquery.ExecuteParams{
			SQLText: sqlText, ExposedSchemaRevision: revision,
		})
		auditErr := service.auditAttempt(ctx, access, workspaceID, revision, attempt.SQLHash, string(attempt.Outcome),
			costPointer(attempt), rowCountPointer(attempt), digestPointer(attempt))
		if execErr != nil {
			lastErr = &Error{code: CodeExecutionFailed, cause: execErr}
			if ctx.Err() != nil {
				break
			}
			continue
		}
		return service.discloseExecutedAttempt(ctx, access, workspaceID, revision, sqlText, attempt, result, auditErr)
	}
	return AskResult{}, lastErr
}

// emitAdmission persists the one admission event that must be durable before
// Ask() reads or executes anything governed. It records the effective actor
// kind (HUMAN | SERVICE), the access decision (OutcomeSuccess = admitted), the
// workspace id as both the event workspace and the resource, and carries no
// SQL text, schema name, row or model content. A failure is returned so the
// caller can fail closed with no data.
//
// The workspace is the resource being admitted, exactly as the governed
// question-run admission names its workspace: the admission itself is an
// access decision, not an attempt outcome, so it must not carry the
// governed-query attempt vocabulary (no SQL hash, revision or outcome).
func (service *Service) emitAdmission(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if service == nil || service.auditor == nil || service.now == nil {
		return errors.New("governedask: admission requires the audit journal")
	}
	eventID, err := newAdmissionID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	workspace := workspaceID
	_, err = service.auditor.Append(ctx, access, audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspace,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionGovernedQueryAdmitted,
		ResourceType:          audit.ResourceWorkspace,
		ResourceID:            workspaceID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{},
		OccurredAt:            service.now().UTC(),
	})
	return err
}

// withAdmission persists the mandatory admission event and only then invokes
// run, which performs every governed read, model call and SQL execution and
// returns the disclosed result. If the admission cannot be recorded the typed
// unavailable error is returned and run is never invoked, so no row, schema or
// answer can be read or disclosed. The existing outcome events are appended,
// unchanged, by run.
func (service *Service) withAdmission(ctx context.Context, access database.AccessContext, workspaceID string, run func() (AskResult, error)) (AskResult, error) {
	if err := service.emitAdmission(ctx, access, workspaceID); err != nil {
		return AskResult{}, &Error{code: CodeUnavailable, cause: err}
	}
	return run()
}

// newAdmissionID mints the server-owned identity of one admission event. It is
// never derived from request content.
func newAdmissionID() (string, error) {
	return ids.New("gqad")
}

// discloseExecutedAttempt is Ask()'s disclosure gate for one governed query
// that already executed successfully (execErr == nil): its own mandatory
// audit record is a precondition of returning any row to the caller. auditErr
// is the already-computed outcome of that append (FIX-1 #1's
// "audit is a condition of disclosure" rule), passed in rather than
// recomputed here so this decision can be exercised directly by a unit test
// without a live database, Model Gateway or governed-execution role
// (INT-2 #4).
func (service *Service) discloseExecutedAttempt(ctx context.Context, access database.AccessContext, workspaceID string, revision int64, sqlText string, attempt governedquery.Attempt, result governedquery.QueryResult, auditErr error) (AskResult, error) {
	// FIX-1 #1: a successful SQL execution never reaches the caller unless
	// its mandatory audit record durably landed in the same disclosure
	// gate every other transport (REST/MCP) shares. Zero rows/columns are
	// returned -- the query already ran (it is read-only), but nothing
	// about its result is disclosed without the audit receipt.
	if auditErr != nil {
		return AskResult{}, &Error{code: CodeUnavailable, cause: auditErr}
	}
	answer := "The database returned " + strconv.Itoa(result.RowCount) + " row(s) for your query."
	// Record what actually ran before answering. This row is the only
	// thing :promote will ever dereference, so a query the operator can
	// see is a query the operator can save without re-posting its text.
	attemptID, recordErr := service.recordExecutedAttempt(ctx, access, workspaceID, revision,
		sqlText, attempt.SQLHash, result.RowCount)
	if recordErr != nil {
		return AskResult{}, recordErr
	}
	return AskResult{
		AttemptID: attemptID, SQL: sqlText, SQLHash: attempt.SQLHash,
		Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount,
		CostEstimate: result.CostEstimate, Answer: answer,
		ConnectionID: service.config.ConnectionID, DatabaseIdentity: service.config.DatabaseIdentity,
		ExposedSchemaRevision: revision, ResultFormat: "postgres-text-table-v1", ResultDigest: attempt.ResultDigest,
		ExecutionStartedAt: result.ExecutionStartedAt, ExecutionCompletedAt: result.ExecutionCompletedAt,
	}, nil
}

func candidateSQL(plan modelgateway.ClaimPlan) (string, bool) {
	if len(plan.Claims) != 1 {
		return "", false
	}
	claim := plan.Claims[0]
	if claim.Kind != "FACT" || claim.Text == nil || *claim.Text == "" {
		return "", false
	}
	return *claim.Text, true
}

// schemaEvidence renders the exposed schema as the bounded Evidence set the
// model must cite from. The evidence ids are DERIVED FROM THE SCHEMA, not
// minted per call.
//
// They used to be fresh random ULIDs. The model is required to echo them back
// verbatim in evidence_ids, and the gateway rejects a plan that does not
// (modelgateway.ClaimPlan.Validate), so every request handed the model a
// different opaque token to copy at temperature 0 — a per-request lottery.
// That is exactly the observed REST/MCP divergence on the acceptance stand:
// the same question, asked over REST and then over MCP, produced two
// different prompts and therefore two different outcomes, one green and one
// GOVERNED_ASK_GENERATION_FAILED with no SQL at all. Deriving the ids from
// the schema makes the two paths byte-identical prompts, so they now succeed
// or fail together — and makes the ids short and copyable, which is what the
// model actually has to do. Nothing about the security boundary changes: the
// ids are opaque handles inside one request, never persisted or authorizing.
func schemaEvidence(schema governedquery.ExposedSchema) ([]modelgateway.Evidence, error) {
	texts := schema.PromptText()
	result := make([]modelgateway.Evidence, 0, len(texts))
	for index, text := range texts {
		id := "gqev-" + strconv.Itoa(index+1)
		hash := canon.Hash([]byte(text))
		result = append(result, modelgateway.Evidence{
			ID: id, SourceObjectID: "governed-schema-" + strconv.Itoa(index),
			SourceVersionID: "governed-schema-" + strconv.Itoa(index),
			ExtractionID:    "governed-schema-" + strconv.Itoa(index),
			TextHash:        hash, AnchorHash: hash, Text: text,
		})
	}
	return result, nil
}

func costPointer(attempt governedquery.Attempt) *float64 {
	if attempt.Outcome != governedquery.OutcomeSucceeded && attempt.Outcome != governedquery.OutcomeCostLimitExceeded {
		return nil
	}
	value := attempt.CostEstimate
	return &value
}

func rowCountPointer(attempt governedquery.Attempt) *int {
	if attempt.Outcome != governedquery.OutcomeSucceeded {
		return nil
	}
	value := attempt.RowCount
	return &value
}

func digestPointer(attempt governedquery.Attempt) *string {
	if attempt.Outcome != governedquery.OutcomeSucceeded || attempt.ResultDigest == "" {
		return nil
	}
	value := attempt.ResultDigest
	return &value
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
