package question

// R2 Outcome 2: the server-validated QueryIntent gate.
//
// A workspace that has at least one APPROVED MetricDefinition must answer a
// structured question through queryintent.Validator (POSITION.md §3
// "Execution"): the model only proposes a
// {metric_id, version, period, filters, output, as_of} Proposal, the server
// either seals it into an Intent or returns a typed, content-free refusal with
// a clarification text, and only a sealed Intent is handed to execution. A
// workspace with no APPROVED definition keeps today's path verbatim -- the
// gate makes no governed read and returns immediately.
//
// This file adds no query, SQL or free-text field to any exported type. Its
// proposer and executor are narrow, injected seams; when either is absent the
// path fails closed with a clarification rather than falling back to free-text
// planning, so a workspace with approved definitions can never reach the
// planner/retrieval path without a server-validated intent. Production
// composition supplies the real pair built here from in-tree services only:
// plannerIntentProposer (deterministic proposal over the access-re-checked
// catalog) and serviceIntentExecutor (sealed-intent execution over the
// authority's existing persisted-run and structured-snapshot machinery).

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// intentExecutionUnavailableClarification is the server-owned, content-free
// text shown when a workspace has APPROVED definitions but no sealed-intent
// execution capability is mounted. It names no metric, source or model.
const intentExecutionUnavailableClarification = "Structured metric execution is not available in this workspace yet. Try again later."

// MetricDefinitionLister is the access-re-checked read of a workspace's
// MetricDefinition versions. The implementation re-checks the caller's access
// exactly like every other protected read and returns only workspaceID's
// definitions, so one workspace's definitions can never leak into another's.
// It is structurally identical to the read-only REST/MCP catalog interface, so
// one production implementation satisfies both.
type MetricDefinitionLister interface {
	List(ctx context.Context, access database.AccessContext, workspaceID string) ([]metricdef.Definition, error)
}

// QueryIntentProposer proposes at most one QueryIntent for a canonical
// question. ok=false means the model produced no structured intent; the gate
// then refuses with an invalid-proposal clarification instead of planning free
// text.
type QueryIntentProposer interface {
	Propose(ctx context.Context, workspaceID, question string) (queryintent.Proposal, bool)
}

// QueryIntentExecutor executes ONLY a sealed, server-validated Intent. The
// sealed Intent is the sole query-selecting input: the request carries run
// identity for persistence but no question text, plan, filter or SQL.
type QueryIntentExecutor interface {
	ExecuteIntent(ctx context.Context, access database.AccessContext, request IntentExecutionRequest) (Run, error)
}

// IntentExecutionRequest is the only value an executor receives. Beside the
// sealed Intent it carries only identity the run already owned (workspace,
// run/conversation ids, idempotency key and the already-validated answer
// mode), never a query the executor could reinterpret and never the original
// free-text question.
type IntentExecutionRequest struct {
	WorkspaceID        string
	RunID              string
	ConversationID     string
	ConversationTurnID string
	// IdempotencyKey and AnswerMode are run identity/mode the caller already
	// validated (CreateRequest); they let the production executor persist the
	// run through the same `start` path the legacy flow uses. Neither selects
	// or narrows a query.
	IdempotencyKey string
	AnswerMode     string
	// CreateConversation mirrors CreateRequest.ConversationID == "": the run
	// opens a new conversation when true, and continues the existing one when
	// false. It is identity, never a query.
	CreateConversation bool
	Intent             queryintent.Intent
}

// EnableQueryIntents wires the R2 Outcome 2 gate. A nil lister leaves the gate
// inert and every workspace on today's path (the default until composition
// mounts a definition catalog). A wired lister with a nil proposer or executor
// keeps the gate fail-closed for workspaces that do hold APPROVED definitions.
func (service *Service) EnableQueryIntents(lister MetricDefinitionLister, proposer QueryIntentProposer, executor QueryIntentExecutor) {
	if service == nil {
		return
	}
	service.intentDefinitions = lister
	service.intentProposer = proposer
	service.intentExecutor = executor
}

// ClarificationOf returns the server-owned clarification text of a typed
// QueryIntent refusal, or "" for any other error. It carries no model, source
// or definition content: queryintent builds every refusal text from a closed
// dictionary keyed only by the refusal code.
func ClarificationOf(err error) string {
	if err == nil {
		return ""
	}
	var typed *Error
	if errors.As(err, &typed) && typed.clarification != "" {
		return typed.clarification
	}
	var refusal *queryintent.Error
	if errors.As(err, &refusal) {
		return refusal.Clarification()
	}
	return ""
}

// validateStructuredIntent is the gate's decision step. It returns:
//
//   - (zero, false, nil)  when the workspace has no APPROVED definition (or no
//     catalog is mounted): the caller continues today's path unchanged;
//   - (sealed, true, nil) when queryintent.Validator sealed the proposal: the
//     intent is the only input the caller may execute;
//   - (zero, false, err)  on a typed refusal, including a missing proposal or a
//     missing proposer -- never a fabricated intent and never a free-text plan.
//
// The definition read is a governed read: a failure to list fails closed with
// the typed unavailable error rather than assuming the workspace has no
// definitions.
func (service *Service) validateStructuredIntent(ctx context.Context, access database.AccessContext, workspaceID, questionText string) (queryintent.Intent, bool, error) {
	if service == nil || service.intentDefinitions == nil {
		return queryintent.Intent{}, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	definitions, err := service.intentDefinitions.List(ctx, access, workspaceID)
	if err != nil {
		return queryintent.Intent{}, false, &Error{code: CodeUnavailable, cause: err}
	}
	if !hasApprovedDefinition(definitions, workspaceID) {
		// No APPROVED definition in this workspace: short-circuit and keep
		// today's path byte-for-byte.
		return queryintent.Intent{}, false, nil
	}
	// The catalog exposes every version (DRAFT, APPROVED, RETIRED) so the
	// validator can distinguish a retired/not-approved version from an unknown
	// one; the validator alone decides which versions may execute.
	validator, err := queryintent.NewValidator(workspaceID, definitionCatalog(workspaceID, definitions))
	if err != nil {
		return queryintent.Intent{}, false, refusalAsError(err)
	}
	if service.intentProposer == nil {
		return queryintent.Intent{}, false, refusalAsError(invalidProposalRefusal(validator))
	}
	proposal, ok := service.intentProposer.Propose(contextWithIntentAccess(ctx, access), workspaceID, questionText)
	if !ok {
		return queryintent.Intent{}, false, refusalAsError(invalidProposalRefusal(validator))
	}
	intent, err := validator.Validate(proposal)
	if err != nil {
		return queryintent.Intent{}, false, refusalAsError(err)
	}
	if intent == (queryintent.Intent{}) {
		// Validate can never seal a zero intent; refuse rather than execute a
		// partially populated one.
		return queryintent.Intent{}, false, refusalAsError(invalidProposalRefusal(validator))
	}
	return intent, true, nil
}

// executeStructuredIntent hands a sealed intent to the injected executor. A
// zero intent is refused before the executor is consulted, so a partial intent
// is never executed.
func (service *Service) executeStructuredIntent(ctx context.Context, access database.AccessContext, request CreateRequest,
	runID, conversationID, conversationTurnID string, intent queryintent.Intent) (Run, error) {
	if intent == (queryintent.Intent{}) {
		return Run{}, &Error{code: CodeInvalid, clarification: intentExecutionUnavailableClarification}
	}
	if service == nil || service.intentExecutor == nil {
		return Run{}, &Error{code: CodeUnavailable, clarification: intentExecutionUnavailableClarification}
	}
	return service.intentExecutor.ExecuteIntent(ctx, access, IntentExecutionRequest{
		WorkspaceID:        request.WorkspaceID,
		RunID:              runID,
		ConversationID:     conversationID,
		ConversationTurnID: conversationTurnID,
		IdempotencyKey:     request.IdempotencyKey,
		AnswerMode:         request.AnswerMode,
		CreateConversation: request.ConversationID == "",
		Intent:             intent,
	})
}

func hasApprovedDefinition(definitions []metricdef.Definition, workspaceID string) bool {
	for _, definition := range definitions {
		if definition.WorkspaceID() == workspaceID && definition.Status() == metricdef.StatusApproved {
			return true
		}
	}
	return false
}

// definitionCatalog adapts the listed definitions to queryintent's lookup
// boundary. It copies the slice so the validator can never observe a later
// mutation of the caller's slice.
func definitionCatalog(workspaceID string, definitions []metricdef.Definition) queryintent.Catalog {
	copied := make([]metricdef.Definition, len(definitions))
	copy(copied, definitions)
	return queryintent.CatalogFunc(func(catalogWorkspaceID, metricID string) ([]metricdef.Definition, bool) {
		if catalogWorkspaceID != workspaceID {
			return nil, false
		}
		var versions []metricdef.Definition
		for _, definition := range copied {
			if definition.WorkspaceID() == workspaceID && definition.ID() == metricID {
				versions = append(versions, definition)
			}
		}
		if len(versions) == 0 {
			return nil, false
		}
		return versions, true
	})
}

// invalidProposalRefusal obtains the package's own invalid-proposal refusal
// through its only public entry point: a zero proposal is always invalid.
func invalidProposalRefusal(validator queryintent.Validator) error {
	if _, err := validator.Validate(queryintent.Proposal{}); err != nil {
		return err
	}
	// Defensive: a zero proposal must never validate. Stay content-free.
	return &Error{code: CodeInvalid}
}

// refusalAsError wraps a typed queryintent refusal as this authority's
// REQUEST_INVALID error, keeping the typed cause reachable through
// queryintent.CodeOf and queryintent.ClarificationOf for the transport and the
// UI.
func refusalAsError(refusal error) error {
	var typed *queryintent.Error
	if errors.As(refusal, &typed) {
		return &Error{code: CodeInvalid, cause: typed}
	}
	return &Error{code: CodeInvalid, cause: refusal}
}

// intentAccessContextKey threads the request's already-validated access
// context from the gate into a proposer. Propose's interface signature carries
// no AccessContext, and a proposer that lists a workspace's definitions must
// still re-check access exactly like every other protected read, so the gate
// hands it the same access value it is already using -- never a wider one and
// never reconstructed from model/user input.
type intentAccessContextKey struct{}

func contextWithIntentAccess(ctx context.Context, access database.AccessContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, intentAccessContextKey{}, access)
}

func intentAccessFromContext(ctx context.Context) (database.AccessContext, bool) {
	if ctx == nil {
		return database.AccessContext{}, false
	}
	access, ok := ctx.Value(intentAccessContextKey{}).(database.AccessContext)
	return access, ok
}

// plannerIntentProposer is the production QueryIntentProposer. There is no
// model provider: it derives at most one proposal from the SAME access-
// re-checked definition catalog the validator uses and the SAME deterministic
// planner the legacy path uses. It never emits SQL, free text or a query: only
// the closed {metric_id, version, period, filters, output, as_of} shape. When
// the question cannot be tied to exactly one APPROVED definition it returns
// ok=false and the gate refuses with a clarification instead of guessing.
type plannerIntentProposer struct {
	service     *Service
	definitions MetricDefinitionLister
}

// NewPlannerIntentProposer builds the production proposer over the workspace's
// access-re-checked definition catalog and the question authority's existing
// deterministic planner/calendar services. It adds no dependency.
func NewPlannerIntentProposer(service *Service, definitions MetricDefinitionLister) QueryIntentProposer {
	return &plannerIntentProposer{service: service, definitions: definitions}
}

// Propose implements QueryIntentProposer. A nil service/catalog, a missing or
// invalid access context, a failed catalog read, no unambiguous APPROVED
// definition, an unresolvable planner outcome or a failed reporting-calendar
// read all yield ok=false -- the gate then produces a typed clarification and
// never falls through to free-text planning.
func (proposer *plannerIntentProposer) Propose(ctx context.Context, workspaceID, questionText string) (queryintent.Proposal, bool) {
	if proposer == nil || proposer.service == nil || proposer.definitions == nil {
		return queryintent.Proposal{}, false
	}
	access, ok := intentAccessFromContext(ctx)
	if !ok || access.Validate() != nil || !validOpaque(workspaceID) || strings.TrimSpace(questionText) == "" {
		return queryintent.Proposal{}, false
	}
	definitions, err := proposer.definitions.List(ctx, access, workspaceID)
	if err != nil {
		return queryintent.Proposal{}, false
	}
	definition, ok := selectApprovedDefinition(definitions, workspaceID, questionText)
	if !ok {
		return queryintent.Proposal{}, false
	}
	planned, err := proposer.service.planQuestion(questionText)
	if err != nil {
		return queryintent.Proposal{}, false
	}
	today, _, err := proposer.service.reportingCalendar(ctx, access)
	if err != nil {
		return queryintent.Proposal{}, false
	}
	start, end, ok := intentPeriodWindow(planned.Filters, today, definition.Grain())
	if !ok {
		return queryintent.Proposal{}, false
	}
	now := time.Now
	if proposer.service.now != nil {
		now = proposer.service.now
	}
	return queryintent.Proposal{
		MetricID: definition.ID(),
		Version:  definition.Version(),
		Period:   queryintent.Period{Grain: definition.Grain(), Start: start, End: end},
		Filters:  intentPlanFilters(planned),
		Output:   intentPlanOutput(planned),
		AsOf:     now().UTC(),
	}, true
}

// selectApprovedDefinition picks exactly one APPROVED definition for the
// question: the sole match by name or entity key, or the workspace's only
// APPROVED definition when no name matches. Two matches (or several APPROVED
// definitions with none matching) are ambiguous and refuse, never guess.
func selectApprovedDefinition(definitions []metricdef.Definition, workspaceID, questionText string) (metricdef.Definition, bool) {
	lowered := strings.ToLower(questionText)
	var matched, approved []metricdef.Definition
	for _, definition := range definitions {
		if definition.WorkspaceID() != workspaceID || definition.Status() != metricdef.StatusApproved {
			continue
		}
		approved = append(approved, definition)
		name := strings.ToLower(strings.TrimSpace(definition.Name()))
		if name != "" && strings.Contains(lowered, name) {
			matched = append(matched, definition)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(definition.EntityKey()))
		if key != "" && strings.Contains(lowered, key) {
			matched = append(matched, definition)
		}
	}
	if len(matched) == 1 {
		return matched[0], true
	}
	if len(matched) == 0 && len(approved) == 1 {
		return approved[0], true
	}
	return metricdef.Definition{}, false
}

// intentPlanFilters maps the planner's already-validated equality conditions to
// the filter names queryintent validates against the definition's allowed set.
// A condition the planner did not recognize is simply not proposed; the
// validator (not this adapter) decides what the definition allows.
func intentPlanFilters(planned planner.Plan) []string {
	var filters []string
	for _, filter := range planned.Filters {
		if strings.HasPrefix(filter.Name, "equals:") {
			filters = append(filters, strings.TrimPrefix(filter.Name, "equals:"))
		}
	}
	return filters
}

// intentPlanOutput maps the planner's requested reduction to queryintent's
// closed output vocabulary: LIST is a rowset, every other aggregate is a value.
func intentPlanOutput(planned planner.Plan) queryintent.Output {
	if planned.Operation == planner.Aggregate && planned.Aggregate != nil && planned.Aggregate.Function == "LIST" {
		return queryintent.OutputRowset
	}
	return queryintent.OutputValue
}

// intentPeriodWindow resolves the proposal's period from the planner's own
// time conditions and the tenant reporting calendar. A scoped window is aligned
// to the definition grain so the result is a whole grain period; no time
// condition at all yields the current grain window containing `today`.
func intentPeriodWindow(filters []planner.Filter, today time.Time, grain metricdef.PeriodGrain) (time.Time, time.Time, bool) {
	if start, end, scoped, ok := snapshotWindow(filters, today); ok && scoped {
		return intentAlignWindow(start, end, grain)
	}
	return intentGrainWindow(today, grain)
}

func intentAlignWindow(start, end time.Time, grain metricdef.PeriodGrain) (time.Time, time.Time, bool) {
	if grain == "" || grain == metricdef.GrainDay {
		if !start.Before(end) {
			return time.Time{}, time.Time{}, false
		}
		return start, end, true
	}
	aligned := intentGrainStart(start, grain)
	alignedEnd := intentGrainEnd(aligned, grain)
	if !aligned.Before(alignedEnd) {
		return time.Time{}, time.Time{}, false
	}
	return aligned, alignedEnd, true
}

func intentGrainWindow(day time.Time, grain metricdef.PeriodGrain) (time.Time, time.Time, bool) {
	start := intentGrainStart(day, grain)
	end := intentGrainEnd(start, grain)
	if !start.Before(end) {
		return time.Time{}, time.Time{}, false
	}
	return start, end, true
}

func intentGrainStart(day time.Time, grain metricdef.PeriodGrain) time.Time {
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	switch grain {
	case metricdef.GrainWeek:
		offset := (int(day.Weekday()) + 6) % 7
		return day.AddDate(0, 0, -offset)
	case metricdef.GrainMonth:
		return time.Date(day.Year(), day.Month(), 1, 0, 0, 0, 0, time.UTC)
	case metricdef.GrainQuarter:
		month := time.Month(((int(day.Month())-1)/3)*3 + 1)
		return time.Date(day.Year(), month, 1, 0, 0, 0, 0, time.UTC)
	case metricdef.GrainYear:
		return time.Date(day.Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
	default:
		return day
	}
}

func intentGrainEnd(start time.Time, grain metricdef.PeriodGrain) time.Time {
	switch grain {
	case metricdef.GrainWeek:
		return start.AddDate(0, 0, 7)
	case metricdef.GrainMonth:
		return start.AddDate(0, 1, 0)
	case metricdef.GrainQuarter:
		return start.AddDate(0, 3, 0)
	case metricdef.GrainYear:
		return start.AddDate(1, 0, 0)
	default:
		return start.AddDate(0, 0, 1)
	}
}

// serviceIntentExecutor is the production QueryIntentExecutor. It receives
// only a sealed Intent plus run identity, re-checks the exact APPROVED
// definition version (fail-closed if it was retired or superseded between
// validation and execution), and drives the authority's existing persisted-run
// and structured-snapshot reduction machinery. No model, SQL or free-text plan
// is added; when the validated intent cannot be bound to a structured
// reduction the executor refuses with a clarification instead of falling back
// to retrieval.
type serviceIntentExecutor struct {
	service *Service
}

// NewServiceIntentExecutor builds the production sealed-intent executor over
// the question authority's existing services. It adds no dependency.
func NewServiceIntentExecutor(service *Service) QueryIntentExecutor {
	return &serviceIntentExecutor{service: service}
}

// ExecuteIntent implements QueryIntentExecutor.
func (executor *serviceIntentExecutor) ExecuteIntent(ctx context.Context, access database.AccessContext, request IntentExecutionRequest) (Run, error) {
	if executor == nil || executor.service == nil {
		return Run{}, &Error{code: CodeUnavailable, clarification: intentExecutionUnavailableClarification}
	}
	return executor.service.executeValidatedIntent(ctx, access, request)
}

func (service *Service) executeValidatedIntent(ctx context.Context, access database.AccessContext, request IntentExecutionRequest) (Run, error) {
	if service == nil || request.Intent == (queryintent.Intent{}) || service.intentDefinitions == nil {
		return Run{}, &Error{code: CodeInvalid, clarification: intentExecutionUnavailableClarification}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	definitions, err := service.intentDefinitions.List(ctx, access, request.WorkspaceID)
	if err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	definition, found := findApprovedDefinitionVersion(definitions, request.WorkspaceID,
		request.Intent.MetricID(), request.Intent.Version())
	if !found {
		// The definition was retired, superseded or is no longer readable
		// between validation and execution: fail closed rather than execute
		// against a stale or unapproved binding.
		return Run{}, &Error{code: CodeInvalid, clarification: intentExecutionUnavailableClarification}
	}
	questionText, err := canonicalQuestion(intentExecutionQuestion(definition))
	if err != nil {
		return Run{}, &Error{code: CodeInvalid, clarification: intentExecutionUnavailableClarification}
	}
	planned, err := service.planQuestion(questionText)
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Aggregate || planned.Aggregate == nil {
		// The validated intent cannot be bound to a structured reduction in
		// this workspace. Refuse with a clarification rather than falling back
		// to free-text planning/retrieval.
		return Run{}, &Error{code: CodeInvalid, clarification: intentExecutionUnavailableClarification}
	}
	runRequest := CreateRequest{WorkspaceID: request.WorkspaceID, IdempotencyKey: request.IdempotencyKey, AnswerMode: request.AnswerMode}
	if !request.CreateConversation {
		runRequest.ConversationID = request.ConversationID
	}
	hash := requestHash(questionText, runRequest.AnswerMode, runRequest.ConversationID)
	if replay, found, replayErr := service.lookupIdempotency(ctx, access, runRequest.IdempotencyKey, hash, request.WorkspaceID); replayErr != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: replayErr}
	} else if found {
		return replay, nil
	}
	started, err := service.start(ctx, access, runRequest, questionText, planned, hash,
		request.RunID, request.ConversationID, request.ConversationTurnID)
	if err != nil {
		return Run{}, err
	}
	// The sealed intent and APPROVED version ride beside the producing run's own
	// persisted corpus_status, so the unified AnswerResult reports the run's
	// derived completeness (PARTIAL for a partial corpus) rather than an
	// asserted COMPLETE.
	intentIdentity := answerResultIdentityForRunStatus(
		answerResultIdentityForIntent(request.Intent, definition), started.CorpusStatus)
	answered, execErr := service.answerStructuredAggregate(ctx, access, request.RunID, request.WorkspaceID, questionText, planned,
		intentIdentity)
	if execErr != nil {
		service.reportFailureCleanup(ctx, access, request.RunID, request.WorkspaceID, execErr)
		return Run{}, execErr
	}
	if !answered {
		refusal := &Error{code: CodeUnavailable, clarification: intentExecutionUnavailableClarification}
		service.reportFailureCleanup(ctx, access, request.RunID, request.WorkspaceID, refusal)
		return Run{}, refusal
	}
	return service.Get(ctx, access, request.WorkspaceID, request.RunID)
}

// findApprovedDefinitionVersion re-checks the exact APPROVED definition
// version the sealed intent was validated against. Any other status (DRAFT,
// RETIRED) or an unknown version is not found.
func findApprovedDefinitionVersion(definitions []metricdef.Definition, workspaceID, metricID string, version int64) (metricdef.Definition, bool) {
	for _, definition := range definitions {
		if definition.WorkspaceID() == workspaceID && definition.ID() == metricID &&
			definition.Version() == version && definition.Status() == metricdef.StatusApproved {
			return definition, true
		}
	}
	return metricdef.Definition{}, false
}

// answerResultIdentityForIntent projects the run's own sealed QueryIntent and
// the re-checked APPROVED definition version into the identity the structured
// aggregate reducer carries into R2 Outcome 3's unified AnswerResult. Every
// member is data this run already holds: the intent was sealed by the server
// validator, and the metric version is the definition the executor re-checked
// immediately before execution. The projection never fabricates a filter value
// or a period the intent did not carry, so a member the intent left empty stays
// absent rather than invented.
func answerResultIdentityForIntent(intent queryintent.Intent, definition metricdef.Definition) answerResultIdentity {
	period := intent.Period()
	names := intent.Filters()
	filters := make([]AnswerFilter, 0, len(names))
	for _, name := range names {
		filters = append(filters, AnswerFilter{Name: name})
	}
	return answerResultIdentity{
		Intent: &AnswerIntent{
			MetricID: intent.MetricID(),
			Version:  intent.Version(),
			Period: &AnswerPeriod{
				From: period.Start.Format("2006-01-02"),
				To:   period.End.AddDate(0, 0, -1).Format("2006-01-02"),
			},
			Filters: filters,
			Output:  string(intent.Output()),
			AsOf:    intent.AsOf().Format(time.RFC3339Nano),
		},
		MetricVersion: strconv.FormatInt(definition.Version(), 10),
	}
}

// intentExecutionQuestion builds the server-owned question text the existing
// structured planner/reducer resolves the definition's source scope by. It
// names only the validated definition's own server-stored name (or entity
// key), never model or user text, and carries no query, filter or SQL.
func intentExecutionQuestion(definition metricdef.Definition) string {
	subject := strings.TrimSpace(definition.Name())
	if subject == "" {
		subject = strings.TrimSpace(definition.EntityKey())
	}
	if subject == "" {
		return "\u0441\u043a\u043e\u043b\u044c\u043a\u043e"
	}
	return "\u0441\u043a\u043e\u043b\u044c\u043a\u043e " + subject
}
