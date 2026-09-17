// R2 Outcome 2 contract for the server-validated QueryIntent gate.
//
// These tests drive both the gate decision (validateStructuredIntent) and the
// real Create entry point. They are protected-independent: no PostgreSQL, no
// model provider and no protected file is touched. The executor seam records
// exactly which sealed intent it received, so "the validated intent is the
// only input to execution" is asserted directly, and the idempotency seam is
// armed to fail if the free-text planner/retrieval path is ever reached for a
// workspace that has an APPROVED definition.
package question

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// gateTestAuditor satisfies metricdef's approval and retirement boundaries.
type gateTestAuditor struct{}

func (gateTestAuditor) RecordApproval(metricdef.ApprovalEvent) error     { return nil }
func (gateTestAuditor) RecordRetirement(metricdef.RetirementEvent) error { return nil }

func gateNewSeries(t *testing.T, id string, grain metricdef.PeriodGrain, filters []string) metricdef.Series {
	t.Helper()
	series, err := metricdef.NewSeries(id, "ws_0001", "usr_owner", metricdef.Spec{
		Name:           "Metric " + id,
		Source:         metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 1},
		EntityKey:      "order_id",
		Grain:          grain,
		Unit:           "RUB",
		AllowedFilters: filters,
	})
	if err != nil {
		t.Fatalf("metricdef.NewSeries(%q) = %v", id, err)
	}
	return series
}

func gateApprovedSeries(t *testing.T, id string, grain metricdef.PeriodGrain, filters []string) metricdef.Series {
	t.Helper()
	approved, err := gateNewSeries(t, id, grain, filters).Approve("usr_owner", gateTestAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Approve(%q) = %v", id, err)
	}
	return approved
}

func gateRetiredSeries(t *testing.T, id string, grain metricdef.PeriodGrain, filters []string) metricdef.Series {
	t.Helper()
	retired, err := gateApprovedSeries(t, id, grain, filters).Retire("usr_owner", gateTestAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Retire(%q) = %v", id, err)
	}
	return retired
}

// gateTestCatalog is the access-re-checked definition lister seam.
type gateTestCatalog struct {
	definitions []metricdef.Definition
	err         error
	calls       int
}

func (catalog *gateTestCatalog) List(_ context.Context, _ database.AccessContext, _ string) ([]metricdef.Definition, error) {
	catalog.calls++
	if catalog.err != nil {
		return nil, catalog.err
	}
	return catalog.definitions, nil
}

// gateTestProposer is the model-proposal seam.
type gateTestProposer struct {
	proposal queryintent.Proposal
	ok       bool
	calls    int
}

func (proposer *gateTestProposer) Propose(_ context.Context, _, _ string) (queryintent.Proposal, bool) {
	proposer.calls++
	return proposer.proposal, proposer.ok
}

// gateTestExecutor is the sealed-intent execution seam.
type gateTestExecutor struct {
	calls    int
	received queryintent.Intent
	run      Run
	err      error
}

func (executor *gateTestExecutor) ExecuteIntent(_ context.Context, _ database.AccessContext, request IntentExecutionRequest) (Run, error) {
	executor.calls++
	executor.received = request.Intent
	if executor.err != nil {
		return Run{}, executor.err
	}
	return executor.run, nil
}

func gateValidProposal() queryintent.Proposal {
	return queryintent.Proposal{
		MetricID: "md_revenue",
		Version:  1,
		Period: queryintent.Period{
			Grain: metricdef.GrainMonth,
			Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		Filters: []string{"region"},
		Output:  queryintent.OutputValue,
		AsOf:    time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
	}
}

func gateTestDefinitions(t *testing.T) []metricdef.Definition {
	t.Helper()
	return []metricdef.Definition{
		gateApprovedSeries(t, "md_revenue", metricdef.GrainMonth, []string{"region"}).Current(),
		gateApprovedSeries(t, "md_cost", metricdef.GrainMonth, []string{"region"}).Current(),
		gateNewSeries(t, "md_margin", metricdef.GrainDay, nil).Current(),
		gateRetiredSeries(t, "md_legacy", metricdef.GrainMonth, nil).Current(),
	}
}

func TestIntentGateRefusalsAreTypedAndCarryClarification(t *testing.T) {
	catalog := &gateTestCatalog{definitions: gateTestDefinitions(t)}
	base := gateValidProposal()

	cases := []struct {
		name     string
		mutate   func(queryintent.Proposal) queryintent.Proposal
		wantCode queryintent.ErrorCode
	}{
		{"unknown metric", func(p queryintent.Proposal) queryintent.Proposal {
			p.MetricID = "md_missing"
			return p
		}, queryintent.CodeUnknownMetric},
		{"unknown version", func(p queryintent.Proposal) queryintent.Proposal {
			p.Version = 9
			return p
		}, queryintent.CodeUnknownVersion},
		{"retired version", func(p queryintent.Proposal) queryintent.Proposal {
			p.MetricID = "md_legacy"
			return p
		}, queryintent.CodeRetiredVersion},
		{"draft is not approved", func(p queryintent.Proposal) queryintent.Proposal {
			p.MetricID = "md_margin"
			p.Period.Grain = metricdef.GrainDay
			return p
		}, queryintent.CodeNotApproved},
		{"filter not allowed", func(p queryintent.Proposal) queryintent.Proposal {
			p.Filters = []string{"salary"}
			return p
		}, queryintent.CodeFilterNotAllowed},
		{"period grain mismatch", func(p queryintent.Proposal) queryintent.Proposal {
			p.Period.Grain = metricdef.GrainDay
			return p
		}, queryintent.CodeMalformedPeriod},
		{"missing as-of", func(p queryintent.Proposal) queryintent.Proposal {
			p.AsOf = time.Time{}
			return p
		}, queryintent.CodeInvalidProposal},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			proposer := &gateTestProposer{proposal: testCase.mutate(base), ok: true}
			service := &Service{intentDefinitions: catalog, intentProposer: proposer}
			intent, hasIntent, err := service.validateStructuredIntent(
				context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?")
			if err == nil {
				t.Fatalf("validateStructuredIntent = nil, want a typed refusal")
			}
			if hasIntent {
				t.Fatal("refusal was reported as a validated intent")
			}
			if intent != (queryintent.Intent{}) {
				t.Fatalf("refusal returned intent %#v, want the zero value", intent)
			}
			if got := queryintent.CodeOf(err); got != testCase.wantCode {
				t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, testCase.wantCode)
			}
			clarification := ClarificationOf(err)
			if clarification == "" {
				t.Fatal("ClarificationOf(err) = empty, want the clarification text")
			}
			if clarification != queryintent.ClarificationOf(err) {
				t.Fatalf("ClarificationOf(err) = %q, want the wrapped refusal text", clarification)
			}
			for _, forbidden := range []string{"md_revenue", "md_missing", "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d"} {
				if strings.Contains(clarification, forbidden) {
					t.Fatalf("clarification %q echoed forbidden content %q", clarification, forbidden)
				}
			}
		})
	}
}

func TestIntentGateSealsApprovedProposal(t *testing.T) {
	catalog := &gateTestCatalog{definitions: gateTestDefinitions(t)}
	proposer := &gateTestProposer{proposal: gateValidProposal(), ok: true}
	service := &Service{intentDefinitions: catalog, intentProposer: proposer}

	intent, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?")
	if err != nil || !hasIntent {
		t.Fatalf("validateStructuredIntent = (%v, %v), want a sealed intent", hasIntent, err)
	}
	if intent.MetricID() != "md_revenue" || intent.Version() != 1 || intent.Unit() != "RUB" {
		t.Fatalf("sealed intent = %q/%d/%q, want md_revenue/1/RUB", intent.MetricID(), intent.Version(), intent.Unit())
	}
	if filters := intent.Filters(); len(filters) != 1 || filters[0] != "region" {
		t.Fatalf("sealed intent filters = %v, want [region]", filters)
	}
	if intent.Output() != queryintent.OutputValue {
		t.Fatalf("sealed intent output = %q, want VALUE", intent.Output())
	}
}

func TestIntentGateMissingProposerRefuses(t *testing.T) {
	catalog := &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service := &Service{intentDefinitions: catalog}

	_, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438?")
	if err == nil || hasIntent {
		t.Fatalf("validateStructuredIntent = (%v, %v), want an invalid-proposal refusal", hasIntent, err)
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeInvalidProposal {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeInvalidProposal)
	}
	if ClarificationOf(err) == "" {
		t.Fatal("ClarificationOf(err) = empty, want a clarification")
	}
}

func TestIntentGateListFailureFailsClosed(t *testing.T) {
	catalog := &gateTestCatalog{err: errors.New("injected definition read failure")}
	proposer := &gateTestProposer{proposal: gateValidProposal(), ok: true}
	service := &Service{intentDefinitions: catalog, intentProposer: proposer}

	_, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438?")
	if err == nil || hasIntent {
		t.Fatalf("validateStructuredIntent = (%v, %v), want a fail-closed unavailable error", hasIntent, err)
	}
	if got := CodeOf(err); got != CodeUnavailable {
		t.Fatalf("CodeOf(err) = %q, want %q", got, CodeUnavailable)
	}
	if proposer.calls != 0 {
		t.Fatalf("proposer calls = %d, want 0 after a failed definition read", proposer.calls)
	}
}

func TestIntentGateWithoutApprovedDefinitionShortCircuits(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{
		definitions: []metricdef.Definition{gateNewSeries(t, "md_margin", metricdef.GrainDay, nil).Current()},
	}
	proposer := &gateTestProposer{proposal: gateValidProposal(), ok: true}
	service.intentProposer = proposer
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		journal.order = append(journal.order, "lookup")
		return Run{}, false, nil
	}

	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest()); err == nil {
		t.Fatal("Create with no APPROVED definition = nil, want the existing fresh-path failure")
	}
	if proposer.calls != 0 {
		t.Fatalf("proposer calls = %d, want 0 for a workspace with no APPROVED definition", proposer.calls)
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "lookup" {
		t.Fatalf("execution order = %v, want the unchanged admission-then-lookup path", journal.order)
	}
}

func TestIntentGateCreateExecutesOnlyTheSealedIntent(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service.intentProposer = &gateTestProposer{proposal: gateValidProposal(), ok: true}
	executor := &gateTestExecutor{run: Run{ID: "qrun_gated", WorkspaceID: "ws_0001", Answer: "sealed answer"}}
	service.intentExecutor = executor
	// The free-text planner/retrieval path ends in the idempotency read; make
	// reaching it a test failure so the intent path is proven to bypass it.
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		t.Fatal("free-text/idempotency path was reached on the validated-intent path")
		return Run{}, false, nil
	}

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err != nil {
		t.Fatalf("Create = %v, want the executor's run", err)
	}
	if run.ID != "qrun_gated" || run.Answer != "sealed answer" {
		t.Fatalf("Create run = %#v, want the executor's run", run)
	}
	if executor.calls != 1 {
		t.Fatalf("executor calls = %d, want exactly 1", executor.calls)
	}
	if executor.received.MetricID() != "md_revenue" || executor.received.Version() != 1 {
		t.Fatalf("executor received %q/%d, want the sealed md_revenue/1", executor.received.MetricID(), executor.received.Version())
	}
	if len(journal.order) != 1 || journal.order[0] != "admission" {
		t.Fatalf("execution order = %v, want the admission before the governed definition read", journal.order)
	}
}

func TestIntentGateCreateRefusalNeverExecutes(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service.intentProposer = &gateTestProposer{proposal: queryintent.Proposal{
		MetricID: "md_legacy", Version: 1,
		Period: queryintent.Period{Grain: metricdef.GrainMonth,
			Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), End: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)},
		Output: queryintent.OutputValue, AsOf: time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
	}, ok: true}
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		t.Fatal("free-text/idempotency path was reached on a refused intent")
		return Run{}, false, nil
	}

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err == nil {
		t.Fatal("Create on a retired version = nil, want a typed refusal")
	}
	if run.ID != "" || run.Answer != "" {
		t.Fatalf("Create run = %#v, want no result on a refusal", run)
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeRetiredVersion {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeRetiredVersion)
	}
	if ClarificationOf(err) == "" {
		t.Fatal("ClarificationOf(err) = empty, want a clarification")
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on a refusal", executor.calls)
	}
}

func TestIntentGateMissingExecutorFailsClosed(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service.intentProposer = &gateTestProposer{proposal: gateValidProposal(), ok: true}
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		t.Fatal("free-text/idempotency path was reached without a sealed-intent executor")
		return Run{}, false, nil
	}

	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest()); err == nil {
		t.Fatal("Create without a sealed-intent executor = nil, want a fail-closed refusal")
	} else if ClarificationOf(err) == "" {
		t.Fatal("ClarificationOf(err) = empty, want a clarification")
	}
}

func TestIntentGateZeroIntentIsNeverExecuted(t *testing.T) {
	executor := &gateTestExecutor{}
	service := &Service{intentExecutor: executor}

	if _, err := service.executeStructuredIntent(context.Background(), questionAccess(database.ActorKindHuman),
		questionCreateRequest(), "qrun_1", "", "", queryintent.Intent{}); err == nil {
		t.Fatal("executeStructuredIntent(zero) = nil, want a refusal")
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 for a zero intent", executor.calls)
	}
}

// R2 Outcome 2 production wiring: composition must be able to mount a real,
// non-nil proposer/executor pair built from in-tree services, and both must
// still fail closed when their dependencies are absent -- never silently
// falling back to free-text planning.
func TestIntentGateProductionWiringIsNonNil(t *testing.T) {
	service := &Service{}
	catalog := &gateTestCatalog{}
	if NewPlannerIntentProposer(service, catalog) == nil {
		t.Fatal("NewPlannerIntentProposer = nil, want a production proposer")
	}
	if NewServiceIntentExecutor(service) == nil {
		t.Fatal("NewServiceIntentExecutor = nil, want a production executor")
	}
}

func TestIntentGateProductionProposerRefusesWithoutAccess(t *testing.T) {
	proposer := NewPlannerIntentProposer(&Service{}, &gateTestCatalog{definitions: gateTestDefinitions(t)})
	if _, ok := proposer.Propose(context.Background(), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?"); ok {
		t.Fatal("Propose without an access context = ok, want a refusal")
	}
}

func TestIntentGateProductionExecutorFailsClosedWithoutService(t *testing.T) {
	executor := NewServiceIntentExecutor(nil)
	_, err := executor.ExecuteIntent(context.Background(), questionAccess(database.ActorKindHuman), IntentExecutionRequest{})
	if err == nil || ClarificationOf(err) == "" {
		t.Fatal("ExecuteIntent without a service = nil/empty, want a fail-closed clarification")
	}
}

func TestIntentGateProductionProposerRequiresUnambiguousDefinition(t *testing.T) {
	sole := []metricdef.Definition{
		gateApprovedSeries(t, "md_revenue", metricdef.GrainMonth, []string{"region"}).Current(),
	}
	if _, ok := selectApprovedDefinition(sole, "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?"); !ok {
		t.Fatal("selectApprovedDefinition(sole approved) = false, want the only approved definition")
	}
	if _, ok := selectApprovedDefinition(gateTestDefinitions(t), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?"); ok {
		t.Fatal("selectApprovedDefinition(two approved, no name match) = true, want an ambiguous refusal")
	}
}
