// R2 Outcome 3 negative controls for the server-validated QueryIntent gate and
// the unified AnswerResult digest.
//
// These controls are protected-independent: no PostgreSQL, no model provider
// and no protected file is touched. They pin the refusal surface of
// internal/question/intent_gate.go (a RETIRED version and a filter outside the
// APPROVED definition's allowed set are refused with a typed queryintent
// clarification and the executor seam is never consulted), the deterministic
// tie-out of internal/question/structured_result.go's canonical result_digest
// (same validated intent + snapshot/execution identity => same digest; a
// changed value, period, filter set, completeness or metric version => a
// different digest; a PARTIAL execution stays PARTIAL), and the unchanged
// legacy path for a workspace with no APPROVED definition. The helper seams
// (gateTestCatalog / gateTestProposer / gateTestExecutor and the Create
// fixtures) are defined in intent_gate_test.go; the snapshot fixture and the
// digest carrier live in structured_result.go.
package question

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// armNoLegacyPath makes reaching the free-text planner/idempotency path a test
// failure, so a refusal or a sealed execution is proven to bypass it.
func armNoLegacyPath(t *testing.T, service *Service) {
	t.Helper()
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		t.Fatal("free-text/idempotency path was reached where only a validated intent may run")
		return Run{}, false, nil
	}
}

// TestOutcome3RetiredVersionRefusedNeverExecuted proves that a model proposal
// naming the RETIRED version of a previously APPROVED definition is refused
// with a typed queryintent clarification and that the sealed-intent executor is
// never consulted.
func TestOutcome3RetiredVersionRefusedNeverExecuted(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	proposal := gateValidProposal()
	proposal.MetricID = "md_legacy" // APPROVED, then retired by gateRetiredSeries.
	proposer := &gateTestProposer{proposal: proposal, ok: true}
	service.intentProposer = proposer
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	armNoLegacyPath(t, service)

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err == nil {
		t.Fatal("Create over a RETIRED version = nil, want a typed refusal")
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeRetiredVersion {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeRetiredVersion)
	}
	if clarification := ClarificationOf(err); clarification == "" || clarification != queryintent.ClarificationOf(err) {
		t.Fatalf("ClarificationOf(err) = %q, want the wrapped non-empty refusal text", clarification)
	}
	if run.ID != "" || run.Answer != "" {
		t.Fatalf("refusal returned a run: %#v", run)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on a retired-version refusal", executor.calls)
	}
	if proposer.calls != 1 {
		t.Fatalf("proposer calls = %d, want exactly 1", proposer.calls)
	}
	if len(journal.order) != 1 || journal.order[0] != "admission" {
		t.Fatalf("execution order = %v, want only the admission", journal.order)
	}
}

// TestOutcome3DisallowedFilterRefusedNeverExecuted proves that a model proposal
// carrying a filter outside the APPROVED definition's allowed_filters set is
// refused with a typed queryintent clarification and never executed.
func TestOutcome3DisallowedFilterRefusedNeverExecuted(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	proposal := gateValidProposal()
	proposal.Filters = []string{"salary"} // md_revenue only allows "region".
	proposer := &gateTestProposer{proposal: proposal, ok: true}
	service.intentProposer = proposer
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	armNoLegacyPath(t, service)

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err == nil {
		t.Fatal("Create with a disallowed filter = nil, want a typed refusal")
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeFilterNotAllowed {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeFilterNotAllowed)
	}
	if clarification := ClarificationOf(err); clarification == "" || clarification != queryintent.ClarificationOf(err) {
		t.Fatalf("ClarificationOf(err) = %q, want the wrapped non-empty refusal text", clarification)
	}
	if run.ID != "" || run.Answer != "" {
		t.Fatalf("refusal returned a run: %#v", run)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on a disallowed-filter refusal", executor.calls)
	}
	if len(journal.order) != 1 || journal.order[0] != "admission" {
		t.Fatalf("execution order = %v, want only the admission", journal.order)
	}
}

// TestOutcome3DigestTieOutForValidatedIntent proves the R2 Outcome 3 negative
// control on the server side: a validated intent executed twice over the same
// snapshot/execution identity produces the same canonical result_digest, while
// a changed value, period, filter set, completeness or metric version
// necessarily changes it. The digest is never a function of the per-run run_id.
func TestOutcome3DigestTieOutForValidatedIntent(t *testing.T) {
	// Seal a real intent through the gate so the projection is bound to a
	// server-validated intent, not a hand-built one.
	catalog := &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service := &Service{
		intentDefinitions: catalog,
		intentProposer:    &gateTestProposer{proposal: gateValidProposal(), ok: true},
	}
	intent, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?")
	if err != nil || !hasIntent {
		t.Fatalf("validateStructuredIntent = (%v, %v), want a sealed intent", hasIntent, err)
	}
	definition, found := findApprovedDefinitionVersion(catalog.definitions, "ws_0001", intent.MetricID(), intent.Version())
	if !found {
		t.Fatalf("no re-checked APPROVED definition for the sealed intent")
	}
	// The identity the executor projects for this run must carry the sealed
	// intent binding: a weakening that returns only the metric version would
	// leave the digest tie-out with no run's own intent to hash.
	carried := answerResultIdentityForIntent(intent, definition)
	if carried.Intent == nil {
		t.Fatal("answerResultIdentityForIntent dropped the validated intent binding")
	}
	if carried.Intent.MetricID != intent.MetricID() || carried.Intent.Version != intent.Version() {
		t.Fatalf("carried intent = %#v, want metric_id %q version %d",
			carried.Intent, intent.MetricID(), intent.Version())
	}
	if carried.Intent.Output != string(intent.Output()) {
		t.Fatalf("carried intent output = %q, want %q", carried.Intent.Output, string(intent.Output()))
	}
	if carried.Intent.Period == nil ||
		carried.Intent.Period.From != intent.Period().Start.Format("2006-01-02") ||
		carried.Intent.Period.To != intent.Period().End.AddDate(0, 0, -1).Format("2006-01-02") {
		t.Fatalf("carried intent period = %#v, want the sealed intent window", carried.Intent.Period)
	}
	metricVersion := strconv.FormatInt(definition.Version(), 10)
	if carried.MetricVersion != metricVersion {
		t.Fatalf("carried metric_version = %q, want %q", carried.MetricVersion, metricVersion)
	}
	intentAnswer := carried.Intent

	result := r2AggregateFixture(t)
	identity := func(runID, version string) answerResultIdentity {
		return answerResultIdentity{
			RunID:         runID,
			Intent:        intentAnswer,
			MetricVersion: version,
			SnapshotID:    result.sourceScopeID,
			ExecutionID:   "exec_digest_0001",
		}
	}
	first := buildAnswerResult(result, identity("run_first", metricVersion))
	second := buildAnswerResult(result, identity("run_second", metricVersion))
	if first.RunID == second.RunID {
		t.Fatal("negative control is vacuous: both runs carry the same run_id")
	}
	baseDigest := first.CanonicalDigest()
	if baseDigest == "" {
		t.Fatal("CanonicalDigest() = empty, want a deterministic digest")
	}
	if !strings.HasPrefix(baseDigest, "sha256:") || len(baseDigest) != len("sha256:")+64 {
		t.Fatalf("CanonicalDigest() = %q, want a sha256 digest", baseDigest)
	}
	if first.ResultDigest != baseDigest || second.ResultDigest != baseDigest {
		t.Fatalf("stored digests = %q / %q, want the canonical %q", first.ResultDigest, second.ResultDigest, baseDigest)
	}
	if first.CanonicalDigest() != second.CanonicalDigest() {
		t.Fatalf("same validated intent/snapshot/execution produced different digests: %s vs %s",
			first.CanonicalDigest(), second.CanonicalDigest())
	}

	changedValue := *first
	changedValue.Value = first.Value + "0"
	if changedValue.CanonicalDigest() == baseDigest {
		t.Fatal("a changed value left the digest unchanged")
	}

	changedPeriod := *first
	changedPeriod.Period = &AnswerPeriod{From: "1999-01-01", To: "1999-01-31", Label: "probe"}
	if changedPeriod.CanonicalDigest() == baseDigest {
		t.Fatal("a changed period left the digest unchanged")
	}

	changedFilters := *first
	changedFilters.Filters = []AnswerFilter{{Name: "probe_digest_column", Value: "probe"}}
	if changedFilters.CanonicalDigest() == baseDigest {
		t.Fatal("a changed filter set left the digest unchanged")
	}

	changedCompleteness := *first
	changedCompleteness.Completeness = "PARTIAL"
	if changedCompleteness.Completeness != "PARTIAL" {
		t.Fatal("PARTIAL completeness was rewritten, want it preserved verbatim")
	}
	if changedCompleteness.CanonicalDigest() == baseDigest {
		t.Fatal("a changed completeness left the digest unchanged")
	}

	changedVersion := buildAnswerResult(result, identity("run_first", "999"))
	if changedVersion.CanonicalDigest() == baseDigest {
		t.Fatal("a changed metric version left the digest unchanged")
	}
}

// TestOutcome3ValidatedIntentBindingCarriedIntoAnswerResult proves the R2
// Outcome 3 identity binding of the production validated-intent path: the
// identity projected from a sealed QueryIntent and the re-checked APPROVED
// definition carries the run's own intent and metric_version through the merge
// into the unified AnswerResult, while a run that never carried an intent
// omits both rather than inventing them.
func TestOutcome3ValidatedIntentBindingCarriedIntoAnswerResult(t *testing.T) {
	catalog := &gateTestCatalog{definitions: gateTestDefinitions(t)}
	service := &Service{
		intentDefinitions: catalog,
		intentProposer:    &gateTestProposer{proposal: gateValidProposal(), ok: true},
	}
	intent, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0440\u0443\u0447\u043a\u0438 \u0437\u0430 \u044f\u043d\u0432\u0430\u0440\u044c?")
	if err != nil || !hasIntent {
		t.Fatalf("validateStructuredIntent = (%v, %v), want a sealed intent", hasIntent, err)
	}
	definition, found := findApprovedDefinitionVersion(catalog.definitions, "ws_0001", intent.MetricID(), intent.Version())
	if !found {
		t.Fatalf("no re-checked APPROVED definition for the sealed intent")
	}
	wantVersion := strconv.FormatInt(definition.Version(), 10)

	carried := answerResultIdentityForIntent(intent, definition)
	if carried.Intent == nil {
		t.Fatal("validated-intent identity carried no intent")
	}
	if carried.Intent.MetricID != intent.MetricID() || carried.Intent.Version != intent.Version() {
		t.Fatalf("carried intent = %#v, want metric_id %q version %d",
			carried.Intent, intent.MetricID(), intent.Version())
	}
	if carried.Intent.Output != string(intent.Output()) {
		t.Fatalf("carried intent output = %q, want %q", carried.Intent.Output, string(intent.Output()))
	}
	if carried.Intent.AsOf != intent.AsOf().Format(time.RFC3339Nano) {
		t.Fatalf("carried intent as_of = %q, want %q", carried.Intent.AsOf, intent.AsOf().Format(time.RFC3339Nano))
	}
	if carried.MetricVersion != wantVersion {
		t.Fatalf("carried metric_version = %q, want %q", carried.MetricVersion, wantVersion)
	}
	if carried.Intent.Period == nil ||
		carried.Intent.Period.From != intent.Period().Start.Format("2006-01-02") ||
		carried.Intent.Period.To != intent.Period().End.AddDate(0, 0, -1).Format("2006-01-02") {
		t.Fatalf("carried intent period = %#v, want the sealed intent window", carried.Intent.Period)
	}
	if len(carried.Intent.Filters) != 1 || carried.Intent.Filters[0].Name != "region" {
		t.Fatalf("carried intent filters = %#v, want the sealed intent's filter names", carried.Intent.Filters)
	}

	// The reducer's own run/snapshot/evidence identity wins for what it owns;
	// the carried identity supplies intent + metric_version.
	base := answerResultIdentity{
		RunID: "run_intent", SnapshotID: "scope-fleet", EvidenceRefs: []string{"frg_a"},
	}
	merged := carryAnswerResultIdentity(base, carried)
	if merged.RunID != base.RunID || merged.SnapshotID != base.SnapshotID ||
		len(merged.EvidenceRefs) != 1 || merged.EvidenceRefs[0] != "frg_a" {
		t.Fatalf("base run identity lost while carrying the intent: %#v", merged)
	}
	if merged.Intent == nil || merged.MetricVersion != wantVersion {
		t.Fatalf("intent/metric_version dropped while merging: %#v", merged)
	}
	answer := buildAnswerResult(r2AggregateFixture(t), merged)
	if answer.Intent == nil || answer.Intent.MetricID != intent.MetricID() ||
		answer.Intent.Version != intent.Version() || answer.MetricVersion != wantVersion {
		t.Fatalf("AnswerResult intent/metric_version = (%#v, %q), want the sealed intent and %q",
			answer.Intent, answer.MetricVersion, wantVersion)
	}

	// A run that never carried an intent keeps the legacy R1 shape: no invented
	// intent and no invented metric_version.
	legacy := buildAnswerResult(r2AggregateFixture(t), answerResultIdentity{
		RunID: "run_legacy", SnapshotID: "scope-fleet",
	})
	if legacy.Intent != nil || legacy.MetricVersion != "" {
		t.Fatalf("legacy answer invented intent/metric_version: %#v %q", legacy.Intent, legacy.MetricVersion)
	}
}

// TestOutcome3PartialCompletenessSurvivesTheWire proves the REST/MCP
// representation of an R2 AnswerResult: a PARTIAL execution is reported PARTIAL
// and a missing unified field is omitted rather than filled with an invented
// value (the UI therefore renders "no data" for it).
func TestOutcome3PartialCompletenessSurvivesTheWire(t *testing.T) {
	partial := AnswerResult{
		Kind: "CALCULATION", Operation: "COUNT", Rule: "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a",
		Value: "3", Completeness: "PARTIAL",
		Snapshot: AnswerSnapshot{ID: "scope-fleet", RowCount: 7},
	}
	raw, err := json.Marshal(partial)
	if err != nil {
		t.Fatalf("marshal PARTIAL AnswerResult: %v", err)
	}
	if !strings.Contains(string(raw), `"completeness":"PARTIAL"`) {
		t.Fatalf("PARTIAL completeness was not preserved on the wire: %s", raw)
	}
	for _, key := range []string{
		"run_id", "intent", "rowset_ref", "metric_version", "snapshot_id",
		"execution_id", "result_digest", "freshness", "evidence_refs", "audit_receipt",
	} {
		if strings.Contains(string(raw), `"`+key+`"`) {
			t.Fatalf("missing unified field %q was invented on the wire: %s", key, raw)
		}
	}

	// The same probe drives the completeness-derivation seam the mutation
	// corpus weakens: completeness is folded from the producing run's persisted
	// corpus_status rather than asserted, so a hardcoded COMPLETE return or a
	// dropped corpus_status carry fails here (as it does in
	// TestOutcome3PartialRunDerivesPartialCompletenessFromCorpusStatus) while an
	// absent status stays empty instead of being inferred as full.
	reduced := r2AggregateFixture(t)
	derive := func(runID, corpusStatus string) string {
		base := answerResultIdentity{RunID: runID, SnapshotID: reduced.sourceScopeID}
		carried := answerResultIdentityForRunStatus(answerResultIdentity{}, corpusStatus)
		return buildAnswerResult(reduced, carryAnswerResultIdentity(base, carried)).Completeness
	}
	if got := derive("qrun_partial", "PARTIAL"); got != "PARTIAL" {
		t.Fatalf("derived completeness for a PARTIAL run = %q, want PARTIAL", got)
	}
	if got := derive("qrun_missing", ""); got != "" {
		t.Fatalf("derived completeness for an absent status = %q, want empty", got)
	}
}

// TestOutcome3PartialRunDerivesPartialCompletenessFromCorpusStatus proves the
// R2 Outcome 3 completeness rule through the real structured reduction path: a
// producing run whose persisted corpus_status is PARTIAL publishes the literal
// "PARTIAL" (never COMPLETE) across the answerStructuredAggregate identity
// merge into buildAnswerResult, a genuinely whole run still publishes
// "COMPLETE", and an absent/unreadable status stays empty rather than being
// inferred as full. The reduction fixture is r2AggregateFixture -- the real
// reduceStructuredSnapshot output -- not a hand-set AnswerResult.
func TestOutcome3PartialRunDerivesPartialCompletenessFromCorpusStatus(t *testing.T) {
	result := r2AggregateFixture(t)

	// Mirrors answerStructuredAggregate: the reducer builds the base identity
	// from the run itself, while the producing run's persisted corpus_status
	// rides in the carried identity and is merged in.
	answerForRun := func(run Run) *AnswerResult {
		base := answerResultIdentity{
			RunID: run.ID, SnapshotID: result.sourceScopeID, EvidenceRefs: []string{"frg_a"},
		}
		carried := answerResultIdentityForRunStatus(answerResultIdentity{}, run.CorpusStatus)
		merged := carryAnswerResultIdentity(base, carried)
		return buildAnswerResult(result, merged)
	}

	partial := answerForRun(Run{ID: "qrun_partial", CorpusStatus: "PARTIAL"})
	if partial.Completeness != "PARTIAL" {
		t.Fatalf("partial run completeness = %q, want PARTIAL", partial.Completeness)
	}
	if partial.Completeness == "COMPLETE" {
		t.Fatal("a PARTIAL run was reported COMPLETE")
	}

	whole := answerForRun(Run{ID: "qrun_whole", CorpusStatus: "COMPLETE"})
	if whole.Completeness != "COMPLETE" {
		t.Fatalf("whole run completeness = %q, want COMPLETE", whole.Completeness)
	}
	if whole.Completeness == "PARTIAL" {
		t.Fatal("a COMPLETE run was reported PARTIAL")
	}

	// An absent or unreadable status must not be inferred as full.
	for _, status := range []string{"", "UNREADABLE"} {
		missing := answerForRun(Run{ID: "qrun_missing", CorpusStatus: status})
		if missing.Completeness != "" {
			t.Fatalf("corpus_status %q completeness = %q, want empty", status, missing.Completeness)
		}
	}

	// The digest binds the derived completeness: the same reducer output for a
	// partial and a whole run must not tie out as the same result.
	if partial.CanonicalDigest() == whole.CanonicalDigest() {
		t.Fatal("a PARTIAL and a COMPLETE run produced the same result_digest")
	}
}

// TestOutcome3WithoutApprovedDefinitionKeepsLegacyPath proves that a workspace
// with no APPROVED definition keeps today's path unchanged: the gate returns
// (zero intent, false, nil) without invoking the proposer or the executor, and
// Create proceeds to the admission-then-idempotency-lookup path exactly as
// before R2.
func TestOutcome3WithoutApprovedDefinitionKeepsLegacyPath(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{
		definitions: []metricdef.Definition{gateNewSeries(t, "md_draft_only", metricdef.GrainDay, nil).Current()},
	}
	proposer := &gateTestProposer{proposal: gateValidProposal(), ok: true}
	service.intentProposer = proposer
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		journal.order = append(journal.order, "lookup")
		return Run{}, false, nil
	}

	intent, hasIntent, err := service.validateStructuredIntent(
		context.Background(), questionAccess(database.ActorKindHuman), "ws_0001", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?")
	if err != nil || hasIntent || intent != (queryintent.Intent{}) {
		t.Fatalf("validateStructuredIntent without an APPROVED definition = (%v, %v, %v), want (zero, false, nil)", intent, hasIntent, err)
	}
	if proposer.calls != 0 {
		t.Fatalf("proposer calls = %d, want 0 for a workspace with no APPROVED definition", proposer.calls)
	}

	// Create still reaches the legacy fresh path, where the zero database
	// refuses the subsequent write. That typed failure is expected; the
	// ordering assertion below is the unchanged-path contract.
	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest()); err == nil {
		t.Fatal("Create without an APPROVED definition = nil, want the existing fresh-path failure")
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "lookup" {
		t.Fatalf("execution order = %v, want the unchanged admission-then-lookup path", journal.order)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on the unchanged legacy path", executor.calls)
	}
}
