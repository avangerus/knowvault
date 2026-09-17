// R2 Outcome 3 mutation anchors for the remaining QueryIntent validation
// classes: an unknown metric id and a malformed period.
//
// These controls are protected-independent: no PostgreSQL, no model provider
// and no protected file is touched. They drive the real Create entry point,
// assert that the server refuses the model proposal with the typed queryintent
// code and its wrapped clarification text, and arm the idempotency seam so that
// reaching the free-text path is a test failure. Together with the retired
// version and disallowed filter controls they give every refusal branch of
// internal/queryintent/intent.go's Validator a killed RED-only mutant in
// tests/contracts/mutation-registry.json.
//
// The helper seams (gateTestCatalog / gateTestProposer / gateTestExecutor and
// armNoLegacyPath) are defined in intent_gate_test.go and
// outcome3_negative_controls_test.go.
package question

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// TestOutcome3UnknownMetricRefusedNeverExecuted proves that a model proposal
// naming a metric id the workspace catalog does not know is refused with the
// typed CodeUnknownMetric clarification and that the sealed-intent executor is
// never consulted.
func TestOutcome3UnknownMetricRefusedNeverExecuted(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	proposal := gateValidProposal()
	proposal.MetricID = "md_missing" // never present in the workspace catalog.
	proposer := &gateTestProposer{proposal: proposal, ok: true}
	service.intentProposer = proposer
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	armNoLegacyPath(t, service)

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err == nil {
		t.Fatal("Create over an unknown metric = nil, want a typed refusal")
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeUnknownMetric {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeUnknownMetric)
	}
	if clarification := ClarificationOf(err); clarification == "" || clarification != queryintent.ClarificationOf(err) {
		t.Fatalf("ClarificationOf(err) = %q, want the wrapped non-empty refusal text", clarification)
	}
	if run.ID != "" || run.Answer != "" {
		t.Fatalf("refusal returned a run: %#v", run)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on an unknown-metric refusal", executor.calls)
	}
	if proposer.calls != 1 {
		t.Fatalf("proposer calls = %d, want exactly 1", proposer.calls)
	}
	if len(journal.order) != 1 || journal.order[0] != "admission" {
		t.Fatalf("execution order = %v, want only the admission", journal.order)
	}
}

// TestOutcome3MalformedPeriodRefusedNeverExecuted proves that a model proposal
// whose period grain does not match the APPROVED definition's grain is refused
// with the typed CodeMalformedPeriod clarification and never executed.
func TestOutcome3MalformedPeriodRefusedNeverExecuted(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.intentDefinitions = &gateTestCatalog{definitions: gateTestDefinitions(t)}
	proposal := gateValidProposal()
	proposal.Period.Grain = metricdef.GrainDay // md_revenue is defined at month grain.
	proposer := &gateTestProposer{proposal: proposal, ok: true}
	service.intentProposer = proposer
	executor := &gateTestExecutor{}
	service.intentExecutor = executor
	armNoLegacyPath(t, service)

	run, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest())
	if err == nil {
		t.Fatal("Create over a malformed period = nil, want a typed refusal")
	}
	if got := queryintent.CodeOf(err); got != queryintent.CodeMalformedPeriod {
		t.Fatalf("queryintent.CodeOf(err) = %q, want %q", got, queryintent.CodeMalformedPeriod)
	}
	if clarification := ClarificationOf(err); clarification == "" || clarification != queryintent.ClarificationOf(err) {
		t.Fatalf("ClarificationOf(err) = %q, want the wrapped non-empty refusal text", clarification)
	}
	if run.ID != "" || run.Answer != "" {
		t.Fatalf("refusal returned a run: %#v", run)
	}
	if executor.calls != 0 {
		t.Fatalf("executor calls = %d, want 0 on a malformed-period refusal", executor.calls)
	}
	if proposer.calls != 1 {
		t.Fatalf("proposer calls = %d, want exactly 1", proposer.calls)
	}
	if len(journal.order) != 1 || journal.order[0] != "admission" {
		t.Fatalf("execution order = %v, want only the admission", journal.order)
	}
}
