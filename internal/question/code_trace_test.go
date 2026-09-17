package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func codeTracePlan(t *testing.T) planner.Plan {
	t.Helper()
	planned, err := planner.Default().Plan("Which business processes are implemented in code and only described?")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Status != planner.Ready || planned.Operation != planner.CodeTrace {
		t.Fatalf("plan=%+v, want ready CODE_TRACE", planned)
	}
	return planned
}

func TestRenderCodeTraceUsesArbitraryExplicitKeyAndSourceMetadata(t *testing.T) {
	planned := codeTracePlan(t)
	selected := []candidate{
		{ID: "evidence-code", ParserProfileRevision: "source-code-v1", Text: []byte("billing_flow = implemented\n")},
		{ID: "evidence-doc", ParserProfileRevision: "text-v1", Text: []byte("billing_flow = described\n")},
	}
	answer, citations := renderCodeTrace("workspace-a", planned, selected)
	if !strings.Contains(answer, "billing_flow") || !strings.Contains(answer, "implemented") || !strings.Contains(answer, "described") {
		t.Fatalf("answer=%q", answer)
	}
	if len(citations) != 2 || citations[0].EvidenceFragment == citations[1].EvidenceFragment {
		t.Fatalf("citations=%+v, want both source Evidence IDs", citations)
	}
	conflicts := codeTraceConflicts(planned, selected)
	if len(conflicts) != 1 || conflicts[0].Code != "CONFLICT_CODE_TRACE_VALUE" || len(conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("conflicts=%+v", conflicts)
	}
}

func TestRenderCodeTraceDoesNotGuessMissingSourceClass(t *testing.T) {
	planned := codeTracePlan(t)
	selected := []candidate{
		{ID: "evidence-unknown", Text: []byte("billing_flow = implemented\n")},
		{ID: "evidence-doc", ParserProfileRevision: "text-v1", Text: []byte("billing_flow = described\n")},
	}
	if answer, citations := renderCodeTrace("workspace-a", planned, selected); answer != "" || len(citations) != 0 {
		t.Fatalf("missing source class was promoted: answer=%q citations=%+v", answer, citations)
	}
}

func TestRenderCodeTraceSupportsQualifiedGitObjectType(t *testing.T) {
	planned := codeTracePlan(t)
	selected := []candidate{
		{ID: "evidence-commit", ObjectType: "GIT_COMMIT", Text: []byte("etl_flow = implemented\n")},
		{ID: "evidence-spec", ObjectType: "FILE", CanonicalFormat: "TEXT", Text: []byte("etl_flow = described\n")},
	}
	answer, citations := renderCodeTrace("workspace-a", planned, selected)
	if !strings.Contains(answer, "etl_flow") || len(citations) != 2 {
		t.Fatalf("git trace answer=%q citations=%+v", answer, citations)
	}
}

func TestRenderCodeTracePreservesClassificationAfterLayoutUpgrade(t *testing.T) {
	planned := codeTracePlan(t)
	selected := []candidate{
		{ID: "code-layout", ParserProfileRevision: canon.TextLayoutParserRevision("source-code-v1"), Text: []byte("billing_flow = implemented\n")},
		{ID: "doc-layout", ParserProfileRevision: canon.TextLayoutParserRevision("text-v1"), Text: []byte("billing_flow = described\n")},
	}
	answer, citations := renderCodeTrace("workspace-a", planned, selected)
	if !strings.Contains(answer, "billing_flow") || len(citations) != 2 {
		t.Fatalf("layout upgrade changed code classification: answer=%q citations=%+v", answer, citations)
	}
}
