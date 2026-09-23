package question

import (
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestTypedMetricV2FrozenAnswer(t *testing.T) {
	call, dependency := metricAnswerFixture(t, false)
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192},
		Calls: []ToolCallRecord{call}, PresentationVersion: presentationString("metric-comparison-v2")}
	for language, expected := range map[string]string{
		"en": "sha256:6af8ae50ba86f86c8dc8d00e6e3de29fc5fe720a45ceaf2d5d67623042659547",
		"ru": "sha256:05987c6d0e63b275260b87c9c555d3afa4274fc4c13d2889444bdc4aa212d49c",
	} {
		answer, err := renderTypedMetricAnswer("qrun_current", record, []governedQueryDependency{dependency}, nil, language)
		if err != nil {
			t.Fatal(err)
		}
		if actual := canon.Hash([]byte(answer)); actual != expected {
			t.Fatalf("stored %s v2 answer changed: %s, want %s", language, actual, expected)
		}
	}
}

func TestTypedMetricV3StillRequiresGatedCitations(t *testing.T) {
	loop := &ToolLoopRecord{PresentationVersion: presentationString("metric-comparison-v3")}
	citation := Citation{CitationID: "citation_1", Number: 1, Excerpt: "Rule", ExcerptHash: canon.Hash([]byte("Rule"))}
	if !typedMetricCitationsMatchGated(loop, []Citation{citation}, []Citation{citation}) ||
		typedMetricCitationsMatchGated(loop, []Citation{citation}, nil) {
		t.Fatal("v3 citation read did not require independent gated evidence")
	}
	changed := citation
	changed.Excerpt = "Changed rule"
	if typedMetricCitationsMatchGated(loop, []Citation{citation}, []Citation{changed}) {
		t.Fatal("v3 disclosed a changed excerpt")
	}
}
