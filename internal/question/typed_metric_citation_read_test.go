package question

import (
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestTypedMetricCitationsMatchIndependentGatedArtifacts(t *testing.T) {
	text := "The source defines this metric."
	first := Citation{CitationID: "citation_1", Number: 1, Excerpt: text, ExcerptHash: canon.Hash([]byte(text))}
	second := Citation{CitationID: "citation_2", Number: 2, Excerpt: "Second source", ExcerptHash: canon.Hash([]byte("Second source"))}
	version := "metric-comparison-v2"
	loop := &ToolLoopRecord{PresentationVersion: &version}
	if !typedMetricCitationsMatchGated(loop, []Citation{first, second}, []Citation{second, first}) {
		t.Fatal("matching independently gated excerpts refused")
	}
	for _, test := range []struct {
		name       string
		structured []Citation
		gated      []Citation
	}{
		{"changed artifact text", []Citation{first}, []Citation{{CitationID: first.CitationID, Number: first.Number, Excerpt: "Changed", ExcerptHash: first.ExcerptHash}}},
		{"changed metadata hash", []Citation{first}, []Citation{{CitationID: first.CitationID, Number: first.Number, Excerpt: text, ExcerptHash: canon.Hash([]byte("Changed"))}}},
		{"changed structured text", []Citation{{CitationID: first.CitationID, Number: first.Number, Excerpt: "Changed", ExcerptHash: first.ExcerptHash}}, []Citation{first}},
		{"changed structured hash", []Citation{{CitationID: first.CitationID, Number: first.Number, Excerpt: text, ExcerptHash: canon.Hash([]byte("Changed"))}}, []Citation{first}},
		{"changed citation number", []Citation{{CitationID: first.CitationID, Number: 2, Excerpt: text, ExcerptHash: first.ExcerptHash}}, []Citation{first}},
		{"changed citation id", []Citation{{CitationID: "citation_other", Number: 1, Excerpt: text, ExcerptHash: first.ExcerptHash}}, []Citation{first}},
		{"missing gated citation", []Citation{first, second}, []Citation{first}},
		{"extra gated citation", []Citation{first}, []Citation{first, second}},
		{"duplicate gated id", []Citation{first, second}, []Citation{first, first}},
		{"duplicate structured id", []Citation{first, first}, []Citation{first, second}},
		{"duplicate gated number", []Citation{first, second}, []Citation{first, {CitationID: second.CitationID, Number: first.Number, Excerpt: second.Excerpt, ExcerptHash: second.ExcerptHash}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if typedMetricCitationsMatchGated(loop, test.structured, test.gated) {
				t.Fatal("changed v2 citation or independent artifact was accepted")
			}
		})
	}
	if !typedMetricCitationsMatchGated(nil, []Citation{first}, nil) {
		t.Fatal("legacy citation behavior changed")
	}
}
