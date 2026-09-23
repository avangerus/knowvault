package question

import (
	"bytes"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestStoredTypedMetricAnswerRequiresMatchingArtifactAndRunDigests(t *testing.T) {
	answer := "Assigned jobs: 3,888 on the selected day."
	hash := canon.Hash([]byte(answer))
	base := structuredAnswer{
		AnswerHash: hash,
		ToolLoop: &ToolLoopRecord{
			PresentationVersion:    presentationString("metric-comparison-v2"),
			PresentationLanguage:   presentationString("en"),
			PresentationAnswerHash: presentationString(hash),
		},
	}
	if !storedTypedMetricAnswerMatches(answer, hash, base) {
		t.Fatal("matching v2 presentation was rejected")
	}
	for _, test := range []struct {
		name, answer, runHash string
		change                func(*structuredAnswer)
	}{
		{name: "missing markdown", runHash: hash},
		{name: "changed markdown", answer: answer + " ", runHash: hash},
		{name: "missing database digest", answer: answer},
		{name: "changed database digest", answer: answer, runHash: canon.Hash([]byte("changed"))},
		{name: "missing structured digest", answer: answer, runHash: hash, change: func(s *structuredAnswer) { s.AnswerHash = "" }},
		{name: "changed structured digest", answer: answer, runHash: hash, change: func(s *structuredAnswer) { s.AnswerHash = canon.Hash([]byte("changed")) }},
		{name: "missing envelope digest", answer: answer, runHash: hash, change: func(s *structuredAnswer) { s.ToolLoop.PresentationAnswerHash = nil }},
		{name: "partial envelope", answer: answer, runHash: hash, change: func(s *structuredAnswer) { s.ToolLoop.PresentationVersion = nil }},
		{name: "unknown envelope", answer: answer, runHash: hash, change: func(s *structuredAnswer) { s.ToolLoop.PresentationVersion = presentationString("other") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			loop := *base.ToolLoop
			changed.ToolLoop = &loop
			if test.change != nil {
				test.change(&changed)
			}
			if storedTypedMetricAnswerMatches(test.answer, test.runHash, changed) {
				t.Fatal("changed v2 answer or digest was accepted")
			}
		})
	}
	if !storedTypedMetricAnswerMatches("legacy prose", "", structuredAnswer{ToolLoop: &ToolLoopRecord{}}) {
		t.Fatal("legacy v1 read behavior changed")
	}
}

func TestStructuredReadRefusesNullOrPartialPresentationFields(t *testing.T) {
	base, err := marshalStructuredAnswer("qrun_read_gate", "legacy-hash", nil, nil, nil, &ToolLoopRecord{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStructuredAnswer("qrun_read_gate", base); err != nil {
		t.Fatalf("valid legacy artifact rejected: %v", err)
	}
	for _, test := range []struct {
		name, fields string
	}{
		{"explicit null", `"presentation_version":null,`},
		{"all explicit null", `"presentation_version":null,"presentation_language":null,"presentation_answer_hash":null,`},
		{"partial fields", `"presentation_version":"metric-comparison-v2",`},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := bytes.Replace(base, []byte(`"tool_loop":{`), []byte(`"tool_loop":{`+test.fields), 1)
			if bytes.Equal(changed, base) {
				t.Fatal("fixture did not locate tool loop")
			}
			if _, err := decodeStructuredAnswer("qrun_read_gate", changed); err == nil {
				t.Fatal("malformed presentation fields were accepted")
			}
		})
	}
}
