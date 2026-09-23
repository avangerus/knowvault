package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func presentationString(value string) *string { return &value }

func TestToolLoopPresentationEnvelopeBindsCanonicalAnswer(t *testing.T) {
	call, dependency := metricAnswerFixture(t, false)
	record := &ToolLoopRecord{
		Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192},
		Calls:   []ToolCallRecord{call}, AllClaimsBound: true, ClaimEvidenceVersion: "v1",
	}
	claim := toolClaim{Text: "The comparison is available.", Citations: []toolCitation{}, LiveReads: []toolLiveReadReference{{
		ResultID: call.Evidence.AttemptID, ReceiptDigest: call.Evidence.ReceiptDigest,
	}}}
	setPersistedToolAnswer(t, record, toolAnswer{Claims: []toolClaim{claim}})
	record.ClaimEvidence = []ToolClaimEvidence{{TextHash: canon.Hash([]byte(claim.Text)), LiveReads: claim.LiveReads}}
	dependencies := []governedQueryDependency{dependency}
	if _, _, valid := governedQueryToolExecutions("qrun_current", dependencies, record); !valid {
		t.Fatal("metric fixture dependencies do not bind")
	}
	if _, ok := finalToolAnswerFromRecord(record); !ok {
		t.Fatal("metric fixture final answer does not parse")
	}
	canonical, err := renderTypedMetricAnswer("qrun_current", record, dependencies, nil, "en")
	if err != nil {
		t.Fatal(err)
	}
	if !validateToolLoopClaimEvidence("qrun_current", claim.Text+" [Live result 1]", record, dependencies, nil) {
		t.Fatal("legacy v1 claim answer was rejected")
	}
	record.PresentationVersion = presentationString("metric-comparison-v2")
	record.PresentationLanguage = presentationString("en")
	record.PresentationAnswerHash = presentationString(canon.Hash([]byte(canonical)))
	for _, text := range []string{canonical, ""} { // Empty text is the marshal/decode sentinel.
		if !validateToolLoopClaimEvidence("qrun_current", text, record, dependencies, nil) {
			t.Fatalf("valid v2 answer %q was rejected", text)
		}
	}
	russian, err := renderTypedMetricAnswer("qrun_current", record, dependencies, nil, "ru")
	if err != nil {
		t.Fatal(err)
	}
	russianRecord := *record
	russianRecord.PresentationLanguage = presentationString("ru")
	russianRecord.PresentationAnswerHash = presentationString(canon.Hash([]byte(russian)))
	if !validateToolLoopClaimEvidence("qrun_current", russian, &russianRecord, dependencies, nil) {
		t.Fatal("valid Russian v2 answer was rejected")
	}
	for _, test := range []struct {
		name   string
		answer string
		mutate func(*ToolLoopRecord, *[]governedQueryDependency)
	}{
		{"tampered answer", canonical + " extra", nil},
		{"legacy model prose", claim.Text + " [Live result 1]", nil},
		{"tampered hash", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationAnswerHash = presentationString(canon.Hash([]byte("forged")))
		}},
		{"tampered hash with no answer sentinel", "", func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationAnswerHash = presentationString(canon.Hash([]byte("forged")))
		}},
		{"tampered v1 claim binding", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.ClaimEvidence = []ToolClaimEvidence{{TextHash: canon.Hash([]byte("forged")), LiveReads: claim.LiveReads}}
		}},
		{"missing v1 claim binding", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.ClaimEvidenceVersion = ""
			r.ClaimEvidence = nil
		}},
		{"unknown version", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationVersion = presentationString("metric-comparison-v3")
		}},
		{"missing version", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationVersion = nil
		}},
		{"empty language", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationLanguage = presentationString("")
		}},
		{"missing hash", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationAnswerHash = nil
		}},
		{"unknown language", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.PresentationLanguage = presentationString("de")
		}},
		{"tampered metric result", canonical, func(r *ToolLoopRecord, _ *[]governedQueryDependency) {
			r.Calls = append([]ToolCallRecord(nil), r.Calls...)
			r.Calls[0].Result.Text = strings.Replace(r.Calls[0].Result.Text, "3888", "3889", 1)
		}},
		{"revoked dependency", canonical, func(_ *ToolLoopRecord, d *[]governedQueryDependency) {
			*d = nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := *record
			bound := append([]governedQueryDependency(nil), dependencies...)
			if test.mutate != nil {
				test.mutate(&changed, &bound)
			}
			if validateToolLoopClaimEvidence("qrun_current", test.answer, &changed, bound, nil) {
				t.Fatal("invalid presentation envelope was accepted")
			}
		})
	}
}
