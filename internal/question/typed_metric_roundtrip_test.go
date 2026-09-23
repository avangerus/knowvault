package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// This crosses the production artifact encoder/decoder and both governed read
// checks. The model's plausible but wrong percentage must never become the
// stored or subsequently disclosed answer.
func TestTypedMetricPresentationPersistsAndReadsCanonicalPercentage(t *testing.T) {
	const runID = "qrun_current"
	call, dependency := metricAnswerFixture(t, true)
	modelClaim := toolClaim{
		Text:      "September 9 is 6.09% higher than September 10.",
		Citations: []toolCitation{},
		LiveReads: []toolLiveReadReference{{
			ResultID: call.Evidence.AttemptID, ReceiptDigest: call.Evidence.ReceiptDigest,
		}},
	}
	record := &ToolLoopRecord{
		Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192},
		Calls:   []ToolCallRecord{call}, StopReason: "ANSWER", AllClaimsBound: true,
		ClaimEvidenceVersion: "v1",
		ClaimEvidence: []ToolClaimEvidence{{
			TextHash: canon.Hash([]byte(modelClaim.Text)), LiveReads: modelClaim.LiveReads,
		}},
	}
	setPersistedToolAnswer(t, record, toolAnswer{Claims: []toolClaim{modelClaim}})
	dependencies := []governedQueryDependency{dependency}
	answer, selected, err := completedTypedMetricAnswer(runID, "\u0410 \u043A\u0430\u043A\u043E\u0439 \u0434\u0435\u043D\u044C \u0432\u044B\u0448\u0435 \u0438 \u043D\u0430 \u0441\u043A\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u043E\u0446\u0435\u043D\u0442\u043E\u0432?", record, dependencies, nil)
	if err != nil || !selected || !strings.Contains(answer, "\u043D\u0430 6.48% \u0432\u044B\u0448\u0435") || strings.Contains(answer, "6.09% \u0432\u044B\u0448\u0435") {
		t.Fatalf("server presentation = %q, selected=%v, error=%v", answer, selected, err)
	}
	executions, successful, valid := governedQueryToolExecutions(runID, dependencies, record)
	if !successful || !valid {
		t.Fatal("governed comparison fixture was not authenticated")
	}
	answerResult, err := liveDataAnswerResults(runID, executions)
	if err != nil || answerResult.Kind != "LIVE_TABLE" || answerResult.ExecutionID != call.Evidence.AttemptID || answerResult.ReceiptDigest == "" {
		t.Fatalf("governed receipt = %#v, error=%v", answerResult, err)
	}
	hash := canon.Hash([]byte(answer))
	if !validateGovernedQueryAnswerResults(runID, dependencies, record, answerResult) {
		t.Fatal("answer result did not bind to governed receipt")
	}
	if parsed, ok := finalToolAnswerFromRecord(record); !ok || len(parsed.Claims) != 1 {
		t.Fatalf("model claim did not parse: %#v, valid=%v", parsed, ok)
	}
	if !validateToolLoopClaimEvidenceV1(runID, "", record, dependencies, nil) {
		t.Fatal("underlying model claim did not bind")
	}
	if !validateToolLoopClaimEvidence(runID, "", record, dependencies, nil) {
		t.Fatal("presentation envelope did not bind to model claim")
	}
	raw, err := marshalStructuredAnswerWithDependencyList(runID, hash, nil, answerResult, nil, nil, dependencies, record)
	if err != nil {
		t.Fatalf("persist canonical answer: %v", err)
	}
	stored, err := decodeStructuredAnswerCleared(runID, append([]byte(nil), raw...))
	if err != nil || stored.AnswerResult == nil || stored.AnswerResult.ExecutionID != call.Evidence.AttemptID || len(stored.governedQueryDependencies) != 1 {
		t.Fatalf("read stored answer and receipt: result=%#v, dependencies=%d, error=%v", stored.AnswerResult, len(stored.governedQueryDependencies), err)
	}
	if !storedTypedMetricAnswerMatches(answer, hash, stored) ||
		!validateToolLoopClaimEvidence(runID, answer, stored.ToolLoop, stored.governedQueryDependencies, stored.Citations) {
		t.Fatal("canonical answer failed the governed read gate")
	}
	for _, tampered := range []string{modelClaim.Text + " [Live result 1]", strings.Replace(answer, "6.48%", "6.09%", 1)} {
		if storedTypedMetricAnswerMatches(tampered, hash, stored) ||
			validateToolLoopClaimEvidence(runID, tampered, stored.ToolLoop, stored.governedQueryDependencies, stored.Citations) {
			t.Fatalf("tampered percentage disclosed: %q", tampered)
		}
	}
}
