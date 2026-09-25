package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/question"
)

// stubKindModel answers every recognition call with the kind its map holds for
// the question, through the recognition tool. It is the scripted model channel
// of this command's test, never product code.
type stubKindModel struct {
	answers map[string]string
}

func (stub *stubKindModel) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Messages []modelgateway.Message `json:"messages"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil || len(input.Messages) == 0 {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	kind := ""
	for _, message := range input.Messages {
		if message.Role == "user" {
			kind = stub.answers[message.Content]
		}
	}
	arguments, _ := json.Marshal(map[string]any{"kind": kind})
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"model": "kind-test",
		"choices": []any{map[string]any{
			"message": map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"id": "call-1", "type": "function",
					"function": map[string]any{"name": "submit_question_kind", "arguments": string(arguments)},
				}},
			},
			"finish_reason": "tool_calls",
		}},
		"usage": map[string]any{"prompt_tokens": 700, "completion_tokens": 4, "total_tokens": 704},
	})
}

func kindMeasureAdapter(t *testing.T, endpoint string) *modelgateway.LabAdapter {
	t.Helper()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion,
		Endpoint:      endpoint, ModelID: "kind-test",
		MaxOutputTokens: 2048, InsecureLabMode: true,
		ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "kind-test", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 65536,
			MaxToolResultBytes: 8192, MaxOutputTokens: 2048, TimeoutSeconds: 30,
		},
	})
	if err != nil {
		t.Fatalf("build kind measure adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return adapter
}

// Card D-15 result 3: with a stubbed model the per-kind counts and the
// full-to-another-kind list are exactly the scripted outcomes.
func TestMeasureCountsWithStubbedModel(t *testing.T) {
	phrasings := []phrasing{
		{Question: "сколько действующих договоров?", Kind: "full"},
		{Question: "покажи данные", Kind: "full"},
		{Question: "привет", Kind: "greeting"},
	}
	server := httptest.NewServer(&stubKindModel{answers: map[string]string{
		"сколько действующих договоров?": "full",
		// The scripted model gets this full question wrong on purpose.
		"покажи данные": "greeting",
		"привет":        "greeting",
	}})
	defer server.Close()

	recogniser := question.NewModelKindRecogniser(kindMeasureAdapter(t, server.URL), "ws_kind_measure_test")
	attempts := measure(context.Background(), recogniser, phrasings, 3)

	if len(attempts) != 9 {
		t.Fatalf("measure produced %d attempts, want 9", len(attempts))
	}
	correct := 0
	for _, item := range attempts {
		if item.Correct() {
			correct++
		}
	}
	if correct != 6 {
		t.Fatalf("correct attempts = %d, want 6", correct)
	}

	perKind := map[question.AnswerKind]tally{}
	for _, entry := range tallies(attempts) {
		perKind[entry.Expected] = entry
	}
	if got := perKind[question.AnswerKindFull]; got.Correct != 3 || got.Total != 6 {
		t.Fatalf("full tally = %d/%d, want 3/6", got.Correct, got.Total)
	}
	if got := perKind[question.AnswerKindGreeting]; got.Correct != 3 || got.Total != 3 {
		t.Fatalf("greeting tally = %d/%d, want 3/3", got.Correct, got.Total)
	}

	misses := fullMisrecognitions(attempts)
	if len(misses) != 3 {
		t.Fatalf("full misrecognitions = %d, want 3", len(misses))
	}
	for _, miss := range misses {
		if miss.Got != question.AnswerKindGreeting || miss.Expected != question.AnswerKindFull {
			t.Fatalf("full misrecognition = %+v, want full -> greeting", miss)
		}
	}

	var out bytes.Buffer
	render(&out, attempts, 3, "kind-test", 0.95)
	text := out.String()
	for _, want := range []string{
		"per expected kind:",
		fmt.Sprintf("  %-18s %d/%d", "full", 3, 6),
		fmt.Sprintf("  %-18s %d/%d", "greeting", 3, 3),
		"full questions recognised as another kind: 3",
		fmt.Sprintf("  got %-18s run %d  %q", "greeting", 1, "покажи данные"),
		"recognised correctly: 6/9 (66.7%)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("command output does not contain %q:\n%s", want, text)
		}
	}
}

func TestLoadPhrasingsAcceptsArrayAndDocument(t *testing.T) {
	dir := t.TempDir()
	arrayPath := filepath.Join(dir, "array.json")
	if err := os.WriteFile(arrayPath, []byte(`[{"question":"привет","kind":"greeting"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	array, err := loadPhrasings(arrayPath)
	if err != nil || len(array) != 1 || array[0].Kind != "greeting" {
		t.Fatalf("array phrasings = %#v, %v", array, err)
	}

	documentPath := filepath.Join(dir, "document.json")
	if err := os.WriteFile(documentPath, []byte(`{"phrasings":[{"question":"покажи данные","kind":"vague"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	document, err := loadPhrasings(documentPath)
	if err != nil || len(document) != 1 || document[0].Question != "покажи данные" {
		t.Fatalf("document phrasings = %#v, %v", document, err)
	}

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte(`[{"question":"x","kind":"overview"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPhrasings(badPath); err == nil {
		t.Fatal("an expected kind outside the closed list was accepted")
	}
}
