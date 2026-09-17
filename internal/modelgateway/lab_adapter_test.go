package modelgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func validLabPlanJSON() string {
	return "{\"schema_version\":\"1.4\",\"claims\":[{\"claim_id\":\"C1\",\"text\":\"\u041e\u0442\u0432\u0435\u0442 \u043f\u043e \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0443.\",\"kind\":\"FACT\",\"unknown_reason\":null,\"evidence_ids\":[\"ev_1\"],\"supporting_claim_ids\":[]}],\"sections\":[{\"section_id\":\"S1\",\"title\":null,\"ordered_claim_ids\":[\"C1\"]}]}"
}

func labTestEvidence() []Evidence {
	return []Evidence{{
		ID: "ev_1", SourceObjectID: "obj1", SourceVersionID: "ver1", ExtractionID: "ext1",
		TextHash: "sha256:" + strings.Repeat("a", 64), AnchorHash: "sha256:" + strings.Repeat("b", 64),
		Text: "\u0424\u0440\u0430\u0433\u043c\u0435\u043d\u0442 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430.",
	}}
}

func labServerHost(t *testing.T, server *httptest.Server) string {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	return parsed.Hostname() + ":" + parsed.Port()
}

func newLabConfig(t *testing.T, server *httptest.Server, modelID string) LabAdapterConfig {
	t.Helper()
	return LabAdapterConfig{
		SchemaVersion: LabAdapterSchemaVersion, Endpoint: "http://" + labServerHost(t, server) + "/v1",
		ModelID: modelID, MaxOutputTokens: 256, InsecureLabMode: true,
	}
}

func TestLabAdapterGenerateSuccess(t *testing.T) {
	const modelID = "test-model"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": modelID,
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message":       map[string]any{"content": validLabPlanJSON()},
			}},
		})
	}))
	defer server.Close()

	adapter, err := NewLabAdapter(newLabConfig(t, server, modelID))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	plan, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !result.Succeeded || result.ModelID != modelID || result.RequestBytes == 0 || result.ResponseBytes == 0 || result.ResponseStage != ResponseStageClaim {
		t.Fatalf("unexpected attempt result: %+v", result)
	}
	if len(plan.Claims) != 1 || plan.Claims[0].EvidenceIDs[0] != "ev_1" {
		t.Fatalf("unexpected claim plan: %+v", plan)
	}
}

func TestLabAdapterRequestUsesConfiguredThinkingAndJSONResponseFormat(t *testing.T) {
	const modelID = "test-model"
	var captured map[string]json.RawMessage
	var decodeErr error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = make(map[string]json.RawMessage)
		decodeErr = json.NewDecoder(r.Body).Decode(&captured)
		if decodeErr != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": modelID,
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message":       map[string]any{"content": validLabPlanJSON()},
			}},
		})
	}))
	defer server.Close()

	config := newLabConfig(t, server, modelID)
	config.ThinkingMode = ThinkingModeDisabled
	adapter, err := NewLabAdapter(config)
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	if _, _, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if decodeErr != nil {
		t.Fatalf("decode request: %v", decodeErr)
	}
	wantKeys := map[string]bool{
		"model": true, "messages": true, "temperature": true, "max_tokens": true,
		"stream": true, "thinking": true, "response_format": true,
	}
	if len(captured) != len(wantKeys) {
		t.Fatalf("request key count=%d, want exactly %d", len(captured), len(wantKeys))
	}
	for key := range wantKeys {
		if _, ok := captured[key]; !ok {
			t.Fatalf("request omitted exact field %q", key)
		}
	}
	for key := range captured {
		if !wantKeys[key] {
			t.Fatalf("request added unexpected field %q", key)
		}
	}
	var fields struct {
		Model          string                   `json:"model"`
		Temperature    float64                  `json:"temperature"`
		MaxTokens      int                      `json:"max_tokens"`
		Stream         bool                     `json:"stream"`
		Thinking       completionThinking       `json:"thinking"`
		ResponseFormat completionResponseFormat `json:"response_format"`
	}
	raw, err := json.Marshal(captured)
	if err != nil {
		t.Fatalf("re-marshal request: %v", err)
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode request fields: %v", err)
	}
	if fields.Model != modelID || fields.Temperature != 0 || fields.MaxTokens != 128 || fields.Stream ||
		fields.Thinking.Type != string(ThinkingModeDisabled) || fields.ResponseFormat.Type != "json_object" {
		t.Fatalf("unexpected request fields: %+v", fields)
	}
}

func TestProductionCompletionRequestOmitsLabOnlyControls(t *testing.T) {
	raw, err := json.Marshal(completionRequest{Model: "model", Temperature: 0, MaxTokens: 128, Stream: false})
	if err != nil {
		t.Fatalf("marshal production request: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode production request: %v", err)
	}
	if _, ok := fields["thinking"]; ok {
		t.Fatal("production request unexpectedly included lab thinking control")
	}
	if _, ok := fields["response_format"]; ok {
		t.Fatal("production request unexpectedly included lab response format")
	}
}

func TestLabAdapterRejectsEvidenceIDNotInAllowList(t *testing.T) {
	const modelID = "test-model"
	invented := `{"schema_version":"1.4","claims":[{"claim_id":"C1","text":"x","kind":"FACT","unknown_reason":null,"evidence_ids":["ev_invented"],"supporting_claim_ids":[]}],"sections":[{"section_id":"S1","title":null,"ordered_claim_ids":["C1"]}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   modelID,
			"choices": []map[string]any{{"finish_reason": "stop", "message": map[string]any{"content": invented}}},
		})
	}))
	defer server.Close()

	adapter, err := NewLabAdapter(newLabConfig(t, server, modelID))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	_, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err == nil {
		t.Fatal("expected rejection for an invented evidence id")
	}
	if CodeOf(err) != CodeResponse || result.Succeeded {
		t.Fatalf("expected CodeResponse/not-succeeded, got code=%s result=%+v", CodeOf(err), result)
	}
}

func TestLabAdapterResponseInvalidRetainsHTTPStatusWithoutBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-a-model-response"))
	}))
	defer server.Close()

	adapter, err := NewLabAdapter(newLabConfig(t, server, "m"))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	_, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err == nil || CodeOf(err) != CodeResponse || result.FailureCode != CodeResponse || result.StatusCode != http.StatusOK || result.ResponseStage != ResponseStageWire {
		t.Fatalf("expected content-free response classification, err=%v result=%+v", err, result)
	}
	var gatewayErr *Error
	if !errors.As(err, &gatewayErr) || gatewayErr.StatusCode() != http.StatusOK {
		status := 0
		if gatewayErr != nil {
			status = gatewayErr.StatusCode()
		}
		t.Fatalf("response-invalid error status=%d, want %d", status, http.StatusOK)
	}
	if err.Error() != string(CodeResponse) || strings.Contains(err.Error(), "not-a-model-response") {
		t.Fatalf("response-invalid error exposed response content: %q", err.Error())
	}
	if result.ResponseBytes == 0 {
		t.Fatal("content-free attempt summary lost response byte count")
	}
}

func TestLabAdapterInvalidJSONResponseStage(t *testing.T) {
	const modelID = "test-model"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   modelID,
			"choices": []map[string]any{{"finish_reason": "stop", "message": map[string]any{"content": "{not-json"}}},
		})
	}))
	defer server.Close()

	config := newLabConfig(t, server, modelID)
	config.ThinkingMode = ThinkingModeDisabled
	adapter, err := NewLabAdapter(config)
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	_, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err == nil || CodeOf(err) != CodeResponse || result.ResponseStage != ResponseStageJSON {
		t.Fatalf("expected JSON-stage response rejection, err=%v result=%+v", err, result)
	}
}

func TestLabAdapterInvalidClaimPlanRetainsHTTPStatus(t *testing.T) {
	const modelID = "test-model"
	invalidPlan := `{"schema_version":"1.4","claims":[],"sections":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model":   modelID,
			"choices": []map[string]any{{"finish_reason": "stop", "message": map[string]any{"content": invalidPlan}}},
		})
	}))
	defer server.Close()

	adapter, err := NewLabAdapter(newLabConfig(t, server, modelID))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	_, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err == nil || CodeOf(err) != CodeResponse || result.FailureCode != CodeResponse || result.StatusCode != http.StatusOK || result.ResponseStage != ResponseStageClaim {
		t.Fatalf("expected invalid plan classification, err=%v result=%+v", err, result)
	}
	var gatewayErr *Error
	if !errors.As(err, &gatewayErr) || gatewayErr.StatusCode() != http.StatusOK {
		status := 0
		if gatewayErr != nil {
			status = gatewayErr.StatusCode()
		}
		t.Fatalf("invalid-plan error status=%d, want %d", status, http.StatusOK)
	}
}

func TestLabAdapterRejectsNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	adapter, err := NewLabAdapter(newLabConfig(t, server, "m"))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	_, result, err := adapter.Generate(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128)
	if err == nil || CodeOf(err) != CodeRejected || result.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected CodeRejected/500, got err=%v result=%+v", err, result)
	}
}

func TestLabAdapterConfigRejectsPublicEndpoint(t *testing.T) {
	_, err := NewLabAdapter(LabAdapterConfig{
		SchemaVersion: LabAdapterSchemaVersion, Endpoint: "http://93.184.216.34:8080", ModelID: "m",
		MaxOutputTokens: 128, InsecureLabMode: true,
	})
	if err == nil {
		t.Fatal("expected a public IP endpoint to be rejected")
	}
}

func TestLabAdapterConfigRequiresExplicitAcknowledgement(t *testing.T) {
	_, err := NewLabAdapter(LabAdapterConfig{
		SchemaVersion: LabAdapterSchemaVersion, Endpoint: "http://127.0.0.1:8080", ModelID: "m",
		MaxOutputTokens: 128, InsecureLabMode: false,
	})
	if err == nil {
		t.Fatal("expected a config without InsecureLabMode to be rejected")
	}
}

func TestGenerateBoundedRetriesOnlyTransientFailure(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	adapter, err := NewLabAdapter(newLabConfig(t, server, "m"))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	var attempts []AttemptResult
	_, err = adapter.GenerateBounded(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128, func(result AttemptResult) {
		attempts = append(attempts, result)
	})
	if err == nil {
		t.Fatal("expected a terminal error")
	}
	// CodeRejected is not retried, so exactly one attempt must be recorded.
	if calls != 1 || len(attempts) != 1 {
		t.Fatalf("expected exactly one attempt for a non-transient failure, got calls=%d attempts=%d", calls, len(attempts))
	}
}

func TestGenerateBoundedStopsAtTwoAttempts(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server must support hijacking")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	}))
	defer server.Close()
	adapter, err := NewLabAdapter(newLabConfig(t, server, "m"))
	if err != nil {
		t.Fatalf("NewLabAdapter: %v", err)
	}
	defer adapter.Close()

	var attempts []AttemptResult
	_, err = adapter.GenerateBounded(context.Background(), "\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 AIS?", "Answer using only cited Evidence.", []byte(`{"type":"object"}`), labTestEvidence(), 128, func(result AttemptResult) {
		attempts = append(attempts, result)
	})
	if err == nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("expected a terminal CodeUnavailable error, got %v", err)
	}
	if calls != labMaxAttemptsPerCall || len(attempts) != labMaxAttemptsPerCall {
		t.Fatalf("expected exactly %d attempts, got calls=%d attempts=%d", labMaxAttemptsPerCall, calls, len(attempts))
	}
}

func TestVerifierAcceptsAndRejectsBySimilarity(t *testing.T) {
	var gotWorkspace, gotOperation []string
	embed := func(_ context.Context, workspaceID, operationID, text string) ([]float32, error) {
		gotWorkspace = append(gotWorkspace, workspaceID)
		gotOperation = append(gotOperation, operationID)
		switch text {
		case "claim-supported":
			return []float32{1, 0}, nil
		case "claim-unsupported":
			return []float32{0, 1}, nil
		case "evidence":
			return []float32{1, 0}, nil
		default:
			return nil, errUnexpectedText(text)
		}
	}
	verifier, err := NewVerifier(embed, DefaultVerifierThreshold)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ok, err := verifier.VerifyClaim(context.Background(), "ws1", "qrun1:claim1", "claim-supported", []string{"evidence"})
	if err != nil || !ok {
		t.Fatalf("expected a supported claim to verify, ok=%v err=%v", ok, err)
	}
	ok, err = verifier.VerifyClaim(context.Background(), "ws1", "qrun1:claim2", "claim-unsupported", []string{"evidence"})
	if err != nil || ok {
		t.Fatalf("expected an unsupported claim to fail verification, ok=%v err=%v", ok, err)
	}
	for _, workspaceID := range gotWorkspace {
		if workspaceID != "ws1" {
			t.Fatalf("expected every embed call bound to workspace ws1, got %q", workspaceID)
		}
	}
	if len(gotOperation) != 4 || gotOperation[0] != "qrun1:claim1:claim" || gotOperation[1] != "qrun1:claim1:evidence:0" ||
		gotOperation[2] != "qrun1:claim2:claim" || gotOperation[3] != "qrun1:claim2:evidence:0" {
		t.Fatalf("expected exact per-call operation ids, got %v", gotOperation)
	}
}

type unexpectedTextError struct{ text string }

func (e unexpectedTextError) Error() string {
	return "unexpected embedding text: " + strconv.Quote(e.text)
}

func errUnexpectedText(text string) error { return unexpectedTextError{text: text} }
