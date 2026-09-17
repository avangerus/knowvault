package modelgateway

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testSamplingParameters() *SamplingParameters {
	return &SamplingParameters{Temperature: 0.7, TopP: 0.8, TopK: 20, MinP: 0, PresencePenalty: 1.5, RepeatPenalty: 1, Seed: 135}
}

func TestConverseSamplingIsExplicitAndImmutable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&wire) != nil {
			t.Fatal("invalid request")
		}
		for key, value := range map[string]string{"temperature": "0.7", "top_p": "0.8", "top_k": "20", "min_p": "0", "presence_penalty": "1.5", "repeat_penalty": "1", "seed": "135"} {
			if string(wire[key]) != value {
				t.Errorf("%s=%s, want %s", key, wire[key], value)
			}
		}
		_, _ = w.Write([]byte(`{"model":"test-chat","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"answer"}}]}`))
	}))
	defer server.Close()
	profile := testConverseProfile()
	profile.Sampling = testSamplingParameters()
	adapter, err := NewLabAdapter(LabAdapterConfig{SchemaVersion: LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "test-chat", MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: ThinkingModeDisabled, ToolLoop: profile})
	if err != nil {
		t.Fatal(err)
	}
	profile.Sampling.Temperature = 99
	returned, _ := adapter.ToolLoopProfile()
	returned.Sampling.Temperature = 88
	_, _, err = adapter.Converse(context.Background(), "ws-test", []Message{{Role: "system", Content: "rules"}, {Role: "user", Content: "question"}}, testConverseTools())
	if err != nil {
		t.Fatal(err)
	}
}

func TestConverseSamplingRejectsInvalidProfile(t *testing.T) {
	for _, mutate := range []func(*SamplingParameters){
		func(s *SamplingParameters) { s.Temperature = math.NaN() },
		func(s *SamplingParameters) { s.PresencePenalty = math.Inf(1) },
		func(s *SamplingParameters) { s.Temperature = -1 },
		func(s *SamplingParameters) { s.TopP = 0 },
		func(s *SamplingParameters) { s.TopK = 0 },
		func(s *SamplingParameters) { s.MinP = 2 },
		func(s *SamplingParameters) { s.PresencePenalty = 3 },
		func(s *SamplingParameters) { s.RepeatPenalty = 0 },
		func(s *SamplingParameters) { s.Seed = -1 },
	} {
		profile := testConverseProfile()
		profile.Sampling = testSamplingParameters()
		mutate(profile.Sampling)
		if profile.Validate() == nil {
			t.Fatal("invalid sampling profile accepted")
		}
	}
}
