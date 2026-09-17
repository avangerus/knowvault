package purge

import (
	"context"
	"testing"
	"time"
)

func TestRequestSpecValidationIsClosed(t *testing.T) {
	valid := RequestSpec{
		RequestID:   "purge_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		WorkspaceID: "ws_queue", ConversationID: "conv_queue",
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "queue-key",
		Priority: 10, MaxAttempts: 3, AvailableAfter: 0,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RequestSpec){
		"raw request id":     func(spec *RequestSpec) { spec.RequestID = "conv_queue" },
		"raw reason":         func(spec *RequestSpec) { spec.ReasonCode = "retention request" },
		"negative priority":  func(spec *RequestSpec) { spec.Priority = -1 },
		"oversized attempts": func(spec *RequestSpec) { spec.MaxAttempts = 101 },
		"negative delay":     func(spec *RequestSpec) { spec.AvailableAfter = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestRunnerConfigValidationIsBounded(t *testing.T) {
	valid := RunnerConfig{WorkerID: "purger_worker", LeaseSeconds: 30, PollInterval: time.Second, ReclaimLimit: 10}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid runner config rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RunnerConfig){
		"empty worker":       func(config *RunnerConfig) { config.WorkerID = "" },
		"poll reaches lease": func(config *RunnerConfig) { config.PollInterval = 30 * time.Second },
		"poll too fast":      func(config *RunnerConfig) { config.PollInterval = 500 * time.Millisecond },
		"reclaim limit zero": func(config *RunnerConfig) { config.ReclaimLimit = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("invalid runner config accepted")
			}
		})
	}
}

func TestRunnerCancellationStopsCleanly(t *testing.T) {
	runner := &Runner{config: RunnerConfig{
		WorkerID: "purger_worker", LeaseSeconds: 30, PollInterval: time.Second, ReclaimLimit: 10,
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("cancelled runner returned %v", err)
	}
}
