package governedask

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

// captureHandler is a slog.Handler that records the attribute set of every
// record it is given and never emits to a real sink. It exists so a test can
// assert the EXACT fields logModelAttempt writes and prove no content leaked.
type captureHandler struct {
	records []capturedRecord
	attrs   []slog.Attr
}

type capturedRecord struct {
	message string
	attrs   map[string]any
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make(map[string]any)
	for _, attr := range h.attrs {
		attrs[attr.Key] = attr.Value.Any()
	}
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	h.records = append(h.records, capturedRecord{message: record.Message, attrs: attrs})
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	return &captureHandler{attrs: combined}
}

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

// TestLogModelAttemptRecordsFixedSafeAttributes drives logModelAttempt once,
// captures the single emitted record, and asserts the exact message, the exact
// twelve attributes, and that neither the message nor the rendered attribute
// set carries any content sentinel.
func TestLogModelAttemptRecordsFixedSafeAttributes(t *testing.T) {
	handler := &captureHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(previous) })

	service := &Service{}
	service.logModelAttempt(2, 1, modelgateway.AttemptResult{
		ModelID:            "qwen3.5-35b-a3b",
		StatusCode:         200,
		ResponseStage:      modelgateway.ResponseStageClaim,
		ResponseDiagnostic: modelgateway.ResponseJSONInvalid,
		Succeeded:          false,
		RequestBytes:       512,
		ResponseBytes:      2048,
		FailureCode:        modelgateway.CodeResponse,
	})

	if len(handler.records) != 1 {
		t.Fatalf("expected exactly one log record, got %d", len(handler.records))
	}
	record := handler.records[0]

	const wantMessage = "governed model attempt completed"
	if record.message != wantMessage {
		t.Fatalf("message = %q, want %q", record.message, wantMessage)
	}

	want := map[string]any{
		"component":           "knowvault-server",
		"operation":           "governed-query-compose",
		"compose_attempt":     int64(2),
		"model_attempt":       int64(1),
		"model_id":            "qwen3.5-35b-a3b",
		"status_code":         int64(200),
		"response_stage":      string(modelgateway.ResponseStageClaim),
		"response_diagnostic": modelgateway.ResponseJSONInvalid.ReasonCode(),
		"succeeded":           false,
		"request_bytes":       int64(512),
		"response_bytes":      int64(2048),
		"failure_code":        string(modelgateway.CodeResponse),
	}
	if len(record.attrs) != 12 {
		t.Fatalf("expected exactly 12 attributes, got %d: %v", len(record.attrs), record.attrs)
	}
	for key, value := range want {
		got, ok := record.attrs[key]
		if !ok {
			t.Fatalf("missing attribute %q (have %v)", key, record.attrs)
		}
		if got != value {
			t.Fatalf("attribute %q = %v (%T), want %v (%T)", key, got, got, value, value)
		}
	}

	rendered := record.message + " " + fmt.Sprint(record.attrs)
	for _, secret := range []string{
		"PRIVATE_QUESTION",
		"PRIVATE_SQL",
		"PRIVATE_MODEL_RESPONSE",
		"PRIVATE_DSN",
		"PRIVATE_TOKEN",
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("content sentinel %q leaked into model-attempt record: %q", secret, rendered)
		}
	}
}
