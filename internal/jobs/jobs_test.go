package jobs

import (
	"errors"
	"strings"
	"testing"
)

const validJobID = "job_00000000000000000000000001"

func TestSpecValidateRejectsOutOfContract(t *testing.T) {
	base := Spec{
		JobID:          validJobID,
		Type:           TypeSourceScopeSync,
		IdempotencyKey: "idem-1",
		Priority:       100,
		MaxAttempts:    3,
		AvailableAfter: 0,
	}
	if err := base.validate(); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Spec){
		"bad job id":        func(s *Spec) { s.JobID = "not-a-ulid" },
		"display job id":    func(s *Spec) { s.JobID = "alice@example.com" },
		"unknown type":      func(s *Spec) { s.Type = Type("CHAT_REPLY") },
		"empty type":        func(s *Spec) { s.Type = "" },
		"control idem key":  func(s *Spec) { s.IdempotencyKey = "idem\x00" },
		"empty idem key":    func(s *Spec) { s.IdempotencyKey = "" },
		"priority negative": func(s *Spec) { s.Priority = -1 },
		"priority over max": func(s *Spec) { s.Priority = 1001 },
		"attempts zero":     func(s *Spec) { s.MaxAttempts = 0 },
		"attempts over max": func(s *Spec) { s.MaxAttempts = 101 },
		"delay negative":    func(s *Spec) { s.AvailableAfter = -1 },
		"delay over max":    func(s *Spec) { s.AvailableAfter = 2592001 },
	} {
		t.Run(name, func(t *testing.T) {
			spec := base
			mutate(&spec)
			if err := spec.validate(); err == nil {
				t.Fatalf("mutation %q was accepted", name)
			}
		})
	}
}

func TestPayloadValidateClosedInventory(t *testing.T) {
	for name, payload := range map[string]Payload{
		"reference": {"source_object_id": "sob_00000000000000000000000001"},
		"hash":      {"content_hash": "sha256:" + strings.Repeat("a", 64)},
		"fence":     {"retention_fence": int64(3)},
		"operation": {"operation": "UPSERT"},
		"empty":     {},
	} {
		t.Run("accepts "+name, func(t *testing.T) {
			if err := payload.Validate(); err != nil {
				t.Fatalf("valid payload %q rejected: %v", name, err)
			}
		})
	}
	for name, payload := range map[string]Payload{
		"unknown key":        {"text": "secret contents"},
		"path smuggle":       {"source_object_id": "/secret/contract.pdf"},
		"email smuggle":      {"artifact_id": "alice@example.com"},
		"bad hash":           {"content_hash": "deadbeef"},
		"fence wrong type":   {"retention_fence": "3"},
		"fence negative":     {"retention_fence": int64(-1)},
		"unknown operation":  {"operation": "MERGE"},
		"reference non-text": {"workspace_id": 42},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if err := payload.Validate(); err == nil {
				t.Fatalf("invalid payload %q accepted", name)
			}
		})
	}
}

func TestPayloadMarshalNilIsEmptyObject(t *testing.T) {
	encoded, err := Payload(nil).marshal()
	if err != nil {
		t.Fatalf("nil payload marshal: %v", err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("nil payload marshalled to %q, want {}", encoded)
	}
}

func TestCodeOfMapsLeaseAndFallback(t *testing.T) {
	if got := CodeOf(&Error{code: CodeLeaseLost}); got != CodeLeaseLost {
		t.Fatalf("CodeOf lease error = %q", got)
	}
	if got := CodeOf(errors.New("raw driver failure")); got != CodePersistence {
		t.Fatalf("CodeOf unknown error = %q, want %q", got, CodePersistence)
	}
	if got := CodeOf(nil); got != CodePersistence {
		t.Fatalf("CodeOf nil = %q", got)
	}
}

func TestNewFailsClosedOnNilStore(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) unexpectedly succeeded")
	}
}

func TestMapLeaseErrorClassifiesSQLState(t *testing.T) {
	q := &Queue{}
	if err := q.mapLeaseError(nil); err != nil {
		t.Fatalf("nil write error mapped to %v", err)
	}
	leaseErr := q.mapLeaseError(fakeSQLStateError{state: leaseLostSQLState})
	if CodeOf(leaseErr) != CodeLeaseLost {
		t.Fatalf("lease SQL state mapped to %q", CodeOf(leaseErr))
	}
	otherErr := q.mapLeaseError(fakeSQLStateError{state: "42501"})
	if CodeOf(otherErr) != CodePersistence {
		t.Fatalf("non-lease SQL state mapped to %q", CodeOf(otherErr))
	}
}

type fakeSQLStateError struct{ state string }

func (e fakeSQLStateError) Error() string    { return "sqlstate " + e.state }
func (e fakeSQLStateError) SQLState() string { return e.state }
