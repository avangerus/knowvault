package purge

import "testing"

func TestSourceRequestSpecValidationIsClosed(t *testing.T) {
	valid := SourceRequestSpec{
		RequestID: "purge_01ARZ3NDEKTSV4RRFFQ69G5FAV", SourceVersion: "version_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "source-queue-key",
		Priority: 10, MaxAttempts: 3, AvailableAfter: 0,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid source request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*SourceRequestSpec){
		"raw request id":     func(spec *SourceRequestSpec) { spec.RequestID = "request" },
		"raw version id":     func(spec *SourceRequestSpec) { spec.SourceVersion = "version" },
		"raw reason":         func(spec *SourceRequestSpec) { spec.ReasonCode = "retention request" },
		"negative priority":  func(spec *SourceRequestSpec) { spec.Priority = -1 },
		"oversized attempts": func(spec *SourceRequestSpec) { spec.MaxAttempts = 101 },
		"negative delay":     func(spec *SourceRequestSpec) { spec.AvailableAfter = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("invalid source request accepted")
			}
		})
	}
}

func TestSourceQueueRejectsNilStore(t *testing.T) {
	if _, err := NewSourceQueue(nil); err == nil || QueueCodeOf(err) != QueueCodeInvalid {
		t.Fatalf("nil store error=%v code=%s", err, QueueCodeOf(err))
	}
}
