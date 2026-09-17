package ingestion

import (
	"context"
	"errors"
	"testing"
)

// A nested pipeline failure must report the INNERMOST content-free code: the
// worker log is the only place an operator can tell a missing source-trust
// bundle from an unresolvable credential when both surface to the caller as
// the single category code INGEST_ADAPTER_UNAVAILABLE.
func TestDiagnosticClassReportsInnermostPipelineCode(t *testing.T) {
	err := failure("INGEST_ADAPTER_UNAVAILABLE", failure("INGEST_REMOTE_TRUST_UNAVAILABLE", nil))
	if got, want := DiagnosticClass(err), "CAUSE_INGEST_REMOTE_TRUST_UNAVAILABLE"; got != want {
		t.Fatalf("DiagnosticClass = %q, want %q", got, want)
	}
	if got, want := CodeOf(err), "INGEST_ADAPTER_UNAVAILABLE"; got != want {
		t.Fatalf("CodeOf = %q, want %q (the caller-facing category must not change)", got, want)
	}
}

func TestDiagnosticClassReportsInnermostPipelineCodeAndCauseType(t *testing.T) {
	sentinel := errors.New("connector refused")
	err := failure("INGEST_ADAPTER_UNAVAILABLE", failure("INGEST_REMOTE_CONNECTOR_INVALID", sentinel))
	want := "CAUSE_INGEST_REMOTE_CONNECTOR_INVALID_TYPE_*errors.errorString"
	if got := DiagnosticClass(err); got != want {
		t.Fatalf("DiagnosticClass = %q, want %q", got, want)
	}
}

// A single, unnested pipeline error adds no cause information, and the
// transport/context classes keep priority over the nested-code class.
func TestDiagnosticClassKeepsExistingClasses(t *testing.T) {
	if got, want := DiagnosticClass(failure("INGEST_ROOT_UNRESOLVED", nil)), "ERROR_TYPE_*ingestion.errPipeline"; got != want {
		t.Fatalf("DiagnosticClass(single) = %q, want %q", got, want)
	}
	if got, want := DiagnosticClass(failure("INGEST_DISCOVER", context.DeadlineExceeded)), "CONTEXT_DEADLINE_EXCEEDED"; got != want {
		t.Fatalf("DiagnosticClass(deadline) = %q, want %q", got, want)
	}
	if got := DiagnosticClass(nil); got != "" {
		t.Fatalf("DiagnosticClass(nil) = %q, want empty", got)
	}
}
