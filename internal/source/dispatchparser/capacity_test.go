package dispatchparser

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/source/docparser"
)

type capacityTransport func(context.Context, sandboxdispatch.JobV2, []byte) (sandboxdispatch.SubmitResultV2, bool, error)

func (f capacityTransport) SubmitV2(ctx context.Context, job sandboxdispatch.JobV2, input []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
	return f(ctx, job, input)
}

func TestProductionWaitsForFreshNativeCapacityWithoutResendingDocument(t *testing.T) {
	office, pdf, err := NewProduction("/unused-native-test.sock")
	if err != nil || office.shared.ready == nil || pdf.shared.ready == nil {
		t.Fatal("production adapters lack native capacity handling")
	}
	var jobs []sandboxdispatch.JobV2
	payload := []byte("same original bytes")
	office.shared.transport = capacityTransport(func(_ context.Context, job sandboxdispatch.JobV2, input []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
		if !bytes.Equal(input, payload) {
			t.Fatal("original bytes changed during retry")
		}
		jobs = append(jobs, job)
		if len(jobs) == 1 {
			return sandboxdispatch.SubmitResultV2{}, true, nil
		}
		return successTerminal(officeResult(QualifiedArtifactHash)), false, nil
	})
	probes := 0
	office.shared.ready = func(context.Context) error {
		probes++
		if probes < 3 {
			if len(jobs) != 1 {
				t.Fatal("document resent while the next peer was still starting")
			}
			return sandboxdispatch.ErrNativeNotReady
		}
		return nil
	}
	result, err := office.Extract(context.Background(), docparser.FormatDOCX, payload)
	if err != nil || result == nil || len(jobs) != 2 || probes != 3 {
		t.Fatalf("fresh peer did not finish the original document: jobs=%d probes=%d err=%v", len(jobs), probes, err)
	}
	if jobs[0].JobID == jobs[1].JobID || jobs[0].LeaseID == jobs[1].LeaseID || jobs[0].InputArtifact.ArtifactID == jobs[1].InputArtifact.ArtifactID {
		t.Fatal("retry reused admission identities")
	}
	if jobs[0].ParserRequest != jobs[1].ParserRequest || jobs[0].InputArtifact.ContentDigest != jobs[1].InputArtifact.ContentDigest {
		t.Fatal("retry changed the parser contract or source digest")
	}
}

func TestNativeCapacityWaitPreservesRetryOnCancellation(t *testing.T) {
	office, _, _ := NewProduction("/unused-native-test.sock")
	calls := 0
	office.shared.transport = capacityTransport(func(context.Context, sandboxdispatch.JobV2, []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
		calls++
		return sandboxdispatch.SubmitResultV2{}, true, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	office.shared.ready = func(context.Context) error { cancel(); return sandboxdispatch.ErrNativeNotReady }
	result, err := office.Extract(ctx, docparser.FormatDOCX, []byte("original"))
	if result != nil || !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) || calls != 1 {
		t.Fatalf("safe wait cancellation quarantined or resent the document: calls=%d err=%v", calls, err)
	}
}

func TestNativeCapacityDoesNotRetryAmbiguousTransferFailures(t *testing.T) {
	for _, initialRetry := range []bool{false, true} {
		office, _, _ := NewProduction("/unused-native-test.sock")
		calls, probes := 0, 0
		office.shared.transport = capacityTransport(func(context.Context, sandboxdispatch.JobV2, []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
			calls++
			if initialRetry && calls == 1 {
				return sandboxdispatch.SubmitResultV2{}, true, nil
			}
			return sandboxdispatch.SubmitResultV2{}, false, errors.New("ambiguous disconnect after payload")
		})
		office.shared.ready = func(context.Context) error { probes++; return nil }
		result, err := office.Extract(context.Background(), docparser.FormatDOCX, []byte("original"))
		wantCalls, wantProbes := 1, 0
		if initialRetry {
			wantCalls, wantProbes = 2, 1
		}
		if result != nil || !errors.Is(err, ErrExtractionFailed) || calls != wantCalls || probes != wantProbes {
			t.Fatalf("ambiguous transfer retried: initialRetry=%t calls=%d probes=%d err=%v", initialRetry, calls, probes, err)
		}
	}
}
