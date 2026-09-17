package sandboxdispatch

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubmitV2RejectsResultBeforeTerminalOutcome(t *testing.T) {
	directory, err := os.MkdirTemp("", "kv-v2-client")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "submit.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		kind, _, readErr := readFrame(conn, maxFrameBody)
		if readErr != nil || kind != kindJobV2 {
			serverDone <- ErrWireRejected
			return
		}
		_, _, readErr = readPayloadFrameV2(conn, 1024)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		serverDone <- writeResultFrame(conn, []byte("premature-result"), 1024)
	}()

	payload := []byte("opaque")
	now := time.Now().UTC()
	request := ParserRequestV1{
		SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypePDF,
		Operation: OperationObservePDFText, MediaFamily: "PDF",
		SandboxProfileRevision: "pdf-sandbox-v2", ObservationProfileRevision: "pdf-obs-v1",
		MaxInputBytes: 1024, MaxOutputBytes: 1024, MaxUnits: 100,
		MaxPages: 10, MaxDecodedPixels: 1, OutputContract: "pdf-parser-result-v1",
	}
	job := JobV2{
		SchemaVersion: JobVersionV2, JobID: "job-result-order", LeaseID: "lease-result-order",
		ParserRequest: request,
		InputArtifact: InputArtifact{ArtifactID: "artifact-result-order", ContentDigest: digestFor(payload), MediaType: "application/pdf"},
		SubmittedAt:   now.Format(time.RFC3339), DeadlineAt: now.Add(5 * time.Second).Format(time.RFC3339),
		WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN",
	}
	submitter := &Submitter{V2SubmitSocketPath: socketPath, MaxPayloadBytes: 1024, FrameTimeout: time.Second}
	result, retryable, err := submitter.SubmitV2(context.Background(), job, payload)
	if !errors.Is(err, ErrSubmitFailed) || retryable || result.Result != nil || result.Confirmation != nil {
		t.Fatalf("premature result was retained: result=%#v retry=%v err=%v", result, retryable, err)
	}
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatalf("malicious relay server failed: %v", serverErr)
	}
}

func TestWorkerClientV2SelectsDedicatedOCRRegistrationSocket(t *testing.T) {
	client := &WorkerClient{
		V2OfficeRegistrationSocketPath: "office.sock",
		V2PDFRegistrationSocketPath:    "pdf.sock",
		V2OCRRegistrationSocketPath:    "ocr.sock",
	}
	for parserType, want := range map[string]string{
		ParserTypeOffice: "office.sock",
		ParserTypePDF:    "pdf.sock",
		ParserTypeOCR:    "ocr.sock",
	} {
		if got := client.v2RegistrationSocket(parserType); got != want {
			t.Fatalf("parser %s selected %q, want %q", parserType, got, want)
		}
	}
	if got := client.v2RegistrationSocket(ParserTypeText); got != "" {
		t.Fatalf("unsupported parser selected socket %q", got)
	}
}

func TestSubmitV2RefusedConnectionIsRetryButCancellationIsNot(t *testing.T) {
	directory, err := os.MkdirTemp("", "kv-v2-offline")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "submit.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	submitter := &Submitter{V2SubmitSocketPath: socketPath, MaxPayloadBytes: 1024, FrameTimeout: time.Second}
	result, retry, err := submitter.SubmitV2(context.Background(), JobV2{}, []byte("not transferred"))
	if err != nil || !retry || result.Result != nil || result.Confirmation != nil {
		t.Fatalf("refused connection: retry=%v error=%v result=%#v", retry, err, result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, retry, err = submitter.SubmitV2(ctx, JobV2{}, []byte("not transferred"))
	if !errors.Is(err, ErrSubmitFailed) || retry {
		t.Fatalf("canceled request retried: retry=%v error=%v", retry, err)
	}
}

func TestSubmitV2DisconnectAfterPayloadCannotAuthorizeRetry(t *testing.T) {
	directory, err := os.MkdirTemp("", "kv-v2-drop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "submit.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		kind, _, err := readFrame(conn, maxFrameBody)
		if err != nil || kind != kindJobV2 {
			serverDone <- ErrWireRejected
			return
		}
		_, _, err = readPayloadFrameV2(conn, 1024)
		serverDone <- err
	}()
	submitter := &Submitter{V2SubmitSocketPath: socketPath, MaxPayloadBytes: 1024, FrameTimeout: time.Second}
	job := JobV2{LeaseID: "lease-disconnect", DeadlineAt: time.Now().UTC().Add(5 * time.Second).Format(time.RFC3339)}
	result, retry, err := submitter.SubmitV2(context.Background(), job, []byte("possibly transferred"))
	if !errors.Is(err, ErrSubmitFailed) || retry || result.Result != nil || result.Confirmation != nil {
		t.Fatalf("disconnect authorized retry: retry=%v error=%v result=%#v", retry, err, result)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
