// Package sandboxdispatch_test exercises the sandbox dispatcher (ADR-0068) over a
// real unix socket loopback: one dispatcher, one registered parser worker and one
// submitter per exchange. The kernel observer and the supervisor killer are fakes
// that live in this test package — the dispatcher boundary itself never carries
// them. This is the executable acceptance corpus for SAN-001..SAN-004.
package sandboxdispatch_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

type fakeObserver struct {
	obs sandboxdispatch.Observation
	err error
}

func (f fakeObserver) Observe(_ *net.UnixConn) (sandboxdispatch.Observation, error) {
	return f.obs, f.err
}

type fakeKiller struct {
	mu     sync.Mutex
	killed []sandboxdispatch.Observation
}

func (f *fakeKiller) Kill(obs sandboxdispatch.Observation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, obs)
	return nil
}

func (f *fakeKiller) Killed() []sandboxdispatch.Observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sandboxdispatch.Observation(nil), f.killed...)
}

// startDispatcher opens the broker on a per-test unix socket. The socket lives
// under a short temp directory of its own: AF_UNIX sockets have a bounded path
// length on every platform, and t.TempDir inherits the (long) test name.
func startDispatcher(t *testing.T, observer sandboxdispatch.KernelObserver, killer sandboxdispatch.ProcessKiller) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kvdispatch")
	if err != nil {
		t.Fatalf("temp socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "dispatch.sock")
	dispatcher, err := sandboxdispatch.New(sandboxdispatch.Config{
		SocketPath:      socketPath,
		MaxPayloadBytes: 1 << 20,
		MaxAttempts:     3,
		FrameTimeout:    5 * time.Second,
		Observer:        observer,
		Killer:          killer,
	})
	if err != nil {
		t.Fatalf("start dispatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = dispatcher.ListenAndServe(ctx) }()
	t.Cleanup(cancel)
	return socketPath
}

func defaultObservation() sandboxdispatch.Observation {
	return sandboxdispatch.Observation{
		Limits:     sandboxdispatch.Limits{CPUMillis: 500, MemoryBytes: 512 << 20, PIDsMax: 64},
		PID:        4242,
		ObservedAt: time.Date(2026, time.August, 14, 9, 0, 0, 0, time.UTC),
		CgroupPath: "/kv.slice/kv-dispatch.scope",
	}
}

func newJob(leaseID, parserType string, payload []byte, deadline time.Duration) sandboxdispatch.Job {
	now := time.Now().UTC()
	digest := sha256.Sum256(payload)
	return sandboxdispatch.Job{
		SchemaVersion:   sandboxdispatch.JobVersion,
		JobID:           "job-" + leaseID,
		LeaseID:         leaseID,
		ParserType:      parserType,
		SourceVersionID: "sv-" + leaseID,
		InputArtifact: sandboxdispatch.InputArtifact{
			ArtifactID:    "art-" + leaseID,
			ContentDigest: "sha256:" + hex.EncodeToString(digest[:]),
			MediaType:     "text/plain",
		},
		SubmittedAt:          now.Format(time.RFC3339),
		DeadlineAt:           now.Add(deadline).Format(time.RFC3339),
		WorkerPullOnly:       true,
		ContainerCreationCap: "FORBIDDEN",
		OutputContract:       sandboxdispatch.OutputContractV1,
	}
}

func confirmedOutcome(lease *sandboxdispatch.Lease, identity string) sandboxdispatch.Outcome {
	return sandboxdispatch.Outcome{
		SchemaVersion:      sandboxdispatch.OutcomeVersion,
		LeaseID:            lease.LeaseID,
		JobID:              lease.JobID,
		WorkerID:           lease.WorkerID,
		ParserType:         lease.ParserType,
		Handoff:            sandboxdispatch.Handoff{TransferState: sandboxdispatch.TransferConfirmed, ConfirmationID: "conf-1"},
		Status:             sandboxdispatch.StatusSucceeded,
		ReportedAt:         time.Now().UTC().Format(time.RFC3339),
		ExtractionIdentity: &identity,
	}
}

func retryOutcomeFor(lease *sandboxdispatch.Lease) sandboxdispatch.Outcome {
	return sandboxdispatch.Outcome{
		SchemaVersion: sandboxdispatch.OutcomeVersion,
		LeaseID:       lease.LeaseID,
		JobID:         lease.JobID,
		WorkerID:      lease.WorkerID,
		ParserType:    lease.ParserType,
		Handoff:       sandboxdispatch.Handoff{TransferState: sandboxdispatch.TransferRetry, ConfirmationID: "conf-1"},
		Status:        sandboxdispatch.StatusFailed,
		ReportedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

type submitOutcome struct {
	result    sandboxdispatch.SubmitResult
	retryable bool
	err       error
}

// submitAsync runs the blocking Submit in the background and returns the channel.
func submitAsync(submitter *sandboxdispatch.Submitter, job sandboxdispatch.Job, payload []byte) <-chan submitOutcome {
	done := make(chan submitOutcome, 1)
	go func() {
		result, retryable, err := submitter.Submit(context.Background(), job, payload)
		done <- submitOutcome{result: result, retryable: retryable, err: err}
	}()
	return done
}

// writeRawFrame sends one transport frame by hand (kind byte, 4-byte BE length,
// body) — the integration way to speak as a foreign socket.
func writeRawFrame(conn net.Conn, kind byte, body []byte) error {
	buffer := make([]byte, 5+len(body))
	buffer[0] = kind
	binary.BigEndian.PutUint32(buffer[1:5], uint32(len(body)))
	copy(buffer[5:], body)
	_, err := conn.Write(buffer)
	return err
}

// TestDispatcherLoopbackHappyPath runs the full pull-based lease unit:
// REGISTER -> JOB+PAYLOAD -> OFFERED -> CLAIM -> TRANSFERRED+PAYLOAD ->
// RESULT -> CONFIRMED outcome with the echoed extraction identity -> LIMITS
// confirmation minted from the kernel observation.
func TestDispatcherLoopbackHappyPath(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("the leased document bytes")
	job := newJob("l-happy", sandboxdispatch.ParserTypeText, payload, 10*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	lease, leasedPayload, identity, err := worker.Pull(ctx)
	if err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	if lease.JobID != job.JobID || lease.State != sandboxdispatch.LeaseTransferred {
		t.Fatalf("transferred lease drifted: %#v", lease)
	}
	if string(leasedPayload) != string(payload) {
		t.Fatalf("leased payload drifted: %q", leasedPayload)
	}
	if identity == "" {
		t.Fatalf("dispatcher issued no extraction identity")
	}

	resultBytes := []byte("document-parser-result-v1 payload")
	if err := worker.Report(confirmedOutcome(lease, identity), resultBytes); err != nil {
		t.Fatalf("report outcome: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("submit failed: %v (retryable=%v)", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferConfirmed {
		t.Fatalf("expected CONFIRMED, got %#v", answer.result.Outcome)
	}
	if string(answer.result.Result) != string(resultBytes) {
		t.Fatalf("relayed result drifted: %q", answer.result.Result)
	}
	confirmation := answer.result.Confirmation
	if confirmation == nil {
		t.Fatalf("no limit confirmation relayed")
	}
	if !confirmation.Confirmed || confirmation.ObservationMethod != "KERNEL_CGROUP_NAMESPACE" {
		t.Fatalf("confirmation not kernel-derived: %#v", confirmation)
	}
	if confirmation.Limits.CPUMillis != 500 || confirmation.Limits.MemoryBytes != 512<<20 || confirmation.Limits.PIDsMax != 64 {
		t.Fatalf("confirmation limits drifted: %#v", confirmation.Limits)
	}
	if confirmation.ExtractionIdentity != identity {
		t.Fatalf("confirmation identity drifted: %q != %q", confirmation.ExtractionIdentity, identity)
	}
}

// TestDispatcherLoopbackDigestMismatchRefused proves the payload digest is
// re-derived before any handoff: a declared digest that does not hash the payload
// fails closed and the submitter exchange dies without an answer.
func TestDispatcherLoopbackDigestMismatchRefused(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})
	payload := []byte("payload that does not match the declaration")
	job := newJob("l-digest", sandboxdispatch.ParserTypeText, payload, 10*time.Second)
	job.InputArtifact.ContentDigest = "sha256:" + strings.Repeat("0", 64)

	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	_, retryable, err := submitter.Submit(context.Background(), job, payload)
	if err == nil || retryable {
		t.Fatalf("digest mismatch accepted (err=%v retryable=%v)", err, retryable)
	}
	if !errors.Is(err, sandboxdispatch.ErrSubmitFailed) {
		t.Fatalf("unexpected sentinel: %v", err)
	}
}

// TestDispatcherLoopbackNoWorkerRetry proves a job for a parser type without a
// registered socket comes back RETRY before any transfer, without touching the
// killer or the kernel limits.
func TestDispatcherLoopbackNoWorkerRetry(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})
	payload := []byte("unclaimed document")
	job := newJob("l-retry", sandboxdispatch.ParserTypeOffice, payload, 10*time.Second)

	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	result, retryable, err := submitter.Submit(context.Background(), job, payload)
	if err != nil || !retryable {
		t.Fatalf("expected a retryable answer, got err=%v retryable=%v", err, retryable)
	}
	if result.Outcome.Handoff.TransferState != sandboxdispatch.TransferRetry {
		t.Fatalf("expected RETRY, got %#v", result.Outcome)
	}
	if result.Confirmation != nil {
		t.Fatalf("a job without a transfer must not mint a limit confirmation")
	}
}

// TestDispatcherLoopbackParserTypeMismatchRetry proves a job for another parser
// type never reaches the only registered socket (SAN-002).
func TestDispatcherLoopbackParserTypeMismatchRetry(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("a pdf-shaped document")
	job := newJob("l-mismatch", sandboxdispatch.ParserTypePDF, payload, 10*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	result, retryable, err := submitter.Submit(context.Background(), job, payload)
	if err != nil || !retryable {
		t.Fatalf("expected a retryable answer, got err=%v retryable=%v", err, retryable)
	}
	if result.Outcome.Handoff.TransferState != sandboxdispatch.TransferRetry {
		t.Fatalf("expected RETRY, got %#v", result.Outcome)
	}
}

// TestDispatcherLoopbackRetryAfterTransferQuarantined proves the handoff line:
// a RETRY outcome after the transfer was sent is answered to the submitter as
// QUARANTINED — the supervisor's word, not the worker's (SAN-003, ADR-0068 R-11).
func TestDispatcherLoopbackRetryAfterTransferQuarantined(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("document transferred then failed")
	job := newJob("l-after", sandboxdispatch.ParserTypeText, payload, 10*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	lease, _, _, err := worker.Pull(ctx)
	if err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	if err := worker.Report(retryOutcomeFor(lease), nil); err != nil {
		t.Fatalf("report retry: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("expected a terminal answer, got err=%v retryable=%v", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferQuarantine {
		t.Fatalf("expected QUARANTINED, got %#v", answer.result.Outcome)
	}
}

// TestDispatcherLoopbackDeadlineKillsTheSandboxProcess proves the supervisor owns
// the deadline: when the timer fires after the transfer, the sandbox process is
// killed by its observed pid and the submitter receives QUARANTINED (ADR-0068 R-9).
func TestDispatcherLoopbackDeadlineKillsTheSandboxProcess(t *testing.T) {
	killer := &fakeKiller{}
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, killer)

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("document the worker never answers")
	// The lease window must be long enough for the offer/claim round trip on a
	// loaded host; the deadline-fire is what the test measures, not the round
	// trip latency.
	job := newJob("l-deadline", sandboxdispatch.ParserTypeText, payload, 3*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	// Claim the lease so the transfer is sent, then answer nothing: the deadline
	// must fire and the supervisor must kill the observed pid.
	if _, _, _, err := worker.Pull(ctx); err != nil {
		t.Fatalf("pull lease: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("expected a terminal answer, got err=%v retryable=%v", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferQuarantine {
		t.Fatalf("expected QUARANTINED after the deadline, got %#v", answer.result.Outcome)
	}
	if killed := killer.Killed(); len(killed) != 1 || killed[0].PID != defaultObservation().PID {
		t.Fatalf("supervisor killed wrong process set: %v", killed)
	}
}

// TestDispatcherLoopbackSecondRegistrationSocketRejected proves one parser type
// binds exactly one socket: a second registration for TEXT is closed (SAN-002).
func TestDispatcherLoopbackSecondRegistrationSocketRejected(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register first worker: %v", err)
	}
	defer first.Close()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	hello := `{"worker_id":"w2","parser_type":"TEXT","capabilities":["PULL_JOB","PUSH_OUTCOME"]}`
	if err := writeRawFrame(conn, 1, []byte(hello)); err != nil {
		t.Fatalf("write registration: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("second registration socket not closed: %v", err)
	}
}

// TestDispatcherLoopbackForeignSocketClosed proves an unknown first frame is a
// foreign socket and is closed without an answer (ADR-0068 R-8).
func TestDispatcherLoopbackForeignSocketClosed(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := writeRawFrame(conn, 200, []byte(`{}`)); err != nil {
		t.Fatalf("write foreign frame: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("foreign socket not closed: %v", err)
	}
}

// TestDispatcherLoopbackForgedIdentityQuarantined proves the extraction identity
// is verified against the dispatcher's kernel-derived value: an outcome echoing a
// foreign identity is answered as QUARANTINED, never as a success (SAN-004).
func TestDispatcherLoopbackForgedIdentityQuarantined(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("document with a forged identity echo")
	job := newJob("l-forged", sandboxdispatch.ParserTypeText, payload, 10*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	lease, _, _, err := worker.Pull(ctx)
	if err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	outcome := confirmedOutcome(lease, "sha256:"+strings.Repeat("f", 64))
	if err := worker.Report(outcome, []byte("result-document")); err != nil {
		t.Fatalf("report forged outcome: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("expected a terminal answer, got err=%v retryable=%v", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferQuarantine {
		t.Fatalf("expected QUARANTINED for a forged identity, got %#v", answer.result.Outcome)
	}
}

// TestDispatcherLoopbackDeadlineInversionRejected proves an outcome reported after
// the supervisor's deadline is refused (CONTRACT_VALIDATION.md §10): the lease is
// not confirmed, the deadline fires, the process is killed and the submitter
// receives QUARANTINED (SAN-001, ADR-0068 R-9).
func TestDispatcherLoopbackDeadlineInversionRejected(t *testing.T) {
	killer := &fakeKiller{}
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, killer)

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("document answered after its own deadline")
	job := newJob("l-inversion", sandboxdispatch.ParserTypeText, payload, 3*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	lease, _, identity, err := worker.Pull(ctx)
	if err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	outcome := confirmedOutcome(lease, identity)
	outcome.ReportedAt = time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	if err := worker.Report(outcome, []byte("result-document")); err != nil {
		t.Fatalf("report inverted outcome: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("expected a terminal answer, got err=%v retryable=%v", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferQuarantine {
		t.Fatalf("expected QUARANTINED for a deadline inversion, got %#v", answer.result.Outcome)
	}
	if killed := killer.Killed(); len(killed) != 1 || killed[0].PID != defaultObservation().PID {
		t.Fatalf("supervisor killed wrong process set: %v", killed)
	}
}

// TestDispatcherLoopbackRegistrationWithoutKernelObservationRejected proves the
// registration fails closed when the kernel observation is unavailable: no
// dispatch without evidence (SAN-004).
func TestDispatcherLoopbackRegistrationWithoutKernelObservationRejected(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{err: sandboxdispatch.ErrObservationUnavailable}, &fakeKiller{})
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	hello := `{"worker_id":"w1","parser_type":"TEXT","capabilities":["PULL_JOB","PUSH_OUTCOME"]}`
	if err := writeRawFrame(conn, 1, []byte(hello)); err != nil {
		t.Fatalf("write registration: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := conn.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("registration without observation not closed: %v", err)
	}
}

// TestDispatcherLoopbackDisconnectAfterTransferKillsTheSandboxProcess proves
// ADR-0068 §1.5: a worker that disconnects after the transfer was sent is killed
// by the supervisor — the lease is quarantined and the sandbox process must not
// outlive it, even though the deadline never fired.
func TestDispatcherLoopbackDisconnectAfterTransferKillsTheSandboxProcess(t *testing.T) {
	killer := &fakeKiller{}
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, killer)

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}

	payload := []byte("document whose worker vanishes after the transfer")
	job := newJob("l-disconnect", sandboxdispatch.ParserTypeText, payload, 20*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	// Claim the lease so the transfer is sent, then drop the socket without any
	// answer: the dispatcher must quarantine the lease and kill the sandbox.
	if _, _, _, err := worker.Pull(ctx); err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	if err := worker.Close(); err != nil {
		t.Fatalf("close worker: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("expected a terminal answer, got err=%v retryable=%v", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferQuarantine {
		t.Fatalf("expected QUARANTINED after a post-transfer disconnect, got %#v", answer.result.Outcome)
	}
	if killed := killer.Killed(); len(killed) != 1 || killed[0].PID != defaultObservation().PID {
		t.Fatalf("supervisor killed wrong process set: %v", killed)
	}
}

// TestDispatcherLoopbackLargeResultRelayed proves the result frame is
// payload-sized in both directions: a result above the fixed frame bound (64 KiB)
// is relayed to the submitter intact.
func TestDispatcherLoopbackLargeResultRelayed(t *testing.T) {
	socketPath := startDispatcher(t, fakeObserver{obs: defaultObservation()}, &fakeKiller{})

	workerClient := &sandboxdispatch.WorkerClient{SocketPath: socketPath, MaxPayloadBytes: 1 << 20}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	worker, err := workerClient.Register(ctx, "w1", sandboxdispatch.ParserTypeText)
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	defer worker.Close()

	payload := []byte("small input, large result")
	job := newJob("l-large", sandboxdispatch.ParserTypeText, payload, 20*time.Second)
	submitter := &sandboxdispatch.Submitter{SocketPath: socketPath, MaxPayloadBytes: 1 << 20, FrameTimeout: 5 * time.Second}
	pending := submitAsync(submitter, job, payload)

	lease, _, identity, err := worker.Pull(ctx)
	if err != nil {
		t.Fatalf("pull lease: %v", err)
	}
	resultBytes := []byte(strings.Repeat("r", 128*1024))
	if err := worker.Report(confirmedOutcome(lease, identity), resultBytes); err != nil {
		t.Fatalf("report large result: %v", err)
	}

	answer := <-pending
	if answer.err != nil || answer.retryable {
		t.Fatalf("submit failed: %v (retryable=%v)", answer.err, answer.retryable)
	}
	if answer.result.Outcome.Handoff.TransferState != sandboxdispatch.TransferConfirmed {
		t.Fatalf("expected CONFIRMED, got %#v", answer.result.Outcome)
	}
	if len(answer.result.Result) != len(resultBytes) || string(answer.result.Result) != string(resultBytes) {
		t.Fatalf("relayed result drifted: got %d bytes, want %d", len(answer.result.Result), len(resultBytes))
	}
}
