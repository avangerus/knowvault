package sandboxdispatch

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config pins one dispatcher. Every bound is mandatory: an unbounded socket path,
// payload size, attempt count, frame timeout or a missing observer/killer is a
// configuration error, not a runtime surprise.
type Config struct {
	// SocketPath is the unix socket the dispatcher listens on; the submitter and
	// the parser workers dial it.
	SocketPath string
	// MaxPayloadBytes caps one document payload in either direction.
	MaxPayloadBytes int
	// MaxAttempts is the closed lease attempt bound (1..1000, sandbox-lease-v1).
	MaxAttempts int
	// FrameTimeout bounds one submitter exchange and the registration hello/ack.
	FrameTimeout time.Duration
	// Observer is the kernel observation source; production uses the Linux cgroup
	// observer, tests use a fake.
	Observer KernelObserver
	// Killer is the supervisor's deadline enforcement; production signals the
	// sandbox process, tests use a fake that records the pid.
	Killer ProcessKiller
}

// maxFrameBody keeps a non-payload frame body far below any resource concern while
// staying well above every wire document's schema bound.
const (
	maxFrameBody     = 64 * 1024
	maxPayloadHeader = 4 * 1024
)

// jobResult carries the terminal answer back to the submitter connection.
type jobResult struct {
	outcome      Outcome
	result       []byte
	confirmation *LimitConfirmation
	retryable    bool
}

// workerConn is one registered socket: exactly one parser type, one worker id and
// one kernel observation per connection (SAN-002).
type workerConn struct {
	conn      *net.UnixConn
	hello     RegisterHello
	obs       Observation
	active    *lease
	ready     bool
	readyCh   chan struct{}
	readyOnce sync.Once
	writeMu   sync.Mutex
}

func (worker *workerConn) signalReady() { worker.readyOnce.Do(func() { close(worker.readyCh) }) }

// workerEligible is the synchronous admission predicate for a registered
// worker. The dispatcher calls it while holding d.mu; keeping the predicate
// pure makes the protocol boundary independently testable without turning a
// scheduler timeout into readiness evidence.
func workerEligible(worker *workerConn) bool {
	return worker != nil && worker.ready
}

// Dispatcher is the broker. It holds no container runtime capability: the package
// never spawns a process and never invokes a container runtime; it only leases
// documents to sockets that registered themselves.
type Dispatcher struct {
	cfg Config
	ln  *net.UnixListener

	mu       sync.Mutex
	workers  map[string]*workerConn // parser_type -> the one registered socket
	leases   map[string]*lease      // lease_id -> active lease
	attempts map[string]int         // lease_id -> attempt counter across retries
}

// New validates the configuration and opens the listening socket.
func New(cfg Config) (*Dispatcher, error) {
	if cfg.SocketPath == "" {
		return nil, fmt.Errorf("%w: socket path", ErrInvalidConfig)
	}
	if cfg.MaxPayloadBytes <= 0 {
		return nil, fmt.Errorf("%w: payload bound", ErrInvalidConfig)
	}
	if cfg.MaxAttempts < 1 || cfg.MaxAttempts > 1000 {
		return nil, fmt.Errorf("%w: attempt bound", ErrInvalidConfig)
	}
	if cfg.FrameTimeout <= 0 {
		return nil, fmt.Errorf("%w: frame timeout", ErrInvalidConfig)
	}
	if cfg.Observer == nil || cfg.Killer == nil {
		return nil, fmt.Errorf("%w: observer/killer", ErrInvalidConfig)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		return nil, fmt.Errorf("%w: socket directory", ErrInvalidConfig)
	}
	// A stale socket from a dead dispatcher must not be mistaken for a live one.
	_ = os.Remove(cfg.SocketPath)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: cfg.SocketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("%w: listen", ErrInvalidConfig)
	}
	if err := chmodSocket(cfg.SocketPath); err != nil {
		return nil, fmt.Errorf("%w: socket mode", ErrInvalidConfig)
	}
	return &Dispatcher{
		cfg:      cfg,
		ln:       listener,
		workers:  make(map[string]*workerConn),
		leases:   make(map[string]*lease),
		attempts: make(map[string]int),
	}, nil
}

// SocketPath reports the configured socket path.
func (d *Dispatcher) SocketPath() string { return d.cfg.SocketPath }

// ListenAndServe accepts connections until the context is done.
func (d *Dispatcher) ListenAndServe(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = d.ln.Close()
	}()
	for {
		conn, err := d.ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.handleConn(conn)
	}
}

// handleConn routes a connection by its first frame: a registration hello makes it
// a worker socket, a job makes it a submitter exchange, and anything else is a
// foreign socket and is closed (ADR-0068 R-8).
func (d *Dispatcher) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	kind, body, err := readFrame(conn, maxFrameBody)
	if err != nil {
		return
	}
	switch kind {
	case kindRegister:
		d.registerWorker(conn, body)
	case kindJob:
		d.handleSubmitter(conn, body)
	default:
		// Foreign socket.
		return
	}
}

// registerWorker binds one worker socket to its parser type and serves its frames
// until the connection breaks. A second socket for an already-bound parser type,
// an invalid hello, or a missing kernel observation is rejected (SAN-002).
func (d *Dispatcher) registerWorker(conn *net.UnixConn, body []byte) {
	var hello RegisterHello
	if err := decodeStrict(body, &hello); err != nil || !hello.validate() {
		return
	}
	obs, err := d.cfg.Observer.Observe(conn)
	if err != nil {
		// No kernel evidence: the registration is refused, never retried.
		return
	}

	worker := &workerConn{conn: conn, hello: hello, obs: obs, readyCh: make(chan struct{})}
	d.mu.Lock()
	existing, taken := d.workers[hello.ParserType]
	if !taken || existing == nil {
		d.workers[hello.ParserType] = worker
	}
	d.mu.Unlock()
	if taken {
		// Second registration socket for the same parser type.
		return
	}
	// The parser slot is reserved before the acknowledgment, so a concurrent
	// second registration cannot win. The worker remains ineligible until the
	// complete ACK write succeeds and readiness is published below.
	worker.writeMu.Lock()
	if err := conn.SetWriteDeadline(time.Now().Add(d.cfg.FrameTimeout)); err != nil {
		worker.writeMu.Unlock()
		d.dropWorker(worker)
		return
	}
	if err := writeFrame(conn, kindRegisterAccepted, []byte(registrationAcceptedBody)); err != nil {
		worker.writeMu.Unlock()
		// An acknowledgment write failure means the peer did not complete the
		// registration protocol. Remove the just-published binding before the
		// socket is closed; an unacknowledged worker must never receive leases.
		d.dropWorker(worker)
		return
	}
	// Clear both handshake deadlines before publishing readiness. A submitter
	// may proceed only after the socket is fully in its long-lived session mode.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		worker.writeMu.Unlock()
		d.dropWorker(worker)
		return
	}
	d.mu.Lock()
	if d.workers[hello.ParserType] != worker {
		d.mu.Unlock()
		worker.writeMu.Unlock()
		d.dropWorker(worker)
		return
	}
	worker.ready = true
	worker.signalReady()
	d.mu.Unlock()
	worker.writeMu.Unlock()
	defer d.dropWorker(worker)
	d.serveWorkerFrames(worker)
}

// dropWorker removes a broken or idle registration and resolves its active lease:
// before the transfer the job retries, after the transfer it is quarantined — the
// supervisor's word, not the worker's.
func (d *Dispatcher) dropWorker(worker *workerConn) {
	d.mu.Lock()
	current := d.workers[worker.hello.ParserType]
	if current == worker {
		delete(d.workers, worker.hello.ParserType)
	}
	active := worker.active
	worker.active = nil
	worker.ready = false
	worker.signalReady()
	d.mu.Unlock()
	if active != nil {
		d.expire(active, false)
	}
}

func (d *Dispatcher) writeWorkerLease(worker *workerConn, body []byte) error {
	worker.writeMu.Lock()
	defer worker.writeMu.Unlock()
	return writeFrame(worker.conn, kindLease, body)
}

func (d *Dispatcher) writeWorkerTransfer(worker *workerConn, leaseBody, headerBody, payload []byte) error {
	worker.writeMu.Lock()
	defer worker.writeMu.Unlock()
	if err := writeFrame(worker.conn, kindLease, leaseBody); err != nil {
		return err
	}
	return writePayloadFrame(worker.conn, headerBody, payload)
}

// serveWorkerFrames reads claim and outcome frames from a registered worker. The
// worker socket is read without a frame deadline: a pull-based worker idles while
// it waits for an offer, and the lease deadline, not an idle timeout, owns the
// wall clock.
func (d *Dispatcher) serveWorkerFrames(worker *workerConn) {
	for {
		// The result frame is a payload-sized document; every other worker kind
		// is a fixed-frame wire document.
		kind, body, err := readFrameWith(worker.conn, func(kind frameKind) int {
			if kind == kindResult {
				return d.cfg.MaxPayloadBytes
			}
			return maxFrameBody
		})
		if err != nil {
			return
		}
		switch kind {
		case kindClaim:
			d.handleClaim(worker, body)
		case kindOutcome:
			d.handleOutcome(worker, body)
		case kindResult:
			d.handleResult(worker, body)
		default:
			// Only claim/outcome/result exist on a worker socket.
			return
		}
	}
}

// handleClaim accepts an offered lease (OFFERED -> CLAIMED -> TRANSFERRED), then
// hands over the lease and the payload. From this point the transfer has been
// sent: the handoff is done and every later failure quarantines.
func (d *Dispatcher) handleClaim(worker *workerConn, body []byte) {
	var claim Claim
	if err := decodeStrict(body, &claim); err != nil {
		return
	}
	d.mu.Lock()
	active := d.leases[claim.LeaseID]
	if active == nil || active != worker.active || active.doc.WorkerID != claim.WorkerID ||
		active.doc.WorkerID != worker.hello.WorkerID {
		d.mu.Unlock()
		return
	}
	if err := active.transition(LeaseClaimed, worker.hello.WorkerID, worker.hello.ParserType); err != nil {
		d.mu.Unlock()
		return
	}
	if err := active.transition(LeaseTransferred, worker.hello.WorkerID, worker.hello.ParserType); err != nil {
		d.mu.Unlock()
		return
	}
	active.transferSent = true
	leaseBytes, _ := json.Marshal(active.doc)
	headerBytes, _ := json.Marshal(PayloadHeader{
		LeaseID:            active.doc.LeaseID,
		ExtractionIdentity: d.extractionIdentityLocked(active),
	})
	d.mu.Unlock()

	if err := d.writeWorkerTransfer(worker, leaseBytes, headerBytes, active.payload); err != nil {
		return
	}
}

// handleResult stores the raw result document for the active lease. The dispatcher
// never parses it: it is relayed to the submitter only after a validated outcome,
// and its size is bounded by the payload cap.
func (d *Dispatcher) handleResult(worker *workerConn, body []byte) {
	d.mu.Lock()
	active := worker.active
	if active == nil || active.doc.State != LeaseTransferred {
		d.mu.Unlock()
		return
	}
	active.resultBytes = append(active.resultBytes[:0], body...)
	d.mu.Unlock()
}

// handleOutcome validates the worker outcome against the closed matrix, the lease
// identity and the dispatcher's own kernel-derived extraction identity, then
// resolves the lease. A worker self-report that contradicts the dispatcher is
// quarantined, never retried (SAN-004).
func (d *Dispatcher) handleOutcome(worker *workerConn, body []byte) {
	var outcome Outcome
	if err := decodeStrict(body, &outcome); err != nil {
		return
	}
	reportedAt, err := outcome.validate()
	if err != nil {
		return
	}
	d.mu.Lock()
	active := worker.active
	if active == nil || active != d.leases[outcome.LeaseID] {
		d.mu.Unlock()
		return
	}
	if outcome.JobID != active.doc.JobID || outcome.WorkerID != active.doc.WorkerID ||
		outcome.ParserType != active.doc.ParserType {
		d.mu.Unlock()
		return
	}
	// Deadline inversion: an outcome reported after the supervisor's deadline is
	// refused (CONTRACT_VALIDATION.md §10).
	if reportedAt.After(active.deadlineAt()) || reportedAt.Before(active.issuedAt()) {
		d.mu.Unlock()
		return
	}
	transferState := outcome.Handoff.TransferState
	if transferState == TransferConfirmed {
		if outcome.ExtractionIdentity == nil ||
			*outcome.ExtractionIdentity != d.extractionIdentityLocked(active) {
			// The worker echoed an identity the dispatcher never issued.
			transferState = TransferQuarantine
		}
		if len(active.resultBytes) == 0 {
			// A successful outcome without a result document is not a success.
			transferState = TransferQuarantine
		}
	}
	state, err := active.confirmOutcome(transferState)
	if err != nil {
		d.mu.Unlock()
		return
	}
	if state == LeaseCompleted {
		// The worker result frame is stored in active.resultBytes by handleResult.
		d.resolveLocked(active, jobResult{
			outcome:      outcome,
			result:       append([]byte(nil), active.resultBytes...),
			confirmation: d.confirmationLocked(active),
		})
		return
	}
	if state == LeaseQuarantined {
		d.resolveLocked(active, jobResult{outcome: quarantinedOutcome(active)})
		return
	}
	// RETRY before transfer: the job goes back to the submitter for another
	// attempt, the attempt counter grows and the lease dies.
	d.resolveLocked(active, jobResult{outcome: retryOutcome(active), retryable: true})
}

// resolveLocked finishes a lease: the deadline timer stops, the worker is freed
// and the terminal result is delivered exactly once. Must be called with d.mu held.
func (d *Dispatcher) resolveLocked(active *lease, result jobResult) {
	if active.deadline != nil {
		active.deadline.Stop()
	}
	if worker := d.workers[active.doc.ParserType]; worker != nil && worker.active == active {
		worker.active = nil
	}
	delete(d.leases, active.doc.LeaseID)
	if !result.retryable {
		// The attempt counter survives retries only: a terminal outcome ends
		// the lease identity entirely.
		delete(d.attempts, active.doc.LeaseID)
	}
	select {
	case active.result <- result:
	default:
	}
}

// expire runs when the supervisor's deadline fires. Before the transfer the job is
// retryable; after the transfer it is quarantined. Either way the sandbox process
// is killed — kernel namespaces are torn down with the process, so no descendant
// can survive the lease (ADR-0068 R-9).
func (d *Dispatcher) expire(active *lease, deadlineFired bool) {
	d.mu.Lock()
	if _, stillActive := d.leases[active.doc.LeaseID]; !stillActive {
		d.mu.Unlock()
		return
	}
	if active.deadline != nil {
		active.deadline.Stop()
	}
	// The supervisor kills the sandbox when the deadline fires or when the worker
	// disconnects after the transfer (ADR-0068 §1.5): either way the lease ends
	// and the process must not outlive it. The killer re-verifies the recorded
	// cgroup before signalling, so a reused pid is never hit.
	if active.obs.PID > 0 && (deadlineFired || active.transferSent) {
		_ = d.cfg.Killer.Kill(active.obs)
	}
	if active.transferSent {
		if err := active.transition(LeaseQuarantined, active.doc.WorkerID, active.doc.ParserType); err == nil {
			d.resolveLocked(active, jobResult{outcome: quarantinedOutcome(active)})
		} else {
			d.mu.Unlock()
			return
		}
		return
	}
	if err := active.transition(LeaseExpired, active.doc.WorkerID, active.doc.ParserType); err != nil {
		d.mu.Unlock()
		return
	}
	if active.doc.Attempt >= d.cfg.MaxAttempts {
		d.resolveLocked(active, jobResult{outcome: quarantinedOutcome(active)})
		return
	}
	d.resolveLocked(active, jobResult{outcome: retryOutcome(active), retryable: true})
}

// handleSubmitter serves one job exchange: job frame, payload frame, digest check,
// lease offer, and the terminal relay. The connection is a single exchange, so
// every read runs under the frame timeout.
func (d *Dispatcher) handleSubmitter(conn *net.UnixConn, jobBody []byte) {
	var job Job
	if err := decodeStrict(jobBody, &job); err != nil {
		return
	}
	now := time.Now().UTC()
	submittedAt, deadlineAt, err := job.Validate(now)
	if err != nil {
		_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(d.cfg.FrameTimeout))
	header, payload, err := readPayloadFrame(conn, d.cfg.MaxPayloadBytes)
	if err != nil {
		return
	}
	if header.LeaseID != "" && header.LeaseID != job.LeaseID {
		return
	}
	// Digest re-derivation before any handoff: a payload that does not hash to the
	// declared content_digest is refused (fail-closed).
	digest := sha256.Sum256(payload)
	if "sha256:"+hex.EncodeToString(digest[:]) != job.InputArtifact.ContentDigest {
		return
	}

	var worker *workerConn
	for {
		d.mu.Lock()
		if active, exists := d.leases[job.LeaseID]; exists && active != nil {
			d.mu.Unlock()
			_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
			return
		}
		worker = d.workers[job.ParserType]
		if worker == nil || (worker.active != nil && !worker.active.canOffer()) {
			d.mu.Unlock()
			_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
			return
		}
		if workerEligible(worker) {
			break
		}
		readyCh := worker.readyCh
		d.mu.Unlock()
		wait := d.cfg.FrameTimeout
		if remaining := time.Until(deadlineAt); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
			return
		}
		timer := time.NewTimer(wait)
		select {
		case <-readyCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
			_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
			return
		}
	}
	attempt := d.attempts[job.LeaseID] + 1
	// Wall-clock is a dispatcher policy quantity derived from the validated
	// job's lease window, not a kernel reading (no kernel clock observation
	// exists); it binds the extraction identity the same way the kernel-derived
	// limits do, so a job cannot mint its own bound.
	wallClock := deadlineAt.Sub(submittedAt)
	active := &lease{
		doc: Lease{
			SchemaVersion: LeaseVersion,
			LeaseID:       job.LeaseID,
			JobID:         job.JobID,
			WorkerID:      worker.hello.WorkerID,
			ParserType:    job.ParserType,
			Registration: Registration{
				SocketID:     "unix://" + d.cfg.SocketPath,
				ParserType:   worker.hello.ParserType,
				SingleSock:   true,
				Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome},
			},
			IssuedAt:  now.Format(time.RFC3339),
			ExpiresAt: deadlineAt.UTC().Format(time.RFC3339),
			Attempt:   attempt,
			State:     LeaseOffered,
		},
		job:       job,
		payload:   payload,
		obs:       worker.obs,
		wallClock: wallClock,
		result:    make(chan jobResult, 1),
	}
	worker.active = active
	d.leases[job.LeaseID] = active
	d.attempts[job.LeaseID] = attempt
	active.deadline = time.AfterFunc(time.Until(deadlineAt), func() { d.expire(active, true) })
	leaseBytes, _ := json.Marshal(active.doc)
	d.mu.Unlock()

	if err := d.writeWorkerLease(worker, leaseBytes); err != nil {
		d.expire(active, false)
		_ = writeFrame(conn, kindOutcome, marshalOutcome(retryOutcomeDoc(job)))
		return
	}
	result := <-active.result
	_ = writeFrame(conn, kindOutcome, marshalOutcome(result.outcome))
	if result.result != nil {
		_ = writeResultFrame(conn, result.result, d.cfg.MaxPayloadBytes)
	}
	if result.confirmation != nil {
		_ = writeFrame(conn, kindLimits, marshalOutcome(result.confirmation))
	}
}

// extractionIdentityLocked derives the identity for a lease from the kernel
// observation the dispatcher owns. Must be called with d.mu held.
func (d *Dispatcher) extractionIdentityLocked(active *lease) string {
	return CanonicalLimitsIdentity(
		active.doc.LeaseID, active.doc.JobID, active.doc.WorkerID, active.doc.ParserType,
		active.obs.ObservedAt,
		Limits{
			CPUMillis:   active.obs.Limits.CPUMillis,
			MemoryBytes: active.obs.Limits.MemoryBytes,
			PIDsMax:     active.obs.Limits.PIDsMax,
			WallClockMS: active.wallClock.Milliseconds(),
		},
	)
}

// confirmationLocked mints the kernel limit confirmation for a completed lease.
// Must be called with d.mu held.
func (d *Dispatcher) confirmationLocked(active *lease) *LimitConfirmation {
	limits := Limits{
		CPUMillis:   active.obs.Limits.CPUMillis,
		MemoryBytes: active.obs.Limits.MemoryBytes,
		PIDsMax:     active.obs.Limits.PIDsMax,
		WallClockMS: active.wallClock.Milliseconds(),
	}
	return &LimitConfirmation{
		SchemaVersion:      LimitsVersion,
		LeaseID:            active.doc.LeaseID,
		JobID:              active.doc.JobID,
		WorkerID:           active.doc.WorkerID,
		ObservedAt:         active.obs.ObservedAt.UTC().Format(time.RFC3339),
		ObservationMethod:  "KERNEL_CGROUP_NAMESPACE",
		Limits:             limits,
		ExtractionIdentity: d.extractionIdentityLocked(active),
		Confirmed:          true,
	}
}

func (l *lease) deadlineAt() time.Time {
	parsed, _ := parseTimestamp(l.doc.ExpiresAt)
	return parsed
}

func (l *lease) issuedAt() time.Time {
	parsed, _ := parseTimestamp(l.doc.IssuedAt)
	return parsed
}

// retryOutcomeDoc builds the dispatcher's own retry answer for a job that never
// reached a worker. The confirmation id is dispatcher-owned.
func retryOutcomeDoc(job Job) Outcome {
	return Outcome{
		SchemaVersion: OutcomeVersion,
		LeaseID:       job.LeaseID,
		JobID:         job.JobID,
		WorkerID:      "dispatcher",
		ParserType:    job.ParserType,
		Handoff:       Handoff{TransferState: TransferRetry, ConfirmationID: "dispatcher:" + job.LeaseID},
		Status:        StatusFailed,
		ReportedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func retryOutcome(active *lease) Outcome {
	outcome := retryOutcomeDoc(active.job)
	outcome.WorkerID = active.doc.WorkerID
	outcome.ReportedAt = time.Now().UTC().Format(time.RFC3339)
	return outcome
}

func quarantinedOutcome(active *lease) Outcome {
	return Outcome{
		SchemaVersion: OutcomeVersion,
		LeaseID:       active.doc.LeaseID,
		JobID:         active.doc.JobID,
		WorkerID:      active.doc.WorkerID,
		ParserType:    active.doc.ParserType,
		Handoff:       Handoff{TransferState: TransferQuarantine, ConfirmationID: "dispatcher:" + active.doc.LeaseID},
		Status:        StatusQuarantine,
		ReportedAt:    time.Now().UTC().Format(time.RFC3339),
	}
}

func marshalOutcome(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// readFrame reads one framed message body with a single cap for every kind.
func readFrame(conn net.Conn, maxBody int) (frameKind, []byte, error) {
	return readFrameWith(conn, func(frameKind) int { return maxBody })
}

// readFrameWith reads one framed message body with a per-kind cap: the result
// frame is bounded by the payload cap, every other kind by the fixed frame cap.
func readFrameWith(conn net.Conn, capFor func(frameKind) int) (frameKind, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(head[1:])
	if length == 0 || length > uint32(capFor(frameKind(head[0]))) {
		return 0, nil, fmt.Errorf("%w: frame length", ErrWireRejected)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return frameKind(head[0]), body, nil
}

// writeFrame writes one framed message capped at the fixed frame bound.
func writeFrame(conn net.Conn, kind frameKind, body []byte) error {
	return writeFrameCap(conn, kind, body, maxFrameBody)
}

// writeFrameCap writes one framed message capped at maxBody.
func writeFrameCap(conn net.Conn, kind frameKind, body []byte, maxBody int) error {
	if len(body) > maxBody {
		return fmt.Errorf("%w: frame length", ErrWireRejected)
	}
	var head [5]byte
	head[0] = byte(kind)
	binary.BigEndian.PutUint32(head[1:], uint32(len(body)))
	if err := writeAll(conn, head[:]); err != nil {
		return err
	}
	if err := writeAll(conn, body); err != nil {
		return err
	}
	return nil
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		written, err := conn.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// writeResultFrame writes a result frame capped at the payload bound: the
// relayed result is a payload-sized document, not a fixed-frame-sized one.
func writeResultFrame(conn net.Conn, body []byte, maxResult int) error {
	return writeFrameCap(conn, kindResult, body, maxResult)
}

// writePayloadFrame writes a payload frame: header length, payload length, header
// JSON, raw document bytes.
func writePayloadFrame(conn net.Conn, header []byte, payload []byte) error {
	if len(header) > maxPayloadHeader {
		return fmt.Errorf("%w: payload header", ErrWireRejected)
	}
	var head [9]byte
	head[0] = byte(kindPayload)
	binary.BigEndian.PutUint32(head[1:], uint32(len(header)))
	binary.BigEndian.PutUint32(head[5:], uint32(len(payload)))
	if err := writeAll(conn, head[:]); err != nil {
		return err
	}
	if err := writeAll(conn, header); err != nil {
		return err
	}
	if err := writeAll(conn, payload); err != nil {
		return err
	}
	return nil
}

// readPayloadFrame reads a payload frame with the payload capped at maxPayload.
func readPayloadFrame(conn net.Conn, maxPayload int) (PayloadHeader, []byte, error) {
	var head [9]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return PayloadHeader{}, nil, err
	}
	headerLen := binary.BigEndian.Uint32(head[1:])
	payloadLen := binary.BigEndian.Uint32(head[5:])
	if headerLen == 0 || headerLen > maxPayloadHeader || payloadLen == 0 || payloadLen > uint32(maxPayload) {
		return PayloadHeader{}, nil, fmt.Errorf("%w: payload length", ErrWireRejected)
	}
	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(conn, headerBytes); err != nil {
		return PayloadHeader{}, nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return PayloadHeader{}, nil, err
	}
	var header PayloadHeader
	if err := decodeStrict(headerBytes, &header); err != nil {
		return PayloadHeader{}, nil, fmt.Errorf("%w: payload header", ErrWireRejected)
	}
	return header, payload, nil
}

// readPayloadFrameV2 is the same bounded opaque payload envelope with the v2
// transport header. It is separate from the v1 decoder so extraction_identity
// cannot cross protocol versions.
func readPayloadFrameV2(conn net.Conn, maxPayload int) (PayloadHeaderV2, []byte, error) {
	var head [9]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return PayloadHeaderV2{}, nil, err
	}
	headerLen := binary.BigEndian.Uint32(head[1:])
	payloadLen := binary.BigEndian.Uint32(head[5:])
	if headerLen == 0 || headerLen > maxPayloadHeader || payloadLen == 0 || payloadLen > uint32(maxPayload) {
		return PayloadHeaderV2{}, nil, fmt.Errorf("%w: v2 payload length", ErrWireRejected)
	}
	headerBytes := make([]byte, headerLen)
	if _, err := io.ReadFull(conn, headerBytes); err != nil {
		return PayloadHeaderV2{}, nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return PayloadHeaderV2{}, nil, err
	}
	var header PayloadHeaderV2
	if err := decodeStrict(headerBytes, &header); err != nil {
		return PayloadHeaderV2{}, nil, fmt.Errorf("%w: v2 payload header", ErrWireRejected)
	}
	return header, payload, nil
}
