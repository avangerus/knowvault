package sandboxdispatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// Submitter dials the dispatcher for one job exchange: job, payload, and the
// terminal relay — outcome, raw result and the kernel limit confirmation. It is
// the future production wiring point of the ingestion worker; today it is used by
// the dispatcher's integration tests on a real unix socket.
type Submitter struct {
	SocketPath         string
	V2SubmitSocketPath string
	MaxPayloadBytes    int
	FrameTimeout       time.Duration
}

// SubmitResult is the terminal relay a submitter receives.
type SubmitResult struct {
	Outcome      Outcome
	Result       []byte
	Confirmation *LimitConfirmation
}

// ErrSubmitFailed is the single content-free submitter sentinel.
var ErrSubmitFailed = fmt.Errorf("%w: submit failed", ErrDispatchFailed)

// Submit runs one job exchange. Retryable is true when the dispatcher answered
// RETRY before any transfer; the caller may resubmit with the same job.
func (s *Submitter) Submit(ctx context.Context, job Job, payload []byte) (SubmitResult, bool, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", s.SocketPath)
	if err != nil {
		return SubmitResult{}, false, ErrSubmitFailed
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.FrameTimeout))

	jobBytes, err := json.Marshal(job)
	if err != nil {
		return SubmitResult{}, false, ErrSubmitFailed
	}
	if err := writeFrame(conn, kindJob, jobBytes); err != nil {
		return SubmitResult{}, false, ErrSubmitFailed
	}
	// The submitter's payload header is empty: the dispatcher already knows the
	// job it bound this exchange to.
	if err := writePayloadFrame(conn, []byte("{}"), payload); err != nil {
		return SubmitResult{}, false, ErrSubmitFailed
	}

	result := SubmitResult{}
	for {
		// The relayed result is payload-sized; every other frame is a fixed-frame
		// wire document.
		kind, body, err := readFrameWith(conn, func(kind frameKind) int {
			if kind == kindResult {
				return s.MaxPayloadBytes
			}
			return maxFrameBody
		})
		if err != nil {
			return SubmitResult{}, false, ErrSubmitFailed
		}
		switch kind {
		case kindOutcome:
			if err := decodeStrict(body, &result.Outcome); err != nil {
				return SubmitResult{}, false, ErrSubmitFailed
			}
			switch result.Outcome.Handoff.TransferState {
			case TransferRetry:
				return result, true, nil
			case TransferQuarantine:
				return result, false, nil
			}
		case kindResult:
			result.Result = append([]byte(nil), body...)
		case kindLimits:
			var confirmation LimitConfirmation
			if err := decodeStrict(body, &confirmation); err != nil {
				return SubmitResult{}, false, ErrSubmitFailed
			}
			result.Confirmation = &confirmation
			return result, false, nil
		default:
			return SubmitResult{}, false, ErrSubmitFailed
		}
	}
}

// WorkerClient dials the dispatcher as a parser worker and pulls one leased
// document at a time. It exists for the dispatcher's integration tests and the
// future parser-worker composition.
type WorkerClient struct {
	SocketPath                     string
	V2OfficeRegistrationSocketPath string
	V2PDFRegistrationSocketPath    string
	// V2OCRRegistrationSocketPath is populated only by an OCR-enabled
	// DispatcherV2 composition. Keeping it separate preserves the physical
	// role/socket boundary; an OCR worker cannot register through Office/PDF.
	V2OCRRegistrationSocketPath string
	MaxPayloadBytes             int
}

// WorkerSession is one registered socket: exactly one parser type, one worker id.
type WorkerSession struct {
	conn            *net.UnixConn
	WorkerID        string
	ParserType      string
	maxPayloadBytes int
	v2              bool
	v2Lease         *LeaseV2
	v2Header        PayloadHeaderV2
	v2StateMu       sync.Mutex
}

// Register binds the worker id and parser type to a fresh socket and returns the
// session. A second socket for the same parser type, or a host without kernel
// observation, is rejected by the dispatcher.
func (w *WorkerClient) Register(ctx context.Context, workerID, parserType string) (*WorkerSession, error) {
	if ctx == nil {
		return nil, ErrRegistrationRejected
	}
	// Register must wait for a bounded acceptance acknowledgment. Requiring a
	// caller deadline is fail-closed and prevents a missing/slow dispatcher from
	// leaving a worker blocked forever in the registration handshake.
	deadline, bounded := ctx.Deadline()
	if !bounded || ctx.Err() != nil {
		return nil, ErrRegistrationRejected
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", w.SocketPath)
	if err != nil {
		return nil, ErrRegistrationRejected
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, ErrRegistrationRejected
	}
	// Bound both the hello write and the exact acceptance read by the caller's
	// context deadline. The deadline is cleared only after the ACK is accepted.
	if err := unixConn.SetDeadline(deadline); err != nil {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		// SetDeadline is safe while another goroutine is blocked in read/write;
		// it wakes the handshake immediately when the caller cancels.
		_ = unixConn.SetDeadline(time.Now())
	})
	watcherActive := true
	defer func() {
		if watcherActive {
			stopCancellation()
		}
	}()
	hello := RegisterHello{
		WorkerID:     workerID,
		ParserType:   parserType,
		Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome},
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	if err := writeFrame(unixConn, kindRegister, helloBytes); err != nil {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	kind, body, err := readFrame(unixConn, maxFrameBody)
	if err != nil || kind != kindRegisterAccepted || string(body) != registrationAcceptedBody {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	// Stop the cancellation watcher and observe the context once more before
	// clearing the handshake deadline. If cancellation won the race, never
	// return a session whose socket could be left usable after cancellation.
	if stopped := stopCancellation(); stopped {
		watcherActive = false
	} else {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	if err := ctx.Err(); err != nil {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	if err := unixConn.SetDeadline(time.Time{}); err != nil {
		unixConn.Close()
		return nil, ErrRegistrationRejected
	}
	return &WorkerSession{
		conn:            unixConn,
		WorkerID:        workerID,
		ParserType:      parserType,
		maxPayloadBytes: w.MaxPayloadBytes,
	}, nil
}

// Close ends the session.
func (w *WorkerSession) Close() error { return w.conn.Close() }

// Pull waits for one offered lease, claims it, and returns the lease document and
// the leased payload bytes together with the dispatcher-issued extraction
// identity. It is the pull side of the one-document lease unit.
func (w *WorkerSession) Pull(ctx context.Context) (*Lease, []byte, string, error) {
	for {
		if ctx.Err() != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		kind, body, err := readFrame(w.conn, maxFrameBody)
		if err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if kind != kindLease {
			return nil, nil, "", ErrLeaseRejected
		}
		var offered Lease
		if err := decodeStrict(body, &offered); err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if offered.State != LeaseOffered || offered.WorkerID != w.WorkerID ||
			offered.ParserType != w.ParserType {
			return nil, nil, "", ErrLeaseRejected
		}
		claim := Claim{LeaseID: offered.LeaseID, WorkerID: w.WorkerID}
		claimBytes, err := json.Marshal(claim)
		if err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if err := writeFrame(w.conn, kindClaim, claimBytes); err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		kind, body, err = readFrame(w.conn, maxFrameBody)
		if err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if kind != kindLease {
			return nil, nil, "", ErrLeaseRejected
		}
		var transferred Lease
		if err := decodeStrict(body, &transferred); err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if transferred.State != LeaseTransferred || transferred.LeaseID != offered.LeaseID {
			return nil, nil, "", ErrLeaseRejected
		}
		header, payload, err := readPayloadFrame(w.conn, w.maxPayloadBytes)
		if err != nil {
			return nil, nil, "", ErrLeaseRejected
		}
		if header.LeaseID != offered.LeaseID {
			return nil, nil, "", ErrLeaseRejected
		}
		return &transferred, payload, header.ExtractionIdentity, nil
	}
}

// Report sends the raw result document and the outcome back to the dispatcher.
// The extraction identity is the dispatcher-issued value echoed verbatim.
func (w *WorkerSession) Report(outcome Outcome, result []byte) error {
	if result != nil {
		if err := writeResultFrame(w.conn, result, w.maxPayloadBytes); err != nil {
			return ErrOutcomeRejected
		}
	}
	outcomeBytes, err := json.Marshal(outcome)
	if err != nil {
		return ErrOutcomeRejected
	}
	if err := writeFrame(w.conn, kindOutcome, outcomeBytes); err != nil {
		return ErrOutcomeRejected
	}
	return nil
}
