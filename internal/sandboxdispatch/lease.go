package sandboxdispatch

import (
	"fmt"
	"time"
)

// lease is the dispatcher's internal lease bookkeeping: the wire document it hands
// the worker plus the private fields the worker never sees — the registered socket
// it is bound to, the job payload digest, the kernel observation, the wall-clock
// deadline the supervisor owns and the channel that carries the terminal result
// back to the submitter's connection.
type lease struct {
	doc          Lease
	job          Job
	payload      []byte
	resultBytes  []byte
	obs          Observation
	wallClock    time.Duration
	transferSent bool
	result       chan jobResult
	deadline     *time.Timer
}

// transition validates and applies one state change. The closed machine is
// OFFERED -> CLAIMED -> TRANSFERRED -> COMPLETED | QUARANTINED | EXPIRED, with a
// retry outcome accepted only while no transfer has been sent (SAN-003: retry
// before transfer, quarantine after transfer). A call that would move the lease
// out of the machine, out of order, or off its bound worker is rejected.
func (l *lease) transition(next LeaseState, boundWorker, boundParser string) error {
	if l.doc.WorkerID != boundWorker || l.doc.ParserType != boundParser {
		return fmt.Errorf("%w: worker binding", ErrLeaseRejected)
	}
	valid := false
	switch l.doc.State {
	case LeaseOffered:
		valid = next == LeaseClaimed || next == LeaseExpired || next == LeaseQuarantined
	case LeaseClaimed:
		valid = next == LeaseTransferred || next == LeaseExpired || next == LeaseQuarantined
	case LeaseTransferred:
		valid = next == LeaseCompleted || next == LeaseQuarantined || next == LeaseExpired
	case LeaseCompleted, LeaseQuarantined, LeaseExpired:
		valid = false
	default:
		return fmt.Errorf("%w: unknown state", ErrLeaseRejected)
	}
	if !valid {
		return fmt.Errorf("%w: %s -> %s", ErrLeaseRejected, l.doc.State, next)
	}
	l.doc.State = next
	return nil
}

// canOffer reports whether the bound worker has no active lease: the unit of a
// lease is one document, and a second offer is not made until the current lease is
// terminal.
func (l *lease) canOffer() bool {
	switch l.doc.State {
	case LeaseCompleted, LeaseQuarantined, LeaseExpired:
		return true
	}
	return false
}

// confirmOutcome folds a validated worker outcome into the machine: CONFIRMED
// completes the lease, QUARANTINED quarantines it, and RETRY is accepted only
// before the transfer — after the transfer it is overridden by the dispatcher's
// own quarantine, never by the worker's word.
func (l *lease) confirmOutcome(transferState string) (LeaseState, error) {
	switch transferState {
	case TransferConfirmed:
		if !l.transferSent {
			return l.doc.State, fmt.Errorf("%w: confirmation before transfer", ErrOutcomeRejected)
		}
		if err := l.transition(LeaseCompleted, l.doc.WorkerID, l.doc.ParserType); err != nil {
			return l.doc.State, err
		}
		return LeaseCompleted, nil
	case TransferRetry:
		if l.transferSent {
			if err := l.transition(LeaseQuarantined, l.doc.WorkerID, l.doc.ParserType); err != nil {
				return l.doc.State, err
			}
			return LeaseQuarantined, nil
		}
		if err := l.transition(LeaseExpired, l.doc.WorkerID, l.doc.ParserType); err != nil {
			return l.doc.State, err
		}
		return LeaseExpired, nil
	case TransferQuarantine:
		if err := l.transition(LeaseQuarantined, l.doc.WorkerID, l.doc.ParserType); err != nil {
			return l.doc.State, err
		}
		return LeaseQuarantined, nil
	default:
		return l.doc.State, fmt.Errorf("%w: transfer_state", ErrOutcomeRejected)
	}
}
