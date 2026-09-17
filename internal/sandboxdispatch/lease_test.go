package sandboxdispatch

import (
	"testing"
	"time"
)

func newTestLease(state LeaseState) *lease {
	return &lease{
		doc: Lease{
			LeaseID:    "l1",
			JobID:      "j1",
			WorkerID:   "w1",
			ParserType: ParserTypeText,
			State:      state,
		},
		wallClock: time.Minute,
		result:    make(chan jobResult, 1),
	}
}

func TestLeaseStateMachineClosedPaths(t *testing.T) {
	t.Parallel()

	happy := newTestLease(LeaseOffered)
	if err := happy.transition(LeaseClaimed, "w1", ParserTypeText); err != nil {
		t.Fatalf("OFFERED -> CLAIMED: %v", err)
	}
	if err := happy.transition(LeaseTransferred, "w1", ParserTypeText); err != nil {
		t.Fatalf("CLAIMED -> TRANSFERRED: %v", err)
	}
	happy.transferSent = true
	if err := happy.transition(LeaseCompleted, "w1", ParserTypeText); err != nil {
		t.Fatalf("TRANSFERRED -> COMPLETED: %v", err)
	}
	if err := happy.transition(LeaseOffered, "w1", ParserTypeText); err == nil {
		t.Fatalf("terminal lease re-opened")
	}
}

func TestLeaseStateMachineRejectsOutOfOrderAndForeignWorker(t *testing.T) {
	t.Parallel()

	skip := newTestLease(LeaseOffered)
	if err := skip.transition(LeaseTransferred, "w1", ParserTypeText); err == nil {
		t.Fatalf("OFFERED -> TRANSFERRED without claim accepted")
	}
	if err := skip.transition(LeaseClaimed, "w2", ParserTypeText); err == nil {
		t.Fatalf("foreign worker transition accepted")
	}
	if err := skip.transition(LeaseClaimed, "w1", ParserTypeOffice); err == nil {
		t.Fatalf("foreign parser type transition accepted")
	}
}

func TestLeaseConfirmOutcomeHandoffSemantics(t *testing.T) {
	t.Parallel()

	// RETRY before transfer: the lease expires and the job retries.
	before := newTestLease(LeaseOffered)
	state, err := before.confirmOutcome(TransferRetry)
	if err != nil || state != LeaseExpired {
		t.Fatalf("pre-transfer retry: state=%s err=%v", state, err)
	}

	// RETRY after transfer: the dispatcher quarantines, never retries.
	after := newTestLease(LeaseTransferred)
	after.transferSent = true
	state, err = after.confirmOutcome(TransferRetry)
	if err != nil || state != LeaseQuarantined {
		t.Fatalf("post-transfer retry: state=%s err=%v", state, err)
	}

	// CONFIRMED before transfer is impossible.
	early := newTestLease(LeaseOffered)
	if _, err := early.confirmOutcome(TransferConfirmed); err == nil {
		t.Fatalf("confirmation before transfer accepted")
	}

	// QUARANTINED quarantines from any active state.
	quarantine := newTestLease(LeaseClaimed)
	state, err = quarantine.confirmOutcome(TransferQuarantine)
	if err != nil || state != LeaseQuarantined {
		t.Fatalf("quarantine: state=%s err=%v", state, err)
	}
}

func TestLeaseCanOfferOnlyWhenTerminal(t *testing.T) {
	t.Parallel()

	for _, state := range []LeaseState{LeaseCompleted, LeaseQuarantined, LeaseExpired} {
		if !newTestLease(state).canOffer() {
			t.Fatalf("terminal lease %s cannot offer again", state)
		}
	}
	for _, state := range []LeaseState{LeaseOffered, LeaseClaimed, LeaseTransferred} {
		if newTestLease(state).canOffer() {
			t.Fatalf("active lease %s offers a second document", state)
		}
	}
}
