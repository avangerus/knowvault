package sandboxdispatch

import (
	"net"
	"testing"
	"time"
)

// This is deliberately a state-machine test: kernel-dependent teardown and
// cgroup success are exercised only by the privileged Linux integration gate.
func TestDispatcherV2RedDrainLatchesAndStopsAdmission(t *testing.T) {
	d := &DispatcherV2{
		workers:         make(map[string]*v2Worker),
		leases:          make(map[string]*v2Lease),
		terminal:        make(map[string]time.Time),
		handoffs:        make(map[string]*v2Handoff),
		handoffTerminal: make(map[string]time.Time),
		conns:           make(map[*net.UnixConn]struct{}),
	}
	d.markV2Red()
	if d.Ready() {
		t.Fatal("RED dispatcher reported ready")
	}
	d.markV2Red()
	if !d.red {
		t.Fatal("RED latch was cleared")
	}
	// This call must be a no-op after the latch, including with no socket;
	// publication is forbidden once RED is visible.
	d.writeV2SubmitResult(nil, v2JobResult{})
}
