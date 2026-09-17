package sandboxdispatch

import (
	"net"
	"time"
)

// Observation is the kernel-observed fact set for one registered socket: the
// finite resource bounds read from the peer's cgroup and the peer's process id.
// The process id is the supervisor's kill target when a lease ends; kernel
// namespaces are torn down with that process, so no descendant can survive the
// lease (ADR-0068 R-9).
type Observation struct {
	Limits Limits
	PID    int
	// ObservedAt is the instant the kernel state was read; the extraction
	// identity binds the observation time, so a replayed observation cannot be
	// re-keyed later.
	ObservedAt time.Time
	// CgroupPath is the unified hierarchy path the limits were read from. The
	// production killer re-verifies it against /proc/<pid>/cgroup before
	// signalling, so a reused pid is never hit (SAN-001).
	CgroupPath string
}

// KernelObserver reads trusted kernel state for a connected worker socket. The
// dispatcher never accepts limits from a worker self-report: the only accepted
// source is this observation, taken from the socket peer's credentials (SAN-004).
// The production implementation is the Linux cgroup v2 observer; on any other
// platform Observe returns ErrObservationUnavailable and every registration is
// refused — the dispatcher fails closed rather than dispatch without evidence.
type KernelObserver interface {
	Observe(conn *net.UnixConn) (Observation, error)
}

// ProcessKiller terminates the sandbox process when a lease ends: on a deadline
// fire or on a worker disconnect after the transfer. The production
// implementation re-verifies the recorded cgroup before signalling; the fake
// used in tests records the observation instead, so a unit test can assert the
// supervisor acted without killing a real process.
type ProcessKiller interface {
	Kill(obs Observation) error
}

// unavailableObserver is the fail-closed observer for platforms without the
// Linux cgroup namespace observation.
type unavailableObserver struct{}

func (unavailableObserver) Observe(_ *net.UnixConn) (Observation, error) {
	return Observation{}, ErrObservationUnavailable
}

// NewKernelObserver returns the production observer for this platform.
func NewKernelObserver() KernelObserver { return newPlatformObserver() }

// NewProcessKiller returns the production supervisor killer for this platform.
func NewProcessKiller() ProcessKiller { return newPlatformKiller() }
