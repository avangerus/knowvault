//go:build linux

package sandboxdispatch

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	v2CgroupRoot       = "/sys/fs/cgroup"
	v2SupervisorPollMS = 50
)

var errV2PidfdPollTimeout = errors.New("sandboxdispatch: pidfd poll timeout")

// linuxV2Supervisor is the built-in one-shot process boundary. It neither
// launches nor reuses a parser. Teardown sends a pidfd-scoped SIGKILL and then
// writes cgroup.kill so descendants are fenced; ConfirmGone waits on the same
// pidfd and requires both cgroup.events populated=0 and an empty cgroup.procs.
// The timeout is supplied by the deployment's bounded frame timeout and is
// never unbounded by a worker or submitter.
type linuxV2Supervisor struct {
	timeout time.Duration
}

func newV2PlatformSupervisor(timeout time.Duration) (KernelObserver, V2Supervisor, error) {
	if timeout <= 0 {
		return nil, nil, ErrSupervisorHandoffUnavailable
	}
	return NewKernelObserver(), linuxV2Supervisor{timeout: timeout}, nil
}

func (s linuxV2Supervisor) Teardown(ctx context.Context, peer V2PeerHandle) error {
	if ctx == nil {
		return ErrKillUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ErrKillUnavailable
	}
	if err := validateV2SupervisorPeer(peer); err != nil {
		return err
	}
	// A normally reaped pidfd reports Pid:-1. validateV2SupervisorPeer has
	// already proved it is readable and exited; cgroup.kill remains mandatory
	// because descendants may outlive a leader in a malformed setup.
	pid, err := readV2PidfdPID(peer.PIDFD)
	if err != nil {
		return ErrKillUnavailable
	}
	if pid > 0 {
		if err := unix.PidfdSendSignal(peer.PIDFD, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return ErrKillUnavailable
		}
	}
	if err := writeV2CgroupKillPeer(peer); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return ErrKillUnavailable
	}
	return nil
}

func (s linuxV2Supervisor) ConfirmGone(ctx context.Context, peer V2PeerHandle) error {
	if ctx == nil {
		return ErrKillUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ErrKillUnavailable
	}
	if err := validateV2SupervisorPeer(peer); err != nil {
		return err
	}
	deadline := time.Now().Add(s.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	pidGone := false
	for {
		if err := ctx.Err(); err != nil {
			return ErrKillUnavailable
		}
		if err := pollV2Pidfd(ctx, peer.PIDFD, remainingV2Duration(deadline)); err != nil {
			if !errors.Is(err, errV2PidfdPollTimeout) {
				return err
			}
		} else {
			pidGone = true
		}
		if pidGone && v2CgroupGonePeer(peer) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return ErrKillUnavailable
		}
	}
}

func validateV2SupervisorPeer(peer V2PeerHandle) error {
	if peer.PIDFD < 0 || peer.Observation.PID < 1 || !validCgroupPath(peer.Observation.CgroupPath) ||
		peer.NamespaceID == "" || !validNamespaceInode(peer.NamespaceID) {
		return ErrSupervisorHandoffUnavailable
	}
	if err := setV2PidfdCloexec(peer.PIDFD); err != nil {
		return ErrSupervisorHandoffUnavailable
	}
	if peer.cgroupFD >= 0 {
		var stat unix.Stat_t
		if err := unix.Fstat(peer.cgroupFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrSupervisorHandoffUnavailable
		}
	}
	pid, err := readV2PidfdPID(peer.PIDFD)
	if err != nil {
		return ErrSupervisorHandoffUnavailable
	}
	if pid == -1 {
		if !v2PidfdPollReadable(peer.PIDFD) {
			return ErrSupervisorHandoffUnavailable
		}
		if err := unix.PidfdSendSignal(peer.PIDFD, 0, nil, 0); err == nil || !errors.Is(err, unix.ESRCH) {
			return ErrSupervisorHandoffUnavailable
		}
		return nil
	}
	if pid != peer.Observation.PID {
		return ErrSupervisorHandoffUnavailable
	}
	// Re-verify the kernel identity immediately before every signal. A pidfd
	// prevents PID reuse, while this cgroup/namespace check prevents an already
	// admitted process that escaped its dedicated boundary from being treated as
	// the original peer. If /proc disappeared, the pidfd has already observed an
	// exit and cgroup.kill remains the safe descendant cleanup path.
	if namespace, namespaceErr := readV2PIDNamespaceInode(pid); namespaceErr == nil {
		if namespace != peer.NamespaceID {
			return ErrSupervisorHandoffUnavailable
		}
		if cgroup, cgroupErr := readProcCgroupPath(pid); cgroupErr == nil {
			if cgroup != peer.Observation.CgroupPath {
				return ErrSupervisorHandoffUnavailable
			}
		} else {
			// A positive fdinfo PID is still live: missing /proc cgroup proof
			// must fail closed. Only the explicit Pid:-1 reaped branch above
			// permits /proc disappearance.
			return ErrSupervisorHandoffUnavailable
		}
	} else {
		return ErrSupervisorHandoffUnavailable
	}
	return nil
}

func v2PidfdPollReadable(pidfd int) bool {
	if pidfd < 0 {
		return false
	}
	pollFD := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	n, err := unix.Poll(pollFD, 0)
	return err == nil && n == 1 && pollFD[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 && pollFD[0].Revents&unix.POLLNVAL == 0
}

func pollV2Pidfd(ctx context.Context, pidfd int, remaining time.Duration) error {
	if ctx == nil {
		return ErrKillUnavailable
	}
	if remaining <= 0 {
		return ErrKillUnavailable
	}
	timeoutMS := int(remaining / time.Millisecond)
	if timeoutMS > v2SupervisorPollMS {
		timeoutMS = v2SupervisorPollMS
	}
	if timeoutMS < 1 {
		timeoutMS = 1
	}
	if timeoutMS > 2147483647 {
		timeoutMS = 2147483647
	}
	if err := ctx.Err(); err != nil {
		return ErrKillUnavailable
	}
	pollFD := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN | unix.POLLHUP | unix.POLLERR}}
	n, err := unix.Poll(pollFD, timeoutMS)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			if ctx.Err() != nil {
				return ErrKillUnavailable
			}
			return errV2PidfdPollTimeout
		}
		return ErrKillUnavailable
	}
	if n == 0 {
		return errV2PidfdPollTimeout
	}
	if pollFD[0].Revents&(unix.POLLNVAL) != 0 {
		return ErrKillUnavailable
	}
	return nil
}

func remainingV2Duration(deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	return remaining
}

func openV2CgroupFD(cgroupPath string) (int, error) {
	if !validCgroupPath(cgroupPath) {
		return -1, ErrKillUnavailable
	}
	fd, err := unix.Open(v2CgroupRoot+cgroupPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrKillUnavailable
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return -1, ErrKillUnavailable
	}
	return fd, nil
}

func closeV2CgroupFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func readV2CgroupFile(fd int, name string) ([]byte, error) {
	if fd < 0 || (name != "memory.max" && name != "pids.max" && name != "cpu.max" && name != "cgroup.events" && name != "cgroup.procs" && name != "cgroup.kill") {
		return nil, ErrKillUnavailable
	}
	return os.ReadFile("/proc/self/fd/" + strconv.Itoa(fd) + "/" + name)
}

func writeV2CgroupKillPeer(peer V2PeerHandle) error {
	fd := peer.cgroupFD
	owned := false
	if fd < 0 {
		var err error
		fd, err = openV2CgroupFD(peer.Observation.CgroupPath)
		if err != nil {
			return err
		}
		owned = true
	}
	if owned {
		defer closeV2CgroupFD(fd)
	}
	file, err := os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd)+"/cgroup.kill", os.O_WRONLY, 0)
	if err != nil {
		return ErrKillUnavailable
	}
	defer file.Close()
	if _, err := file.WriteString("1\n"); err != nil {
		return ErrKillUnavailable
	}
	return nil
}

func v2CgroupGoneFD(fd int) bool {
	events, err := readV2CgroupFile(fd, "cgroup.events")
	if err != nil || !v2CgroupPopulatedZero(string(events)) {
		return false
	}
	procs, err := readV2CgroupFile(fd, "cgroup.procs")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(procs)) == ""
}

func v2CgroupGonePeer(peer V2PeerHandle) bool {
	fd := peer.cgroupFD
	owned := false
	if fd < 0 {
		var err error
		fd, err = openV2CgroupFD(peer.Observation.CgroupPath)
		if err != nil {
			return false
		}
		owned = true
	}
	if owned {
		defer closeV2CgroupFD(fd)
	}
	return v2CgroupGoneFD(fd)
}

// readV2FinalLimits is deliberately separate from the admission observer. It
// re-reads the actual cgroup after pidfd exit and emptiness have been proven,
// closing the window in which a supervisor could drift a limit after worker
// registration. WallClockMS is the immutable registry value because cgroup v2
// has no wall-clock controller.
func readV2FinalLimits(cgroupPath string, wallClockMS int64, cgroupFD int) (Limits, time.Time, error) {
	if !validCgroupPath(cgroupPath) || wallClockMS < 1 || cgroupFD < 0 {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	var stat unix.Stat_t
	if err := unix.Fstat(cgroupFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	memoryRaw, err := readV2CgroupFile(cgroupFD, "memory.max")
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	pidsRaw, err := readV2CgroupFile(cgroupFD, "pids.max")
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	cpuRaw, err := readV2CgroupFile(cgroupFD, "cpu.max")
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	memory, err := parseCgroupMemoryMax(string(memoryRaw))
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	pids, err := parseCgroupPIDsMax(string(pidsRaw))
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	cpu, err := parseCgroupCPUMax(string(cpuRaw))
	if err != nil {
		return Limits{}, time.Time{}, ErrObservationUnavailable
	}
	return Limits{CPUMillis: cpu, MemoryBytes: memory, PIDsMax: pids, WallClockMS: wallClockMS}, time.Now().UTC(), nil
}

func v2CgroupPopulatedZero(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			return fields[1] == "0"
		}
	}
	return false
}
