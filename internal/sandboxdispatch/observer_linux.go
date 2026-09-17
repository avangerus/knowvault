//go:build linux

package sandboxdispatch

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// cgroupObserver reads the peer process credentials of a connected worker socket
// and derives the finite resource bounds from its cgroup v2 namespace. The
// dispatcher is expected to run on the container host, so the observed pid is the
// host-visible process whose cgroup carries the sandbox limits.
type cgroupObserver struct{}

func newPlatformObserver() KernelObserver { return cgroupObserver{} }

func newPlatformKiller() ProcessKiller { return signalKiller{} }

// signalKiller sends SIGKILL to the sandbox process after re-verifying that the
// pid still lives in the cgroup the observation recorded. The re-check closes
// the pid-reuse window: a reused pid — or an unreadable /proc entry — is never
// signalled. The container's pid 1 is the root of its kernel namespaces; killing
// it tears the namespaces down with the process, so no descendant can survive
// the lease.
type signalKiller struct{}

func (signalKiller) Kill(obs Observation) error {
	if obs.PID < 1 || obs.CgroupPath == "" {
		return ErrKillUnavailable
	}
	current, err := readProcCgroupPath(obs.PID)
	if err != nil || current != obs.CgroupPath {
		return ErrKillUnavailable
	}
	if err := syscall.Kill(obs.PID, syscall.SIGKILL); err != nil {
		return ErrKillUnavailable
	}
	return nil
}

// chmodSocket restricts the listening socket to its owner. The parent directory
// is already 0700; the socket mode closes the residual window for a socket path
// configured outside the dispatcher's own directory.
func chmodSocket(socketPath string) error {
	return os.Chmod(socketPath, 0o600)
}

// Observe implements KernelObserver for Linux: SO_PEERCRED identifies the peer
// process, its /proc/<pid>/cgroup names the unified hierarchy path, and the
// memory.max / cpu.max / pids.max files under /sys/fs/cgroup carry the finite
// bounds. A bound that is "max" or missing is refused, not treated as a limit.
func (cgroupObserver) Observe(conn *net.UnixConn) (Observation, error) {
	pid, err := peerCredPID(conn)
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	cgroupPath, err := readProcCgroupPath(pid)
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	memoryMax, err := os.ReadFile("/sys/fs/cgroup" + cgroupPath + "/memory.max")
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	pidsMax, err := os.ReadFile("/sys/fs/cgroup" + cgroupPath + "/pids.max")
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	cpuMax, err := os.ReadFile("/sys/fs/cgroup" + cgroupPath + "/cpu.max")
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	memory, err := parseCgroupMemoryMax(string(memoryMax))
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	pids, err := parseCgroupPIDsMax(string(pidsMax))
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	cpu, err := parseCgroupCPUMax(string(cpuMax))
	if err != nil {
		return Observation{}, ErrObservationUnavailable
	}
	return Observation{
		Limits:     Limits{CPUMillis: cpu, MemoryBytes: memory, PIDsMax: pids},
		PID:        pid,
		ObservedAt: time.Now().UTC(),
		CgroupPath: cgroupPath,
	}, nil
}

func readProcCgroupPath(pid int) (string, error) {
	content, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	return cgroupV2Path(string(content))
}

// peerCredPID reads SO_PEERCRED for the socket. It is implemented over the raw
// getsockopt syscall so the package carries no platform dependency beyond the
// standard library.
func peerCredPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		pid     uint32
		credLen uint32
		errno   syscall.Errno
	)
	controlErr := raw.Control(func(fd uintptr) {
		cred := make([]byte, 12) // struct ucred: pid, uid, gid
		credLen = uint32(len(cred))
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT, fd,
			uintptr(syscall.SOL_SOCKET), uintptr(17), // SO_PEERCRED
			uintptr(unsafe.Pointer(&cred[0])),
			uintptr(unsafe.Pointer(&credLen)), 0,
		)
		if errno == 0 {
			pid = *(*uint32)(unsafe.Pointer(&cred[0]))
		}
	})
	if controlErr != nil || errno != 0 || pid == 0 {
		return 0, ErrObservationUnavailable
	}
	return int(pid), nil
}
