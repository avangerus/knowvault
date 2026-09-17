//go:build linux

package sandboxdispatch

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// proveV2Peer is the only production path that turns an untrusted registration
// socket and a supervisor handoff into a V2PeerHandle. Every authority used in
// this function comes from the kernel (SO_PEERCRED, /proc and the pidfd), or
// from the immutable registry/handoff records already validated by the
// dispatcher. Worker JSON never supplies a PID, namespace, cgroup or limit.
func proveV2Peer(hello RegisterHelloV2, handoff SupervisorHandoffV1, pidfd int, peerPID int, obs Observation, uid, gid int, entry V2RegistryEntry) (V2PeerHandle, error) {
	if pidfd < 0 || hello.ParserType != handoff.ParserType ||
		peerPID < 1 || obs.PID != peerPID ||
		uid != entry.ExpectedWorkerUID || gid != entry.ExpectedWorkerGID ||
		uid != handoff.ExpectedWorkerUID || gid != handoff.ExpectedWorkerGID ||
		obs.CgroupPath != handoff.CgroupPath || !validCgroupPath(obs.CgroupPath) ||
		obs.Limits.CPUMillis != entry.ExpectedLimits.CPUMillis ||
		obs.Limits.MemoryBytes != entry.ExpectedLimits.MemoryBytes ||
		obs.Limits.PIDsMax != entry.ExpectedLimits.PIDsMax {
		return V2PeerHandle{}, ErrSupervisorHandoffUnavailable
	}
	if err := setV2PidfdCloexec(pidfd); err != nil {
		return V2PeerHandle{}, ErrSupervisorHandoffUnavailable
	}
	if err := validateV2Pidfd(pidfd, peerPID, handoff.PIDNamespaceInode, handoff.CgroupPath); err != nil {
		return V2PeerHandle{}, ErrSupervisorHandoffUnavailable
	}
	cgroupFD, err := openV2CgroupFD(handoff.CgroupPath)
	if err != nil {
		return V2PeerHandle{}, ErrSupervisorHandoffUnavailable
	}
	return V2PeerHandle{
		WorkerID: hello.WorkerID, ParserType: hello.ParserType,
		ArtifactHash: hello.ArtifactHash, ArtifactIdentity: hello.ArtifactHash,
		SandboxProfileRevision:     hello.SandboxProfileRevision,
		ObservationProfileRevision: hello.ObservationProfileRevision,
		Observation:                obs, PIDFD: pidfd, NamespaceID: handoff.PIDNamespaceInode,
		cgroupFD: cgroupFD,
	}, nil
}

func setV2PidfdCloexec(fd int) error {
	if fd < 0 {
		return ErrSupervisorHandoffUnavailable
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return err
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		if err != nil {
			return err
		}
		return ErrSupervisorHandoffUnavailable
	}
	return nil
}

// validateV2PidfdDescriptor is the early handoff gate. It runs before the FD
// enters the pending-handoff map, so an ordinary descriptor cannot be held
// until a later registration attempt.
func validateV2PidfdDescriptor(fd int) error {
	if err := setV2PidfdCloexec(fd); err != nil {
		return ErrSupervisorHandoffUnavailable
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || link != "anon_inode:[pidfd]" {
		return ErrSupervisorHandoffUnavailable
	}
	pid, err := readV2PidfdPID(fd)
	if err != nil || pid < 1 {
		return ErrSupervisorHandoffUnavailable
	}
	return nil
}

// validateV2Pidfd rejects ordinary descriptors (for example /dev/null),
// checks that the supervisor passed the registration peer's process, and
// proves the dedicated PID namespace/cgroup contract before the worker is
// admitted. fdinfo Pid is intentionally compared to SO_PEERCRED PID rather
// than to a worker-supplied number.
func validateV2Pidfd(pidfd, peerPID int, namespaceInode, cgroupPath string) error {
	if pidfd < 0 || peerPID < 1 || !validNamespaceInode(namespaceInode) || !validCgroupPath(cgroupPath) {
		return ErrSupervisorHandoffUnavailable
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(pidfd))
	if err != nil || link != "anon_inode:[pidfd]" {
		return ErrSupervisorHandoffUnavailable
	}
	pid, err := readV2PidfdPID(pidfd)
	if err != nil || pid != peerPID {
		return ErrSupervisorHandoffUnavailable
	}
	actualNamespace, err := readV2PIDNamespaceInode(peerPID)
	if err != nil || actualNamespace != namespaceInode {
		return ErrSupervisorHandoffUnavailable
	}
	if err := requireV2NSpidOne(peerPID); err != nil {
		return err
	}
	actualCgroup, err := readProcCgroupPath(peerPID)
	if err != nil || actualCgroup != cgroupPath {
		return ErrSupervisorHandoffUnavailable
	}
	return nil
}

func readV2PidfdPID(pidfd int) (int, error) {
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(pidfd))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "Pid:" {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || (pid < 1 && pid != -1) {
			return 0, fmt.Errorf("invalid pidfd pid")
		}
		return pid, nil
	}
	return 0, fmt.Errorf("pidfd pid unavailable")
}

func readV2PIDNamespaceInode(pid int) (string, error) {
	link, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/pid")
	if err != nil {
		return "", err
	}
	const prefix, suffix = "pid:[", "]"
	if !strings.HasPrefix(link, prefix) || !strings.HasSuffix(link, suffix) {
		return "", fmt.Errorf("invalid pid namespace link")
	}
	value := strings.TrimSuffix(strings.TrimPrefix(link, prefix), suffix)
	if !validNamespaceInode(value) {
		return "", fmt.Errorf("invalid pid namespace inode")
	}
	return value, nil
}

func requireV2NSpidOne(pid int) error {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return ErrSupervisorHandoffUnavailable
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "NSpid:" {
			continue
		}
		last, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || last != 1 {
			return ErrSupervisorHandoffUnavailable
		}
		return nil
	}
	if err := scanner.Err(); err != nil {
		return ErrSupervisorHandoffUnavailable
	}
	return ErrSupervisorHandoffUnavailable
}
