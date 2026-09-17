//go:build linux

package sandboxdispatch

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestV2PidfdDescriptorRejectsOrdinaryFDAndAcceptsRealPidfd(t *testing.T) {
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateV2PidfdDescriptor(int(file.Fd())); err == nil {
		t.Fatal("/dev/null was accepted as pidfd")
	}
	_ = file.Close()

	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	defer unix.Close(pidfd)
	if err := validateV2PidfdDescriptor(pidfd); err != nil {
		t.Fatalf("real pidfd rejected: %v", err)
	}
}

func TestV2SCMRightspidfdOwnershipTransfersAndClosesOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	defer unix.Close(pidfd)
	body := []byte(`{"schema_version":"handoff"}`)
	frame := make([]byte, 5+len(body))
	frame[0] = byte(kindSupervisorHandoffV2)
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(body)))
	copy(frame[5:], body)
	if _, _, err := sender.WriteMsgUnix(frame, unix.UnixRights(pidfd), nil); err != nil {
		t.Fatal(err)
	}
	_, _, received, err := readV2HandoffFrame(receiver, maxFrameBody)
	if err != nil {
		t.Fatal(err)
	}
	if received < 0 {
		t.Fatal("SCM_RIGHTS returned no pidfd")
	}
	if _, err := os.Stat("/proc/self/fd/" + strconv.Itoa(received)); err != nil {
		t.Fatal(err)
	}
	closeV2PeerFD(received)
	if _, err := os.Stat("/proc/self/fd/" + strconv.Itoa(received)); err == nil {
		t.Fatal("received pidfd remained open after ownership close")
	}
	// A second close must be harmless and must not close a subsequently reused
	// descriptor (no intervening open is performed here).
	closeV2PeerFD(received)
}

func TestV2PidfdProofRejectsWrongPeerIdentity(t *testing.T) {
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	defer unix.Close(pidfd)

	namespace, err := readV2PIDNamespaceInode(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := validateV2Pidfd(pidfd, os.Getpid()+1, namespace, "/wrong"); err == nil {
		t.Fatal("pidfd accepted a different SO_PEERCRED pid")
	}
	if err := validateV2Pidfd(pidfd, os.Getpid(), namespace, "/wrong"); err == nil {
		t.Fatal("pidfd accepted a mismatched cgroup")
	}
	if err := validateV2Pidfd(pidfd, os.Getpid(), "1", "/wrong"); err == nil {
		t.Fatal("pidfd accepted a mismatched namespace")
	}
}

func TestV2PidfdProofRejectsWorkerUIDDriftBeforeKernelUse(t *testing.T) {
	entry := V2RegistryEntry{ExpectedWorkerUID: 65532, ExpectedWorkerGID: 65532}
	hello := RegisterHelloV2{ParserType: ParserTypePDF}
	handoff := SupervisorHandoffV1{ParserType: ParserTypePDF, ExpectedWorkerUID: 65532, ExpectedWorkerGID: 65532, PIDNamespaceInode: "1", CgroupPath: "/kv/parser"}
	obs := Observation{PID: os.Getpid(), CgroupPath: "/kv/parser", Limits: Limits{CPUMillis: 1, MemoryBytes: 1, PIDsMax: 1}}
	if _, err := proveV2Peer(hello, handoff, -1, os.Getpid(), obs, 1000, 65532, entry); err == nil {
		t.Fatal("worker UID drift was accepted")
	}
}

func TestV2CgroupGoneRequiresEventsAndEmptyProcs(t *testing.T) {
	if !v2CgroupPopulatedZero("populated 0\n") {
		t.Fatal("populated=0 was rejected")
	}
	for _, raw := range []string{"populated 1\n", "frozen 0\n", "populated nope\n"} {
		if v2CgroupPopulatedZero(raw) {
			t.Fatalf("invalid cgroup.events accepted: %q", raw)
		}
	}
}

func TestV2SupervisorTeardownFailureFailsClosedOnCgroupEscape(t *testing.T) {
	pidfd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open unavailable: %v", err)
	}
	defer unix.Close(pidfd)
	namespace, err := readV2PIDNamespaceInode(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	peer := V2PeerHandle{PIDFD: pidfd, NamespaceID: namespace, Observation: Observation{PID: os.Getpid(), CgroupPath: "/escaped/cgroup"}}
	d := &DispatcherV2{supervisor: linuxV2Supervisor{timeout: time.Millisecond}, conns: make(map[*net.UnixConn]struct{}), workers: make(map[string]*v2Worker), leases: make(map[string]*v2Lease), terminal: make(map[string]time.Time), handoffs: make(map[string]*v2Handoff), handoffTerminal: make(map[string]time.Time)}
	if d.teardownAndConfirmV2(peer) {
		t.Fatal("cgroup escape teardown unexpectedly succeeded")
	}
	if d.Ready() {
		t.Fatal("cgroup escape did not latch RED")
	}
}
