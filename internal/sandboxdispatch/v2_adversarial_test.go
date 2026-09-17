//go:build linux

package sandboxdispatch

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newV2BookkeepingDispatcher() *DispatcherV2 {
	return &DispatcherV2{
		workers:         make(map[string]*v2Worker),
		leases:          make(map[string]*v2Lease),
		terminal:        make(map[string]time.Time),
		handoffs:        make(map[string]*v2Handoff),
		handoffTerminal: make(map[string]time.Time),
		conns:           make(map[*net.UnixConn]struct{}),
	}
}

func adversarialHandoff(id string, state v2HandoffState) *v2Handoff {
	now := time.Now().UTC()
	return &v2Handoff{
		metadata: SupervisorHandoffV1{HandoffID: id, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)},
		pidfd:    -1, state: state,
	}
}

func TestV2SupervisorACKFailureFencesPendingHandoff(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	h := adversarialHandoff("ack-failure-000000000000000000000000", v2HandoffAcknowledged)
	d.handoffs[h.metadata.HandoffID] = h
	d.expireV2Handoff(h)
	if _, ok := d.handoffs[h.metadata.HandoffID]; ok || h.state != v2HandoffExpired {
		t.Fatalf("failed ACK handoff remained admitted: state=%v", h.state)
	}
}

func TestV2SupervisorACKFailureWireDrainsRED(t *testing.T) {
	path := filepath.Join(t.TempDir(), "handoff.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	d := newV2BookkeepingDispatcher()
	d.cfg.SupervisorUID, d.cfg.SupervisorGID = os.Geteuid(), os.Getegid()
	d.trackV2Conn(server)
	done := make(chan struct{})
	go func() { d.handleV2Handoff(server); close(done) }()
	frame := make([]byte, 5)
	frame[0] = byte(kindSupervisorHandoffV2)
	binary.BigEndian.PutUint32(frame[1:], uint32(maxFrameBody+1))
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handoff ACK failure handler did not terminate")
	}
	if !d.red {
		t.Fatal("handoff ACK failure did not latch RED")
	}
}

func TestV2SupervisorACKReplayRejected(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	h := adversarialHandoff("ack-replay-0000000000000000000000000", v2HandoffAcknowledged)
	d.handoffs[h.metadata.HandoffID] = h
	d.mu.Lock()
	d.pruneV2ReplayLocked(time.Now().UTC())
	d.handoffTerminal[h.metadata.HandoffID] = time.Now().Add(time.Hour)
	d.mu.Unlock()
	if _, ok := d.takeV2Handoff(RegisterHelloV2{SupervisorHandoffID: h.metadata.HandoffID}); ok {
		t.Fatal("terminal ACK identity was replayed")
	}
}

func TestV2ExpiredHandoffAndIdlePendingCleanup(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	h := adversarialHandoff("expired-idle-000000000000000000000000", v2HandoffAcknowledged)
	d.handoffs[h.metadata.HandoffID] = h
	d.expireV2Handoff(h)
	if len(d.handoffs) != 0 || h.state != v2HandoffExpired {
		t.Fatalf("expired idle handoff was not removed: state=%v pending=%d", h.state, len(d.handoffs))
	}
}

func TestV2DispatcherShutdownCleansIdleState(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	d.shutdownV2()
	if !d.closed {
		t.Fatal("shutdown did not close dispatcher")
	}
	d.shutdownV2() // idempotent and bounded
}

func TestV2RejectsWrongGIDAndCrossRoleCredentials(t *testing.T) {
	if err := (RegisterHelloV2{SchemaVersion: RegistrationVersionV2, WorkerID: "worker", ParserType: ParserTypePDF, ArtifactHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000", SandboxProfileRevision: "sandbox-v2", ObservationProfileRevision: "obs-v1", SupervisorHandoffID: "handoff-0000000000000000000000000000", OneShot: true, MaxLeases: 1, Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome}}).Validate(ParserTypeOffice); err == nil {
		t.Fatal("cross-role registration credentials were accepted")
	}
	entry := V2RegistryEntry{ExpectedWorkerUID: 1000, ExpectedWorkerGID: 1000}
	handoff := SupervisorHandoffV1{ParserType: ParserTypePDF, ExpectedWorkerUID: 1000, ExpectedWorkerGID: 1000, CgroupPath: "/kv/parser", PIDNamespaceInode: "1"}
	obs := Observation{PID: 1, CgroupPath: "/kv/parser", Limits: Limits{CPUMillis: 1, MemoryBytes: 1, PIDsMax: 1}}
	if _, err := proveV2Peer(RegisterHelloV2{ParserType: ParserTypePDF}, handoff, -1, 1, obs, 1000, 1001, entry); err == nil {
		t.Fatal("wrong worker GID was accepted")
	}
}

func TestV2RejectsArtifactAndProfileHandoffDrift(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	request := ParserRequestV1{ParserType: ParserTypePDF, SandboxProfileRevision: "sandbox-v2", ObservationProfileRevision: "obs-v1"}
	d.cfg.Registry = []V2RegistryEntry{{ParserRequest: request, ArtifactHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}}
	handoff := SupervisorHandoffV1{ParserType: ParserTypePDF, ArtifactHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111", SandboxProfileRevision: request.SandboxProfileRevision, ObservationProfileRevision: request.ObservationProfileRevision}
	if d.registryForHandoff(handoff) {
		t.Fatal("artifact-drifted handoff matched registry")
	}
	handoff.ArtifactHash = d.cfg.Registry[0].ArtifactHash
	handoff.ObservationProfileRevision = "other-obs-v1"
	if d.registryForHandoff(handoff) {
		t.Fatal("profile-drifted handoff matched registry")
	}
}

func TestV2FinalLimitDriftFailsClosedWithoutPinnedCgroup(t *testing.T) {
	expected := Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 1000}
	if exactV2Limits(expected, Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 15, WallClockMS: 1000}) {
		t.Fatal("final cgroup limit drift was accepted")
	}
	if _, _, err := readV2FinalLimits("/missing", 1000, -1); err == nil {
		t.Fatal("final limits accepted without same-instance cgroup proof")
	}
}

func TestV2InvalidPreTransferFrameFencesWorker(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	worker := &v2Worker{hello: RegisterHelloV2{WorkerID: "worker"}}
	worker.active = &v2Lease{worker: worker}
	if d.handleV2Outcome(worker, []byte("{")) {
		t.Fatal("invalid pre-transfer outcome was accepted")
	}
}

func TestV2DuplicateResultReplayAndStaleConfirmationRejected(t *testing.T) {
	d := newV2BookkeepingDispatcher()
	worker := &v2Worker{hello: RegisterHelloV2{WorkerID: "worker"}}
	worker.active = &v2Lease{worker: worker, resultSeen: true}
	if d.handleV2Result(worker, []byte("result")) {
		t.Fatal("duplicate result replay was accepted")
	}
	if exactParserRequestInOutcome([]byte(`{"parser_request":{}}`), ParserRequestV1{ParserType: ParserTypePDF}) {
		t.Fatal("stale/foreign confirmation envelope was accepted")
	}
}

func TestV2FDOwnershipCloseIsIdempotent(t *testing.T) {
	closeV2PeerFD(-1)
	closeV2PeerFD(-1)
}

func TestV2ConnectionTrackingHasBoundedFailClosedAdmission(t *testing.T) {
	if !v2ConnectionCapacityAvailable(maxV2Connections - 1) {
		t.Fatal("last connection slot was not available")
	}
	if v2ConnectionCapacityAvailable(maxV2Connections) || v2ConnectionCapacityAvailable(maxV2Connections+1) {
		t.Fatal("connection tracking exceeded its hard cap")
	}
}

func TestV2ParserReadyRequiresFreshAcceptedCapacity(t *testing.T) {
	worker := &v2Worker{ready: true}
	dispatcher := &DispatcherV2{workers: map[string]*v2Worker{ParserTypeOffice: worker}}
	if !dispatcher.ParserReady(ParserTypeOffice) {
		t.Fatal("fresh accepted OFFICE worker was not reported ready")
	}
	if dispatcher.ParserReady("UNKNOWN") {
		t.Fatal("unknown parser role was reported ready")
	}
	worker.used = true
	if dispatcher.ParserReady(ParserTypeOffice) {
		t.Fatal("used one-shot worker was reported ready")
	}
	worker.used = false
	worker.active = &v2Lease{}
	if dispatcher.ParserReady(ParserTypeOffice) {
		t.Fatal("active worker was reported as spare capacity")
	}
	worker.active = nil
	dispatcher.red = true
	if dispatcher.ParserReady(ParserTypeOffice) {
		t.Fatal("RED dispatcher reported parser capacity")
	}
}

func TestV2RegistrationPolicyAllowsHomogeneousRoleCapabilitiesOnly(t *testing.T) {
	limits := Limits{CPUMillis: 100, MemoryBytes: 64 << 20, PIDsMax: 16, WallClockMS: 1000}
	request := ParserRequestV1{ParserType: ParserTypeOffice, SandboxProfileRevision: "sandbox-v2", ObservationProfileRevision: "office-obs-v1"}
	left := V2RegistryEntry{ParserRequest: request, ArtifactHash: digestFor([]byte("artifact")), ExpectedLimits: limits,
		RuntimeProfileHash: RuntimeProfileHash(ParserTypeOffice, request.SandboxProfileRevision, limits), ExpectedWorkerUID: 10, ExpectedWorkerGID: 10}
	right := left
	right.ParserRequest.MediaFamily = "PPTX"
	if !sameV2RegistrationPolicy(left, right) {
		t.Fatal("homogeneous DOCX/PPTX role capabilities were split by job-only media")
	}
	for name, mutate := range map[string]func(*V2RegistryEntry){
		"artifact": func(entry *V2RegistryEntry) { entry.ArtifactHash = digestFor([]byte("other")) },
		"limits":   func(entry *V2RegistryEntry) { entry.ExpectedLimits.MemoryBytes++ },
		"runtime":  func(entry *V2RegistryEntry) { entry.RuntimeProfileHash = digestFor([]byte("runtime")) },
		"uid":      func(entry *V2RegistryEntry) { entry.ExpectedWorkerUID++ },
	} {
		candidate := right
		mutate(&candidate)
		if sameV2RegistrationPolicy(left, candidate) {
			t.Fatalf("heterogeneous %s authority was accepted for one registration role", name)
		}
	}
}
