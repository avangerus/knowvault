package sandboxdispatch

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const testStatusHandoffID = "handoff-00000000000000000000000000000000"

type statusMemoryWriter struct {
	mu        sync.Mutex
	writes    [][]byte
	calls     int
	failFirst bool
	started   chan struct{}
	release   chan struct{}
	closed    bool
}

func (writer *statusMemoryWriter) Write(data []byte) error {
	writer.mu.Lock()
	call := writer.calls
	writer.calls++
	writer.mu.Unlock()
	if call == 0 && writer.started != nil {
		close(writer.started)
		<-writer.release
	}
	if call == 0 && writer.failFirst {
		return errors.New("write failed")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.writes = append(writer.writes, append([]byte(nil), data...))
	return nil
}

func (writer *statusMemoryWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.closed = true
	return nil
}

func statusTestDispatcher(writer v2StatusWriter, ocr bool) *DispatcherV2 {
	cfg := V2Config{}
	if ocr {
		cfg.OCRRegistrationSocketPath = "ocr.sock"
	}
	return &DispatcherV2{
		statusWriter:    writer,
		statusEpoch:     "0123456789abcdef0123456789abcdef",
		statusRoles:     initialV2StatusRoles(cfg),
		workers:         make(map[string]*v2Worker),
		leases:          make(map[string]*v2Lease),
		terminal:        make(map[string]time.Time),
		handoffs:        make(map[string]*v2Handoff),
		handoffTerminal: make(map[string]time.Time),
		conns:           make(map[*net.UnixConn]struct{}),
	}
}

func TestV2SupervisorStatusDocumentIsBoundedAndContainsOnlyPublicState(t *testing.T) {
	d := statusTestDispatcher(nil, true)
	d.mu.Lock()
	d.setV2HandoffStatusLocked(ParserTypeOffice, testStatusHandoffID)
	d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleReady, time.Time{})
	deadline := time.Date(2026, time.August, 31, 20, 0, 0, 0, time.UTC)
	d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleBusy, deadline)
	status := d.nextV2StatusLocked(time.Date(2026, time.August, 31, 19, 59, 59, 0, time.UTC))
	d.mu.Unlock()

	encoded, err := marshalV2StatusDocument(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	if len(encoded) > v2StatusMaximumBytes {
		t.Fatalf("status has %d bytes, limit %d", len(encoded), v2StatusMaximumBytes)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	wantFields := []string{"schema_version", "dispatcher_epoch", "sequence", "written_at", "valid_until", "dispatcher_state", "roles"}
	if len(fields) != len(wantFields) {
		t.Fatalf("status fields = %v", fields)
	}
	for _, key := range wantFields {
		if _, ok := fields[key]; !ok {
			t.Fatalf("status field %q missing", key)
		}
	}
	for _, forbidden := range []string{"job_id", "source_id", "worker_id", "lease_id", "payload_hash", "payload_path", "error_text", "cgroup_path"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("private field %q leaked in status: %s", forbidden, encoded)
		}
	}
	if status.SchemaVersion != SupervisorStatusSchemaVersionV1 || status.Sequence != 1 || status.DispatcherState != v2StatusRunning || len(status.Roles) != 3 {
		t.Fatalf("unexpected status identity: %#v", status)
	}
	writtenAt, _ := time.Parse(time.RFC3339Nano, status.WrittenAt)
	validUntil, _ := time.Parse(time.RFC3339Nano, status.ValidUntil)
	if validUntil.Sub(writtenAt) != v2StatusValidityWindow {
		t.Fatalf("validity window = %s", validUntil.Sub(writtenAt))
	}
	office := status.Roles[ParserTypeOffice]
	if office.State != v2RoleBusy || office.HandoffID == nil || *office.HandoffID != testStatusHandoffID || office.LeaseDeadline == nil {
		t.Fatalf("busy role lost handoff/deadline: %#v", office)
	}
	if got := status.Roles[ParserTypePDF]; got.State != v2RoleEmpty || got.HandoffID != nil || got.LeaseDeadline != nil {
		t.Fatalf("empty role has unexpected identifiers: %#v", got)
	}
	if got := status.Roles[ParserTypeOCR]; got.State != v2RoleEmpty {
		t.Fatalf("configured OCR role missing: %#v", got)
	}
	if got := len(statusTestDispatcher(nil, false).statusRoles); got != 2 {
		t.Fatalf("unconfigured OCR role was published: role count=%d", got)
	}
}

func TestV2SupervisorStatusRejectsMalformedStateAndRoleTuples(t *testing.T) {
	d := statusTestDispatcher(nil, false)
	d.mu.Lock()
	valid := d.nextV2StatusLocked(time.Now())
	d.mu.Unlock()
	clone := func() v2DispatcherStatusDocument {
		copy := valid
		copy.Roles = make(map[string]v2StatusRoleDocument, len(valid.Roles))
		for role, state := range valid.Roles {
			copy.Roles[role] = state
		}
		return copy
	}
	cases := map[string]func(*v2DispatcherStatusDocument){
		"bad epoch":     func(doc *v2DispatcherStatusDocument) { doc.DispatcherEpoch = "not-random" },
		"zero sequence": func(doc *v2DispatcherStatusDocument) { doc.Sequence = 0 },
		"unknown role":  func(doc *v2DispatcherStatusDocument) { doc.Roles["VECTOR"] = v2StatusRoleDocument{State: v2RoleEmpty} },
		"empty handoff": func(doc *v2DispatcherStatusDocument) {
			id := testStatusHandoffID
			role := doc.Roles[ParserTypeOffice]
			role.HandoffID = &id
			doc.Roles[ParserTypeOffice] = role
		},
		"busy without deadline": func(doc *v2DispatcherStatusDocument) {
			role := doc.Roles[ParserTypeOffice]
			role.State = v2RoleBusy
			id := testStatusHandoffID
			role.HandoffID = &id
			doc.Roles[ParserTypeOffice] = role
		},
		"red mismatch": func(doc *v2DispatcherStatusDocument) {
			role := doc.Roles[ParserTypeOffice]
			role.State = v2RoleRed
			doc.Roles[ParserTypeOffice] = role
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := clone()
			mutate(&doc)
			if validateV2StatusDocument(doc) {
				t.Fatalf("accepted malformed status: %#v", doc)
			}
		})
	}
}

func TestV2SupervisorStatusRoleTransitionsBindHandoffAndLease(t *testing.T) {
	d := statusTestDispatcher(nil, false)
	d.mu.Lock()
	if d.setV2RoleStatusLocked(ParserTypeOffice, "", v2RoleReady, time.Time{}) {
		d.mu.Unlock()
		t.Fatal("role became ready before an acknowledged handoff")
	}
	if !d.setV2HandoffStatusLocked(ParserTypeOffice, testStatusHandoffID) {
		d.mu.Unlock()
		t.Fatal("validated handoff was not recorded")
	}
	if d.setV2RoleStatusLocked(ParserTypeOffice, "handoff-ffffffffffffffffffffffffffffffff", v2RoleReady, time.Time{}) {
		d.mu.Unlock()
		t.Fatal("role accepted a different handoff ID")
	}
	if !d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleReady, time.Time{}) {
		d.mu.Unlock()
		t.Fatal("accepted registration did not become ready")
	}
	if d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleBusy, time.Time{}) {
		d.mu.Unlock()
		t.Fatal("busy reservation omitted its one-shot lease deadline")
	}
	deadline := time.Now().UTC().Add(time.Minute)
	if !d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleBusy, deadline) {
		d.mu.Unlock()
		t.Fatal("valid one-shot reservation was not published")
	}
	if d.setV2HandoffStatusLocked(ParserTypeOffice, testStatusHandoffID) {
		d.mu.Unlock()
		t.Fatal("same handoff replaced current role state")
	}
	if !d.setV2RoleStatusLocked(ParserTypeOffice, testStatusHandoffID, v2RoleReaped, time.Time{}) {
		d.mu.Unlock()
		t.Fatal("proved cleanup did not permit reaped state")
	}
	if d.statusRoles[ParserTypeOffice].LeaseDeadline.IsZero() == false {
		d.mu.Unlock()
		t.Fatal("lease deadline remained after reservation ended")
	}
	newHandoff := "handoff-11111111111111111111111111111111"
	if !d.setV2HandoffStatusLocked(ParserTypeOffice, newHandoff) {
		d.mu.Unlock()
		t.Fatal("reaped state did not accept a distinct handoff")
	}
	got := d.statusRoles[ParserTypeOffice]
	d.mu.Unlock()
	if got.State != v2RoleHandedOff || got.HandoffID != newHandoff {
		t.Fatalf("distinct handoff did not reset role state: %#v", got)
	}
}

func TestV2SupervisorStatusReapedRequiresCleanupProof(t *testing.T) {
	for _, cleanupProven := range []bool{false, true} {
		d := statusTestDispatcher(&statusMemoryWriter{}, false)
		d.statusRoles[ParserTypeOffice] = v2StatusRoleState{State: v2RoleBusy, HandoffID: testStatusHandoffID, LeaseDeadline: time.Now().UTC().Add(time.Minute)}
		worker := &v2Worker{hello: RegisterHelloV2{ParserType: ParserTypeOffice}, handoff: SupervisorHandoffV1{HandoffID: testStatusHandoffID}, peer: V2PeerHandle{PIDFD: -1, cgroupFD: -1}}
		active := &v2Lease{worker: worker, lease: LeaseV2{LeaseID: "lease-status-test", ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}, cleanupProven: cleanupProven, result: make(chan v2JobResult, 1)}
		worker.active = active
		d.leases[active.lease.LeaseID] = active
		d.mu.Lock()
		changed := d.resolveV2Locked(active, v2JobResult{retryable: true})
		got := d.statusRoles[ParserTypeOffice]
		d.mu.Unlock()
		if cleanupProven {
			if !changed || got.State != v2RoleReaped {
				t.Fatalf("successful cleanup did not reap role: changed=%v status=%#v", changed, got)
			}
		} else if changed || got.State != v2RoleBusy {
			t.Fatalf("unproved cleanup was marked reaped: changed=%v status=%#v", changed, got)
		}
	}
}

func TestV2SupervisorStatusWriteFailureLatchesRed(t *testing.T) {
	writer := &statusMemoryWriter{failFirst: true}
	d := statusTestDispatcher(writer, false)
	if d.publishV2Status() {
		t.Fatal("failed status write was reported successful")
	}
	if d.Ready() {
		t.Fatal("status write failure did not synchronously latch RED")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for role, status := range d.statusRoles {
		if status.State != v2RoleRed || !status.LeaseDeadline.IsZero() {
			t.Fatalf("role %s not red after write failure: %#v", role, status)
		}
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.writes) != 1 {
		t.Fatalf("best-effort RED write count=%d, want 1", len(writer.writes))
	}
	var red v2DispatcherStatusDocument
	if err := json.Unmarshal(writer.writes[0], &red); err != nil || red.DispatcherState != v2StatusRed {
		t.Fatalf("best-effort status is not RED: err=%v status=%#v", err, red)
	}
}

func TestV2SupervisorStatusConcurrentWritesAreMonotonic(t *testing.T) {
	writer := &statusMemoryWriter{started: make(chan struct{}), release: make(chan struct{})}
	d := statusTestDispatcher(writer, false)
	firstDone := make(chan struct{})
	go func() {
		d.publishV2Status()
		close(firstDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("first status write did not start")
	}
	secondDone := make(chan struct{})
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		d.publishV2Status()
		close(secondDone)
	}()
	<-secondStarted
	close(writer.release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first status publish did not finish")
	}
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second status publish did not finish")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.writes) != 2 {
		t.Fatalf("status write count=%d, want 2", len(writer.writes))
	}
	var first, second v2DispatcherStatusDocument
	if err := json.Unmarshal(writer.writes[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(writer.writes[1], &second); err != nil {
		t.Fatal(err)
	}
	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("status writes regressed or skipped: %d then %d", first.Sequence, second.Sequence)
	}
}

func TestV2SupervisorStatusDropsStaleSnapshotAndUsesDistinctEpochs(t *testing.T) {
	writer := &statusMemoryWriter{}
	d := statusTestDispatcher(writer, false)
	d.mu.Lock()
	stale := d.nextV2StatusLocked(time.Now())
	fresh := d.nextV2StatusLocked(time.Now().Add(time.Millisecond))
	d.mu.Unlock()
	if err := d.writeV2StatusDocument(fresh); err != nil {
		t.Fatal(err)
	}
	if err := d.writeV2StatusDocument(stale); err != nil {
		t.Fatal(err)
	}
	writer.mu.Lock()
	if len(writer.writes) != 1 {
		writer.mu.Unlock()
		t.Fatalf("stale snapshot was written; writes=%d", len(writer.writes))
	}
	writer.mu.Unlock()
	first, err := newV2StatusEpoch()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newV2StatusEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !v2StatusEpochPattern.MatchString(first) || !v2StatusEpochPattern.MatchString(second) {
		t.Fatalf("invalid/non-distinct dispatcher epochs: %q %q", first, second)
	}
}
