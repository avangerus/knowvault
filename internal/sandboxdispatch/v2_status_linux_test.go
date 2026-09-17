//go:build linux

package sandboxdispatch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type blockingStatusSupervisor struct {
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
	confirmErr error
}

func (supervisor *blockingStatusSupervisor) Teardown(context.Context, V2PeerHandle) error {
	return nil
}

func (supervisor *blockingStatusSupervisor) ConfirmGone(ctx context.Context, _ V2PeerHandle) error {
	supervisor.once.Do(func() { close(supervisor.entered) })
	select {
	case <-supervisor.release:
		return supervisor.confirmErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestLinuxV2SupervisorStatusWriterAtomicallyReplacesPrivateFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "status.json")
	writer, err := newV2StatusWriter(path)
	if err != nil {
		t.Fatalf("open writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	values := [][]byte{[]byte(`{"sequence":1,"value":"old"}`), []byte(`{"sequence":2,"value":"new"}`)}
	if err := writer.Write(values[0]); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writer.Write(values[1]); err != nil {
		t.Fatalf("replacement write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(values[1]) {
		t.Fatalf("replacement contents = %q", got)
	}
	var info unix.Stat_t
	if err := unix.Stat(path, &info); err != nil {
		t.Fatal(err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != uint32(os.Geteuid()) || info.Mode&0o7777 != 0o600 {
		t.Fatalf("status file permissions/owner = mode %#o uid %d", info.Mode&0o7777, info.Uid)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "status.json" {
		t.Fatalf("atomic writer left temporary files: %v", entries)
	}
}

func TestLinuxV2SupervisorStatusWriterRejectsSymlinkAndUnsafeModes(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(parent, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkDir := filepath.Join(parent, "link")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2StatusWriter(filepath.Join(symlinkDir, "status.json")); err == nil {
		t.Fatal("symlinked status directory was accepted")
	}

	wrongModeDir := filepath.Join(parent, "permissive")
	if err := os.Mkdir(wrongModeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wrongModeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2StatusWriter(filepath.Join(wrongModeDir, "status.json")); err == nil {
		t.Fatal("status directory without 0700 mode was accepted")
	}

	fileDir := filepath.Join(parent, "file")
	if err := os.Mkdir(fileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(fileDir, "status.json")
	if err := os.WriteFile(statusPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statusPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2StatusWriter(statusPath); err == nil {
		t.Fatal("status file without 0600 mode was accepted")
	}
	if err := os.Remove(statusPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(fileDir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, statusPath); err != nil {
		t.Fatal(err)
	}
	if _, err := newV2StatusWriter(statusPath); err == nil {
		t.Fatal("symlinked status file was accepted")
	}
}

func TestLinuxV2SupervisorStatusWriterNeverPublishesTornFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "status.json")
	writer, err := newV2StatusWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	values := [][]byte{
		[]byte(`{"sequence":1,"value":"` + strings.Repeat("a", 2000) + `"}`),
		[]byte(`{"sequence":2,"value":"` + strings.Repeat("b", 3000) + `"}`),
	}
	if err := writer.Write(values[0]); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for index := 0; index < 40; index++ {
			if err := writer.Write(values[index%len(values)]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(contents) != string(values[0]) && string(contents) != string(values[1]) {
			t.Fatalf("reader observed torn status file (%d bytes)", len(contents))
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("atomic write loop did not finish")
		}
	}
}

func TestV2SupervisorStatusDoesNotReportReapedBeforeConfirmAndFinalLimits(t *testing.T) {
	d, worker, supervisor, _ := newV2StatusCleanupFixture(t, nil, false, false)
	d.supervisor = supervisor
	dropDone := make(chan struct{})
	go func() {
		d.dropV2Worker(worker)
		close(dropDone)
	}()
	select {
	case <-supervisor.entered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not reach ConfirmGone")
	}
	d.mu.Lock()
	before := d.statusRoles[ParserTypeOffice]
	d.mu.Unlock()
	if before.State != v2RoleReady {
		t.Fatalf("role became %q before ConfirmGone completed", before.State)
	}
	close(supervisor.release)
	select {
	case <-dropDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after ConfirmGone")
	}
	d.mu.Lock()
	after := d.statusRoles[ParserTypeOffice]
	d.mu.Unlock()
	if after.State != v2RoleReaped || worker.peer.PIDFD != -1 || worker.peer.cgroupFD != -1 {
		t.Fatalf("role not reaped after proof and FD close: status=%#v peer=%#v", after, worker.peer)
	}
}

func TestV2SupervisorStatusDoesNotReportReapedWhileFinalLimitsAreBlocked(t *testing.T) {
	d, worker, supervisor, cgroupDir := newV2StatusCleanupFixture(t, nil, false, true)
	d.supervisor = supervisor
	close(supervisor.release)
	dropDone := make(chan struct{})
	go func() {
		d.dropV2Worker(worker)
		close(dropDone)
	}()
	type openedFIFO struct {
		fd  int
		err error
	}
	opened := make(chan openedFIFO, 1)
	// Opening the FIFO writer pairs with the final-limit reader. Once open
	// returns, the reader is blocked for its bytes and the role must remain
	// un-reaped.
	fifoPath := filepath.Join(cgroupDir, "memory.max")
	go func() {
		fd, err := unix.Open(fifoPath, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		opened <- openedFIFO{fd: fd, err: err}
	}()
	var result openedFIFO
	select {
	case result = <-opened:
	case <-time.After(time.Second):
		t.Fatal("final-limit reader did not open the FIFO")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	d.mu.Lock()
	before := d.statusRoles[ParserTypeOffice]
	d.mu.Unlock()
	if before.State != v2RoleReady {
		_ = unix.Close(result.fd)
		t.Fatalf("role became %q while final limits were unread", before.State)
	}
	if _, err := unix.Write(result.fd, []byte("1048576\n")); err != nil {
		_ = unix.Close(result.fd)
		t.Fatal(err)
	}
	if err := unix.Close(result.fd); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dropDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after final limits arrived")
	}
	d.mu.Lock()
	after := d.statusRoles[ParserTypeOffice]
	d.mu.Unlock()
	if after.State != v2RoleReaped {
		t.Fatalf("role did not become reaped after final limits: %#v", after)
	}
}

func TestV2SupervisorStatusFailedConfirmOrFinalLimitsCannotReap(t *testing.T) {
	for _, test := range []struct {
		name       string
		confirmErr error
		badLimits  bool
	}{
		{name: "confirm-failure", confirmErr: errors.New("confirm failed")},
		{name: "final-limits-failure", badLimits: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, worker, supervisor, _ := newV2StatusCleanupFixture(t, test.confirmErr, test.badLimits, false)
			d.supervisor = supervisor
			close(supervisor.release)
			d.dropV2Worker(worker)
			d.mu.Lock()
			status := d.statusRoles[ParserTypeOffice]
			red := d.red
			d.mu.Unlock()
			if !red || status.State != v2RoleRed {
				t.Fatalf("failed cleanup did not latch RED: red=%v status=%#v", red, status)
			}
			if worker.peer.PIDFD != -1 || worker.peer.cgroupFD != -1 {
				t.Fatalf("failed cleanup left dispatcher FDs open: %#v", worker.peer)
			}
		})
	}
}

func newV2StatusCleanupFixture(t *testing.T, confirmErr error, badLimits, blockingMemory bool) (*DispatcherV2, *v2Worker, *blockingStatusSupervisor, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	limitsFiles := map[string]string{
		"pids.max": "2\n",
		"cpu.max":  "50000 100000\n",
	}
	if !badLimits && !blockingMemory {
		limitsFiles["memory.max"] = "1048576\n"
	}
	for name, content := range limitsFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if blockingMemory {
		if err := unix.Mkfifo(filepath.Join(dir, "memory.max"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cgroupFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(cgroupFD)
		t.Fatal(err)
	}
	writer := &statusMemoryWriter{}
	d := statusTestDispatcher(writer, false)
	d.cfg.FrameTimeout = time.Second
	d.statusRoles[ParserTypeOffice] = v2StatusRoleState{State: v2RoleReady, HandoffID: testStatusHandoffID}
	expected := Limits{CPUMillis: 500, MemoryBytes: 1048576, PIDsMax: 2, WallClockMS: 2000}
	worker := &v2Worker{
		hello:   RegisterHelloV2{ParserType: ParserTypeOffice},
		handoff: SupervisorHandoffV1{HandoffID: testStatusHandoffID},
		entry:   V2RegistryEntry{ExpectedLimits: expected},
		peer: V2PeerHandle{
			ParserType: ParserTypeOffice, PIDFD: pidfd, cgroupFD: cgroupFD,
			Observation: Observation{PID: 1, CgroupPath: "/kv/status-test"},
		},
	}
	d.workers[ParserTypeOffice] = worker
	supervisor := &blockingStatusSupervisor{entered: make(chan struct{}), release: make(chan struct{}), confirmErr: confirmErr}
	t.Cleanup(func() {
		if worker.peer.PIDFD >= 0 {
			_ = unix.Close(worker.peer.PIDFD)
		}
		if worker.peer.cgroupFD >= 0 {
			_ = unix.Close(worker.peer.cgroupFD)
		}
		_ = writer.Close()
	})
	return d, worker, supervisor, dir
}

func TestV2SupervisorStatusPathRejectsTraversalAndNonSibling(t *testing.T) {
	for _, path := range []string{
		"relative/status.json",
		"/run/knowvault/sandbox/supervisor/../status.json",
		"/run/knowvault/sandbox/other/status.json",
		"/run/knowvault/sandbox/supervisor/status.txt",
	} {
		if validV2SupervisorStatusPath(path, "/run/knowvault/sandbox/supervisor/handoff.sock") {
			t.Errorf("accepted invalid status path %q", path)
		}
	}
	if !validV2SupervisorStatusPath("/run/knowvault/sandbox/supervisor/status.json", "/run/knowvault/sandbox/supervisor/handoff.sock") {
		t.Fatal("rejected canonical status sibling")
	}
}

func TestLinuxV2ProvedRegistrationRejectionClosesOnlyNewCgroupFD(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*DispatcherV2)
	}{
		{
			name: "dispatcher closed after peer proof",
			setup: func(d *DispatcherV2) {
				d.closed = true
			},
		},
		{
			name: "role already has worker after peer proof",
			setup: func(d *DispatcherV2) {
				d.workers[ParserTypeOffice] = &v2Worker{}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			cgroupFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			pidfd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				_ = unix.Close(cgroupFD)
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(pidfd) })
			d := &DispatcherV2{workers: make(map[string]*v2Worker)}
			test.setup(d)
			worker := &v2Worker{peer: V2PeerHandle{PIDFD: pidfd, cgroupFD: cgroupFD}}
			handoff := &v2Handoff{pidfd: pidfd}

			if statusCgroupFD, installed := d.installV2ProvedWorker(ParserTypeOffice, worker, handoff); installed || statusCgroupFD != -1 {
				t.Fatalf("rejected post-proof peer was installed: fd=%d installed=%v", statusCgroupFD, installed)
			}
			if worker.peer.cgroupFD != -1 {
				t.Fatalf("rejected peer retained cgroup fd %d", worker.peer.cgroupFD)
			}
			var stat unix.Stat_t
			if err := unix.Fstat(cgroupFD, &stat); !errors.Is(err, unix.EBADF) {
				t.Fatalf("new cgroup fd remains open after rejection: fstat err=%v", err)
			}
			if err := unix.Fstat(pidfd, &stat); err != nil {
				t.Fatalf("pending handoff pidfd was closed by worker rejection: %v", err)
			}
		})
	}
}
