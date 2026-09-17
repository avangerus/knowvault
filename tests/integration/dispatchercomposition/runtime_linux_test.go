//go:build linux

package dispatchercomposition_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/dispatchercomposition"
)

const (
	testDispatcherRoot = "/run/knowvault/sandbox"
	testSubmitSocket   = "/run/knowvault/sandbox/submit/dispatcher.sock"
	testHandoffSocket  = "/run/knowvault/sandbox/supervisor/handoff.sock"
	testOfficeSocket   = "/run/knowvault/sandbox/office/register.sock"
	testPDFSocket      = "/run/knowvault/sandbox/pdf/register.sock"
)

// TestNewProductionRunsRealDispatcherV2 is an opt-in privileged proof of the
// production composition root. It creates the exact manifest layout inside an
// isolated Linux test container, starts the real four-listener broker (not a
// fake observer/supervisor), verifies socket ownership/mode, and proves
// cancellation drains Run. The opt-in keeps ordinary developer tests from
// mutating a host deployment's /run tree.
func TestNewProductionRunsRealDispatcherV2(t *testing.T) {
	if os.Getenv("KNOWVAULT_RUN_DISPATCHER_COMPOSITION_TEST") != "1" {
		t.Skip("set KNOWVAULT_RUN_DISPATCHER_COMPOSITION_TEST=1 in an isolated privileged Linux runner")
	}
	if os.Geteuid() != 0 {
		t.Skip("DispatcherV2 composition proof requires root for exact socket ownership")
	}
	if _, err := os.Lstat(testDispatcherRoot); err == nil {
		t.Skip("canonical dispatcher root already exists; refusing to touch a deployment tree")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat canonical dispatcher root: %v", err)
	}
	if err := os.MkdirAll(testDispatcherRoot, 0o750); err != nil {
		t.Fatalf("create canonical dispatcher root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testDispatcherRoot) })
	for _, role := range []string{"submit", "supervisor", "office", "pdf"} {
		path := filepath.Join(testDispatcherRoot, role)
		if err := os.Mkdir(path, 0o710); err != nil {
			t.Fatalf("create role root %s: %v", role, err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatalf("own role root %s: %v", role, err)
		}
	}
	if err := os.Chown(testDispatcherRoot, 0, 0); err != nil {
		t.Fatalf("own canonical dispatcher root: %v", err)
	}

	configEnvironment := []string{
		"KNOWVAULT_DISPATCHER_ROOT_DIR=" + testDispatcherRoot,
		"KNOWVAULT_DISPATCHER_SUBMIT_SOCKET=unix://" + testSubmitSocket,
		"KNOWVAULT_DISPATCHER_HANDOFF_SOCKET=unix://" + testHandoffSocket,
		"KNOWVAULT_DISPATCHER_OFFICE_REGISTER_SOCKET=unix://" + testOfficeSocket,
		"KNOWVAULT_DISPATCHER_PDF_REGISTER_SOCKET=unix://" + testPDFSocket,
		"KNOWVAULT_DISPATCHER_SUPERVISOR_UID=0", "KNOWVAULT_DISPATCHER_SUPERVISOR_GID=0",
		"KNOWVAULT_DISPATCHER_SUBMITTER_UID=65530", "KNOWVAULT_DISPATCHER_SUBMITTER_GID=65530",
		"KNOWVAULT_DISPATCHER_OFFICE_WORKER_UID=65532", "KNOWVAULT_DISPATCHER_OFFICE_WORKER_GID=65532",
		"KNOWVAULT_DISPATCHER_PDF_WORKER_UID=65533", "KNOWVAULT_DISPATCHER_PDF_WORKER_GID=65533",
		"KNOWVAULT_DISPATCHER_MAX_PAYLOAD_BYTES=67108864", "KNOWVAULT_DISPATCHER_FRAME_TIMEOUT_MS=5000",
	}
	for _, entry := range configEnvironment {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("invalid test environment entry")
		}
		t.Setenv(name, value)
	}
	// The opt-in switch is intentionally not part of the production allowlist;
	// remove it while exercising the exact binary-facing environment snapshot.
	if value, exists := os.LookupEnv("KNOWVAULT_RUN_DISPATCHER_COMPOSITION_TEST"); exists {
		_ = os.Unsetenv("KNOWVAULT_RUN_DISPATCHER_COMPOSITION_TEST")
		t.Cleanup(func() { _ = os.Setenv("KNOWVAULT_RUN_DISPATCHER_COMPOSITION_TEST", value) })
	}
	config, err := dispatchercomposition.LoadProduction()
	if err != nil {
		t.Fatalf("load exact manifest configuration: %v", err)
	}
	runtime, err := dispatchercomposition.NewProduction(config)
	if err != nil {
		t.Fatalf("construct real DispatcherV2 composition: %v", err)
	}
	defer runtime.Close()
	for _, socket := range []struct {
		path string
		uid  uint32
		gid  uint32
	}{
		{testSubmitSocket, 65530, 65530}, {testHandoffSocket, 0, 0},
		{testOfficeSocket, 65532, 65532}, {testPDFSocket, 65533, 65533},
	} {
		info, statErr := os.Lstat(socket.path)
		if statErr != nil {
			t.Fatalf("socket %s: %v", socket.path, statErr)
		}
		if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
			t.Fatalf("socket %s mode/type = %v, want unix 0600", socket.path, info.Mode())
		}
		uid, gid, ok := socketOwner(info)
		if !ok || uid != socket.uid || gid != socket.gid {
			t.Fatalf("socket %s owner = %d/%d, want %d/%d", socket.path, uid, gid, socket.uid, socket.gid)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case runErr := <-runDone:
		if runErr != nil {
			t.Fatalf("real DispatcherV2 Run after cancellation: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real DispatcherV2 Run did not drain after cancellation")
	}
}

// Keep syscall ownership metadata in this integration-only file so the
// production composition boundary remains free of kernel imports. This helper
// is used by the acceptance harness when it inspects the four socket paths.
func socketOwner(info os.FileInfo) (uint32, uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}
