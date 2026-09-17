package main

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestWorkerRejectsUnknownCommands(t *testing.T) {
	for _, arguments := range [][]string{nil, {"ready"}, {"native-readiness", "extra"}, {"/tmp/parser.sock"}} {
		if got := runArguments(arguments); got != 2 {
			t.Fatalf("unsupported command %q returned %d", arguments, got)
		}
	}
}

func TestWorkerReadinessCommandDoesNotStartDisabledRuntime(t *testing.T) {
	for _, item := range os.Environ() {
		name, value, _ := strings.Cut(item, "=")
		if strings.HasPrefix(strings.ToUpper(name), "KNOWVAULT_") {
			if err := os.Unsetenv(name); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Setenv(name, value) })
		}
	}
	for name, value := range map[string]string{
		"KNOWVAULT_ORGANIZATION_ID": "org_001", "KNOWVAULT_PROVIDER_ID": "provider_001",
		"KNOWVAULT_WORKER_ID": "worker_001", "KNOWVAULT_WORKER_LEASE_SECONDS": "60",
		"KNOWVAULT_WORKER_POLL_SECONDS": "2", "KNOWVAULT_WORKER_NATIVE_PROFILE": "disabled",
	} {
		t.Setenv(name, value)
	}
	previousArgs, previousLogger := os.Args, slog.Default()
	t.Cleanup(func() { os.Args = previousArgs; slog.SetDefault(previousLogger) })
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	os.Args = []string{"knowvault-worker", "native-readiness"}
	if code := run(); code != 1 {
		t.Fatalf("disabled readiness returned %d", code)
	}
	if !strings.Contains(logs.String(), "WORKER_NATIVE_DISABLED") || strings.Contains(logs.String(), "component starting") {
		t.Fatalf("probe started a runtime or lost its disabled classification: %s", logs.String())
	}
}
