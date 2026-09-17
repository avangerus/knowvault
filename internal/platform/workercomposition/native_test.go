package workercomposition

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
)

func nativeTestEnvironment() []string {
	return []string{"KNOWVAULT_ORGANIZATION_ID=org_001", "KNOWVAULT_PROVIDER_ID=provider_001", "KNOWVAULT_WORKER_ID=worker_001", "KNOWVAULT_WORKER_LEASE_SECONDS=60", "KNOWVAULT_WORKER_POLL_SECONDS=2"}
}

func TestNativeProfileIsOptionalAndClosed(t *testing.T) {
	for _, item := range []struct {
		profile                 string
		present, valid, enabled bool
	}{
		{"", false, true, false}, {"disabled", true, true, false}, {NativeProfileRevision, true, true, true},
		{"", true, false, false}, {"true", true, false, false}, {"document-parser-sandbox-v2", true, false, false},
		{"/tmp/parser.sock", true, false, false}, {" document-parser-sandbox-v3", true, false, false},
	} {
		env := nativeTestEnvironment()
		if item.present {
			env = append(env, nativeProfileEnvironment+"="+item.profile)
		}
		config, err := loadProduction(env)
		if (err == nil) != item.valid || (err == nil && config.NativeEnabled() != item.enabled) {
			t.Fatalf("profile %q present=%t accepted=%t enabled=%t", item.profile, item.present, err == nil, config.NativeEnabled())
		}
		if err == nil {
			office, pdf, err := nativeExtractors(config)
			if err != nil || (office != nil) != item.enabled || (pdf != nil) != item.enabled {
				t.Fatal("native extractors do not match the selected profile")
			}
		}
	}
	env := append(nativeTestEnvironment(), nativeProfileEnvironment+"=disabled", nativeProfileEnvironment+"="+NativeProfileRevision)
	if _, err := loadProduction(env); err == nil {
		t.Fatal("duplicate native profile accepted")
	}
}

func TestNativeDisabledIsNotReadyAndUnavailableFailsBeforeMounts(t *testing.T) {
	config, err := loadProduction(nativeTestEnvironment())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckNativeReadiness(context.Background(), config); CodeOf(err) != CodeNativeDisabled {
		t.Fatalf("disabled reported ready: %v", err)
	}
	config.nativeEnabled = true
	// A canceled readiness call is deterministic even on a host with a real
	// dispatcher. Startup separately preserves the typed native stage on a
	// live context when the canonical endpoint is unavailable in this fixture.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := CheckNativeReadiness(ctx, config); CodeOf(err) != CodeNativeNotReady {
		t.Fatalf("canceled probe=%v", err)
	}
	if canonicalNativeSubmitSocket != "/run/knowvault/sandbox/submit/dispatcher.sock" {
		t.Fatal("native socket changed")
	}
	// In the isolated test container no canonical endpoint, secret or database
	// mount is supplied. A developer host with live native service runs the
	// protocol assertions above but cannot exercise this missing-service case.
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if CheckNativeReadiness(ctx, config) == nil {
		t.Skip("isolated missing-dispatcher startup case requires no live native endpoint")
	}
	runtime, err := NewProduction(ctx, config, buildinfo.Info{})
	if runtime != nil || DiagnosticClass(err) != "NATIVE_PARSER:WORKER_NATIVE_NOT_READY" {
		t.Fatalf("native startup failure lost: %v %q", err, DiagnosticClass(err))
	}
}
