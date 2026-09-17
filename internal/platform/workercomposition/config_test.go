package workercomposition

import "testing"

func TestLoadProductionRejectsUnknownAndServerEnvironment(t *testing.T) {
	valid := []string{
		"KNOWVAULT_ORGANIZATION_ID=org_001",
		"KNOWVAULT_PROVIDER_ID=provider_001",
		"KNOWVAULT_WORKER_ID=worker_001",
		"KNOWVAULT_WORKER_LEASE_SECONDS=60",
		"KNOWVAULT_WORKER_POLL_SECONDS=2",
	}
	if config, err := loadProduction(valid); err != nil || config.WorkerID() != "worker_001" {
		t.Fatalf("valid config=%#v err=%v", config, err)
	}
	for name, extra := range map[string]string{
		"unknown":        "KNOWVAULT_HTTP_ADDR=127.0.0.1:8080",
		"case duplicate": "knowvault_worker_id=worker_002",
		"malformed":      "KNOWVAULT_BROKEN",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]string(nil), valid...)
			candidate = append(candidate, extra)
			if _, err := loadProduction(candidate); CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("config accepted: err=%v", err)
			}
		})
	}
}

func TestLoadProductionRejectsUnsafeLeaseProfiles(t *testing.T) {
	base := []string{
		"KNOWVAULT_ORGANIZATION_ID=org_001",
		"KNOWVAULT_PROVIDER_ID=provider_001",
		"KNOWVAULT_WORKER_ID=worker_001",
		"KNOWVAULT_WORKER_LEASE_SECONDS=60",
		"KNOWVAULT_WORKER_POLL_SECONDS=2",
	}
	for index, value := range map[int]string{
		3: "KNOWVAULT_WORKER_LEASE_SECONDS=2",
		4: "KNOWVAULT_WORKER_POLL_SECONDS=60",
	} {
		candidate := append([]string(nil), base...)
		candidate[index] = value
		if _, err := loadProduction(candidate); CodeOf(err) != CodeConfigInvalid {
			t.Fatalf("unsafe profile %q accepted: err=%v", value, err)
		}
	}
}

// TestDiagnosticClassReportsStartupStage is the contract test for a worker
// startup rejection: substituting one staged-acquisition condition (here, an
// unavailable source mount) must still surface a specific, content-free
// class in the log -- the stage that failed and, when known, the failing
// collaborator's own code -- never just the flat top-level ErrorCode every
// startup failure otherwise shares.
func TestDiagnosticClassReportsStartupStage(t *testing.T) {
	err := startupError(stageSourceMounts, workerError(CodeMountsUnavailable))
	if code := CodeOf(err); code != CodeStartupFailed {
		t.Fatalf("code = %v, want %v", code, CodeStartupFailed)
	}
	if class := DiagnosticClass(err); class != "SOURCE_MOUNTS:WORKER_MOUNTS_UNAVAILABLE" {
		t.Fatalf("class = %q", class)
	}
}

// TestDiagnosticClassReportsStageWithoutCause covers a stage failure whose
// cause was never captured (nil): the stage alone is still a usable class,
// never an empty string masquerading as "no information".
func TestDiagnosticClassReportsStageWithoutCause(t *testing.T) {
	if class := DiagnosticClass(startupError(stageDatabaseOpen, nil)); class != stageDatabaseOpen {
		t.Fatalf("class = %q", class)
	}
}

// TestDiagnosticClassEmptyForNonStartupErrors keeps DiagnosticClass safe to
// call unconditionally next to CodeOf: an error from a different rejection
// path (or no error at all) reports no stage, rather than a misleading one.
func TestDiagnosticClassEmptyForNonStartupErrors(t *testing.T) {
	if class := DiagnosticClass(workerError(CodeRuntimeState)); class != "" {
		t.Fatalf("class = %q, want empty", class)
	}
	if class := DiagnosticClass(nil); class != "" {
		t.Fatalf("class = %q, want empty", class)
	}
}
