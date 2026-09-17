package governedquery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMountedConfigAbsent(t *testing.T) {
	_, err := LoadMountedConfigAt(filepath.Join(t.TempDir(), "does-not-exist"))
	if CodeOf(err) != CodeMountUnavailable {
		t.Fatalf("expected CodeMountUnavailable for a missing mount, got %v", CodeOf(err))
	}
}

func TestLoadMountedConfigValid(t *testing.T) {
	root := t.TempDir()
	writeMount(t, root, `{"schema_version":"governed-query-mount-v1","connection_id":"demo-ops-govquery","database_identity":"demo_ops","workspace_id":"tko-operations","dsn_file":"dsn","trust_bundle_file":"trust.pem","statement_timeout_seconds":5,"max_rows":1000,"max_result_bytes":1048576,"max_cost_estimate":1000}`,
		"postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full", testCACertPEM)

	config, err := LoadMountedConfigAt(root)
	if err != nil {
		t.Fatalf("expected a valid mount, got %v", err)
	}
	if config.ConnectionID != "demo-ops-govquery" || config.Limits.MaxRows != 1000 {
		t.Fatalf("unexpected config: %+v", config)
	}
}

func TestLoadMountedConfigInvalidIsNeverAbsent(t *testing.T) {
	root := t.TempDir()
	// insecure_lab_mode-equivalent guard: a malformed schema_version must be a
	// hard failure, never treated as "capability absent".
	writeMount(t, root, `{"schema_version":"wrong","connection_id":"x","database_identity":"x","workspace_id":"x","dsn_file":"dsn","trust_bundle_file":"trust.pem","statement_timeout_seconds":5,"max_rows":1000,"max_result_bytes":1048576,"max_cost_estimate":1000}`,
		"postgres://u:p@host:5432/db?sslmode=verify-full", testCACertPEM)
	_, err := LoadMountedConfigAt(root)
	if CodeOf(err) != CodeMountInvalid {
		t.Fatalf("expected CodeMountInvalid, got %v", CodeOf(err))
	}
}

func writeMount(t *testing.T, root, config, dsn, trustBundle string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, mountConfigFilename), []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "dsn"), []byte(dsn), 0o600); err != nil {
		t.Fatalf("write dsn: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "trust.pem"), []byte(trustBundle), 0o600); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}
}
