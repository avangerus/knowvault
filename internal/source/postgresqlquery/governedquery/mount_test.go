package governedquery

import (
	"fmt"
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

func TestLoadMountedConfigWithPresets(t *testing.T) {
	root := t.TempDir()
	writeMount(t, root, `{"schema_version":"governed-query-mount-v1","connection_id":"demo-ops-govquery","database_identity":"demo_ops","workspace_id":"tko-operations","dsn_file":"dsn","trust_bundle_file":"trust.pem","presets_file":"presets.json","mode":"ADHOC","statement_timeout_seconds":5,"max_rows":1000,"max_result_bytes":1048576,"max_cost_estimate":1000}`,
		"postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full", testCACertPEM)
	if err := os.WriteFile(filepath.Join(root, "presets.json"), []byte(`{"schema_version":"governed-query-presets-v1","presets":[{"id":"contract-count","version":"v1","name":"Contract count","description":"Current contract count.","phrases":["check contracts"],"workspace_id":"tko-operations","source_attempt_id":"gqat_reviewed","sql_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exposed_schema_revision":3}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadMountedConfigAt(root)
	if err != nil || !config.HasPresets() || len(config.PresetSummaries("tko-operations")) != 1 || len(config.PresetSummaries("another-workspace")) != 0 {
		t.Fatalf("preset mount failed: config=%+v err=%v", config, err)
	}
}

func TestLoadMountedConfigRejectsSQLTextInPreset(t *testing.T) {
	root := t.TempDir()
	writeMount(t, root, `{"schema_version":"governed-query-mount-v1","connection_id":"demo-ops-govquery","database_identity":"demo_ops","workspace_id":"tko-operations","dsn_file":"dsn","trust_bundle_file":"trust.pem","presets_file":"presets.json","mode":"ADHOC","statement_timeout_seconds":5,"max_rows":1000,"max_result_bytes":1048576,"max_cost_estimate":1000}`,
		"postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full", testCACertPEM)
	if err := os.WriteFile(filepath.Join(root, "presets.json"), []byte(`{"schema_version":"governed-query-presets-v1","presets":[{"id":"unsafe","version":"v1","name":"Unsafe","description":"Must fail.","phrases":["do it"],"workspace_id":"tko-operations","source_attempt_id":"gqat_reviewed","sql_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exposed_schema_revision":3,"sql":"UPDATE reporting.contracts SET active = false"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadMountedConfigAt(root)
	if CodeOf(err) != CodeMountInvalid {
		t.Fatalf("a preset carrying SQL text must make the mount invalid, got %v", err)
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

func TestLoadMountedConfigEnforcesPresetModeContract(t *testing.T) {
	const presetFixture = `{"schema_version":"governed-query-presets-v1","presets":[{"id":"contract-count","version":"v1","name":"Contract count","description":"Current contract count.","phrases":["check contracts"],"workspace_id":"tko-operations","source_attempt_id":"gqat_reviewed","sql_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exposed_schema_revision":3}]}`
	tests := []struct {
		name           string
		mountMembers   string
		writePresets   bool
		wantPresetOnly bool
		wantInvalid    bool
	}{
		{name: "legacy mount without mode", mountMembers: "", wantPresetOnly: false},
		{name: "explicit adhoc without presets", mountMembers: `,"mode":"ADHOC"`, wantPresetOnly: false},
		{name: "adhoc with presets", mountMembers: `,"presets_file":"presets.json","mode":"ADHOC"`, writePresets: true, wantPresetOnly: false},
		{name: "preset only with presets", mountMembers: `,"presets_file":"presets.json","mode":"PRESET_ONLY"`, writePresets: true, wantPresetOnly: true},
		{name: "presets require explicit mode", mountMembers: `,"presets_file":"presets.json"`, writePresets: true, wantInvalid: true},
		{name: "unknown mode is invalid", mountMembers: `,"presets_file":"presets.json","mode":"SOMETHING_ELSE"`, writePresets: true, wantInvalid: true},
		{name: "preset only requires presets", mountMembers: `,"mode":"PRESET_ONLY"`, wantInvalid: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			manifest := fmt.Sprintf(`{"schema_version":"governed-query-mount-v1","connection_id":"demo-ops-govquery","database_identity":"demo_ops","workspace_id":"tko-operations","dsn_file":"dsn","trust_bundle_file":"trust.pem"%s,"statement_timeout_seconds":5,"max_rows":1000,"max_result_bytes":1048576,"max_cost_estimate":1000}`, test.mountMembers)
			writeMount(t, root, manifest,
				"postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full", testCACertPEM)
			if test.writePresets {
				if err := os.WriteFile(filepath.Join(root, "presets.json"), []byte(presetFixture), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			config, err := LoadMountedConfigAt(root)
			if test.wantInvalid {
				if CodeOf(err) != CodeMountInvalid {
					t.Fatalf("expected CodeMountInvalid, got config=%+v err=%v", config, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected valid mode contract, got %v", err)
			}
			if config.PresetOnly != test.wantPresetOnly {
				t.Fatalf("PresetOnly=%v, want %v", config.PresetOnly, test.wantPresetOnly)
			}
		})
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
