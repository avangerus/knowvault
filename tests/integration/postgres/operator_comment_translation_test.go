package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/operator"
)

var operatorCommentTranslations = []struct{ name, legacy, translated string }{
	{"000077_stage2_evidence_fragment_readable_per_scope.sql", "83ce299c009c877b379f436272dd62780306e659d806d2e62f004387c3055779", "e7706f35480571675c537821b1640e712b12333c79f15b395ccc1fbb2bfa681c"},
	{"000078_stage3_governed_query_workspace_binding.sql", "eeb5f884582201564fda16a5fbd66791ce1b3db81ea3b72de8f789be3234eb45", "a7a988e1b492622c98e604fc4ff3eb9fc682cd3cea7760c268a4c3cbfe096ade"},
	{"000080_stage3_conversation_continuation_revision_tolerant.sql", "60c1745f0274638c97d090a220ede58f26d8dc8292f32d14cd58fd988a5aee27", "8eed587de6da613698860d0072f9bcb3a963dcffc2c653e3bb0f64097c2267cd"},
	{"000082_stage3_structured_snapshot_status_role.sql", "37dc121288e5a3ed63b61bb4a26d3bbec8bf1e6687e68ff1129abb811ed935f6", "8d5ea8f86a88ec814fa30d3d9b3bce383c54dc5a9b3df1cc718866348578d408"},
	{"000083_stage3_structured_source_scope_names.sql", "7456d5908c9356f471c0a465fd1f68041251333c5d8e9ffbcf2dc12ea6853672", "369bb4184bc418040310841979d54b2533f788e05bd5fc4011e38ec3c4a25545"},
	{"000094_stage3_metric_definitions.sql", "fc4927677050e97753598fe04a580c49f97d57b4780551621557c7bcc1c3e6c8", "9de3a3797bfcfcb99f500cc67b64f29d1d5285389cbf0c8541c5b03cb307d440"},
}

// Runs only against the package's isolated integration database. Replacing
// ledger hashes here simulates the six historically applied comment versions;
// production operators must never rewrite that ledger.
func TestOperatorCommentTranslationPreservesLegacyLedger(t *testing.T) {
	ctx := context.Background()
	admin := resetForOperatorBootstrap(t)
	if err := operator.EnsureRoles(ctx, admin, map[string]string{
		operator.RoleApplication: appPassword, operator.RoleWorker: workerPassword, operator.RolePurger: appPassword,
	}); err != nil {
		t.Fatal(err)
	}
	migrationsDir := operatorMigrationsDir(t)
	first, err := operator.ApplyMigrations(ctx, admin, migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Applied) != len(migrationSequence) || len(first.Skipped) != 0 {
		t.Fatalf("fresh bootstrap report=%+v", first)
	}
	timestamps := make(map[string]string)
	for _, fixture := range operatorCommentTranslations {
		var recorded, appliedAt string
		if err := admin.QueryRow(ctx, "SELECT checksum, applied_at::text FROM operator.schema_migrations WHERE name=$1", fixture.name).Scan(&recorded, &appliedAt); err != nil {
			t.Fatal(err)
		}
		if recorded != fixture.translated {
			t.Fatalf("fresh %s checksum=%s", fixture.name, recorded)
		}
		timestamps[fixture.name] = appliedAt
		tag, err := admin.Exec(ctx, "UPDATE operator.schema_migrations SET checksum=$1 WHERE name=$2 AND checksum=$3", fixture.legacy, fixture.name, fixture.translated)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("prepare isolated legacy ledger fixture: rows=%d error=%v", tag.RowsAffected(), err)
		}
	}
	repeated, err := operator.ApplyMigrations(ctx, admin, migrationsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(repeated.Applied) != 0 || len(repeated.Skipped) != len(migrationSequence) {
		t.Fatalf("legacy bootstrap reapplied SQL: %+v", repeated)
	}
	assertMigrationReadiness := func(dir, want string) {
		t.Helper()
		report, err := operator.Readiness(ctx, operator.ReadinessConfig{AdminURL: testDatabaseURL(t), MigrationsDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		for _, dependency := range report.Dependencies {
			if dependency.Name == operator.DependencyMigrationState {
				if dependency.Status != want {
					t.Fatalf("migration readiness=%s, want %s", dependency.Status, want)
				}
				return
			}
		}
		t.Fatal("migration readiness dependency absent")
	}
	assertMigrationReadiness(migrationsDir, operator.StatusReady)
	for _, fixture := range operatorCommentTranslations {
		var recorded, appliedAt string
		if err := admin.QueryRow(ctx, "SELECT checksum, applied_at::text FROM operator.schema_migrations WHERE name=$1", fixture.name).Scan(&recorded, &appliedAt); err != nil {
			t.Fatal(err)
		}
		if recorded != fixture.legacy || appliedAt != timestamps[fixture.name] {
			t.Fatalf("compatibility rewrote %s accounting", fixture.name)
		}
	}
	// A changed executable statement is not covered by the comment whitelist.
	tamperedDir := t.TempDir()
	for _, name := range migrationSequence {
		raw, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == operatorCommentTranslations[0].name {
			raw = append(raw, []byte("\nSELECT 1;\n")...)
		}
		if err := os.WriteFile(filepath.Join(tamperedDir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rejected, err := operator.ApplyMigrations(ctx, admin, tamperedDir)
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible || len(rejected.Applied) != 0 {
		t.Fatalf("tampered migration was not refused: report=%+v error=%v", rejected, err)
	}
	assertMigrationReadiness(tamperedDir, operator.StatusIncompatible)
}
