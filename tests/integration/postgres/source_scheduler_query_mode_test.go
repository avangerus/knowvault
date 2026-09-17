package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/operator"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// TestAutoSyncAfterOperatorUpgrade exercises the deployed upgrade path that a
// worker sees when a database already accounted for 000088 and the scheduler
// migration is applied afterward. The scheduler's worker query then runs
// through the same pgx default prepared-statement mode as production.
func TestAutoSyncAfterOperatorUpgrade(t *testing.T) {
	ctx := context.Background()
	admin := resetForOperatorBootstrap(t)
	passwords := map[string]string{
		operator.RoleApplication: appPassword,
		operator.RoleWorker:      workerPassword,
		operator.RolePurger:      appPassword,
	}
	if err := operator.EnsureRoles(ctx, admin, passwords); err != nil {
		t.Fatalf("EnsureRoles: %v", err)
	}

	preSchedulerDir := migrationDirectoryThrough(t, "000088_stage1_identity_session_sliding_renewal.sql")
	preReport, err := operator.ApplyMigrations(ctx, admin, preSchedulerDir)
	if err != nil {
		t.Fatalf("apply pre-scheduler migrations: %v", err)
	}
	if len(preReport.Applied) == 0 || len(preReport.Skipped) != 0 {
		t.Fatalf("pre-scheduler bootstrap applied=%d skipped=%d", len(preReport.Applied), len(preReport.Skipped))
	}
	var scheduleLockPresent bool
	if err := admin.QueryRow(ctx, `SELECT to_regprocedure('app.source_scope_schedule_lock(text,bigint)') IS NOT NULL`).Scan(&scheduleLockPresent); err != nil {
		t.Fatalf("check pre-upgrade schedule lock: %v", err)
	}
	if scheduleLockPresent {
		t.Fatal("schedule lock exists before its migration")
	}

	schedulerDir := migrationDirectoryThrough(t, "000089_stage3_source_periodic_sync.sql")
	report, err := operator.ApplyMigrations(ctx, admin, schedulerDir)
	if err != nil {
		t.Fatalf("apply scheduler upgrade: %v", err)
	}
	if len(report.Applied) != 1 || report.Applied[0] != "000089_stage3_source_periodic_sync.sql" || len(report.Skipped) != len(preReport.Applied) {
		t.Fatalf("scheduler upgrade applied=%v skipped=%d", report.Applied, len(report.Skipped))
	}
	if err := admin.QueryRow(ctx, `SELECT to_regprocedure('app.source_scope_schedule_lock(text,bigint)') IS NOT NULL`).Scan(&scheduleLockPresent); err != nil {
		t.Fatalf("check post-upgrade schedule lock: %v", err)
	}
	if !scheduleLockPresent {
		t.Fatal("scheduler migration did not install schedule lock")
	}

	codec := s1dCodec(t, s1dOrg)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_scheduler_upgrade", "confirmation_scheduler_upgrade")
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(store)
	if err != nil {
		t.Fatalf("create worker queue: %v", err)
	}
	auditStore, err := audit.NewStore(store)
	if err != nil {
		t.Fatalf("create worker audit store: %v", err)
	}
	scheduler, err := registration.New(store, auditStore, codec, queue, s1dDigestKey, 1)
	if err != nil {
		t.Fatalf("create worker source scheduler: %v", err)
	}
	access := workerAccess(t, s1dOrg)
	bootstrapScheduledScope(t, ctx, admin, store, queue, access, s1dScopeID, jobs.TypeSourceScopeSync, "")

	count, err := scheduler.AutoSync(ctx, access)
	if err != nil || count != 1 {
		t.Fatalf("upgraded folder autosync count=%d err=%v", count, err)
	}
	var jobType, status string
	if err := admin.QueryRow(ctx, `SELECT type,status FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2
		ORDER BY created_at DESC LIMIT 1`, s1dOrg, s1dScopeID).Scan(&jobType, &status); err != nil {
		t.Fatalf("read scheduled job: %v", err)
	}
	if jobType != string(jobs.TypeSourceScopeSync) || status != "PENDING" {
		t.Fatalf("upgraded folder scheduled job type/status=%q/%q", jobType, status)
	}
}

func migrationDirectoryThrough(t *testing.T, lastMigration string) string {
	t.Helper()
	directory := t.TempDir()
	applied := false
	for _, migrationName := range migrationSequence {
		raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "db", "migrations", migrationName))
		if err != nil {
			t.Fatalf("read migration %s: %v", migrationName, err)
		}
		if err := os.WriteFile(filepath.Join(directory, migrationName), raw, 0o600); err != nil {
			t.Fatalf("write migration %s: %v", migrationName, err)
		}
		if migrationName == lastMigration {
			applied = true
			break
		}
	}
	if !applied {
		t.Fatalf("migration %s is not part of the known migration sequence", lastMigration)
	}
	return directory
}
