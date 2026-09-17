package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/operator"
)

// resetForOperatorBootstrap drops the complete stage-1 surface including the
// runtime roles and the operator accounting schema, so the operator's own
// bootstrap path runs against a clean database. Every other suite in this
// package rebuilds what it needs through its own reset helper.
func resetForOperatorBootstrap(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("open admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	for _, statement := range []string{
		"DROP SCHEMA IF EXISTS public CASCADE",
		"DROP SCHEMA IF EXISTS app CASCADE",
		"DROP SCHEMA IF EXISTS operator CASCADE",
		"DROP ROLE IF EXISTS knowvault_app",
		"DROP ROLE IF EXISTS knowvault_worker",
		"DROP ROLE IF EXISTS knowvault_purger",
		"CREATE SCHEMA public AUTHORIZATION CURRENT_USER",
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("operator bootstrap reset with %q: %v", statement, err)
		}
	}
	return admin
}

func operatorMigrationsDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repositoryRoot(t), "db", "migrations")
}

func TestOperatorBootstrapFromCleanDatabase(t *testing.T) {
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
	for _, role := range []string{operator.RoleApplication, operator.RoleWorker, operator.RolePurger} {
		var super, bypassrls, canlogin bool
		if err := admin.QueryRow(ctx, `
			SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = $1`, role).
			Scan(&super, &bypassrls, &canlogin); err != nil {
			t.Fatalf("role %s missing after EnsureRoles: %v", role, err)
		}
		if super || bypassrls || !canlogin {
			t.Fatalf("role %s has a non-runtime profile (super=%v bypassrls=%v canlogin=%v)", role, super, bypassrls, canlogin)
		}
	}

	report, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t))
	if err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	if report.Total != len(migrationSequence) || len(report.Applied) != report.Total || len(report.Skipped) != 0 {
		t.Fatalf("first run: total=%d applied=%d skipped=%d", report.Total, len(report.Applied), len(report.Skipped))
	}
	var accountingRows int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM operator.schema_migrations").Scan(&accountingRows); err != nil {
		t.Fatalf("accounting count: %v", err)
	}
	if accountingRows != len(migrationSequence) {
		t.Fatalf("accounting rows=%d, want %d", accountingRows, len(migrationSequence))
	}

	// A repeat bootstrap is state-idempotent: every migration is skipped by
	// checksum and every role is re-verified/reconciled to the same password.
	report, err = operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t))
	if err != nil {
		t.Fatalf("repeat ApplyMigrations: %v", err)
	}
	if len(report.Applied) != 0 || len(report.Skipped) != len(migrationSequence) {
		t.Fatalf("repeat run: applied=%d skipped=%d", len(report.Applied), len(report.Skipped))
	}
	if err := operator.EnsureRoles(ctx, admin, passwords); err != nil {
		t.Fatalf("repeat EnsureRoles: %v", err)
	}
}

func TestOperatorBootstrapDetectsTamperedAccounting(t *testing.T) {
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
	if _, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t)); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	// An applied migration whose recorded checksum no longer matches the file is
	// an incompatible migration state, never silently skipped.
	if _, err := admin.Exec(ctx, `
		UPDATE operator.schema_migrations SET checksum = 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
		WHERE name = (SELECT min(name) FROM operator.schema_migrations)`); err != nil {
		t.Fatal(err)
	}
	_, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t))
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("tampered accounting: err=%v", err)
	}
}

func TestOperatorRegisterProviderIdempotentAndConflicting(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_ops", "usr_ops", "ws_ops")

	registration := operator.ProviderRegistration{
		OrganizationID: "org_ops", ProviderID: "provider_ops",
		IssuerURL: "https://idp.example/auth", ClientID: "client_ops",
		ClientSecretReference: "secret_ops", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_ops",
	}
	created, err := operator.RegisterProvider(ctx, admin, registration)
	if err != nil || !created {
		t.Fatalf("first registration: created=%v err=%v", created, err)
	}
	// A repeat with the identical payload verifies the recorded configuration
	// and creates nothing.
	created, err = operator.RegisterProvider(ctx, admin, registration)
	if err != nil || created {
		t.Fatalf("repeat registration: created=%v err=%v", created, err)
	}
	state, err := operator.LookupProvider(ctx, admin, "org_ops", "provider_ops")
	if err != nil {
		t.Fatalf("LookupProvider: %v", err)
	}
	if state.Status != "ACTIVE" || state.Revision != 1 || state.ClientID != "client_ops" ||
		state.SecretRef != "secret_ops" || state.RedirectURI != "https://workspace.example/auth/callback" ||
		state.IssuerURL != "https://idp.example/auth" {
		t.Fatalf("recorded provider state=%+v", state)
	}
	if len(state.ConfigurationHash) < len("sha256:") || state.ConfigurationHash[:len("sha256:")] != "sha256:" {
		t.Fatalf("configuration hash not recorded as sha256 fingerprint: %q", state.ConfigurationHash)
	}

	// A payload that conflicts with the recorded configuration is a typed
	// incompatible state, never a silent overwrite.
	conflicting := registration
	conflicting.ClientSecretReference = "secret_ops_other"
	_, err = operator.RegisterProvider(ctx, admin, conflicting)
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("conflicting registration: err=%v", err)
	}
}

func TestOperatorReadinessRedOnMissingMountAgainstRealDatabase(t *testing.T) {
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
	if _, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t)); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	seedOrganization(t, ctx, admin, "org_rdy", "usr_rdy", "ws_rdy")
	if _, err := operator.RegisterProvider(ctx, admin, operator.ProviderRegistration{
		OrganizationID: "org_rdy", ProviderID: "provider_rdy",
		IssuerURL: "https://idp.example/auth", ClientID: "client_rdy",
		ClientSecretReference: "secret_rdy", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_rdy",
	}); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}

	// PostgreSQL and migration accounting are fully bootstrapped; the missing
	// server, worker and trust mounts are the red dependencies. Readiness must
	// not be green.
	report, err := operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: testDatabaseURL(t), ServerMountRoot: t.TempDir(), WorkerMountRoot: t.TempDir(), TrustMountRoot: t.TempDir(),
		OrganizationID: identity.OrganizationID("org_rdy"), ProviderID: identity.ProviderID("provider_rdy"),
		MigrationsDir: operatorMigrationsDir(t),
	})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if report.Readiness {
		t.Fatal("readiness is green without a key mount")
	}
	for _, dependency := range report.Dependencies {
		switch dependency.Name {
		case operator.DependencyPostgreSQL:
			if dependency.Status != operator.StatusReady {
				t.Fatalf("postgresql dependency=%s (%s)", dependency.Status, dependency.Detail)
			}
		case operator.DependencyMigrationState:
			if dependency.Status != operator.StatusReady {
				t.Fatalf("migration state dependency=%s (%s)", dependency.Status, dependency.Detail)
			}
		case operator.DependencyServerSecretMount, operator.DependencyWorkerSecretMount, operator.DependencyTrustBundle:
			if dependency.Status != operator.StatusUnavailable {
				t.Fatalf("mount/trust dependency %s=%s, want UNAVAILABLE", dependency.Name, dependency.Status)
			}
		default:
			t.Fatalf("unknown dependency %q in report", dependency.Name)
		}
	}
	if failure := report.FirstFailure(); failure == nil || failure.Code != operator.FailureDependencyUnavailable {
		t.Fatalf("first failure=%v", failure)
	}
}

// An elevated runtime role is a deployment-state conflict: readiness reports
// POSTGRESQL INCOMPATIBLE and the first failure maps to MIGRATION_INCOMPATIBLE
// (the unavailable key mount never outranks an incompatible dependency).
func TestOperatorReadinessRedsOnElevatedRuntimeRole(t *testing.T) {
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
	if _, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t)); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	seedOrganization(t, ctx, admin, "org_elv", "usr_elv", "ws_elv")
	if _, err := operator.RegisterProvider(ctx, admin, operator.ProviderRegistration{
		OrganizationID: "org_elv", ProviderID: "provider_elv",
		IssuerURL: "https://idp.example/auth", ClientID: "client_elv",
		ClientSecretReference: "secret_elv", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_elv",
	}); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}

	report, err := operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: testDatabaseURL(t), ServerMountRoot: t.TempDir(), WorkerMountRoot: t.TempDir(), TrustMountRoot: t.TempDir(),
		OrganizationID: identity.OrganizationID("org_elv"), ProviderID: identity.ProviderID("provider_elv"),
		MigrationsDir: operatorMigrationsDir(t),
	})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if report.Readiness {
		t.Fatal("readiness is green with a fully bootstrapped database")
	}
	if failure := report.FirstFailure(); failure == nil || failure.Code != operator.FailureDependencyUnavailable {
		t.Fatalf("baseline first failure=%v", failure)
	}

	// Elevate one runtime role: the bootstrap contract is broken and readiness
	// must classify it as an incompatible deployment state.
	if _, err := admin.Exec(ctx, "ALTER ROLE knowvault_app CREATEROLE"); err != nil {
		t.Fatal(err)
	}
	report, err = operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: testDatabaseURL(t), ServerMountRoot: t.TempDir(), WorkerMountRoot: t.TempDir(), TrustMountRoot: t.TempDir(),
		OrganizationID: identity.OrganizationID("org_elv"), ProviderID: identity.ProviderID("provider_elv"),
		MigrationsDir: operatorMigrationsDir(t),
	})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if report.Readiness {
		t.Fatal("readiness is green with an elevated runtime role")
	}
	for _, dependency := range report.Dependencies {
		switch dependency.Name {
		case operator.DependencyPostgreSQL:
			if dependency.Status != operator.StatusIncompatible {
				t.Fatalf("postgresql dependency=%s (%s), want INCOMPATIBLE", dependency.Status, dependency.Detail)
			}
		case operator.DependencyServerSecretMount, operator.DependencyWorkerSecretMount, operator.DependencyTrustBundle:
			if dependency.Status != operator.StatusUnavailable {
				t.Fatalf("mount/trust dependency %s=%s, want UNAVAILABLE", dependency.Name, dependency.Status)
			}
		case operator.DependencyMigrationState:
			if dependency.Status != operator.StatusReady {
				t.Fatalf("migration state dependency=%s (%s), want READY", dependency.Status, dependency.Detail)
			}
		default:
			t.Fatalf("unknown dependency %q in report", dependency.Name)
		}
	}
	if failure := report.FirstFailure(); failure == nil || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("elevated-role first failure=%v, want MIGRATION_INCOMPATIBLE", failure)
	}
}

// Two concurrent registrations of the same provider race on the unique index;
// exactly one wins the insert and the loser re-verifies the recorded
// configuration. Both observe success and the recorded state is single.
func TestOperatorRegisterProviderConcurrentCreationIsSingleWinner(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_cc", "usr_cc", "ws_cc")

	registration := operator.ProviderRegistration{
		OrganizationID: "org_cc", ProviderID: "provider_cc",
		IssuerURL: "https://idp.example/auth", ClientID: "client_cc",
		ClientSecretReference: "secret_cc", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_cc",
	}
	start := make(chan struct{})
	results := make(chan struct {
		created bool
		err     error
	}, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			created, err := operator.RegisterProvider(ctx, admin, registration)
			results <- struct {
				created bool
				err     error
			}{created, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var winners int
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent registration: err=%v", result.err)
		}
		if result.created {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent registration winners=%d, want 1", winners)
	}
	state, err := operator.LookupProvider(ctx, admin, "org_cc", "provider_cc")
	if err != nil {
		t.Fatalf("LookupProvider: %v", err)
	}
	if state.Status != "ACTIVE" || state.Revision != 1 || state.ClientID != "client_cc" {
		t.Fatalf("recorded provider state=%+v", state)
	}
}

// A migration file whose content no longer matches the applied checksum is an
// incompatible migration state: readiness reports MIGRATION_STATE INCOMPATIBLE
// against the tampered directory copy.
func TestOperatorReadinessDetectsMigrationFileTamper(t *testing.T) {
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
	if _, err := operator.ApplyMigrations(ctx, admin, operatorMigrationsDir(t)); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	seedOrganization(t, ctx, admin, "org_tmp", "usr_tmp", "ws_tmp")
	if _, err := operator.RegisterProvider(ctx, admin, operator.ProviderRegistration{
		OrganizationID: "org_tmp", ProviderID: "provider_tmp",
		IssuerURL: "https://idp.example/auth", ClientID: "client_tmp",
		ClientSecretReference: "secret_tmp", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_tmp",
	}); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}

	tampered := t.TempDir()
	entries, err := os.ReadDir(operatorMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	var copied []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(operatorMigrationsDir(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(copied) == 0 {
			// Tamper only the lexically first migration; the applied checksum
			// still records the original content.
			raw = append(raw, []byte("\n-- tampered by test\n")...)
		}
		if err := os.WriteFile(filepath.Join(tampered, entry.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		copied = append(copied, entry.Name())
	}
	if len(copied) != len(migrationSequence) {
		t.Fatalf("copied %d migrations, want %d", len(copied), len(migrationSequence))
	}

	report, err := operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: testDatabaseURL(t), ServerMountRoot: t.TempDir(), WorkerMountRoot: t.TempDir(), TrustMountRoot: t.TempDir(),
		OrganizationID: identity.OrganizationID("org_tmp"), ProviderID: identity.ProviderID("provider_tmp"),
		MigrationsDir: tampered,
	})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if report.Readiness {
		t.Fatal("readiness is green against a tampered migration directory")
	}
	for _, dependency := range report.Dependencies {
		switch dependency.Name {
		case operator.DependencyMigrationState:
			if dependency.Status != operator.StatusIncompatible {
				t.Fatalf("migration state dependency=%s (%s), want INCOMPATIBLE", dependency.Status, dependency.Detail)
			}
		case operator.DependencyPostgreSQL:
			if dependency.Status != operator.StatusReady {
				t.Fatalf("postgresql dependency=%s (%s), want READY", dependency.Status, dependency.Detail)
			}
		case operator.DependencyServerSecretMount, operator.DependencyWorkerSecretMount, operator.DependencyTrustBundle:
			if dependency.Status != operator.StatusUnavailable {
				t.Fatalf("mount/trust dependency %s=%s, want UNAVAILABLE", dependency.Name, dependency.Status)
			}
		default:
			t.Fatalf("unknown dependency %q in report", dependency.Name)
		}
	}
	if failure := report.FirstFailure(); failure == nil || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("tamper first failure=%v, want MIGRATION_INCOMPATIBLE", failure)
	}
}

// A runtime role that was elevated after bootstrap breaks the runtime-profile
// contract. EnsureRoles must detect the elevation on a repeat run and report a
// typed incompatible state instead of silently proceeding.
func TestOperatorBootstrapRefusesElevatedRuntimeRole(t *testing.T) {
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
	if _, err := admin.Exec(ctx, "ALTER ROLE knowvault_app CREATEROLE"); err != nil {
		t.Fatal(err)
	}
	err := operator.EnsureRoles(ctx, admin, passwords)
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("elevated runtime role: err=%v", err)
	}
}

// Two provider registrations under different ids with the same issuer are a
// permanent configuration conflict: the issuer index rejects the second insert
// and the re-verification path classifies it MIGRATION_INCOMPATIBLE, never a
// retryable dependency outage.
func TestOperatorRegisterProviderRefusesDuplicateIssuerUnderDifferentID(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_dup", "usr_dup", "ws_dup")

	first := operator.ProviderRegistration{
		OrganizationID: "org_dup", ProviderID: "provider_first",
		IssuerURL: "https://idp.example/auth", ClientID: "client_first",
		ClientSecretReference: "secret_first", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_dup",
	}
	if created, err := operator.RegisterProvider(ctx, admin, first); err != nil || !created {
		t.Fatalf("first registration: created=%v err=%v", created, err)
	}
	second := first
	second.ProviderID = "provider_second"
	second.ClientID = "client_second"
	second.ClientSecretReference = "secret_second"
	_, err := operator.RegisterProvider(ctx, admin, second)
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("duplicate issuer under different id: err=%v", err)
	}
	if failure.Retryable {
		t.Fatalf("duplicate issuer must not be retryable: %+v", failure)
	}
}
