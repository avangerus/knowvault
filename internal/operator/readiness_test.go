package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The readiness report wire shape is closed by
// architecture/contracts/operator-readiness.schema.json: a dependency record
// carries exactly name and status (additionalProperties is false), so Detail
// must never reach the report JSON even on a red dependency.
func TestReadinessReportWireConformsToClosedContract(t *testing.T) {
	report := &ReadinessReport{
		SchemaVersion: "operator-readiness-v1", Liveness: true, Readiness: false,
		ReadinessSource: readinessSourceDependencyCheck,
		Dependencies: []Dependency{
			{Name: DependencyPostgreSQL, Status: StatusIncompatible, Detail: "runtime roles are not fully bootstrapped"},
			{Name: DependencyKeyProvider, Status: StatusUnavailable, Detail: "mount unavailable"},
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	dependencies, ok := wire["dependencies"].([]any)
	if !ok || len(dependencies) != 2 {
		t.Fatalf("dependencies=%v", wire["dependencies"])
	}
	for _, rawDependency := range dependencies {
		dependency, ok := rawDependency.(map[string]any)
		if !ok {
			t.Fatalf("dependency record=%v", rawDependency)
		}
		if len(dependency) != 2 || dependency["name"] == nil || dependency["status"] == nil {
			t.Fatalf("dependency record carries members outside the closed schema: %v", dependency)
		}
		if _, leaked := dependency["detail"]; leaked {
			t.Fatalf("dependency record leaks detail: %v", dependency)
		}
	}
	// The in-memory detail still feeds the typed failure mapping.
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("first failure=%v", failure)
	}
}

func TestReadinessFirstFailureMapping(t *testing.T) {
	report := &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyKeyProvider, Status: StatusIncompatible, Detail: "manifest invalid"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMountInvalid {
		t.Fatalf("mount mapping=%v", failure)
	}
	report = &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "migration not applied"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("migration mapping=%v", failure)
	}
	report = &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "down"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureDependencyUnavailable {
		t.Fatalf("dependency mapping=%v", failure)
	}
	green := &ReadinessReport{Readiness: true}
	if failure := green.FirstFailure(); failure != nil {
		t.Fatalf("green report produced %v", failure)
	}
}

// The mapping is status-guarded: a READY dependency never shadows a red one,
// and INCOMPATIBLE always outranks UNAVAILABLE regardless of declaration order.
func TestReadinessFirstFailureStatusGuards(t *testing.T) {
	// A READY key mount must not shadow an incompatible migration state.
	report := &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyKeyProvider, Status: StatusReady},
		{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "checksum mismatch"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("ready key provider shadowed the migration failure: %v", failure)
	}
	// An INCOMPATIBLE dependency outranks an UNAVAILABLE one even when the
	// unavailable dependency is declared first.
	report = &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "down"},
		{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "migration not applied"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("unavailable outranked incompatible: %v", failure)
	}
	// An incompatible key mount is MOUNT_INVALID first even when other
	// dependencies are incompatible too.
	report = &ReadinessReport{Readiness: false, Dependencies: []Dependency{
		{Name: DependencyPostgreSQL, Status: StatusIncompatible, Detail: "role profile elevated"},
		{Name: DependencyKeyProvider, Status: StatusIncompatible, Detail: "manifest invalid"},
	}}
	if failure := report.FirstFailure(); failure == nil || failure.Code != FailureMountInvalid {
		t.Fatalf("mount mapping not first: %v", failure)
	}
}

// probeMigrationState classifies an unusable migration directory before any
// database access: a stray non-versioned *.sql is an incompatible deployment
// state, matching ApplyMigrations.
func TestProbeMigrationStateClassifiesUnusableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "000001_init.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	dependency := probeMigrationState(context.Background(), ReadinessConfig{MigrationsDir: dir})
	if dependency.Status != StatusIncompatible {
		t.Fatalf("status=%s detail=%s", dependency.Status, dependency.Detail)
	}
}

// probePostgreSQL reports UNAVAILABLE (never READY and never INCOMPATIBLE)
// when the admin URL is absent: a missing prerequisite stays red.
func TestProbePostgreSQLUnconfiguredAdminURL(t *testing.T) {
	dependency := probePostgreSQL(context.Background(), ReadinessConfig{})
	if dependency.Status != StatusUnavailable {
		t.Fatalf("status=%s detail=%s", dependency.Status, dependency.Detail)
	}
}

func TestMigrationAccountingAcceptsOnlyExactCommentTranslations(t *testing.T) {
	dir := t.TempDir()
	names := make([]string, 0, len(migrationCommentFixtures))
	legacy := make(map[string]string)
	current := make(map[string]string)
	for _, fixture := range migrationCommentFixtures {
		names = append(names, fixture.name)
		legacy[fixture.name] = fixture.legacy
		current[fixture.name] = fixture.translated
		if err := os.WriteFile(filepath.Join(dir, fixture.name), readMigrationCommentFixture(t, fixture.name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for label, recorded := range map[string]map[string]string{"legacy": legacy, "current": current} {
		t.Run(label, func(t *testing.T) {
			if result := migrationAccountingState(dir, names, recorded); result.Status != StatusReady {
				t.Fatalf("compatible accounting=%+v", result)
			}
		})
	}
	for _, fixture := range migrationCommentFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(dir, fixture.name)
			raw := readMigrationCommentFixture(t, fixture.name)
			if err := os.WriteFile(path, append(append([]byte(nil), raw...), []byte("\nSELECT 1;\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if result := migrationAccountingState(dir, names, legacy); result.Status != StatusIncompatible {
				t.Fatalf("changed SQL passed readiness: %+v", result)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			delete(legacy, fixture.name)
			if result := migrationAccountingState(dir, names, legacy); result.Status != StatusIncompatible {
				t.Fatalf("missing ledger entry passed readiness: %+v", result)
			}
			legacy[fixture.name] = fixture.legacy
		})
	}
	first, second := migrationCommentFixtures[0], migrationCommentFixtures[1]
	legacy[first.name] = second.legacy
	if result := migrationAccountingState(dir, names, legacy); result.Status != StatusIncompatible {
		t.Fatalf("cross-paired ledger hash passed readiness: %+v", result)
	}
	legacy[first.name] = first.legacy
	legacy["000999_unlisted.sql"] = first.legacy
	if result := migrationAccountingState(dir, names, legacy); result.Status != StatusIncompatible {
		t.Fatalf("unknown ledger migration passed readiness: %+v", result)
	}
}

// Every production mount is a required input. In particular, supplying only
// one historical single-mount input cannot make a report green or suppress
// either component's secret/database probe.
func TestReadinessRequiresAllExplicitRoots(t *testing.T) {
	report, err := Readiness(context.Background(), ReadinessConfig{ServerMountRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if report.Readiness {
		t.Fatal("readiness is green without explicit server, worker and trust roots")
	}
	want := map[string]bool{
		DependencyPostgreSQL:        false,
		DependencyServerSecretMount: false,
		DependencyWorkerSecretMount: false,
		DependencyTrustBundle:       false,
		DependencyMigrationState:    false,
	}
	for _, dependency := range report.Dependencies {
		if _, exists := want[dependency.Name]; !exists {
			t.Fatalf("unexpected dependency %q", dependency.Name)
		}
		want[dependency.Name] = true
		if dependency.Status == StatusReady {
			t.Fatalf("missing-root dependency %q reported READY", dependency.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Fatalf("required dependency %q missing", name)
		}
	}
}

func TestReadinessRuntimeProbeSpecsAreDistinct(t *testing.T) {
	config := ReadinessConfig{ServerMountRoot: "/server-only", WorkerMountRoot: "/worker-only"}
	specifications := runtimeProbeSpecs(config)
	if len(specifications) != 2 {
		t.Fatalf("runtime probe count=%d, want 2", len(specifications))
	}
	server, worker := specifications[0], specifications[1]
	if server.rootPath != config.ServerMountRoot || server.dependencyName != DependencyServerSecretMount || server.expectedRole != RoleApplication {
		t.Fatalf("server runtime probe=%+v", server)
	}
	if worker.rootPath != config.WorkerMountRoot || worker.dependencyName != DependencyWorkerSecretMount || worker.expectedRole != RoleWorker {
		t.Fatalf("worker runtime probe=%+v", worker)
	}
	if server.rootPath == worker.rootPath || server.dependencyName == worker.dependencyName || server.expectedRole == worker.expectedRole {
		t.Fatalf("runtime probes are not capability-distinct: server=%+v worker=%+v", server, worker)
	}
}

// Readiness diagnostics are operator-visible, so path, DSN and secret
// material must remain absent from both the report JSON and the typed failure.
func TestReadinessDiagnosticsAreContentFree(t *testing.T) {
	canary := "readiness-secret-canary"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := Readiness(ctx, ReadinessConfig{
		AdminURL:        "postgres://user:" + canary + "@db.example:5432/knowvault?sslmode=verify-full",
		ServerMountRoot: "/sealed/" + canary,
		WorkerMountRoot: "/sealed/worker-" + canary,
		TrustMountRoot:  "/trust/" + canary,
		MigrationsDir:   "/migrations/" + canary,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("readiness JSON leaked diagnostic material: %s", raw)
	}
	failure := report.FirstFailure()
	if failure == nil || strings.Contains(failure.Error(), canary) || strings.Contains(failure.Detail, canary) {
		t.Fatalf("readiness failure leaked diagnostic material: %+v", failure)
	}
}
