package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

// Readiness dependency names are closed by
// architecture/contracts/operator-readiness.schema.json. Every dependency in
// the production topology is declared explicitly; undeclared names are
// unknown dependencies and are rejected by the contract, never assumed ready.
const (
	DependencyPostgreSQL        = "POSTGRESQL"
	DependencyServerSecretMount = "SERVER_SECRET_MOUNT"
	DependencyWorkerSecretMount = "WORKER_SECRET_MOUNT"
	DependencyTrustBundle       = "TRUST_BUNDLE"
	DependencyMigrationState    = "MIGRATION_STATE"

	// DependencyKeyProvider is retained as a source-compatible name for code
	// that used the original single-mount readiness report. It denotes the
	// server mount; Readiness always probes both component mounts separately.
	DependencyKeyProvider = DependencyServerSecretMount

	StatusReady        = "READY"
	StatusUnavailable  = "UNAVAILABLE"
	StatusIncompatible = "INCOMPATIBLE"

	readinessSourceDependencyCheck = "DEPENDENCY_CHECK"

	readinessPrincipal = "knowvault-readiness"
	readinessRequest   = "knowvault-readiness"
)

// ReadinessConfig is the closed input of one readiness evaluation. The three
// mount roots are deliberately independent: readiness must not silently reuse
// one component's credentials or trust material for another component.
type ReadinessConfig struct {
	AdminURL        string
	ServerMountRoot string
	WorkerMountRoot string
	TrustMountRoot  string
	OrganizationID  identity.OrganizationID
	ProviderID      identity.ProviderID
	MigrationsDir   string
}

// Dependency is one named readiness probe result. The wire shape is closed by
// architecture/contracts/operator-readiness.schema.json: a dependency record
// carries exactly name and status (additionalProperties is false). Detail is
// in-memory only — it feeds FirstFailure and is intentionally never emitted in
// report JSON. All details produced by this file are fixed, content-free
// tokens; no secret, DSN, or filesystem path is included.
type Dependency struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"-"`
}

// ReadinessReport conforms to architecture/contracts/operator-readiness.
// schema.json: readiness is true only when every declared dependency is
// READY; an unavailable or incompatible dependency is always red (OPS-011).
type ReadinessReport struct {
	SchemaVersion   string       `json:"schema_version"`
	Liveness        bool         `json:"liveness"`
	Readiness       bool         `json:"readiness"`
	ReadinessSource string       `json:"readiness_source"`
	Dependencies    []Dependency `json:"dependencies"`
}

// Readiness evaluates every dependency of the current topology and returns a
// schema-conforming report. It never turns a missing prerequisite into a
// green gate. Liveness describes this operator evaluation process only; it is
// not a substitute for a worker component heartbeat.
func Readiness(ctx context.Context, config ReadinessConfig) (*ReadinessReport, error) {
	if ctx == nil {
		return nil, DependencyUnavailable("nil context")
	}

	// Load the trust bundle once through the real product loader. The resulting
	// database-purpose handle is passed to both runtime probes; a missing or
	// invalid trust root therefore cannot be bypassed by either mount.
	databaseRoots, trustDependency, trustReady := readinessTrustBundle(config.TrustMountRoot)
	dependencies := []Dependency{probePostgreSQL(ctx, config)}
	for _, specification := range runtimeProbeSpecs(config) {
		dependencies = append(dependencies, probeRuntimeMount(ctx, specification.rootPath,
			config.OrganizationID, config.ProviderID, specification.dependencyName,
			specification.expectedRole, databaseRoots, trustReady))
	}
	dependencies = append(dependencies, trustDependency, probeMigrationState(ctx, config))
	ready := true
	for _, dependency := range dependencies {
		if dependency.Status != StatusReady {
			ready = false
			break
		}
	}
	return &ReadinessReport{
		SchemaVersion: "operator-readiness-v1", Liveness: true, Readiness: ready,
		ReadinessSource: readinessSourceDependencyCheck, Dependencies: dependencies,
	}, nil
}

type runtimeProbeSpec struct {
	rootPath       string
	dependencyName string
	expectedRole   string
}

// runtimeProbeSpecs is deliberately data-only so the distinct server/worker
// credential paths have a cheap mutation proof in addition to the live TLS
// R3 exercise. Neither root nor role may be reused across the two components.
func runtimeProbeSpecs(config ReadinessConfig) []runtimeProbeSpec {
	return []runtimeProbeSpec{
		{rootPath: config.ServerMountRoot, dependencyName: DependencyServerSecretMount, expectedRole: RoleApplication},
		{rootPath: config.WorkerMountRoot, dependencyName: DependencyWorkerSecretMount, expectedRole: RoleWorker},
	}
}

// readinessTrustBundle loads both purpose-separated bundles from the exact
// administrator-supplied root. It returns only the database-purpose handle to
// runtime probes; the OIDC-purpose handle is still required to prove that the
// complete bundle was loaded and validated.
func readinessTrustBundle(rootPath string) (trustbundle.DatabaseRoots, Dependency, bool) {
	bundle, err := trustbundle.LoadMountedAt(rootPath)
	if err != nil {
		return trustbundle.DatabaseRoots{}, trustBundleDependency(rootPath, err), false
	}
	databaseRoots, databaseErr := bundle.DatabaseRoots()
	oidcRoots, oidcErr := bundle.OIDCRoots()
	if databaseErr != nil || oidcErr != nil {
		return trustbundle.DatabaseRoots{}, Dependency{
			Name: DependencyTrustBundle, Status: StatusIncompatible,
			Detail: "trust bundle purpose separation invalid",
		}, false
	}
	// Keep the OIDC handle live through this scope so the compiler cannot
	// accidentally reduce the purpose check to a database-only load.
	_ = oidcRoots
	return databaseRoots, Dependency{Name: DependencyTrustBundle, Status: StatusReady}, true
}

func trustBundleDependency(rootPath string, err error) Dependency {
	_ = rootPath // root paths are never reflected in diagnostics.
	status := StatusUnavailable
	if trustbundle.CodeOf(err) == trustbundle.CodeInvalid {
		status = StatusIncompatible
	}
	return Dependency{Name: DependencyTrustBundle, Status: status, Detail: trustBundleDetail(status)}
}

func trustBundleDetail(status string) string {
	if status == StatusIncompatible {
		return "trust bundle invalid"
	}
	return "trust bundle unavailable"
}

// FirstFailure maps a red readiness report to the typed operator failure the
// CLI must emit. The mapping is code-to-action per the protected failure
// schema and is never silent.
func (report *ReadinessReport) FirstFailure() *Failure {
	if report == nil {
		return DependencyUnavailable("no readiness report")
	}
	if report.Readiness {
		return nil
	}
	// A present-but-invalid secret or trust mount is fixed by replacing the
	// mount, while an incompatible database/migration state remains a
	// migration/deployment conflict. Status is checked before name so READY
	// dependencies can never shadow a red one.
	for _, dependency := range report.Dependencies {
		if isMountDependency(dependency.Name) && dependency.Status == StatusIncompatible {
			return MountInvalid(safeFailureDetail(dependency.Detail, "mount is invalid"))
		}
	}
	for _, dependency := range report.Dependencies {
		if dependency.Status == StatusIncompatible {
			return MigrationIncompatible(safeFailureDetail(dependency.Detail, "deployment state is incompatible"))
		}
	}
	for _, dependency := range report.Dependencies {
		if dependency.Status == StatusUnavailable {
			return DependencyUnavailable(safeFailureDetail(dependency.Detail, "dependency unavailable"))
		}
	}
	return DependencyUnavailable("readiness is red without a mapped dependency failure")
}

func isMountDependency(name string) bool {
	return name == DependencyServerSecretMount || name == DependencyWorkerSecretMount || name == DependencyTrustBundle
}

// Details are generated internally as fixed tokens. The fallback also keeps a
// manually assembled report from turning an arbitrary string into a CLI
// diagnostic when FirstFailure is called by a consumer.
func safeFailureDetail(detail, fallback string) string {
	switch detail {
	case "mount invalid", "mount unavailable",
		"trust bundle invalid", "trust bundle unavailable",
		"runtime database trust bundle unavailable",
		"runtime database URL capability unavailable",
		"runtime database connection unavailable",
		"runtime database identity/profile incompatible",
		"runtime database query unavailable",
		"admin database URL is not configured",
		"admin database unavailable", "admin database role lookup unavailable",
		"admin runtime role profile incompatible", "provider registration incompatible",
		"provider lookup unavailable", "migration directory incompatible",
		"migration directory unavailable", "migration accounting unavailable",
		"migration accounting incompatible", "migration accounting file unavailable":
		return detail
	default:
		return fallback
	}
}

func probePostgreSQL(ctx context.Context, config ReadinessConfig) Dependency {
	if strings.TrimSpace(config.AdminURL) == "" {
		return Dependency{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "admin database URL is not configured"}
	}
	pool, err := pgxpool.New(ctx, config.AdminURL)
	if err != nil {
		return Dependency{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "admin database unavailable"}
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return Dependency{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "admin database unavailable"}
	}
	// The full runtime profile, all 8 catalog flags, exactly as bootstrap
	// enforces it: any elevated or login-less flag makes the deployment red.
	var profilesSatisfied int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_roles
		WHERE rolname = ANY($1)
		  AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls
		  AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolinherit`,
		runtimeRoles).Scan(&profilesSatisfied); err != nil {
		return Dependency{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "admin database role lookup unavailable"}
	}
	if profilesSatisfied != len(runtimeRoles) {
		return Dependency{Name: DependencyPostgreSQL, Status: StatusIncompatible, Detail: "admin runtime role profile incompatible"}
	}
	if _, err := LookupProvider(ctx, pool, string(config.OrganizationID), string(config.ProviderID)); err != nil {
		failure, _ := IsFailure(err)
		if failure != nil && failure.Code == FailureMigrationIncompatible {
			return Dependency{Name: DependencyPostgreSQL, Status: StatusIncompatible, Detail: "provider registration incompatible"}
		}
		return Dependency{Name: DependencyPostgreSQL, Status: StatusUnavailable, Detail: "provider lookup unavailable"}
	}
	return Dependency{Name: DependencyPostgreSQL, Status: StatusReady}
}

// probeRuntimeMount verifies one component's complete runtime path. The
// product secretmount loader is always called first; only its DatabaseURL
// capability is then handed to the product TLS database constructor. This
// means a valid-looking file set cannot report green without a live connection
// under the intended runtime identity.
func probeRuntimeMount(ctx context.Context, rootPath string, organizationID identity.OrganizationID,
	providerID identity.ProviderID, dependencyName, expectedRole string,
	databaseRoots trustbundle.DatabaseRoots, trustReady bool) Dependency {
	consumer := "server"
	if expectedRole == RoleWorker {
		consumer = "worker"
	}
	provider, err := loadSecretMount(rootPath, organizationID, providerID, consumer)
	if err != nil {
		status := StatusUnavailable
		if secretmount.CodeOf(err) != secretmount.CodeUnavailable {
			status = StatusIncompatible
		}
		return Dependency{Name: dependencyName, Status: status, Detail: mountDetail(status)}
	}
	defer provider.Close()

	databaseURL, err := provider.DatabaseURL()
	if err != nil {
		return Dependency{Name: dependencyName, Status: StatusUnavailable, Detail: "runtime database URL capability unavailable"}
	}
	if !trustReady {
		// The mount was genuinely loaded, but opening it without the
		// administrator's database-purpose roots would be an insecure false
		// green. Keep the failure tied to this runtime dependency as well as
		// the explicit TRUST_BUNDLE record.
		return Dependency{Name: dependencyName, Status: StatusUnavailable, Detail: "runtime database trust bundle unavailable"}
	}

	databaseConfig := database.DefaultConfig()
	databaseConfig.ApplicationRole = expectedRole
	databaseConfig.MaxConnections = 1
	databaseConfig.URL = databaseURL
	store, openErr := database.OpenProduction(ctx, databaseConfig, databaseRoots)
	databaseConfig.URL = ""
	databaseURL = ""
	if openErr != nil {
		switch database.CodeOf(openErr) {
		case database.CodeConfigInvalid, database.CodeRuntimeRoleRejected:
			return Dependency{Name: dependencyName, Status: StatusIncompatible, Detail: "runtime database identity/profile incompatible"}
		default:
			return Dependency{Name: dependencyName, Status: StatusUnavailable, Detail: "runtime database connection unavailable"}
		}
	}
	defer store.Close()
	if err := verifyRuntimeDatabase(ctx, store, organizationID, expectedRole); err != nil {
		return Dependency{Name: dependencyName, Status: StatusIncompatible, Detail: "runtime database identity/profile incompatible"}
	}
	return Dependency{Name: dependencyName, Status: StatusReady}
}

// verifyRuntimeDatabase performs the explicit post-connect gate in addition
// to database.OpenProduction's AfterConnect check. It intentionally selects
// current_user and session_user from the live connection, then checks every
// runtime role flag enforced by bootstrap and the role/session RLS setting.
func verifyRuntimeDatabase(ctx context.Context, store *database.Store, organizationID identity.OrganizationID, expectedRole string) error {
	if store == nil || ctx == nil {
		return databaseErrorSentinel{}
	}
	access := database.AccessContext{
		OrganizationID: string(organizationID),
		PrincipalID:    readinessPrincipal,
		RequestID:      readinessRequest,
	}
	if err := access.Validate(); err != nil {
		return err
	}
	var currentUser, sessionUser, rowSecurity string
	var canLogin, superuser, bypassRLS, createRole, createDB, replication, inherit, roleRLS bool
	err := store.Read(ctx, access, func(queryContext context.Context, transaction database.Transaction) error {
		return transaction.QueryRow(queryContext, `
			SELECT current_user::text,
			       session_user::text,
			       role_record.rolcanlogin,
			       role_record.rolsuper,
			       role_record.rolbypassrls,
			       role_record.rolcreaterole,
			       role_record.rolcreatedb,
			       role_record.rolreplication,
			       role_record.rolinherit,
			       current_setting('row_security', true),
			       COALESCE(role_record.rolconfig @> ARRAY['row_security=on']::text[], false)
			FROM pg_catalog.pg_roles AS role_record
			WHERE role_record.rolname = current_user::text`).
			Scan(&currentUser, &sessionUser, &canLogin, &superuser, &bypassRLS,
				&createRole, &createDB, &replication, &inherit, &rowSecurity, &roleRLS)
	})
	if err != nil {
		return err
	}
	if currentUser != expectedRole || sessionUser != expectedRole || !canLogin || superuser || bypassRLS ||
		createRole || createDB || replication || inherit || rowSecurity != "on" || !roleRLS {
		return databaseErrorSentinel{}
	}
	return nil
}

// databaseErrorSentinel is intentionally opaque. The caller only needs a
// non-nil result to classify a failed runtime identity/profile gate and must
// never expose a driver message, DSN, or filesystem path.
type databaseErrorSentinel struct{}

func (databaseErrorSentinel) Error() string { return "runtime database identity/profile incompatible" }

func mountDetail(status string) string {
	if status == StatusIncompatible {
		return "mount invalid"
	}
	return "mount unavailable"
}

func probeMigrationState(ctx context.Context, config ReadinessConfig) Dependency {
	// Classification matches bootstrap: the migration directory is operator
	// input, so an unusable directory is an incompatible deployment state,
	// not a transient outage (ApplyMigrations reports MIGRATION_INCOMPATIBLE
	// for the same condition).
	names, err := migrationFiles(config.MigrationsDir)
	if err != nil {
		return Dependency{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "migration directory incompatible"}
	}
	pool, err := pgxpool.New(ctx, config.AdminURL)
	if err != nil {
		return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting unavailable"}
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting unavailable"}
	}
	recorded := make(map[string]string, len(names))
	rows, err := pool.Query(ctx, `SELECT name, checksum FROM operator.schema_migrations`)
	if err != nil {
		return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting unavailable"}
	}
	defer rows.Close()
	for rows.Next() {
		var name, checksum string
		if err := rows.Scan(&name, &checksum); err != nil {
			return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting unavailable"}
		}
		recorded[name] = checksum
	}
	if err := rows.Err(); err != nil {
		return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting unavailable"}
	}
	return migrationAccountingState(config.MigrationsDir, names, recorded)
}

// migrationAccountingState shares bootstrap's exact checksum compatibility
// rule. It never updates accounting or treats arbitrary comment changes as safe.
func migrationAccountingState(migrationsDir string, names []string, recorded map[string]string) Dependency {
	known := make(map[string]bool, len(names))
	for _, name := range names {
		known[name] = true
		raw, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			return Dependency{Name: DependencyMigrationState, Status: StatusUnavailable, Detail: "migration accounting file unavailable"}
		}
		sum := sha256.Sum256(raw)
		checksum, exists := recorded[name]
		if !exists || !migrationChecksumMatches(name, checksum, hex.EncodeToString(sum[:])) {
			return Dependency{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "migration accounting incompatible"}
		}
	}
	for name := range recorded {
		if !known[name] {
			return Dependency{Name: DependencyMigrationState, Status: StatusIncompatible, Detail: "migration accounting incompatible"}
		}
	}
	return Dependency{Name: DependencyMigrationState, Status: StatusReady}
}
