package operator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The three runtime database roles are compile-time constants. The operator
// does not accept caller-supplied role names; the grants themselves live in
// the versioned migration stream.
const (
	RoleApplication = "knowvault_app"
	RoleWorker      = "knowvault_worker"
	RolePurger      = "knowvault_purger"

	accountingSchema   = "operator"
	accountingTable    = "operator.schema_migrations"
	maximumPasswordLen = 128
)

var runtimeRoles = []string{RoleApplication, RoleWorker, RolePurger}

// EnsureRoles creates the three non-privileged runtime roles when absent and
// verifies the privilege profile of already-existing roles. A role that
// exists with elevated or login-less flags is a deployment-state conflict,
// not a transient outage.
func EnsureRoles(ctx context.Context, pool *pgxpool.Pool, passwords map[string]string) error {
	if ctx == nil || pool == nil {
		return DependencyUnavailable("nil context or pool")
	}
	for _, role := range runtimeRoles {
		password, ok := passwords[role]
		if !ok || !validRolePassword(password) {
			return MigrationIncompatible("role password missing or invalid for " + role)
		}
	}
	for _, role := range runtimeRoles {
		profile, err := readRoleProfile(ctx, pool, role)
		if err != nil {
			return DependencyUnavailable("role lookup failed: " + err.Error())
		}
		if profile.exists {
			if !profile.runtimeProfileSatisfied() {
				return MigrationIncompatible("role exists with a non-runtime privilege profile: " + role)
			}
			// Password files are desired deployment state, not create-only input.
			// Reconcile every existing role so a repeated bootstrap performs an
			// actual credential rotation instead of reporting success while the
			// server and worker mounts carry credentials PostgreSQL will reject.
			if err := setRuntimeRolePassword(ctx, pool, role, passwords[role]); err != nil {
				return err
			}
			continue
		}
		if err := createRuntimeRole(ctx, pool, role, passwords[role]); err != nil {
			return err
		}
	}
	return nil
}

// roleProfile is the complete privilege profile of one database role as
// enforced by both bootstrap and readiness (all 8 catalog flags).
type roleProfile struct {
	exists                                                                 bool
	super, bypassrls, createrole, createdb, replication, inherit, canlogin bool
}

// runtimeProfileSatisfied reports whether an existing role carries exactly
// the runtime profile: login-enabled, no superuser, no BYPASSRLS, no role or
// database creation, no replication, no role inheritance.
func (profile roleProfile) runtimeProfileSatisfied() bool {
	return !profile.super && !profile.bypassrls && !profile.createrole &&
		!profile.createdb && !profile.replication && !profile.inherit && profile.canlogin
}

// readRoleProfile reads the full privilege profile of one role. The bool_or
// aggregate over the catalog always yields one row, so a role that does not
// exist yet scans cleanly instead of surfacing as a query failure.
func readRoleProfile(ctx context.Context, pool *pgxpool.Pool, role string) (roleProfile, error) {
	var profile roleProfile
	err := pool.QueryRow(ctx, `
		SELECT COALESCE(bool_or(rolname = $1), false),
		       COALESCE(bool_or(rolname = $1 AND rolsuper), false),
		       COALESCE(bool_or(rolname = $1 AND rolbypassrls), false),
		       COALESCE(bool_or(rolname = $1 AND rolcreaterole), false),
		       COALESCE(bool_or(rolname = $1 AND rolcreatedb), false),
		       COALESCE(bool_or(rolname = $1 AND rolreplication), false),
		       COALESCE(bool_or(rolname = $1 AND rolinherit), false),
		       COALESCE(bool_or(rolname = $1 AND rolcanlogin), false)
		FROM pg_roles
	`, role).Scan(&profile.exists, &profile.super, &profile.bypassrls, &profile.createrole,
		&profile.createdb, &profile.replication, &profile.inherit, &profile.canlogin)
	if err != nil {
		return profile, err
	}
	return profile, nil
}

// validRolePassword confines role passwords to a closed character set so the
// material can be safely quoted into the CREATE ROLE utility statement. The
// runtime roles never log in interactively; a rejected character is a
// deployment input error.
func validRolePassword(value string) bool {
	if value == "" || len(value) > maximumPasswordLen {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '\'' || character == '\\' {
			return false
		}
	}
	return true
}

func createRuntimeRole(ctx context.Context, pool *pgxpool.Pool, role, password string) error {
	statement := fmt.Sprintf(
		"CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		role, password,
	)
	if _, err := pool.Exec(ctx, statement); err != nil {
		if !isDuplicateObject(err) {
			return DependencyUnavailable("role creation failed for " + role + ": " + err.Error())
		}
		// A concurrent operator created the role between the lookup and the
		// CREATE; re-verify the full profile instead of trusting the race.
		profile, verifyErr := readRoleProfile(ctx, pool, role)
		if verifyErr != nil {
			return DependencyUnavailable("concurrent role profile verification failed for " + role + ": " + verifyErr.Error())
		}
		if !profile.exists {
			return DependencyUnavailable("role vanished during concurrent creation: " + role)
		}
		if !profile.runtimeProfileSatisfied() {
			return MigrationIncompatible("concurrently created role carries a non-runtime privilege profile: " + role)
		}
		// The concurrent creator may have supplied a different password. The
		// caller's protected password file remains authoritative for this run.
		if err := setRuntimeRolePassword(ctx, pool, role, password); err != nil {
			return err
		}
	}
	return nil
}

// setRuntimeRolePassword reconciles one already-validated fixed role to the
// protected password-file value. Role names are compile-time constants and
// validRolePassword excludes SQL quoting characters, so no caller-controlled
// identifier or literal can reach this utility statement. Failure detail names
// only the role; secret material is never retained or emitted.
func setRuntimeRolePassword(ctx context.Context, pool *pgxpool.Pool, role, password string) error {
	statement := fmt.Sprintf("ALTER ROLE %s PASSWORD '%s'", role, password)
	if _, err := pool.Exec(ctx, statement); err != nil {
		return DependencyUnavailable("role password reconciliation failed for " + role)
	}
	return nil
}

func isDuplicateObject(err error) bool {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return pgError.Code == "42710" || pgError.Code == "42P07"
	}
	return false
}

// AppliedReport is the bootstrap result for one migration directory run.
type AppliedReport struct {
	Total   int      `json:"total"`
	Applied []string `json:"applied"`
	Skipped []string `json:"skipped"`
}

// ApplyMigrations applies every *.sql file of the migration directory in
// lexical order under the single operator accounting stream
// (operator.schema_migrations: name, sha256 checksum, applied_at). Applied
// migrations are immutable. The six explicitly pinned English comment
// translations accept their exact legacy ledger checksum without rewriting it
// or replaying SQL; every other mismatch remains incompatible.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, migrationsDir string) (AppliedReport, error) {
	var report AppliedReport
	if ctx == nil || pool == nil {
		return report, DependencyUnavailable("nil context or pool")
	}
	if err := ensureAccounting(ctx, pool); err != nil {
		return report, err
	}
	names, err := migrationFiles(migrationsDir)
	if err != nil {
		return report, MigrationIncompatible("migration directory unusable: " + err.Error())
	}
	report.Total = len(names)
	for _, name := range names {
		raw, readErr := os.ReadFile(filepath.Join(migrationsDir, name))
		if readErr != nil {
			return report, DependencyUnavailable("migration file unreadable " + name + ": " + readErr.Error())
		}
		sum := sha256.Sum256(raw)
		checksum := hex.EncodeToString(sum[:])
		var recorded string
		err := pool.QueryRow(ctx, `SELECT checksum FROM operator.schema_migrations WHERE name = $1`, name).Scan(&recorded)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			if err := applyOneMigration(ctx, pool, name, checksum, raw); err != nil {
				return report, err
			}
			report.Applied = append(report.Applied, name)
		case err != nil:
			return report, DependencyUnavailable("accounting lookup failed for " + name + ": " + err.Error())
		case !migrationChecksumMatches(name, recorded, checksum):
			return report, MigrationIncompatible("applied migration checksum mismatch: " + name)
		default:
			report.Skipped = append(report.Skipped, name)
		}
	}
	return report, nil
}

func migrationFiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		name := filepath.Base(match)
		if name == "." || name == ".." {
			continue
		}
		// Only the versioned 0-prefixed stream may live in the migration
		// directory; a stray *.sql is a deployment input error, never a
		// silent skip.
		if !strings.HasPrefix(name, "0") {
			return nil, errors.New("migration directory carries a non-versioned *.sql file: " + name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, errors.New("no 000*.sql migration files found")
	}
	return names, nil
}

func applyOneMigration(ctx context.Context, pool *pgxpool.Pool, name, checksum string, raw []byte) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return DependencyUnavailable("begin migration transaction failed: " + err.Error())
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, string(raw)); err != nil {
		return DependencyUnavailable("migration failed " + name + ": " + err.Error())
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO operator.schema_migrations (name, checksum, applied_at) VALUES ($1, $2, transaction_timestamp())`,
		name, checksum); err != nil {
		return DependencyUnavailable("accounting insert failed for " + name + ": " + err.Error())
	}
	if err := tx.Commit(ctx); err != nil {
		return DependencyUnavailable("migration commit failed for " + name + ": " + err.Error())
	}
	return nil
}

// ensureAccounting creates the operator accounting schema and table when
// absent and verifies the exact column shape of an existing table. Accounting
// shape drift is an incompatible deployment state.
func ensureAccounting(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS operator`); err != nil {
		return DependencyUnavailable("accounting schema creation failed: " + err.Error())
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS operator.schema_migrations (
			name text PRIMARY KEY,
			checksum text NOT NULL,
			applied_at timestamptz NOT NULL
		)`); err != nil {
		return DependencyUnavailable("accounting table creation failed: " + err.Error())
	}
	rows, err := pool.Query(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'operator' AND table_name = 'schema_migrations'
		ORDER BY ordinal_position`)
	if err != nil {
		return DependencyUnavailable("accounting shape lookup failed: " + err.Error())
	}
	defer rows.Close()
	columns := make([]string, 0, 3)
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return DependencyUnavailable("accounting shape scan failed: " + err.Error())
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		return DependencyUnavailable("accounting shape iteration failed: " + err.Error())
	}
	if strings.Join(columns, ",") != "name,checksum,applied_at" {
		return MigrationIncompatible("operator.schema_migrations has an incompatible column shape")
	}
	return nil
}
