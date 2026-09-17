// Package database provides the only PostgreSQL transaction entry point for
// application code. A transaction cannot begin before all three request
// identity values are validated and installed as transaction-local settings.
package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultApplicationRole = "knowvault_app"

const oidcServicePrincipal = "svc_oidc"

// ErrorCode is safe to expose to structured logs and API error mapping.
type ErrorCode string

const (
	CodeConfigInvalid       ErrorCode = "DATABASE_CONFIG_INVALID"
	CodeConnectionFailed    ErrorCode = "DATABASE_CONNECTION_FAILED"
	CodeRuntimeRoleRejected ErrorCode = "DATABASE_RUNTIME_ROLE_REJECTED"
	CodeContextInvalid      ErrorCode = "DATABASE_CONTEXT_INVALID"
	CodeTransactionFailed   ErrorCode = "DATABASE_TRANSACTION_FAILED"
)

// Error preserves a stable, content-free error code. Its cause must not be
// returned to an untrusted caller because it can contain a locator or role.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps unexpected errors to a safe generic code.
func CodeOf(err error) ErrorCode {
	var databaseError *Error
	if errors.As(err, &databaseError) {
		return databaseError.code
	}
	return CodeTransactionFailed
}

// IsSerializationFailure reports a PostgreSQL retryable serialization error
// without exposing a query, a database locator or an error message. Domain
// repositories use it only for bounded replay of their whole transaction.
func IsSerializationFailure(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "40001"
}

// IsNotFound keeps the pgx no-row sentinel inside the database boundary.
// Domain repositories use it to make absence a safe product outcome without
// importing the database driver directly.
func IsNotFound(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}

// SQLStateCode returns the PostgreSQL error code behind err, or "" when err
// does not carry one. Domain repositories use it to map closed database gate
// outcomes without importing the driver; the value is a fixed five-character
// code, never an error message.
func SQLStateCode(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}

// SQLConstraintName returns only the stable PostgreSQL constraint identifier
// carried by an error. Domain packages may use it for bounded diagnostics
// without importing the driver or exposing the database error text.
func SQLConstraintName(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.ConstraintName
	}
	return ""
}

// ActorKind distinguishes a human session from a SERVICE (agent access-code)
// principal for audit and MCP-surface gating (ADR-0079 §3). It is never used
// to widen or narrow RLS/organization scoping: organization_id/principal_id
// alone still drive every tenant/membership check.
type ActorKind string

const (
	// ActorKindHuman is the implicit default: every existing AccessContext
	// literal that never sets ActorKind (the vast majority of the codebase)
	// remains exactly as authored before this field existed.
	ActorKindHuman   ActorKind = "HUMAN"
	ActorKindService ActorKind = "SERVICE"
)

// AccessContext is derived only from an authenticated server request or a
// claimed worker job. Values are opaque identifiers, never client SQL filters.
type AccessContext struct {
	OrganizationID string
	PrincipalID    string
	RequestID      string
	// ActorKind is empty (treated as ActorKindHuman) for every access path
	// that predates the agent access-code capability. Only the MCP service
	// access-code authenticator (internal/serviceprincipal) sets it to
	// ActorKindService.
	ActorKind ActorKind
}

// NewOIDCServiceAccess creates the sole OIDC pre-authentication database
// context. It is limited to one tenant and has a fixed non-human principal
// marker. The marker is never written as the actor of an audit event:
// identity flows use ActorSystem and, after a verified mapping, an
// on-behalf-of principal.
func NewOIDCServiceAccess(organizationID, requestID string) (AccessContext, error) {
	access := AccessContext{
		OrganizationID: organizationID,
		PrincipalID:    oidcServicePrincipal,
		RequestID:      requestID,
	}
	if err := access.Validate(); err != nil {
		return AccessContext{}, err
	}
	return access, nil
}

const servicePrincipalPreAuthPrincipal = "svc_access_code"

// NewServicePrincipalPreAuthAccess creates the second, independently-scoped
// pre-authentication database context (ADR-0079 §3, V1-C): it is used only by
// internal/serviceprincipal to resolve a raw agent access code's digest
// before the SERVICE principal it names is known, exactly mirroring
// NewOIDCServiceAccess's own contract with its own distinct fixed marker
// principal (never the same identifier, so the two pre-auth contexts can
// never be confused with one another). This marker is likewise never written
// as the actor of an audit event; a successful resolution always continues
// with the actual resolved SERVICE principal's own AccessContext.
func NewServicePrincipalPreAuthAccess(organizationID, requestID string) (AccessContext, error) {
	access := AccessContext{
		OrganizationID: organizationID,
		PrincipalID:    servicePrincipalPreAuthPrincipal,
		RequestID:      requestID,
	}
	if err := access.Validate(); err != nil {
		return AccessContext{}, err
	}
	return access, nil
}

// Validate rejects empty, control-character, whitespace-padded and oversized
// identifiers before a connection can be given a tenant context.
func (access AccessContext) Validate() error {
	for _, value := range []string{access.OrganizationID, access.PrincipalID, access.RequestID} {
		if !safeIdentifier(value) {
			return &Error{code: CodeContextInvalid}
		}
	}
	if access.ActorKind != "" && access.ActorKind != ActorKindHuman && access.ActorKind != ActorKindService {
		return &Error{code: CodeContextInvalid}
	}
	return nil
}

// EffectiveActorKind normalizes the empty (unset) ActorKind of every
// pre-existing access path to ActorKindHuman.
func (access AccessContext) EffectiveActorKind() ActorKind {
	if access.ActorKind == ActorKindService {
		return ActorKindService
	}
	return ActorKindHuman
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, runeValue := range value {
		if (runeValue >= 'a' && runeValue <= 'z') ||
			(runeValue >= 'A' && runeValue <= 'Z') ||
			(runeValue >= '0' && runeValue <= '9') ||
			strings.ContainsRune("_-.:", runeValue) {
			continue
		}
		return false
	}
	return true
}

// Config deliberately has no generic runtime parameters or raw connection
// hooks. Those would allow callers to dilute transaction or role guarantees.
type Config struct {
	URL             string
	ApplicationRole string
	MaxConnections  int32
	MinConnections  int32
}

// DefaultConfig is a bounded profile; the actual database URL remains an
// external secret and is never logged.
func DefaultConfig() Config {
	return Config{ApplicationRole: defaultApplicationRole, MaxConnections: 8, MinConnections: 0}
}

func (config Config) validate() error {
	if strings.TrimSpace(config.URL) == "" || !safeIdentifier(config.ApplicationRole) ||
		config.MaxConnections < 1 || config.MaxConnections > 64 || config.MinConnections < 0 || config.MinConnections > config.MaxConnections {
		return &Error{code: CodeConfigInvalid}
	}
	return nil
}

// Store keeps the raw pool private. Transport handlers cannot get a pool or
// start an unscoped transaction from this package.
type Store struct {
	pool *pgxpool.Pool
}

// Open establishes only a non-owner, non-bypass runtime pool. Migration roles
// must use the dedicated migration workflow and cannot reuse this constructor.
func Open(ctx context.Context, config Config) (*Store, error) {
	if ctx == nil {
		return nil, &Error{code: CodeConfigInvalid}
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	poolConfig, err := pgxpool.ParseConfig(config.URL)
	if err != nil {
		return nil, &Error{code: CodeConfigInvalid, cause: err}
	}
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "knowvault-runtime"
	poolConfig.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
		return verifyRuntimeRole(connectContext, connection, config.ApplicationRole)
	}
	return openPool(ctx, poolConfig)
}

func openPool(ctx context.Context, poolConfig *pgxpool.Config) (*Store, error) {
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, &Error{code: CodeConnectionFailed, cause: err}
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, &Error{code: CodeConnectionFailed, cause: err}
	}
	return &Store{pool: pool}, nil
}

func verifyRuntimeRole(ctx context.Context, connection *pgx.Conn, expectedRole string) error {
	var currentRole, sessionRole string
	var privileged bool
	err := connection.QueryRow(ctx, `
		SELECT current_user::text,
		       session_user::text,
		       (current_role_record.rolsuper OR current_role_record.rolbypassrls OR session_role_record.rolsuper OR session_role_record.rolbypassrls)
		FROM pg_roles AS current_role_record
		JOIN pg_roles AS session_role_record ON session_role_record.rolname = session_user
		WHERE current_role_record.rolname = current_user
	`).Scan(&currentRole, &sessionRole, &privileged)
	if err != nil || currentRole != expectedRole || sessionRole != expectedRole || privileged {
		return &Error{code: CodeRuntimeRoleRejected, cause: err}
	}
	return nil
}

// Close retires the application pool. It is safe to call after a failed
// startup only when a Store was returned by Open.
func (store *Store) Close() {
	if store != nil && store.pool != nil {
		store.pool.Close()
	}
}

// Transaction is intentionally a value with no exported handle to pgx.Tx.
// Repository code may execute only inside the caller's already-authorized
// transaction and cannot obtain a connection pool from it.
type Transaction struct {
	tx pgx.Tx
}

// Valid reports whether Transaction came from Store.Read or Store.Write. It
// exposes no driver handle and exists so domain persistence adapters can fail
// closed instead of invoking a zero-value transaction.
func (transaction Transaction) Valid() bool {
	return transaction.tx != nil
}

func (transaction Transaction) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	return transaction.tx.Exec(ctx, sql, arguments...)
}

func (transaction Transaction) Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error) {
	return transaction.tx.Query(ctx, sql, arguments...)
}

func (transaction Transaction) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	return transaction.tx.QueryRow(ctx, sql, arguments...)
}

// Read starts a read-only transaction whose organization/principal/request
// settings are local to that transaction and therefore cannot leak through a
// reused pool connection.
func (store *Store) Read(ctx context.Context, access AccessContext, work func(context.Context, Transaction) error) error {
	return store.withTransaction(ctx, access, pgx.ReadOnly, work)
}

// Write is the only write transaction entry point. The Stage 1 database role
// still has no DELETE privilege, so lifecycle removal must be explicit later.
func (store *Store) Write(ctx context.Context, access AccessContext, work func(context.Context, Transaction) error) error {
	return store.withTransaction(ctx, access, pgx.ReadWrite, work)
}

func (store *Store) withTransaction(ctx context.Context, access AccessContext, accessMode pgx.TxAccessMode, work func(context.Context, Transaction) error) error {
	if ctx == nil || store == nil || store.pool == nil || work == nil {
		return &Error{code: CodeTransactionFailed}
	}
	if err := access.Validate(); err != nil {
		return err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: accessMode})
	if err != nil {
		return &Error{code: CodeTransactionFailed, cause: err}
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		SELECT set_config('app.organization_id', $1, true),
		       set_config('app.principal_id', $2, true),
		       set_config('app.request_id', $3, true)
	`, access.OrganizationID, access.PrincipalID, access.RequestID); err != nil {
		return &Error{code: CodeTransactionFailed, cause: err}
	}
	if err := work(ctx, Transaction{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return &Error{code: CodeTransactionFailed, cause: err}
	}
	return nil
}

// Explain is intentionally restricted to code and stable metadata. It never
// includes a DSN, database error or raw SQL.
func Explain(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprint(CodeOf(err))
}
