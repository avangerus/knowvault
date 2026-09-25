// Package governedquery is the single owner of ADR-0089's governed SQL
// execution path, including model-authored asks and reviewed presets. It is the
// only code in the repository
// that may hold the dedicated, least-privilege database role's connection
// capability and pass SQL text to that connection. No other
// package may construct or forward that text to a database call.
//
// The security boundary this package enforces is the external PostgreSQL
// server's own grants, a read-only transaction, a statement timeout and
// row/byte caps -- never a SQL parser. A lightweight static pre-check exists
// only as a cheap first-pass rejection to save a round trip; passing it is
// never treated as proof of safety (ADR-0089 §3).
//
// This package is deliberately independent of internal/source/postgresqlquery
// (the ADR-0078 scheduled-projection connector): it defines its own
// CredentialResolver/TrustRoots capability types and its own DSN validation so
// the two dedicated database roles stay on two distinct, non-interchangeable
// code paths, exactly as ADR-0089 §3 requires.
package governedquery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type ErrorCode string

const (
	CodeInvalid           ErrorCode = "GOVERNED_QUERY_REQUEST_INVALID"
	CodeMountUnavailable  ErrorCode = "GOVERNED_QUERY_MOUNT_UNAVAILABLE"
	CodeMountInvalid      ErrorCode = "GOVERNED_QUERY_MOUNT_INVALID"
	CodeSchemaUnavailable ErrorCode = "GOVERNED_QUERY_SCHEMA_UNAVAILABLE"
	CodeExternalFailure   ErrorCode = "GOVERNED_QUERY_EXTERNAL_FAILURE"
	// S3 card 2b's closed query-credential check vocabulary. The first two are
	// the distinct refusals the card names (wrong database identity, and a role
	// that can read an excluded column); the third covers a connection that is
	// not read-only or cannot be reached at all.
	CodeQueryCredentialDatabaseMismatch ErrorCode = "SOURCE_QUERY_CREDENTIAL_DATABASE_MISMATCH"
	CodeQueryCredentialColumnPrivilege  ErrorCode = "SOURCE_QUERY_CREDENTIAL_COLUMN_PRIVILEGE"
	CodeQueryCredentialRejected         ErrorCode = "SOURCE_QUERY_CREDENTIAL_DATABASE_REJECTED"
	// S3 card 2c's server-owned load-limit refusals. Both are decided before
	// any external connection is opened, so an over-limit call never reaches
	// the customer database.
	CodeSourceSQLConcurrencyLimited ErrorCode = "SOURCE_SQL_CONCURRENCY_LIMITED"
	CodeSourceSQLRateLimited        ErrorCode = "SOURCE_SQL_RATE_LIMITED"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var governedError *Error
	if errors.As(err, &governedError) {
		return governedError.code
	}
	return CodeExternalFailure
}

// Outcome is the closed, content-free attempt vocabulary ADR-0089 §4 and §6
// require. It is safe to persist verbatim in an audit event.
type Outcome string

const (
	OutcomeSucceeded         Outcome = "SUCCEEDED"
	OutcomeRejectedStatic    Outcome = "REJECTED_STATIC"
	OutcomeRejectedDatabase  Outcome = "REJECTED_DATABASE"
	OutcomeTimeout           Outcome = "TIMEOUT"
	OutcomeRowLimitExceeded  Outcome = "ROW_LIMIT_EXCEEDED"
	OutcomeCostLimitExceeded Outcome = "COST_LIMIT_EXCEEDED"
)

// Limits are server-derived, operator-configured bounds. They are never
// supplied by a question or model.
type Limits struct {
	StatementTimeout time.Duration
	MaxRows          int
	MaxResultBytes   int
	MaxCostEstimate  float64
}

func (l Limits) valid() bool {
	return l.StatementTimeout >= time.Second && l.StatementTimeout <= 5*time.Minute &&
		l.MaxRows > 0 && l.MaxRows <= 100_000 &&
		l.MaxResultBytes > 0 && l.MaxResultBytes <= 64<<20 &&
		l.MaxCostEstimate > 0 && l.MaxCostEstimate <= 1_000_000_000
}

// Config is the administrator-mounted capability to reach the dedicated
// governed-execution role. It is never constructed from a question, a model
// response or a workspace/API request.
type Config struct {
	ConnectionID     string
	DatabaseIdentity string
	WorkspaceID      string
	// DSN is the exact postgres://user:pass@host:port/db?sslmode=verify-full
	// connection string for the dedicated governed-execution role. It is
	// never logged, never echoed to a caller and never the ADR-0078
	// ingestion role's DSN.
	DSN        string
	TrustRoots *x509.CertPool
	Limits     Limits
	// Presets are immutable administrator-mounted references to already
	// executed, reviewed attempts. They never contain SQL text.
	Presets []Preset
	// PresetOnly is the mounted closed-mode decision (PRESET_ONLY
	// compatibility). Its zero value (false) is the legacy/ad hoc default: a
	// mount with no presets_file, or a mount that declares ADHOC, leaves it
	// false and the model-composed ad hoc ask stays advertised and
	// dispatchable. It is true only for a manifest that carries a presets_file
	// AND declares mode=PRESET_ONLY, where the ad hoc ask must neither be
	// advertised nor dispatched. The polarity is chosen for the safe zero
	// value: a Config built directly in Go (never through the mount) can only
	// ever mean "ad hoc allowed", so a forgotten field can never silently
	// close a capability. It is set from the mount manifest, never from a
	// request.
	PresetOnly bool
	// Card S3.2d deliberately has no cached-proof field here. The
	// least-privilege proof is re-run inside the same read-only transaction as
	// the statement on every execution, so no stored verdict can authorize a
	// statement: a proof recorded for an earlier role, credential revision or
	// projection can never stand in for the role that is connected now.
}

func (config Config) Validate() error {
	if !validOpaque(config.ConnectionID) || !validOpaque(config.DatabaseIdentity) || !validOpaque(config.WorkspaceID) ||
		config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 || !config.Limits.valid() {
		return &Error{code: CodeInvalid}
	}
	if err := validateDSN([]byte(config.DSN)); err != nil {
		return &Error{code: CodeInvalid, cause: err}
	}
	if err := validatePresets(config.Presets); err != nil {
		return &Error{code: CodeInvalid, cause: err}
	}
	return nil
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 200 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

// validateDSN applies the same strict shape internal/source/postgresqlquery
// pins for its own external connection, duplicated deliberately (not
// imported) so the two dedicated roles never share a validator, connector
// instance or code path.
func validateDSN(raw []byte) error {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) || strings.ContainsAny(string(raw), "\x00\r\n") {
		return errors.New("invalid governed query database URL")
	}
	parsed, err := url.Parse(string(raw))
	if err != nil || parsed.Scheme != "postgres" || parsed.Host == "" || parsed.User == nil || parsed.Opaque != "" ||
		parsed.RawPath != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawQuery != "sslmode=verify-full" ||
		parsed.String() != string(raw) || parsed.Path == "" || parsed.Path == "/" || strings.Count(parsed.Path, "/") != 1 {
		return errors.New("governed query database URL policy rejected")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	portNumber, portErr := strconv.Atoi(port)
	password, hasPassword := parsed.User.Password()
	if err != nil || !validDNSHost(host) || portErr != nil || portNumber < 1 || portNumber > 65535 ||
		parsed.User.Username() == "" || !hasPassword || password == "" {
		return errors.New("governed query database URL target rejected")
	}
	return nil
}

func validDNSHost(host string) bool {
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

// dial opens one physical connection to the dedicated governed-execution
// role. It is the only function in the repository that turns a Config into a
// live external PostgreSQL connection for governed SQL.
func dial(ctx context.Context, config Config) (*pgx.Conn, error) {
	if ctx == nil || config.Validate() != nil {
		return nil, &Error{code: CodeInvalid}
	}
	pgxConfig, err := pgx.ParseConfig(config.DSN)
	if err != nil || pgxConfig == nil || pgxConfig.TLSConfig == nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	parsed, parseErr := url.Parse(config.DSN)
	expectedHost, _, splitErr := net.SplitHostPort(parsed.Host)
	if parseErr != nil || splitErr != nil || !validDNSHost(expectedHost) || pgxConfig.TLSConfig.ServerName != expectedHost {
		// pgx may leave the server name unset or derive it from a value we did
		// not validate; pin it explicitly rather than trust the driver default.
		if parseErr == nil && splitErr == nil && validDNSHost(expectedHost) {
			pgxConfig.TLSConfig.ServerName = expectedHost
		} else {
			return nil, &Error{code: CodeExternalFailure}
		}
	}
	pgxConfig.TLSConfig.RootCAs = config.TrustRoots
	pgxConfig.TLSConfig.InsecureSkipVerify = false
	if pgxConfig.TLSConfig.MinVersion < tls.VersionTLS12 {
		pgxConfig.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if pgxConfig.RuntimeParams == nil {
		pgxConfig.RuntimeParams = map[string]string{}
	}
	for key := range pgxConfig.RuntimeParams {
		delete(pgxConfig.RuntimeParams, key)
	}
	pgxConfig.RuntimeParams["application_name"] = "knowvault-governed-query"
	connection, err := pgx.ConnectConfig(ctx, pgxConfig)
	if err != nil {
		return nil, &Error{code: CodeExternalFailure, cause: err}
	}
	return connection, nil
}

// connectReadOnlyTxOptions is the one fixed read-only transaction shape this
// package ever opens against the dedicated governed-execution role.
func connectReadOnlyTxOptions() pgx.TxOptions {
	return pgx.TxOptions{AccessMode: pgx.ReadOnly}
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}
