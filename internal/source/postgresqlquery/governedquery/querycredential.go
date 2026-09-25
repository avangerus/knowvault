package governedquery

// querycredential.go is S3 card 2b's pre-acceptance check for a source's
// candidate SQL query credential (ADR-0097). It is the only code that opens a
// connection with a credential that is not yet configured for a source, and it
// deliberately executes no caller-supplied SQL: it proves three facts and
// returns, disclosing nothing about the customer database.
//
//   - the candidate DSN opens a read-only session (so the role is a reader,
//     not the ingestion writer);
//   - the session reaches the exact database identity the source was
//     registered against, recomputed from this connection's own
//     (database oid, database name) pair; and
//   - the role cannot SELECT any column that the registered tables exclude
//     (has_column_privilege), so the administrator's column-narrowing cannot be
//     bypassed by the query credential.
//
// Every refusal is one of the closed codes added to this package for the card;
// none carries a DSN, a relation name, a column name or a driver message.

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// QueryCredentialParams is the closed, server-owned scope a candidate query
// credential is checked against: the source's registered relations and the
// exact projected columns of each. It is never built from a request.
type QueryCredentialParams struct {
	Relations []ScopedRelation
}

// VerifyQueryCredential proves the candidate credential in config.DSN against
// the source scope in params. A nil error means every check passed; every
// failure is a closed Error whose code the caller maps onto its own refusal
// vocabulary.
func VerifyQueryCredential(ctx context.Context, config Config, params QueryCredentialParams) error {
	if ctx == nil || ctx.Err() != nil || len(params.Relations) == 0 {
		return &Error{code: CodeInvalid}
	}
	if err := (ScopedSchema{Relations: params.Relations}).Validate(); err != nil {
		return &Error{code: CodeInvalid}
	}
	connection, err := dial(ctx, config)
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	defer connection.Close(ctx)
	transaction, err := connection.BeginTx(ctx, connectReadOnlyTxOptions())
	if err != nil {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	var readOnly string
	if err := transaction.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		return &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	identity, err := queryCredentialDatabaseIdentity(ctx, transaction)
	if err != nil {
		return err
	}
	if identity != config.DatabaseIdentity {
		return &Error{code: CodeQueryCredentialDatabaseMismatch}
	}
	// Card S3.2c: the candidate is accepted only when it passes the full
	// least-privilege proof, not merely the column check. Every rule failure is
	// a distinct closed code that names the rule.
	return VerifyQueryRole(ctx, transaction, params.Relations)
}

// queryCredentialDatabaseIdentity recomputes the source's immutable "pgdb:…"
// identity from this connection's own database oid and name plus the server it
// actually reached: the host and port carried in the connection's own parsed
// configuration, which is the exact registered/DSN authority the TLS policy
// validated. Card S3.2d binds the host and port into the identity, so a DSN
// that reaches another server with the same database name and oid is a
// different identity and is refused as a mismatch. It is the exact derivation
// registration applies, so a credential pointing at another database on the
// same server is refused too.
func queryCredentialDatabaseIdentity(ctx context.Context, transaction pgx.Tx) (string, error) {
	if transaction == nil || transaction.Conn() == nil || transaction.Conn().Config() == nil {
		return "", &Error{code: CodeQueryCredentialRejected}
	}
	host := transaction.Conn().Config().Host
	port := transaction.Conn().Config().Port
	if host == "" || port < 1 {
		return "", &Error{code: CodeQueryCredentialRejected}
	}
	var oid uint32
	var name string
	if err := transaction.QueryRow(ctx, `
		SELECT database.oid, database.datname
		FROM pg_catalog.pg_database AS database
		WHERE database.datname = current_database()`).Scan(&oid, &name); err != nil {
		return "", &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	if oid < 1 || name == "" || len(name) > 128 || !utf8.ValidString(name) {
		return "", &Error{code: CodeQueryCredentialRejected}
	}
	raw, err := canon.CanonicalJSON(struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
		OID  uint32 `json:"oid"`
		Name string `json:"name"`
	}{Host: host, Port: port, OID: oid, Name: name})
	if err != nil || len(raw) == 0 {
		return "", &Error{code: CodeQueryCredentialRejected, cause: err}
	}
	return "pgdb:" + strings.TrimPrefix(canon.Hash(raw), "sha256:"), nil
}
