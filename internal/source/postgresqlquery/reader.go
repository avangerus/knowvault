package postgresqlquery

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Limits are enforced by the connector before a row is retained. They are
// server-derived scope limits, never values supplied by a question or model.
type Limits struct {
	MaxRows            int
	MaxColumns         int
	MaxFieldBytes      int
	MaxRowBytes        int
	MaxTotalBytes      int
	StatementTimeout   time.Duration
	TransactionTimeout time.Duration
}

func (l Limits) valid() bool {
	return l.MaxRows > 0 && l.MaxRows <= 10_000_000 &&
		l.MaxColumns > 0 && l.MaxColumns <= 256 &&
		l.MaxFieldBytes > 0 && l.MaxFieldBytes <= 64<<20 &&
		l.MaxRowBytes >= l.MaxFieldBytes && l.MaxRowBytes <= 64<<20 &&
		l.MaxTotalBytes >= l.MaxRowBytes && l.MaxTotalBytes <= 1<<40 &&
		l.StatementTimeout >= time.Second && l.StatementTimeout <= 24*time.Hour &&
		l.TransactionTimeout >= l.StatementTimeout && l.TransactionTimeout <= 24*time.Hour
}

// Validate exposes the server-owned limit contract to adapters that cross the
// source-agnostic observation boundary. Invalid limits must fail during
// composition, before a connector can read or retain any external row.
func (l Limits) Validate() error {
	if !l.valid() {
		return &Error{code: CodeInvalidProjection}
	}
	return nil
}

func DefaultLimits() Limits {
	return Limits{
		MaxRows: 1_000_000, MaxColumns: 256, MaxFieldBytes: 16 << 20,
		MaxRowBytes: 32 << 20, MaxTotalBytes: 4 << 30,
		StatementTimeout: 2 * time.Minute, TransactionTimeout: 5 * time.Minute,
	}
}

// Snapshot is a complete, bounded external read-only result. Rows are kept in
// memory only as typed canonical descriptors; no raw driver row is retained.
type Snapshot struct {
	Rows             []Row
	RowCount         int
	DecodedBytes     int
	CoverageComplete bool
	SnapshotHash     string
}

// ReadProjection executes exactly the generated parameterless projection
// SELECT inside one SERIALIZABLE READ ONLY DEFERRABLE transaction. It streams
// rows and refuses cap+1 before publication can consume the result. The caller
// is responsible for the separate attestation/privilege/fingerprint checks
// mandated by ADR-0078; this function never treats a connection as trusted.
func ReadProjection(ctx context.Context, connection *pgx.Conn, projection Projection, limits Limits) (Snapshot, error) {
	if ctx == nil || connection == nil {
		return Snapshot{}, &Error{code: CodeExternalFailure}
	}
	if err := projection.Validate(); err != nil {
		return Snapshot{}, err
	}
	if err := limits.Validate(); err != nil {
		return Snapshot{}, err
	}
	statement, err := projection.SelectSQL()
	if err != nil {
		return Snapshot{}, err
	}
	return readBoundedProjection(ctx, connection, statement, nil, projection.Columns, limits)
}

// readBoundedProjection owns the one bounded read transaction shared by every
// projection read: the SERIALIZABLE READ ONLY DEFERRABLE transaction, the
// connector-fixed session settings and timeouts, the JSON text-format result
// selection, the streaming bounded-value loop, CanonicalizeRow, SnapshotSetHash
// and the commit/error semantics. The statement is always server-generated and
// args carry only canonicalized scalar values; columns are the ordered 1..N
// projection columns that statement selects. A cap+1 row or any failure returns
// the zero Snapshot with an existing content-free code and never partial data.
func readBoundedProjection(ctx context.Context, connection *pgx.Conn, statement string, args []any, columns []Column, limits Limits) (Snapshot, error) {
	tx, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly, DeferrableMode: pgx.Deferrable,
	})
	if err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, setting := range []string{
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL row_security = on",
		"SET LOCAL max_parallel_workers_per_gather = 0",
		"SET LOCAL jit = off",
		// These limits are fixed by the connector profile, never inherited
		// from a caller-provided DSN.  Keeping them transaction-local also
		// prevents a pooled external session from carrying a relaxed value to
		// a later snapshot.
		"SET LOCAL work_mem = '16MB'",
	} {
		if _, err := tx.Exec(ctx, setting); err != nil {
			return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
		}
	}
	if err := enforceTempFileLimit(ctx, tx); err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('statement_timeout', $1, true)", strconv.FormatInt(limits.StatementTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('idle_in_transaction_session_timeout', $1, true)", strconv.FormatInt(limits.TransactionTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", strconv.FormatInt(limits.StatementTimeout.Milliseconds(), 10)+"ms"); err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	if err := setTransactionTimeoutIfSupported(ctx, tx, limits.TransactionTimeout); err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	var readOnly string
	if err := tx.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	// Ask PostgreSQL for JSON/JSONB in text format and retain the raw bytes for
	// canonicalization. pgx's decoded `any` path turns JSON numbers into
	// float64/map values, which can lose precision before Evidence is hashed;
	// the raw text path preserves exact canonical JSON business-object leaves.
	// pgx only recognizes a QueryResultFormats option at the head of the
	// argument list, so the option precedes the canonicalized scalar args.
	queryArgs := make([]any, 0, len(args)+1)
	queryArgs = append(queryArgs, pgx.QueryResultFormatsByOID{
		pgtype.JSONOID: pgx.TextFormatCode, pgtype.JSONBOID: pgx.TextFormatCode,
	})
	queryArgs = append(queryArgs, args...)
	rows, err := tx.Query(ctx, statement, queryArgs...)
	if err != nil {
		return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rows.Close()
	if len(rows.FieldDescriptions()) != len(columns) || len(columns) > limits.MaxColumns {
		return Snapshot{}, &Error{code: CodeInvalidProjection}
	}
	var result Snapshot
	for rows.Next() {
		if result.RowCount >= limits.MaxRows {
			return Snapshot{}, &Error{code: CodeLimitExceeded}
		}
		raw, err := rows.Values()
		if err != nil {
			return Snapshot{}, &Error{code: CodeExternalFailure, cause: err}
		}
		rawValues := rows.RawValues()
		if len(rawValues) != len(raw) {
			return Snapshot{}, &Error{code: CodeInvalidProjection}
		}
		for index, column := range columns {
			if column.LogicalType == TypeJSON || column.LogicalType == TypeJSONB {
				raw[index] = append([]byte(nil), rawValues[index]...)
			}
		}
		if len(raw) != len(columns) {
			return Snapshot{}, &Error{code: CodeInvalidProjection}
		}
		rowBytes := 0
		for _, value := range raw {
			fieldBytes, ok := boundedValueSize(value, limits.MaxFieldBytes)
			if !ok || rowBytes > limits.MaxRowBytes-fieldBytes || result.DecodedBytes > limits.MaxTotalBytes-fieldBytes {
				return Snapshot{}, &Error{code: CodeLimitExceeded}
			}
			rowBytes += fieldBytes
		}
		row, err := CanonicalizeRow(columns, raw)
		if err != nil {
			return Snapshot{}, err
		}
		if len(row.Canonical) > limits.MaxRowBytes || result.DecodedBytes > limits.MaxTotalBytes-len(row.Canonical) {
			return Snapshot{}, &Error{code: CodeLimitExceeded}
		}
		result.Rows = append(result.Rows, row)
		result.RowCount++
		result.DecodedBytes += len(row.Canonical)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, &Error{code: CodeIncomplete, cause: err}
	}
	if err := tx.Commit(ctx); err != nil {
		return Snapshot{}, &Error{code: CodeIncomplete, cause: err}
	}
	hash, err := SnapshotSetHash(result.Rows)
	if err != nil {
		return Snapshot{}, err
	}
	result.CoverageComplete = true
	result.SnapshotHash = hash
	return result, nil
}

const maxTempFileLimitKB int64 = 256 * 1024

// enforceTempFileLimit pins the connector's spill bound when the external
// login may SET the GUC and otherwise verifies the administrator-pinned role
// default. The savepoint contains a denied SET without aborting the read-only
// transaction, so a NOSUPERUSER query role remains usable while an unlimited
// (-1) or oversized default fails closed.
func enforceTempFileLimit(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return &Error{code: CodeExternalFailure}
	}
	if _, err := tx.Exec(ctx, "SAVEPOINT knowvault_temp_file_limit"); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL temp_file_limit = '256MB'"); err != nil {
		if _, rollbackErr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT knowvault_temp_file_limit"); rollbackErr != nil {
			return rollbackErr
		}
	} else if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT knowvault_temp_file_limit"); err != nil {
		return err
	}
	var raw string
	if err := tx.QueryRow(ctx, "SHOW temp_file_limit").Scan(&raw); err != nil {
		return err
	}
	value, ok := tempFileLimitKB(raw)
	if !ok || value < 0 || value > maxTempFileLimitKB {
		return &Error{code: CodeExternalFailure}
	}
	return nil
}

// tempFileLimitKB parses PostgreSQL's human-readable SHOW value (for example
// "256MB" or "64MB") into kibibytes. It intentionally accepts only integral
// units emitted by pg_settings and rejects the unlimited sentinel and any
// fractional/unknown representation.
func tempFileLimitKB(raw string) (int64, bool) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	if value == "" || value == "-1" {
		return 0, false
	}
	multiplier := int64(1)
	for suffix, factor := range map[string]int64{"KB": 1, "MB": 1024, "GB": 1024 * 1024} {
		if strings.HasSuffix(value, suffix) {
			value = strings.TrimSpace(strings.TrimSuffix(value, suffix))
			multiplier = factor
			break
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 || (parsed > 0 && parsed > int64(^uint64(0)>>1)/multiplier) {
		return 0, false
	}
	return parsed * multiplier, true
}

func boundedValueSize(value any, limit int) (int, bool) {
	switch item := value.(type) {
	case nil:
		return 0, true
	case string:
		return len(item), len(item) <= limit
	case []byte:
		return len(item), len(item) <= limit
	case bool:
		return 5, true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return 24, true
	case time.Time:
		return 64, true
	case [16]byte, pgtype.UUID:
		return 16, true
	case pgtype.Numeric:
		if !item.Valid || item.NaN || item.InfinityModifier != 0 || item.Int == nil {
			return 0, false
		}
		// pgx keeps NUMERIC's coefficient in a big.Int.  Account for the
		// decimal representation rather than charging every value a tiny
		// constant; otherwise a hostile high-precision value could pass the
		// field cap and only fail after a large canonical allocation.
		digits := len(item.Int.Text(10))
		if item.Exp < 0 {
			digits += int(-item.Exp) + 1
		} else {
			digits += int(item.Exp)
		}
		if digits < 1 || digits > limit {
			return digits, false
		}
		return digits, true
	default:
		return 0, false
	}
}

// transactionTimeoutMinimumServerVersion is the first PostgreSQL release with
// the transaction_timeout setting. Older servers reject the parameter name;
// statement_timeout and idle_in_transaction_session_timeout still bound them.
const transactionTimeoutMinimumServerVersion = 170000

// setTransactionTimeoutIfSupported applies transaction_timeout only on servers
// that know the parameter, so PostgreSQL 13-16 sources remain readable.
func setTransactionTimeoutIfSupported(ctx context.Context, tx pgx.Tx, timeout time.Duration) error {
	var version int
	if err := tx.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); err != nil {
		return err
	}
	if version < transactionTimeoutMinimumServerVersion {
		return nil
	}
	_, err := tx.Exec(ctx, "SELECT set_config('transaction_timeout', $1, true)", strconv.FormatInt(timeout.Milliseconds(), 10)+"ms")
	return err
}
