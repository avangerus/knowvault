package governedquery

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	maxSQLTextBytes = 8192
	maxColumnCount  = 64
)

// ExecuteParams is the untrusted candidate SQL text bound to one exposed
// schema revision. SQLText is model output, never caller-supplied.
type ExecuteParams struct {
	SQLText               string
	ExposedSchemaRevision int64
}

// QueryResult is what the user is shown alongside the model's answer
// (ADR-0089 §4: "the exact SQL executed and its result are shown to the
// user"). It is never persisted to audit/logs -- only its content-free
// digest is (see Attempt.ResultDigest).
type QueryResult struct {
	Columns              []string
	Rows                 [][]*string
	RowCount             int
	CostEstimate         float64
	Elapsed              time.Duration
	ExecutionStartedAt   time.Time
	ExecutionCompletedAt time.Time
}

// Attempt is the content-free record ADR-0089 §4 requires: exposed-schema
// revision, exact SQL hash (never the text), cost estimate, row count,
// content-free result digest, elapsed time and typed outcome.
type Attempt struct {
	ExposedSchemaRevision int64
	SQLHash               string
	CostEstimate          float64
	RowCount              int
	ResultDigest          string
	Elapsed               time.Duration
	Outcome               Outcome
	// RoleVerificationDigest is S3 card 2c's content-free evidence that the
	// query role passed the least-privilege proof for the registered
	// projection during this attempt. Card S3.2d recomputes it on every
	// execution inside the statement's own read-only transaction; it is
	// recorded as evidence for the store's proof row and never authorizes a
	// later statement.
	RoleVerificationDigest string
}

// Execute is the single production entry point. It never treats the static
// pre-check as a security boundary: the read-only role, transaction and
// bounds below are what refuse an unsafe statement.
func Execute(ctx context.Context, config Config, params ExecuteParams) (QueryResult, Attempt, error) {
	return execute(ctx, config, params, false)
}

func execute(ctx context.Context, config Config, params ExecuteParams, skipStaticCheckForTest bool) (QueryResult, Attempt, error) {
	attempt := Attempt{ExposedSchemaRevision: params.ExposedSchemaRevision}
	if ctx == nil || config.Validate() != nil || len(params.SQLText) == 0 || len(params.SQLText) > maxSQLTextBytes ||
		params.ExposedSchemaRevision < 1 {
		return QueryResult{}, attempt, &Error{code: CodeInvalid}
	}
	attempt.SQLHash = sha256Hex(params.SQLText)

	if !skipStaticCheckForTest {
		if err := staticPrecheck(params.SQLText); err != nil {
			attempt.Outcome = OutcomeRejectedStatic
			return QueryResult{}, attempt, err
		}
	}

	started := time.Now()
	connection, err := dial(ctx, config)
	if err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, err
	}
	defer connection.Close(ctx)

	dialCtx, cancel := context.WithTimeout(ctx, config.Limits.StatementTimeout+5*time.Second)
	defer cancel()

	tx, err := connection.BeginTx(dialCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: err}
	}
	defer func() { _ = tx.Rollback(dialCtx) }()

	timeoutMS := strconv.FormatInt(config.Limits.StatementTimeout.Milliseconds(), 10) + "ms"
	for _, statement := range []string{
		"SET LOCAL search_path = pg_catalog",
		"SET LOCAL max_parallel_workers_per_gather = 0",
		"SET LOCAL jit = off",
	} {
		if _, err := tx.Exec(dialCtx, statement); err != nil {
			attempt.Outcome = OutcomeRejectedDatabase
			return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: err}
		}
	}
	if _, err := tx.Exec(dialCtx, "SELECT set_config('statement_timeout', $1, true)", timeoutMS); err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: err}
	}
	if _, err := tx.Exec(dialCtx, "SELECT set_config('idle_in_transaction_session_timeout', $1, true)", timeoutMS); err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: err}
	}
	var readOnly string
	if err := tx.QueryRow(dialCtx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: err}
	}

	cost, explainErr := explainCost(dialCtx, tx, params.SQLText)
	if explainErr != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, explainErr
	}
	attempt.CostEstimate = cost
	if cost > config.Limits.MaxCostEstimate {
		attempt.Outcome = OutcomeCostLimitExceeded
		return QueryResult{}, attempt, &Error{code: CodeInvalid}
	}

	result, rowsErr := runQuery(dialCtx, tx, params.SQLText, config.Limits)
	elapsed := time.Since(started)
	attempt.Elapsed = elapsed
	if rowsErr != nil {
		if errors.Is(rowsErr, context.DeadlineExceeded) || isTimeoutError(rowsErr) {
			attempt.Outcome = OutcomeTimeout
			return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: rowsErr}
		}
		if CodeOf(rowsErr) == CodeInvalid {
			attempt.Outcome = OutcomeRowLimitExceeded
			return QueryResult{}, attempt, rowsErr
		}
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeExternalFailure, cause: rowsErr}
	}
	result.CostEstimate = cost
	result.Elapsed = elapsed
	attempt.RowCount = result.RowCount
	attempt.ResultDigest = resultDigest(result)
	attempt.Outcome = OutcomeSucceeded
	return result, attempt, nil
}

func isTimeoutError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "statement timeout") || strings.Contains(message, "canceling statement") ||
		strings.Contains(message, "context deadline exceeded")
}

// staticPrecheck is a cheap, non-authoritative first pass: exactly one
// statement, no forbidden keyword as a whole word, no comment that could
// hide a second statement in a naive scanner. Passing it proves nothing;
// PostgreSQL's own grants are what refuse an unsafe statement (ADR-0089 §3).
func staticPrecheck(sqlText string) error {
	trimmed := strings.TrimSpace(sqlText)
	if trimmed == "" {
		return &Error{code: CodeInvalid}
	}
	if strings.Contains(trimmed, "--") || strings.Contains(trimmed, "/*") || strings.Contains(trimmed, "\x00") {
		return &Error{code: CodeInvalid}
	}
	body := trimmed
	if strings.HasSuffix(body, ";") {
		body = strings.TrimSpace(body[:len(body)-1])
	}
	if strings.Contains(body, ";") {
		return &Error{code: CodeInvalid}
	}
	lower := strings.ToLower(body)
	if !strings.HasPrefix(lower, "select") && !strings.HasPrefix(lower, "with") {
		return &Error{code: CodeInvalid}
	}
	for _, forbidden := range []string{
		"insert", "update", "delete", "drop", "alter", "create", "grant", "revoke",
		"truncate", "copy", "call", "do ", "vacuum", "merge", "execute", "prepare",
		"listen", "notify", "begin", "commit", "rollback", "savepoint",
		"lock ",
	} {
		if containsWord(lower, strings.TrimSpace(forbidden)) {
			return &Error{code: CodeInvalid}
		}
	}
	// `set` and `reset` are deliberately absent from the word list: both are
	// ordinary identifiers (a column or alias named set/reset is valid SQL) and
	// a setting change is refused by the statement shape above plus the gate's
	// set_config call rule below, never by a bare spelling.
	// Card S3.2d: a deterministic, spelling-aware gate refuses a setting change
	// and the cross-session, file, large-object and query-executing function
	// families before EXPLAIN. The keyword scan above is only a first pass; this
	// one case-folds and unquotes every identifier and also strips a schema
	// qualifier, so `pg_catalog.set_config`, `"SET"` and `U&"set"` are refused
	// too.
	return staticGate(body)
}

func containsWord(haystack, word string) bool {
	index := 0
	for {
		position := strings.Index(haystack[index:], word)
		if position < 0 {
			return false
		}
		absolute := index + position
		before := byte(' ')
		if absolute > 0 {
			before = haystack[absolute-1]
		}
		after := byte(' ')
		if absolute+len(word) < len(haystack) {
			after = haystack[absolute+len(word)]
		}
		if !isWordByte(before) && !isWordByte(after) {
			return true
		}
		index = absolute + len(word)
		if index >= len(haystack) {
			return false
		}
	}
}

func isWordByte(value byte) bool {
	return value == '_' || (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')
}

// explainCost runs EXPLAIN (no ANALYZE, no execution) and returns the
// top-level plan node's estimated total cost. It is a resource guard, not a
// semantic one (ADR-0089 §3).
func explainCost(ctx context.Context, tx pgx.Tx, sqlText string) (float64, error) {
	rows, err := tx.Query(ctx, "EXPLAIN (FORMAT JSON) "+sqlText)
	if err != nil {
		return 0, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rows.Close()
	var planJSON string
	if !rows.Next() {
		return 0, &Error{code: CodeExternalFailure}
	}
	if err := rows.Scan(&planJSON); err != nil {
		return 0, &Error{code: CodeExternalFailure, cause: err}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, &Error{code: CodeExternalFailure, cause: err}
	}
	var plan []struct {
		Plan struct {
			TotalCost float64 `json:"Total Cost"`
		} `json:"Plan"`
	}
	if err := jsonv2.Unmarshal([]byte(planJSON), &plan); err != nil || len(plan) != 1 {
		return 0, &Error{code: CodeExternalFailure, cause: err}
	}
	if plan[0].Plan.TotalCost < 0 {
		return 0, &Error{code: CodeExternalFailure}
	}
	return plan[0].Plan.TotalCost, nil
}

func runQuery(ctx context.Context, tx pgx.Tx, sqlText string, limits Limits) (QueryResult, error) {
	started := time.Now().UTC()
	// PostgreSQL's text representation preserves numeric precision and type
	// rendering. A decoded Go value formatted with %%v is not the SQL value.
	rows, err := tx.Query(ctx, sqlText, pgx.QueryResultFormats{pgx.TextFormatCode})
	if err != nil {
		return QueryResult{}, &Error{code: CodeExternalFailure, cause: err}
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	if len(fields) == 0 || len(fields) > maxColumnCount {
		// A statement PostgreSQL cancels or refuses can produce no
		// RowDescription at all (a statement timeout is the common case), so
		// the reader must be drained here: otherwise the driver's own error is
		// masked by the shape check and the attempt is reported with no cause.
		_ = rows.Next()
		if err := rows.Err(); err != nil {
			return QueryResult{}, &Error{code: CodeExternalFailure, cause: err}
		}
		return QueryResult{}, &Error{code: CodeExternalFailure}
	}
	result := QueryResult{Columns: make([]string, len(fields)), Rows: make([][]*string, 0), ExecutionStartedAt: started}
	for index, field := range fields {
		result.Columns[index] = string(field.Name)
	}
	totalBytes := 0
	for rows.Next() {
		if result.RowCount >= limits.MaxRows {
			return QueryResult{}, &Error{code: CodeInvalid}
		}
		values := rows.RawValues()
		rendered := make([]*string, len(values))
		for index, value := range values {
			if value == nil {
				continue // SQL NULL is JSON null, distinct from an empty string.
			}
			totalBytes += len(value)
			if totalBytes > limits.MaxResultBytes {
				return QueryResult{}, &Error{code: CodeInvalid}
			}
			text := string(value)
			rendered[index] = &text
		}
		result.Rows = append(result.Rows, rendered)
		result.RowCount++
	}
	if err := rows.Err(); err != nil {
		return QueryResult{}, &Error{code: CodeExternalFailure, cause: err}
	}
	result.ExecutionCompletedAt = time.Now().UTC()
	return result, nil
}

// resultDigest covers the disclosed table, including values and NULLs. Only
// this hash, never the table, enters the audit event. Execution time is not
// part of the digest, so identical ordered results have identical hashes.
func resultDigest(result QueryResult) string {
	canonical := struct {
		Format   string      `json:"format"`
		Columns  []string    `json:"columns"`
		RowCount int         `json:"row_count"`
		Rows     [][]*string `json:"rows"`
	}{"postgres-text-table-v1", result.Columns, result.RowCount, result.Rows}
	raw, err := jsonv2.Marshal(canonical)
	if err != nil {
		return ""
	}
	value := jsontext.Value(raw)
	if err := value.Canonicalize(); err != nil {
		return ""
	}
	return sha256Hex(string(value))
}

// VerifyTextTableResultDigest re-computes the canonical digest for the exact
// public text-table projection returned by a governed read. It is intentionally
// narrow: callers supply only the result fields covered by the digest, and the
// function accepts only the canonical lowercase sha256 spelling used by this
// package's attempt records.
func VerifyTextTableResultDigest(columns []string, rowCount int, rows [][]*string, digest string) bool {
	if !validSQLHash(digest) || rowCount < 0 || rowCount != len(rows) {
		return false
	}
	actual := resultDigest(QueryResult{Columns: columns, RowCount: rowCount, Rows: rows})
	return actual != "" && actual == digest
}
