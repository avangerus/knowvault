package governedquery

// scoped.go is ADR-0097's agent-authored read-only SQL execution path: the one
// entry point behind the knowvault_source_sql knowledge tool. It deliberately
// reuses this package's single governed-execution machinery -- the static
// single-statement pre-check, the read-only transaction, the statement
// timeout, the EXPLAIN cost cap and the row/byte cap -- and adds exactly the
// two ADR-0097 §3 decisions the mounted ADR-0089 connection does not need:
//
//   - the statement runs with the SOURCE's own query credential (a role that is
//     distinct from the ingestion role and holds SELECT only on the source's
//     selected tables), never with a workspace-wide mounted DSN; and
//   - every relation the planner touches must belong to the relations
//     registered for that source, so a statement cannot reach pg_catalog,
//     information_schema, another schema or a function that reads a table
//     outside the source.
//
// The scope walk is defence in depth, exactly as ADR-0097 §3 says: the
// database's own grants and the read-only transaction remain the security
// boundary, and a statement that passes the walk still runs with the query
// role's rights only. No second way to send SQL to a customer database is
// added here: this file calls the same dial/staticPrecheck/runQuery/resultDigest
// primitives the mounted path uses, inside the same package.

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The closed error vocabulary ADR-0097's tool returns to its caller. Each is a
// content-free code an agent can react to; none carries SQL, a relation name, a
// row or a driver message.
const (
	// CodeSQLRejectedStatic is the static pre-check refusal: not exactly one
	// SELECT/WITH statement, or a comment/write/DDL keyword.
	CodeSQLRejectedStatic ErrorCode = "SQL_REJECTED_STATIC"
	// CodeRelationNotInSource is the plan-walk refusal: a relation, system
	// catalog or function scan outside the source's registered scope. A column
	// the administrator excluded is refused one layer lower: registration
	// REVOKEs it from the source's query role, so PostgreSQL itself answers
	// DATABASE_REJECTED (ADR-0097 §3), which the plan walk cannot and must not
	// replace.
	CodeRelationNotInSource ErrorCode = "RELATION_NOT_IN_SOURCE"
	// CodeCostLimit is the EXPLAIN cost-cap refusal.
	CodeCostLimit ErrorCode = "COST_LIMIT"
	// CodeRowLimit is the row/byte-cap refusal.
	CodeRowLimit ErrorCode = "ROW_LIMIT"
	// CodeTimeout is the statement-timeout refusal.
	CodeTimeout ErrorCode = "TIMEOUT"
	// CodeDatabaseRejected is every refusal PostgreSQL itself returned: a
	// missing grant, a revoked excluded column, a syntax error, an unreadable
	// relation.
	CodeDatabaseRejected ErrorCode = "DATABASE_REJECTED"
	// CodeSourceSQLNotConfigured is returned when the source connection has no
	// query credential. ExecuteScoped never invents one; the caller that
	// resolves the credential produces this code before execution.
	CodeSourceSQLNotConfigured ErrorCode = "SOURCE_SQL_NOT_CONFIGURED"
)

const (
	// maxScopedRelations bounds one source scope. It mirrors the ADR-0089
	// exposed-schema bound so a stored scope can never grow unbounded.
	maxScopedRelations = 512
	// scopedWorkMem is the server-owned per-operation memory bound of every
	// agent-authored transaction (card S3.2c). It is a string literal so it can
	// only ever be a valid PostgreSQL memory unit, never request input.
	scopedWorkMem = "16MB"
	// scopedTempFileLimit is the bounded spill-to-disk allowance. PostgreSQL
	// makes temp_file_limit superuser-only, so it is pinned only when the
	// server permits it (see prepareScopedTransaction).
	scopedTempFileLimit = "64MB"
	// scopedLockTimeout is the card's "<= 2 s" bound on waiting for a lock held
	// by the customer's own workloads.
	scopedLockTimeout = "2s"
)

// ScopedRelation is one relation registered for a source plus the exact set of
// columns the workspace projection allows. Columns is retained as the source's
// immutable projection contract (and for the audit/schema digest); the plan
// walk itself is relation-scoped, because PostgreSQL's own column grants are
// what refuse an excluded column (see CodeRelationNotInSource).
type ScopedRelation struct {
	Schema  string
	Table   string
	Columns []string
}

// ScopedSchema is the immutable relation scope of one source. It is derived
// from stored registration data, never from a request.
type ScopedSchema struct {
	Relations []ScopedRelation
}

// Validate checks the closed scope shape before any connection is opened.
func (schema ScopedSchema) Validate() error {
	if len(schema.Relations) == 0 || len(schema.Relations) > maxScopedRelations {
		return &Error{code: CodeInvalid}
	}
	seen := make(map[string]struct{}, len(schema.Relations))
	for _, relation := range schema.Relations {
		if !validIdentifier(relation.Schema) || !validIdentifier(relation.Table) ||
			len(relation.Columns) == 0 || len(relation.Columns) > maxExposedColumns {
			return &Error{code: CodeInvalid}
		}
		key := relation.Schema + "." + relation.Table
		if _, duplicate := seen[key]; duplicate {
			return &Error{code: CodeInvalid}
		}
		seen[key] = struct{}{}
		seenColumns := make(map[string]struct{}, len(relation.Columns))
		for _, column := range relation.Columns {
			if !validIdentifier(column) {
				return &Error{code: CodeInvalid}
			}
			if _, duplicate := seenColumns[column]; duplicate {
				return &Error{code: CodeInvalid}
			}
			seenColumns[column] = struct{}{}
		}
	}
	return nil
}

// ScopedParams is the untrusted candidate statement bound to one source scope.
// SQLText is agent output (the chat model or an authenticated MCP/API agent),
// never a user-facing API field; Purpose is bounded server-side audit context.
type ScopedParams struct {
	SQLText string
	Purpose string
	Schema  ScopedSchema
}

// ExecuteScoped is the single production entry point for agent-authored SQL
// over one workspace source. It reuses this package's governed primitives and
// maps every refusal onto the closed ADR-0097 vocabulary above.
func ExecuteScoped(ctx context.Context, config Config, params ScopedParams) (QueryResult, Attempt, error) {
	attempt := Attempt{}
	if ctx == nil || config.Validate() != nil || len(params.SQLText) == 0 ||
		len(params.SQLText) > maxSQLTextBytes || params.Schema.Validate() != nil {
		return QueryResult{}, attempt, &Error{code: CodeInvalid}
	}
	attempt.SQLHash = sha256Hex(params.SQLText)

	if err := staticPrecheck(params.SQLText); err != nil {
		attempt.Outcome = OutcomeRejectedStatic
		return QueryResult{}, attempt, &Error{code: CodeSQLRejectedStatic}
	}

	started := time.Now()
	connection, err := dial(ctx, config)
	if err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: err}
	}
	defer connection.Close(ctx)

	dialCtx, cancel := context.WithTimeout(ctx, config.Limits.StatementTimeout+5*time.Second)
	defer cancel()

	tx, err := connection.BeginTx(dialCtx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: err}
	}
	defer func() { _ = tx.Rollback(dialCtx) }()

	if err := prepareScopedTransaction(dialCtx, tx, config.Limits, params.Schema); err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: err}
	}

	// ADR-0097 §3 / card S3.2c: the connected database must be the exact
	// database the source was registered against. The check runs after the
	// connection and before any statement (including any role proof or plan
	// walk), so a credential repointed at another database is refused as
	// DATABASE_REJECTED with nothing executed.
	identity, identityErr := queryCredentialDatabaseIdentity(dialCtx, tx)
	if identityErr != nil || identity != config.DatabaseIdentity {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: identityErr}
	}

	// The database role is the security boundary (ADR-0097 §3), so the server
	// proves it is least privilege before the agent's statement is even
	// planned. A cached proof bound to the same connection/credential/scope
	// pair (server-owned Config.RoleProven) stands in for a fresh proof; a
	// failure is the tool's closed SOURCE_SQL_NOT_CONFIGURED and nothing runs.
	if config.RoleProven {
		attempt.RoleVerificationDigest = roleVerificationDigest(params.Schema.Relations)
	} else if roleErr := VerifyQueryRole(dialCtx, tx, params.Schema.Relations); roleErr != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeSourceSQLNotConfigured, cause: roleErr}
	} else {
		attempt.RoleVerificationDigest = roleVerificationDigest(params.Schema.Relations)
	}

	planJSON, cost, err := explainPlan(dialCtx, tx, params.SQLText)
	if err != nil {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: err}
	}
	if code := PlanScopeProblem(planJSON, params.Schema); code != "" {
		attempt.Outcome = OutcomeRejectedStatic
		return QueryResult{}, attempt, &Error{code: code}
	}
	if cost < 0 {
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected}
	}
	attempt.CostEstimate = cost
	if cost > config.Limits.MaxCostEstimate {
		attempt.Outcome = OutcomeCostLimitExceeded
		return QueryResult{}, attempt, &Error{code: CodeCostLimit}
	}

	result, rowsErr := runQuery(dialCtx, tx, params.SQLText, config.Limits)
	elapsed := time.Since(started)
	attempt.Elapsed = elapsed
	if rowsErr != nil {
		if scopedTimeoutError(rowsErr) {
			attempt.Outcome = OutcomeTimeout
			return QueryResult{}, attempt, &Error{code: CodeTimeout, cause: rowsErr}
		}
		if CodeOf(rowsErr) == CodeInvalid {
			attempt.Outcome = OutcomeRowLimitExceeded
			return QueryResult{}, attempt, &Error{code: CodeRowLimit}
		}
		attempt.Outcome = OutcomeRejectedDatabase
		return QueryResult{}, attempt, &Error{code: CodeDatabaseRejected, cause: rowsErr}
	}
	result.CostEstimate = cost
	result.Elapsed = elapsed
	attempt.RowCount = result.RowCount
	attempt.ResultDigest = resultDigest(result)
	attempt.Outcome = OutcomeSucceeded
	return result, attempt, nil
}

// prepareScopedTransaction is the one fixed transaction shape the scoped path
// opens: read-only (already begun), parallel workers off, the registered
// schemas on the search path so an unqualified registered relation resolves,
// the statement/idle timeouts pinned to the server-owned limits and the
// read-only mode re-read from PostgreSQL rather than assumed.
func prepareScopedTransaction(ctx context.Context, tx pgx.Tx, limits Limits, schema ScopedSchema) error {
	if tx == nil {
		return &Error{code: CodeDatabaseRejected}
	}
	statements := []string{
		"SET LOCAL max_parallel_workers_per_gather = 0",
		"SET LOCAL max_parallel_workers = 0",
		"SET LOCAL jit = off",
		"SET LOCAL search_path = " + scopedSearchPath(schema),
		// Card S3.2c: every agent-authored transaction pins the lock wait and
		// the per-operation memory bound. lock_timeout is the card's <= 2s
		// bound; work_mem is a bounded server-owned value, never a request
		// field. Both are settable by any role, so a failure here is a real
		// refusal rather than a tolerated server difference.
		"SET LOCAL lock_timeout = '" + scopedLockTimeout + "'",
		"SET LOCAL work_mem = '" + scopedWorkMem + "'",
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return &Error{code: CodeDatabaseRejected, cause: err}
		}
	}
	// temp_file_limit is superuser-only on PostgreSQL, so the card says "where
	// the server allows it": pin it inside a savepoint so a refusal rolls back
	// only the pin instead of aborting the whole transaction.
	if _, err := tx.Exec(ctx, "SAVEPOINT kv_scoped_settings"); err == nil {
		if _, err := tx.Exec(ctx, "SET LOCAL temp_file_limit = '"+scopedTempFileLimit+"'"); err != nil {
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT kv_scoped_settings")
		}
		_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT kv_scoped_settings")
	}
	timeoutMS := strconv.FormatInt(limits.StatementTimeout.Milliseconds(), 10) + "ms"
	for _, name := range []string{"statement_timeout", "idle_in_transaction_session_timeout"} {
		if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", name, timeoutMS); err != nil {
			return &Error{code: CodeDatabaseRejected, cause: err}
		}
	}
	var readOnly string
	if err := tx.QueryRow(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil || readOnly != "on" {
		return &Error{code: CodeDatabaseRejected, cause: err}
	}
	return nil
}

// scopedSearchPath renders the registered schemas as a quoted, duplicate-free
// search path. Identifiers are already restricted to [a-z0-9_] by
// ScopedSchema.Validate, so quoting cannot be escaped.
func scopedSearchPath(schema ScopedSchema) string {
	seen := make(map[string]struct{}, len(schema.Relations))
	schemas := make([]string, 0, len(schema.Relations))
	for _, relation := range schema.Relations {
		if _, exists := seen[relation.Schema]; exists {
			continue
		}
		seen[relation.Schema] = struct{}{}
		schemas = append(schemas, `"`+relation.Schema+`"`)
	}
	sort.Strings(schemas)
	if len(schemas) == 0 {
		return "pg_catalog"
	}
	return strings.Join(schemas, ", ")
}

// explainPlan runs EXPLAIN (VERBOSE, no ANALYZE, no execution) and returns the
// raw JSON plan together with the top-level estimated total cost. VERBOSE is
// required because only it makes PostgreSQL print each scan node's "Schema",
// which is what lets the walk tell a registered table from a same-named system
// catalog relation. VERBOSE never executes the statement.
func explainPlan(ctx context.Context, tx pgx.Tx, sqlText string) ([]byte, float64, error) {
	rows, err := tx.Query(ctx, "EXPLAIN (VERBOSE, FORMAT JSON) "+sqlText)
	if err != nil {
		return nil, 0, &Error{code: CodeDatabaseRejected, cause: err}
	}
	defer rows.Close()
	var planJSON string
	if !rows.Next() {
		return nil, 0, &Error{code: CodeDatabaseRejected}
	}
	if err := rows.Scan(&planJSON); err != nil {
		return nil, 0, &Error{code: CodeDatabaseRejected, cause: err}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, &Error{code: CodeDatabaseRejected, cause: err}
	}
	var plan []struct {
		Plan struct {
			TotalCost float64 `json:"Total Cost"`
		} `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(planJSON), &plan); err != nil || len(plan) != 1 {
		return nil, 0, &Error{code: CodeDatabaseRejected, cause: err}
	}
	if plan[0].Plan.TotalCost < 0 {
		return nil, 0, &Error{code: CodeDatabaseRejected}
	}
	return []byte(planJSON), plan[0].Plan.TotalCost, nil
}

// planDocument and planNode are the subset of PostgreSQL's JSON plan shape the
// scope walk needs. Unknown members are ignored, so a newer server's extra
// fields can never make a plan unreadable.
type planDocument struct {
	Plan planNode `json:"Plan"`
}

type planNode struct {
	NodeType     string     `json:"Node Type"`
	RelationName string     `json:"Relation Name"`
	Schema       string     `json:"Schema"`
	Alias        string     `json:"Alias"`
	FunctionName string     `json:"Function Name"`
	Output       []string   `json:"Output"`
	Plans        []planNode `json:"Plans"`
}

// PlanScopeProblem walks one EXPLAIN (FORMAT JSON) plan and reports the closed
// refusal code for the first relation, catalog, function scan or projected
// column outside the source scope, or the empty code when the whole plan stays
// inside it. It is exported so the plan walk can be proven against synthetic
// plans and against real PostgreSQL planner output without opening the
// governed execution role.
func PlanScopeProblem(planJSON []byte, schema ScopedSchema) ErrorCode {
	if len(planJSON) == 0 || schema.Validate() != nil {
		return CodeRelationNotInSource
	}
	var plans []planDocument
	if err := json.Unmarshal(planJSON, &plans); err != nil || len(plans) != 1 {
		return CodeRelationNotInSource
	}
	index := newScopeIndex(schema)
	if problem := walkPlan(plans[0].Plan, index); problem != "" {
		return problem
	}
	return ""
}

// scopeIndex resolves a plan node's Relation Name to its registered scope.
// A node without a schema field (PostgreSQL omits it for a relation resolved
// through the search path) resolves only when the table name is unambiguous
// across the registered schemas; an ambiguous name is refused rather than
// guessed.
type scopeIndex struct {
	byKey   map[string]ScopedRelation
	byTable map[string][]ScopedRelation
}

func newScopeIndex(schema ScopedSchema) scopeIndex {
	index := scopeIndex{
		byKey:   make(map[string]ScopedRelation, len(schema.Relations)),
		byTable: make(map[string][]ScopedRelation, len(schema.Relations)),
	}
	for _, relation := range schema.Relations {
		index.byKey[relation.Schema+"."+relation.Table] = relation
		index.byTable[relation.Table] = append(index.byTable[relation.Table], relation)
	}
	return index
}

func (index scopeIndex) resolve(schemaName, tableName string) (ScopedRelation, bool) {
	if schemaName != "" {
		relation, ok := index.byKey[schemaName+"."+tableName]
		return relation, ok
	}
	candidates := index.byTable[tableName]
	if len(candidates) != 1 {
		return ScopedRelation{}, false
	}
	return candidates[0], true
}

func walkPlan(node planNode, index scopeIndex) ErrorCode {
	if node.FunctionName != "" || node.NodeType == "Function Scan" {
		// ADR-0097 §3: a function scan is not a registered relation. The query
		// role's grants still decide whether the function may run at all; the
		// walk refuses it before execution.
		return CodeRelationNotInSource
	}
	if node.RelationName != "" {
		if _, ok := index.resolve(node.Schema, node.RelationName); !ok {
			return CodeRelationNotInSource
		}
	}
	for _, child := range node.Plans {
		if problem := walkPlan(child, index); problem != "" {
			return problem
		}
	}
	return ""
}

// scopedTimeoutError recognises a statement-timeout cancellation through the
// wrapped cause. Error() renders only the closed code, so the SQLSTATE must be
// read from the driver error itself: 57014 is PostgreSQL's query_canceled,
// which is what both statement_timeout and a cancelled context produce.
func scopedTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
		return true
	}
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "57014"
}
