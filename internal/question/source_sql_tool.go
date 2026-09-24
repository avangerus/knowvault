package question

// source_sql_tool.go is ADR-0097's chat-run bound for the agent-authored SQL
// tool. knowvault_source_sql itself is advertised and dispatched through the
// shared workspace tool runtime, but the card's limit — at most three
// SUCCESSFUL statements per chat run — is a property of one question run, so it
// lives here beside the run-scoped live-data state rather than in the
// transport. A refusal (a closed error result) does not consume the budget: the
// agent may correct a statement and retry.

import (
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// sourceSQLToolName is the registry name of ADR-0097's agent-authored SQL tool.
const sourceSQLToolName = "knowvault_source_sql"

// sourceSQLMaxSuccessfulCalls is the card's per-run bound on successful
// statements. It mirrors the ADR-0089 live-read bound and is deliberately a
// server-owned constant: no request can widen it.
const sourceSQLMaxSuccessfulCalls = 3

// sourceSQLRunState is the run-local budget. It is retained beside
// liveDataRunState by executeToolLoop and is never persisted or shared between
// runs.
type sourceSQLRunState struct {
	successfulCalls int
}

// allow reports whether one more successful call may run.
func (state *sourceSQLRunState) allow() bool {
	return state != nil && state.successfulCalls < sourceSQLMaxSuccessfulCalls
}

// record consumes one unit of the budget only for a successful call.
func (state *sourceSQLRunState) record(result workspacetools.Result) {
	if state == nil || result.IsError {
		return
	}
	state.successfulCalls++
}

// refused renders the content-free refusal the fourth successful call receives.
func (state *sourceSQLRunState) refused() workspacetools.Result {
	payload := `{"error":"SQL_LIMIT_REACHED","advice":"At most three successful SQL statements per answer. Use the results already returned."}`
	return workspacetools.Result{Text: payload, Structured: []byte(payload), IsError: true}
}
