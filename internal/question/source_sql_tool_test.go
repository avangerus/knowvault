package question

// S3 card 2 focused test for the chat-run budget of ADR-0097's
// knowvault_source_sql tool: the third successful statement is allowed and the
// fourth is refused, while a closed refusal does not consume the budget.

import (
	"encoding/json"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestSourceSQLRunStateAllowsThreeAndRefusesTheFourth(t *testing.T) {
	var state sourceSQLRunState
	for call := 1; call <= sourceSQLMaxSuccessfulCalls; call++ {
		if !state.allow() {
			t.Fatalf("call %d was refused before the bound", call)
		}
		state.record(workspacetools.Result{Structured: []byte(`{"row_count":1}`)})
	}
	if state.successfulCalls != sourceSQLMaxSuccessfulCalls {
		t.Fatalf("successful calls = %d, want %d", state.successfulCalls, sourceSQLMaxSuccessfulCalls)
	}
	if state.allow() {
		t.Fatal("the fourth successful call was allowed")
	}
	refusal := state.refused()
	if !refusal.IsError {
		t.Fatal("the limit refusal is not marked as an error result")
	}
	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(refusal.Text), &decoded); err != nil || decoded.Error != "SQL_LIMIT_REACHED" {
		t.Fatalf("refusal payload = %s err=%v", refusal.Text, err)
	}
}

func TestSourceSQLBudgetChargesFromProviderOutcomeBeforeRetain(t *testing.T) {
	canonical := testSourceSQLCanonicalResult(t)
	var state sourceSQLRunState
	for call := 1; call <= sourceSQLMaxSuccessfulCalls+1; call++ {
		if !state.allow() {
			if call != sourceSQLMaxSuccessfulCalls+1 {
				t.Fatalf("call %d was refused before the bound", call)
			}
			refusal := state.refused()
			var decoded struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(refusal.Text), &decoded); err != nil || decoded.Error != "SQL_LIMIT_REACHED" {
				t.Fatalf("fourth call refusal = %s err=%v", refusal.Text, err)
			}
			return
		}
		// Every provider success here is too large to retain; card S3.2d R5
		// charges it before post-processing, so it still costs one.
		retained, execution := state.invoke(testSourceSQLRunID, canonical, 1)
		if execution != nil {
			t.Fatalf("call %d retained a result above the limit", call)
		}
		var decoded struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(retained.Text), &decoded); err != nil || decoded.Error != "SOURCE_SQL_RESULT_TOO_LARGE" {
			t.Fatalf("call %d post-processing = %s err=%v", call, retained.Text, err)
		}
	}
	t.Fatal("the fourth executed statement was allowed")
}

// TestSourceSQLBudgetChargesWhenPostProcessingCannotAuthenticate is card S3.2d
// R5's ordering proof: a provider success whose post-processing rejects the
// payload (a code that never reached the database layer) still consumes the
// budget, because the charge happens before the post-processing.
func TestSourceSQLBudgetChargesWhenPostProcessingCannotAuthenticate(t *testing.T) {
	malformed := workspacetools.Result{Structured: []byte(`{"source_id":"conn_malformed"}`)}
	var state sourceSQLRunState
	for call := 1; call <= sourceSQLMaxSuccessfulCalls; call++ {
		if !state.allow() {
			t.Fatalf("call %d was refused before the bound", call)
		}
		state.invoke(testSourceSQLRunID, malformed, 1<<20)
	}
	if state.successfulCalls != sourceSQLMaxSuccessfulCalls || state.allow() {
		t.Fatalf("provider successes were not charged before post-processing: successful=%d allow=%v", state.successfulCalls, state.allow())
	}
}

func TestSourceSQLRunStateRefusalsDoNotConsumeTheBudget(t *testing.T) {
	var state sourceSQLRunState
	for call := 0; call < sourceSQLMaxSuccessfulCalls*2; call++ {
		state.record(workspacetools.Result{IsError: true, Text: `{"error":"RELATION_NOT_IN_SOURCE"}`})
	}
	if state.successfulCalls != 0 || !state.allow() {
		t.Fatalf("refusals consumed the budget: successful=%d allow=%v", state.successfulCalls, state.allow())
	}
	// A nil state (a run that never received it) never panics.
	var nilState *sourceSQLRunState
	nilState.record(workspacetools.Result{})
	if nilState.allow() {
		t.Fatal("a nil run state allowed a call")
	}
}

// TestSourceSQLRunStateCountsAttemptsThatReachedExecution is card S3.2c's chat
// budget rule: a statement that ran and then timed out, hit the row cap or hit
// the cost cap consumes the same budget a success does, so four timeouts refuse
// the fifth call while a pre-execution refusal stays free.
func TestSourceSQLRunStateCountsAttemptsThatReachedExecution(t *testing.T) {
	for _, code := range []string{"TIMEOUT", "ROW_LIMIT", "COST_LIMIT", "DATABASE_REJECTED"} {
		var state sourceSQLRunState
		for call := 0; call < sourceSQLMaxSuccessfulCalls; call++ {
			state.record(workspacetools.Result{IsError: true, Text: `{"error":"` + code + `"}`})
		}
		if state.successfulCalls != sourceSQLMaxSuccessfulCalls || state.allow() {
			t.Fatalf("%s consumed %d of %d budget units, allow=%v", code, state.successfulCalls, sourceSQLMaxSuccessfulCalls, state.allow())
		}
	}
	for _, code := range []string{
		"SQL_REJECTED_STATIC", "RELATION_NOT_IN_SOURCE", "SOURCE_SQL_NOT_CONFIGURED",
		"SOURCE_SQL_CONCURRENCY_LIMITED", "SOURCE_SQL_RATE_LIMITED", "SQL_LIMIT_REACHED",
	} {
		var state sourceSQLRunState
		for call := 0; call < sourceSQLMaxSuccessfulCalls*2; call++ {
			state.record(workspacetools.Result{IsError: true, Structured: []byte(`{"error":"` + code + `"}`)})
		}
		if state.successfulCalls != 0 || !state.allow() {
			t.Fatalf("pre-execution refusal %s consumed the budget: successful=%d", code, state.successfulCalls)
		}
	}
}
