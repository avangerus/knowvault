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
