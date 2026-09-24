package question

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestActionRequestTextExtractsOnlyKnownSafeFields(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args string
		want string
	}{
		{"knowvault_search", `{"workspace_id":"ws_1","query":"termination clause"}`, "termination clause"},
		{"knowvault_read", `{"fragment_id":"frag_1"}`, "frag_1"},
		{"knowvault_evidence_read", `{"address":"kv1:src:ver:obj:0:10:hash"}`, "kv1:src:ver:obj:0:10:hash"},
		{liveDataToolName, `{"question":"orders placed on 2026-09-10"}`, "orders placed on 2026-09-10"},
		{trustedMetricToolName, `{"metric_id":"mrr","date_a":"2026-09-01","date_b":"2026-09-08"}`, "mrr: 2026-09-01 vs 2026-09-08"},
		{"knowvault_grep", `{"workspace_id":"ws_1","pattern":"renewal"}`, "renewal"},
		{"knowvault_related", `{"fragment_id":"frag_2"}`, "frag_2"},
		{"knowvault_sources", `{"workspace_id":"ws_1"}`, "Workspace sources"},
		{"knowvault_list_objects", `{"workspace_id":"ws_1"}`, "Workspace object inventory"},
		// A tool name outside the reviewed set never has its arguments
		// inspected, even when a field happens to be named like a known one.
		{"custom_connector_tool", `{"sql":"SELECT * FROM customers","query":"do-not-leak"}`, ""},
		{"knowvault_search", `{"workspace_id":"ws_1"}`, ""},
	} {
		if got := actionRequestText(testCase.name, json.RawMessage(testCase.args)); got != testCase.want {
			t.Fatalf("%s: request = %q, want %q", testCase.name, got, testCase.want)
		}
	}
}

func TestActionRequestTextIsBounded(t *testing.T) {
	long := strings.Repeat("a", 500)
	got := actionRequestText("knowvault_search", json.RawMessage(`{"query":"`+long+`"}`))
	runes := []rune(got)
	if len(runes) != ActionTextMaxRunes+1 || runes[ActionTextMaxRunes] != '…' {
		t.Fatalf("request text not bounded to %d runes: len=%d text=%q", ActionTextMaxRunes, len(runes), got)
	}
}

func TestActionResultTextSummarizesKnownToolsWithoutLeakingPayload(t *testing.T) {
	const secret = "internal_connection_identity_should_never_appear"
	for _, testCase := range []struct {
		name      string
		succeeded bool
		result    workspacetools.Result
		want      string
	}{
		{"knowvault_search", true, workspacetools.Result{Structured: json.RawMessage(`{"results":[]}`)}, "No results"},
		{"knowvault_search", true, workspacetools.Result{Structured: json.RawMessage(
			`{"results":[{"excerpt":"Termination requires 30 days notice."},{"excerpt":"Renewal is automatic unless notice is given."}]}`)},
			"2 hits: Termination requires 30 days notice.; Renewal is automatic unless notice is given."},
		{"knowvault_read", true, workspacetools.Result{Structured: json.RawMessage(`{"text":"hello","has_more":false}`)}, "Read 5 characters"},
		{"knowvault_read", true, workspacetools.Result{Structured: json.RawMessage(`{"text":"hello","has_more":true}`)}, "Read 5 characters (more available)"},
		{liveDataToolName, true, workspacetools.Result{Structured: json.RawMessage(`{"row_count":0}`)}, "No results"},
		{liveDataToolName, true, workspacetools.Result{Structured: json.RawMessage(
			`{"row_count":3,"database_identity":"` + secret + `","sql_hash":"` + secret + `"}`)}, "3 rows returned"},
		{trustedMetricToolName, true, workspacetools.Result{Structured: json.RawMessage(`{"delta":"12","unit":"USD","percent_change":"4.5"}`)}, "Delta: 12 USD (4.5%)"},
		{"knowvault_grep", true, workspacetools.Result{Structured: json.RawMessage(`{"matches":[]}`)}, "No results"},
		{"knowvault_sources", true, workspacetools.Result{Structured: json.RawMessage(`{"sources":[{},{},{}]}`)}, "3 sources"},
		{"unrecognized_tool", true, workspacetools.Result{Structured: json.RawMessage(`{"anything":"` + secret + `"}`)}, "Completed"},
		{"knowvault_search", false, workspacetools.Result{IsError: true, Text: `{"error":"TOOL_UNAVAILABLE"}`}, "Unavailable"},
		{"knowvault_read", false, workspacetools.Result{IsError: true, Text: `{"error":"` + secret + `"}`}, "Failed"},
		{"knowvault_read", false, workspacetools.Result{IsError: true, Text: secret}, "Failed"},
	} {
		got := actionResultText(testCase.name, testCase.succeeded, testCase.result)
		if got != testCase.want {
			t.Fatalf("%s succeeded=%v: detail = %q, want %q", testCase.name, testCase.succeeded, got, testCase.want)
		}
		if strings.Contains(got, secret) {
			t.Fatalf("%s: sensitive payload leaked into detail: %q", testCase.name, got)
		}
	}
}

func TestActionResultTextIsBounded(t *testing.T) {
	titles := make([]map[string]string, 0, 10)
	for index := 0; index < 10; index++ {
		titles = append(titles, map[string]string{"excerpt": strings.Repeat("word ", 40)})
	}
	payload, err := json.Marshal(map[string]any{"results": titles})
	if err != nil {
		t.Fatal(err)
	}
	got := actionResultText("knowvault_search", true, workspacetools.Result{Structured: payload})
	if runes := []rune(got); len(runes) > ActionTextMaxRunes+1 {
		t.Fatalf("result text not bounded to %d runes: len=%d", ActionTextMaxRunes, len(runes))
	}
}
