package question

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

type liveDataAskProbe struct {
	calls     int
	ctx       context.Context
	access    database.AccessContext
	workspace string
	question  string
	result    governedask.AskResult
	err       error
}

func (probe *liveDataAskProbe) AskWorkspace(ctx context.Context, access database.AccessContext, workspaceID, question string) (governedask.AskResult, error) {
	probe.calls++
	probe.ctx, probe.access, probe.workspace, probe.question = ctx, access, workspaceID, question
	return probe.result, probe.err
}

func TestLiveDataToolDefinitionIsQuestionOwnedAndExact(t *testing.T) {
	if got := liveDataToolDefinitions(nil); len(got) != 0 {
		t.Fatalf("definitions without governed ask = %#v, want none", got)
	}
	probe := &liveDataAskProbe{}
	definitions := liveDataToolDefinitions(probe)
	if len(definitions) != 1 {
		t.Fatalf("definitions with governed ask = %#v, want one", definitions)
	}
	definition := definitions[0]
	if definition.Type != "function" || definition.Function.Name != liveDataToolName {
		t.Fatalf("definition identity = %#v", definition)
	}
	var schema map[string]json.RawMessage
	if err := json.Unmarshal(definition.Function.Parameters, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if len(schema) != 4 {
		t.Fatalf("schema fields = %#v; want only type/additionalProperties/required/properties", schema)
	}
	var schemaType string
	if json.Unmarshal(schema["type"], &schemaType) != nil || schemaType != "object" {
		t.Fatalf("schema type = %s", schema["type"])
	}
	var additionalProperties bool
	if json.Unmarshal(schema["additionalProperties"], &additionalProperties) != nil || additionalProperties {
		t.Fatalf("additionalProperties = %s, want false", schema["additionalProperties"])
	}
	var required []string
	if json.Unmarshal(schema["required"], &required) != nil || !reflect.DeepEqual(required, []string{"question"}) {
		t.Fatalf("required = %#v, want [question]", required)
	}
	var properties map[string]json.RawMessage
	if json.Unmarshal(schema["properties"], &properties) != nil || len(properties) != 1 {
		t.Fatalf("properties = %#v, want only question", properties)
	}
	var questionProperty map[string]json.RawMessage
	if json.Unmarshal(properties["question"], &questionProperty) != nil || len(questionProperty) != 1 {
		t.Fatalf("question property = %#v, want only its string type", questionProperty)
	}
	var questionType string
	if json.Unmarshal(questionProperty["type"], &questionType) != nil || questionType != "string" {
		t.Fatalf("question type = %s, want string", questionProperty["type"])
	}
	if _, registered := workspacetools.KnowledgeTools().Lookup(liveDataToolName); registered {
		t.Fatal("synthetic live-data tool was added to the workspace registry")
	}
}

func TestEnableGovernedAskInstallsOnce(t *testing.T) {
	service := &Service{}
	probe := &liveDataAskProbe{}
	if err := service.EnableGovernedAsk(probe); err != nil {
		t.Fatalf("install governed ask: %v", err)
	}
	if err := service.EnableGovernedAsk(&liveDataAskProbe{}); CodeOf(err) != CodeInvalid {
		t.Fatalf("second install error = %v, want %s", err, CodeInvalid)
	}
	if definitions := liveDataToolDefinitions(service.liveDataAsk); len(definitions) != 1 {
		t.Fatalf("installed ask advertised %d definitions, want one", len(definitions))
	}
}

func TestInvokeLiveDataToolDelegatesCurrentScopeAndProjectsOnlySafeFields(t *testing.T) {
	ctx := context.WithValue(context.Background(), struct{}{}, "run-context")
	access := database.AccessContext{OrganizationID: "org_current", PrincipalID: "usr_current", RequestID: "req_current"}
	probe := &liveDataAskProbe{result: liveDataResultFixture()}
	state := &liveDataRunState{}
	result, err := state.invoke(ctx, access, "workspace_current", "qrun_live_current", probe, json.RawMessage(`{"question":"How many records?"}`), 8192)
	if err != nil || result.IsError {
		t.Fatalf("invoke result = %#v, err = %v", result, err)
	}
	if probe.calls != 1 || probe.ctx != ctx || probe.access != access || probe.workspace != "workspace_current" || probe.question != "How many records?" {
		t.Fatalf("delegation = calls %d, ctx same %v, access %#v, workspace %q, question %q", probe.calls, probe.ctx == ctx, probe.access, probe.workspace, probe.question)
	}
	var projected map[string]json.RawMessage
	if err := json.Unmarshal(result.Structured, &projected); err != nil {
		t.Fatalf("decode projection: %v", err)
	}
	for _, key := range []string{"format", "columns", "rows", "row_count", "attempt_id", "sql_hash", "exposed_schema_revision", "result_digest", "read_window", "database_identity", "execution_started_at", "execution_completed_at", "complete"} {
		if _, ok := projected[key]; !ok {
			t.Fatalf("projection missing %q: %s", key, result.Text)
		}
	}
	for _, forbidden := range []string{"sql", "connection_id", "connection_selection", "cost_estimate", "answer"} {
		if _, ok := projected[forbidden]; ok {
			t.Fatalf("projection contains forbidden field %q: %s", forbidden, result.Text)
		}
	}
	for _, secret := range []string{"SELECT private_sql_secret", "private_connection_secret", "private_internal_error"} {
		if strings.Contains(result.Text, secret) {
			t.Fatalf("projection leaked %q: %s", secret, result.Text)
		}
	}
	var complete bool
	if err := json.Unmarshal(projected["complete"], &complete); err != nil || !complete {
		t.Fatalf("complete = %s, want true", projected["complete"])
	}
	var rowCount int
	if err := json.Unmarshal(projected["row_count"], &rowCount); err != nil || rowCount != 1 {
		t.Fatalf("row_count = %s, want one", projected["row_count"])
	}
}

func TestLiveDataRunStateRefusesSecondSuccessfulResult(t *testing.T) {
	probe := &liveDataAskProbe{result: liveDataResultFixture()}
	state := &liveDataRunState{}
	args := json.RawMessage(`{"question":"first"}`)
	first, err := state.invoke(context.Background(), database.AccessContext{}, "workspace_current", "qrun_live_current", probe, args, 8192)
	if err != nil || first.IsError {
		t.Fatalf("first invoke = %#v, err %v", first, err)
	}
	second, err := state.invoke(context.Background(), database.AccessContext{}, "workspace_current", "qrun_live_current", probe, json.RawMessage(`{"question":"second"}`), 8192)
	if err != nil || !second.IsError || probe.calls != 1 {
		t.Fatalf("second invoke = %#v, err %v, ask calls %d", second, err, probe.calls)
	}
	if !strings.Contains(second.Text, "LIVE_DATA_ALREADY_RECORDED") || strings.Contains(second.Text, "private") {
		t.Fatalf("second result = %q, want content-free already-recorded refusal", second.Text)
	}
	if !strings.Contains(first.Text, "private_row_value") {
		t.Fatal("the first successful result was replaced")
	}
}

func TestLiveDataProjectionRefusesOversizedResultsWithoutTruncating(t *testing.T) {
	tooMany := liveDataResultFixture()
	tooMany.RowCount = liveDataMaxRows + 1
	tooMany.Rows = make([][]*string, tooMany.RowCount)
	for index := range tooMany.Rows {
		value := fmt.Sprintf("private_row_%d", index)
		tooMany.Rows[index] = []*string{&value}
	}
	for _, example := range []struct {
		name   string
		result governedask.AskResult
		budget int
	}{
		{name: "row limit", result: tooMany, budget: 8192},
		{name: "model byte budget", result: liveDataResultFixture(), budget: 1},
		{name: "row count mismatch", result: func() governedask.AskResult { value := liveDataResultFixture(); value.RowCount++; return value }(), budget: 8192},
		{name: "cell byte limit", result: func() governedask.AskResult {
			value := liveDataResultFixture()
			cell := strings.Repeat("x", liveDataMaxCellBytes+1)
			value.Rows[0][0] = &cell
			return value
		}(), budget: 8192},
	} {
		t.Run(example.name, func(t *testing.T) {
			probe := &liveDataAskProbe{result: example.result}
			result, err := invokeLiveDataTool(context.Background(), database.AccessContext{}, "workspace_current", probe, json.RawMessage(`{"question":"q"}`), example.budget)
			if err != nil || !result.IsError || !strings.Contains(result.Text, "LIVE_DATA_RESULT_TOO_LARGE") {
				t.Fatalf("result = %#v, err = %v; want bounded too-large refusal", result, err)
			}
			if strings.Contains(result.Text, "private_row") || strings.Contains(result.Text, "private_sql_secret") || len(result.Text) > 256 {
				t.Fatalf("oversized refusal disclosed or retained content: %q", result.Text)
			}
		})
	}
}

func TestLiveDataRunStateDoesNotRetainFailedOrOversizedResults(t *testing.T) {
	oversized := liveDataResultFixture()
	oversized.RowCount = liveDataMaxRows + 1
	oversized.Rows = make([][]*string, oversized.RowCount)
	for index := range oversized.Rows {
		value := fmt.Sprintf("private_row_%d", index)
		oversized.Rows[index] = []*string{&value}
	}
	for _, probe := range []*liveDataAskProbe{
		{err: errors.New("private failure")},
		{result: oversized},
	} {
		state := &liveDataRunState{}
		result, err := state.invoke(context.Background(), database.AccessContext{}, "workspace_current", "qrun_live_current", probe, json.RawMessage(`{"question":"q"}`), 8192)
		if err == nil && !result.IsError {
			t.Fatalf("invalid invocation unexpectedly succeeded: %#v", result)
		}
		if state.retained != nil || state.successfulCall {
			t.Fatalf("refused result retained a private live dependency: %#v", state)
		}
	}
}

func TestLiveDataZeroRowsRemainACompleteSuccess(t *testing.T) {
	result := liveDataResultFixture()
	result.Rows = nil
	result.RowCount = 0
	result.ResultDigest = "sha256:cb4866cde14981d9bcf537b509093aad146e66bfb2aa1df1c6a90f2a62d56ce6"
	probe := &liveDataAskProbe{result: result}
	got, err := invokeLiveDataTool(context.Background(), database.AccessContext{}, "workspace_current", probe, json.RawMessage(`{"question":"q"}`), 8192)
	if err != nil || got.IsError {
		t.Fatalf("zero-row result = %#v, err = %v", got, err)
	}
	var projected struct {
		Rows       [][]*string        `json:"rows"`
		RowCount   int                `json:"row_count"`
		Complete   bool               `json:"complete"`
		ReadWindow liveDataReadWindow `json:"read_window"`
	}
	if err := json.Unmarshal(got.Structured, &projected); err != nil {
		t.Fatal(err)
	}
	if projected.Rows == nil || len(projected.Rows) != 0 || projected.RowCount != 0 || !projected.Complete || !projected.ReadWindow.Complete {
		t.Fatalf("zero-row projection = %#v", projected)
	}
}

func TestLiveDataToolRefusesInvalidGovernedReceiptMetadata(t *testing.T) {
	for _, example := range []struct {
		name   string
		mutate func(*governedask.AskResult)
	}{
		{name: "digest mismatch", mutate: func(result *governedask.AskResult) { result.ResultDigest = "sha256:" + strings.Repeat("0", 64) }},
		{name: "malformed attempt", mutate: func(result *governedask.AskResult) { result.AttemptID = "attempt_bad" }},
		{name: "malformed connection", mutate: func(result *governedask.AskResult) { result.ConnectionID = "bad connection" }},
		{name: "malformed sql hash", mutate: func(result *governedask.AskResult) { result.SQLHash = "sha256:abc" }},
		{name: "invalid schema revision", mutate: func(result *governedask.AskResult) { result.ExposedSchemaRevision = 0 }},
		{name: "invalid result format", mutate: func(result *governedask.AskResult) { result.ResultFormat = "json" }},
		{name: "missing timestamp", mutate: func(result *governedask.AskResult) { result.ExecutionStartedAt = time.Time{} }},
		{name: "reversed timestamps", mutate: func(result *governedask.AskResult) {
			result.ExecutionCompletedAt = result.ExecutionStartedAt.Add(-time.Second)
		}},
		{name: "future timestamp", mutate: func(result *governedask.AskResult) { result.ExecutionCompletedAt = time.Now().UTC().Add(time.Hour) }},
	} {
		t.Run(example.name, func(t *testing.T) {
			invalid := liveDataResultFixture()
			example.mutate(&invalid)
			got, err := invokeLiveDataTool(context.Background(), database.AccessContext{}, "workspace_current", &liveDataAskProbe{result: invalid}, json.RawMessage(`{"question":"q"}`), 8192)
			if err != nil || !got.IsError || strings.Contains(got.Text, "private") {
				t.Fatalf("invalid receipt result = %#v, err = %v", got, err)
			}
		})
	}
}

func TestInvokeLiveDataToolPreservesCancellationAndHidesErrors(t *testing.T) {
	privateErr := errors.New("internal error with private_connection_secret and SELECT private_sql_secret")
	probe := &liveDataAskProbe{err: privateErr}
	result, err := invokeLiveDataTool(context.Background(), database.AccessContext{}, "workspace_current", probe, json.RawMessage(`{"question":"q"}`), 8192)
	if !errors.Is(err, privateErr) || !result.IsError {
		t.Fatalf("failed ask = %#v, err %v", result, err)
	}
	if strings.Contains(result.Text, "private_connection_secret") || strings.Contains(result.Text, "private_sql_secret") || strings.Contains(result.Text, "internal error") {
		t.Fatalf("failed ask disclosed internal details: %q", result.Text)
	}
	probe.err = nil
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = invokeLiveDataTool(canceled, database.AccessContext{}, "workspace_current", probe, json.RawMessage(`{"question":"q"}`), 8192)
	if !errors.Is(err, context.Canceled) || !result.IsError || probe.calls != 1 {
		t.Fatalf("canceled ask = %#v, err %v, ask calls %d", result, err, probe.calls)
	}
	if strings.Contains(result.Text, "private") {
		t.Fatalf("canceled refusal disclosed content: %q", result.Text)
	}
}

func liveDataResultFixture() governedask.AskResult {
	count := "1"
	return governedask.AskResult{
		AttemptID:             "gqat_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SQL:                   "SELECT private_sql_secret",
		SQLHash:               "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Columns:               []string{"record_name", "count"},
		Rows:                  [][]*string{{stringPointer("private_row_value"), &count}},
		RowCount:              1,
		Answer:                "private answer",
		ConnectionID:          "conn_private_secret",
		DatabaseIdentity:      "demo_company_database",
		ExposedSchemaRevision: 7,
		ResultFormat:          liveDataResultFormat,
		ResultDigest:          "sha256:ab5c0f39cdfeb8036ddd3404514f6d4ec2d4cc4dc5d03dd8a272aa025b651e03",
		ExecutionStartedAt:    time.Date(2026, 9, 10, 0, 0, 1, 0, time.UTC),
		ExecutionCompletedAt:  time.Date(2026, 9, 10, 0, 0, 2, 0, time.UTC),
	}
}

func stringPointer(value string) *string { return &value }

var _ GovernedAsk = (*governedask.Service)(nil)
