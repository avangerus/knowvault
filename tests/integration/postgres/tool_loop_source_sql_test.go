package postgres_test

// S3 card 2b's end-to-end proof that a knowvault_source_sql result is evidence
// in a real chat run: the scripted model reads the source schema, runs one SQL
// statement, and cites the returned live read; the run completes with a
// LIVE_TABLE AnswerResult bound to the source. A forged receipt is rejected and
// the fourth SQL statement is refused, all through the real question.Service,
// the real workspaceapi tool runtime and the real encrypted run persistence.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const sourceSQLToolLoopSourceID = "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ"

func sourceSQLToolLoopDigest(columns []string, rows [][]*string) string {
	raw, err := canon.CanonicalJSON(struct {
		Format   string      `json:"format"`
		Columns  []string    `json:"columns"`
		RowCount int         `json:"row_count"`
		Rows     [][]*string `json:"rows"`
	}{"postgres-text-table-v1", columns, len(rows), rows})
	if err != nil {
		return ""
	}
	return canon.Hash(raw)
}

// sqlToolLoopSourceService satisfies the required SourceService boundary and
// adds exactly the two optional ADR-0097 capabilities the run needs; every
// other method still fails closed through the embedded fixture.
type sqlToolLoopSourceService struct {
	kvA01SourceService
	calls    int
	lastSQL  string
	lastArgs string
}

func (service *sqlToolLoopSourceService) ListSourceSchemas(context.Context, database.AccessContext, string) ([]workspacerepository.SourceSchemaSource, error) {
	return []workspacerepository.SourceSchemaSource{{
		ID: sourceSQLToolLoopSourceID, Name: "Live contracts", TableCount: 1,
	}}, nil
}

func (service *sqlToolLoopSourceService) SourceSchema(context.Context, database.AccessContext, string, string, string, int, int) (workspacerepository.SourceSchema, error) {
	return workspacerepository.SourceSchema{
		SourceID: sourceSQLToolLoopSourceID, DatabaseIdentity: "pgdb:alpha",
		Tables: []workspacerepository.SourceSchemaTable{{
			Schema: "public", Name: "contracts", Kind: "TABLE",
			Columns: []workspacerepository.SourceSchemaColumn{{Name: "id", Type: "uuid", PrimaryKey: true}, {Name: "status", Type: "text"}},
		}},
	}, nil
}

func (service *sqlToolLoopSourceService) SourceSQL(_ context.Context, _ database.AccessContext, _ string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {	service.calls++
	service.lastSQL = request.SQL
	service.lastArgs = request.SourceID
	value := "42"
	rows := [][]*string{{&value}}
	attemptID, err := ids.New("gqat")
	if err != nil {
		return workspaceapi.SourceSQLResult{}, err
	}
	now := time.Now().UTC()
	return workspaceapi.SourceSQLResult{
		Format: "postgres-text-table-v1", SourceID: sourceSQLToolLoopSourceID, ExposedSchemaRevision: 3,
		Columns: []string{"contract_count"}, Rows: rows, RowCount: 1,
		AttemptID: attemptID, SQLHash: canon.Hash([]byte(request.SQL)),
		ResultDigest: sourceSQLToolLoopDigest([]string{"contract_count"}, rows),
		DatabaseIdentity: "pgdb:alpha", ExecutionStartedAt: now.Add(-time.Second), ExecutionCompletedAt: now,
	}, nil
}

// ReauthorizeSourceSQLAttempt is the read-time source-access check the chat
// disclosure gate discovers on the source service. The fixture's source is not
// registered in the product schema, so the check accepts and the gate plumbing
// itself is what this test exercises.
func (service *sqlToolLoopSourceService) ReauthorizeSourceSQLAttempt(context.Context, database.AccessContext, string, question.SourceSQLAttemptDisclosure) error {
	return nil
}

func scriptedSourceSQLHandler(t *testing.T, organizationID, principal string, sources *sqlToolLoopSourceService,
	viewer *evidence.Viewer, authority *workspacerepository.Store) (*workspaceapi.Handler, string, string) {
	t.Helper()
	authenticator, err := httpauth.New(
		kvA01TenantResolver{organizationID: organizationID},
		kvA01SessionResolver{organizationID: organizationID, principalID: principal, claims: kvA01Claims(t, organizationID, principal)},
	)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	appStore := openStore(t, context.Background(), appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(authenticator, authority, sources, viewer, nil, conversations)
	if err != nil {
		t.Fatalf("workspace handler: %v", err)
	}
	rawToken := make([]byte, 32)
	for index := range rawToken {
		rawToken[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	proof, err := (kvA01Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("csrf proof: %v", err)
	}
	return handler, token, proof.Value()
}

// sourceSQLToolLoopAdapter builds the one scripted model adapter this test
// drives the real tool loop with.
func sourceSQLToolLoopAdapter(t *testing.T, endpoint, modelID string) *modelgateway.LabAdapter {
	t.Helper()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: endpoint, ModelID: modelID,
		MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{ID: "sql-fixture", MaxTurns: 8, MaxToolCalls: 12,
			MaxInputBytes: 60000, MaxToolResultBytes: 16000, MaxOutputTokens: 2048, TimeoutSeconds: 120},
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func TestToolLoopSourceSQLResultIsCitedLiveRead(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_4K895FKH1CRX252KVCTX0FNXXZ", "grant_s1d_admin", "confirmation_s1d_admin", true)

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	sources := &sqlToolLoopSourceService{}
	handler, _, _ := scriptedSourceSQLHandler(t, s1dOrg, s1dOwner, sources, viewer, authority)
	questions.EnableToolLoop(handler)

	scenario := "answer"
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Messages []modelgateway.Message        `json:"messages"`
			Tools    []modelgateway.ToolDefinition `json:"tools"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.Messages) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		last := input.Messages[len(input.Messages)-1]
		message := map[string]any{"role": "assistant"}
		finish := "stop"
		toolCall := func(id, name, arguments string) {
			message["tool_calls"] = []any{map[string]any{"id": id, "type": "function",
				"function": map[string]any{"name": name, "arguments": arguments}}}
			finish = "tool_calls"
		}
		sqlAttempt, sqlReceipt := lastSQLReceipt(input.Messages)
		switch {
		case last.Role == "user":
			toolCall("schema-1", "knowvault_source_schema", `{"source_id":"`+sourceSQLToolLoopSourceID+`"}`)
		case last.Role == "tool" && strings.Contains(last.Content, `"tables"`):
			toolCall("sql-1", "knowvault_source_sql", `{"source_id":"`+sourceSQLToolLoopSourceID+`","sql":"SELECT count(*) FROM public.contracts","purpose":"count contracts"}`)
		case last.Role == "tool" && scenario == "limit" && !containsLimitRefusal(input.Messages):
			toolCall("sql-more", "knowvault_source_sql", `{"source_id":"`+sourceSQLToolLoopSourceID+`","sql":"SELECT count(*) FROM public.contracts","purpose":"count again"}`)
		case last.Role == "tool":
			receipt := sqlReceipt
			if scenario == "forged" {
				receipt = "sha256:" + strings.Repeat("c", 64)
			}
			arguments, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{map[string]any{
				// Card D-6a: the answer is prose, so it names no raw relation or
				// column; the live read carries the technical location.
				"text":       "There are 42 registered contracts.",
				"citations":  []any{},
				"live_reads": []any{map[string]any{"result_id": sqlAttempt, "receipt_digest": receipt}},
			}}})
			toolCall("submit-1", "submit_answer", string(arguments))
		default:
			toolCall("sql-fallback", "knowvault_source_sql", `{"source_id":"`+sourceSQLToolLoopSourceID+`","sql":"SELECT count(*) FROM public.contracts"}`)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "sql-tool-loop-fixture",
			"choices": []any{map[string]any{"message": message, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
	}))
	defer model.Close()
	adapter := sourceSQLToolLoopAdapter(t, model.URL, "sql-tool-loop-fixture")
	questions.EnableGeneration(adapter, nil)

	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_sql_tool_loop"}
	questionKey := func(marker byte) string {
		key := make([]byte, 32)
		key[0] = marker
		return base64.RawURLEncoding.EncodeToString(key)
	}

	t.Run("a citing answer completes with a source-bound live result", func(t *testing.T) {
		scenario = "answer"
		sources.calls = 0
		run, err := questions.Create(ctx, access, question.CreateRequest{
			WorkspaceID: s1dWorkspace, Question: "How many contracts are registered?",
			IdempotencyKey: questionKey(0x71),
		})
		if err != nil {
			logQuestionCauses(t, err)
			t.Fatalf("create run: %v (%s)", err, question.CodeOf(err))
		}
		if run.ResultStatus != "COMPLETED" || run.ToolLoop == nil || !run.ToolLoop.AllClaimsBound || run.ToolLoop.StopReason != "ANSWER" {
			t.Fatalf("run = %+v", run)
		}
		if sources.calls != 1 || sources.lastSQL != "SELECT count(*) FROM public.contracts" {
			t.Fatalf("SQL calls = %d last = %q", sources.calls, sources.lastSQL)
		}
		if run.AnswerResult == nil || run.AnswerResult.Kind != "LIVE_TABLE" || run.AnswerResult.SourceID != sourceSQLToolLoopSourceID ||
			run.AnswerResult.ResultDigest == "" || run.AnswerResult.ReceiptDigest == "" {
			t.Fatalf("UI live result = %#v", run.AnswerResult)
		}
		if len(run.ToolLoop.Calls) != 2 || run.ToolLoop.Calls[0].Name != "knowvault_source_schema" || run.ToolLoop.Calls[1].Name != "knowvault_source_sql" {
			t.Fatalf("calls = %#v", run.ToolLoop.Calls)
		}
		if !strings.Contains(run.ToolLoop.Calls[1].Result.Text, `"receipt_digest"`) {
			t.Fatalf("the model never received a citable receipt: %s", run.ToolLoop.Calls[1].Result.Text)
		}
	})

	t.Run("a forged receipt is rejected", func(t *testing.T) {
		scenario = "forged"
		sources.calls = 0
		run, err := questions.Create(ctx, access, question.CreateRequest{
			WorkspaceID: s1dWorkspace, Question: "How many contracts are registered?",
			IdempotencyKey: questionKey(0x72),
		})
		if err != nil {
			t.Fatalf("create forged run: %v", err)
		}
		if run.ResultStatus != "INSUFFICIENT_EVIDENCE" || run.ToolLoop == nil || run.ToolLoop.StopReason != "CITATIONS_UNVERIFIED" ||
			run.AnswerResult != nil {
			t.Fatalf("forged run = %+v result=%#v", run.ToolLoop, run.AnswerResult)
		}
	})

	t.Run("the fourth SQL statement is refused", func(t *testing.T) {
		scenario = "limit"
		sources.calls = 0
		run, err := questions.Create(ctx, access, question.CreateRequest{
			WorkspaceID: s1dWorkspace, Question: "How many contracts are registered?",
			IdempotencyKey: questionKey(0x73),
		})
		if err != nil {
			t.Fatalf("create limit run: %v", err)
		}
		refused := 0
		succeeded := 0
		for _, call := range run.ToolLoop.Calls {
			if call.Name != "knowvault_source_sql" {
				continue
			}
			if call.Outcome == "REFUSED" && strings.Contains(call.Result.Text, "SQL_LIMIT_REACHED") {
				refused++
			}
			if call.Outcome == "SUCCEEDED" {
				succeeded++
			}
		}
		if sources.calls != 3 || succeeded != 3 || refused != 1 {
			t.Fatalf("SQL budget: provider=%d succeeded=%d refused=%d", sources.calls, succeeded, refused)
		}
		if run.ResultStatus != "COMPLETED" || run.AnswerResult == nil || run.AnswerResult.Kind != "LIVE_TABLE" {
			t.Fatalf("limit run = %+v result=%#v", run.ToolLoop, run.AnswerResult)
		}
	})
}

var sqlReceiptPattern = regexp.MustCompile(`"attempt_id":"([^"]+)"`)

func logQuestionCauses(t *testing.T, err error) {
	t.Helper()
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(cause) {
		t.Logf("cause: %v", cause)
	}
}

// containsLimitRefusal reports whether the model has already been told the SQL
// budget is exhausted, so the scripted run stops issuing statements and answers
// from the results it already holds.
func containsLimitRefusal(messages []modelgateway.Message) bool {
	for _, message := range messages {
		if message.Role == "tool" && strings.Contains(message.Content, "SQL_LIMIT_REACHED") {
			return true
		}
	}
	return false
}

var sqlDigestPattern = regexp.MustCompile(`"receipt_digest":"(sha256:[0-9a-f]{64})"`)

// lastSQLReceipt returns the most recent SQL attempt id and receipt digest the
// model was shown, so the scripted answer can cite exactly what the server
// produced.
func lastSQLReceipt(messages []modelgateway.Message) (string, string) {	attempt, digest := "", ""
	for _, message := range messages {
		if message.Role != "tool" {
			continue
		}
		if match := sqlReceiptPattern.FindStringSubmatch(message.Content); match != nil {
			attempt = match[1]
		}
		if match := sqlDigestPattern.FindStringSubmatch(message.Content); match != nil {
			digest = match[1]
		}
	}
	return attempt, digest
}
