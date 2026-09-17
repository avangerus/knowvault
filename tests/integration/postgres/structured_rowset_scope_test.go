package postgres_test

// FIX-7 #1, real-PostgreSQL end to end. StructuredRowset used to hard-return
// the ENTIRE current snapshot of a fragment's source scope, regardless of
// what filter the citing answer actually applied -- an owner asking "how
// many machines" and getting "3" would open that citation's basis panel and
// see every row the source has ever had, not the 3 that gave the answer.
//
// This test drives the real production pipeline (registration -> authority
// confirm -> ingestion -> a real aggregate question over a real external
// PostgreSQL projection, exactly like the AGG-2 regression in
// snapshot_aggregate_workspace_binding_test.go) with THREE rows, two of which
// match an explicit equality filter and one that does not, then asks
// question.Service.StructuredRowset directly for one of the resulting
// citations: by default (RowsetScopeMatched) it must return exactly the two
// matched rows and a filter_label naming the filter actually applied; asked
// for RowsetScopeFull it must return all three.
import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
)

func TestStructuredRowsetDefaultsToMatchedRowsAndFullIsExplicit(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live FIX-7 #1 rowset-scope proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_rowset_scope"
	// Truncated to milliseconds: the projection's collected_at column is
	// contracted at Precision:3 (matching isolationProjectionRequest), and
	// postgresqlquery.timestampValue rejects a real wall-clock value whose
	// sub-millisecond digits are non-zero.
	collected := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_rowset_scope" CASCADE;
		CREATE SCHEMA "kv_pgq_rowset_scope";
		CREATE TABLE "kv_pgq_rowset_scope"."fleet_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`); err != nil {
		t.Fatalf("seed external rowset-scope table: %v", err)
	}
	rows := []struct {
		id     string
		tonnes string
		note   string
	}{
		{"550e8400-e29b-41d4-a716-446655440060", "10.000", "target-note"},
		{"550e8400-e29b-41d4-a716-446655440061", "15.000", "target-note"},
		{"550e8400-e29b-41d4-a716-446655440062", "7.000", "other-note"},
	}
	for _, row := range rows {
		if _, err := external.Exec(ctx, `INSERT INTO "kv_pgq_rowset_scope"."fleet_data" VALUES ($1, $2, $3, $4)`,
			row.id, collected, row.tonnes, row.note); err != nil {
			t.Fatalf("seed row %s: %v", row.id, err)
		}
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_rowset_scope"."fleet_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_rowset_scope"."fleet_data";
	`); err != nil {
		t.Fatalf("create external rowset-scope view: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_rowset_scope" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	request := isolationProjectionRequest(schema, "fleet_view", "rowset-scope-lineage", "FIX-7 rowset scope fleet", "sha256:"+strings.Repeat("f", 64))
	source, err := service.Register(ctx, regOwnerAccess("req_rowset_register"), request)
	if err != nil {
		t.Fatalf("register projection: %v (code=%s)", err, registration.CodeOf(err))
	}
	verifyIsolationTrust(t, ctx, admin, source.ConnectionID)

	authority := newAuthorityRuntime(t, ctx)
	bindingID := agg2StableWorkspaceSourceID(regOrg, regWorkspace, source.SourceScopeID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, source.SourceScopeID, source.ScopeConfigHash, bindingID)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "rowset-scope-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_rowset_confirm"), confirmRuntimeRequest(binding, grant, "rowset-scope-confirm")); err != nil {
		t.Fatalf("confirm workspace source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, source, request, "rowset-scope")

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
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_rowset_question"}
	run, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: "\u041a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a, note = \"target-note\"?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: isolationQuestionKey("rowset-scope-question"),
	})
	if err != nil {
		t.Fatalf("aggregate question: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "COMPLETED" || run.AnswerResult == nil || run.AnswerResult.Operation != "COUNT" || run.AnswerResult.Value != "2" || !strings.HasPrefix(run.Answer, "Answer: 2.") || !strings.Contains(run.Answer, "Selection: note = target-note") {
		t.Fatalf("run=%#v, want explicit COUNT=2 over the target-note rows", run)
	}
	if len(run.Citations) != 2 {
		t.Fatalf("citations=%d, want exactly the two matched rows", len(run.Citations))
	}
	fragmentID := run.Citations[0].EvidenceFragment

	matched, err := questions.StructuredRowset(ctx, access, regWorkspace, fragmentID, "")
	if err != nil {
		t.Fatalf("StructuredRowset(default): %v", err)
	}
	if matched == nil {
		t.Fatal("StructuredRowset(default) = nil, want the matched rowset")
	}
	if matched.Total != 2 || len(matched.Rows) != 2 {
		t.Fatalf("default scope rowset=%#v, want exactly the 2 matched rows (not the whole 3-row snapshot)", matched)
	}
	for _, row := range matched.Rows {
		if row["note"] != "target-note" {
			t.Fatalf("default scope rowset leaked a non-matched row: %#v", row)
		}
	}
	if !strings.Contains(matched.FilterLabel, "note") || !strings.Contains(matched.FilterLabel, "target-note") {
		t.Fatalf("filter_label=%q, want it to name the applied filter (note = target-note)", matched.FilterLabel)
	}
	if matched.Snapshot.RowCount != 3 {
		t.Fatalf("matched.Snapshot.RowCount=%d, want 3 (the full source scope's own size, unaffected by scope)", matched.Snapshot.RowCount)
	}

	full, err := questions.StructuredRowset(ctx, access, regWorkspace, fragmentID, question.RowsetScopeFull)
	if err != nil {
		t.Fatalf("StructuredRowset(full): %v", err)
	}
	if full == nil || full.Total != 3 || len(full.Rows) != 3 {
		t.Fatalf("full scope rowset=%#v, want all 3 rows of the source scope's current snapshot", full)
	}
	seenNotes := map[string]bool{}
	for _, row := range full.Rows {
		seenNotes[row["note"]] = true
	}
	if !seenNotes["target-note"] || !seenNotes["other-note"] {
		t.Fatalf("full scope rowset=%#v, missing an expected note value", full)
	}

	if _, err := questions.StructuredRowset(ctx, access, regWorkspace, fragmentID, "bogus"); question.CodeOf(err) != question.CodeInvalid {
		t.Fatalf("unknown scope value: err=%v code=%s, want CodeInvalid", err, question.CodeOf(err))
	}

	// The same real PostgreSQL-backed Question service must feed both public
	// adapters through one authorized projection. This catches transport drift
	// where REST includes the matched rowset but MCP silently drops it.
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("conversation service: %v", err)
	}
	authenticator, err := httpauth.New(r22TenantResolver{}, r22SessionResolver{claims: r22Claims(t, regOwner)})
	if err != nil {
		t.Fatalf("workspace auth: %v", err)
	}
	apiHandler, err := workspaceapi.NewWithQuestionsAndConversations(
		authenticator, authority,
		r22SourceService{registrations: service, workspaces: authority},
		viewer, questions, conversations,
	)
	if err != nil {
		t.Fatalf("workspace handler: %v", err)
	}
	rawToken := make([]byte, sha256.Size)
	for index := range rawToken {
		rawToken[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	csrf, err := (r22Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("csrf proof: %v", err)
	}
	restRequest := httptest.NewRequest(http.MethodGet, "https://workspace.example/api/v1/workspaces/"+regWorkspace+"/evidence/"+fragmentID, nil)
	restRequest.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	restResponse := httptest.NewRecorder()
	apiHandler.ServeHTTP(restResponse, restRequest)
	if restResponse.Code != http.StatusOK {
		t.Fatalf("REST evidence status=%d body=%s", restResponse.Code, restResponse.Body.String())
	}
	var restProjection map[string]any
	if err := jsonv2.Unmarshal(restResponse.Body.Bytes(), &restProjection); err != nil {
		t.Fatalf("decode REST evidence projection: %v", err)
	}
	if _, ok := restProjection["rowset"]; !ok {
		t.Fatalf("REST evidence omitted real matched rowset: %#v", restProjection)
	}
	mcpBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "rowset-parity", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_evidence_get", "arguments": map[string]any{
			"workspace_id": regWorkspace, "fragment_id": fragmentID,
		}},
	})
	if err != nil {
		t.Fatalf("marshal MCP evidence request: %v", err)
	}
	mcpRequest := httptest.NewRequest(http.MethodPost, "https://workspace.example/api/v1/mcp", strings.NewReader(string(mcpBody)))
	mcpRequest.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	mcpRequest.Header.Set("Content-Type", "application/json")
	mcpRequest.Header.Set("Origin", "https://workspace.example")
	mcpRequest.Header.Set(httpauth.CSRFHeader, csrf.Value())
	mcpResponse := httptest.NewRecorder()
	apiHandler.ServeHTTP(mcpResponse, mcpRequest)
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP evidence status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	var mcpEnvelope r22MCPResponse
	if err := jsonv2.Unmarshal(mcpResponse.Body.Bytes(), &mcpEnvelope); err != nil {
		t.Fatalf("decode MCP evidence envelope: %v", err)
	}
	if mcpEnvelope.Error != nil || len(mcpEnvelope.Result.StructuredContent) == 0 {
		t.Fatalf("MCP evidence failed or omitted projection: %+v", mcpEnvelope)
	}
	var mcpProjection map[string]any
	if err := jsonv2.Unmarshal(mcpEnvelope.Result.StructuredContent, &mcpProjection); err != nil {
		t.Fatalf("decode MCP evidence projection: %v", err)
	}
	if !reflect.DeepEqual(restProjection, mcpProjection) {
		t.Fatalf("real PostgreSQL REST/MCP evidence projections differ\nREST: %#v\nMCP:  %#v", restProjection, mcpProjection)
	}
}
