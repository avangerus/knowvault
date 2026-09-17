package workspaceapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

type governedTransportProbe struct {
	workspace, connection, question string
	calls                           int
	result                          governedask.AskResult
}

func (p *governedTransportProbe) SetLiveQueries(_ context.Context, _ database.AccessContext, w, c string, _ bool) error {
	p.workspace, p.connection = w, c
	p.calls++
	return nil
}
func (p *governedTransportProbe) RegisterExposedSchema(_ context.Context, _ database.AccessContext, w, c string, _ []governedquery.ExposedObject) (int64, error) {
	p.workspace, p.connection = w, c
	p.calls++
	return 1, nil
}
func (p *governedTransportProbe) Ask(_ context.Context, _ database.AccessContext, w, c, q string) (governedask.AskResult, error) {
	p.workspace, p.connection, p.question = w, c, q
	p.calls++
	return p.result, nil
}
func (p *governedTransportProbe) Promote(_ context.Context, _ database.AccessContext, w, c, _, _ string) (governedquery.PromotionResult, error) {
	p.workspace, p.connection = w, c
	p.calls++
	return governedquery.PromotionResult{}, nil
}

func TestGovernedQueryTransportsPreserveConnectionAndCompleteResult(t *testing.T) {
	h := newTestHarness(t)
	number, empty := "9007199254740993.123456789", ""
	p := &governedTransportProbe{result: governedask.AskResult{
		AttemptID: "attempt", SQL: "SELECT amount, missing, empty FROM example", SQLHash: "sha256:sql",
		Columns: []string{"amount", "missing", "empty"}, Rows: [][]*string{{&number, nil, &empty}}, RowCount: 1,
		Answer: "One row", ConnectionID: "conn_requested", DatabaseIdentity: "fixture", ExposedSchemaRevision: 2,
		ResultFormat: "postgres-text-table-v1", ResultDigest: "sha256:result",
		ExecutionStartedAt: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC), ExecutionCompletedAt: time.Date(2026, 9, 15, 12, 0, 1, 0, time.UTC),
	}}
	h.handler.EnableGovernedQuery(p)
	for _, tc := range []struct{ suffix, body string }{
		{":ask", `{"question":"how many?"}`},
		{":set-live-queries", `{"enabled":true}`},
		{"/exposed-schema", `{"objects":[{"schema_name":"example","table_name":"items","description":"Items","columns":[]}]}`},
		{":promote", `{"attempt_id":"attempt","sql_hash":"sha256:result"}`},
	} {
		req := h.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/governed-query-connections/conn_requested"+tc.suffix, tc.body)
		h.mutationHeaders(req, h.hash)
		req.Header.Del("If-Match")
		rr := httptest.NewRecorder()
		h.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || p.connection != "conn_requested" || p.workspace != "ws_alpha" {
			t.Fatalf("%s: %d %s, probe %+v", tc.suffix, rr.Code, rr.Body, p)
		}
		if tc.suffix == ":ask" {
			var body struct {
				Result governedask.AskResult `json:"result"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || !reflect.DeepEqual(body.Result, p.result) {
				t.Fatalf("REST changed result: %s", rr.Body)
			}
		}
	}
	p.connection = ""
	req := h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"sql","method":"tools/call","params":{"name":"knowvault_governed_query_ask","arguments":{"workspace_id":"ws_alpha","connection_id":"conn_requested","question":"how many?"}}}`)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Structured governedask.AskResult `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil || len(envelope.Result.Content) != 1 || p.connection != "conn_requested" || p.question != "how many?" {
		t.Fatalf("MCP failed: %s", rr.Body)
	}
	var textResult governedask.AskResult
	if err := json.Unmarshal([]byte(envelope.Result.Content[0].Text), &textResult); err != nil || !reflect.DeepEqual(textResult, p.result) || !reflect.DeepEqual(envelope.Result.Structured, p.result) {
		t.Fatalf("MCP lost SQL table/provenance: %s", rr.Body)
	}
}
