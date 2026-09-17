package workspaceapi

// R2 Outcome 2 transport tests: a typed QueryIntent refusal is produced by the
// server-side gate/executor over a workspace that holds an APPROVED
// MetricDefinition, together with a server-owned, closed-dictionary
// clarification (question.ClarificationOf). These tests prove that the
// production *question.Error{code: CodeInvalid} refusal maps to REST's
// 400 REQUEST_INVALID (and not the generic 503/SERVICE_UNAVAILABLE a raw
// transport error used to get) while the clarification survives both
// transports unchanged -- the REST JSON error envelope's additive
// error.clarification member and the MCP JSON-RPC error's additive
// error.data.clarification member -- and that every error without one keeps
// exactly its pre-R2 body.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/question"
)

// clarificationApprovalAuditor satisfies metricdef's approval/retirement
// boundary without persistence: the test only needs a real APPROVED definition
// value, not an audited store.
type clarificationApprovalAuditor struct{}

func (clarificationApprovalAuditor) RecordApproval(metricdef.ApprovalEvent) error   { return nil }
func (clarificationApprovalAuditor) RecordRetirement(metricdef.RetirementEvent) error { return nil }

func clarificationSeries(t *testing.T, id string, filters []string) metricdef.Series {
	t.Helper()
	series, err := metricdef.NewSeries(id, "ws_alpha", "usr_alice", metricdef.Spec{
		Name:           "Metric " + id,
		Source:         metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 1},
		EntityKey:      "order_id",
		Grain:          metricdef.GrainMonth,
		Unit:           "RUB",
		AllowedFilters: filters,
	})
	if err != nil {
		t.Fatalf("metricdef.NewSeries(%q) = %v", id, err)
	}
	return series
}

// clarificationDefinitionCatalog is the access-re-checked definition lister the
// production gate/executor reads. It carries no workspace filtering of its own
// because the unit test supplies the single workspace's definitions directly.
type clarificationDefinitionCatalog struct {
	definitions []metricdef.Definition
}

func (catalog *clarificationDefinitionCatalog) List(_ context.Context, _ database.AccessContext, _ string) ([]metricdef.Definition, error) {
	return catalog.definitions, nil
}

func clarificationQuestionAccess() database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_alpha",
		PrincipalID:    "usr_alice",
		RequestID:      "req_clarification_test",
		ActorKind:      database.ActorKindHuman,
	}
}

// testProductionIntentRefusal drives the production sealed-intent executor over
// a workspace that holds an APPROVED MetricDefinition. The sealed intent was
// validated against md_legacy while it was APPROVED; at execution time the
// executor's own re-check sees that exact version RETIRED and fails closed with
// the authority's typed *question.Error{code: CodeInvalid} plus a server-owned
// clarification -- exactly the production error object the transports map,
// never a raw queryintent error handed to the fake.
func testProductionIntentRefusal(t *testing.T) error {
	t.Helper()

	approvedLegacy, err := clarificationSeries(t, "md_legacy", nil).
		Approve("usr_alice", clarificationApprovalAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Approve(md_legacy) = %v", err)
	}
	approvedRevenue, err := clarificationSeries(t, "md_revenue", []string{"region"}).
		Approve("usr_alice", clarificationApprovalAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Approve(md_revenue) = %v", err)
	}
	retiredLegacy, err := approvedLegacy.Retire("usr_alice", clarificationApprovalAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Retire(md_legacy) = %v", err)
	}

	// Seal a real intent for md_legacy v1 while it is APPROVED.
	validator, err := queryintent.NewValidator("ws_alpha", queryintent.CatalogFunc(
		func(catalogWorkspaceID, metricID string) ([]metricdef.Definition, bool) {
			if catalogWorkspaceID != "ws_alpha" || metricID != "md_legacy" {
				return nil, false
			}
			return []metricdef.Definition{approvedLegacy.Current()}, true
		}))
	if err != nil {
		t.Fatalf("queryintent.NewValidator: %v", err)
	}
	intent, refusal := validator.Validate(queryintent.Proposal{
		MetricID: "md_legacy",
		Version:  1,
		Period: queryintent.Period{
			Grain: metricdef.GrainMonth,
			Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		Output: queryintent.OutputValue,
		AsOf:   time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
	})
	if refusal != nil {
		t.Fatalf("validator.Validate(approved md_legacy) = %v, want a sealed intent", refusal)
	}

	// The execution-time catalog holds an APPROVED definition (md_revenue) and
	// the now-RETIRED md_legacy version the intent names: the production
	// executor's re-check must refuse rather than execute a stale binding.
	service := &question.Service{}
	service.EnableQueryIntents(&clarificationDefinitionCatalog{
		definitions: []metricdef.Definition{approvedRevenue.Current(), retiredLegacy.Current()},
	}, nil, nil)

	_, execErr := question.NewServiceIntentExecutor(service).ExecuteIntent(
		context.Background(), clarificationQuestionAccess(),
		question.IntentExecutionRequest{WorkspaceID: "ws_alpha", Intent: intent})
	if execErr == nil {
		t.Fatal("production executor executed a retired definition version; want a typed refusal")
	}
	if question.CodeOf(execErr) != question.CodeInvalid {
		t.Fatalf("production refusal code = %q, want %q", question.CodeOf(execErr), question.CodeInvalid)
	}
	if question.ClarificationOf(execErr) == "" {
		t.Fatal("production refusal carries no clarification text")
	}
	return execErr
}

// clarificationValidatorRefusal is one validator-produced refusal: the exact
// closed-dictionary clarification literal and the real *queryintent.Error the
// transports relay.
type clarificationValidatorRefusal struct {
	name          string
	clarification string
	refusal       error
}

// clarificationValidatorRefusals drives the production queryintent.Validator
// over an owner-approved catalog and returns the three model-proposal refusals
// this work package covers: an unknown metric id, a filter outside the
// APPROVED definition's allowed_filters, and a malformed period (grain
// mismatch). Each returned refusal is the real *queryintent.Error the server
// seals a proposal into, asserted here against its literal closed-dictionary
// text so the transport tests below compare the wire body to the dictionary
// itself, never to a value they computed from the same accessor.
func clarificationValidatorRefusals(t *testing.T) []clarificationValidatorRefusal {
	t.Helper()

	approvedRevenue, err := clarificationSeries(t, "md_revenue", []string{"region"}).
		Approve("usr_alice", clarificationApprovalAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Approve(md_revenue) = %v", err)
	}
	approvedLegacy, err := clarificationSeries(t, "md_legacy", nil).
		Approve("usr_alice", clarificationApprovalAuditor{}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("Approve(md_legacy) = %v", err)
	}
	validator, err := queryintent.NewValidator("ws_alpha", queryintent.CatalogFunc(
		func(workspaceID, metricID string) ([]metricdef.Definition, bool) {
			if workspaceID != "ws_alpha" {
				return nil, false
			}
			switch metricID {
			case "md_revenue":
				return []metricdef.Definition{approvedRevenue.Current()}, true
			case "md_legacy":
				return []metricdef.Definition{approvedLegacy.Current()}, true
			default:
				return nil, false
			}
		}))
	if err != nil {
		t.Fatalf("queryintent.NewValidator: %v", err)
	}

	base := queryintent.Proposal{
		MetricID: "md_revenue",
		Version:  1,
		Period: queryintent.Period{
			Grain: metricdef.GrainMonth,
			Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			End:   time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		Output: queryintent.OutputValue,
		AsOf:   time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC),
	}
	unknownMetric := base
	unknownMetric.MetricID = "md_missing"
	disallowedFilter := base
	disallowedFilter.Filters = []string{"salary"}
	malformedPeriod := base
	malformedPeriod.Period.Grain = metricdef.GrainDay

	cases := []struct {
		name          string
		code          queryintent.ErrorCode
		clarification string
		proposal      queryintent.Proposal
	}{
		{
			name:          "unknown metric",
			code:          queryintent.CodeUnknownMetric,
			clarification: "No metric definition with this id exists in this workspace. Choose an existing metric.",
			proposal:      unknownMetric,
		},
		{
			name:          "disallowed filter",
			code:          queryintent.CodeFilterNotAllowed,
			clarification: "One or more requested filters are not allowed by this metric definition. Remove them or use an allowed filter.",
			proposal:      disallowedFilter,
		},
		{
			name:          "malformed period",
			code:          queryintent.CodeMalformedPeriod,
			clarification: "The requested period is missing or does not match this metric definition's grain. Provide a start and end that match the definition grain.",
			proposal:      malformedPeriod,
		},
	}

	refusals := make([]clarificationValidatorRefusal, 0, len(cases))
	for _, testCase := range cases {
		intent, refusal := validator.Validate(testCase.proposal)
		if refusal == nil {
			t.Fatalf("validator.Validate(%s) sealed %#v; want the typed refusal", testCase.name, intent)
		}
		// A refusal never yields a sealed intent, so there is no execution
		// input: the proposal cannot reach the executor or fall back to a
		// free-text plan.
		if intent != (queryintent.Intent{}) {
			t.Fatalf("validator.Validate(%s) returned intent %#v on refusal; want the zero intent", testCase.name, intent)
		}
		if got := queryintent.CodeOf(refusal); got != testCase.code {
			t.Fatalf("queryintent.CodeOf(%s) = %q, want %q", testCase.name, got, testCase.code)
		}
		var typed *queryintent.Error
		if !errors.As(refusal, &typed) {
			t.Fatalf("validator.Validate(%s) = %T, want *queryintent.Error", testCase.name, refusal)
		}
		if typed.Clarification() != testCase.clarification {
			t.Fatalf("refusal clarification(%s) = %q, want the closed-dictionary literal %q", testCase.name, typed.Clarification(), testCase.clarification)
		}
		if got := question.ClarificationOf(refusal); got != testCase.clarification {
			t.Fatalf("question.ClarificationOf(%s) = %q, want %q", testCase.name, got, testCase.clarification)
		}
		refusals = append(refusals, clarificationValidatorRefusal{
			name:          testCase.name,
			clarification: testCase.clarification,
			refusal:       refusal,
		})
	}
	return refusals
}

// TestRESTValidatorQueryIntentRefusalsCarryDictionaryClarification proves that
// each validator-produced refusal -- unknown metric, disallowed filter,
// malformed period -- reaches a REST client with the exact closed-dictionary
// clarification under the additive error.clarification member, while the
// status and error code stay the unchanged pre-R2 SERVICE_UNAVAILABLE mapping
// a non-question refusal always had. A plain error keeps a body with no
// clarification member at all.
func TestRESTValidatorQueryIntentRefusalsCarryDictionaryClarification(t *testing.T) {
	for _, refusal := range clarificationValidatorRefusals(t) {
		t.Run(refusal.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.questions.err = refusal.refusal

			request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
			request.Header.Set("Content-Type", jsonContentType)
			harness.mutationHeaders(request, harness.hash)
			request.Header.Del("If-Match")
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("refused question status=%d body=%s, want the unchanged 503", response.Code, response.Body.String())
			}
			var body struct {
				Error struct {
					Code          string `json:"code"`
					Clarification string `json:"clarification"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("refused question body did not decode: err=%v body=%s", err, response.Body.String())
			}
			if body.Error.Code != "SERVICE_UNAVAILABLE" {
				t.Fatalf("refused question code=%q body=%s, want SERVICE_UNAVAILABLE", body.Error.Code, response.Body.String())
			}
			if body.Error.Clarification != refusal.clarification {
				t.Fatalf("error.clarification=%q, want the closed-dictionary literal %q (body=%s)", body.Error.Clarification, refusal.clarification, response.Body.String())
			}
		})
	}

	// Negative control: a plain non-refusal error keeps the exact pre-R2 503
	// body, so the additive member never appears without a typed refusal.
	harness := newTestHarness(t)
	harness.questions.err = errors.New("plain failure")
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "clarification") {
		t.Fatalf("plain error status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestMCPValidatorQueryIntentRefusalsCarryDictionaryClarification proves the
// same three validator refusals reach an agent client through the JSON-RPC
// error's additive data.clarification member, with code -32000 and message
// "question unavailable" unchanged, so the browser and an agent show exactly
// the same server-owned text. A plain error keeps the data-less object.
func TestMCPValidatorQueryIntentRefusalsCarryDictionaryClarification(t *testing.T) {
	for _, refusal := range clarificationValidatorRefusals(t) {
		t.Run(refusal.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.questions.err = refusal.refusal

			request := harness.request(http.MethodPost, apiPrefix+"/mcp",
				"{\"jsonrpc\":\"2.0\",\"id\":\"q1\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_question\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"question\":\"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?\"}}}")
			request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("MCP refused question status=%d body=%s", response.Code, response.Body.String())
			}
			var envelope struct {
				Error *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
					Data    *struct {
						Clarification string `json:"clarification"`
					} `json:"data"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error == nil {
				t.Fatalf("MCP refused question did not decode: err=%v body=%s", err, response.Body.String())
			}
			if envelope.Error.Code != -32000 || envelope.Error.Message != "question unavailable" {
				t.Fatalf("MCP error code/message=%d/%q, want -32000/question unavailable", envelope.Error.Code, envelope.Error.Message)
			}
			if envelope.Error.Data == nil || envelope.Error.Data.Clarification != refusal.clarification {
				t.Fatalf("MCP error data=%#v, want the closed-dictionary literal %q (body=%s)", envelope.Error.Data, refusal.clarification, response.Body.String())
			}
		})
	}

	// Negative control: a plain non-refusal error keeps the data-less pre-R2
	// error object.
	harness := newTestHarness(t)
	harness.questions.err = errors.New("plain failure")
	plain := harness.request(http.MethodPost, apiPrefix+"/mcp",
		"{\"jsonrpc\":\"2.0\",\"id\":\"q1\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_question\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"question\":\"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?\"}}}")
	plain.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, plain)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "clarification") {
		t.Fatalf("plain MCP error status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestRESTQuestionErrorCarriesQueryIntentClarification proves a refusal
// produced by the production gate/executor maps to the typed
// 400 REQUEST_INVALID -- never the generic 503/SERVICE_UNAVAILABLE a raw
// transport error used to get -- while the server-owned clarification reaches
// the REST client additively and an error without a clarification omits the
// member entirely (backward-compatible body).
func TestRESTQuestionErrorCarriesQueryIntentClarification(t *testing.T) {
	harness := newTestHarness(t)
	refusal := testProductionIntentRefusal(t)
	clarification := question.ClarificationOf(refusal)
	harness.questions.err = refusal

	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("refused question status=%d body=%s, want 400 REQUEST_INVALID", response.Code, response.Body.String())
	}
	var body struct {
		Error struct {
			Code          string `json:"code"`
			RequestID     string `json:"request_id"`
			Clarification string `json:"clarification"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("refused question body did not decode: err=%v body=%s", err, response.Body.String())
	}
	if body.Error.Code != "REQUEST_INVALID" {
		t.Fatalf("refused question code=%q body=%s, want REQUEST_INVALID", body.Error.Code, response.Body.String())
	}
	if body.Error.Clarification != clarification {
		t.Fatalf("error.clarification=%q, want %q (body=%s)", body.Error.Clarification, clarification, response.Body.String())
	}

	// Negative control: an error that carries no clarification must not gain a
	// clarification member, so every pre-R2 error body is unchanged. A plain
	// non-refusal error keeps the generic 503 mapping.
	harness.questions.err = errors.New("plain failure")
	plain := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
	plain.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(plain, harness.hash)
	plain.Header.Del("If-Match")
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, plain)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "clarification") {
		t.Fatalf("plain error status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestMCPQuestionErrorCarriesQueryIntentClarification proves the same
// production refusal text reaches an agent client under the JSON-RPC error's
// additive data member, with the message and code unchanged, and that a plain
// error keeps the exact pre-R2 error object.
func TestMCPQuestionErrorCarriesQueryIntentClarification(t *testing.T) {
	harness := newTestHarness(t)
	refusal := testProductionIntentRefusal(t)
	clarification := question.ClarificationOf(refusal)
	harness.questions.err = refusal

	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		"{\"jsonrpc\":\"2.0\",\"id\":\"q1\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_question\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"question\":\"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?\"}}}")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("MCP refused question status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    *struct {
				Clarification string `json:"clarification"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error == nil {
		t.Fatalf("MCP refused question did not decode: err=%v body=%s", err, response.Body.String())
	}
	if envelope.Error.Code != -32000 || envelope.Error.Message != "question unavailable" {
		t.Fatalf("MCP error code/message=%d/%q, want -32000/question unavailable", envelope.Error.Code, envelope.Error.Message)
	}
	if envelope.Error.Data == nil || envelope.Error.Data.Clarification != clarification {
		t.Fatalf("MCP error data=%#v, want clarification %q (body=%s)", envelope.Error.Data, clarification, response.Body.String())
	}

	// Negative control: a plain error keeps the error object with no data member.
	harness.questions.err = errors.New("plain failure")
	plain := harness.request(http.MethodPost, apiPrefix+"/mcp",
		"{\"jsonrpc\":\"2.0\",\"id\":\"q1\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_question\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"question\":\"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?\"}}}")
	plain.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, plain)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "clarification") {
		t.Fatalf("plain MCP error status=%d body=%s", response.Code, response.Body.String())
	}
}
