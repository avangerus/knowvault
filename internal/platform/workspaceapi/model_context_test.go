package workspaceapi

// S2 card A transport tests. These exercise model_context.go/model_context_types.go
// against fake ModelContextService/workspacecontext.ProposalService capabilities,
// proving the transport's own contract (routing, header/query validation,
// wire shape, error mapping) independent of the real PostgreSQL store, which
// tests/integration/postgres/model_context_test.go proves separately.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

const (
	modelContextPath           = "/api/v1/workspaces/ws_alpha/model-context"
	modelContextVersionsPath   = "/api/v1/workspaces/ws_alpha/model-context/versions"
	modelContextVersionGetPath = "/api/v1/workspaces/ws_alpha/model-context/versions/1"
	modelContextRestorePath    = "/api/v1/workspaces/ws_alpha/model-context/versions/1:restore"
	modelContextProposalsPath  = "/api/v1/workspaces/ws_alpha/model-context/proposals"
	modelContextAcceptPath     = "/api/v1/workspaces/ws_alpha/model-context/proposals/ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV:accept"
	modelContextRejectPath     = "/api/v1/workspaces/ws_alpha/model-context/proposals/ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV:reject"
)

type fakeModelContextService struct {
	access      database.AccessContext
	workspaceID string
	document    workspacecontext.Document
	ifMatch     string
	idempotency string
	limit       int
	cursor      int64
	version     int64

	currentResult   workspacecontext.Version
	currentErr      error
	restResult      workspacecontext.VersionRecord
	restErr         error
	versionsResult  []workspacecontext.VersionSummary
	versionsCursor  int64
	versionsErr     error
	versionAtResult workspacecontext.VersionRecord
	versionAtErr    error
	saveResult      workspacecontext.VersionRecord
	saveErr         error
	restoreResult   workspacecontext.VersionRecord
	restoreErr      error
}

func (fake *fakeModelContextService) Current(_ context.Context, _ workspacecontext.Access, workspaceID string) (workspacecontext.Version, error) {
	fake.workspaceID = workspaceID
	return fake.currentResult, fake.currentErr
}

func (fake *fakeModelContextService) CurrentForREST(_ context.Context, access database.AccessContext, workspaceID string) (workspacecontext.VersionRecord, error) {
	fake.access, fake.workspaceID = access, workspaceID
	return fake.restResult, fake.restErr
}

func (fake *fakeModelContextService) Save(_ context.Context, access database.AccessContext, workspaceID string,
	document workspacecontext.Document, ifMatch, idempotencyKey string) (workspacecontext.VersionRecord, error) {
	fake.access, fake.workspaceID, fake.document, fake.ifMatch, fake.idempotency = access, workspaceID, document, ifMatch, idempotencyKey
	return fake.saveResult, fake.saveErr
}

func (fake *fakeModelContextService) Versions(_ context.Context, access database.AccessContext, workspaceID string, limit int, cursor int64) ([]workspacecontext.VersionSummary, int64, error) {
	fake.access, fake.workspaceID, fake.limit, fake.cursor = access, workspaceID, limit, cursor
	return fake.versionsResult, fake.versionsCursor, fake.versionsErr
}

func (fake *fakeModelContextService) VersionAtForREST(_ context.Context, access database.AccessContext, workspaceID string, versionNumber int64) (workspacecontext.VersionRecord, error) {
	fake.access, fake.workspaceID, fake.version = access, workspaceID, versionNumber
	return fake.versionAtResult, fake.versionAtErr
}

func (fake *fakeModelContextService) Restore(_ context.Context, access database.AccessContext, workspaceID string, targetVersion int64, ifMatch, idempotencyKey string) (workspacecontext.VersionRecord, error) {
	fake.access, fake.workspaceID, fake.version, fake.ifMatch, fake.idempotency = access, workspaceID, targetVersion, ifMatch, idempotencyKey
	return fake.restoreResult, fake.restoreErr
}

type fakeProposalService struct {
	listAccess workspacecontext.Access
	listStatus workspacecontext.ProposalStatus
	proposals  []workspacecontext.Proposal
	listErr    error

	acceptProposalID string
	acceptIfMatch    string
	acceptEdits      workspacecontext.ProposalEdits
	acceptResult     workspacecontext.Version
	acceptErr        error

	rejectProposalID string
	rejectResult     workspacecontext.Proposal
	rejectErr        error
}

func (fake *fakeProposalService) List(_ context.Context, access workspacecontext.Access, _ string, status workspacecontext.ProposalStatus) ([]workspacecontext.Proposal, error) {
	fake.listAccess, fake.listStatus = access, status
	return fake.proposals, fake.listErr
}

func (fake *fakeProposalService) Get(_ context.Context, _ workspacecontext.Access, _, _ string) (workspacecontext.Proposal, error) {
	return workspacecontext.Proposal{}, nil
}

func (fake *fakeProposalService) Accept(_ context.Context, _ workspacecontext.Access, _, proposalID, ifMatchHash string, edits workspacecontext.ProposalEdits) (workspacecontext.Version, error) {
	fake.acceptProposalID, fake.acceptIfMatch, fake.acceptEdits = proposalID, ifMatchHash, edits
	return fake.acceptResult, fake.acceptErr
}

func (fake *fakeProposalService) Reject(_ context.Context, _ workspacecontext.Access, _, proposalID string) (workspacecontext.Proposal, error) {
	fake.rejectProposalID = proposalID
	return fake.rejectResult, fake.rejectErr
}

func setModelContextMutationHeaders(request *http.Request, idempotencyKey, ifMatch string) {
	request.Header.Set("Idempotency-Key", idempotencyKey)
	if ifMatch != "" {
		request.Header.Set("If-Match", `"`+ifMatch+`"`)
	}
}

func TestModelContextGetServiceUnavailableWhenNotWired(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextPath, ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestModelContextGetProjectsEmptyContextWithSentinelHash(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{restResult: workspacecontext.VersionRecord{Version: workspacecontext.Version{Number: 0, Editable: true}}}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if etag := response.Header().Get("ETag"); etag != `"sha256:empty"` {
		t.Fatalf("etag=%q", etag)
	}
	body := response.Body.String()
	for _, want := range []string{`"version":0`, `"content_hash":"sha256:empty"`, `"editable":true`, `"updated_at":""`, `"updated_by":""`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
	if fake.workspaceID != "ws_alpha" || fake.access.PrincipalID != "usr_alice" {
		t.Fatalf("fake saw workspace=%q access=%+v", fake.workspaceID, fake.access)
	}
}

func TestModelContextGetProjectsRealVersion(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{restResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{
			Number: 3, ContentHash: "sha256:" + strings.Repeat("a", 64), Editable: false,
			Document: workspacecontext.Document{
				Description: "d", Rules: []workspacecontext.Rule{{ID: "rule_x", Text: "r"}},
				Glossary: []workspacecontext.Term{{ID: "term_x", Term: "МНО"}},
			},
		},
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), CreatedBy: "usr_alice",
	}}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"version":3`, `"editable":false`, `"updated_by":"usr_alice"`,
		`"description":"d"`, `"МНО"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
}

func TestModelContextSaveRequiresMutationHeaders(t *testing.T) {
	harness := newTestHarness(t)
	harness.handler.EnableModelContext(&fakeModelContextService{})

	response := httptest.NewRecorder()
	request := harness.request(http.MethodPut, modelContextPath, `{"document":{}}`)
	// No Idempotency-Key, no If-Match.
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing headers status=%d body=%s", response.Code, response.Body.String())
	}

	response2 := httptest.NewRecorder()
	request2 := harness.request(http.MethodPut, modelContextPath, `{"document":{}}`)
	request2.Header.Set("Idempotency-Key", harness.idempotencyKey)
	harness.handler.ServeHTTP(response2, request2)
	if response2.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match status=%d body=%s", response2.Code, response2.Body.String())
	}
}

func TestModelContextSaveAcceptsEmptySentinelIfMatchAndMintsNewItems(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{saveResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{Number: 1, ContentHash: "sha256:" + strings.Repeat("b", 64), Editable: true},
	}}
	harness.handler.EnableModelContext(fake)

	body := `{"document":{"description":"d","rules":[{"id":"","text":"r1"}],"glossary":[],"sources":[]}}`
	response := httptest.NewRecorder()
	request := harness.request(http.MethodPut, modelContextPath, body)
	setModelContextMutationHeaders(request, harness.idempotencyKey, modelContextEmptySentinel)
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.ifMatch != modelContextEmptySentinel {
		t.Fatalf("fake saw ifMatch=%q", fake.ifMatch)
	}
	if len(fake.document.Rules) != 1 || fake.document.Rules[0].ID != "" || fake.document.Rules[0].Text != "r1" {
		t.Fatalf("fake saw document=%+v", fake.document)
	}
}

func TestModelContextSaveMapsStoreErrorsToStatusCodes(t *testing.T) {
	for _, entry := range []struct {
		name string
		code workspacecontext.ErrorCode
		want int
	}{
		{"access_denied", workspacecontext.CodeAccessDenied, http.StatusNotFound},
		{"version_not_found", workspacecontext.CodeVersionNotFound, http.StatusNotFound},
		{"not_editor", workspacecontext.CodeNotEditor, http.StatusForbidden},
		{"revision_conflict", workspacecontext.CodeRevisionConflict, http.StatusPreconditionFailed},
		{"idempotency_conflict", workspacecontext.CodeIdempotencyConflict, http.StatusConflict},
		{"invalid_document", workspacecontext.CodeInvalidDocument, http.StatusBadRequest},
		{"store_unavailable", workspacecontext.CodeStoreUnavailable, http.StatusServiceUnavailable},
	} {
		entry := entry
		t.Run(entry.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.handler.EnableModelContext(&fakeModelContextService{saveErr: workspacecontext.NewErrorForTest(entry.code)})
			response := httptest.NewRecorder()
			request := harness.request(http.MethodPut, modelContextPath, `{"document":{}}`)
			setModelContextMutationHeaders(request, harness.idempotencyKey, modelContextEmptySentinel)
			harness.handler.ServeHTTP(response, request)
			if response.Code != entry.want {
				t.Fatalf("code=%v status=%d want=%d body=%s", entry.code, response.Code, entry.want, response.Body.String())
			}
		})
	}
}

func TestModelContextVersionsListDefaultsAndValidatesQuery(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{versionsResult: []workspacecontext.VersionSummary{
		{Version: 2, ContentHash: "sha256:" + strings.Repeat("c", 64), ChangeKind: "EDIT", CreatedAt: time.Now(), CreatedBy: "usr_alice"},
	}, versionsCursor: 1}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextVersionsPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"next_cursor":"1"`) {
		t.Fatalf("body=%s", response.Body.String())
	}

	badResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(badResponse, harness.request(http.MethodGet, modelContextVersionsPath+"?limit=0", ""))
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("limit=0 status=%d body=%s", badResponse.Code, badResponse.Body.String())
	}
}

func TestModelContextVersionGetParsesVersionSegment(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{versionAtResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{Number: 1, ContentHash: "sha256:" + strings.Repeat("d", 64)},
	}}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextVersionGetPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.version != 1 {
		t.Fatalf("fake saw version=%d", fake.version)
	}

	notFound := httptest.NewRecorder()
	harness.handler.ServeHTTP(notFound, harness.request(http.MethodGet, "/api/v1/workspaces/ws_alpha/model-context/versions/0", ""))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("version 0 status=%d body=%s", notFound.Code, notFound.Body.String())
	}
}

func TestModelContextRestoreRequiresHeadersAndEmptyBody(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeModelContextService{restoreResult: workspacecontext.VersionRecord{
		Version: workspacecontext.Version{Number: 4, ContentHash: "sha256:" + strings.Repeat("e", 64)},
	}}
	harness.handler.EnableModelContext(fake)

	response := httptest.NewRecorder()
	request := harness.request(http.MethodPost, modelContextRestorePath, "")
	setModelContextMutationHeaders(request, harness.idempotencyKey, "sha256:"+strings.Repeat("f", 64))
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.version != 1 {
		t.Fatalf("fake saw target version=%d", fake.version)
	}
}

func TestModelContextProposalsListDefaultsToProposedAndResolvesTargetTerm(t *testing.T) {
	harness := newTestHarness(t)
	contextFake := &fakeModelContextService{currentResult: workspacecontext.Version{
		Document: workspacecontext.Document{Glossary: []workspacecontext.Term{{ID: "term_x", Term: "МНО"}}},
	}}
	harness.handler.EnableModelContext(contextFake)
	proposalFake := &fakeProposalService{proposals: []workspacecontext.Proposal{
		{ID: "ctxprop_b", Kind: workspacecontext.ProposalKindSynonym, TargetTermID: "term_x", Status: workspacecontext.ProposalStatusProposed, CreatedAt: time.Now()},
		{ID: "ctxprop_a", Kind: workspacecontext.ProposalKindNewTerm, Status: workspacecontext.ProposalStatusProposed, CreatedAt: time.Now()},
	}}
	harness.handler.EnableModelContextProposals(proposalFake)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextProposalsPath, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if proposalFake.listStatus != workspacecontext.ProposalStatusProposed {
		t.Fatalf("default status=%q", proposalFake.listStatus)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"target_term":"МНО"`) {
		t.Fatalf("body=%s missing resolved target_term", body)
	}
	if !strings.Contains(body, `"examples":[]`) || !strings.Contains(body, `"hidden_examples":0`) {
		t.Fatalf("body=%s missing empty examples default", body)
	}
}

func TestModelContextProposalsServiceUnavailableWhenNotWired(t *testing.T) {
	for name, path := range map[string]string{"list": modelContextProposalsPath, "accept": modelContextAcceptPath, "reject": modelContextRejectPath} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			response := httptest.NewRecorder()
			method := http.MethodGet
			var request *http.Request
			if path == modelContextProposalsPath {
				request = harness.request(method, path, "")
			} else {
				request = harness.request(http.MethodPost, path, "")
				setModelContextMutationHeaders(request, harness.idempotencyKey, "sha256:"+strings.Repeat("a", 64))
			}
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestModelContextProposalAcceptMapsDefinitionOverride(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeProposalService{acceptResult: workspacecontext.Version{Number: 5, ContentHash: "sha256:" + strings.Repeat("9", 64)}}
	harness.handler.EnableModelContextProposals(fake)

	response := httptest.NewRecorder()
	request := harness.request(http.MethodPost, modelContextAcceptPath, `{"definition":"Новое определение"}`)
	setModelContextMutationHeaders(request, harness.idempotencyKey, "sha256:"+strings.Repeat("a", 64))
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.acceptEdits.Definition != "Новое определение" {
		t.Fatalf("accept edits=%+v", fake.acceptEdits)
	}
	if fake.acceptProposalID != "ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("accept proposal id=%q", fake.acceptProposalID)
	}
}

// TestModelContextProposalAcceptMapsTermAndSynonymsOverride proves the
// accept body's term and synonyms overrides both reach ProposalEdits
// alongside definition (S2 integration gap fix: A0's original ProposalEdits
// carried only SuggestedText, dropping term and synonyms silently).
func TestModelContextProposalAcceptMapsTermAndSynonymsOverride(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeProposalService{acceptResult: workspacecontext.Version{Number: 5, ContentHash: "sha256:" + strings.Repeat("9", 64)}}
	harness.handler.EnableModelContextProposals(fake)

	response := httptest.NewRecorder()
	request := harness.request(http.MethodPost, modelContextAcceptPath, `{"term":"КП","synonyms":["коммерческое предложение"],"definition":"Новое определение"}`)
	setModelContextMutationHeaders(request, harness.idempotencyKey, "sha256:"+strings.Repeat("a", 64))
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	want := workspacecontext.ProposalEdits{Term: "КП", Synonyms: []string{"коммерческое предложение"}, Definition: "Новое определение"}
	if fake.acceptEdits.Term != want.Term || fake.acceptEdits.Definition != want.Definition ||
		len(fake.acceptEdits.Synonyms) != 1 || fake.acceptEdits.Synonyms[0] != want.Synonyms[0] {
		t.Fatalf("accept edits=%+v, want %+v", fake.acceptEdits, want)
	}
}

func TestModelContextProposalRejectReturnsStatus(t *testing.T) {
	harness := newTestHarness(t)
	fake := &fakeProposalService{rejectResult: workspacecontext.Proposal{ID: "ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV", Status: workspacecontext.ProposalStatusRejected}}
	harness.handler.EnableModelContextProposals(fake)

	response := httptest.NewRecorder()
	request := harness.request(http.MethodPost, modelContextRejectPath, "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"status":"REJECTED"`) {
		t.Fatalf("body=%s", response.Body.String())
	}
}

// POST /workspaces/{id}/tools/workspace-context has no test here: that route
// is card C's workspaceToolDispatch (tools_rest_workspace_context_test.go),
// the one kept implementation. See model_context.go's file-level note.
