package workspaceapi

// R2 Outcome 1 transport tests for the additive, owner-only MetricDefinition
// write routes. The routes are deliberately on their own colon paths so the
// existing GET routes keep 405-on-POST with Allow: GET. The transport validates
// the envelope, then forwards the authenticated access context and the
// workspace named in the path to the injected MetricDefinitionAuthoring
// capability: the capability owns the access re-check, the owner check, the
// audit event and version monotonicity. A handler whose service is not
// composed fails closed as SERVICE_UNAVAILABLE.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	metricDefinitionDraftPath   = "/api/v1/workspaces/ws_alpha/metric-definitions:draft"
	metricDefinitionApprovePath = "/api/v1/workspaces/ws_alpha/metric-definitions/md_revenue:approve"
)

const validMetricDefinitionDraftBody = `{"id":"md_revenue","name":"Revenue","source_connection_id":"conn_orders","projection_version":3,"entity_key":"order_id","grain":"MONTH","allowed_filters":["region","channel"],"unit":"RUB"}`

// fakeMetricDefinitionAuthoring records what the transport forwarded and
// returns one canned result or one canned failure.
type fakeMetricDefinitionAuthoring struct {
	access       database.AccessContext
	workspaceID  string
	definitionID string
	spec         metricdef.Spec
	draftCalls   int
	approveCalls int
	definition   metricdef.Definition
	err          error
}

func (authoring *fakeMetricDefinitionAuthoring) CreateDraft(_ context.Context, access database.AccessContext, workspaceID, definitionID string, spec metricdef.Spec) (metricdef.Definition, error) {
	authoring.draftCalls++
	authoring.access, authoring.workspaceID, authoring.definitionID, authoring.spec = access, workspaceID, definitionID, spec
	return authoring.definition, authoring.err
}

func (authoring *fakeMetricDefinitionAuthoring) Approve(_ context.Context, access database.AccessContext, workspaceID, definitionID string) (metricdef.Definition, error) {
	authoring.approveCalls++
	authoring.access, authoring.workspaceID, authoring.definitionID = access, workspaceID, definitionID
	return authoring.definition, authoring.err
}

// metricDefinitionDraftFixture builds one real DRAFT version 1 through the
// repository's own metricdef authority.
func metricDefinitionDraftFixture(t *testing.T) metricdef.Definition {
	t.Helper()
	series, err := metricdef.NewSeries("md_revenue", "ws_alpha", "usr_alice", metricdef.Spec{
		Name:           "Revenue",
		Source:         metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3},
		EntityKey:      "order_id",
		Grain:          metricdef.GrainMonth,
		AllowedFilters: []string{"region", "channel"},
		Unit:           "RUB",
	})
	if err != nil {
		t.Fatal(err)
	}
	definition, ok := series.Version(1)
	if !ok {
		t.Fatal("draft version 1 missing from series")
	}
	return definition
}

func metricDefinitionWriteRequest(harness *testHarness, method, path, body string) *http.Request {
	request := harness.request(method, path, body)
	// These routes carry an Idempotency-Key but no workspace If-Match
	// precondition, unlike the configuration mutations apiMutation targets.
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	return request
}

func TestMetricDefinitionDraftForwardsSpecAndProjectsDraft(t *testing.T) {
	harness := newTestHarness(t)
	authoring := &fakeMetricDefinitionAuthoring{definition: metricDefinitionDraftFixture(t)}
	harness.handler.EnableMetricDefinitionAuthoring(authoring)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionDraftPath, validMetricDefinitionDraftBody))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"id":"md_revenue"`, `"version":1`, `"status":"DRAFT"`, `"name":"Revenue"`,
		`"source_connection_id":"conn_orders"`, `"projection_version":3`,
		`"entity_key":"order_id"`, `"grain":"MONTH"`, `"allowed_filters":["channel","region"]`, `"unit":"RUB"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
	if authoring.workspaceID != "ws_alpha" || authoring.definitionID != "md_revenue" {
		t.Fatalf("authoring saw workspace=%q id=%q", authoring.workspaceID, authoring.definitionID)
	}
	if authoring.access.RequestID != "req_server_001" || authoring.access.PrincipalID != "usr_alice" {
		t.Fatalf("authoring saw access=%+v", authoring.access)
	}
	if authoring.spec.Name != "Revenue" || authoring.spec.Source.ConnectionID != "conn_orders" ||
		authoring.spec.Source.ProjectionVersion != 3 || authoring.spec.EntityKey != "order_id" ||
		authoring.spec.Grain != metricdef.GrainMonth || authoring.spec.Unit != "RUB" {
		t.Fatalf("authoring saw spec=%+v", authoring.spec)
	}
}

func TestMetricDefinitionApproveProjectsApprovedVersion(t *testing.T) {
	harness := newTestHarness(t)
	authoring := &fakeMetricDefinitionAuthoring{definition: metricDefinitionTestFixture(t)}
	harness.handler.EnableMetricDefinitionAuthoring(authoring)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionApprovePath, ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"status":"APPROVED"`) {
		t.Fatalf("body=%s", response.Body.String())
	}
	if authoring.workspaceID != "ws_alpha" || authoring.definitionID != "md_revenue" {
		t.Fatalf("authoring saw workspace=%q id=%q", authoring.workspaceID, authoring.definitionID)
	}
}

func TestMetricDefinitionWriteRoutesFailClosedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	for name, request := range map[string]*http.Request{
		"draft":   metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionDraftPath, validMetricDefinitionDraftBody),
		"approve": metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionApprovePath, ""),
	} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
}

func TestMetricDefinitionWriteRoutesRejectMalformedBodies(t *testing.T) {
	harness := newTestHarness(t)
	authoring := &fakeMetricDefinitionAuthoring{definition: metricDefinitionDraftFixture(t)}
	harness.handler.EnableMetricDefinitionAuthoring(authoring)
	for name, body := range map[string]string{
		"missing_grain": `{"id":"md_revenue","name":"Revenue","source_connection_id":"conn_orders","projection_version":3,"entity_key":"order_id"}`,
		"unparseable":   `{"id":`,
		"unknown_field": `{"id":"md_revenue","name":"Revenue","source_connection_id":"conn_orders","projection_version":3,"entity_key":"order_id","grain":"MONTH","status":"APPROVED"}`,
	} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionDraftPath, body))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"REQUEST_INVALID"`) {
			t.Fatalf("%s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	if authoring.draftCalls != 0 {
		t.Fatalf("malformed body reached the authoring capability %d times", authoring.draftCalls)
	}
}

func TestMetricDefinitionWriteRoutesMapRefusals(t *testing.T) {
	spec := metricdef.Spec{
		Name: "Revenue", Source: metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3},
		EntityKey: "order_id", Grain: metricdef.GrainMonth, Unit: "RUB",
	}
	// Every refusal below is produced by the real internal/metricdef authority,
	// never a hand-built code, so the mapping is exercised against the errors a
	// production implementation would actually return.
	series, err := metricdef.NewSeries("md_revenue", "ws_alpha", "usr_alice", spec)
	if err != nil {
		t.Fatal(err)
	}
	notOwner := func() error {
		_, err := series.Approve("usr_bob", &metricDefinitionTestAuditor{}, time.Now().UTC())
		return err
	}()
	invalidDefinition := func() error {
		_, err := metricdef.NewSeries("md_revenue", "ws_alpha", "usr_alice", metricdef.Spec{})
		return err
	}()
	auditUnavailable := func() error {
		_, err := series.Approve("usr_alice", nil, time.Now().UTC())
		return err
	}()
	for name, testCase := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"denied":            {ErrMetricDefinitionDenied, http.StatusNotFound, "NOT_FOUND"},
		"unknown":           {ErrMetricDefinitionNotFound, http.StatusNotFound, "NOT_FOUND"},
		"not_owner":         {notOwner, http.StatusNotFound, "NOT_FOUND"},
		"invalid":           {invalidDefinition, http.StatusBadRequest, "REQUEST_INVALID"},
		"audit_unavailable": {auditUnavailable, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"},
	} {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			authoring := &fakeMetricDefinitionAuthoring{err: testCase.err}
			harness.handler.EnableMetricDefinitionAuthoring(authoring)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionApprovePath, ""))
			if response.Code != testCase.status || !strings.Contains(response.Body.String(), `"code":"`+testCase.code+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMetricDefinitionWriteRoutesRequireIdempotencyKey(t *testing.T) {
	harness := newTestHarness(t)
	authoring := &fakeMetricDefinitionAuthoring{definition: metricDefinitionDraftFixture(t)}
	harness.handler.EnableMetricDefinitionAuthoring(authoring)
	request := harness.request(http.MethodPost, metricDefinitionDraftPath, validMetricDefinitionDraftBody)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if authoring.draftCalls != 0 {
		t.Fatalf("request without an idempotency key reached the authoring capability")
	}
}

// TestMetricDefinitionWriteRoutesDoNotWeakenTheReadContract pins the additive
// intent: POST on the existing GET paths is still 405 with Allow: GET, and the
// authoring capability is never reached through them.
func TestMetricDefinitionWriteRoutesDoNotWeakenTheReadContract(t *testing.T) {
	harness := newTestHarness(t)
	authoring := &fakeMetricDefinitionAuthoring{definition: metricDefinitionDraftFixture(t)}
	harness.handler.EnableMetricDefinitionAuthoring(authoring)
	for _, path := range []string{metricDefinitionListPath, metricDefinitionGetPath} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, metricDefinitionWriteRequest(harness, http.MethodPost, path, ""))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("path=%s status=%d Allow=%q", path, response.Code, response.Header().Get("Allow"))
		}
	}
	if authoring.draftCalls != 0 || authoring.approveCalls != 0 {
		t.Fatalf("read paths reached the authoring capability: draft=%d approve=%d", authoring.draftCalls, authoring.approveCalls)
	}
}

// auditedMetricDefinitionStore is a test-only MetricDefinitionAuthoring backed
// by the real internal/metricdef Series, so the transport is exercised against
// the in-tree owner-only, audited, monotonic semantics instead of a stub. It
// deliberately mirrors only what a production implementation would do; it adds
// no rule of its own.
type auditedMetricDefinitionStore struct {
	series  map[string]metricdef.Series
	ownerID string
	auditor metricdef.ApprovalAuditor
}

func newAuditedMetricDefinitionStore(ownerID string, auditor metricdef.ApprovalAuditor) *auditedMetricDefinitionStore {
	return &auditedMetricDefinitionStore{series: map[string]metricdef.Series{}, ownerID: ownerID, auditor: auditor}
}

func (store *auditedMetricDefinitionStore) CreateDraft(_ context.Context, _ database.AccessContext, workspaceID, definitionID string, spec metricdef.Spec) (metricdef.Definition, error) {
	if existing, ok := store.series[definitionID]; ok {
		next, err := existing.Supersede(spec)
		if err != nil {
			return metricdef.Definition{}, err
		}
		store.series[definitionID] = next
		return next.Current(), nil
	}
	created, err := metricdef.NewSeries(definitionID, workspaceID, store.ownerID, spec)
	if err != nil {
		return metricdef.Definition{}, err
	}
	store.series[definitionID] = created
	return created.Current(), nil
}

func (store *auditedMetricDefinitionStore) Approve(_ context.Context, access database.AccessContext, _, definitionID string) (metricdef.Definition, error) {
	existing, ok := store.series[definitionID]
	if !ok {
		return metricdef.Definition{}, ErrMetricDefinitionNotFound
	}
	approved, err := existing.Approve(access.PrincipalID, store.auditor, time.Now().UTC())
	if err != nil {
		return metricdef.Definition{}, err
	}
	store.series[definitionID] = approved
	return approved.Current(), nil
}

type failingMetricDefinitionAuditor struct{}

func (failingMetricDefinitionAuditor) RecordApproval(metricdef.ApprovalEvent) error {
	return errMetricDefinitionAuditRefused
}

var errMetricDefinitionAuditRefused = errors.New("audit boundary refused the approval")

// TestMetricDefinitionWritesUseTheRealOwnerOnlyAuditedSemantics drives the
// additive routes through a store backed by internal/metricdef: an owner
// drafts and approves version 1, the approval is audited exactly once, an
// approved version is immutable so the next draft is a new monotonic version,
// a non-owner approval is refused as NOT_FOUND, and a failing auditor refuses
// with no status change.
func TestMetricDefinitionWritesUseTheRealOwnerOnlyAuditedSemantics(t *testing.T) {
	harness := newTestHarness(t)
	auditor := &metricDefinitionTestAuditor{}
	store := newAuditedMetricDefinitionStore("usr_alice", auditor)
	harness.handler.EnableMetricDefinitionAuthoring(store)

	draft := httptest.NewRecorder()
	harness.handler.ServeHTTP(draft, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionDraftPath, validMetricDefinitionDraftBody))
	if draft.Code != http.StatusOK || !strings.Contains(draft.Body.String(), `"status":"DRAFT"`) || !strings.Contains(draft.Body.String(), `"version":1`) {
		t.Fatalf("draft status=%d body=%s", draft.Code, draft.Body.String())
	}

	approve := httptest.NewRecorder()
	harness.handler.ServeHTTP(approve, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionApprovePath, ""))
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), `"status":"APPROVED"`) {
		t.Fatalf("approve status=%d body=%s", approve.Code, approve.Body.String())
	}
	if auditor.approvals != 1 {
		t.Fatalf("approval audit events=%d", auditor.approvals)
	}

	redraft := httptest.NewRecorder()
	harness.handler.ServeHTTP(redraft, metricDefinitionWriteRequest(harness, http.MethodPost, metricDefinitionDraftPath, validMetricDefinitionDraftBody))
	if redraft.Code != http.StatusOK || !strings.Contains(redraft.Body.String(), `"status":"DRAFT"`) || !strings.Contains(redraft.Body.String(), `"version":2`) {
		t.Fatalf("redraft status=%d body=%s", redraft.Code, redraft.Body.String())
	}

	// A non-owner is refused through the real Series.Approve and mapped to the
	// content-free NOT_FOUND, never to an existence or ownership oracle.
	nonOwnerHarness := newTestHarness(t)
	nonOwnerStore := newAuditedMetricDefinitionStore("usr_bob", &metricDefinitionTestAuditor{})
	nonOwnerHarness.handler.EnableMetricDefinitionAuthoring(nonOwnerStore)
	if _, err := nonOwnerStore.CreateDraft(context.Background(), database.AccessContext{}, "ws_alpha", "md_revenue", metricdef.Spec{
		Name: "Revenue", Source: metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3},
		EntityKey: "order_id", Grain: metricdef.GrainMonth, Unit: "RUB",
	}); err != nil {
		t.Fatal(err)
	}
	refused := httptest.NewRecorder()
	nonOwnerHarness.handler.ServeHTTP(refused, metricDefinitionWriteRequest(nonOwnerHarness, http.MethodPost, metricDefinitionApprovePath, ""))
	if refused.Code != http.StatusNotFound {
		t.Fatalf("non-owner approve status=%d body=%s", refused.Code, refused.Body.String())
	}

	// A failing auditor refuses and changes no status: the deployed
	// metricdef.CodeAuditFailed stays the current DRAFT.
	auditHarness := newTestHarness(t)
	auditStore := newAuditedMetricDefinitionStore("usr_alice", failingMetricDefinitionAuditor{})
	auditHarness.handler.EnableMetricDefinitionAuthoring(auditStore)
	if _, err := auditStore.CreateDraft(context.Background(), database.AccessContext{}, "ws_alpha", "md_revenue", metricdef.Spec{
		Name: "Revenue", Source: metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3},
		EntityKey: "order_id", Grain: metricdef.GrainMonth, Unit: "RUB",
	}); err != nil {
		t.Fatal(err)
	}
	auditFailed := httptest.NewRecorder()
	auditHarness.handler.ServeHTTP(auditFailed, metricDefinitionWriteRequest(auditHarness, http.MethodPost, metricDefinitionApprovePath, ""))
	if auditFailed.Code != http.StatusServiceUnavailable {
		t.Fatalf("failing auditor status=%d body=%s", auditFailed.Code, auditFailed.Body.String())
	}
	current := auditStore.series["md_revenue"].Current()
	if current.Status() != metricdef.StatusDraft {
		t.Fatalf("failing auditor changed status to %s", current.Status())
	}
}
