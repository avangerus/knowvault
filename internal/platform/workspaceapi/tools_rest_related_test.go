package workspaceapi

// R3a-1 focused tests: the REST parity twin of the workspace
// knowvault_related tool. They prove GET and POST
// /api/v1/workspaces/{workspace_id}/tools/related both dispatch through the
// identical authorized EvidenceRelated capability the MCP tool composes, that
// the success projection (relations/direction/limit/has_more/next_cursor/
// truncated) is byte-for-byte the MCP structured projection, that a denial stays
// the single content-free not-found without a workspace-id echo, that a service
// without the capability fails closed as SERVICE_UNAVAILABLE, and that invalid
// query members, an unparsable or mismatching address and an unexpected body are
// refused before the capability reads anything.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// relatedRESTEnvelope is the explicit page projection the REST route returns,
// identical to the MCP structuredContent shape (including truncated).
type relatedRESTEnvelope struct {
	Relations  []map[string]any `json:"relations"`
	Direction  string           `json:"direction"`
	Limit      int64            `json:"limit"`
	HasMore    bool             `json:"has_more"`
	NextCursor *string          `json:"next_cursor"`
	Truncated  bool             `json:"truncated"`
}

// restRelatedEvidence is a self-contained relation capability fake for the REST
// tests. It records the exact capability call so a test can prove the route
// delegates to EvidenceRelated rather than re-deriving relations, and lets a
// test drive the page (has_more, next_cursor, truncated) directly.
type restRelatedEvidence struct {
	*fakeEvidenceService
	page        RelatedPage
	relatedErr  error
	relatedCall string
	workspaceID string
	fragmentID  string
	direction   string
	offset      int64
	limit       int64
}

func (service *restRelatedEvidence) RelatedObjects(_ context.Context, _ database.AccessContext, workspaceID, fragmentID, direction string, offset, limit int64) (RelatedPage, error) {
	service.relatedCall = "related"
	service.workspaceID = workspaceID
	service.fragmentID = fragmentID
	service.direction = direction
	service.offset = offset
	service.limit = limit
	if service.relatedErr != nil {
		return RelatedPage{}, service.relatedErr
	}
	return service.page, nil
}

func restRelatedHarness(t *testing.T, service *restRelatedEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	service.fakeEvidenceService = harness.evidence
	harness.handler.evidence = service
	return harness
}

func callRestRelated(t *testing.T, harness *testHarness, method, query string) (*httptest.ResponseRecorder, relatedRESTEnvelope) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/related"+query, ""))
	var envelope relatedRESTEnvelope
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("related REST did not decode: %v: %s", err, response.Body.String())
		}
	}
	return response, envelope
}

// callMCPRelatedStructured decodes the MCP knowvault_related structuredContent
// into the same envelope the REST route returns, so the two can be compared.
func callMCPRelatedStructured(t *testing.T, harness *testHarness, arguments string) relatedRESTEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"r","method":"tools/call","params":{"name":"`+mcpToolRelated+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP related status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded struct {
		Result struct {
			Structured relatedRESTEnvelope `json:"structuredContent"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("MCP related did not decode: %v: %s", err, response.Body.String())
	}
	if decoded.Error != nil {
		t.Fatalf("MCP related denied unexpectedly: %#v", decoded.Error)
	}
	return decoded.Result.Structured
}

// TestWorkspaceToolRelatedRESTParity proves both methods route to the same
// authorized capability and return exactly the MCP structured projection,
// including has_more, next_cursor and truncated.
func TestWorkspaceToolRelatedRESTParity(t *testing.T) {
	hit := testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWXY")
	page := RelatedPage{Hits: []RelatedHit{hit}, HasMore: true, NextOffset: 1, Truncated: true}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			restService := &restRelatedEvidence{page: page}
			restHarness := restRelatedHarness(t, restService)
			mcpService := &restRelatedEvidence{page: page}
			mcpHarness := restRelatedHarness(t, mcpService)

			mcp := callMCPRelatedStructured(t, mcpHarness,
				`{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","direction":"referencing","limit":1}`)
			response, rest := callRestRelated(t, restHarness, method,
				"?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&direction=referencing&limit=1")
			if response.Code != http.StatusOK {
				t.Fatalf("related REST status=%d body=%s", response.Code, response.Body.String())
			}
			if !reflect.DeepEqual(mcp, rest) {
				t.Fatalf("REST projection differs from MCP:\nmcp =%#v\nrest=%#v", mcp, rest)
			}
			if restService.relatedCall != "related" || restService.workspaceID != "ws_alpha" ||
				restService.fragmentID != "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" ||
				restService.direction != mcpRelatedDirectionReferencing ||
				restService.offset != 0 || restService.limit != 1 {
				t.Fatalf("relation capability got call=%q workspace=%q fragment=%q direction=%q offset=%d limit=%d",
					restService.relatedCall, restService.workspaceID, restService.fragmentID,
					restService.direction, restService.offset, restService.limit)
			}
			if rest.Direction != mcpRelatedDirectionReferencing || rest.Limit != 1 ||
				!rest.HasMore || rest.NextCursor == nil || *rest.NextCursor != "v1:1" || !rest.Truncated {
				t.Fatalf("related REST page lost its window: %#v", rest)
			}
			if len(rest.Relations) != 1 {
				t.Fatalf("related REST relations=%#v", rest.Relations)
			}
			relation := rest.Relations[0]
			if relation["relation_kind"] != hit.RelationKind || relation["excerpt"] != hit.Excerpt {
				t.Fatalf("related REST hit kind/excerpt=%#v", relation)
			}
			if relation["fragment_id"] != hit.Fragment.FragmentID || relation["version_id"] != hit.Fragment.SourceVersionID {
				t.Fatalf("related REST hit ids=%#v", relation)
			}
			address, _ := relation["address"].(map[string]any)
			if address == nil {
				t.Fatalf("related REST hit missing address: %#v", relation)
			}
		})
	}
}

// TestWorkspaceToolRelatedRESTAddressSelector proves the canonical address alone
// selects the object and both selectors must agree, exactly as the MCP tool.
func TestWorkspaceToolRelatedRESTAddressSelector(t *testing.T) {
	fragment := testEvidenceFragment(t)
	canonical, err := mcpCanonicalEvidenceAddress(fragment)
	if err != nil {
		t.Fatal(err)
	}
	service := &restRelatedEvidence{page: RelatedPage{}}
	harness := restRelatedHarness(t, service)
	response, _ := callRestRelated(t, harness, http.MethodGet, "?address="+url.QueryEscape(canonical.String()))
	if response.Code != http.StatusOK {
		t.Fatalf("related REST address status=%d body=%s", response.Code, response.Body.String())
	}
	if service.relatedCall != "related" || service.fragmentID != canonical.Object {
		t.Fatalf("related REST address selected %q, want %q", service.fragmentID, canonical.Object)
	}
}

// TestWorkspaceToolRelatedRESTLimitBounds proves the effective limit is the MCP
// default when omitted and the MCP maximum when a larger one is requested, and
// is always echoed.
func TestWorkspaceToolRelatedRESTLimitBounds(t *testing.T) {
	for name, testCase := range map[string]struct {
		query     string
		wantLimit int64
	}{
		"default": {"?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", mcpRelatedDefaultLimit},
		"capped":  {"?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&limit=100000", mcpRelatedMaxLimit},
	} {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			service := &restRelatedEvidence{page: RelatedPage{}}
			harness := restRelatedHarness(t, service)
			response, envelope := callRestRelated(t, harness, http.MethodGet, testCase.query)
			if response.Code != http.StatusOK {
				t.Fatalf("related REST status=%d body=%s", response.Code, response.Body.String())
			}
			if service.limit != testCase.wantLimit || envelope.Limit != testCase.wantLimit {
				t.Fatalf("related REST limit capability=%d echo=%d want=%d", service.limit, envelope.Limit, testCase.wantLimit)
			}
		})
	}
}

// TestWorkspaceToolRelatedRESTDeniesContentFree proves a denial is the single
// content-free not-found with no relation and no workspace-id echo.
func TestWorkspaceToolRelatedRESTDeniesContentFree(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		service := &restRelatedEvidence{relatedErr: evidence.ErrNotFound}
		harness := restRelatedHarness(t, service)
		response, envelope := callRestRelated(t, harness, method, "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ")
		if response.Code != http.StatusNotFound {
			t.Fatalf("related REST denial status=%d body=%s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "ws_alpha") {
			t.Fatalf("related REST denial echoed the workspace id: %s", response.Body.String())
		}
		if len(envelope.Relations) != 0 || envelope.HasMore || envelope.NextCursor != nil || envelope.Truncated {
			t.Fatalf("related REST denial leaked content: %#v", envelope)
		}
	}
}

// TestWorkspaceToolRelatedRESTServicesUnavailable proves a service mounted
// without the relation capability fails closed as SERVICE_UNAVAILABLE.
func TestWorkspaceToolRelatedRESTServicesUnavailable(t *testing.T) {
	harness := newTestHarness(t)
	response, _ := callRestRelated(t, harness, http.MethodGet, "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("related REST no-capability status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("related REST no-capability body=%s", response.Body.String())
	}
}

// TestWorkspaceToolRelatedRESTRejectsInvalidBeforeRead proves a missing selector,
// an unknown direction, an unparsable address, an address/selector mismatch,
// invalid or unknown query members and an unexpected body are refused as
// REQUEST_INVALID before the capability is touched.
func TestWorkspaceToolRelatedRESTRejectsInvalidBeforeRead(t *testing.T) {
	fragment := testEvidenceFragment(t)
	canonical, err := mcpCanonicalEvidenceAddress(fragment)
	if err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"missing_selector":  "?direction=both",
		"empty_fragment_id": "?fragment_id=",
		"bad_direction":     "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&direction=sideways",
		"negative_limit":    "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&limit=-1",
		"bad_cursor":        "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&cursor=nope",
		"unknown_member":    "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&extra=true",
		"duplicate":         "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&fragment_id=fragment_other",
		"malformed_address": "?address=knowvault://address/v1?kind=text",
		"address_mismatch":  "?fragment_id=fragment_other_01H9ABCDEFGHJKMNPQRSTVWX&address=" + url.QueryEscape(canonical.String()),
		"bare_question":     "?",
		"malformed_escape":  "?fragment_id=%zz",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			service := &restRelatedEvidence{}
			harness := restRelatedHarness(t, service)
			response, _ := callRestRelated(t, harness, http.MethodGet, query)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.Code, response.Body.String())
			}
			if service.relatedCall != "" {
				t.Fatalf("invalid query reached the relation source: %q", service.relatedCall)
			}
		})
	}

	// A POST body is not a parameter channel: a non-empty body is refused
	// rather than silently ignored.
	service := &restRelatedEvidence{}
	harness := restRelatedHarness(t, service)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost,
		apiPrefix+"/workspaces/ws_alpha/tools/related?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", `{"fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unexpected body, got %d body=%s", response.Code, response.Body.String())
	}
	if service.relatedCall != "" {
		t.Fatalf("unexpected body reached the relation source: %q", service.relatedCall)
	}
}
