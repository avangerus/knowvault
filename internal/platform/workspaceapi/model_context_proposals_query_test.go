package workspaceapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// Card U-1 found on the stand that the web interface's proposal review queue
// request (GET .../model-context/proposals?status=PROPOSED) answered
// REQUEST_INVALID: parseEndpoint's generic "this route takes no query string"
// rule ran before modelContextProposalsList's own closed validator, so the
// queue never loaded. This test fails with that 400 and passes once
// parseEndpoint accepts exactly the query shape the handler already validates.
func TestModelContextProposalsStatusQueryIsAccepted(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextProposalsPath+"?status=PROPOSED", ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired status=%d body=%s, want the handler's 503", response.Code, response.Body.String())
	}

	harness = newTestHarness(t)
	fake := &fakeProposalService{}
	harness.handler.EnableModelContextProposals(fake)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextProposalsPath+"?status=PROPOSED", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("wired status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if fake.listStatus != workspacecontext.ProposalStatusProposed {
		t.Fatalf("list status=%q, want PROPOSED", fake.listStatus)
	}

	// Every other query shape stays refused, so the new exception is exactly
	// the documented one.
	for _, query := range []string{"?status=BOGUS", "?status=PROPOSED&unknown=1", "?status="} {
		response = httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, modelContextProposalsPath+query, ""))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("query %q status=%d body=%s, want 400", query, response.Code, response.Body.String())
		}
	}
}
