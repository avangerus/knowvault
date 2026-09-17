package workspaceapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// evidenceQueryFragmentPath is the exact evidence rowset route used by the
// scope-query tests: a well-formed workspace and fragment under ws_alpha.
const evidenceQueryFragmentPath = workspacesPath + "/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"

// TestEvidenceGetRejectsMalformedRowsetScopeQueries proves strict evidence
// query parsing at the transport boundary. Each syntactically broken query --
// a malformed escape in the scope value itself, a malformed escape in an
// extra parameter, a stray semicolon, a duplicate "scope" key, an unknown
// key, and a bare ForceQuery -- must be diagnosed as REQUEST_INVALID (400)
// before the evidence reader is invoked, so not one evidence.Read call is
// made. url.ParseQuery reports these instead of silently dropping the broken
// portion the way URL.Query() would.
func TestEvidenceGetRejectsMalformedRowsetScopeQueries(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"malformed escape in scope value", evidenceQueryFragmentPath + "?scope=%ZZ"},
		{"malformed escape in extra parameter", evidenceQueryFragmentPath + "?scope=matched&broken=%ZZ"},
		{"semicolon in extra value", evidenceQueryFragmentPath + "?scope=matched&broken=a;b"},
		{"duplicate scope", evidenceQueryFragmentPath + "?scope=matched&scope=full"},
		{"unknown key", evidenceQueryFragmentPath + "?scope=matched&unknown=value"},
		{"force query", evidenceQueryFragmentPath + "?"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.evidence.result = testEvidenceFragment(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, tc.path, ""))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "REQUEST_INVALID") {
				t.Fatalf("malformed query was not diagnosed REQUEST_INVALID: body=%s", response.Body.String())
			}
			if harness.evidence.call != "" {
				t.Fatalf("malformed query reached the evidence reader: call=%q", harness.evidence.call)
			}
		})
	}
}

// TestEvidenceGetRowsetScopeAcceptedQueriesStillReachReader proves strict
// rejection never loosens the legitimate rowset scope: a valid no-query
// request and the accepted matched/full scope values still dispatch through
// the authenticated evidence reader exactly as before.
func TestEvidenceGetRowsetScopeAcceptedQueriesStillReachReader(t *testing.T) {
	for name, path := range map[string]string{
		"no query":      evidenceQueryFragmentPath,
		"scope matched": evidenceQueryFragmentPath + "?scope=matched",
		"scope full":    evidenceQueryFragmentPath + "?scope=full",
	} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.evidence.result = testEvidenceFragment(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, path, ""))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if harness.evidence.call != "read" {
				t.Fatalf("valid query did not reach the evidence reader: call=%q", harness.evidence.call)
			}
		})
	}
}
