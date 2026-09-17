package workspaceapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

type fakeEvidenceService struct {
	call        string
	access      database.AccessContext
	workspaceID string
	fragmentID  string
	err         error
	result      evidence.Fragment
}

func (service *fakeEvidenceService) Read(_ context.Context, access database.AccessContext, workspaceID, fragmentID string) (evidence.Fragment, error) {
	service.call = "read"
	service.access = access
	service.workspaceID = workspaceID
	service.fragmentID = fragmentID
	return service.result, service.err
}

func testEvidenceFragment(t *testing.T) evidence.Fragment {
	t.Helper()
	return evidence.Fragment{
		FragmentID: "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", Text: []byte("\u043d\u043e\u0440\u043c\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442"),
		Anchor:       []byte(`{"locator":"file://vol-1/projects/alpha/doc.md","offset":120}`),
		ExtractionID: "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceVersionID: "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		Ordinal: 3, ExternalVersionKey: "hash:sha256:" + strings.Repeat("ab", 32),
		ContentHash: strings.Repeat("cd", 32), ObservedAt: time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC),
		SourceObjectID: "object_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionID: "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ",
	}
}

func TestEvidenceGetReturnsFragmentTextAnchorAndProvenance(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.result = testEvidenceFragment(t)
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.evidence.call != "read" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.evidence.call, response.Body.String())
	}
	if harness.evidence.workspaceID != "ws_alpha" || harness.evidence.fragmentID != "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("viewer got workspace=%q fragment=%q", harness.evidence.workspaceID, harness.evidence.fragmentID)
	}
	if harness.evidence.access.RequestID != "req_server_001" {
		t.Fatalf("viewer did not receive authenticated access context: %#v", harness.evidence.access)
	}
	if harness.auth.csrfCalls != 0 {
		t.Fatalf("GET route must not require CSRF, csrf=%d", harness.auth.csrfCalls)
	}
	body := response.Body.String()
	wantAnchor := base64.StdEncoding.EncodeToString(testEvidenceFragment(t).Anchor)
	// The structured address also contains an anchor. Check the actual public
	// field, so a correct nested copy cannot hide a corrupted top-level anchor.
	var returned struct {
		FragmentID string `json:"fragment_id"`
		Text       string `json:"text"`
		Anchor     string `json:"anchor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &returned); err != nil ||
		returned.FragmentID != harness.evidence.result.FragmentID ||
		returned.Text != string(harness.evidence.result.Text) || returned.Anchor != wantAnchor {
		t.Fatalf("public fragment text/anchor differs from authorized evidence: %s", body)
	}
	for _, want := range []string{
		`"fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		"\"text\":\"\u043d\u043e\u0440\u043c\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442\"",
		`"anchor":"` + wantAnchor + `"`,
		`"extraction_id":"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		`"source_version_id":"version_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		`"ordinal":3`,
		`"observed_at":"2026-08-13T10:00:00Z"`,
		`"connection_id":"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
}

func TestEvidencePageMetadataUsesAuthorizedFragment(t *testing.T) {
	for _, current := range []bool{true, false} {
		harness := newTestHarness(t)
		fragment := testEvidenceFragment(t)
		fragment.IsCurrentVersion = current
		fragment.SourcePath = "projects/report.docx"
		harness.evidence.result = fragment
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+fragment.FragmentID, ""))
		var body struct {
			CanonicalAddress string         `json:"canonical_address"`
			Current          bool           `json:"is_current_version"`
			SourcePath       string         `json:"source_path"`
			Address          map[string]any `json:"address"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Current != current || body.SourcePath != fragment.SourcePath || body.Address == nil {
			t.Fatalf("page metadata differs from authorized read: status=%d", response.Code)
		}
		locator, err := address.Parse(body.CanonicalAddress)
		if err != nil {
			t.Fatalf("unreadable canonical address: %v", err)
		}
		if _, err := address.VerifySpan(fragment.Text, locator); err != nil || !strings.Contains(body.CanonicalAddress, fragment.SourceVersionID) {
			t.Fatal("address does not bind the authorized version and full fragment")
		}
	}
}

// TestEvidenceDenialsAreIndistinguishable proves the no-oracle property of
// ADR-0073 §1.2: every viewer error — the typed not-found and any other
// failure — is the same 404 NOT_FOUND body, and no fragment id is echoed.
func TestEvidenceDenialsAreIndistinguishable(t *testing.T) {
	for name, err := range map[string]error{
		"not_found":    evidence.ErrNotFound,
		"db_failure":   errors.New("database is down"),
		"decrypt_fail": errors.New("codec open failed"),
	} {
		name, err := name, err
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.evidence.err = err
			request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", "")
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ") {
				t.Fatalf("denial echoed the fragment id: %s", response.Body.String())
			}
		})
	}
}

func TestEvidenceRouteRejectsMalformedIdentifiersAndMethods(t *testing.T) {
	t.Run("unknown_fragment_denied_by_viewer", func(t *testing.T) {
		// "not-an-id" is structurally a valid opaque path segment, so the route
		// dispatches and the viewer's fail-closed gate denies it with the same
		// 404 — the format of source_generated ids is checked by the gate.
		harness := newTestHarness(t)
		harness.evidence.err = evidence.ErrNotFound
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/not-an-id", ""))
		if response.Code != http.StatusNotFound || harness.evidence.call != "read" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.evidence.call, response.Body.String())
		}
	})
	t.Run("structurally_invalid_path", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ/extra", ""))
		if response.Code != http.StatusNotFound || harness.evidence.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.evidence.call, response.Body.String())
		}
	})
	t.Run("method_not_allowed", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodPost, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", `{}`))
		if response.Code != http.StatusMethodNotAllowed || harness.evidence.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.evidence.call, response.Body.String())
		}
		if allow := response.Header().Get("Allow"); allow != http.MethodGet {
			t.Fatalf("Allow=%q", allow)
		}
	})
}

func TestEvidenceRouteRequiresAuthentication(t *testing.T) {
	harness := newTestHarness(t)
	harness.auth.authenticateErr = errors.New("session rejected")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", ""))
	if response.Code != http.StatusUnauthorized || harness.evidence.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.evidence.call, response.Body.String())
	}
}
