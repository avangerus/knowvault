package workspaceapi

// R3a-1 focused tests: the REST parity twin of the workspace knowvault_read
// knowledge tool. They prove GET and POST /api/v1/workspaces/{workspace_id}/
// tools/read both dispatch through the identical authorized Evidence viewer
// (fragment-page mode) and the EvidenceWholeObject capability plus address.Read
// (whole-object cursor mode) the MCP knowvault_read core composes, that pages
// concatenate byte for byte to the stored original and the whole hash, that a
// denial stays the single content-free not-found without a workspace-id echo,
// that a missing whole-object capability and a missing viewer fail closed as
// SERVICE_UNAVAILABLE, that a tampered address or a mismatching
// expected_span_hash is the typed content-free 409 EVIDENCE_SPAN_HASH_MISMATCH,
// and that invalid query members and an unexpected body are refused before the
// viewer reads anything.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// restReadEvidence is a self-contained evidence service implementing both the
// required EvidenceService read and the optional EvidenceWholeObject capability
// under test. It records the exact capability call so a test can prove the route
// delegates to the authorized viewer rather than re-deriving a read, and returns
// the configured fragment or whole object.
type restReadEvidence struct {
	fragment   evidence.Fragment
	readErr    error
	readCall   string
	object     evidence.WholeObject
	objectErr  error
	objectCall string
}

func (service *restReadEvidence) Read(_ context.Context, _ database.AccessContext, _, _ string) (evidence.Fragment, error) {
	service.readCall = "read"
	if service.readErr != nil {
		return evidence.Fragment{}, service.readErr
	}
	return service.fragment, nil
}

func (service *restReadEvidence) ReadObject(_ context.Context, _ database.AccessContext, _, _ string) (evidence.WholeObject, error) {
	service.objectCall = "read_object"
	if service.objectErr != nil {
		return evidence.WholeObject{}, service.objectErr
	}
	return service.object, nil
}

func restReadHarness(t *testing.T, service *restReadEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	harness.handler.evidence = service
	return harness
}

func callRestRead(t *testing.T, harness *testHarness, method, query, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/read"+query, body))
	var decoded map[string]any
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("read REST did not decode: %v: %s", err, response.Body.String())
		}
	}
	return response, decoded
}

// TestWorkspaceToolReadRESTFragmentPagesReassemble proves both GET and POST
// page a fragment through the authorized viewer and that continuing from
// next_offset until has_more is false reassembles the stored original byte for
// byte, with the effective limit always echoed.
func TestWorkspaceToolReadRESTFragmentPagesReassemble(t *testing.T) {
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("first page bytes and second page bytes and tail")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			service := &restReadEvidence{fragment: fragment}
			harness := restReadHarness(t, service)

			var assembled []byte
			offset := 0
			pages := 0
			for {
				response, body := callRestRead(t, harness, method,
					"?fragment_id="+fragment.FragmentID+"&offset="+strconv.Itoa(offset)+"&limit=8", "")
				if response.Code != http.StatusOK {
					t.Fatalf("read REST status=%d body=%s", response.Code, response.Body.String())
				}
				if body["limit"] != float64(8) {
					t.Fatalf("read REST effective limit=%#v want 8", body["limit"])
				}
				if body["total_length"] != float64(len(fragment.Text)) {
					t.Fatalf("read REST total_length=%#v want %d", body["total_length"], len(fragment.Text))
				}
				if body["fragment_id"] != fragment.FragmentID {
					t.Fatalf("read REST fragment_id=%#v", body["fragment_id"])
				}
				if body["text_hash"] != fragment.EvidenceTextHash {
					t.Fatalf("read REST text_hash=%#v want %q", body["text_hash"], fragment.EvidenceTextHash)
				}
				encoded, _ := body["text_base64"].(string)
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatalf("read REST text_base64 did not decode: %v", err)
				}
				if body["length"] != float64(len(decoded)) {
					t.Fatalf("read REST length=%#v page bytes=%d", body["length"], len(decoded))
				}
				assembled = append(assembled, decoded...)
				pages++
				if hasMore, _ := body["has_more"].(bool); !hasMore {
					if body["next_offset"] != nil {
						t.Fatalf("final page offered next_offset: %#v", body)
					}
					break
				}
				next, ok := body["next_offset"].(float64)
				if !ok {
					t.Fatalf("non-final page missing next_offset: %#v", body)
				}
				offset = int(next)
				if pages > len(fragment.Text) {
					t.Fatalf("fragment pagination did not terminate")
				}
			}
			if pages < 2 {
				t.Fatalf("expected a multi-page read, got %d page(s)", pages)
			}
			if string(assembled) != string(fragment.Text) {
				t.Fatalf("reassembled %q != original %q", assembled, fragment.Text)
			}
			if service.readCall != "read" {
				t.Fatalf("route did not dispatch through Evidence.Read: %q", service.readCall)
			}
		})
	}
}

// TestWorkspaceToolReadRESTCanonicalAddressSelector proves the canonical address
// alone selects the object and a mismatching address/selector pair is refused
// before the viewer is touched.
func TestWorkspaceToolReadRESTCanonicalAddressSelector(t *testing.T) {
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("address-selected fragment text")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	canonical := mcpTestCanonicalAddress(t, fragment)

	service := &restReadEvidence{fragment: fragment}
	harness := restReadHarness(t, service)
	response, body := callRestRead(t, harness, http.MethodGet, "?address="+url.QueryEscape(canonical.String()), "")
	if response.Code != http.StatusOK {
		t.Fatalf("read REST address status=%d body=%s", response.Code, response.Body.String())
	}
	if body["fragment_id"] != fragment.FragmentID {
		t.Fatalf("read REST address selected %#v", body["fragment_id"])
	}
	if body["canonical_address"] != canonical.String() {
		t.Fatalf("read REST canonical_address=%#v want %q", body["canonical_address"], canonical.String())
	}
	if service.readCall != "read" {
		t.Fatalf("address read did not dispatch through the viewer: %q", service.readCall)
	}

	mismatch := &restReadEvidence{fragment: fragment}
	mismatchHarness := restReadHarness(t, mismatch)
	response, _ = callRestRead(t, mismatchHarness, http.MethodGet,
		"?fragment_id=fragment_other_01H9ABCDEFGHJKMNPQRSTVWX&address="+url.QueryEscape(canonical.String()), "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("read REST address mismatch status=%d body=%s", response.Code, response.Body.String())
	}
	if mismatch.readCall != "" {
		t.Fatalf("address mismatch reached the viewer: %q", mismatch.readCall)
	}
}

// TestWorkspaceToolReadRESTWholeObjectPagesReassemble proves cursor mode pages
// the whole source version through EvidenceWholeObject and address.Read, that
// every page carries whole_hash/total_bytes and that the concatenation equals
// the whole original.
func TestWorkspaceToolReadRESTWholeObjectPagesReassemble(t *testing.T) {
	anchor := testEvidenceFragment(t)
	anchor.Text = []byte("anchor fragment ")
	anchor.EvidenceTextHash = mcpEvidenceReadTextHash(anchor.Text)
	whole := append(append([]byte(nil), anchor.Text...), []byte(strings.Repeat("whole-object text ", 20))...)
	service := &restReadEvidence{object: evidence.WholeObject{
		Fragment: anchor, Text: whole, FragmentCount: 3, FirstOrdinal: 1, LastOrdinal: 3,
	}}
	harness := restReadHarness(t, service)

	var assembled []byte
	cursor := "v1:0"
	pages := 0
	var last map[string]any
	for {
		response, body := callRestRead(t, harness, http.MethodGet,
			"?fragment_id="+anchor.FragmentID+"&cursor="+url.QueryEscape(cursor)+"&limit=16", "")
		if response.Code != http.StatusOK {
			t.Fatalf("whole-object REST status=%d body=%s", response.Code, response.Body.String())
		}
		last = body
		if body["whole_hash"] != address.WholeHash(whole) {
			t.Fatalf("page whole_hash=%#v want %q", body["whole_hash"], address.WholeHash(whole))
		}
		if body["total_bytes"] != float64(len(whole)) {
			t.Fatalf("page total_bytes=%#v want %d", body["total_bytes"], len(whole))
		}
		encoded, _ := body["text_base64"].(string)
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("page text_base64 did not decode: %v", err)
		}
		assembled = append(assembled, decoded...)
		pages++
		if hasMore, _ := body["has_more"].(bool); !hasMore {
			if body["complete"] != true {
				t.Fatalf("final page not marked complete: %#v", body)
			}
			if body["next_cursor"] != nil {
				t.Fatalf("final page offered next_cursor: %#v", body)
			}
			break
		}
		next, ok := body["next_cursor"].(string)
		if !ok || next == "" {
			t.Fatalf("non-final page missing next_cursor: %#v", body)
		}
		cursor = next
		if pages > len(whole) {
			t.Fatalf("whole-object pagination did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("expected a multi-page whole-object read, got %d page(s)", pages)
	}
	if string(assembled) != string(whole) || address.WholeHash(assembled) != address.WholeHash(whole) {
		t.Fatalf("reassembled bytes/hash != whole original")
	}
	if service.objectCall != "read_object" {
		t.Fatalf("cursor mode did not dispatch through EvidenceWholeObject: %q", service.objectCall)
	}
	if last["fragment_count"] != float64(3) || last["ordinal_start"] != float64(1) || last["ordinal_end"] != float64(3) {
		t.Fatalf("whole-object ordinals/count=%#v", last)
	}
	if parsed, err := address.Parse(last["canonical_address"].(string)); err != nil {
		t.Fatalf("whole-object canonical_address did not parse: %v", err)
	} else if parsed.Object != anchor.FragmentID {
		t.Fatalf("whole-object canonical_address object=%q want %q", parsed.Object, anchor.FragmentID)
	}
}

// TestWorkspaceToolReadRESTDeniesContentFree proves a denial is the single
// content-free not-found with no page and no workspace-id echo.
func TestWorkspaceToolReadRESTDeniesContentFree(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		service := &restReadEvidence{readErr: evidence.ErrNotFound}
		harness := restReadHarness(t, service)
		response, body := callRestRead(t, harness, method, "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", "")
		if response.Code != http.StatusNotFound {
			t.Fatalf("read REST denial status=%d body=%s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "ws_alpha") {
			t.Fatalf("read REST denial echoed the workspace id: %s", response.Body.String())
		}
		if len(body) != 0 {
			t.Fatalf("read REST denial leaked content: %#v", body)
		}
	}
}

// TestWorkspaceToolReadRESTFailsClosed proves a missing viewer and a viewer
// without the whole-object capability both fail closed as SERVICE_UNAVAILABLE.
func TestWorkspaceToolReadRESTFailsClosed(t *testing.T) {
	noViewer := newTestHarness(t)
	noViewer.handler.evidence = nil
	response, _ := callRestRead(t, noViewer, http.MethodGet, "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("read REST no-viewer status=%d body=%s", response.Code, response.Body.String())
	}

	// The default harness viewer is a fragment-only fake: cursor mode must fail
	// closed rather than widen the required interface.
	noWholeObject := newTestHarness(t)
	response, _ = callRestRead(t, noWholeObject, http.MethodGet,
		"?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&cursor=v1:0", "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("read REST no-whole-object status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestWorkspaceToolReadRESTRefusesTamperedSpan proves a mismatching
// expected_span_hash and a tampered address are the typed, content-free 409
// EVIDENCE_SPAN_HASH_MISMATCH with no page bytes.
func TestWorkspaceToolReadRESTRefusesTamperedSpan(t *testing.T) {
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("tamper-controlled fragment text")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	canonical := mcpTestCanonicalAddress(t, fragment)

	service := &restReadEvidence{fragment: fragment}
	harness := restReadHarness(t, service)
	response, body := callRestRead(t, harness, http.MethodGet,
		"?fragment_id="+fragment.FragmentID+"&expected_span_hash=sha256:"+strings.Repeat("0", 64), "")
	if response.Code != http.StatusConflict {
		t.Fatalf("expected_span_hash mismatch status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "EVIDENCE_SPAN_HASH_MISMATCH") {
		t.Fatalf("expected_span_hash mismatch code=%s", response.Body.String())
	}
	if len(body) != 0 || strings.Contains(response.Body.String(), "tamper-controlled") {
		t.Fatalf("span refusal leaked content: %s", response.Body.String())
	}

	// A tampered address keeps a parseable form but its span digest no longer
	// verifies against the stored text.
	raw := canonical.String()
	replacement := byte('0')
	if raw[len(raw)-1] == '0' {
		replacement = '1'
	}
	tampered := raw[:len(raw)-1] + string(replacement)
	tamperedService := &restReadEvidence{fragment: fragment}
	tamperedHarness := restReadHarness(t, tamperedService)
	response, _ = callRestRead(t, tamperedHarness, http.MethodGet, "?address="+url.QueryEscape(tampered), "")
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "EVIDENCE_SPAN_HASH_MISMATCH") {
		t.Fatalf("tampered address status=%d body=%s", response.Code, response.Body.String())
	}
	if tamperedService.readCall != "read" {
		t.Fatalf("tampered address did not reach the authorized read: %q", tamperedService.readCall)
	}
}

// TestWorkspaceToolReadRESTRejectsInvalidBeforeRead proves a closed set of
// malformed requests is refused as REQUEST_INVALID before any read, and that a
// non-empty POST body is not a parameter channel.
func TestWorkspaceToolReadRESTRejectsInvalidBeforeRead(t *testing.T) {
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("closed-envelope fragment text")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	canonical := mcpTestCanonicalAddress(t, fragment)

	for name, query := range map[string]string{
		"missing_selector":  "?offset=0",
		"empty_fragment_id": "?fragment_id=",
		"negative_offset":   "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&offset=-1",
		"negative_limit":    "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&limit=-1",
		"nondecimal_limit":  "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&limit=1x",
		"bad_cursor":        "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&cursor=nope",
		"empty_cursor":      "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&cursor=",
		"cursor_and_offset": "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&cursor=v1:0&offset=1",
		"unknown_member":    "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&extra=true",
		"duplicate":         "?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&fragment_id=fragment_other",
		"malformed_address": "?address=knowvault://address/v1?kind=text",
		"address_mismatch":  "?fragment_id=fragment_other_01H9ABCDEFGHJKMNPQRSTVWX&address=" + url.QueryEscape(canonical.String()),
		"bare_question":     "?",
		"malformed_escape":  "?fragment_id=%zz",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			service := &restReadEvidence{fragment: fragment}
			harness := restReadHarness(t, service)
			response, _ := callRestRead(t, harness, http.MethodGet, query, "")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.Code, response.Body.String())
			}
			if service.readCall != "" || service.objectCall != "" {
				t.Fatalf("invalid query reached the viewer: read=%q object=%q", service.readCall, service.objectCall)
			}
		})
	}

	// A POST body is not a parameter channel: a non-empty body is refused
	// rather than silently ignored.
	service := &restReadEvidence{fragment: fragment}
	harness := restReadHarness(t, service)
	response, _ := callRestRead(t, harness, http.MethodPost,
		"?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ", `{"fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unexpected body, got %d body=%s", response.Code, response.Body.String())
	}
	if service.readCall != "" || service.objectCall != "" {
		t.Fatalf("unexpected body reached the viewer: read=%q object=%q", service.readCall, service.objectCall)
	}

	// GET and POST of the same valid request return the byte-identical page.
	getService := &restReadEvidence{fragment: fragment}
	getHarness := restReadHarness(t, getService)
	_, getBody := callRestRead(t, getHarness, http.MethodGet, "?fragment_id="+fragment.FragmentID+"&limit=8", "")
	postService := &restReadEvidence{fragment: fragment}
	postHarness := restReadHarness(t, postService)
	_, postBody := callRestRead(t, postHarness, http.MethodPost, "?fragment_id="+fragment.FragmentID+"&limit=8", "")
	if !reflect.DeepEqual(getBody, postBody) {
		t.Fatalf("REST GET/POST read projections differ:\nget =%#v\npost=%#v", getBody, postBody)
	}
}
