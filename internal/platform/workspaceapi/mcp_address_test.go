package workspaceapi

// KV-A01c: the canonical internal/address primitive wired into the MCP evidence
// read. These tests prove the emitted address string round-trips through
// address.Parse, that the canonical address is accepted as a selector and
// verified against the fragment's canonical text, and that malformed, tampered
// and cross-workspace addresses are refused content-free before any page is
// served.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpTestCanonicalAddress builds the canonical address of one test fragment the
// same way the read core does, so a test can hand a genuine address back and
// tamper with a copy of it.
func mcpTestCanonicalAddress(t *testing.T, fragment evidence.Fragment) address.Address {
	t.Helper()
	built, err := mcpCanonicalEvidenceAddress(fragment)
	if err != nil {
		t.Fatalf("canonical address build failed: %v", err)
	}
	return built
}

func mcpAddressArguments(t *testing.T, values map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("address arguments did not marshal: %v", err)
	}
	return string(encoded)
}

// TestMCPEvidenceReadEmitsCanonicalAddressThatRoundTrips proves the address
// string emitted on the read result parses back to an equal Address (source,
// object, version, span and span hash) and verifies against the fragment's
// canonical text, while the existing address map is preserved alongside it.
func TestMCPEvidenceReadEmitsCanonicalAddressThatRoundTrips(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("\u043a\u0430\u043d\u043e\u043d\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0442\u0435\u043a\u0441\u0442: KnowVault")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID}))
	if envelope.Error != nil {
		t.Fatalf("read refused: %#v", envelope.Error)
	}
	emitted, ok := envelope.Result.Structured["canonical_address"].(string)
	if !ok || emitted == "" {
		t.Fatalf("read result missing canonical_address: %#v", envelope.Result.Structured)
	}
	parsed, err := address.Parse(emitted)
	if err != nil {
		t.Fatalf("emitted canonical address did not parse: %v (%q)", err, emitted)
	}
	want := mcpTestCanonicalAddress(t, fragment)
	if parsed != want {
		t.Fatalf("emitted address did not round-trip: got %#v want %#v", parsed, want)
	}
	span, err := address.VerifySpan(fragment.Text, parsed)
	if err != nil || string(span) != string(fragment.Text) {
		t.Fatalf("emitted address did not verify against the fragment text: err=%v span=%q", err, span)
	}
	if _, ok := envelope.Result.Structured["address"].(map[string]any); !ok {
		t.Fatalf("canonical string replaced the existing address map: %#v", envelope.Result.Structured)
	}
}

// TestMCPEvidenceReadAcceptsCanonicalAddressSelector proves an address is an
// accepted selector on its own (fragment_id omitted) and alongside a matching
// fragment_id, resolving through the unchanged authorized viewer path.
func TestMCPEvidenceReadAcceptsCanonicalAddressSelector(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("selected through the canonical address")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment
	emitted := mcpTestCanonicalAddress(t, fragment).String()

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "address": emitted}))
	if envelope.Error != nil {
		t.Fatalf("address selector refused: %#v", envelope.Error)
	}
	if harness.evidence.fragmentID != fragment.FragmentID {
		t.Fatalf("address selector resolved fragment %q want %q", harness.evidence.fragmentID, fragment.FragmentID)
	}
	if envelope.Result.Structured["text"] != string(fragment.Text) {
		t.Fatalf("address selector returned text=%#v want %q", envelope.Result.Structured["text"], fragment.Text)
	}

	together := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID, "address": emitted}))
	if together.Error != nil {
		t.Fatalf("address with matching fragment_id refused: %#v", together.Error)
	}
}

// TestMCPEvidenceReadRefusesAddressForAnotherObject proves an address whose
// object disagrees with the requested fragment is refused with a typed,
// content-free -32602 before the viewer is touched.
func TestMCPEvidenceReadRefusesAddressForAnotherObject(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("original")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	other := mcpTestCanonicalAddress(t, fragment)
	other.Object = "fragment_other"
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID, "address": other.String()}))
	if harness.evidence.call != "" {
		t.Fatalf("mismatching address reached the viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("expected content-free -32602, got: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("mismatching address leaked content: %#v", envelope.Result)
	}
}

// TestMCPEvidenceReadRefusesTamperedAddress proves the tampered-index control:
// an address whose span hash does not match the fragment's canonical text is
// refused with the typed, content-free -32005 and no page text and no address,
// after the authorized read.
func TestMCPEvidenceReadRefusesTamperedAddress(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("tamper target")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	tampered := mcpTestCanonicalAddress(t, fragment)
	tampered.SpanHash = strings.Repeat("0", 16)
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID, "address": tampered.String()}))
	if harness.evidence.call != "read" {
		t.Fatalf("tampered address did not resolve through the authorized viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32005 {
		t.Fatalf("expected content-free -32005, got: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("tampered address leaked content or address: %#v", envelope.Result)
	}
}

// TestMCPEvidenceReadRefusesMalformedAddressBeforeRead proves a value that is
// not a canonical address is refused with -32602 before the evidence viewer is
// touched.
func TestMCPEvidenceReadRefusesMalformedAddressBeforeRead(t *testing.T) {
	harness := newTestHarness(t)
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID, "address": "knowvault://address/not-canonical"}))
	if harness.evidence.call != "" {
		t.Fatalf("malformed address reached the viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("expected content-free -32602, got: %#v", envelope.Error)
	}
}

// TestMCPEvidenceReadDeniesForeignWorkspaceAddressContentFree proves an address
// resolved in a workspace the caller is not a member of is the viewer's single
// content-free -32004 with no content or address and no workspace echo.
func TestMCPEvidenceReadDeniesForeignWorkspaceAddressContentFree(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("foreign content")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment
	harness.evidence.err = evidence.ErrNotFound

	emitted := mcpTestCanonicalAddress(t, fragment).String()
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_other", "address": emitted}))
	if harness.evidence.call != "read" {
		t.Fatalf("foreign address denial did not dispatch through the viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("expected content-free -32004, got: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("foreign address denial leaked content or address: %#v", envelope.Result)
	}
	if strings.Contains(envelope.Error.Message, "ws_other") || strings.Contains(envelope.Error.Message, evidenceFragmentID) {
		t.Fatalf("denial echoed the workspace or fragment: %#v", envelope.Error)
	}
}

// fakeWholeObjectEvidence is a self-contained evidence service implementing the
// required EvidenceService read, the optional EvidenceInventory capability and
// the whole-object capability under test (R3a-1 KV-A02a). It records the anchor
// the whole-object read resolved and returns the configured whole object or
// error.
type fakeWholeObjectEvidence struct {
	object     evidence.WholeObject
	objectErr  error
	objectCall string
}

func (service *fakeWholeObjectEvidence) Read(_ context.Context, _ database.AccessContext, _ string, _ string) (evidence.Fragment, error) {
	if service.objectErr != nil {
		return evidence.Fragment{}, service.objectErr
	}
	return service.object.Fragment, nil
}

func (service *fakeWholeObjectEvidence) ListObjects(_ context.Context, _ database.AccessContext, _ string, _ bool, _, _ int64) (evidence.ObjectInventoryPage, error) {
	return evidence.ObjectInventoryPage{}, nil
}

func (service *fakeWholeObjectEvidence) ReadObject(_ context.Context, _ database.AccessContext, _, _ string) (evidence.WholeObject, error) {
	service.objectCall = "read_object"
	if service.objectErr != nil {
		return evidence.WholeObject{}, service.objectErr
	}
	return service.object, nil
}

func wholeObjectHarness(t *testing.T, service *fakeWholeObjectEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	harness.handler.evidence = service
	return harness
}

// testWholeObjectAnchor is the anchor fragment plus a whole assembly long enough
// to require more than one page: the assembly is the anchor fragment text
// followed by the remaining fragments.
func testWholeObjectAnchor(t *testing.T) (evidence.Fragment, []byte, string) {
	t.Helper()
	anchor := testEvidenceFragment(t)
	anchor.Text = []byte("anchor fragment ")
	anchor.EvidenceTextHash = mcpEvidenceReadTextHash(anchor.Text)
	whole := append(append([]byte(nil), anchor.Text...), []byte(strings.Repeat("whole-object text ", 40))...)
	return anchor, whole, mcpTestCanonicalAddress(t, anchor).String()
}

// TestMCPEvidenceReadWholeObjectPagesReassembleWithWholeHash proves the
// whole-object page contract (R3a-1 Outcome 1 / KV-A02a): a cursor-driven
// request pages the ordinal-ordered assembly, every page carries offset,
// total_bytes, has_more and whole_hash, the pages concatenate to the whole
// original, and the returned canonical address hashes the whole original.
func TestMCPEvidenceReadWholeObjectPagesReassembleWithWholeHash(t *testing.T) {
	harness := newTestHarness(t)
	anchor, whole, emitted := testWholeObjectAnchor(t)
	service := &fakeWholeObjectEvidence{object: evidence.WholeObject{
		Fragment: anchor, Text: whole, FragmentCount: 3, FirstOrdinal: 1, LastOrdinal: 3,
	}}
	harness = wholeObjectHarness(t, service)

	var assembled []byte
	var last map[string]any
	cursor := ""
	pages := 0
	for {
		envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
			"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID,
			"address": emitted, "cursor": cursor, "limit": 64, "include_text_base64": true,
		}))
		if envelope.Error != nil {
			t.Fatalf("whole-object page refused: %#v", envelope.Error)
		}
		structured := envelope.Result.Structured
		last = structured
		if structured["whole_hash"] != address.WholeHash(whole) {
			t.Fatalf("page whole_hash=%#v want %q", structured["whole_hash"], address.WholeHash(whole))
		}
		if structured["total_bytes"] != float64(len(whole)) {
			t.Fatalf("page total_bytes=%#v want %d", structured["total_bytes"], len(whole))
		}
		encoded, ok := structured["text_base64"].(string)
		if !ok {
			t.Fatalf("page missing text_base64: %#v", structured)
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("page text_base64 did not decode: %v", err)
		}
		assembled = append(assembled, decoded...)
		pages++
		if hasMore, _ := structured["has_more"].(bool); !hasMore {
			if structured["next_cursor"] != nil {
				t.Fatalf("final page offered next_cursor: %#v", structured)
			}
			break
		}
		next, ok := structured["next_cursor"].(string)
		if !ok || next == "" {
			t.Fatalf("non-final page missing next_cursor: %#v", structured)
		}
		cursor = next
		if pages > len(whole) {
			t.Fatalf("whole-object pagination did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("expected a multi-page whole-object read, got %d page(s)", pages)
	}
	if string(assembled) != string(whole) {
		t.Fatalf("reassembled %d bytes != whole original %d bytes", len(assembled), len(whole))
	}
	if address.WholeHash(assembled) != address.WholeHash(whole) {
		t.Fatalf("reassembled hash does not equal whole_hash")
	}
	parsed, err := address.Parse(last["canonical_address"].(string))
	if err != nil {
		t.Fatalf("whole-object canonical_address did not parse: %v", err)
	}
	span, err := address.VerifySpan(whole, parsed)
	if err != nil || string(span) != string(whole) {
		t.Fatalf("whole-object address did not verify against the whole original: err=%v", err)
	}
}

// TestMCPEvidenceReadWholeObjectRefusesTamperedAddress proves the tampered-index
// control in whole-object mode: an address whose span hash matches neither the
// anchor fragment nor the whole original is refused with the typed, content-free
// -32005 and no page content.
func TestMCPEvidenceReadWholeObjectRefusesTamperedAddress(t *testing.T) {
	harness := newTestHarness(t)
	anchor, whole, _ := testWholeObjectAnchor(t)
	tampered := mcpTestCanonicalAddress(t, anchor)
	tampered.SpanHash = strings.Repeat("0", 16)
	service := &fakeWholeObjectEvidence{object: evidence.WholeObject{Fragment: anchor, Text: whole}}
	harness = wholeObjectHarness(t, service)

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID,
		"address": tampered.String(), "cursor": "",
	}))
	if envelope.Error == nil || envelope.Error.Code != -32005 {
		t.Fatalf("expected content-free -32005, got: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("tampered whole-object address leaked content: %#v", envelope.Result)
	}
}

// TestMCPEvidenceReadWholeObjectRefusesForeignCursor proves a cursor this
// package did not produce, or one past the end of the original, is refused with
// the typed, content-free -32602 without serving a page.
func TestMCPEvidenceReadWholeObjectRefusesForeignCursor(t *testing.T) {
	for name, cursor := range map[string]string{
		"not_a_cursor": "somewhere-else",
		"past_end":     "v1:999999",
		"negative":     "v1:-4",
		"non_numeric":  "v1:abc",
	} {
		name, cursor := name, cursor
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			anchor, whole, emitted := testWholeObjectAnchor(t)
			service := &fakeWholeObjectEvidence{object: evidence.WholeObject{Fragment: anchor, Text: whole}}
			harness = wholeObjectHarness(t, service)
			envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
				"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID,
				"address": emitted, "cursor": cursor,
			}))
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected content-free -32602, got: %#v", envelope.Error)
			}
			if envelope.Result.Structured != nil || envelope.Result.Content != nil {
				t.Fatalf("foreign cursor leaked content: %#v", envelope.Result)
			}
		})
	}
}

// TestMCPEvidenceReadWholeObjectDenialIsContentFree proves a denied or foreign
// workspace in whole-object mode is the viewer's single content-free -32004 with
// no page content and no workspace echo.
func TestMCPEvidenceReadWholeObjectDenialIsContentFree(t *testing.T) {
	harness := newTestHarness(t)
	anchor, _, emitted := testWholeObjectAnchor(t)
	service := &fakeWholeObjectEvidence{objectErr: evidence.ErrNotFound}
	harness = wholeObjectHarness(t, service)

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_other", "fragment_id": anchor.FragmentID,
		"address": emitted, "cursor": "",
	}))
	if service.objectCall != "read_object" {
		t.Fatalf("whole-object denial did not dispatch through the viewer: call=%q", service.objectCall)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("expected content-free -32004, got: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("whole-object denial leaked content: %#v", envelope.Result)
	}
}

// TestMCPEvidenceReadWholeObjectPage proves the canonical knowvault_read
// reaches the whole-object page core with the stable cursor.
func TestMCPEvidenceReadWholeObjectPage(t *testing.T) {
	harness := newTestHarness(t)
	anchor, whole, _ := testWholeObjectAnchor(t)
	service := &fakeWholeObjectEvidence{object: evidence.WholeObject{Fragment: anchor, Text: whole}}
	harness = wholeObjectHarness(t, service)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"wg","method":"tools/call","params":{"name":"`+mcpToolEvidenceRead+`","arguments":{"workspace_id":"ws_alpha","fragment_id":"`+
			anchor.FragmentID+`","cursor":""}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("knowvault_evidence_read status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpReadEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil || envelope.Error != nil {
		t.Fatalf("knowvault_evidence_read did not decode: err=%v error=%#v body=%s", err, envelope.Error, response.Body.String())
	}
	structured := envelope.Result.Structured
	if structured["whole_hash"] != address.WholeHash(whole) || structured["total_bytes"] != float64(len(whole)) {
		t.Fatalf("knowvault_evidence_read whole-object shape=%#v", structured)
	}
	if service.objectCall != "read_object" {
		t.Fatalf("knowvault_evidence_read did not reach the whole-object core: call=%q", service.objectCall)
	}
}
