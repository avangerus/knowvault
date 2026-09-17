package workspaceapi

// R3a-1 KV-A04b focused tests: knowvault_read (and its REST parity) resolves a
// canonical address whose version is a named code-source ref. They prove the
// canonical_address a ref-scoped knowvault_grep hit emits round-trips through
// the read to full readable code content at that ref, that the read and REST
// routes dispatch through the same resolution path, and that an unknown ref is
// refused content-free before any content is read.

import (
	"net/http"
	"net/url"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
)

// refReadCanonical runs a ref-scoped knowvault_grep and returns the canonical
// address of its single hit.
func refReadCanonical(t *testing.T, service *fakeGrepInventoryEvidence, ref string) string {
	t.Helper()
	harness := grepInventoryHarness(t, service)
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","ref":"`+ref+`"}`)
	if envelope.Error != nil {
		t.Fatalf("ref grep denied unexpectedly: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("ref grep matches=%#v, want one", envelope.Result.Structured.Matches)
	}
	canonical, _ := envelope.Result.Structured.Matches[0]["canonical_address"].(string)
	if canonical == "" {
		t.Fatalf("ref grep hit has no canonical_address: %#v", envelope.Result.Structured.Matches[0])
	}
	return canonical
}

// TestMCPReadNamedRefAddressRoundTrips proves the canonical_address a ref-scoped
// knowvault_grep hit emits resolves through knowvault_read whole-object page mode
// to the code content at that ref, and that the read resolved the ref from
// inventory metadata before reading the object.
func TestMCPReadNamedRefAddressRoundTrips(t *testing.T) {
	service, ids := grepRefService(t)
	canonical := refReadCanonical(t, service, "aaaa")
	object := service.objects[ids["a"]]

	// Reset the grep's read record so the assertion below covers only the read.
	service.objectCalls = nil
	harness := grepInventoryHarness(t, service)
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "address": canonical, "cursor": "", "limit": 4096,
	}))
	if envelope.Error != nil {
		t.Fatalf("named-ref read refused: %#v", envelope.Error)
	}
	if envelope.Result.Structured["text"] != string(object.Text) {
		t.Fatalf("named-ref read text=%#v want %q", envelope.Result.Structured["text"], object.Text)
	}
	if envelope.Result.Structured["whole_hash"] != address.WholeHash(object.Text) {
		t.Fatalf("named-ref read whole_hash=%#v want %q", envelope.Result.Structured["whole_hash"], address.WholeHash(object.Text))
	}
	if len(service.objectCalls) != 1 || service.objectCalls[0] != ids["a"] {
		t.Fatalf("named-ref read objects=%#v want only %q", service.objectCalls, ids["a"])
	}
}

// TestMCPReadUnknownRefContentFreeBeforeRead proves an address naming a version
// that is neither the object's immutable source version id nor a matching
// code-source ref is refused content-free (without reading any object content)
// when the workspace inventory lists the object.
func TestMCPReadUnknownRefContentFreeBeforeRead(t *testing.T) {
	service, _ := grepRefService(t)
	canonical := refReadCanonical(t, service, "aaaa")
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatalf("canonical address did not parse: %v", err)
	}
	parsed.Version = "deadbeef"
	service.objectCalls = nil

	harness := grepInventoryHarness(t, service)
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "address": parsed.String(), "cursor": "",
	}))
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("unknown ref error=%#v, want -32602", envelope.Error)
	}
	if len(service.objectCalls) != 0 {
		t.Fatalf("unknown ref read object content: %#v", service.objectCalls)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("unknown ref leaked content: %#v", envelope.Result)
	}
}

// TestRESTReadNamedRefAddressRoundTrips proves GET and POST
// /workspaces/{id}/tools/read resolve the same named-ref address through the
// same path and return the identical whole-object projection.
func TestRESTReadNamedRefAddressRoundTrips(t *testing.T) {
	service, ids := grepRefService(t)
	canonical := refReadCanonical(t, service, "aaaa")
	object := service.objects[ids["a"]]

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			service.objectCalls = nil
			harness := grepInventoryHarness(t, service)
			response, body := callRestRead(t, harness, method,
				"?address="+url.QueryEscape(canonical)+"&cursor=v1:0", "")
			if response.Code != http.StatusOK {
				t.Fatalf("named-ref REST read status=%d body=%s", response.Code, response.Body.String())
			}
			if body["text"] != string(object.Text) {
				t.Fatalf("named-ref REST text=%#v want %q", body["text"], object.Text)
			}
			if body["whole_hash"] != address.WholeHash(object.Text) {
				t.Fatalf("named-ref REST whole_hash=%#v want %q", body["whole_hash"], address.WholeHash(object.Text))
			}
			if len(service.objectCalls) != 1 || service.objectCalls[0] != ids["a"] {
				t.Fatalf("named-ref REST read objects=%#v want only %q", service.objectCalls, ids["a"])
			}
		})
	}
}
