package workspaceapi

// R3a-1 KV-A04a focused tests: named-ref (code-source) scoping for
// knowvault_grep. They prove the optional `ref` member is advertised, that a
// ref-scoped call resolves the ref from object-inventory metadata before reading
// any fragment content and scans only the code-source object versions whose
// immutable identity matches the ref, that the ref is the emitted address
// version, that a hit at ref A is not reported for ref B when the file differs
// there, that an unknown or foreign ref stays the single content-free -32004
// without reading anything, and that a call omitting `ref` is unchanged.

import (
	"encoding/json"
	"net/http"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// grepRefService builds a workspace with one document object and two immutable
// versions of one git code source: ref "aaaa" whose file matches needle, and the
// non-current ref "bbbb" whose file differs and does not.
func grepRefService(t *testing.T) (*fakeGrepInventoryEvidence, map[string]string) {
	t.Helper()
	docItem, docObject := grepRefObject(t, "frag_doc", "obj_doc", "ver_doc", "native:doc-a", "FILE",
		"needle in a document", "projects/alpha/notes.txt")
	refAItem, refAObject := grepRefObject(t, "frag_a", "obj_code", "ver_a", "native:commit:aaaa;blob:1111", mcpGrepCodeObjectType,
		"package main\n\n// needle lives at ref A\n", "internal/code/main.go")
	refBItem, refBObject := grepRefObject(t, "frag_b", "obj_code", "ver_b", "native:commit:bbbb;blob:2222", mcpGrepCodeObjectType,
		"a different file at ref B", "internal/code/main.go")
	service := &fakeGrepInventoryEvidence{
		items: []evidence.ObjectInventoryItem{docItem, refAItem, refBItem},
		objects: map[string]evidence.WholeObject{
			docObject.Fragment.FragmentID:  docObject,
			refAObject.Fragment.FragmentID: refAObject,
			refBObject.Fragment.FragmentID: refBObject,
		},
	}
	return service, map[string]string{"doc": docObject.Fragment.FragmentID, "a": refAObject.Fragment.FragmentID, "b": refBObject.Fragment.FragmentID}
}

// grepRefObject builds one inventory item and its whole object for a canonical
// text, anchored by the shared test fragment. externalID is the object's
// authorized external identity (a repository-relative path for a code source).
func grepRefObject(t *testing.T, fragmentID, sourceObjectID, versionID, externalKey, objectType, text, externalID string) (evidence.ObjectInventoryItem, evidence.WholeObject) {
	t.Helper()
	fragment := testEvidenceFragment(t)
	fragment.FragmentID = fragmentID
	fragment.SourceObjectID = sourceObjectID
	fragment.SourceVersionID = versionID
	fragment.ExternalVersionKey = externalKey
	fragment.ObjectType = objectType
	fragment.Text = []byte(text)
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	object := evidence.WholeObject{
		Fragment: fragment, Text: fragment.Text, FragmentCount: 1,
		FirstOrdinal: fragment.Ordinal, LastOrdinal: fragment.Ordinal,
		Fragments: []evidence.ObjectFragmentSpan{{
			FragmentID: fragment.FragmentID, Ordinal: fragment.Ordinal, Offset: 0, Length: len(fragment.Text),
		}},
	}
	item := evidence.ObjectInventoryItem{
		SourceObjectID: sourceObjectID, ObjectType: objectType, ConnectionID: fragment.ConnectionID,
		SourceVersionID: versionID, ExternalVersionKey: externalKey, ContentHash: fragment.ContentHash,
		ObservedAt: fragment.ObservedAt, FragmentCount: 1, FirstFragmentID: fragmentID,
		FirstOrdinal: fragment.Ordinal, LastOrdinal: fragment.Ordinal,
		ExternalID: externalID,
	}
	return item, object
}

// TestMCPGrepAdvertisesRef proves the closed inputSchema advertises the optional
// ref member.
func TestMCPGrepAdvertisesRef(t *testing.T) {
	harness := grepHarness(t, &fakeGrepEvidence{})
	canonical, ok := listToolSchemas(t, harness)[mcpToolGrep]
	if !ok {
		t.Fatalf("tools/list omitted %s", mcpToolGrep)
	}
	properties, _ := canonical["properties"].(map[string]any)
	if _, ok := properties["ref"]; !ok {
		t.Fatalf("canonical grep schema does not advertise ref: %#v", canonical)
	}
	required, _ := canonical["required"].([]any)
	if len(required) != 2 {
		t.Fatalf("ref must stay optional, required=%#v", required)
	}
}

// TestMCPGrepRefScopesToCodeSourceVersion proves a ref-scoped call reads only
// the matching code-source version (never the document, never the other ref) and
// emits the ref as the address version.
func TestMCPGrepRefScopesToCodeSourceVersion(t *testing.T) {
	service, ids := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","ref":"aaaa"}`)
	if envelope.Error != nil {
		t.Fatalf("ref grep denied unexpectedly: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("ref grep matches=%#v", envelope.Result.Structured.Matches)
	}
	if service.allVersions != true {
		t.Fatalf("ref scan did not consider all versions: allVersions=%v", service.allVersions)
	}
	if len(service.objectCalls) != 1 || service.objectCalls[0] != ids["a"] {
		t.Fatalf("ref grep read objects=%#v, want only %q", service.objectCalls, ids["a"])
	}
	match := envelope.Result.Structured.Matches[0]
	addressObject, _ := match["address"].(map[string]any)
	version, _ := addressObject["version"].(map[string]any)
	if version["ref"] != "aaaa" {
		t.Fatalf("ref grep address version=%#v", version)
	}
	canonical, _ := match["canonical_address"].(string)
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatalf("ref grep canonical address does not parse: %v (%q)", err, canonical)
	}
	if parsed.Version != "aaaa" {
		t.Fatalf("ref grep canonical address version=%q, want aaaa", parsed.Version)
	}
	// R3a-1 code sources: a ref-scoped hit of a registered git code source
	// carries the file:lines locator.
	if match["path"] != "internal/code/main.go" {
		t.Fatalf("ref grep hit path=%#v, want the repository-relative file", match["path"])
	}
	if match["line"] != float64(3) || match["column"] != float64(4) ||
		match["end_line"] != float64(3) || match["end_column"] != float64(10) {
		t.Fatalf("ref grep hit file:lines=%#v", match)
	}
}

// TestMCPGrepAddressAcceptsEmittedNamedRefWithoutInventory proves the
// canonical address emitted by a Git-ref grep can be used as an exact selector
// directly. The second grep must read only the already named object; resolving
// the ref again through workspace inventory would make this test fail.
func TestMCPGrepAddressAcceptsEmittedNamedRefWithoutInventory(t *testing.T) {
	service, ids := grepRefService(t)
	canonical := refReadCanonical(t, service, "aaaa")
	service.listCall = ""
	service.objectCalls = nil
	harness := grepInventoryHarness(t, service)
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","address":`+jsonString(t, canonical)+`}`)
	if envelope.Error != nil {
		t.Fatalf("address grep for emitted ref denied: %#v", envelope.Error)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 || service.objectCalls[0] != ids["a"] {
		t.Fatalf("address ref grep calls list=%q objects=%#v", service.listCall, service.objectCalls)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("address ref grep matches=%#v", envelope.Result.Structured.Matches)
	}
	match := envelope.Result.Structured.Matches[0]
	parsed, err := address.Parse(match["canonical_address"].(string))
	if err != nil || parsed.Version != "aaaa" {
		t.Fatalf("address ref grep output address=%v version=%q", err, parsed.Version)
	}
}

// TestMCPGrepRefHitCarriesFileLinesAddress proves a ref-scoped hit of a
// registered git code source carries the canon file:lines locator — the
// repository-relative path plus the 1-based half-open start/end line and column
// computed from the match's byte offsets in the canonical text — identically
// over MCP and REST, while the existing offset/length projection is unchanged and
// a document object never gains a path member.
func TestMCPGrepRefHitCarriesFileLinesAddress(t *testing.T) {
	service, _ := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","ref":"aaaa"}`)
	if envelope.Error != nil {
		t.Fatalf("ref grep denied unexpectedly: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("ref grep matches=%#v", envelope.Result.Structured.Matches)
	}
	match := envelope.Result.Structured.Matches[0]
	if match["path"] != "internal/code/main.go" {
		t.Fatalf("MCP ref hit path=%#v", match["path"])
	}
	if match["line"] != float64(3) || match["column"] != float64(4) ||
		match["end_line"] != float64(3) || match["end_column"] != float64(10) {
		t.Fatalf("MCP ref hit file:lines=%#v", match)
	}
	// The existing projection members keep their exact prior values.
	if match["offset"] != float64(17) || match["length"] != float64(6) {
		t.Fatalf("MCP ref hit offset/length changed: %#v", match)
	}

	// REST parity returns the same file:lines members for the same hit.
	response := callRestGrep(t, harness, http.MethodGet, "?pattern=needle&ref=aaaa")
	if response.Code != http.StatusOK {
		t.Fatalf("ref grep REST status=%d body=%s", response.Code, response.Body.String())
	}
	var rest restGrepEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &rest); err != nil {
		t.Fatalf("ref grep REST did not decode: %v: %s", err, response.Body.String())
	}
	if len(rest.Matches) != 1 {
		t.Fatalf("ref grep REST matches=%#v", rest.Matches)
	}
	for _, member := range []string{"path", "line", "column", "end_line", "end_column"} {
		if rest.Matches[0][member] != match[member] {
			t.Fatalf("REST/MCP parity lost %s: rest=%#v mcp=%#v", member, rest.Matches[0][member], match[member])
		}
	}

	// A document (non-code) hit never gains a path member even when the object
	// carries an external identity: the locator is gated on object_type.
	document := testGrepHit(t)
	document.Path = "projects/alpha/notes.txt"
	document.Fragment.ObjectType = "FILE"
	projection := mcpGrepHitProjection(document, "")
	for _, member := range []string{"path", "line", "column", "end_line", "end_column"} {
		if _, ok := projection[member]; ok {
			t.Fatalf("document hit gained %s: %#v", member, projection)
		}
	}
}

// TestMCPGrepRefDoesNotReportAnotherRef proves the negative control: a hit at
// ref A is not reported for ref B once the file differs at B.
func TestMCPGrepRefDoesNotReportAnotherRef(t *testing.T) {
	service, ids := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","ref":"bbbb"}`)
	if envelope.Error != nil {
		t.Fatalf("ref B grep denied unexpectedly: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Matches) != 0 {
		t.Fatalf("ref B reported ref A's hit: %#v", envelope.Result.Structured.Matches)
	}
	if len(service.objectCalls) != 1 || service.objectCalls[0] != ids["b"] {
		t.Fatalf("ref B read objects=%#v, want only %q", service.objectCalls, ids["b"])
	}
}

// TestMCPGrepUnknownRefContentFreeBeforeRead proves an unknown or foreign ref is
// the single content-free -32004 resolved from metadata, with no fragment read
// and no workspace echo.
func TestMCPGrepUnknownRefContentFreeBeforeRead(t *testing.T) {
	service, _ := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_secret","pattern":"needle","ref":"deadbeef"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("unknown ref error=%#v, want -32004", envelope.Error)
	}
	if len(service.objectCalls) != 0 {
		t.Fatalf("unknown ref read fragment content: %#v", service.objectCalls)
	}
	if len(envelope.Result.Structured.Matches) != 0 || len(envelope.Result.Content) != 0 {
		t.Fatalf("unknown ref leaked content: %#v", envelope.Result)
	}
}

// TestMCPGrepRefRejectsMalformedRef proves a ref that cannot be rendered into a
// canonical address is refused with -32602 before the capability is touched.
func TestMCPGrepRefRejectsMalformedRef(t *testing.T) {
	for name, ref := range map[string]string{
		"colon":      "native:commit:aaaa",
		"whitespace": "ref a",
	} {
		name, ref := name, ref
		t.Run(name, func(t *testing.T) {
			service := &fakeGrepEvidence{}
			harness := grepHarness(t, service)
			envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","ref":`+jsonString(t, ref)+`}`)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("malformed ref %q error=%#v, want -32602", ref, envelope.Error)
			}
			if service.grepCall != "" {
				t.Fatalf("malformed ref reached the grep source: %q", service.grepCall)
			}
		})
	}
}

// TestMCPGrepRefCapabilityMissingFailsClosed proves a service that serves grep
// but not named-ref scoping fails closed instead of silently scanning every
// object as if the ref had been ignored.
func TestMCPGrepRefCapabilityMissingFailsClosed(t *testing.T) {
	service := &fakeGrepEvidence{page: GrepPage{}}
	harness := grepHarness(t, service)
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","ref":"aaaa"}`)
	if envelope.Error == nil || envelope.Error.Code != -32000 {
		t.Fatalf("missing ref capability error=%#v, want -32000", envelope.Error)
	}
}

// TestMCPGrepWithoutRefUnchanged proves a call that omits ref still dispatches
// through the plain EvidenceGrep capability with the all_versions switch and no
// code-source filtering.
func TestMCPGrepWithoutRefUnchanged(t *testing.T) {
	hit := testGrepHit(t)
	service := &fakeGrepEvidence{page: GrepPage{Hits: []GrepHit{hit}}}
	harness := grepHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","all_versions":true}`)
	if envelope.Error != nil {
		t.Fatalf("no-ref grep denied unexpectedly: %#v", envelope.Error)
	}
	if service.grepCall != "grep" || !service.allVersions {
		t.Fatalf("no-ref grep capability got call=%q allVersions=%v", service.grepCall, service.allVersions)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("no-ref grep matches=%#v", envelope.Result.Structured.Matches)
	}
	match := envelope.Result.Structured.Matches[0]
	canonical, _ := match["canonical_address"].(string)
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatalf("no-ref canonical address does not parse: %v (%q)", err, canonical)
	}
	if parsed.Version != hit.Fragment.SourceVersionID {
		t.Fatalf("no-ref canonical address version=%q, want %q", parsed.Version, hit.Fragment.SourceVersionID)
	}
	// A no-ref grep keeps its projection byte for byte: it never gains the
	// code-source file:lines members.
	for _, member := range []string{"path", "line", "column", "end_line", "end_column"} {
		if _, ok := match[member]; ok {
			t.Fatalf("no-ref grep hit gained %s: %#v", member, match)
		}
	}
}

// Compile-time guard: the shared fake remains a plain EvidenceGrep.
var _ EvidenceGrep = (*fakeGrepEvidence)(nil)
