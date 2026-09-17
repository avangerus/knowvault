package workspaceapi

// R3a-1 KV-A03-related focused tests: the workspace cross-source relation tool.
// They prove the canonical tool is advertised only when the mounted evidence
// service implements the relation capability, that it dispatches to the
// authorized relation source with the closed argument envelope forwarded, that
// every hit carries the relation kind, an excerpt and an immutable address, that
// paging is explicit and reassembles a multi-page relation set exactly once,
// that a denial stays content-free, and that the source records admission before
// data (including a denied outcome).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// fakeRelatedEvidence is the fakeEvidenceService plus the additive optional
// relation capability. Embedding keeps the existing Read harness behavior and
// records. The RelationObjects implementation records the source's admission
// step before any hit and the terminal outcome after it, so a test can prove the
// tool delegates to a source that journals admission before data.

// mcpRelatedUnheldFragment is the fragment selector that names a root fragment
// the relation double does not hold. The canonical content-text contract uses it
// for the empty relation page; the double deliberately answers it with an empty
// page rather than paging its (unrelated) hit set.
const mcpRelatedUnheldFragment = "fragment_absent"

type fakeRelatedEvidence struct {
	*fakeEvidenceService
	hits        []RelatedHit
	relatedErr  error
	relatedCall string
	direction   string
	offset      int64
	limit       int64
	order       []string
	// unheldFragments names additional root fragment ids the double does not
	// hold; they are answered with an empty page, mirroring the production
	// relation source for a fragment it cannot resolve.
	unheldFragments map[string]bool
}

// holdsRelatedFragment reports whether the double holds relation content for a
// root fragment id. Reading a nil map is a no-op, so the zero value holds every
// selector except the shared empty-page sentinel.
func (service *fakeRelatedEvidence) holdsRelatedFragment(fragmentID string) bool {
	return fragmentID != mcpRelatedUnheldFragment && !service.unheldFragments[fragmentID]
}

func (service *fakeRelatedEvidence) RelatedObjects(_ context.Context, _ database.AccessContext, workspaceID, fragmentID, direction string, offset, limit int64) (RelatedPage, error) {
	service.relatedCall = "related"
	service.workspaceID = workspaceID
	service.fragmentID = fragmentID
	service.direction = direction
	service.offset = offset
	service.limit = limit
	// Admission is recorded before any relation content is produced; the
	// terminal outcome (data or denial) is recorded after it.
	service.order = append(service.order, "admission")
	if service.relatedErr != nil {
		service.order = append(service.order, "denied")
		return RelatedPage{}, service.relatedErr
	}
	service.order = append(service.order, "data")
	if !service.holdsRelatedFragment(fragmentID) {
		// A root fragment the double does not hold has no relations: the page is
		// empty (no hits, no further page) even though other roots do.
		return RelatedPage{}, nil
	}
	total := int64(len(service.hits))
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	page := RelatedPage{Hits: append([]RelatedHit(nil), service.hits[start:end]...)}
	page.HasMore = end < total
	page.NextOffset = end
	return page, nil
}

func relatedHarness(t *testing.T, service *fakeRelatedEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	service.fakeEvidenceService = harness.evidence
	harness.handler.evidence = service
	return harness
}

func testRelatedHit(t *testing.T, fragmentID string) RelatedHit {
	t.Helper()
	fragment := testEvidenceFragment(t)
	fragment.FragmentID = fragmentID
	fragment.Text = []byte("the alpha project document references KnowVault in full")
	fragment.EvidenceTextHash = "sha256:" + strings.Repeat("ef", 32)
	return RelatedHit{Fragment: fragment, RelationKind: "context.mentions", Excerpt: "…alpha project references KnowVault…"}
}

type mcpRelatedEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured struct {
			Relations  []map[string]any `json:"relations"`
			Direction  string           `json:"direction"`
			Limit      int64            `json:"limit"`
			HasMore    bool             `json:"has_more"`
			NextCursor *string          `json:"next_cursor"`
		} `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPRelated(t *testing.T, harness *testHarness, tool, arguments string) mcpRelatedEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"r","method":"tools/call","params":{"name":"`+tool+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s status=%d body=%s", tool, response.Code, response.Body.String())
	}
	var envelope mcpRelatedEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP %s did not decode: %v: %s", tool, err, response.Body.String())
	}
	return envelope
}

// TestMCPRelatedAdvertisesCanonicalTool proves the canonical relation name is
// listed when the mounted evidence service implements the capability, that its
// schema is closed and requires the workspace, and that no wiki-rag name is
// present.
func TestMCPRelatedAdvertisesCanonicalTool(t *testing.T) {
	harness := relatedHarness(t, &fakeRelatedEvidence{})
	schemas := listToolSchemas(t, harness)

	canonical, ok := schemas[mcpToolRelated]
	if !ok {
		t.Fatalf("tools/list omitted %s: %#v", mcpToolRelated, schemas)
	}
	required, _ := canonical["required"].([]any)
	if len(required) != 1 || required[0] != "workspace_id" {
		t.Fatalf("related required=%#v", canonical["required"])
	}
	if additional, _ := canonical["additionalProperties"].(bool); additional {
		t.Fatalf("related schema is not closed: %#v", canonical)
	}
	for _, removed := range []string{"wiki_find_related", "wiki_search", "wiki_get_page", "wiki_list_pages"} {
		if _, ok := schemas[removed]; ok {
			t.Fatalf("tools/list advertises removed wiki-rag name %q", removed)
		}
	}
}

// TestMCPRelatedNotAdvertisedWithoutCapability proves a service without the
// relation capability never advertises the tool, so tools/list cannot promise a
// call that would fail closed.
func TestMCPRelatedNotAdvertisedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	schemas := listToolSchemas(t, harness)
	if _, ok := schemas[mcpToolRelated]; ok {
		t.Fatalf("related tool advertised without the capability: %#v", schemas[mcpToolRelated])
	}
}

// TestMCPRelatedReturnsAddressKindExcerptMoment proves an authorized call
// forwards the closed envelope to the relation source and returns every
// required field from the canonical result shape: relation kind, excerpt, the
// related object's address (source, version, object, span hash) and the moment.
func TestMCPRelatedReturnsAddressKindExcerptMoment(t *testing.T) {
	hit := testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWXY")
	service := &fakeRelatedEvidence{hits: []RelatedHit{hit}}
	harness := relatedHarness(t, service)

	envelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","direction":"referencing","limit":5}`)
	if envelope.Error != nil {
		t.Fatalf("related denied unexpectedly: %#v", envelope.Error)
	}
	if service.relatedCall != "related" || service.workspaceID != "ws_alpha" ||
		service.fragmentID != "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" || service.direction != mcpRelatedDirectionReferencing {
		t.Fatalf("relation source got call=%q workspace=%q fragment=%q direction=%q", service.relatedCall, service.workspaceID, service.fragmentID, service.direction)
	}
	if service.limit != 5 || service.offset != 0 {
		t.Fatalf("relation source got limit=%d offset=%d", service.limit, service.offset)
	}
	if envelope.Result.Structured.Direction != mcpRelatedDirectionReferencing {
		t.Fatalf("related direction=%q", envelope.Result.Structured.Direction)
	}
	if len(envelope.Result.Structured.Relations) != 1 {
		t.Fatalf("related results=%#v", envelope.Result.Structured.Relations)
	}
	result := envelope.Result.Structured.Relations[0]
	if result["relation_kind"] != hit.RelationKind || result["excerpt"] != hit.Excerpt {
		t.Fatalf("related hit kind/excerpt=%#v", result)
	}
	if result["version_id"] != hit.Fragment.SourceVersionID || result["observed_at"] != "2026-08-13T10:00:00Z" {
		t.Fatalf("related hit version/moment=%#v", result)
	}
	address, _ := result["address"].(map[string]any)
	if address == nil {
		t.Fatalf("related hit missing address: %#v", result)
	}
	span, _ := address["span"].(map[string]any)
	if span == nil || span["text_hash"] != hit.Fragment.EvidenceTextHash {
		t.Fatalf("related hit address span=%#v", address)
	}
	object, _ := address["object"].(map[string]any)
	if object == nil || object["fragment_id"] != hit.Fragment.FragmentID {
		t.Fatalf("related hit address object=%#v", address)
	}
}

// TestMCPRelatedPaginationReassemblesExactlyOnce proves the page window is
// explicit and that iterating from next_cursor until has_more is false returns
// every relation exactly once, in stable order, without silent truncation.
func TestMCPRelatedPaginationReassemblesExactlyOnce(t *testing.T) {
	all := []RelatedHit{
		testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWX1"),
		testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWX2"),
		testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWX3"),
	}
	service := &fakeRelatedEvidence{hits: all}
	harness := relatedHarness(t, service)

	seen := make(map[string]int)
	cursor := ""
	for page := 0; page < 10; page++ {
		arguments := `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","limit":1`
		if cursor != "" {
			arguments += `,"cursor":"` + cursor + `"`
		}
		arguments += `}`
		envelope := callMCPRelated(t, harness, mcpToolRelated, arguments)
		if envelope.Error != nil {
			t.Fatalf("related page %d denied: %#v", page, envelope.Error)
		}
		if envelope.Result.Structured.Limit != 1 {
			t.Fatalf("related page %d effective limit=%d", page, envelope.Result.Structured.Limit)
		}
		for _, result := range envelope.Result.Structured.Relations {
			fragmentID, _ := result["fragment_id"].(string)
			seen[fragmentID]++
		}
		if !envelope.Result.Structured.HasMore {
			break
		}
		if envelope.Result.Structured.NextCursor == nil || *envelope.Result.Structured.NextCursor == "" {
			t.Fatalf("related page %d has_more without a stable next_cursor", page)
		}
		cursor = *envelope.Result.Structured.NextCursor
	}
	if len(seen) != len(all) {
		t.Fatalf("reassembly saw %d distinct relations, want %d: %#v", len(seen), len(all), seen)
	}
	for _, hit := range all {
		if seen[hit.Fragment.FragmentID] != 1 {
			t.Fatalf("relation %s reassembled %d times, want exactly 1", hit.Fragment.FragmentID, seen[hit.Fragment.FragmentID])
		}
	}
}

// TestMCPRelatedDeniesContentFreeWithoutWorkspaceEcho proves a denied or unknown
// workspace is the relation source's single denial, mapped to the existing
// content-free -32004 that carries no relation, excerpt or address and never
// echoes the workspace id.
func TestMCPRelatedDeniesContentFreeWithoutWorkspaceEcho(t *testing.T) {
	service := &fakeRelatedEvidence{relatedErr: evidence.ErrNotFound}
	harness := relatedHarness(t, service)

	envelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_secret","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("related denial=%#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Relations) != 0 || len(envelope.Result.Content) != 0 {
		t.Fatalf("related denial leaked content: %#v", envelope.Result)
	}
}

// TestMCPRelatedRejectsClosedEnvelope proves the closed envelope: a missing
// selector, a missing workspace, an unknown member, an unknown direction, a
// negative limit and a malformed cursor are rejected before the relation source
// is touched, and a mismatching address/fragment selector is refused.
func TestMCPRelatedRejectsClosedEnvelope(t *testing.T) {
	fragment := testEvidenceFragment(t)
	canonical, err := mcpCanonicalEvidenceAddress(fragment)
	if err != nil {
		t.Fatal(err)
	}
	for name, arguments := range map[string]string{
		"missing_selector":  `{"workspace_id":"ws_alpha"}`,
		"missing_workspace": `{"fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`,
		"unknown_member":    `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","extra":true}`,
		"bad_direction":     `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","direction":"sideways"}`,
		"negative_limit":    `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","limit":-1}`,
		"bad_cursor":        `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","cursor":"nope"}`,
		"malformed_address": `{"workspace_id":"ws_alpha","address":"knowvault://address/v1?kind=text"}`,
		"address_mismatch":  `{"workspace_id":"ws_alpha","fragment_id":"fragment_other_01H9ABCDEFGHJKMNPQRSTVWX","address":"` + canonical.String() + `"}`,
	} {
		name, arguments := name, arguments
		t.Run(name, func(t *testing.T) {
			service := &fakeRelatedEvidence{}
			harness := relatedHarness(t, service)
			envelope := callMCPRelated(t, harness, mcpToolRelated, arguments)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602, got %#v", envelope.Error)
			}
			if service.relatedCall != "" {
				t.Fatalf("invalid arguments reached the relation source: %q", service.relatedCall)
			}
		})
	}
}

// TestMCPRelatedAdmissionBeforeData proves the tool delegates to a source that
// records admission before any relation content and its terminal outcome after
// it, for both a served call and a denied call (with the denial outcome).
func TestMCPRelatedAdmissionBeforeData(t *testing.T) {
	hit := testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWXY")
	served := &fakeRelatedEvidence{hits: []RelatedHit{hit}}
	servedHarness := relatedHarness(t, served)
	envelope := callMCPRelated(t, servedHarness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if envelope.Error != nil {
		t.Fatalf("related denied unexpectedly: %#v", envelope.Error)
	}
	if strings.Join(served.order, ",") != "admission,data" {
		t.Fatalf("served call audit order=%v, want [admission data]", served.order)
	}

	denied := &fakeRelatedEvidence{relatedErr: evidence.ErrNotFound}
	deniedHarness := relatedHarness(t, denied)
	deniedEnvelope := callMCPRelated(t, deniedHarness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if deniedEnvelope.Error == nil || deniedEnvelope.Error.Code != -32004 {
		t.Fatalf("related denial=%#v", deniedEnvelope.Error)
	}
	if strings.Join(denied.order, ",") != "admission,denied" {
		t.Fatalf("denied call audit order=%v, want [admission denied]", denied.order)
	}
}

// TestMCPRelatedReturnsBothDirectionsWithAddressVersion proves the canonical
// relation tool serves both directions of a relation in one workspace: the
// documents that reference the addressed object (direction "referencing") and
// the objects the addressed object references (direction "references"), each hit
// carrying the related object's immutable address (source, version, object and
// span hash), its version and its moment. Dropping either direction from the
// closed vocabulary makes the corresponding call fail, so this focused guard
// kills that weakening.
func TestMCPRelatedReturnsBothDirectionsWithAddressVersion(t *testing.T) {
	referencingHit := testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWX1")
	referencingHit.RelationKind = "context.referenced_by"
	referencesHit := testRelatedHit(t, "fragment_related_01H9ABCDEFGHJKMNPQRSTVWX2")
	referencesHit.RelationKind = "context.references"

	for _, directionCase := range []struct {
		direction string
		hit       RelatedHit
	}{
		{mcpRelatedDirectionReferencing, referencingHit},
		{mcpRelatedDirectionReferences, referencesHit},
	} {
		service := &fakeRelatedEvidence{hits: []RelatedHit{directionCase.hit}}
		harness := relatedHarness(t, service)

		envelope := callMCPRelated(t, harness, mcpToolRelated,
			`{"workspace_id":"ws_alpha","fragment_id":"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ","direction":"`+directionCase.direction+`"}`)
		if envelope.Error != nil {
			t.Fatalf("related %s denied: %#v", directionCase.direction, envelope.Error)
		}
		if service.relatedCall != "related" || service.direction != directionCase.direction {
			t.Fatalf("relation source got call=%q direction=%q, want %q", service.relatedCall, service.direction, directionCase.direction)
		}
		if envelope.Result.Structured.Direction != directionCase.direction {
			t.Fatalf("related direction=%q, want %q", envelope.Result.Structured.Direction, directionCase.direction)
		}
		if len(envelope.Result.Structured.Relations) != 1 {
			t.Fatalf("related %s relations=%#v", directionCase.direction, envelope.Result.Structured.Relations)
		}
		result := envelope.Result.Structured.Relations[0]
		if result["fragment_id"] != directionCase.hit.Fragment.FragmentID || result["relation_kind"] != directionCase.hit.RelationKind {
			t.Fatalf("related %s hit=%#v", directionCase.direction, result)
		}
		if result["version_id"] != directionCase.hit.Fragment.SourceVersionID || result["observed_at"] != "2026-08-13T10:00:00Z" {
			t.Fatalf("related %s version/moment=%#v", directionCase.direction, result)
		}
		address, _ := result["address"].(map[string]any)
		span, _ := address["span"].(map[string]any)
		object, _ := address["object"].(map[string]any)
		if span == nil || span["text_hash"] != directionCase.hit.Fragment.EvidenceTextHash ||
			object == nil || object["fragment_id"] != directionCase.hit.Fragment.FragmentID {
			t.Fatalf("related %s address=%#v", directionCase.direction, address)
		}
	}
}
