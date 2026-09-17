package workspaceapi

// R3a-1 KV-A02a/02b contract tests: the content[].text channel of
// knowvault_search, knowvault_list_objects and knowvault_read must carry the
// same hits, addresses, page cursor and page bytes the structuredContent
// channel carries, so a client (and a model) that reads only content[].text
// sees the data instead of a content-free banner. The read assertions also pin
// the compact trailing metadata line and the opt-in text_base64, so a default
// read page is no longer duplicated as text plus base64 plus the envelope.
// They also prove the denial paths stay content-free: a
// refused call returns the existing typed error and no text hit, address or
// object. structuredContent is not asserted here beyond reading it as the
// source of truth, so these tests pin the text channel without pinning a
// changed structured projection.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// mcpTextInventoryEvidence is the inventory harness variant that returns a page
// with skipped ledger rows, which the shared fakeInventoryEvidence does not
// build from its items slice.
type mcpTextInventoryEvidence struct {
	*fakeEvidenceService
	page evidence.ObjectInventoryPage
}

func (service *mcpTextInventoryEvidence) ListObjects(_ context.Context, _ database.AccessContext, _ string, _ bool, _, _ int64) (evidence.ObjectInventoryPage, error) {
	return service.page, nil
}

// mcpContentTextBlock extracts the single text block of an MCP result and fails
// the test when the channel is absent or empty.
func mcpContentTextBlock(t *testing.T, content []map[string]any) string {
	t.Helper()
	if len(content) != 1 {
		t.Fatalf("content blocks=%#v, want exactly one text block", content)
	}
	if kind, _ := content[0]["type"].(string); kind != "text" {
		t.Fatalf("content[0].type=%#v, want text", content[0]["type"])
	}
	text, _ := content[0]["text"].(string)
	if strings.TrimSpace(text) == "" {
		t.Fatalf("content[0].text is empty: %#v", content[0])
	}
	return text
}

// mcpAssertAddressesInText asserts that, per address, the text channel contains
// the identical address value the structured channel carries. The structured
// value is marshalled the same deterministic way the production renderer
// marshals it, so a dropped or altered address fails the assertion.
func mcpAssertAddressesInText(t *testing.T, text string, addresses []any) {
	t.Helper()
	if len(addresses) == 0 {
		t.Fatal("structured channel carried no address to compare")
	}
	for index, raw := range addresses {
		encoded, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("structured address[%d] did not marshal: %v", index, err)
		}
		if !strings.Contains(text, string(encoded)) {
			t.Fatalf("text channel omitted structured address[%d] %s: %q", index, encoded, text)
		}
	}
}

// TestMCPContentTextCarriesSearchHitsAndCursor proves a text-channel-only
// client of knowvault_search sees every hit's address, excerpt, score and
// version id, one line per hit, plus the page offset/limit/has_more/next_offset.
func TestMCPContentTextCarriesSearchHitsAndCursor(t *testing.T) {
	first := testSearchHit(t)
	second := testSearchHit(t)
	second.Fragment.SourceVersionID = "version_02"
	second.Fragment.FragmentID = "fragment_02"
	second.Excerpt = "line one\nline two"
	second.Score = 7
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{first, second}, HasMore: true, NextOffset: 1}}
	harness := searchHarness(t, service)

	envelope := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"alpha","limit":1}`)
	if envelope.Error != nil {
		t.Fatalf("search denied unexpectedly: %#v", envelope.Error)
	}
	text := mcpContentTextBlock(t, envelope.Result.Content)

	for _, result := range envelope.Result.Structured.Results {
		canonical, _ := result["canonical_address"].(string)
		selector, err := address.Parse(canonical)
		if err != nil || selector.Object != result["fragment_id"] || !strings.Contains(text, "canonical_address="+canonical+" ") {
			t.Fatalf("search text lost a readable canonical address: %q %v", canonical, err)
		}
		if result["address"] == nil {
			t.Fatal("structured compatibility address was removed")
		}
	}
	if strings.Contains(text, " address=") {
		t.Fatal("search text duplicates the canonical address as compatibility JSON")
	}

	for _, want := range []string{
		"excerpt=" + first.Excerpt, "score=3", "version_id=version_02",
		"fragment_id=" + second.Fragment.FragmentID,
		"excerpt=line one line two", "score=7",
		"offset=0", "limit=1", "has_more=true", "next_offset=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("search text channel omitted %q: %q", want, text)
		}
	}
	if lines := strings.Count(text, "\n"); lines != len(envelope.Result.Structured.Results)+1 {
		t.Fatalf("search text is not one line per hit: %d newline(s) for %d hit(s): %q", lines, len(envelope.Result.Structured.Results), text)
	}
	if strings.Contains(text, "line one\nline two") {
		t.Fatalf("search text kept a multi-line excerpt: %q", text)
	}
}

func TestMCPSearchTextKeepsCompatibilityAddressWhenCanonicalUnavailable(t *testing.T) {
	hit := workspaceSearchHit{Fragment: testSearchHit(t).Fragment}
	projection := mcpSearchHitProjection(hit)
	var text strings.Builder
	mcpSearchHitLine(&text, "[1]", hit, projection)
	mcpAssertAddressesInText(t, text.String(), []any{projection["address"]})
}

// TestMCPContentTextCarriesInventoryObjectsSkipsAndCursor proves a
// text-channel-only client of knowvault_list_objects sees every object's
// address, object_type, version keys and moment, every skipped row's reason
// code, plus the page offset/limit/has_more/next_offset.
func TestMCPContentTextCarriesInventoryObjectsSkipsAndCursor(t *testing.T) {
	moment := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	items := testInventoryItems()
	page := evidence.ObjectInventoryPage{
		Items:      items[:1],
		HasMore:    true,
		NextOffset: 1,
		Skipped: []evidence.ObjectInventorySkip{{
			ExternalID: "native:skipped-a", ReasonCode: "FOLDER_MEDIA_SIGNATURE_MISMATCH", ObservedAt: moment,
		}},
	}
	harness := newTestHarness(t)
	service := &mcpTextInventoryEvidence{fakeEvidenceService: harness.evidence, page: page}
	harness.handler.evidence = service

	envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha","limit":1}`)
	if envelope.Error != nil {
		t.Fatalf("inventory list refused: %#v", envelope.Error)
	}
	text := mcpContentTextBlock(t, envelope.Result.Content)

	objects, _ := envelope.Result.Structured["objects"].([]any)
	addresses := make([]any, 0, len(objects))
	for _, raw := range objects {
		object, _ := raw.(map[string]any)
		addresses = append(addresses, object["address"])
	}
	mcpAssertAddressesInText(t, text, addresses)

	for _, want := range []string{
		"object_type=FILE", "version_id=version_01", "content_hash=" + items[0].ContentHash,
		"observed_at=2026-08-13T10:00:00Z", "current=true", "version_state=CURRENT",
		"reason_code=FOLDER_MEDIA_SIGNATURE_MISMATCH", "external_id=native:skipped-a",
		"offset=0", "limit=1", "has_more=true", "next_offset=1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("inventory text channel omitted %q: %q", want, text)
		}
	}
	if !strings.Contains(text, "skipped:") {
		t.Fatalf("inventory text channel omitted the skipped ledger: %q", text)
	}
}

// TestMCPContentTextDenialStaysContentFree proves both tools keep the existing
// content-free denial: a non-member or cross-workspace call returns the typed
// -32004 with no text block, no hit text and no address.
func TestMCPContentTextDenialStaysContentFree(t *testing.T) {
	searchService := &fakeSearchEvidence{searchErr: evidence.ErrNotFound}
	searchEnvelope := callMCPSearch(t, searchHarness(t, searchService), mcpToolSearch, `{"workspace_id":"ws_secret","query":"alpha"}`)
	if searchEnvelope.Error == nil || searchEnvelope.Error.Code != -32004 {
		t.Fatalf("search denial=%#v", searchEnvelope.Error)
	}
	if len(searchEnvelope.Result.Content) != 0 || len(searchEnvelope.Result.Structured.Results) != 0 {
		t.Fatalf("search denial leaked content: %#v", searchEnvelope.Result)
	}

	listEnvelope := callMCPWorkspaceList(t, workspaceListHarness(t, &fakeInventoryEvidence{listErr: evidence.ErrNotFound}), `{"workspace_id":"ws_secret"}`)
	if listEnvelope.Error == nil || listEnvelope.Error.Code != -32004 {
		t.Fatalf("inventory denial=%#v", listEnvelope.Error)
	}
	if len(listEnvelope.Result.Content) != 0 {
		t.Fatalf("inventory denial leaked a text block: %#v", listEnvelope.Result.Content)
	}
	if objects, _ := listEnvelope.Result.Structured["objects"].([]any); len(objects) != 0 {
		t.Fatalf("inventory denial leaked objects: %#v", listEnvelope.Result.Structured)
	}
}

// mcpAssertGrepTextMatches asserts, for one knowvault_grep result, that the text
// channel carries every structured match address, that each match is exactly one
// line carrying its excerpt and version id, and that the trailing line is the
// page cursor with offset, effective limit, has_more and next_offset. It is
// shared by the no-ref and the ref-scoped assertions so both call shapes pin the
// same text-channel contract.
func mcpAssertGrepTextMatches(t *testing.T, text string, matches []map[string]any, offset, limit int64, hasMore bool, nextOffset string) {
	t.Helper()
	addresses := make([]any, 0, len(matches))
	for _, match := range matches {
		addresses = append(addresses, match["address"])
	}
	mcpAssertAddressesInText(t, text, addresses)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != len(matches)+1 {
		t.Fatalf("grep text is not one line per match plus the trailing cursor: %d line(s) for %d match(es): %q", len(lines), len(matches), text)
	}
	for index, match := range matches {
		line := lines[index]
		for _, member := range []string{"address=", "canonical_address=", "fragment_id=", "offset=", "length=", "version_id=", "observed_at=", "content_hash=", "excerpt="} {
			if !strings.Contains(line, member) {
				t.Fatalf("grep text match line %d omitted %s: %q", index, member, line)
			}
		}
		// The canonical kv1 address string itself, not just the compact-JSON
		// address object, so a text-channel-only model can re-address the hit
		// into knowvault_read by passing this exact string (R3a-1 r8c).
		canonical, _ := match["canonical_address"].(string)
		if canonical == "" {
			t.Fatalf("grep structured match %d carries no canonical_address: %#v", index, match)
		}
		if !strings.Contains(line, "canonical_address="+canonical) {
			t.Fatalf("grep text match line %d omitted the canonical address %q: %q", index, canonical, line)
		}
		if excerpt, _ := match["excerpt"].(string); excerpt != "" {
			if !strings.Contains(line, "excerpt="+mcpContentSingleLine(excerpt)) {
				t.Fatalf("grep text match line %d omitted the excerpt %q: %q", index, excerpt, line)
			}
		}
		if version, _ := match["version_id"].(string); version != "" && !strings.Contains(line, "version_id="+version) {
			t.Fatalf("grep text match line %d omitted version %q: %q", index, version, line)
		}
	}
	cursor := lines[len(lines)-1]
	for _, want := range []string{
		"offset=" + strconv.FormatInt(offset, 10),
		"limit=" + strconv.FormatInt(limit, 10),
		"has_more=" + strconv.FormatBool(hasMore),
		"next_offset=" + nextOffset,
	} {
		if !strings.Contains(cursor, want) {
			t.Fatalf("grep text cursor line omitted %q: %q", want, cursor)
		}
	}
}

// mcpGrepStructuredNextOffset renders the structured next_offset the same way
// the text cursor renders it, so the assertion compares the two channels.
func mcpGrepStructuredNextOffset(value *int64) string {
	if value == nil {
		return "null"
	}
	return strconv.FormatInt(*value, 10)
}

// TestMCPContentTextCarriesGrepMatchesAndCursor proves a text-channel-only
// client of knowvault_grep sees every match's address, excerpt, offset, version
// id and moment, exactly one line per match, plus the trailing page cursor. For
// a ref-scoped call it also sees the repository-relative path and the 1-based
// file:lines range of each code-source match, while a no-ref document hit never
// gains that code locator.
func TestMCPContentTextCarriesGrepMatchesAndCursor(t *testing.T) {
	service, _ := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	documentEnvelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle"}`)
	if documentEnvelope.Error != nil {
		t.Fatalf("no-ref grep denied unexpectedly: %#v", documentEnvelope.Error)
	}
	documentText := mcpContentTextBlock(t, documentEnvelope.Result.Content)
	mcpAssertGrepTextMatches(t, documentText,
		documentEnvelope.Result.Structured.Matches,
		documentEnvelope.Result.Structured.Offset,
		documentEnvelope.Result.Structured.Limit,
		documentEnvelope.Result.Structured.HasMore,
		mcpGrepStructuredNextOffset(documentEnvelope.Result.Structured.NextOffset))
	if strings.Contains(documentText, " path=") {
		t.Fatalf("no-ref grep text gained a code locator: %q", documentText)
	}

	refEnvelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"needle","ref":"aaaa"}`)
	if refEnvelope.Error != nil {
		t.Fatalf("ref grep denied unexpectedly: %#v", refEnvelope.Error)
	}
	refText := mcpContentTextBlock(t, refEnvelope.Result.Content)
	mcpAssertGrepTextMatches(t, refText,
		refEnvelope.Result.Structured.Matches,
		refEnvelope.Result.Structured.Offset,
		refEnvelope.Result.Structured.Limit,
		refEnvelope.Result.Structured.HasMore,
		mcpGrepStructuredNextOffset(refEnvelope.Result.Structured.NextOffset))
	for _, want := range []string{"path=internal/code/main.go", "line=3", "column=4", "end_line=3", "end_column=10"} {
		if !strings.Contains(refText, want) {
			t.Fatalf("ref grep text omitted %q: %q", want, refText)
		}
	}
}

// TestMCPContentTextGrepDenialStaysContentFree proves the grep text channel
// stays content-free on a denial: the existing typed -32004 with no text block
// and no address, exactly as before the text channel carried the matches.
func TestMCPContentTextGrepDenialStaysContentFree(t *testing.T) {
	service := &fakeGrepEvidence{grepErr: evidence.ErrNotFound}
	harness := grepHarness(t, service)
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_secret","pattern":"needle"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("grep denial=%#v", envelope.Error)
	}
	if len(envelope.Result.Content) != 0 {
		t.Fatalf("grep denial leaked a text block: %#v", envelope.Result.Content)
	}
	if len(envelope.Result.Structured.Matches) != 0 {
		t.Fatalf("grep denial leaked matches: %#v", envelope.Result.Structured.Matches)
	}
}

// --- R3a-1: knowvault_read content[].text contract ---

// mcpReadTextPage splits one knowvault_read content[].text value into the page
// text and its single trailing metadata line. The metadata line is the last
// line; the page text is every byte before its delimiter, so the page's own
// newlines (and empty pages) are preserved exactly.
func mcpReadTextPage(t *testing.T, content []map[string]any) (string, map[string]string) {
	t.Helper()
	if len(content) != 1 {
		t.Fatalf("read content blocks=%#v, want exactly one text block", content)
	}
	if kind, _ := content[0]["type"].(string); kind != "text" {
		t.Fatalf("read content[0].type=%#v, want text", content[0]["type"])
	}
	text, _ := content[0]["text"].(string)
	index := strings.LastIndex(text, "\n")
	if index < 0 {
		t.Fatalf("read text has no trailing metadata line: %q", text)
	}
	return text[:index], mcpReadMetadataFields(t, text[index+1:])
}

// mcpReadMetadataFields parses the single trailing knowvault_read line into its
// key=value members. The address JSON is the final member and is taken as the
// whole remainder, so a JSON string value containing a space cannot split the
// space-separated window members.
func mcpReadMetadataFields(t *testing.T, line string) map[string]string {
	t.Helper()
	const prefix = "knowvault_read"
	const addressMarker = " address="
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("read metadata line does not open with %q: %q", prefix, line)
	}
	body := strings.TrimPrefix(line, prefix)
	index := strings.Index(body, addressMarker)
	if index < 0 {
		t.Fatalf("read metadata line carries no address member: %q", line)
	}
	fields := map[string]string{"address": body[index+len(addressMarker):]}
	for _, token := range strings.Split(strings.TrimSpace(body[:index]), " ") {
		key, value, ok := strings.Cut(token, "=")
		if !ok || key == "" {
			t.Fatalf("read metadata token %q is not key=value: %q", token, line)
		}
		fields[key] = value
	}
	return fields
}

// mcpAssertReadGeometry asserts that the trailing line of one read page carries
// the same offset, has_more, window and page hash the structuredContent channel
// carries, plus the identical structured address.
func mcpAssertReadGeometry(t *testing.T, structured map[string]any, meta map[string]string, pageText string) {
	t.Helper()
	addressJSON, err := json.Marshal(structured["address"])
	if err != nil {
		t.Fatalf("structured address did not marshal: %v", err)
	}
	if meta["address"] != string(addressJSON) {
		t.Fatalf("read text address=%q want structured address %s", meta["address"], addressJSON)
	}
	// The canonical kv1 address string itself must appear in the text channel,
	// not only the structured address object's members, so a text-channel-only
	// model can pass it straight back to knowvault_read (R3a-1 r8c).
	canonicalAddress, _ := structured["canonical_address"].(string)
	if canonicalAddress == "" {
		t.Fatalf("read structuredContent carries no canonical_address: %#v", structured)
	}
	if meta["canonical_address"] != canonicalAddress {
		t.Fatalf("read text canonical_address=%q want structured %q", meta["canonical_address"], canonicalAddress)
	}
	offset, _ := structured["offset"].(float64)
	if meta["offset"] != strconv.FormatInt(int64(offset), 10) {
		t.Fatalf("read text offset=%q want %d", meta["offset"], int64(offset))
	}
	if meta["length"] != strconv.FormatInt(int64(len(pageText)), 10) {
		t.Fatalf("read text length=%q want %d", meta["length"], len(pageText))
	}
	hasMore, _ := structured["has_more"].(bool)
	if meta["has_more"] != strconv.FormatBool(hasMore) {
		t.Fatalf("read text has_more=%q want %v", meta["has_more"], hasMore)
	}
	if _, wholeObject := structured["next_cursor"]; wholeObject {
		// The whole-object page core windows the reassembled object with the
		// stable address.Read cursor instead of a plain byte offset, so its
		// structuredContent carries next_cursor and no next_offset member and
		// the text channel must match that cursor exactly.
		if nextOffset, present := structured["next_offset"]; present && nextOffset != nil {
			t.Fatalf("whole-object read page offered next_offset=%#v; the cursor mode uses next_cursor", nextOffset)
		}
		if structured["next_cursor"] == nil {
			if meta["next_cursor"] != "null" {
				t.Fatalf("final whole-object read text page next_cursor=%q want null", meta["next_cursor"])
			}
		} else if next, _ := structured["next_cursor"].(string); meta["next_cursor"] != next {
			t.Fatalf("read text next_cursor=%q want %q", meta["next_cursor"], next)
		}
	} else if structured["next_offset"] == nil {
		if meta["next_offset"] != "null" {
			t.Fatalf("final read text page next_offset=%q want null", meta["next_offset"])
		}
	} else if next, _ := structured["next_offset"].(float64); meta["next_offset"] != strconv.FormatInt(int64(next), 10) {
		t.Fatalf("read text next_offset=%q want %d", meta["next_offset"], int64(next))
	}
	if meta["page_hash"] != structured["page_hash"] || meta["page_hash"] != mcpEvidencePageHash([]byte(pageText)) {
		t.Fatalf("read text page_hash=%q want structured %v and the returned page", meta["page_hash"], structured["page_hash"])
	}
}

// TestMCPContentTextReadPagesCarryAddressWindowAndHashes proves the
// knowvault_read content[].text channel of the single-fragment page core is the
// page text plus exactly one trailing metadata line carrying the identical
// structured address, the window (offset/length/next_offset/has_more/limit), the
// whole-fragment text_hash and the page_hash, that no page duplicates its bytes
// as text_base64 by default, and that concatenating every page's text-channel
// bytes reproduces the stored original, which hashes to text_hash.
func TestMCPContentTextReadPagesCarryAddressWindowAndHashes(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte(strings.Repeat("\u043d\u043e\u0440\u043c\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442 ", 20))
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	var assembled []byte
	offset := 0
	pages := 0
	for {
		envelope := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","offset":`+strconv.Itoa(offset)+`,"limit":9}`)
		if envelope.Error != nil {
			t.Fatalf("read page at offset %d refused: %#v", offset, envelope.Error)
		}
		structured := envelope.Result.Structured
		if _, present := structured["text_base64"]; present {
			t.Fatalf("default read page duplicated its bytes as text_base64: %#v", structured)
		}
		pageText, meta := mcpReadTextPage(t, envelope.Result.Content)
		if structured["text"] != pageText {
			t.Fatalf("structured text does not equal the text-channel page: %#v vs %q", structured["text"], pageText)
		}
		mcpAssertReadGeometry(t, structured, meta, pageText)
		if meta["limit"] != "9" {
			t.Fatalf("read text limit=%q want the effective limit 9", meta["limit"])
		}
		if meta["text_hash"] != fragment.EvidenceTextHash {
			t.Fatalf("read text text_hash=%q want %q", meta["text_hash"], fragment.EvidenceTextHash)
		}
		assembled = append(assembled, []byte(pageText)...)
		pages++
		hasMore, _ := structured["has_more"].(bool)
		if !hasMore {
			if structured["next_offset"] != nil {
				t.Fatalf("final read page offered next_offset: %#v", structured)
			}
			break
		}
		next, _ := meta["next_offset"]
		value, err := strconv.Atoi(next)
		if err != nil || value <= offset {
			t.Fatalf("non-progressing read next_offset=%q at offset=%d", next, offset)
		}
		offset = value
		if pages > len(fragment.Text) {
			t.Fatalf("read pagination did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("expected a multi-page read, got %d page(s)", pages)
	}
	if string(assembled) != string(fragment.Text) {
		t.Fatalf("text-channel reassembly %d bytes != stored original %d bytes", len(assembled), len(fragment.Text))
	}
	if mcpEvidenceReadTextHash(assembled) != fragment.EvidenceTextHash {
		t.Fatalf("text-channel reassembly does not hash to text_hash")
	}
}

// TestMCPContentTextReadBase64OnlyWhenRequested proves the default read result
// no longer duplicates every page as text plus base64 plus the envelope: the
// base64 member is absent unless the caller passes the additive
// include_text_base64 argument, and when requested it decodes to exactly the
// page the text channel carries.
func TestMCPContentTextReadBase64OnlyWhenRequested(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("\u043a\u043e\u043c\u043f\u0430\u043a\u0442\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442 \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u044b: KnowVault")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	byDefault := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`"}`)
	if byDefault.Error != nil {
		t.Fatalf("default read refused: %#v", byDefault.Error)
	}
	if encoded, present := byDefault.Result.Structured["text_base64"]; present {
		t.Fatalf("default read carried text_base64=%#v", encoded)
	}
	defaultPage, _ := mcpReadTextPage(t, byDefault.Result.Content)
	if defaultPage != string(fragment.Text) {
		t.Fatalf("default text channel page=%q want %q", defaultPage, fragment.Text)
	}

	requested := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","include_text_base64":true}`)
	if requested.Error != nil {
		t.Fatalf("base64 read refused: %#v", requested.Error)
	}
	encoded, ok := requested.Result.Structured["text_base64"].(string)
	if !ok || encoded == "" {
		t.Fatalf("requested read carried no text_base64: %#v", requested.Result.Structured)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("requested text_base64 did not decode: %v", err)
	}
	requestedPage, _ := mcpReadTextPage(t, requested.Result.Content)
	if string(decoded) != requestedPage || requestedPage != defaultPage {
		t.Fatalf("text_base64 does not decode to the text-channel page")
	}
}

// TestMCPContentTextWholeObjectReadCarriesCursorAndReassembles proves the
// knowvault_read content[].text channel of the whole-object page core is the
// page text plus exactly one trailing metadata line carrying the identical
// structured address, offset, next_cursor, has_more, whole_hash and page_hash,
// that no page duplicates its bytes as text_base64 by default, and that
// concatenating every page's text-channel bytes reproduces the whole original
// that hashes to whole_hash.
func TestMCPContentTextWholeObjectReadCarriesCursorAndReassembles(t *testing.T) {
	anchor, whole, emitted := testWholeObjectAnchor(t)
	service := &fakeWholeObjectEvidence{object: evidence.WholeObject{
		Fragment: anchor, Text: whole, FragmentCount: 3, FirstOrdinal: 1, LastOrdinal: 3,
	}}
	harness := wholeObjectHarness(t, service)

	var assembled []byte
	cursor := ""
	pages := 0
	for {
		envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
			"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID,
			"address": emitted, "cursor": cursor, "limit": 64,
		}))
		if envelope.Error != nil {
			t.Fatalf("whole-object text page refused: %#v", envelope.Error)
		}
		structured := envelope.Result.Structured
		if _, present := structured["text_base64"]; present {
			t.Fatalf("default whole-object page duplicated its bytes as text_base64: %#v", structured)
		}
		pageText, meta := mcpReadTextPage(t, envelope.Result.Content)
		mcpAssertReadGeometry(t, structured, meta, pageText)
		if meta["whole_hash"] != structured["whole_hash"] {
			t.Fatalf("read text whole_hash=%q want %v", meta["whole_hash"], structured["whole_hash"])
		}
		if structured["next_cursor"] == nil {
			if meta["next_cursor"] != "null" {
				t.Fatalf("final whole-object text page next_cursor=%q want null", meta["next_cursor"])
			}
		} else if next, _ := structured["next_cursor"].(string); meta["next_cursor"] != next {
			t.Fatalf("read text next_cursor=%q want %q", meta["next_cursor"], next)
		}
		assembled = append(assembled, []byte(pageText)...)
		pages++
		hasMore, _ := structured["has_more"].(bool)
		if !hasMore {
			break
		}
		cursor, _ = structured["next_cursor"].(string)
		if pages > len(whole) {
			t.Fatalf("whole-object text pagination did not terminate")
		}
	}
	if pages < 2 {
		t.Fatalf("expected a multi-page whole-object read, got %d page(s)", pages)
	}
	if string(assembled) != string(whole) {
		t.Fatalf("text-channel reassembly %d bytes != whole original %d bytes", len(assembled), len(whole))
	}
	if address.WholeHash(assembled) != address.WholeHash(whole) {
		t.Fatalf("text-channel reassembly does not hash to the whole-object hash")
	}
}

// --- R3a-1: knowvault_related content[].text contract ---

// mcpAssertRelatedTextHits asserts, for one knowvault_related result, that the
// text channel carries every structured relation address byte-identically, that
// each relation is exactly one line carrying its kind, flattened excerpt,
// fragment id, version id, moment and content hash, and that the leading page
// line carries the same direction, effective limit, has_more and next_cursor the
// structuredContent channel carries.
func mcpAssertRelatedTextHits(t *testing.T, text string, relations []map[string]any, direction string, limit int64, hasMore bool, nextCursor string) {
	t.Helper()
	if len(relations) == 0 {
		if strings.Contains(text, " address=") {
			t.Fatalf("related text leaked an address for an empty page: %q", text)
		}
	} else {
		addresses := make([]any, 0, len(relations))
		for _, relation := range relations {
			addresses = append(addresses, relation["address"])
		}
		mcpAssertAddressesInText(t, text, addresses)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != len(relations)+1 {
		t.Fatalf("related text is not one line per relation plus the page line: %d line(s) for %d relation(s): %q", len(lines), len(relations), text)
	}
	for index, relation := range relations {
		line := lines[index+1]
		for _, member := range []string{"address=", "relation_kind=", "excerpt=", "fragment_id=", "version_id=", "observed_at=", "content_hash="} {
			if !strings.Contains(line, member) {
				t.Fatalf("related text relation line %d omitted %s: %q", index, member, line)
			}
		}
		for _, member := range []string{"relation_kind", "version_id", "observed_at", "content_hash"} {
			value, _ := relation[member].(string)
			if value != "" && !strings.Contains(line, member+"="+value) {
				t.Fatalf("related text relation line %d omitted %s=%q: %q", index, member, value, line)
			}
		}
		if fragment, _ := relation["fragment_id"].(string); fragment != "" && !strings.Contains(line, "fragment_id="+fragment) {
			t.Fatalf("related text relation line %d omitted fragment_id=%q: %q", index, fragment, line)
		}
		if excerpt, _ := relation["excerpt"].(string); excerpt != "" && !strings.Contains(line, "excerpt="+mcpContentSingleLine(excerpt)) {
			t.Fatalf("related text relation line %d omitted the flattened excerpt %q: %q", index, excerpt, line)
		}
	}
	pageLine := lines[0]
	for _, want := range []string{
		"direction=" + direction,
		"limit=" + strconv.FormatInt(limit, 10),
		"has_more=" + strconv.FormatBool(hasMore),
		"next_cursor=" + nextCursor,
	} {
		if !strings.Contains(pageLine, want) {
			t.Fatalf("related text page line omitted %q: %q", want, pageLine)
		}
	}
}

// mcpRelatedStructuredNextCursor renders the structured next_cursor the same way
// the text page line renders it, so the assertion compares the two channels.
func mcpRelatedStructuredNextCursor(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

// TestMCPContentTextCarriesRelatedHitsAndCursor proves a text-channel-only client
// of knowvault_related sees, on every page, one line per relation with its
// address, kind, flattened excerpt, fragment id, version id, moment and content
// hash, plus the direction, effective limit, has_more and next_cursor, including
// the null cursor on the final page.
func TestMCPContentTextCarriesRelatedHitsAndCursor(t *testing.T) {
	first := testRelatedHit(t, "fragment_01")
	second := testRelatedHit(t, "fragment_02")
	second.RelationKind = "context.references"
	second.Excerpt = "line one\nline two"
	service := &fakeRelatedEvidence{hits: []RelatedHit{first, second}}
	harness := relatedHarness(t, service)

	firstEnvelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_root","limit":1}`)
	if firstEnvelope.Error != nil {
		t.Fatalf("related page one refused: %#v", firstEnvelope.Error)
	}
	if !firstEnvelope.Result.Structured.HasMore || firstEnvelope.Result.Structured.NextCursor == nil {
		t.Fatalf("related page one did not report a next page: %#v", firstEnvelope.Result.Structured)
	}
	firstText := mcpContentTextBlock(t, firstEnvelope.Result.Content)
	mcpAssertRelatedTextHits(t, firstText,
		firstEnvelope.Result.Structured.Relations,
		firstEnvelope.Result.Structured.Direction,
		firstEnvelope.Result.Structured.Limit,
		firstEnvelope.Result.Structured.HasMore,
		mcpRelatedStructuredNextCursor(firstEnvelope.Result.Structured.NextCursor))

	secondEnvelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_root","limit":1,"cursor":"v1:1"}`)
	if secondEnvelope.Error != nil {
		t.Fatalf("related page two refused: %#v", secondEnvelope.Error)
	}
	if secondEnvelope.Result.Structured.HasMore || secondEnvelope.Result.Structured.NextCursor != nil {
		t.Fatalf("related page two was not the final page: %#v", secondEnvelope.Result.Structured)
	}
	secondText := mcpContentTextBlock(t, secondEnvelope.Result.Content)
	mcpAssertRelatedTextHits(t, secondText,
		secondEnvelope.Result.Structured.Relations,
		secondEnvelope.Result.Structured.Direction,
		secondEnvelope.Result.Structured.Limit,
		secondEnvelope.Result.Structured.HasMore,
		mcpRelatedStructuredNextCursor(secondEnvelope.Result.Structured.NextCursor))
	for _, want := range []string{"next_cursor=null", "excerpt=line one line two"} {
		if !strings.Contains(secondText, want) {
			t.Fatalf("related final-page text omitted %q: %q", want, secondText)
		}
	}
	if strings.Contains(secondText, "line one\nline two") {
		t.Fatalf("related text kept a multi-line excerpt: %q", secondText)
	}

	emptyEnvelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_alpha","fragment_id":"fragment_absent"}`)
	if emptyEnvelope.Error != nil {
		t.Fatalf("empty related page refused: %#v", emptyEnvelope.Error)
	}
	emptyText := mcpContentTextBlock(t, emptyEnvelope.Result.Content)
	mcpAssertRelatedTextHits(t, emptyText,
		emptyEnvelope.Result.Structured.Relations,
		emptyEnvelope.Result.Structured.Direction,
		emptyEnvelope.Result.Structured.Limit,
		emptyEnvelope.Result.Structured.HasMore,
		mcpRelatedStructuredNextCursor(emptyEnvelope.Result.Structured.NextCursor))
	if !strings.Contains(emptyText, "0 relation(s)") {
		t.Fatalf("empty related text did not state the empty page: %q", emptyText)
	}
}

// TestMCPContentTextRelatedDenialStaysContentFree proves the related text channel
// stays content-free on a denial: the existing typed -32004 with no content block
// and no relation, excerpt or address, exactly as before the text channel carried
// the relation hits.
func TestMCPContentTextRelatedDenialStaysContentFree(t *testing.T) {
	service := &fakeRelatedEvidence{relatedErr: evidence.ErrNotFound}
	harness := relatedHarness(t, service)
	envelope := callMCPRelated(t, harness, mcpToolRelated, `{"workspace_id":"ws_secret","fragment_id":"fragment_01"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("related denial=%#v", envelope.Error)
	}
	if len(envelope.Result.Content) != 0 {
		t.Fatalf("related denial leaked a text block: %#v", envelope.Result.Content)
	}
	if len(envelope.Result.Structured.Relations) != 0 {
		t.Fatalf("related denial leaked relations: %#v", envelope.Result.Structured.Relations)
	}
}

// --- R3a-1: knowvault_sources content[].text contract ---

// mcpSourcesTextEnvelope is the decoded envelope of one knowvault_sources call,
// exposing both the text channel and the structured source inventory so the test
// can compare them.
type mcpSourcesTextEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured struct {
			Sources []map[string]any `json:"sources"`
		} `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPSourcesText(t *testing.T, harness *testHarness) mcpSourcesTextEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"src-text","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_alpha"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP sources text status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpSourcesTextEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP sources text did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// mcpAssertSourcesInText asserts that every structuredContent source entry is
// present in the text channel with its identical workspace_source_id and
// source_scope_id, so a text-channel-only client can never lose a source the
// structured channel carried.
func mcpAssertSourcesInText(t *testing.T, text string, sources []map[string]any) {
	t.Helper()
	if len(sources) == 0 {
		t.Fatal("structured channel carried no source to compare")
	}
	for index, source := range sources {
		for _, member := range []string{"workspace_source_id", "source_scope_id"} {
			value, _ := source[member].(string)
			if value == "" {
				t.Fatalf("structured source[%d] had no %s: %#v", index, member, source)
			}
			if !strings.Contains(text, member+"="+value) {
				t.Fatalf("text channel omitted structured source[%d] %s=%q: %q", index, member, value, text)
			}
		}
	}
}

// TestMCPContentTextCarriesSourcesInventory proves a text-channel-only client of
// knowvault_sources sees every structured source entry with the same
// workspace_source_id, source_scope_id, enabled, activation/sync status and
// schedule/freshness values, one line per source, without parsing
// structuredContent.
func TestMCPContentTextCarriesSourcesInventory(t *testing.T) {
	harness := newTestHarness(t)
	started := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	completed := started.Add(2 * time.Minute)
	syncStatus := "SYNCED"
	freshnessState := "FRESH"
	secondSyncStatus := "FAILED"
	secondFreshness := "STALE"
	postgresqlSchemaName, postgresqlRelationName := "reporting", "waste_daily"
	zero := int64(0)
	harness.sources.statuses = []workspacerepository.SourceStatus{
		{
			WorkspaceSourceID: "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: testScopeID,
			Enabled: true, ActivationStatus: "READY", TrustVerified: true,
			SourceType: "POSTGRESQL_QUERY", PostgreSQLSchemaName: &postgresqlSchemaName, PostgreSQLRelationName: &postgresqlRelationName,
			SyncStatus: &syncStatus, LastSuccessfulSyncAt: &completed,
			FreshnessState: freshnessState, SyncIntervalSeconds: 1800, Confirmed: true,
			ObjectsSeen: &zero, ObjectsIngested: &zero, Quarantined: &zero,
		},
		{
			WorkspaceSourceID: "wsrc_01H9ABCDEFGHJKMNPQRSTVWXY2", SourceScopeID: testScopeID + "2",
			Enabled: false, ActivationStatus: "PENDING", TrustVerified: false,
			SyncStatus: &secondSyncStatus, LastSuccessfulSyncAt: nil,
			FreshnessState: secondFreshness, SyncIntervalSeconds: 3600, Confirmed: false,
		},
	}
	harness.sources.confirmationContext = workspacerepository.ConfirmationContext{
		ExpectedPolicyRevision: "policy-acc-0001", ViewerPrincipalID: "principal_alpha",
	}

	envelope := callMCPSourcesText(t, harness)
	if envelope.Error != nil {
		t.Fatalf("sources text call refused: %#v", envelope.Error)
	}
	text := mcpContentTextBlock(t, envelope.Result.Content)
	mcpAssertSourcesInText(t, text, envelope.Result.Structured.Sources)

	for _, want := range []string{
		"workspace_source_id=wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		"source_scope_id=" + testScopeID,
		"source_type=POSTGRESQL_QUERY", "postgresql_schema_name=reporting", "postgresql_relation_name=waste_daily",
		"enabled=true", "activation_status=READY", "sync_status=SYNCED",
		"freshness_state=FRESH", "sync_interval_seconds=1800",
		"last_successful_sync_at=2026-09-12T10:02:00Z",
		"objects_seen=0", "objects_ingested=0", "quarantined=0",
		"enabled=false", "activation_status=PENDING", "sync_status=FAILED",
		"freshness_state=STALE", "sync_interval_seconds=3600",
		"last_successful_sync_at=null",
		"objects_seen=null", "objects_ingested=null", "quarantined=null",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("sources text channel omitted %q: %q", want, text)
		}
	}
	if lines := strings.Count(text, "\n"); lines != len(envelope.Result.Structured.Sources)+1 {
		t.Fatalf("sources text is not one line per source: %d newline(s) for %d source(s): %q", lines, len(envelope.Result.Structured.Sources), text)
	}
}

// TestMCPContentTextSourcesDenialStaysContentFree proves a denied knowvault_sources
// call still returns the existing typed error with no content text block and no
// source entry, exactly as before the text channel carried the inventory.
func TestMCPContentTextSourcesDenialStaysContentFree(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.err = workspacerepository.NewError(workspacerepository.CodeDenied, nil)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"src-text-deny","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_foreign"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP sources denial status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpSourcesTextEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP sources denial did not decode: %v: %s", err, response.Body.String())
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("MCP sources denial error=%#v body=%s", envelope.Error, response.Body.String())
	}
	if len(envelope.Result.Content) != 0 {
		t.Fatalf("sources denial leaked a text block: %#v", envelope.Result.Content)
	}
	if len(envelope.Result.Structured.Sources) != 0 {
		t.Fatalf("sources denial leaked sources: %#v", envelope.Result.Structured.Sources)
	}
	for _, leaked := range []string{testScopeID, "ws_foreign", "knowvault_sources:"} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("sources denial leaked %q: %s", leaked, response.Body.String())
		}
	}
}

// --- R3a-1: knowvault_refresh content[].text contract ---

// mcpRefreshStructuredPage is the structured refresh page of one
// knowvault_refresh result, exposing every member the text channel must carry.
type mcpRefreshStructuredPage struct {
	Refreshed  []map[string]any `json:"refreshed"`
	Skipped    []map[string]any `json:"skipped"`
	Offset     int64            `json:"offset"`
	Limit      int64            `json:"limit"`
	HasMore    bool             `json:"has_more"`
	NextOffset *int64           `json:"next_offset"`
}

// mcpRefreshTextEnvelope is the decoded envelope of one knowvault_refresh call,
// exposing both the text channel and the structured refresh page so the test can
// compare them member by member.
type mcpRefreshTextEnvelope struct {
	Result struct {
		Content    []map[string]any         `json:"content"`
		Structured mcpRefreshStructuredPage `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPRefreshText(t *testing.T, harness *testHarness, arguments string) mcpRefreshTextEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"refresh-text","method":"tools/call","params":{"name":"`+mcpToolRefresh+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP refresh text status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpRefreshTextEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP refresh text did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// mcpRefreshTextNextOffset renders the structured next_offset the same way the
// text cursor line renders it, so the assertion compares the two channels.
func mcpRefreshTextNextOffset(value *int64) string {
	if value == nil {
		return "null"
	}
	return strconv.FormatInt(*value, 10)
}

// mcpAssertRefreshTextMatchesPage asserts, entry by entry and member by member,
// that the text channel carries every refreshed source's source_scope_id and
// job_id, every skipped source's source_scope_id and closed reason, and the same
// page cursor (offset, effective limit, has_more and next_offset) the
// structured channel carries, so a text-channel-only client can never lose a
// source or the page position.
func mcpAssertRefreshTextMatchesPage(t *testing.T, text string, page mcpRefreshStructuredPage) {
	t.Helper()
	if len(page.Refreshed)+len(page.Skipped) == 0 {
		t.Fatal("structured refresh page carried no source entry to compare")
	}
	for index, entry := range page.Refreshed {
		for _, member := range []string{"source_scope_id", "job_id"} {
			value, _ := entry[member].(string)
			if value == "" {
				t.Fatalf("structured refreshed[%d] had no %s: %#v", index, member, entry)
			}
			if !strings.Contains(text, member+"="+value) {
				t.Fatalf("refresh text omitted refreshed[%d] %s=%q: %q", index, member, value, text)
			}
		}
	}
	for index, entry := range page.Skipped {
		for _, member := range []string{"source_scope_id", "reason"} {
			value, _ := entry[member].(string)
			if value == "" {
				t.Fatalf("structured skipped[%d] had no %s: %#v", index, member, entry)
			}
			if !strings.Contains(text, member+"="+value) {
				t.Fatalf("refresh text omitted skipped[%d] %s=%q: %q", index, member, value, text)
			}
		}
	}
	for _, member := range []string{
		"offset=" + strconv.FormatInt(page.Offset, 10),
		"limit=" + strconv.FormatInt(page.Limit, 10),
		"has_more=" + strconv.FormatBool(page.HasMore),
		"next_offset=" + mcpRefreshTextNextOffset(page.NextOffset),
	} {
		if !strings.Contains(text, member) {
			t.Fatalf("refresh text omitted cursor member %q: %q", member, text)
		}
	}
}

// TestMCPContentTextCarriesRefreshSourcesAndCursor proves a text-channel-only
// client of knowvault_refresh sees every refreshed source's source_scope_id and
// job_id, every skipped source's source_scope_id and reason, and the page
// offset/limit/has_more/next_offset, one compact line per source, both on the
// final page (next_offset null) and on a windowed page (concrete next_offset).
func TestMCPContentTextCarriesRefreshSourcesAndCursor(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{
		{SourceScopeID: "scope_alpha", Enabled: true, ActivationStatus: "READY", TrustVerified: true, Confirmed: true},
		{SourceScopeID: "scope_beta", Enabled: false, ActivationStatus: "READY", TrustVerified: true, Confirmed: true},
	}
	harness.sources.syncResult = registration.SyncResult{JobID: "job_alpha"}

	envelope := callMCPRefreshText(t, harness, `{"workspace_id":"ws_alpha"}`)
	if envelope.Error != nil {
		t.Fatalf("refresh text call refused: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Refreshed) != 1 || len(envelope.Result.Structured.Skipped) != 1 {
		t.Fatalf("refresh page did not carry one refreshed and one skipped source: %#v", envelope.Result.Structured)
	}
	text := mcpContentTextBlock(t, envelope.Result.Content)
	mcpAssertRefreshTextMatchesPage(t, text, envelope.Result.Structured)
	if envelope.Result.Structured.HasMore || envelope.Result.Structured.NextOffset != nil {
		t.Fatalf("refresh final page reported a next page: %#v", envelope.Result.Structured)
	}
	for _, want := range []string{
		"source_scope_id=scope_alpha", "job_id=job_alpha",
		"source_scope_id=scope_beta", "reason=DISABLED",
		"offset=0", "limit=100", "has_more=false", "next_offset=null",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("refresh text channel omitted %q: %q", want, text)
		}
	}
	// A leading count line, exactly one line per source entry, a trailing
	// cursor line — never a copy of the structured JSON envelope.
	if lines := strings.Count(text, "\n"); lines != len(envelope.Result.Structured.Refreshed)+len(envelope.Result.Structured.Skipped)+2 {
		t.Fatalf("refresh text is not one line per source plus header and cursor: %d line(s): %q", lines, text)
	}

	windowed := callMCPRefreshText(t, harness, `{"workspace_id":"ws_alpha","limit":1}`)
	if windowed.Error != nil {
		t.Fatalf("windowed refresh text call refused: %#v", windowed.Error)
	}
	if !windowed.Result.Structured.HasMore || windowed.Result.Structured.NextOffset == nil || *windowed.Result.Structured.NextOffset != 1 {
		t.Fatalf("windowed refresh page did not report the next page: %#v", windowed.Result.Structured)
	}
	windowedText := mcpContentTextBlock(t, windowed.Result.Content)
	mcpAssertRefreshTextMatchesPage(t, windowedText, windowed.Result.Structured)
	if !strings.Contains(windowedText, "next_offset=1") {
		t.Fatalf("windowed refresh text omitted the concrete next_offset: %q", windowedText)
	}
}
