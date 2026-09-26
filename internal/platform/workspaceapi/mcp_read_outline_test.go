package workspaceapi

// mcp_read_outline_test.go proves the R1.S9.s1.T1 knowvault_read outline mode:
// the pure Markdown ATX heading extraction (levels, fenced-code exclusion,
// gist, UTF-8 truncation, the 200-heading bound, a document with no headings,
// and a heading at a fragment boundary) plus the MCP handler (success,
// denials and the cursor/offset conflict), matching the style of
// mcp_read_fragments_test.go and mcp_address_test.go.

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

func TestExtractOutlineHeadingsLevelsAndOrder(t *testing.T) {
	text := []byte("# Title\nintro line\n\n## Section One\nfirst body line\n\n###### Deep\nlast\n")
	headings, truncated := extractOutlineHeadings(text)
	if truncated {
		t.Fatal("small document reported truncated")
	}
	want := []struct {
		level int
		text  string
		gist  string
	}{
		{1, "Title", "intro line"},
		{2, "Section One", "first body line"},
		{6, "Deep", "last"},
	}
	if len(headings) != len(want) {
		t.Fatalf("headings=%#v want %d entries", headings, len(want))
	}
	for i, entry := range want {
		if headings[i].Level != entry.level || headings[i].Text != entry.text || headings[i].Gist != entry.gist {
			t.Fatalf("heading[%d]=%#v want level=%d text=%q gist=%q", i, headings[i], entry.level, entry.text, entry.gist)
		}
	}
	if text[headings[0].Offset] != '#' {
		t.Fatalf("heading[0].Offset=%d does not point at its own line: %q", headings[0].Offset, text[headings[0].Offset])
	}
}

func TestExtractOutlineHeadingsSkipsFencedCode(t *testing.T) {
	text := []byte("# Real Heading\n```\n# not a heading\n~~~\nstill code\n```\n## Also Real\nbody\n")
	headings, truncated := extractOutlineHeadings(text)
	if truncated {
		t.Fatal("small document reported truncated")
	}
	if len(headings) != 2 || headings[0].Text != "Real Heading" || headings[1].Text != "Also Real" {
		t.Fatalf("fenced code leaked into headings: %#v", headings)
	}
}

func TestExtractOutlineHeadingsTildeFenceAndUnterminatedFenceHidesRest(t *testing.T) {
	// An unterminated fence hides every remaining "#" line: it is still inside
	// code as far as the document goes, exactly like a real Markdown renderer.
	text := []byte("# Before\n~~~~\n# inside tilde fence\n" + strings.Repeat("# more code\n", 3))
	headings, _ := extractOutlineHeadings(text)
	if len(headings) != 1 || headings[0].Text != "Before" {
		t.Fatalf("unterminated fence did not hide trailing headings: %#v", headings)
	}
}

func TestExtractOutlineHeadingsRequiresSpaceAfterMarker(t *testing.T) {
	text := []byte("#NoSpace\n#\n# \nreal gist\n")
	headings, _ := extractOutlineHeadings(text)
	// "#NoSpace" is not a heading (no space/tab/EOL after the marker); "#" alone
	// (marker is the whole line) and "# " (marker plus only whitespace) are both
	// valid empty-text ATX headings.
	if len(headings) != 2 || headings[0].Text != "" || headings[1].Text != "" || headings[1].Gist != "real gist" {
		t.Fatalf("marker-without-space handling wrong: %#v", headings)
	}
}

func TestExtractOutlineHeadingsNoHeadingsReturnsEmptyList(t *testing.T) {
	headings, truncated := extractOutlineHeadings([]byte("plain text\nwith no markdown headings at all\n"))
	if len(headings) != 0 || truncated {
		t.Fatalf("document without headings returned %#v truncated=%v", headings, truncated)
	}
}

func TestExtractOutlineHeadingsBoundedAt200(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < 205; i++ {
		builder.WriteString("# H\nbody\n")
	}
	headings, truncated := extractOutlineHeadings([]byte(builder.String()))
	if len(headings) != mcpEvidenceOutlineMaxHeadings || !truncated {
		t.Fatalf("got %d headings truncated=%v, want exactly %d and truncated=true", len(headings), truncated, mcpEvidenceOutlineMaxHeadings)
	}
}

func TestExtractOutlineHeadingsExactly200IsNotTruncated(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < mcpEvidenceOutlineMaxHeadings; i++ {
		builder.WriteString("# H\nbody\n")
	}
	headings, truncated := extractOutlineHeadings([]byte(builder.String()))
	if len(headings) != mcpEvidenceOutlineMaxHeadings || truncated {
		t.Fatalf("got %d headings truncated=%v, want exactly %d and truncated=false", len(headings), truncated, mcpEvidenceOutlineMaxHeadings)
	}
}

func TestOutlineGistTruncatesAtUTF8Boundary(t *testing.T) {
	// Each "к" is 2 bytes; 80 of them is 160 bytes exactly, so one more
	// character must be dropped whole, never split.
	rune2 := "к"
	gistLine := strings.Repeat(rune2, 81)
	text := []byte("# Heading\n" + gistLine + "\n")
	headings, _ := extractOutlineHeadings(text)
	if len(headings) != 1 {
		t.Fatalf("headings=%#v", headings)
	}
	got := headings[0].Gist
	if len(got) > mcpEvidenceOutlineGistMaxBytes {
		t.Fatalf("gist=%d bytes, want <= %d", len(got), mcpEvidenceOutlineGistMaxBytes)
	}
	for i := 0; i < len(got); {
		r := got[i]
		if r>>6 == 2 { // a continuation byte at a boundary means we split a rune
			t.Fatalf("gist was cut mid rune: %q", got)
		}
		if r < 0x80 {
			i++
		} else if r>>5 == 0x6 {
			i += 2
		} else {
			i++
		}
	}
	if !strings.HasPrefix(gistLine, got) {
		t.Fatalf("gist=%q is not a prefix of the original line", got)
	}
}

func TestOutlineGistSkipsBlankLinesAndFurtherHeadings(t *testing.T) {
	text := []byte("# Heading\n\n\n## Next Heading Line Is Not The Gist\nactual gist\n")
	headings, _ := extractOutlineHeadings(text)
	if len(headings) != 2 || headings[0].Gist != "" {
		// The first heading's own gist search stops as soon as it reaches
		// another heading line, so it has no gist of its own.
		t.Fatalf("headings=%#v", headings)
	}
	if headings[1].Gist != "actual gist" {
		t.Fatalf("second heading gist=%q", headings[1].Gist)
	}
}

func TestOutlineHeadingAddressAtFragmentBoundary(t *testing.T) {
	anchor, _, _ := testWholeObjectAnchor(t)
	other := "fragment_01H9ABCDEFGHJKMNPQRSTVWXYA"
	firstFragment := []byte("# First\nbody one\n")
	secondFragment := []byte("# Second\nbody two\n")
	whole := append(append([]byte(nil), firstFragment...), secondFragment...)
	anchor.Text = firstFragment
	object := evidence.WholeObject{
		Fragment: anchor, Text: whole, FragmentCount: 2, FirstOrdinal: 1, LastOrdinal: 2,
		Fragments: []evidence.ObjectFragmentSpan{
			{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len(firstFragment)},
			{FragmentID: other, Ordinal: 2, Offset: len(firstFragment), Length: len(secondFragment)},
		},
	}
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})

	headings, truncated := extractOutlineHeadings(object.Text)
	if truncated || len(headings) != 2 {
		t.Fatalf("headings=%#v truncated=%v", headings, truncated)
	}
	// The second heading's line starts exactly at the second fragment's Offset:
	// the boundary case. It must resolve to the SECOND fragment's address, not
	// the first.
	firstAddress, err := harness.handler.outlineHeadingAddress(object, headings[0].Offset)
	if err != nil {
		t.Fatal(err)
	}
	secondAddress, err := harness.handler.outlineHeadingAddress(object, headings[1].Offset)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(firstAddress, anchor.FragmentID) {
		t.Fatalf("first heading address=%q does not name the first fragment", firstAddress)
	}
	if !strings.Contains(secondAddress, other) {
		t.Fatalf("second heading address=%q does not name the boundary fragment %q", secondAddress, other)
	}
}

// --- MCP handler tests ---

func mcpOutlineWholeObject(t *testing.T) evidence.WholeObject {
	t.Helper()
	anchor, _, _ := testWholeObjectAnchor(t)
	fragmentOne := []byte("# Overview\nWhat this document covers.\n\n")
	fragmentTwo := []byte("## Details\nThe fine print goes here.\n")
	whole := append(append([]byte(nil), fragmentOne...), fragmentTwo...)
	anchor.Text = fragmentOne
	other := "fragment_01H9ABCDEFGHJKMNPQRSTVWXYA"
	return evidence.WholeObject{
		Fragment: anchor, Text: whole, FragmentCount: 2, FirstOrdinal: 1, LastOrdinal: 2,
		Fragments: []evidence.ObjectFragmentSpan{
			{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len(fragmentOne)},
			{FragmentID: other, Ordinal: 2, Offset: len(fragmentOne), Length: len(fragmentTwo)},
		},
	}
}

func TestMCPEvidenceReadOutlineReturnsOrderedHeadings(t *testing.T) {
	object := mcpOutlineWholeObject(t)
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": object.Fragment.FragmentID, "outline": true,
	}))
	if envelope.Error != nil {
		t.Fatalf("outline read refused: %#v", envelope.Error)
	}
	encoded, err := json.Marshal(envelope.Result.Structured["headings"])
	if err != nil {
		t.Fatal(err)
	}
	var headings []outlineEntry
	if err := json.Unmarshal(encoded, &headings); err != nil || len(headings) != 2 {
		t.Fatalf("outline headings=%s err=%v", encoded, err)
	}
	if headings[0].Level != 1 || headings[0].Text != "Overview" || headings[0].Gist != "What this document covers." || headings[0].CanonicalAddress == "" {
		t.Fatalf("first heading wrong: %#v", headings[0])
	}
	if headings[1].Level != 2 || headings[1].Text != "Details" || headings[1].Gist != "The fine print goes here." {
		t.Fatalf("second heading wrong: %#v", headings[1])
	}
	if headings[0].CanonicalAddress == headings[1].CanonicalAddress {
		t.Fatal("headings in different fragments resolved to the same address")
	}
	if envelope.Result.Structured["truncated"] != false {
		t.Fatalf("truncated=%#v, want false", envelope.Result.Structured["truncated"])
	}
	if envelope.Result.Structured["fragment_count"] != float64(2) {
		t.Fatalf("fragment_count=%#v, want 2", envelope.Result.Structured["fragment_count"])
	}
	if envelope.Result.Structured["canonical_address"] == nil || envelope.Result.Structured["canonical_address"] == "" {
		t.Fatal("outline result missing the whole-document canonical_address")
	}
	if len(envelope.Result.Content) != 1 {
		t.Fatalf("outline content channel=%#v", envelope.Result.Content)
	}
	rendered, _ := envelope.Result.Content[0]["text"].(string)
	if !strings.Contains(rendered, "Overview") || !strings.Contains(rendered, "Details") || !strings.Contains(rendered, headings[0].CanonicalAddress) {
		t.Fatalf("outline content[].text missing heading data: %q", rendered)
	}
}

func TestMCPEvidenceReadOutlineNoHeadingsReturnsEmptyList(t *testing.T) {
	anchor, _, _ := testWholeObjectAnchor(t)
	object := evidence.WholeObject{Fragment: anchor, Text: []byte("no headings here, just prose.\n"), FragmentCount: 1, FirstOrdinal: 1, LastOrdinal: 1,
		Fragments: []evidence.ObjectFragmentSpan{{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len("no headings here, just prose.\n")}}}
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID, "outline": true,
	}))
	if envelope.Error != nil {
		t.Fatalf("outline read refused: %#v", envelope.Error)
	}
	headings, ok := envelope.Result.Structured["headings"].([]any)
	if !ok || len(headings) != 0 {
		t.Fatalf("headings=%#v, want an empty list", envelope.Result.Structured["headings"])
	}
}

func TestMCPEvidenceReadOutlineRejectsCursorCombination(t *testing.T) {
	object := mcpOutlineWholeObject(t)
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": object.Fragment.FragmentID, "outline": true, "cursor": "",
	}))
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("outline+cursor not refused: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("outline+cursor refusal leaked content: %#v", envelope.Result)
	}
}

func TestMCPEvidenceReadOutlineRejectsNonzeroOffset(t *testing.T) {
	object := mcpOutlineWholeObject(t)
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": object.Fragment.FragmentID, "outline": true, "offset": 4,
	}))
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("outline+offset not refused: %#v", envelope.Error)
	}
}

func TestMCPEvidenceReadOutlineDeniesForeignWorkspaceContentFree(t *testing.T) {
	object := mcpOutlineWholeObject(t)
	service := &fakeWholeObjectEvidence{object: object, objectErr: evidence.ErrNotFound}
	harness := wholeObjectHarness(t, service)

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_other", "fragment_id": object.Fragment.FragmentID, "outline": true,
	}))
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("foreign workspace outline not denied content-free: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("foreign workspace outline denial leaked content: %#v", envelope.Result)
	}
	if strings.Contains(envelope.Error.Message, "ws_other") || strings.Contains(envelope.Error.Message, object.Fragment.FragmentID) {
		t.Fatalf("denial echoed the workspace or fragment: %#v", envelope.Error)
	}
}

func TestMCPEvidenceReadOutlineWithoutWholeObjectCapabilityFailsClosed(t *testing.T) {
	harness := newTestHarness(t)
	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "fragment_id": evidenceFragmentID, "outline": true,
	}))
	if envelope.Error == nil || envelope.Error.Code != -32000 {
		t.Fatalf("outline without whole-object capability not refused as service unavailable: %#v", envelope.Error)
	}
}

func TestMCPEvidenceReadOutlineRefusesTamperedAddress(t *testing.T) {
	object := mcpOutlineWholeObject(t)
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})
	tampered := mcpTestCanonicalAddress(t, object.Fragment)
	tampered.SpanHash = strings.Repeat("0", 16)

	envelope := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "address": tampered.String(), "outline": true,
	}))
	if envelope.Error == nil || envelope.Error.Code != -32005 {
		t.Fatalf("tampered address outline not refused: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("tampered outline leaked content: %#v", envelope.Result)
	}
}
