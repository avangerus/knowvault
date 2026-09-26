package workspaceapi

// mcp_read_outline.go adds the knowvault_read outline mode (R1.S9.s1.T1): an
// orientation projection of one document's Markdown ATX heading structure,
// built from the same canonical whole-object text the cursor mode pages,
// through the identical authorized EvidenceWholeObject capability and audit
// path. It never introduces a second read path or a second canonicalization:
// the headings are extracted from the already-assembled evidence.WholeObject
// text, and each heading's canonical_address is the address of the existing
// fragment span that contains its heading line, computed the same way
// readPageFragments locates a page's fragments.
//
// Outline is explicitly ORIENTATION, not evidence: the tool description tells
// a caller to read the addressed fragment before asserting anything, and this
// mode returns no fragment text at all, only heading lines, their level, the
// first following non-empty non-heading line (the section's "gist", bounded
// to 160 bytes on a UTF-8 boundary) and the address to read next.

import (
	"net/http"
	"strconv"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpEvidenceOutlineMaxHeadings bounds the number of headings a single outline
// response discloses. A document with more headings than this still returns
// exactly this many, in document order, with truncated=true, so a caller never
// receives a silently incomplete list without knowing it.
const mcpEvidenceOutlineMaxHeadings = 200

// mcpEvidenceOutlineGistMaxBytes bounds the gist member: the first non-empty,
// non-heading line following a heading, cut to at most this many bytes on a
// UTF-8 rune boundary (never a partial multi-byte character).
const mcpEvidenceOutlineGistMaxBytes = 160

// outlineHeading is one extracted Markdown ATX heading: its level (1-6), its
// literal text exactly as written after the marker and the leading space (no
// CommonMark closing-hash trimming, no re-wording), the byte offset of the
// heading LINE's first byte within the whole document text, and the gist: the
// first non-empty line after the heading line that is not itself a heading,
// trimmed to mcpEvidenceOutlineGistMaxBytes bytes on a UTF-8 boundary.
type outlineHeading struct {
	Level  int
	Text   string
	Offset int
	Gist   string
}

// extractOutlineHeadings scans canonical whole-document text line by line for
// Markdown ATX headings ("#".."######" followed by a space or end of line,
// with at most 3 leading spaces of indentation, exactly like CommonMark),
// skipping every line inside a fenced code block ("```" or "~~~", at least
// three characters, closed only by a matching or longer fence of the same
// character). It returns headings in document order, each with the gist
// already resolved, and reports whether the document held more than
// mcpEvidenceOutlineMaxHeadings headings (in which case only the first
// mcpEvidenceOutlineMaxHeadings are returned).
func extractOutlineHeadings(text []byte) ([]outlineHeading, bool) {
	lines := splitOutlineLines(text)
	headings := make([]outlineHeading, 0)
	truncated := false
	inFence := false
	var fenceChar byte
	var fenceLen int
	for index, line := range lines {
		stripped, indent := outlineStripIndent(line.data)
		if inFence {
			if outlineFenceCloses(stripped, fenceChar, fenceLen) {
				inFence = false
			}
			continue
		}
		if indent > 3 {
			continue
		}
		if ch, length, ok := outlineFenceOpens(stripped); ok {
			inFence = true
			fenceChar = ch
			fenceLen = length
			continue
		}
		level, headingText, ok := outlineParseATXHeading(stripped)
		if !ok {
			continue
		}
		if len(headings) >= mcpEvidenceOutlineMaxHeadings {
			truncated = true
			continue
		}
		headings = append(headings, outlineHeading{
			Level:  level,
			Text:   headingText,
			Offset: line.offset,
			Gist:   outlineGist(lines, index+1),
		})
	}
	return headings, truncated
}

// outlineLine is one line of the scanned text (excluding its terminating LF)
// together with the byte offset of its first byte within the whole text.
type outlineLine struct {
	data   []byte
	offset int
}

// splitOutlineLines splits text into lines on LF, keeping the byte offset of
// each line's start. A trailing CR (Windows line endings) is stripped from
// the line's data but not from its length accounting for the next offset,
// since the offset tracks the original byte stream.
func splitOutlineLines(text []byte) []outlineLine {
	lines := make([]outlineLine, 0)
	start := 0
	for index := 0; index <= len(text); index++ {
		if index == len(text) || text[index] == '\n' {
			raw := text[start:index]
			if len(raw) > 0 && raw[len(raw)-1] == '\r' {
				raw = raw[:len(raw)-1]
			}
			lines = append(lines, outlineLine{data: raw, offset: start})
			start = index + 1
		}
	}
	return lines
}

// outlineStripIndent trims up to 3 leading spaces (CommonMark's allowance for
// an ATX heading or a fence) and reports how many were stripped. A tab or a
// fourth leading space is left in place: the line is then either not indented
// enough to hide a heading/fence marker from column 0 within the 3-space
// budget, or genuinely indented code, and outlineParseATXHeading/
// outlineFenceOpens simply will not match a line that does not start with
// '#', '`' or '~' after this trim.
func outlineStripIndent(line []byte) ([]byte, int) {
	indent := 0
	for indent < len(line) && indent < 3 && line[indent] == ' ' {
		indent++
	}
	return line[indent:], indent
}

// outlineFenceOpens reports whether stripped opens a fenced code block: a run
// of at least 3 identical '`' or '~' characters. It returns the fence
// character and the run length (the minimum length a closing fence must
// match).
func outlineFenceOpens(stripped []byte) (byte, int, bool) {
	if len(stripped) == 0 {
		return 0, 0, false
	}
	ch := stripped[0]
	if ch != '`' && ch != '~' {
		return 0, 0, false
	}
	length := 0
	for length < len(stripped) && stripped[length] == ch {
		length++
	}
	if length < 3 {
		return 0, 0, false
	}
	return ch, length, true
}

// outlineFenceCloses reports whether stripped closes a fence opened with
// fenceChar/minLen: a run of at least minLen of the same character, followed
// only by trailing whitespace.
func outlineFenceCloses(stripped []byte, fenceChar byte, minLen int) bool {
	length := 0
	for length < len(stripped) && stripped[length] == fenceChar {
		length++
	}
	if length < minLen || length == 0 {
		return false
	}
	rest := stripped[length:]
	for _, b := range rest {
		if b != ' ' && b != '\t' {
			return false
		}
	}
	return true
}

// outlineParseATXHeading reports whether stripped is a Markdown ATX heading
// line: 1-6 '#' characters followed by a space/tab or end of line. It returns
// the level and the literal text after the marker and its separating
// whitespace, trimmed only of trailing whitespace -- never re-worded, never
// stripped of an optional closing "##" sequence, so the returned text is
// exactly what a reader sees after the marker.
func outlineParseATXHeading(stripped []byte) (int, string, bool) {
	level := 0
	for level < len(stripped) && level < 7 && stripped[level] == '#' {
		level++
	}
	if level == 0 || level > 6 {
		return 0, "", false
	}
	if level == len(stripped) {
		return level, "", true
	}
	next := stripped[level]
	if next != ' ' && next != '\t' {
		return 0, "", false
	}
	rest := stripped[level:]
	start := 0
	for start < len(rest) && (rest[start] == ' ' || rest[start] == '\t') {
		start++
	}
	end := len(rest)
	for end > start && (rest[end-1] == ' ' || rest[end-1] == '\t') {
		end--
	}
	return level, string(rest[start:end]), true
}

// outlineGist returns the first non-empty, non-heading line at or after
// lines[from], trimmed to mcpEvidenceOutlineGistMaxBytes bytes on a UTF-8
// boundary. Blank lines are skipped; reaching another heading line before any
// content line ends the search with "" (a gist never crosses into the next
// section), and so does reaching the end of the document.
func outlineGist(lines []outlineLine, from int) string {
	for index := from; index < len(lines); index++ {
		stripped, _ := outlineStripIndent(lines[index].data)
		if len(stripped) == 0 {
			continue
		}
		if _, _, ok := outlineParseATXHeading(stripped); ok {
			return ""
		}
		return outlineTruncateUTF8(string(lines[index].data), mcpEvidenceOutlineGistMaxBytes)
	}
	return ""
}

// outlineTruncateUTF8 cuts value to at most maxBytes bytes, backing off to the
// start of a rune whenever the exact cut point would split a multi-byte UTF-8
// character.
func outlineTruncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// outlineHeadingAddress locates the fragment span containing byte offset
// within object.Text and returns its canonical address, exactly the way
// readPageFragments locates a page's intersecting fragments. offset is always
// inside some span because it is the start of an actual line of object.Text.
func (handler *Handler) outlineHeadingAddress(object evidence.WholeObject, offset int) (string, error) {
	for _, span := range object.Fragments {
		if span.Offset < 0 || span.Length < 0 || span.Offset > len(object.Text)-span.Length || span.FragmentID == "" {
			return "", errInvalidOutlineFragmentSpan
		}
		if offset < span.Offset || offset >= span.Offset+span.Length {
			continue
		}
		fragment := object.Fragment
		fragment.FragmentID = span.FragmentID
		fragment.Ordinal = span.Ordinal
		fragment.Text = object.Text[span.Offset : span.Offset+span.Length]
		canonical, err := handler.canonicalEvidenceAddress(fragment)
		if err != nil {
			return "", err
		}
		return canonical.String(), nil
	}
	return "", errOutlineHeadingOutsideFragment
}

var (
	errInvalidOutlineFragmentSpan    = evidenceOutlineError("invalid canonical fragment span")
	errOutlineHeadingOutsideFragment = evidenceOutlineError("heading outside any fragment span")
)

type evidenceOutlineError string

func (err evidenceOutlineError) Error() string { return string(err) }

// outlineEntry is the closed per-heading projection: level, the literal
// heading text, the canonical_address of the fragment the heading line sits
// in, and the gist.
type outlineEntry struct {
	Level            int    `json:"level"`
	Text             string `json:"text"`
	CanonicalAddress string `json:"canonical_address"`
	Gist             string `json:"gist"`
}

// mcpEvidenceReadOutlinePage is the outline-mode core of knowvault_read
// (R1.S9.s1.T1). It resolves the whole source version through the identical
// optional EvidenceWholeObject capability the cursor mode composes (the
// production *evidence.Viewer.ReadObject), so authorization, the ADR-0077
// fragment hash and the admission/outcome audit journal are the canonical
// ones and no second read path exists. The address keeps its KV-A01c meaning
// exactly like whole-object mode: it must name the same source/object/version
// as the anchor fragment and its span hash must verify against the anchor
// fragment's canonical text (or the reassembled whole text). A document with
// no headings returns an empty list, not an error, so the caller falls back
// to reading the document normally.
func (handler *Handler) mcpEvidenceReadOutlinePage(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, workspaceID, fragmentID string, selector *address.Address, refVersionID, expectedSpanHash string) {
	_, ok := handler.evidenceWholeObjectCapability()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	object, err := handler.readEvidenceObjectSelection(request.Context(), access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil || object.Fragment.FragmentID == "" {
		writeMCPError(writer, envelope.ID, -32004, "evidence not found")
		return
	}
	if selector != nil {
		if selector.Source != object.Fragment.SourceObjectID || selector.Object != object.Fragment.FragmentID || !mcpReadAddressVersionMatches(*selector, object.Fragment.SourceVersionID, refVersionID) {
			writeMCPError(writer, envelope.ID, -32602, "invalid evidence read arguments")
			return
		}
		if !handler.verifyAddressSpan(object.Fragment.Text, *selector) && !handler.verifyAddressSpan(object.Text, *selector) {
			writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
			return
		}
	}
	if expectedSpanHash != "" && expectedSpanHash != object.Fragment.EvidenceTextHash {
		writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
		return
	}
	canonicalAddress, addressErr := handler.canonicalEvidenceWholeAddress(object)
	if addressErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	headings, truncated := extractOutlineHeadings(object.Text)
	entries := make([]outlineEntry, 0, len(headings))
	for _, heading := range headings {
		headingAddress, addrErr := handler.outlineHeadingAddress(object, heading.Offset)
		if addrErr != nil {
			writeMCPError(writer, envelope.ID, -32000, "service unavailable")
			return
		}
		entries = append(entries, outlineEntry{
			Level:            heading.Level,
			Text:             heading.Text,
			CanonicalAddress: headingAddress,
			Gist:             heading.Gist,
		})
	}
	structured := map[string]any{
		"headings":          entries,
		"truncated":         truncated,
		"fragment_count":    object.FragmentCount,
		"address":           mcpEvidenceAddress(object.Fragment),
		"canonical_address": canonicalAddress.String(),
	}
	structured["is_current_version"] = object.Fragment.IsCurrentVersion
	if object.Fragment.SourcePath != "" {
		structured["source_path"] = object.Fragment.SourcePath
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": mcpEvidenceOutlineContent(entries, truncated, canonicalAddress.String())}},
		"structuredContent": structured,
		"isError":           false,
	}})
}

// mcpEvidenceOutlineContent renders the content[].text channel of an outline
// response: one compact line per heading (indented by level, the heading
// text, its gist and its canonical_address to read next), a truncation notice
// when the document held more headings than were returned, and a trailing
// metadata line naming the whole-document canonical_address, exactly the
// convention mcpEvidenceReadMetadata uses for a page.
func mcpEvidenceOutlineContent(entries []outlineEntry, truncated bool, canonicalAddress string) string {
	text := ""
	for _, entry := range entries {
		indent := ""
		for i := 1; i < entry.Level; i++ {
			indent += "  "
		}
		line := indent + "#" + strconv.Itoa(entry.Level) + " " + entry.Text
		if entry.Gist != "" {
			line += " -- " + entry.Gist
		}
		line += " (" + entry.CanonicalAddress + ")"
		text += line + "\n"
	}
	if truncated {
		text += "(outline truncated at " + strconv.Itoa(mcpEvidenceOutlineMaxHeadings) + " headings)\n"
	}
	return text + "knowvault_read outline canonical_address=" + canonicalAddress
}
