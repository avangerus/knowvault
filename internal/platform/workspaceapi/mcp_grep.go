package workspaceapi

// This file is the additive R3a-1 KV-A02c workspace exact-regex grep tool. It is
// a read-only, workspace-scoped MCP surface: a capable model runs one regular
// expression over the canonical text of one workspace's document/evidence
// objects and receives, per match, the immutable address (source, version,
// object and exact span with a hash of that span), the matched offset/length
// inside the canonical object text, a bounded excerpt plus the version id, the
// moment and the content hash. It is paginated with an explicit window
// (offset, effective limit, has_more, next_offset) so a limit is never silent
// truncation, and every hit's canonical address resolves the whole object
// through knowvault_evidence_read.
//
// It composes only the existing authorized Evidence capabilities: the object
// inventory (ListObjects) and the whole-object read (ReadObject), both of which
// already run the fail-closed visibility gates, append admission-before-data and
// their outcome to the R1 audit journal, and collapse every denial to the single
// content-free ErrNotFound. The tool therefore inherits that authorization,
// admission ordering and denial shape unchanged; it introduces no new store, no
// new read path, no new REST route, no new dependency and no migration.
//
// The tool set is KnowVault's own (owner decision 12.09.2026): no wiki-rag tool
// name is advertised or dispatched. A session that used wiki-rag reconfigures to
// `knowvault_grep` as documented in docs/MCP-TOOLS.md.

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpToolGrep is the canonical workspace exact-regex grep tool.
const mcpToolGrep = "knowvault_grep"

// Page and pattern bounds for knowvault_grep. A caller that omits limit gets one
// default page and an explicit next_offset while more remains; a caller that asks
// for more than the maximum is served the maximum page and told so through
// limit/has_more/next_offset rather than silently truncated. mcpGrepScanPageSize
// bounds one inventory page the scan walks: the scan follows the inventory cursor
// until it is exhausted, so the page size never truncates the result.
const (
	mcpGrepDefaultLimit     = 20
	mcpGrepMaxLimit         = 100
	mcpGrepScanPageSize     = 200
	mcpGrepPatternMaxLength = 4096
	mcpGrepExcerptRunes     = 160
	mcpGrepReadFragmentsMax = 8
	// mcpGrepRefMaxLength bounds the optional named code-source ref. It is a
	// bounded opaque token: long enough for a git commit or ref fragment, short
	// enough that it can never be a smuggling channel.
	mcpGrepRefMaxLength = 256
	// mcpGrepCodeObjectType is the catalog object_type of a registered git
	// code-source file (observation.GitAdapter publishes "GIT_FILE"). Only
	// objects of this type are eligible for named-ref scoping, so a ref can
	// never widen a document grep onto a non-code object.
	mcpGrepCodeObjectType = "GIT_FILE"
)

var (
	// errMCPGrepInvalidAddress is a typed closed-envelope refusal. It is kept
	// private so an address mismatch never becomes a content-bearing error.
	errMCPGrepInvalidAddress = errors.New("grep: invalid address selector")
	// errMCPGrepWholeObjectUnavailable means the exact-address mode cannot be
	// served by the mounted evidence service. It must never fall back to the
	// workspace inventory scan.
	errMCPGrepWholeObjectUnavailable = errors.New("grep: whole-object capability unavailable")
	// errMCPGrepReadFragmentsInvalid means an authorized whole-object result
	// cannot safely resolve its fragment spans. It is always mapped to a
	// content-free generic failure at the MCP and REST boundaries.
	errMCPGrepReadFragmentsInvalid = errors.New("grep: invalid read fragment spans")
)

// mcpGrepArguments is the closed argument envelope for knowvault_grep: the
// workspace to search, the Go regular expression (RE2, linear time), an optional
// all_versions switch (default false = current versions only), the optional
// offset/limit page window and the optional named code-source ref. A negative or
// wrong-typed offset/limit/all_versions, an empty or over-long pattern, a
// malformed ref or any unknown member is rejected before any fragment row is
// read.
type mcpGrepArguments struct {
	WorkspaceID string `json:"workspace_id"`
	Pattern     string `json:"pattern"`
	AllVersions bool   `json:"all_versions"`
	Offset      int64  `json:"offset"`
	Limit       int64  `json:"limit"`
	// Address is an optional complete canonical kv1 selector. It narrows the
	// regex to exactly one authorized object version; it is mutually exclusive
	// with Ref and AllVersions.
	// Address retains the raw JSON value so omission remains distinct from an
	// explicit null. A supplied null or non-string selector must be rejected;
	// silently treating it as absent would widen an exact-address request into
	// a workspace inventory scan.
	Address jsontext.Value `json:"address"`
	// Ref, when non-empty, restricts the scan to the workspace's registered git
	// code-source objects whose immutable version identity matches the named
	// ref. It is resolved from object-inventory metadata before any fragment
	// content is read; an unknown or foreign ref is refused content-free.
	Ref string `json:"ref"`
}

// mcpGrepRefValid reports whether a caller-supplied named ref is a well-formed,
// address-safe opaque token. An empty ref is valid (it means "no ref scoping").
// A ref that carries whitespace, a control character or a colon is refused:
// whitespace/control would be an unrendered smuggling channel, and a colon would
// break the compact `kv1:<object>:<version>:<span>:<hash16>` address grammar the
// ref is rendered into, so the tool never emits an unparsable address.
func mcpGrepRefValid(ref string) bool {
	if len(ref) > mcpGrepRefMaxLength {
		return false
	}
	for _, r := range ref {
		if r <= 0x20 || r == 0x7f || r == ':' {
			return false
		}
	}
	return true
}

// GrepHit is one exact-regex match inside one object version's canonical text.
// Fragment is the anchor fragment of that version (the object the address names),
// Object is the whole reassembled object version the match was found in, and
// Offset/Length are the matched half-open byte range within Object.Text.
type GrepHit struct {
	Fragment evidence.Fragment
	Object   evidence.WholeObject
	Offset   int64
	Length   int64
	Excerpt  string
	// Path is the repository-relative external identity of the code-source
	// object the hit was read from (R3a-1 code sources). It is populated only
	// for a named-ref scan of a registered git code-source object
	// (object_type GIT_FILE) and stays empty for a document/evidence object,
	// so a no-ref grep and a non-code object never gain a file locator.
	Path string
}

// GrepPage is one explicit page of a workspace grep result. HasMore true means
// more matches remain after this page; NextOffset is the stable cursor the caller
// passes back as offset to fetch the next page, so a limit is never silent
// truncation.
type GrepPage struct {
	Hits       []GrepHit
	HasMore    bool
	NextOffset int64
}

// EvidenceGrep is the optional exact-regex capability the grep tool composes.
// It is deliberately separate from EvidenceService so every existing
// EvidenceService implementation (including the REST read boundary and its
// fakes) stays source-compatible: a service that does not implement it leaves
// the grep tool unadvertised and failing closed as service unavailable rather
// than widening the required interface.
type EvidenceGrep interface {
	GrepFragments(ctx context.Context, access database.AccessContext, workspaceID, pattern string, allVersions bool, offset, limit int64) (GrepPage, error)
}

// EvidenceGrepRef is the optional named-ref scoping capability the grep tool
// composes when a caller supplies `ref`. It is deliberately a second optional
// interface, not a widened EvidenceGrep: every existing EvidenceGrep
// implementation (including the REST read boundary, its fakes and the shipped
// tests) stays source-compatible, and a service that supports grep but not
// named-ref scoping keeps serving the byte-identical no-ref behaviour while a
// ref call fails closed instead of silently scanning everything.
//
// GrepFragmentsAtRef scans only the workspace's registered git code-source
// objects whose immutable version identity matches ref. The match is decided
// from object-inventory metadata alone, before any fragment content is read; an
// unknown or foreign ref yields the single content-free ErrNotFound.
type EvidenceGrepRef interface {
	GrepFragmentsAtRef(ctx context.Context, access database.AccessContext, workspaceID, pattern, ref string, offset, limit int64) (GrepPage, error)
}

// inventoryGrepEvidence is the production grep source: it composes the mounted
// evidence service's own inventory and whole-object reads, so grep cannot widen
// authorization, add a read path or drift from the evidence read/search gates.
type inventoryGrepEvidence struct {
	inventory EvidenceInventory
	objects   EvidenceWholeObject
}

// The compile-time assertion is the wiring proof: the adapter the capability
// resolver builds is a real EvidenceGrep and a real EvidenceGrepRef.
var (
	_ EvidenceGrep    = inventoryGrepEvidence{}
	_ EvidenceGrepRef = inventoryGrepEvidence{}
)

// mcpGrepCapability exposes the grep capability to the tools/list and tools/call
// boundaries without widening EvidenceService. A service that already implements
// EvidenceGrep is used directly; otherwise, when the mounted evidence service
// implements both the object inventory and the whole-object read (the production
// *evidence.Viewer does), the grep tool is served over those existing authorized
// reads. A service with neither leaves grep unadvertised and failing closed.
func (handler *Handler) mcpGrepCapability() (EvidenceGrep, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	if grep, ok := handler.evidence.(EvidenceGrep); ok {
		return grep, true
	}
	inventory, ok := handler.evidence.(EvidenceInventory)
	if !ok {
		return nil, false
	}
	objects, ok := handler.evidence.(EvidenceWholeObject)
	if !ok {
		return nil, false
	}
	return inventoryGrepEvidence{inventory: inventory, objects: objects}, true
}

// mcpGrepRefCapability exposes the optional named-ref scoping capability to the
// tools/call boundaries. A service that already implements EvidenceGrepRef is
// used directly; otherwise, when the mounted evidence service implements both
// the object inventory and the whole-object read (the production
// *evidence.Viewer does), named-ref scoping is served over those existing
// authorized reads. A service with neither leaves only ref-scoped grep
// unserved, which the caller refuses closed.
func (handler *Handler) mcpGrepRefCapability() (EvidenceGrepRef, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	if grep, ok := handler.evidence.(EvidenceGrepRef); ok {
		return grep, true
	}
	inventory, ok := handler.evidence.(EvidenceInventory)
	if !ok {
		return nil, false
	}
	objects, ok := handler.evidence.(EvidenceWholeObject)
	if !ok {
		return nil, false
	}
	return inventoryGrepEvidence{inventory: inventory, objects: objects}, true
}

// mcpGrepToolDefinitions is the tools/list projection of the canonical grep
// tool. It is appended only when the mounted evidence service actually supports
// grep (directly or through the inventory + whole-object reads); the exact
// address selector is advertised only when the existing whole-object reader is
// also mounted.
func mcpGrepToolDefinitions(addressAvailable bool) []any {
	canAddress := addressAvailable
	description := "Run an exact regular expression (Go/RE2) over the canonical text of one workspace's document/evidence objects. Returns one entry per match with the matched offset/length inside the canonical object text, a bounded excerpt, the version id, the moment, the content hash and the immutable address (source, version, object and exact span with a span hash and a canonical address that resolves the whole object through knowvault_evidence_read). Each match also includes up to 8 full overlapping read_fragments in ordinal order, with a canonical_address, fragment_id and full byte length; read_fragments_total and read_fragments_has_more report the complete overlap count. Read each returned fragment using its canonical_address; respect knowvault_read has_more/next_offset when paging a fragment. Current versions only unless all_versions is true; grep results are paginated with offset, the effective limit, has_more and next_offset (no silent truncation). The optional ref scopes the scan to registered Git GIT_FILE immutable version identities; it is not a repository path. Each ref-scoped hit also carries the repository-relative path and the 1-based line/column range of the match (file:lines). Read-only."
	properties := map[string]any{
		"workspace_id": map[string]any{"type": "string"},
		"pattern":      map[string]any{"type": "string", "minLength": 1, "maxLength": mcpGrepPatternMaxLength},
		"all_versions": map[string]any{"type": "boolean"},
		"offset":       map[string]any{"type": "integer", "minimum": 0},
		"limit":        map[string]any{"type": "integer", "minimum": 1},
		"ref": map[string]any{
			"type": "string", "minLength": 1, "maxLength": mcpGrepRefMaxLength,
			"description": "Named Git immutable version identity for registered GIT_FILE objects; this is not a repository file path and does not select document objects.",
		},
	}
	if canAddress {
		properties["address"] = map[string]any{"type": "string", "minLength": 1, "description": "Complete canonical text address returned by a knowledge tool; searches only its authorized object/version without an inventory scan. Mutually exclusive with ref and all_versions."}
		description += " The optional address selects exactly one canonical text object/version through the authorized whole-object read without an inventory scan; address is mutually exclusive with ref and all_versions."
	}
	return []any{
		map[string]any{
			"name":        mcpToolGrep,
			"description": description,
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "pattern"}, "properties": properties},
		},
	}
}

// mcpGrepToolCall dispatches knowvault_grep onto the authorized grep capability.
// It fails closed as service unavailable when composition mounted an evidence
// service without grep support, refuses a malformed or empty pattern with the
// closed-envelope -32602 before any fragment is read, and maps the underlying
// single content-free ErrNotFound to the existing -32004 not-found so an
// unknown, non-member or cross-workspace call leaks no match, excerpt or address
// and never echoes the requested workspace id.
func (handler *Handler) mcpGrepToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	grep, ok := handler.mcpGrepCapability()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpGrepArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || strings.TrimSpace(arguments.Pattern) == "" ||
		len(arguments.Pattern) > mcpGrepPatternMaxLength || arguments.Offset < 0 || arguments.Limit < 0 ||
		!mcpGrepRefValid(arguments.Ref) {
		writeMCPError(writer, envelope.ID, -32602, "invalid grep arguments")
		return
	}
	var selector *address.Address
	if len(arguments.Address) > 0 {
		var rawAddress string
		if jsonv2.Unmarshal(arguments.Address, &rawAddress) != nil {
			writeMCPError(writer, envelope.ID, -32602, "invalid grep arguments")
			return
		}
		parsed, selectorErr := mcpGrepAddressSelector(rawAddress)
		if rawAddress == "" || selectorErr != nil || arguments.Ref != "" || arguments.AllVersions {
			writeMCPError(writer, envelope.ID, -32602, "invalid grep arguments")
			return
		}
		selector = &parsed
	}
	// A malformed regular expression is a closed-envelope refusal: it is
	// rejected here, before the capability is asked to read anything.
	if _, compileErr := regexp.Compile(arguments.Pattern); compileErr != nil {
		writeMCPError(writer, envelope.ID, -32602, "invalid grep arguments")
		return
	}
	limit := mcpEffectiveGrepLimit(arguments.Limit)
	var page GrepPage
	projectionRef := arguments.Ref
	var err error
	if selector != nil {
		page, projectionRef, err = handler.mcpGrepAtAddress(request.Context(), access, arguments.WorkspaceID, *selector, arguments.Pattern, arguments.Offset, limit)
	} else if arguments.Ref != "" {
		// Named-ref scoping is a separate optional capability: a service that
		// serves grep but not code-source scoping fails closed instead of
		// silently scanning every object as if the ref had been ignored.
		refGrep, ok := handler.mcpGrepRefCapability()
		if !ok {
			writeMCPError(writer, envelope.ID, -32000, "service unavailable")
			return
		}
		page, err = refGrep.GrepFragmentsAtRef(request.Context(), access, arguments.WorkspaceID, arguments.Pattern, arguments.Ref, arguments.Offset, limit)
	} else {
		page, err = grep.GrepFragments(request.Context(), access, arguments.WorkspaceID, arguments.Pattern, arguments.AllVersions, arguments.Offset, limit)
	}
	if err != nil {
		switch {
		case errors.Is(err, errMCPGrepInvalidAddress):
			writeMCPError(writer, envelope.ID, -32602, "invalid grep arguments")
			return
		case errors.Is(err, address.ErrSpanMismatch):
			writeMCPError(writer, envelope.ID, -32005, "evidence span hash mismatch")
			return
		case errors.Is(err, errMCPGrepWholeObjectUnavailable):
			writeMCPError(writer, envelope.ID, -32000, "service unavailable")
			return
		case errors.Is(err, errMCPGrepReadFragmentsInvalid):
			writeMCPError(writer, envelope.ID, -32000, "service unavailable")
			return
		}
		writeMCPError(writer, envelope.ID, -32004, "workspace documents not found")
		return
	}
	matches := make([]any, 0, len(page.Hits))
	for _, hit := range page.Hits {
		projection, err := handler.grepHitProjection(hit, projectionRef)
		if err != nil {
			writeMCPError(writer, envelope.ID, -32000, "service unavailable")
			return
		}
		matches = append(matches, projection)
	}
	// The text channel is rendered from the same match projections the
	// structured channel carries, so a text-channel-only client (and a model)
	// sees the identical address, excerpt, offsets, version id, moment and — for
	// a ref-scoped code hit — the file:lines locator, plus the trailing page
	// cursor. structuredContent is the source of truth and is not altered by the
	// text rendering.
	nextOffset := mcpGrepNextOffset(page, arguments.Offset)
	textResult := mcpGrepText(matches, arguments.Offset, limit, page.HasMore, nextOffset)
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": textResult}},
		"structuredContent": map[string]any{
			"matches":     matches,
			"offset":      arguments.Offset,
			"limit":       limit,
			"has_more":    page.HasMore,
			"next_offset": nextOffset,
		},
		"isError": false,
	}})
}

// mcpGrepAddressSelector parses the exact-address selector accepted by grep.
// Grep searches canonical text, so code/table coordinate addresses are not
// meaningful selectors. Full-span verification remains object-dependent and is
// performed only after the authorized whole-object read.
func mcpGrepAddressSelector(raw string) (address.Address, error) {
	selector, err := address.Parse(raw)
	if err != nil || selector.SpanKind != address.SpanKindText {
		return address.Address{}, errMCPGrepInvalidAddress
	}
	return selector, nil
}

// mcpGrepAtAddress runs a regex against exactly one object version selected by
// a canonical address. It deliberately calls ReadObject directly: an address
// already names the authorized fragment anchor, so a workspace inventory walk
// would add latency and could accidentally turn an exact version request into
// a broader search. The returned ref is only non-empty when the address used a
// Git immutable external-version identity, preserving the existing projection
// shape for ref-scoped hits.
func (handler *Handler) mcpGrepAtAddress(ctx context.Context, access database.AccessContext, workspaceID string, selector address.Address, pattern string, offset, limit int64) (GrepPage, string, error) {
	objects, ok := handler.evidenceWholeObjectCapability()
	if !ok {
		return GrepPage{}, "", errMCPGrepWholeObjectUnavailable
	}
	object, err := objects.ReadObject(ctx, access, workspaceID, selector.Object)
	if err != nil || object.Fragment.FragmentID == "" {
		return GrepPage{}, "", evidence.ErrNotFound
	}
	if selector.Source != object.Fragment.SourceObjectID || selector.Object != object.Fragment.FragmentID {
		return GrepPage{}, "", errMCPGrepInvalidAddress
	}
	projectionRef := ""
	if selector.Version != object.Fragment.SourceVersionID {
		if object.Fragment.ObjectType != mcpGrepCodeObjectType || !mcpGrepVersionKeyMatches(object.Fragment.ExternalVersionKey, selector.Version) {
			return GrepPage{}, "", errMCPGrepInvalidAddress
		}
		projectionRef = selector.Version
	}
	if selector.CharStart != 0 {
		return GrepPage{}, "", errMCPGrepInvalidAddress
	}
	fullSpan := false
	if selector.CharEnd == utf8.RuneCount(object.Fragment.Text) && handler.verifyAddressSpan(object.Fragment.Text, selector) {
		fullSpan = true
	}
	if selector.CharEnd == utf8.RuneCount(object.Text) && handler.verifyAddressSpan(object.Text, selector) {
		fullSpan = true
	}
	if !fullSpan {
		return GrepPage{}, "", address.ErrSpanMismatch
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return GrepPage{}, "", errMCPGrepInvalidAddress
	}
	path := ""
	if projectionRef != "" {
		path = object.Fragment.SourcePath
	}
	hits := mcpGrepMatches(matcher, object, path)
	return mcpGrepPage(hits, offset, limit), projectionRef, nil
}

// mcpEffectiveGrepLimit applies the grep page bounds, always returning the value
// the response must echo as limit so a capped request is never silent.
func mcpEffectiveGrepLimit(limit int64) int64 {
	if limit == 0 {
		return mcpGrepDefaultLimit
	}
	if limit > mcpGrepMaxLimit {
		return mcpGrepMaxLimit
	}
	return limit
}

// mcpGrepNextOffset renders the stable next-page cursor while more matches
// remain, and null once the page is the end of the result.
func mcpGrepNextOffset(page GrepPage, offset int64) any {
	if !page.HasMore {
		return nil
	}
	if page.NextOffset != 0 {
		return page.NextOffset
	}
	return offset + int64(len(page.Hits))
}

// mcpGrepText renders the content[].text channel of knowvault_grep as a
// compact, model-readable page: one line per match carrying the identical
// address the structuredContent match carries (the same compact JSON) plus the
// canonical kv1 address string (the exact value of
// structuredContent.matches[].canonical_address that a client passes back to
// knowvault_read), the fragment id, the matched offset/length, the bounded
// excerpt, the match hash,
// the version id, the moment and the content hash, followed by a trailing
// page-cursor line with offset, the effective limit, has_more and next_offset. A
// ref-scoped hit of a registered git code source additionally carries the
// repository-relative path and the 1-based line/column range (file:lines), so a
// client that reads only content[].text sees every address and code locator it
// can cite and can reach the next page without parsing structuredContent.
//
// Every match is exactly one line: a multi-line excerpt is flattened so one hit
// never becomes several and the per-hit addresses stay aligned with the
// structured channel. The rendering is reached only after the authorized page
// was read, so it stays content-free on a denial.
func mcpGrepText(matches []any, offset, limit int64, hasMore bool, nextOffset any) string {
	var builder strings.Builder
	for index, raw := range matches {
		match, _ := raw.(map[string]any)
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("] address=")
		builder.WriteString(mcpContentAddress(match["address"]))
		// The canonical kv1 address string itself, not just the compact-JSON
		// address object, so a text-channel-only model can re-address the hit
		// into knowvault_read by passing this exact string (R3a-1 r8c).
		builder.WriteString(" canonical_address=")
		builder.WriteString(mcpContentSingleLine(mcpGrepTextMember(match["canonical_address"])))
		builder.WriteString(" fragment_id=")
		builder.WriteString(mcpGrepTextMember(match["fragment_id"]))
		builder.WriteString(" offset=")
		builder.WriteString(mcpGrepTextMember(match["offset"]))
		builder.WriteString(" length=")
		builder.WriteString(mcpGrepTextMember(match["length"]))
		builder.WriteString(" version_id=")
		builder.WriteString(mcpGrepTextMember(match["version_id"]))
		builder.WriteString(" observed_at=")
		builder.WriteString(mcpGrepTextMember(match["observed_at"]))
		builder.WriteString(" content_hash=")
		builder.WriteString(mcpGrepTextMember(match["content_hash"]))
		builder.WriteString(" match_hash=")
		builder.WriteString(mcpGrepTextMember(match["match_hash"]))
		builder.WriteString(" excerpt=")
		builder.WriteString(mcpContentSingleLine(mcpGrepTextMember(match["excerpt"])))
		builder.WriteString(" read_fragments_total=")
		builder.WriteString(mcpGrepTextMember(match["read_fragments_total"]))
		builder.WriteString(" read_fragments_has_more=")
		builder.WriteString(mcpGrepTextMember(match["read_fragments_has_more"]))
		builder.WriteString(" read_fragments=")
		builder.WriteString(mcpGrepTextFragments(match["read_fragments"]))
		// The canon file:lines locator of a ref-scoped code hit. The path is
		// present only when the structured projection carries it, so a document
		// hit never gains a code locator in the text channel.
		if path, ok := match["path"].(string); ok && path != "" {
			builder.WriteString(" path=")
			builder.WriteString(mcpContentSingleLine(path))
			builder.WriteString(" line=")
			builder.WriteString(mcpGrepTextMember(match["line"]))
			builder.WriteString(" column=")
			builder.WriteString(mcpGrepTextMember(match["column"]))
			builder.WriteString(" end_line=")
			builder.WriteString(mcpGrepTextMember(match["end_line"]))
			builder.WriteString(" end_column=")
			builder.WriteString(mcpGrepTextMember(match["end_column"]))
		}
		builder.WriteString("\n")
	}
	// The trailing page-cursor line: the explicit, non-truncating window a
	// text-channel-only client uses to fetch the next page.
	builder.WriteString("offset=")
	builder.WriteString(strconv.FormatInt(offset, 10))
	builder.WriteString(" limit=")
	builder.WriteString(strconv.FormatInt(limit, 10))
	builder.WriteString(" has_more=")
	builder.WriteString(strconv.FormatBool(hasMore))
	builder.WriteString(" next_offset=")
	builder.WriteString(mcpContentCursor(nextOffset))
	if len(matches) > 0 {
		builder.WriteString(" read_hint=knowvault_read(address=canonical_address,offset=offset,limit=4096); omit cursor")
		builder.WriteString(" fragment_read_hint=knowvault_read(address=read_fragments[].canonical_address,offset=0,limit=min(read_fragments[].length,65536)); if has_more, follow knowvault_read next_offset")
	}
	builder.WriteString("\n")
	return builder.String()
}

// mcpGrepTextMember renders one scalar projection member of a grep match into
// the text channel. The structured projection uses strings, int64 counts and
// offsets, so those are rendered exactly; any other shape yields the empty
// string rather than a Go-formatted value that would not match the structured
// channel.
func mcpGrepTextMember(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int64:
		return strconv.FormatInt(typed, 10)
	case int:
		return strconv.Itoa(typed)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

func mcpGrepTextFragments(value any) string {
	fragments, ok := value.([]any)
	if !ok {
		return "[]"
	}
	encoded, err := jsonv2.Marshal(fragments)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// GrepFragments walks the workspace object inventory (current versions only
// unless allVersions is true), reads each object version's whole canonical text
// through the same authorized whole-object read the evidence read tool uses, and
// returns every non-empty regular-expression match ordered deterministically and
// paged by offset/limit. Every authorization, visibility-gate, admission and
// denial decision belongs to the underlying inventory and whole-object reads, so
// a denied, unknown or cross-workspace call is the single content-free
// ErrNotFound with no match, excerpt or address.
func (source inventoryGrepEvidence) GrepFragments(ctx context.Context, access database.AccessContext, workspaceID, pattern string, allVersions bool, offset, limit int64) (GrepPage, error) {
	if source.inventory == nil || source.objects == nil || workspaceID == "" ||
		strings.TrimSpace(pattern) == "" || offset < 0 || limit < 1 {
		return GrepPage{}, evidence.ErrNotFound
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return GrepPage{}, evidence.ErrNotFound
	}
	hits := []GrepHit{}
	cursor := int64(0)
	for {
		inventory, err := source.inventory.ListObjects(ctx, access, workspaceID, allVersions, cursor, mcpGrepScanPageSize)
		if err != nil {
			return GrepPage{}, evidence.ErrNotFound
		}
		for _, item := range inventory.Items {
			if item.FirstFragmentID == "" {
				continue
			}
			object, err := source.objects.ReadObject(ctx, access, workspaceID, item.FirstFragmentID)
			if err != nil || object.Fragment.FragmentID == "" {
				return GrepPage{}, evidence.ErrNotFound
			}
			for _, match := range matcher.FindAllIndex(object.Text, -1) {
				// A zero-length match is not a retrievable span; skipping it
				// keeps a pattern that can match the empty string from
				// exploding into one meaningless hit per position.
				if match[1] <= match[0] {
					continue
				}
				hits = append(hits, GrepHit{
					Fragment: object.Fragment,
					Object:   object,
					Offset:   int64(match[0]),
					Length:   int64(match[1] - match[0]),
					Excerpt:  mcpGrepExcerpt(object.Text, match[0], match[1]),
				})
			}
		}
		if !inventory.HasMore {
			break
		}
		next := cursor + int64(len(inventory.Items))
		if next <= cursor {
			break
		}
		cursor = next
	}
	return mcpGrepPage(hits, offset, limit), nil
}

// GrepFragmentsAtRef is the named-ref scoping mode of the workspace grep. It
// resolves the ref from object-inventory metadata alone, before reading any
// fragment content: it walks every version of the workspace's objects (a ref is
// an immutable identity, so the current-version default would hide a
// non-current ref) and keeps only the registered git code-source objects whose
// immutable version identity matches ref. When no code-source object matches,
// the ref is unknown or foreign to this workspace and the call is the single
// content-free ErrNotFound with no match, excerpt or address. Only the versions
// that already matched by metadata are then read, through the same authorized
// whole-object read the no-ref mode uses, so an A/B file difference at two refs
// is never conflated and authorization, admission and the denial shape stay the
// canonical ones.
func (source inventoryGrepEvidence) GrepFragmentsAtRef(ctx context.Context, access database.AccessContext, workspaceID, pattern, ref string, offset, limit int64) (GrepPage, error) {
	if source.inventory == nil || source.objects == nil || workspaceID == "" ||
		strings.TrimSpace(pattern) == "" || ref == "" || !mcpGrepRefValid(ref) || offset < 0 || limit < 1 {
		return GrepPage{}, evidence.ErrNotFound
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return GrepPage{}, evidence.ErrNotFound
	}
	// Phase 1: resolve the ref from the object inventory (metadata only). No
	// whole-object read happens until at least one code-source version has
	// matched the ref by its immutable identity.
	resolved := []evidence.ObjectInventoryItem{}
	cursor := int64(0)
	for {
		inventory, err := source.inventory.ListObjects(ctx, access, workspaceID, true, cursor, mcpGrepScanPageSize)
		if err != nil {
			return GrepPage{}, evidence.ErrNotFound
		}
		for _, item := range inventory.Items {
			if mcpGrepCodeRefMatches(item, ref) {
				resolved = append(resolved, item)
			}
		}
		if !inventory.HasMore {
			break
		}
		next := cursor + int64(len(inventory.Items))
		if next <= cursor {
			break
		}
		cursor = next
	}
	if len(resolved) == 0 {
		// An unknown or foreign ref discloses no match and no workspace echo.
		return GrepPage{}, evidence.ErrNotFound
	}
	// Phase 2: read only the code-source versions the ref resolved to.
	hits := []GrepHit{}
	for _, item := range resolved {
		if item.FirstFragmentID == "" {
			continue
		}
		object, err := source.objects.ReadObject(ctx, access, workspaceID, item.FirstFragmentID)
		if err != nil || object.Fragment.FragmentID == "" {
			return GrepPage{}, evidence.ErrNotFound
		}
		hits = append(hits, mcpGrepMatches(matcher, object, item.ExternalID)...)
	}
	return mcpGrepPage(hits, offset, limit), nil
}

// mcpGrepCodeRefMatches decides, from object-inventory metadata alone, whether a
// code-source object version is the named ref. Only a registered git code-source
// object (object_type "GIT_FILE") is eligible, so a ref can never pull a
// document/evidence object into a code-scoped result. The immutable version
// identity is the object version's external_version_key; a ref matches it
// exactly, matches it with the `native:` prefix stripped, or matches one of its
// `;`-separated key:value tokens (so a caller can name the immutable commit or
// blob identity that a registered git ref resolved to). The decision reads
// metadata only and never touches fragment content.
func mcpGrepCodeRefMatches(item evidence.ObjectInventoryItem, ref string) bool {
	if ref == "" || item.ObjectType != mcpGrepCodeObjectType {
		return false
	}
	return mcpGrepVersionKeyMatches(item.ExternalVersionKey, ref)
}

// mcpGrepVersionKeyMatches decides whether one immutable external_version_key
// identity is the named ref: it matches the whole key exactly, matches it with
// the `native:` prefix stripped, or matches one of its `;`-separated key:value
// tokens (so a caller can name the immutable commit or blob identity a
// registered git ref resolved to). It is the single identity authority the
// grep scoping and the named-ref read resolution share, so a ref that grep
// emits can always be resolved back by the read.
func mcpGrepVersionKeyMatches(externalVersionKey, ref string) bool {
	if ref == "" || externalVersionKey == "" {
		return false
	}
	key := externalVersionKey
	if key == ref {
		return true
	}
	if tail, ok := strings.CutPrefix(key, "native:"); ok {
		if tail == ref {
			return true
		}
		key = tail
	}
	for _, token := range strings.Split(key, ";") {
		if token == ref {
			return true
		}
		if _, value, ok := strings.Cut(token, ":"); ok && value == ref {
			return true
		}
	}
	return false
}

// mcpReadVersionResolution is the metadata-only outcome of resolving an address
// version against the workspace object inventory for knowvault_read (R3a-1
// KV-A04b). Available is true only when the mounted evidence service exposed the
// inventory capability and the read succeeded. ObjectSeen is true when the
// inventory lists at least one version of the source object the address names.
// VersionKnown is true when the inventory matched the address version as either
// its immutable source version id or a named code-source ref; RefVersionID is
// the immutable source_version_id a ref resolved to, empty when the version was
// matched as the source version id itself.
type mcpReadVersionResolution struct {
	RefVersionID string
	ObjectSeen   bool
	VersionKnown bool
	Available    bool
}

// mcpReadAddressResolution resolves an address version that names a named
// code-source ref (R3a-1 KV-A04b). It decides from object-inventory metadata
// alone, before any fragment content is read: it walks every version of the
// workspace's objects (a ref is an immutable identity, so the current-version
// default could hide a non-current ref) and reports the immutable
// source_version_id of the registered git code-source object version whose
// external_version_key identity matches the address version and whose source
// object is the one the address names. Only a registered git code-source object
// (object_type "GIT_FILE") is eligible, so a ref can never resolve a document or
// evidence object. It reads no fragment content.
//
// A false Available means the mounted evidence service has no inventory
// capability or the inventory read failed (a denial); the caller then keeps its
// existing immutable source-version-id comparison and its authorized-read
// denial. ObjectSeen true with VersionKnown false means the address names a
// version of an object this workspace lists that is neither its immutable
// source version id nor a matching code-source ref, so the caller can refuse it
// content-free before reading any content.
func (handler *Handler) mcpReadAddressResolution(ctx context.Context, access database.AccessContext, workspaceID string, selector address.Address) mcpReadVersionResolution {
	if handler == nil || handler.evidence == nil || workspaceID == "" || selector.Source == "" || selector.Version == "" {
		return mcpReadVersionResolution{}
	}
	// Catalog version IDs are checked against the authorized fragment below.
	// Walking and decrypting the entire inventory is only needed for named refs.
	if strings.HasPrefix(selector.Version, "version_") {
		return mcpReadVersionResolution{}
	}
	inventory, ok := handler.evidence.(EvidenceInventory)
	if !ok {
		return mcpReadVersionResolution{}
	}
	cursor := int64(0)
	objectSeen := false
	for {
		page, err := inventory.ListObjects(ctx, access, workspaceID, true, cursor, mcpGrepScanPageSize)
		if err != nil {
			return mcpReadVersionResolution{}
		}
		for _, item := range page.Items {
			if item.SourceObjectID != selector.Source {
				continue
			}
			objectSeen = true
			if item.SourceVersionID == selector.Version {
				return mcpReadVersionResolution{ObjectSeen: true, VersionKnown: true, Available: true}
			}
			if mcpGrepCodeRefMatches(item, selector.Version) {
				return mcpReadVersionResolution{RefVersionID: item.SourceVersionID, ObjectSeen: true, VersionKnown: true, Available: true}
			}
		}
		if !page.HasMore {
			break
		}
		next := cursor + int64(len(page.Items))
		if next <= cursor {
			break
		}
		cursor = next
	}
	return mcpReadVersionResolution{ObjectSeen: objectSeen, Available: true}
}

// mcpReadAddressVersionMatches reports whether the version an authorized read
// resolved satisfies the address: either it is the immutable source version id
// the address names, or the address names a named code-source ref that
// mcpReadAddressResolution resolved to exactly this immutable version id, so a
// ref-scoped canonical address round-trips back through the read.
func mcpReadAddressVersionMatches(selector address.Address, sourceVersionID, refVersionID string) bool {
	if selector.Version == sourceVersionID {
		return true
	}
	return refVersionID != "" && refVersionID == sourceVersionID
}

// mcpGrepMatches returns every non-empty regular-expression match inside one
// object version's canonical text as a GrepHit. path is the repository-relative
// external identity of a named-ref code source (empty for a document/evidence
// object); it is carried on the hit so the projection can render the
// canon-required file:lines locator.
func mcpGrepMatches(matcher *regexp.Regexp, object evidence.WholeObject, path string) []GrepHit {
	hits := []GrepHit{}
	for _, match := range matcher.FindAllIndex(object.Text, -1) {
		// A zero-length match is not a retrievable span; skipping it keeps a
		// pattern that can match the empty string from exploding into one
		// meaningless hit per position.
		if match[1] <= match[0] {
			continue
		}
		hits = append(hits, GrepHit{
			Fragment: object.Fragment,
			Object:   object,
			Offset:   int64(match[0]),
			Length:   int64(match[1] - match[0]),
			Excerpt:  mcpGrepExcerpt(object.Text, match[0], match[1]),
			Path:     path,
		})
	}
	return hits
}

// mcpGrepPage orders the match set deterministically by immutable address
// (source object, source version, ordinal) and then by match offset, and returns
// the explicit offset/limit window with HasMore/NextOffset so a limit is never
// silent truncation.
func mcpGrepPage(hits []GrepHit, offset, limit int64) GrepPage {
	sort.SliceStable(hits, func(i, j int) bool {
		left, right := hits[i], hits[j]
		if left.Fragment.SourceObjectID != right.Fragment.SourceObjectID {
			return left.Fragment.SourceObjectID < right.Fragment.SourceObjectID
		}
		if left.Fragment.SourceVersionID != right.Fragment.SourceVersionID {
			return left.Fragment.SourceVersionID < right.Fragment.SourceVersionID
		}
		if left.Fragment.Ordinal != right.Fragment.Ordinal {
			return left.Fragment.Ordinal < right.Fragment.Ordinal
		}
		return left.Offset < right.Offset
	})
	start := offset
	if start > int64(len(hits)) {
		start = int64(len(hits))
	}
	end := start + limit
	if end > int64(len(hits)) {
		end = int64(len(hits))
	}
	page := GrepPage{Hits: append([]GrepHit(nil), hits[start:end]...)}
	if end < int64(len(hits)) {
		page.HasMore = true
		page.NextOffset = end
	}
	return page
}

// mcpGrepHitProjection renders one canonical grep match: the matched offset and
// length inside the canonical object text, a bounded excerpt, the version id,
// the moment and the content hash, plus the immutable address. The address span
// is the whole canonical object text and carries the shared canonical hash of
// exactly that span; the `match` member locates the matched range inside it with
// the hash of exactly the matched bytes. `canonical_address` round-trips through
// address.Parse and resolves the whole object through knowvault_evidence_read.
// When ref is non-empty the match came from a code source at that named ref, so
// the canonical address version is the ref (the immutable version id stays
// visible as address.version.source_version_id). A named-ref hit of a registered
// git code source additionally carries the canon file:lines locator (path,
// line, column, end_line, end_column); every other hit keeps the projection
// above byte for byte.
// mcpGrepHitProjection renders one canonical grep match with the package's
// anonymous compatibility digest. A product caller dispatches through
// Handler.grepHitProjection so the organization key is applied.
func mcpGrepHitProjection(hit GrepHit, ref string) map[string]any {
	return mcpGrepHitProjectionKeyed(nil, hit, ref)
}

// mcpGrepHitProjectionKeyed renders one canonical grep match: it is
// mcpGrepHitProjection with an explicit organization span digest key (nil keeps
// the anonymous compatibility digest), so the emitted canonical_address carries
// the organization-keyed SpanHash the REST and MCP grep surfaces share (R3a-1).
func mcpGrepHitProjectionKeyed(key *address.SpanDigestKey, hit GrepHit, ref string) map[string]any {
	projection, err := mcpGrepHitProjectionKeyedChecked(key, hit, ref)
	if err != nil {
		return nil
	}
	return projection
}

func mcpGrepHitProjectionKeyedChecked(key *address.SpanDigestKey, hit GrepHit, ref string) (map[string]any, error) {
	readFragments, readFragmentsTotal, readFragmentsHasMore, err := mcpGrepReadFragments(key, hit)
	if err != nil {
		return nil, err
	}
	projection := map[string]any{
		"fragment_id":             hit.Fragment.FragmentID,
		"offset":                  hit.Offset,
		"length":                  hit.Length,
		"excerpt":                 hit.Excerpt,
		"match_hash":              mcpGrepSpanHash(hit.Object.Text, hit.Offset, hit.Length),
		"version_id":              hit.Fragment.SourceVersionID,
		"observed_at":             hit.Fragment.ObservedAt.UTC().Format(time.RFC3339),
		"content_hash":            hit.Fragment.ContentHash,
		"address":                 mcpGrepAddress(hit.Object, hit.Offset, hit.Length, ref),
		"canonical_address":       mcpGrepCanonicalAddressKeyed(key, hit.Object, ref),
		"read_fragments":          readFragments,
		"read_fragments_total":    readFragmentsTotal,
		"read_fragments_has_more": readFragmentsHasMore,
	}
	// The canon file:lines locator (R3a-1 code sources): a named-ref hit of a
	// registered git code source carries the repository-relative path plus the
	// 1-based half-open line/column range of the match inside that file. A
	// document/evidence hit and every no-ref hit keep the projection above
	// byte for byte, so no document span is ever mislabelled as a code file.
	if hit.Path != "" && hit.Fragment.ObjectType == mcpGrepCodeObjectType {
		line, column := mcpGrepLineColumn(hit.Object.Text, hit.Offset)
		endLine, endColumn := mcpGrepLineColumn(hit.Object.Text, hit.Offset+hit.Length)
		projection["path"] = hit.Path
		projection["line"] = line
		projection["column"] = column
		projection["end_line"] = endLine
		projection["end_column"] = endColumn
	}
	return projection, nil
}

func mcpGrepReadFragments(key *address.SpanDigestKey, hit GrepHit) ([]any, int64, bool, error) {
	object := hit.Object
	anchor := object.Fragment
	if anchor.FragmentID == "" || anchor.SourceObjectID == "" || anchor.SourceVersionID == "" ||
		anchor.Ordinal <= 0 || hit.Fragment.FragmentID != anchor.FragmentID ||
		hit.Fragment.SourceObjectID != anchor.SourceObjectID ||
		hit.Fragment.SourceVersionID != anchor.SourceVersionID || hit.Fragment.Ordinal != anchor.Ordinal ||
		!utf8.Valid(object.Text) || len(object.Fragments) == 0 ||
		object.FragmentCount != int64(len(object.Fragments)) ||
		object.FirstOrdinal <= 0 || object.LastOrdinal < object.FirstOrdinal {
		return nil, 0, false, errMCPGrepReadFragmentsInvalid
	}

	seenFragmentIDs := make(map[string]struct{}, len(object.Fragments))
	nextOffset := 0
	anchorFound := false
	var previousOrdinal int64
	for index, span := range object.Fragments {
		if span.FragmentID == "" || span.Ordinal <= 0 || span.Length <= 0 ||
			span.Offset > len(object.Text) || span.Length > len(object.Text)-span.Offset {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		if !mcpGrepFragmentGapAllowed(object, nextOffset, span.Offset) {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		if index == 0 {
			if span.Ordinal != object.FirstOrdinal || span.Offset != 0 {
				return nil, 0, false, errMCPGrepReadFragmentsInvalid
			}
		} else if span.Ordinal <= previousOrdinal || span.Ordinal-previousOrdinal != 1 {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		if _, duplicate := seenFragmentIDs[span.FragmentID]; duplicate {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		seenFragmentIDs[span.FragmentID] = struct{}{}

		spanEnd := span.Offset + span.Length
		if !mcpGrepUTF8Boundary(object.Text, span.Offset) ||
			!mcpGrepUTF8Boundary(object.Text, spanEnd) ||
			!utf8.Valid(object.Text[span.Offset:spanEnd]) {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		if span.FragmentID == anchor.FragmentID {
			if span.Ordinal != anchor.Ordinal {
				return nil, 0, false, errMCPGrepReadFragmentsInvalid
			}
			anchorFound = true
		}
		nextOffset = spanEnd
		previousOrdinal = span.Ordinal
	}
	if !mcpGrepFragmentGapAllowed(object, nextOffset, len(object.Text)) || previousOrdinal != object.LastOrdinal || !anchorFound {
		return nil, 0, false, errMCPGrepReadFragmentsInvalid
	}

	textLength := int64(len(object.Text))
	if hit.Offset < 0 || hit.Length <= 0 || hit.Offset > textLength ||
		hit.Length > textLength-hit.Offset {
		return nil, 0, false, errMCPGrepReadFragmentsInvalid
	}
	matchStart := int(hit.Offset)
	matchEnd := matchStart + int(hit.Length)
	if !mcpGrepUTF8Boundary(object.Text, matchStart) || !mcpGrepUTF8Boundary(object.Text, matchEnd) {
		return nil, 0, false, errMCPGrepReadFragmentsInvalid
	}

	fragments := make([]any, 0, mcpGrepReadFragmentsMax)
	var total int64
	for _, span := range object.Fragments {
		spanEnd := span.Offset + span.Length
		if span.Offset >= matchEnd || spanEnd <= matchStart {
			continue
		}
		total++
		if len(fragments) == mcpGrepReadFragmentsMax {
			continue
		}

		fragmentText := object.Text[span.Offset:spanEnd]
		base := address.Address{
			Source:    anchor.SourceObjectID,
			Object:    span.FragmentID,
			Version:   anchor.SourceVersionID,
			SpanKind:  address.SpanKindText,
			CharStart: 0,
			CharEnd:   utf8.RuneCount(fragmentText),
		}
		var (
			fragmentAddress address.Address
			err             error
		)
		if key == nil {
			fragmentAddress, err = base.WithSpanHash(fragmentText)
		} else {
			fragmentAddress, err = key.WithSpanHash(base, fragmentText)
		}
		if err != nil {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		canonicalAddress := fragmentAddress.String()
		parsed, err := address.Parse(canonicalAddress)
		if err != nil || parsed != fragmentAddress {
			return nil, 0, false, errMCPGrepReadFragmentsInvalid
		}
		fragments = append(fragments, map[string]any{
			"canonical_address": canonicalAddress,
			"fragment_id":       span.FragmentID,
			"length":            int64(span.Length),
		})
	}
	return fragments, total, total > mcpGrepReadFragmentsMax, nil
}

func mcpGrepFragmentGapAllowed(object evidence.WholeObject, start, end int) bool {
	if start < 0 || end < start || end > len(object.Text) {
		return false
	}
	if start == end {
		return true
	}
	if object.TextRepresentation() != evidence.CanonicalTextV1LayoutV2 {
		return false
	}
	for _, value := range object.Text[start:end] {
		if value != '\n' {
			return false
		}
	}
	return true
}

func mcpGrepUTF8Boundary(text []byte, offset int) bool {
	if offset < 0 || offset > len(text) {
		return false
	}
	return offset == len(text) || utf8.RuneStart(text[offset])
}

// grepHitProjection is the product emitter of one grep hit: it is
// mcpGrepHitProjection dispatched with the handler's organization span digest
// key, so the canonical_address and address every grep hit carries use the
// organization-keyed SpanHash the REST and MCP surfaces share (R3a-1).
func (handler *Handler) grepHitProjection(hit GrepHit, ref string) (map[string]any, error) {
	if handler == nil || handler.spanDigestKey == nil {
		return mcpGrepHitProjectionKeyedChecked(nil, hit, ref)
	}
	return mcpGrepHitProjectionKeyedChecked(handler.spanDigestKey, hit, ref)
}

// mcpGrepLineColumn maps a byte offset in the canonical text to a 1-based
// (line, column) pair. Lines are separated by '\n'; the column counts the
// UTF-8 bytes of the canonical text from the start of the line to the offset,
// so a half-open match end at the start of the next line is (line+1, 1) and an
// end at the end of a line is one past its last byte. The offset is clamped to
// the text so a caller can never index outside it.
func mcpGrepLineColumn(text []byte, offset int64) (int64, int64) {
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(text)) {
		offset = int64(len(text))
	}
	line := int64(1)
	lineStart := int64(0)
	for index := int64(0); index < offset; index++ {
		if text[index] == '\n' {
			line++
			lineStart = index + 1
		}
	}
	return line, offset - lineStart + 1
}

// mcpGrepAddress renders the immutable address of one matched object version:
// source, version, object and the whole canonical text as its exact span, with
// the shared canonical hash of that span and a nested match locating the hit.
// When ref is non-empty it is added to the version as `ref`, the named
// code-source ref the hit was resolved at.
func mcpGrepAddress(object evidence.WholeObject, offset, length int64, ref string) map[string]any {
	version := map[string]any{
		"source_version_id":    object.Fragment.SourceVersionID,
		"external_version_key": object.Fragment.ExternalVersionKey,
		"content_hash":         object.Fragment.ContentHash,
		"observed_at":          object.Fragment.ObservedAt.UTC().Format(time.RFC3339),
	}
	if ref != "" {
		version["ref"] = ref
	}
	return map[string]any{
		"source": map[string]any{
			"source_object_id": object.Fragment.SourceObjectID,
			"connection_id":    object.Fragment.ConnectionID,
		},
		"version": version,
		"object": map[string]any{
			"extraction_id": object.Fragment.ExtractionID,
			"ordinal":       object.Fragment.Ordinal,
			"fragment_id":   object.Fragment.FragmentID,
		},
		"span": map[string]any{
			"offset":         0,
			"length":         int64(len(object.Text)),
			"total_length":   int64(len(object.Text)),
			"text_hash":      address.WholeHash(object.Text),
			"fragment_count": object.FragmentCount,
			"ordinal_start":  object.FirstOrdinal,
			"ordinal_end":    object.LastOrdinal,
		},
		"match": map[string]any{
			"offset": offset,
			"length": length,
			"hash":   mcpGrepSpanHash(object.Text, offset, length),
		},
	}
}

// mcpGrepCanonicalAddressKeyed is the string round-trippable internal/address
// value of the matched object version: its span covers the whole reassembled
// canonical text, so knowvault_evidence_read resolves it and pages the whole
// object. When ref is non-empty the address version is the named code-source
// ref, so the address names exactly the code source at the ref the caller asked
// for. A non-nil key attaches the organization-scoped ADR-0077 span digest; a
// nil key keeps the package's anonymous compatibility digest.
func mcpGrepCanonicalAddressKeyed(key *address.SpanDigestKey, object evidence.WholeObject, ref string) string {
	version := object.Fragment.SourceVersionID
	if ref != "" {
		version = ref
	}
	base := address.Address{
		Source:    object.Fragment.SourceObjectID,
		Object:    object.Fragment.FragmentID,
		Version:   version,
		SpanKind:  address.SpanKindText,
		CharStart: 0,
		CharEnd:   utf8.RuneCount(object.Text),
	}
	var (
		whole address.Address
		err   error
	)
	if key != nil {
		whole, err = key.WithSpanHash(base, object.Text)
	} else {
		whole, err = base.WithSpanHash(object.Text)
	}
	if err != nil {
		return ""
	}
	return whole.String()
}

// mcpGrepSpanHash is the shared canonical SHA-256 of exactly the matched bytes,
// or the empty string for an index that does not resolve.
func mcpGrepSpanHash(text []byte, offset, length int64) string {
	start := int(offset)
	end := start + int(length)
	if start < 0 || end < start || end > len(text) {
		return ""
	}
	return address.WholeHash(text[start:end])
}

// mcpGrepExcerpt returns a bounded, rune-safe window around one match: up to
// mcpGrepExcerptRunes whole runes on either side, with an ellipsis where the
// window was cut.
func mcpGrepExcerpt(text []byte, start, end int) string {
	if start < 0 || end > len(text) || start >= end {
		return ""
	}
	before := start
	for runes := 0; runes < mcpGrepExcerptRunes && before > 0; runes++ {
		_, size := utf8.DecodeLastRune(text[:before])
		if size <= 0 {
			break
		}
		before -= size
	}
	after := end
	for runes := 0; runes < mcpGrepExcerptRunes && after < len(text); runes++ {
		_, size := utf8.DecodeRune(text[after:])
		if size <= 0 {
			break
		}
		after += size
	}
	var excerpt strings.Builder
	if before > 0 {
		excerpt.WriteString("…")
	}
	excerpt.Write(text[before:after])
	if after < len(text) {
		excerpt.WriteString("…")
	}
	return excerpt.String()
}
