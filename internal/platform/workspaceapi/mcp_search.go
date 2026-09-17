package workspaceapi

// This file is the additive R3a-1 KV-A02a workspace lexical search tool. It is
// a read-only, workspace-scoped MCP surface: it searches the current-version
// canonical document fragments of one workspace, returning for every hit an
// excerpt, a numeric score and the immutable address (source, version, object
// and exact span) with the version id, moment and content hash. It resolves
// through the same authorized Evidence viewer as the REST evidence route,
// knowvault_evidence_read and knowvault_workspace_list, so
// admission-before-data, the audit journal and the content-free denial stay
// exactly the existing ones. It introduces no new REST route, no new
// persistence and no migration.
//
// The tool set is KnowVault's own: no wiki-rag tool name is advertised or
// dispatched by the product (owner decision 12.09.2026). A session that used
// wiki-rag is reconfigured by changing the endpoint and the tool name to
// `knowvault_search`; the parameters and result shape are documented in
// docs/MCP-TOOLS.md.

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpToolSearch is the canonical workspace lexical search tool.
const mcpToolSearch = "knowvault_search"

// Page bounds for the search tool. A caller that omits limit gets one default
// page and an explicit next_offset while more remains; a caller that asks for
// more than the maximum is served the maximum page and told so through
// limit/has_more/next_offset rather than silently truncated.
const (
	mcpSearchDefaultLimit = 20
	mcpSearchMaxLimit     = 100
)

// EvidenceSearch is the optional lexical-search capability the workspace search
// tool composes (declared beside EvidenceService in workspaceapi.go). It is
// deliberately separate from EvidenceService so every existing EvidenceService
// implementation (including the REST read boundary and its fakes) stays
// source-compatible: a service that does not implement it leaves the tool
// unadvertised and failing closed as service unavailable rather than widening
// the required interface.
var _ EvidenceSearch = (*evidence.Viewer)(nil)

// evidenceSearchCapability exposes the optional search capability to the
// tools/list and tools/call boundaries without widening EvidenceService.
func (handler *Handler) evidenceSearchCapability() (EvidenceSearch, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	search, ok := handler.evidence.(EvidenceSearch)
	return search, ok
}

// mcpSearchArguments is the closed argument envelope for knowvault_search: the
// workspace to search, the lexical query, an optional all_versions switch
// (default false = current versions only) and the optional offset/limit page
// window. A negative offset or limit, an empty query or any unknown member is
// rejected before any fragment is read.
type mcpSearchArguments struct {
	WorkspaceID string `json:"workspace_id"`
	Query       string `json:"query"`
	AllVersions bool   `json:"all_versions"`
	Offset      int64  `json:"offset"`
	Limit       int64  `json:"limit"`
}

const mcpSearchQueryMaxLength = 4096

// mcpSearchToolDefinitions is the tools/list projection of the canonical search
// tool. It is appended only when the mounted evidence service actually
// implements EvidenceSearch, so the surface never advertises a tool it cannot
// serve.
func mcpSearchToolDefinitions() []any {
	return []any{
		map[string]any{
			"name": mcpToolSearch, "description": "Search the current-version data of one workspace with the available lexical and semantic channels. Returns an excerpt, a numeric score and the immutable address (source, version, object and exact span with text hash) plus the version id, moment and content hash for every hit. Indexed results rank chunks, including a table row as one result; read the address for complete data. Current versions only unless all_versions is true; paginated with offset, the effective limit, has_more and next_offset. partial=true reports bounded candidate coverage or a page limited by the evidence-read budget; it is not proof that no other data exists. Read-only.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id", "query"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"query":        map[string]any{"type": "string", "minLength": 1, "maxLength": mcpSearchQueryMaxLength},
				"all_versions": map[string]any{"type": "boolean"},
				"offset":       map[string]any{"type": "integer", "minimum": 0},
				"limit":        map[string]any{"type": "integer", "minimum": 1},
			}},
		},
	}
}

// mcpSearchToolCall dispatches knowvault_search onto the authorized evidence
// search. It fails closed as service unavailable when composition mounted an
// evidence service without the search capability, and maps the viewer's single
// content-free ErrNotFound to the existing -32004 not-found so an unknown,
// non-member or cross-workspace call leaks no hit and never echoes the
// requested workspace id.
func (handler *Handler) mcpSearchToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	var arguments mcpSearchArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || strings.TrimSpace(arguments.Query) == "" ||
		len(arguments.Query) > mcpSearchQueryMaxLength || arguments.Offset < 0 || arguments.Limit < 0 {
		writeMCPError(writer, envelope.ID, -32602, "invalid search arguments")
		return
	}
	page, limit, available, err := handler.workspaceSearchPage(request, access, arguments.WorkspaceID, arguments.Query, arguments.AllVersions, arguments.Offset, arguments.Limit)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "workspace documents not found")
		return
	}
	results, err := handler.workspaceSearchResults(page)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	structured := map[string]any{
		"results":     results,
		"offset":      arguments.Offset,
		"limit":       limit,
		"has_more":    page.HasMore,
		"partial":     page.Partial,
		"next_offset": mcpSearchNextOffset(page, arguments.Offset),
		"profile":     page.Profile,
	}
	// The term channel is additive: it appears only when the workspace's own
	// catalogue actually defines the asked name, and never replaces a ranked
	// result. A workspace with no catalogue therefore sees no `terms` member at
	// all, rather than an empty one that would suggest the product looked for a
	// definition and found none.
	terms, err := handler.workspaceSearchHitResults(page.TermHits)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if len(terms) > 0 {
		structured["terms"] = terms
		structured["terms_truncated"] = page.TermsTruncated
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": mcpSearchText(page, arguments.Offset, limit, results, terms)}},
		"structuredContent": structured,
		"isError":           false,
	}})
}

// workspaceSearchPage is the single authorized search core both the
// knowvault_search MCP tool and its R3a-1 REST parity route
// (GET/POST /api/v1/workspaces/{workspace_id}/tools/search) dispatch through.
// It resolves the optional EvidenceSearch capability on the injected evidence
// service (the production *evidence.Viewer implements it), applies the canonical
// default/maximum page bounds, and reads one page. available is false only when
// composition mounted no search capability, so the caller can emit its own
// content-free service-unavailable refusal; otherwise err is the viewer's
// content-free ErrNotFound (or its wrapped denial-journal failure). The limit
// returned is always the effective one, so neither surface can truncate
// silently.
// S3 extends it with the hybrid channel: when composition mounted the hybrid
// retrieval capability the page comes from the lexical and vector channels
// fused by reciprocal-rank fusion and re-authorized afterwards, under the
// retrieval profile the owner-only channel resolved for this call; without that
// capability it is the unchanged lexical page, reported as lexical rather than
// dressed up as hybrid. Either way the result carries the profile that actually
// ran, and every hit carries the channel that found it.
func (handler *Handler) workspaceSearchPage(request *http.Request, access database.AccessContext, workspaceID, query string, allVersions bool, offset, limit int64) (workspaceSearchOutcome, int64, bool, error) {
	effectiveLimit := mcpEffectiveSearchLimit(limit)
	if handler != nil && handler.hybridSearch != nil {
		outcome, err := handler.hybridSearchOutcome(request, access, workspaceID, query, allVersions, offset, effectiveLimit)
		if err != nil {
			return workspaceSearchOutcome{}, effectiveLimit, true, err
		}
		return outcome, effectiveLimit, true, nil
	}
	search, ok := handler.evidenceSearchCapability()
	if !ok {
		return workspaceSearchOutcome{}, 0, false, nil
	}
	page, err := search.SearchFragments(request.Context(), access, workspaceID, query, allVersions, offset, effectiveLimit)
	if err != nil {
		return workspaceSearchOutcome{}, effectiveLimit, true, err
	}
	return lexicalSearchOutcome(page, offset), effectiveLimit, true, nil
}

// mcpEffectiveSearchLimit applies the search page bounds, always returning the
// value the response must echo as limit so a capped request is never silent.
func mcpEffectiveSearchLimit(limit int64) int64 {
	if limit == 0 {
		return mcpSearchDefaultLimit
	}
	if limit > mcpSearchMaxLimit {
		return mcpSearchMaxLimit
	}
	return limit
}

// mcpSearchNextOffset renders the stable next-page cursor while more matches
// remain, and null once the page is the end of the result.
func mcpSearchNextOffset(page workspaceSearchOutcome, offset int64) any {
	if !page.HasMore {
		return nil
	}
	if page.NextOffset != 0 {
		return page.NextOffset
	}
	return offset + int64(len(page.Hits))
}

// mcpSearchText renders the content[].text channel of knowvault_search as a
// compact, model-readable page: one line per hit carrying the same immutable
// address, fragment id, excerpt, score, version id and moment the
// structuredContent hit carries, followed by the explicit page cursor (offset,
// effective limit, has_more, next_offset). A client that reads only
// content[].text therefore sees every hit and can reach the next page without
// parsing structuredContent.
// Every hit is exactly one line: a multi-line excerpt is flattened so one hit
// never becomes several and the per-hit addresses stay aligned with the
// structured channel. The rendering is content-free on a denial, because it is
// only reached once the authorized page was read.
// S3 additions keep that property across the new channels: the banner also
// names the retrieval profile the call ran under, every hit line carries the
// channel that found it and the version state it was served under, and a term
// hit is rendered on its own line with the same address the structured `terms`
// member carries. A client that reads only the text channel therefore sees the
// same hits, the same addresses and the same algorithm as one that parses
// structuredContent.
func mcpSearchText(page workspaceSearchOutcome, offset, limit int64, projected ...[]any) string {
	nextOffset := mcpSearchNextOffset(page, offset)
	var builder strings.Builder
	builder.WriteString("knowvault_search: ")
	builder.WriteString(strconv.Itoa(len(page.Hits)))
	builder.WriteString(" hit(s); offset=")
	builder.WriteString(strconv.FormatInt(offset, 10))
	builder.WriteString(" limit=")
	builder.WriteString(strconv.FormatInt(limit, 10))
	builder.WriteString(" has_more=")
	builder.WriteString(strconv.FormatBool(page.HasMore))
	builder.WriteString(" partial=")
	builder.WriteString(strconv.FormatBool(page.Partial))
	builder.WriteString(" next_offset=")
	builder.WriteString(mcpContentCursor(nextOffset))
	builder.WriteString(" profile=")
	builder.WriteString(mcpContentAddress(page.Profile))
	builder.WriteString("\n")
	for index, hit := range page.Hits {
		projection := mcpSearchHitProjection(hit)
		if len(projected) > 0 {
			projection = projected[0][index].(map[string]any)
		}
		mcpSearchHitLine(&builder, "["+strconv.Itoa(index+1)+"]", hit, projection)
	}
	for index, hit := range page.TermHits {
		projection := mcpSearchHitProjection(hit)
		if len(projected) > 1 {
			projection = projected[1][index].(map[string]any)
		}
		mcpSearchHitLine(&builder, "[term "+strconv.Itoa(index+1)+"]", hit, projection)
	}
	return builder.String()
}

// mcpSearchHitLine renders exactly one hit on exactly one line, carrying the
// same canonical address the structured projection carries. The compatibility
// address object stays in structuredContent; repeating both encodings in the
// model's text wastes context and encourages clients to reconstruct addresses.
func mcpSearchHitLine(builder *strings.Builder, label string, hit workspaceSearchHit, projection map[string]any) {
	builder.WriteString(label)
	builder.WriteString(mcpSourcePathText(hit.Fragment.SourcePath))
	if canonical, ok := projection["canonical_address"].(string); ok && canonical != "" {
		builder.WriteString(" canonical_address=")
		builder.WriteString(canonical)
	} else {
		builder.WriteString(" address=")
		builder.WriteString(mcpContentAddress(projection["address"]))
	}
	builder.WriteString(" fragment_id=")
	builder.WriteString(hit.Fragment.FragmentID)
	builder.WriteString(" channel=")
	builder.WriteString(hit.Channel)
	builder.WriteString(" score=")
	builder.WriteString(mcpContentScore(hit.Score))
	builder.WriteString(" version_id=")
	builder.WriteString(hit.Fragment.SourceVersionID)
	if hit.VersionState != "" {
		builder.WriteString(" version_state=")
		builder.WriteString(hit.VersionState)
	}
	if hit.TermKind != "" {
		builder.WriteString(" term_kind=")
		builder.WriteString(hit.TermKind)
	}
	builder.WriteString(" observed_at=")
	builder.WriteString(hit.Fragment.ObservedAt.UTC().Format(time.RFC3339))
	builder.WriteString(" excerpt=")
	builder.WriteString(mcpContentSingleLine(hit.Excerpt))
	builder.WriteString("\n")
}

// mcpContentScore renders a ranking score identically in both channels. A
// lexical term-frequency count keeps printing as the whole number it is; a
// fused reciprocal-rank score prints as the fraction it is.
func mcpContentScore(score float64) string {
	return strconv.FormatFloat(score, 'f', -1, 64)
}

// mcpContentAddress renders one address map as compact JSON so the text channel
// carries the identical address object the structuredContent channel carries
// (same members, same values, deterministic member order). It is shared by the
// search and the inventory text renderers, so both surfaces carry their
// addresses the same way.
func mcpContentAddress(address any) string {
	encoded, err := json.Marshal(address)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// mcpContentCursor renders the page cursor member of the text channel. A nil
// cursor (the last page) is the literal null, matching the structured
// next_offset, so a text-channel-only client can tell the page is the end.
func mcpContentCursor(nextOffset any) string {
	switch value := nextOffset.(type) {
	case nil:
		return "null"
	case int64:
		return strconv.FormatInt(value, 10)
	case int:
		return strconv.Itoa(value)
	default:
		return "null"
	}
}

// mcpContentSingleLine flattens a value onto one line so a hit or a skip stays
// exactly one line in the text channel and a multi-line excerpt cannot shift
// the per-hit alignment of addresses.
func mcpContentSingleLine(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	return strings.ReplaceAll(value, "\n", " ")
}

// mcpFirstNonEmpty returns the first non-empty value, used to resolve the
// wiki-rag workspace and page selector aliases of the evidence surfaces.
func mcpFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// mcpSearchHitProjection renders one canonical search hit: the fragment id, the
// excerpt, the numeric score, the version id, the moment and the content hash,
// plus the same immutable address the read tool returns. The excerpt is the
// bounded lexical excerpt; the address resolves the whole object through
// knowvault_evidence_read.
// S3 adds the channel that produced the hit and, where the serving path can
// establish it, the version state it was served under. `channel` is provenance,
// not a knob: it tells a reader why a fragment is in the page (matched words,
// matched meaning, both, or the workspace's own definition of the asked term),
// and it is never accepted as an input.
func mcpSearchHitProjection(hit workspaceSearchHit) map[string]any {
	projection := map[string]any{
		"fragment_id":  hit.Fragment.FragmentID,
		"excerpt":      hit.Excerpt,
		"score":        hit.Score,
		"channel":      hit.Channel,
		"version_id":   hit.Fragment.SourceVersionID,
		"observed_at":  hit.Fragment.ObservedAt.UTC().Format(time.RFC3339),
		"content_hash": hit.Fragment.ContentHash,
		"address":      mcpEvidenceAddress(hit.Fragment),
	}
	if hit.Fragment.SourcePath != "" {
		projection["source_path"] = hit.Fragment.SourcePath
	}
	if hit.VersionState != "" {
		projection["version_state"] = hit.VersionState
	}
	if hit.TermKind != "" {
		projection["term_kind"] = hit.TermKind
	}
	return projection
}

// workspaceSearchResults emits addresses using the same organization key as
// read. Both transports use this projection; no client must synthesize a hash
// or a selector from the compatibility address object.
func (handler *Handler) workspaceSearchResults(page workspaceSearchOutcome) ([]any, error) {
	return handler.workspaceSearchHitResults(page.Hits)
}

func (handler *Handler) workspaceSearchHitResults(hits []workspaceSearchHit) ([]any, error) {
	results := make([]any, 0, len(hits))
	for _, hit := range hits {
		canonical, err := handler.canonicalEvidenceAddress(hit.Fragment)
		if err != nil {
			return nil, err
		}
		projection := mcpSearchHitProjection(hit)
		projection["canonical_address"] = canonical.String()
		results = append(results, projection)
	}
	return results, nil
}
