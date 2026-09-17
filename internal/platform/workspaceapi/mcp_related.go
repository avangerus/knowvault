package workspaceapi

// This file is the additive R3a-1 KV-A03-related workspace relation tool. It is
// a read-only, workspace-scoped MCP surface: for one addressed object in a
// workspace it returns the canonical cross-source relations the Evidence-graph
// capability persists, page by page, with the related object's immutable
// address, the relation kind, an excerpt and the moment. It resolves through the
// same authorized relation-source as the cross-source Evidence-graph read, so
// admission-before-data, the audit journal and the content-free denial stay the
// existing ones. It introduces no new store, index or migration and no new REST
// route.
//
// The tool set is KnowVault's own: no wiki-rag tool name is advertised or
// dispatched by the product (owner decision 12.09.2026). A session that used
// wiki-rag is reconfigured to `knowvault_related`; the parameters and result
// shape are documented in docs/MCP-TOOLS.md.

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpToolRelated is the canonical workspace relation tool.
const mcpToolRelated = "knowvault_related"

// The closed direction vocabulary. "referencing" returns the relations whose
// object is the addressed object (who references it); "references" returns the
// relations whose subject is the addressed object (what it references); "both"
// returns either. An absent direction defaults to "both".
const (
	mcpRelatedDirectionReferencing = "referencing"
	mcpRelatedDirectionReferences  = "references"
	mcpRelatedDirectionBoth        = "both"
)

// Page bounds for the related tool. A caller that omits limit gets one default
// page and an explicit next_cursor while more remains; a caller that asks for
// more than the maximum is served the maximum page and told so through
// limit/has_more/next_cursor rather than silently truncated.
const (
	mcpRelatedDefaultLimit = 50
	mcpRelatedMaxLimit     = 200
)

// mcpRelatedCursorPrefix is the stable, server-owned result-set cursor form. A
// cursor is the canonical offset token (the same v1: convention as the
// whole-object read cursor), so a client can persist it and resume the same
// relation set later; a cursor this server did not produce is refused before
// the relation-source is touched.
const mcpRelatedCursorPrefix = "v1:"

// mcpRelatedArguments is the closed argument envelope for knowvault_related: the
// workspace that owns the object, the object selected by fragment_id or by the
// canonical address, the optional direction (default both), the optional stable
// cursor and the optional limit. A missing selector, an unknown member, an
// unknown direction, a negative limit or a malformed cursor is rejected before
// any relation is read.
type mcpRelatedArguments struct {
	WorkspaceID string `json:"workspace_id"`
	FragmentID  string `json:"fragment_id"`
	Address     string `json:"address"`
	Direction   string `json:"direction"`
	Cursor      string `json:"cursor"`
	Limit       int64  `json:"limit"`
}

// RelatedHit is one canonical relation touching the addressed object: the
// related object's full authorized fragment projection (so its address, version
// and moment are the ones the read tool resolves), the relation kind and a
// bounded excerpt. It carries no different content than the authorized fragment
// read already returns.
type RelatedHit struct {
	Fragment     evidence.Fragment
	RelationKind string
	Excerpt      string
}

// RelatedPage is one explicit page of a workspace's relations. HasMore true
// means more relations remain after this page; NextOffset is the stable cursor
// the caller passes back as cursor to fetch the next page, so a limit is never
// silent truncation.
type RelatedPage struct {
	Hits       []RelatedHit
	HasMore    bool
	NextOffset int64
	// Truncated reports that the relation source hit its own bounded expansion
	// cap: more relations may exist than this page sequence can return. It is
	// disclosed to the caller (never silently dropped), and it is only ever true
	// on the final page, where HasMore is false.
	Truncated bool
}

// EvidenceRelated is the optional relation capability the related tool composes.
// It is deliberately separate from EvidenceService so every existing
// EvidenceService implementation (including the REST read boundary and its
// fakes) stays source-compatible: a service that does not implement it leaves
// the related tool unadvertised and failing closed as service unavailable rather
// than widening the required interface. The authorized relation-source that the
// cross-source Evidence-graph capability persists implements it (or is exposed
// through it) under the same admission/outcome audit as the fragment read.
type EvidenceRelated interface {
	RelatedObjects(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, direction string, offset, limit int64) (RelatedPage, error)
}

// evidenceRelatedCapability exposes the optional relation capability to the
// tools/list and tools/call boundaries without widening EvidenceService.
func (handler *Handler) evidenceRelatedCapability() (EvidenceRelated, bool) {
	if handler == nil || handler.evidence == nil {
		return nil, false
	}
	related, ok := handler.evidence.(EvidenceRelated)
	return related, ok
}

// mcpRelatedToolDefinitions is the tools/list projection of the canonical
// relation tool. It is appended only when the mounted evidence service actually
// implements EvidenceRelated, so the surface never advertises a tool it cannot
// serve.
func mcpRelatedToolDefinitions() []any {
	return []any{
		map[string]any{
			"name": mcpToolRelated, "description": "Return the canonical cross-source relations touching one addressed object of a workspace: the related object with its immutable address (source, version, object and exact span hash), the relation kind, an excerpt, the version and the moment. direction selects referencing, references or both. Paginated with cursor, the effective limit, has_more and next_cursor (no silent truncation); stable ordering. Read-only.",
			"inputSchema": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"workspace_id"}, "properties": map[string]any{
				"workspace_id": map[string]any{"type": "string"},
				"fragment_id":  map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"address":      map[string]any{"type": "string", "minLength": 1},
				"direction":    map[string]any{"type": "string", "enum": []string{mcpRelatedDirectionReferencing, mcpRelatedDirectionReferences, mcpRelatedDirectionBoth}},
				"cursor":       map[string]any{"type": "string"},
				"limit":        map[string]any{"type": "integer", "minimum": 1},
			}},
		},
	}
}

// mcpRelatedToolCall dispatches knowvault_related onto the authorized relation
// source. It fails closed as service unavailable when composition mounted an
// evidence service without the relation capability, and maps the source's single
// content-free denial to the existing -32004 not-found so an unknown, non-member
// or cross-workspace call leaks no relation, excerpt or address and never echoes
// the requested workspace id.
func (handler *Handler) mcpRelatedToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	related, ok := handler.evidenceRelatedCapability()
	if !ok {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpRelatedArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
		return
	}
	if arguments.WorkspaceID == "" || (arguments.FragmentID == "" && arguments.Address == "") || arguments.Limit < 0 {
		writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
		return
	}
	direction, ok := mcpRelatedDirection(arguments.Direction)
	if !ok {
		writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
		return
	}
	offset, ok := mcpRelatedCursorOffset(arguments.Cursor)
	if !ok {
		writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
		return
	}
	fragmentID := arguments.FragmentID
	if arguments.Address != "" {
		parsed, parseErr := address.Parse(arguments.Address)
		if parseErr != nil {
			writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
			return
		}
		if fragmentID == "" {
			fragmentID = parsed.Object
		} else if parsed.Object != fragmentID {
			// The address and the explicit selector must name the same object;
			// a mismatch is refused before any relation is read.
			writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
			return
		}
	}
	if fragmentID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid related arguments")
		return
	}
	limit := mcpEffectiveRelatedLimit(arguments.Limit)
	page, err := related.RelatedObjects(request.Context(), access, arguments.WorkspaceID, fragmentID, direction, offset, limit)
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "workspace relations not found")
		return
	}
	results := make([]any, 0, len(page.Hits))
	for _, hit := range page.Hits {
		results = append(results, mcpRelatedHitProjection(hit))
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": mcpRelatedText(page, direction, limit)}},
		"structuredContent": map[string]any{
			"relations":   results,
			"direction":   direction,
			"limit":       limit,
			"has_more":    page.HasMore,
			"next_cursor": mcpRelatedNextCursor(page),
			"truncated":   page.Truncated,
		},
		"isError": false,
	}})
}

// mcpRelatedDirection resolves the closed direction vocabulary, returning
// false for any other non-empty value. An absent direction is "both".
func mcpRelatedDirection(direction string) (string, bool) {
	switch direction {
	case "":
		return mcpRelatedDirectionBoth, true
	case mcpRelatedDirectionReferencing, mcpRelatedDirectionReferences, mcpRelatedDirectionBoth:
		return direction, true
	default:
		return "", false
	}
}

// mcpRelatedCursorOffset parses the stable result-set cursor into the offset it
// names. An empty cursor is the first page; a cursor this server did not produce
// (wrong prefix, non-integer, negative) is refused.
func mcpRelatedCursorOffset(cursor string) (int64, bool) {
	if cursor == "" {
		return 0, true
	}
	if !strings.HasPrefix(cursor, mcpRelatedCursorPrefix) {
		return 0, false
	}
	offset, err := strconv.ParseInt(strings.TrimPrefix(cursor, mcpRelatedCursorPrefix), 10, 64)
	if err != nil || offset < 0 {
		return 0, false
	}
	return offset, true
}

// mcpEffectiveRelatedLimit applies the relation page bounds, always returning
// the value the response must echo as limit so a capped request is never silent.
func mcpEffectiveRelatedLimit(limit int64) int64 {
	if limit == 0 {
		return mcpRelatedDefaultLimit
	}
	if limit > mcpRelatedMaxLimit {
		return mcpRelatedMaxLimit
	}
	return limit
}

// mcpRelatedNextCursor renders the stable next-page cursor while more relations
// remain, and null once the page is the end of the result.
func mcpRelatedNextCursor(page RelatedPage) any {
	if !page.HasMore {
		return nil
	}
	return mcpRelatedCursorPrefix + strconv.FormatInt(page.NextOffset, 10)
}

// mcpRelatedNextCursorText renders the page cursor member of the content[].text
// channel: the same stable cursor value the structuredContent channel carries,
// or the literal null on the final page, so a text-channel-only client can tell
// the page is the end and resume the next one without parsing structuredContent.
func mcpRelatedNextCursorText(page RelatedPage) string {
	cursor, ok := mcpRelatedNextCursor(page).(string)
	if !ok {
		return "null"
	}
	return cursor
}

// mcpRelatedText renders the content[].text channel of knowvault_related as a
// compact, model-readable page: one line per relation hit carrying the same
// immutable address, relation kind, excerpt, fragment id, version id, moment and
// content hash the structuredContent hit carries, followed by a leading page
// line with the direction, effective limit, has_more, next_cursor and truncated
// members. A client (or a model) that reads only content[].text therefore sees
// every relation and can reach the next page without parsing structuredContent.
// Every hit is exactly one line: a multi-line excerpt is flattened so one hit
// never becomes several and the per-hit addresses stay aligned with the
// structured channel. The rendering is content-free on a denial, because it is
// only reached once the authorized page was read.
func mcpRelatedText(page RelatedPage, direction string, limit int64) string {
	var builder strings.Builder
	builder.WriteString("knowvault_related: ")
	builder.WriteString(strconv.Itoa(len(page.Hits)))
	builder.WriteString(" relation(s); direction=")
	builder.WriteString(direction)
	builder.WriteString(" limit=")
	builder.WriteString(strconv.FormatInt(limit, 10))
	builder.WriteString(" has_more=")
	builder.WriteString(strconv.FormatBool(page.HasMore))
	builder.WriteString(" next_cursor=")
	builder.WriteString(mcpRelatedNextCursorText(page))
	builder.WriteString(" truncated=")
	builder.WriteString(strconv.FormatBool(page.Truncated))
	builder.WriteString("\n")
	for index, hit := range page.Hits {
		projection := mcpRelatedHitProjection(hit)
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("] address=")
		builder.WriteString(mcpContentAddress(projection["address"]))
		builder.WriteString(" relation_kind=")
		builder.WriteString(hit.RelationKind)
		builder.WriteString(" excerpt=")
		builder.WriteString(mcpContentSingleLine(hit.Excerpt))
		builder.WriteString(" fragment_id=")
		builder.WriteString(hit.Fragment.FragmentID)
		builder.WriteString(" version_id=")
		builder.WriteString(hit.Fragment.SourceVersionID)
		builder.WriteString(" observed_at=")
		builder.WriteString(hit.Fragment.ObservedAt.UTC().Format(time.RFC3339))
		builder.WriteString(" content_hash=")
		builder.WriteString(hit.Fragment.ContentHash)
		builder.WriteString("\n")
	}
	return builder.String()
}

// mcpRelatedHitProjection renders one canonical relation hit: the relation kind,
// the bounded excerpt, the related object's version id, moment and content hash,
// plus the same immutable address the read tool returns. The address resolves
// the whole related object through knowvault_evidence_read.
func mcpRelatedHitProjection(hit RelatedHit) map[string]any {
	return map[string]any{
		"relation_kind": hit.RelationKind,
		"excerpt":       hit.Excerpt,
		"fragment_id":   hit.Fragment.FragmentID,
		"version_id":    hit.Fragment.SourceVersionID,
		"observed_at":   hit.Fragment.ObservedAt.UTC().Format(time.RFC3339),
		"content_hash":  hit.Fragment.ContentHash,
		"address":       mcpEvidenceAddress(hit.Fragment),
	}
}
