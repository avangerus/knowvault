package workspaceapi

// This file is the additive R3a-1 KV-A02 workspace object-inventory tool. It is
// a read-only, workspace-scoped MCP surface: it selects the documents/evidence
// objects of one workspace with their current source version, content hash,
// external version key and moment, current versions only by default with an
// optional all_versions flag, and explicit offset/limit/next_offset paging. It
// resolves through the same authorized Evidence viewer the REST evidence route
// and knowvault_evidence_read use, so admission-before-data, the audit journal
// and the content-free denial stay exactly the existing ones. It introduces no
// new persistence and no migration; its KV-A02 REST parity route lives in
// tools_rest.go and dispatches through the same workspaceInventoryPage core.

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// mcpToolWorkspaceList is the additive, read-only workspace object-inventory
// tool. It is offered to non-SERVICE (human/operator) principals only: the
// SERVICE allow-list in mcpToolCatalog/mcpToolCall already hides and refuses
// every name outside the ADR-0079 section 3 matrix.
const mcpToolWorkspaceList = "knowvault_list_objects"

// mcpToolWorkspaceListCompat is the former advertised name of the same
// inventory tool, kept dispatchable for backward compatibility (a client that
// pinned the pre-rename name still reaches the identical implementation). It is
// deliberately not advertised in mcpToolCatalog: the canonical name above is
// the only one tools/list offers.
const mcpToolWorkspaceListCompat = "knowvault_workspace_list"

// Page bounds for knowvault_list_objects. A caller that omits limit gets one
// default page and an explicit next_offset while more remains; a caller that
// asks for more than the maximum is served the maximum page and told so through
// limit/has_more/next_offset rather than silently truncated.
const (
	mcpWorkspaceListDefaultLimit = 100
	mcpWorkspaceListMaxLimit     = 1000
)

// mcpWorkspaceListArguments is the closed argument envelope for
// knowvault_list_objects: the workspace whose objects are listed, an optional
// all_versions switch (default false = current versions only) and the optional
// offset/limit page window. A negative offset or limit is rejected before any
// read.
type mcpWorkspaceListArguments struct {
	WorkspaceID string `json:"workspace_id"`
	AllVersions bool   `json:"all_versions"`
	Offset      int64  `json:"offset"`
	Limit       int64  `json:"limit"`
}

// EvidenceInventory is the optional inventory capability the workspace object
// list tool composes. It is deliberately separate from EvidenceService so every
// existing EvidenceService implementation (including the REST read boundary and
// its fakes) stays source-compatible: a service that does not implement it
// leaves the tool failing closed as service unavailable rather than widening the
// required interface.
type EvidenceInventory interface {
	ListObjects(context.Context, database.AccessContext, string, bool, int64, int64) (evidence.ObjectInventoryPage, error)
}

// mcpWorkspaceListToolCall lists one page of a workspace's document/evidence
// object inventory. It type-asserts the optional inventory capability on the
// injected evidence service (the production *evidence.Viewer implements it),
// fails closed when composition mounted a service without it, and maps the
// viewer's single content-free ErrNotFound to the existing -32004 not-found so
// an unknown, non-member or cross-workspace call leaks no row and no workspace
// echo. The result carries an explicit page window and the whole-inventory
// cursor, never a silently truncated list.
func (handler *Handler) mcpWorkspaceListToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	if handler.evidence == nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	var arguments mcpWorkspaceListArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" || arguments.Offset < 0 || arguments.Limit < 0 {
		writeMCPError(writer, envelope.ID, -32602, "invalid workspace list arguments")
		return
	}
	handler.mcpWorkspaceListPage(writer, request, access, envelope, arguments.WorkspaceID, arguments.AllVersions, arguments.Offset, arguments.Limit)
}

// mcpWorkspaceListPage is the single inventory core of
// knowvault_list_objects (and of its former name, which dispatches here). It
// type-asserts the
// optional inventory capability on the injected evidence service (the
// production *evidence.Viewer implements it), fails closed when composition
// mounted a service without it, and maps the viewer's single content-free
// ErrNotFound to the existing -32004 not-found so an unknown, non-member or
// cross-workspace call leaks no row and no workspace echo. The result carries
// an explicit page window and the whole-inventory cursor, never a silently
// truncated list.
func (handler *Handler) mcpWorkspaceListPage(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, workspaceID string, allVersions bool, offset, limit int64) {
	page, effectiveLimit, available, err := handler.workspaceInventoryPage(request, access, workspaceID, allVersions, offset, limit)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "workspace objects not found")
		return
	}
	objects := make([]any, 0, len(page.Items))
	for _, item := range page.Items {
		objects = append(objects, mcpWorkspaceObjectProjection(item))
	}
	skipped := make([]any, 0, len(page.Skipped))
	for _, skip := range page.Skipped {
		skipped = append(skipped, mcpWorkspaceSkipProjection(skip))
	}
	var nextOffset any
	if page.HasMore {
		nextOffset = offset + int64(len(page.Items))
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content": []any{map[string]any{"type": "text", "text": mcpWorkspaceListText(page, offset, effectiveLimit, nextOffset)}},
		"structuredContent": map[string]any{
			"objects":       objects,
			"offset":        offset,
			"limit":         effectiveLimit,
			"has_more":      page.HasMore,
			"next_offset":   nextOffset,
			"skipped":       skipped,
			"skipped_count": len(page.Skipped),
		},
		"isError": false,
	}})
}

// workspaceInventoryPage is the single authorized inventory core both the
// knowvault_list_objects MCP tool and its KV-A02 REST parity route dispatch
// through. It resolves the optional EvidenceInventory capability on the injected
// evidence service (the production *evidence.Viewer implements it), applies the
// canonical default/maximum page bounds, and reads one page. available is false
// only when composition mounted no inventory capability, so the caller can emit
// its own content-free service-unavailable refusal; otherwise err is the
// viewer's content-free ErrNotFound (or its wrapped denial-journal failure).
func (handler *Handler) workspaceInventoryPage(request *http.Request, access database.AccessContext, workspaceID string, allVersions bool, offset, limit int64) (evidence.ObjectInventoryPage, int64, bool, error) {
	if handler.evidence == nil {
		return evidence.ObjectInventoryPage{}, 0, false, nil
	}
	inventory, ok := handler.evidence.(EvidenceInventory)
	if !ok {
		return evidence.ObjectInventoryPage{}, 0, false, nil
	}
	if limit == 0 {
		limit = mcpWorkspaceListDefaultLimit
	}
	if limit > mcpWorkspaceListMaxLimit {
		limit = mcpWorkspaceListMaxLimit
	}
	page, err := inventory.ListObjects(request.Context(), access, workspaceID, allVersions, offset, limit)
	if err != nil {
		return evidence.ObjectInventoryPage{}, limit, true, err
	}
	return page, limit, true, nil
}

// mcpWorkspaceListText renders the content[].text channel of
// knowvault_list_objects as a compact, model-readable page: one line per
// inventoried object carrying the same immutable address, object_type, version
// keys, current/version_state and moment the structuredContent object carries;
// one line per skipped ledger row carrying its external id, closed reason code
// and moment; and the explicit page cursor (offset, effective limit, has_more,
// next_offset). A client that reads only content[].text therefore sees every
// object, every skip and the cursor without parsing structuredContent. Every
// object and every skip is exactly one line so the row alignment cannot drift.
func mcpWorkspaceListText(page evidence.ObjectInventoryPage, offset, limit int64, nextOffset any) string {
	var builder strings.Builder
	builder.WriteString("knowvault_list_objects: ")
	builder.WriteString(strconv.Itoa(len(page.Items)))
	builder.WriteString(" object(s); offset=")
	builder.WriteString(strconv.FormatInt(offset, 10))
	builder.WriteString(" limit=")
	builder.WriteString(strconv.FormatInt(limit, 10))
	builder.WriteString(" has_more=")
	builder.WriteString(strconv.FormatBool(page.HasMore))
	builder.WriteString(" next_offset=")
	builder.WriteString(mcpContentCursor(nextOffset))
	builder.WriteString("\n")
	for index, item := range page.Items {
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("] address=")
		builder.WriteString(mcpContentAddress(mcpWorkspaceObjectAddress(item)))
		builder.WriteString(mcpSourcePathText(item.ExternalID))
		builder.WriteString(" object_type=")
		builder.WriteString(item.ObjectType)
		builder.WriteString(" version_id=")
		builder.WriteString(item.SourceVersionID)
		builder.WriteString(" external_version_key=")
		builder.WriteString(mcpContentSingleLine(item.ExternalVersionKey))
		builder.WriteString(" content_hash=")
		builder.WriteString(item.ContentHash)
		builder.WriteString(" observed_at=")
		builder.WriteString(item.ObservedAt.UTC().Format(time.RFC3339))
		builder.WriteString(" current=")
		builder.WriteString(strconv.FormatBool(item.Current))
		builder.WriteString(" version_state=")
		builder.WriteString(item.VersionState)
		// Ingest metadata cannot prove current semantic index coverage. Both
		// channels report that uncertainty, including for a recorded profile.
		builder.WriteString(" embedded=unknown embedding_status=UNKNOWN")
		builder.WriteString("\n")
	}
	for _, skip := range page.Skipped {
		builder.WriteString("skipped: external_id=")
		builder.WriteString(mcpContentSingleLine(skip.ExternalID))
		builder.WriteString(" reason_code=")
		builder.WriteString(skip.ReasonCode)
		builder.WriteString(" moment=")
		builder.WriteString(skip.ObservedAt.UTC().Format(time.RFC3339))
		builder.WriteString("\n")
	}
	return builder.String()
}

// mcpWorkspaceObjectProjection renders one inventory row with its identifiers,
// version keys, moment and immutable address. It carries only non-content
// metadata already visible through the gated control-plane surface. A
// code-source object (object_type GIT_FILE, R3a-1 KV-A04a) additionally carries
// its mirror age derived from the code source's already-persisted last
// successful mirror/sync moment; a document/evidence row carries no mirror
// member.
func mcpWorkspaceObjectProjection(item evidence.ObjectInventoryItem) map[string]any {
	projection := map[string]any{
		"source_object_id":     item.SourceObjectID,
		"source_version_id":    item.SourceVersionID,
		"external_version_key": item.ExternalVersionKey,
		"content_hash":         item.ContentHash,
		"observed_at":          item.ObservedAt.UTC().Format(time.RFC3339),
		"object_type":          item.ObjectType,
		"current":              item.Current,
		"version_state":        item.VersionState,
		"address":              mcpWorkspaceObjectAddress(item),
	}
	if item.ExternalID != "" {
		projection["source_path"] = item.ExternalID
	}
	// The mirror age is added only for a code-source object, so a document is
	// never mislabelled as a mirror. It is never silent: when the projection
	// applies, mirror_age_seconds is always present and non-negative, and
	// mirrored_at is added whenever a moment is persisted.
	if item.ObjectType == mcpGrepCodeObjectType {
		projection["mirror_age_seconds"] = mcpWorkspaceMirrorAgeSeconds(item)
		if item.MirroredAt != nil {
			projection["mirrored_at"] = item.MirroredAt.UTC().Format(time.RFC3339)
		}
	}
	// M1 semantic inventory limitation: immutable ingest metadata is neither
	// an index acknowledgement nor current-profile coverage. Correct the old
	// always-boolean claim with an explicit null/UNKNOWN; do not present the
	// ingest profile as the profile under which this version is searchable.
	projection["embedded"] = nil
	projection["embedding_status"] = "UNKNOWN"
	return projection
}

// mcpWorkspaceMirrorAgeSeconds returns the non-negative mirror age of one
// code-source inventory row. A caller never sees a negative age: a missing or
// future moment is reported as zero.
func mcpWorkspaceMirrorAgeSeconds(item evidence.ObjectInventoryItem) int64 {
	if item.MirrorAgeSeconds < 0 {
		return 0
	}
	return item.MirrorAgeSeconds
}

// mcpWorkspaceSkipProjection renders one typed skip ledger row (R3a-1 KV-A02):
// the object's stable external id, the closed reason code and the moment the
// skip was observed. It carries no source content.
func mcpWorkspaceSkipProjection(skip evidence.ObjectInventorySkip) map[string]any {
	return map[string]any{
		"external_id": skip.ExternalID,
		"reason_code": skip.ReasonCode,
		"moment":      skip.ObservedAt.UTC().Format(time.RFC3339),
	}
}

// mcpWorkspaceObjectAddress renders the immutable address of one inventoried
// object version: source, version, object and the exact ordinal span of the
// version's fragments (the fragment anchor the read tool resolves). It carries
// no source content.
func mcpWorkspaceObjectAddress(item evidence.ObjectInventoryItem) map[string]any {
	return map[string]any{
		"source": map[string]any{
			"source_object_id": item.SourceObjectID,
			"connection_id":    item.ConnectionID,
			"object_type":      item.ObjectType,
		},
		"version": map[string]any{
			"source_version_id":    item.SourceVersionID,
			"external_version_key": item.ExternalVersionKey,
			"content_hash":         item.ContentHash,
			"observed_at":          item.ObservedAt.UTC().Format(time.RFC3339),
		},
		"object": map[string]any{
			"first_fragment_id": item.FirstFragmentID,
		},
		"span": map[string]any{
			"kind":           "OBJECT",
			"fragment_count": item.FragmentCount,
			"ordinal_start":  item.FirstOrdinal,
			"ordinal_end":    item.LastOrdinal,
		},
	}
}
