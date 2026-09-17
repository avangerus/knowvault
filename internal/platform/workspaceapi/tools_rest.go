package workspaceapi

// This file is R3a-1's REST parity surface for the workspace knowledge tools.
// It serves GET/POST /api/v1/workspaces/{workspace_id}/tools/list-objects
// (KV-A02), GET/POST /api/v1/workspaces/{workspace_id}/tools/search
// (KV-A03), GET/POST /api/v1/workspaces/{workspace_id}/tools/grep
// (KV-A02c), GET/POST /api/v1/workspaces/{workspace_id}/tools/related and
// GET/POST /api/v1/workspaces/{workspace_id}/tools/read,
// GET/POST /api/v1/workspaces/{workspace_id}/tools/sources and
// GET/POST /api/v1/workspaces/{workspace_id}/tools/refresh (KV-A04),
// the HTTP twins of the MCP knowvault_list_objects,
// knowvault_search, knowvault_grep, knowvault_related, knowvault_read,
// knowvault_sources (compat knowvault_sources_list) and knowvault_refresh calls, by dispatching through the
// identical authorized capabilities the MCP tools compose: the Evidence viewer
// (workspaceInventoryPage, workspaceSearchPage, the EvidenceGrep capability, the
// EvidenceRelated capability and the EvidenceService.Read / EvidenceWholeObject
// -> address.Read pair -> the production *evidence.Viewer) and the injected
// SourceService (ListSources, ConfirmationContext and the authorized Sync
// command). Every tools/{segment} subpath is resolved through the one
// internal/workspacetools registry (LookupREST) and the dispatcher switches on
// the resolved kind, so REST and MCP cannot drift on a tool name, alias or
// kind. Authorization, the admission-before-data audit journal, the
// content-free denial and the paginated projections are therefore the same
// implementation as MCP, not a re-derivation. It introduces no new persistence
// and no migration, and it neither changes nor re-advertises any existing REST
// or MCP route.

import (
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// workspaceToolDispatch is the one registry-driven entry point the dispatcher
// routes every workspace knowledge tool REST parity endpoint kind through. The
// route recognition resolved the tools/{segment} subpath through
// workspacetools.KnowledgeTools().LookupREST and stored the resolved kind here,
// so this function switches on the workspacetools.Kind and calls the existing
// seven implementations. The endpoint kind only selected the OpenAPI-described
// route; it never selects the implementation, exactly as the MCP adapter
// switches on the same registry kind. A zero/unknown kind is unreachable from
// the route recognition but is refused as the existing content-free NOT_FOUND
// rather than falling through to a capability.
func (handler *Handler) workspaceToolDispatch(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID string, endpoint endpoint) {
	switch endpoint.workspaceToolKind {
	case workspacetools.KindListObjects:
		handler.workspaceToolListObjects(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.listObjectsAllVersions, endpoint.listObjectsOffset, endpoint.listObjectsLimit)
	case workspacetools.KindSearch:
		handler.workspaceToolSearch(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.searchQuery, endpoint.searchAllVersions, endpoint.searchOffset, endpoint.searchLimit)
	case workspacetools.KindGrep:
		handler.workspaceToolGrep(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.grepPattern, endpoint.grepAddress, endpoint.grepRef, endpoint.grepAllVersions, endpoint.grepOffset, endpoint.grepLimit)
	case workspacetools.KindRelated:
		handler.workspaceToolRelated(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.relatedFragmentID, endpoint.relatedAddress, endpoint.relatedDirection,
			endpoint.relatedOffset, endpoint.relatedLimit)
	case workspacetools.KindRead:
		handler.workspaceToolRead(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.readFragmentID, endpoint.readAddress, endpoint.readOffset, endpoint.readLimit,
			endpoint.readExpectedSpanHash, endpoint.readCursor)
	case workspacetools.KindSources:
		handler.workspaceToolSources(writer, request, access, requestID, endpoint.workspaceID)
	case workspacetools.KindRefresh:
		handler.workspaceToolRefresh(writer, request, access, requestID, endpoint.workspaceID,
			endpoint.refreshSourceScopeID, endpoint.refreshOffset, endpoint.refreshLimit)
	default:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	}
}

// restRelatedFragmentID resolves the closed selector pair of the tools/related
// REST route to the single addressed object id, with exactly the semantics the
// MCP knowvault_related tool applies inline: a supplied address is parsed with
// address.Parse; when fragment_id is absent the address selects the object, and
// when both are present they must name the same object. An unparsable address, a
// missing selector or an address/selector mismatch returns false so the handler
// refuses the request with REQUEST_INVALID before the relation capability is
// touched, exactly as the MCP tool refuses it with -32602.
func restRelatedFragmentID(fragmentID, rawAddress string) (string, bool) {
	if rawAddress == "" {
		if fragmentID == "" {
			return "", false
		}
		return fragmentID, true
	}
	parsed, err := address.Parse(rawAddress)
	if err != nil || parsed.Object == "" {
		return "", false
	}
	if fragmentID == "" {
		return parsed.Object, true
	}
	if parsed.Object != fragmentID {
		return "", false
	}
	return fragmentID, true
}

// workspaceToolListObjects serves one page of the workspace document/evidence
// object inventory. It returns exactly the projection the MCP
// knowvault_list_objects tool returns: one row per (source_object_id,
// source_version_id) with version, external_version_key, content_hash,
// observed_at, object_type, current/version_state and the immutable address,
// plus the explicit page window offset/limit/has_more/next_offset. A
// code-source (GIT_FILE) row additionally carries the mirror age
// (mirror_age_seconds and, when a moment is persisted, an RFC3339 mirrored_at)
// through the same shared mcpWorkspaceObjectProjection the MCP tool uses, so the
// two transports cannot drift; a document/evidence row keeps its prior
// projection with no mirror member. An unknown
// workspace or a non-member caller collapses to the viewer's single
// content-free not-found; no row and no workspace-id echo are disclosed. A
// service mounted without the inventory capability fails closed as
// SERVICE_UNAVAILABLE, exactly like the other capability-gated routes.
func (handler *Handler) workspaceToolListObjects(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string, allVersions bool, offset, limit int64) {
	page, effectiveLimit, available, err := handler.workspaceInventoryPage(request, access, workspaceID, allVersions, offset, limit)
	if !available {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
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
	writeJSON(writer, http.StatusOK, map[string]any{
		"objects":       objects,
		"offset":        offset,
		"limit":         effectiveLimit,
		"has_more":      page.HasMore,
		"next_offset":   nextOffset,
		"skipped":       skipped,
		"skipped_count": len(page.Skipped),
	})
}

// workspaceToolSearch serves one page of the workspace lexical search. It
// returns exactly the projection the MCP knowvault_search tool returns:
// per-hit fragment_id, excerpt, score, version_id, observed_at, content_hash
// and the immutable address, plus the explicit page window
// offset/limit/has_more/next_offset. The effective limit is echoed, so a
// capped request is visible rather than silently truncated. An unknown
// workspace or a non-member caller collapses to the viewer's single
// content-free not-found; no hit and no workspace-id echo are disclosed. A
// service mounted without the search capability fails closed as
// SERVICE_UNAVAILABLE, exactly like the other capability-gated routes.
func (handler *Handler) workspaceToolSearch(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, query string, allVersions bool, offset, limit int64) {
	page, effectiveLimit, available, err := handler.workspaceSearchPage(request, access, workspaceID, query, allVersions, offset, limit)
	if !available {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	results, err := handler.workspaceSearchResults(page)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var nextOffset any
	if page.HasMore {
		nextOffset = mcpSearchNextOffset(page, offset)
	}
	body := map[string]any{
		"results":     results,
		"offset":      offset,
		"limit":       effectiveLimit,
		"has_more":    page.HasMore,
		"next_offset": nextOffset,
		"profile":     page.Profile,
		"partial":     page.Partial,
	}
	// The REST parity carries the term channel exactly as MCP does, including
	// its absence: the two surfaces are two addressings of one implementation,
	// so a client must not have to know which one it is speaking to.
	if len(page.TermHits) > 0 {
		terms, err := handler.workspaceSearchHitResults(page.TermHits)
		if err != nil {
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		body["terms"] = terms
		body["terms_truncated"] = page.TermsTruncated
	}
	writeJSON(writer, http.StatusOK, body)
}

// workspaceToolGrep serves one page of the workspace exact-regex grep. It
// returns exactly the projection the MCP knowvault_grep tool returns: per-match
// offset/length inside the canonical object text, a bounded excerpt, the hash of
// the matched bytes, the version id, the moment, the content hash and the
// immutable address (including the canonical address that resolves the whole
// object through the read tool), plus the explicit page window
// offset/limit/has_more/next_offset. The effective limit is echoed, so a capped
// request is visible rather than silently truncated.
//
// The pattern and page window travel in the query string for both the GET and
// the POST form (the REST parity of the MCP arguments); the request body is not
// a parameter channel, so a non-empty body is an unexpected member and is
// refused as REQUEST_INVALID rather than silently ignored. A missing or
// whitespace-only pattern, a pattern longer than the MCP bound, a malformed
// regular expression, a negative or non-decimal offset/limit, an unknown query
// key, a duplicate and an empty value are all refused before the capability is
// asked to read anything. The optional `ref` query key is the named code-source
// ref: when present, only the workspace's registered git code-source object
// versions whose immutable identity matches the ref are scanned (resolved from
// object-inventory metadata before any fragment content is read) and the ref
// becomes the address version, exactly as the MCP `ref` argument. The optional
// `address` query key is a complete canonical text address and selects one
// exact object/version through the existing authorized whole-object read,
// without an inventory scan; it is mutually exclusive with ref and
// all_versions. An unknown
// workspace or a non-member caller collapses to the viewer's single
// content-free not-found; no match and no workspace-id echo are disclosed. A
// service mounted without the grep capability fails closed as
// SERVICE_UNAVAILABLE, exactly like the other capability-gated routes.
func (handler *Handler) workspaceToolGrep(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, pattern, rawAddress, ref string, allVersions bool, offset, limit int64) {
	// A malformed RE2 expression is a closed-envelope refusal, rejected here
	// before the capability is asked to read anything, exactly as the MCP tool
	// rejects it with -32602.
	if _, err := regexp.Compile(pattern); err != nil {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	if code, _ := emptyBody(writer, request); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	var selector *address.Address
	if rawAddress != "" {
		parsed, selectorErr := mcpGrepAddressSelector(rawAddress)
		if selectorErr != nil || ref != "" || allVersions {
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
		selector = &parsed
	}
	grep, ok := handler.mcpGrepCapability()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	effectiveLimit := mcpEffectiveGrepLimit(limit)
	var page GrepPage
	projectionRef := ref
	var err error
	if selector != nil {
		page, projectionRef, err = handler.mcpGrepAtAddress(request.Context(), access, workspaceID, *selector, pattern, offset, effectiveLimit)
	} else if ref != "" {
		// Named-ref scoping parity with MCP: a service that serves grep but not
		// code-source scoping fails closed rather than scanning every object as
		// if the ref had been ignored.
		refGrep, refOK := handler.mcpGrepRefCapability()
		if !refOK {
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		page, err = refGrep.GrepFragmentsAtRef(request.Context(), access, workspaceID, pattern, ref, offset, effectiveLimit)
	} else {
		page, err = grep.GrepFragments(request.Context(), access, workspaceID, pattern, allVersions, offset, effectiveLimit)
	}
	if err != nil {
		switch {
		case errors.Is(err, errMCPGrepInvalidAddress):
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		case errors.Is(err, address.ErrSpanMismatch):
			writeError(writer, http.StatusConflict, "EVIDENCE_SPAN_HASH_MISMATCH", requestID)
			return
		case errors.Is(err, errMCPGrepWholeObjectUnavailable):
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	matches := make([]any, 0, len(page.Hits))
	for _, hit := range page.Hits {
		projection, err := handler.grepHitProjection(hit, projectionRef)
		if err != nil {
			writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
			return
		}
		matches = append(matches, projection)
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"matches":     matches,
		"offset":      offset,
		"limit":       effectiveLimit,
		"has_more":    page.HasMore,
		"next_offset": mcpGrepNextOffset(page, offset),
	})
}

// workspaceToolRelated serves one page of the workspace cross-source relations.
// It returns exactly the projection the MCP knowvault_related tool returns:
// per-relation relation_kind, excerpt, fragment_id, version_id, observed_at,
// content_hash and the immutable address, plus direction, the effective limit,
// has_more, next_cursor and truncated. The effective limit is always echoed, so
// a capped request is visible rather than silently truncated, and next_cursor is
// rendered by the identical mcpRelatedNextCursor the MCP tool uses.
//
// The object is selected by fragment_id or by the canonical kv1 address (or
// both, which must name the same object); direction is the closed vocabulary and
// cursor is the stable v1:<offset> form. All of those are validated before the
// capability is touched, exactly as the MCP tool refuses them with -32602. The
// page window travels in the query string for both the GET and the POST form;
// the request body is not a parameter channel, so a non-empty body is refused as
// REQUEST_INVALID rather than silently ignored. An unknown workspace or a
// non-member caller collapses to the relation source's single content-free
// not-found; no relation, excerpt or address and no workspace-id echo are
// disclosed. A service mounted without the relation capability fails closed as
// SERVICE_UNAVAILABLE, exactly like the other capability-gated routes.
func (handler *Handler) workspaceToolRelated(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, fragmentID, rawAddress, direction string, offset, limit int64) {
	if code, _ := emptyBody(writer, request); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	// The selector is resolved before the capability is asked for, so an
	// unparsable address, a missing selector or an address that names a
	// different object than an explicit fragment_id is a closed-envelope 400
	// rather than a service probe.
	fragmentID, selectorOK := restRelatedFragmentID(fragmentID, rawAddress)
	if !selectorOK {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	resolvedDirection, directionOK := mcpRelatedDirection(direction)
	if !directionOK {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	related, ok := handler.evidenceRelatedCapability()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	effectiveLimit := mcpEffectiveRelatedLimit(limit)
	page, err := related.RelatedObjects(request.Context(), access, workspaceID, fragmentID, resolvedDirection, offset, effectiveLimit)
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	relations := make([]any, 0, len(page.Hits))
	for _, hit := range page.Hits {
		relations = append(relations, mcpRelatedHitProjection(hit))
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"relations":   relations,
		"direction":   resolvedDirection,
		"limit":       effectiveLimit,
		"has_more":    page.HasMore,
		"next_cursor": mcpRelatedNextCursor(page),
		"truncated":   page.Truncated,
	})
}

// writeEvidenceSpanRefusal maps the MCP -32005 typed, content-free refusal
// (a caller-supplied expected_span_hash or an address span digest that does not
// match the stored keyed text_hash) onto REST: 409 Conflict with the stable
// code EVIDENCE_SPAN_HASH_MISMATCH. It carries neither the supplied nor the
// stored hash and no page bytes and no address, exactly like the MCP error.
func writeEvidenceSpanRefusal(writer http.ResponseWriter, requestID string) {
	writeError(writer, http.StatusConflict, "EVIDENCE_SPAN_HASH_MISMATCH", requestID)
}

// workspaceToolRead is the REST parity of the MCP knowvault_read tool
// (R3a-1 Outcome 1: by address, paged). It dispatches through the identical
// authorized Evidence viewer handler.evidence.Read in fragment-page mode and
// through the identical EvidenceWholeObject capability plus address.Read in
// whole-object cursor mode (selected by the presence of the cursor query
// parameter), so the admission-before-data audit journal, the R1 outcome and
// the content-free denial are the existing implementation and no new read path
// exists.
//
// Fragment mode returns exactly the projection the MCP tool returns:
// fragment_id, text, text_base64, offset, length, next_offset, has_more, the
// effective limit, total_length, text_hash, page_hash, the immutable address
// and the canonical_address. Cursor mode returns offset, length, next_cursor,
// has_more, complete, the effective limit, total_bytes, whole_hash, page_hash,
// the immutable address, canonical_address, fragment_count, ordinal_start and
// ordinal_end; concatenating the decoded text_base64 payloads of every page
// reproduces the whole original that hashes to whole_hash. A limit is always
// echoed, so it is never silent truncation.
//
// A missing selector, an unparsable or object-mismatching address, an
// out-of-range offset, an unknown or past-end cursor and a non-empty request
// body are refused before any fragment is read: the closed query validation
// lives in validWorkspaceToolReadQuery (400 REQUEST_INVALID) and the
// address/object check happens here before the capability is touched. A
// tampered address or a mismatching expected_span_hash is the typed,
// content-free 409 EVIDENCE_SPAN_HASH_MISMATCH with no page bytes and no
// address. An unknown workspace or a non-member caller collapses to the
// viewer's single content-free 404 NOT_FOUND with no workspace-id echo. A
// service mounted without the whole-object capability fails closed 503
// SERVICE_UNAVAILABLE, exactly like the other capability-gated routes.
func (handler *Handler) workspaceToolRead(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, fragmentID, rawAddress string, offset, limit int64, expectedSpanHash string, cursor *string) {
	if code, _ := emptyBody(writer, request); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	if handler.evidence == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var selector *address.Address
	if rawAddress != "" {
		parsed, parseErr := address.Parse(rawAddress)
		if parseErr != nil {
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
		selector = &parsed
		if fragmentID == "" {
			// The address is the selector: its object names the fragment. The
			// read still goes through the authorized viewer, so a foreign
			// workspace or object is the single content-free denial.
			fragmentID = parsed.Object
		} else if parsed.Object != fragmentID {
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
	}
	if workspaceID == "" || fragmentID == "" {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	// A named code-source ref version (R3a-1 KV-A04b) is resolved from
	// object-inventory metadata only, before any fragment content is read, so a
	// ref-scoped canonical address round-trips. A version of a listed object
	// that is neither its immutable source version id nor a matching
	// code-source ref is refused content-free here; an object the inventory does
	// not list falls through to the authorized read's own denial.
	refVersionID := ""
	if selector != nil {
		resolution := handler.mcpReadAddressResolution(request.Context(), access, workspaceID, *selector)
		if resolution.Available && resolution.ObjectSeen && !resolution.VersionKnown {
			// The address names a version of an object this workspace's
			// inventory lists, but it is neither the immutable source version
			// id nor a matching code-source ref: an unknown or foreign ref,
			// refused content-free before any content is read.
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
		refVersionID = resolution.RefVersionID
	}
	if cursor != nil {
		handler.workspaceToolReadWholeObject(writer, request, access, requestID, workspaceID, fragmentID, selector, refVersionID, *cursor, limit, expectedSpanHash)
		return
	}
	fragment, err := handler.readEvidenceSelection(request.Context(), access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	// The address must name exactly the object the authorized read resolved,
	// else it names something the caller was not authorized to read: refuse it
	// with a typed, content-free error and no page text and no address.
	if selector != nil {
		if selector.Source != fragment.SourceObjectID || selector.Object != fragment.FragmentID || !mcpReadAddressVersionMatches(*selector, fragment.SourceVersionID, refVersionID) {
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
		if !handler.verifyAddressSpan(fragment.Text, *selector) {
			if selector.SpanKind == address.SpanKindText && selector.CharEnd > utf8.RuneCount(fragment.Text) {
				if _, available := handler.evidenceWholeObjectCapability(); available {
					handler.workspaceToolReadWholeObject(writer, request, access, requestID, workspaceID, fragmentID, selector, refVersionID, "v1:"+strconv.FormatInt(offset, 10), limit, expectedSpanHash)
					return
				}
			}
			writeEvidenceSpanRefusal(writer, requestID)
			return
		}
	}
	// The stored fragment hash is the hash of the whole retrievable object. A
	// caller that demanded a different hash gets a typed, content-free refusal
	// that carries neither the supplied nor the stored hash and no page text.
	if expectedSpanHash != "" && expectedSpanHash != fragment.EvidenceTextHash {
		writeEvidenceSpanRefusal(writer, requestID)
		return
	}
	canonicalAddress, addressErr := handler.canonicalEvidenceAddress(fragment)
	if addressErr != nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	total := int64(len(fragment.Text))
	if offset > total {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	start := mcpEvidencePageStart(fragment.Text, int(offset))
	if limit == 0 {
		limit = mcpEvidenceReadDefaultLimit
	}
	if limit > mcpEvidenceReadMaxLimit {
		limit = mcpEvidenceReadMaxLimit
	}
	end := mcpEvidencePageEnd(fragment.Text, start, limit)
	page := fragment.Text[start:end]
	hasMore := int64(end) < total
	var nextOffset any
	if hasMore {
		nextOffset = int64(end)
	}
	var neighbors *readNeighborsProjection
	if start == 0 && !hasMore {
		neighbors = handler.readNeighborsProjection(request.Context(), access, workspaceID, fragment)
	}
	projection := map[string]any{
		"fragment_id":       fragment.FragmentID,
		"source_path":       fragment.SourcePath,
		"text":              string(page),
		"text_base64":       base64.StdEncoding.EncodeToString(page),
		"offset":            int64(start),
		"length":            int64(len(page)),
		"next_offset":       nextOffset,
		"has_more":          hasMore,
		"limit":             limit,
		"total_length":      total,
		"text_hash":         fragment.EvidenceTextHash,
		"page_hash":         mcpEvidencePageHash(page),
		"address":           mcpEvidenceAddress(fragment),
		"canonical_address": canonicalAddress.String(),
	}
	if neighbors != nil {
		projection["neighbors"] = neighbors
	}
	if pageURL := handler.evidenceSourcePageURL(workspaceID, fragment.FragmentID, canonicalAddress.String()); pageURL != "" {
		projection["source_page_url"] = pageURL
	}
	projection["is_current_version"] = fragment.IsCurrentVersion
	writeJSON(writer, http.StatusOK, projection)
}

// workspaceSourceToolErrorIsDenial reports whether err is the production source
// facade's typed workspacerepository denial (CodeNotFound or CodeDenied) that
// SourceService.ListSources returns for a non-member, unknown or foreign
// workspace. It recognises only those two typed codes: every other error,
// including a plain Go error (whose workspacerepository.CodeOf result is
// CodePersistence) and every registration-typed command error, stays on the
// existing registration mapping and is never reclassified as a denial. The
// workspacerepository denial is content-free, so no source content, no
// confirmation context, no source scope id and no workspace-id echo is ever
// derived from it.
func workspaceSourceToolErrorIsDenial(err error) bool {
	// A registration-typed command error keeps its existing mapping exactly,
	// even if its cause chain happens to carry a repository error.
	if registration.CodeOf(err) != registration.CodePersistence {
		return false
	}
	switch workspacerepository.CodeOf(err) {
	case workspacerepository.CodeDenied, workspacerepository.CodeNotFound:
		return true
	default:
		return false
	}
}

// handleWorkspaceSourceToolError normalizes the injected SourceService error
// surface of the workspace source knowledge tools onto the documented
// content-free denial: the production workspacerepository CodeNotFound/CodeDenied
// becomes the single 404 NOT_FOUND, exactly as serviceErrorResponse already maps
// it for the workspace routes, while every registration-typed error keeps its
// current mapping byte for byte.
func handleWorkspaceSourceToolError(writer http.ResponseWriter, err error, requestID string) {
	if workspaceSourceToolErrorIsDenial(err) {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	handleSourceServiceError(writer, err, requestID, false)
}

// workspaceToolSources is the REST parity of the MCP
// knowvault_sources (compat knowvault_sources_list) source-inventory/schedule knowledge tool (R3a-1
// Outcome 2). It composes the identical injected SourceService.ListSources and
// SourceService.ConfirmationContext reads the MCP tool and the existing
// GET /api/v1/workspaces/{id}/sources route use, and renders the identical
// projection through mcpSourcesListProjection, so a REST client and an MCP
// client observe byte-identical {sources, confirmation_context} JSON and no
// second source read, authorization decision or projection exists.
//
// The request body is not a parameter channel: a non-empty body is refused as
// REQUEST_INVALID rather than silently ignored. No query parameters are
// accepted (the pre-dispatch query hook refuses any unknown key, duplicate,
// empty value or bare "?" before this handler runs). An unauthenticated caller
// is the shared 401. An unknown workspace or a non-member caller collapses to
// the SourceService's single content-free 404 NOT_FOUND with no source content
// and no workspace-id echo. A composition mounted without the source capability
// fails closed as 503 SERVICE_UNAVAILABLE, the REST twin of the MCP -32000.
// Every call records admission before data and its outcome (including denials
// with a class) in the existing audit journal through the SourceService, exactly
// as the MCP tool and the existing REST listSources route do.
func (handler *Handler) workspaceToolSources(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	if code, _ := emptyBody(writer, request); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	if handler.sources == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	statuses, err := handler.sources.ListSources(request.Context(), access, workspaceID)
	if err != nil {
		handleWorkspaceSourceToolError(writer, err, requestID)
		return
	}
	confirmation, err := handler.sources.ConfirmationContext(request.Context(), access, workspaceID)
	if err != nil {
		handleWorkspaceSourceToolError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, mcpSourcesListProjection(statuses, confirmation))
}

// workspaceToolReadWholeObject is the whole-object page mode of the REST
// knowvault_read parity, dispatched when the request carried a cursor. It
// resolves the whole source version through the identical optional
// EvidenceWholeObject capability the MCP core composes (the production
// *evidence.Viewer.ReadObject), so authorization, the ADR-0077 fragment hash
// and the admission/outcome audit journal are the canonical ones and no second
// read path exists. The address keeps its KV-A01c meaning: it must name the same
// source/object/version as the anchor fragment and its span digest must verify
// against the anchor fragment's canonical text (or against the reassembled whole
// text, for the address this mode itself emits). The whole text is paged with
// address.Read, so every page carries offset, total_bytes, has_more, next_cursor
// and the shared canonical whole_hash. A malformed or past-end cursor is refused
// with the typed, content-free 400 REQUEST_INVALID; a tampered address is the
// typed, content-free 409 EVIDENCE_SPAN_HASH_MISMATCH; a denied or foreign
// workspace is the viewer's single 404 NOT_FOUND with no content.
func (handler *Handler) workspaceToolReadWholeObject(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, fragmentID string, selector *address.Address, refVersionID, cursor string, limit int64, expectedSpanHash string) {
	_, ok := handler.evidenceWholeObjectCapability()
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	object, err := handler.readEvidenceObjectSelection(request.Context(), access, workspaceID, fragmentID, selector, refVersionID)
	if err != nil || object.Fragment.FragmentID == "" {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	if selector != nil {
		if selector.Source != object.Fragment.SourceObjectID || selector.Object != object.Fragment.FragmentID || !mcpReadAddressVersionMatches(*selector, object.Fragment.SourceVersionID, refVersionID) {
			writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
			return
		}
		if !handler.verifyAddressSpan(object.Fragment.Text, *selector) && !handler.verifyAddressSpan(object.Text, *selector) {
			writeEvidenceSpanRefusal(writer, requestID)
			return
		}
	}
	if expectedSpanHash != "" && expectedSpanHash != object.Fragment.EvidenceTextHash {
		writeEvidenceSpanRefusal(writer, requestID)
		return
	}
	if limit == 0 {
		limit = mcpEvidenceReadDefaultLimit
	}
	if limit > mcpEvidenceReadMaxLimit {
		limit = mcpEvidenceReadMaxLimit
	}
	page, err := address.Read(object.Text, cursor, int(limit))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	canonicalAddress, addressErr := handler.canonicalEvidenceWholeAddress(object)
	if addressErr != nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	fragments, fragmentErr := handler.readPageFragments(workspaceID, object, page)
	if fragmentErr != nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	var nextCursor any
	if page.HasMore {
		nextCursor = page.NextCursor
	}
	projection := map[string]any{
		"fragment_id":         object.Fragment.FragmentID,
		"source_path":         object.Fragment.SourcePath,
		"text":                string(page.Data),
		"text_base64":         base64.StdEncoding.EncodeToString(page.Data),
		"offset":              int64(page.Offset),
		"length":              int64(len(page.Data)),
		"next_cursor":         nextCursor,
		"has_more":            page.HasMore,
		"complete":            page.Complete,
		"limit":               limit,
		"total_bytes":         int64(page.TotalBytes),
		"whole_hash":          page.WholeHash,
		"text_representation": object.TextRepresentation(),
		"page_hash":           mcpEvidencePageHash(page.Data),
		"address":             mcpEvidenceAddress(object.Fragment),
		"canonical_address":   canonicalAddress.String(),
		"fragment_count":      object.FragmentCount,
		"fragments":           fragments,
		"ordinal_start":       object.FirstOrdinal,
		"ordinal_end":         object.LastOrdinal,
		"is_current_version":  object.Fragment.IsCurrentVersion,
	}
	if pageURL := handler.evidenceFragmentPageURL(workspaceID, object.Fragment); pageURL != "" {
		projection["source_page_url"] = pageURL
	}
	writeJSON(writer, http.StatusOK, projection)
}

// Page bounds for knowvault_refresh. The tool resolves the refreshable sources
// of one workspace, so the resolved source list is paginated with an explicit
// window: a caller that omits limit gets one default page and a next_offset
// while more remains, and a caller that asks for more than the maximum is
// served the maximum page and told so through limit/has_more/next_offset rather
// than silently truncated.
const (
	mcpRefreshDefaultLimit = 100
	mcpRefreshMaxLimit     = 1000
)

// workspaceRefreshedSource is one source that allowed refresh and whose refresh
// command was accepted by the authorized SourceService. It carries the durable
// refresh job id and no source content.
type workspaceRefreshedSource struct {
	SourceScopeID string
	JobID         string
}

// workspaceSkippedSource is one workspace source that does not allow a refresh
// right now, with the closed content-free reason code. A skipped source is not
// a failure: the tool reports it so the caller learns which sources were left
// alone and why.
type workspaceSkippedSource struct {
	SourceScopeID string
	Reason        string
}

// workspaceRefreshPage is the single result the MCP knowvault_refresh tool and
// its REST twin project: the page window plus, per source on the page, either a
// refreshed job or a skip reason.
type workspaceRefreshPage struct {
	Refreshed []workspaceRefreshedSource
	Skipped   []workspaceSkippedSource
	Offset    int64
	Limit     int64
	HasMore   bool
}

// workspaceSourceSkipReason is the closed content-free reason a bound source
// does not allow refresh. It mirrors the registration.Sync gate: only an
// enabled, READY, trust-verified and confirmed source may be refreshed, so the
// tool never submits a source the service would refuse.
func workspaceSourceSkipReason(status workspacerepository.SourceStatus) string {
	switch {
	case !status.Enabled:
		return "DISABLED"
	case status.ActivationStatus != "READY":
		return "NOT_READY"
	case !status.TrustVerified:
		return "TRUST_UNVERIFIED"
	case !status.Confirmed:
		return "NOT_CONFIRMED"
	default:
		return ""
	}
}

// workspaceRefreshIdempotencyKey derives the durable refresh-job idempotency
// key of one source. A caller-supplied HTTP Idempotency-Key is honoured when it
// is present (the caller then owns retry convergence exactly as on the
// administrative :sync route); when it is absent the key is derived from the
// authenticated request and the scope. The MCP tool and the REST route are a
// workspace knowledge surface, so a missing Idempotency-Key must not turn a
// refresh into a REQUEST_INVALID. The value is unique per (request, scope),
// stays well inside the service's 256-byte bound and carries no content.
func workspaceRefreshIdempotencyKey(request *http.Request, access database.AccessContext, sourceScopeID string, sources int) string {
	base := ""
	if request != nil {
		if key, ok := exactHeader(request.Header, "Idempotency-Key"); ok && key != "" && len(key) <= 128 {
			base = key
		}
	}
	if base == "" {
		requestID := access.RequestID
		if requestID == "" {
			requestID = "refresh"
		}
		base = "refresh:" + requestID
	}
	if sources > 1 {
		base = base + ":" + sourceScopeID
	}
	if len(base) > 256 {
		base = base[:256]
	}
	return base
}

// workspaceToolRefreshPage is the single authorized refresh core both the MCP
// knowvault_refresh tool and its REST parity route dispatch through. It reads
// the workspace's bound sources through the same injected
// SourceService.ListSources the REST listSources route and the MCP
// knowvault_sources tool compose (so an unknown, foreign or non-member
// workspace is the source service's single content-free denial before any
// refresh command), narrows to an explicitly named source_scope_id, applies the
// canonical default/maximum page bounds and submits the eligible sources to the
// same authorized SourceService.Sync command the REST syncSource route and the
// MCP knowvault_source_sync tool reach. available is false only when
// composition mounted no source capability, so each transport can emit its own
// content-free service-unavailable refusal; otherwise err is the source
// service's typed error and every source refresh/job id stays inside the
// existing service authorization and audit boundary.
func (handler *Handler) workspaceToolRefreshPage(request *http.Request, access database.AccessContext, workspaceID, sourceScopeID string, offset, limit int64) (workspaceRefreshPage, bool, error) {
	if handler.sources == nil {
		return workspaceRefreshPage{}, false, nil
	}
	statuses, err := handler.sources.ListSources(request.Context(), access, workspaceID)
	if err != nil {
		return workspaceRefreshPage{}, true, err
	}
	if sourceScopeID != "" {
		narrowed := make([]workspacerepository.SourceStatus, 0, 1)
		for _, status := range statuses {
			if status.SourceScopeID == sourceScopeID {
				narrowed = append(narrowed, status)
			}
		}
		if len(narrowed) == 0 {
			if len(statuses) > 0 {
				// The named scope is not bound to this workspace: the same
				// content-free not-found a denied workspace produces, with no
				// source content and no workspace-id echo.
				return workspaceRefreshPage{}, true, registration.NewRegistrationError(registration.CodeNotFound, nil)
			}
			// The workspace lists no sources at all, so it cannot disambiguate
			// the explicitly named scope. Submit it once to the authorized
			// Sync, which re-authorizes and re-checks readiness, trust and
			// confirmation, instead of inventing a membership answer from an
			// empty inventory.
			statuses = []workspacerepository.SourceStatus{{
				SourceScopeID: sourceScopeID, Enabled: true, ActivationStatus: "READY",
				TrustVerified: true, Confirmed: true,
			}}
		} else {
			statuses = narrowed
		}
	}
	ordered := make([]workspacerepository.SourceStatus, len(statuses))
	copy(ordered, statuses)
	statuses = ordered
	sort.SliceStable(statuses, func(left, right int) bool {
		return statuses[left].SourceScopeID < statuses[right].SourceScopeID
	})
	if limit == 0 {
		limit = mcpRefreshDefaultLimit
	}
	if limit > mcpRefreshMaxLimit {
		limit = mcpRefreshMaxLimit
	}
	total := int64(len(statuses))
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := workspaceRefreshPage{Offset: offset, Limit: limit, HasMore: end < total}
	window := statuses[offset:end]
	for _, status := range window {
		if reason := workspaceSourceSkipReason(status); reason != "" {
			page.Skipped = append(page.Skipped, workspaceSkippedSource{SourceScopeID: status.SourceScopeID, Reason: reason})
			continue
		}
		result, syncErr := handler.sources.Sync(request.Context(), access, registration.SyncRequest{
			IdempotencyKey: workspaceRefreshIdempotencyKey(request, access, status.SourceScopeID, len(window)),
			SourceScopeID:  status.SourceScopeID,
		})
		if syncErr != nil {
			return workspaceRefreshPage{}, true, syncErr
		}
		page.Refreshed = append(page.Refreshed, workspaceRefreshedSource{SourceScopeID: status.SourceScopeID, JobID: result.JobID})
	}
	return page, true, nil
}

// workspaceRefreshProjection renders the one projection the MCP knowvault_refresh
// structuredContent and the REST tools/refresh response body share, so a REST
// client and an MCP client observe byte-identical refresh results. It carries
// only the source scope ids, the durable job ids and the closed skip reasons —
// never source content, a credential or a query.
func workspaceRefreshProjection(page workspaceRefreshPage) map[string]any {
	refreshed := make([]any, 0, len(page.Refreshed))
	for _, item := range page.Refreshed {
		refreshed = append(refreshed, map[string]any{"source_scope_id": item.SourceScopeID, "job_id": item.JobID})
	}
	skipped := make([]any, 0, len(page.Skipped))
	for _, item := range page.Skipped {
		skipped = append(skipped, map[string]any{"source_scope_id": item.SourceScopeID, "reason": item.Reason})
	}
	return map[string]any{
		"refreshed":   refreshed,
		"skipped":     skipped,
		"offset":      page.Offset,
		"limit":       page.Limit,
		"has_more":    page.HasMore,
		"next_offset": workspaceRefreshNextOffset(page),
	}
}

// workspaceRefreshNextOffset computes the one next_offset value both the
// structured projection and the content[].text cursor line report, so the two
// channels can never disagree about where the next page starts. It is the
// literal nil (JSON null / text "null") on the final page.
func workspaceRefreshNextOffset(page workspaceRefreshPage) any {
	if !page.HasMore {
		return nil
	}
	return page.Offset + int64(len(page.Refreshed)+len(page.Skipped))
}

// workspaceRefreshText is the content[].text channel of knowvault_refresh. It
// renders the same page the structuredContent projection carries so a client (or
// a model) that reads only `content` sees every refreshed source with its
// source_scope_id and job_id, every skipped source with its source_scope_id and
// closed reason, and the page cursor (offset, effective limit, has_more and
// next_offset, the literal null on the final page). It is compact: a leading
// count line, exactly one single-line entry per source (multi-line values are
// flattened) and a trailing cursor line, never a copy of the structured JSON
// envelope. The rendering is only reached once the authorized page was read, so
// a denial stays content-free.
func workspaceRefreshText(page workspaceRefreshPage) string {
	var builder strings.Builder
	builder.WriteString("knowvault_refresh: ")
	builder.WriteString(strconv.Itoa(len(page.Refreshed)))
	builder.WriteString(" source(s) refreshed, ")
	builder.WriteString(strconv.Itoa(len(page.Skipped)))
	builder.WriteString(" skipped\n")
	for index, item := range page.Refreshed {
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(index + 1))
		builder.WriteString("] source_scope_id=")
		builder.WriteString(mcpContentSingleLine(item.SourceScopeID))
		builder.WriteString(" job_id=")
		builder.WriteString(mcpContentSingleLine(item.JobID))
		builder.WriteString("\n")
	}
	for index, item := range page.Skipped {
		builder.WriteString("[")
		builder.WriteString(strconv.Itoa(len(page.Refreshed) + index + 1))
		builder.WriteString("] source_scope_id=")
		builder.WriteString(mcpContentSingleLine(item.SourceScopeID))
		builder.WriteString(" reason=")
		builder.WriteString(mcpContentSingleLine(item.Reason))
		builder.WriteString("\n")
	}
	builder.WriteString("offset=")
	builder.WriteString(strconv.FormatInt(page.Offset, 10))
	builder.WriteString(" limit=")
	builder.WriteString(strconv.FormatInt(page.Limit, 10))
	builder.WriteString(" has_more=")
	builder.WriteString(strconv.FormatBool(page.HasMore))
	builder.WriteString(" next_offset=")
	builder.WriteString(mcpContentCursor(workspaceRefreshNextOffset(page)))
	builder.WriteString("\n")
	return builder.String()
}

// workspaceToolRefresh is the REST parity of the MCP knowvault_refresh
// workspace knowledge tool (R3a-1 Outcome 2). It delegates to the identical
// workspaceToolRefreshPage core the MCP tool composes and renders the identical
// projection through workspaceRefreshProjection, so the REST GET/POST
// /api/v1/workspaces/{workspace_id}/tools/refresh response body is byte-for-byte
// the MCP structuredContent. Authorization, admission-before-data and the R1
// audit outcome (including denials with a class) stay in the injected
// SourceService. The request body is not a parameter channel: a non-empty body
// is refused as REQUEST_INVALID before the service is touched. An unauthenticated
// caller is the shared 401; an unknown workspace or a non-member caller is the
// source service's content-free NOT_FOUND with no source content and no
// workspace-id echo; a composition mounted without the source capability fails
// closed as 503 SERVICE_UNAVAILABLE (the REST twin of the MCP -32000).
func (handler *Handler) workspaceToolRefresh(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, sourceScopeID string, offset, limit int64) {
	if code, _ := emptyBody(writer, request); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	page, available, err := handler.workspaceToolRefreshPage(request, access, workspaceID, sourceScopeID, offset, limit)
	if !available {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err != nil {
		handleWorkspaceSourceToolError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, workspaceRefreshProjection(page))
}
