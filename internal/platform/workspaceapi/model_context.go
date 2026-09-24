package workspaceapi

// S2 card A: the REST transport for the workspace model context (ADR-0098,
// S2-CONTRACT.md, S2-MODEL-CONTEXT-DESIGN.md). This file holds no persistence
// or validation logic of its own: it decodes/encodes the wire shape,
// converts between database.AccessContext and workspacecontext.Access, and
// forwards every request to the injected capabilities
// (internal/workspacecontext.Store for the document, workspacecontext.ProposalService
// for proposals -- card E's implementation). Both capabilities are optional:
// a nil value keeps every route content-free SERVICE_UNAVAILABLE, exactly
// like every other capability-gated surface in this file.
//
// Deviations from S2-CONTRACT.md, and why they are unavoidable given the
// frozen internal/workspacecontext (card A0) shapes this file builds on:
//
//  1. "400 REQUEST_INVALID with field paths when validation fails": A0's
//     Validate returns only a flat, content-free ErrorCode
//     (WORKSPACE_CONTEXT_DOCUMENT_INVALID / WORKSPACE_CONTEXT_LOCATION_UNKNOWN),
//     never a field path. This transport returns REQUEST_INVALID with an
//     empty fields list rather than fabricate a path Validate never computed.
//  2. The proposal accept body's three independent overrides ({"term",
//     "synonyms", "definition"}) are decoded here in full (so the wire shape
//     matches the contract), but workspacecontext.ProposalEdits (A0, frozen)
//     carries only one SuggestedText field. definition, if present, maps to
//     SuggestedText; otherwise term does; synonyms has no destination and is
//     accepted but not forwarded. See modelContextProposalEdits below.
//  3. "examples"/"hidden_examples" on a listed proposal need conversation
//     content resolved through internal/question.Service.GetBatch
//     (S2-MODEL-CONTEXT-DESIGN.md), which is outside this card's owned
//     packages. Until composition wires a ProposalExampleResolver, every
//     listed proposal reports examples: [] and hidden_examples: 0 -- a safe
//     under-approximation (never over-exposure), not a fabricated answer.

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// ModelContextService is card A's PostgreSQL-backed workspace model context
// capability. internal/workspacecontext.Store satisfies it exactly (its
// Current/CurrentForREST/Save/Versions/VersionAtForREST/Restore methods have
// these identical signatures). Wired by composition only once the store is
// mounted; nil keeps every model-context document route content-free
// SERVICE_UNAVAILABLE.
type ModelContextService interface {
	// Current is the unaudited Reader read, used here only to resolve a
	// listed proposal's target_term display text -- never as the response to
	// a GET route (CurrentForREST is).
	Current(ctx context.Context, access workspacecontext.Access, workspaceID string) (workspacecontext.Version, error)
	CurrentForREST(ctx context.Context, access database.AccessContext, workspaceID string) (workspacecontext.VersionRecord, error)
	Save(ctx context.Context, access database.AccessContext, workspaceID string,
		document workspacecontext.Document, ifMatchHash, idempotencyKey string) (workspacecontext.VersionRecord, error)
	Versions(ctx context.Context, access database.AccessContext, workspaceID string, limit int, cursor int64) ([]workspacecontext.VersionSummary, int64, error)
	VersionAtForREST(ctx context.Context, access database.AccessContext, workspaceID string, versionNumber int64) (workspacecontext.VersionRecord, error)
	Restore(ctx context.Context, access database.AccessContext, workspaceID string, targetVersion int64, ifMatchHash, idempotencyKey string) (workspacecontext.VersionRecord, error)
}

// ProposalExampleResolver resolves the example dialogue excerpts
// S2-CONTRACT.md's proposal listing carries: at most 300-character question
// excerpts from runs the current viewer can read now. See the file-level
// deviation note 3; a nil resolver keeps every proposal's examples empty.
type ProposalExampleResolver interface {
	Examples(ctx context.Context, access database.AccessContext, workspaceID, proposalID string, limit int) ([]ModelContextProposalExample, int, error)
}

// ModelContextProposalExample is one resolved example the ProposalExampleResolver
// returns: S2-CONTRACT.md's {"conversation_id", "question_excerpt"}.
type ModelContextProposalExample struct {
	ConversationID  string
	QuestionExcerpt string
}

// EnableModelContext wires the mandatory document capability. A nil service
// leaves every model-context document route SERVICE_UNAVAILABLE.
func (handler *Handler) EnableModelContext(service ModelContextService) {
	if handler == nil || service == nil {
		return
	}
	handler.modelContext = service
}

// EnableModelContextProposals wires card E's ProposalService. A nil service
// leaves every proposal route SERVICE_UNAVAILABLE, per this card's contract
// ("call the workspacecontext.ProposalService interface; if nil, return
// SERVICE_UNAVAILABLE").
func (handler *Handler) EnableModelContextProposals(service workspacecontext.ProposalService) {
	if handler == nil || service == nil {
		return
	}
	handler.modelContextProposals = service
}

// EnableModelContextProposalExamples wires the optional example resolver
// (deviation note 3).
func (handler *Handler) EnableModelContextProposalExamples(resolver ProposalExampleResolver) {
	if handler == nil || resolver == nil {
		return
	}
	handler.modelContextProposalExamples = resolver
}

func contextAccess(access database.AccessContext) workspacecontext.Access {
	return workspacecontext.Access{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID}
}

// --- GET /workspaces/{id}/model-context ---

func (handler *Handler) modelContextGet(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	record, err := handler.modelContext.CurrentForREST(request.Context(), access, workspaceID)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	writeModelContextRecord(writer, http.StatusOK, record)
}

// --- PUT /workspaces/{id}/model-context ---

func (handler *Handler) modelContextSave(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	idempotencyKey, ifMatch, code, fields := modelContextMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body modelContextSaveBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.Document == nil {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"document"})
		return
	}
	document, missing := body.Document.toDocument()
	if len(missing) != 0 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", missing)
		return
	}
	record, err := handler.modelContext.Save(request.Context(), access, workspaceID, document, ifMatch, idempotencyKey)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	writeModelContextRecord(writer, http.StatusOK, record)
}

// --- GET /workspaces/{id}/model-context/versions ---

const (
	modelContextVersionsPageLimitMax = 100
)

func (handler *Handler) modelContextVersionsList(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	limit, cursor, ok := validModelContextVersionsQuery(request.URL)
	if !ok {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", nil)
		return
	}
	summaries, nextCursor, err := handler.modelContext.Versions(request.Context(), access, workspaceID, limit, cursor)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	items := make([]map[string]any, len(summaries))
	for index, summary := range summaries {
		item := map[string]any{
			"version": summary.Version, "content_hash": summary.ContentHash,
			"change_kind": summary.ChangeKind, "created_at": summary.CreatedAt.UTC().Format(time.RFC3339),
			"created_by": summary.CreatedBy,
		}
		if summary.ProposalID != "" {
			item["proposal_id"] = summary.ProposalID
		}
		items[index] = item
	}
	response := map[string]any{"versions": items}
	if nextCursor > 0 {
		response["next_cursor"] = strconv.FormatInt(nextCursor, 10)
	}
	writeJSON(writer, http.StatusOK, response)
}

// --- GET /workspaces/{id}/model-context/versions/{version} ---

func (handler *Handler) modelContextVersionGet(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string, versionNumber int64) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	record, err := handler.modelContext.VersionAtForREST(request.Context(), access, workspaceID, versionNumber)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	writeModelContextRecord(writer, http.StatusOK, record)
}

// --- POST /workspaces/{id}/model-context/versions/{version}:restore ---

func (handler *Handler) modelContextRestore(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string, versionNumber int64) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	idempotencyKey, ifMatch, code, fields := modelContextMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	record, err := handler.modelContext.Restore(request.Context(), access, workspaceID, versionNumber, ifMatch, idempotencyKey)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	writeModelContextRecord(writer, http.StatusOK, record)
}

// --- GET /workspaces/{id}/model-context/proposals ---

func (handler *Handler) modelContextProposalsList(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.modelContextProposals == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	status, limit, cursor, ok := validModelContextProposalsQuery(request.URL)
	if !ok {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", nil)
		return
	}
	proposals, err := handler.modelContextProposals.List(request.Context(), contextAccess(access), workspaceID, status)
	if err != nil {
		writeModelContextProposalError(writer, err, requestID)
		return
	}
	page, nextCursor := paginateProposals(proposals, limit, cursor)
	targetTerms := handler.resolveTargetTerms(request.Context(), access, workspaceID, page)
	items := make([]map[string]any, len(page))
	for index, proposal := range page {
		items[index] = handler.projectProposal(request.Context(), access, workspaceID, proposal, targetTerms)
	}
	response := map[string]any{"proposals": items}
	if nextCursor != "" {
		response["next_cursor"] = nextCursor
	}
	writeJSON(writer, http.StatusOK, response)
}

// --- POST /workspaces/{id}/tools/workspace-context ---

func (handler *Handler) modelContextToolParity(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.modelContext == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body modelContextToolBody
	if code := decodeOptionalJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if len(body.Terms) > 10 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"terms"})
		return
	}
	if !validModelContextToolSection(body.Section) {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"section"})
		return
	}
	record, err := handler.modelContext.CurrentForREST(request.Context(), access, workspaceID)
	if err != nil {
		writeModelContextError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, modelContextToolResponse(record, body.Terms, stringValueOrEmpty(body.Section)))
}

// --- POST /workspaces/{id}/model-context/proposals/{proposal_id}:accept ---

func (handler *Handler) modelContextProposalAccept(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID, proposalID string) {
	if handler.modelContextProposals == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	_, ifMatch, code, fields := modelContextMutationHeaders(request)
	if code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body modelContextProposalAcceptBody
	if code := decodeOptionalJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	version, err := handler.modelContextProposals.Accept(request.Context(), contextAccess(access), workspaceID, proposalID, ifMatch, body.toEdits())
	if err != nil {
		writeModelContextProposalError(writer, err, requestID)
		return
	}
	writeModelContextVersion(writer, http.StatusOK, access, version)
}

// --- POST /workspaces/{id}/model-context/proposals/{proposal_id}:reject ---

func (handler *Handler) modelContextProposalReject(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID, proposalID string) {
	if handler.modelContextProposals == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	proposal, err := handler.modelContextProposals.Reject(request.Context(), contextAccess(access), workspaceID, proposalID)
	if err != nil {
		writeModelContextProposalError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"proposal_id": proposal.ID, "status": string(proposal.Status)})
}

// resolveTargetTerms reads the current document once (unaudited: resolving a
// display name is not itself "reading the context") and returns a
// termID -> term-name lookup for the proposals being projected.
func (handler *Handler) resolveTargetTerms(ctx context.Context, access database.AccessContext, workspaceID string, proposals []workspacecontext.Proposal) map[string]string {
	needsLookup := false
	for _, proposal := range proposals {
		if proposal.TargetTermID != "" {
			needsLookup = true
			break
		}
	}
	if !needsLookup || handler.modelContext == nil {
		return nil
	}
	version, err := handler.modelContext.Current(ctx, contextAccess(access), workspaceID)
	if err != nil {
		return nil
	}
	names := make(map[string]string, len(version.Document.Glossary))
	for _, term := range version.Document.Glossary {
		names[term.ID] = term.Term
	}
	return names
}

func (handler *Handler) projectProposal(ctx context.Context, access database.AccessContext, workspaceID string,
	proposal workspacecontext.Proposal, targetTerms map[string]string) map[string]any {
	item := map[string]any{
		"proposal_id": proposal.ID, "kind": string(proposal.Kind), "candidate_term": proposal.CandidateTerm,
		"target_term_id": proposal.TargetTermID, "target_term": targetTerms[proposal.TargetTermID],
		"suggested_text": proposal.SuggestedText, "status": string(proposal.Status),
		"occurrences": proposal.Occurrences, "created_at": proposal.CreatedAt.UTC().Format(time.RFC3339),
	}
	examples := []map[string]any{}
	hiddenExamples := 0
	if handler.modelContextProposalExamples != nil {
		resolved, hidden, err := handler.modelContextProposalExamples.Examples(ctx, access, workspaceID, proposal.ID, modelContextExampleLimit)
		if err == nil {
			hiddenExamples = hidden
			for _, example := range resolved {
				examples = append(examples, map[string]any{
					"conversation_id": example.ConversationID, "question_excerpt": example.QuestionExcerpt,
				})
			}
		}
	}
	item["examples"] = examples
	item["hidden_examples"] = hiddenExamples
	return item
}

const modelContextExampleLimit = 20

// paginateProposals applies the REST layer's own limit/cursor windowing,
// since workspacecontext.ProposalService.List (A0, frozen) takes neither: it
// returns every PROPOSED (or requested-status) proposal, and this transport
// pages that result itself. Proposals are ordered newest-first by their
// server-assigned id (a typed ULID, lexicographically time-ordered), so the
// order is stable across calls without re-sorting by a mutable field.
func paginateProposals(proposals []workspacecontext.Proposal, limit int, cursor string) ([]workspacecontext.Proposal, string) {
	sorted := make([]workspacecontext.Proposal, len(proposals))
	copy(sorted, proposals)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].ID > sorted[j-1].ID; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	start := 0
	if cursor != "" {
		for index, proposal := range sorted {
			if proposal.ID == cursor {
				start = index + 1
				break
			}
		}
	}
	if start >= len(sorted) {
		return []workspacecontext.Proposal{}, ""
	}
	end := start + limit
	if end >= len(sorted) {
		return sorted[start:], ""
	}
	return sorted[start:end], sorted[end-1].ID
}
