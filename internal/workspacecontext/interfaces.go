package workspacecontext

import "context"

// Access is the minimal caller identity Reader, RunObserver and
// ProposalService need: the same three values every request-derived
// database.AccessContext already carries. This package stays free of
// internal/platform/database (no DB, no HTTP — see the package doc) by
// taking its own copy of the fields instead of importing that type; a caller
// builds one from its own access context with a one-line conversion
// (Access{OrganizationID: access.OrganizationID, PrincipalID: ...}).
type Access struct {
	OrganizationID string
	PrincipalID    string
	RequestID      string
}

// Version is one immutable, server-assigned revision of a workspace's model
// context (workspace_model_context_version, migration 000112) as the store
// persists it and REST/chat/MCP read it: `{version, content_hash, document,
// editable}` in the REST GET response shape. Editable mirrors the caller's
// own OWNER/MANAGER standing, resolved by the reader, not by this package.
type Version struct {
	Number      int64
	ContentHash string
	Document    Document
	Editable    bool
}

// SourceNotes is one enabled source's description and table/column notes as
// rendered into the context, plus the context version they were read from.
// S3's knowvault_source_schema tool returns these fields
// (source.description, tables[].note, columns[].note, context_version)
// through Reader.SourceNotes.
type SourceNotes struct {
	ContextVersion int64
	Source         Source
}

// Reader is the read surface the store (card A) implements and chat
// (question/tool_loop.go, card B) and MCP (workspacetools, card C) call.
// Current returns the workspace's pinned current version; per the design
// ("The context version is pinned once per run") a caller reads it once per
// run or turn and renders that same Version throughout. SourceNotes serves
// the narrower S3 read of a single enabled source's own notes.
type Reader interface {
	Current(ctx context.Context, access Access, workspaceID string) (Version, error)
	SourceNotes(ctx context.Context, access Access, workspaceID, sourceConnectionID string) (SourceNotes, error)
}

// RunEvent is the minimal, already-persisted-run projection the proposer's
// deterministic heuristics (S2-MODEL-CONTEXT-DESIGN.md "Proposer") need:
// enough to detect an unknown token that co-occurs with a matched glossary
// term (SYNONYM), a correction marker at the start of a turn
// (DEFINITION_CORRECTION), or a repeated unknown token (NEW_TERM), without
// re-deriving anything the run already computed once. It carries no
// document/evidence text beyond the question itself and the tool arguments
// the run already sent to a search tool.
type RunEvent struct {
	OrganizationID     string
	WorkspaceID        string
	ConversationID     string
	TurnID             string
	QuestionRunID      string
	ContextVersion     int64
	QuestionText       string
	MatchedTerms       []TermMatch
	SearchArgumentText string
}

// RunObserver receives one notice per completed, already-persisted question
// run. Per the design, "the proposer runs after a completed run has been
// persisted" and "errors only reach a metric": an implementation (the
// proposer, card E) must not block, retry into, or fail the run it reports
// on, and a caller (card B) must not let a slow or failing observer affect
// the answer it just returned to the user.
type RunObserver interface {
	ObserveRun(ctx context.Context, event RunEvent) error
}

// ProposalService is the list/decide surface the REST and tool-parity
// proposal endpoints call (`GET .../proposals`, `GET .../proposals/{pid}`,
// `POST .../proposals/{pid}:accept|:reject`). The store (card A), backed by
// the proposer's migration 000113 rows (card E), implements it; this
// package only fixes its shape. Accept is atomic with minting the new
// Version, per ADR-0098 decision 4 ("a proposal takes effect only after an
// explicit, audited decision").
type ProposalService interface {
	List(ctx context.Context, access Access, workspaceID string, status ProposalStatus) ([]Proposal, error)
	Get(ctx context.Context, access Access, workspaceID, proposalID string) (Proposal, error)
	Accept(ctx context.Context, access Access, workspaceID, proposalID, ifMatchHash string, edits ProposalEdits) (Version, error)
	Reject(ctx context.Context, access Access, workspaceID, proposalID string) (Proposal, error)
}
