package proposer

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// VersionMinter is the seam Store.Accept uses to make accepting a proposal
// atomic with minting a new workspace model context version (ADR-0098
// decision 4; S2-MODEL-CONTEXT-DESIGN.md: "Accept ... creates a new version
// atomically"). It is deliberately not one of workspacecontext's A0
// interfaces: Reader has no write path, and minting a version is card A's
// store (workspacecontext/store.go, migration 000112), which this package
// does not import and which does not exist yet in this worktree. The lead
// supplies the concrete adapter, wrapping card A's store, when wiring this
// package into composition/runtime.go.
//
// An implementation MUST, inside exactly one internal/platform/database.
// Store.Write transaction: validate ifMatchHash against workspaceID's
// current pointer (412/CodeIfMatchStale-equivalent on mismatch), insert the
// new immutable version row (document = the already-edited, caller-supplied
// Document; change_kind = PROPOSAL_ACCEPTED; proposal_id = proposalID),
// advance the current-version pointer, then call decideProposal with that
// same transaction and the version number it just minted. The whole
// transaction commits only if decideProposal also returns nil:
// decideProposal performs its own compare-and-swap (workspace_context_
// proposal PROPOSED -> ACCEPTED) and returns an error when a concurrent
// request already decided the proposal first, which must roll back the
// version insert with it — a proposal is never marked ACCEPTED without a
// matching version, and a version is never minted for a proposal that was
// not actually still PROPOSED at commit time.
type VersionMinter interface {
	MintAcceptedVersion(
		ctx context.Context,
		access workspacecontext.Access,
		workspaceID, ifMatchHash string,
		document workspacecontext.Document,
		proposalID string,
		decideProposal func(ctx context.Context, tx database.Transaction, mintedVersion int64) error,
	) (workspacecontext.Version, error)
}

// RunExcerptReader resolves a proposal's evidence question_run_ids to a
// short, viewer-authorized excerpt, exactly as S2-MODEL-CONTEXT-DESIGN.md's
// "Examples are resolved live through question.Service.GetBatch" and
// S2-CONTRACT.md's "examples lists only runs the viewer can read now"
// require. It is deliberately not internal/question.Service itself: this
// package must not import card B's package (S2-MODEL-CONTEXT-DESIGN.md
// "Cards" lists internal/question as card B's alone). The lead supplies an
// adapter over question.Service.GetBatch in composition/runtime.go.
type RunExcerptReader interface {
	// GetBatch returns one RunExcerpt per id in runIDs that access is
	// currently authorized to read; an id access cannot read (or that no
	// longer exists) is simply omitted, never an error, so the caller
	// (Store.ListPage/GetWithExamples) computes HiddenExamples as the
	// remainder. QuestionExcerpt may be longer than 300 characters — the
	// caller clips it; a single layer's bound is never trusted alone.
	GetBatch(ctx context.Context, access workspacecontext.Access, runIDs []string) ([]RunExcerpt, error)
}

// RunExcerpt is one question run's viewer-authorized excerpt, as
// RunExcerptReader.GetBatch resolves it.
type RunExcerpt struct {
	QuestionRunID   string
	ConversationID  string
	QuestionExcerpt string
}

// maxExcerptRunes is S2-CONTRACT.md's "question_excerpt is at most 300
// characters" (this package treats "characters" as runes, matching
// workspacecontext's own maxSuggestedTextChars/maxTermChars convention).
const maxExcerptRunes = 300

// ListedProposal is one workspace_context_proposal row as the REST and
// tool-parity proposals list actually needs it (S2-CONTRACT.md
// "Proposals"): the A0 Proposal shape plus Examples resolved live through a
// RunExcerptReader (only for runs the current viewer can read now) and
// HiddenExamples counting the rest. workspacecontext.Proposal (A0, frozen)
// has no Examples field, so this type — and the ListPage/GetWithExamples
// methods that return it — are this package's own addition beyond
// ProposalService; the lead's REST/tool-parity handlers should call these,
// not the bare ProposalService.List/Get, wherever S2-CONTRACT.md's
// `examples`/`hidden_examples` fields are needed.
type ListedProposal struct {
	workspacecontext.Proposal
	Examples       []Example
	HiddenExamples int
}

// Example is one resolved, viewer-authorized evidence example.
type Example struct {
	ConversationID  string
	QuestionExcerpt string
}
