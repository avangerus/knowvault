package workspacecontext

import "time"

// ProposalKind is the closed set of deterministic heuristics the proposer
// (`heuristic-v1`, card E) may derive a PROPOSED glossary change from, per
// S2-MODEL-CONTEXT-DESIGN.md "Proposer".
type ProposalKind string

const (
	// ProposalKindNewTerm: an unknown non-stop-list token queued after at
	// least two distinct runs.
	ProposalKindNewTerm ProposalKind = "NEW_TERM"
	// ProposalKindSynonym: an unknown abbreviation or quoted phrase in the
	// question, while the model's search arguments in the same run contain a
	// known glossary term but not it.
	ProposalKindSynonym ProposalKind = "SYNONYM"
	// ProposalKindDefinitionCorrection: a follow-up turn starting with a
	// correction marker.
	ProposalKindDefinitionCorrection ProposalKind = "DEFINITION_CORRECTION"
)

// Valid reports whether kind is one of the three closed values.
func (kind ProposalKind) Valid() bool {
	switch kind {
	case ProposalKindNewTerm, ProposalKindSynonym, ProposalKindDefinitionCorrection:
		return true
	default:
		return false
	}
}

// ProposalStatus is the closed lifecycle of one workspace_context_proposal
// row.
type ProposalStatus string

const (
	ProposalStatusProposed  ProposalStatus = "PROPOSED"
	ProposalStatusAccepted  ProposalStatus = "ACCEPTED"
	ProposalStatusRejected  ProposalStatus = "REJECTED"
	ProposalStatusWithdrawn ProposalStatus = "WITHDRAWN"
)

// Valid reports whether status is one of the four closed values.
func (status ProposalStatus) Valid() bool {
	switch status {
	case ProposalStatusProposed, ProposalStatusAccepted, ProposalStatusRejected, ProposalStatusWithdrawn:
		return true
	default:
		return false
	}
}

// maxSuggestedTextChars is S2-MODEL-CONTEXT-DESIGN.md's suggested_text bound.
const maxSuggestedTextChars = 300

// proposalPrefix is the internal/source/ids.New prefix card E's proposer
// mints a workspace_context_proposal id with.
const proposalPrefix = "ctxprop"

// Proposal is one workspace_context_proposal row (migration 000113, card E):
// a system-derived, PROPOSED glossary change that takes effect only after an
// explicit, audited OWNER/MANAGER decision (ADR-0098 decision 4). Its text
// (CandidateTerm, SuggestedText) is erased once WITHDRAWN for lack of
// evidence, per the design; a zero DecidedAt/DecidedBy/DecidedVersion means
// no decision has been made yet.
type Proposal struct {
	ID              string
	WorkspaceID     string
	Kind            ProposalKind
	CandidateTerm   string
	TargetTermID    string
	SuggestedText   string
	Status          ProposalStatus
	Occurrences     int
	DetectorVersion string
	CreatedAt       time.Time
	DecidedBy       string
	DecidedAt       time.Time
	DecidedVersion  int64
}

// Valid performs the same bounds/format checks a persisted proposal row must
// already satisfy: a server-assigned id, a closed Kind and Status, and
// CandidateTerm/SuggestedText within their bounds. It does not check
// TargetTermID against a live glossary — that is the store's job, in the
// same transaction that reads the current document.
func (proposal Proposal) Valid() bool {
	if !validAssignedID(proposalPrefix, proposal.ID) || !proposal.Kind.Valid() || !proposal.Status.Valid() {
		return false
	}
	if proposal.TargetTermID != "" && !validAssignedID(termPrefix, proposal.TargetTermID) {
		return false
	}
	if !validText(proposal.CandidateTerm, 0, maxTermChars) {
		return false
	}
	return validText(proposal.SuggestedText, 0, maxSuggestedTextChars)
}

// ProposalEdits carries the optional override POST
// .../proposals/{pid}:accept may apply before minting the new version, per
// S2-MODEL-CONTEXT-DESIGN.md's "Изменить и принять" ("edit and accept") UI
// action. An empty SuggestedText keeps the proposal's own suggested text.
type ProposalEdits struct {
	SuggestedText string
}
