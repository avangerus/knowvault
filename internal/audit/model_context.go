package audit

// The S2 workspace model context audit contract (ADR-0098,
// S2-MODEL-CONTEXT-DESIGN.md, S2-CONTRACT.md "Audit actions"). A workspace's
// explicit description, answer rules, glossary and source notes is visible
// configuration, not hidden model memory, and every revision or read of it is
// journalled without ever carrying the document's own text.
//
// The four actions are exactly the contract's closed vocabulary:
//   - workspace.model_context_revised: an OWNER/MANAGER wrote a new version
//     (a direct edit or a restore). resource_id is the workspace itself
//     (ResourceWorkspaceModelContext has exactly one row per workspace, so the
//     workspace id is already the document's own identity).
//   - workspace.model_context_read: a caller (human, REST, MCP or the tool
//     -parity surface) read the current or an historical version's content.
//   - workspace.context_proposal_created: the deterministic proposer (card E,
//     ActorSystem) derived a PROPOSED glossary change from a completed
//     question run.
//   - workspace.context_proposal_decided: an OWNER/MANAGER accepted or
//     rejected a proposal. resource_id is the proposal's own id
//     (ResourceWorkspaceContextProposal). Accepting also mints a new context
//     version (recorded structurally by the version row's own change_kind and
//     proposal_id columns), so acceptance is journalled once, as a decision,
//     not twice.
//
// No event in this vocabulary ever carries a Metadata field: the action name,
// the outcome and the named resource are the whole content-free story, mirroring
// search.profile_revision_requested (searchprofile.go).

const (
	ActionWorkspaceModelContextRevised    Action = "workspace.model_context_revised"
	ActionWorkspaceModelContextRead       Action = "workspace.model_context_read"
	ActionWorkspaceContextProposalCreated Action = "workspace.context_proposal_created"
	ActionWorkspaceContextProposalDecided Action = "workspace.context_proposal_decided"
)

// ResourceWorkspaceModelContext and ResourceWorkspaceContextProposal are the
// two resource types this vocabulary reserves (S2-CONTRACT.md).
const (
	ResourceWorkspaceModelContext    ResourceType = "WORKSPACE_MODEL_CONTEXT"
	ResourceWorkspaceContextProposal ResourceType = "WORKSPACE_CONTEXT_PROPOSAL"
)

// isModelContextDocumentAction reports whether action operates on the
// context document itself (revise/read), as opposed to a proposal decision.
func isModelContextDocumentAction(action Action) bool {
	return action == ActionWorkspaceModelContextRevised || action == ActionWorkspaceModelContextRead
}

// isModelContextProposalAction reports whether action belongs to the
// proposal lifecycle.
func isModelContextProposalAction(action Action) bool {
	return action == ActionWorkspaceContextProposalCreated || action == ActionWorkspaceContextProposalDecided
}

func isModelContextAction(action Action) bool {
	return isModelContextDocumentAction(action) || isModelContextProposalAction(action)
}

// validModelContextProjection is the Go half of the contract: the
// action/resource-type pairing is closed and one-to-one, every event names
// the workspace the command or read targeted, the actor is always a real
// principal (a human for a revision or decision, ActorSystem only for the
// proposer's own creation event, and any actor kind for a read, since a
// SERVICE credential or MCP client reads context too), and no vocabulary from
// any other feature rides along.
func validModelContextProjection(input EventInput) bool {
	known := isModelContextAction(input.Action)
	wantResource := ResourceWorkspaceModelContext
	if isModelContextProposalAction(input.Action) {
		wantResource = ResourceWorkspaceContextProposal
	}
	if known != (input.ResourceType == wantResource) {
		return false
	}
	if !known {
		return true
	}
	if input.WorkspaceID == nil {
		return false
	}
	if input.Action == ActionWorkspaceContextProposalCreated {
		if input.ActorType != ActorSystem {
			return false
		}
	} else if input.ActorType != ActorHuman && input.ActorType != ActorService {
		return false
	}
	if len(input.ReferencedEvidenceIDs) != 0 || input.PolicyDecisionID != nil {
		return false
	}
	return modelContextMetadataEmpty(input.Metadata)
}

// modelContextMetadataEmpty admits no metadata at all: the action, the
// outcome and the named workspace/resource are the entire content-free story.
func modelContextMetadataEmpty(metadata Metadata) bool {
	return metadata.WorkspaceRevision == nil && metadata.WorkspaceSourceID == nil &&
		metadata.SourceScopeID == nil && metadata.SourceScopeRevision == nil &&
		metadata.ScopeConfigHash == nil && metadata.AccessMode == nil && metadata.Enabled == nil &&
		metadata.SourceConnectionID == nil && metadata.ConnectorJobID == nil &&
		metadata.SyncRunID == nil && metadata.QuestionRunID == nil && metadata.ModelRunID == nil &&
		metadata.CitationNumber == nil && metadata.ManifestHash == nil && metadata.PolicyRevision == nil &&
		len(metadata.ReasonCodes) == 0 && metadata.RemoteAddressDigest == nil &&
		metadata.UserAgentFamily == nil && !hasAuthorityMetadata(metadata) &&
		!hasRotationMetadata(metadata) && !hasAnswerMetadata(metadata) &&
		!hasTrustVerificationMetadata(metadata) && !hasGovernedQueryMetadata(metadata)
}
