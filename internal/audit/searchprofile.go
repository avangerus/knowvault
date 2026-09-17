package audit

// The EMB-1 search profile revision audit contract. Moving a tenant onto a new
// retrieval vector space changes what every later answer is retrieved from, so
// the operator command that requests it appends exactly one
// search.profile_revision_requested event.
//
// The event is content-free by construction: the only identity it carries is
// the immutable embedding profile hash of the deployment-mounted channel the
// tenant is being moved onto (SRCH-011 already makes that hash cover code,
// analyzers, model artifacts, limits and budgets), never a model artifact,
// corpus text, chunk or row. The re-index and cutover themselves stay
// observable through public.job / job_attempt, which is where partial progress
// belongs; the audit journal records the human decision, not the machine work.

// ActionSearchProfileRevisionRequested is the operator command that moves a
// tenant onto another vector space.
const ActionSearchProfileRevisionRequested Action = "search.profile_revision_requested"

// The per-call retrieval profile of the S3 ablation channel. A measurement run
// switches the vector channel off to prove it contributes something, and a
// journal that did not record which algorithm answered a question could not
// tell a weak answer from a deliberately weakened one afterwards. The action
// itself names the profile, so the journal answers "under which retrieval
// profile did this call run" without carrying any free-form metadata: the
// vocabulary is closed at three values and can never become a bag of strings.
//
// The choice never arrives from a model. It is an operator channel, and a
// principal who is not an owner of the workspace has the header ignored and
// the attempt journalled as DENIED — which is the only way "the model does not
// pick the algorithm" is observable after the fact rather than merely intended.
const (
	ActionSearchProfileCallLexical Action = "search.profile_call_lexical"
	ActionSearchProfileCallVector  Action = "search.profile_call_vector"
	ActionSearchProfileCallHybrid  Action = "search.profile_call_hybrid"
)

// ResourceSearchProfile is the one resource type this vocabulary reserves.
// resource_id is exactly the requested embedding profile hash, so repeated
// requests for the same vector space share one provenance anchor.
const ResourceSearchProfile ResourceType = "SEARCH_PROFILE"

// isSearchProfileAction reports whether the action belongs to this contract.
// The action/resource pair is one-to-one: neither may appear without the other.
func isSearchProfileAction(action Action) bool {
	return action == ActionSearchProfileRevisionRequested || isSearchProfileCallAction(action)
}

// isSearchProfileCallAction reports whether the action records the retrieval
// profile one call ran under, as opposed to the operator command that changes
// the tenant's vector space.
func isSearchProfileCallAction(action Action) bool {
	return action == ActionSearchProfileCallLexical || action == ActionSearchProfileCallVector ||
		action == ActionSearchProfileCallHybrid
}

// validSearchProfileProjection is the Go half of the contract: the pairing is
// closed, the event names the workspace the operator issued the command from
// and a human actor, resource_id is the requested profile hash, and no other
// vocabulary's metadata may ride along.
func validSearchProfileProjection(input EventInput) bool {
	known := isSearchProfileAction(input.Action)
	if known != (input.ResourceType == ResourceSearchProfile) {
		return false
	}
	if !known {
		return true
	}
	if input.WorkspaceID == nil || !validHash(input.ResourceID) {
		return false
	}
	// The revision command is a human decision. A per-call profile selection is
	// journalled for whoever presented the channel — including a service
	// principal whose attempt is being refused, because "an agent tried to pick
	// the retrieval algorithm" is exactly the event worth keeping.
	if isSearchProfileCallAction(input.Action) {
		if input.ActorType != ActorHuman && input.ActorType != ActorService {
			return false
		}
	} else if input.ActorType != ActorHuman {
		return false
	}
	if len(input.ReferencedEvidenceIDs) != 0 || input.PolicyDecisionID != nil {
		return false
	}
	// The decision is fully described by the action, the workspace it was
	// issued from and the requested profile hash. No other vocabulary may ride
	// along, so this event can never become a bag of metadata.
	return searchProfileMetadataEmpty(input.Metadata)
}

func searchProfileMetadataEmpty(metadata Metadata) bool {
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
