package searchprofile

// This file owns the S3 §7.5 per-call retrieval profile: the operator channel
// that selects lexical, vector or hybrid for one search so the vector layer's
// contribution can be measured rather than asserted.
//
// It is deliberately NOT a tool parameter. A model that chooses the retrieval
// algorithm has made the algorithm part of its answer, and an ablation whose
// result the model could have influenced measures nothing. So the choice
// arrives on a transport channel, is honoured only for an OWNER of the
// workspace it is issued against, and is journalled either way — a refused
// attempt is exactly the event worth keeping.

import (
	"context"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// CallProfile is the closed retrieval-profile vocabulary of one call.
type CallProfile string

const (
	CallProfileLexical CallProfile = "lexical"
	CallProfileVector  CallProfile = "vector"
	CallProfileHybrid  CallProfile = "hybrid"
)

// callProfileDeniedCode is the content-free reason a presented profile channel
// was ignored. It names no principal, workspace or corpus.
const callProfileDeniedCode = "SEARCH_PROFILE_CHANNEL_DENIED"

// ValidCallProfile reports whether value is one of the three server-owned
// profiles. Anything else is not a profile this deployment can run, so it is
// refused rather than silently defaulted: an ablation that quietly ran the
// default would report the default's score under the ablation's name.
func ValidCallProfile(value string) bool {
	switch CallProfile(value) {
	case CallProfileLexical, CallProfileVector, CallProfileHybrid:
		return true
	default:
		return false
	}
}

// ResolveCallProfile decides which retrieval profile one search call runs
// under and journals the decision.
//
// requested is the raw value presented on the operator channel; an empty value
// means the caller presented none, which is the ordinary case and is not an
// event. A presented value is granted only to an OWNER of workspaceID and only
// while this deployment actually has a vector space to ablate — with no mounted
// embedding profile there is no algorithm to choose between, and the profile
// hash that anchors the journal entry does not exist. Every other presented
// value (unknown profile, non-owner, service principal) is ignored, the call
// runs under the product default, and the attempt is journalled as DENIED.
//
// The returned profile is always the one the call must actually run under, so
// a caller cannot accidentally run one profile and report another.
func (service *Service) ResolveCallProfile(ctx context.Context, access database.AccessContext,
	workspaceID, requested string) (CallProfile, bool, error) {
	if service == nil || service.audit == nil || ctx == nil || access.Validate() != nil || workspaceID == "" {
		return CallProfileHybrid, false, &Error{code: CodeInvalid}
	}
	if requested == "" {
		return CallProfileHybrid, false, nil
	}
	if !service.mounted.Available() {
		// Nothing to ablate and no profile hash to anchor the record on. The
		// call runs the only retrieval this deployment has.
		return CallProfileHybrid, false, nil
	}
	granted := ValidCallProfile(requested) && service.authorize(ctx, access, workspaceID) == nil
	profile := CallProfile(requested)
	if !granted {
		profile = CallProfileHybrid
	}
	if err := service.appendCallProfileEvent(ctx, access, workspaceID, requested, granted); err != nil {
		// The decision is not observable, so it does not happen: the call falls
		// back to the product default rather than running an unrecorded
		// ablation.
		return CallProfileHybrid, false, &Error{code: CodeUnavailable, cause: err}
	}
	return profile, granted, nil
}

// appendCallProfileEvent writes exactly one journal entry for one presented
// profile channel. The action names the profile, so the journal answers "under
// which retrieval profile did this call run" from a closed vocabulary and
// without carrying free-form metadata. A refused attempt is recorded under the
// profile that was asked for, not under the one that ran, because what is worth
// keeping is what the caller tried to do.
func (service *Service) appendCallProfileEvent(ctx context.Context, access database.AccessContext,
	workspaceID, requested string, granted bool) error {
	action, known := callProfileAction(requested)
	if !known {
		// An unrecognised value is recorded against the profile the call
		// actually ran, so the journal never invents a fourth algorithm.
		action = audit.ActionSearchProfileCallHybrid
	}
	eventID, err := service.newID("aev")
	if err != nil {
		return err
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	outcome := audit.OutcomeSuccess
	var errorCode *string
	if !granted {
		outcome = audit.OutcomeDenied
		code := callProfileDeniedCode
		errorCode = &code
	}
	_, appendErr := service.audit.Append(ctx, access, audit.EventInput{
		EventID: eventID, ActorType: service.actorType(access), ActorPrincipalID: &actorID,
		Action: action, ResourceType: audit.ResourceSearchProfile,
		ResourceID: service.mounted.ProfileHash, RequestID: access.RequestID,
		WorkspaceID: &workspaceValue, Outcome: outcome, ErrorCode: errorCode,
		OccurredAt: service.now().UTC(),
	})
	return appendErr
}

// actorType reports how the journal names the presenter of the channel. An
// external agent calling through MCP is a SERVICE principal, and "an agent
// tried to pick the retrieval algorithm" is precisely the entry an operator
// wants to be able to find.
func (service *Service) actorType(access database.AccessContext) audit.ActorType {
	if access.ActorKind == database.ActorKindService {
		return audit.ActorService
	}
	return audit.ActorHuman
}

func callProfileAction(requested string) (audit.Action, bool) {
	switch CallProfile(requested) {
	case CallProfileLexical:
		return audit.ActionSearchProfileCallLexical, true
	case CallProfileVector:
		return audit.ActionSearchProfileCallVector, true
	case CallProfileHybrid:
		return audit.ActionSearchProfileCallHybrid, true
	default:
		return "", false
	}
}
