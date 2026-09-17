package question

import (
	"context"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// ModelProfile is the content-free selection captured with a run. It is never
// reconstructed from today's configuration when an older answer is read.
type ModelProfile struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Location string `json:"location"`
}

type ModelProfileOption struct {
	ModelProfile
	IsDefault bool `json:"is_default"`
}

type generationSelection struct {
	adapter *modelgateway.LabAdapter
	profile ModelProfile
}

func ValidModelProfileID(value string) bool { return modelgateway.ValidProfileID(value) }

// EnableGenerationProfiles is a composition-time operation. Requests retain
// their own selected adapter; they never replace Service.generation.
func (service *Service) EnableGenerationProfiles(profiles *modelgateway.ProfileRegistry) {
	if service != nil {
		service.generationProfiles = profiles
	}
}

// ModelProfiles is projected only after the transport's workspace read gate.
// The registry's exact workspace allow-list is also enforced again by Select
// and by Converse. Legacy GENERATIVE-only adapters are not UI tool-loop choices.
func (service *Service) ModelProfiles(workspaceID string) []ModelProfileOption {
	options := make([]ModelProfileOption, 0)
	if service == nil || service.tools == nil {
		return options
	}
	if service.generationProfiles != nil {
		for _, info := range service.generationProfiles.List(workspaceID) {
			adapter, err := service.generationProfiles.Select(workspaceID, info.ID)
			if err != nil || !toolLoopAdapterAvailable(adapter, workspaceID) {
				continue
			}
			options = append(options, ModelProfileOption{
				ModelProfile: ModelProfile{ID: info.ID, Label: info.Label, Location: info.Location},
				IsDefault:    info.IsDefault,
			})
		}
		return options
	}
	if toolLoopAdapterAvailable(service.generation, workspaceID) {
		options = append(options, ModelProfileOption{ModelProfile: legacyModelProfile(service.generation), IsDefault: true})
	}
	return options
}

func toolLoopAdapterAvailable(adapter *modelgateway.LabAdapter, workspaceID string) bool {
	if adapter == nil || !adapter.AllowsWorkspace(workspaceID) {
		return false
	}
	_, ok := adapter.ToolLoopProfile()
	return ok
}

func legacyModelProfile(adapter *modelgateway.LabAdapter) ModelProfile {
	location := ProcessingModeInternal
	if adapter.RuntimeScope() == modelgateway.RuntimeScopeExternalWorkspaceScoped {
		location = ProcessingModeExternal
	}
	label := []rune(adapter.ProviderName())
	if len(label) > 80 {
		label = label[:80]
	}
	return ModelProfile{ID: "default", Label: string(label), Location: location}
}

func (service *Service) selectGeneration(workspaceID, profileID string) (generationSelection, error) {
	if service == nil || service.tools == nil {
		return generationSelection{}, &Error{code: CodeUnsupportedMode}
	}
	if service.generationProfiles == nil {
		if (profileID != "" && profileID != "default") || !toolLoopAdapterAvailable(service.generation, workspaceID) {
			return generationSelection{}, &Error{code: CodeUnsupportedMode}
		}
		return generationSelection{adapter: service.generation, profile: legacyModelProfile(service.generation)}, nil
	}
	adapter, err := service.generationProfiles.Select(workspaceID, profileID)
	if err != nil || !toolLoopAdapterAvailable(adapter, workspaceID) {
		return generationSelection{}, &Error{code: CodeUnsupportedMode}
	}
	for _, info := range service.generationProfiles.List(workspaceID) {
		if info.ID == profileID || profileID == "" && info.IsDefault {
			return generationSelection{adapter: adapter, profile: ModelProfile{ID: info.ID, Label: info.Label, Location: info.Location}}, nil
		}
	}
	return generationSelection{}, &Error{code: CodeUnsupportedMode}
}

func copyModelProfile(profile *ModelProfile) *ModelProfile {
	if profile == nil {
		return nil
	}
	copy := *profile
	return &copy
}

func toolLoopRequestHash(questionText, conversationID, profileID string) string {
	if profileID == "" {
		// Preserve the replay identity of requests made before model selection.
		return requestHash(questionText, AnswerModeToolLoop, conversationID)
	}
	return canon.Hash([]byte("question-request-model-v1\x00" + profileID + "\x00" + conversationID + "\x00" + questionText))
}

func (service *Service) admitModelSelection(ctx context.Context, access database.AccessContext, workspaceID, runID, profileID string) (generationSelection, error) {
	// The first event is durable before the governed authorization read. A
	// nullable workspace FK does not distinguish a hidden workspace from one
	// that does not exist. Neither event contains the requested profile ID.
	if err := service.emitModelSelectionEvent(ctx, access, workspaceID, runID, false, audit.OutcomeSuccess, ""); err != nil {
		return generationSelection{}, &Error{code: CodeUnavailable, cause: err}
	}
	authorize := service.authorizeModelSelectionFn
	if authorize == nil {
		authorize = service.authorizeModelSelection
	}
	if err := authorize(ctx, access, workspaceID); err != nil {
		outcome, code := audit.OutcomeDenied, "QUESTION_MODEL_ACCESS_DENIED"
		if CodeOf(err) != CodeDenied {
			outcome, code = audit.OutcomeFailed, "QUESTION_MODEL_ACCESS_FAILED"
		}
		if auditErr := service.emitModelSelectionEvent(ctx, access, workspaceID, runID, false, outcome, code); auditErr != nil {
			return generationSelection{}, &Error{code: CodeUnavailable, cause: auditErr}
		}
		return generationSelection{}, err
	}
	selected, err := service.selectGeneration(workspaceID, profileID)
	if err != nil {
		if auditErr := service.emitModelSelectionEvent(ctx, access, workspaceID, runID, true, audit.OutcomeDenied, "QUESTION_MODEL_PROFILE_UNAVAILABLE"); auditErr != nil {
			return generationSelection{}, &Error{code: CodeUnavailable, cause: auditErr}
		}
		return generationSelection{}, err
	}
	return selected, nil
}

func (service *Service) emitModelSelectionEvent(ctx context.Context, access database.AccessContext, workspaceID, runID string, workspaceKnown bool, outcome audit.Outcome, code string) error {
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return err
	}
	input := audit.EventInput{
		EventID: eventID, ActorType: audit.ActorType(access.EffectiveActorKind()), ActorPrincipalID: &access.PrincipalID,
		Action: audit.ActionQuestionRunAdmitted, ResourceType: audit.ResourceWorkspace, ResourceID: workspaceID,
		RequestID: access.RequestID, Outcome: outcome, ReferencedEvidenceIDs: []string{},
		Metadata: audit.Metadata{QuestionRunID: &runID}, OccurredAt: service.now().UTC(),
	}
	if workspaceKnown {
		input.WorkspaceID = &workspaceID
	}
	if code != "" {
		input.ErrorCode = &code
	}
	_, err = journal.Append(ctx, access, input)
	return err
}

func (service *Service) authorizeModelSelection(ctx context.Context, access database.AccessContext, workspaceID string) error {
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var organizationStatus, workspaceStatus, principalStatus, role string
		var principalRevision int64
		if err := tx.QueryRow(txCtx, `
			SELECT o.status, w.status, p.status, p.session_revision, COALESCE(m.role, '')
			  FROM public.organization o
			  JOIN public.workspace w ON w.organization_id=o.id AND w.id=$2
			  JOIN public.principal p ON p.organization_id=o.id AND p.id=$3
			  LEFT JOIN public.workspace_member m ON m.organization_id=w.organization_id
			   AND m.workspace_id=w.id AND m.principal_id=p.id AND m.removed_at IS NULL
			 WHERE o.id=$1`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(
			&organizationStatus, &workspaceStatus, &principalStatus, &principalRevision, &role); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeDenied}
			}
			return err
		}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceAsk,
			Subject: policy.Subject{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
				Status: policy.PrincipalStatus(principalStatus), SessionRevision: principalRevision},
			Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: workspaceID, Status: policy.WorkspaceStatus(workspaceStatus)},
			Membership: policy.Membership{Present: role != "", Role: policy.WorkspaceRole(role)},
		})
		if organizationStatus != "ACTIVE" || !decision.Allowed {
			return &Error{code: CodeDenied}
		}
		return nil
	})
	if err != nil && CodeOf(err) != CodeDenied {
		return &Error{code: CodeUnavailable, cause: err}
	}
	return err
}
