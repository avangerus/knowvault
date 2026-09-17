package audit

import (
	"testing"
	"time"
)

// A reserved resource type is worthless unless the common validator admits it.
// SEARCH_PROFILE and GOVERNED_QUERY_ATTEMPT were both declared as constants and
// wired into their own projection rules while validResource still rejected them,
// so every append of those events failed validation — silently for the governed
// query attempt (its caller discards the append error) and as a 503 for the
// search profile command. This test pins the whole closed vocabulary against the
// admission check so the next reserved resource cannot repeat it.
func TestEveryReservedResourceTypeIsAdmitted(t *testing.T) {
	for _, resource := range []ResourceType{
		ResourceOrganization, ResourceIdentity, ResourceWorkspace, ResourceWorkspaceMember,
		ResourceWorkspaceSource, ResourceWorkspaceAuthorityCommand, ResourceSourceConnection,
		ResourceSourceScope, ResourceSourceObject, ResourceConversation, ResourceQuestionRun,
		ResourceAnswerDocument, ResourceCitation, ResourceModelRun, ResourcePolicy,
		ResourceSigningKey, ResourceAuditCheckpoint, ResourceCryptoKey,
		ResourceGovernedQueryAttempt, ResourceSearchProfile,
	} {
		if !validResource(resource) {
			t.Fatalf("reserved resource type %q is not admitted by validResource", resource)
		}
	}
}

func TestSearchProfileRevisionEventBuilds(t *testing.T) {
	workspaceID := "tko-operations"
	actorID := "demo-admin"
	profileHash := "sha256:" + "12d33c57c0edc6d090342ac262001e699e23ebd7884c6dc2c31882239770f02a"
	input := EventInput{
		EventID: "aev_01M1WZZGSWJCM36MJ3KCXAD0AS", ActorType: ActorHuman, ActorPrincipalID: &actorID,
		Action: ActionSearchProfileRevisionRequested, ResourceType: ResourceSearchProfile,
		ResourceID: profileHash, RequestID: "req_6Pc8pKACedUypvtbuniWDQ",
		WorkspaceID: &workspaceID, Outcome: OutcomeSuccess,
		OccurredAt: time.Unix(1757000000, 0).UTC(),
	}
	if _, err := Build("knowvault-demo", input, 0, ""); err != nil {
		t.Fatalf("search profile revision event does not build: %v", err)
	}
}

// The vocabulary is reserved, not shared: the resource type may not appear
// under another action, the action may not appear under another resource type,
// and the event must name a workspace, a human actor and a real profile hash.
func TestSearchProfileRevisionEventRejectsForeignShapes(t *testing.T) {
	workspaceID := "tko-operations"
	actorID := "demo-admin"
	profileHash := "sha256:" + "12d33c57c0edc6d090342ac262001e699e23ebd7884c6dc2c31882239770f02a"
	base := EventInput{
		EventID: "aev_01M1WZZGSWJCM36MJ3KCXAD0AS", ActorType: ActorHuman, ActorPrincipalID: &actorID,
		Action: ActionSearchProfileRevisionRequested, ResourceType: ResourceSearchProfile,
		ResourceID: profileHash, RequestID: "req_6Pc8pKACedUypvtbuniWDQ",
		WorkspaceID: &workspaceID, Outcome: OutcomeSuccess,
		OccurredAt: time.Unix(1757000000, 0).UTC(),
	}
	for name, mutate := range map[string]func(*EventInput){
		"resource type without the action": func(input *EventInput) { input.Action = ActionWorkspaceUpdated },
		"action without the resource type": func(input *EventInput) { input.ResourceType = ResourceWorkspace },
		"no workspace":                     func(input *EventInput) { input.WorkspaceID = nil },
		"service actor":                    func(input *EventInput) { input.ActorType = ActorService },
		"resource id is not a hash":        func(input *EventInput) { input.ResourceID = "multilingual-e5-small-cpu-v1" },
		"foreign metadata": func(input *EventInput) {
			revision := int64(3)
			input.Metadata = Metadata{WorkspaceRevision: &revision}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			if _, err := Build("knowvault-demo", input, 0, ""); err == nil {
				t.Fatalf("Build accepted a search profile event it must reject")
			}
		})
	}
}
