package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildDerivesCanonicalEventAndHash(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspace := "ws_alpha"
	policy := "policy_001"
	event, err := Build("org_alpha", EventInput{
		EventID:               "aud_001",
		WorkspaceID:           &workspace,
		ActorType:             ActorHuman,
		ActorPrincipalID:      &actor,
		Action:                ActionWorkspaceCreated,
		ResourceType:          ResourceWorkspace,
		ResourceID:            workspace,
		RequestID:             "req_001",
		PolicyDecisionID:      &policy,
		Outcome:               OutcomeSuccess,
		ReferencedEvidenceIDs: []string{"ev_001", "ev_002"},
		Metadata:              Metadata{ReasonCodes: []string{"POLICY_ALLOWED"}},
		OccurredAt:            time.Date(2026, time.July, 14, 10, 0, 0, 0, time.FixedZone("Moscow", 3*60*60)),
	}, 0, "")
	if err != nil {
		t.Fatalf("build valid event: %v", err)
	}
	if event.Sequence != 1 || event.PreviousEventHash != zeroHash || event.EventHash != hash(event.CanonicalBytes) {
		t.Fatalf("unexpected derived chain: %#v", event)
	}

	full, err := canonicalEvent(event, true)
	if err != nil {
		t.Fatalf("full canonical event: %v", err)
	}
	var projection map[string]any
	if err := json.Unmarshal(full, &projection); err != nil {
		t.Fatalf("decode canonical event: %v", err)
	}
	metadata := projection["metadata"].(map[string]any)
	if len(metadata) != 1 || metadata["reason_codes"] == nil {
		t.Fatalf("metadata contains null or unallowlisted projection: %#v", metadata)
	}
	if projection["occurred_at"] != "2026-07-14T07:00:00Z" {
		t.Fatalf("event time was not normalized to UTC: %#v", projection["occurred_at"])
	}
}

func TestBuildAcceptsConversationArchiveVocabulary(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspace := "ws_alpha"
	event, err := Build("org_alpha", EventInput{
		EventID: "aud_conversation_001", WorkspaceID: &workspace,
		ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionConversationArchived, ResourceType: ResourceConversation,
		ResourceID: "conv_01ARZ3NDEKTSV4RRFFQ69G5FBV", RequestID: "req_conversation_001",
		Outcome: OutcomeSuccess, OccurredAt: time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC),
	}, 0, "")
	if err != nil {
		t.Fatalf("conversation archive vocabulary rejected: %v", err)
	}
	full, err := canonicalEvent(event, true)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(full, &projection); err != nil {
		t.Fatal(err)
	}
	if projection["resource_type"] != string(ResourceConversation) || projection["action"] != string(ActionConversationArchived) {
		t.Fatalf("unexpected conversation archive projection: %#v", projection)
	}
}

func TestBuildMatchesIndependentAuditGolden(t *testing.T) {
	actor := "usr_alice"
	workspace := "ws_alpha"
	policy := "policy_001"
	event, err := Build("org_alpha", EventInput{
		EventID: "aud_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionWorkspaceCreated, ResourceType: ResourceWorkspace, ResourceID: workspace,
		RequestID: "req_001", PolicyDecisionID: &policy, Outcome: OutcomeSuccess,
		ReferencedEvidenceIDs: []string{"ev_001", "ev_002"}, Metadata: Metadata{ReasonCodes: []string{"POLICY_ALLOWED"}},
		OccurredAt: time.Date(2026, time.July, 14, 10, 0, 0, 0, time.FixedZone("Moscow", 3*60*60)),
	}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	const wantCanonical = `{"action":"workspace.created","actor_principal_id":"usr_alice","actor_type":"HUMAN","error_code":null,"event_id":"aud_001","metadata":{"reason_codes":["POLICY_ALLOWED"]},"occurred_at":"2026-07-14T07:00:00Z","on_behalf_of_principal_id":null,"organization_id":"org_alpha","outcome":"SUCCESS","policy_decision_id":"policy_001","previous_event_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","referenced_evidence_ids":["ev_001","ev_002"],"request_id":"req_001","resource_id":"ws_alpha","resource_type":"WORKSPACE","schema_version":"audit-event-v1","sequence":1,"workspace_id":"ws_alpha"}`
	const wantHash = "sha256:bc0d2970da04ffd931af1c0b6231b2e68c57e378bf4a16d105e4d1264908807b"
	if string(event.CanonicalBytes) != wantCanonical {
		t.Fatalf("audit canonical bytes drifted:\n got %s\nwant %s", event.CanonicalBytes, wantCanonical)
	}
	if event.EventHash != wantHash {
		t.Fatalf("audit event hash = %s, want %s", event.EventHash, wantHash)
	}
}

func TestBuildRejectsAmbiguousAndNonCanonicalInput(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	base := EventInput{
		EventID:          "aud_001",
		ActorType:        ActorHuman,
		ActorPrincipalID: &actor,
		Action:           ActionPolicyDecision,
		ResourceType:     ResourcePolicy,
		ResourceID:       "policy_001",
		RequestID:        "req_001",
		Outcome:          OutcomeDenied,
		ErrorCode:        ptr("POLICY_DENIED"),
		OccurredAt:       time.Date(2026, time.July, 14, 10, 0, 0, 0, time.UTC),
	}

	for name, mutate := range map[string]func(*EventInput){
		"unordered evidence": func(input *EventInput) { input.ReferencedEvidenceIDs = []string{"ev_002", "ev_001"} },
		"unknown action":     func(input *EventInput) { input.Action = "audit.export_raw_source" },
		"success with error": func(input *EventInput) { input.Outcome = OutcomeSuccess },
		"control character":  func(input *EventInput) { input.ResourceID = "ws\nalpha" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := base
			mutate(&input)
			if _, err := Build("org_alpha", input, 0, ""); CodeOf(err) != CodeInvalidEvent {
				t.Fatalf("invalid input got %v", err)
			}
		})
	}
}

func TestBuildCannotAcceptCallerSuppliedBrokenHead(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	_, err := Build("org_alpha", EventInput{
		EventID: "aud_001", ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionAuditViewed, ResourceType: ResourceWorkspace, ResourceID: "ws_alpha", RequestID: "req_001",
		Outcome: OutcomeSuccess, OccurredAt: time.Now().UTC(),
	}, 2, "sha256:"+strings.Repeat("g", 64))
	if CodeOf(err) != CodeInvalidEvent {
		t.Fatalf("broken head accepted: %v", err)
	}
}

func TestBuildSerializesEmptyEvidenceAsArray(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	event, err := Build("org_alpha", EventInput{
		EventID: "aud_002", ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionAuditViewed, ResourceType: ResourceWorkspace, ResourceID: "ws_alpha", RequestID: "req_002",
		Outcome: OutcomeSuccess, OccurredAt: time.Date(2026, time.July, 14, 10, 0, 0, 0, time.UTC),
	}, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	full, err := canonicalEvent(event, true)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(full, &projection); err != nil {
		t.Fatal(err)
	}
	if evidence, ok := projection["referenced_evidence_ids"].([]any); !ok || len(evidence) != 0 {
		t.Fatalf("empty evidence was not a JSON array: %#v", projection["referenced_evidence_ids"])
	}
}

func TestBuildWorkspaceSourceMutationUsesExactContentFreeProjection(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspace := "ws_alpha"
	workspaceRevision := int64(7)
	scopeRevision := int64(3)
	bindingID := "wsrc_alpha_docs"
	scopeID := "scope_docs"
	scopeHash := "sha256:" + strings.Repeat("a", 64)
	accessMode := "WORKSPACE_MANAGED"
	enabled := true

	event, err := Build("org_alpha", EventInput{
		EventID: "aud_source_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionWorkspaceSourceAdded, ResourceType: ResourceWorkspaceSource, ResourceID: bindingID,
		RequestID: "req_source_001", Outcome: OutcomeSuccess,
		Metadata: Metadata{
			WorkspaceRevision: &workspaceRevision, WorkspaceSourceID: &bindingID,
			SourceScopeID: &scopeID, SourceScopeRevision: &scopeRevision, ScopeConfigHash: &scopeHash,
			AccessMode: &accessMode, Enabled: &enabled,
		},
		OccurredAt: time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC),
	}, 0, "")
	if err != nil {
		t.Fatalf("build workspace source event: %v", err)
	}

	full, err := canonicalEvent(event, true)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(full, &projection); err != nil {
		t.Fatal(err)
	}
	metadata := projection["metadata"].(map[string]any)
	if len(metadata) != 7 || metadata["enabled"] != true || metadata["workspace_source_id"] != bindingID || metadata["scope_config_hash"] != scopeHash {
		t.Fatalf("workspace source metadata is not exact: %#v", metadata)
	}
	if projection["resource_type"] != "WORKSPACE_SOURCE" || projection["action"] != "workspace.source_added" {
		t.Fatalf("unexpected source mutation vocabulary: %#v", projection)
	}

	// Build must own copies of pointer-backed metadata; caller mutation cannot
	// rewrite the already-derived canonical event.
	bindingID = "wsrc_tampered"
	enabled = false
	if event.Metadata.WorkspaceSourceID == nil || *event.Metadata.WorkspaceSourceID != "wsrc_alpha_docs" || event.Metadata.Enabled == nil || !*event.Metadata.Enabled {
		t.Fatalf("event metadata aliases caller memory: %#v", event.Metadata)
	}
}

func TestBuildWorkspaceSourceMutationAcceptsEveryTerminalOutcome(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspaceID := "ws_alpha"
	workspaceRevision := int64(7)
	scopeRevision := int64(3)
	bindingID := "wsrc_alpha_docs"
	scopeID := "scope_docs"
	scopeHash := "sha256:" + strings.Repeat("a", 64)
	accessMode := "WORKSPACE_MANAGED"
	enabled := true

	for _, testCase := range []struct {
		name        string
		outcome     Outcome
		errorCode   *string
		workspaceID *string
	}{
		{name: "success", outcome: OutcomeSuccess, workspaceID: &workspaceID},
		{name: "denied hidden workspace", outcome: OutcomeDenied, errorCode: ptr("WORKSPACE_SOURCE_DENIED")},
		{name: "denied known workspace", outcome: OutcomeDenied, errorCode: ptr("WORKSPACE_SOURCE_DENIED"), workspaceID: &workspaceID},
		{name: "failed missing workspace", outcome: OutcomeFailed, errorCode: ptr("WORKSPACE_SOURCE_NOT_FOUND")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			_, err := Build("org_alpha", EventInput{
				EventID: "aud_source_" + testCase.name, WorkspaceID: testCase.workspaceID,
				ActorType: ActorHuman, ActorPrincipalID: &actor,
				Action: ActionWorkspaceSourceAdded, ResourceType: ResourceWorkspaceSource, ResourceID: bindingID,
				RequestID: "req_source_" + testCase.name, Outcome: testCase.outcome, ErrorCode: testCase.errorCode,
				Metadata: Metadata{
					WorkspaceRevision: &workspaceRevision, WorkspaceSourceID: &bindingID,
					SourceScopeID: &scopeID, SourceScopeRevision: &scopeRevision, ScopeConfigHash: &scopeHash,
					AccessMode: &accessMode, Enabled: &enabled,
				},
				OccurredAt: time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC),
			}, 0, "")
			if err != nil {
				t.Fatalf("terminal source outcome rejected: %v", err)
			}
		})
	}
}

func TestBuildRejectsInexactWorkspaceSourceMutationProjection(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspace := "ws_alpha"
	workspaceRevision := int64(7)
	scopeRevision := int64(3)
	bindingID := "wsrc_alpha_docs"
	scopeID := "scope_docs"
	scopeHash := "sha256:" + strings.Repeat("a", 64)
	accessMode := "WORKSPACE_MANAGED"
	enabled := true
	base := EventInput{
		EventID: "aud_source_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionWorkspaceSourceAdded, ResourceType: ResourceWorkspaceSource, ResourceID: bindingID,
		RequestID: "req_source_001", Outcome: OutcomeSuccess,
		Metadata: Metadata{
			WorkspaceRevision: &workspaceRevision, WorkspaceSourceID: &bindingID,
			SourceScopeID: &scopeID, SourceScopeRevision: &scopeRevision, ScopeConfigHash: &scopeHash,
			AccessMode: &accessMode, Enabled: &enabled,
		},
		OccurredAt: time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC),
	}

	for name, mutate := range map[string]func(*EventInput){
		"wrong resource":        func(input *EventInput) { input.ResourceType = ResourceSourceScope },
		"wrong resource id":     func(input *EventInput) { input.ResourceID = "wsrc_other" },
		"missing workspace":     func(input *EventInput) { input.WorkspaceID = nil },
		"missing revision":      func(input *EventInput) { input.Metadata.WorkspaceRevision = nil },
		"premature policy":      func(input *EventInput) { input.Metadata.PolicyRevision = ptr("policy_007") },
		"premature decision":    func(input *EventInput) { input.PolicyDecisionID = ptr("pd_source_add_001") },
		"invalid access mode":   func(input *EventInput) { input.Metadata.AccessMode = ptr("SHARED") },
		"wrong add state":       func(input *EventInput) { input.Metadata.Enabled = boolPtr(false) },
		"extra content hint":    func(input *EventInput) { input.Metadata.UserAgentFamily = ptr("raw browser value") },
		"failed without code":   func(input *EventInput) { input.Outcome = OutcomeFailed },
		"resource without verb": func(input *EventInput) { input.Action = ActionWorkspaceUpdated },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := base
			mutate(&input)
			if _, err := Build("org_alpha", input, 0, ""); CodeOf(err) != CodeInvalidEvent {
				t.Fatalf("inexact source mutation accepted: %v", err)
			}
		})
	}

	removed := base
	removed.Action = ActionWorkspaceSourceRemoved
	removed.Metadata.Enabled = boolPtr(false)
	if _, err := Build("org_alpha", removed, 0, ""); err != nil {
		t.Fatalf("exact source removal rejected: %v", err)
	}
}

func TestBuildAnswerAmendmentMetadataClosedVocabulary(t *testing.T) {
	t.Parallel()

	actor := "usr_alice"
	workspace := "ws_alpha"
	version := int64(2)
	class := "SUPERSEDE"
	base := EventInput{
		EventID: "aud_answer_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionAnswerDocumentAmended, ResourceType: ResourceAnswerDocument, ResourceID: "ansdoc_alpha",
		RequestID: "req_answer_001", Outcome: OutcomeSuccess,
		Metadata:   Metadata{AnswerDocumentVersion: &version, AmendmentClass: &class},
		OccurredAt: time.Date(2026, time.August, 14, 11, 0, 0, 0, time.UTC),
	}

	event, err := Build("org_alpha", base, 0, "")
	if err != nil {
		t.Fatalf("build answer amendment event: %v", err)
	}
	full, err := canonicalEvent(event, true)
	if err != nil {
		t.Fatalf("full canonical event: %v", err)
	}
	var projection map[string]any
	if err := json.Unmarshal(full, &projection); err != nil {
		t.Fatalf("decode canonical event: %v", err)
	}
	metadata := projection["metadata"].(map[string]any)
	if len(metadata) != 2 || metadata["answer_document_version"] != float64(2) || metadata["amendment_class"] != "SUPERSEDE" {
		t.Fatalf("answer amendment metadata not carried canonically: %#v", metadata)
	}

	closedClass := base
	closedClass.Metadata.AmendmentClass = ptr("RENAME")
	if _, err := Build("org_alpha", closedClass, 0, ""); CodeOf(err) != CodeInvalidEvent {
		t.Fatalf("closed amendment class leak accepted: %v", err)
	}
	zeroVersion := base
	zeroVersion.Metadata.AnswerDocumentVersion = int64Ptr(0)
	if _, err := Build("org_alpha", zeroVersion, 0, ""); CodeOf(err) != CodeInvalidEvent {
		t.Fatalf("out-of-range amendment version accepted: %v", err)
	}
	otherAction := base
	otherAction.Action = ActionWorkspaceCreated
	otherAction.ResourceType = ResourceWorkspace
	otherAction.ResourceID = workspace
	if _, err := Build("org_alpha", otherAction, 0, ""); CodeOf(err) != CodeInvalidEvent {
		t.Fatalf("answer amendment metadata leaked onto another action: %v", err)
	}
}

func TestSourceObjectPresenceActionsAreClosedAndContentFree(t *testing.T) {
	t.Parallel()
	for _, action := range []Action{ActionSourceObjectMissing, ActionSourceObjectRestored} {
		input := EventInput{
			EventID: "aud_presence", ActorType: ActorSystem, Action: action,
			ResourceType: ResourceSourceObject, ResourceID: "object_presence",
			RequestID: "req_presence", Outcome: OutcomeSuccess,
			OccurredAt: time.Date(2026, time.September, 16, 10, 0, 0, 0, time.UTC),
			Metadata:   Metadata{SyncRunID: ptr("syncrun_presence"), ConnectorJobID: ptr("job_presence")},
		}
		if _, err := Build("org_alpha", input, 0, ""); err != nil {
			t.Fatalf("presence action %s: %v", action, err)
		}
		input.Action = action + "_forced"
		if _, err := Build("org_alpha", input, 0, ""); CodeOf(err) != CodeInvalidEvent {
			t.Fatalf("unknown presence action accepted: %v", err)
		}
	}
}

func ptr(value string) *string    { return &value }
func boolPtr(value bool) *bool    { return &value }
func int64Ptr(value int64) *int64 { return &value }
