package audit

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestSourceMetadataReadProjectionIsClosed(t *testing.T) {
	t.Parallel()
	principal, workspace, code, extra := "svcp_agent", "ws_alpha", "SOURCE_METADATA_READ_DENIED", "scope_extra"
	failureCode := "SOURCE_METADATA_READ_FAILED"
	base := EventInput{EventID: "aud_sources", WorkspaceID: &workspace, ActorType: ActorService, ActorPrincipalID: &principal,
		Action: ActionSourceMetadataReadAdmitted, ResourceType: ResourceWorkspace, ResourceID: workspace,
		RequestID: "req_sources", Outcome: OutcomeSuccess, Metadata: Metadata{ReasonCodes: []string{"SOURCE_STATUS_LIST"}},
		OccurredAt: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)}
	for _, test := range []struct {
		name  string
		edit  func(*EventInput)
		valid bool
	}{
		{"admitted", func(*EventInput) {}, true},
		{"completed", func(in *EventInput) { in.Action = ActionSourceMetadataReadCompleted }, true},
		{"confirmation", func(in *EventInput) { in.Metadata.ReasonCodes = []string{"SOURCE_CONFIRMATION_CONTEXT"} }, true},
		{"connection_draft_list", func(in *EventInput) { in.Metadata.ReasonCodes = []string{"SOURCE_CONNECTION_DRAFT_LIST"} }, true},
		{"source_schema_list", func(in *EventInput) { in.Metadata.ReasonCodes = []string{"SOURCE_SCHEMA_LIST"} }, true},
		{"source_schema", func(in *EventInput) { in.Metadata.ReasonCodes = []string{"SOURCE_SCHEMA"} }, true},
		{"denied_admission_unknown_workspace", func(in *EventInput) { in.WorkspaceID = nil; in.Outcome = OutcomeDenied; in.ErrorCode = &code }, true},
		{"denied_outcome", func(in *EventInput) {
			in.Action = ActionSourceMetadataReadFailed
			in.Outcome = OutcomeDenied
			in.ErrorCode = &code
		}, true},
		{"failed_outcome", func(in *EventInput) {
			in.Action = ActionSourceMetadataReadFailed
			in.Outcome = OutcomeFailed
			in.ErrorCode = &failureCode
		}, true},
		{"human", func(in *EventInput) { in.ActorType = ActorHuman }, true},
		{"unexpected_actor", func(in *EventInput) { in.ActorType = ActorConnector }, false},
		{"on_behalf_reference", func(in *EventInput) { in.OnBehalfOfPrincipalID = &extra }, false},
		{"wrong_denial_code", func(in *EventInput) { in.Outcome = OutcomeDenied; in.ErrorCode = &failureCode }, false},
		{"unknown_reason", func(in *EventInput) { in.Metadata.ReasonCodes = []string{"SOURCE_CONTENT"} }, false},
		{"two_reasons", func(in *EventInput) {
			in.Metadata.ReasonCodes = []string{"SOURCE_STATUS_LIST", "SOURCE_CONFIRMATION_CONTEXT"}
		}, false},
		{"extra_metadata", func(in *EventInput) { in.Metadata.SourceScopeID = &extra }, false},
		{"evidence_reference", func(in *EventInput) { in.ReferencedEvidenceIDs = []string{"ev_extra"} }, false},
		{"policy_reference", func(in *EventInput) { in.PolicyDecisionID = &extra }, false},
		{"wrong_resource", func(in *EventInput) { in.ResourceType = ResourceIdentity }, false},
		{"wrong_workspace", func(in *EventInput) { in.WorkspaceID = &extra }, false},
		{"success_without_workspace", func(in *EventInput) { in.WorkspaceID = nil }, false},
		{"completed_denied", func(in *EventInput) {
			in.Action = ActionSourceMetadataReadCompleted
			in.Outcome = OutcomeDenied
			in.ErrorCode = &code
		}, false},
		{"failed_success", func(in *EventInput) { in.Action = ActionSourceMetadataReadFailed }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := base
			test.edit(&input)
			event, err := Build("org_alpha", input, 0, "")
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
			if err != nil {
				return
			}
			var canonical map[string]any
			if err := json.Unmarshal(event.CanonicalBytes, &canonical); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"reason_codes": []any{input.Metadata.ReasonCodes[0]}}
			if !reflect.DeepEqual(canonical["metadata"], want) {
				t.Fatalf("non-exact metadata: %#v", canonical["metadata"])
			}
		})
	}
}
