package audit

import "reflect"

// The source-read projection deliberately has no data fields. A closed reason
// identifies which of the shared repository reads the event covers: the source
// status list, the confirmation context, card D-1's connection draft list, or
// ADR-0097's source schema list/schema read (S3 card 1).
func validSourceMetadataReadProjection(input EventInput) bool {
	if input.ResourceType != ResourceWorkspace || input.PolicyDecisionID != nil || input.OnBehalfOfPrincipalID != nil ||
		(input.ActorType != ActorHuman && input.ActorType != ActorService) || len(input.ReferencedEvidenceIDs) != 0 ||
		len(input.Metadata.ReasonCodes) != 1 {
		return false
	}
	kind := input.Metadata.ReasonCodes[0]
	if kind != "SOURCE_STATUS_LIST" && kind != "SOURCE_CONFIRMATION_CONTEXT" && kind != "SOURCE_CONNECTION_DRAFT_LIST" &&
		kind != "SOURCE_SCHEMA_LIST" && kind != "SOURCE_SCHEMA" {
		return false
	}
	// Comparison with the same struct carrying only this field also rejects
	// future metadata members without growing another parallel field list.
	if !reflect.DeepEqual(input.Metadata, Metadata{ReasonCodes: input.Metadata.ReasonCodes}) {
		return false
	}
	if input.WorkspaceID != nil && *input.WorkspaceID != input.ResourceID {
		return false
	}
	if input.Outcome == OutcomeDenied && (input.ErrorCode == nil || *input.ErrorCode != "SOURCE_METADATA_READ_DENIED") ||
		input.Outcome == OutcomeFailed && (input.ErrorCode == nil || *input.ErrorCode != "SOURCE_METADATA_READ_FAILED") {
		return false
	}
	switch input.Action {
	case ActionSourceMetadataReadAdmitted:
		return input.Outcome == OutcomeSuccess && input.WorkspaceID != nil || input.Outcome == OutcomeDenied
	case ActionSourceMetadataReadCompleted:
		return input.Outcome == OutcomeSuccess && input.WorkspaceID != nil
	case ActionSourceMetadataReadFailed:
		return input.Outcome == OutcomeDenied || input.Outcome == OutcomeFailed
	}
	return false
}
