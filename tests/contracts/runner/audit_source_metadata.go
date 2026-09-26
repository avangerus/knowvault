package contracts

// This validator is independent of the production audit builder. Rehashing a
// polluted source-metadata event must not make its projection acceptable.
func validateSourceMetadataAuditProjection(event map[string]any) error {
	action := stringValue(event["action"])
	if action != "source.metadata.read.admitted" && action != "source.metadata.read.completed" && action != "source.metadata.read.failed" {
		return nil
	}
	actor, outcome := stringValue(event["actor_type"]), stringValue(event["outcome"])
	metadata := object(event["metadata"])
	reasons := array(metadata["reason_codes"])
	if stringValue(event["resource_type"]) != "WORKSPACE" || (actor != "HUMAN" && actor != "SERVICE") ||
		event["policy_decision_id"] != nil || event["on_behalf_of_principal_id"] != nil ||
		len(array(event["referenced_evidence_ids"])) != 0 || len(metadata) != 1 || len(reasons) != 1 ||
		(stringValue(reasons[0]) != "SOURCE_STATUS_LIST" && stringValue(reasons[0]) != "SOURCE_CONFIRMATION_CONTEXT" &&
			stringValue(reasons[0]) != "SOURCE_SCHEMA_LIST" && stringValue(reasons[0]) != "SOURCE_SCHEMA") {
		return fail("AUDIT_SOURCE_METADATA_PROJECTION_INVALID")
	}
	workspaceID := stringValue(event["workspace_id"])
	if workspaceID != "" && workspaceID != stringValue(event["resource_id"]) || outcome == "SUCCESS" && workspaceID == "" {
		return fail("AUDIT_SOURCE_METADATA_PROJECTION_INVALID")
	}
	if outcome == "DENIED" && stringValue(event["error_code"]) != "SOURCE_METADATA_READ_DENIED" ||
		outcome == "FAILED" && stringValue(event["error_code"]) != "SOURCE_METADATA_READ_FAILED" ||
		action == "source.metadata.read.admitted" && outcome != "SUCCESS" && outcome != "DENIED" ||
		action == "source.metadata.read.completed" && outcome != "SUCCESS" ||
		action == "source.metadata.read.failed" && outcome != "DENIED" && outcome != "FAILED" {
		return fail("AUDIT_SOURCE_METADATA_OUTCOME_INVALID")
	}
	return nil
}
