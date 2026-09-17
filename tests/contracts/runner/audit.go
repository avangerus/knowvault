package contracts

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

func auditEventContent(event map[string]any) map[string]any {
	content := cloneObject(event)
	delete(content, "event_hash")
	return content
}

func validateAuditEventAgainst(event map[string]any, organizationID, previousEventHash string, expectedSequence int) error {
	if err := assertAllowedFields(event, []string{
		"schema_version", "event_id", "organization_id", "sequence", "workspace_id", "actor_type", "actor_principal_id",
		"on_behalf_of_principal_id", "action", "resource_type", "resource_id", "request_id", "policy_decision_id",
		"outcome", "error_code", "referenced_evidence_ids", "metadata", "previous_event_hash", "event_hash", "occurred_at",
	}); err != nil {
		return err
	}
	if stringValue(event["schema_version"]) != "audit-event-v1" || stringValue(event["organization_id"]) != organizationID ||
		intValue(event["sequence"]) != expectedSequence || stringValue(event["previous_event_hash"]) != previousEventHash {
		return fail("AUDIT_EVENT_CHAIN_MISMATCH")
	}
	actorType := stringValue(event["actor_type"])
	if (actorType == "SYSTEM") != (event["actor_principal_id"] == nil) {
		return fail("AUDIT_EVENT_ACTOR_INVALID")
	}
	if (stringValue(event["outcome"]) == "SUCCESS") != (event["error_code"] == nil) {
		return fail("AUDIT_EVENT_OUTCOME_INVALID")
	}
	if err := validateWorkspaceSourceAuditProjection(event); err != nil {
		return err
	}
	if err := validateSourceMetadataAuditProjection(event); err != nil {
		return err
	}
	lastEvidenceID := ""
	for _, rawID := range array(event["referenced_evidence_ids"]) {
		id := stringValue(rawID)
		if id == "" || (lastEvidenceID != "" && id <= lastEvidenceID) {
			return fail("AUDIT_EVENT_EVIDENCE_SET_NOT_CANONICAL")
		}
		lastEvidenceID = id
	}
	if _, err := time.Parse(time.RFC3339, stringValue(event["occurred_at"])); err != nil {
		return fail("AUDIT_EVENT_TIME_INVALID")
	}
	contentHash, err := hashCanonical(auditEventContent(event))
	if err != nil {
		return err
	}
	if stringValue(event["event_hash"]) != contentHash {
		return fail("AUDIT_EVENT_HASH_MISMATCH")
	}
	return nil
}

func validateWorkspaceSourceAuditProjection(event map[string]any) error {
	action := stringValue(event["action"])
	resourceType := stringValue(event["resource_type"])
	if action != "workspace.source_added" && action != "workspace.source_removed" {
		if resourceType == "WORKSPACE_SOURCE" {
			return fail("AUDIT_WORKSPACE_SOURCE_ACTION_INVALID")
		}
		return nil
	}
	metadata := object(event["metadata"])
	if resourceType != "WORKSPACE_SOURCE" || stringValue(event["outcome"]) == "SUCCESS" && stringValue(event["workspace_id"]) == "" ||
		event["policy_decision_id"] != nil ||
		len(array(event["referenced_evidence_ids"])) != 0 {
		return fail("AUDIT_WORKSPACE_SOURCE_PROJECTION_INVALID")
	}
	if err := assertAllowedFields(metadata, []string{
		"workspace_revision", "workspace_source_id", "source_scope_id", "source_scope_revision",
		"scope_config_hash", "access_mode", "enabled",
	}); err != nil {
		return err
	}
	if intValue(metadata["workspace_revision"]) < 1 || stringValue(metadata["workspace_source_id"]) == "" ||
		stringValue(metadata["workspace_source_id"]) != stringValue(event["resource_id"]) ||
		stringValue(metadata["source_scope_id"]) == "" || intValue(metadata["source_scope_revision"]) < 1 ||
		stringValue(metadata["scope_config_hash"]) == "" ||
		(stringValue(metadata["access_mode"]) != "WORKSPACE_MANAGED" && stringValue(metadata["access_mode"]) != "SOURCE_ENFORCED") {
		return fail("AUDIT_WORKSPACE_SOURCE_PROJECTION_INVALID")
	}
	enabled, isBool := metadata["enabled"].(bool)
	if !isBool || enabled != (action == "workspace.source_added") {
		return fail("AUDIT_WORKSPACE_SOURCE_STATE_INVALID")
	}
	return nil
}

func validateAuditEvent(event, context map[string]any) error {
	return validateAuditEventAgainst(event, stringValue(context["organization_id"]), stringValue(context["previous_event_hash"]), intValue(context["expected_sequence"]))
}

func applyAuditEventMutation(event map[string]any, mutation string) error {
	switch mutation {
	case "", "NONE":
		return nil
	case "AUDIT_EVENT_BODY_TAMPER":
		object(event["metadata"])["policy_revision"] = "policy-tampered"
	default:
		return fail("UNKNOWN_AUDIT_EVENT_MUTATION", mutation)
	}
	return nil
}

func auditCheckpointContent(checkpoint map[string]any) map[string]any {
	content := cloneObject(checkpoint)
	delete(content, "checkpoint_hash")
	delete(content, "signature")
	return content
}

func auditCheckpointSigningObject(checkpoint map[string]any) map[string]any {
	signature := object(checkpoint["signature"])
	return map[string]any{
		"algorithm":       signature["algorithm"],
		"checkpoint_hash": checkpoint["checkpoint_hash"],
		"key_id":          signature["key_id"],
		"signed_at":       signature["signed_at"],
	}
}

func rehashAndSignAuditCheckpoint(checkpoint, context map[string]any) error {
	contentBytes, err := canonicalValue(auditCheckpointContent(checkpoint))
	if err != nil {
		return err
	}
	checkpoint["checkpoint_hash"] = sha256String(contentBytes)
	privateKey, _, keyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	signature := object(checkpoint["signature"])
	signature["key_id"] = keyID
	signingBytes, err := canonicalValue(auditCheckpointSigningObject(checkpoint))
	if err != nil {
		return err
	}
	signature["value_base64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signingBytes))
	return nil
}

func validateAuditCheckpoint(checkpoint, context map[string]any) error {
	if err := assertAllowedFields(checkpoint, []string{
		"schema_version", "organization_id", "checkpoint_sequence", "event_first_sequence", "event_last_sequence",
		"first_event_hash", "last_event_hash", "previous_checkpoint_hash", "created_at", "checkpoint_hash", "signature",
	}); err != nil {
		return err
	}
	if intValue(checkpoint["event_first_sequence"]) > intValue(checkpoint["event_last_sequence"]) {
		return fail("AUDIT_CHECKPOINT_RANGE_INVALID")
	}
	organizationID := stringValue(checkpoint["organization_id"])
	activeCount := 0
	var selectedKey map[string]any
	keyID := stringValue(object(checkpoint["signature"])["key_id"])
	for _, rawKey := range array(context["keys"]) {
		key := object(rawKey)
		if stringValue(key["organization_id"]) != organizationID || stringValue(key["purpose"]) != "AUDIT_CHECKPOINT" {
			continue
		}
		if stringValue(key["status"]) == "ACTIVE" {
			activeCount++
		}
		if stringValue(key["key_id"]) == keyID {
			selectedKey = key
		}
	}
	if activeCount > 1 {
		return fail("SIGNING_KEY_MULTIPLE_ACTIVE")
	}
	if selectedKey == nil {
		return fail("AUDIT_SIGNING_KEY_UNKNOWN")
	}
	status := stringValue(selectedKey["status"])
	if status == "REVOKED" {
		return fail("AUDIT_SIGNING_KEY_REVOKED")
	}
	if status != "ACTIVE" && status != "RETIRED" {
		return fail("AUDIT_SIGNING_KEY_INVALID")
	}
	signedAt, signedErr := time.Parse(time.RFC3339, stringValue(object(checkpoint["signature"])["signed_at"]))
	createdAt, createdErr := time.Parse(time.RFC3339, stringValue(checkpoint["created_at"]))
	notBefore, beforeErr := time.Parse(time.RFC3339, stringValue(selectedKey["not_before"]))
	signUntil, untilErr := time.Parse(time.RFC3339, stringValue(selectedKey["sign_until"]))
	if signedErr != nil || createdErr != nil || beforeErr != nil || untilErr != nil || signedAt.Before(notBefore) || signedAt.After(signUntil) {
		return fail("AUDIT_SIGNATURE_TIME_INVALID")
	}
	if !signedAt.Equal(createdAt) {
		return fail("AUDIT_CHECKPOINT_TIME_INVALID")
	}

	contentBytes, err := canonicalValue(auditCheckpointContent(checkpoint))
	if err != nil {
		return err
	}
	expectedHash := sha256String(contentBytes)
	if stringValue(checkpoint["checkpoint_hash"]) != expectedHash {
		return fail("AUDIT_CHECKPOINT_HASH_MISMATCH", expectedHash)
	}
	_, publicKey, trustedKeyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	if keyID != trustedKeyID {
		return fail("AUDIT_SIGNING_KEY_UNKNOWN")
	}
	signingBytes, err := canonicalValue(auditCheckpointSigningObject(checkpoint))
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(stringValue(object(checkpoint["signature"])["value_base64"]))
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signatureBytes) {
		expected := base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(privateSeed(context)), signingBytes))
		return fail("AUDIT_CHECKPOINT_SIGNATURE_INVALID", expected)
	}

	previous := object(context["previous_checkpoint"])
	zeroHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if previous == nil {
		if intValue(checkpoint["checkpoint_sequence"]) != 1 || intValue(checkpoint["event_first_sequence"]) != 1 || stringValue(checkpoint["previous_checkpoint_hash"]) != zeroHash {
			return fail("AUDIT_CHECKPOINT_CHAIN_MISMATCH")
		}
	} else if intValue(checkpoint["checkpoint_sequence"]) != intValue(previous["checkpoint_sequence"])+1 ||
		intValue(checkpoint["event_first_sequence"]) != intValue(previous["event_last_sequence"])+1 ||
		stringValue(checkpoint["previous_checkpoint_hash"]) != stringValue(previous["checkpoint_hash"]) {
		return fail("AUDIT_CHECKPOINT_CHAIN_MISMATCH")
	} else {
		previousCreatedAt, parseErr := time.Parse(time.RFC3339, stringValue(previous["created_at"]))
		if parseErr != nil || !createdAt.After(previousCreatedAt) {
			return fail("AUDIT_CHECKPOINT_TIME_INVALID")
		}
	}
	events := array(context["audit_events"])
	expectedCount := intValue(checkpoint["event_last_sequence"]) - intValue(checkpoint["event_first_sequence"]) + 1
	if len(events) != expectedCount {
		return fail("AUDIT_CHECKPOINT_EVENT_GAP")
	}
	if len(events) == 0 || intValue(object(events[0])["sequence"]) != intValue(checkpoint["event_first_sequence"]) ||
		intValue(object(events[len(events)-1])["sequence"]) != intValue(checkpoint["event_last_sequence"]) ||
		stringValue(object(events[0])["event_hash"]) != stringValue(checkpoint["first_event_hash"]) ||
		stringValue(object(events[len(events)-1])["event_hash"]) != stringValue(checkpoint["last_event_hash"]) {
		return fail("AUDIT_CHECKPOINT_EVENT_RANGE_MISMATCH")
	}
	previousEventHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if previous != nil {
		previousEventHash = stringValue(previous["last_event_hash"])
	}
	for index, rawEvent := range events {
		event := object(rawEvent)
		if intValue(event["sequence"]) != intValue(checkpoint["event_first_sequence"])+index || stringValue(event["previous_event_hash"]) != previousEventHash {
			return fail("AUDIT_CHECKPOINT_EVENT_GAP")
		}
		if err := validateAuditEventAgainst(event, organizationID, previousEventHash, intValue(checkpoint["event_first_sequence"])+index); err != nil {
			return err
		}
		previousEventHash = stringValue(event["event_hash"])
	}
	return nil
}

func privateSeed(context map[string]any) []byte {
	privateKey, _, _, err := decodeSeed(context)
	if err != nil {
		return nil
	}
	return privateKey.Seed()
}

func applyAuditCheckpointMutation(checkpoint, context map[string]any, mutation string) error {
	switch mutation {
	case "", "NONE":
		return nil
	case "CHECKPOINT_CHAIN_MISMATCH":
		checkpoint["previous_checkpoint_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		return rehashAndSignAuditCheckpoint(checkpoint, context)
	case "CHECKPOINT_EVENT_GAP":
		checkpoint["event_last_sequence"] = float64(3)
		return rehashAndSignAuditCheckpoint(checkpoint, context)
	case "CHECKPOINT_BACKDATED":
		object(checkpoint["signature"])["signed_at"] = "2026-07-14T12:29:59Z"
		return rehashAndSignAuditCheckpoint(checkpoint, context)
	case "KEY_RETIRED":
		object(array(context["keys"])[0])["status"] = "RETIRED"
	case "KEY_REVOKED":
		object(array(context["keys"])[0])["status"] = "REVOKED"
	case "MULTIPLE_ACTIVE_KEY":
		context["keys"] = append(array(context["keys"]), map[string]any{
			"organization_id": "org1", "purpose": "AUDIT_CHECKPOINT", "key_id": "audit-key-02", "status": "ACTIVE",
			"not_before": "2026-07-14T00:00:00Z", "sign_until": "2026-07-15T00:00:00Z",
		})
	}
	return nil
}
