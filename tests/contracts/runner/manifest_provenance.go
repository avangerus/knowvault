package contracts

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"time"
)

var authorityTimestampV1Pattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

const authorityTimestampV1Layout = "2006-01-02T15:04:05Z"

func parseAuthorityTimestampV1(value string) (time.Time, error) {
	if !authorityTimestampV1Pattern.MatchString(value) {
		return time.Time{}, fail("AUTHORITY_TIMESTAMP_INVALID", value)
	}
	parsed, err := time.Parse(authorityTimestampV1Layout, value)
	if err != nil || parsed.Format(authorityTimestampV1Layout) != value {
		return time.Time{}, fail("AUTHORITY_TIMESTAMP_INVALID", value)
	}
	return parsed, nil
}

func loadContextFixture(context map[string]any, field string) (map[string]any, error) {
	mode := stringValue(context["_active_answer_mode"])
	if mode != "" {
		modeOverrides := object(object(context["mode_fixture_overrides"])[mode])
		if field == "model_execution_plan_fixture" {
			if override := object(modeOverrides[field]); override != nil {
				return override, nil
			}
		}
		if field == "retrieval_context_fixture" {
			if override := object(modeOverrides[field]); override != nil {
				path := stringValue(context[field])
				base, _, err := loadObject(path)
				if err != nil {
					return nil, err
				}
				result := cloneObject(base)
				snapshot := object(result["authorization_snapshot"])
				snapshot["model_execution_plan_hash"] = override["model_execution_plan_hash"]
				snapshotHash, err := hashCanonical(snapshot)
				if err != nil {
					return nil, err
				}
				result["authorization_snapshot_hash"] = snapshotHash
				return result, nil
			}
		}
	}
	if override := object(context[field+"_override"]); override != nil {
		return override, nil
	}
	path := stringValue(context[field])
	if path == "" {
		return nil, fail("TRUSTED_CONTEXT_FIXTURE_MISSING", field)
	}
	value, _, err := loadObject(path)
	return value, err
}

func questionRunManifestProjection(manifest map[string]any) map[string]any {
	return map[string]any{
		"question_run_id":            manifest["question_run_id"],
		"organization_id":            manifest["organization_id"],
		"workspace_id":               manifest["workspace_id"],
		"workspace_revision":         manifest["workspace_revision"],
		"question_text":              manifest["question_text"],
		"question_hash":              manifest["question_hash"],
		"created_by":                 manifest["created_by"],
		"started_at":                 manifest["started_at"],
		"completed_at":               manifest["completed_at"],
		"supersedes_question_run_id": manifest["supersedes_question_run_id"],
	}
}

func validateQuestionRunProvenance(manifest, context map[string]any) error {
	trusted := object(context["question_run_context"])
	if trusted == nil || !canonicalObjectsEqual(questionRunManifestProjection(manifest), trusted) {
		return fail("QUESTION_RUN_PROVENANCE_MISMATCH")
	}
	if stringValue(context["corpus_captured_at"]) != stringValue(manifest["started_at"]) {
		return fail("CORPUS_CAPTURE_TIME_MISMATCH")
	}
	return nil
}

func principalSetHashInput(snapshot map[string]any) map[string]any {
	return map[string]any{
		"human_principal_id":         snapshot["human_principal_id"],
		"identity_provider_revision": snapshot["identity_provider_revision"],
		"session_revision":           snapshot["session_revision"],
		"digest_key_version":         snapshot["digest_key_version"],
		"effective_principals":       snapshot["effective_principals"],
	}
}

func principalTuple(principal map[string]any) string {
	return stringValue(principal["namespace"]) + "\x00" + stringValue(principal["type"]) + "\x00" + stringValue(principal["subject_digest"]) + "\x00" + stringValue(principal["revision"])
}

func validateAccessContextProvenance(context map[string]any) error {
	access := object(context["access_context"])
	snapshot := object(context["principal_set_snapshot"])
	if access == nil || snapshot == nil || stringValue(snapshot["status"]) != "RESOLVED" {
		return fail("PRINCIPAL_SET_SNAPSHOT_INVALID")
	}
	expectedHash, err := hashCanonical(principalSetHashInput(snapshot))
	if err != nil {
		return err
	}
	if stringValue(snapshot["content_hash"]) != expectedHash ||
		stringValue(access["principal_set_snapshot_id"]) != stringValue(snapshot["id"]) ||
		stringValue(access["principal_set_snapshot_hash"]) != expectedHash ||
		stringValue(access["principal_set_captured_at"]) != stringValue(snapshot["captured_at"]) ||
		stringValue(access["principal_set_expires_at"]) != stringValue(snapshot["expires_at"]) ||
		stringValue(access["human_principal_id"]) != stringValue(snapshot["human_principal_id"]) ||
		!canonicalArraysEqual(array(access["effective_principals"]), array(snapshot["effective_principals"])) {
		return fail("PRINCIPAL_SET_SNAPSHOT_MISMATCH")
	}
	last := ""
	for _, rawPrincipal := range array(access["effective_principals"]) {
		principal := object(rawPrincipal)
		if _, rawSubjectPresent := principal["subject"]; rawSubjectPresent || stringValue(principal["namespace"]) == "" ||
			!strings.HasPrefix(stringValue(principal["subject_digest"]), "hmac-sha256:k") {
			return fail("PRINCIPAL_SUBJECT_DISCLOSURE_OR_DIGEST_INVALID")
		}
		current := principalTuple(principal)
		if last != "" && current <= last {
			return fail("PRINCIPAL_SET_NOT_CANONICAL")
		}
		last = current
	}
	questionStarted, questionErr := time.Parse(time.RFC3339, stringValue(object(context["question_run_context"])["started_at"]))
	questionCompleted, completedErr := time.Parse(time.RFC3339, stringValue(object(context["question_run_context"])["completed_at"]))
	principalCaptured, capturedErr := time.Parse(time.RFC3339, stringValue(snapshot["captured_at"]))
	principalExpires, expiresErr := time.Parse(time.RFC3339, stringValue(snapshot["expires_at"]))
	if questionErr != nil || completedErr != nil || capturedErr != nil || expiresErr != nil || principalCaptured.After(questionStarted) || questionCompleted.Before(questionStarted) || !questionCompleted.Before(principalExpires) {
		return fail("PRINCIPAL_SET_SNAPSHOT_STALE")
	}
	return nil
}

func retrievalManifestProjection(retrieval map[string]any) map[string]any {
	return map[string]any{
		"pipeline_version":              retrieval["pipeline_version"],
		"pipeline_profile_hash":         retrieval["pipeline_profile_hash"],
		"model_execution_plan_hash":     retrieval["model_execution_plan_hash"],
		"authorization_snapshot_hash":   retrieval["authorization_snapshot_hash"],
		"authorized_candidate_set_hash": retrieval["authorized_candidate_set_hash"],
		"authorized_candidate_count":    retrieval["authorized_candidate_count"],
		"context_count":                 retrieval["context_count"],
		"truncated":                     retrieval["truncated"],
		"truncation_reason":             retrieval["truncation_reason"],
		"error_codes":                   retrieval["error_codes"],
	}
}

func retrievalSnapshotProjection(snapshot map[string]any) map[string]any {
	return map[string]any{
		"pipeline_version":              snapshot["pipeline_version"],
		"pipeline_profile_hash":         snapshot["pipeline_profile_hash"],
		"model_execution_plan_hash":     snapshot["model_execution_plan_hash"],
		"authorization_snapshot_hash":   nil,
		"authorized_candidate_set_hash": snapshot["authorized_candidate_set_hash"],
		"authorized_candidate_count":    snapshot["authorized_candidate_count"],
		"context_count":                 snapshot["context_count"],
		"truncated":                     snapshot["truncated"],
		"truncation_reason":             snapshot["truncation_reason"],
		"error_codes":                   snapshot["error_codes"],
	}
}

func retrievalBindingKey(scopeID string, revision int) string {
	return scopeID + "@" + strconvItoa(revision)
}

func retrievalMembershipKey(sourceObjectID, scopeID string, revision int) string {
	return sourceObjectID + "\x00" + retrievalBindingKey(scopeID, revision)
}

func retrievalACLPointerKey(sourceObjectID, sourceVersionID string) string {
	return sourceObjectID + "\x00" + sourceVersionID
}

func workspaceManagedWarningContract() map[string]any {
	return map[string]any{
		"schema_version": "workspace-managed-warning-contract-v1", "warning_version": "workspace-managed-risk-v1", "access_mode": "WORKSPACE_MANAGED",
		"risk_codes":           []any{"SOURCE_NATIVE_ACL_NOT_ENFORCED", "WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"},
		"acknowledgement_code": "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
	}
}

func workspaceManagedConfirmationHashInput(confirmation map[string]any) map[string]any {
	return map[string]any{
		"schema_version": confirmation["schema_version"], "confirmation_id": confirmation["confirmation_id"],
		"organization_id": confirmation["organization_id"], "workspace_id": confirmation["workspace_id"], "workspace_revision": confirmation["workspace_revision"],
		"workspace_configuration_hash": confirmation["workspace_configuration_hash"], "workspace_source_id": confirmation["workspace_source_id"],
		"source_scope_id": confirmation["source_scope_id"], "source_scope_revision": confirmation["source_scope_revision"], "scope_config_hash": confirmation["scope_config_hash"],
		"access_mode": confirmation["access_mode"], "confirmation_actor_grant_id": confirmation["confirmation_actor_grant_id"],
		"confirmation_actor_grant_revision": confirmation["confirmation_actor_grant_revision"], "confirmation_actor_grant_hash": confirmation["confirmation_actor_grant_hash"],
		"warning_version": confirmation["warning_version"], "warning_contract_hash": confirmation["warning_contract_hash"], "acknowledgement_code": confirmation["acknowledgement_code"],
		"confirmed_by": confirmation["confirmed_by"], "confirmed_at": confirmation["confirmed_at"], "policy_revision": confirmation["policy_revision"],
	}
}

func validateWorkspaceManagedConfirmation(manifest, retrievalContext, confirmation map[string]any) bool {
	if assertAllowedFields(confirmation, []string{
		"schema_version", "confirmation_id", "confirmation_hash", "organization_id", "workspace_id", "workspace_revision", "workspace_configuration_hash", "workspace_source_id",
		"source_scope_id", "source_scope_revision", "scope_config_hash", "access_mode", "confirmation_actor_grant_id", "confirmation_actor_grant_revision", "confirmation_actor_grant_hash",
		"warning_version", "warning_contract_hash", "acknowledgement_code", "confirmed_by", "confirmed_at", "policy_revision",
	}) != nil || stringValue(confirmation["schema_version"]) != "workspace-managed-confirmation-v1" || stringValue(confirmation["confirmation_id"]) == "" ||
		stringValue(confirmation["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(confirmation["workspace_id"]) != stringValue(manifest["workspace_id"]) ||
		intValue(confirmation["workspace_revision"]) != intValue(manifest["workspace_revision"]) || stringValue(confirmation["access_mode"]) != "WORKSPACE_MANAGED" {
		return false
	}
	expectedConfirmationHash, confirmationHashErr := hashCanonical(workspaceManagedConfirmationHashInput(confirmation))
	expectedWarningHash, warningHashErr := hashCanonical(workspaceManagedWarningContract())
	live := object(retrievalContext["live_workspace_revision"])
	if confirmationHashErr != nil || warningHashErr != nil || stringValue(confirmation["confirmation_hash"]) != expectedConfirmationHash ||
		stringValue(confirmation["workspace_configuration_hash"]) != stringValue(live["workspace_configuration_hash"]) ||
		stringValue(confirmation["warning_version"]) != "workspace-managed-risk-v1" || stringValue(confirmation["warning_contract_hash"]) != expectedWarningHash ||
		stringValue(confirmation["acknowledgement_code"]) != "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL" {
		return false
	}
	matches := 0
	for _, rawBinding := range array(live["bindings"]) {
		binding := object(rawBinding)
		if stringValue(binding["workspace_source_id"]) == stringValue(confirmation["workspace_source_id"]) &&
			stringValue(binding["source_scope_id"]) == stringValue(confirmation["source_scope_id"]) && intValue(binding["source_scope_revision"]) == intValue(confirmation["source_scope_revision"]) &&
			stringValue(binding["scope_config_hash"]) == stringValue(confirmation["scope_config_hash"]) && stringValue(binding["access_mode"]) == "WORKSPACE_MANAGED" && boolValue(binding["enabled"]) {
			matches++
		}
	}
	return matches == 1 && confirmationActorAuthorized(manifest, retrievalContext, confirmation)
}

func trustedRetrievalRecords(manifest, retrievalContext map[string]any) (map[string]map[string]any, map[string]map[string]any, map[string]map[string]any, map[string]map[string]any, map[string]map[string]any, error) {
	organizationID := stringValue(manifest["organization_id"])
	if err := validateConfirmationActorGrantInventory(manifest, retrievalContext); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	memberships := map[string]map[string]any{}
	for _, rawMembership := range array(retrievalContext["live_object_scope_memberships"]) {
		membership := object(rawMembership)
		if stringValue(membership["organization_id"]) != organizationID {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_OBJECT_SCOPE_MEMBERSHIP_MISMATCH")
		}
		key := retrievalMembershipKey(stringValue(membership["source_object_id"]), stringValue(membership["source_scope_id"]), intValue(membership["source_scope_revision"]))
		if memberships[key] != nil {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_MEMBERSHIP_DUPLICATE", key)
		}
		memberships[key] = membership
	}
	decisions := map[string]map[string]any{}
	for _, rawDecision := range array(retrievalContext["live_policy_decisions"]) {
		decision := object(rawDecision)
		if stringValue(decision["organization_id"]) != organizationID {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_POLICY_DECISION_MISMATCH")
		}
		id := stringValue(decision["policy_decision_id"])
		if decisions[id] != nil {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_POLICY_DECISION_DUPLICATE", id)
		}
		decisions[id] = decision
	}
	acls := map[string]map[string]any{}
	for _, rawACL := range array(retrievalContext["live_acl_snapshots"]) {
		acl := object(rawACL)
		if stringValue(acl["organization_id"]) != organizationID {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
		}
		id := stringValue(acl["acl_snapshot_id"])
		if acls[id] != nil {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_ACL_SNAPSHOT_DUPLICATE", id)
		}
		acls[id] = acl
	}
	confirmations := map[string]map[string]any{}
	liveConfirmationTuples := map[string]bool{}
	for _, rawConfirmation := range array(retrievalContext["live_workspace_managed_confirmations"]) {
		confirmation := object(rawConfirmation)
		if stringValue(confirmation["organization_id"]) != organizationID || !validateWorkspaceManagedConfirmation(manifest, retrievalContext, confirmation) {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		id := stringValue(confirmation["confirmation_id"])
		if confirmations[id] != nil {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_CONFIRMATION_DUPLICATE", id)
		}
		tuple := stringValue(confirmation["workspace_id"]) + "\x00" + strconvItoa(intValue(confirmation["workspace_revision"])) + "\x00" +
			stringValue(confirmation["workspace_configuration_hash"]) + "\x00" + stringValue(confirmation["workspace_source_id"]) + "\x00" +
			stringValue(confirmation["source_scope_id"]) + "\x00" + strconvItoa(intValue(confirmation["source_scope_revision"])) + "\x00" +
			stringValue(confirmation["scope_config_hash"]) + "\x00" + stringValue(confirmation["policy_revision"]) + "\x00" + stringValue(confirmation["warning_contract_hash"])
		if liveConfirmationTuples[tuple] {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		liveConfirmationTuples[tuple] = true
		confirmations[id] = confirmation
	}
	aclPointers := map[string]map[string]any{}
	for _, rawPointer := range array(retrievalContext["live_source_acl_pointers"]) {
		pointer := object(rawPointer)
		if stringValue(pointer["organization_id"]) != organizationID {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
		}
		key := retrievalACLPointerKey(stringValue(pointer["source_object_id"]), stringValue(pointer["source_version_id"]))
		if aclPointers[key] != nil {
			return nil, nil, nil, nil, nil, fail("RETRIEVAL_ACL_POINTER_DUPLICATE", key)
		}
		aclPointers[key] = pointer
	}
	return memberships, decisions, acls, confirmations, aclPointers, nil
}

func validateConfirmationActorGrantInventory(manifest, retrievalContext map[string]any) error {
	seenGrantRevisions := map[string]bool{}
	for _, rawGrant := range array(retrievalContext["confirmation_actor_grants"]) {
		grant := object(rawGrant)
		if assertAllowedFields(grant, []string{"schema_version", "grant_id", "revision", "organization_id", "workspace_id", "principal_id", "permission", "valid_from", "valid_until", "policy_revision", "granted_by", "granted_at", "grant_hash"}) != nil ||
			stringValue(grant["schema_version"]) != "workspace-source-confirmation-grant-v1" ||
			stringValue(grant["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(grant["workspace_id"]) != stringValue(manifest["workspace_id"]) ||
			stringValue(grant["grant_id"]) == "" || intValue(grant["revision"]) < 1 || stringValue(grant["grant_hash"]) == "" ||
			stringValue(grant["principal_id"]) == "" || stringValue(grant["permission"]) != "workspace.source.confirm" ||
			stringValue(grant["policy_revision"]) == "" || stringValue(grant["granted_by"]) == "" {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		expectedHash, hashErr := hashCanonical(confirmationActorGrantHashInput(grant))
		validFrom, fromErr := parseAuthorityTimestampV1(stringValue(grant["valid_from"]))
		validUntil, untilErr := parseAuthorityTimestampV1(stringValue(grant["valid_until"]))
		grantedAt, grantedErr := parseAuthorityTimestampV1(stringValue(grant["granted_at"]))
		grantID := stringValue(grant["grant_id"])
		grantRevisionKey := grantID + "\x00" + strconvItoa(intValue(grant["revision"]))
		if hashErr != nil || stringValue(grant["grant_hash"]) != expectedHash || fromErr != nil || untilErr != nil || !validUntil.After(validFrom) ||
			grantedErr != nil || grantedAt.After(validFrom) || seenGrantRevisions[grantRevisionKey] {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		seenGrantRevisions[grantRevisionKey] = true
	}
	return validateConfirmationRevocationInventories(manifest, retrievalContext)
}

func confirmationActorGrantHashInput(grant map[string]any) map[string]any {
	return map[string]any{
		"schema_version": grant["schema_version"], "grant_id": grant["grant_id"], "revision": grant["revision"],
		"organization_id": grant["organization_id"], "workspace_id": grant["workspace_id"],
		"principal_id": grant["principal_id"], "permission": grant["permission"],
		"valid_from": grant["valid_from"], "valid_until": grant["valid_until"], "policy_revision": grant["policy_revision"],
		"granted_by": grant["granted_by"], "granted_at": grant["granted_at"],
	}
}

func confirmationActorGrantRevocationHashInput(revocation map[string]any) map[string]any {
	return map[string]any{
		"schema_version": revocation["schema_version"], "revocation_id": revocation["revocation_id"], "organization_id": revocation["organization_id"],
		"grant_id": revocation["grant_id"], "grant_revision": revocation["grant_revision"], "grant_hash": revocation["grant_hash"],
		"revoked_by": revocation["revoked_by"], "revoked_at": revocation["revoked_at"], "reason_code": revocation["reason_code"], "policy_revision": revocation["policy_revision"],
	}
}

func workspaceManagedConfirmationRevocationHashInput(revocation map[string]any) map[string]any {
	return map[string]any{
		"schema_version": revocation["schema_version"], "revocation_id": revocation["revocation_id"], "organization_id": revocation["organization_id"],
		"confirmation_id": revocation["confirmation_id"], "confirmation_hash": revocation["confirmation_hash"],
		"revoked_by": revocation["revoked_by"], "revoked_at": revocation["revoked_at"], "reason_code": revocation["reason_code"], "policy_revision": revocation["policy_revision"],
	}
}

func validateConfirmationRevocationInventories(manifest, retrievalContext map[string]any) error {
	seen := map[string]bool{}
	seenParents := map[string]bool{}
	for _, rawRevocation := range array(retrievalContext["confirmation_actor_grant_revocations"]) {
		revocation := object(rawRevocation)
		if assertAllowedFields(revocation, []string{"schema_version", "revocation_id", "organization_id", "grant_id", "grant_revision", "grant_hash", "revoked_by", "revoked_at", "reason_code", "policy_revision", "revocation_hash"}) != nil ||
			stringValue(revocation["schema_version"]) != "workspace-source-confirmation-grant-revocation-v1" || stringValue(revocation["organization_id"]) != stringValue(manifest["organization_id"]) ||
			stringValue(revocation["revocation_id"]) == "" || stringValue(revocation["grant_id"]) == "" || intValue(revocation["grant_revision"]) < 1 || stringValue(revocation["grant_hash"]) == "" ||
			stringValue(revocation["revoked_by"]) == "" || stringValue(revocation["reason_code"]) != "AUTHORITY_REVOKED" || stringValue(revocation["policy_revision"]) == "" {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		expected, hashErr := hashCanonical(confirmationActorGrantRevocationHashInput(revocation))
		revokedAt, timeErr := parseAuthorityTimestampV1(stringValue(revocation["revoked_at"]))
		key := "grant\x00" + stringValue(revocation["revocation_id"])
		parentKey := "grant\x00" + stringValue(revocation["grant_id"]) + "\x00" + strconvItoa(intValue(revocation["grant_revision"])) + "\x00" + stringValue(revocation["grant_hash"])
		parents := 0
		var parentGrantedAt time.Time
		var parentGrantedErr error
		for _, rawGrant := range array(retrievalContext["confirmation_actor_grants"]) {
			grant := object(rawGrant)
			if stringValue(grant["grant_id"]) == stringValue(revocation["grant_id"]) && intValue(grant["revision"]) == intValue(revocation["grant_revision"]) &&
				stringValue(grant["grant_hash"]) == stringValue(revocation["grant_hash"]) {
				parents++
				parentGrantedAt, parentGrantedErr = parseAuthorityTimestampV1(stringValue(grant["granted_at"]))
			}
		}
		if hashErr != nil || timeErr != nil || stringValue(revocation["revocation_hash"]) != expected || seen[key] || seenParents[parentKey] || parents != 1 ||
			parentGrantedErr != nil || revokedAt.Before(parentGrantedAt) {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		seen[key] = true
		seenParents[parentKey] = true
	}
	for _, rawRevocation := range array(retrievalContext["workspace_managed_confirmation_revocations"]) {
		revocation := object(rawRevocation)
		if assertAllowedFields(revocation, []string{"schema_version", "revocation_id", "organization_id", "confirmation_id", "confirmation_hash", "revoked_by", "revoked_at", "reason_code", "policy_revision", "revocation_hash"}) != nil ||
			stringValue(revocation["schema_version"]) != "workspace-managed-confirmation-revocation-v1" || stringValue(revocation["organization_id"]) != stringValue(manifest["organization_id"]) ||
			stringValue(revocation["revocation_id"]) == "" || stringValue(revocation["confirmation_id"]) == "" || stringValue(revocation["confirmation_hash"]) == "" ||
			stringValue(revocation["revoked_by"]) == "" || stringValue(revocation["reason_code"]) != "ACCESS_REVOKED" || stringValue(revocation["policy_revision"]) == "" {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		expected, hashErr := hashCanonical(workspaceManagedConfirmationRevocationHashInput(revocation))
		revokedAt, timeErr := parseAuthorityTimestampV1(stringValue(revocation["revoked_at"]))
		key := "confirmation\x00" + stringValue(revocation["revocation_id"])
		parentKey := "confirmation\x00" + stringValue(revocation["confirmation_id"]) + "\x00" + stringValue(revocation["confirmation_hash"])
		parents := 0
		var parentConfirmedAt time.Time
		var parentConfirmedErr error
		for _, rawConfirmation := range array(retrievalContext["live_workspace_managed_confirmations"]) {
			confirmation := object(rawConfirmation)
			if stringValue(confirmation["confirmation_id"]) == stringValue(revocation["confirmation_id"]) &&
				stringValue(confirmation["confirmation_hash"]) == stringValue(revocation["confirmation_hash"]) {
				parents++
				parentConfirmedAt, parentConfirmedErr = parseAuthorityTimestampV1(stringValue(confirmation["confirmed_at"]))
			}
		}
		if hashErr != nil || timeErr != nil || stringValue(revocation["revocation_hash"]) != expected || seen[key] || seenParents[parentKey] || parents != 1 ||
			parentConfirmedErr != nil || revokedAt.Before(parentConfirmedAt) {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		seen[key] = true
		seenParents[parentKey] = true
	}
	return nil
}

func confirmationActorGrantIsRevoked(retrievalContext, confirmation map[string]any) bool {
	for _, rawRevocation := range array(retrievalContext["confirmation_actor_grant_revocations"]) {
		revocation := object(rawRevocation)
		if stringValue(revocation["grant_id"]) == stringValue(confirmation["confirmation_actor_grant_id"]) &&
			intValue(revocation["grant_revision"]) == intValue(confirmation["confirmation_actor_grant_revision"]) &&
			stringValue(revocation["grant_hash"]) == stringValue(confirmation["confirmation_actor_grant_hash"]) {
			return true
		}
	}
	return false
}

func workspaceManagedConfirmationIsRevoked(retrievalContext, confirmation map[string]any) bool {
	for _, rawRevocation := range array(retrievalContext["workspace_managed_confirmation_revocations"]) {
		revocation := object(rawRevocation)
		if stringValue(revocation["confirmation_id"]) == stringValue(confirmation["confirmation_id"]) &&
			stringValue(revocation["confirmation_hash"]) == stringValue(confirmation["confirmation_hash"]) {
			return true
		}
	}
	return false
}

func confirmationActorAuthorized(manifest, retrievalContext, confirmation map[string]any) bool {
	confirmedAt, confirmedErr := parseAuthorityTimestampV1(stringValue(confirmation["confirmed_at"]))
	if confirmedErr != nil || stringValue(confirmation["confirmed_by"]) == "" || stringValue(confirmation["confirmation_actor_grant_id"]) == "" ||
		intValue(confirmation["confirmation_actor_grant_revision"]) < 1 || stringValue(confirmation["confirmation_actor_grant_hash"]) == "" ||
		confirmationActorGrantIsRevoked(retrievalContext, confirmation) || workspaceManagedConfirmationIsRevoked(retrievalContext, confirmation) {
		return false
	}
	matches := 0
	for _, rawGrant := range array(retrievalContext["confirmation_actor_grants"]) {
		grant := object(rawGrant)
		if assertAllowedFields(grant, []string{"schema_version", "grant_id", "revision", "organization_id", "workspace_id", "principal_id", "permission", "valid_from", "valid_until", "policy_revision", "granted_by", "granted_at", "grant_hash"}) != nil {
			return false
		}
		validFrom, fromErr := parseAuthorityTimestampV1(stringValue(grant["valid_from"]))
		validUntil, untilErr := parseAuthorityTimestampV1(stringValue(grant["valid_until"]))
		grantedAt, grantedErr := parseAuthorityTimestampV1(stringValue(grant["granted_at"]))
		if stringValue(grant["grant_id"]) == stringValue(confirmation["confirmation_actor_grant_id"]) &&
			intValue(grant["revision"]) == intValue(confirmation["confirmation_actor_grant_revision"]) &&
			stringValue(grant["grant_hash"]) == stringValue(confirmation["confirmation_actor_grant_hash"]) &&
			stringValue(grant["organization_id"]) == stringValue(manifest["organization_id"]) &&
			stringValue(grant["workspace_id"]) == stringValue(manifest["workspace_id"]) &&
			stringValue(grant["principal_id"]) == stringValue(confirmation["confirmed_by"]) &&
			stringValue(grant["permission"]) == "workspace.source.confirm" && stringValue(grant["policy_revision"]) == stringValue(confirmation["policy_revision"]) &&
			fromErr == nil && untilErr == nil && grantedErr == nil && !grantedAt.After(validFrom) && !confirmedAt.Before(validFrom) && confirmedAt.Before(validUntil) {
			matches++
		}
	}
	return matches == 1
}

func validateLiveWorkspaceMembership(manifest, context, retrievalContext map[string]any) (map[string]any, error) {
	access := object(context["access_context"])
	var selected map[string]any
	for _, rawMembership := range array(retrievalContext["live_workspace_memberships"]) {
		membership := object(rawMembership)
		if stringValue(membership["organization_id"]) != stringValue(manifest["organization_id"]) {
			return nil, fail("RETRIEVAL_WORKSPACE_MEMBERSHIP_MISMATCH")
		}
		if stringValue(membership["workspace_id"]) == stringValue(manifest["workspace_id"]) &&
			stringValue(membership["human_principal_id"]) == stringValue(access["human_principal_id"]) {
			if selected != nil {
				return nil, fail("RETRIEVAL_WORKSPACE_MEMBERSHIP_DUPLICATE")
			}
			selected = membership
		}
	}
	permissions := stringSet(array(selected["permissions"]))
	if selected == nil || stringValue(selected["status"]) != "ACTIVE" || intValue(selected["workspace_revision"]) != intValue(manifest["workspace_revision"]) ||
		intValue(selected["membership_revision"]) != intValue(access["workspace_membership_revision"]) || stringValue(selected["role"]) != stringValue(access["workspace_role"]) ||
		!permissions["question.create"] || !permissions["evidence.read"] {
		return nil, fail("RETRIEVAL_WORKSPACE_MEMBERSHIP_MISMATCH")
	}
	return selected, nil
}

func validateRetrievalWorkspaceRevision(manifest, context, retrievalContext map[string]any) (map[string]map[string]any, error) {
	live := object(retrievalContext["live_workspace_revision"])
	if live == nil || stringValue(live["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(live["status"]) != "ACTIVE" || stringValue(live["workspace_id"]) != stringValue(manifest["workspace_id"]) ||
		intValue(live["workspace_revision"]) != intValue(manifest["workspace_revision"]) {
		return nil, fail("RETRIEVAL_WORKSPACE_REVISION_MISMATCH")
	}
	bindings := map[string]map[string]any{}
	for _, rawBinding := range array(live["bindings"]) {
		binding := object(rawBinding)
		key := retrievalBindingKey(stringValue(binding["source_scope_id"]), intValue(binding["source_scope_revision"]))
		if bindings[key] != nil || stringValue(binding["organization_id"]) != stringValue(manifest["organization_id"]) || !boolValue(binding["enabled"]) {
			return nil, fail("RETRIEVAL_WORKSPACE_BINDING_MISMATCH", key)
		}
		bindings[key] = binding
	}
	workspaceBindings := array(object(context["workspace_scope"])["bindings"])
	if len(bindings) != len(workspaceBindings) {
		return nil, fail("RETRIEVAL_WORKSPACE_BINDING_MISMATCH")
	}
	for _, rawBinding := range workspaceBindings {
		binding := object(rawBinding)
		key := retrievalBindingKey(stringValue(binding["source_scope_id"]), intValue(binding["source_scope_revision"]))
		liveBinding := bindings[key]
		config := object(object(context["scope_configs"])[key])
		if liveBinding == nil || boolValue(liveBinding["enabled"]) != boolValue(binding["enabled"]) ||
			stringValue(liveBinding["access_mode"]) != stringValue(config["access_mode"]) ||
			stringValue(liveBinding["scope_config_hash"]) != stringValue(binding["scope_config_hash"]) {
			return nil, fail("RETRIEVAL_WORKSPACE_BINDING_MISMATCH", key)
		}
	}
	return bindings, nil
}

func aclPrincipalIntersects(acl map[string]any, access map[string]any) bool {
	effective := map[string]bool{}
	for _, rawPrincipal := range array(access["effective_principals"]) {
		effective[principalTuple(object(rawPrincipal))] = true
	}
	for _, rawToken := range array(acl["principal_token_digests"]) {
		if effective[principalTuple(object(rawToken))] {
			return true
		}
	}
	return false
}

func aclSnapshotHashInput(acl map[string]any) map[string]any {
	return map[string]any{
		"status": acl["status"], "digest_key_version": acl["digest_key_version"],
		"principal_token_digests": acl["principal_token_digests"],
	}
}

func validateACLSnapshotProjection(acl map[string]any) error {
	if acl == nil || stringValue(acl["status"]) != "RESOLVED" || intValue(acl["digest_key_version"]) < 1 {
		return fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
	}
	last := ""
	for _, rawToken := range array(acl["principal_token_digests"]) {
		token := object(rawToken)
		if token == nil || stringValue(token["namespace"]) == "" || !strings.HasPrefix(stringValue(token["subject_digest"]), "hmac-sha256:k") {
			return fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
		}
		current := principalTuple(token)
		if last != "" && current <= last {
			return fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
		}
		last = current
	}
	expected, err := hashCanonical(aclSnapshotHashInput(acl))
	if err != nil {
		return err
	}
	if stringValue(acl["content_hash"]) != expected {
		return fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
	}
	return nil
}

type retrievalGrantPath struct {
	scopeID    string
	revision   int
	decisionID string
}

func grantPathLess(left, right retrievalGrantPath) bool {
	if left.scopeID != right.scopeID {
		return left.scopeID < right.scopeID
	}
	if left.revision != right.revision {
		return left.revision < right.revision
	}
	return left.decisionID < right.decisionID
}

func commonTrustedGrantPathValid(subject, manifest, context, workspaceMembership, binding, membership, decision map[string]any) bool {
	if binding == nil || membership == nil || decision == nil || stringValue(membership["state"]) != "ACTIVE" || !boolValue(binding["enabled"]) {
		return false
	}
	access := object(context["access_context"])
	if stringValue(binding["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(membership["organization_id"]) != stringValue(manifest["organization_id"]) ||
		stringValue(decision["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(decision["decision"]) != "ALLOW" || stringValue(decision["question_run_id"]) != stringValue(manifest["question_run_id"]) ||
		stringValue(decision["workspace_id"]) != stringValue(manifest["workspace_id"]) || intValue(decision["workspace_revision"]) != intValue(manifest["workspace_revision"]) ||
		stringValue(decision["source_object_id"]) != stringValue(subject["source_object_id"]) || stringValue(decision["source_scope_id"]) != stringValue(binding["source_scope_id"]) ||
		intValue(decision["source_scope_revision"]) != intValue(binding["source_scope_revision"]) || stringValue(decision["human_principal_id"]) != stringValue(access["human_principal_id"]) ||
		intValue(decision["workspace_membership_revision"]) != intValue(workspaceMembership["membership_revision"]) || stringValue(decision["principal_set_snapshot_id"]) != stringValue(access["principal_set_snapshot_id"]) ||
		stringValue(decision["principal_set_snapshot_hash"]) != stringValue(access["principal_set_snapshot_hash"]) || stringValue(decision["policy_revision"]) != stringValue(access["policy_revision"]) ||
		stringValue(decision["operation"]) != "evidence.read" {
		return false
	}
	authorizedAt, authorizedErr := time.Parse(time.RFC3339, stringValue(decision["decided_at"]))
	principalCaptured, capturedErr := time.Parse(time.RFC3339, stringValue(access["principal_set_captured_at"]))
	principalExpires, expiresErr := time.Parse(time.RFC3339, stringValue(access["principal_set_expires_at"]))
	questionStarted, startedErr := time.Parse(time.RFC3339, stringValue(manifest["started_at"]))
	questionCompleted, completedErr := time.Parse(time.RFC3339, stringValue(manifest["completed_at"]))
	return authorizedErr == nil && capturedErr == nil && expiresErr == nil && startedErr == nil && completedErr == nil &&
		!authorizedAt.Before(questionStarted) && !authorizedAt.After(questionCompleted) && !authorizedAt.Before(principalCaptured) && authorizedAt.Before(principalExpires)
}

func minimalTrustedGrantPath(subject, manifest, context, workspaceMembership map[string]any, bindings, memberships, decisions, acls, confirmations, aclPointers map[string]map[string]any) (retrievalGrantPath, bool) {
	var minimum retrievalGrantPath
	found := false
	for _, decision := range decisions {
		scopeID := stringValue(decision["source_scope_id"])
		revision := intValue(decision["source_scope_revision"])
		binding := bindings[retrievalBindingKey(scopeID, revision)]
		membership := memberships[retrievalMembershipKey(stringValue(subject["source_object_id"]), scopeID, revision)]
		if !commonTrustedGrantPathValid(subject, manifest, context, workspaceMembership, binding, membership, decision) {
			continue
		}
		valid := false
		if stringValue(binding["access_mode"]) == "WORKSPACE_MANAGED" {
			confirmation := confirmations[stringValue(decision["workspace_managed_confirmation_id"])]
			confirmedAt, timeErr := parseAuthorityTimestampV1(stringValue(confirmation["confirmed_at"]))
			questionStarted, startedErr := time.Parse(time.RFC3339, stringValue(manifest["started_at"]))
			valid = confirmation != nil && stringValue(confirmation["organization_id"]) == stringValue(manifest["organization_id"]) &&
				stringValue(binding["workspace_managed_confirmation_id"]) == stringValue(confirmation["confirmation_id"]) &&
				stringValue(confirmation["workspace_id"]) == stringValue(manifest["workspace_id"]) && intValue(confirmation["workspace_revision"]) == intValue(manifest["workspace_revision"]) &&
				stringValue(confirmation["source_scope_id"]) == scopeID && intValue(confirmation["source_scope_revision"]) == revision &&
				stringValue(confirmation["scope_config_hash"]) == stringValue(binding["scope_config_hash"]) && stringValue(confirmation["policy_revision"]) == stringValue(object(context["access_context"])["policy_revision"]) &&
				stringValue(confirmation["warning_version"]) == "workspace-managed-risk-v1" && timeErr == nil && startedErr == nil && !confirmedAt.After(questionStarted)
		} else if stringValue(binding["access_mode"]) == "SOURCE_ENFORCED" && decision["workspace_managed_confirmation_id"] == nil && binding["workspace_managed_confirmation_id"] == nil {
			pointer := aclPointers[retrievalACLPointerKey(stringValue(subject["source_object_id"]), stringValue(subject["source_version_id"]))]
			acl := acls[stringValue(pointer["acl_snapshot_id"])]
			resolvedAt, resolvedErr := time.Parse(time.RFC3339, stringValue(acl["resolved_at"]))
			expiresAt, expiresErr := time.Parse(time.RFC3339, stringValue(acl["expires_at"]))
			authorizedAt, authorizedErr := time.Parse(time.RFC3339, stringValue(decision["decided_at"]))
			valid = pointer != nil && acl != nil && validateACLSnapshotProjection(acl) == nil &&
				stringValue(pointer["organization_id"]) == stringValue(manifest["organization_id"]) && stringValue(acl["organization_id"]) == stringValue(manifest["organization_id"]) &&
				stringValue(acl["source_object_id"]) == stringValue(subject["source_object_id"]) && stringValue(acl["source_version_id"]) == stringValue(subject["source_version_id"]) &&
				intValue(acl["digest_key_version"]) == intValue(object(context["principal_set_snapshot"])["digest_key_version"]) && aclPrincipalIntersects(acl, object(context["access_context"])) &&
				resolvedErr == nil && expiresErr == nil && authorizedErr == nil && !authorizedAt.Before(resolvedAt) && authorizedAt.Before(expiresAt)
		}
		if !valid {
			continue
		}
		path := retrievalGrantPath{scopeID: scopeID, revision: revision, decisionID: stringValue(decision["policy_decision_id"])}
		if !found || grantPathLess(path, minimum) {
			minimum, found = path, true
		}
	}
	return minimum, found
}

func validateMinimalTrustedGrantPath(subject, manifest, context, workspaceMembership map[string]any, bindings, memberships, decisions, acls, confirmations, aclPointers map[string]map[string]any) error {
	minimum, found := minimalTrustedGrantPath(subject, manifest, context, workspaceMembership, bindings, memberships, decisions, acls, confirmations, aclPointers)
	grant := object(subject["grant"])
	selected := retrievalGrantPath{scopeID: stringValue(grant["source_scope_id"]), revision: intValue(grant["source_scope_revision"]), decisionID: stringValue(grant["policy_decision_id"])}
	if !found || selected != minimum {
		return fail("RETRIEVAL_GRANT_NOT_MINIMAL")
	}
	return nil
}

func validateTrustedRetrievalGrant(subject, manifest, context, workspaceMembership map[string]any, bindings, memberships, decisions, acls, confirmations, aclPointers map[string]map[string]any) error {
	grant := object(subject["grant"])
	if err := assertAllowedFields(grant, []string{
		"source_scope_id", "source_scope_revision", "access_mode", "membership_state", "workspace_membership_revision", "workspace_managed_confirmation_id", "policy_decision_id", "policy_decision",
		"principal_set_snapshot_id", "principal_set_snapshot_hash", "principal_set_captured_at", "principal_set_expires_at", "authorized_at",
		"acl_snapshot_id", "acl_snapshot_hash", "acl_snapshot_status", "acl_resolved_at", "acl_expires_at",
	}); err != nil {
		return fail("RETRIEVAL_GRANT_NOT_MINIMAL")
	}
	scopeID := stringValue(grant["source_scope_id"])
	scopeRevision := intValue(grant["source_scope_revision"])
	binding := bindings[retrievalBindingKey(scopeID, scopeRevision)]
	if binding == nil {
		return fail("RETRIEVAL_WORKSPACE_BINDING_MISMATCH")
	}
	if stringValue(grant["access_mode"]) != stringValue(binding["access_mode"]) {
		return fail("RETRIEVAL_ACCESS_MODE_MISMATCH")
	}
	membership := memberships[retrievalMembershipKey(stringValue(subject["source_object_id"]), scopeID, scopeRevision)]
	if membership == nil || stringValue(membership["state"]) != "ACTIVE" || stringValue(grant["membership_state"]) != "ACTIVE" {
		return fail("RETRIEVAL_OBJECT_SCOPE_MEMBERSHIP_MISMATCH")
	}
	access := object(context["access_context"])
	decision := decisions[stringValue(grant["policy_decision_id"])]
	if err := assertAllowedFields(decision, []string{
		"policy_decision_id", "organization_id", "question_run_id", "workspace_id", "workspace_revision", "workspace_membership_revision", "source_object_id",
		"source_scope_id", "source_scope_revision", "human_principal_id", "principal_set_snapshot_id", "principal_set_snapshot_hash",
		"workspace_managed_confirmation_id", "policy_revision", "operation", "decision", "decided_at",
	}); err != nil {
		return fail("RETRIEVAL_POLICY_DECISION_MISMATCH")
	}
	if decision == nil || stringValue(decision["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(decision["decision"]) != "ALLOW" || stringValue(grant["policy_decision"]) != "ALLOW" ||
		stringValue(decision["question_run_id"]) != stringValue(manifest["question_run_id"]) ||
		stringValue(decision["workspace_id"]) != stringValue(manifest["workspace_id"]) || intValue(decision["workspace_revision"]) != intValue(manifest["workspace_revision"]) ||
		stringValue(decision["source_object_id"]) != stringValue(subject["source_object_id"]) ||
		stringValue(decision["source_scope_id"]) != scopeID || intValue(decision["source_scope_revision"]) != scopeRevision ||
		stringValue(decision["human_principal_id"]) != stringValue(access["human_principal_id"]) ||
		intValue(decision["workspace_membership_revision"]) != intValue(workspaceMembership["membership_revision"]) || intValue(grant["workspace_membership_revision"]) != intValue(workspaceMembership["membership_revision"]) ||
		stringValue(decision["principal_set_snapshot_id"]) != stringValue(access["principal_set_snapshot_id"]) ||
		stringValue(decision["principal_set_snapshot_hash"]) != stringValue(access["principal_set_snapshot_hash"]) ||
		stringValue(decision["policy_revision"]) != stringValue(access["policy_revision"]) || stringValue(decision["operation"]) != "evidence.read" || stringValue(decision["decided_at"]) != stringValue(grant["authorized_at"]) ||
		stringValue(decision["workspace_managed_confirmation_id"]) != stringValue(grant["workspace_managed_confirmation_id"]) {
		return fail("RETRIEVAL_POLICY_DECISION_MISMATCH")
	}
	if stringValue(grant["principal_set_snapshot_id"]) != stringValue(access["principal_set_snapshot_id"]) ||
		stringValue(grant["principal_set_snapshot_hash"]) != stringValue(access["principal_set_snapshot_hash"]) ||
		stringValue(grant["principal_set_captured_at"]) != stringValue(access["principal_set_captured_at"]) ||
		stringValue(grant["principal_set_expires_at"]) != stringValue(access["principal_set_expires_at"]) {
		return fail("RETRIEVAL_PRINCIPAL_SET_STALE")
	}
	authorizedAt, authorizedErr := time.Parse(time.RFC3339, stringValue(grant["authorized_at"]))
	principalCaptured, capturedErr := time.Parse(time.RFC3339, stringValue(grant["principal_set_captured_at"]))
	principalExpires, expiresErr := time.Parse(time.RFC3339, stringValue(grant["principal_set_expires_at"]))
	questionStarted, startedErr := time.Parse(time.RFC3339, stringValue(manifest["started_at"]))
	questionCompleted, completedErr := time.Parse(time.RFC3339, stringValue(manifest["completed_at"]))
	if authorizedErr != nil || capturedErr != nil || expiresErr != nil || startedErr != nil || completedErr != nil ||
		authorizedAt.Before(questionStarted) || authorizedAt.After(questionCompleted) || authorizedAt.Before(principalCaptured) || !authorizedAt.Before(principalExpires) {
		return fail("RETRIEVAL_AUTHORIZATION_OUTSIDE_QUESTION_INTERVAL")
	}
	if stringValue(grant["access_mode"]) == "WORKSPACE_MANAGED" {
		for _, field := range []string{"acl_snapshot_id", "acl_snapshot_hash", "acl_snapshot_status", "acl_resolved_at", "acl_expires_at"} {
			if grant[field] != nil {
				return fail("WORKSPACE_MANAGED_ACL_FIELDS_FORBIDDEN")
			}
		}
		confirmation := confirmations[stringValue(grant["workspace_managed_confirmation_id"])]
		if err := assertAllowedFields(confirmation, []string{
			"schema_version", "confirmation_id", "confirmation_hash", "organization_id", "workspace_id", "workspace_revision", "workspace_configuration_hash", "workspace_source_id",
			"source_scope_id", "source_scope_revision", "scope_config_hash", "access_mode", "confirmation_actor_grant_id", "confirmation_actor_grant_revision", "confirmation_actor_grant_hash",
			"policy_revision", "warning_version", "warning_contract_hash", "acknowledgement_code", "confirmed_by", "confirmed_at",
		}); err != nil {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		if confirmation == nil || stringValue(confirmation["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(binding["workspace_managed_confirmation_id"]) != stringValue(grant["workspace_managed_confirmation_id"]) ||
			stringValue(confirmation["workspace_id"]) != stringValue(manifest["workspace_id"]) || intValue(confirmation["workspace_revision"]) != intValue(manifest["workspace_revision"]) ||
			stringValue(confirmation["source_scope_id"]) != scopeID || intValue(confirmation["source_scope_revision"]) != scopeRevision ||
			stringValue(confirmation["scope_config_hash"]) != stringValue(binding["scope_config_hash"]) || stringValue(confirmation["policy_revision"]) != stringValue(access["policy_revision"]) ||
			stringValue(confirmation["warning_version"]) != "workspace-managed-risk-v1" {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		confirmedAt, confirmedErr := parseAuthorityTimestampV1(stringValue(confirmation["confirmed_at"]))
		if confirmedErr != nil || confirmedAt.After(questionStarted) {
			return fail("RETRIEVAL_WORKSPACE_CONFIRMATION_MISMATCH")
		}
		return validateMinimalTrustedGrantPath(subject, manifest, context, workspaceMembership, bindings, memberships, decisions, acls, confirmations, aclPointers)
	}
	if grant["workspace_managed_confirmation_id"] != nil || decision["workspace_managed_confirmation_id"] != nil || binding["workspace_managed_confirmation_id"] != nil {
		return fail("SOURCE_ENFORCED_WORKSPACE_CONFIRMATION_FORBIDDEN")
	}
	pointer := aclPointers[retrievalACLPointerKey(stringValue(subject["source_object_id"]), stringValue(subject["source_version_id"]))]
	acl := acls[stringValue(grant["acl_snapshot_id"])]
	if acl == nil || stringValue(acl["status"]) != "RESOLVED" || stringValue(grant["acl_snapshot_hash"]) != stringValue(acl["content_hash"]) ||
		stringValue(grant["acl_snapshot_status"]) != stringValue(acl["status"]) || stringValue(grant["acl_resolved_at"]) != stringValue(acl["resolved_at"]) ||
		stringValue(grant["acl_expires_at"]) != stringValue(acl["expires_at"]) || pointer == nil || stringValue(pointer["acl_snapshot_id"]) != stringValue(acl["acl_snapshot_id"]) ||
		stringValue(pointer["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(acl["organization_id"]) != stringValue(manifest["organization_id"]) ||
		stringValue(acl["source_object_id"]) != stringValue(subject["source_object_id"]) || stringValue(acl["source_version_id"]) != stringValue(subject["source_version_id"]) ||
		intValue(acl["digest_key_version"]) != intValue(object(context["principal_set_snapshot"])["digest_key_version"]) {
		return fail("RETRIEVAL_ACL_SNAPSHOT_MISMATCH")
	}
	if err := validateACLSnapshotProjection(acl); err != nil {
		return err
	}
	if !aclPrincipalIntersects(acl, access) {
		return fail("RETRIEVAL_ACL_TOKEN_INTERSECTION_MISSING")
	}
	aclResolved, resolvedErr := time.Parse(time.RFC3339, stringValue(acl["resolved_at"]))
	aclExpires, aclExpiresErr := time.Parse(time.RFC3339, stringValue(acl["expires_at"]))
	if resolvedErr != nil || aclExpiresErr != nil || authorizedAt.Before(aclResolved) || !authorizedAt.Before(aclExpires) {
		return fail("RETRIEVAL_SOURCE_ACL_STALE")
	}
	return validateMinimalTrustedGrantPath(subject, manifest, context, workspaceMembership, bindings, memberships, decisions, acls, confirmations, aclPointers)
}

func validateRetrievalProvenance(manifest, context map[string]any, started, completed time.Time) (map[string]any, error) {
	retrieval := object(manifest["retrieval"])
	if err := assertAllowedFields(retrieval, []string{
		"pipeline_version", "pipeline_profile_hash", "model_execution_plan_hash", "authorization_snapshot_hash", "authorized_candidate_set_hash",
		"context_pack_hash", "authorized_candidate_count", "context_count", "truncated", "truncation_reason", "error_codes",
	}); err != nil {
		return nil, err
	}
	profileFixture, err := loadContextFixture(context, "retrieval_profile_fixture")
	if err != nil {
		return nil, err
	}
	profileHash, err := hashCanonical(profileFixture["profile"])
	if err != nil {
		return nil, err
	}
	if stringValue(profileFixture["profile_hash"]) != profileHash || stringValue(retrieval["pipeline_profile_hash"]) != profileHash ||
		stringValue(retrieval["pipeline_version"]) != stringValue(object(profileFixture["profile"])["profile_revision"]) {
		return nil, fail("RETRIEVAL_PROFILE_MISMATCH")
	}
	retrievalContext, err := loadContextFixture(context, "retrieval_context_fixture")
	if err != nil {
		return nil, err
	}
	bindings, err := validateRetrievalWorkspaceRevision(manifest, context, retrievalContext)
	if err != nil {
		return nil, err
	}
	workspaceMembership, err := validateLiveWorkspaceMembership(manifest, context, retrievalContext)
	if err != nil {
		return nil, err
	}
	memberships, decisions, acls, confirmations, aclPointers, err := trustedRetrievalRecords(manifest, retrievalContext)
	if err != nil {
		return nil, err
	}
	candidates := array(retrievalContext["authorized_candidate_set"])
	candidateIDs := map[string]bool{}
	for index, rawCandidate := range candidates {
		candidate := object(rawCandidate)
		if err := assertAllowedFields(candidate, []string{
			"ordinal", "source_object_id", "source_version_id", "extraction_id", "extraction_profile_hash", "source_version_content_hash",
			"evidence_fragment_id", "evidence_text_hash", "anchor_hash", "exact_context_base64", "exact_context_hash", "grant",
		}); err != nil {
			return nil, fail("AUTHORIZED_CANDIDATE_ARTIFACT_INVALID")
		}
		id := stringValue(candidate["evidence_fragment_id"])
		exactContext, decodeErr := base64.StdEncoding.DecodeString(stringValue(candidate["exact_context_base64"]))
		if intValue(candidate["ordinal"]) != index+1 || id == "" || candidateIDs[id] || decodeErr != nil || stringValue(candidate["exact_context_hash"]) != sha256String(exactContext) {
			return nil, fail("AUTHORIZED_CANDIDATE_ARTIFACT_INVALID", id)
		}
		candidateIDs[id] = true
		if err := validateTrustedRetrievalGrant(candidate, manifest, context, workspaceMembership, bindings, memberships, decisions, acls, confirmations, aclPointers); err != nil {
			return nil, err
		}
	}
	candidateHash, err := hashCanonical(candidates)
	if err != nil {
		return nil, err
	}
	snapshot := object(retrievalContext["authorization_snapshot"])
	snapshotHash, err := hashCanonical(snapshot)
	if err != nil {
		return nil, err
	}
	if stringValue(retrievalContext["authorization_snapshot_hash"]) != snapshotHash ||
		stringValue(retrieval["authorization_snapshot_hash"]) != snapshotHash ||
		stringValue(retrieval["authorized_candidate_set_hash"]) != candidateHash ||
		stringValue(snapshot["authorized_candidate_set_hash"]) != candidateHash ||
		intValue(retrieval["authorized_candidate_count"]) != len(candidates) || intValue(snapshot["authorized_candidate_count"]) != len(candidates) {
		return nil, fail("RETRIEVAL_PROVENANCE_MISMATCH")
	}
	if err := validateModelExecutionPlan(manifest, context, snapshot); err != nil {
		return nil, err
	}
	selectedRuns := map[string]map[string]any{}
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		if boolValue(run["selected_for_result"]) {
			selectedRuns[stringValue(run["purpose"])] = run
		}
	}
	embeddingRun := selectedRuns["EMBEDDING"]
	rerankingRun := selectedRuns["RERANKING"]
	if embeddingRun == nil || stringValue(snapshot["embedding_model_run_id"]) != stringValue(embeddingRun["model_run_id"]) ||
		stringValue(snapshot["embedding_output_hash"]) != stringValue(embeddingRun["output_hash"]) {
		return nil, fail("RETRIEVAL_EMBEDDING_RUN_BINDING_MISMATCH")
	}
	if len(candidates) == 0 {
		if snapshot["reranking_model_run_id"] != nil || snapshot["reranking_output_hash"] != nil || rerankingRun != nil {
			return nil, fail("RETRIEVAL_RERANKING_RUN_BINDING_MISMATCH")
		}
	} else if rerankingRun == nil || stringValue(snapshot["reranking_model_run_id"]) != stringValue(rerankingRun["model_run_id"]) ||
		stringValue(snapshot["reranking_output_hash"]) != stringValue(rerankingRun["output_hash"]) {
		return nil, fail("RETRIEVAL_RERANKING_RUN_BINDING_MISMATCH")
	}
	artifacts, err := loadContextFixture(context, "model_artifacts_fixture")
	if err != nil {
		return nil, err
	}
	if rerankingRun != nil {
		artifact := object(artifacts[stringValue(rerankingRun["model_run_id"])])
		if artifact == nil {
			return nil, fail("MODEL_ARTIFACT_MISSING", stringValue(rerankingRun["model_run_id"]))
		}
		outputHash, hashErr := hashCanonical(artifact["output"])
		if hashErr != nil || outputHash != stringValue(rerankingRun["output_hash"]) {
			return nil, fail("RETRIEVAL_RERANKING_OUTPUT_HASH_MISMATCH")
		}
		ordered := array(object(artifact["output"])["ordered_evidence_fragment_ids"])
		if len(ordered) != len(candidates) {
			return nil, fail("RETRIEVAL_RERANKING_PERMUTATION_MISMATCH")
		}
		seenOrdered := map[string]bool{}
		for _, rawID := range ordered {
			id := stringValue(rawID)
			if !candidateIDs[id] || seenOrdered[id] {
				return nil, fail("RETRIEVAL_RERANKING_PERMUTATION_MISMATCH")
			}
			seenOrdered[id] = true
		}
	}
	manifestProjection := retrievalManifestProjection(retrieval)
	snapshotProjection := retrievalSnapshotProjection(snapshot)
	snapshotProjection["authorization_snapshot_hash"] = snapshotHash
	if !canonicalObjectsEqual(manifestProjection, snapshotProjection) ||
		stringValue(snapshot["question_run_id"]) != stringValue(manifest["question_run_id"]) || stringValue(snapshot["pipeline_profile_hash"]) != profileHash {
		return nil, fail("RETRIEVAL_PROVENANCE_MISMATCH")
	}
	capturedAt, captureErr := time.Parse(time.RFC3339, stringValue(snapshot["captured_at"]))
	if captureErr != nil || capturedAt.Before(started) || capturedAt.After(completed) {
		return nil, fail("RETRIEVAL_AUTHORIZATION_OUTSIDE_QUESTION_INTERVAL")
	}
	entries := array(snapshot["entries"])
	contextPack := array(context["context_pack"])
	if len(entries) != len(contextPack) || intValue(snapshot["context_count"]) != len(entries) {
		return nil, fail("RETRIEVAL_CONTEXT_SET_MISMATCH")
	}
	liveHashes := object(retrievalContext["live_entry_hashes"])
	for index, rawEntry := range entries {
		entry := object(rawEntry)
		item := object(contextPack[index])
		if intValue(entry["ordinal"]) != index+1 ||
			stringValue(entry["evidence_fragment_id"]) != stringValue(item["evidence_fragment_id"]) ||
			stringValue(entry["source_version_id"]) != stringValue(item["source_version_id"]) ||
			stringValue(entry["extraction_id"]) != stringValue(item["extraction_id"]) ||
			stringValue(entry["extraction_profile_hash"]) != stringValue(item["extraction_profile_hash"]) ||
			stringValue(entry["source_version_content_hash"]) != stringValue(item["source_version_content_hash"]) ||
			stringValue(entry["evidence_text_hash"]) != stringValue(item["evidence_text_hash"]) ||
			stringValue(entry["anchor_hash"]) != stringValue(item["anchor_hash"]) ||
			stringValue(entry["exact_context_hash"]) != stringValue(item["exact_context_hash"]) {
			return nil, fail("RETRIEVAL_CONTEXT_SET_MISMATCH")
		}
		if !candidateIDs[stringValue(entry["evidence_fragment_id"])] {
			return nil, fail("RETRIEVAL_CONTEXT_NOT_AUTHORIZED_CANDIDATE")
		}
		if rerankingRun != nil {
			ordered := array(object(object(artifacts[stringValue(rerankingRun["model_run_id"])])["output"])["ordered_evidence_fragment_ids"])
			if index >= len(ordered) || stringValue(ordered[index]) != stringValue(entry["evidence_fragment_id"]) {
				return nil, fail("RETRIEVAL_CONTEXT_RERANK_SELECTION_MISMATCH")
			}
		}
		entryHash, hashErr := hashCanonical(entry)
		if hashErr != nil {
			return nil, hashErr
		}
		if stringValue(liveHashes[stringValue(entry["evidence_fragment_id"])]) != entryHash {
			return nil, fail("RETRIEVAL_LIVE_PROJECTION_DRIFT")
		}
		if stringValue(entry["source_version_state"]) != "CURRENT" || stringValue(entry["source_version_retention_state"]) != "ACTIVE" || !boolValue(entry["source_version_queryable"]) ||
			stringValue(entry["active_extraction_id"]) != stringValue(entry["extraction_id"]) || stringValue(entry["extraction_retention_state"]) != "ACTIVE" || !boolValue(entry["extraction_queryable"]) {
			return nil, fail("RETRIEVAL_NONACTIVE_EVIDENCE")
		}
		grant := object(entry["grant"])
		if err := validateTrustedRetrievalGrant(entry, manifest, context, workspaceMembership, bindings, memberships, decisions, acls, confirmations, aclPointers); err != nil {
			return nil, err
		}
		authorizedAt, authorizedErr := time.Parse(time.RFC3339, stringValue(grant["authorized_at"]))
		principalCaptured, capturedErr := time.Parse(time.RFC3339, stringValue(grant["principal_set_captured_at"]))
		principalExpires, expiresErr := time.Parse(time.RFC3339, stringValue(grant["principal_set_expires_at"]))
		if authorizedErr != nil || capturedErr != nil || expiresErr != nil || authorizedAt.Before(started) || authorizedAt.After(completed) || authorizedAt.Before(principalCaptured) || !authorizedAt.Before(principalExpires) {
			return nil, fail("RETRIEVAL_AUTHORIZATION_OUTSIDE_QUESTION_INTERVAL")
		}
		if stringValue(grant["access_mode"]) == "WORKSPACE_MANAGED" {
			for _, field := range []string{"acl_snapshot_id", "acl_snapshot_hash", "acl_snapshot_status", "acl_resolved_at", "acl_expires_at"} {
				if grant[field] != nil {
					return nil, fail("WORKSPACE_MANAGED_ACL_FIELDS_FORBIDDEN")
				}
			}
		} else {
			aclResolved, resolvedErr := time.Parse(time.RFC3339, stringValue(grant["acl_resolved_at"]))
			aclExpires, aclExpiresErr := time.Parse(time.RFC3339, stringValue(grant["acl_expires_at"]))
			if stringValue(grant["acl_snapshot_status"]) != "RESOLVED" || resolvedErr != nil || aclExpiresErr != nil || authorizedAt.Before(aclResolved) || !authorizedAt.Before(aclExpires) {
				return nil, fail("RETRIEVAL_SOURCE_ACL_STALE")
			}
		}
	}
	return snapshot, nil
}

func modelPlanProjection(manifest map[string]any) map[string]any {
	citationByNumber := map[int]string{}
	for _, rawCitation := range array(manifest["citations"]) {
		citation := object(rawCitation)
		citationByNumber[intValue(citation["citation_number"])] = stringValue(citation["evidence_fragment_id"])
	}
	claims := make([]any, 0, len(array(manifest["claims"])))
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		evidenceIDs := make([]any, 0)
		if stringValue(claim["kind"]) == "FACT" {
			for _, rawNumber := range array(claim["citation_numbers"]) {
				evidenceIDs = append(evidenceIDs, citationByNumber[intValue(rawNumber)])
			}
		}
		text := claim["text"]
		if stringValue(claim["kind"]) == "UNKNOWN" {
			text = nil
		}
		claims = append(claims, map[string]any{
			"claim_id": claim["claim_id"], "text": text, "kind": claim["kind"], "unknown_reason": claim["unknown_reason"],
			"evidence_ids": evidenceIDs, "supporting_claim_ids": claim["supporting_claim_ids"],
		})
	}
	return map[string]any{"schema_version": "1.4", "claims": claims, "sections": manifest["sections"]}
}

func contextModelItems(context map[string]any) ([]any, error) {
	result := make([]any, 0)
	for index, rawItem := range array(context["context_pack"]) {
		item := object(rawItem)
		bytes, err := base64.StdEncoding.DecodeString(stringValue(item["exact_context_base64"]))
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{
			"ordinal": float64(index + 1), "evidence_fragment_id": item["evidence_fragment_id"],
			"exact_context_text": string(bytes), "exact_context_hash": item["exact_context_hash"],
		})
	}
	return result, nil
}

func candidateModelItems(retrievalContext map[string]any) ([]any, error) {
	result := make([]any, 0)
	for index, rawItem := range array(retrievalContext["authorized_candidate_set"]) {
		item := object(rawItem)
		bytes, err := base64.StdEncoding.DecodeString(stringValue(item["exact_context_base64"]))
		if err != nil {
			return nil, err
		}
		result = append(result, map[string]any{
			"ordinal": float64(index + 1), "evidence_fragment_id": item["evidence_fragment_id"],
			"exact_context_text": string(bytes), "exact_context_hash": item["exact_context_hash"],
		})
	}
	return result, nil
}

func derivedRequiredModelPurposes(manifest, retrieval map[string]any) []string {
	result := []string{"EMBEDDING"}
	if intValue(retrieval["authorized_candidate_count"]) > 0 {
		result = append(result, "RERANKING")
	}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" && intValue(retrieval["context_count"]) > 0 {
		result = append(result, "GENERATION")
	}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" {
		for _, rawClaim := range array(manifest["claims"]) {
			kind := stringValue(object(rawClaim)["kind"])
			if kind == "FACT" || kind == "INFERENCE" {
				result = append(result, "VERIFICATION")
				break
			}
		}
	}
	return result
}

func configuredProfileHashes(manifest map[string]any) map[string]any {
	profiles := object(manifest["configured_profiles"])
	result := map[string]any{
		"EMBEDDING": object(profiles["embedding"])["profile_hash"],
		"RERANKING": object(profiles["reranking"])["profile_hash"],
	}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" {
		result["GENERATION"] = object(profiles["generation"])["profile_hash"]
		result["VERIFICATION"] = object(profiles["verification"])["profile_hash"]
	}
	return result
}

func validateModelExecutionPlan(manifest, context, retrievalSnapshot map[string]any) error {
	plan, err := loadContextFixture(context, "model_execution_plan_fixture")
	if err != nil {
		return err
	}
	planHash, err := hashCanonical(plan)
	if err != nil {
		return err
	}
	if stringValue(object(manifest["retrieval"])["model_execution_plan_hash"]) != planHash ||
		stringValue(retrievalSnapshot["model_execution_plan_hash"]) != planHash {
		return fail("MODEL_EXECUTION_PLAN_HASH_MISMATCH")
	}
	if err := assertAllowedFields(plan, []string{"schema_version", "question_run_id", "created_at", "configured_profile_hashes", "planned_purposes", "selected_run_ids", "attempts"}); err != nil {
		return fail("MODEL_EXECUTION_PLAN_MISMATCH")
	}
	if stringValue(plan["schema_version"]) != "model-execution-plan-v1" || stringValue(plan["question_run_id"]) != stringValue(manifest["question_run_id"]) {
		return fail("MODEL_EXECUTION_PLAN_MISMATCH")
	}
	planCreated, createdErr := time.Parse(time.RFC3339, stringValue(plan["created_at"]))
	questionStarted, startedErr := time.Parse(time.RFC3339, stringValue(manifest["started_at"]))
	questionCompleted, completedErr := time.Parse(time.RFC3339, stringValue(manifest["completed_at"]))
	if createdErr != nil || startedErr != nil || completedErr != nil || planCreated.Before(questionStarted) || planCreated.After(questionCompleted) {
		return fail("MODEL_EXECUTION_PLAN_TIME_INVALID")
	}
	requiredPurposes := derivedRequiredModelPurposes(manifest, retrievalSnapshot)
	expectedPurposeValues := make([]any, len(requiredPurposes))
	for index, purpose := range requiredPurposes {
		expectedPurposeValues[index] = purpose
	}
	if !canonicalArraysEqual(array(plan["planned_purposes"]), expectedPurposeValues) {
		return fail("MODEL_EXECUTION_PLAN_REQUIRED_PURPOSE_MISMATCH")
	}
	plannedPurposes := stringSet(array(plan["planned_purposes"]))
	profileHashes := object(plan["configured_profile_hashes"])
	expectedProfileHashes := configuredProfileHashes(manifest)
	profileHashPurposes := make([]string, 0, len(expectedProfileHashes))
	for purpose := range expectedProfileHashes {
		profileHashPurposes = append(profileHashPurposes, purpose)
	}
	sort.Strings(profileHashPurposes)
	if err := assertAllowedFields(profileHashes, profileHashPurposes); err != nil || !canonicalObjectsEqual(profileHashes, expectedProfileHashes) {
		return fail("MODEL_EXECUTION_PLAN_PROFILE_HASH_MISMATCH")
	}
	selectedRunIDs := object(plan["selected_run_ids"])
	if err := assertAllowedFields(selectedRunIDs, requiredPurposes); err != nil || len(selectedRunIDs) != len(requiredPurposes) {
		return fail("MODEL_EXECUTION_PLAN_SELECTED_RUN_MISMATCH")
	}
	plannedAttempts := array(plan["attempts"])
	runs := array(manifest["model_runs"])
	if len(plannedPurposes) != len(array(plan["planned_purposes"])) || len(plannedAttempts) != len(runs) {
		return fail("MODEL_EXECUTION_PLAN_MISMATCH")
	}
	purposeIndex := map[string]int{}
	for index, purpose := range requiredPurposes {
		purposeIndex[purpose] = index
	}
	lastPhase := -1
	nextAttempt := map[string]int{}
	selectedCounts := map[string]int{}
	for index, rawRun := range runs {
		run := object(rawRun)
		attempt := object(plannedAttempts[index])
		if err := assertAllowedFields(attempt, []string{"model_run_id", "purpose", "attempt", "selected_for_result"}); err != nil {
			return fail("MODEL_EXECUTION_PLAN_MISMATCH")
		}
		runStarted, runStartErr := time.Parse(time.RFC3339, stringValue(run["started_at"]))
		if runStartErr != nil || runStarted.Before(questionStarted) || runStarted.After(questionCompleted) {
			return fail("MODEL_RUN_OUTSIDE_QUESTION_INTERVAL", stringValue(run["model_run_id"]))
		}
		if !planCreated.Before(runStarted) {
			return fail("MODEL_EXECUTION_PLAN_TIME_INVALID")
		}
		purpose := stringValue(run["purpose"])
		phase, required := purposeIndex[purpose]
		if !required || phase < lastPhase {
			return fail("MODEL_EXECUTION_PLAN_PHASE_ORDER_INVALID", purpose)
		}
		lastPhase = phase
		nextAttempt[purpose]++
		if intValue(run["attempt"]) != nextAttempt[purpose] {
			return fail("MODEL_EXECUTION_PLAN_ATTEMPT_GAP", purpose)
		}
		if stringValue(run["profile_hash"]) != stringValue(profileHashes[purpose]) {
			return fail("MODEL_EXECUTION_PLAN_PROFILE_HASH_MISMATCH", purpose)
		}
		if !plannedPurposes[purpose] || stringValue(attempt["model_run_id"]) != stringValue(run["model_run_id"]) ||
			stringValue(attempt["purpose"]) != stringValue(run["purpose"]) || intValue(attempt["attempt"]) != intValue(run["attempt"]) ||
			boolValue(attempt["selected_for_result"]) != boolValue(run["selected_for_result"]) {
			return fail("MODEL_EXECUTION_PLAN_MISMATCH", stringValue(run["model_run_id"]))
		}
		if boolValue(run["selected_for_result"]) {
			selectedCounts[purpose]++
			if stringValue(selectedRunIDs[purpose]) != stringValue(run["model_run_id"]) || stringValue(run["outcome"]) != "SUCCEEDED" {
				return fail("MODEL_EXECUTION_PLAN_SELECTED_RUN_MISMATCH", purpose)
			}
		}
	}
	for _, purpose := range requiredPurposes {
		if selectedCounts[purpose] != 1 || stringValue(selectedRunIDs[purpose]) == "" {
			return fail("MODEL_EXECUTION_PLAN_SELECTED_RUN_MISMATCH", purpose)
		}
	}
	return nil
}

func validateConfiguredModelProfileDefinitions(manifest, context map[string]any) error {
	definitions, err := loadContextFixture(context, "model_profile_definitions_fixture")
	if err != nil {
		return err
	}
	profiles := object(manifest["configured_profiles"])
	profileNames := []string{"embedding", "reranking"}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" {
		profileNames = append(profileNames, "generation", "verification")
	}
	for _, name := range profileNames {
		profile := object(profiles[name])
		definition := object(definitions[stringValue(profile["purpose"])])
		profileHash, hashErr := hashCanonical(definition)
		if hashErr != nil {
			return hashErr
		}
		if definition == nil || stringValue(profile["profile_hash"]) != profileHash ||
			stringValue(profile["model_id"]) != stringValue(definition["model_id"]) ||
			stringValue(profile["model_revision"]) != stringValue(definition["model_revision"]) ||
			stringValue(profile["artifact_hash"]) != stringValue(definition["model_artifact_hash"]) ||
			stringValue(profile["profile_revision"]) != stringValue(definition["profile_revision"]) ||
			stringValue(profile["prompt_version"]) != stringValue(definition["prompt_version"]) {
			return fail("MODEL_PROFILE_HASH_MISMATCH", stringValue(profile["purpose"]))
		}
	}
	return nil
}

func validateModelArtifactProvenance(manifest, context, retrievalSnapshot map[string]any, started, completed time.Time) error {
	if err := validateConfiguredModelProfileDefinitions(manifest, context); err != nil {
		return err
	}
	profiles := object(manifest["configured_profiles"])
	artifacts, err := loadContextFixture(context, "model_artifacts_fixture")
	if err != nil {
		return err
	}
	modelContext, err := contextModelItems(context)
	if err != nil {
		return err
	}
	retrievalContext, err := loadContextFixture(context, "retrieval_context_fixture")
	if err != nil {
		return err
	}
	rerankingContext, err := candidateModelItems(retrievalContext)
	if err != nil {
		return err
	}
	if err := validateModelExecutionPlan(manifest, context, retrievalSnapshot); err != nil {
		return err
	}
	startsByPurpose := map[string][]time.Time{}
	endsByPurpose := map[string][]time.Time{}
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		id := stringValue(run["model_run_id"])
		artifact := object(artifacts[id])
		if artifact == nil {
			return fail("MODEL_ARTIFACT_MISSING", id)
		}
		inputHash, hashErr := hashCanonical(artifact["input"])
		if hashErr != nil {
			return hashErr
		}
		outputHash, hashErr := hashCanonical(artifact["output"])
		if hashErr != nil {
			return hashErr
		}
		if stringValue(run["input_hash"]) != inputHash || stringValue(run["output_hash"]) != outputHash {
			return fail("MODEL_ARTIFACT_HASH_MISMATCH", id)
		}
		purpose := stringValue(run["purpose"])
		profile := object(profiles[strings.ToLower(purpose)])
		var expectedInput map[string]any
		switch purpose {
		case "EMBEDDING":
			expectedInput = map[string]any{"schema_version": "embedding-input-v1", "profile_revision": profile["profile_revision"], "profile_hash": profile["profile_hash"], "question_text": manifest["question_text"], "question_hash": manifest["question_hash"]}
		case "RERANKING":
			expectedInput = map[string]any{"schema_version": "reranking-input-v1", "profile_revision": profile["profile_revision"], "profile_hash": profile["profile_hash"], "question_text": manifest["question_text"], "question_hash": manifest["question_hash"], "authorized_candidate_set_hash": retrievalSnapshot["authorized_candidate_set_hash"], "candidates": rerankingContext}
		case "GENERATION":
			expectedInput = map[string]any{"schema_version": "generation-input-v1", "profile_revision": profile["profile_revision"], "profile_hash": profile["profile_hash"], "prompt_version": profile["prompt_version"], "question_text": manifest["question_text"], "question_hash": manifest["question_hash"], "context_pack_hash": object(manifest["retrieval"])["context_pack_hash"], "corpus_status": object(manifest["status"])["corpus"], "context": modelContext}
		}
		if expectedInput != nil && !canonicalObjectsEqual(object(artifact["input"]), expectedInput) {
			return fail("MODEL_RUN_INPUT_PROVENANCE_MISMATCH", purpose)
		}
		if purpose == "GENERATION" && !canonicalObjectsEqual(object(artifact["output"]), modelPlanProjection(manifest)) {
			return fail("MODEL_GENERATION_PLAN_DRIFT")
		}
		runStarted, startErr := time.Parse(time.RFC3339, stringValue(run["started_at"]))
		runCompleted, completedErr := time.Parse(time.RFC3339, stringValue(run["completed_at"]))
		if startErr != nil || completedErr != nil || runStarted.Before(started) || runCompleted.After(completed) || runCompleted.Before(runStarted) {
			return fail("MODEL_RUN_OUTSIDE_QUESTION_INTERVAL", id)
		}
		startsByPurpose[purpose] = append(startsByPurpose[purpose], runStarted)
		endsByPurpose[purpose] = append(endsByPurpose[purpose], runCompleted)
	}
	capturedAt, _ := time.Parse(time.RFC3339, stringValue(retrievalSnapshot["captured_at"]))
	for _, embeddingEnd := range endsByPurpose["EMBEDDING"] {
		if embeddingEnd.After(capturedAt) {
			return fail("MODEL_EMBEDDING_AFTER_RETRIEVAL_CAPTURE")
		}
	}
	for _, rerankingEnd := range endsByPurpose["RERANKING"] {
		if rerankingEnd.After(capturedAt) {
			return fail("MODEL_RERANKING_AFTER_RETRIEVAL_CAPTURE")
		}
	}
	for _, generationStart := range startsByPurpose["GENERATION"] {
		if generationStart.Before(capturedAt) {
			return fail("MODEL_GENERATION_BEFORE_RETRIEVAL_CAPTURE")
		}
	}
	for _, verificationStart := range startsByPurpose["VERIFICATION"] {
		for _, generationEnd := range endsByPurpose["GENERATION"] {
			if verificationStart.Before(generationEnd) {
				return fail("MODEL_VERIFICATION_ORDER_INVALID")
			}
		}
	}
	return nil
}

func verificationInputFromRecord(record map[string]any) map[string]any {
	return map[string]any{
		"claim_id": record["claim_id"], "kind": record["kind"], "claim_text_hash": record["claim_text_hash"],
		"evidence": record["evidence"], "supporting_claims": record["supporting_claims"],
	}
}

func validateDeterministicValidations(manifest, context map[string]any, started, completed time.Time) error {
	trusted, err := loadContextFixture(context, "numeric_validations_fixture")
	if err != nil {
		return err
	}
	claimByID := map[string]map[string]any{}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		claimByID[stringValue(claim["claim_id"])] = claim
	}
	verificationByID := map[string]map[string]any{}
	for _, rawRecord := range array(manifest["claim_verifications"]) {
		record := object(rawRecord)
		verificationByID[stringValue(record["claim_id"])] = record
	}
	actualByID := map[string]map[string]any{}
	for _, rawRecord := range array(manifest["deterministic_validations"]) {
		record := object(rawRecord)
		id := stringValue(record["claim_id"])
		if actualByID[id] != nil {
			return fail("DETERMINISTIC_VALIDATION_DUPLICATE", id)
		}
		actualByID[id] = record
	}
	for id, claim := range claimByID {
		if stringValue(claim["kind"]) == "UNKNOWN" {
			if actualByID[id] != nil {
				return fail("UNKNOWN_DETERMINISTIC_VALIDATION_FORBIDDEN", id)
			}
			continue
		}
		record := actualByID[id]
		verification := verificationByID[id]
		trustedRecord := object(trusted[id])
		output := object(trustedRecord["output"])
		if record == nil || verification == nil || trustedRecord == nil || stringValue(record["validator_version"]) != "numeric-validator-v1" ||
			stringValue(record["validation_input_hash"]) != stringValue(verification["verification_input_hash"]) ||
			stringValue(output["validation_input_hash"]) != stringValue(record["validation_input_hash"]) || stringValue(output["outcome"]) != "PASSED" {
			return fail("DETERMINISTIC_VALIDATION_MISMATCH", id)
		}
		outputHash, hashErr := hashCanonical(output)
		if hashErr != nil {
			return hashErr
		}
		if stringValue(record["output_hash"]) != outputHash {
			return fail("DETERMINISTIC_VALIDATION_OUTPUT_HASH_MISMATCH", id)
		}
		validatedAt, timeErr := time.Parse(time.RFC3339, stringValue(trustedRecord["validated_at"]))
		if timeErr != nil || validatedAt.Before(started) || validatedAt.After(completed) {
			return fail("DETERMINISTIC_VALIDATION_OUTSIDE_QUESTION_INTERVAL", id)
		}
		allowedCitationNumbers := map[int]bool{}
		directSupportingFacts := make([]any, 0)
		if stringValue(claim["kind"]) == "FACT" {
			for _, rawNumber := range array(claim["citation_numbers"]) {
				allowedCitationNumbers[intValue(rawNumber)] = true
			}
		} else if stringValue(claim["kind"]) == "INFERENCE" {
			for _, rawSupportID := range array(claim["supporting_claim_ids"]) {
				supportID := stringValue(rawSupportID)
				supportClaim := claimByID[supportID]
				supportRecord := actualByID[supportID]
				trustedSupport := object(object(trusted[supportID])["output"])
				outcome := "FAILED"
				if supportClaim != nil && supportRecord != nil && trustedSupport != nil && stringValue(supportClaim["kind"]) == "FACT" &&
					stringValue(supportRecord["outcome"]) == "PASSED" && stringValue(trustedSupport["outcome"]) == "PASSED" {
					outcome = "PASSED"
				}
				citationNumbers := make([]any, 0)
				if supportClaim != nil {
					for _, rawNumber := range array(supportClaim["citation_numbers"]) {
						number := intValue(rawNumber)
						allowedCitationNumbers[number] = true
						citationNumbers = append(citationNumbers, float64(number))
					}
				}
				supportText := ""
				supportTextHash := ""
				if supportClaim != nil {
					supportText = canonicalTextV1(stringValue(supportClaim["text"]))
					supportTextHash = sha256String([]byte(supportText))
				}
				supportOutputHash := ""
				if supportRecord != nil {
					supportOutputHash = stringValue(supportRecord["output_hash"])
				}
				directSupportingFacts = append(directSupportingFacts, map[string]any{
					"claim_id": supportID, "kind": "FACT", "deterministic_outcome": outcome, "citation_numbers": citationNumbers,
					"claim_text": supportText, "claim_text_hash": supportTextHash,
					"numeric_output": trustedSupport, "numeric_output_hash": supportOutputHash,
				})
			}
		}
		citations := make([]any, 0)
		for _, rawCitation := range array(manifest["citations"]) {
			citation := object(rawCitation)
			if allowedCitationNumbers[intValue(citation["citation_number"])] {
				citations = append(citations, map[string]any{"citation_number": citation["citation_number"], "cited_excerpt": citation["cited_excerpt"]})
			}
		}
		numericContext := map[string]any{
			"claim": claim, "verification_input": verificationInputFromRecord(verification), "citations": citations,
			"direct_supporting_facts": directSupportingFacts,
		}
		if err := validateNumericOutput(output, numericContext); err != nil {
			return err
		}
	}
	if len(actualByID) != len(verificationByID) {
		return fail("DETERMINISTIC_VALIDATION_SET_MISMATCH")
	}
	return nil
}

func validateUnknownRendering(manifest map[string]any) error {
	fixed := map[string]string{
		"NO_RELEVANT_EVIDENCE": "\u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e \u0434\u0430\u043d\u043d\u044b\u0445, \u043f\u043e\u0437\u0432\u043e\u043b\u044f\u044e\u0449\u0438\u0445 \u043e\u0442\u0432\u0435\u0442\u0438\u0442\u044c \u043d\u0430 \u0432\u043e\u043f\u0440\u043e\u0441.",
		"INSUFFICIENT_SUPPORT": "\u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0439 \u0434\u043b\u044f \u043d\u0430\u0434\u0451\u0436\u043d\u043e\u0433\u043e \u043e\u0442\u0432\u0435\u0442\u0430.",
		"CONFLICTING_EVIDENCE": "\u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438 \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0442 \u043f\u0440\u043e\u0442\u0438\u0432\u043e\u0440\u0435\u0447\u0438\u0432\u044b\u0435 \u0441\u0432\u0435\u0434\u0435\u043d\u0438\u044f; \u043e\u0434\u043d\u043e\u0437\u043d\u0430\u0447\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442 \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d.",
	}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		kind := stringValue(claim["kind"])
		if kind == "UNKNOWN" {
			if stringValue(claim["text"]) != fixed[stringValue(claim["unknown_reason"])] {
				return fail("UNKNOWN_RENDERED_TEXT_MISMATCH")
			}
		} else if claim["unknown_reason"] != nil {
			return fail("KNOWN_CLAIM_UNKNOWN_REASON_FORBIDDEN")
		}
	}
	return nil
}
