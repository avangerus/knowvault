package contracts

import (
	"strings"
	"unicode"
)

func validateOverlappingScopesScenario(value map[string]any) error {
	discoveries := array(value["discoveries"])
	if len(discoveries) != 2 {
		return fail("OVERLAP_MEMBERSHIP_COUNT_INVALID")
	}
	seen := map[string]bool{}
	for _, raw := range discoveries {
		discovery := object(raw)
		key := stringValue(discovery["source_scope_id"]) + ":" + strconvItoa(intValue(discovery["source_scope_revision"]))
		if seen[key] {
			return fail("OVERLAP_MEMBERSHIP_DUPLICATE")
		}
		seen[key] = true
	}
	expected := object(value["expected"])
	if intValue(expected["source_object_count"]) != 1 || intValue(expected["active_scope_memberships"]) != 2 || !boolValue(expected["removing_scope_projects_keeps_scope_audit_queryable"]) {
		return fail("OVERLAP_OBJECT_REUSE_INVALID")
	}
	if intValue(expected["source_version_count"]) != 1 {
		return fail("OVERLAP_SOURCE_VERSION_REUSE_INVALID")
	}
	if intValue(expected["evidence_set_count"]) != 1 {
		return fail("OVERLAP_EVIDENCE_REUSE_INVALID")
	}
	if intValue(expected["vector_set_count"]) != 1 {
		return fail("OVERLAP_VECTOR_REUSE_INVALID")
	}
	if !boolValue(expected["grant_path_must_match_workspace_binding"]) {
		return fail("OVERLAP_GRANT_PATH_INVALID")
	}
	return nil
}

func validateMembershipRemovalScenario(value map[string]any) error {
	memberships := array(value["initial_memberships"])
	event := object(value["event"])
	if stringValue(event["delete_semantics"]) != "SCOPE_MEMBERSHIP_REMOVED" {
		return fail("CONNECTOR_DELETE_SEMANTICS_INVALID")
	}
	target := stringValue(event["source_scope_id"]) + ":" + strconvItoa(intValue(event["scope_revision"]))
	active := 0
	foundTarget := false
	for _, raw := range memberships {
		membership := object(raw)
		key := stringValue(membership["source_scope_id"]) + ":" + strconvItoa(intValue(membership["source_scope_revision"]))
		if key == target {
			foundTarget = true
			continue
		}
		if stringValue(membership["state"]) == "ACTIVE" {
			active++
		}
	}
	if !foundTarget || active == 0 {
		return fail("OVERLAP_MEMBERSHIP_DELETE_INVALID")
	}
	expected := object(value["expected"])
	if stringValue(expected["source_object_lifecycle_state"]) != "ACTIVE" || !boolValue(expected["source_object_queryable"]) || !boolValue(expected["current_version_preserved"]) || !boolValue(expected["evidence_and_vectors_preserved"]) {
		return fail("OVERLAP_MEMBERSHIP_DELETE_INVALID")
	}
	if stringValue(expected["membership_scope_projects_revision_3"]) != "REMOVED" || stringValue(expected["membership_scope_audit_revision_8"]) != "ACTIVE" {
		return fail("OVERLAP_MEMBERSHIP_STATE_INVALID")
	}
	if boolValue(expected["queryable_through_scope_projects_revision_3"]) || !boolValue(expected["queryable_through_scope_audit_revision_8"]) {
		return fail("OVERLAP_GRANT_PATH_INVALID")
	}
	return nil
}

func validateDuplicateSourceObjectScenario(value map[string]any) error {
	seen := map[string]bool{}
	for _, raw := range array(value["persisted_source_objects"]) {
		item := object(raw)
		key := stringValue(item["organization_id"]) + "\x00" + stringValue(item["connection_id"]) + "\x00" + stringValue(item["external_object_id"])
		if seen[key] {
			return fail("VER_004_DUPLICATE_SOURCE_OBJECT")
		}
		seen[key] = true
	}
	return nil
}

func questionRequestHash(request map[string]any) (string, error) {
	question := strings.TrimFunc(canonicalTextV1(stringValue(request["question_text"])), unicode.IsSpace)
	return hashCanonical(map[string]any{
		"workspace_id":       request["workspace_id"],
		"workspace_revision": request["workspace_revision"],
		"question_text":      question,
	})
}

func validateQuestionIdempotencyScenario(value map[string]any) error {
	requests := array(value["requests"])
	if len(requests) != 2 {
		return fail("QUESTION_SCENARIO_INVALID")
	}
	first, second := object(requests[0]), object(requests[1])
	firstHash, err := questionRequestHash(first)
	if err != nil {
		return err
	}
	secondHash, err := questionRequestHash(second)
	if err != nil {
		return err
	}
	if stringValue(first["idempotency_key"]) == stringValue(second["idempotency_key"]) && firstHash != secondHash {
		return fail("QUESTION_IDEMPOTENCY_CONFLICT")
	}
	return nil
}

type connectorReplayState struct {
	events      map[string]string
	idempotency map[string]string
	nonces      map[string]string
}

func newConnectorReplayState() *connectorReplayState {
	return &connectorReplayState{events: map[string]string{}, idempotency: map[string]string{}, nonces: map[string]string{}}
}

func (state *connectorReplayState) accept(event map[string]any) error {
	integrity := object(event["integrity"])
	payloadHash := stringValue(integrity["payload_hash"])
	eventID := stringValue(event["event_id"])
	idempotency := stringValue(event["idempotency_key"])
	nonce := stringValue(integrity["nonce"])
	if prior, ok := state.events[eventID]; ok {
		if prior == payloadHash {
			return nil
		}
		return fail("CONNECTOR_REPLAY_PAYLOAD_CONFLICT")
	}
	if prior, ok := state.idempotency[idempotency]; ok {
		if prior == payloadHash {
			return nil
		}
		return fail("CONNECTOR_REPLAY_PAYLOAD_CONFLICT")
	}
	if _, ok := state.nonces[nonce]; ok {
		return fail("CONNECTOR_NONCE_REPLAYED")
	}
	state.events[eventID] = payloadHash
	state.idempotency[idempotency] = payloadHash
	state.nonces[nonce] = payloadHash
	return nil
}

func validateRetentionPurgeScenario(value map[string]any) error {
	state := stringValue(value["retention_state"])
	if state != "PURGING" && state != "PURGED" {
		return fail("RETENTION_SCENARIO_INVALID")
	}
	if boolValue(object(value["expected"])["disclosure_allowed"]) {
		return fail("RETENTION_DISCLOSURE_STATE_INVALID")
	}
	request := object(value["read_request"])
	if boolValue(request["include_answer_body"]) || boolValue(request["include_cited_excerpts"]) || boolValue(request["include_manifest"]) {
		if state == "PURGING" {
			return fail("ANSWER_CONTENT_PURGING")
		}
		return fail("ANSWER_CONTENT_PURGED")
	}
	return nil
}

func validateRetentionPurgeCompletion(value map[string]any) error {
	if stringValue(value["retention_state"]) != "PURGED" {
		return fail("RETENTION_SCENARIO_INVALID")
	}
	stored := object(value["stored"])
	for _, field := range []string{"question_text", "answer_markdown", "answer_structured_json", "cited_excerpts", "manifest_canonical_bytes"} {
		if stored[field] != nil {
			return fail("RETENTION_PURGE_INCOMPLETE", field)
		}
	}
	return nil
}

func validateSavedAnswerCurrentScope(value map[string]any) error {
	current := object(value["current_reader_context"])
	if !boolValue(current["workspace_member_active"]) {
		return fail("ANSWER_CURRENT_SCOPE_CITATION_DENIED")
	}
	bindings := array(current["enabled_bindings"])
	memberships := array(current["active_object_memberships"])
	for _, rawCitation := range array(value["material_citations"]) {
		citation := object(rawCitation)
		scopeID := stringValue(citation["source_scope_id"])
		revision := intValue(citation["source_scope_revision"])
		bindingAllowed := false
		for _, rawBinding := range bindings {
			binding := object(rawBinding)
			if boolValue(binding["enabled"]) && stringValue(binding["source_scope_id"]) == scopeID && intValue(binding["source_scope_revision"]) == revision {
				bindingAllowed = true
			}
		}
		membershipAllowed := false
		for _, rawMembership := range memberships {
			membership := object(rawMembership)
			if stringValue(membership["source_object_id"]) == stringValue(citation["source_object_id"]) &&
				stringValue(membership["source_scope_id"]) == scopeID && intValue(membership["source_scope_revision"]) == revision &&
				stringValue(membership["state"]) == "ACTIVE" {
				membershipAllowed = true
			}
		}
		if !bindingAllowed || !membershipAllowed {
			return fail("ANSWER_CURRENT_SCOPE_CITATION_DENIED")
		}
		if stringValue(citation["access_mode"]) == "SOURCE_ENFORCED" && !boolValue(citation["current_acl_allows"]) {
			return fail("ANSWER_CURRENT_SCOPE_CITATION_DENIED")
		}
	}
	return nil
}

func validateExtractionLifecycleScenario(value map[string]any) error {
	version := object(value["source_version"])
	sourceObject := object(value["source_object"])
	if stringValue(version["version_state"]) != "CURRENT" || stringValue(sourceObject["lifecycle_state"]) != "ACTIVE" || !boolValue(sourceObject["queryable"]) || stringValue(sourceObject["current_version_id"]) != stringValue(version["source_version_id"]) {
		return fail("RETRIEVAL_SOURCE_VERSION_NOT_CURRENT")
	}
	extractions := map[string]map[string]any{}
	for _, rawExtraction := range array(value["extractions"]) {
		extraction := object(rawExtraction)
		id := stringValue(extraction["extraction_id"])
		if extractions[id] != nil {
			return fail("EXTRACTION_ID_DUPLICATE", id)
		}
		if stringValue(extraction["source_version_id"]) != stringValue(version["source_version_id"]) {
			return fail("EXTRACTION_SOURCE_VERSION_MISMATCH", id)
		}
		extractions[id] = extraction
	}
	activeID := stringValue(version["active_extraction_id"])
	active := extractions[activeID]
	if active == nil || stringValue(active["status"]) != "SUCCEEDED" || stringValue(active["retention_state"]) != "ACTIVE" || !boolValue(active["queryable"]) {
		return fail("ACTIVE_EXTRACTION_POINTER_INVALID", activeID)
	}
	if intValue(version["active_extraction_revision"]) != intValue(active["activation_revision"]) {
		return fail("ACTIVE_EXTRACTION_REVISION_MISMATCH", activeID)
	}

	retrieval := object(value["current_retrieval"])
	requested := extractions[stringValue(retrieval["extraction_id"])]
	if requested == nil || stringValue(retrieval["extraction_id"]) != activeID || stringValue(requested["status"]) != "SUCCEEDED" || stringValue(requested["retention_state"]) != "ACTIVE" || !boolValue(requested["queryable"]) {
		return fail("RETRIEVAL_EXTRACTION_NOT_ACTIVE")
	}
	if stringValue(retrieval["index_extraction_id"]) != activeID {
		return fail("RETRIEVAL_EXTRACTION_NOT_ACTIVE")
	}

	historical := object(value["historical_citation"])
	historicalExtraction := extractions[stringValue(historical["extraction_id"])]
	if historicalExtraction == nil {
		return fail("HISTORICAL_EXTRACTION_MISSING")
	}
	if stringValue(historicalExtraction["retention_state"]) != "ACTIVE" || !boolValue(historicalExtraction["queryable"]) {
		if boolValue(historical["include_body"]) || boolValue(historical["include_excerpt"]) {
			return fail("EXTRACTION_PURGED")
		}
		if stringValue(historical["expected_freshness"]) != "EXTRACTION_PURGED" {
			return fail("EXTRACTION_FRESHNESS_INVALID")
		}
	} else if stringValue(historical["extraction_id"]) != activeID && stringValue(historical["expected_freshness"]) != "EXTRACTION_SUPERSEDED" {
		return fail("EXTRACTION_FRESHNESS_INVALID")
	}

	questionPurge := object(value["question_run_purge"])
	if stringValue(questionPurge["shared_extraction_hash_before"]) != stringValue(questionPurge["shared_extraction_hash_after"]) ||
		intValue(questionPurge["shared_extraction_count_before"]) != intValue(questionPurge["shared_extraction_count_after"]) {
		return fail("QUESTION_PURGE_TOUCHED_SHARED_EXTRACTION")
	}

	sourcePurge := object(value["source_derived_purge"])
	expectedPurgeIDs := stringSet(array(sourcePurge["expected_extraction_ids"]))
	failClose := object(sourcePurge["fail_close_commit"])
	if stringValue(failClose["source_version_retention_state"]) != "PURGING" || failClose["active_extraction_id"] != nil ||
		stringValue(failClose["source_object_current_version_id"]) != stringValue(sourceObject["current_version_id"]) || !boolValue(failClose["source_object_queryable"]) {
		return fail("EXTRACTION_PURGE_NOT_FAIL_CLOSED")
	}
	seenFailClose := map[string]bool{}
	for _, rawExtraction := range array(failClose["extractions"]) {
		extraction := object(rawExtraction)
		id := stringValue(extraction["extraction_id"])
		if !expectedPurgeIDs[id] || seenFailClose[id] || stringValue(extraction["retention_state"]) != "PURGING" || boolValue(extraction["queryable"]) {
			return fail("EXTRACTION_PURGE_NOT_FAIL_CLOSED", id)
		}
		seenFailClose[id] = true
	}
	if len(seenFailClose) != len(expectedPurgeIDs) {
		return fail("EXTRACTION_PURGE_NOT_FAIL_CLOSED")
	}
	completed := object(sourcePurge["completed"])
	if stringValue(completed["source_version_retention_state"]) != "PURGED" || completed["active_extraction_id"] != nil ||
		stringValue(completed["source_object_current_version_id"]) != stringValue(sourceObject["current_version_id"]) || !boolValue(completed["source_object_queryable"]) {
		return fail("EXTRACTION_PURGE_INCOMPLETE")
	}
	seenCompleted := map[string]bool{}
	for _, rawExtraction := range array(completed["extractions"]) {
		extraction := object(rawExtraction)
		id := stringValue(extraction["extraction_id"])
		if !expectedPurgeIDs[id] || seenCompleted[id] || stringValue(extraction["retention_state"]) != "PURGED" || boolValue(extraction["queryable"]) ||
			boolValue(extraction["normalized_text_present"]) || boolValue(extraction["evidence_present"]) || boolValue(extraction["vectors_present"]) || boolValue(extraction["lexical_index_present"]) {
			return fail("EXTRACTION_PURGE_INCOMPLETE", id)
		}
		seenCompleted[id] = true
	}
	if len(seenCompleted) != len(expectedPurgeIDs) {
		return fail("EXTRACTION_PURGE_INCOMPLETE")
	}
	lateCommit := object(value["late_running_extraction_commit"])
	if intValue(lateCommit["current_retention_fence_revision"]) <= intValue(lateCommit["captured_retention_fence_revision"]) ||
		boolValue(lateCommit["terminal_commit_allowed"]) || boolValue(lateCommit["derived_write_allowed"]) || boolValue(lateCommit["stale_index_add_allowed"]) {
		return fail("EXTRACTION_COMMIT_AFTER_PURGE_DENIED")
	}
	currentPurge := object(value["current_version_purge_behavior"])
	if stringValue(currentPurge["target_source_version_id"]) != stringValue(sourceObject["current_version_id"]) || currentPurge["source_object_current_version_id_after_fail_close"] != nil || boolValue(currentPurge["source_object_queryable_after_fail_close"]) {
		return fail("CURRENT_SOURCE_VERSION_PURGE_NOT_FAIL_CLOSED")
	}
	return nil
}
