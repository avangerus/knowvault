package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type aadOwnerRule struct {
	Title, OwnerTable, OwnerColumn, ResourceType, Field, ResourceIDSource string
}

var aadOwnerInventory = []aadOwnerRule{
	{"external_identity.external_subject_artifact_id", "external_identity", "external_subject_artifact_id", "EXTERNAL_IDENTITY", "SUBJECT", "external_identity.id"},
	{"source_connection_revision.trust_profile_artifact_id", "source_connection_revision", "trust_profile_artifact_id", "SOURCE_TRUST_CONFIG", "TRUST_CONFIG", "source_connection_revision(organization_id,connection_id,revision)"},
	{"source_discovery_result.metadata_artifact_id", "source_discovery_result", "metadata_artifact_id", "SOURCE_DISCOVERY_RESULT", "DISCOVERY_METADATA", "source_discovery_result.id"},
	{"source_discovered_scope.identity_artifact_id", "source_discovered_scope", "identity_artifact_id", "SOURCE_SCOPE_IDENTITY", "EXTERNAL_SCOPE_IDENTITY", "source_discovered_scope.id"},
	{"source_discovered_scope.display_metadata_artifact_id", "source_discovered_scope", "display_metadata_artifact_id", "SOURCE_SCOPE_METADATA", "DISPLAY_METADATA", "source_discovered_scope.id"},
	{"source_scope_revision.scope_config_artifact_id", "source_scope_revision", "scope_config_artifact_id", "SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", "source_scope_revision(organization_id,source_scope_id,revision)"},
	{"source_object.external_object_id_artifact_id", "source_object", "external_object_id_artifact_id", "SOURCE_OBJECT_ID", "EXTERNAL_OBJECT_ID", "source_object.id"},
	{"source_object.canonical_locator_artifact_id", "source_object", "canonical_locator_artifact_id", "SOURCE_LOCATOR", "CANONICAL_LOCATOR", "source_object.id"},
	{"source_object.title_artifact_id", "source_object", "title_artifact_id", "SOURCE_TITLE", "DISPLAY_TITLE", "source_object.id"},
	{"acl_snapshot.principal_tokens_artifact_id", "acl_snapshot", "principal_tokens_artifact_id", "ACL_PRINCIPAL_SET", "PRINCIPAL_TOKENS", "acl_snapshot.id"},
	{"evidence_fragment.normalized_text_artifact_id", "evidence_fragment", "normalized_text_artifact_id", "EVIDENCE_TEXT", "NORMALIZED_TEXT", "evidence_fragment.id"},
	{"evidence_fragment.anchor_artifact_id", "evidence_fragment", "anchor_artifact_id", "EVIDENCE_ANCHOR", "CANONICAL_ANCHOR", "evidence_fragment.id"},
	{"evidence_fragment.metadata_artifact_id", "evidence_fragment", "metadata_artifact_id", "EVIDENCE_METADATA", "METADATA", "evidence_fragment.id"},
	{"search_chunk.search_text_artifact_id", "search_chunk", "search_text_artifact_id", "SEARCH_CHUNK_TEXT", "NORMALIZED_TEXT", "search_chunk.id"},
	{"question_run.question_text_artifact_id", "question_run", "question_text_artifact_id", "QUESTION_RUN", "QUESTION_TEXT", "question_run.id"},
	{"question_run.answer_markdown_artifact_id", "question_run", "answer_markdown_artifact_id", "QUESTION_RUN", "ANSWER_MARKDOWN", "question_run.id"},
	{"question_run.answer_structured_artifact_id", "question_run", "answer_structured_artifact_id", "QUESTION_RUN", "ANSWER_STRUCTURED", "question_run.id"},
	{"question_run.manifest_content_artifact_id", "question_run", "manifest_content_artifact_id", "MANIFEST_CONTENT", "CANONICAL_BYTES", "question_run.id"},
	{"question_authorized_candidate_set.canonical_artifact_id", "question_authorized_candidate_set", "canonical_artifact_id", "AUTHORIZED_CANDIDATE_SET", "CANONICAL_BYTES", "question_authorized_candidate_set.question_run_id"},
	{"question_model_execution_plan.canonical_artifact_id", "question_model_execution_plan", "canonical_artifact_id", "MODEL_EXECUTION_PLAN", "CANONICAL_BYTES", "question_model_execution_plan.question_run_id"},
	{"question_claim.text_artifact_id", "question_claim", "text_artifact_id", "CLAIM_TEXT", "CLAIM_TEXT", "question_claim.id"},
	{"claim_deterministic_validation_artifact.output_artifact_id", "claim_deterministic_validation_artifact", "output_artifact_id", "DETERMINISTIC_VALIDATION", "VALIDATION_OUTPUT", "claim_deterministic_validation_artifact(organization_id,question_run_id,claim_id)"},
	{"question_citation.cited_excerpt_artifact_id", "question_citation", "cited_excerpt_artifact_id", "CITED_EXCERPT", "EXACT_TEXT", "question_citation.id"},
	{"question_citation.anchor_artifact_id", "question_citation", "anchor_artifact_id", "CITATION_ANCHOR", "CANONICAL_ANCHOR", "question_citation.id"},
	{"question_citation.deep_link_artifact_id", "question_citation", "deep_link_artifact_id", "SOURCE_DEEPLINK", "DEEPLINK", "question_citation.id"},
	{"model_run_artifact.input_artifact_id", "model_run_artifact", "input_artifact_id", "MODEL_ARTIFACT", "CANONICAL_INPUT", "model_run_artifact.model_run_id"},
	{"model_run_artifact.output_artifact_id", "model_run_artifact", "output_artifact_id", "MODEL_ARTIFACT", "CANONICAL_OUTPUT", "model_run_artifact.model_run_id"},
	{"question_feedback.comment_artifact_id", "question_feedback", "comment_artifact_id", "QUESTION_FEEDBACK", "COMMENT_TEXT", "question_feedback.id"},
}

func aadRuleByOwner(ownerTable, ownerColumn string) *aadOwnerRule {
	for index := range aadOwnerInventory {
		rule := &aadOwnerInventory[index]
		if rule.OwnerTable == ownerTable && rule.OwnerColumn == ownerColumn {
			return rule
		}
	}
	return nil
}

func validateAADSchemaInventory() error {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "architecture", "contracts", "encrypted-artifact-aad.schema.json"))
	if err != nil {
		return err
	}
	if _, err := strictCanonical(raw); err != nil {
		return err
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return err
	}
	allOf := array(schema["allOf"])
	if len(allOf) != 1 {
		return fail("ENCRYPTED_ARTIFACT_AAD_INVENTORY_MISMATCH")
	}
	branches := array(object(allOf[0])["oneOf"])
	if len(branches) != len(aadOwnerInventory) {
		return fail("ENCRYPTED_ARTIFACT_AAD_INVENTORY_MISMATCH")
	}
	seen := map[string]bool{}
	for _, rawBranch := range branches {
		branch := object(rawBranch)
		properties := object(branch["properties"])
		table := stringValue(object(properties["owner_table"])["const"])
		column := stringValue(object(properties["owner_column"])["const"])
		rule := aadRuleByOwner(table, column)
		key := table + "." + column
		if rule == nil || seen[key] || stringValue(branch["title"]) != rule.Title || stringValue(branch["$comment"]) != rule.ResourceIDSource ||
			stringValue(object(properties["resource_type"])["const"]) != rule.ResourceType || stringValue(object(properties["field"])["const"]) != rule.Field {
			return fail("ENCRYPTED_ARTIFACT_AAD_INVENTORY_MISMATCH", key)
		}
		seen[key] = true
	}
	return nil
}

func validateAADOwnerBinding(aad map[string]any) error {
	rule := aadRuleByOwner(stringValue(aad["owner_table"]), stringValue(aad["owner_column"]))
	if rule == nil || stringValue(aad["resource_type"]) != rule.ResourceType || stringValue(aad["field"]) != rule.Field {
		return fail("ENCRYPTED_ARTIFACT_AAD_OWNER_MAPPING_MISMATCH")
	}
	return nil
}

func deriveAADResourceID(rule aadOwnerRule, ownerKey map[string]any) (string, error) {
	switch rule.ResourceIDSource {
	case "external_identity.id", "source_discovery_result.id", "source_discovered_scope.id", "source_object.id", "acl_snapshot.id", "evidence_fragment.id", "search_chunk.id", "question_run.id", "question_claim.id", "question_citation.id", "question_feedback.id":
		if stringValue(ownerKey["id"]) == "" {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
		return stringValue(ownerKey["id"]), nil
	case "question_authorized_candidate_set.question_run_id", "question_model_execution_plan.question_run_id":
		if stringValue(ownerKey["question_run_id"]) == "" {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
		return stringValue(ownerKey["question_run_id"]), nil
	case "model_run_artifact.model_run_id":
		if stringValue(ownerKey["model_run_id"]) == "" {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
		return stringValue(ownerKey["model_run_id"]), nil
	case "source_connection_revision(organization_id,connection_id,revision)":
		if stringValue(ownerKey["organization_id"]) == "" || stringValue(ownerKey["connection_id"]) == "" || intValue(ownerKey["revision"]) < 1 {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
	case "source_scope_revision(organization_id,source_scope_id,revision)":
		if stringValue(ownerKey["organization_id"]) == "" || stringValue(ownerKey["source_scope_id"]) == "" || intValue(ownerKey["revision"]) < 1 {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
	case "claim_deterministic_validation_artifact(organization_id,question_run_id,claim_id)":
		if stringValue(ownerKey["organization_id"]) == "" || stringValue(ownerKey["question_run_id"]) == "" || stringValue(ownerKey["claim_id"]) == "" {
			return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
		}
	default:
		return "", fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVALID", rule.Title)
	}
	return hashCanonical(ownerKey)
}

func validateAADInventoryExamples(context map[string]any) error {
	inventory, err := loadContextFixture(context, "owner_key_inventory_fixture")
	if err != nil {
		return err
	}
	if len(inventory) != len(aadOwnerInventory) {
		return fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVENTORY_MISMATCH")
	}
	for _, rule := range aadOwnerInventory {
		ownerKey := object(inventory[rule.Title])
		resourceID, err := deriveAADResourceID(rule, ownerKey)
		if err != nil {
			return err
		}
		example := map[string]any{
			"schema_version": "encrypted-artifact-aad-v1", "organization_id": "org-inventory", "owner_table": rule.OwnerTable,
			"owner_column": rule.OwnerColumn, "resource_type": rule.ResourceType, "resource_id": resourceID, "field": rule.Field,
		}
		if err := validateAADOwnerBinding(example); err != nil {
			return err
		}
		foreignKey := cloneObject(ownerKey)
		for key, value := range foreignKey {
			switch value.(type) {
			case string:
				foreignKey[key] = stringValue(value) + "_foreign"
			case float64:
				foreignKey[key] = float64(intValue(value) + 1)
			}
			break
		}
		foreignID, deriveErr := deriveAADResourceID(rule, foreignKey)
		if deriveErr != nil || foreignID == resourceID {
			return fail("ENCRYPTED_ARTIFACT_AAD_OWNER_KEY_INVENTORY_MISMATCH", rule.Title)
		}
	}
	return nil
}

func applyEncryptedArtifactAADMutation(aad map[string]any, mutation string) error {
	switch mutation {
	case "", "NONE", "AAD_CLOSED_OWNER_INVENTORY":
		return nil
	case "AAD_TYPE_OR_FIELD_SWAP":
		aad["resource_type"] = "QUESTION_RUN"
		aad["field"] = "ANSWER_MARKDOWN"
	case "AAD_OWNER_COLUMN_SWAP":
		aad["owner_column"] = "manifest_content_artifact_id"
	case "AAD_OWNER_TABLE_SWAP":
		aad["owner_table"] = "question_run"
	case "AAD_RESOURCE_SWAP":
		aad["resource_id"] = "qr_foreign"
	default:
		return fail("UNKNOWN_AAD_MUTATION", mutation)
	}
	return nil
}

func validateEncryptedArtifactAAD(aad, context map[string]any) error {
	if err := validateAADSchemaInventory(); err != nil {
		return err
	}
	if err := validateAADInventoryExamples(context); err != nil {
		return err
	}
	if err := assertAllowedFields(aad, []string{"schema_version", "organization_id", "owner_table", "owner_column", "resource_type", "resource_id", "field"}); err != nil {
		return err
	}
	if stringValue(aad["schema_version"]) != "encrypted-artifact-aad-v1" {
		return fail("ENCRYPTED_ARTIFACT_AAD_VERSION_MISMATCH")
	}
	if err := validateAADOwnerBinding(aad); err != nil {
		return err
	}
	rule := aadRuleByOwner(stringValue(aad["owner_table"]), stringValue(aad["owner_column"]))
	if rule == nil || stringValue(context["owner_mapping_title"]) != rule.Title {
		return fail("ENCRYPTED_ARTIFACT_AAD_BINDING_MISMATCH")
	}
	derivedResourceID, err := deriveAADResourceID(*rule, object(context["owner_key"]))
	if err != nil || stringValue(aad["resource_id"]) != derivedResourceID {
		return fail("ENCRYPTED_ARTIFACT_AAD_BINDING_MISMATCH")
	}
	expected := object(context["expected_aad"])
	expectedHash, err := hashCanonical(expected)
	if err != nil {
		return err
	}
	if stringValue(context["expected_aad_hash"]) != expectedHash {
		return fail("TRUSTED_AAD_CONTEXT_INVALID")
	}
	actualHash, err := hashCanonical(aad)
	if err != nil {
		return err
	}
	if actualHash != expectedHash || !canonicalObjectsEqual(aad, expected) {
		return fail("ENCRYPTED_ARTIFACT_AAD_BINDING_MISMATCH")
	}
	return nil
}
