package contracts

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type registry struct {
	SuiteVersion string         `json:"suite_version"`
	Cases        []registryCase `json:"cases"`
}

type registryCase struct {
	ID                  string  `json:"id"`
	Kind                string  `json:"kind"`
	Contract            string  `json:"contract"`
	Fixture             string  `json:"fixture"`
	Context             string  `json:"context"`
	Validator           string  `json:"validator"`
	Mutation            string  `json:"mutation"`
	SchemaMutation      string  `json:"schema_mutation"`
	ExpectedSchemaValid *bool   `json:"expected_schema_valid"`
	ExpectedErrorCode   *string `json:"expected_error_code"`
}

func loadRegistry(t *testing.T) registry {
	t.Helper()
	raw, err := os.ReadFile(fixturePath("fixture-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictCanonical(raw); err != nil {
		t.Fatalf("registry is not strict I-JSON: %v", err)
	}
	var result registry
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAllContractJSONIsStrictIJSON(t *testing.T) {
	root := fixturePath("fixtures")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := strictCanonical(raw); err != nil {
			t.Errorf("%s is not strict I-JSON: %v", path, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestContractRegistry(t *testing.T) {
	registry := loadRegistry(t)
	if registry.SuiteVersion != "2.0" {
		t.Fatalf("unexpected suite version %q", registry.SuiteVersion)
	}
	seen := map[string]bool{}
	required := map[string]bool{
		"acceptance.answer.current-scope-citation-denied": false,
		"contract.manifest.unsupported-fact":              false,
		"contract.manifest.corpus-snapshot-set-mismatch":  false,
	}
	for _, testCase := range registry.Cases {
		if testCase.ID == "" || seen[testCase.ID] {
			t.Fatalf("duplicate or empty case id %q", testCase.ID)
		}
		seen[testCase.ID] = true
		if _, ok := required[testCase.ID]; ok {
			required[testCase.ID] = true
		}
		if testCase.Validator == "" && testCase.ExpectedSchemaValid == nil {
			t.Fatalf("case %s is not executable by Go or schema runner", testCase.ID)
		}
	}
	for id, present := range required {
		if !present {
			t.Fatalf("required acceptance id missing: %s", id)
		}
	}
}

// TestWorkspaceManagedAuthorityCommandFixtureInventoryMatchesRegistry proves
// fixture-cases.json is the only source of truth for the ADR-0053 fixture
// set: no fixture is registered more than once, no registered fixture is
// missing from disk, and no workspace-managed-authority-command fixture on
// disk is absent from the registry. This is what lets schema-tests.mjs (AJV)
// and this Go runner execute exactly the same case set.
func TestWorkspaceManagedAuthorityCommandFixtureInventoryMatchesRegistry(t *testing.T) {
	registry := loadRegistry(t)
	const contract = "workspace-managed-authority-command"
	registered := map[string]int{}
	for _, testCase := range registry.Cases {
		if testCase.Contract != contract {
			continue
		}
		registered[testCase.Fixture]++
		if testCase.Validator != contract {
			t.Fatalf("case %s targets contract %s but validator is %q", testCase.ID, contract, testCase.Validator)
		}
	}
	for fixture, count := range registered {
		if count != 1 {
			t.Fatalf("fixture %s registered %d times, expected exactly once", fixture, count)
		}
		if _, err := os.Stat(fixturePath(fixture)); err != nil {
			t.Fatalf("registry references missing fixture %s: %v", fixture, err)
		}
	}
	for _, directory := range []string{"valid", "invalid"} {
		entries, err := os.ReadDir(fixturePath(filepath.Join("fixtures", directory)))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "workspace-managed-authority-command") {
				continue
			}
			relative := "fixtures/" + directory + "/" + entry.Name()
			if registered[relative] != 1 {
				t.Fatalf("fixture %s exists on disk but is not registered exactly once in fixture-cases.json", relative)
			}
		}
	}
	if len(registered) != 26 {
		t.Fatalf("expected exactly 26 registered workspace-managed authority command fixtures, found %d", len(registered))
	}
}

func TestSemanticAndStateCases(t *testing.T) {
	registry := loadRegistry(t)
	for _, testCase := range registry.Cases {
		if testCase.Validator == "" {
			continue
		}
		t.Run(testCase.ID, func(t *testing.T) {
			err := executeCase(testCase)
			actual := errorCode(err)
			expected := ""
			if testCase.ExpectedErrorCode != nil {
				expected = *testCase.ExpectedErrorCode
			}
			if actual != expected {
				t.Fatalf("expected error code %q, got %q (%v)", expected, actual, err)
			}
		})
	}
}

func executeCase(testCase registryCase) error {
	switch testCase.Validator {
	case "raw-json":
		raw, err := os.ReadFile(fixturePath(testCase.Fixture))
		if err != nil {
			return err
		}
		_, err = strictCanonical(raw)
		return err
	case "model-plan":
		plan, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		applyModelMutation(plan, testCase.Mutation)
		return validateModelPlan(plan, evidenceContext(context))
	case "connector-event":
		event, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyConnectorMutation(event, context, testCase.Mutation); err != nil {
			return err
		}
		return validateConnectorEvent(event, context)
	case "connector-boundary":
		event, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		return validateConnectorBoundary(event, context, testCase.Mutation)
	case "source-scope":
		scope, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		applySourceScopeMutation(scope, context, testCase.Mutation)
		return validateSourceScope(scope, context)
	case "audit-checkpoint":
		checkpoint, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyAuditCheckpointMutation(checkpoint, context, testCase.Mutation); err != nil {
			return err
		}
		return validateAuditCheckpoint(checkpoint, context)
	case "audit-event":
		event, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyAuditEventMutation(event, testCase.Mutation); err != nil {
			return err
		}
		return validateAuditEvent(event, context)
	case "encrypted-artifact-aad":
		aad, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyEncryptedArtifactAADMutation(aad, testCase.Mutation); err != nil {
			return err
		}
		return validateEncryptedArtifactAAD(aad, context)
	case "targeted-structural":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateTargetedStructural(value, testCase.Mutation)
	case "workspace-managed-authority-command":
		envelope, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateWorkspaceManagedAuthorityCommand(envelope)
	case "answer-manifest":
		manifest, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyManifestMutation(manifest, context, testCase.Mutation); err != nil {
			return err
		}
		return validateAnswerManifest(manifest, context)
	case "extractive-answer-plan":
		plan, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyExtractiveMutation(plan, context, testCase.Mutation); err != nil {
			return err
		}
		return validateExtractiveAnswerPlan(plan, context)
	case "sandbox-job":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSandboxJob(value)
	case "sandbox-parser-request-v1":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSandboxParserRequestV1(value)
	case "sandbox-lease":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSandboxLease(value)
	case "sandbox-outcome":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSandboxOutcome(value)
	case "sandbox-limit-confirmation":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		return validateSandboxLimitConfirmation(value, context)
	case "operator-failure":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateOperatorFailure(value)
	case "operator-readiness":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateOperatorReadiness(value)
	case "verifier-output":
		output, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		applyVerifierOutputMutation(output, context, testCase.Mutation)
		return validateVerifierOutput(output, context)
	case "numeric-validator-output":
		output, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		context, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		if err := applyNumericMutation(output, context, testCase.Mutation); err != nil {
			return err
		}
		return validateNumericOutput(output, context)
	case "numeric-lexer-golden":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateNumericLexerGolden(value)
	case "anchor":
		anchor, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		golden, _, err := loadObject(testCase.Context)
		if err != nil {
			return err
		}
		return validateAnchorFixture(anchor, []byte(stringValue(golden["canonical_text_escaped"])))
	case "golden-unicode":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateUnicodeGolden(value)
	case "golden-renderer":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateRendererGolden(value)
	case "golden-question":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateQuestionJCSGolden(value)
	case "golden-signature":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSignatureEnvelopeGolden(value)
	case "golden-anchors":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateAnchorCollection(value)
	case "golden-anchor-compatibility":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateAnchorCompatibilityCollection(value)
	case "golden-scope-glob":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateScopeGlobGolden(value)
	case "ocr-anchor-tokens":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		applyOCRAnchorMutation(value, testCase.Mutation)
		return validateOCRAnchorFixture(value)
	case "state-overlap":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		applyStateMutation(value, testCase.Mutation)
		return validateOverlappingScopesScenario(value)
	case "state-membership-delete":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		applyStateMutation(value, testCase.Mutation)
		return validateMembershipRemovalScenario(value)
	case "state-duplicate-object":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateDuplicateSourceObjectScenario(value)
	case "state-question-idempotency":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateQuestionIdempotencyScenario(value)
	case "state-connector-replay":
		return executeConnectorReplay(testCase.Mutation)
	case "state-retention":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateRetentionPurgeScenario(value)
	case "state-retention-completion":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateRetentionPurgeCompletion(value)
	case "state-saved-answer":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		return validateSavedAnswerCurrentScope(value)
	case "state-extraction-lifecycle":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		applyExtractionLifecycleMutation(value, testCase.Mutation)
		return validateExtractionLifecycleScenario(value)
	case "state-torn-read":
		value, _, err := loadObject(testCase.Fixture)
		if err != nil {
			return err
		}
		applyTornReadMutation(value, testCase.Mutation)
		return validateTornReadScenario(value)
	default:
		return fail("UNKNOWN_TEST_VALIDATOR", testCase.Validator)
	}
}

func applyVerifierOutputMutation(output, context map[string]any, mutation string) {
	results := array(output["results"])
	switch mutation {
	case "", "NONE":
	case "DUPLICATE_RESULT":
		output["results"] = append(results, cloneObject(object(results[0])))
	case "MISSING_RESULT":
		output["results"] = results[:len(results)-1]
	case "EXTRA_RESULT":
		output["results"] = append(results, map[string]any{
			"claim_id": "C9", "verification_input_hash": "sha256:9999999999999999999999999999999999999999999999999999999999999999", "outcome": "SUPPORTED",
		})
	case "WRONG_INPUT_HASH":
		object(results[0])["verification_input_hash"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	case "WRONG_OUTPUT_HASH":
		for _, rawRun := range array(object(context["model_gateway"])["runs"]) {
			run := object(rawRun)
			if stringValue(run["purpose"]) == "VERIFICATION" {
				run["output_hash"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
			}
		}
	}
}

func applyExtractionLifecycleMutation(value map[string]any, mutation string) {
	extractions := array(value["extractions"])
	switch mutation {
	case "", "NONE":
	case "OLD_EXTRACTION_CURRENT_RETRIEVAL":
		retrieval := object(value["current_retrieval"])
		retrieval["extraction_id"] = "ext_alpha_v1"
		retrieval["index_extraction_id"] = "ext_alpha_v1"
	case "ACTIVE_POINTER_PURGED":
		active := object(extractions[1])
		active["retention_state"] = "PURGING"
		active["queryable"] = false
	case "NON_CURRENT_SOURCE_VERSION_RETRIEVAL":
		object(value["source_version"])["version_state"] = "SUPERSEDED"
	case "QUESTION_PURGE_SHARED_EXTRACTION":
		object(value["question_run_purge"])["shared_extraction_count_after"] = float64(1)
	case "SOURCE_PURGE_POINTER_RETAINED":
		object(object(value["source_derived_purge"])["fail_close_commit"])["active_extraction_id"] = "ext_alpha_v2"
	case "SOURCE_PURGE_EXTRACTION_STILL_QUERYABLE":
		failClose := object(object(value["source_derived_purge"])["fail_close_commit"])
		object(array(failClose["extractions"])[0])["queryable"] = true
	case "LATE_EXTRACTION_COMMIT_ALLOWED":
		object(value["late_running_extraction_commit"])["terminal_commit_allowed"] = true
	case "PURGED_HISTORICAL_DISCLOSURE":
		old := object(extractions[0])
		old["retention_state"] = "PURGED"
		old["queryable"] = false
		object(value["historical_citation"])["expected_freshness"] = "EXTRACTION_PURGED"
	}
}

func applyStateMutation(value map[string]any, mutation string) {
	expected := object(value["expected"])
	switch mutation {
	case "", "NONE":
	case "OVERLAP_EVIDENCE_COUNT":
		expected["evidence_set_count"] = float64(2)
	case "OVERLAP_VECTOR_COUNT":
		expected["vector_set_count"] = float64(2)
	case "OVERLAP_GRANT_PATH":
		expected["grant_path_must_match_workspace_binding"] = false
	case "MEMBERSHIP_REMOVAL_WIDENS_ACCESS":
		expected["queryable_through_scope_projects_revision_3"] = true
	case "MEMBERSHIP_STATE_WRONG":
		expected["membership_scope_projects_revision_3"] = "ACTIVE"
	}
}

func evidenceContext(context map[string]any) map[string]string {
	result := map[string]string{}
	for _, raw := range array(context["authorized_evidence"]) {
		item := object(raw)
		result[stringValue(item["evidence_id"])] = stringValue(item["text"])
	}
	return result
}

func validateTargetedStructural(value map[string]any, mutation string) error {
	switch mutation {
	case "CONNECTOR_DELETE_FIELDS_NOT_NULL":
		if stringValue(value["operation"]) == "DELETE" && (value["external_version_key"] != nil || value["object_metadata"] != nil || value["content_reference"] != nil || value["acl_snapshot"] != nil) {
			return fail("CONNECTOR_DELETE_FIELDS_NOT_NULL")
		}
	case "CONNECTOR_METADATA_DISCRIMINATOR_MISMATCH":
		if stringValue(object(value["object_metadata"])["kind"]) != stringValue(value["object_type"]) {
			return fail("CONNECTOR_METADATA_DISCRIMINATOR_MISMATCH")
		}
	case "ACL_TOKEN_INVALID":
		for _, rawToken := range array(object(value["acl_snapshot"])["principal_tokens"]) {
			token := object(rawToken)
			if strings.Contains(stringValue(token["namespace"]), "*") || strings.Contains(stringValue(token["subject"]), "*") || strings.Contains(stringValue(token["revision"]), "*") {
				return fail("ACL_TOKEN_INVALID")
			}
		}
	}
	return nil
}

func applyModelMutation(plan map[string]any, mutation string) {
	claims := array(plan["claims"])
	sections := array(plan["sections"])
	switch mutation {
	case "", "NONE":
	case "DUPLICATE_CLAIM":
		plan["claims"] = append(claims, cloneObject(object(claims[0])))
	case "DUPLICATE_SECTION":
		plan["sections"] = append(sections, cloneObject(object(sections[0])))
	case "MODEL_SECTION_TITLE":
		object(sections[0])["title"] = "\u041f\u0440\u0438\u0447\u0438\u043d\u0430 \u0437\u0430\u0434\u0435\u0440\u0436\u043a\u0438: API \u043a\u043b\u0438\u0435\u043d\u0442\u0430"
	case "SECTION_FOREIGN_CLAIM":
		object(sections[0])["ordered_claim_ids"] = []any{"C1", "C2", "C99"}
	case "CLAIM_UNPUBLISHED":
		object(sections[0])["ordered_claim_ids"] = []any{"C1", "C2"}
	case "CLAIM_PUBLISHED_MULTIPLE":
		plan["sections"] = append(sections, map[string]any{"section_id": "S2", "title": nil, "ordered_claim_ids": []any{"C1"}})
	case "SUPPORT_FOREIGN":
		object(claims[1])["supporting_claim_ids"] = []any{"C99"}
	case "SUPPORT_SELF":
		object(claims[1])["supporting_claim_ids"] = []any{"C2"}
	case "SUPPORT_CHAIN":
		object(claims[1])["supporting_claim_ids"] = []any{"C3"}
	case "SUPPORT_CYCLE":
		object(claims[1])["supporting_claim_ids"] = []any{"C4"}
		plan["claims"] = append(claims, map[string]any{
			"claim_id": "C4", "text": "\u0426\u0438\u043a\u043b\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0432\u044b\u0432\u043e\u0434.", "kind": "INFERENCE",
			"evidence_ids": []any{}, "supporting_claim_ids": []any{"C2"},
		})
		object(sections[0])["ordered_claim_ids"] = []any{"C1", "C2", "C3", "C4"}
	case "FOREIGN_EVIDENCE":
		object(claims[0])["evidence_ids"] = []any{"ev_foreign"}
	case "UNSUPPORTED_FACT":
		object(claims[0])["evidence_ids"] = []any{}
	case "UNKNOWN_FACTUAL_PAYLOAD":
		object(claims[2])["text"] = "\u041a\u0442\u043e \u0443\u0442\u0432\u0435\u0440\u0434\u0438\u043b \u043f\u0435\u0440\u0435\u043d\u043e\u0441, \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u043e."
	}
}

func applyConnectorMutation(event, context map[string]any, mutation string) error {
	switch mutation {
	case "", "NONE":
		return nil
	case "STALE_SCOPE_REVISION":
		object(context["registered_connector"])["scope_revision"] = float64(4)
		return nil
	case "PAYLOAD_HASH_TAMPER":
		object(event["integrity"])["payload_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		return nil
	case "SIGNATURE_TAMPER":
		object(event["integrity"])["value_base64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		return nil
	case "CONTENT_REFERENCE_EXPIRED":
		object(event["content_reference"])["expires_at"] = "2026-07-14T11:59:59Z"
	case "SOURCE_HASH_WRONG":
		object(event["content_reference"])["content_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "ACL_HASH_WRONG":
		object(event["acl_snapshot"])["content_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "LOCATOR_HASH_WRONG":
		object(event["object_metadata"])["canonical_locator_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "ACL_IDENTITY_COLLISION":
		acl := object(event["acl_snapshot"])
		tokens := array(acl["principal_tokens"])
		acl["principal_tokens"] = append(tokens, cloneObject(object(tokens[0])))
	case "SOURCE_ENFORCED_ACL_MISSING":
		if err := configureVerifiedSourceEnforcedConnector(context); err != nil {
			return err
		}
		event["acl_snapshot"] = nil
	case "SOURCE_ENFORCED_ACL_EXPIRED":
		if err := configureVerifiedSourceEnforcedConnector(context); err != nil {
			return err
		}
		object(event["acl_snapshot"])["expires_at"] = "2026-07-14T11:59:59Z"
	case "SOURCE_ENFORCED_ACL_TIME_INVALID":
		if err := configureVerifiedSourceEnforcedConnector(context); err != nil {
			return err
		}
		object(event["acl_snapshot"])["resolved_at"] = "2026-07-14T12:15:00Z"
		object(event["acl_snapshot"])["expires_at"] = "2026-07-14T12:14:00Z"
	case "SOURCE_ENFORCED_ACCESS_MODE_NOT_TRUSTED":
		object(context["registered_connector"])["access_mode"] = "SOURCE_ENFORCED"
		object(context["source_connection_revision"])["access_mode"] = "SOURCE_ENFORCED"
	case "SOURCE_ENFORCED_CAPABILITY_MISSING":
		if err := configureVerifiedSourceEnforcedConnector(context); err != nil {
			return err
		}
		object(context["capability_profile"])["acl_refresh"] = false
		if err := synchronizeConnectorTrustProfile(context); err != nil {
			return err
		}
	case "PATH_NONCANONICAL":
		object(event["object_metadata"])["relative_path"] = "alpha\\\u041f\u043b\u0430\u043d \u0437\u0430\u043f\u0443\u0441\u043a\u0430.txt"
	case "WEB_URL_NONCANONICAL":
		makeWebEvent(event, "https://EXAMPLE.COM:443/docs")
	case "CONNECTOR_KEY_WRONG_ORGANIZATION":
		object(context["key"])["organization_id"] = "org_foreign"
	case "CONNECTOR_KEY_WRONG_PURPOSE":
		object(context["key"])["purpose"] = "ANSWER_MANIFEST"
	case "CONNECTOR_KEY_WRONG_CONNECTION":
		object(context["key"])["connection_id"] = "conn_foreign"
	case "CONNECTOR_KEY_WRONG_AGENT":
		object(context["key"])["connector_agent_id"] = "agent_foreign"
	case "CONNECTOR_KEY_NOT_BEFORE":
		object(context["key"])["not_before"] = "2026-07-14T12:00:01Z"
	case "CONNECTOR_KEY_SIGN_UNTIL":
		object(context["key"])["sign_until"] = "2026-07-14T11:59:59Z"
	case "CONNECTOR_KEY_RETIRED":
		object(context["key"])["status"] = "RETIRED"
	case "CONNECTOR_KEY_REVOKED":
		object(context["key"])["status"] = "REVOKED"
	case "CONNECTOR_UNTRUSTED_BUILD_WORKSPACE_MANAGED":
		object(context["connector_trust_record"])["status"] = "REVOKED"
	case "CONNECTOR_TRUST_RECORD_MISMATCH":
		object(context["connector_trust_record"])["artifact_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CONNECTOR_TRUST_PROFILE_MISMATCH":
		object(context["source_connection_revision"])["trust_profile_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CONNECTOR_CAPABILITY_BODY_MISMATCH":
		object(context["capability_profile"])["stable_object_ids"] = false
	case "CONNECTOR_CONNECTION_REVISION_MISMATCH":
		object(context["source_connection_revision"])["connection_revision"] = float64(2)
	default:
		return fail("UNKNOWN_CONNECTOR_MUTATION", mutation)
	}
	return rehashAndSignConnector(event, context)
}

func configureVerifiedSourceEnforcedConnector(context map[string]any) error {
	registration := object(context["registered_connector"])
	revision := object(context["source_connection_revision"])
	trust := object(context["connector_trust_record"])
	capability := object(context["capability_profile"])
	registration["access_mode"] = "SOURCE_ENFORCED"
	revision["access_mode"] = "SOURCE_ENFORCED"
	registration["allowed_access_modes"] = []any{"SOURCE_ENFORCED"}
	revision["allowed_access_modes"] = []any{"SOURCE_ENFORCED"}
	registration["capability_profile_id"] = "connector-capability-folder-source-enforced-01"
	revision["capability_profile_id"] = "connector-capability-folder-source-enforced-01"
	trust["capability_profile_id"] = "connector-capability-folder-source-enforced-01"
	registration["trust_record_id"] = "connector-trust-folder-source-enforced-01"
	revision["trust_record_id"] = "connector-trust-folder-source-enforced-01"
	trust["trust_record_id"] = "connector-trust-folder-source-enforced-01"
	capability["stable_object_ids"] = true
	capability["item_level_acl"] = true
	capability["acl_refresh"] = true
	trust["status"] = "VERIFIED"
	return synchronizeConnectorTrustProfile(context)
}

func synchronizeConnectorTrustProfile(context map[string]any) error {
	registration := object(context["registered_connector"])
	revision := object(context["source_connection_revision"])
	trust := object(context["connector_trust_record"])
	capability := object(context["capability_profile"])
	capabilityHash, err := hashCanonical(capability)
	if err != nil {
		return err
	}
	registration["capability_profile_hash"] = capabilityHash
	revision["capability_profile_hash"] = capabilityHash
	trust["capability_profile_hash"] = capabilityHash
	trustProfileHash, err := hashCanonical(connectorEventTrustProfileInput(revision))
	if err != nil {
		return err
	}
	registration["trust_profile_hash"] = trustProfileHash
	revision["trust_profile_hash"] = trustProfileHash
	trust["trust_profile_hash"] = trustProfileHash
	return nil
}

func mutableContextFixture(context map[string]any, field string) (map[string]any, error) {
	if override := object(context[field+"_override"]); override != nil {
		return override, nil
	}
	path := stringValue(context[field])
	if path == "" {
		return nil, fail("TRUSTED_CONTEXT_FIXTURE_MISSING", field)
	}
	value, _, err := loadObject(path)
	if err != nil {
		return nil, err
	}
	context[field+"_override"] = value
	return value, nil
}

func synchronizeModelExecutionPlan(manifest, context map[string]any) error {
	plan, err := mutableContextFixture(context, "model_execution_plan_fixture")
	if err != nil {
		return err
	}
	planHash, err := hashCanonical(plan)
	if err != nil {
		return err
	}
	object(manifest["retrieval"])["model_execution_plan_hash"] = planHash
	return synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
		object(retrievalContext["authorization_snapshot"])["model_execution_plan_hash"] = planHash
		return nil
	})
}

func modelRunForPurpose(manifest map[string]any, purpose string) map[string]any {
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		if stringValue(run["purpose"]) == purpose && boolValue(run["selected_for_result"]) {
			return run
		}
	}
	return nil
}

func synchronizeGatewayRun(context map[string]any, manifestRun map[string]any) error {
	id := stringValue(manifestRun["model_run_id"])
	for _, rawRun := range array(object(context["model_gateway"])["runs"]) {
		run := object(rawRun)
		if stringValue(run["model_run_id"]) == id {
			for key := range run {
				delete(run, key)
			}
			for key, value := range cloneObject(manifestRun) {
				run[key] = value
			}
			return nil
		}
	}
	return fail("MODEL_GATEWAY_RUN_MISSING", id)
}

func synchronizeGenerationArtifact(manifest, context map[string]any, synchronizeInput, synchronizeOutput bool) error {
	artifacts, err := mutableContextFixture(context, "model_artifacts_fixture")
	if err != nil {
		return err
	}
	run := modelRunForPurpose(manifest, "GENERATION")
	if run == nil {
		return fail("MODEL_RUN_MISSING", "GENERATION")
	}
	artifact := object(artifacts[stringValue(run["model_run_id"])])
	if artifact == nil {
		return fail("MODEL_ARTIFACT_MISSING", stringValue(run["model_run_id"]))
	}
	if synchronizeInput {
		modelContext, contextErr := contextModelItems(context)
		if contextErr != nil {
			return contextErr
		}
		profile := object(object(manifest["configured_profiles"])["generation"])
		artifact["input"] = map[string]any{
			"schema_version": "generation-input-v1", "profile_revision": profile["profile_revision"], "profile_hash": profile["profile_hash"],
			"prompt_version": profile["prompt_version"], "question_text": manifest["question_text"], "question_hash": manifest["question_hash"],
			"context_pack_hash": object(manifest["retrieval"])["context_pack_hash"], "corpus_status": object(manifest["status"])["corpus"], "context": modelContext,
		}
	}
	if synchronizeOutput {
		artifact["output"] = modelPlanProjection(manifest)
	}
	inputHash, err := hashCanonical(artifact["input"])
	if err != nil {
		return err
	}
	outputHash, err := hashCanonical(artifact["output"])
	if err != nil {
		return err
	}
	run["input_hash"] = inputHash
	run["output_hash"] = outputHash
	return synchronizeGatewayRun(context, run)
}

func mutateSelectedModelArtifact(manifest, context map[string]any, purpose string, mutate func(map[string]any)) error {
	artifacts, err := mutableContextFixture(context, "model_artifacts_fixture")
	if err != nil {
		return err
	}
	run := modelRunForPurpose(manifest, purpose)
	if run == nil {
		return fail("MODEL_RUN_MISSING", purpose)
	}
	artifact := object(artifacts[stringValue(run["model_run_id"])])
	if artifact == nil {
		return fail("MODEL_ARTIFACT_MISSING", stringValue(run["model_run_id"]))
	}
	mutate(artifact)
	inputHash, err := hashCanonical(artifact["input"])
	if err != nil {
		return err
	}
	outputHash, err := hashCanonical(artifact["output"])
	if err != nil {
		return err
	}
	run["input_hash"] = inputHash
	run["output_hash"] = outputHash
	return synchronizeGatewayRun(context, run)
}

func synchronizeRetrievalFixture(manifest, context map[string]any, mutate func(map[string]any) error) error {
	retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
	if err != nil {
		return err
	}
	if mutate != nil {
		if err := mutate(retrievalContext); err != nil {
			return err
		}
	}
	retrieval := object(manifest["retrieval"])
	candidates := array(retrievalContext["authorized_candidate_set"])
	candidateHash, err := hashCanonical(candidates)
	if err != nil {
		return err
	}
	snapshot := object(retrievalContext["authorization_snapshot"])
	snapshot["pipeline_version"] = retrieval["pipeline_version"]
	snapshot["pipeline_profile_hash"] = retrieval["pipeline_profile_hash"]
	snapshot["authorized_candidate_set_hash"] = candidateHash
	snapshot["authorized_candidate_count"] = float64(len(candidates))
	snapshot["context_count"] = retrieval["context_count"]
	snapshot["truncated"] = retrieval["truncated"]
	snapshot["truncation_reason"] = retrieval["truncation_reason"]
	snapshot["error_codes"] = retrieval["error_codes"]
	liveHashes := map[string]any{}
	for _, rawEntry := range array(snapshot["entries"]) {
		entry := object(rawEntry)
		entryHash, hashErr := hashCanonical(entry)
		if hashErr != nil {
			return hashErr
		}
		liveHashes[stringValue(entry["evidence_fragment_id"])] = entryHash
	}
	retrievalContext["live_entry_hashes"] = liveHashes
	snapshotHash, err := hashCanonical(snapshot)
	if err != nil {
		return err
	}
	retrievalContext["authorization_snapshot_hash"] = snapshotHash
	retrieval["authorization_snapshot_hash"] = snapshotHash
	retrieval["authorized_candidate_set_hash"] = candidateHash
	retrieval["authorized_candidate_count"] = float64(len(candidates))
	return nil
}

func synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext map[string]any) error {
	candidateItems, err := candidateModelItems(retrievalContext)
	if err != nil {
		return err
	}
	candidateHash := object(manifest["retrieval"])["authorized_candidate_set_hash"]
	return mutateSelectedModelArtifact(manifest, context, "RERANKING", func(artifact map[string]any) {
		input := object(artifact["input"])
		input["authorized_candidate_set_hash"] = candidateHash
		input["candidates"] = candidateItems
	})
}

func applyManifestMutation(manifest, context map[string]any, mutation string) error {
	claims := array(manifest["claims"])
	citations := array(manifest["citations"])
	runs := array(manifest["model_runs"])
	switch mutation {
	case "", "NONE":
		return nil
	case "MANIFEST_HASH_TAMPER":
		manifest["manifest_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		return nil
	case "MANIFEST_SIGNATURE_TAMPER":
		object(manifest["signature"])["value_base64"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
		return nil
	case "ASYMMETRIC_CITATIONS":
		object(citations[0])["claim_ids"] = []any{"C2"}
	case "UNVERIFIED_FACT":
		verifications := array(manifest["claim_verifications"])
		manifest["claim_verifications"] = verifications[1:]
	case "VERIFIED_CLAIM_TEXT_SWAPPED":
		object(claims[0])["text"] = "\u0414\u0430\u0442\u0430 \u0437\u0430\u043f\u0443\u0441\u043a\u0430 \u0431\u044b\u043b\u0430 \u043f\u0435\u0440\u0435\u043d\u0435\u0441\u0435\u043d\u0430 \u043d\u0430 26 \u0438\u044e\u043b\u044f."
		if err := rerenderManifest(manifest); err != nil {
			return err
		}
		if err := synchronizeGenerationArtifact(manifest, context, false, true); err != nil {
			return err
		}
	case "VERIFIED_CLAIM_EVIDENCE_SWAPPED":
		object(claims[0])["citation_numbers"] = []any{float64(2)}
		object(citations[0])["claim_ids"] = []any{"C4"}
		object(citations[1])["claim_ids"] = []any{"C1", "C4"}
		if err := synchronizeGenerationArtifact(manifest, context, false, true); err != nil {
			return err
		}
	case "VERIFIED_INFERENCE_SUPPORT_SWAPPED":
		object(claims[1])["supporting_claim_ids"] = []any{"C4"}
		if err := synchronizeGenerationArtifact(manifest, context, false, true); err != nil {
			return err
		}
	case "CITATION_CHAIN_MISSING":
		chains := array(context["source_chains"])
		context["source_chains"] = chains[:len(chains)-1]
	case "CITATION_CHAIN_DUPLICATE":
		chains := array(context["source_chains"])
		context["source_chains"] = append(chains, cloneObject(object(chains[1])))
	case "CITATION_CHAIN_MISMATCH":
		object(array(context["source_chains"])[1])["source_version_id"] = "source_version_foreign"
	case "CITATION_NOT_IN_CONTEXT_PACK":
		badAnchorHash := "hmac-sha256:k1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		object(array(context["context_pack"])[1])["anchor_hash"] = badAnchorHash
		contextHash, err := hashCanonical(contextPackHashInput(array(context["context_pack"])))
		if err != nil {
			return err
		}
		object(manifest["retrieval"])["context_pack_hash"] = contextHash
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			entries := array(object(retrievalContext["authorization_snapshot"])["entries"])
			object(entries[1])["anchor_hash"] = badAnchorHash
			return nil
		}); err != nil {
			return err
		}
		if err := synchronizeGenerationArtifact(manifest, context, true, false); err != nil {
			return err
		}
	case "WRONG_SOURCE_HASH":
		object(citations[0])["source_version_content_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_EVIDENCE_HASH":
		object(citations[0])["evidence_text_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_EXCERPT_HASH":
		object(citations[0])["cited_excerpt_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_ANCHOR_HASH":
		object(citations[0])["anchor_hash"] = "hmac-sha256:k1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_ANSWER_HASH":
		manifest["answer_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_QUESTION_HASH":
		manifest["question_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_MANIFEST_ORGANIZATION":
		manifest["organization_id"] = "org_foreign"
	case "WRONG_MANIFEST_WORKSPACE":
		manifest["workspace_id"] = "ws_foreign"
	case "WRONG_MANIFEST_WORKSPACE_REVISION":
		manifest["workspace_revision"] = float64(8)
	case "WRONG_MANIFEST_CREATOR":
		manifest["created_by"] = "user_foreign"
	case "WRONG_WORKSPACE_SCOPE_HASH":
		manifest["workspace_scope_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_ACCESS_CONTEXT_HASH":
		manifest["access_context_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_CONTEXT_PACK_HASH":
		object(manifest["retrieval"])["context_pack_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "WRONG_CONTEXT_PACK_COUNT":
		object(manifest["retrieval"])["context_count"] = float64(2)
	case "CANDIDATE_COUNT_BELOW_CONTEXT":
		object(manifest["retrieval"])["authorized_candidate_count"] = float64(0)
	case "WRONG_ANSWER_SPAN":
		object(object(claims[0])["answer_span"])["start"] = float64(1)
	case "ANCHOR_PDF_REVERSED":
		if err := setCitationAnchor(context, object(citations[0]), map[string]any{
			"kind": "PDF", "page": float64(1), "text_start": float64(10), "text_end": float64(5),
			"offset_unit": "UTF8_BYTE", "range_semantics": "START_INCLUSIVE_END_EXCLUSIVE", "normalization_version": "text-v1",
		}); err != nil {
			return err
		}
	case "ANCHOR_EMAIL_REVERSED":
		if err := setCitationAnchor(context, object(citations[0]), map[string]any{
			"kind": "EMAIL", "message_id": "message-immutable-42", "mime_part": "text/plain",
			"text_start": float64(10), "text_end": float64(5), "offset_unit": "UTF8_BYTE",
			"range_semantics": "START_INCLUSIVE_END_EXCLUSIVE", "normalization_version": "text-v1",
		}); err != nil {
			return err
		}
	case "ANCHOR_XLSX_REVERSED":
		if err := setCitationAnchor(context, object(citations[0]), map[string]any{"kind": "XLSX", "sheet": "Budget", "range": "B12:A11"}); err != nil {
			return err
		}
	case "ANCHOR_OCR_OUT_OF_BOUNDS":
		if err := setCitationAnchor(context, object(citations[0]), map[string]any{
			"kind": "OCR", "page": float64(1), "coordinate_unit": "NORMALIZED_0_1", "coordinate_origin": "TOP_LEFT",
			"token_start_ordinal": float64(0), "token_end_ordinal": float64(1), "range_semantics": "START_INCLUSIVE_END_EXCLUSIVE",
			"bounding_boxes": []any{map[string]any{"x": 0.8, "y": 0.2, "width": 0.3, "height": 0.2}},
		}); err != nil {
			return err
		}
	case "ANCHOR_PDF_DOWNGRADE_TEXT":
		if err := setCitationAnchor(context, object(citations[0]), map[string]any{"kind": "TEXT", "line_start": float64(2), "line_end": float64(2)}); err != nil {
			return err
		}
	case "ANCHOR_HTML_DOWNGRADE_TEXT":
		if err := setCitationAnchor(context, object(citations[1]), map[string]any{"kind": "TEXT", "line_start": float64(2), "line_end": float64(2)}); err != nil {
			return err
		}
	case "SELECTED_FAILED_MODEL_RUN":
		object(runs[3])["outcome"] = "FAILED"
		object(runs[3])["output_hash"] = nil
	case "DUPLICATE_MODEL_ATTEMPT":
		duplicate := cloneObject(object(runs[3]))
		duplicate["model_run_id"] = "mr_verification_duplicate_attempt"
		manifest["model_runs"] = append(runs, duplicate)
	case "DUPLICATE_MODEL_RUN_ID":
		manifest["model_runs"] = append(runs, cloneObject(object(runs[3])))
	case "MISSING_SELECTED_MODEL_PURPOSE":
		object(runs[3])["selected_for_result"] = false
	case "DUPLICATE_SELECTED_MODEL_PURPOSE":
		duplicate := cloneObject(object(runs[3]))
		duplicate["model_run_id"] = "mr_verification_2"
		duplicate["attempt"] = float64(2)
		manifest["model_runs"] = append(runs, duplicate)
		context["executed_model_run_ids"] = append(array(context["executed_model_run_ids"]), "mr_verification_2")
		gateway := object(context["model_gateway"])
		gateway["runs"] = append(array(gateway["runs"]), cloneObject(duplicate))
	case "MODEL_PROFILE_AND_RUN_TAMPER":
		object(object(manifest["configured_profiles"])["generation"])["model_id"] = "attacker/model"
		object(runs[2])["model_id"] = "attacker/model"
	case "MODEL_PROFILE_HASH_MISMATCH":
		badHash := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		object(object(manifest["configured_profiles"])["generation"])["profile_hash"] = badHash
		for _, rawProfile := range array(object(context["model_gateway"])["profiles"]) {
			profile := object(rawProfile)
			if stringValue(profile["purpose"]) == "GENERATION" {
				profile["profile_hash"] = badHash
			}
		}
		generationRun := modelRunForPurpose(manifest, "GENERATION")
		generationRun["profile_hash"] = badHash
		if err := synchronizeGatewayRun(context, generationRun); err != nil {
			return err
		}
	case "UNRELATED_EMBEDDING_RUN":
		if err := mutateSelectedModelArtifact(manifest, context, "EMBEDDING", func(artifact map[string]any) {
			object(artifact["input"])["question_text"] = "Unrelated question"
		}); err != nil {
			return err
		}
	case "UNRELATED_RERANKING_RUN":
		if err := mutateSelectedModelArtifact(manifest, context, "RERANKING", func(artifact map[string]any) {
			object(artifact["input"])["question_text"] = "Unrelated question"
		}); err != nil {
			return err
		}
	case "UNRELATED_GENERATION_RUN":
		if err := mutateSelectedModelArtifact(manifest, context, "GENERATION", func(artifact map[string]any) {
			object(artifact["input"])["question_text"] = "Unrelated question"
		}); err != nil {
			return err
		}
	case "PROMPT_TEMPLATE_DRIFT":
		if err := mutateSelectedModelArtifact(manifest, context, "GENERATION", func(artifact map[string]any) {
			object(artifact["input"])["prompt_version"] = "attacker-prompt-v9"
		}); err != nil {
			return err
		}
	case "GENERATION_PLAN_DRIFT":
		if err := mutateSelectedModelArtifact(manifest, context, "GENERATION", func(artifact map[string]any) {
			object(array(object(artifact["output"])["claims"])[0])["text"] = "\u041f\u043e\u0434\u043c\u0435\u043d\u0451\u043d\u043d\u044b\u0439 \u0438\u0442\u043e\u0433 \u0433\u0435\u043d\u0435\u0440\u0430\u0446\u0438\u0438."
		}); err != nil {
			return err
		}
	case "MODEL_RUN_OUTSIDE_INTERVAL":
		generationRun := modelRunForPurpose(manifest, "GENERATION")
		generationRun["started_at"] = "2026-07-14T11:59:59Z"
		if err := synchronizeGatewayRun(context, generationRun); err != nil {
			return err
		}
	case "RERANKER_INCOMPLETE_CANDIDATE_SET":
		if err := mutateSelectedModelArtifact(manifest, context, "RERANKING", func(artifact map[string]any) {
			input := object(artifact["input"])
			candidates := array(input["candidates"])
			input["candidates"] = candidates[:len(candidates)-1]
		}); err != nil {
			return err
		}
	case "RERANKER_OUTPUT_OMISSION":
		if err := mutateSelectedModelArtifact(manifest, context, "RERANKING", func(artifact map[string]any) {
			output := object(artifact["output"])
			ordered := array(output["ordered_evidence_fragment_ids"])
			output["ordered_evidence_fragment_ids"] = ordered[:len(ordered)-1]
		}); err != nil {
			return err
		}
		rerankingRun := modelRunForPurpose(manifest, "RERANKING")
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			object(retrievalContext["authorization_snapshot"])["reranking_output_hash"] = rerankingRun["output_hash"]
			return nil
		}); err != nil {
			return err
		}
	case "RERANKER_CONTEXT_ORDER_SWAP":
		if err := mutateSelectedModelArtifact(manifest, context, "RERANKING", func(artifact map[string]any) {
			ordered := array(object(artifact["output"])["ordered_evidence_fragment_ids"])
			ordered[0], ordered[1] = ordered[1], ordered[0]
		}); err != nil {
			return err
		}
		rerankingRun := modelRunForPurpose(manifest, "RERANKING")
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			object(retrievalContext["authorization_snapshot"])["reranking_output_hash"] = rerankingRun["output_hash"]
			return nil
		}); err != nil {
			return err
		}
	case "EXECUTION_PLAN_SELF_DECLARED":
		manifest["execution_plan"] = map[string]any{"planned_purposes": []any{"EMBEDDING"}}
	case "UNPLANNED_MODEL_ATTEMPT":
		generationRun := modelRunForPurpose(manifest, "GENERATION")
		unplanned := cloneObject(generationRun)
		unplanned["model_run_id"] = "mr_generation_unplanned_2"
		unplanned["attempt"] = float64(2)
		unplanned["selected_for_result"] = false
		unplanned["started_at"] = "2026-07-14T12:00:05Z"
		unplanned["completed_at"] = "2026-07-14T12:00:08Z"
		manifest["model_runs"] = append(array(manifest["model_runs"]), unplanned)
		context["executed_model_run_ids"] = append(array(context["executed_model_run_ids"]), "mr_generation_unplanned_2")
		object(context["model_gateway"])["runs"] = append(array(object(context["model_gateway"])["runs"]), cloneObject(unplanned))
	case "MODEL_PLAN_OMIT_REQUIRED_RERANKING":
		plan, err := mutableContextFixture(context, "model_execution_plan_fixture")
		if err != nil {
			return err
		}
		plan["planned_purposes"] = []any{"EMBEDDING", "GENERATION", "VERIFICATION"}
		delete(object(plan["selected_run_ids"]), "RERANKING")
		filteredAttempts := make([]any, 0)
		for _, rawAttempt := range array(plan["attempts"]) {
			if stringValue(object(rawAttempt)["purpose"]) != "RERANKING" {
				filteredAttempts = append(filteredAttempts, rawAttempt)
			}
		}
		plan["attempts"] = filteredAttempts
		if err := synchronizeModelExecutionPlan(manifest, context); err != nil {
			return err
		}
	case "MODEL_PLAN_NONCONTIGUOUS_ATTEMPTS":
		generationRun := modelRunForPurpose(manifest, "GENERATION")
		generationRun["attempt"] = float64(3)
		if err := synchronizeGatewayRun(context, generationRun); err != nil {
			return err
		}
		plan, err := mutableContextFixture(context, "model_execution_plan_fixture")
		if err != nil {
			return err
		}
		for _, rawAttempt := range array(plan["attempts"]) {
			attempt := object(rawAttempt)
			if stringValue(attempt["purpose"]) == "GENERATION" {
				attempt["attempt"] = float64(3)
			}
		}
		if err := synchronizeModelExecutionPlan(manifest, context); err != nil {
			return err
		}
	case "MODEL_PLAN_PROFILE_HASH_SWAP":
		plan, err := mutableContextFixture(context, "model_execution_plan_fixture")
		if err != nil {
			return err
		}
		hashes := object(plan["configured_profile_hashes"])
		hashes["GENERATION"], hashes["RERANKING"] = hashes["RERANKING"], hashes["GENERATION"]
		if err := synchronizeModelExecutionPlan(manifest, context); err != nil {
			return err
		}
	case "EXTRACTION_PROVENANCE_TAMPER":
		extraction := object(array(manifest["extractions"])[0])
		object(object(extraction["profile"])["extractor"])["version"] = "9.9.9"
		profileHash, err := hashCanonical(extraction["profile"])
		if err != nil {
			return err
		}
		extraction["profile_hash"] = profileHash
	case "DUPLICATE_MODEL_PURPOSE":
		object(object(manifest["configured_profiles"])["reranking"])["purpose"] = "EMBEDDING"
	case "COMPLETE_TRUNCATED":
		object(manifest["retrieval"])["truncated"] = true
		object(manifest["retrieval"])["truncation_reason"] = "TOKEN_BUDGET"
		if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
			return err
		}
	case "RETRIEVAL_PROVENANCE_TAMPER":
		object(manifest["retrieval"])["authorized_candidate_count"] = float64(4)
	case "RETRIEVAL_PROFILE_MISMATCH":
		object(manifest["retrieval"])["pipeline_profile_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CANDIDATE_CONTEXT_COUNT_COLLAPSED":
		object(manifest["retrieval"])["authorized_candidate_count"] = object(manifest["retrieval"])["context_count"]
	case "SNAPSHOT_MODEL_BINDING_MISMATCH":
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			object(retrievalContext["authorization_snapshot"])["embedding_model_run_id"] = "mr_embedding_foreign"
			return nil
		}); err != nil {
			return err
		}
	case "UNAUTHORIZED_CANDIDATE_COUNT_FIELD":
		object(manifest["retrieval"])["preauthorization_candidate_count"] = float64(1000)
	case "AUTHORIZATION_OUTSIDE_INTERVAL":
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			object(retrievalContext["authorization_snapshot"])["captured_at"] = "2026-07-14T11:59:59Z"
			return nil
		}); err != nil {
			return err
		}
	case "NONACTIVE_EXTRACTION_CONTEXT":
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			entry := object(array(object(retrievalContext["authorization_snapshot"])["entries"])[0])
			entry["extraction_retention_state"] = "PURGING"
			entry["extraction_queryable"] = false
			return nil
		}); err != nil {
			return err
		}
	case "STALE_PRINCIPAL_SET":
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			grant := object(object(array(object(retrievalContext["authorization_snapshot"])["entries"])[0])["grant"])
			grant["principal_set_snapshot_id"] = "pss_stale"
			return nil
		}); err != nil {
			return err
		}
	case "STALE_ACL_PARTIAL_CITATION":
		object(manifest["status"])["corpus"] = "PARTIAL"
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:00:00Z"); err != nil {
			return err
		}
	case "AUTHORIZATION_FOREIGN_SCOPE":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(object(array(retrievalContext["authorized_candidate_set"])[0])["grant"])["source_scope_id"] = "scope_foreign"
	case "AUTHORIZATION_FOREIGN_POLICY":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(object(array(retrievalContext["authorized_candidate_set"])[0])["grant"])["policy_decision_id"] = "pd_foreign"
	case "AUTHORIZATION_MEMBERSHIP_REMOVED":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(array(retrievalContext["live_object_scope_memberships"])[0])["state"] = "REMOVED"
	case "AUTHORIZATION_WORKSPACE_MEMBERSHIP_REVOKED":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(array(retrievalContext["live_workspace_memberships"])[0])["status"] = "REMOVED"
	case "AUTHORIZATION_CONFIRMATION_REVOKED":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		confirmation := object(array(retrievalContext["live_workspace_managed_confirmations"])[0])
		revocation := map[string]any{
			"schema_version": "workspace-managed-confirmation-revocation-v1", "revocation_id": "revoke_confirmation_1", "organization_id": confirmation["organization_id"],
			"confirmation_id": confirmation["confirmation_id"], "confirmation_hash": confirmation["confirmation_hash"], "revoked_by": "user_security_admin",
			"revoked_at": "2026-07-14T11:55:00Z", "reason_code": "ACCESS_REVOKED", "policy_revision": confirmation["policy_revision"],
		}
		revocationHash, hashErr := hashCanonical(workspaceManagedConfirmationRevocationHashInput(revocation))
		if hashErr != nil {
			return hashErr
		}
		revocation["revocation_hash"] = revocationHash
		retrievalContext["workspace_managed_confirmation_revocations"] = []any{revocation}
	case "AUTHORIZATION_FOREIGN_TENANT":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(retrievalContext["live_workspace_revision"])["organization_id"] = "org_foreign"
	case "AUTHORIZATION_CONFIRMATION_UNAUTHORIZED_ACTOR":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(array(retrievalContext["live_workspace_managed_confirmations"])[0])["confirmed_by"] = "user_attacker"
	case "AUTHORIZATION_ACCESS_MODE_MISMATCH":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		object(object(array(retrievalContext["authorized_candidate_set"])[0])["grant"])["access_mode"] = "SOURCE_ENFORCED"
	case "AUTHORIZATION_NO_ACL_INTERSECTION":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:59:00Z"); err != nil {
			return err
		}
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		acl := object(array(retrievalContext["live_acl_snapshots"])[0])
		acl["principal_token_digests"] = []any{map[string]any{
			"namespace": "oidc:issuer-alpha", "type": "USER",
			"subject_digest": "hmac-sha256:k7:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "revision": "rev-0007",
		}}
		aclHash, err := hashCanonical(aclSnapshotHashInput(acl))
		if err != nil {
			return err
		}
		acl["content_hash"] = aclHash
		updateACLHash := func(grant map[string]any) {
			if stringValue(grant["acl_snapshot_id"]) == stringValue(acl["acl_snapshot_id"]) {
				grant["acl_snapshot_hash"] = aclHash
			}
		}
		for _, rawCandidate := range array(retrievalContext["authorized_candidate_set"]) {
			updateACLHash(object(object(rawCandidate)["grant"]))
		}
		for _, rawEntry := range array(object(retrievalContext["authorization_snapshot"])["entries"]) {
			updateACLHash(object(object(rawEntry)["grant"]))
		}
		if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
			return err
		}
		if err := synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext); err != nil {
			return err
		}
	case "NONDETERMINISTIC_GRANT_PATH":
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		retrievalContext["live_object_scope_memberships"] = append(array(retrievalContext["live_object_scope_memberships"]), map[string]any{
			"organization_id": manifest["organization_id"], "source_object_id": "source_object_1", "source_scope_id": "scope_site", "source_scope_revision": float64(5), "state": "ACTIVE",
		})
		shadowDecision := cloneObject(object(array(retrievalContext["live_policy_decisions"])[1]))
		shadowDecision["policy_decision_id"] = "pd_site_shadow"
		shadowDecision["source_object_id"] = "source_object_1"
		retrievalContext["live_policy_decisions"] = append(array(retrievalContext["live_policy_decisions"]), shadowDecision)
		selectLargerPath := func(grant map[string]any) {
			grant["source_scope_id"] = "scope_site"
			grant["source_scope_revision"] = float64(5)
			grant["workspace_managed_confirmation_id"] = "wmc_site_5"
			grant["policy_decision_id"] = "pd_site_shadow"
		}
		selectLargerPath(object(object(array(retrievalContext["authorized_candidate_set"])[0])["grant"]))
		selectLargerPath(object(object(array(object(retrievalContext["authorization_snapshot"])["entries"])[0])["grant"]))
		if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
			return err
		}
		if err := synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext); err != nil {
			return err
		}
	case "ACL_HASH_TIMESTAMP_CHANGE":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:59:00Z"); err != nil {
			return err
		}
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		acl := object(array(retrievalContext["live_acl_snapshots"])[0])
		acl["resolved_at"] = "2026-07-14T11:58:30Z"
		for _, collection := range [][]any{array(retrievalContext["authorized_candidate_set"]), array(object(retrievalContext["authorization_snapshot"])["entries"])} {
			for _, rawItem := range collection {
				grant := object(object(rawItem)["grant"])
				if stringValue(grant["acl_snapshot_id"]) == stringValue(acl["acl_snapshot_id"]) {
					grant["acl_resolved_at"] = acl["resolved_at"]
				}
			}
		}
		if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
			return err
		}
		if err := synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext); err != nil {
			return err
		}
	case "ACL_HASH_BODY_TAMPER":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:59:00Z"); err != nil {
			return err
		}
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		acl := object(array(retrievalContext["live_acl_snapshots"])[0])
		object(array(acl["principal_token_digests"])[0])["revision"] = "tampered-revision"
	case "AUTHORIZATION_FOREIGN_ACL_OBJECT":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:59:00Z"); err != nil {
			return err
		}
		retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
		if err != nil {
			return err
		}
		foreign := cloneObject(object(array(retrievalContext["live_acl_snapshots"])[0]))
		foreign["acl_snapshot_id"] = "acl_foreign_1"
		foreign["source_object_id"] = "source_object_foreign"
		foreign["source_version_id"] = "source_version_foreign"
		retrievalContext["live_acl_snapshots"] = append(array(retrievalContext["live_acl_snapshots"]), foreign)
		retrievalContext["live_source_acl_pointers"] = append(array(retrievalContext["live_source_acl_pointers"]), map[string]any{
			"organization_id": manifest["organization_id"], "source_object_id": foreign["source_object_id"], "source_version_id": foreign["source_version_id"], "acl_snapshot_id": foreign["acl_snapshot_id"],
		})
		for _, collection := range [][]any{array(retrievalContext["authorized_candidate_set"]), array(object(retrievalContext["authorization_snapshot"])["entries"])} {
			for _, rawItem := range collection {
				item := object(rawItem)
				grant := object(item["grant"])
				if stringValue(item["source_object_id"]) == "source_object_2" {
					grant["acl_snapshot_id"] = foreign["acl_snapshot_id"]
					grant["acl_snapshot_hash"] = foreign["content_hash"]
				}
			}
		}
		if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
			return err
		}
		if err := synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext); err != nil {
			return err
		}
	case "ZERO_CONTEXT_STALE_PRINCIPAL_SET":
		access := object(context["access_context"])
		snapshot := object(context["principal_set_snapshot"])
		access["principal_set_expires_at"] = "2026-07-14T12:59:59Z"
		snapshot["expires_at"] = "2026-07-14T12:59:59Z"
		accessHash, err := hashCanonical(access)
		if err != nil {
			return err
		}
		manifest["access_context_hash"] = accessHash
	case "ZERO_CONTEXT_MIDPOINT_EXPIRED_PRINCIPAL_SET":
		access := object(context["access_context"])
		snapshot := object(context["principal_set_snapshot"])
		access["principal_set_expires_at"] = "2026-07-14T13:00:01Z"
		snapshot["expires_at"] = "2026-07-14T13:00:01Z"
		accessHash, err := hashCanonical(access)
		if err != nil {
			return err
		}
		manifest["access_context_hash"] = accessHash
	case "CORPUS_SOURCE_MISSING":
		corpus := array(manifest["corpus_snapshot"])
		manifest["corpus_snapshot"] = corpus[:len(corpus)-1]
	case "CORPUS_SOURCE_DUPLICATE":
		corpus := array(manifest["corpus_snapshot"])
		manifest["corpus_snapshot"] = append(corpus, cloneObject(object(corpus[1])))
	case "CORPUS_SOURCE_EXTRA":
		corpus := array(manifest["corpus_snapshot"])
		extra := cloneObject(object(corpus[1]))
		extra["source_scope_id"] = "scope_extra"
		extra["source_scope_revision"] = float64(1)
		manifest["corpus_snapshot"] = append(corpus, extra)
	case "CORPUS_SOURCE_BINDING_MISMATCH":
		object(array(manifest["corpus_snapshot"])[1])["scope_config_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CORPUS_PARTIAL_UNAVAILABLE":
		source := object(array(manifest["corpus_snapshot"])[1])
		source["health"] = "UNAVAILABLE"
		source["last_successful_sync"] = nil
		trusted := object(object(context["source_health_snapshots"])["scope_site@5"])
		trusted["health"] = "UNAVAILABLE"
		trusted["last_successful_sync"] = nil
		object(manifest["status"])["corpus"] = "PARTIAL"
		if err := synchronizeGenerationArtifact(manifest, context, true, false); err != nil {
			return err
		}
	case "CORPUS_HEALTH_SELF_DECLARED":
		object(array(manifest["corpus_snapshot"])[1])["content_watermark"] = "crawl:attacker"
	case "CORPUS_STALE_COMPLETE":
		object(array(manifest["corpus_snapshot"])[1])["last_successful_sync"] = "2026-07-14T11:00:00Z"
		object(object(context["source_health_snapshots"])["scope_site@5"])["last_successful_sync"] = "2026-07-14T11:00:00Z"
	case "CORPUS_SOURCE_ENFORCED_FRESH":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:59:00Z"); err != nil {
			return err
		}
	case "CORPUS_SOURCE_ENFORCED_ACL_STALE":
		if err := makeCorpusSourceEnforced(manifest, context, "2026-07-14T11:00:00Z"); err != nil {
			return err
		}
	case "PARTIAL_INSUFFICIENT":
		object(manifest["status"])["result"] = "INSUFFICIENT_EVIDENCE"
		unknown := map[string]any{
			"claim_id": "C5", "text": "\u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438 \u043d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0439 \u0434\u043b\u044f \u043d\u0430\u0434\u0451\u0436\u043d\u043e\u0433\u043e \u043e\u0442\u0432\u0435\u0442\u0430.", "kind": "UNKNOWN", "unknown_reason": "INSUFFICIENT_SUPPORT",
			"support_status": "NOT_APPLICABLE", "citation_numbers": []any{}, "supporting_claim_ids": []any{},
			"answer_span": map[string]any{"start": float64(1), "end": float64(2), "offset_unit": "UTF8_BYTE", "range_semantics": "START_INCLUSIVE_END_EXCLUSIVE", "normalization_version": "text-v1"},
		}
		manifest["claims"] = append(claims, unknown)
		sections := array(manifest["sections"])
		lastSection := object(sections[len(sections)-1])
		lastSection["ordered_claim_ids"] = append(array(lastSection["ordered_claim_ids"]), "C5")
		if err := rerenderManifest(manifest); err != nil {
			return err
		}
		if err := synchronizeGenerationArtifact(manifest, context, false, true); err != nil {
			return err
		}
	case "NONEMPTY_CONTEXT_UNKNOWN_COMPLETED":
		object(manifest["status"])["result"] = "COMPLETED"
		context["context_pack"] = []any{map[string]any{
			"evidence_fragment_id": "ev_irrelevant", "source_version_id": "sv_irrelevant", "extraction_id": "ext_irrelevant",
			"extraction_profile_hash":     "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			"source_version_content_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
			"evidence_text_hash":          "sha256:3333333333333333333333333333333333333333333333333333333333333333",
			"anchor_hash":                 "hmac-sha256:k1:4444444444444444444444444444444444444444444444444444444444444444",
			"exact_context_base64":        "", "exact_context_hash": sha256String([]byte{}),
		}}
		contextHash, err := hashCanonical(contextPackHashInput(array(context["context_pack"])))
		if err != nil {
			return err
		}
		retrieval := object(manifest["retrieval"])
		retrieval["context_pack_hash"] = contextHash
		retrieval["context_count"] = float64(1)
		retrieval["authorized_candidate_count"] = float64(1)
		if err := synchronizeRetrievalFixture(manifest, context, func(retrievalContext map[string]any) error {
			item := object(array(context["context_pack"])[0])
			retrievalContext["authorized_candidate_set"] = []any{map[string]any{
				"ordinal": float64(1), "evidence_fragment_id": item["evidence_fragment_id"], "source_version_id": item["source_version_id"],
				"extraction_id": item["extraction_id"], "evidence_text_hash": item["evidence_text_hash"], "exact_context_hash": item["exact_context_hash"],
			}}
			access := object(context["access_context"])
			object(retrievalContext["authorization_snapshot"])["entries"] = []any{map[string]any{
				"ordinal": float64(1), "source_object_id": "source_irrelevant", "source_version_id": item["source_version_id"],
				"source_version_state": "CURRENT", "source_version_retention_state": "ACTIVE", "source_version_queryable": true, "source_version_retention_fence": float64(1),
				"extraction_id": item["extraction_id"], "active_extraction_id": item["extraction_id"], "activation_revision": float64(1),
				"extraction_retention_state": "ACTIVE", "extraction_queryable": true, "extraction_retention_fence_at_start": float64(1),
				"evidence_fragment_id": item["evidence_fragment_id"], "extraction_profile_hash": item["extraction_profile_hash"],
				"source_version_content_hash": item["source_version_content_hash"], "evidence_text_hash": item["evidence_text_hash"],
				"anchor_hash": item["anchor_hash"], "exact_context_hash": item["exact_context_hash"],
				"grant": map[string]any{
					"source_scope_id": "scope_projects", "source_scope_revision": float64(3), "access_mode": "WORKSPACE_MANAGED", "membership_state": "ACTIVE",
					"policy_decision_id": "pd_irrelevant_1", "policy_decision": "ALLOW", "principal_set_snapshot_id": access["principal_set_snapshot_id"],
					"principal_set_snapshot_hash": access["principal_set_snapshot_hash"], "principal_set_captured_at": access["principal_set_captured_at"],
					"principal_set_expires_at": access["principal_set_expires_at"], "authorized_at": "2026-07-14T13:00:02Z",
					"acl_snapshot_id": nil, "acl_snapshot_hash": nil, "acl_snapshot_status": nil, "acl_resolved_at": nil, "acl_expires_at": nil,
				},
			}}
			return nil
		}); err != nil {
			return err
		}
	case "EMPTY_CONTEXT_COMPLETED":
		object(manifest["status"])["result"] = "COMPLETED"
	case "DUPLICATE_CLAIM":
		manifest["claims"] = append(claims, cloneObject(object(claims[0])))
		if err := synchronizeGenerationArtifact(manifest, context, false, true); err != nil {
			return err
		}
	case "EXTRACTIVE_GENERATOR_PRESENT":
		profiles := object(manifest["configured_profiles"])
		for _, rawProfile := range array(object(context["model_gateway"])["profiles"]) {
			profile := object(rawProfile)
			if stringValue(profile["purpose"]) == "GENERATION" {
				profiles["generation"] = cloneObject(profile)
				break
			}
		}
		if profiles["generation"] == nil {
			return fail("EXTRACTIVE_GENERATION_PROFILE_FIXTURE_MISSING")
		}
	case "SIGNATURE_OUTSIDE_INTERVAL":
		object(manifest["signature"])["signed_at"] = "2026-07-14T11:59:59Z"
	default:
		return fail("UNKNOWN_MANIFEST_MUTATION", mutation)
	}
	return rehashAndSignManifest(manifest, context)
}

func makeCorpusSourceEnforced(manifest, context map[string]any, aclFreshAt string) error {
	config := object(object(context["scope_configs"])["scope_site@5"])
	config["access_mode"] = "SOURCE_ENFORCED"
	configHash, err := hashCanonical(config)
	if err != nil {
		return err
	}
	bindings := array(object(context["workspace_scope"])["bindings"])
	object(bindings[1])["scope_config_hash"] = configHash
	workspaceHash, err := hashCanonical(context["workspace_scope"])
	if err != nil {
		return err
	}
	manifest["workspace_scope_hash"] = workspaceHash
	source := object(array(manifest["corpus_snapshot"])[1])
	source["access_mode"] = "SOURCE_ENFORCED"
	source["scope_config_hash"] = configHash
	source["acl_fresh_at"] = aclFreshAt
	trusted := object(object(context["source_health_snapshots"])["scope_site@5"])
	trusted["access_mode"] = "SOURCE_ENFORCED"
	trusted["scope_config_hash"] = configHash
	trusted["acl_fresh_at"] = aclFreshAt
	retrievalContext, err := mutableContextFixture(context, "retrieval_context_fixture")
	if err != nil {
		return err
	}
	for _, rawBinding := range array(object(retrievalContext["live_workspace_revision"])["bindings"]) {
		binding := object(rawBinding)
		if stringValue(binding["source_scope_id"]) == "scope_site" {
			binding["access_mode"] = "SOURCE_ENFORCED"
			binding["scope_config_hash"] = configHash
			binding["workspace_managed_confirmation_id"] = nil
		}
	}
	workspaceManagedConfirmations := make([]any, 0)
	for _, rawConfirmation := range array(retrievalContext["live_workspace_managed_confirmations"]) {
		confirmation := object(rawConfirmation)
		if stringValue(confirmation["source_scope_id"]) != "scope_site" {
			workspaceManagedConfirmations = append(workspaceManagedConfirmations, confirmation)
		}
	}
	retrievalContext["live_workspace_managed_confirmations"] = workspaceManagedConfirmations
	for _, rawDecision := range array(retrievalContext["live_policy_decisions"]) {
		decision := object(rawDecision)
		if stringValue(decision["source_scope_id"]) == "scope_site" {
			decision["workspace_managed_confirmation_id"] = nil
		}
	}
	aclExpiresAt := "2026-07-14T12:10:00Z"
	if aclFreshAt == "2026-07-14T11:00:00Z" {
		aclExpiresAt = "2026-07-14T11:30:00Z"
	}
	principalTokenDigests := make([]any, 0)
	for _, rawPrincipal := range array(object(context["access_context"])["effective_principals"]) {
		principalTokenDigests = append(principalTokenDigests, cloneObject(object(rawPrincipal)))
	}
	aclSnapshot := map[string]any{
		"acl_snapshot_id": "acl_site_1", "organization_id": manifest["organization_id"], "source_object_id": "source_object_2", "source_version_id": "source_version_2",
		"status": "RESOLVED", "digest_key_version": object(context["principal_set_snapshot"])["digest_key_version"], "resolved_at": aclFreshAt, "expires_at": aclExpiresAt,
		"principal_token_digests": principalTokenDigests,
	}
	aclHash, err := hashCanonical(aclSnapshotHashInput(aclSnapshot))
	if err != nil {
		return err
	}
	aclSnapshot["content_hash"] = aclHash
	retrievalContext["live_acl_snapshots"] = []any{aclSnapshot}
	retrievalContext["live_source_acl_pointers"] = []any{map[string]any{
		"organization_id": manifest["organization_id"], "source_object_id": "source_object_2", "source_version_id": "source_version_2", "acl_snapshot_id": "acl_site_1",
	}}
	setSourceEnforcedGrant := func(grant map[string]any) {
		grant["access_mode"] = "SOURCE_ENFORCED"
		grant["workspace_managed_confirmation_id"] = nil
		grant["acl_snapshot_id"] = "acl_site_1"
		grant["acl_snapshot_hash"] = aclHash
		grant["acl_snapshot_status"] = "RESOLVED"
		grant["acl_resolved_at"] = aclFreshAt
		grant["acl_expires_at"] = aclExpiresAt
	}
	for _, rawCandidate := range array(retrievalContext["authorized_candidate_set"]) {
		candidate := object(rawCandidate)
		grant := object(candidate["grant"])
		if stringValue(grant["source_scope_id"]) == "scope_site" {
			setSourceEnforcedGrant(grant)
		}
	}
	for _, rawEntry := range array(object(retrievalContext["authorization_snapshot"])["entries"]) {
		entry := object(rawEntry)
		grant := object(entry["grant"])
		if stringValue(grant["source_scope_id"]) == "scope_site" {
			setSourceEnforcedGrant(grant)
		}
	}
	if err := synchronizeRetrievalFixture(manifest, context, nil); err != nil {
		return err
	}
	return synchronizeRerankingCandidateArtifact(manifest, context, retrievalContext)
}

func rerenderManifest(manifest map[string]any) error {
	markdown, spans, err := renderAnswer(array(manifest["claims"]), array(manifest["sections"]))
	if err != nil {
		return err
	}
	claims := map[string]map[string]any{}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		claims[stringValue(claim["claim_id"])] = claim
	}
	for _, span := range spans {
		answerSpan := object(claims[span.ClaimID]["answer_span"])
		answerSpan["start"] = float64(span.Start)
		answerSpan["end"] = float64(span.End)
	}
	manifest["answer_hash"] = sha256String(markdown)
	return nil
}

// setCitationAnchor replaces a citation's anchor with the given projection and
// recomputes its anchor_hash as the organization-scoped HMAC of the JCS anchor
// object (CANONICALIZATION.md s7), keyed by the version the citation declares.
func setCitationAnchor(context, citation map[string]any, anchor map[string]any) error {
	citation["anchor"] = anchor
	version, err := keyedDigestVersion(stringValue(citation["anchor_hash"]))
	if err != nil {
		return err
	}
	keyBytes, err := extractiveHMACKey(context, version)
	if err != nil {
		return err
	}
	hash, err := extractiveHMACDigest(keyBytes, version, anchor)
	if err != nil {
		return err
	}
	citation["anchor_hash"] = hash
	return nil
}

func executeConnectorReplay(mutation string) error {
	event, _, err := loadObject("fixtures/valid/connector-upsert-file.json")
	if err != nil {
		return err
	}
	context, _, err := loadObject("fixtures/context/connector-upsert-file.context.json")
	if err != nil {
		return err
	}
	if err := validateConnectorEvent(event, context); err != nil {
		return err
	}
	state := newConnectorReplayState()
	if err := state.accept(event); err != nil {
		return err
	}
	second := cloneObject(event)
	switch mutation {
	case "EXACT_REPLAY":
	case "PAYLOAD_CONFLICT":
		object(second["object_metadata"])["title"] = "\u041f\u043e\u0434\u043c\u0435\u043d\u0451\u043d\u043d\u044b\u0439 \u043f\u043b\u0430\u043d \u0437\u0430\u043f\u0443\u0441\u043a\u0430.txt"
		if err := rehashAndSignConnector(second, context); err != nil {
			return err
		}
	case "NONCE_REPLAY":
		second["event_id"] = "33333333-3333-4333-8333-333333333333"
		second["idempotency_key"] = "connector-file-0001-v1-replay"
		if err := rehashAndSignConnector(second, context); err != nil {
			return err
		}
	}
	if err := validateConnectorEvent(second, context); err != nil {
		return err
	}
	return state.accept(second)
}

func makeWebEvent(event map[string]any, canonicalURL string) {
	sourceBytes := []byte{}
	_ = sourceBytes
	event["object_type"] = "WEB_PAGE"
	event["external_object_id"] = "web-page-0001"
	metadata := map[string]any{
		"kind": "WEB_PAGE", "title": "Release", "mime_type": "text/html",
		"source_updated_at": "2026-07-14T11:58:00Z", "size_bytes": float64(157),
		"canonical_url": canonicalURL, "etag": nil, "last_modified": "2026-07-14T11:58:00Z",
		"canonical_locator_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	event["object_metadata"] = metadata
	object(event["content_reference"])["media_type"] = "text/html"
	locatorURL, err := canonicalWebURL(canonicalURL)
	if err == nil {
		hash, _ := hashCanonical(map[string]any{"canonical_url": locatorURL, "connection_id": event["connection_id"], "kind": "WEB_PAGE"})
		metadata["canonical_locator_hash"] = hash
	}
}

func validateConnectorBoundary(event, context map[string]any, mutation string) error {
	limit := 0
	switch mutation {
	case "GIT_REPOSITORY_MAX":
		limit = 1024
		makeGitEvent(event, strings.Repeat("r", limit))
	case "GIT_REPOSITORY_MAX_PLUS_ONE":
		limit = 1025
		makeGitEvent(event, strings.Repeat("r", limit))
	case "EMAIL_MESSAGE_ID_MAX":
		limit = 2048
		makeEmailEvent(event, strings.Repeat("m", limit))
	case "EMAIL_MESSAGE_ID_MAX_PLUS_ONE":
		limit = 2049
		makeEmailEvent(event, strings.Repeat("m", limit))
	case "WEB_URL_MAX":
		limit = 8192
		prefix := "https://example.com/"
		makeWebEvent(event, prefix+strings.Repeat("a", limit-len(prefix)))
	case "WEB_URL_MAX_PLUS_ONE":
		limit = 8193
		prefix := "https://example.com/"
		makeWebEvent(event, prefix+strings.Repeat("a", limit-len(prefix)))
	case "EXTERNAL_VERSION_HASH_GARBAGE":
		event["external_version_key"] = "hash:sha256:" + strings.Repeat("a", 64) + "garbage"
	}
	if err := rehashAndSignConnector(event, context); err != nil {
		return err
	}
	return validateConnectorEvent(event, context)
}

func makeGitEvent(event map[string]any, repository string) {
	event["object_type"] = "GIT_FILE"
	event["external_object_id"] = "git-file-0001"
	metadata := map[string]any{
		"kind": "GIT_FILE", "title": "release.go", "mime_type": "text/plain",
		"source_updated_at": "2026-07-14T11:58:00Z", "size_bytes": float64(157),
		"provider": "GITHUB", "repository": repository, "commit_sha": strings.Repeat("a", 40),
		"branch": "main", "path": "src/release.go",
		"canonical_locator_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	event["object_metadata"] = metadata
	hash, _ := hashCanonical(map[string]any{"branch": "main", "connection_id": event["connection_id"], "kind": "GIT_FILE", "path": "src/release.go", "provider": "GITHUB", "repository": repository})
	metadata["canonical_locator_hash"] = hash
}

func makeEmailEvent(event map[string]any, messageID string) {
	event["object_type"] = "EMAIL"
	event["external_object_id"] = "email-0001"
	metadata := map[string]any{
		"kind": "EMAIL", "subject": "Release", "mime_type": "message/rfc822",
		"source_updated_at": "2026-07-14T11:58:00Z", "size_bytes": float64(157),
		"immutable_message_id": messageID, "thread_id": nil, "mailbox_id": "mailbox-alpha",
		"folder_id": "folder-alpha", "sender": "sender@example.com", "recipients": []any{"team@example.com"},
		"sent_at":                "2026-07-14T11:57:00Z",
		"canonical_locator_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	event["object_metadata"] = metadata
	object(event["content_reference"])["media_type"] = "message/rfc822"
	hash, _ := hashCanonical(map[string]any{"connection_id": event["connection_id"], "immutable_message_id": messageID, "kind": "EMAIL", "mailbox_id": "mailbox-alpha"})
	metadata["canonical_locator_hash"] = hash
}

func decodedBase64(value string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(value)
	return decoded
}

// TestWorkspaceScopeClosedFormRejectsReintroducedConfirmationID proves the
// workspace_scope v1 form is closed even against an attacker who correctly
// recomputes workspace_scope_hash, manifest_hash and the Ed25519 signature
// after reintroducing workspace_managed_confirmation_id. A single test that
// only checks the old (stale) hash would not exercise this path, since a
// stale hash is rejected before the shape is ever inspected.
func TestWorkspaceScopeClosedFormRejectsReintroducedConfirmationID(t *testing.T) {
	manifest, _, err := loadObject("fixtures/valid/answer-manifest-completed.json")
	if err != nil {
		t.Fatal(err)
	}
	context, _, err := loadObject("fixtures/context/answer-manifest-completed.context.json")
	if err != nil {
		t.Fatal(err)
	}
	bindings := array(object(context["workspace_scope"])["bindings"])
	object(bindings[0])["workspace_managed_confirmation_id"] = "wmc_projects_3"
	workspaceHash, err := hashCanonical(context["workspace_scope"])
	if err != nil {
		t.Fatal(err)
	}
	manifest["workspace_scope_hash"] = workspaceHash
	if err := rehashAndSignManifest(manifest, context); err != nil {
		t.Fatal(err)
	}
	err = validateAnswerManifest(manifest, context)
	if errorCode(err) != "JSON_UNKNOWN_FIELD" {
		t.Fatalf("expected JSON_UNKNOWN_FIELD for a correctly rehashed and resigned manifest carrying workspace_managed_confirmation_id, got %q (%v)", errorCode(err), err)
	}
}
