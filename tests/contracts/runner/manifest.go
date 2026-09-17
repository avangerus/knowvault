package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func validateManifestIntegrity(manifest, context map[string]any) error {
	content := cloneObject(manifest)
	delete(content, "manifest_hash")
	delete(content, "signature")
	contentBytes, err := canonicalValue(content)
	if err != nil {
		return err
	}
	if stringValue(manifest["manifest_hash"]) != sha256String(contentBytes) {
		return fail("MANIFEST_HASH_MISMATCH")
	}
	_, publicKey, keyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	signature := object(manifest["signature"])
	key := object(context["key"])
	if stringValue(key["status"]) == "REVOKED" {
		return fail("SIGNATURE_KEY_REVOKED")
	}
	if (stringValue(key["status"]) != "ACTIVE" && stringValue(key["status"]) != "RETIRED") || stringValue(signature["key_id"]) != keyID {
		return fail("MANIFEST_SIGNING_KEY_INVALID")
	}
	if stringValue(key["organization_id"]) != stringValue(manifest["organization_id"]) || stringValue(key["purpose"]) != "ANSWER_MANIFEST" || key["connection_id"] != nil || key["connector_agent_id"] != nil {
		return fail("MANIFEST_SIGNING_KEY_SCOPE_MISMATCH")
	}
	signedAt, signedErr := time.Parse(time.RFC3339, stringValue(signature["signed_at"]))
	notBefore, beforeErr := time.Parse(time.RFC3339, stringValue(key["not_before"]))
	signUntil, untilErr := time.Parse(time.RFC3339, stringValue(key["sign_until"]))
	if signedErr != nil || beforeErr != nil || untilErr != nil || signedAt.Before(notBefore) || signedAt.After(signUntil) || stringValue(signature["signed_at"]) != stringValue(manifest["completed_at"]) {
		return fail("MANIFEST_SIGNATURE_TIME_INVALID")
	}
	signingBytes, err := canonicalValue(manifestSigningObject(manifest))
	if err != nil {
		return err
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(stringValue(signature["value_base64"]))
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signatureBytes) {
		return fail("MANIFEST_SIGNATURE_INVALID")
	}
	return nil
}

func validateAnswerManifest(manifest, context map[string]any) error {
	if err := assertAllowedFields(manifest, []string{
		"schema_version", "canonicalization", "answer_mode", "verification_method", "question_run_id", "organization_id", "workspace_id",
		"workspace_revision", "workspace_scope_hash", "policy_revision", "access_context_hash",
		"question_text", "question_hash", "created_by", "started_at", "completed_at",
		"supersedes_question_run_id", "corpus_snapshot", "extractions", "retrieval", "configured_profiles",
		"model_runs", "claim_verifications", "deterministic_validations", "claims", "sections", "citations", "status", "answer_hash", "manifest_hash", "signature",
	}); err != nil {
		return err
	}
	previousMode := context["_active_answer_mode"]
	previousExecutedRuns := context["executed_model_run_ids"]
	previousGateway := context["model_gateway"]
	previousSourceChains := context["source_chains"]
	context["_active_answer_mode"] = manifest["answer_mode"]
	applyManifestModeContextProjection(context, stringValue(manifest["answer_mode"]))
	defer func() {
		if previousMode == nil {
			delete(context, "_active_answer_mode")
		} else {
			context["_active_answer_mode"] = previousMode
		}
		context["executed_model_run_ids"] = previousExecutedRuns
		context["model_gateway"] = previousGateway
		context["source_chains"] = previousSourceChains
	}()
	if err := validateManifestIntegrity(manifest, context); err != nil {
		return err
	}
	if err := validateAnswerModeBinding(manifest); err != nil {
		return err
	}
	if err := validateQuestionRunProvenance(manifest, context); err != nil {
		return err
	}
	if err := validateAccessContextProvenance(context); err != nil {
		return err
	}
	accessContext := object(context["access_context"])
	workspaceContext := object(context["workspace_scope"])
	if err := validateWorkspaceScopeShape(workspaceContext); err != nil {
		return err
	}
	if stringValue(manifest["organization_id"]) != stringValue(accessContext["organization_id"]) {
		return fail("MANIFEST_ORGANIZATION_CONTEXT_MISMATCH")
	}
	if stringValue(manifest["workspace_id"]) != stringValue(accessContext["workspace_id"]) || stringValue(manifest["workspace_id"]) != stringValue(workspaceContext["workspace_id"]) {
		return fail("MANIFEST_WORKSPACE_CONTEXT_MISMATCH")
	}
	if intValue(manifest["workspace_revision"]) != intValue(accessContext["workspace_revision"]) || intValue(manifest["workspace_revision"]) != intValue(workspaceContext["workspace_revision"]) {
		return fail("MANIFEST_WORKSPACE_REVISION_CONTEXT_MISMATCH")
	}
	if stringValue(manifest["created_by"]) != stringValue(accessContext["human_principal_id"]) {
		return fail("MANIFEST_CREATOR_CONTEXT_MISMATCH")
	}

	started, err := time.Parse(time.RFC3339, stringValue(manifest["started_at"]))
	if err != nil {
		return fail("MANIFEST_TIME_INVALID")
	}
	completed, err := time.Parse(time.RFC3339, stringValue(manifest["completed_at"]))
	if err != nil || completed.Before(started) {
		return fail("MANIFEST_TIME_INVALID")
	}

	questionText := strings.TrimFunc(canonicalTextV1(stringValue(manifest["question_text"])), unicode.IsSpace)
	questionInput := map[string]any{
		"workspace_id":       manifest["workspace_id"],
		"workspace_revision": manifest["workspace_revision"],
		"question_text":      questionText,
	}
	questionHash, err := hashCanonical(questionInput)
	if err != nil {
		return err
	}
	if stringValue(manifest["question_hash"]) != questionHash {
		return fail("QUESTION_HASH_MISMATCH")
	}

	corpus := array(manifest["corpus_snapshot"])
	if err := validateCorpusSnapshotSet(corpus, context, started, stringValue(object(manifest["status"])["corpus"])); err != nil {
		return err
	}
	workspaceHash, err := hashCanonical(context["workspace_scope"])
	if err != nil {
		return err
	}
	if stringValue(manifest["workspace_scope_hash"]) != workspaceHash {
		return fail("WORKSPACE_SCOPE_HASH_MISMATCH")
	}
	accessHash, err := hashCanonical(context["access_context"])
	if err != nil {
		return err
	}
	if stringValue(manifest["access_context_hash"]) != accessHash {
		return fail("ACCESS_CONTEXT_HASH_MISMATCH")
	}
	if stringValue(manifest["policy_revision"]) != stringValue(accessContext["policy_revision"]) {
		return fail("POLICY_REVISION_MISMATCH")
	}
	contextPackHash, err := hashCanonical(contextPackHashInput(array(context["context_pack"])))
	if err != nil {
		return err
	}
	if stringValue(object(manifest["retrieval"])["context_pack_hash"]) != contextPackHash {
		return fail("CONTEXT_PACK_HASH_MISMATCH")
	}
	if intValue(object(manifest["retrieval"])["context_count"]) != len(array(context["context_pack"])) {
		return fail("CONTEXT_PACK_COUNT_MISMATCH")
	}
	if intValue(object(manifest["retrieval"])["authorized_candidate_count"]) < intValue(object(manifest["retrieval"])["context_count"]) {
		return fail("CONTEXT_CANDIDATE_COUNT_INVALID")
	}
	resultStatus := stringValue(object(manifest["status"])["result"])
	contextCount := intValue(object(manifest["retrieval"])["context_count"])
	if resultStatus == "COMPLETED" && contextCount == 0 {
		return fail("EMPTY_CONTEXT_COMPLETED")
	}
	hasSupportedFact := false
	hasUnknown := false
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		if stringValue(claim["kind"]) == "FACT" && stringValue(claim["support_status"]) == "SUPPORTED" {
			hasSupportedFact = true
		}
		if stringValue(claim["kind"]) == "UNKNOWN" {
			hasUnknown = true
		}
	}
	if resultStatus == "COMPLETED" && (!hasSupportedFact || hasUnknown) {
		return fail("COMPLETED_SUPPORTED_FACT_REQUIRED")
	}
	if resultStatus == "INSUFFICIENT_EVIDENCE" {
		if !hasUnknown {
			return fail("INSUFFICIENT_EVIDENCE_UNKNOWN_REQUIRED")
		}
	}
	if err := validateModelRuns(manifest, context); err != nil {
		return err
	}
	if err := validateConfiguredModelProfileDefinitions(manifest, context); err != nil {
		return err
	}
	retrievalSnapshot, err := validateRetrievalProvenance(manifest, context, started, completed)
	if err != nil {
		return err
	}
	if contextCount == 0 {
		if len(array(manifest["citations"])) != 0 || len(array(manifest["extractions"])) != 0 {
			return fail("ZERO_CONTEXT_EVIDENCE_NOT_EMPTY")
		}
		for _, rawClaim := range array(manifest["claims"]) {
			if stringValue(object(rawClaim)["kind"]) != "UNKNOWN" {
				return fail("ZERO_CONTEXT_CLAIM_KIND_INVALID")
			}
		}
	}

	if err := validateModelArtifactProvenance(manifest, context, retrievalSnapshot, started, completed); err != nil {
		return err
	}
	if err := validateExtractions(manifest, context); err != nil {
		return err
	}
	if err := validateManifestClaimsAndCitations(manifest, context); err != nil {
		return err
	}
	if stringValue(manifest["answer_mode"]) == "EXTRACTIVE" {
		if err := validateExtractiveManifestClaims(manifest); err != nil {
			return err
		}
	} else {
		if err := validateClaimVerifications(manifest, context); err != nil {
			return err
		}
	}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" {
		if err := validateDeterministicValidations(manifest, context, started, completed); err != nil {
			return err
		}
	}
	if err := validateUnknownRendering(manifest); err != nil {
		return err
	}

	markdown, spans, err := renderAnswer(array(manifest["claims"]), array(manifest["sections"]))
	if err != nil {
		return err
	}
	claimByID := map[string]map[string]any{}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		claimByID[stringValue(claim["claim_id"])] = claim
	}
	for _, span := range spans {
		declared := object(claimByID[span.ClaimID]["answer_span"])
		if intValue(declared["end"]) <= intValue(declared["start"]) || intValue(declared["start"]) != span.Start || intValue(declared["end"]) != span.End {
			return fail("ANSWER_SPAN_MISMATCH", span.ClaimID)
		}
		if !bytes.Equal(markdown[span.Start:span.End], []byte(span.Escaped)) {
			return fail("ANSWER_SPAN_MISMATCH", span.ClaimID)
		}
	}
	if stringValue(manifest["answer_hash"]) != sha256String(markdown) {
		return fail("ANSWER_HASH_MISMATCH")
	}

	status := object(manifest["status"])
	retrieval := object(manifest["retrieval"])
	if stringValue(status["corpus"]) == "COMPLETE" {
		if boolValue(retrieval["truncated"]) {
			return fail("CORPUS_STATUS_INCONSISTENT")
		}
		for _, rawSource := range corpus {
			if stringValue(object(rawSource)["health"]) != "READY" {
				return fail("CORPUS_STATUS_INCONSISTENT")
			}
		}
	}
	return nil
}

func applyManifestModeContextProjection(context map[string]any, mode string) {
	overrides := object(object(context["mode_fixture_overrides"])[mode])
	if override := array(overrides["executed_model_run_ids"]); override != nil {
		context["executed_model_run_ids"] = override
	}
	citationNumbers := map[int]bool{}
	for _, rawNumber := range array(overrides["source_chain_citation_numbers"]) {
		citationNumbers[intValue(rawNumber)] = true
	}
	if len(citationNumbers) > 0 {
		chains := make([]any, 0)
		for _, rawChain := range array(context["source_chains"]) {
			if citationNumbers[intValue(object(rawChain)["citation_number"])] {
				chains = append(chains, rawChain)
			}
		}
		context["source_chains"] = chains
	}
	purposes := stringSet(array(overrides["model_gateway_purposes"]))
	if len(purposes) == 0 {
		return
	}
	gateway := object(context["model_gateway"])
	projected := cloneObject(gateway)
	profiles := make([]any, 0)
	for _, rawProfile := range array(gateway["profiles"]) {
		if purposes[stringValue(object(rawProfile)["purpose"])] {
			profiles = append(profiles, rawProfile)
		}
	}
	runs := make([]any, 0)
	for _, rawRun := range array(gateway["runs"]) {
		if purposes[stringValue(object(rawRun)["purpose"])] {
			runs = append(runs, rawRun)
		}
	}
	projected["profiles"] = profiles
	projected["runs"] = runs
	context["model_gateway"] = projected
}

func validateExtractiveManifestClaims(manifest map[string]any) error {
	citations := map[int]map[string]any{}
	for _, rawCitation := range array(manifest["citations"]) {
		citation := object(rawCitation)
		number := intValue(citation["citation_number"])
		if citations[number] != nil {
			return fail("EXTRACTIVE_CITATION_NUMBER_INVALID", strconvItoa(number))
		}
		citations[number] = citation
	}
	seen := map[int]bool{}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		if stringValue(claim["kind"]) == "UNKNOWN" {
			continue
		}
		if stringValue(claim["kind"]) != "FACT" || len(array(claim["citation_numbers"])) != 1 {
			return fail("EXTRACTIVE_CLAIM_SHAPE_INVALID", stringValue(claim["claim_id"]))
		}
		number := intValue(array(claim["citation_numbers"])[0])
		citation := citations[number]
		if citation == nil || len(array(citation["claim_ids"])) != 1 || stringValue(array(citation["claim_ids"])[0]) != stringValue(claim["claim_id"]) {
			return fail("EXTRACTIVE_CITATION_MAPPING_ASYMMETRIC", stringValue(claim["claim_id"]))
		}
		if seen[number] || !bytes.Equal([]byte(canonicalTextV1(stringValue(claim["text"]))), []byte(canonicalTextV1(stringValue(citation["cited_excerpt"])))) {
			return fail("EXTRACTIVE_CLAIM_NOT_EXACT", stringValue(claim["claim_id"]))
		}
		seen[number] = true
	}
	for number := range citations {
		if !seen[number] {
			return fail("EXTRACTIVE_CITATION_ORPHAN", strconvItoa(number))
		}
	}
	return nil
}

// validateAnswerModeBinding is deliberately before retrieval/model validation:
// a signed manifest must first declare a self-consistent proof method, and an
// extractive manifest must be unable to smuggle a generative verifier through a
// later validator path.
func validateAnswerModeBinding(manifest map[string]any) error {
	mode := stringValue(manifest["answer_mode"])
	method := stringValue(manifest["verification_method"])
	switch mode {
	case "GENERATIVE":
		if method != "SEMANTIC_VERIFIER" {
			return fail("ANSWER_MODE_METHOD_MISMATCH")
		}
	case "EXTRACTIVE":
		if method != "BYTE_EXACT_CITATION" {
			return fail("ANSWER_MODE_METHOD_MISMATCH")
		}
		if len(array(manifest["claim_verifications"])) != 0 {
			return fail("EXTRACTIVE_VERIFIER_RECORD_FORBIDDEN")
		}
		for _, name := range []string{"generation", "verification"} {
			if object(object(manifest["configured_profiles"])[name]) != nil {
				return fail("EXTRACTIVE_MODEL_PROFILE_FORBIDDEN", name)
			}
		}
		for _, rawRun := range array(manifest["model_runs"]) {
			purpose := stringValue(object(rawRun)["purpose"])
			if purpose == "GENERATION" || purpose == "VERIFICATION" {
				return fail("EXTRACTIVE_MODEL_RUN_FORBIDDEN", purpose)
			}
		}
		for _, rawClaim := range array(manifest["claims"]) {
			claim := object(rawClaim)
			if stringValue(claim["kind"]) == "UNKNOWN" {
				continue
			}
			if stringValue(claim["kind"]) != "FACT" || len(array(claim["citation_numbers"])) != 1 {
				return fail("EXTRACTIVE_CLAIM_SHAPE_INVALID", stringValue(claim["claim_id"]))
			}
			text := stringValue(claim["text"])
			if strings.ContainsAny(text, "\r\n") || len([]byte(text)) > 2000 {
				return fail("EXTRACTIVE_CLAIM_SENTENCE_INVALID", stringValue(claim["claim_id"]))
			}
		}
	default:
		return fail("ANSWER_MODE_INVALID")
	}
	return nil
}

func contextPackHashInput(items []any) []any {
	result := make([]any, 0, len(items))
	for _, rawItem := range items {
		item := object(rawItem)
		result = append(result, map[string]any{
			"evidence_fragment_id":        item["evidence_fragment_id"],
			"source_version_id":           item["source_version_id"],
			"extraction_id":               item["extraction_id"],
			"extraction_profile_hash":     item["extraction_profile_hash"],
			"source_version_content_hash": item["source_version_content_hash"],
			"evidence_text_hash":          item["evidence_text_hash"],
			"anchor_hash":                 item["anchor_hash"],
			"exact_context_hash":          item["exact_context_hash"],
		})
	}
	return result
}

type trustedEvidenceDescriptor struct {
	extraction map[string]any
	evidence   map[string]any
}

func trustedCatalogEvidence(context map[string]any) (map[string]trustedEvidenceDescriptor, error) {
	result := map[string]trustedEvidenceDescriptor{}
	for _, rawExtraction := range array(context["catalog_extractions"]) {
		extraction := object(rawExtraction)
		for _, rawEvidence := range array(extraction["evidence_set"]) {
			evidence := object(rawEvidence)
			id := stringValue(evidence["evidence_fragment_id"])
			if _, exists := result[id]; exists {
				return nil, fail("CATALOG_EVIDENCE_DUPLICATE", id)
			}
			// CANONICALIZATION.md s7: anchor_hash is the organization-scoped
			// HMAC-SHA-256 of the JCS anchor object, keyed by digest_key_version.
			anchorHash, err := manifestAnchorDigest(context, evidence)
			if err != nil {
				return nil, err
			}
			if stringValue(evidence["anchor_hash"]) != anchorHash {
				return nil, fail("CATALOG_EVIDENCE_ANCHOR_HASH_MISMATCH", id)
			}
			if err := validateAnchorSourceCompatibility(extraction, object(evidence["anchor"])); err != nil {
				return nil, err
			}
			result[id] = trustedEvidenceDescriptor{extraction: extraction, evidence: evidence}
		}
	}
	return result, nil
}

func validateAnchorSourceCompatibility(extraction, anchor map[string]any) error {
	objectType := stringValue(extraction["source_object_type"])
	kind := stringValue(anchor["kind"])
	profile := object(extraction["profile"])
	canonicalFormat := stringValue(profile["canonical_format"])

	allowed := false
	switch objectType {
	case "GIT_FILE":
		allowed = canonicalFormat == "TEXT" && kind == "GIT"
	case "EMAIL":
		allowed = canonicalFormat == "EMAIL" && kind == "EMAIL"
	case "WEB_PAGE":
		allowed = canonicalFormat == "HTML" && kind == "HTML"
	case "FILE", "ATTACHMENT":
		switch canonicalFormat {
		case "TEXT":
			allowed = kind == "TEXT"
		case "PDF":
			allowed = kind == "PDF"
		case "DOCX":
			allowed = kind == "DOCX"
		case "PPTX":
			allowed = kind == "PPTX"
		case "XLSX":
			allowed = kind == "XLSX"
		case "EMAIL":
			allowed = kind == "EMAIL"
		case "HTML":
			allowed = kind == "HTML"
		case "OCR":
			allowed = profile["ocr"] != nil && kind == "OCR"
		}
	}
	if !allowed {
		return fail("ANCHOR_SOURCE_TYPE_INCOMPATIBLE", objectType+":"+canonicalFormat+":"+kind)
	}
	return nil
}

func extractionEvidenceSetHashInput(items []any) []any {
	projection := make([]any, 0, len(items))
	for _, rawItem := range items {
		item := object(rawItem)
		projection = append(projection, map[string]any{
			"evidence_fragment_id": item["evidence_fragment_id"],
			"ordinal":              item["ordinal"],
			"evidence_text_hash":   item["evidence_text_hash"],
			"anchor_hash":          item["anchor_hash"],
		})
	}
	return projection
}

func validateExtractions(manifest, context map[string]any) error {
	if _, err := trustedCatalogEvidence(context); err != nil {
		return err
	}
	trustedByID := map[string]map[string]any{}
	for _, rawTrusted := range array(context["catalog_extractions"]) {
		trusted := object(rawTrusted)
		id := stringValue(trusted["extraction_id"])
		if trustedByID[id] != nil {
			return fail("CATALOG_EXTRACTION_DUPLICATE", id)
		}
		profileHash, err := hashCanonical(trusted["profile"])
		if err != nil {
			return err
		}
		if stringValue(trusted["profile_hash"]) != profileHash {
			return fail("CATALOG_EXTRACTION_PROFILE_HASH_MISMATCH", id)
		}
		lastOrdinal := 0
		for _, rawEvidence := range array(trusted["evidence_set"]) {
			ordinal := intValue(object(rawEvidence)["ordinal"])
			if ordinal <= lastOrdinal {
				return fail("CATALOG_EXTRACTION_EVIDENCE_ORDER_INVALID", id)
			}
			lastOrdinal = ordinal
		}
		evidenceSetHash, err := hashCanonical(extractionEvidenceSetHashInput(array(trusted["evidence_set"])))
		if err != nil {
			return err
		}
		if stringValue(trusted["evidence_set_hash"]) != evidenceSetHash {
			return fail("CATALOG_EXTRACTION_EVIDENCE_SET_HASH_MISMATCH", id)
		}
		trustedByID[id] = trusted
	}

	required := map[string]bool{}
	for _, rawCitation := range array(manifest["citations"]) {
		required[stringValue(object(rawCitation)["extraction_id"])] = true
	}
	actual := map[string]bool{}
	actualByID := map[string]map[string]any{}
	for _, rawExtraction := range array(manifest["extractions"]) {
		extraction := object(rawExtraction)
		id := stringValue(extraction["extraction_id"])
		if actual[id] {
			return fail("MANIFEST_EXTRACTION_DUPLICATE", id)
		}
		actual[id] = true
		actualByID[id] = extraction
		profileHash, err := hashCanonical(extraction["profile"])
		if err != nil {
			return err
		}
		if stringValue(extraction["profile_hash"]) != profileHash {
			return fail("MANIFEST_EXTRACTION_PROFILE_HASH_MISMATCH", id)
		}
		trusted := trustedByID[id]
		if trusted == nil || stringValue(extraction["source_version_id"]) != stringValue(trusted["source_version_id"]) ||
			stringValue(extraction["profile_hash"]) != stringValue(trusted["profile_hash"]) ||
			stringValue(extraction["evidence_set_hash"]) != stringValue(trusted["evidence_set_hash"]) ||
			!canonicalObjectsEqual(object(extraction["profile"]), object(trusted["profile"])) {
			return fail("EXTRACTION_PROVENANCE_MISMATCH", id)
		}
	}
	for id := range required {
		if !actual[id] {
			return fail("MANIFEST_EXTRACTION_MISSING", id)
		}
	}
	for id := range actual {
		if !required[id] {
			return fail("MANIFEST_EXTRACTION_EXTRA", id)
		}
	}
	for _, rawCitation := range array(manifest["citations"]) {
		citation := object(rawCitation)
		extraction := actualByID[stringValue(citation["extraction_id"])]
		if extraction == nil || stringValue(extraction["source_version_id"]) != stringValue(citation["source_version_id"]) {
			return fail("EXTRACTION_CITATION_SOURCE_VERSION_MISMATCH")
		}
	}
	return nil
}

func verificationEvidenceFromCitation(citation map[string]any) map[string]any {
	return map[string]any{
		"citation_number":      citation["citation_number"],
		"source_version_id":    citation["source_version_id"],
		"extraction_id":        citation["extraction_id"],
		"evidence_fragment_id": citation["evidence_fragment_id"],
		"evidence_text_hash":   citation["evidence_text_hash"],
		"cited_excerpt_hash":   citation["cited_excerpt_hash"],
		"anchor_hash":          citation["anchor_hash"],
	}
}

func claimOrdinal(id string) int {
	if len(id) < 2 || id[0] != 'C' {
		return 0
	}
	value, _ := strconv.Atoi(id[1:])
	return value
}

func validateClaimVerifications(manifest, context map[string]any) error {
	claimByID := map[string]map[string]any{}
	for _, rawClaim := range array(manifest["claims"]) {
		claim := object(rawClaim)
		claimByID[stringValue(claim["claim_id"])] = claim
	}
	citationByNumber := map[int]map[string]any{}
	for _, rawCitation := range array(manifest["citations"]) {
		citation := object(rawCitation)
		citationByNumber[intValue(citation["citation_number"])] = citation
	}

	recordByID := map[string]map[string]any{}
	for _, rawRecord := range array(manifest["claim_verifications"]) {
		record := object(rawRecord)
		id := stringValue(record["claim_id"])
		if recordByID[id] != nil {
			return fail("CLAIM_VERIFICATION_DUPLICATE", id)
		}
		recordByID[id] = record
	}
	trustedHashes := object(context["trusted_claim_verification_hashes"])

	requiredIDs := make([]string, 0)
	for id, claim := range claimByID {
		kind := stringValue(claim["kind"])
		if kind == "UNKNOWN" {
			if recordByID[id] != nil {
				return fail("UNKNOWN_CLAIM_VERIFICATION_FORBIDDEN", id)
			}
			continue
		}
		requiredIDs = append(requiredIDs, id)
	}
	sort.Slice(requiredIDs, func(i, j int) bool { return claimOrdinal(requiredIDs[i]) < claimOrdinal(requiredIDs[j]) })

	verificationRun := map[string]any(nil)
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		if stringValue(run["purpose"]) == "VERIFICATION" && boolValue(run["selected_for_result"]) {
			if verificationRun != nil {
				return fail("MODEL_RUN_SELECTION_CARDINALITY", "VERIFICATION")
			}
			verificationRun = run
		}
	}
	if len(requiredIDs) > 0 && (verificationRun == nil || stringValue(verificationRun["outcome"]) != "SUCCEEDED") {
		return fail("CLAIM_VERIFICATION_MODEL_RUN_INVALID")
	}

	batchClaims := make([]any, 0, len(requiredIDs))
	for _, id := range requiredIDs {
		claim := claimByID[id]
		record := recordByID[id]
		if record == nil {
			return fail("CLAIM_VERIFICATION_MISSING", id)
		}
		kind := stringValue(claim["kind"])
		claimTextHash := sha256String([]byte(canonicalTextV1(stringValue(claim["text"]))))
		evidenceNumbers := map[int]bool{}
		supportingClaims := make([]any, 0)
		if kind == "FACT" {
			for _, rawNumber := range array(claim["citation_numbers"]) {
				evidenceNumbers[intValue(rawNumber)] = true
			}
		} else if kind == "INFERENCE" {
			supportIDs := make([]string, 0)
			for _, rawSupport := range array(claim["supporting_claim_ids"]) {
				supportIDs = append(supportIDs, stringValue(rawSupport))
			}
			sort.Slice(supportIDs, func(i, j int) bool { return claimOrdinal(supportIDs[i]) < claimOrdinal(supportIDs[j]) })
			for _, supportID := range supportIDs {
				support := claimByID[supportID]
				if support == nil || stringValue(support["kind"]) != "FACT" {
					return fail("ANSWER_INFERENCE_CHAIN_FORBIDDEN", supportID)
				}
				supportingClaims = append(supportingClaims, map[string]any{
					"claim_id":        supportID,
					"claim_text_hash": sha256String([]byte(canonicalTextV1(stringValue(support["text"])))),
				})
				for _, rawNumber := range array(support["citation_numbers"]) {
					evidenceNumbers[intValue(rawNumber)] = true
				}
			}
		}
		numbers := make([]int, 0, len(evidenceNumbers))
		for number := range evidenceNumbers {
			numbers = append(numbers, number)
		}
		sort.Ints(numbers)
		evidence := make([]any, 0, len(numbers))
		for _, number := range numbers {
			citation := citationByNumber[number]
			if citation == nil {
				return fail("CLAIM_VERIFICATION_CITATION_MISSING", id)
			}
			evidence = append(evidence, verificationEvidenceFromCitation(citation))
		}
		input := map[string]any{
			"claim_id":          id,
			"kind":              kind,
			"claim_text_hash":   claimTextHash,
			"evidence":          evidence,
			"supporting_claims": supportingClaims,
		}
		inputHash, err := hashCanonical(input)
		if err != nil {
			return err
		}
		if stringValue(record["kind"]) != kind || stringValue(record["claim_text_hash"]) != claimTextHash ||
			stringValue(record["verification_input_hash"]) != inputHash ||
			stringValue(record["verifier_model_run_id"]) != stringValue(verificationRun["model_run_id"]) ||
			stringValue(record["outcome"]) != "SUPPORTED" ||
			!canonicalArraysEqual(array(record["evidence"]), evidence) || !canonicalArraysEqual(array(record["supporting_claims"]), supportingClaims) {
			return fail("CLAIM_VERIFICATION_INPUT_MISMATCH", id)
		}
		recordHash, err := hashCanonical(record)
		if err != nil {
			return err
		}
		if stringValue(trustedHashes[id]) != recordHash {
			return fail("CLAIM_VERIFICATION_PROVENANCE_MISMATCH", id)
		}
		batchClaims = append(batchClaims, map[string]any{"claim_id": id, "verification_input_hash": inputHash})
	}
	if len(recordByID) != len(requiredIDs) || len(trustedHashes) != len(requiredIDs) {
		return fail("CLAIM_VERIFICATION_SET_MISMATCH")
	}
	if len(requiredIDs) == 0 {
		return nil
	}
	batchInput := map[string]any{
		"profile_revision": verificationRun["profile_revision"],
		"prompt_version":   verificationRun["prompt_version"],
		"question_hash":    manifest["question_hash"],
		"claims":           batchClaims,
	}
	batchHash, err := hashCanonical(batchInput)
	if err != nil {
		return err
	}
	if stringValue(verificationRun["input_hash"]) != batchHash {
		return fail("CLAIM_VERIFICATION_BATCH_HASH_MISMATCH")
	}
	verifierOutput := object(context["trusted_verifier_output"])
	outputHash, err := hashCanonical(verifierOutput)
	if err != nil {
		return err
	}
	if stringValue(verificationRun["output_hash"]) != outputHash {
		return fail("VERIFIER_OUTPUT_HASH_MISMATCH")
	}
	results := array(verifierOutput["results"])
	if len(results) != len(requiredIDs) {
		return fail("VERIFIER_OUTPUT_SET_MISMATCH")
	}
	for index, id := range requiredIDs {
		result := object(results[index])
		if stringValue(result["claim_id"]) != id || stringValue(result["verification_input_hash"]) != stringValue(recordByID[id]["verification_input_hash"]) || stringValue(result["outcome"]) != "SUPPORTED" {
			return fail("VERIFIER_OUTPUT_SET_MISMATCH")
		}
	}
	return nil
}

func canonicalArraysEqual(left, right []any) bool {
	leftBytes, leftErr := canonicalValue(left)
	rightBytes, rightErr := canonicalValue(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func validateVerifierOutput(output, context map[string]any) error {
	results := array(output["results"])
	seen := map[string]bool{}
	for _, rawResult := range results {
		result := object(rawResult)
		id := stringValue(result["claim_id"])
		if seen[id] {
			return fail("VERIFIER_OUTPUT_DUPLICATE", id)
		}
		seen[id] = true
	}
	expected := array(object(context["trusted_verifier_output"])["results"])
	if len(results) != len(expected) {
		return fail("VERIFIER_OUTPUT_SET_MISMATCH")
	}
	for index, rawExpected := range expected {
		actual := object(results[index])
		expectedResult := object(rawExpected)
		if stringValue(actual["claim_id"]) != stringValue(expectedResult["claim_id"]) {
			return fail("VERIFIER_OUTPUT_SET_MISMATCH")
		}
		if stringValue(actual["verification_input_hash"]) != stringValue(expectedResult["verification_input_hash"]) {
			return fail("VERIFIER_OUTPUT_INPUT_HASH_MISMATCH")
		}
		if stringValue(actual["outcome"]) != stringValue(expectedResult["outcome"]) {
			return fail("VERIFIER_OUTPUT_OUTCOME_MISMATCH")
		}
	}
	outputHash, err := hashCanonical(output)
	if err != nil {
		return err
	}
	expectedHash := ""
	for _, rawRun := range array(object(context["model_gateway"])["runs"]) {
		run := object(rawRun)
		if stringValue(run["purpose"]) == "VERIFICATION" && boolValue(run["selected_for_result"]) {
			expectedHash = stringValue(run["output_hash"])
		}
	}
	if outputHash != expectedHash {
		return fail("VERIFIER_OUTPUT_HASH_MISMATCH")
	}
	return nil
}

func scopeRevisionKey(scopeID string, revision int) string {
	return scopeID + "@" + strconvItoa(revision)
}

// validateWorkspaceScopeShape enforces the closed workspace_scope v1 form: only
// workspace_id, workspace_revision and bindings at the top level, and only
// source_scope_id, source_scope_revision, scope_config_hash and enabled per
// binding. workspace_managed_confirmation_id and workspace_source_id are
// rejected as unknown fields — the canonical workspace bytes never carry the
// confirmation identity. Bindings must be strictly sorted by Unicode
// code-point order of source_scope_id with no repeated source_scope_id.
func validateWorkspaceScopeShape(workspaceScope map[string]any) error {
	if err := assertAllowedFields(workspaceScope, []string{"workspace_id", "workspace_revision", "bindings"}); err != nil {
		return err
	}
	if stringValue(workspaceScope["workspace_id"]) == "" || intValue(workspaceScope["workspace_revision"]) < 1 {
		return fail("WORKSPACE_SCOPE_SHAPE_INVALID")
	}
	bindings, ok := workspaceScope["bindings"].([]any)
	if !ok {
		return fail("WORKSPACE_SCOPE_SHAPE_INVALID")
	}
	previous := ""
	for index, rawBinding := range bindings {
		binding := object(rawBinding)
		if binding == nil {
			return fail("WORKSPACE_SCOPE_SHAPE_INVALID")
		}
		if err := assertAllowedFields(binding, []string{"source_scope_id", "source_scope_revision", "scope_config_hash", "enabled"}); err != nil {
			return err
		}
		scopeID := stringValue(binding["source_scope_id"])
		if scopeID == "" || intValue(binding["source_scope_revision"]) < 1 || stringValue(binding["scope_config_hash"]) == "" {
			return fail("WORKSPACE_SCOPE_SHAPE_INVALID")
		}
		if _, isBool := binding["enabled"].(bool); !isBool {
			return fail("WORKSPACE_SCOPE_SHAPE_INVALID")
		}
		if index > 0 {
			if scopeID == previous {
				return fail("WORKSPACE_SCOPE_BINDING_DUPLICATE", scopeID)
			}
			if scopeID < previous {
				return fail("WORKSPACE_SCOPE_BINDING_UNSORTED", scopeID)
			}
		}
		previous = scopeID
	}
	return nil
}

func validateCorpusSnapshotSet(corpus []any, context map[string]any, questionStarted time.Time, corpusStatus string) error {
	configs := object(context["scope_configs"])
	healthSnapshots := object(context["source_health_snapshots"])
	workspaceScope := object(context["workspace_scope"])
	expected := map[string]map[string]any{}

	for _, rawBinding := range array(workspaceScope["bindings"]) {
		binding := object(rawBinding)
		if !boolValue(binding["enabled"]) {
			continue
		}
		key := scopeRevisionKey(stringValue(binding["source_scope_id"]), intValue(binding["source_scope_revision"]))
		if expected[key] != nil {
			return fail("WORKSPACE_SCOPE_BINDING_DUPLICATE", key)
		}
		config := object(configs[key])
		if config == nil || stringValue(config["source_scope_id"]) != stringValue(binding["source_scope_id"]) || intValue(config["revision"]) != intValue(binding["source_scope_revision"]) {
			return fail("SCOPE_CONFIG_MISSING", key)
		}
		configHash, err := hashCanonical(config)
		if err != nil {
			return err
		}
		if stringValue(binding["scope_config_hash"]) != configHash {
			return fail("SCOPE_CONFIG_HASH_MISMATCH", key)
		}
		expected[key] = map[string]any{
			"scope_config_hash": binding["scope_config_hash"],
			"access_mode":       config["access_mode"],
			"config":            config,
		}
	}

	actual := map[string]map[string]any{}
	for _, rawSource := range corpus {
		source := object(rawSource)
		key := scopeRevisionKey(stringValue(source["source_scope_id"]), intValue(source["source_scope_revision"]))
		if actual[key] != nil {
			return fail("CORPUS_SOURCE_DUPLICATE", key)
		}
		if expected[key] == nil {
			return fail("CORPUS_SOURCE_EXTRA", key)
		}
		actual[key] = source
	}
	for key, binding := range expected {
		source := actual[key]
		if source == nil {
			return fail("CORPUS_SOURCE_MISSING", key)
		}
		if stringValue(source["scope_config_hash"]) != stringValue(binding["scope_config_hash"]) ||
			stringValue(source["access_mode"]) != stringValue(binding["access_mode"]) {
			return fail("CORPUS_SOURCE_BINDING_MISMATCH", key)
		}
		trusted := object(healthSnapshots[key])
		if trusted == nil || !canonicalObjectsEqual(source, trusted) {
			return fail("CORPUS_HEALTH_PROVENANCE_MISMATCH", key)
		}
		config := object(binding["config"])
		contentFresh := false
		if source["last_successful_sync"] != nil {
			lastSync, err := time.Parse(time.RFC3339, stringValue(source["last_successful_sync"]))
			if err != nil || lastSync.After(questionStarted) {
				return fail("CORPUS_SYNC_TIME_INVALID", key)
			}
			contentFresh = questionStarted.Sub(lastSync) <= time.Duration(intValue(config["content_freshness_sla_seconds"]))*time.Second
		}
		aclFresh := true
		if stringValue(source["access_mode"]) == "SOURCE_ENFORCED" {
			aclTime, err := time.Parse(time.RFC3339, stringValue(source["acl_fresh_at"]))
			aclFresh = err == nil && !aclTime.After(questionStarted) && questionStarted.Sub(aclTime) <= time.Duration(intValue(config["acl_freshness_sla_seconds"]))*time.Second
		}
		if corpusStatus == "COMPLETE" && (stringValue(source["health"]) != "READY" || !contentFresh || !aclFresh) {
			return fail("CORPUS_STATUS_INCONSISTENT", key)
		}
	}
	return nil
}

func validateModelRuns(manifest, context map[string]any) error {
	profiles := object(manifest["configured_profiles"])
	profileByPurpose := map[string]map[string]any{}
	profileNames := []string{"embedding", "reranking"}
	if stringValue(manifest["answer_mode"]) == "GENERATIVE" {
		profileNames = append(profileNames, "generation", "verification")
	}
	for _, name := range profileNames {
		profile := object(profiles[name])
		purpose := stringValue(profile["purpose"])
		if profileByPurpose[purpose] != nil {
			return fail("MODEL_PROFILE_PURPOSE_DUPLICATE", purpose)
		}
		profileByPurpose[purpose] = profile
	}
	if len(profileByPurpose) != len(profileNames) {
		return fail("MODEL_PROFILE_PURPOSE_MISSING")
	}
	gateway := object(context["model_gateway"])
	trustedProfiles := map[string]map[string]any{}
	for _, rawProfile := range array(gateway["profiles"]) {
		profile := object(rawProfile)
		purpose := stringValue(profile["purpose"])
		if trustedProfiles[purpose] != nil {
			return fail("MODEL_GATEWAY_PROFILE_DUPLICATE", purpose)
		}
		trustedProfiles[purpose] = profile
	}
	for purpose, profile := range profileByPurpose {
		trusted := trustedProfiles[purpose]
		if trusted == nil || !canonicalObjectsEqual(profile, trusted) {
			return fail("MODEL_PROFILE_PROVENANCE_MISMATCH", purpose)
		}
	}

	executed := stringSet(array(context["executed_model_run_ids"]))
	seenExecuted := map[string]bool{}
	seenRunIDs := map[string]bool{}
	attemptKeys := map[string]bool{}
	selected := map[string]int{}
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		id := stringValue(run["model_run_id"])
		if seenRunIDs[id] {
			return fail("MODEL_RUN_ID_DUPLICATE", id)
		}
		seenRunIDs[id] = true
		seenExecuted[id] = true
		purpose := stringValue(run["purpose"])
		attemptKey := purpose + ":" + strconvItoa(intValue(run["attempt"]))
		if attemptKeys[attemptKey] {
			return fail("MODEL_RUN_ATTEMPT_DUPLICATE", attemptKey)
		}
		attemptKeys[attemptKey] = true
		profile := profileByPurpose[purpose]
		if profile == nil || stringValue(profile["model_id"]) != stringValue(run["model_id"]) ||
			stringValue(profile["model_revision"]) != stringValue(run["model_revision"]) ||
			stringValue(profile["artifact_hash"]) != stringValue(run["artifact_hash"]) ||
			stringValue(profile["profile_revision"]) != stringValue(run["profile_revision"]) ||
			stringValue(profile["profile_hash"]) != stringValue(run["profile_hash"]) ||
			stringValue(profile["prompt_version"]) != stringValue(run["prompt_version"]) {
			return fail("MODEL_RUN_PROFILE_MISMATCH", id)
		}
		started, err := time.Parse(time.RFC3339, stringValue(run["started_at"]))
		if err != nil {
			return fail("MODEL_RUN_TIME_INVALID", id)
		}
		completed, err := time.Parse(time.RFC3339, stringValue(run["completed_at"]))
		if err != nil || completed.Before(started) {
			return fail("MODEL_RUN_TIME_INVALID", id)
		}
		outcome := stringValue(run["outcome"])
		if outcome == "SUCCEEDED" && run["output_hash"] == nil {
			return fail("MODEL_RUN_OUTPUT_HASH_MISSING", id)
		}
		if boolValue(run["selected_for_result"]) {
			if outcome != "SUCCEEDED" {
				return fail("MODEL_RUN_SELECTION_INVALID", id)
			}
			selected[purpose]++
		}
	}
	expectedSelected := stringSet(func() []any {
		purposes := derivedRequiredModelPurposes(manifest, object(manifest["retrieval"]))
		values := make([]any, len(purposes))
		for index, purpose := range purposes {
			values[index] = purpose
		}
		return values
	}())
	for purpose := range expectedSelected {
		if selected[purpose] != 1 {
			return fail("MODEL_RUN_SELECTION_CARDINALITY", purpose)
		}
	}
	for purpose, count := range selected {
		if !expectedSelected[purpose] || count != 1 {
			return fail("MODEL_RUN_SELECTION_CARDINALITY", purpose)
		}
	}
	for id := range executed {
		if !seenExecuted[id] {
			return fail("MODEL_RUN_MISSING", id)
		}
	}
	trustedRuns := map[string]map[string]any{}
	for _, rawRun := range array(gateway["runs"]) {
		run := object(rawRun)
		id := stringValue(run["model_run_id"])
		if trustedRuns[id] != nil {
			return fail("MODEL_GATEWAY_RUN_DUPLICATE", id)
		}
		trustedRuns[id] = run
	}
	for _, rawRun := range array(manifest["model_runs"]) {
		run := object(rawRun)
		id := stringValue(run["model_run_id"])
		if !executed[id] {
			return fail("MODEL_RUN_NOT_EXECUTED", id)
		}
		trusted := trustedRuns[id]
		if trusted == nil || !canonicalObjectsEqual(run, trusted) {
			return fail("MODEL_RUN_PROVENANCE_MISMATCH", id)
		}
	}
	for id := range trustedRuns {
		if !seenRunIDs[id] {
			return fail("MODEL_RUN_MISSING", id)
		}
	}
	return nil
}

func canonicalObjectsEqual(left, right map[string]any) bool {
	leftBytes, leftErr := canonicalValue(left)
	rightBytes, rightErr := canonicalValue(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func validateManifestClaimsAndCitations(manifest, context map[string]any) error {
	claims := array(manifest["claims"])
	claimByID := map[string]map[string]any{}
	for _, rawClaim := range claims {
		claim := object(rawClaim)
		id := stringValue(claim["claim_id"])
		if claimByID[id] != nil {
			return fail("ANSWER_CLAIM_ID_DUPLICATE", id)
		}
		claimByID[id] = claim
		if code := unsafeModelTextCode(stringValue(claim["text"])); code != "" {
			return fail(code)
		}
	}

	published := map[string]int{}
	sectionIDs := map[string]bool{}
	for _, rawSection := range array(manifest["sections"]) {
		section := object(rawSection)
		sectionID := stringValue(section["section_id"])
		if sectionIDs[sectionID] {
			return fail("ANSWER_SECTION_ID_DUPLICATE", sectionID)
		}
		sectionIDs[sectionID] = true
		for _, rawID := range array(section["ordered_claim_ids"]) {
			id := stringValue(rawID)
			if claimByID[id] == nil {
				return fail("ANSWER_SECTION_CLAIM_MISSING", id)
			}
			published[id]++
			if published[id] > 1 {
				return fail("ANSWER_CLAIM_PUBLISHED_MULTIPLE", id)
			}
		}
	}
	for id := range claimByID {
		if published[id] != 1 {
			return fail("ANSWER_CLAIM_UNPUBLISHED", id)
		}
	}

	for id, claim := range claimByID {
		switch stringValue(claim["kind"]) {
		case "FACT":
			if stringValue(claim["support_status"]) != "SUPPORTED" || len(array(claim["citation_numbers"])) == 0 {
				return fail("ANSWER_FACT_NOT_VERIFIED", id)
			}
		case "INFERENCE":
			if stringValue(claim["support_status"]) != "SUPPORTED" || len(array(claim["supporting_claim_ids"])) == 0 {
				return fail("ANSWER_INFERENCE_NOT_VERIFIED", id)
			}
			for _, rawSupport := range array(claim["supporting_claim_ids"]) {
				supportID := stringValue(rawSupport)
				if supportID == id {
					return fail("ANSWER_INFERENCE_SELF_REFERENCE", id)
				}
				if claimByID[supportID] == nil {
					return fail("ANSWER_SUPPORT_CLAIM_MISSING", supportID)
				}
				if stringValue(claimByID[supportID]["kind"]) != "FACT" {
					return fail("ANSWER_INFERENCE_CHAIN_FORBIDDEN", supportID)
				}
			}
		case "UNKNOWN":
			if len(array(claim["citation_numbers"])) != 0 || len(array(claim["supporting_claim_ids"])) != 0 {
				return fail("ANSWER_UNKNOWN_SUPPORT_INVALID", id)
			}
		}
	}

	citationByNumber := map[int]map[string]any{}
	for _, rawCitation := range array(manifest["citations"]) {
		citation := object(rawCitation)
		number := intValue(citation["citation_number"])
		if citationByNumber[number] != nil {
			return fail("ANSWER_CITATION_NUMBER_DUPLICATE")
		}
		citationByNumber[number] = citation
	}
	for id, claim := range claimByID {
		for _, rawNumber := range array(claim["citation_numbers"]) {
			number := intValue(rawNumber)
			citation := citationByNumber[number]
			if citation == nil || !stringSet(array(citation["claim_ids"]))[id] {
				return fail("ANSWER_CITATION_MAPPING_ASYMMETRIC")
			}
		}
	}
	for number, citation := range citationByNumber {
		for _, rawID := range array(citation["claim_ids"]) {
			id := stringValue(rawID)
			claim := claimByID[id]
			found := false
			for _, rawNumber := range array(claim["citation_numbers"]) {
				if intValue(rawNumber) == number {
					found = true
				}
			}
			if claim == nil || !found {
				return fail("ANSWER_CITATION_MAPPING_ASYMMETRIC")
			}
		}
	}

	chainByCitation := map[int]map[string]any{}
	chainByEvidence := map[string]int{}
	for _, rawChain := range array(context["source_chains"]) {
		chain := object(rawChain)
		number := intValue(chain["citation_number"])
		if chainByCitation[number] != nil {
			return fail("CITATION_CHAIN_DUPLICATE")
		}
		evidenceID := stringValue(chain["evidence_fragment_id"])
		if previous, exists := chainByEvidence[evidenceID]; exists {
			return fail("CITATION_EVIDENCE_REUSED", evidenceID+":"+strconvItoa(previous)+":"+strconvItoa(number))
		}
		chainByEvidence[evidenceID] = number
		chainByCitation[number] = chain
	}

	contextByEvidence := map[string]map[string]any{}
	for _, rawContext := range array(context["context_pack"]) {
		contextItem := object(rawContext)
		key := stringValue(contextItem["evidence_fragment_id"])
		if contextByEvidence[key] != nil {
			return fail("CONTEXT_PACK_TUPLE_DUPLICATE")
		}
		contextByEvidence[key] = contextItem
	}
	trustedEvidence, err := trustedCatalogEvidence(context)
	if err != nil {
		return err
	}
	seenCitationEvidence := map[string]bool{}

	for number, citation := range citationByNumber {
		evidenceID := stringValue(citation["evidence_fragment_id"])
		if seenCitationEvidence[evidenceID] {
			return fail("CITATION_EVIDENCE_REUSED", evidenceID)
		}
		seenCitationEvidence[evidenceID] = true
		descriptor, trusted := trustedEvidence[evidenceID]
		if !trusted {
			return fail("CITATION_EVIDENCE_NOT_IN_EXTRACTION", evidenceID)
		}
		trustedExtraction := descriptor.extraction
		trustedFragment := descriptor.evidence
		chain := chainByCitation[number]
		if chain == nil {
			return fail("CITATION_CHAIN_MISSING")
		}
		if stringValue(citation["source_object_id"]) != stringValue(chain["source_object_id"]) ||
			stringValue(citation["source_version_id"]) != stringValue(chain["source_version_id"]) ||
			stringValue(citation["extraction_id"]) != stringValue(chain["extraction_id"]) ||
			evidenceID != stringValue(chain["evidence_fragment_id"]) {
			return fail("CITATION_CHAIN_MISMATCH")
		}
		if stringValue(chain["source_object_id"]) != stringValue(trustedExtraction["source_object_id"]) ||
			stringValue(chain["source_object_type"]) != stringValue(trustedExtraction["source_object_type"]) ||
			stringValue(chain["source_version_id"]) != stringValue(trustedExtraction["source_version_id"]) ||
			stringValue(chain["source_version_media_type"]) != stringValue(trustedExtraction["source_version_media_type"]) ||
			stringValue(chain["source_version_content_hash"]) != stringValue(trustedExtraction["source_version_content_hash"]) ||
			stringValue(chain["extraction_id"]) != stringValue(trustedExtraction["extraction_id"]) ||
			stringValue(chain["extraction_profile_hash"]) != stringValue(trustedExtraction["profile_hash"]) {
			return fail("CITATION_CHAIN_MISMATCH")
		}
		evidenceBytes, err := base64.StdEncoding.DecodeString(stringValue(chain["evidence_text_base64"]))
		if err != nil {
			return err
		}
		excerptBytes, err := base64.StdEncoding.DecodeString(stringValue(chain["cited_excerpt_base64"]))
		if err != nil {
			return err
		}
		if !bytes.Equal(evidenceBytes, excerptBytes) {
			return fail("CITED_EXCERPT_NOT_EXACT_EVIDENCE")
		}
		if stringValue(citation["source_version_content_hash"]) != stringValue(chain["source_version_content_hash"]) {
			return fail("SOURCE_VERSION_CONTENT_HASH_MISMATCH")
		}
		if stringValue(citation["evidence_text_hash"]) != sha256String(evidenceBytes) {
			return fail("EVIDENCE_TEXT_HASH_MISMATCH")
		}
		if stringValue(citation["evidence_text_hash"]) != stringValue(trustedFragment["evidence_text_hash"]) {
			return fail("CITATION_EVIDENCE_DESCRIPTOR_MISMATCH")
		}
		if stringValue(citation["cited_excerpt"]) != string(excerptBytes) || stringValue(citation["cited_excerpt_hash"]) != sha256String(excerptBytes) {
			return fail("CITED_EXCERPT_HASH_MISMATCH")
		}
		// CANONICALIZATION.md s7: anchor_hash is the organization-scoped
		// HMAC-SHA-256 of the JCS anchor object, keyed by digest_key_version.
		anchorHash, err := manifestAnchorDigest(context, citation)
		if err != nil {
			return err
		}
		if stringValue(citation["anchor_hash"]) != anchorHash {
			return fail("ANCHOR_HASH_MISMATCH")
		}
		anchor := object(citation["anchor"])
		anchorText, err := base64.StdEncoding.DecodeString(stringValue(chain["anchor_text_base64"]))
		if err != nil {
			return err
		}
		if err := validateSourceAnchor(anchor, anchorText, excerptBytes); err != nil {
			return err
		}
		if err := validateAnchorSourceCompatibility(trustedExtraction, anchor); err != nil {
			return err
		}
		if stringValue(citation["anchor_hash"]) != stringValue(trustedFragment["anchor_hash"]) || !canonicalObjectsEqual(anchor, object(trustedFragment["anchor"])) {
			return fail("CITATION_EVIDENCE_DESCRIPTOR_MISMATCH")
		}
		contextItem := contextByEvidence[evidenceID]
		if contextItem == nil {
			return fail("CITATION_NOT_IN_CONTEXT_PACK")
		}
		exactContextBytes, err := base64.StdEncoding.DecodeString(stringValue(contextItem["exact_context_base64"]))
		if err != nil {
			return err
		}
		if stringValue(contextItem["source_version_id"]) != stringValue(citation["source_version_id"]) ||
			stringValue(contextItem["extraction_id"]) != stringValue(citation["extraction_id"]) ||
			stringValue(contextItem["extraction_profile_hash"]) != stringValue(trustedExtraction["profile_hash"]) ||
			stringValue(contextItem["source_version_content_hash"]) != stringValue(citation["source_version_content_hash"]) ||
			stringValue(contextItem["evidence_text_hash"]) != stringValue(citation["evidence_text_hash"]) ||
			stringValue(contextItem["anchor_hash"]) != stringValue(trustedFragment["anchor_hash"]) ||
			stringValue(contextItem["exact_context_hash"]) != sha256String(exactContextBytes) {
			return fail("CITATION_NOT_IN_CONTEXT_PACK")
		}
	}
	if len(chainByCitation) != len(citationByNumber) {
		return fail("CITATION_CHAIN_EXTRA")
	}
	return nil
}
