package contracts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// validateExtractiveAnswerPlan is the executable semantic half of ADR-0067.
// The JSON schema constrains shape; this validator owns the cross-object rule
// that a claim has exactly one symmetric citation and the two canonical UTF-8
// byte sequences are identical.
func validateExtractiveAnswerPlan(plan, context map[string]any) error {
	if err := assertAllowedFields(plan, []string{
		"schema_version", "answer_mode", "verification_method", "digest_key_version", "authorized_context_hash", "claims", "citations",
	}); err != nil {
		return err
	}
	if stringValue(plan["schema_version"]) != "extractive-answer-plan-v1" ||
		stringValue(plan["answer_mode"]) != "EXTRACTIVE" ||
		stringValue(plan["verification_method"]) != "BYTE_EXACT_CITATION" {
		return fail("EXTRACTIVE_MODE_BINDING_INVALID")
	}
	if context == nil {
		return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_REQUIRED")
	}
	if err := assertAllowedFields(context, []string{
		"authorized_candidate_set", "authorization_snapshot", "trusted_authorization_catalog", "authorization_hmac_test_keys",
	}); err != nil {
		return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID")
	}
	candidates := array(context["authorized_candidate_set"])
	snapshot := object(context["authorization_snapshot"])
	catalog := object(context["trusted_authorization_catalog"])
	organizationID := stringValue(snapshot["organization_id"])
	workspaceID := stringValue(snapshot["workspace_id"])
	candidateIntegrityHash, err := hashCanonical(candidates)
	if err != nil {
		return err
	}
	keyVersion := intValue(plan["digest_key_version"])
	keyBytes, err := extractiveHMACKey(context, keyVersion)
	if err != nil {
		return err
	}
	if err := validateExtractiveTrustedAuthorization(catalog, snapshot, candidates, candidateIntegrityHash, organizationID, workspaceID, keyVersion, keyBytes); err != nil {
		return err
	}
	if stringValue(plan["authorized_context_hash"]) != stringValue(snapshot["authorized_candidate_set_hash"]) {
		return fail("EXTRACTIVE_CONTEXT_HASH_MISMATCH")
	}
	authorized := map[string]map[string]any{}
	catalogByID := map[string]map[string]any{}
	for _, raw := range array(catalog["entries"]) {
		entry := object(raw)
		id := stringValue(entry["evidence_fragment_id"])
		if id == "" || catalogByID[id] != nil {
			return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID", id)
		}
		catalogByID[id] = entry
	}
	for _, raw := range candidates {
		candidate := object(raw)
		id := stringValue(candidate["evidence_fragment_id"])
		catalogEntry := catalogByID[id]
		if id == "" || authorized[id] != nil || catalogEntry == nil {
			return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID", id)
		}
		if equal, compareErr := extractiveCanonicalEqual(candidate, catalogEntry); compareErr != nil || !equal {
			return fail("EXTRACTIVE_CONTEXT_ENTRY_NOT_AUTHORIZED", id)
		}
		candidateAnchor := object(candidate["anchor"])
		if candidateAnchor == nil {
			return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID", id)
		}
		// CANONICALIZATION.md s7: anchor_hash is the organization-scoped
		// HMAC-SHA-256 of the JCS anchor object, keyed by digest_key_version.
		expectedAnchor, anchorErr := extractiveHMACDigest(keyBytes, keyVersion, candidateAnchor)
		if anchorErr != nil || stringValue(candidate["anchor_hash"]) != expectedAnchor {
			return fail("EXTRACTIVE_CONTEXT_ENTRY_NOT_AUTHORIZED", id)
		}
		exactContext, decodeErr := base64.StdEncoding.DecodeString(stringValue(candidate["exact_context_base64"]))
		if decodeErr != nil || stringValue(candidate["exact_context_hash"]) != sha256String(exactContext) {
			return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID", id)
		}
		authorized[id] = candidate
	}

	claimByID := map[string]map[string]any{}
	for _, raw := range array(plan["claims"]) {
		claim := object(raw)
		id := stringValue(claim["claim_id"])
		if id == "" || claimByID[id] != nil {
			return fail("EXTRACTIVE_CLAIM_ID_INVALID", id)
		}
		if stringValue(claim["kind"]) != "FACT" {
			return fail("EXTRACTIVE_CLAIM_KIND_INVALID", id)
		}
		text := stringValue(claim["text"])
		if text == "" || strings.ContainsAny(text, "\r\n") || len([]byte(text)) > 2000 {
			return fail("EXTRACTIVE_CLAIM_SENTENCE_INVALID", id)
		}
		// The schema bounds utf8_bytes to 1..2000; the executable layer owns
		// the truthfulness of that declaration.
		if intValue(claim["utf8_bytes"]) != len([]byte(canonicalTextV1(text))) {
			return fail("EXTRACTIVE_CLAIM_SENTENCE_INVALID", id)
		}
		if len(array(claim["citation_numbers"])) != 1 {
			return fail("EXTRACTIVE_CITATION_CARDINALITY", id)
		}
		claimByID[id] = claim
	}

	citationByNumber := map[int]map[string]any{}
	for _, raw := range array(plan["citations"]) {
		citation := object(raw)
		number := intValue(citation["citation_number"])
		if number < 1 || citationByNumber[number] != nil {
			return fail("EXTRACTIVE_CITATION_NUMBER_INVALID", strconvItoa(number))
		}
		excerpt := stringValue(citation["cited_excerpt"])
		if excerpt == "" || strings.ContainsAny(excerpt, "\r\n") || len([]byte(excerpt)) > 2000 {
			return fail("EXTRACTIVE_CITATION_SENTENCE_INVALID", strconvItoa(number))
		}
		if intValue(citation["utf8_bytes"]) != len([]byte(canonicalTextV1(excerpt))) {
			return fail("EXTRACTIVE_CITATION_SENTENCE_INVALID", strconvItoa(number))
		}
		candidate := authorized[stringValue(citation["evidence_fragment_id"])]
		if candidate == nil || stringValue(citation["source_object_id"]) != stringValue(candidate["source_object_id"]) ||
			stringValue(citation["source_version_id"]) != stringValue(candidate["source_version_id"]) ||
			stringValue(citation["extraction_id"]) != stringValue(candidate["extraction_id"]) ||
			stringValue(citation["anchor_hash"]) != stringValue(candidate["anchor_hash"]) ||
			!keyedDigestMatchesVersion(stringValue(citation["anchor_hash"]), keyVersion) {
			return fail("EXTRACTIVE_CONTEXT_ENTRY_NOT_AUTHORIZED", strconvItoa(number))
		}
		exactContext, _ := base64.StdEncoding.DecodeString(stringValue(candidate["exact_context_base64"]))
		if !containsAuthorizedSentence(excerpt, exactContext) {
			return fail("EXTRACTIVE_CITATION_NOT_IN_CONTEXT", strconvItoa(number))
		}
		citationByNumber[number] = citation
	}

	seenCitations := map[int]bool{}
	for id, claim := range claimByID {
		number := intValue(array(claim["citation_numbers"])[0])
		citation := citationByNumber[number]
		if citation == nil || stringValue(citation["claim_id"]) != id {
			return fail("EXTRACTIVE_CITATION_MAPPING_ASYMMETRIC", id)
		}
		if seenCitations[number] {
			return fail("EXTRACTIVE_CITATION_REUSED", strconvItoa(number))
		}
		seenCitations[number] = true
		claimBytes := []byte(canonicalTextV1(stringValue(claim["text"])))
		citationBytes := []byte(canonicalTextV1(stringValue(citation["cited_excerpt"])))
		if !bytes.Equal(claimBytes, citationBytes) {
			return fail("EXTRACTIVE_CLAIM_NOT_EXACT", id)
		}
	}
	if len(seenCitations) != len(citationByNumber) {
		return fail("EXTRACTIVE_CITATION_ORPHAN")
	}
	return nil
}

func applyExtractiveMutation(plan, context map[string]any, mutation string) error {
	switch mutation {
	case "", "NONE":
		return nil
	case "EXTRACTIVE_TRUSTED_CATALOG_TAMPER":
		entries := array(object(context["trusted_authorization_catalog"])["entries"])
		if len(entries) == 0 {
			return fail("EXTRACTIVE_AUTHORIZED_CONTEXT_INVALID")
		}
		object(entries[0])["source_object_id"] = "source_object_attacker"
	case "EXTRACTIVE_SNAPSHOT_SIGNATURE_TAMPER":
		object(context["authorization_snapshot"])["signature"] = "hmac-sha256:k1:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	default:
		return fail("UNKNOWN_EXTRACTIVE_MUTATION", mutation)
	}
	return nil
}

func validateExtractiveTrustedAuthorization(catalog, snapshot map[string]any, candidates []any, candidateIntegrityHash, organizationID, workspaceID string, keyVersion int, keyBytes []byte) error {
	if catalog == nil || snapshot == nil || organizationID == "" || workspaceID == "" || len(candidates) == 0 ||
		stringValue(catalog["schema_version"]) != "trusted-authorized-catalog-v1" ||
		stringValue(snapshot["schema_version"]) != "retrieval-authorization-v1" ||
		stringValue(catalog["organization_id"]) != organizationID || stringValue(catalog["workspace_id"]) != workspaceID ||
		stringValue(catalog["catalog_id"]) == "" || stringValue(snapshot["catalog_id"]) != stringValue(catalog["catalog_id"]) ||
		intValue(catalog["digest_key_version"]) != keyVersion || intValue(snapshot["digest_key_version"]) != keyVersion {
		return fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	entries := array(catalog["entries"])
	entriesIntegrityHash, err := hashCanonical(entries)
	if err != nil {
		return err
	}
	if len(entries) == 0 || stringValue(catalog["entries_integrity_hash"]) != entriesIntegrityHash {
		return fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	catalogSignatureInput := map[string]any{
		"schema_version":         catalog["schema_version"],
		"organization_id":        catalog["organization_id"],
		"workspace_id":           catalog["workspace_id"],
		"catalog_id":             catalog["catalog_id"],
		"digest_key_version":     catalog["digest_key_version"],
		"entries_integrity_hash": catalog["entries_integrity_hash"],
	}
	expectedCatalogSignature, err := extractiveHMACDigest(keyBytes, keyVersion, catalogSignatureInput)
	if err != nil || stringValue(catalog["signature"]) != expectedCatalogSignature {
		return fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	if stringValue(snapshot["catalog_entries_integrity_hash"]) != entriesIntegrityHash ||
		stringValue(snapshot["authorized_candidate_set_integrity_hash"]) != candidateIntegrityHash {
		return fail("EXTRACTIVE_CONTEXT_HASH_MISMATCH")
	}
	expectedCandidateSetHash, err := extractiveHMACDigest(keyBytes, keyVersion, candidates)
	if err != nil || stringValue(snapshot["authorized_candidate_set_hash"]) != expectedCandidateSetHash ||
		!keyedDigestMatchesVersion(stringValue(snapshot["authorized_candidate_set_hash"]), keyVersion) {
		return fail("EXTRACTIVE_CONTEXT_HASH_MISMATCH")
	}
	snapshotSignatureInput := map[string]any{
		"schema_version":                          snapshot["schema_version"],
		"organization_id":                         snapshot["organization_id"],
		"workspace_id":                            snapshot["workspace_id"],
		"catalog_id":                              snapshot["catalog_id"],
		"digest_key_version":                      snapshot["digest_key_version"],
		"catalog_entries_integrity_hash":          snapshot["catalog_entries_integrity_hash"],
		"authorized_candidate_set_integrity_hash": snapshot["authorized_candidate_set_integrity_hash"],
		"authorized_candidate_set_hash":           snapshot["authorized_candidate_set_hash"],
	}
	expectedSnapshotSignature, err := extractiveHMACDigest(keyBytes, keyVersion, snapshotSignatureInput)
	if err != nil || stringValue(snapshot["signature"]) != expectedSnapshotSignature {
		return fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	return nil
}

func extractiveHMACKey(context map[string]any, version int) ([]byte, error) {
	if version < 1 {
		return nil, fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	encoded := stringValue(object(context["authorization_hmac_test_keys"])["k"+strconvItoa(version)])
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(keyBytes) < 32 {
		return nil, fail("EXTRACTIVE_AUTHORIZATION_SNAPSHOT_INVALID")
	}
	return keyBytes, nil
}

func extractiveHMACDigest(keyBytes []byte, version int, value any) (string, error) {
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write(canonical)
	return "hmac-sha256:k" + strconvItoa(version) + ":" + hex.EncodeToString(mac.Sum(nil)), nil
}

func extractiveCanonicalEqual(left, right any) (bool, error) {
	leftCanonical, err := canonicalValue(left)
	if err != nil {
		return false, err
	}
	rightCanonical, err := canonicalValue(right)
	if err != nil {
		return false, err
	}
	return bytes.Equal(leftCanonical, rightCanonical), nil
}

// keyedDigestVersion parses the k<version> prefix of a keyed digest string.
// It returns 0 for any value that is not a well-formed keyed digest.
func keyedDigestVersion(value string) (int, error) {
	rest := strings.TrimPrefix(value, "hmac-sha256:k")
	if rest == value || rest == "" {
		return 0, fail("ANCHOR_HASH_MISMATCH")
	}
	digits := strings.SplitN(rest, ":", 2)
	if len(digits) != 2 || len(digits[1]) != 64 {
		return 0, fail("ANCHOR_HASH_MISMATCH")
	}
	for _, c := range digits[1] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return 0, fail("ANCHOR_HASH_MISMATCH")
		}
	}
	version := 0
	for _, c := range digits[0] {
		if c < '0' || c > '9' {
			return 0, fail("ANCHOR_HASH_MISMATCH")
		}
		version = version*10 + int(c-'0')
		if version > 999999999 {
			return 0, fail("ANCHOR_HASH_MISMATCH")
		}
	}
	if version < 1 {
		return 0, fail("ANCHOR_HASH_MISMATCH")
	}
	return version, nil
}

// manifestAnchorDigest recomputes the canonical anchor projection for a
// citation or trusted-evidence descriptor: HMAC-SHA-256 with the k<version>
// key carried by the validation context, over the JCS anchor object.
func manifestAnchorDigest(context, value map[string]any) (string, error) {
	version, err := keyedDigestVersion(stringValue(value["anchor_hash"]))
	if err != nil {
		return "", err
	}
	keyBytes, err := extractiveHMACKey(context, version)
	if err != nil {
		return "", fail("ANCHOR_HASH_MISMATCH")
	}
	return extractiveHMACDigest(keyBytes, version, value["anchor"])
}

func keyedDigestMatchesVersion(value string, version int) bool {
	return version > 0 && discoveredIdentityDigest.MatchString(value) && strings.HasPrefix(value, "hmac-sha256:k"+strconvItoa(version)+":")
}

func containsAuthorizedSentence(excerpt string, context []byte) bool {
	excerpt = strings.TrimSpace(canonicalTextV1(excerpt))
	for _, line := range strings.Split(canonicalTextV1(string(context)), "\n") {
		if containsSentenceInText(excerpt, line) {
			return true
		}
	}
	return false
}

func containsSentenceInText(excerpt, remaining string) bool {
	for len(remaining) > 0 {
		index := strings.IndexAny(remaining, ".!?。！？")
		if index < 0 {
			return strings.TrimSpace(remaining) == excerpt
		}
		_, size := utf8.DecodeRuneInString(remaining[index:])
		end := index + size
		if strings.TrimSpace(remaining[:end]) == excerpt {
			return true
		}
		remaining = remaining[end:]
	}
	return false
}
