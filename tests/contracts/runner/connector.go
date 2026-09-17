package contracts

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	pathpkg "path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var externalVersionHashPattern = regexp.MustCompile(`^hash:sha256:[0-9a-f]{64}$`)

func validExternalVersionKey(value string) bool {
	if externalVersionHashPattern.MatchString(value) {
		return true
	}
	if !strings.HasPrefix(value, "native:") || len(value) < len("native:")+1 || len(value) > 1024 {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "native:") {
		if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("._~:/+=%@-", r) {
			return false
		}
	}
	return true
}

func canonicalSourcePath(input string) (string, error) {
	canonical := norm.NFC.String(strings.ReplaceAll(input, "\\", "/"))
	if input != canonical {
		return "", fail("SOURCE_PATH_NOT_CANONICAL")
	}
	if canonical == "" || strings.HasPrefix(canonical, "/") || (len(canonical) >= 2 && canonical[1] == ':') {
		return "", fail("SOURCE_PATH_INVALID")
	}
	for _, r := range canonical {
		if r == 0 || unicode.IsControl(r) {
			return "", fail("SOURCE_PATH_INVALID")
		}
	}
	for _, segment := range strings.Split(canonical, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", fail("SOURCE_PATH_INVALID")
		}
	}
	return canonical, nil
}

func normalizePercentEscapes(input string) (string, error) {
	var output strings.Builder
	for i := 0; i < len(input); i++ {
		if input[i] != '%' {
			output.WriteByte(input[i])
			continue
		}
		if i+2 >= len(input) {
			return "", fail("WEB_URL_INVALID")
		}
		var value byte
		if _, err := fmt.Sscanf(input[i+1:i+3], "%02X", &value); err != nil {
			var parsed uint64
			if _, scanErr := fmt.Sscanf(strings.ToUpper(input[i+1:i+3]), "%02X", &parsed); scanErr != nil {
				return "", fail("WEB_URL_INVALID")
			}
			value = byte(parsed)
		}
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || strings.ContainsRune("-._~", rune(value)) {
			output.WriteByte(value)
		} else {
			output.WriteString(fmt.Sprintf("%%%02X", value))
		}
		i += 2
	}
	return output.String(), nil
}

func canonicalWebURL(input string) (string, error) {
	parsed, err := url.Parse(input)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fail("WEB_URL_INVALID")
	}
	hostname := parsed.Hostname()
	for _, r := range hostname {
		if r > 127 {
			return "", fail("WEB_URL_INVALID")
		}
	}
	hostname = strings.ToLower(hostname)
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	escapedPath := parsed.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	normalizedPath, pathErr := normalizePercentEscapes(escapedPath)
	if pathErr != nil {
		return "", pathErr
	}
	cleaned := pathpkg.Clean(normalizedPath)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	query, queryErr := normalizePercentEscapes(parsed.RawQuery)
	if queryErr != nil {
		return "", queryErr
	}
	canonical := parsed.Scheme + "://" + host + cleaned
	if query != "" {
		canonical += "?" + query
	}
	return canonical, nil
}

func validateConnectorTrustGate(context map[string]any) error {
	registration := object(context["registered_connector"])
	trust := object(context["connector_trust_record"])
	revision := object(context["source_connection_revision"])
	capability := object(context["capability_profile"])
	if err := assertAllowedFields(capability, []string{"connector_type", "connector_build_id", "connector_version", "connector_artifact_hash", "stable_object_ids", "item_level_acl", "acl_refresh"}); err != nil {
		return fail("CONNECTOR_CAPABILITY_PROFILE_MISMATCH")
	}
	capabilityHash, err := hashCanonical(capability)
	if err != nil {
		return err
	}
	if err := assertAllowedFields(revision, []string{
		"organization_id", "connection_id", "connection_revision", "connector_agent_id", "connector_type", "connector_build_id", "connector_version", "connector_artifact_hash",
		"capability_profile_id", "capability_profile_hash", "trust_profile_hash", "contract_suite_hash", "trust_record_id", "trust_verified_at",
		"source_scope_id", "scope_revision", "scope_state", "connector_job_id", "allowed_access_modes", "access_mode",
	}); err != nil {
		return fail("CONNECTOR_CONNECTION_REVISION_MISMATCH")
	}
	if revision == nil || stringValue(revision["organization_id"]) != stringValue(registration["organization_id"]) ||
		stringValue(revision["connection_id"]) != stringValue(registration["connection_id"]) || intValue(revision["connection_revision"]) != intValue(registration["connection_revision"]) ||
		stringValue(revision["connector_agent_id"]) != stringValue(registration["connector_agent_id"]) || stringValue(revision["connector_type"]) != stringValue(registration["connector_type"]) ||
		stringValue(revision["connector_build_id"]) != stringValue(registration["connector_build_id"]) || stringValue(revision["connector_version"]) != stringValue(registration["connector_version"]) ||
		stringValue(revision["connector_artifact_hash"]) != stringValue(registration["connector_artifact_hash"]) || stringValue(revision["source_scope_id"]) != stringValue(registration["source_scope_id"]) ||
		intValue(revision["scope_revision"]) != intValue(registration["scope_revision"]) || stringValue(revision["scope_state"]) != stringValue(registration["scope_state"]) ||
		stringValue(revision["connector_job_id"]) != stringValue(registration["connector_job_id"]) ||
		!canonicalArraysEqual(array(revision["allowed_access_modes"]), array(registration["allowed_access_modes"])) || stringValue(revision["access_mode"]) != stringValue(registration["access_mode"]) {
		return fail("CONNECTOR_CONNECTION_REVISION_MISMATCH")
	}
	if stringValue(capability["connector_type"]) != stringValue(revision["connector_type"]) || stringValue(capability["connector_build_id"]) != stringValue(revision["connector_build_id"]) ||
		stringValue(capability["connector_version"]) != stringValue(revision["connector_version"]) || stringValue(capability["connector_artifact_hash"]) != stringValue(revision["connector_artifact_hash"]) ||
		stringValue(revision["capability_profile_id"]) != stringValue(registration["capability_profile_id"]) || stringValue(revision["capability_profile_hash"]) != capabilityHash ||
		stringValue(registration["capability_profile_hash"]) != capabilityHash {
		return fail("CONNECTOR_CAPABILITY_PROFILE_MISMATCH")
	}
	trustProfileHash, err := hashCanonical(connectorEventTrustProfileInput(revision))
	if err != nil {
		return err
	}
	if stringValue(revision["trust_profile_hash"]) != trustProfileHash || stringValue(registration["trust_profile_hash"]) != trustProfileHash {
		return fail("CONNECTOR_TRUST_PROFILE_MISMATCH")
	}
	allowedModes := stringSet(array(revision["allowed_access_modes"]))
	accessMode := stringValue(revision["access_mode"])
	if (accessMode != "WORKSPACE_MANAGED" && accessMode != "SOURCE_ENFORCED") || !allowedModes[accessMode] {
		return fail("CONNECTOR_ACCESS_MODE_NOT_TRUSTED")
	}
	if !boolValue(capability["stable_object_ids"]) {
		return fail("CONNECTOR_STABLE_OBJECT_IDS_REQUIRED")
	}
	if accessMode == "SOURCE_ENFORCED" && (!boolValue(capability["item_level_acl"]) || !boolValue(capability["acl_refresh"])) {
		return fail("CONNECTOR_SOURCE_ENFORCED_CAPABILITY_MISSING")
	}
	if err := assertAllowedFields(trust, []string{
		"trust_record_id", "organization_id", "connection_id", "connection_revision", "connector_agent_id", "connector_type", "build_id", "version",
		"artifact_hash", "capability_profile_id", "capability_profile_hash", "trust_profile_hash", "contract_suite_hash", "verified_at", "status",
	}); err != nil {
		return fail("CONNECTOR_TRUST_RECORD_MISMATCH")
	}
	if trust == nil || stringValue(trust["status"]) != "VERIFIED" {
		return fail("CONNECTOR_BUILD_UNTRUSTED")
	}
	if stringValue(trust["trust_record_id"]) != stringValue(registration["trust_record_id"]) ||
		stringValue(trust["trust_record_id"]) != stringValue(revision["trust_record_id"]) ||
		stringValue(trust["organization_id"]) != stringValue(registration["organization_id"]) ||
		stringValue(trust["connection_id"]) != stringValue(registration["connection_id"]) ||
		intValue(trust["connection_revision"]) != intValue(registration["connection_revision"]) ||
		stringValue(trust["connector_agent_id"]) != stringValue(registration["connector_agent_id"]) ||
		stringValue(trust["connector_type"]) != stringValue(registration["connector_type"]) ||
		stringValue(trust["build_id"]) != stringValue(registration["connector_build_id"]) ||
		stringValue(trust["version"]) != stringValue(registration["connector_version"]) ||
		stringValue(trust["artifact_hash"]) != stringValue(registration["connector_artifact_hash"]) ||
		stringValue(trust["capability_profile_id"]) != stringValue(registration["capability_profile_id"]) || stringValue(trust["capability_profile_hash"]) != capabilityHash ||
		stringValue(trust["trust_profile_hash"]) != trustProfileHash ||
		stringValue(trust["contract_suite_hash"]) != stringValue(registration["contract_suite_hash"]) ||
		stringValue(trust["verified_at"]) != stringValue(registration["trust_verified_at"]) {
		return fail("CONNECTOR_TRUST_RECORD_MISMATCH")
	}
	verifiedAt, verifiedErr := time.Parse(time.RFC3339, stringValue(trust["verified_at"]))
	testClock, clockErr := time.Parse(time.RFC3339, stringValue(context["test_clock"]))
	if verifiedErr != nil || clockErr != nil || verifiedAt.After(testClock) {
		return fail("CONNECTOR_TRUST_RECORD_MISMATCH")
	}
	return nil
}

func connectorEventTrustProfileInput(revision map[string]any) map[string]any {
	return map[string]any{
		"connector_type": revision["connector_type"], "connector_build_id": revision["connector_build_id"],
		"connector_version": revision["connector_version"], "connector_artifact_hash": revision["connector_artifact_hash"],
		"capability_profile_id": revision["capability_profile_id"], "capability_profile_hash": revision["capability_profile_hash"],
		"contract_suite_hash": revision["contract_suite_hash"], "allowed_access_modes": revision["allowed_access_modes"],
	}
}

func validateConnectorEvent(event, context map[string]any) error {
	if err := assertAllowedFields(event, []string{
		"schema_version", "event_id", "claimed_organization_id", "connection_id", "source_scope_id",
		"scope_revision", "connector_job_id", "operation", "delete_semantics", "external_object_id",
		"external_version_key", "object_type", "object_metadata", "content_reference", "acl_snapshot",
		"event_time", "observed_at", "idempotency_key", "integrity",
	}); err != nil {
		return err
	}

	registration := object(context["registered_connector"])
	if stringValue(event["claimed_organization_id"]) != stringValue(registration["organization_id"]) {
		return fail("CONNECTOR_ORGANIZATION_MISMATCH")
	}
	if stringValue(event["connection_id"]) != stringValue(registration["connection_id"]) {
		return fail("CONNECTOR_CONNECTION_MISMATCH")
	}
	if stringValue(event["source_scope_id"]) != stringValue(registration["source_scope_id"]) {
		return fail("CONNECTOR_SCOPE_MISMATCH")
	}
	if intValue(event["scope_revision"]) != intValue(registration["scope_revision"]) ||
		(stringValue(registration["scope_state"]) != "READY" && stringValue(registration["scope_state"]) != "SYNCING") {
		return fail("CONNECTOR_SCOPE_REVISION_STALE")
	}
	if stringValue(event["connector_job_id"]) != stringValue(registration["connector_job_id"]) {
		return fail("CONNECTOR_JOB_MISMATCH")
	}
	if err := validateConnectorTrustGate(context); err != nil {
		return err
	}

	integrity := object(event["integrity"])
	payload := cloneObject(event)
	delete(payload, "integrity")
	payloadBytes, err := canonicalValue(payload)
	if err != nil {
		return err
	}
	if stringValue(integrity["payload_hash"]) != sha256String(payloadBytes) {
		return fail("CONNECTOR_PAYLOAD_HASH_MISMATCH")
	}
	_, publicKey, keyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	key := object(context["key"])
	registrationAgentID := stringValue(registration["connector_agent_id"])
	if stringValue(integrity["key_id"]) != keyID {
		return fail("CONNECTOR_SIGNING_KEY_INVALID")
	}
	if stringValue(key["status"]) == "REVOKED" {
		return fail("SIGNATURE_KEY_REVOKED")
	}
	if stringValue(key["status"]) != "ACTIVE" {
		return fail("CONNECTOR_SIGNING_KEY_NOT_ACTIVE")
	}
	if stringValue(key["organization_id"]) != stringValue(registration["organization_id"]) ||
		stringValue(key["purpose"]) != "CONNECTOR_EVENT" ||
		stringValue(key["connection_id"]) != stringValue(registration["connection_id"]) ||
		registrationAgentID == "" || stringValue(key["connector_agent_id"]) != registrationAgentID {
		return fail("CONNECTOR_SIGNING_KEY_SCOPE_MISMATCH")
	}
	testClock, err := time.Parse(time.RFC3339, stringValue(context["test_clock"]))
	if err != nil {
		return err
	}
	signedAt, err := time.Parse(time.RFC3339, stringValue(integrity["signed_at"]))
	if err != nil || signedAt.After(testClock.Add(time.Minute)) || signedAt.Before(testClock.Add(-5*time.Minute)) {
		return fail("CONNECTOR_SIGNATURE_TIME_INVALID")
	}
	notBefore, notBeforeErr := time.Parse(time.RFC3339, stringValue(key["not_before"]))
	signUntil, signUntilErr := time.Parse(time.RFC3339, stringValue(key["sign_until"]))
	if notBeforeErr != nil || signUntilErr != nil || signedAt.Before(notBefore) || signedAt.After(signUntil) {
		return fail("CONNECTOR_SIGNING_KEY_INTERVAL_INVALID")
	}
	signingBytes, err := canonicalValue(connectorSigningObject(event))
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(stringValue(integrity["value_base64"]))
	if err != nil || !ed25519.Verify(publicKey, signingBytes, signature) {
		return fail("CONNECTOR_SIGNATURE_INVALID")
	}

	operation := stringValue(event["operation"])
	if operation == "DELETE" {
		semantics := stringValue(event["delete_semantics"])
		if semantics != "SOURCE_OBJECT_DELETED" && semantics != "SCOPE_MEMBERSHIP_REMOVED" {
			return fail("CONNECTOR_DELETE_SEMANTICS_INVALID")
		}
		if event["external_version_key"] != nil || event["object_metadata"] != nil || event["content_reference"] != nil || event["acl_snapshot"] != nil {
			return fail("CONNECTOR_DELETE_FIELDS_NOT_NULL")
		}
		return nil
	}
	if event["delete_semantics"] != nil {
		return fail("CONNECTOR_DELETE_SEMANTICS_UNEXPECTED")
	}

	versionKey := stringValue(event["external_version_key"])
	if versionKey != "" && !validExternalVersionKey(versionKey) {
		return fail("CONNECTOR_EXTERNAL_VERSION_KEY_INVALID")
	}
	metadata := object(event["object_metadata"])
	if operation == "ACL_CHANGED" {
		if metadata != nil || event["content_reference"] != nil {
			return fail("CONNECTOR_ACL_CHANGED_CONTENT_NOT_NULL")
		}
	} else if stringValue(metadata["kind"]) != stringValue(event["object_type"]) {
		return fail("CONNECTOR_METADATA_DISCRIMINATOR_MISMATCH")
	}

	if content := object(event["content_reference"]); content != nil {
		expiresAt, parseErr := time.Parse(time.RFC3339, stringValue(content["expires_at"]))
		if parseErr != nil || !expiresAt.After(testClock) {
			return fail("CONTENT_REFERENCE_EXPIRED")
		}
		sourceBytes, decodeErr := base64.StdEncoding.DecodeString(stringValue(context["source_bytes_base64"]))
		if decodeErr != nil {
			return decodeErr
		}
		sourceHash := sha256String(sourceBytes)
		if stringValue(content["content_hash"]) != sourceHash {
			return fail("SOURCE_BYTES_HASH_MISMATCH")
		}
		if intValue(content["size_bytes"]) != len(sourceBytes) {
			return fail("SOURCE_BYTES_SIZE_MISMATCH")
		}
		if metadata != nil {
			if intValue(metadata["size_bytes"]) != len(sourceBytes) {
				return fail("SOURCE_METADATA_SIZE_MISMATCH")
			}
			if stringValue(content["media_type"]) != stringValue(metadata["mime_type"]) {
				return fail("SOURCE_MEDIA_TYPE_MISMATCH")
			}
		}
		if strings.HasPrefix(versionKey, "hash:") && versionKey != "hash:"+sourceHash {
			return fail("CONNECTOR_EXTERNAL_VERSION_HASH_MISMATCH")
		}
	}

	if metadata != nil {
		switch stringValue(metadata["kind"]) {
		case "GIT_FILE":
			if utf8.RuneCountInString(stringValue(metadata["repository"])) > 1024 {
				return fail("CONNECTOR_GIT_REPOSITORY_TOO_LONG")
			}
		case "EMAIL":
			if utf8.RuneCountInString(stringValue(metadata["immutable_message_id"])) > 2048 {
				return fail("CONNECTOR_EMAIL_MESSAGE_ID_TOO_LONG")
			}
		case "WEB_PAGE":
			if utf8.RuneCountInString(stringValue(metadata["canonical_url"])) > 8192 {
				return fail("CONNECTOR_WEB_URL_TOO_LONG")
			}
		}
		var locator map[string]any
		switch stringValue(metadata["kind"]) {
		case "FILE":
			canonicalPath, pathErr := canonicalSourcePath(stringValue(metadata["relative_path"]))
			if pathErr != nil {
				return pathErr
			}
			locator = map[string]any{
				"connection_id": event["connection_id"],
				"kind":          "FILE",
				"relative_path": canonicalPath,
			}
		case "GIT_FILE":
			canonicalPath, pathErr := canonicalSourcePath(stringValue(metadata["path"]))
			if pathErr != nil {
				return pathErr
			}
			locator = map[string]any{
				"branch":        metadata["branch"],
				"connection_id": event["connection_id"],
				"kind":          "GIT_FILE",
				"path":          canonicalPath,
				"provider":      metadata["provider"],
				"repository":    metadata["repository"],
			}
		case "EMAIL":
			locator = map[string]any{
				"connection_id":        event["connection_id"],
				"immutable_message_id": metadata["immutable_message_id"],
				"kind":                 "EMAIL",
				"mailbox_id":           metadata["mailbox_id"],
			}
		case "EMAIL_ATTACHMENT":
			locator = map[string]any{
				"connection_id":                     event["connection_id"],
				"kind":                              "EMAIL_ATTACHMENT",
				"mime_part_id":                      metadata["mime_part_id"],
				"parent_message_external_object_id": metadata["parent_message_external_object_id"],
			}
		case "WEB_PAGE":
			canonicalURL, urlErr := canonicalWebURL(stringValue(metadata["canonical_url"]))
			if urlErr != nil {
				return urlErr
			}
			if canonicalURL != stringValue(metadata["canonical_url"]) {
				return fail("WEB_URL_NOT_CANONICAL")
			}
			locator = map[string]any{
				"canonical_url": canonicalURL,
				"connection_id": event["connection_id"],
				"kind":          "WEB_PAGE",
			}
		}
		if locator != nil {
			expected, hashErr := hashCanonical(locator)
			if hashErr != nil {
				return hashErr
			}
			if stringValue(metadata["canonical_locator_hash"]) != expected {
				return fail("CANONICAL_LOCATOR_HASH_MISMATCH")
			}
		}
	}

	acl := object(event["acl_snapshot"])
	if stringValue(registration["access_mode"]) == "SOURCE_ENFORCED" && operation != "DELETE" {
		if acl == nil {
			return fail("SOURCE_ENFORCED_ACL_MISSING")
		}
		if stringValue(acl["status"]) != "RESOLVED" {
			return fail("ACL_UNRESOLVED_FAIL_CLOSED")
		}
		resolvedAt, resolvedErr := time.Parse(time.RFC3339, stringValue(acl["resolved_at"]))
		expiresAt, expiresErr := time.Parse(time.RFC3339, stringValue(acl["expires_at"]))
		if expiresErr != nil || !expiresAt.After(testClock) {
			return fail("SOURCE_ENFORCED_ACL_EXPIRED")
		}
		if resolvedErr != nil || resolvedAt.After(expiresAt) {
			return fail("SOURCE_ENFORCED_ACL_TIME_INVALID")
		}
	}
	if acl != nil {
		tokens := array(acl["principal_tokens"])
		keys := make([]string, 0, len(tokens))
		seen := map[string]bool{}
		for _, rawToken := range tokens {
			token := object(rawToken)
			key := stringValue(token["namespace"]) + "\x00" + stringValue(token["type"]) + "\x00" + stringValue(token["subject"]) + "\x00" + stringValue(token["revision"])
			if seen[key] {
				return fail("ACL_IDENTITY_COLLISION")
			}
			seen[key] = true
			keys = append(keys, key)
		}
		sorted := append([]string(nil), keys...)
		sort.Strings(sorted)
		for i := range keys {
			if keys[i] != sorted[i] {
				return fail("ACL_TOKENS_NOT_CANONICAL")
			}
		}
		hashInput := map[string]any{"status": acl["status"], "principal_tokens": acl["principal_tokens"]}
		expected, hashErr := hashCanonical(hashInput)
		if hashErr != nil {
			return hashErr
		}
		if stringValue(acl["content_hash"]) != expected {
			return fail("ACL_HASH_MISMATCH")
		}
	}
	return nil
}
