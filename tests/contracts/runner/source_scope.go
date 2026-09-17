package contracts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
	"knowvault.local/verified-workspace/internal/source/scopeglob"
)

var windowsDeviceName = regexp.MustCompile(`^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
var rawGitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)
var discoveredIdentityDigest = regexp.MustCompile(`^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$`)

func applySourceScopeMutation(scope, context map[string]any, mutation string) {
	config := object(scope["scope_config"])
	connection := sourceConnectionRevision(scope, context)
	switch mutation {
	case "", "NONE":
	case "SCOPE_UNKNOWN_FIELD":
		scope["unexpected"] = true
	case "SCOPE_TYPE_MISMATCH":
		scope["source_type"] = "MAIL"
	case "FOLDER_PATH_TRAVERSAL":
		config["relative_root"] = "projects/../secrets"
	case "FOLDER_WINDOWS_ADS":
		config["relative_root"] = "projects/report.txt:secret"
	case "FOLDER_WINDOWS_DEVICE":
		config["relative_root"] = "projects/CON.txt"
	case "FOLDER_WINDOWS_TRAILING":
		config["relative_root"] = "projects/alpha. "
	case "GLOB_BRACE":
		config["include_globs"] = []any{"docs/{a,b}.md"}
	case "GLOB_CHARACTER_CLASS":
		config["include_globs"] = []any{"docs/[ab].md"}
	case "GLOB_PARTIAL_DOUBLE_STAR":
		config["include_globs"] = []any{"docs/***.md"}
	case "GLOB_TRAILING_WHITESPACE":
		config["include_globs"] = []any{"docs/*.md "}
	case "GLOB_EXTGLOB":
		config["include_globs"] = []any{"docs/@(plan).md"}
	case "GIT_REVISION_EXPRESSION":
		config["branch_name"] = "main~1"
	case "GIT_LEADING_OPTION":
		config["branch_name"] = "--upload-pack=evil"
	case "SITE_RAW_PREFIX_BOUNDARY":
		config["seed_urls"] = []any{"https://docs.example.com/alpha-evil"}
	case "SITE_ENCODED_SEPARATOR":
		config["seed_urls"] = []any{"https://docs.example.com/alpha%2Fsecret"}
	case "SOURCE_ENFORCED_CAPABILITY_MISSING":
		profile := object(object(context["capability_profiles"])[stringValue(connection["capability_profile_id"])])
		profile["item_level_acl"] = false
		if profileHash, err := hashCanonical(profile); err == nil {
			connection["capability_profile_hash"] = profileHash
			record := object(object(context["connector_trust_records"])[stringValue(connection["connector_trust_record_id"])])
			record["capability_profile_hash"] = profileHash
			if trustProfileHash, hashErr := hashCanonical(sourceConnectionTrustProfileInput(connection)); hashErr == nil {
				connection["trust_profile_hash"] = trustProfileHash
				record["trust_profile_hash"] = trustProfileHash
			}
		}
	case "SOURCE_ENFORCED_CAPABILITY_BUILD_MISMATCH":
		profile := object(object(context["capability_profiles"])[stringValue(connection["capability_profile_id"])])
		profile["connector_build_id"] = "other-build"
	case "WORKSPACE_MANAGED_CONNECTOR_TRUST_MISMATCH":
		record := object(object(context["connector_trust_records"])[stringValue(connection["connector_trust_record_id"])])
		record["connector_artifact_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CONNECTION_PLATFORM_DOWNGRADE":
		connection["platform"] = "POSIX"
	case "CONNECTION_PLATFORM_UNKNOWN_SIGNED":
		connection["platform"] = "ALIEN"
		record := object(object(context["connector_trust_records"])[stringValue(connection["connector_trust_record_id"])])
		record["platform"] = "ALIEN"
		if trustProfileHash, err := hashCanonical(sourceConnectionTrustProfileInput(connection)); err == nil {
			connection["trust_profile_hash"] = trustProfileHash
			record["trust_profile_hash"] = trustProfileHash
		}
	case "WORKSPACE_MANAGED_TRUST_PROFILE_HASH_MISMATCH", "SOURCE_ENFORCED_TRUST_PROFILE_HASH_MISMATCH":
		connection["trust_profile_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "CONNECTION_REVISION_MISMATCH":
		scope["connection_revision"] = float64(999)
	case "CAPABILITY_PROFILE_MISMATCH":
		connection["capability_profile_id"] = "capability_foreign"
	case "ACCESS_MODE_FORBIDDEN":
		connection["allowed_access_modes"] = []any{"WORKSPACE_MANAGED"}
		if trustProfileHash, err := hashCanonical(sourceConnectionTrustProfileInput(connection)); err == nil {
			connection["trust_profile_hash"] = trustProfileHash
			record := object(object(context["connector_trust_records"])[stringValue(connection["connector_trust_record_id"])])
			record["trust_profile_hash"] = trustProfileHash
		}
	case "LIMIT_EXCEEDS_CONNECTION":
		scope["object_limit"] = float64(intValue(connection["max_object_limit"]) + 1)
	case "OBJECT_BYTE_CAP_EXCEEDS_LIMIT":
		scope["byte_limit"] = float64(1024)
	case "DISCOVERED_SCOPE_ID_DRIFT":
		scope["discovered_scope_id"] = "discovered_scope_untrusted"
	case "DISCOVERED_IDENTITY_DIGEST_DRIFT":
		scope["discovered_identity_digest"] = "hmac-sha256:k1:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	case "DISCOVERED_SCOPE_CONNECTION_REVISION_MISMATCH":
		trustedScope := object(object(connection["discovered_scopes"])[stringValue(scope["discovered_scope_id"])])
		trustedScope["connection_revision"] = float64(2)
	case "DISCOVERED_SCOPE_CONFIG_IDENTITY_DRIFT":
		config["allowed_url_prefixes"] = []any{"https://docs.example.com/alpha/start"}
	case "SITE_ROBOTS_FALSE":
		config["respect_robots_txt"] = false
	}
}

func sourceConnectionRevision(scope, context map[string]any) map[string]any {
	connection := object(object(context["connections"])[stringValue(scope["connection_id"])])
	if connection == nil {
		return nil
	}
	return object(object(connection["revisions"])[strconv.Itoa(intValue(scope["connection_revision"]))])
}

func applyTornReadMutation(value map[string]any, mutation string) {
	if mutation == "TORN_READ_COMMIT" {
		commit := object(value["commit_attempt"])
		commit["source_version_created"] = true
		commit["evidence_indexed"] = true
	}
}

func validateSourceScope(scope, context map[string]any) error {
	if err := assertAllowedFields(scope, []string{
		"schema_version", "source_scope_id", "revision", "connection_id", "connection_revision", "source_type", "discovered_scope_id",
		"discovered_identity_digest", "access_mode", "scope_config", "sync_interval_seconds", "content_freshness_sla_seconds",
		"acl_freshness_sla_seconds", "object_limit", "byte_limit", "created_by", "created_at",
	}); err != nil {
		return err
	}
	connection := sourceConnectionRevision(scope, context)
	if connection == nil {
		return fail("SOURCE_SCOPE_CONNECTION_REVISION_MISMATCH")
	}
	if stringValue(connection["source_type"]) != stringValue(scope["source_type"]) {
		return fail("SOURCE_SCOPE_TYPE_MISMATCH")
	}
	capabilities, err := validateSourceConnectionTrust(scope, context, connection)
	if err != nil {
		return err
	}
	accessMode := stringValue(scope["access_mode"])
	if !stringSet(array(connection["allowed_access_modes"]))[accessMode] {
		return fail("SOURCE_SCOPE_ACCESS_MODE_FORBIDDEN")
	}
	if accessMode == "SOURCE_ENFORCED" {
		if !boolValue(capabilities["stable_object_ids"]) || !boolValue(capabilities["item_level_acl"]) || !boolValue(capabilities["acl_refresh"]) {
			return fail("SOURCE_SCOPE_CAPABILITY_MISSING")
		}
	}
	if intValue(scope["object_limit"]) > intValue(connection["max_object_limit"]) || intValue(scope["byte_limit"]) > intValue(connection["max_byte_limit"]) {
		return fail("SOURCE_SCOPE_LIMIT_EXCEEDS_CONNECTION")
	}
	config := object(scope["scope_config"])
	for _, capField := range sourceByteCapFields(stringValue(scope["source_type"])) {
		if intValue(config[capField]) > intValue(scope["byte_limit"]) {
			return fail("SOURCE_SCOPE_OBJECT_BYTE_CAP_EXCEEDS_LIMIT")
		}
	}
	err = nil
	switch stringValue(scope["source_type"]) {
	case "FOLDER":
		err = validateFolderScope(config, connection)
	case "GIT":
		err = validateGitScope(config, connection)
	case "MAIL":
		err = validateMailScope(config, connection)
	case "SITE":
		err = validateSiteScope(config, connection)
	default:
		return fail("SOURCE_SCOPE_TYPE_UNKNOWN")
	}
	if err != nil {
		return err
	}
	return validateDiscoveredScopeTrust(scope, connection, context)
}

func validateDiscoveredScopeTrust(scope, connection, context map[string]any) error {
	discoveredID := stringValue(scope["discovered_scope_id"])
	digest := stringValue(scope["discovered_identity_digest"])
	trusted := object(object(connection["discovered_scopes"])[discoveredID])
	if trusted == nil || !discoveredIdentityDigest.MatchString(digest) {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	if err := assertAllowedFields(trusted, []string{
		"discovered_scope_id", "connection_id", "connection_revision", "discovered_identity_digest",
	}); err != nil {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	if stringValue(trusted["discovered_scope_id"]) != discoveredID ||
		stringValue(trusted["connection_id"]) != stringValue(scope["connection_id"]) ||
		intValue(trusted["connection_revision"]) != intValue(scope["connection_revision"]) ||
		stringValue(trusted["discovered_identity_digest"]) != digest {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	parts := strings.Split(digest, ":")
	if len(parts) != 3 {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	keyBytes, err := base64.StdEncoding.DecodeString(stringValue(object(context["discovery_digest_test_keys"])[parts[1]]))
	if err != nil || len(keyBytes) < 32 {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	identityInput, err := sourceDiscoveryIdentityInput(scope)
	if err != nil {
		return err
	}
	canonical, err := canonicalValue(identityInput)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, keyBytes)
	_, _ = mac.Write(canonical)
	expected := "hmac-sha256:" + parts[1] + ":" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(digest), []byte(expected)) {
		return fail("SOURCE_SCOPE_DISCOVERY_MISMATCH")
	}
	return nil
}

func sourceDiscoveryIdentityInput(scope map[string]any) (map[string]any, error) {
	config := object(scope["scope_config"])
	identity := map[string]any{}
	switch stringValue(scope["source_type"]) {
	case "FOLDER":
		identity["root_alias"] = config["root_alias"]
		identity["relative_root"] = config["relative_root"]
	case "GIT":
		identity["repository_id"] = config["repository_id"]
		identity["branch_name"] = config["branch_name"]
	case "MAIL":
		identity["mailbox_id"] = config["mailbox_id"]
		identity["folder_or_label_ids"] = config["folder_or_label_ids"]
	case "SITE":
		identity["seed_urls"] = config["seed_urls"]
		identity["sitemap_url"] = config["sitemap_url"]
		identity["allowed_url_prefixes"] = config["allowed_url_prefixes"]
	default:
		return nil, fail("SOURCE_SCOPE_TYPE_UNKNOWN")
	}
	return map[string]any{
		"connection_id":       scope["connection_id"],
		"connection_revision": scope["connection_revision"],
		"source_type":         scope["source_type"],
		"identity":            identity,
	}, nil
}

func validateSourceConnectionTrust(scope, context, connection map[string]any) (map[string]any, error) {
	capabilityID := stringValue(connection["capability_profile_id"])
	capabilities := object(object(context["capability_profiles"])[capabilityID])
	if capabilities == nil {
		return nil, fail("SOURCE_SCOPE_CAPABILITY_BUILD_MISMATCH")
	}
	if err := assertAllowedFields(capabilities, []string{
		"connector_type", "connector_build_id", "connector_version", "connector_artifact_hash", "stable_object_ids", "item_level_acl", "acl_refresh",
	}); err != nil {
		return nil, fail("SOURCE_SCOPE_CAPABILITY_BUILD_MISMATCH")
	}
	capabilityHash, err := hashCanonical(capabilities)
	if err != nil {
		return nil, err
	}
	if stringValue(connection["source_type"]) != stringValue(capabilities["connector_type"]) ||
		stringValue(connection["connector_build_id"]) != stringValue(capabilities["connector_build_id"]) ||
		stringValue(connection["connector_version"]) != stringValue(capabilities["connector_version"]) ||
		stringValue(connection["connector_artifact_hash"]) != stringValue(capabilities["connector_artifact_hash"]) ||
		stringValue(connection["capability_profile_hash"]) != capabilityHash {
		return nil, fail("SOURCE_SCOPE_CAPABILITY_BUILD_MISMATCH")
	}
	trust := object(object(context["connector_trust_records"])[stringValue(connection["connector_trust_record_id"])])
	if err := assertAllowedFields(trust, []string{
		"trust_record_id", "organization_id", "connection_id", "connection_revision", "connector_type", "connector_build_id", "connector_version",
		"connector_artifact_hash", "capability_profile_id", "capability_profile_hash", "trust_profile_hash", "contract_suite_hash", "platform", "verified_at", "status",
	}); err != nil {
		return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
	}
	trustProfileHash, hashErr := hashCanonical(sourceConnectionTrustProfileInput(connection))
	if hashErr != nil {
		return nil, hashErr
	}
	sourceType := stringValue(connection["source_type"])
	platform := stringValue(connection["platform"])
	if sourceType == "FOLDER" {
		if platform != "WINDOWS" && platform != "POSIX" && platform != "S3_COMPATIBLE" {
			return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
		}
		if stringValue(trust["platform"]) != platform {
			return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
		}
	} else if connection["platform"] != nil || trust["platform"] != nil {
		return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
	}
	if trust == nil || stringValue(trust["status"]) != "VERIFIED" || stringValue(connection["connector_trust_status"]) != "VERIFIED" ||
		stringValue(trust["trust_record_id"]) != stringValue(connection["connector_trust_record_id"]) ||
		stringValue(trust["organization_id"]) != stringValue(context["organization_id"]) || stringValue(trust["connection_id"]) != stringValue(scope["connection_id"]) ||
		intValue(trust["connection_revision"]) != intValue(scope["connection_revision"]) || stringValue(trust["connector_type"]) != stringValue(scope["source_type"]) ||
		stringValue(trust["connector_type"]) != stringValue(capabilities["connector_type"]) || stringValue(trust["connector_build_id"]) != stringValue(connection["connector_build_id"]) ||
		stringValue(trust["connector_build_id"]) != stringValue(capabilities["connector_build_id"]) || stringValue(trust["connector_version"]) != stringValue(connection["connector_version"]) ||
		stringValue(trust["connector_artifact_hash"]) != stringValue(connection["connector_artifact_hash"]) || stringValue(trust["capability_profile_id"]) != capabilityID ||
		stringValue(trust["capability_profile_hash"]) != capabilityHash ||
		stringValue(connection["trust_profile_hash"]) != trustProfileHash || stringValue(trust["trust_profile_hash"]) != trustProfileHash ||
		stringValue(trust["contract_suite_hash"]) != stringValue(connection["contract_suite_hash"]) || stringValue(trust["verified_at"]) != stringValue(connection["connector_trust_verified_at"]) {
		return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
	}
	verifiedAt, verifiedErr := time.Parse(time.RFC3339, stringValue(trust["verified_at"]))
	createdAt, createdErr := time.Parse(time.RFC3339, stringValue(scope["created_at"]))
	if verifiedErr != nil || createdErr != nil || verifiedAt.After(createdAt) || !boolValue(capabilities["stable_object_ids"]) {
		return nil, fail("SOURCE_SCOPE_CONNECTOR_TRUST_MISMATCH")
	}
	return capabilities, nil
}

func sourceConnectionTrustProfileInput(connection map[string]any) map[string]any {
	profile := map[string]any{
		"connector_type": connection["source_type"], "connector_build_id": connection["connector_build_id"],
		"connector_version": connection["connector_version"], "connector_artifact_hash": connection["connector_artifact_hash"],
		"capability_profile_id": connection["capability_profile_id"], "capability_profile_hash": connection["capability_profile_hash"],
		"contract_suite_hash": connection["contract_suite_hash"], "allowed_access_modes": connection["allowed_access_modes"],
	}
	if stringValue(connection["source_type"]) == "FOLDER" {
		profile["platform"] = connection["platform"]
	}
	return profile
}

func validateFolderScope(config, connection map[string]any) error {
	if err := assertAllowedFields(config, []string{
		"root_alias", "relative_root", "path_matcher_version", "recursive", "include_globs", "exclude_globs", "max_file_bytes",
		"ocr_mode", "follow_symlinks", "formats",
	}); err != nil {
		return err
	}
	if stringValue(config["root_alias"]) != stringValue(connection["root_alias"]) || boolValue(config["follow_symlinks"]) {
		return fail("FOLDER_SCOPE_ROOT_INVALID")
	}
	if stringValue(config["path_matcher_version"]) != "scope-glob-v1" {
		return fail("SOURCE_SCOPE_GLOB_VERSION_INVALID")
	}
	platform := stringValue(connection["platform"])
	if err := validateScopePath(stringValue(config["relative_root"]), true, platform); err != nil {
		return err
	}
	if _, err := compileScopeGlobs(array(config["include_globs"]), array(config["exclude_globs"]), platform); err != nil {
		return err
	}
	return nil
}

func validateScopePath(value string, allowEmpty bool, platform string) error {
	if value == "" && allowEmpty {
		return nil
	}
	if value != norm.NFC.String(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return fail("SOURCE_SCOPE_PATH_ESCAPE")
	}
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return fail("SOURCE_SCOPE_PATH_ESCAPE")
		}
	}
	segments := strings.Split(value, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return fail("SOURCE_SCOPE_PATH_ESCAPE")
		}
		if platform == "WINDOWS" {
			if strings.Contains(segment, ":") || strings.TrimRight(segment, ". ") != segment {
				return fail("SOURCE_SCOPE_WINDOWS_PATH_INVALID")
			}
			base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
			if windowsDeviceName.MatchString(base) {
				return fail("SOURCE_SCOPE_WINDOWS_PATH_INVALID")
			}
		}
	}
	return nil
}

func validateGitScope(config, connection map[string]any) error {
	if err := assertAllowedFields(config, []string{
		"repository_id", "branch_name", "path_matcher_version", "include_paths", "exclude_paths", "max_blob_bytes",
		"text_media_types", "submodules", "lfs_content",
	}); err != nil {
		return err
	}
	if !stringSet(array(connection["repository_ids"]))[stringValue(config["repository_id"])] {
		return fail("GIT_REPOSITORY_NOT_DISCOVERED")
	}
	if stringValue(config["path_matcher_version"]) != "scope-glob-v1" {
		return fail("SOURCE_SCOPE_GLOB_VERSION_INVALID")
	}
	branch := stringValue(config["branch_name"])
	if branch == "HEAD" || strings.HasPrefix(branch, "-") || strings.HasPrefix(branch, "refs/") || rawGitSHA.MatchString(branch) ||
		strings.ContainsAny(branch, "~^:*?[]\\ ") || strings.Contains(branch, "..") || strings.Contains(branch, "@{") {
		return fail("GIT_REF_EXPRESSION_INVALID")
	}
	if !stringSet(array(connection["discovered_branches"]))[branch] {
		return fail("GIT_BRANCH_NOT_DISCOVERED")
	}
	if boolValue(config["submodules"]) || boolValue(config["lfs_content"]) {
		return fail("GIT_SCOPE_ACTIVE_CONTENT_FORBIDDEN")
	}
	if _, err := compileScopeGlobs(array(config["include_paths"]), array(config["exclude_paths"]), "POSIX"); err != nil {
		return err
	}
	return nil
}

func compileScopeGlobs(rawIncludes, rawExcludes []any, platform string) (*scopeglob.Matcher, error) {
	includes := make([]string, len(rawIncludes))
	for index, value := range rawIncludes {
		includes[index] = stringValue(value)
	}
	excludes := make([]string, len(rawExcludes))
	for index, value := range rawExcludes {
		excludes[index] = stringValue(value)
	}
	var mode scopeglob.CaseMode
	switch platform {
	case "WINDOWS":
		mode = scopeglob.CaseWindows
	case "POSIX", "S3_COMPATIBLE":
		mode = scopeglob.CaseSensitive
	default:
		return nil, fail("SOURCE_SCOPE_GLOB_INVALID")
	}
	matcher, err := scopeglob.Compile(includes, excludes, mode)
	if err != nil {
		return nil, fail("SOURCE_SCOPE_GLOB_INVALID")
	}
	return matcher, nil
}

func matchScopeGlobs(rawIncludes, rawExcludes []any, pathValue, platform string) (bool, error) {
	matcher, err := compileScopeGlobs(rawIncludes, rawExcludes, platform)
	if err != nil {
		return false, err
	}
	matched, err := matcher.Match(pathValue)
	if err != nil {
		return false, fail("SOURCE_SCOPE_GLOB_INVALID")
	}
	return matched, nil
}

func validateMailScope(config, connection map[string]any) error {
	if err := assertAllowedFields(config, []string{
		"mailbox_id", "folder_or_label_ids", "from_date", "include_attachments", "max_message_bytes",
		"max_attachment_bytes", "body_preference",
	}); err != nil {
		return err
	}
	if !stringSet(array(connection["mailbox_ids"]))[stringValue(config["mailbox_id"])] {
		return fail("MAILBOX_NOT_DISCOVERED")
	}
	allowedFolders := stringSet(array(connection["folder_or_label_ids"]))
	for _, rawFolder := range array(config["folder_or_label_ids"]) {
		if !allowedFolders[stringValue(rawFolder)] {
			return fail("MAIL_FOLDER_NOT_DISCOVERED")
		}
	}
	return nil
}

func validateSiteScope(config, connection map[string]any) error {
	if err := assertAllowedFields(config, []string{
		"seed_urls", "sitemap_url", "allowed_url_prefixes", "path_matcher_version", "include_patterns", "exclude_patterns", "max_depth",
		"max_response_bytes", "requests_per_second", "max_redirects", "query_policy", "respect_robots_txt", "render_mode",
	}); err != nil {
		return err
	}
	if !boolValue(config["respect_robots_txt"]) {
		return fail("SITE_ROBOTS_REQUIRED")
	}
	if stringValue(config["path_matcher_version"]) != "scope-glob-v1" {
		return fail("SOURCE_SCOPE_GLOB_VERSION_INVALID")
	}
	if _, err := compileScopeGlobs(array(config["include_patterns"]), array(config["exclude_patterns"]), "POSIX"); err != nil {
		return err
	}
	prefixes := make([]*url.URL, 0)
	allowedOrigins := stringSet(array(connection["origin_allowlist"]))
	for _, rawPrefix := range array(config["allowed_url_prefixes"]) {
		prefixText := stringValue(rawPrefix)
		prefix, err := canonicalScopeURL(prefixText)
		if err != nil || prefix.RawQuery != "" || !allowedOrigins[urlOrigin(prefix)] {
			return fail("SITE_PREFIX_INVALID")
		}
		prefixes = append(prefixes, prefix)
	}
	checkTarget := func(targetText string) error {
		target, err := canonicalScopeURL(targetText)
		if err != nil {
			return err
		}
		for _, prefix := range prefixes {
			if urlWithinPrefix(target, prefix) {
				return nil
			}
		}
		return fail("SITE_PREFIX_BOUNDARY_INVALID")
	}
	for _, rawSeed := range array(config["seed_urls"]) {
		if err := checkTarget(stringValue(rawSeed)); err != nil {
			return err
		}
	}
	if config["sitemap_url"] != nil {
		if err := checkTarget(stringValue(config["sitemap_url"])); err != nil {
			return err
		}
	}
	return nil
}

func validateScopeGlobGolden(value map[string]any) error {
	for _, rawVector := range array(value["vectors"]) {
		vector := object(rawVector)
		matched, err := matchScopeGlobs([]any{vector["pattern"]}, nil, stringValue(vector["path"]), stringValue(vector["platform"]))
		if err != nil {
			return fail("SOURCE_SCOPE_GLOB_GOLDEN_INVALID", stringValue(vector["id"]))
		}
		if matched != boolValue(vector["expected_match"]) {
			return fail("SOURCE_SCOPE_GLOB_GOLDEN_MISMATCH", stringValue(vector["id"]))
		}
	}
	for _, rawVector := range array(value["allow_vectors"]) {
		vector := object(rawVector)
		includes := array(vector["includes"])
		excludes := array(vector["excludes"])
		pathValue := stringValue(vector["path"])
		platform := stringValue(vector["platform"])
		allowed, err := matchScopeGlobs(includes, excludes, pathValue, platform)
		if err != nil {
			return err
		}
		if allowed != boolValue(vector["expected_allowed"]) {
			return fail("SOURCE_SCOPE_GLOB_PRECEDENCE_MISMATCH", stringValue(vector["id"]))
		}
	}
	return nil
}

func sourceByteCapFields(sourceType string) []string {
	switch sourceType {
	case "FOLDER":
		return []string{"max_file_bytes"}
	case "GIT":
		return []string{"max_blob_bytes"}
	case "MAIL":
		return []string{"max_message_bytes", "max_attachment_bytes"}
	case "SITE":
		return []string{"max_response_bytes"}
	default:
		return nil
	}
}

func canonicalScopeURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || hasEncodedSeparator(parsed.EscapedPath()) {
		return nil, fail("SITE_ENCODED_SEPARATOR_FORBIDDEN")
	}
	canonical, err := canonicalWebURL(raw)
	if err != nil || canonical != raw {
		return nil, fail("SITE_URL_NOT_CANONICAL")
	}
	return url.Parse(canonical)
}

func hasEncodedSeparator(rawPath string) bool {
	current := rawPath
	for attempt := 0; attempt < 3; attempt++ {
		lower := strings.ToLower(current)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return true
		}
		decoded, err := url.PathUnescape(current)
		if err != nil || decoded == current {
			break
		}
		current = decoded
	}
	return false
}

func urlOrigin(parsed *url.URL) string {
	return parsed.Scheme + "://" + parsed.Host
}

func urlWithinPrefix(target, prefix *url.URL) bool {
	if urlOrigin(target) != urlOrigin(prefix) {
		return false
	}
	targetPath := strings.TrimSuffix(target.EscapedPath(), "/")
	prefixPath := strings.TrimSuffix(prefix.EscapedPath(), "/")
	if prefixPath == "" {
		prefixPath = "/"
	}
	if targetPath == prefixPath {
		return true
	}
	if prefixPath == "/" {
		return strings.HasPrefix(targetPath, "/")
	}
	return strings.HasPrefix(targetPath, prefixPath+"/")
}

func validateTornReadScenario(value map[string]any) error {
	before := object(value["before_read"])
	after := object(value["after_read"])
	stable := stringValue(before["source_object_identity"]) == stringValue(after["source_object_identity"]) &&
		stringValue(before["external_version_key"]) == stringValue(after["external_version_key"]) &&
		intValue(before["size_bytes"]) == intValue(after["size_bytes"])
	commit := object(value["commit_attempt"])
	if !stable && (boolValue(commit["source_version_created"]) || boolValue(commit["evidence_indexed"])) {
		return fail("TORN_READ_VERSION_MISMATCH")
	}
	if !stable && stringValue(commit["outcome"]) != "QUARANTINED_TORN_READ" {
		return fail("TORN_READ_NOT_QUARANTINED")
	}
	return nil
}
