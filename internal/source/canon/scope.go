package canon

// Source-registration plaintext forms (ADR-0074 s1.3). CANONICALIZATION.md
// deliberately does not define these shapes; the registration ADR froze them,
// and they live here next to the other canonical shapes so every producer and
// consumer derives the same bytes.

// ScopeIdentityBytes returns the canonical JCS of the discovered-scope identity:
// {"schema_version":"source-scope-identity-v1","source_type":"FOLDER","connection_id","relative_root"}.
// The stored identity_digest is HMACDigest over these exact bytes, so the
// worker re-derives and compares it against the row the registration surface
// wrote.
func ScopeIdentityBytes(connectionID, relativeRoot string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		SourceType    string `json:"source_type"`
		ConnectionID  string `json:"connection_id"`
		RelativeRoot  string `json:"relative_root"`
	}{
		SchemaVersion: "source-scope-identity-v1", SourceType: "FOLDER",
		ConnectionID: connectionID, RelativeRoot: relativeRoot,
	})
}

// ScopeDisplayBytes returns the canonical JCS of the discovered-scope display
// metadata: {"schema_version":"source-scope-display-v1","name","kind"}.
func ScopeDisplayBytes(name, kind string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		Name          string `json:"name"`
		Kind          string `json:"kind"`
	}{
		SchemaVersion: "source-scope-display-v1", Name: name, Kind: kind,
	})
}

// FolderTrustBytes returns the canonical JCS of the folder trust profile:
// {"schema_version":"source-folder-trust-v1","platform":"POSIX","root_alias","root_identity"}.
func FolderTrustBytes(rootAlias, rootIdentity string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		Platform      string `json:"platform"`
		RootAlias     string `json:"root_alias"`
		RootIdentity  string `json:"root_identity"`
	}{
		SchemaVersion: "source-folder-trust-v1", Platform: "POSIX",
		RootAlias: rootAlias, RootIdentity: rootIdentity,
	})
}

// ScopeConfigBytes returns the canonical JCS of the folder scope configuration
// of source-scope.schema.json. path_matcher_version and follow_symlinks are
// server-side constants of that schema, not caller choices; the remaining
// members are the validated request projection.
func ScopeConfigBytes(rootAlias, relativeRoot string, recursive bool,
	includeGlobs, excludeGlobs []string, maxFileBytes int64, ocrMode string, formats []string) ([]byte, error) {
	return canonicalJSON(struct {
		RootAlias          string   `json:"root_alias"`
		RelativeRoot       string   `json:"relative_root"`
		PathMatcherVersion string   `json:"path_matcher_version"`
		Recursive          bool     `json:"recursive"`
		IncludeGlobs       []string `json:"include_globs"`
		ExcludeGlobs       []string `json:"exclude_globs"`
		MaxFileBytes       int64    `json:"max_file_bytes"`
		OCRMode            string   `json:"ocr_mode"`
		FollowSymlinks     bool     `json:"follow_symlinks"`
		Formats            []string `json:"formats"`
	}{
		RootAlias: rootAlias, RelativeRoot: relativeRoot, PathMatcherVersion: "scope-glob-v1",
		Recursive: recursive, IncludeGlobs: includeGlobs, ExcludeGlobs: excludeGlobs,
		MaxFileBytes: maxFileBytes, OCRMode: ocrMode, FollowSymlinks: false, Formats: formats,
	})
}
