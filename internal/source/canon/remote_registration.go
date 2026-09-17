package canon

// Remote source registration plaintexts.  The control plane seals these
// values as owner artifacts; credentials and private key material are never
// part of any projection.  Keeping the Git and IMAP shapes here makes the
// registration and worker resolver use one JCS implementation instead of
// independently concatenating provider strings.

import "time"

// GitScopeIdentityBytes is the immutable discovered-scope identity for one
// provider repository/branch.  A branch name is the configured expression;
// the connector resolves its current commit during observation.
func GitScopeIdentityBytes(connectionID, provider, repositoryID, branchName string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		SourceType    string `json:"source_type"`
		ConnectionID  string `json:"connection_id"`
		Provider      string `json:"provider"`
		RepositoryID  string `json:"repository_id"`
		BranchName    string `json:"branch_name"`
	}{"source-git-identity-v1", "GIT", connectionID, provider, repositoryID, branchName})
}

// GitTrustBytes contains network/provider trust metadata only.  It contains
// no access token; the token remains an opaque secret-mount reference bound to
// the connection revision.
func GitTrustBytes(connectionID, provider, endpoint, webBaseURL string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		SourceType    string `json:"source_type"`
		ConnectionID  string `json:"connection_id"`
		Provider      string `json:"provider"`
		Endpoint      string `json:"endpoint"`
		WebBaseURL    string `json:"web_base_url"`
	}{"source-git-trust-v1", "GIT", connectionID, provider, endpoint, webBaseURL})
}

// GitScopeConfigBytes is the scope allowlist and bounded-read policy.  The
// provider endpoint and credential are deliberately absent: they belong to
// the connection trust/secret branches, not to path authorization.
func GitScopeConfigBytes(provider, repositoryID, branchName string, includePaths, excludePaths, textMediaTypes []string,
	maxBlobBytes int64) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion  string   `json:"schema_version"`
		SourceType     string   `json:"source_type"`
		Provider       string   `json:"provider"`
		RepositoryID   string   `json:"repository_id"`
		BranchName     string   `json:"branch_name"`
		PathMatcher    string   `json:"path_matcher_version"`
		IncludePaths   []string `json:"include_paths"`
		ExcludePaths   []string `json:"exclude_paths"`
		MaxBlobBytes   int64    `json:"max_blob_bytes"`
		TextMediaTypes []string `json:"text_media_types"`
		Submodules     bool     `json:"submodules"`
		LFSContent     bool     `json:"lfs_content"`
	}{
		SchemaVersion: "source-git-config-v1", SourceType: "GIT", Provider: provider,
		RepositoryID: repositoryID, BranchName: branchName, PathMatcher: "scope-glob-v1",
		IncludePaths: includePaths, ExcludePaths: excludePaths, MaxBlobBytes: maxBlobBytes,
		TextMediaTypes: textMediaTypes, Submodules: false, LFSContent: false,
	})
}

// MailScopeIdentityBytes is the immutable IMAP mailbox/folder identity.  A
// UID is not part of registration; UIDVALIDITY+UID enter the observation
// object's native identity and therefore survive mailbox resynchronisation.
func MailScopeIdentityBytes(connectionID, endpoint, mailbox, folder string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		SourceType    string `json:"source_type"`
		ConnectionID  string `json:"connection_id"`
		Endpoint      string `json:"endpoint"`
		Mailbox       string `json:"mailbox"`
		Folder        string `json:"folder"`
	}{"source-imap-identity-v1", "MAIL", connectionID, endpoint, mailbox, folder})
}

// MailTrustBytes contains only the TLS endpoint and login identity.  The
// password is resolved by its secret reference at worker composition time.
func MailTrustBytes(connectionID, endpoint, username string) ([]byte, error) {
	return canonicalJSON(struct {
		SchemaVersion string `json:"schema_version"`
		SourceType    string `json:"source_type"`
		ConnectionID  string `json:"connection_id"`
		Endpoint      string `json:"endpoint"`
		Username      string `json:"username"`
	}{"source-imap-trust-v1", "MAIL", connectionID, endpoint, username})
}

// MailScopeConfigBytes is the bounded IMAP observation policy.  Since is
// normalized to UTC and represented as an RFC3339 timestamp; nil means no
// lower time bound.  Raw credentials and message data never enter this value.
func MailScopeConfigBytes(endpoint, mailbox, folder string, since *time.Time, includeAttachments bool,
	maxMessageBytes, maxAttachmentBytes int64, attachmentMediaTypes []string) ([]byte, error) {
	var sinceValue *string
	if since != nil {
		value := since.UTC().Format(time.RFC3339Nano)
		sinceValue = &value
	}
	return canonicalJSON(struct {
		SchemaVersion        string   `json:"schema_version"`
		SourceType           string   `json:"source_type"`
		Endpoint             string   `json:"endpoint"`
		Mailbox              string   `json:"mailbox"`
		Folder               string   `json:"folder"`
		Since                *string  `json:"since,omitempty"`
		IncludeAttachments   bool     `json:"include_attachments"`
		MaxMessageBytes      int64    `json:"max_message_bytes"`
		MaxAttachmentBytes   int64    `json:"max_attachment_bytes"`
		AttachmentMediaTypes []string `json:"attachment_media_types"`
	}{"source-imap-config-v1", "MAIL", endpoint, mailbox, folder, sinceValue,
		includeAttachments, maxMessageBytes, maxAttachmentBytes, attachmentMediaTypes})
}
