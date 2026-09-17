package registration

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestRemoteGitRegistrationValidation(t *testing.T) {
	request := RegisterRequest{SourceType: "GIT", Name: "Engineering", Kind: "code",
		Provider: "GITHUB", Endpoint: "https://api.github.com", WebBaseURL: "https://github.com",
		RepositoryID: "acme/knowledge", BranchName: "main", IncludeGlobs: []string{"src/**"},
		ExcludeGlobs: []string{"vendor/**"}, TextMediaTypes: []string{"text/plain", "application/json"}, MaxBlobBytes: 1 << 20}
	if err := request.validateRemote(); err != nil {
		t.Fatalf("valid Git registration rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RegisterRequest){
		"http endpoint":     func(value *RegisterRequest) { value.Endpoint = "http://api.github.com" },
		"branch expression": func(value *RegisterRequest) { value.BranchName = "refs/heads/main" },
		"raw token":         func(value *RegisterRequest) { value.CredentialReference = "token-value" },
		"unknown media":     func(value *RegisterRequest) { value.TextMediaTypes = []string{"application/octet-stream"} },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			copy := request
			mutate(&copy)
			if err := copy.validateRemote(); CodeOf(err) != CodeRequestInvalid {
				t.Fatalf("validation code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestRemoteGitMountRegistrationValidation(t *testing.T) {
	request := RegisterRequest{SourceType: "GIT", Name: "Engineering", Kind: "code",
		Provider: "MOUNT", Endpoint: "demo-git/knowvault",
		RepositoryID: "acme/knowledge", BranchName: "main", IncludeGlobs: []string{"**/*.go", "**/*.md"},
		ExcludeGlobs: []string{"vendor/**"}, TextMediaTypes: []string{"text/x-go", "text/markdown"}, MaxBlobBytes: 1 << 20}
	if err := request.validateRemote(); err != nil {
		t.Fatalf("valid mount Git registration rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RegisterRequest){
		"absolute endpoint":   func(value *RegisterRequest) { value.Endpoint = "/etc/passwd" },
		"traversal endpoint":  func(value *RegisterRequest) { value.Endpoint = "../secrets" },
		"web base url set":    func(value *RegisterRequest) { value.WebBaseURL = "https://github.com" },
		"branch expression":   func(value *RegisterRequest) { value.BranchName = "refs/heads/main" },
		"raw token reference": func(value *RegisterRequest) { value.CredentialReference = "token-value" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			copy := request
			mutate(&copy)
			if err := copy.validateRemote(); CodeOf(err) != CodeRequestInvalid {
				t.Fatalf("validation code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestRemoteMailRegistrationValidation(t *testing.T) {
	since := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	request := RegisterRequest{SourceType: "MAIL", Name: "Operations mail", Kind: "mail",
		Provider: "IMAP", Endpoint: "imap.example.test:993", Mailbox: "tenant-a", Folder: "INBOX",
		Username: "reader@example.test", Since: &since, IncludeAttachments: true,
		MaxMessageBytes: 8 << 20, MaxAttachmentBytes: 4 << 20, AttachmentMediaTypes: []string{"text/plain", "application/pdf"}}
	if err := request.validateRemote(); err != nil {
		t.Fatalf("valid IMAP registration rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RegisterRequest){
		"missing port":                 func(value *RegisterRequest) { value.Endpoint = "imap.example.test" },
		"attachment without allowlist": func(value *RegisterRequest) { value.AttachmentMediaTypes = nil },
		"oversized attachment":         func(value *RegisterRequest) { value.MaxAttachmentBytes = 64 << 20 },
		"control mailbox":              func(value *RegisterRequest) { value.Mailbox = "tenant\n-a" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			copy := request
			mutate(&copy)
			if err := copy.validateRemote(); CodeOf(err) != CodeRequestInvalid {
				t.Fatalf("validation code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestRemoteRegistrationIDsAndCanonicalProjectionsAreDeterministic(t *testing.T) {
	first := remoteConnectionID("org_a", "GIT", "https://api.github.com", "GITHUB", "acme/repo", "")
	second := remoteConnectionID("org_a", "GIT", "https://api.github.com", "GITHUB", "acme/repo", "")
	if first != second {
		t.Fatalf("connection id is not deterministic: %q/%q", first, second)
	}
	identity, err := canon.GitScopeIdentityBytes(first, "GITHUB", "acme/repo", "main")
	if err != nil {
		t.Fatal(err)
	}
	identityAgain, err := canon.GitScopeIdentityBytes(first, "GITHUB", "acme/repo", "main")
	if err != nil || string(identity) != string(identityAgain) {
		t.Fatalf("identity projection is not deterministic: %v", err)
	}
	if remoteDiscoveredScopeID("org_a", first, "GIT", canon.Hash(identity)) == remoteDiscoveredScopeID("org_b", first, "GIT", canon.Hash(identity)) {
		t.Fatal("remote discovered scope crossed organization boundary")
	}
}
