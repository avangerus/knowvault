package observation

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/connector/git"
)

func observationGitBlobSHA(value []byte) string {
	hash := sha1.New()
	_, _ = hash.Write([]byte("blob " + itoa(len(value)) + "\x00"))
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func TestGitAdapterBindsNativeSnapshotToObservationContract(t *testing.T) {
	content := []byte("# source-agnostic\n")
	blob := observationGitBlobSHA(content)
	commit := strings.Repeat("e", 40)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/acme/repo/git/ref/heads/main":
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`))
		case request.URL.Path == "/repos/acme/repo/git/trees/"+commit:
			_, _ = writer.Write([]byte(`{"truncated":false,"tree":[{"path":"docs/meaning.md","type":"blob","sha":"` + blob + `","size":` + itoa(len(content)) + `}]}`))
		case request.URL.Path == "/repos/acme/repo/git/blobs/"+blob:
			_, _ = writer.Write([]byte(`{"content":"` + base64.StdEncoding.EncodeToString(content) + `","encoding":"base64","sha":"` + blob + `"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	connector, err := git.New(git.Config{Provider: git.ProviderGitHub, Endpoint: server.URL,
		RepositoryID: "acme/repo", BranchName: "main", IncludeGlobs: []string{"**/*.md"},
		MaxBlobBytes: 1 << 20, TextMediaTypes: []string{"text/markdown"}, HTTPClient: client})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	adapter, err := NewGitAdapter(connector, "org_demo", "scope_git", 3)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	page, err := adapter.Observe(context.Background(), Request{OrganizationID: "org_demo", SourceScopeID: "scope_git", SourceScopeRevision: 3, MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !page.CoverageComplete || len(page.Objects) != 1 || page.Objects[0].Kind != KindGit || page.Objects[0].ObjectType != "GIT_FILE" {
		t.Fatalf("unexpected page: %+v", page)
	}
	object := page.Objects[0]
	if object.ExternalID != "docs/meaning.md" || object.VersionKey != "native:commit:"+commit+";blob:"+blob || object.Document == nil || string(object.Document.Bytes) != string(content) || object.Document.MediaFamily != "TEXT" {
		t.Fatalf("unexpected object: %+v", object)
	}
}

func TestGitAdapterRejectsCallerScopeMismatch(t *testing.T) {
	connector, err := git.New(git.Config{Provider: git.ProviderGitHub, Endpoint: "https://git.example",
		RepositoryID: "acme/repo", BranchName: "main", IncludeGlobs: []string{"**/*.md"},
		MaxBlobBytes: 1, TextMediaTypes: []string{"text/markdown"}, AccessToken: "token",
		HTTPClient: &http.Client{Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	adapter, err := NewGitAdapter(connector, "org_demo", "scope_git", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Observe(context.Background(), Request{OrganizationID: "other", SourceScopeID: "scope_git", SourceScopeRevision: 1, MaxObjects: 1, MaxBytes: 1})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("mismatch code=%q err=%v", CodeOf(err), err)
	}
}
