package git

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testGitBlobSHA(value []byte) string {
	hash := sha1.New()
	_, _ = hash.Write([]byte("blob " + strconvItoa(len(value)) + "\x00"))
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func strconvItoa(value int) string {
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

func TestGitHubObserveUsesOneCommitAndVerifiesBlobIdentity(t *testing.T) {
	content := []byte("package demo\n")
	blob := testGitBlobSHA(content)
	commit := strings.Repeat("a", 40)
	seenAuth := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("authorization header was not bound to the connector")
		}
		seenAuth = true
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/acme/repo/git/ref/heads/main":
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`))
		case request.URL.Path == "/repos/acme/repo/git/trees/"+commit:
			_, _ = writer.Write([]byte(`{"truncated":false,"tree":[{"path":"docs/readme.md","type":"blob","sha":"` + blob + `","size":` + strconvItoa(len(content)) + `},{"path":"bin/data.bin","type":"blob","sha":"` + strings.Repeat("b", 40) + `","size":4}]}`))
		case request.URL.Path == "/repos/acme/repo/git/blobs/"+blob:
			encoded, _ := json.Marshal(map[string]string{"content": "cGFja2FnZSBkZW1vCg==", "encoding": "base64", "sha": blob})
			_, _ = writer.Write(encoded)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	connector, err := New(Config{
		Provider: ProviderGitHub, Endpoint: server.URL, RepositoryID: "acme/repo", BranchName: "main",
		IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1 << 20,
		TextMediaTypes: []string{"text/markdown"}, AccessToken: "test-token", HTTPClient: client,
	})
	if err != nil {
		t.Fatalf("construct connector: %v", err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if !seenAuth || !page.CoverageComplete || page.CommitSHA != commit || len(page.Objects) != 1 || len(page.Quarantined) != 0 {
		t.Fatalf("unexpected page: %+v auth=%v", page, seenAuth)
	}
	object := page.Objects[0]
	if object.Path != "docs/readme.md" || object.BlobID != blob || string(object.Content) != string(content) || object.NativeVersionKey != "commit:"+commit+";blob:"+blob {
		t.Fatalf("unexpected object: %+v", object)
	}
	if !strings.HasPrefix(page.SnapshotHash, "sha256:") {
		t.Fatalf("snapshot hash missing: %q", page.SnapshotHash)
	}
	link, err := connector.DeepLink(commit, object.Path)
	if err != nil || !strings.Contains(link, "/acme/repo/blob/"+commit+"/docs/readme.md") {
		t.Fatalf("deeplink=%q err=%v", link, err)
	}
}

func TestGitObserveQuarantinesUnsupportedAndOversizedBlobsWithoutFabricatingDeletion(t *testing.T) {
	commit := strings.Repeat("c", 40)
	valid := []byte("ok")
	validSHA := testGitBlobSHA(valid)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/acme/repo/git/ref/heads/main":
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`))
		case request.URL.Path == "/repos/acme/repo/git/trees/"+commit:
			_, _ = writer.Write([]byte(`{"truncated":false,"tree":[{"path":"notes.txt","type":"blob","sha":"` + validSHA + `","size":2},{"path":"archive.zip","type":"blob","sha":"` + strings.Repeat("d", 40) + `","size":999}]}`))
		case request.URL.Path == "/repos/acme/repo/git/blobs/"+validSHA:
			_, _ = writer.Write([]byte(`{"content":"b2s=","encoding":"base64","sha":"` + validSHA + `"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	connector, err := New(Config{Provider: ProviderGitHub, Endpoint: server.URL, RepositoryID: "acme/repo", BranchName: "main", MaxBlobBytes: 4,
		IncludeGlobs: []string{"**/*"}, TextMediaTypes: []string{"text/plain"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(page.Objects) != 1 || page.Objects[0].Path != "notes.txt" || len(page.Quarantined) != 1 || page.Quarantined[0].Code != QuarantineUnsupportedType {
		t.Fatalf("quarantine/page=%+v", page)
	}
}

func TestGitDeepLinkUsesRepositoryWebOrigin(t *testing.T) {
	commit := strings.Repeat("f", 40)
	for name, config := range map[string]Config{
		"github api":   {Provider: ProviderGitHub, Endpoint: "https://api.github.com", RepositoryID: "acme/repo", BranchName: "main", IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1, TextMediaTypes: []string{"text/markdown"}, AccessToken: "token", HTTPClient: &http.Client{Timeout: 5 * time.Second}},
		"gitlab api":   {Provider: ProviderGitLab, Endpoint: "https://gitlab.example/api/v4", RepositoryID: "group/project", BranchName: "main", IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1, TextMediaTypes: []string{"text/markdown"}, AccessToken: "token", HTTPClient: &http.Client{Timeout: 5 * time.Second}},
		"explicit web": {Provider: ProviderGitHub, Endpoint: "https://api.github.example/api/v3", WebBaseURL: "https://code.example/forge", RepositoryID: "acme/repo", BranchName: "main", IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1, TextMediaTypes: []string{"text/markdown"}, AccessToken: "token", HTTPClient: &http.Client{Timeout: 5 * time.Second}},
	} {
		t.Run(name, func(t *testing.T) {
			connector, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			link, err := connector.DeepLink(commit, "docs/readme.md")
			if err != nil {
				t.Fatalf("deeplink: %v", err)
			}
			if !strings.Contains(link, "/"+config.RepositoryID+"/") || !strings.Contains(link, commit) {
				t.Fatalf("link=%q", link)
			}
			switch name {
			case "github api":
				if !strings.HasPrefix(link, "https://github.com/") {
					t.Fatalf("github link=%q", link)
				}
			case "gitlab api":
				if !strings.HasPrefix(link, "https://gitlab.example/") || strings.Contains(link, "/api/v4/") {
					t.Fatalf("gitlab link=%q", link)
				}
			case "explicit web":
				if !strings.HasPrefix(link, "https://code.example/forge/") {
					t.Fatalf("explicit link=%q", link)
				}
			}
		})
	}
}

func TestGitObserveQuarantinesProviderBlobMismatch(t *testing.T) {
	commit := strings.Repeat("1", 40)
	content := []byte("trusted\n")
	entrySHA := testGitBlobSHA(content)
	wrongContent := []byte("tampered\n")
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/acme/repo/git/ref/heads/main":
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`))
		case request.URL.Path == "/repos/acme/repo/git/trees/"+commit:
			_, _ = writer.Write([]byte(`{"truncated":false,"tree":[{"path":"docs/readme.md","type":"blob","sha":"` + entrySHA + `","size":` + strconvItoa(len(content)) + `}]}`))
		case request.URL.Path == "/repos/acme/repo/git/blobs/"+entrySHA:
			_, _ = writer.Write([]byte(`{"content":"` + base64.StdEncoding.EncodeToString(wrongContent) + `","encoding":"base64","sha":"` + entrySHA + `"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	connector, err := New(Config{Provider: ProviderGitHub, Endpoint: server.URL, RepositoryID: "acme/repo", BranchName: "main",
		IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1 << 20, TextMediaTypes: []string{"text/markdown"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(page.Objects) != 0 || len(page.Quarantined) != 1 || page.Quarantined[0].Code != QuarantineBlobMismatch || !page.CoverageComplete {
		t.Fatalf("mismatch was not quarantined: %+v", page)
	}
}

func TestGitObservePreservesPartialTreeState(t *testing.T) {
	commit := strings.Repeat("2", 40)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/acme/repo/git/ref/heads/main":
			_, _ = writer.Write([]byte(`{"object":{"sha":"` + commit + `","type":"commit"}}`))
		case request.URL.Path == "/repos/acme/repo/git/trees/"+commit:
			_, _ = writer.Write([]byte(`{"truncated":true,"tree":[]}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	connector, err := New(Config{Provider: ProviderGitHub, Endpoint: server.URL, RepositoryID: "acme/repo", BranchName: "main",
		IncludeGlobs: []string{"**/*.md"}, MaxBlobBytes: 1, TextMediaTypes: []string{"text/markdown"}, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if page.CoverageComplete || page.SnapshotHash == "" {
		t.Fatalf("truncated tree was treated as complete: %+v", page)
	}
}

func TestGitConfigRejectsUnsafeBranchAndInsecureEndpoint(t *testing.T) {
	base := Config{Provider: ProviderGitHub, Endpoint: "https://git.example", RepositoryID: "acme/repo", BranchName: "main", MaxBlobBytes: 1, TextMediaTypes: []string{"text/plain"}, AccessToken: "x"}
	for name, mutate := range map[string]func(*Config){
		"insecure endpoint":   func(value *Config) { value.Endpoint = "http://git.example" },
		"arbitrary ref":       func(value *Config) { value.BranchName = "refs/heads/main" },
		"revision expression": func(value *Config) { value.BranchName = "main~1" },
		"wildcard":            func(value *Config) { value.BranchName = "feature/*" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := New(value); CodeOf(err) != CodeInvalid {
				t.Fatalf("unsafe config code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestMountObserveReadsCheckedOutTreeAndAppliesScope(t *testing.T) {
	base := t.TempDir()
	mount := filepath.Join(base, "demo-git", "knowvault")
	if err := os.MkdirAll(filepath.Join(mount, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeMountFile(t, mount, "docs/readme.md", "trust verification lives in internal/workspace/repository/trust_verify.go\n")
	writeMountFile(t, mount, "docs/notes.bin", "\x00\x01binary")
	writeMountFile(t, mount, "vendor/skip.md", "excluded by scope\n")
	writeMountFile(t, mount, ".knowvault-commit", strings.Repeat("c", 40)+"\n")
	oversized := make([]byte, 4096)
	for index := range oversized {
		oversized[index] = 'a'
	}
	writeMountFile(t, mount, "docs/big.md", string(oversized))

	connector, err := New(Config{
		Provider: ProviderMount, Endpoint: "demo-git/knowvault", RepositoryID: "acme/knowvault", BranchName: "main",
		IncludeGlobs: []string{"**/*.md"}, ExcludeGlobs: []string{"vendor/**"}, MaxBlobBytes: 1024,
		TextMediaTypes: []string{"text/markdown"}, MountRootOverride: base,
	})
	if err != nil {
		t.Fatalf("construct mount connector: %v", err)
	}
	defer connector.Close()

	page, err := connector.Observe(context.Background(), ObserveRequest{MaxObjects: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if page.CommitSHA != strings.Repeat("c", 40) || !page.CoverageComplete {
		t.Fatalf("unexpected page metadata: %+v", page)
	}
	if len(page.Objects) != 1 || page.Objects[0].Path != "docs/readme.md" {
		t.Fatalf("unexpected objects: %+v", page.Objects)
	}
	if !strings.Contains(string(page.Objects[0].Content), "trust_verify.go") {
		t.Fatalf("unexpected content: %q", page.Objects[0].Content)
	}
	if page.Objects[0].NativeVersionKey == "" || !strings.HasPrefix(page.Objects[0].NativeVersionKey, "mount:content:") {
		t.Fatalf("unexpected native version key: %q", page.Objects[0].NativeVersionKey)
	}
	quarantineCodes := map[string]QuarantineCode{}
	for _, quarantine := range page.Quarantined {
		quarantineCodes[quarantine.Path] = quarantine.Code
	}
	if quarantineCodes["docs/big.md"] != QuarantineOversized {
		t.Fatalf("expected oversized quarantine, got %+v", page.Quarantined)
	}
	if _, sawVendor := quarantineCodes["vendor/skip.md"]; sawVendor {
		t.Fatalf("excluded path should never surface, got %+v", page.Quarantined)
	}
	if _, sawBinary := quarantineCodes["docs/notes.bin"]; sawBinary {
		t.Fatalf("unmatched-glob path should never surface, got %+v", page.Quarantined)
	}

	if _, err := connector.DeepLink(strings.Repeat("c", 40), "docs/readme.md"); CodeOf(err) != CodeInvalid {
		t.Fatalf("expected mount DeepLink to be unsupported, got %v", err)
	}
}

func TestMountConfigRejectsTraversalAndAbsoluteEndpoint(t *testing.T) {
	base := Config{Provider: ProviderMount, RepositoryID: "acme/knowvault", BranchName: "main",
		IncludeGlobs: []string{"**/*"}, MaxBlobBytes: 16, TextMediaTypes: []string{"text/plain"}, MountRootOverride: t.TempDir()}
	for name, endpoint := range map[string]string{
		"traversal":       "../etc",
		"absolute":        "/etc/passwd",
		"empty":           "",
		"embedded dotdot": "demo-git/../../etc",
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Endpoint = endpoint
			if _, err := New(value); CodeOf(err) != CodeInvalid {
				t.Fatalf("unsafe mount endpoint %q code=%q err=%v", endpoint, CodeOf(err), err)
			}
		})
	}
}

func TestMediaTypeForPathCoversV1SourceExtensions(t *testing.T) {
	cases := map[string]string{
		"main.go": "text/x-go", "lib.rs": "text/x-rust", "App.java": "text/x-java-source",
		"script.py": "text/x-python", "Main.kt": "text/x-kotlin", "query.sql": "text/x-sql",
		"config.yaml": "text/x-yaml", "config.yml": "text/x-yaml", "settings.toml": "text/x-toml",
		"service.proto": "text/x-protobuf", "deploy.sh": "text/x-sh", "Program.cs": "text/x-csharp",
		"index.php": "text/x-php", "app.rb": "text/x-ruby", "component.tsx": "application/javascript",
		"readme.md": "text/markdown", "notes.txt": "text/plain",
	}
	for path, want := range cases {
		if got := mediaTypeForPath(path); got != want {
			t.Fatalf("mediaTypeForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func writeMountFile(t *testing.T, root, relative, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %q: %v", relative, err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", relative, err)
	}
}
