// Package git owns the read-only Git tree connector. It resolves one trusted
// branch to one immutable commit, enumerates that commit's tree and reads
// only allowlisted text blobs. The connector has no repository-write, hook,
// credential-helper, build, database or catalog capability.
//
// Two provider families are supported. GITHUB/GITLAB speak the provider
// HTTPS APIs directly instead of shelling out to an ambient git binary; a
// deployment must still qualify the selected provider endpoint, credential
// and response contract before activating a source scope. MOUNT reads a
// pre-populated, read-only working-tree checkout from the same fixed
// worker mount root the FOLDER connector's pre-mounted roots live under
// (deploy compose binds a host directory onto it read-only); refreshing
// that checkout is deployment-owned tooling outside the worker process, so
// this provider never shells out to git, never writes to the mount and
// never resolves a live branch itself.
package git

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/source/scopeglob"
)

const (
	maximumBlobBytes     int64 = 1 << 30
	maximumResponseBytes       = 32 << 20
	maximumTreeEntries         = 1_000_000
	maximumObjects             = 10_000_000
	maximumPageSize            = 100
	maximumGitPages            = 10_000
	defaultTimeout             = 15 * time.Second
	// mountSourcesRoot is the fixed worker mount point for pre-populated
	// read-only source content. Dockerfile.worker provisions exactly this
	// path and deploy compose binds a host directory onto it read-only; it
	// is the same mount root the FOLDER connector's pre-mounted roots live
	// under. Production composition never overrides it; only a controlled
	// composition test may, through Config.MountRootOverride.
	mountSourcesRoot = "/run/knowvault/sources"
	// mountCommitFileName is an optional small file at the root of a MOUNT
	// checkout naming the exact commit it was refreshed from. Its absence
	// is not an error: the provider still serves content-hash versioned
	// objects without a commit label.
	mountCommitFileName = ".knowvault-commit"
)

// Provider identifies a supported Git access mechanism. The provider is part
// of the immutable connection revision; it cannot be selected by a question
// or connector event.
type Provider string

const (
	ProviderGitHub Provider = "GITHUB"
	ProviderGitLab Provider = "GITLAB"
	// ProviderMount reads a pre-populated, read-only mounted git
	// working-tree checkout instead of calling a hosting API. See the
	// package doc comment for its trust boundary.
	ProviderMount Provider = "MOUNT"
)

// ErrorCode is content-free so an endpoint, repository path, token or source
// bytes can never leak through a transport error or metric label.
type ErrorCode string

const (
	CodeInvalid         ErrorCode = "GIT_REQUEST_INVALID"
	CodeUnavailable     ErrorCode = "GIT_DEPENDENCY_UNAVAILABLE"
	CodeRejected        ErrorCode = "GIT_DEPENDENCY_REJECTED"
	CodeResponse        ErrorCode = "GIT_RESPONSE_INVALID"
	CodeCoveragePartial ErrorCode = "GIT_TREE_PARTIAL"
)

// QuarantineCode describes one tree entry that cannot become trusted
// Evidence. A quarantine never means that the entry was deleted.
type QuarantineCode string

const (
	QuarantineUnsupportedType QuarantineCode = "GIT_UNSUPPORTED_MEDIA_TYPE"
	QuarantineOversized       QuarantineCode = "GIT_BLOB_OVERSIZED"
	QuarantineInvalidUTF8     QuarantineCode = "GIT_INVALID_UTF8"
	QuarantineBlobMismatch    QuarantineCode = "GIT_BLOB_ID_MISMATCH"
	QuarantineReadFailed      QuarantineCode = "GIT_BLOB_READ_FAILED"
)

type Error struct {
	code   ErrorCode
	cause  error
	status int
}

func (e *Error) Error() string {
	if e == nil || e.code == "" {
		return string(CodeInvalid)
	}
	return string(e.code)
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

func (e *Error) String() string   { return "git.Error{[REDACTED]}" }
func (e *Error) GoString() string { return "git.Error{[REDACTED]}" }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) && typed != nil {
		return typed.code
	}
	return CodeRejected
}

// Config is trusted connection and scope configuration. AccessToken is
// resolved from an administrator-owned secret mount and is copied only into
// the private HTTP transport; it is never returned or serialized.
type Config struct {
	Provider Provider
	Endpoint string
	// WebBaseURL is the repository web origin used for immutable evidence
	// links. When empty it is derived from the provider API endpoint (for
	// example api.github.com -> github.com and /api/v4 is removed for GitLab).
	WebBaseURL        string
	RepositoryID      string
	BranchName        string
	IncludeGlobs      []string
	ExcludeGlobs      []string
	MaxBlobBytes      int64
	TextMediaTypes    []string
	AccessToken       string
	TrustRoots        *x509.CertPool
	ClientCertificate *tls.Certificate
	HTTPClient        *http.Client
	Timeout           time.Duration
	// MountRootOverride replaces the fixed mountSourcesRoot for a
	// controlled composition test of ProviderMount. Production
	// composition must leave it empty; the fixed mount root is otherwise
	// the only root ever opened.
	MountRootOverride string
}

func (Config) String() string   { return "git.Config{[REDACTED]}" }
func (Config) GoString() string { return "git.Config{[REDACTED]}" }

// Scope is an immutable compiled matcher. It cannot be widened after the
// connector is constructed.
type Scope struct {
	provider     Provider
	endpoint     url.URL
	webBase      url.URL
	repositoryID string
	branchName   string
	matcher      *scopeglob.Matcher
	maxBlobBytes int64
	mediaTypes   map[string]struct{}
	accessToken  string
	http         *http.Client
	// mountRoot is the pinned root handle for ProviderMount. It is nil for
	// every HTTPS provider.
	mountRoot *os.Root
}

// Connector is safe for concurrent Observe calls; credential retirement is
// protected separately from immutable request configuration.
type Connector struct {
	scope Scope
	mu    sync.RWMutex
}

// New validates a complete provider connection/scope and returns an immutable
// read-only connector. Production callers must supply a purpose-specific CA
// pool; a custom HTTP client is accepted only for controlled composition tests
// or an already-qualified transport boundary.
func New(config Config) (*Connector, error) {
	if config.Provider == ProviderMount {
		return newMountConnector(config)
	}
	if config.Provider != ProviderGitHub && config.Provider != ProviderGitLab ||
		!validRepositoryID(config.RepositoryID) || !validBranch(config.BranchName) ||
		config.MaxBlobBytes < 1 || config.MaxBlobBytes > maximumBlobBytes ||
		!validToken(config.AccessToken) || len(config.TextMediaTypes) == 0 || len(config.TextMediaTypes) > 128 {
		return nil, &Error{code: CodeInvalid}
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || !validEndpoint(parsed) {
		return nil, &Error{code: CodeInvalid}
	}
	webBase, err := deriveWebBase(config.Provider, *parsed, config.WebBaseURL)
	if err != nil {
		return nil, err
	}
	mediaTypes := make(map[string]struct{}, len(config.TextMediaTypes))
	for _, value := range config.TextMediaTypes {
		value = strings.ToLower(strings.TrimSpace(value))
		if !validMediaType(value) {
			return nil, &Error{code: CodeInvalid}
		}
		if _, duplicate := mediaTypes[value]; duplicate {
			return nil, &Error{code: CodeInvalid}
		}
		mediaTypes[value] = struct{}{}
	}
	matcher, err := scopeglob.Compile(config.IncludeGlobs, config.ExcludeGlobs, scopeglob.CaseSensitive)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > 60*time.Second {
		return nil, &Error{code: CodeInvalid}
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		if config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 {
			return nil, &Error{code: CodeInvalid}
		}
		tlsConfig := &tls.Config{
			RootCAs:    config.TrustRoots,
			ServerName: parsed.Hostname(),
			MinVersion: tls.VersionTLS12,
		}
		if config.ClientCertificate != nil {
			tlsConfig.Certificates = []tls.Certificate{*config.ClientCertificate}
		}
		httpClient = &http.Client{Transport: &http.Transport{
			Proxy:                  nil,
			TLSClientConfig:        tlsConfig,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 1 << 20,
			ForceAttemptHTTP2:      true,
		}, Timeout: timeout}
	} else if httpClient.Timeout <= 0 || httpClient.Timeout > 60*time.Second {
		return nil, &Error{code: CodeInvalid}
	}
	return &Connector{scope: Scope{
		provider: config.Provider, endpoint: *parsed, webBase: webBase, repositoryID: config.RepositoryID,
		branchName: config.BranchName, matcher: matcher, maxBlobBytes: config.MaxBlobBytes,
		mediaTypes: mediaTypes, accessToken: config.AccessToken, http: httpClient,
	}}, nil
}

// newMountConnector validates a MOUNT scope and pins a root handle under the
// fixed worker mount root. It never resolves a credential, TLS pool or HTTP
// transport: the checkout is read directly from local disk.
func newMountConnector(config Config) (*Connector, error) {
	if !validRepositoryID(config.RepositoryID) || !validBranch(config.BranchName) ||
		config.MaxBlobBytes < 1 || config.MaxBlobBytes > maximumBlobBytes ||
		len(config.TextMediaTypes) == 0 || len(config.TextMediaTypes) > 128 ||
		!validPath(config.Endpoint) || config.WebBaseURL != "" {
		return nil, &Error{code: CodeInvalid}
	}
	mediaTypes := make(map[string]struct{}, len(config.TextMediaTypes))
	for _, value := range config.TextMediaTypes {
		value = strings.ToLower(strings.TrimSpace(value))
		if !validMediaType(value) {
			return nil, &Error{code: CodeInvalid}
		}
		if _, duplicate := mediaTypes[value]; duplicate {
			return nil, &Error{code: CodeInvalid}
		}
		mediaTypes[value] = struct{}{}
	}
	matcher, err := scopeglob.Compile(config.IncludeGlobs, config.ExcludeGlobs, scopeglob.CaseSensitive)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	base := config.MountRootOverride
	if base == "" {
		base = mountSourcesRoot
	}
	root, err := os.OpenRoot(filepath.Join(base, filepath.FromSlash(config.Endpoint)))
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	return &Connector{scope: Scope{
		provider: ProviderMount, repositoryID: config.RepositoryID, branchName: config.BranchName,
		matcher: matcher, maxBlobBytes: config.MaxBlobBytes, mediaTypes: mediaTypes, mountRoot: root,
	}}, nil
}

// Close retires idle connections without exposing the underlying transport.
func (connector *Connector) Close() error {
	if connector == nil {
		return nil
	}
	if connector.scope.mountRoot != nil {
		_ = connector.scope.mountRoot.Close()
	}
	if connector.scope.http == nil {
		return nil
	}
	if closer, ok := connector.scope.http.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	connector.mu.Lock()
	connector.scope.accessToken = ""
	connector.mu.Unlock()
	return nil
}

// ObserveRequest bounds one immutable branch snapshot. Git has no portable
// continuation cursor for an exact tree API response, so a complete result has
// no NextCursor; a provider-truncated tree is explicitly partial.
type ObserveRequest struct {
	MaxObjects int
	MaxBytes   int64
}

// Object is a transient, source-native blob observation. The caller owns
// publication of SourceObject/SourceVersion/Evidence and receives no write
// capability from this type.
type Object struct {
	Path             string
	CommitSHA        string
	BlobID           string
	MediaType        string
	ContentHash      string
	NativeVersionKey string
	Content          []byte
}

type Quarantine struct {
	Path string
	Code QuarantineCode
}

type Page struct {
	RepositoryID     string
	BranchName       string
	CommitSHA        string
	Objects          []Object
	Quarantined      []Quarantine
	CoverageComplete bool
	SnapshotHash     string
}

// Observe resolves the branch at call time, then reads only blobs from the
// resulting commit. A branch movement after resolution cannot mix versions:
// every object carries the same commit SHA and its provider blob ID.
func (connector *Connector) Observe(ctx context.Context, request ObserveRequest) (Page, error) {
	if connector == nil || ctx == nil || connector.scope.matcher == nil ||
		request.MaxObjects < 1 || request.MaxObjects > maximumObjects ||
		request.MaxBytes < 1 || request.MaxBytes > 1<<40 {
		return Page{}, &Error{code: CodeInvalid}
	}
	if connector.scope.provider == ProviderMount {
		return connector.observeMount(ctx, request)
	}
	commit, err := connector.resolveCommit(ctx)
	if err != nil {
		return Page{}, err
	}
	entries, complete, err := connector.readTree(ctx, commit)
	if err != nil {
		return Page{}, err
	}
	if len(entries) > maximumTreeEntries {
		return Page{}, &Error{code: CodeResponse}
	}
	page := Page{RepositoryID: connector.scope.repositoryID, BranchName: connector.scope.branchName,
		CommitSHA: commit, CoverageComplete: complete}
	var totalBytes int64
	for _, entry := range entries {
		if entry.Type != "blob" {
			continue
		}
		matched, matchErr := connector.scope.matcher.Match(entry.Path)
		if matchErr != nil {
			return Page{}, &Error{code: CodeInvalid, cause: matchErr}
		}
		if !matched {
			continue
		}
		mediaType := mediaTypeForPath(entry.Path)
		if _, allowed := connector.scope.mediaTypes[mediaType]; !allowed {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: entry.Path, Code: QuarantineUnsupportedType})
			continue
		}
		if entry.Size < 0 || entry.Size > connector.scope.maxBlobBytes || entry.Size > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: entry.Path, Code: QuarantineOversized})
			continue
		}
		if len(page.Objects) >= request.MaxObjects {
			page.CoverageComplete = false
			break
		}
		content, readErr := connector.readBlob(ctx, entry)
		if readErr != nil {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: entry.Path, Code: quarantineCode(readErr)})
			continue
		}
		if int64(len(content)) > connector.scope.maxBlobBytes || int64(len(content)) > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: entry.Path, Code: QuarantineOversized})
			clearBytes(content)
			continue
		}
		if !utf8.Valid(content) {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: entry.Path, Code: QuarantineInvalidUTF8})
			clearBytes(content)
			continue
		}
		totalBytes += int64(len(content))
		contentHash := sha256Digest(content)
		page.Objects = append(page.Objects, Object{Path: entry.Path, CommitSHA: commit, BlobID: entry.SHA,
			MediaType: mediaType, ContentHash: contentHash,
			NativeVersionKey: "commit:" + commit + ";blob:" + entry.SHA, Content: content})
	}
	page.SnapshotHash = snapshotHash(page)
	return page, nil
}

// observeMount walks the pinned mount root directly instead of calling a
// hosting API. It never shells out to git and never resolves a live branch:
// the checkout is refreshed by deployment-owned tooling outside the worker
// process, and every object is versioned by its exact content hash, mirroring
// the FOLDER connector's own trust model for a pre-mounted root.
func (connector *Connector) observeMount(ctx context.Context, request ObserveRequest) (Page, error) {
	if connector.scope.mountRoot == nil {
		return Page{}, &Error{code: CodeInvalid}
	}
	commit := readMountCommitLabel(connector.scope.mountRoot)
	page := Page{RepositoryID: connector.scope.repositoryID, BranchName: connector.scope.branchName,
		CommitSHA: commit, CoverageComplete: true}
	rootFS := connector.scope.mountRoot.FS()
	var paths []string
	walkErr := fs.WalkDir(rootFS, ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if walkErr != nil {
			// A denied or vanished entry makes the tree partial, never a
			// trusted omission.
			page.CoverageComplete = false
			return nil
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		if name == mountCommitFileName {
			return nil
		}
		paths = append(paths, name)
		if len(paths) > maximumTreeEntries {
			return &Error{code: CodeResponse}
		}
		return nil
	})
	if walkErr != nil {
		return Page{}, &Error{code: CodeResponse, cause: walkErr}
	}
	sort.Strings(paths)
	var totalBytes int64
	for _, name := range paths {
		if len(page.Objects) >= request.MaxObjects {
			page.CoverageComplete = false
			break
		}
		slashPath := filepath.ToSlash(name)
		matched, matchErr := connector.scope.matcher.Match(slashPath)
		if matchErr != nil {
			return Page{}, &Error{code: CodeInvalid, cause: matchErr}
		}
		if !matched {
			continue
		}
		mediaType := mediaTypeForPath(slashPath)
		if _, allowed := connector.scope.mediaTypes[mediaType]; !allowed {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineUnsupportedType})
			continue
		}
		info, statErr := fs.Stat(rootFS, name)
		if statErr != nil || !info.Mode().IsRegular() {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineReadFailed})
			continue
		}
		if info.Size() < 0 || info.Size() > connector.scope.maxBlobBytes || info.Size() > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineOversized})
			continue
		}
		content, readErr := fs.ReadFile(rootFS, name)
		if readErr != nil {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineReadFailed})
			continue
		}
		if int64(len(content)) > connector.scope.maxBlobBytes || int64(len(content)) > request.MaxBytes-totalBytes {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineOversized})
			clearBytes(content)
			continue
		}
		if !utf8.Valid(content) {
			page.Quarantined = append(page.Quarantined, Quarantine{Path: slashPath, Code: QuarantineInvalidUTF8})
			clearBytes(content)
			continue
		}
		totalBytes += int64(len(content))
		contentHash := sha256Digest(content)
		page.Objects = append(page.Objects, Object{
			Path: slashPath, CommitSHA: commit, BlobID: contentHash, MediaType: mediaType, ContentHash: contentHash,
			NativeVersionKey: "mount:content:" + contentHash, Content: content,
		})
	}
	page.SnapshotHash = snapshotHash(page)
	return page, nil
}

// readMountCommitLabel best-effort reads the optional commit label file at
// the mount root. Its absence or an invalid value is never an error: the
// caller falls back to an empty label.
func readMountCommitLabel(root *os.Root) string {
	file, err := root.Open(mountCommitFileName)
	if err != nil {
		return ""
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return ""
	}
	label := strings.TrimSpace(string(raw))
	if !validSHA(label) {
		return ""
	}
	return label
}

// DeepLink returns a provider-specific immutable commit URL. It is a display
// hint only; the citation authority must still bind the exact Evidence anchor.
func (connector *Connector) DeepLink(commitSHA, path string) (string, error) {
	if connector == nil || connector.scope.matcher == nil {
		return "", &Error{code: CodeInvalid}
	}
	if connector.scope.provider == ProviderMount {
		// The managed mount has no portable source-native URL; the
		// authorized Evidence viewer resolves the exact anchor instead,
		// mirroring the accepted PostgreSQL-source precedent (ADR-0078 §6).
		return "", &Error{code: CodeInvalid}
	}
	if !validSHA(commitSHA) || !validPath(path) {
		return "", &Error{code: CodeInvalid}
	}
	matched, err := connector.scope.matcher.Match(path)
	if err != nil || !matched {
		return "", &Error{code: CodeInvalid, cause: err}
	}
	base := connector.scope.webBase
	base.Scheme = "https"
	prefix := strings.TrimSuffix(base.Path, "/")
	if connector.scope.provider == ProviderGitHub {
		base.Path = prefix + "/" + connector.scope.repositoryID + "/blob/" + commitSHA + "/" + path
	} else {
		base.Path = prefix + "/" + connector.scope.repositoryID + "/-/blob/" + commitSHA + "/" + path
	}
	base.RawPath = ""
	base.RawQuery, base.Fragment, base.User = "", "", nil
	return base.String(), nil
}

type treeEntry struct {
	Path string
	Type string
	SHA  string
	Size int64
}

func (connector *Connector) resolveCommit(ctx context.Context) (string, error) {
	var response struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
		Commit struct {
			ID string `json:"id"`
		} `json:"commit"`
	}
	var err error
	if connector.scope.provider == ProviderGitHub {
		err = connector.getJSON(ctx, []string{"repos", connector.scope.repositoryID, "git", "ref", "heads", connector.scope.branchName}, "", &response)
		if err == nil && response.Object.Type != "commit" {
			err = &Error{code: CodeResponse}
		}
		if err == nil && !validSHA(response.Object.SHA) {
			err = &Error{code: CodeResponse}
		}
		if err == nil {
			return response.Object.SHA, nil
		}
	} else {
		err = connector.getJSON(ctx, []string{"projects", connector.scope.repositoryID, "repository", "branches", connector.scope.branchName}, "", &response)
		if err == nil && !validSHA(response.Commit.ID) {
			err = &Error{code: CodeResponse}
		}
		if err == nil {
			return response.Commit.ID, nil
		}
	}
	return "", err
}

func (connector *Connector) readTree(ctx context.Context, commit string) ([]treeEntry, bool, error) {
	if connector.scope.provider == ProviderGitHub {
		var response struct {
			Truncated bool `json:"truncated"`
			Tree      []struct {
				Path string `json:"path"`
				Type string `json:"type"`
				SHA  string `json:"sha"`
				Size int64  `json:"size"`
			} `json:"tree"`
		}
		if err := connector.getJSON(ctx, []string{"repos", connector.scope.repositoryID, "git", "trees", commit}, "recursive=1", &response); err != nil {
			return nil, false, err
		}
		entries := make([]treeEntry, 0, len(response.Tree))
		for _, item := range response.Tree {
			entries = append(entries, treeEntry{Path: item.Path, Type: item.Type, SHA: item.SHA, Size: item.Size})
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Path != entries[j].Path {
				return entries[i].Path < entries[j].Path
			}
			if entries[i].Type != entries[j].Type {
				return entries[i].Type < entries[j].Type
			}
			return entries[i].SHA < entries[j].SHA
		})
		if err := validateTreeEntries(entries); err != nil {
			return nil, false, err
		}
		return entries, !response.Truncated, nil
	}
	entries := make([]treeEntry, 0)
	for page := 1; page <= maximumGitPages; page++ {
		var response []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			ID   string `json:"id"`
			Size int64  `json:"size"`
		}
		query := "recursive=true&ref=" + url.QueryEscape(commit) + "&per_page=" + strconv.Itoa(maximumPageSize) + "&page=" + strconv.Itoa(page)
		if err := connector.getJSON(ctx, []string{"projects", connector.scope.repositoryID, "repository", "tree"}, query, &response); err != nil {
			return nil, false, err
		}
		for _, item := range response {
			entries = append(entries, treeEntry{Path: item.Path, Type: item.Type, SHA: item.ID, Size: item.Size})
			if len(entries) > maximumTreeEntries {
				return nil, false, &Error{code: CodeResponse}
			}
		}
		if len(response) < maximumPageSize {
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].Path != entries[j].Path {
					return entries[i].Path < entries[j].Path
				}
				if entries[i].Type != entries[j].Type {
					return entries[i].Type < entries[j].Type
				}
				return entries[i].SHA < entries[j].SHA
			})
			if err := validateTreeEntries(entries); err != nil {
				return nil, false, err
			}
			return entries, true, nil
		}
	}
	return entries, false, &Error{code: CodeCoveragePartial}
}

func (connector *Connector) readBlob(ctx context.Context, entry treeEntry) ([]byte, error) {
	if !validSHA(entry.SHA) {
		return nil, &Error{code: CodeResponse}
	}
	var content []byte
	if connector.scope.provider == ProviderGitHub {
		var response struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			SHA      string `json:"sha"`
		}
		if err := connector.getJSON(ctx, []string{"repos", connector.scope.repositoryID, "git", "blobs", entry.SHA}, "", &response); err != nil {
			return nil, err
		}
		if response.Encoding != "base64" || response.SHA != entry.SHA {
			return nil, &Error{code: CodeResponse}
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(response.Content, "\n", ""))
		if err != nil {
			return nil, &Error{code: CodeResponse, cause: err}
		}
		content = decoded
	} else {
		var err error
		content, err = connector.getBytes(ctx, []string{"projects", connector.scope.repositoryID, "repository", "blobs", entry.SHA, "raw"}, "")
		if err != nil {
			return nil, err
		}
	}
	if int64(len(content)) > connector.scope.maxBlobBytes || (entry.Size > 0 && int64(len(content)) != entry.Size) {
		clearBytes(content)
		return nil, &Error{code: CodeResponse}
	}
	if gitBlobSHA(content) != entry.SHA {
		clearBytes(content)
		return nil, &Error{code: CodeResponse}
	}
	return content, nil
}

func (connector *Connector) getJSON(ctx context.Context, parts []string, query string, destination any) error {
	raw, err := connector.getBytes(ctx, parts, query)
	if err != nil {
		return err
	}
	defer clearBytes(raw)
	if err := json.Unmarshal(raw, destination); err != nil {
		return &Error{code: CodeResponse, cause: err}
	}
	return nil
}

func (connector *Connector) getBytes(ctx context.Context, parts []string, query string) ([]byte, error) {
	if connector == nil || ctx == nil || len(parts) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	target := connector.scope.endpoint
	basePath := strings.TrimSuffix(target.Path, "/")
	for _, part := range parts {
		if !validURLPart(part) {
			return nil, &Error{code: CodeInvalid}
		}
		basePath += "/" + url.PathEscape(part)
	}
	// PathEscape is retained in RawPath while Path contains the decoded form;
	// this preserves repository/branch slashes as data rather than URL paths.
	escaped := basePath
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	target.Path, target.RawPath = decoded, escaped
	target.RawQuery, target.Fragment, target.User = query, "", nil
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "knowvault-git-connector/1")
	connector.mu.RLock()
	accessToken := connector.scope.accessToken
	connector.mu.RUnlock()
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	response, err := connector.scope.http.Do(request)
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil {
		return nil, &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	if len(raw) > maximumResponseBytes {
		clearBytes(raw)
		return nil, &Error{code: CodeResponse, status: response.StatusCode}
	}
	return raw, nil
}

func validEndpoint(value *url.URL) bool {
	return value != nil && value.Scheme == "https" && value.Host != "" && value.User == nil &&
		value.RawQuery == "" && value.Fragment == "" && value.Opaque == "" &&
		netcanon.ValidCanonicalHost(value.Hostname()) && !strings.HasSuffix(value.Hostname(), ".")
}

func deriveWebBase(provider Provider, endpoint url.URL, configured string) (url.URL, error) {
	if configured != "" {
		parsed, err := url.Parse(configured)
		if err != nil || !validEndpoint(parsed) {
			return url.URL{}, &Error{code: CodeInvalid, cause: err}
		}
		return *parsed, nil
	}
	web := endpoint
	web.RawQuery, web.Fragment, web.User, web.RawPath = "", "", nil, ""
	pathValue := strings.TrimSuffix(web.Path, "/")
	switch provider {
	case ProviderGitHub:
		if strings.EqualFold(web.Hostname(), "api.github.com") {
			web.Host = "github.com"
		}
		if strings.HasSuffix(pathValue, "/api/v3") {
			pathValue = strings.TrimSuffix(pathValue, "/api/v3")
		}
	case ProviderGitLab:
		if strings.HasSuffix(pathValue, "/api/v4") {
			pathValue = strings.TrimSuffix(pathValue, "/api/v4")
		}
	default:
		return url.URL{}, &Error{code: CodeInvalid}
	}
	web.Path = strings.TrimSuffix(pathValue, "/")
	return web, nil
}

func validRepositoryID(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\?#") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\r\n") {
			return false
		}
	}
	return true
}

func validBranch(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		value == "HEAD" || strings.HasPrefix(value, "refs/") || strings.HasPrefix(value, "-") || strings.Contains(value, "..") ||
		strings.ContainsAny(value, "~^:?*[\\\r\n") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	if len(value) > 4096 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	if value == "" || len(value) > 128 || !strings.HasPrefix(value, "text/") && value != "application/json" && value != "application/xml" && value != "application/javascript" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '/' || character == '+' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return strings.Count(value, "/") == 1 && !strings.HasSuffix(value, "/")
}

func validURLPart(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n")
}

func validSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F') {
			return false
		}
	}
	return true
}

func validPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return utf8.ValidString(value)
}

func mediaTypeForPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".go"):
		return "text/x-go"
	case strings.HasSuffix(lower, ".rs"):
		return "text/x-rust"
	case strings.HasSuffix(lower, ".java"):
		return "text/x-java-source"
	case strings.HasSuffix(lower, ".json"):
		return "application/json"
	case strings.HasSuffix(lower, ".xml"):
		return "application/xml"
	case strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx"):
		return "application/javascript"
	case strings.HasSuffix(lower, ".md"):
		return "text/markdown"
	case strings.HasSuffix(lower, ".html") || strings.HasSuffix(lower, ".htm"):
		return "text/html"
	case strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".csv") || strings.HasSuffix(lower, ".eml"):
		return "text/plain"
	case strings.HasSuffix(lower, ".py"):
		return "text/x-python"
	case strings.HasSuffix(lower, ".kt"):
		return "text/x-kotlin"
	case strings.HasSuffix(lower, ".sql"):
		return "text/x-sql"
	case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"):
		return "text/x-yaml"
	case strings.HasSuffix(lower, ".toml"):
		return "text/x-toml"
	case strings.HasSuffix(lower, ".proto"):
		return "text/x-protobuf"
	case strings.HasSuffix(lower, ".sh"):
		return "text/x-sh"
	case strings.HasSuffix(lower, ".cs"):
		return "text/x-csharp"
	case strings.HasSuffix(lower, ".php"):
		return "text/x-php"
	case strings.HasSuffix(lower, ".rb"):
		return "text/x-ruby"
	default:
		return "application/octet-stream"
	}
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func gitBlobSHA(value []byte) string {
	header := []byte("blob " + strconv.Itoa(len(value)) + "\x00")
	hash := sha1.New()
	_, _ = hash.Write(header)
	_, _ = hash.Write(value)
	return hex.EncodeToString(hash.Sum(nil))
}

func snapshotHash(page Page) string {
	hash := sha256.New()
	coverage := "partial"
	if page.CoverageComplete {
		coverage = "complete"
	}
	_, _ = hash.Write([]byte(page.RepositoryID + "\x00" + page.BranchName + "\x00" + page.CommitSHA + "\x00" + coverage))
	for _, item := range page.Objects {
		_, _ = hash.Write([]byte("\x00" + item.Path + "\x00" + item.BlobID + "\x00" + item.ContentHash))
	}
	for _, item := range page.Quarantined {
		_, _ = hash.Write([]byte("\x01" + item.Path + "\x00" + string(item.Code)))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validateTreeEntries(entries []treeEntry) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !validPath(entry.Path) {
			return &Error{code: CodeResponse}
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return &Error{code: CodeResponse}
		}
		seen[entry.Path] = struct{}{}
		switch entry.Type {
		case "blob", "tree", "commit":
			if !validSHA(entry.SHA) {
				return &Error{code: CodeResponse}
			}
		default:
			return &Error{code: CodeResponse}
		}
		if entry.Size < -1 {
			return &Error{code: CodeResponse}
		}
	}
	return nil
}

func quarantineCode(err error) QuarantineCode {
	var typed *Error
	if errors.As(err, &typed) && typed != nil && typed.code == CodeResponse {
		return QuarantineBlobMismatch
	}
	return QuarantineReadFailed
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
