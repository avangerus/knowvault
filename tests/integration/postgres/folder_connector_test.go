package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/connector/folder"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// hostPlatform picks the connector platform matching the host so the canonical
// path and case rules line up with the real filesystem the test writes to.
func hostPlatform() folder.Platform {
	if runtime.GOOS == "windows" {
		return folder.PlatformWindows
	}
	return folder.PlatformPOSIX
}

func writeFile(t *testing.T, dir, rel string, content []byte) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func textScope(t *testing.T, root string, include, exclude []string, maxBytes int64) *folder.Scope {
	t.Helper()
	scope, err := folder.NewScope(folder.ScopeParams{
		RootPath:     root,
		Platform:     hostPlatform(),
		Access:       folder.AccessWorkspaceManaged,
		RelativeRoot: "",
		Recursive:    true,
		IncludeGlobs: include,
		ExcludeGlobs: exclude,
		MaxFileBytes: maxBytes,
		Formats:      []folder.Format{folder.FormatTXT, folder.FormatMarkdown, folder.FormatCSV, folder.FormatJSON},
	})
	if err != nil {
		t.Fatalf("build scope: %v", err)
	}
	return scope
}

// TestFolderConnectorRuntimeContainment proves SRC-007 at runtime on a real
// filesystem: a normal in-scope UTF-8 file is discovered and read, while
// traversal, absolute-path substitution, out-of-root paths, POSIX symlinks and
// Windows reparse points/junctions all fail closed and never expose an
// out-of-root secret.
func TestFolderConnectorRuntimeContainment(t *testing.T) {
	ctx := context.Background()
	connector := folder.New()

	outside := t.TempDir()
	secret := []byte("OUT-OF-ROOT-SECRET-should-never-surface")
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), secret, 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	writeFile(t, root, "docs/hello.txt", []byte("hello canonical utf8 \u0444\u0430\u0439\u043b\n"))
	scope := textScope(t, root, nil, nil, 1<<20)

	t.Run("happy discover and read", func(t *testing.T) {
		discovery, err := connector.Discover(ctx, scope)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		found := false
		for _, object := range discovery.Objects {
			if object.RelativePath == "docs/hello.txt" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected docs/hello.txt to be discovered, got %+v", discovery.Objects)
		}
		result, quarantine, err := connector.Read(ctx, scope, "docs/hello.txt")
		if err != nil || quarantine != nil {
			t.Fatalf("read: err=%v quarantine=%+v", err, quarantine)
		}
		if !strings.Contains(string(result.Content), "canonical utf8") {
			t.Fatalf("unexpected content")
		}
		sum := sha256.Sum256(result.Content)
		if result.ContentSHA256 != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("content hash mismatch")
		}
	})

	t.Run("traversal and absolute paths rejected", func(t *testing.T) {
		for _, bad := range []string{
			"../" + filepath.Base(outside) + "/secret.txt",
			"docs/../../secret.txt",
			"/etc/passwd",
			`C:\Windows\system32\drivers\etc\hosts`,
			`\\server\share\secret.txt`,
			"docs/./../../secret.txt",
		} {
			if _, quarantine, err := connector.Read(ctx, scope, bad); err == nil && quarantine == nil {
				t.Fatalf("path %q was not rejected", bad)
			}
		}
	})

	t.Run("symlink escape rejected", func(t *testing.T) {
		linkDir := filepath.Join(root, "docs", "escape")
		if err := os.Symlink(outside, linkDir); err != nil {
			t.Skipf("symlink unsupported on host: %v", err)
		}
		discovery, err := connector.Discover(ctx, scope)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		for _, object := range discovery.Objects {
			if strings.Contains(object.RelativePath, "escape") {
				t.Fatalf("symlink target was traversed: %s", object.RelativePath)
			}
			if strings.Contains(object.RelativePath, "secret") {
				t.Fatalf("out-of-root secret surfaced via symlink")
			}
		}
		sawSymlinkQuarantine := false
		for _, notice := range discovery.Quarantined {
			if notice.Code == folder.QuarantineSymlinkRejected {
				sawSymlinkQuarantine = true
			}
		}
		if !sawSymlinkQuarantine {
			t.Fatalf("expected a symlink-rejected quarantine, got %+v", discovery.Quarantined)
		}
		if _, quarantine, err := connector.Read(ctx, scope, "docs/escape/secret.txt"); err == nil && (quarantine == nil || quarantine.Code == "") {
			t.Fatalf("read through symlink was not rejected")
		}
	})

	t.Run("in-root intermediate symlink not followed", func(t *testing.T) {
		// teamA and teamB are sibling subtrees of one trusted root. A scope
		// narrowed to teamA must not read teamB content through an in-root
		// symlink teamA/link -> ../teamB, even though os.Root would let that link
		// resolve because it stays inside the root.
		narrowRoot := t.TempDir()
		writeFile(t, narrowRoot, "teamA/own.txt", []byte("team A own file"))
		writeFile(t, narrowRoot, "teamB/secret.txt", []byte("TEAM-B-SECRET"))
		if err := os.Symlink(filepath.Join(narrowRoot, "teamB"), filepath.Join(narrowRoot, "teamA", "link")); err != nil {
			t.Skipf("symlink unsupported on host: %v", err)
		}
		narrowScope, err := folder.NewScope(folder.ScopeParams{
			RootPath: narrowRoot, Platform: hostPlatform(), Access: folder.AccessWorkspaceManaged,
			RelativeRoot: "teamA", Recursive: true, MaxFileBytes: 1 << 20,
			Formats: []folder.Format{folder.FormatTXT},
		})
		if err != nil {
			t.Fatalf("narrow scope: %v", err)
		}
		result, quarantine, err := connector.Read(ctx, narrowScope, "teamA/link/secret.txt")
		if err == nil && quarantine == nil {
			t.Fatalf("read followed in-root symlink into teamB: %q", string(result.Content))
		}
		if quarantine != nil && strings.Contains(string(result.Content), "TEAM-B-SECRET") {
			t.Fatalf("teamB secret surfaced")
		}
		discovery, err := connector.Discover(ctx, narrowScope)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		for _, object := range discovery.Objects {
			if strings.Contains(object.RelativePath, "secret") || strings.Contains(object.RelativePath, "link") {
				t.Fatalf("in-root symlink traversed during discovery: %s", object.RelativePath)
			}
		}
	})

	t.Run("windows junction escape rejected", func(t *testing.T) {
		if runtime.GOOS != "windows" {
			t.Skip("windows-only reparse semantics")
		}
		junction := filepath.Join(root, "docs", "junction")
		cmd := exec.Command("cmd", "/c", "mklink", "/J", junction, outside)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("mklink /J unsupported: %v (%s)", err, output)
		}
		discovery, err := connector.Discover(ctx, scope)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		for _, object := range discovery.Objects {
			if strings.Contains(object.RelativePath, "secret") || strings.Contains(object.RelativePath, "junction") {
				t.Fatalf("junction target was traversed: %s", object.RelativePath)
			}
		}
	})
}

// TestFolderConnectorTornReadFailsClosed proves SRC-012: a file mutated in place
// during the read never surfaces as a trusted result. Over bounded attempts a
// concurrent in-place truncation is caught as a torn read, and every successful
// read is a byte-consistent snapshot.
func TestFolderConnectorTornReadFailsClosed(t *testing.T) {
	ctx := context.Background()
	connector := folder.New()
	root := t.TempDir()
	scope := textScope(t, root, nil, nil, 64<<20)

	target := filepath.Join(root, "big.txt")
	long := make([]byte, 8<<20)
	for i := range long {
		long[i] = 'A'
	}
	longSum := sha256.Sum256(long)
	longHash := "sha256:" + hex.EncodeToString(longSum[:])

	short := []byte("A short consistent replacement snapshot.\n")
	shortSum := sha256.Sum256(short)
	shortHash := "sha256:" + hex.EncodeToString(shortSum[:])

	sawTorn := false
	for attempt := 0; attempt < 32 && !sawTorn; attempt++ {
		if err := os.WriteFile(target, long, 0o644); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Continuously rewrite the same inode in place so a rewrite lands
			// mid-read; alternating sizes makes size/mtime and the double-read
			// hash disagree.
			for iteration := 0; ; iteration++ {
				select {
				case <-stop:
					return
				default:
				}
				if iteration%2 == 0 {
					_ = os.WriteFile(target, short, 0o644)
				} else {
					_ = os.WriteFile(target, long, 0o644)
				}
			}
		}()
		result, quarantine, err := connector.Read(ctx, scope, "big.txt")
		close(stop)
		wg.Wait()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if quarantine != nil {
			if quarantine.Code == folder.QuarantineTornRead {
				sawTorn = true
			}
			continue
		}
		// A success must be one of the two byte-consistent snapshots, never a
		// torn blend.
		if result.ContentSHA256 != longHash && result.ContentSHA256 != shortHash {
			t.Fatalf("torn content surfaced as a trusted result: size=%d", result.SizeBytes)
		}
	}
	if !sawTorn {
		t.Fatalf("expected at least one torn-read quarantine across attempts")
	}
}

// TestFolderConnectorRuntimeQuarantine proves the bounded-stable-read fail-closed
// taxonomy: oversized, invalid UTF-8, unsupported/executable, media-signature
// mismatch and non-regular objects all quarantine and never read as success.
func TestFolderConnectorRuntimeQuarantine(t *testing.T) {
	ctx := context.Background()
	connector := folder.New()
	root := t.TempDir()

	// A file that reads as text in its signature window but carries an invalid
	// UTF-8 sequence past the window is an INVALID_UTF8 quarantine; a file whose
	// leading bytes are binary (NUL) is UNSUPPORTED_TYPE.
	lateBadUTF8 := append([]byte(strings.Repeat("A", 520)), 0xff, 0xfe)
	writeFile(t, root, "big.txt", []byte(strings.Repeat("A", 4096)))
	writeFile(t, root, "latebad.txt", lateBadUTF8)
	writeFile(t, root, "binary.txt", []byte{0x66, 0x6f, 0x6f, 0x00, 0x99, 0x01})
	writeFile(t, root, "prog.txt", []byte("\x7fELF\x02\x01\x01ignored executable payload"))
	writeFile(t, root, "image.txt", []byte("\x89PNG\r\n\x1a\nnot really text"))

	textOnly := textScope(t, root, nil, nil, 1024)

	cases := []struct {
		path string
		want folder.QuarantineCode
	}{
		{"big.txt", folder.QuarantineOversized},
		{"latebad.txt", folder.QuarantineInvalidUTF8},
		{"binary.txt", folder.QuarantineUnsupportedType},
		{"prog.txt", folder.QuarantineUnsupportedType},
		{"image.txt", folder.QuarantineMediaSignature},
	}
	for _, testCase := range cases {
		result, quarantine, err := connector.Read(ctx, textOnly, testCase.path)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", testCase.path, err)
		}
		if quarantine == nil {
			t.Fatalf("%s: expected quarantine %s, got success %+v", testCase.path, testCase.want, result)
		}
		if quarantine.Code != testCase.want {
			t.Fatalf("%s: expected %s, got %s", testCase.path, testCase.want, quarantine.Code)
		}
	}

	t.Run("non-regular quarantined", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("fifo semantics are POSIX")
		}
		fifo := filepath.Join(root, "pipe.txt")
		if err := makeFIFO(fifo); err != nil {
			t.Skipf("mkfifo unsupported: %v", err)
		}
		discovery, err := connector.Discover(ctx, textOnly)
		if err != nil {
			t.Fatalf("discover: %v", err)
		}
		sawNonRegular := false
		for _, notice := range discovery.Quarantined {
			if notice.Code == folder.QuarantineNonRegular {
				sawNonRegular = true
			}
		}
		if !sawNonRegular {
			t.Fatalf("expected non-regular quarantine, got %+v", discovery.Quarantined)
		}
	})
}

// TestFolderConnectorGlobParityAndIsolation proves SRC-013 (server/connector use
// the one shared glob grammar with exclude precedence), deterministic repeat
// discovery with no durable state, and that concurrent reads never widen scope.
func TestFolderConnectorGlobParityAndIsolation(t *testing.T) {
	ctx := context.Background()
	connector := folder.New()
	root := t.TempDir()
	writeFile(t, root, "a/keep.txt", []byte("keep"))
	writeFile(t, root, "a/skip.txt", []byte("skip"))
	writeFile(t, root, "b/keep.txt", []byte("keep"))
	writeFile(t, root, "b/drop/keep.txt", []byte("keep"))

	scope := textScope(t, root, []string{"**/keep.txt"}, []string{"b/drop/**"}, 1<<20)

	first, err := connector.Discover(ctx, scope)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	got := discoveredPaths(first)
	want := []string{"a/keep.txt", "b/keep.txt"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("include/exclude parity mismatch: got %v want %v", got, want)
	}

	// Deterministic repeat: identical ordered result, no durable state changed.
	second, err := connector.Discover(ctx, scope)
	if err != nil {
		t.Fatalf("second discover: %v", err)
	}
	if strings.Join(discoveredPaths(second), ",") != strings.Join(got, ",") {
		t.Fatalf("discovery is not deterministic")
	}

	// Concurrent reads never widen scope: an excluded/out-of-scope object stays
	// unreadable no matter how many readers run.
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, quarantine, err := connector.Read(ctx, scope, "a/skip.txt"); err == nil && quarantine == nil {
				errs <- fmt.Errorf("excluded object became readable under concurrency")
			}
			if _, quarantine, err := connector.Read(ctx, scope, "b/drop/keep.txt"); err == nil && quarantine == nil {
				errs <- fmt.Errorf("excluded subtree became readable under concurrency")
			}
			if _, _, err := connector.Read(ctx, scope, "a/keep.txt"); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestFolderConnectorTransientBytesNeverReachDurableSinks proves the
// transient-content boundary (ING-006, and the connector read-only capability
// SRC-002): the connector reads canary bytes into an in-process result, a
// SOURCE_SCOPE_SYNC job carries only content-free references, a job payload
// cannot even hold the canary, and the canary appears in no durable PostgreSQL
// sink.
func TestFolderConnectorTransientBytesNeverReachDurableSinks(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	const canary = "CANARY-7Q3Z-transient-source-bytes-must-not-persist"
	root := t.TempDir()
	writeFile(t, root, "notes/canary.txt", []byte("prefix "+canary+" suffix\n"))
	scope := textScope(t, root, nil, nil, 1<<20)

	result, quarantine, err := folder.New().Read(ctx, scope, "notes/canary.txt")
	if err != nil || quarantine != nil {
		t.Fatalf("read canary: err=%v quarantine=%+v", err, quarantine)
	}
	if !strings.Contains(string(result.Content), canary) {
		t.Fatalf("connector did not read the canary into its transient result")
	}

	// The durable job substrate can only carry a content-free reference payload.
	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	store, err := database.Open(ctx, config)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(store.Close)
	queue, err := jobs.New(store)
	if err != nil {
		t.Fatalf("new queue: %v", err)
	}
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_folder_sync"}

	// A legitimate SOURCE_SCOPE_SYNC job references the scope by id only.
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{
		JobID:          "job_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Type:           jobs.TypeSourceScopeSync,
		Payload:        jobs.Payload{"source_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		IdempotencyKey: "folder-sync-canary",
		Priority:       100,
		MaxAttempts:    5,
		AvailableAfter: 0,
	}); err != nil {
		t.Fatalf("enqueue content-free job: %v", err)
	}

	// Smuggling source bytes into a job payload is rejected outright.
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{
		JobID:          "job_01ARZ3NDEKTSV4RRFFQ69G5FBW",
		Type:           jobs.TypeSourceScopeSync,
		Payload:        jobs.Payload{"content_hash": canary},
		IdempotencyKey: "folder-sync-smuggle",
		Priority:       100,
		MaxAttempts:    5,
		AvailableAfter: 0,
	}); err == nil {
		t.Fatalf("a job payload carrying source content was accepted")
	}

	// No durable PostgreSQL column anywhere contains the canary.
	if hits := scanForCanary(t, ctx, admin, canary); len(hits) != 0 {
		t.Fatalf("canary leaked into durable sinks: %v", hits)
	}
}

func discoveredPaths(result folder.DiscoveryResult) []string {
	paths := make([]string, 0, len(result.Objects))
	for _, object := range result.Objects {
		paths = append(paths, object.RelativePath)
	}
	return paths
}

// scanForCanary inspects every text-bearing column of every public table for the
// canary substring, so the assertion is not limited to a hand-picked sink list.
func scanForCanary(t *testing.T, ctx context.Context, admin *pgxpool.Pool, canary string) []string {
	t.Helper()
	rows, err := admin.Query(ctx, `
		SELECT table_name, column_name
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND data_type IN ('text','character varying','jsonb','json','bytea','character','name')`)
	if err != nil {
		t.Fatalf("list columns: %v", err)
	}
	type column struct{ table, name string }
	var columns []column
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.table, &c.name); err != nil {
			rows.Close()
			t.Fatalf("scan column: %v", err)
		}
		columns = append(columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("column rows: %v", err)
	}

	var hits []string
	for _, c := range columns {
		var count int64
		query := `SELECT count(*) FROM public.` + quoteIdent(c.table) +
			` WHERE ` + quoteIdent(c.name) + `::text LIKE '%' || $1 || '%'`
		if err := admin.QueryRow(ctx, query, canary).Scan(&count); err != nil {
			t.Fatalf("scan %s.%s: %v", c.table, c.name, err)
		}
		if count > 0 {
			hits = append(hits, c.table+"."+c.name)
		}
	}
	return hits
}

func quoteIdent(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
