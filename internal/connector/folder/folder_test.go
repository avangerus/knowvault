package folder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validParams(root string) ScopeParams {
	return ScopeParams{
		RootPath:     root,
		Platform:     PlatformPOSIX,
		Access:       AccessWorkspaceManaged,
		RelativeRoot: "",
		Recursive:    true,
		IncludeGlobs: nil,
		ExcludeGlobs: nil,
		MaxFileBytes: 1 << 20,
		Formats:      []Format{FormatTXT},
	}
}

func TestNewScopeAcceptsTrustedConfigAndRejectsUnsafe(t *testing.T) {
	root := "/mnt/share"
	if _, err := NewScope(validParams(root)); err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}

	mutate := func(f func(*ScopeParams)) ScopeParams {
		p := validParams(root)
		f(&p)
		return p
	}
	cases := map[string]ScopeParams{
		"source enforced unsupported": mutate(func(p *ScopeParams) { p.Access = AccessSourceEnforced }),
		"unknown platform":            mutate(func(p *ScopeParams) { p.Platform = Platform(9) }),
		"zero max bytes":              mutate(func(p *ScopeParams) { p.MaxFileBytes = 0 }),
		"over cap max bytes":          mutate(func(p *ScopeParams) { p.MaxFileBytes = maximumScopeByteCap + 1 }),
		"no formats":                  mutate(func(p *ScopeParams) { p.Formats = nil }),
		"unknown format":              mutate(func(p *ScopeParams) { p.Formats = []Format{"EXE"} }),
		"relative traversal":          mutate(func(p *ScopeParams) { p.RelativeRoot = "a/../../b" }),
		"relative absolute":           mutate(func(p *ScopeParams) { p.RelativeRoot = "/etc" }),
		"relative backslash":          mutate(func(p *ScopeParams) { p.RelativeRoot = `a\b` }),
		"non-absolute root":           mutate(func(p *ScopeParams) { p.RootPath = "relative/root" }),
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewScope(params); err == nil {
				t.Fatalf("unsafe scope %q was accepted", name)
			}
		})
	}
}

func TestNewScopeWindowsSpecialRelativeRootRejected(t *testing.T) {
	for _, bad := range []string{"CON.txt", "docs/NUL", "team:stream", "trailing.", "space "} {
		params := validParams(`C:\share`)
		params.Platform = PlatformWindows
		params.RelativeRoot = bad
		if _, err := NewScope(params); err == nil {
			t.Fatalf("windows special relative_root %q was accepted", bad)
		}
	}
}

func TestClassifyFamilies(t *testing.T) {
	cases := []struct {
		content []byte
		want    family
	}{
		{[]byte("%PDF-1.7 body"), familyPDF},
		{[]byte("\x89PNG\r\n\x1a\n....."), familyPNG},
		{[]byte("\xff\xd8\xff\xe0 jpeg"), familyJPEG},
		{[]byte("PK\x03\x04 zip ooxml"), familyOOXML},
		{[]byte("plain text ascii\n"), familyText},
		{[]byte("\u042e\u043d\u0438\u043a\u043e\u0434 \u0442\u0435\u043a\u0441\u0442 \u0432 NFC\n"), familyText},
		{[]byte("First page\fSecond page\n"), familyText},
		{[]byte("Text\x00binary"), familyUnknown},
		{[]byte("Text\x1bterminal escape"), familyUnknown},
		{[]byte("\x7fELF binary"), familyExecutable},
		{[]byte("MZ\x90\x00 dos"), familyExecutable},
		{[]byte("#!/bin/sh\necho hi"), familyExecutable},
		{[]byte{0x00, 0x01, 0x02}, familyUnknown},
		{[]byte{}, familyUnknown},
	}
	for _, c := range cases {
		if got := classify(c.content); got != c.want {
			t.Fatalf("classify(%q) = %d, want %d", c.content, got, c.want)
		}
	}
}

func TestTextExportReadPreservesPageSeparatorAndHash(t *testing.T) {
	root := t.TempDir()
	const original = "Page one\n\fPage two\n"
	if err := os.WriteFile(filepath.Join(root, "export.pdf.txt"), []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	params := validParams(root)
	params.Platform = hostPlatformForTest()
	scope, err := NewScope(params)
	if err != nil {
		t.Fatal(err)
	}
	result, quarantine, err := New().Read(context.Background(), scope, "export.pdf.txt")
	digest := sha256.Sum256([]byte(original))
	wantHash := "sha256:" + hex.EncodeToString(digest[:])
	if err != nil || quarantine != nil || string(result.Content) != original || result.MediaFamily != MediaFamilyText || result.ContentSHA256 != wantHash {
		t.Fatalf("text page separator was rejected or changed: %v %+v %+v", err, quarantine, result)
	}
}

func TestCanonicalRootRelativeRejectsUnsafePaths(t *testing.T) {
	for _, bad := range []string{"", "/abs", "trail/", "a//b", "a/./b", "a/../b", `a\b`, "a/\x01/b", "..", "."} {
		if _, err := canonicalRootRelative(bad, PlatformPOSIX); err == nil {
			t.Fatalf("unsafe path %q accepted", bad)
		}
	}
	if got, err := canonicalRootRelative("projects/alpha/spec.txt", PlatformPOSIX); err != nil || got != "projects/alpha/spec.txt" {
		t.Fatalf("valid path rejected: got=%q err=%v", got, err)
	}
	if _, err := canonicalRootRelative("team:stream/a", PlatformWindows); err == nil {
		t.Fatalf("windows ADS colon accepted")
	}
}

func TestScopeRelativeAndContainment(t *testing.T) {
	if scopeRelative("a/b/c.txt", "a/b") != "c.txt" {
		t.Fatal("scopeRelative strip failed")
	}
	if scopeRelative("a/b/c.txt", "") != "a/b/c.txt" {
		t.Fatal("scopeRelative empty root failed")
	}
	if withinRelativeRoot("a/bc/x", "a/b") {
		t.Fatal("segment-boundary containment breached")
	}
	if !withinRelativeRoot("a/b/x", "a/b") {
		t.Fatal("valid containment rejected")
	}
}

func TestDiscoverReadAndSymlinkRejection(t *testing.T) {
	ctx := context.Background()
	connector := New()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}

	scope, err := NewScope(ScopeParams{
		RootPath: root, Platform: hostPlatformForTest(), Access: AccessWorkspaceManaged,
		Recursive: true, MaxFileBytes: 1 << 20, Formats: []Format{FormatTXT},
	})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := connector.Discover(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(discovery.Objects) != 1 || discovery.Objects[0].RelativePath != "docs/a.txt" {
		t.Fatalf("unexpected discovery: %+v", discovery.Objects)
	}
	result, quarantine, err := connector.Read(ctx, scope, "docs/a.txt")
	if err != nil || quarantine != nil || string(result.Content) != "alpha" {
		t.Fatalf("read: err=%v q=%+v content=%q", err, quarantine, result.Content)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "docs", "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	discovery, err = connector.Discover(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range discovery.Objects {
		if strings.Contains(object.RelativePath, "link") || strings.Contains(object.RelativePath, "secret") {
			t.Fatalf("symlink target traversed: %s", object.RelativePath)
		}
	}
}

func hostPlatformForTest() Platform {
	if os.PathSeparator == '\\' {
		return PlatformWindows
	}
	return PlatformPOSIX
}

// TestDiscoverReportsCompleteCoverage proves a fully enumerable tree is reported
// Complete, and that a file-level quarantine (an object observed but deliberately
// not admitted) does not clear Complete — only a directory-level gap can.
func TestDiscoverReportsCompleteCoverage(t *testing.T) {
	ctx := context.Background()
	connector := New()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "sub", "b.txt"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An oversized object: observed, quarantined at the file level, identity known.
	if err := os.WriteFile(filepath.Join(root, "docs", "big.txt"), []byte("way too large"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope, err := NewScope(ScopeParams{
		RootPath: root, Platform: hostPlatformForTest(), Access: AccessWorkspaceManaged,
		Recursive: true, MaxFileBytes: 5, Formats: []Format{FormatTXT},
	})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := connector.Discover(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if !discovery.Complete {
		t.Fatalf("fully enumerable tree reported partial: %+v", discovery.Quarantined)
	}
	var oversized bool
	for _, q := range discovery.Quarantined {
		if q.Code == QuarantineOversized {
			oversized = true
		}
	}
	if !oversized {
		t.Fatal("expected the oversized object to be quarantined")
	}
	if !discovery.Complete {
		t.Fatal("a file-level quarantine must not clear Complete")
	}
}

// TestDiscoverPartialOnMissingRelativeRoot proves that a scope whose relative_root
// subtree cannot be resolved yields a PARTIAL scan (Complete=false) with no
// objects — the authoritative-absence boundary: nothing may be inferred deleted.
func TestDiscoverPartialOnMissingRelativeRoot(t *testing.T) {
	ctx := context.Background()
	connector := New()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "present"), 0o755); err != nil {
		t.Fatal(err)
	}
	scope, err := NewScope(ScopeParams{
		RootPath: root, Platform: hostPlatformForTest(), Access: AccessWorkspaceManaged,
		RelativeRoot: "present/missing", Recursive: true, MaxFileBytes: 1 << 20, Formats: []Format{FormatTXT},
	})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := connector.Discover(ctx, scope)
	if err != nil {
		t.Fatalf("missing relative_root should be a partial scan, not a hard error: %v", err)
	}
	if discovery.Complete {
		t.Fatal("an unresolvable relative_root must not be reported Complete")
	}
	if len(discovery.Objects) != 0 {
		t.Fatalf("a partial scan of a missing subtree found objects: %+v", discovery.Objects)
	}
}

// TestDiscoverPartialOnUnreadableSubtree proves that a subtree the pass cannot
// enumerate makes the whole scan PARTIAL while the readable siblings are still
// discovered. It is skipped where directory permissions are not enforced (root or
// a filesystem that ignores the mode change).
func TestDiscoverPartialOnUnreadableSubtree(t *testing.T) {
	if hostPlatformForTest() == PlatformWindows {
		t.Skip("POSIX directory-permission semantics required")
	}
	ctx := context.Background()
	connector := New()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "readable"), 0o755); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "readable", "seen.txt"), []byte("seen"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "hidden.txt"), []byte("hidden"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Skipf("cannot remove directory permission: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	// Probe: if the mode change is not enforced (running as root), skip.
	if f, probeErr := os.Open(blocked); probeErr == nil {
		_ = f.Close()
		t.Skip("directory permissions not enforced in this environment")
	}
	discovery, err := connector.Discover(ctx, scope(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Complete {
		t.Fatal("a scan with an unreadable subtree must be reported partial")
	}
	var sawSeen bool
	for _, object := range discovery.Objects {
		if object.RelativePath == "readable/seen.txt" {
			sawSeen = true
		}
		if object.RelativePath == "blocked/hidden.txt" {
			t.Fatal("an object under the unreadable subtree was somehow enumerated")
		}
	}
	if !sawSeen {
		t.Fatal("the readable sibling was not discovered")
	}
}

func scope(t *testing.T, root string) *Scope {
	t.Helper()
	s, err := NewScope(ScopeParams{
		RootPath: root, Platform: hostPlatformForTest(), Access: AccessWorkspaceManaged,
		Recursive: true, MaxFileBytes: 1 << 20, Formats: []Format{FormatTXT},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
