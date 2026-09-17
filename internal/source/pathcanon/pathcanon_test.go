package pathcanon_test

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/pathcanon"
	"knowvault.local/verified-workspace/internal/source/scopeglob"
)

// vector is one parity case: whether the path is canonical under a given case.
type vector struct {
	name   string
	raw    string
	mode   pathcanon.Case
	accept bool
}

// parityVectors cover every dimension the S1d charter requires one normative
// semantics for: relative root, separators, Unicode NFC, dot segments, Windows
// special cases, per-platform case behaviour, and control characters.
func parityVectors() []vector {
	return []vector{
		{"relative root", "projects/alpha/spec.txt", pathcanon.CaseSensitive, true},
		{"single segment", "notes.txt", pathcanon.CaseSensitive, true},
		{"empty", "", pathcanon.CaseSensitive, false},
		{"leading slash", "/projects/a", pathcanon.CaseSensitive, false},
		{"trailing slash", "projects/a/", pathcanon.CaseSensitive, false},
		{"backslash separator", "projects\\a", pathcanon.CaseSensitive, false},
		{"dot segment", "projects/./a", pathcanon.CaseSensitive, false},
		{"dotdot segment", "projects/../a", pathcanon.CaseSensitive, false},
		{"lone dot", ".", pathcanon.CaseSensitive, false},
		{"empty segment", "projects//a", pathcanon.CaseSensitive, false},
		{"control char", "projects/a\x01b", pathcanon.CaseSensitive, false},
		{"nul", "projects/a\x00b", pathcanon.CaseSensitive, false},
		// Case behaviour: reserved names and colons are POSIX-legal but Windows-illegal.
		{"posix allows CON", "CON/data", pathcanon.CaseSensitive, true},
		{"posix allows colon", "a:b/data", pathcanon.CaseSensitive, true},
		{"windows rejects CON", "CON/data", pathcanon.CaseWindows, false},
		{"windows rejects con lowercase", "con.txt", pathcanon.CaseWindows, false},
		{"windows rejects COM1", "COM1", pathcanon.CaseWindows, false},
		{"windows rejects colon ADS", "a:b/data", pathcanon.CaseWindows, false},
		{"windows rejects trailing dot", "name./data", pathcanon.CaseWindows, false},
		{"windows rejects trailing space", "name /data", pathcanon.CaseWindows, false},
		{"windows rejects angle", "a<b/data", pathcanon.CaseWindows, false},
		{"windows allows normal", "projects/alpha", pathcanon.CaseWindows, true},
	}
}

// TestPathRejectsNonNFC proves the Unicode dimension without ambiguous source
// literals: the same grapheme in NFD (e + U+0301) is rejected while its NFC form
// (U+00E9) is accepted, so a durable identity path is always the composed form.
func TestPathRejectsNonNFC(t *testing.T) {
	nfd := "caf" + string(rune(0x65)) + string(rune(0x0301)) + "/x"
	nfc := "caf" + string(rune(0x00e9)) + "/x"
	if _, err := pathcanon.Path(nfd, pathcanon.CaseSensitive); err == nil {
		t.Fatal("NFD (decomposed) path was accepted; identity would not be canonical")
	}
	if _, err := pathcanon.Path(nfc, pathcanon.CaseSensitive); err != nil {
		t.Fatalf("NFC (composed) path rejected: %v", err)
	}
}

func TestPathParityVectors(t *testing.T) {
	for _, v := range parityVectors() {
		_, err := pathcanon.Path(v.raw, v.mode)
		if (err == nil) != v.accept {
			t.Errorf("%s: pathcanon.Path accept=%v, want %v", v.name, err == nil, v.accept)
		}
	}
}

// TestServerAndCatalogAgreeWithPathcanon proves the server-side scope-glob
// matcher (which the connector also uses) and the catalog identity path both
// route through the exact same normative semantics: for every vector, the
// matcher accepts a path iff pathcanon does. An empty include set matches the
// whole root, so scopeglob.Match succeeds exactly when canonicalization succeeds.
func TestServerAndCatalogAgreeWithPathcanon(t *testing.T) {
	for _, v := range parityVectors() {
		mode := scopeglob.CaseSensitive
		if v.mode == pathcanon.CaseWindows {
			mode = scopeglob.CaseWindows
		}
		matcher, err := scopeglob.Compile(nil, nil, mode)
		if err != nil {
			t.Fatalf("%s: compile: %v", v.name, err)
		}
		_, matchErr := matcher.Match(v.raw)
		canonical := func() bool { _, e := pathcanon.Path(v.raw, v.mode); return e == nil }()
		if (matchErr == nil) != canonical {
			t.Errorf("%s: scopeglob matcher accept=%v disagrees with pathcanon accept=%v", v.name, matchErr == nil, canonical)
		}
	}
}

// TestPatternVariantAllowsGlobMetacharacters confirms the pattern entry point
// admits * and ? but still rejects the same structural violations.
func TestPatternVariantAllowsGlobMetacharacters(t *testing.T) {
	if _, err := pathcanon.Pattern("projects/**/*.txt", pathcanon.CaseSensitive); err != nil {
		t.Fatalf("valid glob pattern rejected: %v", err)
	}
	if _, err := pathcanon.Path("projects/*.txt", pathcanon.CaseWindows); err == nil {
		t.Fatal("Path accepted a glob metacharacter path as a literal")
	}
	if _, err := pathcanon.Pattern("projects/a"+strings.Repeat("x", pathcanon.MaxBytes), pathcanon.CaseSensitive); err == nil {
		t.Fatal("Pattern accepted an over-length input")
	}
}
