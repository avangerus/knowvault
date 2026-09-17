package scopeglob

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatcherSupportsBoundedGrammarAndExcludePrecedence(t *testing.T) {
	matcher, err := Compile([]string{"docs/**", "src/?uth/*.go"}, []string{"**/private/**", "**/*.tmp"}, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"docs/readme.md":       true,
		"docs/a/b/guide.md":    true,
		"docs/private/plan.md": false,
		"docs/cache.tmp":       false,
		"src/auth/login.go":    true,
		"src/oauth/login.go":   false,
		"unrelated/readme.md":  false,
	}
	for path, want := range cases {
		got, matchErr := matcher.Match(path)
		if matchErr != nil || got != want {
			t.Errorf("Match(%q) = %v, %v; want %v", path, got, matchErr, want)
		}
	}
}

func TestEmptyIncludeMeansAllAndGlobstarMatchesZeroSegments(t *testing.T) {
	matcher, err := Compile(nil, []string{"archive/**/deleted.*"}, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"notes/today.md":           true,
		"archive/deleted.txt":      false,
		"archive/2026/deleted.txt": false,
	} {
		got, matchErr := matcher.Match(path)
		if matchErr != nil || got != want {
			t.Errorf("Match(%q) = %v, %v; want %v", path, got, matchErr, want)
		}
	}
}

func TestUnicodeIsNFCAndWindowsModeUsesSimpleFold(t *testing.T) {
	nfc := "caf\u00e9/\u041e\u0442\u0447\u0451\u0442.TXT"
	matcher, err := Compile([]string{"CAFÉ/*.txt"}, nil, CaseWindows)
	if err != nil {
		t.Fatal(err)
	}
	got, matchErr := matcher.Match(nfc)
	if matchErr != nil || !got {
		t.Fatalf("Match(%q) = %v, %v", nfc, got, matchErr)
	}
	sensitive, err := Compile([]string{"CAFÉ/*.txt"}, nil, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := sensitive.Match(nfc); got {
		t.Fatal("case-sensitive matcher folded case")
	}
}

func TestWindowsModeRejectsUnsafeNames(t *testing.T) {
	for _, pattern := range []string{"C:/**", "folder/file:stream", "folder/name.", "CON", "nul.txt", "dir/COM9.log", "LPT1.*"} {
		if _, err := Compile([]string{pattern}, nil, CaseWindows); CodeOf(err) != CodePatternInvalid {
			t.Errorf("Compile(%q) code = %q", pattern, CodeOf(err))
		}
	}
	matcher, err := Compile(nil, nil, CaseWindows)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"C:/Windows/System32", "C:secret", "folder/file:stream", "folder/name.", "folder/name ", "CON", "nul.txt", "dir/COM9.log", "LPT1.any", "CON*", "NUL?", `bad<name`} {
		if allowed, matchErr := matcher.Match(path); allowed || CodeOf(matchErr) != CodePathInvalid {
			t.Errorf("Match(%q) = %v, %v; want fail closed", path, allowed, matchErr)
		}
	}
}

func TestInvalidPatternsFailClosed(t *testing.T) {
	invalid := []string{"", "/root/**", "root/", "a//b", ".", "..", "a/./b", "a/../b", `a\b`, "a ", "a/**x", "a/x**", "a/***", "a/[bc]", "a/{b,c}", "a/@(b)", "!a", "cafe\u0301", "a\x00b", "a\nb", string([]byte{0xff})}
	for _, pattern := range invalid {
		t.Run(fmt.Sprintf("%q", pattern), func(t *testing.T) {
			_, err := Compile([]string{pattern}, nil, CaseSensitive)
			if CodeOf(err) != CodePatternInvalid {
				t.Fatalf("CodeOf(%v) = %q", err, CodeOf(err))
			}
		})
	}
}

func TestInvalidPathsFailClosed(t *testing.T) {
	matcher, err := Compile(nil, nil, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", `a\b`, "cafe\u0301/file", "a\x00b", "a\tb", string([]byte{0xff})} {
		if _, matchErr := matcher.Match(path); CodeOf(matchErr) != CodePathInvalid {
			t.Errorf("Match(%q) code = %q", path, CodeOf(matchErr))
		}
	}
}

func TestLimitsAndInvalidModeFailClosed(t *testing.T) {
	patterns := make([]string, maximumPatterns+1)
	for index := range patterns {
		patterns[index] = fmt.Sprintf("p%d", index)
	}
	if _, err := Compile(patterns, nil, CaseSensitive); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("pattern count code = %q", CodeOf(err))
	}
	if _, err := Compile(nil, nil, CaseMode(99)); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("mode code = %q", CodeOf(err))
	}
	if _, err := Compile([]string{strings.Repeat("a", maximumBytes+1)}, nil, CaseSensitive); CodeOf(err) != CodePatternInvalid {
		t.Fatalf("byte limit code = %q", CodeOf(err))
	}
	segments := strings.Repeat("a/", maximumSegments) + "a"
	if _, err := Compile([]string{segments}, nil, CaseSensitive); CodeOf(err) != CodePatternInvalid {
		t.Fatalf("segment limit code = %q", CodeOf(err))
	}
}

func TestZeroValueAndNilMatcherFailClosed(t *testing.T) {
	var zero Matcher
	for name, matcher := range map[string]*Matcher{
		"nil":       nil,
		"zero":      &zero,
		"allocated": new(Matcher),
	} {
		t.Run(name, func(t *testing.T) {
			allowed, err := matcher.Match("anything")
			if allowed || CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("Match = %v, %v; want fail closed", allowed, err)
			}
		})
	}
}

func TestCompiledMatcherValueCopyRemainsValid(t *testing.T) {
	matcher, err := Compile([]string{"docs/**"}, nil, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	copy := *matcher
	if allowed, matchErr := copy.Match("docs/readme.md"); matchErr != nil || !allowed {
		t.Fatalf("copied matcher = %v, %v", allowed, matchErr)
	}
}

func TestTotalMatchBudgetFailsClosed(t *testing.T) {
	pattern := strings.Repeat("x/", maximumSegments-1) + "y"
	excludes := make([]string, maximumPatterns)
	for index := range excludes {
		excludes[index] = pattern
	}
	matcher, err := Compile(nil, excludes, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	path := strings.Repeat("x/", maximumSegments-1) + "z"
	allowed, matchErr := matcher.Match(path)
	if allowed || CodeOf(matchErr) != CodeMatchLimit {
		t.Fatalf("Match = %v, %v; want bounded fail closed", allowed, matchErr)
	}
}

func TestAdversarialStarsRemainDeterministic(t *testing.T) {
	segment := strings.Repeat("*a", 128) + "*"
	matcher, err := Compile([]string{"**/" + segment}, nil, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	if got, matchErr := matcher.Match("one/two/" + strings.Repeat("a", 128)); matchErr != nil || !got {
		t.Fatalf("adversarial Match = %v, %v", got, matchErr)
	}
}

func TestAcceptedContractGoldenVectors(t *testing.T) {
	type vector struct {
		Pattern       string   `json:"pattern"`
		Path          string   `json:"path"`
		Platform      string   `json:"platform"`
		ExpectedMatch bool     `json:"expected_match"`
		Includes      []string `json:"includes"`
		Excludes      []string `json:"excludes"`
		ExpectedAllow bool     `json:"expected_allowed"`
	}
	var fixture struct {
		Version      string   `json:"vector_version"`
		Vectors      []vector `json:"vectors"`
		AllowVectors []vector `json:"allow_vectors"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "contracts", "fixtures", "golden", "source-scope-glob-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := jsonv2.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != Version {
		t.Fatalf("fixture version = %q, want %q", fixture.Version, Version)
	}
	mode := func(platform string) CaseMode {
		if platform == "WINDOWS" {
			return CaseWindows
		}
		return CaseSensitive
	}
	for _, item := range fixture.Vectors {
		matcher, compileErr := Compile([]string{item.Pattern}, nil, mode(item.Platform))
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		got, matchErr := matcher.Match(item.Path)
		if matchErr != nil || got != item.ExpectedMatch {
			t.Fatalf("vector %q/%q = %v, %v; want %v", item.Pattern, item.Path, got, matchErr, item.ExpectedMatch)
		}
	}
	for _, item := range fixture.AllowVectors {
		matcher, compileErr := Compile(item.Includes, item.Excludes, mode(item.Platform))
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		got, matchErr := matcher.Match(item.Path)
		if matchErr != nil || got != item.ExpectedAllow {
			t.Fatalf("allow vector %q = %v, %v; want %v", item.Path, got, matchErr, item.ExpectedAllow)
		}
	}
}

func TestFormattingAndErrorsAreContentFree(t *testing.T) {
	matcher, err := Compile([]string{"secret-name/**"}, nil, CaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"pointer": matcher, "value": *matcher} {
		if got := fmt.Sprintf("%v %#v", value, value); strings.Contains(got, "secret-name") || got != "scopeglob.Matcher{[REDACTED]} scopeglob.Matcher{[REDACTED]}" {
			t.Fatalf("unsafe %s matcher formatting: %q", name, got)
		}
	}
	_, err = Compile([]string{"bad/**x/private"}, nil, CaseSensitive)
	if err == nil || err.Error() != string(CodePatternInvalid) || strings.Contains(err.Error(), "private") {
		t.Fatalf("unsafe error: %v", err)
	}
	if got := fmt.Sprintf("%v %#v", err, err); got != "SCOPE_GLOB_PATTERN_INVALID scopeglob.Error{[REDACTED]}" {
		t.Fatalf("unsafe error formatting: %q", got)
	}
	value := *err.(*Error)
	if got := fmt.Sprintf("%v %#v", value, value); got != "scopeglob.Error{[REDACTED]} scopeglob.Error{[REDACTED]}" {
		t.Fatalf("unsafe error value formatting: %q", got)
	}
}
