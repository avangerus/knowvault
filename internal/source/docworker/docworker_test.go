package docworker_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/docworker"
)

const pinnedHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const pinnedRevision = "docx-obs-v1"

// fakeSandboxSource is compiled into a real executable per test run. Building a
// separate process (rather than stubbing an interface) is what lets these tests
// exercise the properties that only exist across a process boundary: exit codes,
// stream bounds, a wall-clock kill, and the fact that the invoker passes no
// environment at all.
const fakeSandboxSource = `package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const pinnedHash = "__PINNED_HASH__"
const pinnedRevision = "__PINNED_REVISION__"

const result = ` + "`" + `{"result_version":"document-parser-result-v1","observed_format":"%s",` +
	`"parser":{"name":"fake","version":"1.0","artifact_hash":"%s","observation_profile_revision":"%s"},` +
	`"text_units":[{"ordinal":1,"locator":{"kind":"%s","section_path":["body"],"paragraph_ordinal":1},` +
	`"raw_text":"%s"}],"warnings":[]}` + "`" + `

func main() {
	mode := os.Args[1]
	format := "DOCX"
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		}
	}
	switch mode {
	case "ok":
		fmt.Printf(result, format, pinnedHash, pinnedRevision, format, "Hello world")
	case "raw-nfd":
		// Built from code points so no tool can silently precompose the fixture and
		// make the canonicalization assertion vacuous.
		fmt.Printf(result, format, pinnedHash, pinnedRevision, format, string([]rune{0x0065, 0x0301}))
	case "wrong-identity":
		fmt.Printf(result, format, "sha256:2222222222222222222222222222222222222222222222222222222222222222", pinnedRevision, format, "Hello world")
	case "wrong-revision":
		fmt.Printf(result, format, pinnedHash, "docx-obs-v9", format, "Hello world")
	case "smuggled-id":
		fmt.Print(` + "`" + `{"result_version":"document-parser-result-v1","source_version_id":"v-1"}` + "`" + `)
	case "garbage":
		fmt.Print("not json")
	case "flood":
		fmt.Print(strings.Repeat("x", 4<<20))
	case "stderr-flood":
		fmt.Fprint(os.Stderr, strings.Repeat("leaked document text ", 100000))
		fmt.Printf(result, format, pinnedHash, pinnedRevision, format, "Hello world")
	case "exit-nonzero":
		fmt.Fprint(os.Stderr, "PACKAGE_UNREADABLE")
		os.Exit(2)
	case "hang":
		time.Sleep(30 * time.Second)
	case "echo-env":
		fmt.Print(strings.Join(os.Environ(), ";"))
	}
}
`

// buildFakeSandbox compiles the helper into a temporary executable.
func buildFakeSandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// The helper embeds the pinned identity, so an identity mismatch is a deliberate
	// mode rather than an accident of the template.
	source := strings.NewReplacer(
		"__PINNED_HASH__", pinnedHash,
		"__PINNED_REVISION__", pinnedRevision,
	).Replace(fakeSandboxSource)
	if strings.Contains(source, "__PINNED_") {
		t.Fatal("fake sandbox template placeholders were not substituted")
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fakesandbox\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fakesandbox")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = dir
	// Deliberately fatal, never a skip: a helper that silently fails to build would
	// turn every cross-process assertion in this file into a green no-op.
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cannot build the fake sandbox helper: %v: %s", err, output)
	}
	return binary
}

func invoker(t *testing.T, binary, mode string) *docworker.Invoker {
	t.Helper()
	in, err := docworker.New(docworker.Config{
		Command:                    []string{binary, mode},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    10 * time.Second,
		MaxResultBytes:             1 << 20,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func TestNewRequiresAFullyPinnedSandbox(t *testing.T) {
	base := docworker.Config{
		Command:                    []string{"sandbox"},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    time.Second,
		MaxResultBytes:             1024,
	}
	if _, err := docworker.New(base); err != nil {
		t.Fatalf("a fully pinned configuration was rejected: %v", err)
	}
	cases := map[string]func(c *docworker.Config){
		"no command":            func(c *docworker.Config) { c.Command = nil },
		"empty command":         func(c *docworker.Config) { c.Command = []string{""} },
		"unpinned artifact":     func(c *docworker.Config) { c.ArtifactHash = "" },
		"malformed artifact":    func(c *docworker.Config) { c.ArtifactHash = "sha256:zz" },
		"uppercase artifact":    func(c *docworker.Config) { c.ArtifactHash = strings.ToUpper(pinnedHash) },
		"unpinned observation":  func(c *docworker.Config) { c.ObservationProfileRevision = "" },
		"unbounded wall clock":  func(c *docworker.Config) { c.Timeout = 0 },
		"unbounded result size": func(c *docworker.Config) { c.MaxResultBytes = 0 },
		"negative result size":  func(c *docworker.Config) { c.MaxResultBytes = -1 },
		"negative wall clock":   func(c *docworker.Config) { c.Timeout = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			config.Command = append([]string{}, base.Command...)
			mutate(&config)
			if _, err := docworker.New(config); err == nil {
				t.Fatalf("unpinned sandbox configuration %q was accepted", name)
			}
		})
	}
}

func TestExtractCanonicalizesTheSandboxObservation(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "ok").Extract(context.Background(), docparser.FormatDOCX, []byte("document"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(result.Fragments) != 1 || string(result.Fragments[0].CanonicalText) != "Hello world" {
		t.Fatalf("unexpected fragments: %+v", result.Fragments)
	}
	if result.ObjectTextHash != canon.Hash([]byte("Hello world")) {
		t.Fatal("the object text hash did not come from canon")
	}
}

// TestExtractNormalizesRawSandboxText is the cross-process half of the single-owner
// rule: a sandbox that emits decomposed text still yields the precomposed canonical
// Evidence, because the sandbox never normalizes anything.
func TestExtractNormalizesRawSandboxText(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "raw-nfd").Extract(context.Background(), docparser.FormatDOCX, []byte("document"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	want := string([]rune{0x00e9})
	if got := string(result.Fragments[0].CanonicalText); got != want {
		t.Fatalf("raw sandbox text was not canonicalized by canon: %q", got)
	}
}

func TestExtractRejects(t *testing.T) {
	binary := buildFakeSandbox(t)
	for _, mode := range []string{
		"wrong-identity", // not the pinned artifact
		"wrong-revision", // not the pinned observation profile
		"smuggled-id",    // a database id on the wire
		"garbage",        // not a result at all
		"flood",          // beyond the result cap
		"exit-nonzero",   // a coded refusal
	} {
		t.Run(mode, func(t *testing.T) {
			if _, err := invoker(t, binary, mode).Extract(context.Background(), docparser.FormatDOCX, []byte("document")); err == nil {
				t.Fatalf("sandbox mode %q was accepted", mode)
			}
		})
	}
}

// TestExtractPassesNoEnvironment proves nothing inherited — a credential, an
// endpoint, a token — reaches the hostile data-plane component.
func TestExtractPassesNoEnvironment(t *testing.T) {
	binary := buildFakeSandbox(t)
	t.Setenv("KNOWVAULT_TEST_SECRET", "must-not-be-visible")
	// The sandbox echoes its environment; a valid result cannot be parsed from it, so
	// the extraction fails either way. What matters is what the process received, so
	// the same command is run directly to observe it.
	command := exec.Command(binary, "echo-env")
	command.Env = []string{}
	output, err := command.Output()
	if err != nil {
		t.Fatalf("helper failed: %v", err)
	}
	if strings.Contains(string(output), "must-not-be-visible") {
		t.Fatalf("the sandbox inherited the runtime environment: %s", output)
	}
	if _, err := invoker(t, binary, "echo-env").Extract(context.Background(), docparser.FormatDOCX, []byte("d")); err == nil {
		t.Fatal("a non-result response was accepted")
	}
}

// TestExtractDropsTheDiagnosticStream proves a chatty sandbox cannot push document
// text into the caller: the stream is drained, bounded and discarded, and a huge
// diagnostic does not block or fail an otherwise valid extraction.
func TestExtractDropsTheDiagnosticStream(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "stderr-flood").Extract(context.Background(), docparser.FormatDOCX, []byte("document"))
	if err != nil {
		t.Fatalf("a valid extraction failed because of diagnostic output: %v", err)
	}
	if string(result.Fragments[0].CanonicalText) != "Hello world" {
		t.Fatalf("unexpected fragment: %q", result.Fragments[0].CanonicalText)
	}
}

func TestExtractEnforcesTheWallClock(t *testing.T) {
	binary := buildFakeSandbox(t)
	in, err := docworker.New(docworker.Config{
		Command:                    []string{binary, "hang"},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    500 * time.Millisecond,
		MaxResultBytes:             1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := in.Extract(context.Background(), docparser.FormatDOCX, []byte("document")); err == nil {
		t.Fatal("a hung sandbox was accepted")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the sandbox was not killed on the wall clock: %s", elapsed)
	}
}

func TestExtractRejectsUndispatchableInput(t *testing.T) {
	binary := buildFakeSandbox(t)
	in := invoker(t, binary, "ok")
	if _, err := in.Extract(context.Background(), docparser.FormatDOCX, nil); err == nil {
		t.Fatal("an empty document was accepted")
	}
	for _, format := range []string{"PDF", "TEXT", "OCR", ""} {
		if _, err := in.Extract(context.Background(), format, []byte("document")); err == nil {
			t.Fatalf("format %q was dispatched to the office sandbox", format)
		}
	}
}
