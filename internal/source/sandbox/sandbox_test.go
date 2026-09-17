package sandbox_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/sandbox"
)

const pinnedHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// helperSource is compiled into a real executable per test run. Building a separate
// process (rather than stubbing an interface) is what lets these tests exercise the
// properties that only exist across a process boundary: exit codes, stream bounds, a
// wall-clock kill, and the fact that the runner passes no environment at all.
const helperSource = `package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	switch os.Args[1] {
	case "ok":
		fmt.Print("RESULT:" + strings.Join(os.Args[2:], ","))
	case "echo-env":
		fmt.Print(strings.Join(os.Environ(), ";"))
	case "echo-stdin":
		buf := make([]byte, 1024)
		n, _ := os.Stdin.Read(buf)
		fmt.Print(string(buf[:n]))
	case "flood":
		fmt.Print(strings.Repeat("x", 4<<20))
	case "stderr-flood":
		fmt.Fprint(os.Stderr, strings.Repeat("leaked document text ", 100000))
		fmt.Print("RESULT:ok")
	case "exit-nonzero":
		fmt.Fprint(os.Stderr, "PACKAGE_UNREADABLE")
		os.Exit(2)
	case "hang":
		time.Sleep(30 * time.Second)
	}
}
`

// buildHelper compiles the helper into a temporary executable.
func buildHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(helperSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module sandboxhelper\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "sandboxhelper")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = dir
	// Deliberately fatal, never a skip: a helper that silently fails to build would
	// turn every cross-process assertion in this file into a green no-op. That exact
	// failure mode already produced one false green in this repository.
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cannot build the sandbox helper: %v: %s", err, output)
	}
	return binary
}

func runner(t *testing.T, binary, mode string, kind sandbox.Kind) *sandbox.Runner {
	t.Helper()
	r, err := sandbox.New(sandbox.Config{
		Kind:           kind,
		Command:        []string{binary, mode},
		ArtifactHash:   pinnedHash,
		Timeout:        10 * time.Second,
		MaxResultBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestNewRequiresAFullyPinnedSandbox(t *testing.T) {
	base := sandbox.Config{
		Kind:           sandbox.KindOffice,
		Command:        []string{"/bin/true"},
		ArtifactHash:   pinnedHash,
		Timeout:        time.Second,
		MaxResultBytes: 1024,
	}
	if _, err := sandbox.New(base); err != nil {
		t.Fatalf("a fully pinned sandbox was rejected: %v", err)
	}

	unpinned := map[string]func(sandbox.Config) sandbox.Config{
		"no kind":            func(c sandbox.Config) sandbox.Config { c.Kind = ""; return c },
		"unknown kind":       func(c sandbox.Config) sandbox.Config { c.Kind = sandbox.Kind("ANYTHING"); return c },
		"no command":         func(c sandbox.Config) sandbox.Config { c.Command = nil; return c },
		"empty command":      func(c sandbox.Config) sandbox.Config { c.Command = []string{""}; return c },
		"no artifact hash":   func(c sandbox.Config) sandbox.Config { c.ArtifactHash = ""; return c },
		"short hash":         func(c sandbox.Config) sandbox.Config { c.ArtifactHash = "sha256:abc"; return c },
		"uppercase hash":     func(c sandbox.Config) sandbox.Config { c.ArtifactHash = strings.ToUpper(pinnedHash); return c },
		"unprefixed hash":    func(c sandbox.Config) sandbox.Config { c.ArtifactHash = strings.Repeat("a", 64); return c },
		"no timeout":         func(c sandbox.Config) sandbox.Config { c.Timeout = 0; return c },
		"negative timeout":   func(c sandbox.Config) sandbox.Config { c.Timeout = -time.Second; return c },
		"unbounded result":   func(c sandbox.Config) sandbox.Config { c.MaxResultBytes = 0; return c },
		"negative max bytes": func(c sandbox.Config) sandbox.Config { c.MaxResultBytes = -1; return c },
	}
	for name, mutate := range unpinned {
		t.Run(name, func(t *testing.T) {
			if _, err := sandbox.New(mutate(base)); !errors.Is(err, sandbox.ErrInvalidConfig) {
				t.Fatalf("unpinned sandbox %q was accepted: %v", name, err)
			}
		})
	}
}

// TestNewCopiesTheCommand proves a caller cannot mutate the pinned argv after
// construction, so the command a document is actually sent to is the command that was
// reviewed. The assertion is made across the real process boundary: the helper prints
// the arguments it was launched with.
func TestNewCopiesTheCommand(t *testing.T) {
	binary := buildHelper(t)
	command := []string{binary, "ok", "marker-original"}
	r, err := sandbox.New(sandbox.Config{
		Kind: sandbox.KindOffice, Command: command, ArtifactHash: pinnedHash,
		Timeout: 10 * time.Second, MaxResultBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	command[2] = "marker-mutated"

	out, err := r.Run(context.Background(), sandbox.KindOffice, nil, []byte("x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	launched := strings.TrimPrefix(string(out), "RESULT:")
	if launched != "marker-original" {
		t.Fatalf("the runner shares its caller's argv slice: launched with %q", launched)
	}
	if r.ArtifactHash() != pinnedHash || r.Kind() != sandbox.KindOffice {
		t.Fatal("pinned identity drifted")
	}
}

// TestRunRefusesAKindItWasNotPinnedFor is the structural half of cross-parser
// isolation: a sandbox configured to observe Office documents cannot be handed OCR
// work, so a misrouted dispatch fails closed instead of sending a document to the
// wrong engine.
func TestRunRefusesAKindItWasNotPinnedFor(t *testing.T) {
	binary := buildHelper(t)
	office := runner(t, binary, "ok", sandbox.KindOffice)
	for _, wrong := range []sandbox.Kind{sandbox.KindPDFText, sandbox.KindPDFRender, sandbox.KindOCR, sandbox.Kind("")} {
		if _, err := office.Run(context.Background(), wrong, nil, []byte("x")); !errors.Is(err, sandbox.ErrRunFailed) {
			t.Fatalf("office sandbox accepted %q work: %v", wrong, err)
		}
	}
	if _, err := office.Run(context.Background(), sandbox.KindOffice, nil, nil); !errors.Is(err, sandbox.ErrRunFailed) {
		t.Fatalf("empty input was accepted: %v", err)
	}
}

// TestRunPassesNoEnvironment proves the emptied environment across a real process
// boundary: an inherited variable could carry a credential or an endpoint into a
// hostile data-plane component.
func TestRunPassesNoEnvironment(t *testing.T) {
	t.Setenv("KNOWVAULT_TEST_SECRET", "super-secret-value")
	binary := buildHelper(t)
	out, err := runner(t, binary, "echo-env", sandbox.KindOffice).
		Run(context.Background(), sandbox.KindOffice, nil, []byte("x"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, entry := range strings.Split(strings.TrimSpace(string(out)), ";") {
		if entry == "" {
			continue
		}
		// Go's exec injects SYSTEMROOT on Windows when Env is empty, because a process
		// cannot start without it. It carries no runtime configuration, so it is the one
		// tolerated entry; anything else means the environment was inherited.
		if runtime.GOOS == "windows" && strings.HasPrefix(strings.ToUpper(entry), "SYSTEMROOT=") {
			continue
		}
		t.Fatalf("the sandbox inherited an environment entry: %q", entry)
	}
	if strings.Contains(string(out), "super-secret-value") {
		t.Fatalf("a runtime secret reached the sandbox: %q", string(out))
	}
}

// TestRunDeliversTheInputAndReturnsRawStdout proves the two things that legitimately
// cross the boundary do cross it, and nothing interprets them on the way.
func TestRunDeliversTheInputAndReturnsRawStdout(t *testing.T) {
	binary := buildHelper(t)
	out, err := runner(t, binary, "echo-stdin", sandbox.KindOCR).
		Run(context.Background(), sandbox.KindOCR, nil, []byte("transient bytes"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != "transient bytes" {
		t.Fatalf("input did not reach the sandbox verbatim: %q", string(out))
	}
}

func TestRunFailsClosed(t *testing.T) {
	binary := buildHelper(t)
	for _, mode := range []string{"flood", "exit-nonzero"} {
		t.Run(mode, func(t *testing.T) {
			_, err := runner(t, binary, mode, sandbox.KindPDFText).
				Run(context.Background(), sandbox.KindPDFText, nil, []byte("x"))
			if !errors.Is(err, sandbox.ErrRunFailed) {
				t.Fatalf("%s was not refused: %v", mode, err)
			}
			// Nothing about why it failed may be recoverable from the error: a parser
			// diagnostic can carry a fragment of the document.
			if err != nil && err.Error() != sandbox.ErrRunFailed.Error() {
				t.Fatalf("the failure leaked detail: %q", err.Error())
			}
		})
	}
}

// TestRunDropsTheDiagnosticStream proves a chatty sandbox cannot fail an otherwise
// correct run, and that nothing it wrote there is retained.
func TestRunDropsTheDiagnosticStream(t *testing.T) {
	binary := buildHelper(t)
	out, err := runner(t, binary, "stderr-flood", sandbox.KindOffice).
		Run(context.Background(), sandbox.KindOffice, nil, []byte("x"))
	if err != nil {
		t.Fatalf("a diagnostic flood failed a valid run: %v", err)
	}
	if strings.Contains(string(out), "leaked document text") {
		t.Fatal("the diagnostic stream reached the result")
	}
}

// TestRunEnforcesTheWallClock proves a hung sandbox is killed rather than holding the
// ingestion worker.
func TestRunEnforcesTheWallClock(t *testing.T) {
	binary := buildHelper(t)
	r, err := sandbox.New(sandbox.Config{
		Kind: sandbox.KindPDFRender, Command: []string{binary, "hang"}, ArtifactHash: pinnedHash,
		Timeout: 250 * time.Millisecond, MaxResultBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := r.Run(context.Background(), sandbox.KindPDFRender, nil, []byte("x")); !errors.Is(err, sandbox.ErrRunFailed) {
		t.Fatalf("a hung sandbox was not refused: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the wall clock did not bound the run: %s", elapsed)
	}
}

func TestValidArtifactHash(t *testing.T) {
	valid := []string{pinnedHash, "sha256:" + strings.Repeat("0", 64), "sha256:" + strings.Repeat("f", 64)}
	for _, value := range valid {
		if !sandbox.ValidArtifactHash(value) {
			t.Fatalf("exact identity rejected: %q", value)
		}
	}
	invalid := []string{
		"", "sha256:", strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65), "sha256:" + strings.Repeat("A", 64),
		"sha512:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("g", 64),
	}
	for _, value := range invalid {
		if sandbox.ValidArtifactHash(value) {
			t.Fatalf("inexact identity accepted: %q", value)
		}
	}
}
