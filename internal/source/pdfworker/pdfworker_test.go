package pdfworker_test

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
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfworker"
)

const pinnedHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const pinnedRevision = "pdf-obs-v1"

const (
	maxPDFPages      = 10000
	maxPDFRectangles = 4096
	maxPDFObjects    = 1000000
	maxPagePoints    = 14400
	maxOutputBytes   = 1 << 20
)

// fakePDFSandboxSource is compiled into a real process so these tests exercise the
// same command, stream, timeout and identity boundary used by the production facade.
// It is deliberately a plain observer: no canonical text, offsets, hashes or anchors
// are emitted by the helper.
const fakePDFSandboxSource = `package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

const pinnedHash = "__PINNED_HASH__"
const pinnedRevision = "__PINNED_REVISION__"

const result = ` + "`" + `{"result_version":"pdf-parser-result-v1","observed_format":"%s",` +
	`"parser":{"name":"fake-pdf","version":"1.0","artifact_hash":"%s","observation_profile_revision":"%s"},` +
	`"text_units":[{"ordinal":1,"locator":{"kind":"PDF","page":1,"page_width":612,"page_height":792,"rotation":0,` +
	`"bounding_boxes":[{"x":72,"y":144,"width":24,"height":12,"coordinate_unit":"PDF_POINT","coordinate_origin":"TOP_LEFT"}]},` +
	`"raw_text":"%s"}],"warnings":[]}` + "`" + `

func main() {
	mode := os.Args[1]
	format := "PDF"
	profile := ""
	for _, arg := range os.Args[2:] {
		if strings.HasPrefix(arg, "--format=") {
			format = strings.TrimPrefix(arg, "--format=")
		}
		if strings.HasPrefix(arg, "--observation-profile-revision=") {
			profile = strings.TrimPrefix(arg, "--observation-profile-revision=")
		}
	}
	switch mode {
	case "ok":
		fmt.Printf(result, format, pinnedHash, pinnedRevision, "Hello PDF")
	case "requires-flags":
		required := []string{
			"--format=PDF",
			"--observation-profile-revision=" + pinnedRevision,
			"--max-pdf-pages=10000",
			"--max-pdf-boxes=4096",
			"--max-pdf-objects=1000000",
			"--max-page-points=14400",
			"--max-output-bytes=1048576",
		}
		args := os.Args[2:]
		for _, want := range required {
			found := false
			for _, arg := range args {
				if arg == want {
					found = true
					break
				}
			}
			if !found {
				os.Exit(3)
			}
		}
		if format != "PDF" || profile != pinnedRevision {
			os.Exit(3)
		}
		fmt.Printf(result, format, pinnedHash, pinnedRevision, "Hello PDF")
	case "raw-nfd":
		fmt.Printf(result, format, pinnedHash, pinnedRevision, string([]rune{0x0065, 0x0301}))
	case "wrong-identity":
		fmt.Printf(result, format, "sha256:2222222222222222222222222222222222222222222222222222222222222222", pinnedRevision, "Hello PDF")
	case "wrong-revision":
		fmt.Printf(result, format, pinnedHash, "pdf-obs-v9", "Hello PDF")
	case "wrong-format":
		fmt.Printf(result, "DOCX", pinnedHash, pinnedRevision, "Hello PDF")
	case "smuggled-id":
		fmt.Print(` + "`" + `{"result_version":"pdf-parser-result-v1","source_version_id":"v-1"}` + "`" + `)
	case "garbage":
		fmt.Print("not json")
	case "flood":
		fmt.Print(strings.Repeat("x", 4<<20))
	case "stderr-flood":
		fmt.Fprint(os.Stderr, strings.Repeat("leaked document text ", 100000))
		fmt.Printf(result, format, pinnedHash, pinnedRevision, "Hello PDF")
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

func buildFakeSandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := strings.NewReplacer(
		"__PINNED_HASH__", pinnedHash,
		"__PINNED_REVISION__", pinnedRevision,
	).Replace(fakePDFSandboxSource)
	if strings.Contains(source, "__PINNED_") {
		t.Fatal("fake PDF sandbox template placeholders were not substituted")
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fakepdfsandbox\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fakepdfsandbox")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = dir
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("cannot build fake PDF sandbox helper: %v: %s", err, output)
	}
	return binary
}

func invoker(t *testing.T, binary, mode string) *pdfworker.Invoker {
	t.Helper()
	in, err := pdfworker.New(pdfworker.Config{
		Command:                    []string{binary, mode},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    10 * time.Second,
		MaxPDFPages:                maxPDFPages,
		MaxPDFRectangles:           maxPDFRectangles,
		MaxPDFObjects:              maxPDFObjects,
		MaxPagePoints:              maxPagePoints,
		MaxOutputBytes:             maxOutputBytes,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return in
}

func TestNewRequiresAFullyPinnedPDFSandbox(t *testing.T) {
	base := pdfworker.Config{
		Command:                    []string{"sandbox"},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    time.Second,
		MaxPDFPages:                maxPDFPages,
		MaxPDFRectangles:           maxPDFRectangles,
		MaxPDFObjects:              maxPDFObjects,
		MaxPagePoints:              maxPagePoints,
		MaxOutputBytes:             1024,
	}
	if _, err := pdfworker.New(base); err != nil {
		t.Fatalf("fully pinned PDF configuration was rejected: %v", err)
	}
	upperBoundary := base
	upperBoundary.MaxOutputBytes = 16 << 20
	if _, err := pdfworker.New(upperBoundary); err != nil {
		t.Fatalf("maximum bounded PDF output was rejected: %v", err)
	}
	cases := map[string]func(*pdfworker.Config){
		"no command":            func(c *pdfworker.Config) { c.Command = nil },
		"empty command":         func(c *pdfworker.Config) { c.Command = []string{""} },
		"unpinned artifact":     func(c *pdfworker.Config) { c.ArtifactHash = "" },
		"malformed artifact":    func(c *pdfworker.Config) { c.ArtifactHash = "sha256:zz" },
		"uppercase artifact":    func(c *pdfworker.Config) { c.ArtifactHash = strings.ToUpper(pinnedHash) },
		"unpinned observation":  func(c *pdfworker.Config) { c.ObservationProfileRevision = "" },
		"unbounded wall clock":  func(c *pdfworker.Config) { c.Timeout = 0 },
		"unbounded output size": func(c *pdfworker.Config) { c.MaxOutputBytes = 0 },
		"negative output size":  func(c *pdfworker.Config) { c.MaxOutputBytes = -1 },
		"unbounded PDF pages":   func(c *pdfworker.Config) { c.MaxPDFPages = 0 },
		"too many PDF pages":    func(c *pdfworker.Config) { c.MaxPDFPages = pdfparser.MaxTextUnits + 1 },
		"unbounded rectangles":  func(c *pdfworker.Config) { c.MaxPDFRectangles = 0 },
		"too many rectangles":   func(c *pdfworker.Config) { c.MaxPDFRectangles = pdfparser.MaxPDFRectangles + 1 },
		"unbounded PDF objects": func(c *pdfworker.Config) { c.MaxPDFObjects = 0 },
		"too many PDF objects":  func(c *pdfworker.Config) { c.MaxPDFObjects = maxPDFObjects + 1 },
		"unbounded page points": func(c *pdfworker.Config) { c.MaxPagePoints = 0 },
		"too many page points":  func(c *pdfworker.Config) { c.MaxPagePoints = maxPagePoints + 1 },
		"too much output":       func(c *pdfworker.Config) { c.MaxOutputBytes = 16<<20 + 1 },
		"negative wall clock":   func(c *pdfworker.Config) { c.Timeout = -time.Second },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			config.Command = append([]string{}, base.Command...)
			mutate(&config)
			if _, err := pdfworker.New(config); err == nil {
				t.Fatalf("invalid PDF sandbox configuration %q was accepted", name)
			}
		})
	}
}

func TestExtractBindsPDFFlagsAndCanonicalizesObservation(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "requires-flags").Extract(context.Background(), pdfparser.FormatPDF, []byte("document"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if result.ObservedFormat != pdfparser.FormatPDF || len(result.Fragments) != 1 {
		t.Fatalf("unexpected PDF result: %+v", result)
	}
	if string(result.Fragments[0].CanonicalText) != "Hello PDF" {
		t.Fatalf("unexpected canonical text: %q", result.Fragments[0].CanonicalText)
	}
	if result.Fragments[0].Anchor.PageWidth != 612 || result.Fragments[0].Anchor.PageHeight != 792 ||
		result.Fragments[0].Anchor.Rotation != 0 {
		t.Fatalf("page geometry was not retained: %+v", result.Fragments[0].Anchor)
	}
	if result.ObjectTextHash != canon.Hash([]byte("Hello PDF")) {
		t.Fatal("object hash did not come from canon")
	}
}

func TestExtractCanonicalizesRawObserverText(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "raw-nfd").Extract(context.Background(), pdfparser.FormatPDF, []byte("document"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if got := string(result.Fragments[0].CanonicalText); got != string([]rune{0x00e9}) {
		t.Fatalf("observer text was not canonicalized by Go: %q", got)
	}
}

func TestExtractRejectsOtherIdentitiesAndMalformedObservations(t *testing.T) {
	binary := buildFakeSandbox(t)
	for _, mode := range []string{
		"wrong-identity", "wrong-revision", "wrong-format", "smuggled-id", "garbage", "flood", "exit-nonzero",
	} {
		t.Run(mode, func(t *testing.T) {
			if _, err := invoker(t, binary, mode).Extract(context.Background(), pdfparser.FormatPDF, []byte("document")); err == nil {
				t.Fatalf("malformed PDF observation %q was accepted", mode)
			}
		})
	}
}

func TestExtractDropsDiagnosticsAndEnforcesWallClock(t *testing.T) {
	binary := buildFakeSandbox(t)
	result, err := invoker(t, binary, "stderr-flood").Extract(context.Background(), pdfparser.FormatPDF, []byte("document"))
	if err != nil || string(result.Fragments[0].CanonicalText) != "Hello PDF" {
		t.Fatalf("diagnostic output changed a valid PDF result: %v", err)
	}

	in, err := pdfworker.New(pdfworker.Config{
		Command:                    []string{binary, "hang"},
		ArtifactHash:               pinnedHash,
		ObservationProfileRevision: pinnedRevision,
		Timeout:                    500 * time.Millisecond,
		MaxPDFPages:                maxPDFPages,
		MaxPDFRectangles:           maxPDFRectangles,
		MaxPDFObjects:              maxPDFObjects,
		MaxPagePoints:              maxPagePoints,
		MaxOutputBytes:             maxOutputBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := in.Extract(context.Background(), pdfparser.FormatPDF, []byte("document")); err == nil {
		t.Fatal("hung PDF sandbox was accepted")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("PDF sandbox was not killed on the wall clock: %s", elapsed)
	}
}

func TestExtractRefusesNonPDFDispatchWithoutFallback(t *testing.T) {
	binary := buildFakeSandbox(t)
	in := invoker(t, binary, "ok")
	for _, format := range []string{"DOCX", "TEXT", "OCR", "", "PDF_RENDER"} {
		if _, err := in.Extract(context.Background(), format, []byte("document")); err == nil {
			t.Fatalf("non-PDF format %q reached or passed the PDF facade", format)
		}
	}
	if _, err := in.Extract(context.Background(), pdfparser.FormatPDF, nil); err == nil {
		t.Fatal("empty PDF input was accepted")
	}
}
