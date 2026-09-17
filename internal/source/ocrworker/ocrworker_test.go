package ocrworker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const workerHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const modelHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func TestNewRejectsUnpinnedOCRConfig(t *testing.T) {
	base := Config{Command: []string{"/bin/true"}, ArtifactHash: workerHash, ObservationProfileRevision: "ocr-obs-v1", OCRProfileRevision: "ocr-model-v1", ModelID: "eng", ModelRevision: "4.1.0", ModelArtifactHash: modelHash, Timeout: time.Second, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20}
	if _, err := New(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no model hash", func(c *Config) { c.ModelArtifactHash = "" }},
		{"no observation revision", func(c *Config) { c.ObservationProfileRevision = "" }},
		{"no OCR revision", func(c *Config) { c.OCRProfileRevision = "" }},
		{"zero input limit", func(c *Config) { c.MaxInputBytes = 0 }},
		{"oversized output limit", func(c *Config) { c.MaxOutputBytes = MaxOutputBytes + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			tc.mutate(&candidate)
			if _, err := New(candidate); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("invalid config accepted: %v", err)
			}
		})
	}
}

func TestExtractRejectsWrongMediaBeforeSandbox(t *testing.T) {
	invoker, err := New(Config{Command: []string{"/bin/true"}, ArtifactHash: workerHash, ObservationProfileRevision: "ocr-obs-v1", OCRProfileRevision: "ocr-model-v1", ModelID: "eng", ModelRevision: "4.1.0", ModelArtifactHash: modelHash, Timeout: time.Second, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"PDF", "TEXT", "", "PNG ", "jpeg"} {
		if _, err := invoker.Extract(context.Background(), format, []byte("x")); !errors.Is(err, ErrExtractionFailed) {
			t.Fatalf("format %q was accepted: %v", format, err)
		}
	}
}

func TestExtractUsesRealWorkerBoundaryAndFailsClosedOnBadResult(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "worker.go")
	source := `package main
import "fmt"
func main(){fmt.Print(` + "`" + `{"result_version":"ocr-result-v1"}` + "`" + `)}
`
	if err := os.WriteFile(script, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module ocr-worker-helper\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "worker")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	// A real executable is intentionally used here; the invoker test does not
	// replace the sandbox with an interface or a fake result object.
	if output, err := runGoBuild(dir, binary); err != nil {
		t.Fatalf("build worker: %v: %s", err, output)
	}
	invoker, err := New(Config{Command: []string{binary}, ArtifactHash: workerHash, ObservationProfileRevision: "ocr-obs-v1", OCRProfileRevision: "ocr-model-v1", ModelID: "eng", ModelRevision: "4.1.0", ModelArtifactHash: modelHash, Timeout: time.Second, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invoker.Extract(context.Background(), "PNG", []byte("not-an-image")); !errors.Is(err, ErrExtractionFailed) {
		t.Fatalf("malformed worker output was accepted: %v", err)
	}
}

func runGoBuild(dir, output string) ([]byte, error) {
	command := exec.Command("go", "build", "-o", output, ".")
	command.Dir = dir
	return command.CombinedOutput()
}
