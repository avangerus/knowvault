package pdfrenderworker_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderworker"
)

const (
	renderHash  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	renderRev   = "pdf-render-v1"
	onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)

const helperSource = `package main

import (
 "fmt"
 "os"
 "strings"
)

const hash = "` + renderHash + `"
const rev = "` + renderRev + `"
const png = "` + onePixelPNG + `"

func main() {
 mode := os.Args[1]
 if mode == "flags" {
  required := []string{"--format=PDF", "--renderer-profile-revision=" + rev, "--max-pages=3", "--max-decoded-pixels=10"}
  for _, want := range required { found := false; for _, arg := range os.Args[2:] { if arg == want { found = true } }; if !found { os.Exit(3) } }
 }
 if mode == "garbage" { fmt.Print("not json"); return }
 if mode == "wrong" { fmt.Printf(` + "`" + `{"result_version":"pdf-render-result-v1","observed_format":"PDF","renderer":{"name":"fake","version":"1","artifact_hash":"sha256:%s","renderer_profile_revision":"%s"},"pages":[],"warnings":[]}` + "`" + `, strings.Repeat("2", 64), rev); return }
 fmt.Printf(` + "`" + `{"result_version":"pdf-render-result-v1","observed_format":"PDF","renderer":{"name":"fake-renderer","version":"1.0.0","artifact_hash":"%s","renderer_profile_revision":"%s"},"pages":[{"ordinal":1,"page":1,"pixel_width":1,"pixel_height":1,"png_base64":"%s"}],"warnings":[]}` + "`" + `, hash, rev, png)
}
`

func helper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(helperSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fakepdfrender\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "fakepdfrender")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v: %s", err, output)
	}
	return binary
}

func invoker(t *testing.T, binary, mode string) *pdfrenderworker.Invoker {
	t.Helper()
	value, err := pdfrenderworker.New(pdfrenderworker.Config{Command: []string{binary, mode}, ArtifactHash: renderHash, RendererProfileRevision: renderRev, Timeout: 5 * time.Second, MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20, MaxPages: 3, MaxDecodedPixels: 10})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return value
}

func TestExtractBindsRenderFlagsAndPNG(t *testing.T) {
	result, err := invoker(t, helper(t), "flags").Extract(context.Background(), pdfrenderparser.FormatPDF, []byte("pdf"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(result.Pages) != 1 || result.Pages[0].PixelWidth != 1 || len(result.Pages[0].PNGBytes) == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestExtractRejectsWrongIdentityAndMalformedResult(t *testing.T) {
	for _, mode := range []string{"wrong", "garbage"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := invoker(t, helper(t), mode).Extract(context.Background(), pdfrenderparser.FormatPDF, []byte("pdf")); err == nil {
				t.Fatal("malformed render result accepted")
			}
		})
	}
	if _, err := invoker(t, helper(t), "flags").Extract(context.Background(), "PNG", []byte("pdf")); err == nil {
		t.Fatal("non-PDF input accepted")
	}
	if _, err := invoker(t, helper(t), "flags").Extract(context.Background(), pdfrenderparser.FormatPDF, nil); err == nil {
		t.Fatal("empty PDF accepted")
	}
	if strings.TrimSpace(renderHash) == "" {
		t.Fatal("test identity missing")
	}
}
