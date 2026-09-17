package pdfrenderparser

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"
)

const (
	renderArtifact = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	renderProfile  = "pdf-render-v1"
)

func pngFixture(t *testing.T, width, height int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func validRender(t *testing.T) string {
	t.Helper()
	return `{"result_version":"pdf-render-result-v1","observed_format":"PDF","renderer":{"name":"knowvault-pdf-renderer","version":"1.0.0","artifact_hash":"` + renderArtifact + `","renderer_profile_revision":"` + renderProfile + `"},"pages":[{"ordinal":1,"page":1,"pixel_width":2,"pixel_height":1,"png_base64":"` + pngFixture(t, 2, 1) + `"}],"warnings":[]}`
}

func TestParseValidatesClosedRenderAndPNGIdentity(t *testing.T) {
	result, err := Parse([]byte(validRender(t)), renderProfile, renderArtifact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(result.Pages) != 1 || result.Pages[0].PixelWidth != 2 || result.Pages[0].PixelHeight != 1 || len(result.Pages[0].PNGBytes) == 0 {
		t.Fatalf("unexpected render result: %+v", result)
	}
	if CanonicalHash(result.Pages[0]) == "" {
		t.Fatal("render page has no immutable digest")
	}
}

func TestParseRejectsRenderBoundaryMutations(t *testing.T) {
	base := validRender(t)
	cases := map[string]string{
		"unknown member":   strings.Replace(base, `"warnings":[]`, `"warnings":[],"source_version_id":"v-1"`, 1),
		"duplicate member": strings.Replace(base, `"observed_format":"PDF"`, `"observed_format":"PDF","observed_format":"PDF"`, 1),
		"wrong artifact":   strings.Replace(base, renderArtifact, "sha256:"+strings.Repeat("2", 64), 1),
		"wrong page order": strings.Replace(base, `"ordinal":1,"page":1`, `"ordinal":2,"page":1`, 1),
		"wrong dimensions": strings.Replace(base, `"pixel_width":2`, `"pixel_width":3`, 1),
		"invalid png":      strings.Replace(base, `"png_base64":"`+pngFixture(t, 2, 1)+`"`, `"png_base64":"aGVsbG8="`, 1),
		"warning code":     strings.Replace(base, `"warnings":[]`, `"warnings":[{"code":"bad"}]`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw), renderProfile, renderArtifact); err != ErrInvalidResult {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
}

func TestParseRejectsUnpinnedExpectedIdentity(t *testing.T) {
	raw := []byte(validRender(t))
	for _, revision := range []string{"", "PDF-RENDER-V1", "pdf render"} {
		if _, err := Parse(raw, revision, renderArtifact); err == nil {
			t.Fatalf("revision %q accepted", revision)
		}
	}
	if _, err := Parse(raw, renderProfile, ""); err == nil {
		t.Fatal("empty artifact accepted")
	}
}
