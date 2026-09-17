// Package pdfrenderparser is the Go-owned validation boundary for the
// Isolated page-render observation. The renderer is allowed to return transient
// PNG bytes only; it cannot provide source ids, text, anchors or queryability.
// Every page and identity field is re-validated here before a caller may hand
// a page to the OCR boundary.
package pdfrenderparser

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"image"
	_ "image/png"
	"regexp"

	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	ResultVersion = "pdf-render-result-v1"
	FormatPDF     = "PDF"
	MaxPages      = 10000
	MaxPixels     = 50_000_000
	MaxPagePixels = 50_000_000
	MaxPNGBytes   = 16 << 20
	MaxWarnings   = 4096
)

var ErrInvalidResult = errors.New("pdfrenderparser: renderer result rejected")

var (
	artifactHashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	identityRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	warningCodeRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

type Renderer struct {
	Name            string
	Version         string
	ArtifactHash    string
	ProfileRevision string
}

type Page struct {
	Ordinal     int
	Page        int
	PixelWidth  int
	PixelHeight int
	PNGBytes    []byte
}

type Result struct {
	ObservedFormat string
	Renderer       Renderer
	Pages          []Page
	Warnings       []string
}

type wireResult struct {
	ResultVersion  string         `json:"result_version"`
	ObservedFormat string         `json:"observed_format"`
	Renderer       wireRenderer   `json:"renderer"`
	Pages          []wirePage     `json:"pages"`
	Warnings       *[]wireWarning `json:"warnings"`
}

type wireRenderer struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ArtifactHash    string `json:"artifact_hash"`
	ProfileRevision string `json:"renderer_profile_revision"`
}

type wirePage struct {
	Ordinal     *int   `json:"ordinal"`
	Page        *int   `json:"page"`
	PixelWidth  *int   `json:"pixel_width"`
	PixelHeight *int   `json:"pixel_height"`
	PNGBase64   string `json:"png_base64"`
}

type wireWarning struct {
	Code string `json:"code"`
}

// Parse strictly validates one closed renderer observation. expectedRevision
// and expectedArtifact are supplied by the pinned worker composition; empty
// values are rejected rather than weakening the identity gate.
func Parse(raw []byte, expectedRevision, expectedArtifact string) (*Result, error) {
	if len(raw) == 0 || !revisionRe.MatchString(expectedRevision) || !artifactHashRe.MatchString(expectedArtifact) {
		return nil, ErrInvalidResult
	}
	var wire wireResult
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return nil, ErrInvalidResult
	}
	if wire.ResultVersion != ResultVersion || wire.ObservedFormat != FormatPDF || len(wire.Pages) < 1 || len(wire.Pages) > MaxPages || wire.Warnings == nil || len(*wire.Warnings) > MaxWarnings {
		return nil, ErrInvalidResult
	}
	if !identityRe.MatchString(wire.Renderer.Name) || !identityRe.MatchString(wire.Renderer.Version) || wire.Renderer.ArtifactHash != expectedArtifact || wire.Renderer.ProfileRevision != expectedRevision {
		return nil, ErrInvalidResult
	}
	warnings, ok := validateWarnings(*wire.Warnings)
	if !ok {
		return nil, ErrInvalidResult
	}

	pages := make([]Page, 0, len(wire.Pages))
	var totalPixels int64
	for index, value := range wire.Pages {
		if value.Ordinal == nil || value.Page == nil || value.PixelWidth == nil || value.PixelHeight == nil || *value.Ordinal != index+1 || *value.Page != index+1 || *value.Page < 1 || *value.Page > MaxPages || *value.PixelWidth < 1 || *value.PixelWidth > MaxPagePixels || *value.PixelHeight < 1 || *value.PixelHeight > MaxPagePixels {
			return nil, ErrInvalidResult
		}
		pixels := int64(*value.PixelWidth) * int64(*value.PixelHeight)
		if pixels <= 0 || pixels > MaxPagePixels || totalPixels > MaxPixels-pixels {
			return nil, ErrInvalidResult
		}
		totalPixels += pixels
		pngBytes, width, height, ok := decodePNG(value.PNGBase64)
		if !ok || width != *value.PixelWidth || height != *value.PixelHeight {
			return nil, ErrInvalidResult
		}
		pages = append(pages, Page{Ordinal: *value.Ordinal, Page: *value.Page, PixelWidth: width, PixelHeight: height, PNGBytes: pngBytes})
	}
	return &Result{ObservedFormat: FormatPDF, Renderer: Renderer{Name: wire.Renderer.Name, Version: wire.Renderer.Version, ArtifactHash: wire.Renderer.ArtifactHash, ProfileRevision: wire.Renderer.ProfileRevision}, Pages: pages, Warnings: warnings}, nil
}

func validateWarnings(values []wireWarning) ([]string, bool) {
	out := make([]string, 0, len(values))
	for _, warning := range values {
		if !warningCodeRe.MatchString(warning.Code) {
			return nil, false
		}
		out = append(out, warning.Code)
	}
	return out, true
}

func decodePNG(encoded string) ([]byte, int, int, bool) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(MaxPNGBytes) || bytes.IndexFunc([]byte(encoded), func(r rune) bool { return r == ' ' || r == '\n' || r == '\r' || r == '\t' }) >= 0 {
		return nil, 0, 0, false
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > MaxPNGBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, 0, 0, false
	}
	config, err := pngDecodeConfig(decoded)
	if err != nil || config.Width < 1 || config.Height < 1 || int64(config.Width)*int64(config.Height) > MaxPagePixels {
		return nil, 0, 0, false
	}
	return decoded, config.Width, config.Height, true
}

// pngDecodeConfig is kept as a tiny wrapper so the image/png decoder is linked
// exactly once and malformed/truncated streams are refused, not merely checked
// by their magic bytes.
func pngDecodeConfig(raw []byte) (image.Config, error) {
	config, _, err := image.DecodeConfig(bytes.NewReader(raw))
	return config, err
}

// CanonicalHash is exposed for callers that need an immutable digest of the
// transient render page without persisting the page bytes themselves.
func CanonicalHash(page Page) string { return canon.Hash(page.PNGBytes) }
