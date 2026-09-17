//go:build linux

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/tests/integration/parserv2harness"
)

const ocrWorkerImageEnv = "KNOWVAULT_TEST_OCR_WORKER_IMAGE"

// liveOCRPNG creates a deterministic high-contrast page containing the text
// "WASTE 125". The bytes are handed to the real OCR image over DispatcherV2
// and are never persisted by the worker or dispatcher.
func liveOCRPNG() ([]byte, error) {
	const scale = 40
	glyphs := map[byte][7]string{
		'W': {"10001", "10001", "10001", "10101", "10101", "11011", "10001"},
		'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
		'S': {"01111", "10000", "10000", "01110", "00001", "00001", "11110"},
		'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
		'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
		'1': {"00100", "01100", "00100", "00100", "00100", "00100", "01110"},
		// A closed, blocky 2 survives PDFBox's RGB rasterization without
		// becoming a 4 at the fixed render scale.
		'2': {"11110", "00001", "00001", "01110", "10000", "10000", "11111"},
		'5': {"11111", "10000", "10000", "11110", "00001", "00001", "11110"},
	}
	const text = "WASTE 125"
	img := image.NewRGBA(image.Rect(0, 0, len(text)*6*scale+80, 9*scale))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.Set(x, y, color.White)
		}
	}
	x0, y0 := 40, 40
	for i := 0; i < len(text); i++ {
		char := text[i]
		if char == ' ' {
			x0 += 3 * scale
			continue
		}
		glyph := glyphs[char]
		for row, bits := range glyph {
			for col := 0; col < len(bits); col++ {
				if bits[col] != '1' {
					continue
				}
				for yy := 0; yy < scale; yy++ {
					for xx := 0; xx < scale; xx++ {
						img.Set(x0+col*scale+xx, y0+row*scale+yy, color.Black)
					}
				}
			}
		}
		x0 += 6 * scale
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, img); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}

func TestS2dOCRDispatcherV2Real(t *testing.T) {
	imageName := strings.TrimSpace(os.Getenv(ocrWorkerImageEnv))
	if imageName == "" {
		// v3 is the current candidate whose worker identity is bound to the
		// checked-in lock/SBOM. The old v2 tag is intentionally not a fallback:
		// it can make a live gate select an obsolete artifact.
		imageName = "knowvault-tesseract-ocr:gauntlet-20260829-v3"
	}
	harness := parserv2harness.New(t, imageName)
	pngBytes, err := liveOCRPNG()
	if err != nil {
		t.Fatalf("encode live OCR input: %v", err)
	}
	// The production registry pins a 120-second lease window. The caller fence
	// must therefore be at least that long; the worker itself remains bounded by
	// the registry's exact deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	result, err := submitQualificationOCR(ctx, harness.SubmitSocketPath(), pngBytes)
	if err != nil {
		t.Fatalf("real DispatcherV2 OCR extraction: %v", err)
	}
	if result.Parser.ArtifactHash != parserv2harness.QualifiedOCRArtifactHash {
		t.Fatalf("worker artifact identity was not preserved: %s", result.Parser.ArtifactHash)
	}
	if result.OCR.ModelID != "eng" || result.OCR.ModelRevision != "tessdata-v1" || result.OCR.ProfileRevision != "tessdata-v1" {
		t.Fatalf("unexpected OCR identity: %#v", result.OCR)
	}
	if len(result.Pages) != 1 || len(result.Pages[0].Tokens) < 1 {
		t.Fatalf("real OCR returned no evidence tokens: %#v", result.Pages)
	}
	var joined strings.Builder
	for _, token := range result.Pages[0].Tokens {
		joined.WriteString(token.CanonicalTokenText)
	}
	if !strings.Contains(joined.String(), "125") {
		t.Fatalf("real OCR did not recover the numeric evidence: %q", joined.String())
	}
}

// submitQualificationOCR is intentionally test-owned. The OCR image remains
// EVIDENCE_ONLY until its reproducibility, offline provenance and vulnerability
// gates close, so the production registry must not expose an OCR adapter. This
// helper still exercises the exact public DispatcherV2 submit protocol and the
// Go-owned result parser against the real image; it is not a fake extractor.
func submitQualificationOCR(ctx context.Context, socketPath string, document []byte) (*ocrparser.Result, error) {
	if ctx == nil || socketPath == "" || len(document) == 0 {
		return nil, errQualificationOCR
	}
	request := sandboxdispatch.ParserRequestV1{
		SchemaVersion:              sandboxdispatch.ParserRequestVersionV1,
		ParserType:                 sandboxdispatch.ParserTypeOCR,
		Operation:                  sandboxdispatch.OperationObserveOCRTokens,
		MediaFamily:                ocrparser.FormatPNG,
		SandboxProfileRevision:     "ocr-sandbox-v1",
		ObservationProfileRevision: "ocr-observation-v1",
		OCRProfileRevision:         "tessdata-v1",
		MaxInputBytes:              32 << 20,
		MaxOutputBytes:             8 << 20,
		MaxUnits:                   100000,
		MaxPages:                   1,
		MaxDecodedPixels:           100_000_000,
		OutputContract:             "ocr-result-v1",
	}
	jobID, err := randomQualificationID()
	if err != nil {
		return nil, err
	}
	leaseID, err := randomQualificationID()
	if err != nil {
		return nil, err
	}
	artifactID, err := randomQualificationID()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(document)
	now := time.Now().UTC()
	job := sandboxdispatch.JobV2{
		SchemaVersion:        sandboxdispatch.JobVersionV2,
		JobID:                jobID,
		LeaseID:              leaseID,
		ParserRequest:        request,
		InputArtifact:        sandboxdispatch.InputArtifact{ArtifactID: artifactID, ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), MediaType: "image/png"},
		SubmittedAt:          now.Format(time.RFC3339Nano),
		DeadlineAt:           now.Add(120 * time.Second).Format(time.RFC3339Nano),
		WorkerPullOnly:       true,
		ContainerCreationCap: "FORBIDDEN",
	}
	submitter := &sandboxdispatch.Submitter{V2SubmitSocketPath: socketPath, MaxPayloadBytes: 64 << 20, FrameTimeout: 5 * time.Second}
	relay, retryable, err := submitter.SubmitV2(ctx, job, document)
	if err != nil || retryable || relay.Outcome.Handoff.TransferState != sandboxdispatch.TransferConfirmed || len(relay.Result) == 0 {
		return nil, errQualificationOCR
	}
	return ocrparser.Parse(relay.Result, ocrparser.FormatPNG)
}

var errQualificationOCR = errors.New("qualification OCR exchange failed")

func randomQualificationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "q" + hex.EncodeToString(raw[:]), nil
}
