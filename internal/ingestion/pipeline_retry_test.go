package ingestion

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/format"
	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
)

type retryOfficeExtractor struct{}

func (retryOfficeExtractor) Extract(context.Context, string, []byte) (*docparser.Result, error) {
	return nil, sandboxdispatch.ErrRetryBeforeTransfer
}

// nilOfficeExtractor models a malformed dispatcher envelope. The production
// boundary must quarantine this result; it must never dereference a nil
// parser result or publish an empty observation (PARSER_CONTRACTS.md §2).
type nilOfficeExtractor struct{}

func (nilOfficeExtractor) Extract(context.Context, string, []byte) (*docparser.Result, error) {
	return nil, nil
}

type retryPDFExtractor struct{}

func (retryPDFExtractor) Extract(context.Context, string, []byte) (*pdfparser.Result, error) {
	return nil, sandboxdispatch.ErrRetryBeforeTransfer
}

type scannedPDFExtractor struct{}

func (scannedPDFExtractor) Extract(context.Context, string, []byte) (*pdfparser.Result, error) {
	return nil, pdfparser.ErrScannedOrMixedPDF
}

type testPDFRenderer struct{}

func (testPDFRenderer) Extract(context.Context, string, []byte) (*pdfrenderparser.Result, error) {
	return &pdfrenderparser.Result{
		ObservedFormat: pdfrenderparser.FormatPDF,
		Renderer:       pdfrenderparser.Renderer{Name: "renderer", Version: "1.0", ArtifactHash: "sha256:" + "1" + "111111111111111111111111111111111111111111111111111111111111111", ProfileRevision: "render-v1"},
		Pages:          []pdfrenderparser.Page{{Ordinal: 1, Page: 1, PixelWidth: 1, PixelHeight: 1, PNGBytes: []byte{0x89, 0x50, 0x4e, 0x47}}},
	}, nil
}

type testOCRExtractor struct{}

func (testOCRExtractor) Extract(context.Context, string, []byte) (*ocrparser.Result, error) {
	box := canon.OCRRectangle{X: 0.1, Y: 0.1, Width: 0.2, Height: 0.1}
	anchor, err := canon.OCRAnchorBytes(1, 0, 1, []canon.OCRRectangle{box})
	if err != nil {
		return nil, err
	}
	text := []byte("scanned")
	token := ocrparser.OCRToken{Page: 1, TokenID: "token-0", CanonicalTokenText: "scanned", Ordinal: 0, JoinAfter: "NONE", BoundingBox: box, Confidence: 0.9}
	return &ocrparser.Result{
		ObservedFormat: ocrparser.FormatPNG,
		Parser:         ocrparser.Parser{Name: "ocr", Version: "1.0", ArtifactHash: "sha256:" + "2" + "222222222222222222222222222222222222222222222222222222222222222", ObservationProfileRevision: "ocr-obs-v1"},
		OCR:            ocrparser.OCRIdentity{ModelID: "eng", ModelRevision: "ocr-model-v1", ArtifactHash: "sha256:" + "3" + "333333333333333333333333333333333333333333333333333333333333333", ProfileRevision: "ocr-model-v1"},
		Pages:          []ocrparser.Page{{Page: 1, Tokens: []ocrparser.OCRToken{token}}}, ObjectText: text,
		ObjectTextHash: canon.Hash(text), Fragments: []ocrparser.Fragment{{Ordinal: 1, Page: 1, TokenStartOrdinal: 0, TokenEndOrdinal: 1, CanonicalText: text, AnchorBytes: anchor, Tokens: []ocrparser.OCRToken{token}}},
	}, nil
}

func TestPlanPreservesRetryOnlyBeforeSandboxTransfer(t *testing.T) {
	for name, run := range map[string]func() (bool, bool){
		"office": func() (bool, bool) {
			h := (&Handler{}).WithOfficeExtractor(retryOfficeExtractor{})
			_, _, _, ok, retryable := h.plan(context.Background(), format.RevisionDOCX, "docx-v1", []byte("carrier"))
			return ok, retryable
		},
		"pdf": func() (bool, bool) {
			h := (&Handler{}).WithPDFExtractor(retryPDFExtractor{})
			_, _, _, ok, retryable := h.plan(context.Background(), format.RevisionPDF, "pdf-v1", []byte("carrier"))
			return ok, retryable
		},
	} {
		t.Run(name, func(t *testing.T) {
			ok, retryable := run()
			if ok || !retryable {
				t.Fatalf("pre-transfer unavailability lost: ok=%v retryable=%v", ok, retryable)
			}
		})
	}
}

func TestPlanOfficeNilResultQuarantines(t *testing.T) {
	h := (&Handler{}).WithOfficeExtractor(nilOfficeExtractor{})
	canonical, planned, observer, ok, retryable := h.plan(context.Background(), format.RevisionDOCX, "docx-v1", []byte("carrier"))
	if canonical != "" || len(planned) != 0 || observer != nil || ok || retryable {
		t.Fatalf("nil office observation was not quarantined: canonical=%q units=%d observer=%+v ok=%v retry=%v", canonical, len(planned), observer, ok, retryable)
	}
}

func TestPlanScannedPDFRequiresExplicitClassificationAndRepagesOCR(t *testing.T) {
	h := (&Handler{}).WithPDFExtractor(scannedPDFExtractor{}).WithPDFRenderExtractor(testPDFRenderer{}).WithOCRExtractor(testOCRExtractor{})
	canonical, planned, observer, ok, retryable := h.plan(context.Background(), format.RevisionPDF, "pdf-v1", []byte("pdf"))
	if !ok || retryable || canonical != "OCR" || len(planned) != 1 || observer == nil {
		t.Fatalf("scanned PDF was not composed through render/OCR: canonical=%q units=%d observer=%+v ok=%v retry=%v", canonical, len(planned), observer, ok, retryable)
	}
	if !containsBytes(planned[0].ocrAnchor, []byte(`"page":1`)) || planned[0].ocrProfile == nil {
		t.Fatalf("OCR anchor/profile missing: %+v", planned[0])
	}
	// A generic PDF observer failure must not gain access to the renderer/OCR path.
	h = (&Handler{}).WithPDFExtractor(genericPDFFailureExtractor{}).WithPDFRenderExtractor(testPDFRenderer{}).WithOCRExtractor(testOCRExtractor{})
	if _, _, _, ok, retryable := h.plan(context.Background(), format.RevisionPDF, "pdf-v1", []byte("pdf")); ok || retryable {
		t.Fatalf("generic PDF failure was routed to OCR: ok=%v retry=%v", ok, retryable)
	}
}

type genericPDFFailureExtractor struct{}

func (genericPDFFailureExtractor) Extract(context.Context, string, []byte) (*pdfparser.Result, error) {
	return nil, pdfparser.ErrInvalidResult
}

func containsBytes(value, needle []byte) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		match := true
		for j := range needle {
			if value[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
