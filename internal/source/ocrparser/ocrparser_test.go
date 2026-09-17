package ocrparser

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const validOCR = "{\n  \"result_version\":\"ocr-result-v1\",\n  \"observed_format\":\"PNG\",\n  \"parser\":{\"name\":\"knowvault-ocr-observer\",\"version\":\"1.0.0\",\"artifact_hash\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"observation_profile_revision\":\"ocr-obs-v1\"},\n  \"ocr\":{\"model_id\":\"eng\",\"model_revision\":\"4.1.0\",\"artifact_hash\":\"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\"profile_revision\":\"ocr-model-v1\"},\n  \"pages\":[{\"page\":1,\"tokens\":[\n    {\"page\":1,\"token_id\":\"ocr-token-0\",\"canonical_token_text\":\"Alpha\",\"ordinal\":0,\"join_after\":\"SPACE\",\"bounding_box\":{\"x\":0.1,\"y\":0.1,\"width\":0.2,\"height\":0.1},\"confidence\":0.99},\n    {\"page\":1,\"token_id\":\"ocr-token-1\",\"canonical_token_text\":\"\u0437\u0430\u043f\u0443\u0441\u043a\",\"ordinal\":1,\"join_after\":\"LINE_BREAK\",\"bounding_box\":{\"x\":0.32,\"y\":0.1,\"width\":0.25,\"height\":0.1},\"confidence\":0.8},\n    {\"page\":1,\"token_id\":\"ocr-token-2\",\"canonical_token_text\":\"\u0433\u043e\u0442\u043e\u0432\",\"ordinal\":2,\"join_after\":\"NONE\",\"bounding_box\":{\"x\":0.1,\"y\":0.25,\"width\":0.2,\"height\":0.1},\"confidence\":1}\n  ],\"warnings\":[]}],\n  \"warnings\":[]\n}"

func TestParseBuildsCanonicalOCRFragments(t *testing.T) {
	result, err := Parse([]byte(validOCR), FormatPNG)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if string(result.ObjectText) != "Alpha \u0437\u0430\u043f\u0443\u0441\u043a\n\u0433\u043e\u0442\u043e\u0432" {
		t.Fatalf("unexpected object text: %q", result.ObjectText)
	}
	if result.ObjectTextHash == "" || len(result.Fragments) != 1 {
		t.Fatalf("unexpected result identity/fragments: %+v", result)
	}
	fragment := result.Fragments[0]
	if fragment.Page != 1 || fragment.TokenStartOrdinal != 0 || fragment.TokenEndOrdinal != 3 || string(fragment.CanonicalText) != "Alpha \u0437\u0430\u043f\u0443\u0441\u043a\n\u0433\u043e\u0442\u043e\u0432" {
		t.Fatalf("unexpected OCR fragment: %+v", fragment)
	}
	if !strings.Contains(string(fragment.AnchorBytes), `"kind":"OCR"`) || strings.Contains(string(fragment.AnchorBytes), "text_start") {
		t.Fatalf("anchor is not an OCR token-range anchor: %s", fragment.AnchorBytes)
	}
}

func TestParseRejectsBoundaryAndBindingMutations(t *testing.T) {
	cases := map[string]string{
		"unknown member":     strings.Replace(validOCR, `"warnings":[]`, `"warnings":[],"unexpected":true`, 1),
		"duplicate member":   strings.Replace(validOCR, `"observed_format":"PNG"`, `"observed_format":"PNG","observed_format":"PNG"`, 1),
		"wrong format":       strings.Replace(validOCR, `"observed_format":"PNG"`, `"observed_format":"JPEG"`, 1),
		"gap ordinal":        strings.Replace(validOCR, `"ordinal":2`, `"ordinal":4`, 1),
		"box mismatch":       strings.Replace(validOCR, `"width":0.2,"height":0.1},"confidence":1`, `"width":0.0,"height":0.1},"confidence":1`, 1),
		"bidi token":         strings.Replace(validOCR, `"canonical_token_text":"Alpha"`, `"canonical_token_text":"Al\u202Epha"`, 1),
		"missing confidence": strings.Replace(validOCR, `,"confidence":0.99`, ``, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw), FormatPNG); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("mutation was accepted: %v", err)
			}
		})
	}
}

func TestParseRejectsNonCanonicalTokenAndPageOrder(t *testing.T) {
	leadingSpace := strings.Replace(validOCR, `"canonical_token_text":"Alpha"`, `"canonical_token_text":" Alpha"`, 1)
	if _, err := Parse([]byte(leadingSpace), FormatPNG); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("leading whitespace token accepted: %v", err)
	}
	pageTwo := strings.Replace(validOCR, `"page":1,"tokens"`, `"page":2,"tokens"`, 1)
	if _, err := Parse([]byte(pageTwo), FormatPNG); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("non-contiguous page accepted: %v", err)
	}
}

func TestRepageRebuildsTokenRangeAnchor(t *testing.T) {
	result, err := Parse([]byte(validOCR), FormatPNG)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	repaged, err := Repage(result, 7)
	if err != nil {
		t.Fatalf("Repage: %v", err)
	}
	if repaged.Pages[0].Page != 7 || repaged.Pages[0].Tokens[0].Page != 7 || repaged.Fragments[0].Page != 7 {
		t.Fatalf("page identity was not rebound: %+v", repaged)
	}
	if strings.Contains(string(repaged.Fragments[0].AnchorBytes), `"page":1`) || !strings.Contains(string(repaged.Fragments[0].AnchorBytes), `"page":7`) {
		t.Fatalf("anchor page was not rebuilt: %s", repaged.Fragments[0].AnchorBytes)
	}
	if string(repaged.ObjectText) != string(result.ObjectText) || repaged.ObjectTextHash != result.ObjectTextHash {
		t.Fatalf("repage changed object text identity")
	}
	if _, err := Repage(result, 0); !errors.Is(err, ErrInvalidResult) {
		t.Fatalf("page zero accepted: %v", err)
	}
}

// TestParseLiveWorkerResultWhenConfigured is the release-gate bridge between
// the pinned OCI OCR worker and the Go-owned contract boundary. It is skipped
// during ordinary unit runs; the live gauntlet sets the path to stdout captured
// from the real worker image and therefore proves that no fixture or alternate
// parser is standing in for the production result.
func TestParseLiveWorkerResultWhenConfigured(t *testing.T) {
	path := strings.TrimSpace(os.Getenv("KNOWVAULT_OCR_RESULT_FILE"))
	if path == "" {
		t.Skip("KNOWVAULT_OCR_RESULT_FILE is not configured")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read live OCR result: %v", err)
	}
	result, err := Parse(raw, FormatPNG)
	if err != nil {
		t.Fatalf("parse live OCR result: %v", err)
	}
	if result.Parser.Name == "" || len(result.Pages) == 0 || len(result.Fragments) == 0 || len(result.ObjectText) == 0 {
		t.Fatalf("live OCR result was structurally empty: %+v", result)
	}
}
