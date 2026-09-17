package pdfparser_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
)

const parserHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func pdfRectangle(x, y, width, height float64) map[string]any {
	return map[string]any{
		"x": x, "y": y, "width": width, "height": height,
		"coordinate_unit": "PDF_POINT", "coordinate_origin": "TOP_LEFT",
	}
}

func pdfUnit(ordinal, page int, raw string, boxes ...map[string]any) map[string]any {
	return map[string]any{
		"ordinal": ordinal,
		"locator": map[string]any{
			"kind": "PDF", "page": page, "page_width": 612.0, "page_height": 792.0,
			"rotation": 0, "bounding_boxes": boxes,
		},
		"raw_text": raw,
	}
}

func validPDFResult() map[string]any {
	return map[string]any{
		"result_version":  pdfparser.ResultVersion,
		"observed_format": pdfparser.FormatPDF,
		"parser": map[string]any{
			"name": "knowvault-pdf-observer", "version": "1.0",
			"artifact_hash": parserHash, "observation_profile_revision": "pdf-obs-v1",
		},
		"text_units": []any{
			pdfUnit(1, 1, string([]rune{'C', 'a', 'f', 'e', 0x0301, '\r', '\n', 'p', 'l', 'a', 'n'}), pdfRectangle(72, 144, 24, 12)),
			pdfUnit(2, 2, "Second page", pdfRectangle(100, 200, 60, 14)),
		},
		"warnings": []any{},
	}
}

func unit0(value map[string]any) map[string]any {
	return value["text_units"].([]any)[0].(map[string]any)
}

func locator0(value map[string]any) map[string]any {
	return unit0(value)["locator"].(map[string]any)
}

func TestParseValidPDFBuildsCanonicalFullPageAnchors(t *testing.T) {
	parsed, err := pdfparser.Parse(mustJSON(t, validPDFResult()), pdfparser.FormatPDF)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.ObservedFormat != pdfparser.FormatPDF || len(parsed.Fragments) != 2 {
		t.Fatalf("unexpected result shape: %+v", parsed)
	}
	first := parsed.Fragments[0]
	wantFirst := string([]rune{'C', 'a', 'f', 0x00e9, '\n', 'p', 'l', 'a', 'n'})
	if got := string(first.CanonicalText); got != wantFirst {
		t.Fatalf("worker raw text was not canonicalized by Go: %q", got)
	}
	if first.Anchor.Kind != pdfparser.FormatPDF || first.Anchor.Page != 1 ||
		first.Anchor.TextStart != 0 || first.Anchor.TextEnd != len(first.CanonicalText) ||
		first.Anchor.PageWidth != 612 || first.Anchor.PageHeight != 792 || first.Anchor.Rotation != 0 {
		t.Fatalf("unexpected first PDF anchor: %+v", first.Anchor)
	}
	if first.PageWidth != first.Anchor.PageWidth || first.PageHeight != first.Anchor.PageHeight || first.Rotation != first.Anchor.Rotation {
		t.Fatalf("fragment did not expose page geometry: %+v", first)
	}
	wantObject := wantFirst + "\nSecond page"
	if string(parsed.ObjectText) != wantObject {
		t.Fatalf("unexpected canonical object text: %q", parsed.ObjectText)
	}
	if parsed.ObjectTextHash != canon.Hash([]byte(wantObject)) {
		t.Fatalf("object hash was not computed by canon: %q", parsed.ObjectTextHash)
	}
	wantAnchor, err := canon.PdfAnchorBytes(1, 0, len(first.CanonicalText), first.Anchor.BoundingBoxes)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.AnchorBytes) != string(wantAnchor) {
		t.Fatalf("PDF anchor was not built by canon:\n got=%s\nwant=%s", first.AnchorBytes, wantAnchor)
	}
	if second := parsed.Fragments[1].Anchor; second.Page != 2 || second.TextStart != 0 || second.TextEnd != len("Second page") {
		t.Fatalf("second page was not a full canonical unit: %+v", second)
	}
}

func TestParseRequiresStrictIncreasingPageOrder(t *testing.T) {
	value := validPDFResult()
	units := value["text_units"].([]any)
	units[0].(map[string]any)["locator"].(map[string]any)["page"] = 2
	units[1].(map[string]any)["locator"].(map[string]any)["page"] = 1
	if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); err == nil {
		t.Fatal("reversed page order was accepted")
	}
	value = validPDFResult()
	units = value["text_units"].([]any)
	units[1].(map[string]any)["locator"].(map[string]any)["page"] = 3
	if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); err != nil {
		t.Fatalf("a gap for an omitted blank page was rejected: %v", err)
	}
}

func TestParseRejectsPDFProtocolViolations(t *testing.T) {
	cases := map[string]func(map[string]any){
		"wrong result version":         func(v map[string]any) { v["result_version"] = "document-parser-result-v1" },
		"wrong observed format":        func(v map[string]any) { v["observed_format"] = "DOCX" },
		"wrong locator kind":           func(v map[string]any) { locator0(v)["kind"] = "DOCX" },
		"missing page":                 func(v map[string]any) { delete(locator0(v), "page") },
		"missing page width":           func(v map[string]any) { delete(locator0(v), "page_width") },
		"missing page height":          func(v map[string]any) { delete(locator0(v), "page_height") },
		"missing rotation":             func(v map[string]any) { delete(locator0(v), "rotation") },
		"missing warnings":             func(v map[string]any) { delete(v, "warnings") },
		"zero page":                    func(v map[string]any) { locator0(v)["page"] = 0 },
		"zero page width":              func(v map[string]any) { locator0(v)["page_width"] = 0 },
		"negative page height":         func(v map[string]any) { locator0(v)["page_height"] = -1 },
		"page width above safe bound":  func(v map[string]any) { locator0(v)["page_width"] = canon.MaxPDFCoordinate + 1 },
		"page height above safe bound": func(v map[string]any) { locator0(v)["page_height"] = canon.MaxPDFCoordinate + 1 },
		"invalid rotation":             func(v map[string]any) { locator0(v)["rotation"] = 45 },
		"empty boxes":                  func(v map[string]any) { locator0(v)["bounding_boxes"] = []any{} },
		"wrong box unit":               func(v map[string]any) { box0(v)["coordinate_unit"] = "PIXEL" },
		"wrong box origin":             func(v map[string]any) { box0(v)["coordinate_origin"] = "BOTTOM_LEFT" },
		"missing box x":                func(v map[string]any) { delete(box0(v), "x") },
		"missing box y":                func(v map[string]any) { delete(box0(v), "y") },
		"missing box width":            func(v map[string]any) { delete(box0(v), "width") },
		"missing box height":           func(v map[string]any) { delete(box0(v), "height") },
		"missing box unit":             func(v map[string]any) { delete(box0(v), "coordinate_unit") },
		"missing box origin":           func(v map[string]any) { delete(box0(v), "coordinate_origin") },
		"negative x":                   func(v map[string]any) { box0(v)["x"] = -1 },
		"negative y":                   func(v map[string]any) { box0(v)["y"] = -1 },
		"zero width":                   func(v map[string]any) { box0(v)["width"] = 0 },
		"zero height":                  func(v map[string]any) { box0(v)["height"] = 0 },
		"box outside right edge":       func(v map[string]any) { box0(v)["x"] = 600; box0(v)["width"] = 13 },
		"box outside bottom edge":      func(v map[string]any) { box0(v)["y"] = 790; box0(v)["height"] = 3 },
		"box edge overflow":            func(v map[string]any) { box0(v)["x"] = canon.MaxPDFCoordinate; box0(v)["width"] = 1 },
		"smuggled text range":          func(v map[string]any) { locator0(v)["text_start"] = 0 },
		"smuggled canonical text":      func(v map[string]any) { unit0(v)["canonical_text"] = "Café" },
		"smuggled hash":                func(v map[string]any) { unit0(v)["anchor_hash"] = parserHash },
		"smuggled locator id":          func(v map[string]any) { locator0(v)["source_version_id"] = "sv-1" },
		"smuggled box field":           func(v map[string]any) { box0(v)["text_offset"] = 0 },
		"smuggled parser field":        func(v map[string]any) { v["parser"].(map[string]any)["tenant_id"] = "t-1" },
		"smuggled result field":        func(v map[string]any) { v["source_version_id"] = "sv-1" },
		"empty raw text":               func(v map[string]any) { unit0(v)["raw_text"] = "" },
		"oversized raw text":           func(v map[string]any) { unit0(v)["raw_text"] = strings.Repeat("x", pdfparser.MaxUnitRawBytes+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := validPDFResult()
			mutate(value)
			if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); err == nil {
				t.Fatalf("protocol violation %q was accepted", name)
			}
		})
	}
}

func TestParseClassifiesExplicitScannedPDFObservation(t *testing.T) {
	value := validPDFResult()
	value["text_units"] = []any{}
	value["warnings"] = []any{map[string]any{"code": "SCANNED_OR_MIXED_PDF"}}
	if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); !errors.Is(err, pdfparser.ErrScannedOrMixedPDF) {
		t.Fatalf("explicit scanned classification was not preserved: %v", err)
	}
	value["warnings"] = []any{map[string]any{"code": "PDF_UNREADABLE"}}
	if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); !errors.Is(err, pdfparser.ErrInvalidResult) {
		t.Fatalf("non-classification empty result was accepted: %v", err)
	}
}

func box0(value map[string]any) map[string]any {
	boxes := locator0(value)["bounding_boxes"].([]map[string]any)
	return boxes[0]
}

func TestParseRejectsNonFiniteJSONGeometry(t *testing.T) {
	// JSON has no NaN/Infinity literals. An exponent beyond float64 is the wire
	// representation closest to a non-finite number and must fail closed after
	// decode even if a decoder chooses to represent it as +Inf.
	valid := strings.Replace(string(mustJSON(t, validPDFResult())), `"x":72`, `"x":1e400`, 1)
	if _, err := pdfparser.Parse([]byte(valid), pdfparser.FormatPDF); err == nil {
		t.Fatal("non-finite JSON geometry was accepted")
	}
	if _, err := pdfparser.Parse(mustJSON(t, map[string]any{
		"result_version": pdfparser.ResultVersion, "observed_format": pdfparser.FormatPDF,
		"parser": validPDFResult()["parser"], "text_units": []any{}, "warnings": []any{},
	}), pdfparser.FormatPDF); err == nil {
		t.Fatal("empty PDF result was accepted")
	}
}

func TestParseRejectsWrongDispatch(t *testing.T) {
	if _, err := pdfparser.Parse(mustJSON(t, validPDFResult()), "DOCX"); err == nil {
		t.Fatal("PDF result was accepted for a non-PDF dispatch")
	}
}

func TestParseRejectsDuplicatePageAndDuplicateNames(t *testing.T) {
	value := validPDFResult()
	units := value["text_units"].([]any)
	units[1].(map[string]any)["locator"].(map[string]any)["page"] = 1
	if _, err := pdfparser.Parse(mustJSON(t, value), pdfparser.FormatPDF); err == nil {
		t.Fatal("duplicate page was accepted")
	}
	raw := `{"result_version":"pdf-parser-result-v1","observed_format":"PDF","observed_format":"PDF",` +
		`"parser":{"name":"w","version":"1","artifact_hash":"` + parserHash +
		`","observation_profile_revision":"pdf-obs-v1"},"text_units":[],"warnings":[]}`
	if _, err := pdfparser.Parse([]byte(raw), pdfparser.FormatPDF); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
}
