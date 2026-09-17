package canon

import (
	"math"
	"strings"
	"testing"
)

func TestPdfAnchorBytesGolden(t *testing.T) {
	boxes := []PDFRectangle{{
		X: 72, Y: 144, Width: 24, Height: 12,
		CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT",
	}}
	got, err := PdfAnchorBytes(1, 18, 22, boxes)
	if err != nil {
		t.Fatalf("PdfAnchorBytes: %v", err)
	}
	want := `{"bounding_boxes":[{"coordinate_origin":"TOP_LEFT","coordinate_unit":"PDF_POINT","height":12,"width":24,"x":72,"y":144}],"kind":"PDF","normalization_version":"text-v1","offset_unit":"UTF8_BYTE","page":1,"range_semantics":"START_INCLUSIVE_END_EXCLUSIVE","text_end":22,"text_start":18}`
	if string(got) != want {
		t.Fatalf("PDF anchor JCS drift:\n got=%s\nwant=%s", got, want)
	}
}

func TestPdfAnchorBytesRejectsInvalidGeometryAndRanges(t *testing.T) {
	valid := PDFRectangle{X: 1, Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}
	cases := map[string]struct {
		page, start, end int
		boxes            []PDFRectangle
	}{
		"page zero":      {0, 0, 1, []PDFRectangle{valid}},
		"reversed range": {1, 2, 2, []PDFRectangle{valid}},
		"empty boxes":    {1, 0, 1, nil},
		"negative x":     {1, 0, 1, []PDFRectangle{{X: -1, Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}}},
		"zero width":     {1, 0, 1, []PDFRectangle{{X: 1, Y: 2, Width: 0, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}}},
		"wrong unit":     {1, 0, 1, []PDFRectangle{{X: 1, Y: 2, Width: 3, Height: 4, CoordinateUnit: "PIXEL", CoordinateOrigin: "TOP_LEFT"}}},
		"wrong origin":   {1, 0, 1, []PDFRectangle{{X: 1, Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "BOTTOM_LEFT"}}},
		"infinite":       {1, 0, 1, []PDFRectangle{{X: math.Inf(1), Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}}},
		"nan":            {1, 0, 1, []PDFRectangle{{X: math.NaN(), Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}}},
		"edge overflow":  {1, 0, 1, []PDFRectangle{{X: MaxPDFCoordinate, Y: 2, Width: 1, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := PdfAnchorBytes(tc.page, tc.start, tc.end, tc.boxes); err == nil {
				t.Fatalf("invalid PDF anchor %q was accepted", name)
			}
		})
	}
}

func TestPdfAnchorBytesBoundsBoxCount(t *testing.T) {
	box := PDFRectangle{X: 1, Y: 2, Width: 3, Height: 4, CoordinateUnit: "PDF_POINT", CoordinateOrigin: "TOP_LEFT"}
	if _, err := PdfAnchorBytes(1, 0, 1, make([]PDFRectangle, MaxPDFRectangles+1)); err == nil {
		t.Fatal("PDF box bomb was accepted")
	}
	// Keep the test fixture construction honest: the valid count is not rejected
	// merely because the bound is present.
	boxes := make([]PDFRectangle, MaxPDFRectangles)
	for i := range boxes {
		boxes[i] = box
	}
	got, err := PdfAnchorBytes(1, 0, 1, boxes)
	if err != nil || !strings.Contains(string(got), `"bounding_boxes"`) {
		t.Fatalf("maximum valid PDF box count was rejected: %v", err)
	}
}
