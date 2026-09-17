package canon

import (
	"math"
	"strings"
	"testing"
)

func TestOCRAnchorBytesGolden(t *testing.T) {
	got, err := OCRAnchorBytes(1, 0, 2, []OCRRectangle{
		{X: 0.1, Y: 0.1, Width: 0.2, Height: 0.1},
		{X: 0.32, Y: 0.1, Width: 0.25, Height: 0.1},
	})
	if err != nil {
		t.Fatalf("OCRAnchorBytes: %v", err)
	}
	want := `{"bounding_boxes":[{"height":0.1,"width":0.2,"x":0.1,"y":0.1},{"height":0.1,"width":0.25,"x":0.32,"y":0.1}],"coordinate_origin":"TOP_LEFT","coordinate_unit":"NORMALIZED_0_1","kind":"OCR","page":1,"range_semantics":"START_INCLUSIVE_END_EXCLUSIVE","token_end_ordinal":2,"token_start_ordinal":0}`
	if string(got) != want {
		t.Fatalf("OCR anchor JCS drift:\n got=%s\nwant=%s", got, want)
	}
}

func TestOCRAnchorBytesRejectsBindingAndGeometryViolations(t *testing.T) {
	box := OCRRectangle{X: 0.1, Y: 0.1, Width: 0.2, Height: 0.1}
	cases := []struct {
		name  string
		start int
		end   int
		boxes []OCRRectangle
	}{
		{"reversed", 2, 1, []OCRRectangle{box}},
		{"count mismatch", 0, 2, []OCRRectangle{box}},
		{"zero width", 0, 1, []OCRRectangle{{X: 0, Y: 0, Width: 0, Height: 0.1}}},
		{"outside edge", 0, 1, []OCRRectangle{{X: 0.9, Y: 0, Width: 0.2, Height: 0.1}}},
		{"nan", 0, 1, []OCRRectangle{{X: 0, Y: 0, Width: 0.1, Height: math.NaN()}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := OCRAnchorBytes(1, tc.start, tc.end, tc.boxes); err == nil {
				t.Fatal("invalid OCR anchor was accepted")
			}
		})
	}
	if _, err := OCRAnchorBytes(0, 0, 1, []OCRRectangle{box}); err == nil {
		t.Fatal("page zero was accepted")
	}
	if _, err := OCRAnchorBytes(1, 0, MaxOCRBoxes+1, make([]OCRRectangle, MaxOCRBoxes+1)); err == nil {
		t.Fatal("oversized OCR anchor was accepted")
	}
	if strings.Contains(string(mustOCRAnchor(t, box)), "text_start") {
		t.Fatal("OCR anchor gained byte offsets")
	}
}

func mustOCRAnchor(t *testing.T, box OCRRectangle) []byte {
	t.Helper()
	value, err := OCRAnchorBytes(1, 0, 1, []OCRRectangle{box})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
