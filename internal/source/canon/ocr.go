package canon

import "math"

// OCRRectangle is the normalized top-left geometry bound to one canonical OCR
// token. Geometry is deliberately kept separate from text and is admitted only
// by OCRAnchorBytes after the one-to-one token/box cardinality check.
type OCRRectangle struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

const MaxOCRBoxes = 256

// OCRAnchorBytes returns the canonical JCS of an OCR token-range anchor. The
// half-open ordinals are 0-based and the boxes must contain exactly one entry
// for each selected token, in the same order. The worker cannot choose offsets
// or hashes: this is the sole Go-owned anchor builder.
func OCRAnchorBytes(page, tokenStart, tokenEnd int, boxes []OCRRectangle) ([]byte, error) {
	if page < 1 || tokenStart < 0 || tokenEnd <= tokenStart || tokenEnd-tokenStart != len(boxes) || len(boxes) > MaxOCRBoxes {
		return nil, ErrCanonical
	}
	for _, box := range boxes {
		if !validOCRRectangle(box) {
			return nil, ErrCanonical
		}
	}
	return canonicalJSON(struct {
		Kind              string         `json:"kind"`
		Page              int            `json:"page"`
		TokenStartOrdinal int            `json:"token_start_ordinal"`
		TokenEndOrdinal   int            `json:"token_end_ordinal"`
		RangeSemantics    string         `json:"range_semantics"`
		CoordinateUnit    string         `json:"coordinate_unit"`
		CoordinateOrigin  string         `json:"coordinate_origin"`
		BoundingBoxes     []OCRRectangle `json:"bounding_boxes"`
	}{
		Kind: "OCR", Page: page, TokenStartOrdinal: tokenStart, TokenEndOrdinal: tokenEnd,
		RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE", CoordinateUnit: "NORMALIZED_0_1",
		CoordinateOrigin: "TOP_LEFT", BoundingBoxes: boxes,
	})
}

func validOCRRectangle(box OCRRectangle) bool {
	for _, value := range []float64{box.X, box.Y, box.Width, box.Height} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			return false
		}
	}
	return box.Width > 0 && box.Height > 0 && box.X <= 1-box.Width && box.Y <= 1-box.Height
}
