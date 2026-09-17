package canon

import "math"

// PDFRectangle is the geometry observed for a text-PDF unit. The unit and origin are
// part of the wire contract even though they are fixed: retaining them here lets
// the Go owner validate the observation before it becomes an anchor. The worker
// does not supply offsets, hashes or canonical text.
type PDFRectangle struct {
	X                float64 `json:"x"`
	Y                float64 `json:"y"`
	Width            float64 `json:"width"`
	Height           float64 `json:"height"`
	CoordinateUnit   string  `json:"coordinate_unit"`
	CoordinateOrigin string  `json:"coordinate_origin"`
}

// MaxPDFRectangles bounds the geometry carried by one observed page. It is deliberately
// shared by the canon builder and the PDF protocol validator so a box bomb cannot
// pass one boundary and fail only after an expensive canonicalization.
const MaxPDFRectangles = 4096

// MaxPDFCoordinate is the largest finite coordinate accepted by the wire and
// canonical anchor contracts. It is the JSON/I-JSON safe integer bound; keeping
// the same ceiling for floating point geometry also prevents an overflowing edge
// from being represented as a plausible anchor.
const MaxPDFCoordinate = 9007199254740991.0

// PdfAnchorBytes returns the canonical JCS of a PDF anchor. The caller must pass the
// complete UTF-8 byte extent of the Go-canonicalized page unit; the worker cannot
// choose textStart/textEnd. Geometry is copied into the anchor only after strict
// validation of its fixed PDF_POINT/TOP_LEFT contract.
func PdfAnchorBytes(page, textStart, textEnd int, boxes []PDFRectangle) ([]byte, error) {
	if page < 1 || float64(page) > MaxPDFCoordinate ||
		textStart < 0 || float64(textStart) > MaxPDFCoordinate ||
		textEnd <= textStart || float64(textEnd) > MaxPDFCoordinate ||
		len(boxes) < 1 || len(boxes) > MaxPDFRectangles {
		return nil, ErrCanonical
	}
	for _, box := range boxes {
		if !validPDFRectangle(box) {
			return nil, ErrCanonical
		}
	}
	return canonicalJSON(struct {
		Kind                 string         `json:"kind"`
		Page                 int            `json:"page"`
		TextStart            int            `json:"text_start"`
		TextEnd              int            `json:"text_end"`
		OffsetUnit           string         `json:"offset_unit"`
		RangeSemantics       string         `json:"range_semantics"`
		NormalizationVersion string         `json:"normalization_version"`
		BoundingBoxes        []PDFRectangle `json:"bounding_boxes"`
	}{
		Kind: "PDF", Page: page, TextStart: textStart, TextEnd: textEnd,
		OffsetUnit: "UTF8_BYTE", RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE",
		NormalizationVersion: NormalizationVersion, BoundingBoxes: boxes,
	})
}

func validPDFRectangle(box PDFRectangle) bool {
	if box.CoordinateUnit != "PDF_POINT" || box.CoordinateOrigin != "TOP_LEFT" {
		return false
	}
	for _, value := range []float64{box.X, box.Y, box.Width, box.Height} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value > MaxPDFCoordinate {
			return false
		}
	}
	if box.X < 0 || box.Y < 0 || box.Width <= 0 || box.Height <= 0 {
		return false
	}
	// There is no page-size field in the observer locator. Keep both edges in the
	// same bounded coordinate domain, and avoid an overflowing addition.
	return box.X <= MaxPDFCoordinate-box.Width && box.Y <= MaxPDFCoordinate-box.Height
}
