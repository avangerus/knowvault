// Package pdfparser is the Go re-validation boundary for the isolated text-PDF
// observer. It accepts only the separate pdf-parser-result-v1 protocol: the
// existing document-parser-result-v1 Office protocol is deliberately untouched.
//
// The worker owns observation only. It reports a page, bounded PDF_POINT/TOP_LEFT
// geometry and raw Unicode text. This package is the sole owner of text-v1
// canonicalization, the full UTF-8 byte range, the canonical PDF anchor bytes and
// the assembled object text. Every malformed or ambiguous response is reduced to
// ErrInvalidResult so callers quarantine without a parser fallback. One explicit
// empty observation is reserved for ErrScannedOrMixedPDF, which is the only
// signal allowed to enter the separately pinned render→OCR composition.
package pdfparser

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"regexp"
	"strconv"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// ResultVersion is the only accepted PDF wire protocol version. The PDF protocol
// has its own version namespace because document-parser-result-v1 is immutable and
// remains Office-only.
const ResultVersion = "pdf-parser-result-v1"

// FormatPDF is the sole format this parser can validate.
const FormatPDF = "PDF"

// ObjectTextSeparator joins canonical page text in page order. It is a canon-side
// decision and never comes from the worker.
const ObjectTextSeparator = "\n"

// Resource bounds are re-checked independently of the worker and sandbox. A
// refusal is for the whole result, never a truncation that could look complete.
const (
	MaxTextUnits         = 100000
	MaxUnitRawBytes      = 262144
	MaxFragmentTextBytes = 262144
	MaxObjectTextBytes   = 67108864
	MaxWarnings          = 4096
	MaxPDFRectangles     = canon.MaxPDFRectangles
)

// ErrInvalidResult is the only rejection value exposed by the parser boundary.
var (
	ErrInvalidResult     = errors.New("pdfparser: worker result rejected")
	ErrScannedOrMixedPDF = errors.New("pdfparser: scanned or mixed PDF")
)

var (
	artifactHashRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	observationRevRe = regexp.MustCompile(`^[a-z0-9]+-obs-v[1-9][0-9]*$`)
	structuralTextRe = regexp.MustCompile(`^[^\x00-\x1f\x{007f}-\x{009f}]+$`)
	warningCodeRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// Parser is the worker's self-declared identity. It is not a database id and is
// accepted only after the PDF worker facade compares it with its pinned identity.
type Parser struct {
	Name                       string
	Version                    string
	ArtifactHash               string
	ObservationProfileRevision string
	// RuntimeProfileHash is attached by the production dispatcher facade from
	// its kernel confirmation; the PDF observer wire contract cannot express it.
	RuntimeProfileHash string
}

// PDFRectangle is the validated geometry copied from a worker observation. The fixed
// unit and origin are retained in the typed result and re-emitted by canon.
type PDFRectangle = canon.PDFRectangle

// Anchor is a PDF anchor built by Go over the complete canonical text of one page.
// TextStart/TextEnd are always [0,len(CanonicalText)); the worker cannot supply
// either offset.
type Anchor struct {
	Kind          string
	Page          int
	PageWidth     float64
	PageHeight    float64
	Rotation      int
	TextStart     int
	TextEnd       int
	BoundingBoxes []PDFRectangle
}

// Fragment is one canonical page unit ready for the ingestion owner. Hash
// projections are intentionally absent; the organization boundary computes them.
type Fragment struct {
	Ordinal       int
	CanonicalText []byte
	AnchorBytes   []byte
	Anchor        Anchor
	// Page geometry is exposed alongside the anchor so persistence and the terminal
	// resolver can replay crop/rotation context without trusting worker offsets.
	PageWidth  float64
	PageHeight float64
	Rotation   int
}

// Result is the accepted, canonicalized PDF extraction. It carries no source or
// lifecycle ids and no queryability/tenant/workspace authority.
type Result struct {
	ObservedFormat string
	Parser         Parser
	ObjectText     []byte
	ObjectTextHash string
	Fragments      []Fragment
	Warnings       []string
}

type wireResult struct {
	ResultVersion  string      `json:"result_version"`
	ObservedFormat string      `json:"observed_format"`
	Parser         wireParser  `json:"parser"`
	TextUnits      []wireUnit  `json:"text_units"`
	Warnings       *[]wireWarn `json:"warnings"`
}

type wireParser struct {
	Name                       string `json:"name"`
	Version                    string `json:"version"`
	ArtifactHash               string `json:"artifact_hash"`
	ObservationProfileRevision string `json:"observation_profile_revision"`
}

type wireUnit struct {
	Ordinal int            `json:"ordinal"`
	Locator jsontext.Value `json:"locator"`
	RawText string         `json:"raw_text"`
}

type wireWarn struct {
	Code string `json:"code"`
}

type wirePDFLocator struct {
	Kind          string             `json:"kind"`
	Page          *int               `json:"page"`
	PageWidth     *float64           `json:"page_width"`
	PageHeight    *float64           `json:"page_height"`
	Rotation      *int               `json:"rotation"`
	BoundingBoxes []wirePDFRectangle `json:"bounding_boxes"`
}

// wirePDFRectangle uses pointers so required numeric/string members cannot be
// silently replaced by Go zero values when a hostile observer omits a field.
type wirePDFRectangle struct {
	X                *float64 `json:"x"`
	Y                *float64 `json:"y"`
	Width            *float64 `json:"width"`
	Height           *float64 `json:"height"`
	CoordinateUnit   *string  `json:"coordinate_unit"`
	CoordinateOrigin *string  `json:"coordinate_origin"`
}

// decodeStrict closes every object in the protocol: unknown members and duplicate
// names cannot smuggle ids, offsets, hashes or canonicalization decisions through.
func decodeStrict(raw []byte, v any) error {
	return jsonv2.Unmarshal(raw, v, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
}

// Parse strictly decodes, validates and canonicalizes one PDF worker observation.
// dispatched must be FormatPDF; no generic format fallback is permitted.
func Parse(raw []byte, dispatched string) (*Result, error) {
	if len(raw) == 0 || dispatched != FormatPDF {
		return nil, ErrInvalidResult
	}
	var wire wireResult
	if err := decodeStrict(raw, &wire); err != nil {
		return nil, ErrInvalidResult
	}
	if wire.ResultVersion != ResultVersion || wire.ObservedFormat != FormatPDF || wire.Warnings == nil || len(*wire.Warnings) > MaxWarnings {
		return nil, ErrInvalidResult
	}
	parser, ok := validateParser(wire.Parser)
	if !ok || len(wire.TextUnits) > MaxTextUnits {
		return nil, ErrInvalidResult
	}

	warnings := make([]string, 0, len(*wire.Warnings))
	for _, warning := range *wire.Warnings {
		if !warningCodeRe.MatchString(warning.Code) {
			return nil, ErrInvalidResult
		}
		warnings = append(warnings, warning.Code)
	}
	// The PDF observer may classify an image-only or mixed document without
	// transferring any page text. This is a closed, content-free observation,
	// not a successful extraction: callers may route only this explicit sentinel
	// to the separately pinned render→OCR path. Every other empty result remains
	// an invalid observation and is quarantined.
	if len(wire.TextUnits) == 0 {
		if len(warnings) == 1 && warnings[0] == "SCANNED_OR_MIXED_PDF" {
			return nil, ErrScannedOrMixedPDF
		}
		return nil, ErrInvalidResult
	}

	fragments := make([]Fragment, 0, len(wire.TextUnits))
	positions := make(map[string]bool, len(wire.TextUnits))
	previousPage := 0
	for index, unit := range wire.TextUnits {
		fragment, position, ok := buildFragment(index, unit)
		// The worker's order is part of the observation semantics. Pages may be
		// absent when they carry no text, but an observed page sequence may never
		// move backwards or repeat; this makes object text and anchor replay stable.
		if !ok || positions[position] || fragment.Anchor.Page <= previousPage {
			return nil, ErrInvalidResult
		}
		positions[position] = true
		previousPage = fragment.Anchor.Page
		fragments = append(fragments, fragment)
	}

	objectText, ok := assembleObjectText(fragments)
	if !ok {
		return nil, ErrInvalidResult
	}
	return &Result{
		ObservedFormat: FormatPDF,
		Parser:         parser,
		ObjectText:     objectText,
		ObjectTextHash: canon.Hash(objectText),
		Fragments:      fragments,
		Warnings:       warnings,
	}, nil
}

func validateParser(p wireParser) (Parser, bool) {
	if p.Name == "" || len(p.Name) > 128 || p.Version == "" || len(p.Version) > 64 {
		return Parser{}, false
	}
	if !structuralTextRe.MatchString(p.Name) || !structuralTextRe.MatchString(p.Version) ||
		!artifactHashRe.MatchString(p.ArtifactHash) || !observationRevRe.MatchString(p.ObservationProfileRevision) {
		return Parser{}, false
	}
	return Parser{
		Name: p.Name, Version: p.Version,
		ArtifactHash: p.ArtifactHash, ObservationProfileRevision: p.ObservationProfileRevision,
	}, true
}

func buildFragment(index int, unit wireUnit) (Fragment, string, bool) {
	if unit.Ordinal != index+1 {
		return Fragment{}, "", false
	}
	canonical, ok := canonicalizeUnit(unit.RawText)
	if !ok {
		return Fragment{}, "", false
	}
	anchor, anchorBytes, position, ok := buildAnchor(unit.Locator, len(canonical))
	if !ok {
		return Fragment{}, "", false
	}
	return Fragment{
		Ordinal: unit.Ordinal, CanonicalText: canonical,
		AnchorBytes: anchorBytes, Anchor: anchor,
		PageWidth: anchor.PageWidth, PageHeight: anchor.PageHeight, Rotation: anchor.Rotation,
	}, position, true
}

func canonicalizeUnit(raw string) ([]byte, bool) {
	if raw == "" || len(raw) > MaxUnitRawBytes {
		return nil, false
	}
	canonical, err := canon.Canonicalize([]byte(raw))
	if err != nil || len(canonical) == 0 || len(canonical) > MaxFragmentTextBytes {
		return nil, false
	}
	return canonical, true
}

func buildAnchor(raw jsontext.Value, canonicalLength int) (Anchor, []byte, string, bool) {
	var locator wirePDFLocator
	if decodeStrict(raw, &locator) != nil || locator.Kind != FormatPDF || locator.Page == nil ||
		*locator.Page < 1 || *locator.Page > MaxTextUnits ||
		locator.PageWidth == nil || locator.PageHeight == nil || locator.Rotation == nil ||
		!validPDFPageGeometry(*locator.PageWidth, *locator.PageHeight, *locator.Rotation) ||
		len(locator.BoundingBoxes) < 1 || len(locator.BoundingBoxes) > MaxPDFRectangles ||
		canonicalLength < 1 {
		return Anchor{}, nil, "", false
	}
	boxes := make([]canon.PDFRectangle, len(locator.BoundingBoxes))
	for index, wireBox := range locator.BoundingBoxes {
		if wireBox.X == nil || wireBox.Y == nil || wireBox.Width == nil || wireBox.Height == nil ||
			wireBox.CoordinateUnit == nil || wireBox.CoordinateOrigin == nil {
			return Anchor{}, nil, "", false
		}
		box := canon.PDFRectangle{
			X: *wireBox.X, Y: *wireBox.Y, Width: *wireBox.Width, Height: *wireBox.Height,
			CoordinateUnit: *wireBox.CoordinateUnit, CoordinateOrigin: *wireBox.CoordinateOrigin,
		}
		boxes[index] = box
		if !validPDFRectangle(box, *locator.PageWidth, *locator.PageHeight) {
			return Anchor{}, nil, "", false
		}
	}
	start, end := 0, canonicalLength
	anchorBytes, err := canon.PdfAnchorBytes(*locator.Page, start, end, boxes)
	if err != nil {
		return Anchor{}, nil, "", false
	}
	position := "PDF\x00" + strconv.Itoa(*locator.Page)
	return Anchor{
		Kind: FormatPDF, Page: *locator.Page,
		PageWidth: *locator.PageWidth, PageHeight: *locator.PageHeight, Rotation: *locator.Rotation,
		TextStart: start, TextEnd: end, BoundingBoxes: boxes,
	}, anchorBytes, position, true
}

func validPDFPageGeometry(width, height float64, rotation int) bool {
	if math.IsNaN(width) || math.IsInf(width, 0) || width <= 0 || width > canon.MaxPDFCoordinate ||
		math.IsNaN(height) || math.IsInf(height, 0) || height <= 0 || height > canon.MaxPDFCoordinate {
		return false
	}
	switch rotation {
	case 0, 90, 180, 270:
		return true
	default:
		return false
	}
}

func validPDFRectangle(box canon.PDFRectangle, pageWidth, pageHeight float64) bool {
	if box.CoordinateUnit != "PDF_POINT" || box.CoordinateOrigin != "TOP_LEFT" {
		return false
	}
	for _, value := range []float64{box.X, box.Y, box.Width, box.Height} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value > canon.MaxPDFCoordinate {
			return false
		}
	}
	if box.X < 0 || box.Y < 0 || box.Width <= 0 || box.Height <= 0 {
		return false
	}
	return box.X <= pageWidth-box.Width && box.Y <= pageHeight-box.Height
}

func assembleObjectText(fragments []Fragment) ([]byte, bool) {
	if len(fragments) == 0 {
		return nil, false
	}
	total := 0
	for i, fragment := range fragments {
		if len(fragment.CanonicalText) > MaxObjectTextBytes-total {
			return nil, false
		}
		total += len(fragment.CanonicalText)
		if i > 0 {
			if len(ObjectTextSeparator) > MaxObjectTextBytes-total {
				return nil, false
			}
			total += len(ObjectTextSeparator)
		}
	}
	objectText := make([]byte, 0, total)
	for i, fragment := range fragments {
		if i > 0 {
			objectText = append(objectText, ObjectTextSeparator...)
		}
		objectText = append(objectText, fragment.CanonicalText...)
	}
	canonical, err := canon.Canonicalize(objectText)
	if err != nil || !bytes.Equal(canonical, objectText) {
		return nil, false
	}
	return objectText, true
}
