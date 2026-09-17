// Package ocrparser is the Go-owned re-validator for the isolated OCR
// observation. It canonicalizes token text, proves the one-to-one token/box
// binding and builds immutable OCR anchors; the worker supplies no offsets,
// hashes, source identifiers or persistence authority.
package ocrparser

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"regexp"
	"unicode"

	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	ResultVersion = "ocr-result-v1"
	FormatPNG     = "PNG"
	FormatJPEG    = "JPEG"

	MaxPages             = 10000
	MaxTokensPerPage     = 100000
	MaxTokenBytes        = 8192
	MaxObjectTextBytes   = 67108864
	MaxWarnings          = 4096
	MaxFragmentsPerPage  = 100000
	MaxFragmentTokens    = canon.MaxOCRBoxes
	MaxFragmentTextBytes = 4096
)

var ErrInvalidResult = errors.New("ocrparser: worker result rejected")

var (
	artifactHashRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	identityRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	warningCodeRe  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

type Parser struct {
	Name                       string
	Version                    string
	ArtifactHash               string
	ObservationProfileRevision string
}

type OCRIdentity struct {
	ModelID         string
	ModelRevision   string
	ArtifactHash    string
	ProfileRevision string
}

type OCRToken struct {
	Page               int
	TokenID            string
	CanonicalTokenText string
	Ordinal            int
	JoinAfter          string
	BoundingBox        canon.OCRRectangle
	Confidence         float64
}

type Page struct {
	Page     int
	Tokens   []OCRToken
	Warnings []string
}

type Fragment struct {
	Ordinal           int
	Page              int
	TokenStartOrdinal int
	TokenEndOrdinal   int
	CanonicalText     []byte
	AnchorBytes       []byte
	Tokens            []OCRToken
}

type Result struct {
	ObservedFormat string
	Parser         Parser
	OCR            OCRIdentity
	Pages          []Page
	ObjectText     []byte
	ObjectTextHash string
	Fragments      []Fragment
	Warnings       []string
}

type wireResult struct {
	ResultVersion  string         `json:"result_version"`
	ObservedFormat string         `json:"observed_format"`
	Parser         wireParser     `json:"parser"`
	OCR            wireOCR        `json:"ocr"`
	Pages          []wirePage     `json:"pages"`
	Warnings       *[]wireWarning `json:"warnings"`
}

type wireParser struct {
	Name                       string `json:"name"`
	Version                    string `json:"version"`
	ArtifactHash               string `json:"artifact_hash"`
	ObservationProfileRevision string `json:"observation_profile_revision"`
}

type wireOCR struct {
	ModelID         string `json:"model_id"`
	ModelRevision   string `json:"model_revision"`
	ArtifactHash    string `json:"artifact_hash"`
	ProfileRevision string `json:"profile_revision"`
}

type wirePage struct {
	Page     *int          `json:"page"`
	Tokens   []wireToken   `json:"tokens"`
	Warnings []wireWarning `json:"warnings"`
}

type wireToken struct {
	Page               *int       `json:"page"`
	TokenID            string     `json:"token_id"`
	CanonicalTokenText string     `json:"canonical_token_text"`
	Ordinal            *int       `json:"ordinal"`
	JoinAfter          string     `json:"join_after"`
	BoundingBox        wireOCRBox `json:"bounding_box"`
	Confidence         *float64   `json:"confidence"`
}

type wireOCRBox struct {
	X      *float64 `json:"x"`
	Y      *float64 `json:"y"`
	Width  *float64 `json:"width"`
	Height *float64 `json:"height"`
}

type wireWarning struct {
	Code string `json:"code"`
}

// Parse strictly decodes and validates one closed ocr-result-v1 observation.
// dispatched must be PNG or JPEG; a scanned PDF is rendered to one of those
// media families before reaching this boundary.
func Parse(raw []byte, dispatched string) (*Result, error) {
	if len(raw) == 0 || (dispatched != FormatPNG && dispatched != FormatJPEG) {
		return nil, ErrInvalidResult
	}
	var wire wireResult
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return nil, ErrInvalidResult
	}
	if wire.ResultVersion != ResultVersion || wire.ObservedFormat != dispatched || len(wire.Pages) < 1 || len(wire.Pages) > MaxPages || wire.Warnings == nil || len(*wire.Warnings) > MaxWarnings {
		return nil, ErrInvalidResult
	}
	parser, ok := validateParser(wire.Parser)
	if !ok {
		return nil, ErrInvalidResult
	}
	ocr, ok := validateOCR(wire.OCR)
	if !ok {
		return nil, ErrInvalidResult
	}
	warnings, ok := validateWarnings(*wire.Warnings)
	if !ok {
		return nil, ErrInvalidResult
	}

	pages := make([]Page, 0, len(wire.Pages))
	fragments := make([]Fragment, 0, len(wire.Pages))
	seenPages := make(map[int]struct{}, len(wire.Pages))
	fragmentOrdinal := 1
	for pageIndex, wirePage := range wire.Pages {
		if wirePage.Page == nil || *wirePage.Page != pageIndex+1 || *wirePage.Page < 1 || *wirePage.Page > MaxPages || len(wirePage.Tokens) < 1 || len(wirePage.Tokens) > MaxTokensPerPage {
			return nil, ErrInvalidResult
		}
		if _, duplicate := seenPages[*wirePage.Page]; duplicate {
			return nil, ErrInvalidResult
		}
		seenPages[*wirePage.Page] = struct{}{}
		page, ok := validatePage(*wirePage.Page, wirePage)
		if !ok {
			return nil, ErrInvalidResult
		}
		pages = append(pages, page)
		pageFragments, ok := buildFragments(page, fragmentOrdinal)
		if !ok || len(pageFragments) > MaxFragmentsPerPage {
			return nil, ErrInvalidResult
		}
		fragmentOrdinal += len(pageFragments)
		fragments = append(fragments, pageFragments...)
	}
	objectText, ok := assembleObjectText(pages)
	if !ok {
		return nil, ErrInvalidResult
	}
	return &Result{
		ObservedFormat: dispatched, Parser: parser, OCR: ocr, Pages: pages,
		ObjectText: objectText, ObjectTextHash: canon.Hash(objectText),
		Fragments: fragments, Warnings: warnings,
	}, nil
}

// Repage returns a copy of a single-page OCR observation with its page identity
// rebound to the trusted renderer page number. The OCR worker intentionally
// knows only the rendered image it received and therefore emits page 1; the
// PDF renderer is the authority for the source page ordinal. Repage rebuilds
// every token-range anchor through canon and refuses multi-page/invalid input so
// a caller cannot silently relabel an arbitrary result.
func Repage(result *Result, pageNumber int) (*Result, error) {
	if result == nil || pageNumber < 1 || pageNumber > MaxPages || len(result.Pages) != 1 || len(result.Pages[0].Tokens) == 0 {
		return nil, ErrInvalidResult
	}
	page := result.Pages[0]
	page.Page = pageNumber
	page.Tokens = append([]OCRToken(nil), page.Tokens...)
	for index := range page.Tokens {
		if page.Tokens[index].Page != result.Pages[0].Page || page.Tokens[index].Ordinal != index {
			return nil, ErrInvalidResult
		}
		page.Tokens[index].Page = pageNumber
	}
	fragments, ok := buildFragments(page, 1)
	if !ok || len(fragments) == 0 {
		return nil, ErrInvalidResult
	}
	pages := []Page{page}
	objectText, ok := assembleObjectText(pages)
	if !ok || !bytes.Equal(objectText, result.ObjectText) || canon.Hash(objectText) != result.ObjectTextHash {
		return nil, ErrInvalidResult
	}
	return &Result{
		ObservedFormat: result.ObservedFormat,
		Parser:         result.Parser,
		OCR:            result.OCR,
		Pages:          pages,
		ObjectText:     objectText,
		ObjectTextHash: result.ObjectTextHash,
		Fragments:      fragments,
		Warnings:       append([]string(nil), result.Warnings...),
	}, nil
}

func validateParser(value wireParser) (Parser, bool) {
	if !identityRe.MatchString(value.Name) || !identityRe.MatchString(value.Version) || !artifactHashRe.MatchString(value.ArtifactHash) || !revisionRe.MatchString(value.ObservationProfileRevision) {
		return Parser{}, false
	}
	return Parser{Name: value.Name, Version: value.Version, ArtifactHash: value.ArtifactHash, ObservationProfileRevision: value.ObservationProfileRevision}, true
}

func validateOCR(value wireOCR) (OCRIdentity, bool) {
	if !identityRe.MatchString(value.ModelID) || !identityRe.MatchString(value.ModelRevision) || !artifactHashRe.MatchString(value.ArtifactHash) || !revisionRe.MatchString(value.ProfileRevision) {
		return OCRIdentity{}, false
	}
	return OCRIdentity{ModelID: value.ModelID, ModelRevision: value.ModelRevision, ArtifactHash: value.ArtifactHash, ProfileRevision: value.ProfileRevision}, true
}

func validateWarnings(values []wireWarning) ([]string, bool) {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !warningCodeRe.MatchString(value.Code) {
			return nil, false
		}
		out = append(out, value.Code)
	}
	return out, true
}

func validatePage(pageNumber int, value wirePage) (Page, bool) {
	warnings, ok := validateWarnings(value.Warnings)
	if !ok || len(value.Warnings) > MaxWarnings {
		return Page{}, false
	}
	tokens := make([]OCRToken, 0, len(value.Tokens))
	seenIDs := make(map[string]struct{}, len(value.Tokens))
	seenOrdinals := make(map[int]struct{}, len(value.Tokens))
	for index, wireToken := range value.Tokens {
		if wireToken.Page == nil || *wireToken.Page != pageNumber || wireToken.Ordinal == nil || *wireToken.Ordinal != index || wireToken.TokenID == "" || !identityRe.MatchString(wireToken.TokenID) {
			return Page{}, false
		}
		if _, duplicate := seenIDs[wireToken.TokenID]; duplicate {
			return Page{}, false
		}
		if _, duplicate := seenOrdinals[*wireToken.Ordinal]; duplicate {
			return Page{}, false
		}
		seenIDs[wireToken.TokenID] = struct{}{}
		seenOrdinals[*wireToken.Ordinal] = struct{}{}
		text, ok := canonicalToken(wireToken.CanonicalTokenText)
		if !ok || (wireToken.Confidence == nil) || math.IsNaN(*wireToken.Confidence) || math.IsInf(*wireToken.Confidence, 0) || *wireToken.Confidence < 0 || *wireToken.Confidence > 1 {
			return Page{}, false
		}
		box, ok := validateBox(wireToken.BoundingBox)
		if !ok {
			return Page{}, false
		}
		if wireToken.JoinAfter != "NONE" && wireToken.JoinAfter != "SPACE" && wireToken.JoinAfter != "LINE_BREAK" {
			return Page{}, false
		}
		tokens = append(tokens, OCRToken{Page: pageNumber, TokenID: wireToken.TokenID, CanonicalTokenText: text, Ordinal: *wireToken.Ordinal, JoinAfter: wireToken.JoinAfter, BoundingBox: box, Confidence: *wireToken.Confidence})
	}
	return Page{Page: pageNumber, Tokens: tokens, Warnings: warnings}, true
}

func canonicalToken(value string) (string, bool) {
	if value == "" || len([]byte(value)) > MaxTokenBytes {
		return "", false
	}
	canonical, err := canon.Canonicalize([]byte(value))
	if err != nil || len(canonical) == 0 || len(canonical) > MaxTokenBytes {
		return "", false
	}
	for _, r := range string(canonical) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", false
		}
	}
	return string(canonical), true
}

func validateBox(value wireOCRBox) (canon.OCRRectangle, bool) {
	if value.X == nil || value.Y == nil || value.Width == nil || value.Height == nil {
		return canon.OCRRectangle{}, false
	}
	box := canon.OCRRectangle{X: *value.X, Y: *value.Y, Width: *value.Width, Height: *value.Height}
	if box.X < 0 || box.Y < 0 || box.Width <= 0 || box.Height <= 0 || math.IsNaN(box.X) || math.IsNaN(box.Y) || math.IsNaN(box.Width) || math.IsNaN(box.Height) || math.IsInf(box.X, 0) || math.IsInf(box.Y, 0) || math.IsInf(box.Width, 0) || math.IsInf(box.Height, 0) || box.X > 1 || box.Y > 1 || box.Width > 1 || box.Height > 1 || box.X > 1-box.Width || box.Y > 1-box.Height {
		return canon.OCRRectangle{}, false
	}
	return box, true
}

func buildFragments(page Page, ordinal int) ([]Fragment, bool) {
	fragments := make([]Fragment, 0, (len(page.Tokens)+MaxFragmentTokens-1)/MaxFragmentTokens)
	for start := 0; start < len(page.Tokens); {
		end := start
		bytesUsed := 0
		for end < len(page.Tokens) && end-start < MaxFragmentTokens {
			candidate := bytesUsed + len([]byte(page.Tokens[end].CanonicalTokenText))
			if end > start {
				candidate++ // a separator is at most one UTF-8 byte for the fixed joins
			}
			if candidate > MaxFragmentTextBytes && end > start {
				break
			}
			bytesUsed = candidate
			end++
		}
		if end <= start {
			return nil, false
		}
		text := joinTokens(page.Tokens[start:end])
		if len(text) == 0 || len(text) > MaxFragmentTextBytes {
			return nil, false
		}
		boxes := make([]canon.OCRRectangle, end-start)
		for index := range boxes {
			boxes[index] = page.Tokens[start+index].BoundingBox
		}
		anchor, err := canon.OCRAnchorBytes(page.Page, page.Tokens[start].Ordinal, page.Tokens[end-1].Ordinal+1, boxes)
		if err != nil {
			return nil, false
		}
		tokens := append([]OCRToken(nil), page.Tokens[start:end]...)
		fragments = append(fragments, Fragment{Ordinal: ordinal, Page: page.Page, TokenStartOrdinal: page.Tokens[start].Ordinal, TokenEndOrdinal: page.Tokens[end-1].Ordinal + 1, CanonicalText: text, AnchorBytes: anchor, Tokens: tokens})
		ordinal++
		start = end
	}
	return fragments, true
}

func joinTokens(tokens []OCRToken) []byte {
	if len(tokens) == 0 {
		return nil
	}
	var out bytes.Buffer
	for index, token := range tokens {
		if index > 0 {
			previous := tokens[index-1]
			switch previous.JoinAfter {
			case "SPACE":
				out.WriteByte(' ')
			case "LINE_BREAK":
				out.WriteByte('\n')
			}
		}
		out.WriteString(token.CanonicalTokenText)
	}
	return out.Bytes()
}

func assembleObjectText(pages []Page) ([]byte, bool) {
	var out bytes.Buffer
	for index, page := range pages {
		if index > 0 {
			out.WriteByte('\n')
		}
		out.Write(joinTokens(page.Tokens))
		if out.Len() > MaxObjectTextBytes {
			return nil, false
		}
	}
	canonical, err := canon.Canonicalize(out.Bytes())
	if err != nil || len(canonical) == 0 || !bytes.Equal(canonical, out.Bytes()) {
		return nil, false
	}
	return out.Bytes(), true
}
