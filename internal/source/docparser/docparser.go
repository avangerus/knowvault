// Package docparser is the Go re-validation boundary for the isolated
// document-parser worker (ADR-0062). The worker (an isolated, hostile data-plane
// component; the concrete extraction libraries are named in ADR-0062 and
// PARSER_CONTRACTS.md, not here — this validator is tool-agnostic) returns a
// closed, versioned `document-parser-result-v1` wire result over a transient
// channel; this package is the ONLY thing that turns those untrusted bytes into an
// accepted, publishable extraction.
//
// # Single canonicalization owner
//
// The worker is a parser OBSERVER, not a canonicalization authority. It reports
// what it saw — a structural locator per node plus that node's bounded RAW Unicode
// text — and nothing else. It cannot normalize, hash, offset, range or anchor,
// because the wire protocol has no field in which to say any of those things.
// Everything authoritative is computed here, from the raw text, through
// internal/source/canon: text-v1 normalization, canonical bytes, the canonical
// object text, every text and anchor hash, the derived DOCX paragraph identity,
// the fragment byte ranges, and the source-anchor JCS bytes.
//
// The load-bearing consequence: correctness does NOT depend on the worker's
// Unicode tables agreeing with Go's. A worker built on a different Unicode version
// cannot produce a differently-canonicalized Evidence set, because it produces no
// canonical bytes at all. Cross-language fixtures remain a useful detector of
// worker drift; they are not the foundation of correctness.
//
// # Enforcement
//
//   - STRUCTURAL: strict decode (reject unknown members + reject duplicate names).
//     A worker that smuggles a database id, lifecycle state, queryability, tenant
//     or workspace scope, a current-version pointer — or a hash, an offset, a byte
//     range, a normalization version or a ready-made anchor — is rejected because
//     the wire structs carry no such field: the key is unknown and the decode fails.
//   - RUNTIME: the observed format must equal the format the runtime dispatched and
//     every locator's kind must equal it too (cross-format isolation); every raw
//     unit must be valid UTF-8 within its bound and canonicalize to non-empty text;
//     two units may not claim the same structural position; every bound (unit
//     count, per-unit bytes, assembled object bytes, warning count) is re-checked;
//     and the assembled canonical object text must be idempotent under text-v1.
//
// Every violation collapses to the single content-free ErrInvalidResult sentinel so
// the caller quarantines the object with no fallback (PARSER_CONTRACTS.md §2) and no
// source text/markup/path/stack detail leaves the boundary. The worker output is an
// observation to be canonicalized and verified, never trusted as published; binding
// to a SourceVersion and publication remain the Go ingestion runtime's authority
// (ADR-0062 §2 publication boundary).
package docparser

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// ResultVersion is the only accepted wire protocol version. A new worker/profile
// that changes the wire shape mints a new version, never mutates this one.
const ResultVersion = "document-parser-result-v1"

// Formats this validator dispatches. S2b is Office; PDF joins the same validator in
// S2c through its own locator branch.
const (
	FormatDOCX = "DOCX"
	FormatPPTX = "PPTX"
	FormatXLSX = "XLSX"
)

// ObjectTextSeparator joins the canonical text of consecutive structural units into
// the canonical object text. It is a canon-side decision, not the worker's: the
// worker never sees or influences the assembled object text.
const ObjectTextSeparator = "\n"

// Resource bounds re-checked independently of the worker's own limits (ADR-0062
// §2 resource boundary): a unit-count, per-unit or whole-object bomb is rejected
// here even if the worker failed to bound it.
const (
	MaxTextUnits         = 100000
	MaxUnitRawBytes      = 262144
	MaxFragmentTextBytes = 262144
	MaxObjectTextBytes   = 67108864
	MaxWarnings          = 4096
	maxSectionDepth      = 64
)

// ErrInvalidResult is the single content-free sentinel for every rejection.
var ErrInvalidResult = errors.New("docparser: worker result rejected")

var (
	artifactHashRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	observationRevRe = regexp.MustCompile(`^[a-z0-9]+-obs-v[1-9][0-9]*$`)
	nativeParaIDRe   = regexp.MustCompile(`^native:[A-Za-z0-9._~:-]{1,240}$`)
	structuralTextRe = regexp.MustCompile(`^[^\x00-\x1f\x{007f}-\x{009f}]+$`)
	a1CellRe         = regexp.MustCompile(`^[A-Z]+[1-9][0-9]*$`)
	warningCodeRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// Parser is the worker's self-declared parser identity. It is not a database id and
// not a canonicalization version; the Go runtime re-checks it against the pinned
// worker identity and folds it into the immutable extraction profile hash, which is
// the runtime's own — not the worker's — authority.
type Parser struct {
	Name                       string
	Version                    string
	ArtifactHash               string
	ObservationProfileRevision string
	// RuntimeProfileHash is dispatcher-owned and is populated only by the
	// production facade after a kernel-confirmed one-shot execution. It is not a
	// worker wire field and therefore cannot be self-reported by the parser.
	RuntimeProfileHash string
}

// Anchor is a validated, typed office anchor built entirely by canon from the
// worker's structural locator and the text this package canonicalized. Exactly the
// fields for Kind are set.
type Anchor struct {
	Kind        string
	SectionPath []string // DOCX
	ParagraphID string   // DOCX (native, or derived here from canonical text)
	Slide       int      // PPTX
	ShapeID     string   // PPTX
	TextStart   int      // DOCX/PPTX (UTF-8 byte offset into the node's canonical text)
	TextEnd     int      // DOCX/PPTX
	Sheet       string   // XLSX
	Range       string   // XLSX (A1)
}

// Fragment is one Evidence unit ready for the ingestion runtime to persist: the
// canonical text this package produced and the canonical JCS anchor bytes canon
// built. Equality projections are deliberately absent; the ingestion owner
// computes them at the organization boundary, so a parser result cannot mint a
// public hash projection.
type Fragment struct {
	Ordinal       int
	CanonicalText []byte
	AnchorBytes   []byte
	Anchor        Anchor
}

// Result is the accepted, canonicalized extraction. It deliberately carries no
// database id, lifecycle, queryability, scope or pointer — the worker cannot supply
// those and this type cannot express them.
type Result struct {
	ObservedFormat string
	Parser         Parser
	ObjectText     []byte
	ObjectTextHash string
	Fragments      []Fragment
	Warnings       []string
}

type wireResult struct {
	ResultVersion  string     `json:"result_version"`
	ObservedFormat string     `json:"observed_format"`
	Parser         wireParser `json:"parser"`
	TextUnits      []wireUnit `json:"text_units"`
	Warnings       []wireWarn `json:"warnings"`
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

type wireDocxLocator struct {
	Kind             string   `json:"kind"`
	SectionPath      []string `json:"section_path"`
	ParagraphOrdinal *int     `json:"paragraph_ordinal"`
	ParagraphNative  string   `json:"paragraph_native_id"`
}

type wirePptxLocator struct {
	Kind    string `json:"kind"`
	Slide   *int   `json:"slide"`
	ShapeID string `json:"shape_id"`
}

type wireXlsxLocator struct {
	Kind  string `json:"kind"`
	Sheet string `json:"sheet"`
	Cell  string `json:"cell"`
}

// decodeStrict is the closed-protocol decode: an unknown member (a smuggled db id,
// lifecycle, scope, pointer, hash, offset or anchor) or a duplicate name is
// rejected. Invalid UTF-8 in a string is rejected by the decoder's default.
func decodeStrict(raw []byte, v any) error {
	return jsonv2.Unmarshal(raw, v, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
}

// Parse strictly decodes a worker wire result, canonicalizes it through canon and
// returns the publishable extraction. dispatched is the canonical format the Go
// runtime asked for; the worker's observed format and every locator kind must equal
// it, so a parser cannot answer for a format it was not dispatched for. On any
// violation Parse returns ErrInvalidResult and nil; the caller quarantines.
func Parse(raw []byte, dispatched string) (*Result, error) {
	if len(raw) == 0 || !isDispatchableFormat(dispatched) {
		return nil, ErrInvalidResult
	}
	var wire wireResult
	if err := decodeStrict(raw, &wire); err != nil {
		return nil, ErrInvalidResult
	}

	if wire.ResultVersion != ResultVersion || wire.ObservedFormat != dispatched {
		return nil, ErrInvalidResult
	}
	parser, ok := validateParser(wire.Parser)
	if !ok {
		return nil, ErrInvalidResult
	}
	if len(wire.TextUnits) < 1 || len(wire.TextUnits) > MaxTextUnits {
		return nil, ErrInvalidResult
	}
	if len(wire.Warnings) > MaxWarnings {
		return nil, ErrInvalidResult
	}

	warnings := make([]string, 0, len(wire.Warnings))
	for _, w := range wire.Warnings {
		if !warningCodeRe.MatchString(w.Code) {
			return nil, ErrInvalidResult
		}
		warnings = append(warnings, w.Code)
	}

	fragments := make([]Fragment, 0, len(wire.TextUnits))
	positions := make(map[string]bool, len(wire.TextUnits))
	for i, unit := range wire.TextUnits {
		frag, position, ok := buildFragment(dispatched, i, unit)
		if !ok {
			return nil, ErrInvalidResult
		}
		if positions[position] {
			return nil, ErrInvalidResult
		}
		positions[position] = true
		fragments = append(fragments, frag)
	}

	objectText, ok := assembleObjectText(fragments)
	if !ok {
		return nil, ErrInvalidResult
	}

	return &Result{
		ObservedFormat: wire.ObservedFormat,
		Parser:         parser,
		ObjectText:     objectText,
		ObjectTextHash: canon.Hash(objectText),
		Fragments:      fragments,
		Warnings:       warnings,
	}, nil
}

func isDispatchableFormat(format string) bool {
	return format == FormatDOCX || format == FormatPPTX || format == FormatXLSX
}

func validateParser(p wireParser) (Parser, bool) {
	if p.Name == "" || len(p.Name) > 128 || p.Version == "" || len(p.Version) > 64 {
		return Parser{}, false
	}
	if !structuralTextRe.MatchString(p.Name) || !structuralTextRe.MatchString(p.Version) {
		return Parser{}, false
	}
	if !artifactHashRe.MatchString(p.ArtifactHash) || !observationRevRe.MatchString(p.ObservationProfileRevision) {
		return Parser{}, false
	}
	return Parser{
		Name: p.Name, Version: p.Version,
		ArtifactHash: p.ArtifactHash, ObservationProfileRevision: p.ObservationProfileRevision,
	}, true
}

// buildFragment canonicalizes one raw text unit and builds its anchor. It returns
// the fragment and an opaque structural-position key used to refuse two units that
// claim the same paragraph, shape or cell.
func buildFragment(dispatched string, index int, unit wireUnit) (Fragment, string, bool) {
	if unit.Ordinal != index+1 {
		return Fragment{}, "", false
	}
	canonical, ok := canonicalizeUnit(unit.RawText)
	if !ok {
		return Fragment{}, "", false
	}

	anchor, anchorBytes, position, ok := buildAnchor(dispatched, unit.Locator, canonical)
	if !ok {
		return Fragment{}, "", false
	}

	return Fragment{
		Ordinal:       unit.Ordinal,
		CanonicalText: canonical,
		AnchorBytes:   anchorBytes,
		Anchor:        anchor,
	}, position, true
}

// canonicalizeUnit is the one place a worker's raw text becomes canonical bytes.
// The raw form is bounded before canonicalization (so a bomb cannot be normalized
// first) and the canonical form is bounded after it.
func canonicalizeUnit(raw string) ([]byte, bool) {
	if raw == "" || len(raw) > MaxUnitRawBytes {
		return nil, false
	}
	canonical, err := canon.Canonicalize([]byte(raw))
	if err != nil {
		return nil, false
	}
	if len(canonical) == 0 || len(canonical) > MaxFragmentTextBytes {
		return nil, false
	}
	return canonical, true
}

// buildAnchor validates the structural locator for the dispatched format and asks
// canon to build the anchor over the canonical text this package produced. The
// locator kind must equal the dispatched format (cross-format isolation: a DOCX
// dispatch cannot carry a PPTX/XLSX locator). The DOCX/PPTX byte range is always the
// node's full canonical extent — it is derived here, never declared by the worker,
// so a range that does not correspond to extracted text cannot exist.
func buildAnchor(dispatched string, raw jsontext.Value, canonical []byte) (Anchor, []byte, string, bool) {
	switch dispatched {
	case FormatDOCX:
		var l wireDocxLocator
		if decodeStrict(raw, &l) != nil {
			return Anchor{}, nil, "", false
		}
		if l.Kind != FormatDOCX || !validSectionPath(l.SectionPath) {
			return Anchor{}, nil, "", false
		}
		if l.ParagraphOrdinal == nil || *l.ParagraphOrdinal < 1 || *l.ParagraphOrdinal > MaxTextUnits {
			return Anchor{}, nil, "", false
		}
		paragraphID, ok := paragraphIdentity(l, canonical)
		if !ok {
			return Anchor{}, nil, "", false
		}
		start, end := 0, len(canonical)
		anchorBytes, err := canon.DocxAnchorBytes(l.SectionPath, paragraphID, start, end)
		if err != nil {
			return Anchor{}, nil, "", false
		}
		position := "DOCX\x00" + strings.Join(l.SectionPath, "\x00") + "\x00#" + strconv.Itoa(*l.ParagraphOrdinal)
		return Anchor{
			Kind: FormatDOCX, SectionPath: l.SectionPath, ParagraphID: paragraphID,
			TextStart: start, TextEnd: end,
		}, anchorBytes, position, true

	case FormatPPTX:
		var l wirePptxLocator
		if decodeStrict(raw, &l) != nil {
			return Anchor{}, nil, "", false
		}
		if l.Kind != FormatPPTX || l.Slide == nil || *l.Slide < 1 || *l.Slide > MaxTextUnits {
			return Anchor{}, nil, "", false
		}
		if l.ShapeID == "" || len(l.ShapeID) > 256 || !structuralTextRe.MatchString(l.ShapeID) {
			return Anchor{}, nil, "", false
		}
		start, end := 0, len(canonical)
		anchorBytes, err := canon.PptxAnchorBytes(*l.Slide, l.ShapeID, start, end)
		if err != nil {
			return Anchor{}, nil, "", false
		}
		position := "PPTX\x00" + strconv.Itoa(*l.Slide) + "\x00" + l.ShapeID
		return Anchor{
			Kind: FormatPPTX, Slide: *l.Slide, ShapeID: l.ShapeID,
			TextStart: start, TextEnd: end,
		}, anchorBytes, position, true

	case FormatXLSX:
		var l wireXlsxLocator
		if decodeStrict(raw, &l) != nil {
			return Anchor{}, nil, "", false
		}
		if l.Kind != FormatXLSX || l.Sheet == "" || len(l.Sheet) > 255 || !structuralTextRe.MatchString(l.Sheet) {
			return Anchor{}, nil, "", false
		}
		if !a1CellRe.MatchString(l.Cell) {
			return Anchor{}, nil, "", false
		}
		anchorBytes, err := canon.XlsxAnchorBytes(l.Sheet, l.Cell)
		if err != nil {
			return Anchor{}, nil, "", false
		}
		position := "XLSX\x00" + l.Sheet + "\x00" + l.Cell
		return Anchor{Kind: FormatXLSX, Sheet: l.Sheet, Range: l.Cell}, anchorBytes, position, true

	default:
		return Anchor{}, nil, "", false
	}
}

// paragraphIdentity returns the DOCX paragraph id. A worker may report the OOXML
// native id (a structural observation it legitimately owns); when it does not, the
// id is derived HERE from the section path, the paragraph ordinal and the hash of
// the text this package canonicalized (CANONICALIZATION.md §3). A worker cannot
// supply a "derived:" id — the native pattern refuses it — so the canonicalization
// dependent identity always has exactly one owner.
func paragraphIdentity(l wireDocxLocator, canonical []byte) (string, bool) {
	if l.ParagraphNative != "" {
		if len(l.ParagraphNative) > 256 || !nativeParaIDRe.MatchString(l.ParagraphNative) {
			return "", false
		}
		return l.ParagraphNative, true
	}
	derived, err := canon.DerivedParagraphID(l.SectionPath, *l.ParagraphOrdinal, canon.Hash(canonical))
	if err != nil {
		return "", false
	}
	return derived, true
}

func validSectionPath(path []string) bool {
	if len(path) < 1 || len(path) > maxSectionDepth {
		return false
	}
	for _, seg := range path {
		if seg == "" || len(seg) > 256 || !structuralTextRe.MatchString(seg) {
			return false
		}
	}
	return true
}

// assembleObjectText builds the canonical object text from the canonicalized units.
// The result is bounded and re-checked for text-v1 idempotence: concatenation must
// not produce a form that differs from its own canonicalization, or the object text
// and the fragment texts would disagree about what the canonical bytes are.
func assembleObjectText(fragments []Fragment) ([]byte, bool) {
	texts := make([][]byte, 0, len(fragments))
	total := 0
	for _, frag := range fragments {
		texts = append(texts, frag.CanonicalText)
		total += len(frag.CanonicalText)
	}
	total += len(ObjectTextSeparator) * (len(texts) - 1)
	if total > MaxObjectTextBytes {
		return nil, false
	}
	objectText := bytes.Join(texts, []byte(ObjectTextSeparator))
	canonical, err := canon.Canonicalize(objectText)
	if err != nil || !bytes.Equal(canonical, objectText) {
		return nil, false
	}
	return objectText, true
}
