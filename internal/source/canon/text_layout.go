package canon

import (
	"bytes"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// TextFragmentLayoutSchema is the encrypted metadata schema used by new
	// text-anchor extractions that preserve canonical bytes between fragments.
	TextFragmentLayoutSchema = "text-fragment-layout-v2"
	textLayoutRevisionSuffix = "-layout-v2"
	maxParserProfileRunes    = 64
)

// ErrTextFragmentLayout reports a Segment set or canonical buffer that cannot
// be represented as a complete, exact text-fragment layout.
var ErrTextFragmentLayout = errors.New("canon: invalid text fragment layout")

// TextFragmentLayout records one text-v1 fragment's range in the full
// canonical source plus the exact line-feed gap after that range. The fields
// are encrypted per Evidence fragment; canonical_sha256 and
// canonical_total_bytes are repeated so a reader can validate a complete
// assembly without relying on a mutable extraction pointer.
type TextFragmentLayout struct {
	Schema                string `json:"schema"`
	NormalizationVersion  string `json:"normalization_version"`
	ParserProfileRevision string `json:"parser_profile_revision"`
	Ordinal               int    `json:"ordinal"`
	LineStart             int    `json:"line_start"`
	LineEnd               int    `json:"line_end"`
	CanonicalByteStart    int    `json:"canonical_byte_start"`
	CanonicalByteEnd      int    `json:"canonical_byte_end"`
	GapAfterBase64        string `json:"gap_after_base64"`
	CanonicalTotalBytes   int    `json:"canonical_total_bytes"`
	CanonicalSHA256       string `json:"canonical_sha256"`
}

// TextLayoutParserRevision returns the parser-profile revision that binds a
// text extraction to the v2 fragment-layout metadata. It returns an empty
// string when the source revision is empty, invalid UTF-8, or would exceed the
// immutable catalog's 64-character parser_profile_revision bound.
func TextLayoutParserRevision(revision string) string {
	if IsTextLayoutParserRevision(revision) {
		return revision
	}
	if !validParserProfileRevision(revision) || revision == textLayoutRevisionSuffix {
		return ""
	}
	layoutRevision := revision + textLayoutRevisionSuffix
	if !validParserProfileRevision(layoutRevision) {
		return ""
	}
	return layoutRevision
}

// IsTextLayoutParserRevision reports whether revision is a bounded parser
// profile that explicitly selects the text-fragment-layout-v2 metadata
// contract. A matching suffix is not enough when the complete profile value
// would violate the catalog's 64-character bound.
func IsTextLayoutParserRevision(revision string) bool {
	if !validParserProfileRevision(revision) || len(revision) <= len(textLayoutRevisionSuffix) {
		return false
	}
	base := revision[:len(revision)-len(textLayoutRevisionSuffix)]
	return revision[len(base):] == textLayoutRevisionSuffix && validParserProfileRevision(base)
}

// NewTextFragmentLayouts validates a complete Segment result against its
// canonical buffer and builds one layout record for every segment. Non-fragment
// bytes may only be LF separators; the gap after the final segment contains any
// final LF. The canonical SHA-256 is computed once and copied into each record.
func NewTextFragmentLayouts(canonical []byte, segments []Fragment, parserProfileRevision string) ([]TextFragmentLayout, error) {
	if !IsTextLayoutParserRevision(parserProfileRevision) || !canonicalTextBufferIsValid(canonical) {
		return nil, ErrTextFragmentLayout
	}
	if len(canonical) == 0 {
		if len(segments) == 0 {
			return []TextFragmentLayout{}, nil
		}
		return nil, ErrTextFragmentLayout
	}
	if len(segments) == 0 || segments[0].ByteStart != 0 {
		return nil, ErrTextFragmentLayout
	}

	canonicalHash := Hash(canonical)
	lines := Lines(canonical)
	layouts := make([]TextFragmentLayout, len(segments))
	previousEnd := 0
	previousLineEnd := 0
	for i, segment := range segments {
		if segment.Ordinal != i+1 || segment.LineStart < 1 || segment.LineEnd < segment.LineStart ||
			segment.LineStart <= previousLineEnd || segment.ByteStart < previousEnd ||
			segment.LineEnd > len(lines) || segment.ByteEnd <= segment.ByteStart || segment.ByteEnd > len(canonical) {
			return nil, ErrTextFragmentLayout
		}
		start := lines[segment.LineStart-1].ByteStart
		end := lines[segment.LineEnd-1].ByteEnd
		if start != segment.ByteStart || end != segment.ByteEnd || !bytes.Equal(segment.Text, canonical[segment.ByteStart:segment.ByteEnd]) {
			return nil, ErrTextFragmentLayout
		}
		nextStart := len(canonical)
		if i+1 < len(segments) {
			nextStart = segments[i+1].ByteStart
		}
		if nextStart < segment.ByteEnd || nextStart > len(canonical) {
			return nil, ErrTextFragmentLayout
		}
		gap := canonical[segment.ByteEnd:nextStart]
		for _, value := range gap {
			if value != '\n' {
				return nil, ErrTextFragmentLayout
			}
		}
		layouts[i] = TextFragmentLayout{
			Schema:                TextFragmentLayoutSchema,
			NormalizationVersion:  NormalizationVersion,
			ParserProfileRevision: parserProfileRevision,
			Ordinal:               segment.Ordinal,
			LineStart:             segment.LineStart,
			LineEnd:               segment.LineEnd,
			CanonicalByteStart:    segment.ByteStart,
			CanonicalByteEnd:      segment.ByteEnd,
			GapAfterBase64:        base64.StdEncoding.EncodeToString(gap),
			CanonicalTotalBytes:   len(canonical),
			CanonicalSHA256:       canonicalHash,
		}
		previousEnd = segment.ByteEnd
		previousLineEnd = segment.LineEnd
	}
	return layouts, nil
}

// Marshal returns the complete encrypted-metadata JSON value. No field is
// omitted, including an empty gap_after_base64 for a final non-newline source.
func (layout TextFragmentLayout) Marshal() ([]byte, error) {
	return jsonv2.Marshal(layout)
}

func canonicalTextBufferIsValid(canonical []byte) bool {
	if !utf8.Valid(canonical) || bytes.ContainsRune(canonical, '\r') ||
		bytes.HasPrefix(canonical, []byte{0xEF, 0xBB, 0xBF}) || !norm.NFC.IsNormal(canonical) {
		return false
	}
	return true
}

func validParserProfileRevision(revision string) bool {
	return revision != "" && utf8.ValidString(revision) && utf8.RuneCountInString(revision) <= maxParserProfileRunes
}
