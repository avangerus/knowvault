package canon

import (
	"bytes"
	"errors"
)

const (
	StructuralFragmentLayoutSchema = "structural-fragment-layout-v1"
	structuralLayoutRevisionSuffix = "-struct-layout-v1"
)

var ErrStructuralFragmentLayout = errors.New("canon: invalid structural fragment layout")

// StructuralTextUnit carries canon-owned text and its existing structural anchor.
// The layout does not replace page, cell or paragraph coordinates.
type StructuralTextUnit struct {
	Ordinal      int
	Text, Anchor []byte
}

// StructuralFragmentLayout binds a native fragment to the complete canonical
// object text. Office/PDF join structural units with exactly one LF; the final
// unit has no added separator. Metadata is encrypted with each evidence unit.
type StructuralFragmentLayout struct {
	Schema                string `json:"schema"`
	NormalizationVersion  string `json:"normalization_version"`
	ParserProfileRevision string `json:"parser_profile_revision"`
	CanonicalFormat       string `json:"canonical_format"`
	Ordinal               int    `json:"ordinal"`
	FragmentCount         int    `json:"fragment_count"`
	CanonicalByteStart    int    `json:"canonical_byte_start"`
	CanonicalByteEnd      int    `json:"canonical_byte_end"`
	CanonicalTotalBytes   int    `json:"canonical_total_bytes"`
	CanonicalSHA256       string `json:"canonical_sha256"`
	AnchorSHA256          string `json:"anchor_sha256"`
}

func StructuralLayoutParserRevision(revision string) string {
	if IsStructuralLayoutParserRevision(revision) {
		return revision
	}
	if !validParserProfileRevision(revision) || revision == structuralLayoutRevisionSuffix {
		return ""
	}
	result := revision + structuralLayoutRevisionSuffix
	if !validParserProfileRevision(result) {
		return ""
	}
	return result
}

func IsStructuralLayoutParserRevision(revision string) bool {
	if !validParserProfileRevision(revision) || len(revision) <= len(structuralLayoutRevisionSuffix) {
		return false
	}
	base := revision[:len(revision)-len(structuralLayoutRevisionSuffix)]
	return revision[len(base):] == structuralLayoutRevisionSuffix && validParserProfileRevision(base)
}

func IsStructuralLayoutFormat(format string) bool {
	switch format {
	case "DOCX", "PPTX", "XLSX", "PDF":
		return true
	}
	return false
}

// NewStructuralFragmentLayouts verifies complete, ordered coverage of the
// parser's accepted ObjectText rather than inventing a different assembly.
func NewStructuralFragmentLayouts(canonical []byte, units []StructuralTextUnit, format, profile string) ([]StructuralFragmentLayout, error) {
	if !IsStructuralLayoutFormat(format) || !IsStructuralLayoutParserRevision(profile) || !canonicalTextBufferIsValid(canonical) || len(canonical) == 0 || len(units) == 0 {
		return nil, ErrStructuralFragmentLayout
	}
	result := make([]StructuralFragmentLayout, 0, len(units))
	offset := 0
	digest := Hash(canonical)
	for i, unit := range units {
		if unit.Ordinal != i+1 || len(unit.Text) == 0 || len(unit.Anchor) == 0 || offset > len(canonical) || len(unit.Text) > len(canonical)-offset {
			return nil, ErrStructuralFragmentLayout
		}
		end := offset + len(unit.Text)
		if !bytes.Equal(canonical[offset:end], unit.Text) {
			return nil, ErrStructuralFragmentLayout
		}
		result = append(result, StructuralFragmentLayout{Schema: StructuralFragmentLayoutSchema, NormalizationVersion: NormalizationVersion, ParserProfileRevision: profile, CanonicalFormat: format, Ordinal: i + 1, FragmentCount: len(units), CanonicalByteStart: offset, CanonicalByteEnd: end, CanonicalTotalBytes: len(canonical), CanonicalSHA256: digest, AnchorSHA256: Hash(unit.Anchor)})
		offset = end
		if i+1 < len(units) {
			if offset >= len(canonical) || canonical[offset] != '\n' {
				return nil, ErrStructuralFragmentLayout
			}
			offset++
		}
	}
	if offset != len(canonical) {
		return nil, ErrStructuralFragmentLayout
	}
	return result, nil
}
