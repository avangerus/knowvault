package evidence

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func (assembly *wholeTextAssembler) structuralGap(item orderedObjectFragment, span ObjectFragmentSpan, metadata, anchor []byte) ([]byte, error) {
	var outer map[string]jsontext.Value
	if err := jsonv2.Unmarshal(metadata, &outer); err != nil {
		return nil, ErrNotFound
	}
	var profile string
	if err := jsonv2.Unmarshal(outer["parser_profile_revision"], &profile); err != nil || profile != assembly.profile {
		return nil, ErrNotFound
	}
	encoded := outer["canonical_text_layout"]
	var fields map[string]any
	if err := jsonv2.Unmarshal(encoded, &fields); err != nil || len(fields) != 11 {
		return nil, ErrNotFound
	}
	for _, key := range []string{"schema", "normalization_version", "parser_profile_revision", "canonical_format", "ordinal", "fragment_count", "canonical_byte_start", "canonical_byte_end", "canonical_total_bytes", "canonical_sha256", "anchor_sha256"} {
		if value, present := fields[key]; !present || value == nil {
			return nil, ErrNotFound
		}
	}
	var layout canon.StructuralFragmentLayout
	if err := jsonv2.Unmarshal(encoded, &layout, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, ErrNotFound
	}
	if layout.Schema != canon.StructuralFragmentLayoutSchema || layout.NormalizationVersion != canon.NormalizationVersion || layout.ParserProfileRevision != assembly.profile || layout.CanonicalFormat != assembly.canonicalFormat ||
		layout.Ordinal != int(item.ordinal) || layout.FragmentCount < layout.Ordinal || layout.CanonicalByteStart != span.Offset || layout.CanonicalByteEnd <= layout.CanonicalByteStart || layout.CanonicalByteEnd-layout.CanonicalByteStart != span.Length || layout.CanonicalTotalBytes < layout.CanonicalByteEnd || len(anchor) == 0 || canon.Hash(anchor) != layout.AnchorSHA256 {
		return nil, ErrNotFound
	}
	if len(assembly.structuralLayouts) > 0 {
		first := assembly.structuralLayouts[0]
		if layout.FragmentCount != first.FragmentCount || layout.CanonicalTotalBytes != first.CanonicalTotalBytes || layout.CanonicalSHA256 != first.CanonicalSHA256 {
			return nil, ErrNotFound
		}
	}
	var gap []byte
	if layout.Ordinal < layout.FragmentCount {
		if layout.CanonicalByteEnd >= layout.CanonicalTotalBytes {
			return nil, ErrNotFound
		}
		gap = []byte{'\n'}
	} else if layout.CanonicalByteEnd != layout.CanonicalTotalBytes {
		return nil, ErrNotFound
	}
	assembly.structuralLayouts = append(assembly.structuralLayouts, layout)
	return gap, nil
}

func (assembly *wholeTextAssembler) finishStructural() ([]byte, []ObjectFragmentSpan, WholeTextRepresentation, error) {
	if len(assembly.structuralLayouts) != len(assembly.spans) || len(assembly.structuralLayouts) == 0 {
		return nil, nil, "", ErrNotFound
	}
	first := assembly.structuralLayouts[0]
	if len(assembly.spans) != first.FragmentCount || len(assembly.text) != first.CanonicalTotalBytes || canon.Hash(assembly.text) != first.CanonicalSHA256 {
		return nil, nil, "", ErrNotFound
	}
	canonical, err := canon.Canonicalize(assembly.text)
	if err != nil || !bytes.Equal(canonical, assembly.text) {
		return nil, nil, "", ErrNotFound
	}
	return assembly.text, assembly.spans, CanonicalStructuralTextV1, nil
}
