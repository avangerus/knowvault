package evidence

import (
	"bytes"
	"context"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// WholeTextRepresentation describes what can be proven about returned bytes.
// A legacy assembly must never be labelled as a lossless canonical input.
type WholeTextRepresentation string

const (
	LegacyFragmentConcatV1    WholeTextRepresentation = "LEGACY_FRAGMENT_CONCAT_V1"
	CanonicalTextV1LayoutV2   WholeTextRepresentation = "CANONICAL_TEXT_V1_LAYOUT_V2"
	CanonicalStructuralTextV1 WholeTextRepresentation = "CANONICAL_STRUCTURAL_TEXT_V1"
)

func (object WholeObject) TextRepresentation() WholeTextRepresentation {
	if object.Representation == CanonicalStructuralTextV1 {
		return CanonicalStructuralTextV1
	}
	if object.Representation == CanonicalTextV1LayoutV2 {
		return CanonicalTextV1LayoutV2
	}
	return LegacyFragmentConcatV1
}

type orderedObjectFragment struct {
	id      string
	ordinal int64
}

type wholeTextAssembler struct {
	profile                 string
	requireLayout           bool
	text                    []byte
	spans                   []ObjectFragmentSpan
	layouts                 []canon.TextFragmentLayout
	canonicalFormat         string
	requireStructuralLayout bool
	structuralLayouts       []canon.StructuralFragmentLayout
}

func newWholeTextAssembler(canonicalFormat, profile string) *wholeTextAssembler {
	return &wholeTextAssembler{profile: profile, canonicalFormat: canonicalFormat, requireLayout: canonicalFormat == "TEXT" && canon.IsTextLayoutParserRevision(profile), requireStructuralLayout: canon.IsStructuralLayoutFormat(canonicalFormat) && canon.IsStructuralLayoutParserRevision(profile)}
}

// append accepts already-authorized artifacts. Geometry and the authenticated
// TEXT anchor must agree before bytes enter the candidate result. No candidate
// bytes are returned until finish verifies the complete buffer's hash.
func (assembly *wholeTextAssembler) append(item orderedObjectFragment, text, metadata, anchor []byte) error {
	if item.id == "" || item.ordinal != int64(len(assembly.spans)+1) || !utf8.Valid(text) {
		return ErrNotFound
	}
	span := ObjectFragmentSpan{FragmentID: item.id, Ordinal: item.ordinal, Offset: len(assembly.text), Length: len(text)}
	var gap []byte
	if assembly.requireStructuralLayout {
		var err error
		gap, err = assembly.structuralGap(item, span, metadata, anchor)
		if err != nil {
			return err
		}
	}
	if assembly.requireLayout {
		var fields map[string]any
		if err := jsonv2.Unmarshal(metadata, &fields); err != nil || len(fields) != 11 {
			return ErrNotFound
		}
		for _, key := range []string{"schema", "normalization_version", "parser_profile_revision", "ordinal", "line_start", "line_end", "canonical_byte_start", "canonical_byte_end", "gap_after_base64", "canonical_total_bytes", "canonical_sha256"} {
			if value, present := fields[key]; !present || value == nil {
				return ErrNotFound
			}
		}
		var layout canon.TextFragmentLayout
		if err := jsonv2.Unmarshal(metadata, &layout, jsonv2.RejectUnknownMembers(true)); err != nil {
			return ErrNotFound
		}
		if layout.Schema != "text-fragment-layout-v2" || layout.NormalizationVersion != canon.NormalizationVersion ||
			layout.ParserProfileRevision != assembly.profile || layout.Ordinal != int(item.ordinal) ||
			layout.LineStart < 1 || layout.LineEnd < layout.LineStart ||
			layout.CanonicalByteStart != span.Offset || layout.CanonicalByteEnd < layout.CanonicalByteStart ||
			layout.CanonicalByteEnd-layout.CanonicalByteStart != span.Length ||
			layout.CanonicalTotalBytes < layout.CanonicalByteEnd {
			return ErrNotFound
		}
		if len(assembly.layouts) > 0 {
			first := assembly.layouts[0]
			if layout.CanonicalTotalBytes != first.CanonicalTotalBytes || layout.CanonicalSHA256 != first.CanonicalSHA256 {
				return ErrNotFound
			}
		}
		var err error
		gap, err = base64.StdEncoding.Strict().DecodeString(layout.GapAfterBase64)
		if err != nil || base64.StdEncoding.EncodeToString(gap) != layout.GapAfterBase64 ||
			len(gap) > layout.CanonicalTotalBytes-layout.CanonicalByteEnd {
			return ErrNotFound
		}
		// Segment's omitted bytes can only be line terminators. Additional
		// source content must always belong to an authenticated text artifact.
		for _, value := range gap {
			if value != '\n' {
				return ErrNotFound
			}
		}
		expectedAnchor, err := canon.TextAnchorBytes(layout.LineStart, layout.LineEnd)
		if err != nil || !bytes.Equal(anchor, expectedAnchor) {
			return ErrNotFound
		}
		assembly.layouts = append(assembly.layouts, layout)
	}
	assembly.spans = append(assembly.spans, span)
	assembly.text = append(assembly.text, text...)
	assembly.text = append(assembly.text, gap...)
	return nil
}

func (assembly *wholeTextAssembler) finish() ([]byte, []ObjectFragmentSpan, WholeTextRepresentation, error) {
	if len(assembly.spans) == 0 {
		return nil, nil, "", ErrNotFound
	}
	if assembly.requireStructuralLayout {
		return assembly.finishStructural()
	}
	if !assembly.requireLayout {
		return assembly.text, assembly.spans, LegacyFragmentConcatV1, nil
	}
	first := assembly.layouts[0]
	if len(assembly.text) != first.CanonicalTotalBytes || canon.Hash(assembly.text) != first.CanonicalSHA256 {
		return nil, nil, "", ErrNotFound
	}
	canonical, err := canon.Canonicalize(assembly.text)
	if err != nil || !bytes.Equal(canonical, assembly.text) {
		return nil, nil, "", ErrNotFound
	}
	// The saved line addresses must resolve to precisely the text artifacts,
	// including UTF-8 and the document's leading/trailing blank lines.
	lines := canon.Lines(assembly.text)
	for index, layout := range assembly.layouts {
		if layout.LineEnd > len(lines) || lines[layout.LineStart-1].ByteStart != layout.CanonicalByteStart ||
			lines[layout.LineEnd-1].ByteEnd != layout.CanonicalByteEnd ||
			assembly.spans[index].Offset != layout.CanonicalByteStart {
			return nil, nil, "", ErrNotFound
		}
	}
	return assembly.text, assembly.spans, CanonicalTextV1LayoutV2, nil
}

func (v *Viewer) readWholeFragmentsInTransaction(ctx context.Context, tx database.Transaction, repo *repository.Repository,
	access database.AccessContext, workspaceID, expectedVersionID string, result *WholeObject, ordered []orderedObjectFragment) error {
	assembly := newWholeTextAssembler(result.Fragment.CanonicalFormat, result.Fragment.ParserProfileRevision)
	anchorFound := false
	fetch := func(field artifactcrypto.OwnerField, fragmentID string) ([]byte, error) {
		if expectedVersionID != "" {
			if err := setExactReadGUCs(ctx, tx, workspaceID, expectedVersionID); err != nil {
				return nil, err
			}
		} else if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return nil, err
		}
		owner, envelope, err := repo.Fetch(ctx, tx, access, field, fragmentID)
		if err != nil {
			return nil, err
		}
		return v.codec.Open(owner, envelope)
	}
	for _, item := range ordered {
		text, err := fetch(artifactcrypto.EvidenceNormalizedText, item.id)
		if err != nil {
			return err
		}
		var metadata, anchor []byte
		if assembly.requireLayout || assembly.requireStructuralLayout {
			metadata, err = fetch(artifactcrypto.EvidenceMetadata, item.id)
			if err != nil {
				return err
			}
			anchor, err = fetch(artifactcrypto.EvidenceAnchor, item.id)
			if err != nil {
				return err
			}
		}
		if err := assembly.append(item, text, metadata, anchor); err != nil {
			return err
		}
		if item.id == result.Fragment.FragmentID {
			if !bytes.Equal(text, result.Fragment.Text) {
				return ErrNotFound
			}
			anchorFound = true
		}
	}
	if !anchorFound {
		return ErrNotFound
	}
	text, spans, representation, err := assembly.finish()
	if err != nil {
		return err
	}
	result.Text, result.Fragments, result.Representation = text, spans, representation
	result.FragmentCount = int64(len(spans))
	result.FirstOrdinal, result.LastOrdinal = spans[0].Ordinal, spans[len(spans)-1].Ordinal
	return nil
}
