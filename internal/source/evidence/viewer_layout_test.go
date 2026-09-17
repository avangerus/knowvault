package evidence

import (
	"bytes"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

type layoutTestFragment struct {
	item                   orderedObjectFragment
	text, metadata, anchor []byte
}

func layoutTestParts(t *testing.T, input []byte, maxBytes int) ([]byte, string, []layoutTestFragment) {
	t.Helper()
	canonical, err := canon.Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	segments := canon.Segment(canonical, maxBytes)
	profile := canon.TextLayoutParserRevision("text-v1")
	layouts, err := canon.NewTextFragmentLayouts(canonical, segments, profile)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([]layoutTestFragment, 0, len(segments))
	for index, segment := range segments {
		metadata, err := layouts[index].Marshal()
		if err != nil {
			t.Fatal(err)
		}
		anchor, err := canon.TextAnchorBytes(segment.LineStart, segment.LineEnd)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, layoutTestFragment{orderedObjectFragment{fmt.Sprintf("fragment_%d", index+1), int64(segment.Ordinal)}, segment.Text, metadata, anchor})
	}
	return canonical, profile, parts
}

func assembleTestParts(profile string, parts []layoutTestFragment) ([]byte, []ObjectFragmentSpan, WholeTextRepresentation, error) {
	assembly := newWholeTextAssembler("TEXT", profile)
	for _, part := range parts {
		if err := assembly.append(part.item, part.text, part.metadata, part.anchor); err != nil {
			return nil, nil, "", err
		}
	}
	return assembly.finish()
}

func TestWholeTextLayoutPreservesCanonicalInput(t *testing.T) {
	cases := map[string][]byte{
		"49000 bytes":      []byte(strings.Repeat(strings.Repeat("x", 48)+"\n", 1000)),
		"no trailing LF":   []byte("first\nsecond\nthird"),
		"trailing LF":      []byte("first\nsecond\nthird\n"),
		"blank lines":      []byte("\n\nfirst\n\nsecond\n\n\n"),
		"only blank lines": []byte("\n\n\n"),
		"CRLF BOM Unicode": []byte("\ufeff\u041d\u0430\u0447\u0430\u043b\u043e\U0001faa8\r\ne\u0301\r\n\r\n\u043a\u043e\u043d\u0435\u0446\r"),
		"long line":        []byte(strings.Repeat("🪨", 100) + "\nend\n"),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			canonical, profile, parts := layoutTestParts(t, input, 64)
			text, spans, representation, err := assembleTestParts(profile, parts)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(text, canonical) || canon.Hash(text) != canon.Hash(canonical) || representation != CanonicalTextV1LayoutV2 {
				t.Fatalf("canonical fidelity: returned %d bytes, expected %d, representation %s", len(text), len(canonical), representation)
			}
			for index, span := range spans {
				if !bytes.Equal(text[span.Offset:span.Offset+span.Length], parts[index].text) {
					t.Fatal("fragment span changed")
				}
			}
		})
	}
}

func TestWholeTextLayoutKeepsLegacyAssemblyBytes(t *testing.T) {
	canonical, _, parts := layoutTestParts(t, []byte(strings.Repeat("first\nsecond\n", 20)), 16)
	var retained []byte
	for index := range parts {
		retained = append(retained, parts[index].text...)
		parts[index].metadata = nil
		parts[index].anchor = nil
	}
	text, _, representation, err := assembleTestParts("text-v1", parts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(text, retained) || bytes.Equal(text, canonical) || representation != LegacyFragmentConcatV1 {
		t.Fatal("legacy bytes/hash changed or legacy falsely marked canonical")
	}
	if (WholeObject{}).TextRepresentation() != LegacyFragmentConcatV1 {
		t.Fatal("unset representation claims canonical fidelity")
	}
}

func TestWholeTextLayoutDoesNotSelectNonTextProfileBySuffix(t *testing.T) {
	assembly := newWholeTextAssembler("PDF", "pdf-layout-v2")
	if err := assembly.append(orderedObjectFragment{"fragment", 1}, []byte("paragraph"), nil, nil); err != nil {
		t.Fatal(err)
	}
	text, _, representation, err := assembly.finish()
	if err != nil || string(text) != "paragraph" || representation != LegacyFragmentConcatV1 {
		t.Fatal("non-TEXT format accidentally selected TEXT layout")
	}
}

func TestWholeTextLayoutRejectsIncompleteOrTamperedAssembly(t *testing.T) {
	changeMetadata := func(t *testing.T, part *layoutTestFragment, fn func(map[string]any)) {
		t.Helper()
		var fields map[string]any
		if err := jsonv2.Unmarshal(part.metadata, &fields); err != nil {
			t.Fatal(err)
		}
		fn(fields)
		var err error
		part.metadata, err = jsonv2.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(*testing.T, []layoutTestFragment) []layoutTestFragment{
		"missing metadata": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment { p[0].metadata = nil; return p },
		"legacy metadata in new profile": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			p[0].metadata = []byte(`{"parser_profile_revision":"text-v1","line_start":1,"line_end":2}`)
			return p
		},
		"missing last fragment":  func(t *testing.T, p []layoutTestFragment) []layoutTestFragment { return p[:len(p)-1] },
		"missing first fragment": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment { return p[1:] },
		"wrong order":            func(t *testing.T, p []layoutTestFragment) []layoutTestFragment { p[0], p[1] = p[1], p[0]; return p },
		"changed text": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			p[0].text = bytes.Repeat([]byte("z"), len(p[0].text))
			return p
		},
		"wrong anchor": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment { p[0].anchor = p[1].anchor; return p },
		"missing field": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { delete(m, "gap_after_base64") })
			return p
		},
		"unknown field": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["unexpected"] = true })
			return p
		},
		"null field": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["gap_after_base64"] = nil })
			return p
		},
		"wrong schema": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["schema"] = "v3" })
			return p
		},
		"wrong normalization": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["normalization_version"] = "other" })
			return p
		},
		"wrong profile": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["parser_profile_revision"] = "csv-v1-layout-v2" })
			return p
		},
		"wrong offset": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[1], func(m map[string]any) { m["canonical_byte_start"] = 0 })
			return p
		},
		"wrong ordinal": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["ordinal"] = 2 })
			return p
		},
		"wrong line": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["line_end"] = 10000 })
			return p
		},
		"mixed totals": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[1], func(m map[string]any) { m["canonical_total_bytes"] = 1000000 })
			return p
		},
		"mixed hash": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[1], func(m map[string]any) { m["canonical_sha256"] = canon.Hash([]byte("other")) })
			return p
		},
		"wrong gap encoding": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["gap_after_base64"] = "!" })
			return p
		},
		"wrong gap bytes": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["gap_after_base64"] = base64.StdEncoding.EncodeToString([]byte("x")) })
			return p
		},
		"missing gap": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			changeMetadata(t, &p[0], func(m map[string]any) { m["gap_after_base64"] = "" })
			return p
		},
		"duplicate metadata field": func(t *testing.T, p []layoutTestFragment) []layoutTestFragment {
			p[0].metadata = append([]byte(`{"ordinal":1,`), p[0].metadata[1:]...)
			return p
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, profile, parts := layoutTestParts(t, []byte(strings.Repeat("first\nsecond\n", 20)), 16)
			text, spans, representation, err := assembleTestParts(profile, mutate(t, parts))
			if !errors.Is(err, ErrNotFound) || len(text) != 0 || len(spans) != 0 || representation != "" {
				t.Fatalf("tampering yielded partial result: %v", err)
			}
		})
	}
}
