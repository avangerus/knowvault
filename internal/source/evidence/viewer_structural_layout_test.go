package evidence

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func structuralParts(t *testing.T) (string, []layoutTestFragment) {
	t.Helper()
	profile := canon.StructuralLayoutParserRevision("xlsx-v1")
	units := []canon.StructuralTextUnit{{Ordinal: 1, Text: []byte("\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435\U0001f642"), Anchor: []byte(`{"kind":"XLSX","range":"A1","sheet":"Sheet 1"}`)}, {Ordinal: 2, Text: []byte("30"), Anchor: []byte(`{"kind":"XLSX","range":"D3","sheet":"Sheet 1"}`)}}
	layouts, err := canon.NewStructuralFragmentLayouts([]byte("\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435\U0001f642\n30"), units, "XLSX", profile)
	if err != nil {
		t.Fatal(err)
	}
	parts := make([]layoutTestFragment, 2)
	for i, unit := range units {
		metadata, err := jsonv2.Marshal(map[string]any{"parser_profile_revision": profile, "observer_name": "qualified-native", "canonical_text_layout": layouts[i]})
		if err != nil {
			t.Fatal(err)
		}
		parts[i] = layoutTestFragment{orderedObjectFragment{[]string{"fragment_1", "fragment_2"}[i], int64(i + 1)}, unit.Text, metadata, unit.Anchor}
	}
	return profile, parts
}

func assembleStructuralTest(profile string, parts []layoutTestFragment) ([]byte, []ObjectFragmentSpan, WholeTextRepresentation, error) {
	assembly := newWholeTextAssembler("XLSX", profile)
	for _, p := range parts {
		if err := assembly.append(p.item, p.text, p.metadata, p.anchor); err != nil {
			return nil, nil, "", err
		}
	}
	return assembly.finish()
}

func TestStructuralWholeReadPreservesSeparatorsAndAnchoredSpans(t *testing.T) {
	profile, parts := structuralParts(t)
	text, spans, representation, err := assembleStructuralTest(profile, parts)
	if err != nil || string(text) != "\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435\U0001f642\n30" || representation != CanonicalStructuralTextV1 {
		t.Fatalf("native assembly failed: %s %v", text, err)
	}
	for i, span := range spans {
		if !bytes.Equal(text[span.Offset:span.Offset+span.Length], parts[i].text) {
			t.Fatal("fragment span includes separator or loses UTF-8")
		}
	}
	if spans[1].Offset != len(parts[0].text)+1 || (WholeObject{Representation: representation}).TextRepresentation() != representation {
		t.Fatal("native layout not advertised")
	}
	legacy, _, kind, err := assembleStructuralTest("xlsx-v1", parts)
	if err != nil || string(legacy) != "\u0417\u043d\u0430\u0447\u0435\u043d\u0438\u0435\U0001f64230" || kind != LegacyFragmentConcatV1 {
		t.Fatal("historical address bytes changed")
	}
}

func TestStructuralWholeReadFailsClosedOnIncompleteOrChangedLayout(t *testing.T) {
	cases := map[string]func([]layoutTestFragment){
		"missing metadata":    func(p []layoutTestFragment) { p[0].metadata = nil },
		"different anchor":    func(p []layoutTestFragment) { p[1].anchor = []byte(`{"kind":"XLSX","range":"D4","sheet":"Sheet 1"}`) },
		"changed text":        func(p []layoutTestFragment) { p[1].text = []byte("31") },
		"reordered fragments": func(p []layoutTestFragment) { p[0], p[1] = p[1], p[0] },
	}
	for _, key := range []string{"schema", "parser_profile_revision", "canonical_format", "ordinal", "fragment_count", "canonical_byte_start", "canonical_byte_end", "canonical_total_bytes", "canonical_sha256", "anchor_sha256"} {
		key := key
		cases["changed "+key] = func(p []layoutTestFragment) {
			var outer map[string]any
			if err := jsonv2.Unmarshal(p[0].metadata, &outer); err != nil {
				t.Fatal(err)
			}
			layout := outer["canonical_text_layout"].(map[string]any)
			switch layout[key].(type) {
			case string:
				layout[key] = "wrong"
			default:
				layout[key] = float64(999)
			}
			p[0].metadata, _ = jsonv2.Marshal(outer)
		}
	}
	cases["null zero offset"] = func(p []layoutTestFragment) {
		p[0].metadata = bytes.Replace(p[0].metadata, []byte(`"canonical_byte_start":0`), []byte(`"canonical_byte_start":null`), 1)
	}
	cases["unknown field"] = func(p []layoutTestFragment) {
		p[0].metadata = bytes.Replace(p[0].metadata, []byte(`"canonical_text_layout":{`), []byte(`"canonical_text_layout":{"extra":1,`), 1)
	}
	cases["duplicate layout"] = func(p []layoutTestFragment) {
		p[0].metadata = append([]byte(`{"canonical_text_layout":{},`), p[0].metadata[1:]...)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			profile, parts := structuralParts(t)
			mutate(parts)
			if _, _, _, err := assembleStructuralTest(profile, parts); err == nil {
				t.Fatal("unproven native assembly returned")
			}
		})
	}
	profile, parts := structuralParts(t)
	if _, _, _, err := assembleStructuralTest(profile, parts[:1]); err == nil {
		t.Fatal("missing final fragment accepted")
	}
}
