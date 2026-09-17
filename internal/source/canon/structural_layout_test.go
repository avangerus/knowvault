package canon

import (
	"bytes"
	"strings"
	"testing"
)

func TestStructuralLayoutPreservesAcceptedNativeText(t *testing.T) {
	units := []StructuralTextUnit{{1, []byte("\u041d\u0430\u0447\u0430\u043b\u043e\n\u0432\u043d\u0443\u0442\u0440\u0438"), []byte("paragraph-1")}, {2, []byte("10"), []byte("cell-D3")}, {3, []byte("30🙂\n"), []byte("cell-D5")}}
	whole := []byte("\u041d\u0430\u0447\u0430\u043b\u043e\n\u0432\u043d\u0443\u0442\u0440\u0438\n10\n30\U0001f642\n")
	for _, format := range []string{"DOCX", "PPTX", "XLSX", "PDF"} {
		profile := StructuralLayoutParserRevision("parser-v1")
		layouts, err := NewStructuralFragmentLayouts(whole, units, format, profile)
		if err != nil {
			t.Fatal(err)
		}
		var rebuilt []byte
		for i, layout := range layouts {
			if layout.CanonicalByteStart != len(rebuilt) || layout.AnchorSHA256 != Hash(units[i].Anchor) || layout.CanonicalSHA256 != Hash(whole) || layout.FragmentCount != 3 {
				t.Fatal("layout lost native binding")
			}
			rebuilt = append(rebuilt, units[i].Text...)
			if layout.CanonicalByteEnd != len(rebuilt) {
				t.Fatal("byte offsets disagree")
			}
			if i+1 < len(layouts) {
				rebuilt = append(rebuilt, '\n')
			}
		}
		if !bytes.Equal(rebuilt, whole) {
			t.Fatal("canonical native text changed")
		}
	}
}

func TestStructuralLayoutRejectsUnprovenCoverage(t *testing.T) {
	profile := StructuralLayoutParserRevision("office-v1")
	for name, whole := range map[string]string{"missing separator": "1030", "extra separator": "10\n\n30", "uncovered suffix": "10\n30\n", "wrong text": "10\n20", "CRLF": "10\r\n30"} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewStructuralFragmentLayouts([]byte(whole), []StructuralTextUnit{{1, []byte("10"), []byte("a")}, {2, []byte("30"), []byte("b")}}, "XLSX", profile); err == nil {
				t.Fatal("unproven layout accepted")
			}
		})
	}
	for _, units := range [][]StructuralTextUnit{nil, {{2, []byte("10"), []byte("a")}}, {{1, []byte("10"), nil}}, {{1, nil, []byte("a")}}} {
		if _, err := NewStructuralFragmentLayouts([]byte("10"), units, "DOCX", profile); err == nil {
			t.Fatal("invalid units accepted")
		}
	}
	if _, err := NewStructuralFragmentLayouts([]byte("10"), []StructuralTextUnit{{1, []byte("10"), []byte("a")}}, "TEXT", profile); err == nil {
		t.Fatal("text anchor treated as native")
	}
}

func TestStructuralLayoutRevisionHasSeparateBoundedIdentity(t *testing.T) {
	profile := StructuralLayoutParserRevision("pdf-v1")
	if profile != "pdf-v1-struct-layout-v1" || StructuralLayoutParserRevision(profile) != profile || IsTextLayoutParserRevision(profile) {
		t.Fatal("profile identity is not distinct/idempotent")
	}
	for _, bad := range []string{"", structuralLayoutRevisionSuffix, strings.Repeat("x", 64), string([]byte{0xff})} {
		if StructuralLayoutParserRevision(bad) != "" {
			t.Fatal("invalid profile accepted")
		}
	}
}
