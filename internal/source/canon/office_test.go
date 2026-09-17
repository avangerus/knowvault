package canon

import "testing"

// The office anchor builders are golden-locked: any drift in the JCS form (key
// set, ordering, const values) changes an anchor hash and must force a new
// parser-profile revision (PARSER_CONTRACTS.md §6), so it must break this test
// rather than silently re-anchor historical Evidence.

func TestDocxAnchorBytesGolden(t *testing.T) {
	got, err := DocxAnchorBytes([]string{"a", "b"}, "native:p1", 0, 11)
	if err != nil {
		t.Fatalf("DocxAnchorBytes: %v", err)
	}
	want := `{"kind":"DOCX","normalization_version":"text-v1","offset_unit":"UTF8_BYTE","paragraph_id":"native:p1","range_semantics":"START_INCLUSIVE_END_EXCLUSIVE","section_path":["a","b"],"text_end":11,"text_start":0}`
	if string(got) != want {
		t.Fatalf("DOCX anchor JCS drift:\n got=%s\nwant=%s", got, want)
	}
}

func TestPptxAnchorBytesGolden(t *testing.T) {
	got, err := PptxAnchorBytes(2, "sp1", 0, 5)
	if err != nil {
		t.Fatalf("PptxAnchorBytes: %v", err)
	}
	want := `{"kind":"PPTX","normalization_version":"text-v1","offset_unit":"UTF8_BYTE","range_semantics":"START_INCLUSIVE_END_EXCLUSIVE","shape_id":"sp1","slide":2,"text_end":5,"text_start":0}`
	if string(got) != want {
		t.Fatalf("PPTX anchor JCS drift:\n got=%s\nwant=%s", got, want)
	}
}

// The derived DOCX paragraph identity is a function of canonicalized text, so it is
// canon's authority and golden-locked for the same reason: drift would silently
// re-identify historical paragraphs.
func TestDerivedParagraphIDGolden(t *testing.T) {
	textHash := Hash([]byte("Hello world"))
	got, err := DerivedParagraphID([]string{"a", "b"}, 3, textHash)
	if err != nil {
		t.Fatalf("DerivedParagraphID: %v", err)
	}
	want := "derived:" + Hash([]byte(
		`{"normalization_version":"text-v1","paragraph_ordinal":3,"paragraph_text_hash":"`+textHash+`","section_path":["a","b"]}`))
	if got != want {
		t.Fatalf("derived paragraph id drift:\n got=%s\nwant=%s", got, want)
	}
	if len(got) != len("derived:sha256:")+64 {
		t.Fatalf("unexpected derived id shape: %s", got)
	}
}

// The same paragraph text in a decomposed and a precomposed form must derive the
// SAME id, because the id is taken from canon's own canonicalization. This is what
// makes the identity independent of any second implementation of Unicode.
func TestDerivedParagraphIDIsNormalizationStable(t *testing.T) {
	nfc, err := Canonicalize([]byte(string([]rune{0x00e9, 'x'})))
	if err != nil {
		t.Fatal(err)
	}
	nfd, err := Canonicalize([]byte(string([]rune{'e', 0x0301, 'x'})))
	if err != nil {
		t.Fatal(err)
	}
	a, err := DerivedParagraphID([]string{"s"}, 1, Hash(nfc))
	if err != nil {
		t.Fatal(err)
	}
	b, err := DerivedParagraphID([]string{"s"}, 1, Hash(nfd))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("derived id differs across input normalization forms: %s vs %s", a, b)
	}
}

func TestXlsxAnchorBytesGolden(t *testing.T) {
	got, err := XlsxAnchorBytes("Sheet1", "A1:B2")
	if err != nil {
		t.Fatalf("XlsxAnchorBytes: %v", err)
	}
	want := `{"kind":"XLSX","range":"A1:B2","sheet":"Sheet1"}`
	if string(got) != want {
		t.Fatalf("XLSX anchor JCS drift:\n got=%s\nwant=%s", got, want)
	}
}
