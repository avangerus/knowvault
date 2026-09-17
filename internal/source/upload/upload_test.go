package upload

import "testing"

func TestValidateAcceptsMatchingSignatureAndExtension(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		format  string
		family  Family
	}{
		{"report.pdf", append([]byte("%PDF-1.7\n"), make([]byte, 8)...), "PDF", FamilyPDF},
		{"report.docx", append([]byte("PK\x03\x04"), make([]byte, 8)...), "DOCX", FamilyOOXML},
		{"report.xlsx", append([]byte("PK\x03\x04"), make([]byte, 8)...), "XLSX", FamilyOOXML},
		{"report.pptx", append([]byte("PK\x03\x04"), make([]byte, 8)...), "PPTX", FamilyOOXML},
		{"notes.txt", []byte("hello world"), "TXT", FamilyText},
		{"notes.md", []byte("# hello"), "MARKDOWN", FamilyText},
		{"notes.html", []byte("<html></html>"), "HTML", FamilyText},
		{"rows.csv", []byte("a,b\n1,2\n"), "CSV", FamilyText},
	}
	for _, testCase := range cases {
		result, err := Validate(testCase.name, testCase.content)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", testCase.name, err)
		}
		if result.DeclaredFormat != testCase.format || result.MediaFamily != testCase.family {
			t.Fatalf("%s: got format=%s family=%s", testCase.name, result.DeclaredFormat, result.MediaFamily)
		}
		if result.ObjectKey != testCase.name {
			t.Fatalf("%s: unexpected object key %q", testCase.name, result.ObjectKey)
		}
	}
}

func TestValidateRejectsContentThatDoesNotMatchDeclaredExtension(t *testing.T) {
	// A renamed executable/zip disguised as a text file must fail on content,
	// never be accepted because the name looked safe.
	if _, err := Validate("notes.txt", []byte("PK\x03\x04binary")); CodeOf(err) != CodeSignatureMismatch {
		t.Fatalf("expected signature mismatch, got %v", err)
	}
	if _, err := Validate("report.pdf", []byte("not a pdf")); CodeOf(err) != CodeSignatureMismatch {
		t.Fatalf("expected signature mismatch, got %v", err)
	}
	if _, err := Validate("report.docx", []byte("plain text, not a zip")); CodeOf(err) != CodeSignatureMismatch {
		t.Fatalf("expected signature mismatch, got %v", err)
	}
}

func TestValidateRejectsUnknownExtension(t *testing.T) {
	if _, err := Validate("script.exe", []byte("MZ\x90\x00")); CodeOf(err) != CodeExtensionUnknown {
		t.Fatalf("expected extension unsupported, got %v", err)
	}
	if _, err := Validate("noext", []byte("hello")); CodeOf(err) != CodeExtensionUnknown {
		t.Fatalf("expected extension unsupported, got %v", err)
	}
}

func TestValidateRejectsEmptyAndOversized(t *testing.T) {
	if _, err := Validate("empty.txt", nil); CodeOf(err) != CodeEmpty {
		t.Fatalf("expected empty, got %v", err)
	}
	oversized := make([]byte, MaxFileBytes+1)
	copy(oversized, "hello")
	if _, err := Validate("big.txt", oversized); CodeOf(err) != CodeTooLarge {
		t.Fatalf("expected too large, got %v", err)
	}
}

func TestValidateRejectsBinaryTextDisguise(t *testing.T) {
	withNUL := []byte("hello\x00world")
	if _, err := Validate("notes.txt", withNUL); CodeOf(err) != CodeInvalidUTF8 {
		t.Fatalf("expected invalid utf8 for embedded NUL, got %v", err)
	}
}

func TestSanitizeObjectKeyFlattensPathAndRejectsTraversal(t *testing.T) {
	cases := map[string]string{
		"a/b/report.pdf":     "report.pdf",
		"a\\b\\report.pdf":   "report.pdf",
		"../../etc/passwd":   "passwd",
		"weird:name?.txt":    "weird_name_.txt",
		"  padded name.txt ": "padded name.txt",
	}
	for input, want := range cases {
		got, err := SanitizeObjectKey(input)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", input, err)
		}
		if got != want {
			t.Fatalf("%q: got %q want %q", input, got, want)
		}
	}
}

func TestSanitizeObjectKeyRejectsEmptyOrDotOnly(t *testing.T) {
	for _, input := range []string{"", ".", "..", "///", "   "} {
		if _, err := SanitizeObjectKey(input); CodeOf(err) != CodeNameInvalid {
			t.Fatalf("%q: expected name invalid, got %v", input, err)
		}
	}
}

func TestSanitizeObjectKeyBoundsLengthKeepingExtension(t *testing.T) {
	longStem := make([]byte, MaxObjectKeyLength+50)
	for i := range longStem {
		longStem[i] = 'a'
	}
	name := string(longStem) + ".pdf"
	got, err := SanitizeObjectKey(name)
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if len(got) > MaxObjectKeyLength {
		t.Fatalf("object key not bounded: %d bytes", len(got))
	}
	if got[len(got)-4:] != ".pdf" {
		t.Fatalf("extension not preserved: %q", got)
	}
}
