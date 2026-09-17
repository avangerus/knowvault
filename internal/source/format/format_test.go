package format

import "testing"

func TestDetermineEnforcesAllowlistAndExtension(t *testing.T) {
	allowed := map[string]bool{"JSON": true, "XML": true, "TXT": true, "SOURCE_CODE": true, "PDF": true, "PNG": true, "JPEG": true}
	cases := []struct {
		path     string
		wantName string
		wantRev  string
		wantOK   bool
	}{
		{"projects/a/data.json", "JSON", RevisionJSON, true},
		{"a/b/doc.xml", "XML", RevisionXML, true},
		{"a/notes.txt", "TXT", RevisionText, true},
		{"a/main.go", "SOURCE_CODE", RevisionSourceCode, true},
		{"a/report.PDF", "PDF", RevisionPDF, true},
		{"a/data.csv", "", "", false}, // CSV not in allowlist
		{"a/photo.png", "PNG", RevisionPNG, true},
		{"a/photo.JPG", "JPEG", RevisionJPEG, true},
		{"a/noext", "", "", false},     // no extension
		{"a/trailing.", "", "", false}, // empty extension
	}
	for _, c := range cases {
		name, rev, ok := Determine(c.path, allowed)
		if ok != c.wantOK || name != c.wantName || rev != c.wantRev {
			t.Fatalf("Determine(%q) = (%q,%q,%v), want (%q,%q,%v)", c.path, name, rev, ok, c.wantName, c.wantRev, c.wantOK)
		}
	}
}

func TestDetermineObservationUsesTypedMailMedia(t *testing.T) {
	allowed := map[string]bool{"EML": true, "PDF": true, "TXT": true, "JSON": true}
	if name, revision, ok := DetermineObservation("EMAIL", "imap:mail", "message/rfc822", allowed); !ok || name != "EML" || revision != RevisionEML {
		t.Fatalf("email = (%q,%q,%v)", name, revision, ok)
	}
	if name, revision, ok := DetermineObservation("EMAIL_ATTACHMENT", "imap:mail;part:2", "application/pdf; charset=binary", allowed); !ok || name != "PDF" || revision != RevisionPDF {
		t.Fatalf("pdf attachment = (%q,%q,%v)", name, revision, ok)
	}
	if _, _, ok := DetermineObservation("EMAIL_ATTACHMENT", "imap:mail;part:3", "application/x-unknown", allowed); ok {
		t.Fatal("unknown attachment media type was admitted")
	}
}

func TestPDFRevisionIsClosed(t *testing.T) {
	if format, ok := PDFRevision(RevisionPDF); !ok || format != "PDF" {
		t.Fatalf("PDF revision = (%q,%v), want (PDF,true)", format, ok)
	}
	for _, revision := range []string{"", RevisionDOCX, "pdf-v2", RevisionText} {
		if _, ok := PDFRevision(revision); ok {
			t.Fatalf("non-PDF revision %q admitted", revision)
		}
	}
}

func TestOCRRevisionIsClosed(t *testing.T) {
	for _, tc := range []struct {
		revision, format string
	}{
		{RevisionPNG, "OCR"}, {RevisionJPEG, "OCR"},
	} {
		if format, ok := OCRRevision(tc.revision); !ok || format != tc.format {
			t.Fatalf("OCR revision %q = (%q,%v), want (%s,true)", tc.revision, format, ok, tc.format)
		}
	}
	for _, revision := range []string{"", RevisionPDF, RevisionDOCX, "png-v2", RevisionText} {
		if _, ok := OCRRevision(revision); ok {
			t.Fatalf("non-OCR revision %q admitted", revision)
		}
	}
}

func TestValidateJSON(t *testing.T) {
	if err := Validate(RevisionJSON, []byte(`{"a":1,"b":[2,3]}`)); err != nil {
		t.Fatalf("valid JSON rejected: %v", err)
	}
	for _, bad := range []string{
		``,                 // empty
		`{"a":1`,           // truncated
		`{"a":1} trailing`, // trailing data
		`{"a":1,"a":2}`,    // duplicate key (v2 rejects)
		`{a:1}`,            // unquoted key
	} {
		if err := Validate(RevisionJSON, []byte(bad)); err == nil {
			t.Fatalf("malformed JSON accepted: %q", bad)
		}
	}
}

func TestValidateXMLDeniesDTDAndEntities(t *testing.T) {
	if err := Validate(RevisionXML, []byte(`<?xml version="1.0"?><root><a>x</a></root>`)); err != nil {
		t.Fatalf("valid XML rejected: %v", err)
	}
	for _, bad := range []string{
		``,
		`<root><a></root>`, // mismatched tags
		// DTD / entity-expansion (billion laughs shape) must be denied outright.
		`<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><root>&lol;</root>`,
		// External entity (XXE) — the entity is undefined without DTD processing.
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		`<root>&undefined;</root>`, // undefined entity
	} {
		if err := Validate(RevisionXML, []byte(bad)); err == nil {
			t.Fatalf("unsafe/malformed XML accepted: %q", bad)
		}
	}
}

func TestValidateCSV(t *testing.T) {
	if err := Validate(RevisionCSV, []byte("h1,h2\n1,2\n3,4\n")); err != nil {
		t.Fatalf("valid CSV rejected: %v", err)
	}
	for _, bad := range []string{
		``,
		"a,b\n1,2,3\n", // ragged record
	} {
		if err := Validate(RevisionCSV, []byte(bad)); err == nil {
			t.Fatalf("malformed CSV accepted: %q", bad)
		}
	}
}

func TestValidateTextIsPassThrough(t *testing.T) {
	if err := Validate(RevisionText, []byte("anything at all\n")); err != nil {
		t.Fatalf("text pass-through rejected: %v", err)
	}
	if err := Validate(RevisionSourceCode, []byte("func main() {}\n")); err != nil {
		t.Fatalf("source-code text pass-through rejected: %v", err)
	}
	if err := Validate("unknown-v9", []byte("x")); err == nil {
		t.Fatal("unknown revision accepted")
	}
}
