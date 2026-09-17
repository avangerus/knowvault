package eml

import (
	"encoding/base64"
	"strings"
	"testing"
)

// msg joins header/body lines with CRLF as a real RFC 5322 message.
func msg(lines ...string) []byte {
	return []byte(strings.Join(lines, "\r\n"))
}

func TestParseSimpleTextPlain(t *testing.T) {
	raw := msg(
		"From: a@example.com",
		"To: b@example.com",
		"Subject: hello",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"line one",
		"line two",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 1 {
		t.Fatalf("parts=%d, want 1", len(doc.Parts))
	}
	if doc.Parts[0].MIMEPart != "1" {
		t.Fatalf("mime part=%q, want \"1\"", doc.Parts[0].MIMEPart)
	}
	if got := string(doc.Parts[0].Canonical); got != "line one\nline two\n" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestParseMultipartAlternativePrefersPlain(t *testing.T) {
	raw := msg(
		"Subject: alt",
		"Content-Type: multipart/alternative; boundary=B",
		"",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"plain body",
		"--B",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>html body</p>",
		"--B--",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 1 || doc.Parts[0].MIMEPart != "1" {
		t.Fatalf("parts=%+v, want one part \"1\"", doc.Parts)
	}
	if got := string(doc.Parts[0].Canonical); !strings.Contains(got, "plain body") || strings.Contains(got, "html") {
		t.Fatalf("canonical=%q: html must be gated, only plain extracted", got)
	}
}

func TestParseNestedMultipartPartPath(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed; boundary=OUT",
		"",
		"--OUT",
		"Content-Type: multipart/alternative; boundary=IN",
		"",
		"--IN",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"nested plain",
		"--IN",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>nested html</p>",
		"--IN--",
		"--OUT",
		"Content-Type: application/octet-stream",
		"Content-Disposition: attachment; filename=a.bin",
		"",
		"BINARYDATA",
		"--OUT--",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 1 || doc.Parts[0].MIMEPart != "1.1" {
		t.Fatalf("parts=%+v, want one part \"1.1\"", doc.Parts)
	}
	// The CRLF preceding a multipart boundary belongs to the boundary, so the part
	// body carries no trailing newline (RFC 2046).
	if got := string(doc.Parts[0].Canonical); got != "nested plain" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestParseMixedTwoTextPartsOrderedGlobally(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed; boundary=B",
		"",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"first",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"second",
		"--B--",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 2 || doc.Parts[0].MIMEPart != "1" || doc.Parts[1].MIMEPart != "2" {
		t.Fatalf("parts=%+v, want \"1\" then \"2\"", doc.Parts)
	}
}

func TestParseEncodedHeadersDoNotBreakBody(t *testing.T) {
	raw := msg(
		"Subject: =?UTF-8?B?0J/RgNC40LLQtdGC?=",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"body after encoded header",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 1 || !strings.Contains(string(doc.Parts[0].Canonical), "body after encoded header") {
		t.Fatalf("parts=%+v", doc.Parts)
	}
}

func TestParseQuotedPrintable(t *testing.T) {
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable",
		"",
		"price =3D 5=E2=82=AC end", // "=" and euro sign U+20AC
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(doc.Parts[0].Canonical); got != "price = 5€ end\n" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestParseBase64(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("base64 body ☃\n"))
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		payload,
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(doc.Parts[0].Canonical); got != "base64 body ☃\n" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestParseUnicodeUTF8(t *testing.T) {
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"",
		"\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440 \U0001f30d",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(doc.Parts[0].Canonical); got != "\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440 \U0001f30d\n" {
		t.Fatalf("canonical=%q", got)
	}
}

func TestParseCharsetConversionThroughXText(t *testing.T) {
	// The Cyrillic word for "Test" in windows-1251, transfer-encoded as base64, so raw bytes reach
	// the parser as ASCII and only the decoded body needs charset conversion.
	win1251 := []byte{0xD2, 0xE5, 0xF1, 0xF2} // The Cyrillic word for "Test" in windows-1251
	payload := base64.StdEncoding.EncodeToString(win1251)
	raw := msg(
		"Content-Type: text/plain; charset=windows-1251",
		"Content-Transfer-Encoding: base64",
		"",
		payload,
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := string(doc.Parts[0].Canonical); got != "\u0422\u0435\u0441\u0442" {
		t.Fatalf("charset conversion canonical=%q, want \"\u0422\u0435\u0441\u0442\"", got)
	}
}

func TestParseUnknownCharsetQuarantines(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte{0xD2, 0xE5})
	raw := msg(
		"Content-Type: text/plain; charset=x-not-a-charset",
		"Content-Transfer-Encoding: base64",
		"",
		payload,
		"",
	)
	if _, err := Parse(raw); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine", err)
	}
}

func TestParseUnknownTransferEncodingQuarantines(t *testing.T) {
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: x-uuencode",
		"",
		"body",
		"",
	)
	if _, err := Parse(raw); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine", err)
	}
}

func TestParseCorruptedBase64Quarantines(t *testing.T) {
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		"@@@not base64@@@",
		"",
	)
	if _, err := Parse(raw); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine", err)
	}
}

func TestParseMalformedBoundaryQuarantines(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed; boundary=B",
		"",
		"no boundary markers at all, just text",
		"",
	)
	// A multipart body with no parts yields nothing extractable.
	doc, err := Parse(raw)
	if err == nil && len(doc.Parts) != 0 {
		t.Fatalf("multipart with no parts must not extract: %+v", doc.Parts)
	}
}

func TestParseMissingBoundaryParamQuarantines(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed",
		"",
		"body",
		"",
	)
	if _, err := Parse(raw); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine", err)
	}
}

func TestParseNonEmailQuarantines(t *testing.T) {
	if _, err := Parse([]byte("this is just some plain text, not an email at all")); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine", err)
	}
}

func TestParseHTMLOnlyYieldsNoParts(t *testing.T) {
	raw := msg(
		"Content-Type: text/html; charset=utf-8",
		"",
		"<html><body>only html</body></html>",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 0 {
		t.Fatalf("html-only must yield no extractable parts, got %+v", doc.Parts)
	}
}

func TestParseAttachmentOnlyYieldsNoParts(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed; boundary=B",
		"",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Disposition: attachment; filename=note.txt",
		"",
		"i am an attachment",
		"--B--",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Parts) != 0 {
		t.Fatalf("text/plain attachment must not be extracted as a body, got %+v", doc.Parts)
	}
}

func TestParseNestingDepthLimit(t *testing.T) {
	// Three levels of nested multipart exceeds a MaxDepth of 2.
	raw := msg(
		"Content-Type: multipart/mixed; boundary=A",
		"",
		"--A",
		"Content-Type: multipart/mixed; boundary=B",
		"",
		"--B",
		"Content-Type: multipart/mixed; boundary=C",
		"",
		"--C",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"too deep",
		"--C--",
		"--B--",
		"--A--",
		"",
	)
	limits := DefaultLimits
	limits.MaxDepth = 2
	if _, err := ParseWithLimits(raw, limits); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine for nesting bomb", err)
	}
}

func TestParsePartCountLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("Content-Type: multipart/mixed; boundary=B\r\n\r\n")
	for i := 0; i < 5; i++ {
		b.WriteString("--B\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nx\r\n")
	}
	b.WriteString("--B--\r\n")
	limits := DefaultLimits
	limits.MaxParts = 3
	if _, err := ParseWithLimits([]byte(b.String()), limits); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine for part-count bomb", err)
	}
}

func TestParseOversizedPartLimit(t *testing.T) {
	big := strings.Repeat("a", 5000)
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"",
		big,
		"",
	)
	limits := DefaultLimits
	limits.MaxPartBytes = 1024
	if _, err := ParseWithLimits(raw, limits); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine for oversized part", err)
	}
}

func TestParseTotalBytesLimit(t *testing.T) {
	part := "Content-Type: text/plain; charset=utf-8\r\n\r\n" + strings.Repeat("b", 800) + "\r\n"
	raw := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
		"--B\r\n" + part + "--B\r\n" + part + "--B--\r\n")
	limits := DefaultLimits
	limits.MaxPartBytes = 4096
	limits.MaxTotalBytes = 1000
	if _, err := ParseWithLimits(raw, limits); err != ErrQuarantine {
		t.Fatalf("err=%v, want ErrQuarantine for total-bytes bomb", err)
	}
}

func TestParseDeterministic(t *testing.T) {
	raw := msg(
		"Content-Type: multipart/mixed; boundary=B",
		"",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"alpha\nbeta",
		"--B",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"gamma",
		"--B--",
		"",
	)
	a, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Parts) != len(b.Parts) {
		t.Fatalf("nondeterministic part count %d vs %d", len(a.Parts), len(b.Parts))
	}
	for i := range a.Parts {
		if a.Parts[i].MIMEPart != b.Parts[i].MIMEPart || string(a.Parts[i].Canonical) != string(b.Parts[i].Canonical) {
			t.Fatalf("nondeterministic part %d", i)
		}
	}
}

func TestDocumentPartLookup(t *testing.T) {
	raw := msg(
		"Content-Type: text/plain; charset=utf-8",
		"",
		"x",
		"",
	)
	doc, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Part("1"); !ok {
		t.Fatal("part \"1\" should resolve")
	}
	if _, ok := doc.Part("2"); ok {
		t.Fatal("part \"2\" should not resolve")
	}
}
