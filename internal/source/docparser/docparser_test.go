package docparser_test

import (
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/docparser"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := jsonv2.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return raw
}

func validParser() map[string]any {
	return map[string]any{
		"name":                         "knowvault-office-parser",
		"version":                      "1.0",
		"artifact_hash":                canon.Hash([]byte("worker@1.0")),
		"observation_profile_revision": "docx-obs-v1",
	}
}

func docxUnit(ordinal int, section []string, paragraphOrdinal int, nativeID, raw string) map[string]any {
	locator := map[string]any{
		"kind":              "DOCX",
		"section_path":      section,
		"paragraph_ordinal": paragraphOrdinal,
	}
	if nativeID != "" {
		locator["paragraph_native_id"] = nativeID
	}
	return map[string]any{"ordinal": ordinal, "locator": locator, "raw_text": raw}
}

func validDocxResult() map[string]any {
	return map[string]any{
		"result_version":  docparser.ResultVersion,
		"observed_format": "DOCX",
		"parser":          validParser(),
		"text_units": []any{
			docxUnit(1, []string{"word/document.xml", "body"}, 1, "native:p1", "Hello world"),
		},
		"warnings": []any{},
	}
}

func TestParseValidDOCX(t *testing.T) {
	res, err := docparser.Parse(mustJSON(t, validDocxResult()), docparser.FormatDOCX)
	if err != nil {
		t.Fatalf("valid DOCX rejected: %v", err)
	}
	if res.ObservedFormat != docparser.FormatDOCX || len(res.Fragments) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	f := res.Fragments[0]
	if string(f.CanonicalText) != "Hello world" || f.Anchor.Kind != "DOCX" ||
		f.Anchor.ParagraphID != "native:p1" || f.Anchor.TextStart != 0 || f.Anchor.TextEnd != 11 {
		t.Fatalf("unexpected fragment: %+v", f)
	}
	wantAnchor, err := canon.DocxAnchorBytes([]string{"word/document.xml", "body"}, "native:p1", 0, 11)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.AnchorBytes) != string(wantAnchor) {
		t.Fatalf("anchor not built by canon: %s", f.AnchorBytes)
	}
	if string(res.ObjectText) != "Hello world" || res.ObjectTextHash != canon.Hash([]byte("Hello world")) {
		t.Fatalf("object text not assembled by the validator: %q", res.ObjectText)
	}
}

func TestParseDerivesParagraphIDWhenNativeAbsent(t *testing.T) {
	m := validDocxResult()
	m["text_units"] = []any{docxUnit(1, []string{"word/document.xml", "body"}, 7, "", "\u0410\u0431\u0437\u0430\u0446")}

	res, err := docparser.Parse(mustJSON(t, m), docparser.FormatDOCX)
	if err != nil {
		t.Fatalf("valid DOCX rejected: %v", err)
	}
	want, err := canon.DerivedParagraphID([]string{"word/document.xml", "body"}, 7, canon.Hash([]byte("\u0410\u0431\u0437\u0430\u0446")))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Fragments[0].Anchor.ParagraphID; got != want {
		t.Fatalf("paragraph id not derived by canon: got %s want %s", got, want)
	}
}

// TestCanonicalizationIsGoOwned is the load-bearing proof of the single-owner rule:
// a worker built on different Unicode tables cannot change the Evidence. The same
// text delivered decomposed (NFD), precomposed (NFC), BOM-prefixed and CRLF-folded
// must produce byte-identical canonical text, hashes and anchors.
func TestCanonicalizationIsGoOwned(t *testing.T) {
	// Built from explicit code points so the fixture cannot be silently
	// re-normalized by any editor or tool that touches this file.
	nfc := string([]rune{0x00e9, '\n', 0x0419})              // precomposed
	nfd := string([]rune{'e', 0x0301, '\n', 0x0418, 0x0306}) // decomposed
	bomCRLF := string([]rune{0xfeff, 'e', 0x0301, '\r', '\n', 0x0418, 0x0306})
	crOnly := string([]rune{0xfeff, 'e', 0x0301, '\r', 0x0418, 0x0306})

	var reference docparser.Fragment
	for i, raw := range []string{nfc, nfd, bomCRLF, crOnly} {
		m := validDocxResult()
		m["text_units"] = []any{docxUnit(1, []string{"word/document.xml", "body"}, 1, "", raw)}

		res, err := docparser.Parse(mustJSON(t, m), docparser.FormatDOCX)
		if err != nil {
			t.Fatalf("raw form %d rejected: %v", i, err)
		}
		got := res.Fragments[0]
		if string(got.CanonicalText) != nfc {
			t.Fatalf("raw form %d not canonicalized to text-v1: %q", i, got.CanonicalText)
		}
		if i == 0 {
			reference = got
			continue
		}
		if string(got.AnchorBytes) != string(reference.AnchorBytes) ||
			got.Anchor.ParagraphID != reference.Anchor.ParagraphID ||
			got.Anchor.TextEnd != reference.Anchor.TextEnd {
			t.Fatalf("raw form %d produced a different Evidence identity than the reference form", i)
		}
	}
}

func TestParseAssemblesObjectTextFromUnits(t *testing.T) {
	m := validDocxResult()
	m["text_units"] = []any{
		docxUnit(1, []string{"word/document.xml", "body"}, 1, "", "first"),
		docxUnit(2, []string{"word/document.xml", "body"}, 2, "", "second"),
	}

	res, err := docparser.Parse(mustJSON(t, m), docparser.FormatDOCX)
	if err != nil {
		t.Fatalf("valid DOCX rejected: %v", err)
	}
	if string(res.ObjectText) != "first\nsecond" {
		t.Fatalf("unexpected object text: %q", res.ObjectText)
	}
	if res.ObjectTextHash != canon.Hash([]byte("first\nsecond")) {
		t.Fatalf("object text hash not computed by canon")
	}
}

func TestParseValidPPTX(t *testing.T) {
	res := map[string]any{
		"result_version": docparser.ResultVersion, "observed_format": "PPTX", "parser": validParser(),
		"text_units": []any{map[string]any{
			"ordinal":  1,
			"locator":  map[string]any{"kind": "PPTX", "slide": 1, "shape_id": "sp1"},
			"raw_text": "Slide title",
		}},
		"warnings": []any{},
	}
	parsed, err := docparser.Parse(mustJSON(t, res), docparser.FormatPPTX)
	if err != nil {
		t.Fatalf("valid PPTX rejected: %v", err)
	}
	want, err := canon.PptxAnchorBytes(1, "sp1", 0, len("Slide title"))
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Fragments[0].AnchorBytes) != string(want) {
		t.Fatalf("PPTX anchor not built by canon")
	}
}

func TestParseValidXLSX(t *testing.T) {
	res := map[string]any{
		"result_version": docparser.ResultVersion, "observed_format": "XLSX", "parser": validParser(),
		"text_units": []any{map[string]any{
			"ordinal":  1,
			"locator":  map[string]any{"kind": "XLSX", "sheet": "Sheet1", "cell": "B2"},
			"raw_text": "42",
		}},
		"warnings": []any{},
	}
	parsed, err := docparser.Parse(mustJSON(t, res), docparser.FormatXLSX)
	if err != nil {
		t.Fatalf("valid XLSX rejected: %v", err)
	}
	if parsed.Fragments[0].Anchor.Range != "B2" || parsed.Fragments[0].Anchor.Sheet != "Sheet1" {
		t.Fatalf("unexpected XLSX anchor: %+v", parsed.Fragments[0].Anchor)
	}
}

// mutate returns the valid DOCX result with a mutation applied, marshalled.
func mutate(t *testing.T, fn func(m map[string]any)) []byte {
	t.Helper()
	m := validDocxResult()
	fn(m)
	return mustJSON(t, m)
}

func unit0(m map[string]any) map[string]any { return m["text_units"].([]any)[0].(map[string]any) }
func locator0(m map[string]any) map[string]any {
	return unit0(m)["locator"].(map[string]any)
}

func TestParseRejects(t *testing.T) {
	cases := map[string]func(m map[string]any){
		// Protocol boundary: a smuggled database id / lifecycle / scope / pointer is
		// an unknown member and the strict decode rejects it — at every level.
		"smuggled top-level source_version_id": func(m map[string]any) { m["source_version_id"] = "v-123" },
		"smuggled top-level lifecycle_state":   func(m map[string]any) { m["lifecycle_state"] = "ACTIVE" },
		"smuggled top-level queryable":         func(m map[string]any) { m["queryable"] = true },
		"smuggled top-level scope_id":          func(m map[string]any) { m["source_scope_id"] = "scope-1" },
		"smuggled unit-level db id":            func(m map[string]any) { unit0(m)["fragment_id"] = "frag-1" },
		"smuggled parser-level db id":          func(m map[string]any) { m["parser"].(map[string]any)["version_id"] = "v" },
		"smuggled locator-level key":           func(m map[string]any) { locator0(m)["queryable"] = true },

		// Canonicalization boundary: the worker has no field in which to declare a
		// hash, an offset, a byte range, a normalization version, a canonical text or
		// a ready-made anchor. Each attempt is an unknown member.
		"smuggled evidence_text_hash":    func(m map[string]any) { unit0(m)["evidence_text_hash"] = canon.Hash([]byte("x")) },
		"smuggled anchor_hash":           func(m map[string]any) { unit0(m)["anchor_hash"] = canon.Hash([]byte("x")) },
		"smuggled canonical_text":        func(m map[string]any) { unit0(m)["canonical_text"] = "Hello world" },
		"smuggled canonical_object_text": func(m map[string]any) { m["canonical_object_text"] = "Hello world" },
		"smuggled ready-made anchor":     func(m map[string]any) { unit0(m)["anchor"] = map[string]any{"kind": "DOCX"} },
		"smuggled text_start":            func(m map[string]any) { locator0(m)["text_start"] = 0 },
		"smuggled text_end":              func(m map[string]any) { locator0(m)["text_end"] = 11 },
		"smuggled normalization_version": func(m map[string]any) { locator0(m)["normalization_version"] = "text-v1" },
		"smuggled parser_profile_revision": func(m map[string]any) {
			m["parser"].(map[string]any)["parser_profile_revision"] = "docx-v1"
		},

		// Version / format.
		"wrong result_version":    func(m map[string]any) { m["result_version"] = "document-parser-result-v2" },
		"unknown observed_format": func(m map[string]any) { m["observed_format"] = "RTF" },

		// Parser identity.
		"bad artifact_hash": func(m map[string]any) { m["parser"].(map[string]any)["artifact_hash"] = "deadbeef" },
		"empty parser name": func(m map[string]any) { m["parser"].(map[string]any)["name"] = "" },
		"bad observation revision": func(m map[string]any) {
			m["parser"].(map[string]any)["observation_profile_revision"] = "docx-v1"
		},
		"control char in parser name": func(m map[string]any) { m["parser"].(map[string]any)["name"] = "w\x01" },

		// Unit bounds / ordering.
		"empty text_units":       func(m map[string]any) { m["text_units"] = []any{} },
		"non-contiguous ordinal": func(m map[string]any) { unit0(m)["ordinal"] = 2 },
		"empty raw_text":         func(m map[string]any) { unit0(m)["raw_text"] = "" },
		"oversized raw_text": func(m map[string]any) {
			unit0(m)["raw_text"] = strings.Repeat("a", docparser.MaxUnitRawBytes+1)
		},
		// A unit whose raw text canonicalizes away entirely carries no Evidence.
		"raw_text canonicalizes to empty": func(m map[string]any) { unit0(m)["raw_text"] = string(rune(0xfeff)) },

		// Structural-position integrity: two units cannot claim the same node.
		"duplicate DOCX paragraph position": func(m map[string]any) {
			m["text_units"] = []any{
				docxUnit(1, []string{"body"}, 4, "", "first"),
				docxUnit(2, []string{"body"}, 4, "", "second"),
			}
		},

		// Locator constraints.
		"cross-format locator": func(m map[string]any) {
			unit0(m)["locator"] = map[string]any{"kind": "PPTX", "slide": 1, "shape_id": "sp1"}
		},
		"empty section_path":        func(m map[string]any) { locator0(m)["section_path"] = []any{} },
		"control char in section":   func(m map[string]any) { locator0(m)["section_path"] = []any{"a\x01b"} },
		"missing paragraph_ordinal": func(m map[string]any) { delete(locator0(m), "paragraph_ordinal") },
		"zero paragraph_ordinal":    func(m map[string]any) { locator0(m)["paragraph_ordinal"] = 0 },
		"worker-supplied derived id": func(m map[string]any) {
			locator0(m)["paragraph_native_id"] = "derived:sha256:" + strings.Repeat("a", 64)
		},
		"unprefixed native id": func(m map[string]any) { locator0(m)["paragraph_native_id"] = "p1" },

		// Warnings must be content-free codes.
		"bad warning code": func(m map[string]any) { m["warnings"] = []any{map[string]any{"code": "leaked secret text"}} },
	}

	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := docparser.Parse(mutate(t, fn), docparser.FormatDOCX); err == nil {
				t.Fatalf("mutation %q was accepted; expected rejection", name)
			}
		})
	}
}

func TestParseRejectsDispatchMismatch(t *testing.T) {
	// The worker answered for a format the runtime did not dispatch.
	if _, err := docparser.Parse(mustJSON(t, validDocxResult()), docparser.FormatXLSX); err == nil {
		t.Fatal("format mismatch accepted; expected rejection")
	}
	// And an undispatchable format is refused outright.
	if _, err := docparser.Parse(mustJSON(t, validDocxResult()), "PDF"); err == nil {
		t.Fatal("undispatched format accepted; expected rejection")
	}

	// A response whose observed format disagrees with dispatch must still be
	// rejected even when its locator happens to be valid for the dispatched
	// format. This prevents mutable worker metadata from selecting the resolver.
	mismatched := map[string]any{
		"result_version":  docparser.ResultVersion,
		"observed_format": "DOCX",
		"parser":          validParser(),
		"text_units": []any{map[string]any{
			"ordinal":  1,
			"locator":  map[string]any{"kind": "PPTX", "slide": 1, "shape_id": "sp1"},
			"raw_text": "Slide title",
		}},
		"warnings": []any{},
	}
	if _, err := docparser.Parse(mustJSON(t, mismatched), docparser.FormatPPTX); err == nil {
		t.Fatal("observed-format mismatch with a valid dispatched locator was accepted")
	}
}

func TestParseRejectsBadXLSXLocators(t *testing.T) {
	build := func(locator map[string]any) []byte {
		return mustJSON(t, map[string]any{
			"result_version": docparser.ResultVersion, "observed_format": "XLSX", "parser": validParser(),
			"text_units": []any{map[string]any{"ordinal": 1, "locator": locator, "raw_text": "42"}},
			"warnings":   []any{},
		})
	}
	cases := map[string]map[string]any{
		// The worker cannot widen a cell into a multi-cell range.
		"multi-cell range": {"kind": "XLSX", "sheet": "Sheet1", "cell": "A1:B2"},
		"lowercase column": {"kind": "XLSX", "sheet": "Sheet1", "cell": "b2"},
		"zero row":         {"kind": "XLSX", "sheet": "Sheet1", "cell": "B0"},
		"empty sheet":      {"kind": "XLSX", "sheet": "", "cell": "B2"},
		"control in sheet": {"kind": "XLSX", "sheet": "S\x01", "cell": "B2"},
		"smuggled range":   {"kind": "XLSX", "sheet": "Sheet1", "cell": "B2", "range": "A1:Z99"},
	}
	for name, locator := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := docparser.Parse(build(locator), docparser.FormatXLSX); err == nil {
				t.Fatalf("locator %q accepted; expected rejection", name)
			}
		})
	}
}

func TestParseRejectsDuplicateXLSXCell(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"result_version": docparser.ResultVersion, "observed_format": "XLSX", "parser": validParser(),
		"text_units": []any{
			map[string]any{"ordinal": 1, "locator": map[string]any{"kind": "XLSX", "sheet": "S", "cell": "B2"}, "raw_text": "a"},
			map[string]any{"ordinal": 2, "locator": map[string]any{"kind": "XLSX", "sheet": "S", "cell": "B2"}, "raw_text": "b"},
		},
		"warnings": []any{},
	})
	if _, err := docparser.Parse(raw, docparser.FormatXLSX); err == nil {
		t.Fatal("duplicate cell accepted; expected rejection")
	}
}

func TestParseRejectsDuplicatePPTXShape(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"result_version": docparser.ResultVersion, "observed_format": "PPTX", "parser": validParser(),
		"text_units": []any{
			map[string]any{"ordinal": 1, "locator": map[string]any{"kind": "PPTX", "slide": 2, "shape_id": "sp1"}, "raw_text": "a"},
			map[string]any{"ordinal": 2, "locator": map[string]any{"kind": "PPTX", "slide": 2, "shape_id": "sp1"}, "raw_text": "b"},
		},
		"warnings": []any{},
	})
	if _, err := docparser.Parse(raw, docparser.FormatPPTX); err == nil {
		t.Fatal("duplicate shape accepted; expected rejection")
	}
}

func TestParseRejectsDuplicateNames(t *testing.T) {
	// A duplicate object member is rejected by the strict decode. Built as raw
	// bytes because a Go map cannot express a duplicate key.
	raw := []byte(`{"result_version":"document-parser-result-v1","observed_format":"DOCX","observed_format":"XLSX",` +
		`"parser":{"name":"w","version":"1","artifact_hash":"sha256:` + strings.Repeat("0", 64) +
		`","observation_profile_revision":"docx-obs-v1"},"text_units":[],"warnings":[]}`)
	if _, err := docparser.Parse(raw, docparser.FormatDOCX); err == nil {
		t.Fatal("duplicate member accepted; expected rejection")
	}
}

func TestParseRejectsInvalidUTF8(t *testing.T) {
	prefix := `{"result_version":"document-parser-result-v1","observed_format":"DOCX",` +
		`"parser":{"name":"w","version":"1","artifact_hash":"sha256:` + strings.Repeat("0", 64) +
		`","observation_profile_revision":"docx-obs-v1"},"text_units":[{"ordinal":1,` +
		`"locator":{"kind":"DOCX","section_path":["body"],"paragraph_ordinal":1},"raw_text":"`
	suffix := `"}],"warnings":[]}`

	t.Run("raw invalid byte", func(t *testing.T) {
		raw := append([]byte(prefix), 0x80)
		raw = append(raw, []byte(suffix)...)
		if _, err := docparser.Parse(raw, docparser.FormatDOCX); err == nil {
			t.Fatal("invalid UTF-8 byte accepted; expected rejection")
		}
	})
	t.Run("unpaired surrogate escape", func(t *testing.T) {
		raw := []byte(prefix + `\ud800` + suffix)
		if _, err := docparser.Parse(raw, docparser.FormatDOCX); err == nil {
			t.Fatal("unpaired surrogate accepted; expected rejection")
		}
	})
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := docparser.Parse(nil, docparser.FormatDOCX); err == nil {
		t.Fatal("empty input accepted")
	}
	if _, err := docparser.Parse([]byte("not json"), docparser.FormatDOCX); err == nil {
		t.Fatal("garbage accepted")
	}
}
