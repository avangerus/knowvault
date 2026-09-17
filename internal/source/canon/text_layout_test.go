package canon

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestTextLayoutParserRevision(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		valid bool
	}{
		{name: "default profile", input: "text-v1", want: "text-v1-layout-v2", valid: true},
		{name: "idempotent", input: "custom-layout-v2", want: "custom-layout-v2", valid: true},
		{name: "empty", input: "", valid: false},
		{name: "suffix exceeds catalog bound", input: strings.Repeat("x", 64), valid: false},
		{name: "suffix alone", input: "-layout-v2", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := TextLayoutParserRevision(test.input)
			if got != test.want {
				t.Fatalf("TextLayoutParserRevision(%q) = %q, want %q", test.input, got, test.want)
			}
			if IsTextLayoutParserRevision(got) != test.valid {
				t.Fatalf("IsTextLayoutParserRevision(%q) = %t, want %t", got, IsTextLayoutParserRevision(got), test.valid)
			}
		})
	}
}

func TestNewTextFragmentLayoutsPreserveCanonicalGaps(t *testing.T) {
	raw := []byte("alpha\r\n\nβ🙂\rlast\r\n")
	canonical, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantCanonical := []byte("alpha\n\nβ🙂\nlast\n")
	if !bytes.Equal(canonical, wantCanonical) {
		t.Fatalf("Canonicalize() = %q, want %q", canonical, wantCanonical)
	}
	fragments := Segment(canonical, 6)
	layouts, err := NewTextFragmentLayouts(canonical, fragments, "text-v1-layout-v2")
	if err != nil {
		t.Fatal(err)
	}
	assertTextLayoutReconstructs(t, canonical, fragments, layouts)
	if len(layouts) != 3 {
		t.Fatalf("got %d layouts, want 3", len(layouts))
	}
	if got := layouts[0].GapAfterBase64; got != base64.StdEncoding.EncodeToString([]byte("\n")) {
		t.Fatalf("first layout gap = %q, want base64 LF", got)
	}
	if got := layouts[2].GapAfterBase64; got != base64.StdEncoding.EncodeToString([]byte("\n")) {
		t.Fatalf("last layout gap = %q, want trailing LF", got)
	}
	for _, name := range []string{
		"schema", "normalization_version", "parser_profile_revision", "ordinal",
		"line_start", "line_end", "canonical_byte_start", "canonical_byte_end",
		"gap_after_base64", "canonical_total_bytes", "canonical_sha256",
	} {
		encoded, err := layouts[0].Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(encoded, []byte(`"`+name+`"`)) {
			t.Fatalf("marshaled layout omitted %q: %s", name, encoded)
		}
	}
	if layouts[0].Schema != TextFragmentLayoutSchema ||
		layouts[0].NormalizationVersion != NormalizationVersion ||
		layouts[0].ParserProfileRevision != "text-v1-layout-v2" ||
		layouts[0].CanonicalTotalBytes != len(canonical) ||
		layouts[0].CanonicalSHA256 != Hash(canonical) {
		t.Fatalf("layout header does not bind canonical text: %+v", layouts[0])
	}
}

func TestNewTextFragmentLayoutsLongSourceAndMultibyteBoundaries(t *testing.T) {
	longCanonical := []byte(strings.Repeat(strings.Repeat("x", 999)+"\n", 49))
	if len(longCanonical) != 49000 {
		t.Fatalf("test source size = %d, want 49000", len(longCanonical))
	}
	longFragments := Segment(longCanonical, 4096)
	longLayouts, err := NewTextFragmentLayouts(longCanonical, longFragments, "text-v1-layout-v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(longLayouts) < 2 {
		t.Fatalf("long source produced %d fragment layouts, want multiple", len(longLayouts))
	}
	assertTextLayoutReconstructs(t, longCanonical, longFragments, longLayouts)

	multibyte := []byte(strings.Repeat("α", 3000) + "\n\n" + strings.Repeat("🙂", 1400) + "\n")
	fragments := Segment(multibyte, 4096)
	layouts, err := NewTextFragmentLayouts(multibyte, fragments, "text-v1-layout-v2")
	if err != nil {
		t.Fatal(err)
	}
	assertTextLayoutReconstructs(t, multibyte, fragments, layouts)
	if len(layouts) != 2 || layouts[0].GapAfterBase64 != base64.StdEncoding.EncodeToString([]byte("\n\n")) {
		t.Fatalf("blank-line/multibyte boundaries were not preserved: %+v", layouts)
	}
}

func TestNewTextFragmentLayoutsHandleTailAndNoTailLF(t *testing.T) {
	for _, test := range []struct {
		name string
		text string
		gap  string
	}{
		{name: "trailing LF", text: "one\ntwo\n", gap: "\n"},
		{name: "no trailing LF", text: "one\ntwo", gap: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			canonical := []byte(test.text)
			fragments := Segment(canonical, 3)
			layouts, err := NewTextFragmentLayouts(canonical, fragments, "text-v1-layout-v2")
			if err != nil {
				t.Fatal(err)
			}
			assertTextLayoutReconstructs(t, canonical, fragments, layouts)
			if got := layouts[len(layouts)-1].GapAfterBase64; got != base64.StdEncoding.EncodeToString([]byte(test.gap)) {
				t.Fatalf("final gap = %q, want %q", got, test.gap)
			}
		})
	}
}

func TestNewTextFragmentLayoutsRejectInvalidCoverage(t *testing.T) {
	profile := "text-v1-layout-v2"
	tests := []struct {
		name      string
		canonical []byte
		segments  []Fragment
		profile   string
	}{
		{
			name:      "missing segments for nonempty source",
			canonical: []byte("a"),
			profile:   profile,
		},
		{
			name:      "leading gap",
			canonical: []byte("a\nb"),
			segments:  []Fragment{{Ordinal: 1, LineStart: 2, LineEnd: 2, ByteStart: 2, ByteEnd: 3, Text: []byte("b")}},
			profile:   profile,
		},
		{
			name:      "non-LF omitted source bytes",
			canonical: []byte("a\nskip\nb"),
			segments: []Fragment{
				{Ordinal: 1, LineStart: 1, LineEnd: 1, ByteStart: 0, ByteEnd: 1, Text: []byte("a")},
				{Ordinal: 2, LineStart: 3, LineEnd: 3, ByteStart: 7, ByteEnd: 8, Text: []byte("b")},
			},
			profile: profile,
		},
		{
			name:      "tampered fragment text",
			canonical: []byte("a\nb"),
			segments:  []Fragment{{Ordinal: 1, LineStart: 1, LineEnd: 2, ByteStart: 0, ByteEnd: 3, Text: []byte("a\nx")}},
			profile:   profile,
		},
		{
			name:      "out of order ordinal",
			canonical: []byte("a\nb"),
			segments:  []Fragment{{Ordinal: 2, LineStart: 1, LineEnd: 2, ByteStart: 0, ByteEnd: 3, Text: []byte("a\nb")}},
			profile:   profile,
		},
		{
			name:      "legacy profile cannot claim layout",
			canonical: []byte("a"),
			segments:  Segment([]byte("a"), 10),
			profile:   "text-v1",
		},
		{
			name:      "noncanonical CR byte",
			canonical: []byte("a\rb"),
			segments:  Segment([]byte("a\rb"), 10),
			profile:   profile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewTextFragmentLayouts(test.canonical, test.segments, test.profile); err == nil {
				t.Fatal("NewTextFragmentLayouts succeeded for invalid coverage")
			}
		})
	}
}

func assertTextLayoutReconstructs(t *testing.T, canonical []byte, fragments []Fragment, layouts []TextFragmentLayout) {
	t.Helper()
	if len(fragments) != len(layouts) {
		t.Fatalf("fragments/layouts count mismatch: %d/%d", len(fragments), len(layouts))
	}
	var rebuilt []byte
	for i, layout := range layouts {
		fragment := fragments[i]
		if layout.Ordinal != fragment.Ordinal || layout.LineStart != fragment.LineStart || layout.LineEnd != fragment.LineEnd ||
			layout.CanonicalByteStart != fragment.ByteStart || layout.CanonicalByteEnd != fragment.ByteEnd {
			t.Fatalf("layout %d does not match segment: %+v vs %+v", i, layout, fragment)
		}
		if layout.CanonicalTotalBytes != len(canonical) || layout.CanonicalSHA256 != Hash(canonical) {
			t.Fatalf("layout %d has inconsistent whole-source identity: %+v", i, layout)
		}
		gap, err := base64.StdEncoding.DecodeString(layout.GapAfterBase64)
		if err != nil {
			t.Fatalf("layout %d gap is invalid base64: %v", i, err)
		}
		rebuilt = append(rebuilt, fragment.Text...)
		rebuilt = append(rebuilt, gap...)
	}
	if !bytes.Equal(rebuilt, canonical) {
		t.Fatalf("layout reconstruction mismatch: got %q, want %q", rebuilt, canonical)
	}
}
