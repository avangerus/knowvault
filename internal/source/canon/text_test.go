package canon

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

func TestCanonicalizeStripsBOMFoldsNewlinesAndComposes(t *testing.T) {
	// BOM + CRLF + lone CR + an NFD "e + combining acute (U+0301)" that NFC
	// composes to U+00E9. Written with escapes so the fixture is unambiguous.
	raw := append([]byte{0xEF, 0xBB, 0xBF}, []byte("a\r\nb\rc\né")...)
	got, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("a\nb\nc\né")
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
	if !utf8.Valid(got) {
		t.Fatal("canonical is not valid UTF-8")
	}
}

func TestCanonicalizeRejectsInvalidUTF8(t *testing.T) {
	if _, err := Canonicalize([]byte{0xff, 0xfe}); err != ErrInvalidUTF8 {
		t.Fatalf("err = %v, want ErrInvalidUTF8", err)
	}
}

func TestLineRangeBytesRoundTripsWithCyrillicAndEmoji(t *testing.T) {
	canonical, err := Canonicalize([]byte("\u041f\u0440\u0438\u043c\u0435\u0440\nline two \U0001f642 tail\n\u0442\u0440\u0435\u0442\u044c\u044f"))
	if err != nil {
		t.Fatal(err)
	}
	start, end, ok := LineRangeBytes(canonical, 2, 2)
	if !ok {
		t.Fatal("line 2 not resolvable")
	}
	if got := string(canonical[start:end]); got != "line two \U0001f642 tail" {
		t.Fatalf("line 2 = %q", got)
	}
	slice, ok := Slice(canonical, 1, 2)
	if !ok || string(slice) != "\u041f\u0440\u0438\u043c\u0435\u0440\nline two \U0001f642 tail" {
		t.Fatalf("range 1-2 = %q ok=%v", slice, ok)
	}
	if !utf8.Valid(slice) {
		t.Fatal("range slice split a code point")
	}
}

func TestLineRangeBytesRejectsOutOfRange(t *testing.T) {
	canonical := []byte("only")
	for _, c := range []struct{ s, e int }{{0, 1}, {1, 2}, {2, 1}} {
		if _, _, ok := LineRangeBytes(canonical, c.s, c.e); ok {
			t.Fatalf("range %d-%d unexpectedly resolved", c.s, c.e)
		}
	}
}

func TestSegmentPartitionsAllLinesWithoutGaps(t *testing.T) {
	canonical, err := Canonicalize([]byte("one\ntwo\nthree\nfour\n"))
	if err != nil {
		t.Fatal(err)
	}
	frags := Segment(canonical, 8)
	if len(frags) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frags))
	}
	expectLine := 1
	for i, f := range frags {
		if f.Ordinal != i+1 {
			t.Fatalf("fragment %d ordinal %d", i, f.Ordinal)
		}
		if f.LineStart != expectLine {
			t.Fatalf("fragment %d starts at line %d, want %d", i, f.LineStart, expectLine)
		}
		if f.ByteEnd <= f.ByteStart {
			t.Fatalf("fragment %d is empty", i)
		}
		slice, _ := Slice(canonical, f.LineStart, f.LineEnd)
		if !bytes.Equal(slice, f.Text) {
			t.Fatalf("fragment %d text disagrees with slice", i)
		}
		expectLine = f.LineEnd + 1
	}
	if frags[len(frags)-1].LineEnd != 4 {
		t.Fatalf("last fragment ends at line %d, want 4", frags[len(frags)-1].LineEnd)
	}
}

func TestSegmentEmptyDocumentYieldsNoFragments(t *testing.T) {
	if got := Segment(nil, 100); got != nil {
		t.Fatalf("empty document produced %d fragments", len(got))
	}
}

// TestSegmentLineCoverageIsGapFree pins the "contiguous, gap-free line ranges"
// invariant across CRLF, blank lines, and a missing trailing newline — the cases
// the database does not check (it only closes the ordinal set).
func TestSegmentLineCoverageIsGapFree(t *testing.T) {
	for _, raw := range []string{
		"one\r\ntwo\r\nthree\r\n",      // CRLF, trailing
		"a\n\nb\n\n\nc",                // interior blank lines, no trailing newline
		"only-one-line",                // single line, no newline
		"lead\n\n\ntail\n",             // leading run then trailing newline
		"x\nyyyyyyyyyyyyyyyyyyyy\nz\n", // a long middle line forcing a cut at small budget
	} {
		canonical, err := Canonicalize([]byte(raw))
		if err != nil {
			t.Fatalf("canonicalize %q: %v", raw, err)
		}
		for _, budget := range []int{3, 8, 4096} {
			frags := Segment(canonical, budget)
			if len(frags) == 0 {
				if len(canonical) == 0 {
					continue
				}
				t.Fatalf("no fragments for %q budget %d", raw, budget)
			}
			// Fragments partition lines 1..lastCovered contiguously with no gap.
			expect := frags[0].LineStart
			if expect != 1 {
				t.Fatalf("%q budget %d: first fragment starts at line %d", raw, budget, expect)
			}
			for _, f := range frags {
				if f.LineStart != expect {
					t.Fatalf("%q budget %d: gap at line %d (fragment starts %d)", raw, budget, expect, f.LineStart)
				}
				if f.ByteEnd <= f.ByteStart {
					t.Fatalf("%q budget %d: empty fragment", raw, budget)
				}
				slice, _ := Slice(canonical, f.LineStart, f.LineEnd)
				if string(slice) != string(f.Text) {
					t.Fatalf("%q budget %d: fragment text disagrees with its line range", raw, budget)
				}
				expect = f.LineEnd + 1
			}
		}
	}
}
