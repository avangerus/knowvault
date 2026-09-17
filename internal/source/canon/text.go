// Package canon owns the one normative text-v1 canonicalization, the exact
// line<->UTF-8-byte mapping used by both the extractor and the anchor resolver,
// and the canonical JCS/hash forms of the source locator, extraction profile and
// Evidence set. Keeping a single implementation here is what lets an anchor
// resolve unambiguously and identically no matter who computes it.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// NormalizationVersion is the only canonical text form in 1.0.
const NormalizationVersion = "text-v1"

// ErrInvalidUTF8 is returned when the declared UTF-8 source does not decode
// unambiguously. S1d supports only UTF-8 text; a torn or mislabelled byte stream
// is quarantined upstream, never canonicalized into trusted Evidence.
var ErrInvalidUTF8 = errors.New("canon: source is not valid UTF-8")

// Canonicalize applies text-v1 in the fixed order of CANONICALIZATION.md s1:
// decode UTF-8 (error on ambiguity), strip a single leading BOM, fold CRLF and a
// lone CR to LF, apply Unicode NFC via the pinned x/text tables, and emit UTF-8
// without a BOM. Every other whitespace and newline is preserved.
func Canonicalize(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidUTF8
	}
	s := raw
	if len(s) >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		s = s[3:]
	}
	s = foldNewlines(s)
	return norm.NFC.Bytes(s), nil
}

// foldNewlines replaces every CRLF and lone CR with a single LF in one pass.
func foldNewlines(s []byte) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' {
			out = append(out, '\n')
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			continue
		}
		out = append(out, s[i])
	}
	return out
}

// Hash formats SHA-256 of the given bytes as sha256:<lowercase hex>.
func Hash(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Line is a 1-based logical line and its half-open UTF-8 byte range within the
// canonical text. ByteEnd excludes the terminating LF.
type Line struct {
	Number    int
	ByteStart int
	ByteEnd   int
}

// Lines splits canonical text into logical lines on LF. This is the single
// authority for the line<->byte mapping; both extractor and resolver use it, so
// a line range always resolves to the same bytes.
func Lines(canonical []byte) []Line {
	lines := make([]Line, 0, 16)
	start := 0
	number := 1
	for i := 0; i < len(canonical); i++ {
		if canonical[i] == '\n' {
			lines = append(lines, Line{Number: number, ByteStart: start, ByteEnd: i})
			number++
			start = i + 1
		}
	}
	lines = append(lines, Line{Number: number, ByteStart: start, ByteEnd: len(canonical)})
	return lines
}

// LineRangeBytes maps a 1-based inclusive line range to a half-open UTF-8 byte
// range [start,end). ok is false for an out-of-range or reversed range.
func LineRangeBytes(canonical []byte, lineStart, lineEnd int) (start int, end int, ok bool) {
	lines := Lines(canonical)
	if lineStart < 1 || lineEnd < lineStart || lineEnd > len(lines) {
		return 0, 0, false
	}
	return lines[lineStart-1].ByteStart, lines[lineEnd-1].ByteEnd, true
}

// Slice returns the exact canonical bytes of a 1-based inclusive line range.
func Slice(canonical []byte, lineStart, lineEnd int) ([]byte, bool) {
	start, end, ok := LineRangeBytes(canonical, lineStart, lineEnd)
	if !ok {
		return nil, false
	}
	return canonical[start:end], true
}

// Fragment is one contiguous line-range Evidence unit.
type Fragment struct {
	Ordinal   int
	LineStart int
	LineEnd   int
	ByteStart int
	ByteEnd   int
	Text      []byte
}

// Segment partitions the canonical text into ordered, gap-free, non-overlapping
// line-range fragments, each at most maxBytes where possible and never splitting
// a line. A single line longer than maxBytes becomes its own fragment. A final
// empty line produced by a trailing newline is folded away so no zero-byte
// fragment is emitted; an empty document yields no fragments.
func Segment(canonical []byte, maxBytes int) []Fragment {
	if len(canonical) == 0 || maxBytes < 1 {
		return nil
	}
	lines := Lines(canonical)
	if len(lines) > 1 {
		last := lines[len(lines)-1]
		if last.ByteStart == last.ByteEnd {
			lines = lines[:len(lines)-1]
		}
	}
	frags := make([]Fragment, 0, 8)
	ordinal := 1
	i := 0
	for i < len(lines) {
		startLine := i
		j := i
		for j < len(lines) {
			span := lines[j].ByteEnd - lines[startLine].ByteStart
			if span > maxBytes && j > startLine {
				break
			}
			j++
		}
		endLine := j - 1
		start := lines[startLine].ByteStart
		end := lines[endLine].ByteEnd
		if end > start {
			frags = append(frags, Fragment{
				Ordinal:   ordinal,
				LineStart: lines[startLine].Number,
				LineEnd:   lines[endLine].Number,
				ByteStart: start,
				ByteEnd:   end,
				Text:      canonical[start:end],
			})
			ordinal++
		}
		i = j
	}
	return frags
}
