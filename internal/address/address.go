// Package address owns the one address primitive of the RAG data product: a
// canonical, string-round-trippable pointer to an exact span of a retrievable
// object. An address names the source, the object and its version, the kind of
// span (character offsets into canonical text, file:line range into code, or
// snapshot:row range into a table) and a short digest of exactly the addressed
// bytes. It carries no content: content is only produced when the original is
// supplied and the span digest verifies, and whole-object reads are paged with
// an explicit continuation cursor so a caller can always detect that more data
// exists instead of receiving a silently truncated answer.
//
// The canonical textual form is the fixed compact value
//
//	kv1:<object>:<version>:<span>:<hash16>
//
// where:
//
//   - <object> is the source-qualified object reference <source>~<object>;
//   - <version> is the object version (a source version id or a named ref);
//   - <span> is text.<start>-<end> (half-open Unicode code point offsets),
//     code.<file>@<first>-<last> (1-based inclusive lines) or
//     table.<snapshot>@<first>-<last> (1-based inclusive rows);
//   - <hash16> is the first 16 lowercase hex characters of the
//     organization-scoped HMAC-SHA-256 of exactly the addressed bytes (ADR-0077,
//     the same keyed family as evidence_fragment.text_hash).
//
// The digest is never a bare SHA-256 of plaintext: a bare content hash would let
// an outsider confirm a guess about content offline. The digest key is supplied
// by the caller through SpanDigestKey. The package-level
// HashSpan/WithSpanHash/VerifySpan helpers use a non-secret anonymous key for
// callers that do not hold the organization digester; a product emitter must use
// its organization's key.
//
// String and Parse are exact inverses. The former knowvault://address/v1?...
// URL is not an address and Parse refuses it.
package address

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// Canonical form markers. The form is fixed so an address has exactly one
// canonical rendering and one canonical parse.
const (
	addressVersionPrefix = "kv1:"
	addressVersionToken  = "kv1"
	// hash16Length is the fixed number of lowercase hex characters of the
	// address span digest prefix.
	hash16Length = 16
	// objectRefSep qualifies the object by its source object id inside the
	// canonical <object> field.
	objectRefSep = "~"
	// spanKindSep separates the span kind from its coordinates.
	spanKindSep = "."
	// spanAuxSep separates a code file or table snapshot from its range.
	spanAuxSep = "@"
	// spanRangeSep separates the inclusive start of a range from its inclusive
	// end.
	spanRangeSep = "-"
)

// SpanKind names the coordinate system of an address span.
type SpanKind string

const (
	// SpanKindText addresses a half-open range of characters (Unicode code
	// points) in the canonical text of a document.
	SpanKindText SpanKind = "text"
	// SpanKindCode addresses a 1-based inclusive line range within a file of a
	// named ref of a code source.
	SpanKindCode SpanKind = "code"
	// SpanKindTable addresses a 1-based inclusive row range within a named
	// snapshot of a table source.
	SpanKindTable SpanKind = "table"
)

// Typed refusals. Every failure mode is a sentinel so a caller can branch on it
// (errors.Is) instead of matching strings.
var (
	// ErrMalformedAddress is returned by Parse for any value that is not a
	// well-formed canonical address.
	ErrMalformedAddress = errors.New("address: malformed address")
	// ErrSpanMismatch is returned by VerifySpan when the recomputed keyed digest
	// of the addressed bytes does not equal the digest carried by the address.
	ErrSpanMismatch = errors.New("address: span hash mismatch")
	// ErrSpanOutOfRange is returned when a span cannot be resolved against the
	// supplied original.
	ErrSpanOutOfRange = errors.New("address: span out of range")
	// ErrInvalidCursor is returned by Read for a cursor that is not one this
	// package produced.
	ErrInvalidCursor = errors.New("address: invalid cursor")
	// ErrInvalidLimit is returned by Read for a non-positive page limit.
	ErrInvalidLimit = errors.New("address: page limit must be positive")
	// ErrInvalidDigestKey is returned when a keyed digest is requested with a
	// key version that is not a positive rotation version.
	ErrInvalidDigestKey = errors.New("address: invalid span digest key")
)

// Address identifies an exact span of one version of one object. It is
// comparable, so Parse(String()) round-trips to an equal value.
type Address struct {
	Source   string
	Object   string
	Version  string
	SpanKind SpanKind

	// CharStart/CharEnd are half-open character (Unicode code point) offsets
	// used when SpanKind is SpanKindText.
	CharStart int
	CharEnd   int

	// File/LineStart/LineEnd are used when SpanKind is SpanKindCode.
	File      string
	LineStart int
	LineEnd   int

	// Snapshot/RowStart/RowEnd are used when SpanKind is SpanKindTable.
	Snapshot string
	RowStart int
	RowEnd   int

	// SpanHash is the 16 lowercase hex character prefix of the keyed digest of
	// exactly the addressed bytes.
	SpanHash string
}

// String renders the canonical compact address form. Parse inverts it exactly.
func (a Address) String() string {
	return addressVersionPrefix +
		a.Source + objectRefSep + a.Object + ":" +
		a.Version + ":" +
		a.spanToken() + ":" +
		a.SpanHash
}

// spanToken renders the kind and coordinates of the span as the single
// colon-free <span> field of the canonical form.
func (a Address) spanToken() string {
	switch a.SpanKind {
	case SpanKindText:
		return string(SpanKindText) + spanKindSep + strconv.Itoa(a.CharStart) + spanRangeSep + strconv.Itoa(a.CharEnd)
	case SpanKindCode:
		return string(SpanKindCode) + spanKindSep + a.File + spanAuxSep + strconv.Itoa(a.LineStart) + spanRangeSep + strconv.Itoa(a.LineEnd)
	case SpanKindTable:
		return string(SpanKindTable) + spanKindSep + a.Snapshot + spanAuxSep + strconv.Itoa(a.RowStart) + spanRangeSep + strconv.Itoa(a.RowEnd)
	default:
		return string(a.SpanKind)
	}
}

// Parse accepts the canonical rendering produced by String and rejects every
// other value with an error wrapping ErrMalformedAddress. In particular the
// former knowvault://address/v1?... URL is refused.
func Parse(value string) (Address, error) {
	if !strings.HasPrefix(value, addressVersionPrefix) {
		return Address{}, fmt.Errorf("%w: missing %q prefix", ErrMalformedAddress, addressVersionPrefix)
	}
	fields := strings.Split(value, ":")
	if len(fields) != 5 {
		return Address{}, fmt.Errorf("%w: expected 5 fields, got %d", ErrMalformedAddress, len(fields))
	}
	if fields[0] != addressVersionToken {
		return Address{}, fmt.Errorf("%w: unexpected version %q", ErrMalformedAddress, fields[0])
	}

	source, object, ok := strings.Cut(fields[1], objectRefSep)
	if !ok || source == "" || object == "" || strings.Contains(object, objectRefSep) {
		return Address{}, fmt.Errorf("%w: invalid object reference", ErrMalformedAddress)
	}
	version := fields[2]
	if version == "" {
		return Address{}, fmt.Errorf("%w: missing version", ErrMalformedAddress)
	}
	if !validHash16(fields[4]) {
		return Address{}, fmt.Errorf("%w: invalid span digest", ErrMalformedAddress)
	}
	kind, span, err := parseSpanKind(fields[3])
	if err != nil {
		return Address{}, err
	}

	parsed := Address{
		Source: source, Object: object, Version: version,
		SpanKind: kind, SpanHash: fields[4],
	}
	switch kind {
	case SpanKindText:
		start, end, rangeErr := parseSpanRange(span)
		if rangeErr != nil {
			return Address{}, rangeErr
		}
		if start < 0 {
			return Address{}, fmt.Errorf("%w: invalid character span", ErrMalformedAddress)
		}
		parsed.CharStart, parsed.CharEnd = start, end
	case SpanKindCode:
		file, rest, auxErr := parseSpanAux(span)
		if auxErr != nil {
			return Address{}, auxErr
		}
		start, end, rangeErr := parseSpanRange(rest)
		if rangeErr != nil {
			return Address{}, rangeErr
		}
		if start < 1 {
			return Address{}, fmt.Errorf("%w: invalid line span", ErrMalformedAddress)
		}
		parsed.File, parsed.LineStart, parsed.LineEnd = file, start, end
	case SpanKindTable:
		snapshot, rest, auxErr := parseSpanAux(span)
		if auxErr != nil {
			return Address{}, auxErr
		}
		start, end, rangeErr := parseSpanRange(rest)
		if rangeErr != nil {
			return Address{}, rangeErr
		}
		if start < 1 {
			return Address{}, fmt.Errorf("%w: invalid row span", ErrMalformedAddress)
		}
		parsed.Snapshot, parsed.RowStart, parsed.RowEnd = snapshot, start, end
	}
	return parsed, nil
}

// parseSpanKind splits the leading kind token from the span coordinates.
func parseSpanKind(value string) (SpanKind, string, error) {
	kind, rest, ok := strings.Cut(value, spanKindSep)
	if !ok || rest == "" {
		return "", "", fmt.Errorf("%w: invalid span %q", ErrMalformedAddress, value)
	}
	switch SpanKind(kind) {
	case SpanKindText, SpanKindCode, SpanKindTable:
		return SpanKind(kind), rest, nil
	default:
		return "", "", fmt.Errorf("%w: unknown span kind %q", ErrMalformedAddress, kind)
	}
}

// parseSpanAux splits the file/snapshot from its inclusive range and refuses a
// missing, empty or duplicated auxiliary separator.
func parseSpanAux(value string) (string, string, error) {
	aux, rest, ok := strings.Cut(value, spanAuxSep)
	if !ok || aux == "" || rest == "" || strings.Contains(rest, spanAuxSep) {
		return "", "", fmt.Errorf("%w: invalid span locator %q", ErrMalformedAddress, value)
	}
	return aux, rest, nil
}

// parseSpanRange parses the canonical <start>-<end> range. It refuses a missing,
// empty, duplicated, reversed or non-canonical (leading zero, signed) bound.
func parseSpanRange(value string) (int, int, error) {
	startText, endText, ok := strings.Cut(value, spanRangeSep)
	if !ok || startText == "" || endText == "" || strings.Contains(endText, spanRangeSep) {
		return 0, 0, fmt.Errorf("%w: invalid span range %q", ErrMalformedAddress, value)
	}
	start, err := parseCanonicalInt(startText)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: invalid span range %q", ErrMalformedAddress, value)
	}
	end, err := parseCanonicalInt(endText)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: invalid span range %q", ErrMalformedAddress, value)
	}
	if end < start {
		return 0, 0, fmt.Errorf("%w: reversed span range %q", ErrMalformedAddress, value)
	}
	return start, end, nil
}

// parseCanonicalInt accepts only the exact rendering strconv.Itoa produces, so a
// value with a sign or a leading zero cannot create a second textual form.
func parseCanonicalInt(value string) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if strconv.Itoa(number) != value {
		return 0, fmt.Errorf("non-canonical integer %q", value)
	}
	return number, nil
}

// validHash16 accepts exactly 16 lowercase hex characters.
func validHash16(value string) bool {
	if len(value) != hash16Length {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// Span resolves the addressed bytes against the supplied original. It returns
// exactly the addressed bytes and performs no hashing; a caller that needs
// integrity should use a SpanDigestKey verification.
func (a Address) Span(original []byte) ([]byte, error) {
	switch a.SpanKind {
	case SpanKindText:
		return textSpan(original, a.CharStart, a.CharEnd)
	case SpanKindCode:
		return lineSpan(original, a.LineStart, a.LineEnd)
	case SpanKindTable:
		return lineSpan(original, a.RowStart, a.RowEnd)
	default:
		return nil, fmt.Errorf("%w: unknown span kind %q", ErrMalformedAddress, string(a.SpanKind))
	}
}

// SpanDigestKey is an organization-scoped HMAC-SHA-256 digest key of the same
// keyed family as evidence_fragment.text_hash (ADR-0077). Its key material is
// never rendered, and it is a value so it is safe to copy. A zero key version is
// refused when it is used, never silently treated as version 1.
type SpanDigestKey struct {
	key     []byte
	version int
}

// NewSpanDigestKey returns the digest key for one organization. key is the
// ADR-0077 key material supplied by the caller's trusted digester; version is
// the positive rotation version the digest carries.
func NewSpanDigestKey(key []byte, version int) SpanDigestKey {
	return SpanDigestKey{key: append([]byte(nil), key...), version: version}
}

// anonymousSpanDigestKey is the non-secret compatibility key the package-level
// helpers use. It is deliberately not an organization key: a product emitter
// must build a SpanDigestKey from its organization digester.
var anonymousSpanDigestKey = SpanDigestKey{version: 1}

// Hash16 returns the 16 lowercase hex characters of the keyed digest of exactly
// the bytes a resolves to in original.
func (k SpanDigestKey) Hash16(original []byte, a Address) (string, error) {
	span, err := a.Span(original)
	if err != nil {
		return "", err
	}
	return k.hash16Of(span)
}

// hash16Of returns the digest prefix of an already resolved span.
func (k SpanDigestKey) hash16Of(span []byte) (string, error) {
	if k.version < 1 {
		return "", fmt.Errorf("%w: version %d", ErrInvalidDigestKey, k.version)
	}
	digest := canon.HMACDigest(k.key, k.version, span)
	hexPart := digest[strings.LastIndexByte(digest, ':')+1:]
	if len(hexPart) < hash16Length {
		return "", fmt.Errorf("%w: digest too short", ErrInvalidDigestKey)
	}
	return hexPart[:hash16Length], nil
}

// WithSpanHash returns a copy of a carrying the keyed digest prefix of the span
// a currently resolves to in original. It is the construction path for index
// entries; VerifySpan is the consumption path.
func (k SpanDigestKey) WithSpanHash(a Address, original []byte) (Address, error) {
	digest, err := k.Hash16(original, a)
	if err != nil {
		return Address{}, err
	}
	a.SpanHash = digest
	return a, nil
}

// VerifySpan resolves a against original and refuses it when the recomputed
// keyed digest prefix does not equal the digest the address carries. On refusal
// it returns no content and an error wrapping ErrSpanMismatch, so a tampered
// index entry can never be served as if it were the original span.
func (k SpanDigestKey) VerifySpan(original []byte, a Address) ([]byte, error) {
	if a.SpanHash == "" {
		return nil, fmt.Errorf("%w: address carries no span hash", ErrSpanMismatch)
	}
	span, err := a.Span(original)
	if err != nil {
		return nil, err
	}
	actual, err := k.hash16Of(span)
	if err != nil {
		return nil, err
	}
	if actual != a.SpanHash {
		return nil, fmt.Errorf("%w: address span digest does not match original", ErrSpanMismatch)
	}
	return span, nil
}

// HashSpan returns the anonymous-key digest prefix of exactly the bytes a points
// at. A product emitter must use its organization key through
// SpanDigestKey.WithSpanHash instead.
func HashSpan(original []byte, a Address) (string, error) {
	return anonymousSpanDigestKey.Hash16(original, a)
}

// WithSpanHash returns a copy of a carrying the anonymous-key digest prefix of
// the span it resolves to in original. It is the compatibility construction
// path; a product emitter must use SpanDigestKey.WithSpanHash.
func (a Address) WithSpanHash(original []byte) (Address, error) {
	return anonymousSpanDigestKey.WithSpanHash(a, original)
}

// VerifySpan is the anonymous-key verification path. It refuses a tampered index
// entry with an error wrapping ErrSpanMismatch; a product verifier must use
// SpanDigestKey.VerifySpan with the organization key.
func VerifySpan(original []byte, a Address) ([]byte, error) {
	return anonymousSpanDigestKey.VerifySpan(original, a)
}

// WholeHash is the shared canonical SHA-256 digest of the entire original, the
// value every page of a whole-object read reports so a caller can prove the
// reassembled document equals the stored original.
func WholeHash(original []byte) string {
	return canon.Hash(original)
}

// Page is one bounded slice of a whole-object read.
type Page struct {
	// Data is the page's bytes; concatenating the Data of successive pages
	// reproduces the original exactly.
	Data []byte
	// Offset is the byte offset of Data within the original.
	Offset int
	// TotalBytes is the size of the whole original (not of the page).
	TotalBytes int
	// WholeHash is the digest of the whole original, present on every page.
	WholeHash string
	// NextCursor is the stable cursor for the next page. It is empty exactly
	// when HasMore is false.
	NextCursor string
	// HasMore reports that the page stops before the end of the original and
	// that more data exists.
	HasMore bool
	// Complete reports that this page reaches the end of the original. It is
	// the explicit completion indicator mirroring HasMore.
	Complete bool
}

// Cursor prefix; a cursor is the canonical offset token, so a client can store
// it and resume a read later against the same original.
const cursorPrefix = "v1:"

// Read returns up to limit bytes of original starting at cursor. An empty
// cursor starts at the beginning. Every page reports the hash of the whole
// original and, when the page stops before the end, an explicit HasMore marker
// and the NextCursor that yields the following page. No page is ever silently
// truncated: reaching the last byte exactly sets Complete and clears NextCursor.
// Page boundaries never fall inside a multi-byte UTF-8 rune, so Data is always
// valid UTF-8 when original is; concatenating the pages still reproduces the
// original byte-for-byte.
func Read(original []byte, cursor string, limit int) (Page, error) {
	if limit < 1 {
		return Page{}, fmt.Errorf("%w: got %d", ErrInvalidLimit, limit)
	}
	offset, err := parseCursor(cursor)
	if err != nil {
		return Page{}, err
	}
	total := len(original)
	if offset > total {
		return Page{}, fmt.Errorf("%w: offset %d past end %d", ErrInvalidCursor, offset, total)
	}
	// Cursors produced by Read already sit on rune boundaries; a client-supplied
	// cursor that does not is advanced to the next boundary so a page never
	// begins inside a multi-byte rune.
	for offset < total && !utf8.RuneStart(original[offset]) {
		offset++
	}
	end := pageEnd(original, offset, limit)
	page := Page{
		Data:       append([]byte(nil), original[offset:end]...),
		Offset:     offset,
		TotalBytes: total,
		WholeHash:  canon.Hash(original),
	}
	if end < total {
		page.HasMore = true
		page.NextCursor = cursorPrefix + strconv.Itoa(end)
	} else {
		page.Complete = true
	}
	return page, nil
}

// pageEnd returns the exclusive end of a page starting at a rune-boundary
// offset. It clamps to the original, snaps back to a rune boundary so the page
// never ends inside a multi-byte rune, and always advances by at least one
// whole rune so pagination can never stall on a limit smaller than one rune.
func pageEnd(original []byte, start, limit int) int {
	total := len(original)
	end := start + limit
	if end > total {
		end = total
	}
	for end > start && end < total && !utf8.RuneStart(original[end]) {
		end--
	}
	if end == start && start < total {
		_, size := utf8.DecodeRune(original[start:])
		if size < 1 {
			size = 1
		}
		end = start + size
	}
	return end
}

func parseCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	if !strings.HasPrefix(cursor, cursorPrefix) {
		return 0, fmt.Errorf("%w: %q", ErrInvalidCursor, cursor)
	}
	offset, err := strconv.Atoi(strings.TrimPrefix(cursor, cursorPrefix))
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidCursor, cursor)
	}
	return offset, nil
}

// textSpan maps a half-open character (Unicode code point) range onto the exact
// UTF-8 bytes of original.
func textSpan(original []byte, start, end int) ([]byte, error) {
	if start < 0 || end < start {
		return nil, fmt.Errorf("%w: character [%d,%d)", ErrSpanOutOfRange, start, end)
	}
	offsets := runeByteOffsets(original)
	if end >= len(offsets) {
		return nil, fmt.Errorf("%w: character [%d,%d) past %d runes", ErrSpanOutOfRange, start, end, len(offsets)-1)
	}
	return original[offsets[start]:offsets[end]], nil
}

// runeByteOffsets returns the byte offset of each rune start plus a final entry
// equal to len(original), so offsets[k] is the start of the k-th rune and
// offsets[runeCount] == len(original).
func runeByteOffsets(original []byte) []int {
	offsets := make([]int, 0, len(original)+1)
	for i := 0; i < len(original); {
		offsets = append(offsets, i)
		_, size := utf8.DecodeRune(original[i:])
		if size < 1 {
			size = 1
		}
		i += size
	}
	return append(offsets, len(original))
}

// lineSpan maps a 1-based inclusive line range (rows use the same mechanics) to
// the exact bytes via the shared canonical line authority.
func lineSpan(original []byte, start, end int) ([]byte, error) {
	if start < 1 || end < start {
		return nil, fmt.Errorf("%w: line/row [%d,%d]", ErrSpanOutOfRange, start, end)
	}
	byteStart, byteEnd, ok := canon.LineRangeBytes(original, start, end)
	if !ok {
		return nil, fmt.Errorf("%w: line/row [%d,%d]", ErrSpanOutOfRange, start, end)
	}
	return original[byteStart:byteEnd], nil
}
