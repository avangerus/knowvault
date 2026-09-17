package address

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func mustAddress(t *testing.T, a Address, original []byte) Address {
	t.Helper()
	withHash, err := a.WithSpanHash(original)
	if err != nil {
		t.Fatalf("WithSpanHash(%v): %v", a, err)
	}
	return withHash
}

// canonicalCompactPattern is the fixed compact textual form: kv1, the
// source-qualified object, the version, the span and a 16 lowercase hex digit
// digest, colon separated, with no URL scheme, host, path or query.
var canonicalCompactPattern = regexp.MustCompile(`^kv1:[^:]+:[^:]+:[^:]+:[0-9a-f]{16}$`)

func TestAddressStringIsCompactFormWithoutURL(t *testing.T) {
	withHash := mustAddress(t, Address{
		Source: "conn-1", Object: "doc-1", Version: "v3", SpanKind: SpanKindText,
		CharStart: 1, CharEnd: 3,
	}, []byte("héllo world"))

	rendered := withHash.String()
	if !canonicalCompactPattern.MatchString(rendered) {
		t.Fatalf("String() = %q, want the compact kv1 form", rendered)
	}
	if strings.Contains(rendered, "://") || strings.Contains(rendered, "?") {
		t.Fatalf("String() = %q must not carry a URL scheme or query", rendered)
	}
	if strings.Count(rendered, ":") != 4 {
		t.Fatalf("String() = %q, want exactly four field separators", rendered)
	}
	if !strings.HasPrefix(rendered, "kv1:conn-1~doc-1:v3:text.1-3:") {
		t.Fatalf("String() = %q, want the fixed prefix", rendered)
	}
	if len(withHash.SpanHash) != 16 {
		t.Fatalf("address digest %q must be 16 hex chars", withHash.SpanHash)
	}

	// The full rendering is fixed: kv1, the source-qualified object, the
	// version, the span and the 16-hex prefix of the anonymous keyed digest.
	span, err := withHash.Span([]byte("héllo world"))
	if err != nil {
		t.Fatalf("Span: %v", err)
	}
	digest := canon.HMACDigest(nil, 1, span)
	hash16 := digest[strings.LastIndexByte(digest, ':')+1:][:16]
	want := "kv1:conn-1~doc-1:v3:text.1-3:" + hash16
	if rendered != want {
		t.Fatalf("String() = %q, want exact compact form %q", rendered, want)
	}
}

func TestAddressRoundTripAllSpanKinds(t *testing.T) {
	textOriginal := []byte("héllo world")
	codeOriginal := []byte("package main\nfunc main() {}\n// end\n")
	tableOriginal := []byte("row-a\nrow-b\nrow-c")

	cases := []struct {
		name     string
		address  Address
		original []byte
	}{
		{
			name: "text character offsets",
			address: Address{
				Source: "conn-1", Object: "doc-1", Version: "v3", SpanKind: SpanKindText,
				CharStart: 1, CharEnd: 3,
			},
			original: textOriginal,
		},
		{
			name: "code file lines",
			address: Address{
				Source: "git-1", Object: "src/main.go", Version: "refs/heads/main", SpanKind: SpanKindCode,
				File: "src/main.go", LineStart: 2, LineEnd: 3,
			},
			original: codeOriginal,
		},
		{
			name: "table snapshot rows",
			address: Address{
				Source: "pg-1", Object: "public.orders", Version: "snap-9", SpanKind: SpanKindTable,
				Snapshot: "snap-9", RowStart: 1, RowEnd: 2,
			},
			original: tableOriginal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHash := mustAddress(t, tc.address, tc.original)
			rendered := withHash.String()

			parsed, err := Parse(rendered)
			if err != nil {
				t.Fatalf("Parse(%q): %v", rendered, err)
			}
			if parsed != withHash {
				t.Fatalf("round trip mismatch:\n parsed  = %#v\n original= %#v", parsed, withHash)
			}
			if again := parsed.String(); again != rendered {
				t.Fatalf("String is not canonical: %q != %q", again, rendered)
			}
			if !canonicalCompactPattern.MatchString(rendered) {
				t.Fatalf("rendered %q is not the compact canonical form", rendered)
			}
		})
	}
}

func TestParseRefusesFormerURLAddress(t *testing.T) {
	for _, value := range []string{
		"knowvault://address/v1?kind=text&source=a&object=b&version=c&char_start=0&char_end=1&hash=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"knowvault://address/not-canonical",
		"knowvault://address/v1",
	} {
		if _, err := Parse(value); !errors.Is(err, ErrMalformedAddress) {
			t.Fatalf("Parse(%q) error = %v, want ErrMalformedAddress", value, err)
		}
	}
}

func TestParseRejectsMalformedCompactAddresses(t *testing.T) {
	valid := mustAddress(t, Address{
		Source: "conn-1", Object: "doc-1", Version: "v1", SpanKind: SpanKindText,
		CharStart: 0, CharEnd: 1,
	}, []byte("hello"))

	cases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "not an address", value: "hello"},
		{name: "missing prefix", value: "v1:conn-1~doc-1:v1:text.0-1:" + valid.SpanHash},
		{name: "wrong version token", value: "kv2:conn-1~doc-1:v1:text.0-1:" + valid.SpanHash},
		{name: "missing object ref separator", value: "kv1:doc-1:v1:text.0-1:" + valid.SpanHash},
		{name: "empty source", value: "kv1:~doc-1:v1:text.0-1:" + valid.SpanHash},
		{name: "empty object", value: "kv1:conn-1~:v1:text.0-1:" + valid.SpanHash},
		{name: "duplicated object ref separator", value: "kv1:conn-1~doc-1~extra:v1:text.0-1:" + valid.SpanHash},
		{name: "empty version", value: "kv1:conn-1~doc-1::text.0-1:" + valid.SpanHash},
		{name: "missing span", value: "kv1:conn-1~doc-1:v1:" + valid.SpanHash},
		{name: "missing hash", value: "kv1:conn-1~doc-1:v1:text.0-1"},
		{name: "empty hash", value: "kv1:conn-1~doc-1:v1:text.0-1:"},
		{name: "short hash", value: "kv1:conn-1~doc-1:v1:text.0-1:0123"},
		{name: "long hash", value: "kv1:conn-1~doc-1:v1:text.0-1:" + valid.SpanHash + "0"},
		{name: "non-hex hash", value: "kv1:conn-1~doc-1:v1:text.0-1:0123456789abcdeg"},
		{name: "uppercase hash", value: "kv1:conn-1~doc-1:v1:text.0-1:0123456789ABCDEF"},
		{name: "unknown span kind", value: "kv1:conn-1~doc-1:v1:binary.0-1:" + valid.SpanHash},
		{name: "missing span kind separator", value: "kv1:conn-1~doc-1:v1:text0-1:" + valid.SpanHash},
		{name: "missing span coordinates", value: "kv1:conn-1~doc-1:v1:text.:" + valid.SpanHash},
		{name: "reversed char span", value: "kv1:conn-1~doc-1:v1:text.3-1:" + valid.SpanHash},
		{name: "negative char start", value: "kv1:conn-1~doc-1:v1:text.-1-1:" + valid.SpanHash},
		{name: "leading zero char start", value: "kv1:conn-1~doc-1:v1:text.01-1:" + valid.SpanHash},
		{name: "signed char start", value: "kv1:conn-1~doc-1:v1:text.+0-1:" + valid.SpanHash},
		{name: "missing char end", value: "kv1:conn-1~doc-1:v1:text.0-:" + valid.SpanHash},
		{name: "duplicated range separator", value: "kv1:conn-1~doc-1:v1:text.0-1-2:" + valid.SpanHash},
		{name: "code missing file", value: "kv1:conn-1~doc-1:v1:code.@1-2:" + valid.SpanHash},
		{name: "code zero line", value: "kv1:conn-1~doc-1:v1:code.f@0-1:" + valid.SpanHash},
		{name: "code duplicated aux separator", value: "kv1:conn-1~doc-1:v1:code.f@1-2@3:" + valid.SpanHash},
		{name: "table missing snapshot", value: "kv1:conn-1~doc-1:v1:table.@1-2:" + valid.SpanHash},
		{name: "table zero row", value: "kv1:conn-1~doc-1:v1:table.s@0-2:" + valid.SpanHash},
		{name: "unexpected trailing field", value: valid.String() + ":extra"},
		{name: "unexpected empty trailing field", value: valid.String() + ":"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.value)
			if !errors.Is(err, ErrMalformedAddress) {
				t.Fatalf("Parse(%q) error = %v, want ErrMalformedAddress", tc.value, err)
			}
		})
	}
}

// TestKeyedDigestIsOrgScopedAndPrefixOfHMAC proves the address digest is the
// 16-hex prefix of the organization-keyed HMAC-SHA-256 of the span (ADR-0077
// family), is never the bare SHA-256 of plaintext, and is refused when tampered.
func TestKeyedDigestIsOrgScopedAndPrefixOfHMAC(t *testing.T) {
	original := []byte("organization scoped canonical text")
	base := Address{
		Source: "conn-1", Object: "doc-1", Version: "v1", SpanKind: SpanKindText,
		CharStart: 0, CharEnd: 9,
	}
	span, err := base.Span(original)
	if err != nil {
		t.Fatalf("Span: %v", err)
	}

	key := NewSpanDigestKey([]byte("org-digest-key-material"), 7)
	signed, err := key.WithSpanHash(base, original)
	if err != nil {
		t.Fatalf("keyed WithSpanHash: %v", err)
	}
	want := canon.HMACDigest(key.key, 7, span)
	want = want[strings.LastIndexByte(want, ':')+1:][:16]
	if signed.SpanHash != want {
		t.Fatalf("keyed digest = %q, want HMAC prefix %q", signed.SpanHash, want)
	}
	if signed.SpanHash == canon.Hash(span)[len("sha256:"):][:16] {
		t.Fatalf("keyed digest equals the bare SHA-256 prefix of plaintext")
	}
	if _, err := key.VerifySpan(original, signed); err != nil {
		t.Fatalf("keyed VerifySpan refused the genuine address: %v", err)
	}

	// A digest produced under another key must not verify.
	other := NewSpanDigestKey([]byte("another-org-key-material"), 7)
	if _, err := other.VerifySpan(original, signed); !errors.Is(err, ErrSpanMismatch) {
		t.Fatalf("foreign-key VerifySpan error = %v, want ErrSpanMismatch", err)
	}

	// A tampered digest prefix must be refused with no content.
	tampered := signed
	tampered.SpanHash = strings.Repeat("0", 16)
	if tampered.SpanHash == signed.SpanHash {
		tampered.SpanHash = strings.Repeat("1", 16)
	}
	content, err := key.VerifySpan(original, tampered)
	if !errors.Is(err, ErrSpanMismatch) {
		t.Fatalf("tampered VerifySpan error = %v, want ErrSpanMismatch", err)
	}
	if content != nil {
		t.Fatalf("refused span must carry no content, got %q", content)
	}

	// A zero rotation version is refused instead of being treated as version 1.
	if _, err := NewSpanDigestKey([]byte("k"), 0).Hash16(original, base); !errors.Is(err, ErrInvalidDigestKey) {
		t.Fatalf("zero-version Hash16 error = %v, want ErrInvalidDigestKey", err)
	}
}

// TestAnonymousHelpersAreKeyedNotBareSHA256 pins the compatibility path: even
// without an organization key the digest is an HMAC of the span, never the bare
// SHA-256 of plaintext.
func TestAnonymousHelpersAreKeyedNotBareSHA256(t *testing.T) {
	original := []byte("compatibility path span")
	base := Address{
		Source: "conn-1", Object: "doc-1", Version: "v1", SpanKind: SpanKindText,
		CharStart: 0, CharEnd: 4,
	}
	hash16, err := HashSpan(original, base)
	if err != nil {
		t.Fatalf("HashSpan: %v", err)
	}
	span, err := base.Span(original)
	if err != nil {
		t.Fatalf("Span: %v", err)
	}
	if hash16 == canon.Hash(span)[len("sha256:"):][:16] {
		t.Fatalf("anonymous digest is the bare SHA-256 prefix of plaintext")
	}
	if len(hash16) != 16 {
		t.Fatalf("anonymous digest = %q, want 16 hex chars", hash16)
	}
}

func TestVerifySpanResolvesExactBytesForEachKind(t *testing.T) {
	cases := []struct {
		name     string
		address  Address
		original []byte
		want     string
	}{
		{
			name: "text uses character offsets",
			address: Address{
				Source: "conn-1", Object: "doc-1", Version: "v1", SpanKind: SpanKindText,
				CharStart: 1, CharEnd: 3,
			},
			original: []byte("héllo"),
			want:     "él",
		},
		{
			name: "code uses inclusive lines",
			address: Address{
				Source: "git-1", Object: "f.go", Version: "refs/heads/main", SpanKind: SpanKindCode,
				File: "f.go", LineStart: 2, LineEnd: 3,
			},
			original: []byte("package main\nfunc main() {}\n// end\n"),
			want:     "func main() {}\n// end",
		},
		{
			name: "table uses inclusive rows",
			address: Address{
				Source: "pg-1", Object: "t", Version: "snap-1", SpanKind: SpanKindTable,
				Snapshot: "snap-1", RowStart: 1, RowEnd: 2,
			},
			original: []byte("row-a\nrow-b\nrow-c"),
			want:     "row-a\nrow-b",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHash := mustAddress(t, tc.address, tc.original)
			span, err := VerifySpan(tc.original, withHash)
			if err != nil {
				t.Fatalf("VerifySpan: %v", err)
			}
			if string(span) != tc.want {
				t.Fatalf("span = %q, want %q", span, tc.want)
			}
		})
	}
}

func TestVerifySpanRefusesTamperedIndexEntry(t *testing.T) {
	original := []byte("héllo world")
	good := mustAddress(t, Address{
		Source: "conn-1", Object: "doc-1", Version: "v1", SpanKind: SpanKindText,
		CharStart: 6, CharEnd: 11,
	}, original)

	tampered := good
	tampered.SpanHash = strings.Repeat("a", 16)
	if tampered.SpanHash == good.SpanHash {
		tampered.SpanHash = strings.Repeat("b", 16)
	}

	content, err := VerifySpan(original, tampered)
	if !errors.Is(err, ErrSpanMismatch) {
		t.Fatalf("VerifySpan tampered hash error = %v, want ErrSpanMismatch", err)
	}
	if content != nil {
		t.Fatalf("refused span must carry no content, got %q", content)
	}

	// The address covers characters 6..11 of "héllo world", i.e. bytes [7,12)
	// ("world"); mutating a byte inside that span changes the hashed content.
	altered := append([]byte(nil), original...)
	altered[7] = 'X'
	content, err = VerifySpan(altered, good)
	if !errors.Is(err, ErrSpanMismatch) {
		t.Fatalf("VerifySpan altered original error = %v, want ErrSpanMismatch", err)
	}
	if content != nil {
		t.Fatalf("refused span must carry no content, got %q", content)
	}

	// A change outside the addressed span leaves the span bytes intact, so the
	// address is deliberately not refused: the digest is span-scoped, not
	// whole-object, and this pins that contract rather than relying on an
	// accidental byte choice.
	outside := append([]byte(nil), original...)
	outside[0] = 'X'
	span, err := VerifySpan(outside, good)
	if err != nil {
		t.Fatalf("VerifySpan changed outside span error = %v, want nil", err)
	}
	if string(span) != "world" {
		t.Fatalf("span = %q, want %q", span, "world")
	}

	missing := good
	missing.SpanHash = ""
	if _, err := VerifySpan(original, missing); !errors.Is(err, ErrSpanMismatch) {
		t.Fatalf("VerifySpan missing hash error = %v, want ErrSpanMismatch", err)
	}
}

func TestReadReassemblesPagesToWholeOriginalHash(t *testing.T) {
	original := []byte("the whole original document, longer than a single response page")
	const limit = 7

	var reassembled []byte
	cursor := ""
	pages := 0
	for {
		page, err := Read(original, cursor, limit)
		if err != nil {
			t.Fatalf("Read(cursor=%q): %v", cursor, err)
		}
		if page.WholeHash != WholeHash(original) {
			t.Fatalf("page %d whole hash = %q, want %q", pages, page.WholeHash, WholeHash(original))
		}
		if page.TotalBytes != len(original) {
			t.Fatalf("page %d total bytes = %d, want %d", pages, page.TotalBytes, len(original))
		}
		if len(page.Data) > limit {
			t.Fatalf("page %d returned %d bytes, limit %d", pages, len(page.Data), limit)
		}
		reassembled = append(reassembled, page.Data...)
		pages++
		if page.Complete {
			if page.HasMore {
				t.Fatalf("complete page also reports HasMore")
			}
			if page.NextCursor != "" {
				t.Fatalf("complete page offers cursor %q", page.NextCursor)
			}
			break
		}
		if !page.HasMore {
			t.Fatalf("page %d neither complete nor offering more data", pages)
		}
		if page.NextCursor == "" {
			t.Fatalf("page %d reports HasMore with empty cursor", pages)
		}
		cursor = page.NextCursor
		if pages > len(original)+1 {
			t.Fatalf("pagination did not terminate")
		}
	}

	if string(reassembled) != string(original) {
		t.Fatalf("reassembled = %q, want %q", reassembled, original)
	}
	if canon.Hash(reassembled) != WholeHash(original) {
		t.Fatalf("reassembled hash = %q, want %q", canon.Hash(reassembled), WholeHash(original))
	}
}

// TestReadWholeObjectPagesSnapToRuneBoundaries proves that whole-object paging
// never splits a multi-byte UTF-8 rune: every page is valid UTF-8, no boundary
// falls inside a rune, pagination always advances, and the pages still
// reassemble byte-for-byte into the original hash. On the unpatched raw byte
// slicing a limit of 1 byte cuts every Cyrillic rune and this test fails.
func TestReadWholeObjectPagesSnapToRuneBoundaries(t *testing.T) {
	original := []byte("\u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440! \u0414\u0430\u043d\u043d\u044b\u0435 \u043d\u0435 \u043e\u0431\u0440\u0435\u0437\u0430\u043d\u044b \u2014 \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u044b \u0441\u043e\u0431\u0438\u0440\u0430\u044e\u0442\u0441\u044f \u0432 \u0446\u0435\u043b\u043e\u0435.")
	limits := []int{1, 2, 3, 5, 7, 11, 13, len(original) - 1, len(original), len(original) + 5}
	for _, limit := range limits {
		var reassembled []byte
		cursor := ""
		pages := 0
		previousOffset := -1
		for {
			page, err := Read(original, cursor, limit)
			if err != nil {
				t.Fatalf("limit %d: Read(cursor=%q): %v", limit, cursor, err)
			}
			if !utf8.Valid(page.Data) {
				t.Fatalf("limit %d: page %d data is not valid UTF-8: %q", limit, pages, page.Data)
			}
			if page.Offset > 0 && page.Offset < len(original) && !utf8.RuneStart(original[page.Offset]) {
				t.Fatalf("limit %d: page %d begins mid-rune at byte %d", limit, pages, page.Offset)
			}
			if end := page.Offset + len(page.Data); end < len(original) && !utf8.RuneStart(original[end]) {
				t.Fatalf("limit %d: page %d ends mid-rune at byte %d", limit, pages, end)
			}
			if page.Offset <= previousOffset {
				t.Fatalf("limit %d: page %d did not advance (offset %d after %d)", limit, pages, page.Offset, previousOffset)
			}
			previousOffset = page.Offset
			if page.WholeHash != WholeHash(original) {
				t.Fatalf("limit %d: page %d whole hash = %q, want %q", limit, pages, page.WholeHash, WholeHash(original))
			}
			if page.TotalBytes != len(original) {
				t.Fatalf("limit %d: page %d total bytes = %d, want %d", limit, pages, page.TotalBytes, len(original))
			}
			reassembled = append(reassembled, page.Data...)
			pages++
			if page.Complete {
				if page.HasMore || page.NextCursor != "" {
					t.Fatalf("limit %d: complete page %d also offers more: %+v", limit, pages, page)
				}
				break
			}
			if !page.HasMore || page.NextCursor == "" {
				t.Fatalf("limit %d: page %d neither complete nor offering more: %+v", limit, pages, page)
			}
			cursor = page.NextCursor
			if pages > len(original)+1 {
				t.Fatalf("limit %d: pagination did not terminate", limit)
			}
		}
		if string(reassembled) != string(original) {
			t.Fatalf("limit %d: reassembled = %q, want %q", limit, reassembled, original)
		}
		if canon.Hash(reassembled) != WholeHash(original) {
			t.Fatalf("limit %d: reassembled hash = %q, want %q", limit, canon.Hash(reassembled), WholeHash(original))
		}
	}

	// A limit smaller than one rune still yields the whole rune, never a split.
	single := []byte("\u0416")
	page, err := Read(single, "", 1)
	if err != nil {
		t.Fatalf("Read single rune: %v", err)
	}
	if !utf8.Valid(page.Data) || string(page.Data) != string(single) {
		t.Fatalf("Read single rune limit 1 data = %q, want %q", page.Data, single)
	}
	if !page.Complete || page.HasMore || page.NextCursor != "" {
		t.Fatalf("Read single rune = %+v, want complete at the end of the rune", page)
	}
}

func TestReadExactLimitFinalPageReportsCompletion(t *testing.T) {
	original := []byte("0123456789")

	// One call whose limit exactly equals the remaining length.
	page, err := Read(original, "", len(original))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !page.Complete || page.HasMore || page.NextCursor != "" {
		t.Fatalf("exact-limit page = %+v, want complete with no next cursor", page)
	}
	if string(page.Data) != string(original) {
		t.Fatalf("exact-limit page data = %q", page.Data)
	}

	// A second page whose limit exactly equals the remaining length.
	first, err := Read(original, "", 4)
	if err != nil {
		t.Fatalf("Read first: %v", err)
	}
	if first.Complete || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page = %+v, want more data", first)
	}
	second, err := Read(original, first.NextCursor, 6)
	if err != nil {
		t.Fatalf("Read second: %v", err)
	}
	if !second.Complete || second.HasMore || second.NextCursor != "" {
		t.Fatalf("second page = %+v, want completion at exact remaining length", second)
	}
	if string(first.Data)+string(second.Data) != string(original) {
		t.Fatalf("pages do not reassemble: %q + %q", first.Data, second.Data)
	}
}

func TestReadPageCutBeforeEndOffersNextCursor(t *testing.T) {
	original := []byte("0123456789")
	page, err := Read(original, "", 4)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !page.HasMore || page.Complete {
		t.Fatalf("cut page = %+v, want HasMore and not Complete", page)
	}
	if page.NextCursor == "" {
		t.Fatalf("cut page must offer a next cursor")
	}
	if page.Offset != 0 || page.TotalBytes != len(original) {
		t.Fatalf("page offsets = %+v", page)
	}

	// The cursor is stable: re-reading yields the same page.
	again, err := Read(original, "", 4)
	if err != nil {
		t.Fatalf("Read again: %v", err)
	}
	if again.NextCursor != page.NextCursor || string(again.Data) != string(page.Data) {
		t.Fatalf("cursor or data is not stable across reads")
	}

	// Cursor at the end yields an empty complete page.
	tail, err := Read(original, page.NextCursor, 4)
	if err != nil {
		t.Fatalf("Read tail: %v", err)
	}
	if tail.Offset != 4 || string(tail.Data) != "4567" {
		t.Fatalf("resumed page = %+v", tail)
	}
}

func TestReadEmptyOriginalAndInvalidArguments(t *testing.T) {
	empty, err := Read(nil, "", 10)
	if err != nil {
		t.Fatalf("Read empty: %v", err)
	}
	if !empty.Complete || empty.HasMore || len(empty.Data) != 0 || empty.TotalBytes != 0 {
		t.Fatalf("empty read = %+v", empty)
	}
	if empty.WholeHash != WholeHash(nil) {
		t.Fatalf("empty whole hash = %q", empty.WholeHash)
	}

	for _, limit := range []int{0, -1} {
		if _, err := Read([]byte("abc"), "", limit); !errors.Is(err, ErrInvalidLimit) {
			t.Fatalf("Read limit %d error = %v, want ErrInvalidLimit", limit, err)
		}
	}

	for _, cursor := range []string{"bogus", "v1:-1", "v1:abc", "4"} {
		if _, err := Read([]byte("abc"), cursor, 2); !errors.Is(err, ErrInvalidCursor) {
			t.Fatalf("Read cursor %q error = %v, want ErrInvalidCursor", cursor, err)
		}
	}

	if _, err := Read([]byte("abc"), "v1:9", 2); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("Read past end error = %v, want ErrInvalidCursor", err)
	}
}

func TestSpanOutOfRangeIsTyped(t *testing.T) {
	original := []byte("short")
	cases := []Address{
		{SpanKind: SpanKindText, CharStart: 0, CharEnd: 99},
		{SpanKind: SpanKindText, CharStart: -1, CharEnd: 1},
		{SpanKind: SpanKindCode, LineStart: 4, LineEnd: 9},
		{SpanKind: SpanKindTable, RowStart: 8, RowEnd: 9},
	}
	for _, a := range cases {
		if _, err := a.Span(original); !errors.Is(err, ErrSpanOutOfRange) {
			t.Fatalf("Span(%#v) error = %v, want ErrSpanOutOfRange", a, err)
		}
	}
}

func ExampleRead() {
	original := []byte("0123456789")
	page, _ := Read(original, "", 4)
	fmt.Printf("%q %v %s\n", page.Data, page.HasMore, page.NextCursor)
	// Output: "0123" true v1:4
}
