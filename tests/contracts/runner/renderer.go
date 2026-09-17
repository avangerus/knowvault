package contracts

import (
	"bytes"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var markdownSpecial = map[rune]bool{
	'\\': true, '`': true, '*': true, '_': true, '{': true, '}': true,
	'[': true, ']': true, '<': true, '>': true, '(': true, ')': true,
	'#': true, '+': true, '-': true, '.': true, '!': true, '|': true, '~': true,
}

type renderedSpan struct {
	ClaimID string
	Start   int
	End     int
	Escaped string
}

func canonicalTextV1(input string) string {
	input = strings.TrimPrefix(input, "\ufeff")
	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = strings.ReplaceAll(input, "\r", "\n")
	return norm.NFC.String(input)
}

func unsafeModelTextCode(input string) string {
	if strings.TrimFunc(input, unicode.IsSpace) != input {
		return "MODEL_TEXT_EDGE_WHITESPACE"
	}
	for _, r := range input {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return "MODEL_TEXT_CONTROL_CHARACTER"
		}
		if r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return "MODEL_TEXT_BIDI_CONTROL"
		}
		if r == utf8.RuneError {
			// RuneError itself is valid Unicode; invalid UTF-8 was rejected by
			// jsontext before this point, so it remains ordinary data here.
			continue
		}
	}
	return ""
}

func escapeMarkdownText(input string) string {
	input = norm.NFC.String(input)
	input = strings.ReplaceAll(input, "&", "&amp;")
	var output strings.Builder
	for _, r := range input {
		if markdownSpecial[r] {
			output.WriteByte('\\')
		}
		output.WriteRune(r)
	}
	return output.String()
}

func renderAnswer(claims []any, sections []any) ([]byte, []renderedSpan, error) {
	claimByID := make(map[string]map[string]any, len(claims))
	for _, rawClaim := range claims {
		claim := object(rawClaim)
		claimByID[stringValue(claim["claim_id"])] = claim
	}

	blocks := make([]string, 0, len(claims)+len(sections))
	type pendingSpan struct {
		claimID string
		block   int
		prefix  string
		escaped string
	}
	pending := make([]pendingSpan, 0, len(claims))
	for _, rawSection := range sections {
		section := object(rawSection)
		if section["title"] != nil {
			return nil, nil, fail("MODEL_SECTION_TITLE_FORBIDDEN")
		}
		for _, rawID := range array(section["ordered_claim_ids"]) {
			id := stringValue(rawID)
			claim := claimByID[id]
			if claim == nil {
				return nil, nil, fail("MODEL_SECTION_CLAIM_MISSING", id)
			}
			text := stringValue(claim["text"])
			if code := unsafeModelTextCode(text); code != "" {
				return nil, nil, fail(code)
			}
			escaped := escapeMarkdownText(text)
			prefix := ""
			suffix := ""
			switch stringValue(claim["kind"]) {
			case "FACT":
				numbers := make([]int, 0)
				for _, rawNumber := range array(claim["citation_numbers"]) {
					numbers = append(numbers, intValue(rawNumber))
				}
				for i := 0; i < len(numbers); i++ {
					for j := i + 1; j < len(numbers); j++ {
						if numbers[j] < numbers[i] {
							numbers[i], numbers[j] = numbers[j], numbers[i]
						}
					}
				}
				for _, number := range numbers {
					suffix += " [" + strconvItoa(number) + "]"
				}
			case "INFERENCE":
				prefix = "**\u0412\u044b\u0432\u043e\u0434:** "
			case "UNKNOWN":
				prefix = "**\u041d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043e:** "
			default:
				return nil, nil, fail("MODEL_CLAIM_KIND_INVALID", id)
			}
			blockIndex := len(blocks)
			blocks = append(blocks, prefix+escaped+suffix)
			pending = append(pending, pendingSpan{claimID: id, block: blockIndex, prefix: prefix, escaped: escaped})
		}
	}

	for i := range blocks {
		blocks[i] = strings.TrimRightFunc(blocks[i], func(r rune) bool { return r == ' ' || r == '\t' })
	}
	markdown := norm.NFC.String(strings.Join(blocks, "\n\n")) + "\n"
	spans := make([]renderedSpan, 0, len(pending))
	byteOffsetByBlock := make([]int, len(blocks))
	offset := 0
	for i, block := range blocks {
		byteOffsetByBlock[i] = offset
		offset += len([]byte(block))
		if i != len(blocks)-1 {
			offset += 2
		}
	}
	for _, item := range pending {
		start := byteOffsetByBlock[item.block] + len([]byte(item.prefix))
		spans = append(spans, renderedSpan{
			ClaimID: item.claimID,
			Start:   start,
			End:     start + len([]byte(item.escaped)),
			Escaped: item.escaped,
		})
	}
	return []byte(markdown), spans, nil
}

func strconvItoa(value int) string {
	if value == 0 {
		return "0"
	}
	var buffer [32]byte
	i := len(buffer)
	for value > 0 {
		i--
		buffer[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[i:])
}

func validateUnicodeGolden(value map[string]any) error {
	canonical := canonicalTextV1(stringValue(value["source_text_escaped"]))
	if canonical != stringValue(value["canonical_text_escaped"]) {
		return fail("GOLDEN_TEXT_CANONICAL_MISMATCH")
	}
	bytesValue := []byte(canonical)
	if hex.EncodeToString(bytesValue) != stringValue(value["canonical_utf8_hex"]) {
		return fail("GOLDEN_TEXT_UTF8_MISMATCH")
	}
	if len(bytesValue) != intValue(value["canonical_utf8_length"]) {
		return fail("GOLDEN_TEXT_LENGTH_MISMATCH")
	}
	if sha256String(bytesValue) != stringValue(value["canonical_text_hash"]) {
		return fail("GOLDEN_TEXT_HASH_MISMATCH")
	}
	for _, rawRange := range array(value["byte_ranges"]) {
		rangeValue := object(rawRange)
		start, end := intValue(rangeValue["start"]), intValue(rangeValue["end"])
		if start < 0 || end > len(bytesValue) || start >= end || !utf8.Valid(bytesValue[start:end]) {
			return fail("GOLDEN_TEXT_RANGE_INVALID")
		}
		if string(bytesValue[start:end]) != stringValue(rangeValue["text"]) {
			return fail("GOLDEN_TEXT_RANGE_MISMATCH")
		}
	}
	trimmed := strings.TrimFunc(canonical, unicode.IsSpace)
	if trimmed != stringValue(value["question_trimmed_text_escaped"]) {
		return fail("GOLDEN_QUESTION_TRIM_MISMATCH")
	}
	trimmedBytes := []byte(trimmed)
	if hex.EncodeToString(trimmedBytes) != stringValue(value["question_trimmed_utf8_hex"]) ||
		len(trimmedBytes) != intValue(value["question_trimmed_utf8_length"]) ||
		sha256String(trimmedBytes) != stringValue(value["question_trimmed_text_hash"]) {
		return fail("GOLDEN_QUESTION_TRIM_MISMATCH")
	}
	return nil
}

func validateUTF8Range(bytesValue []byte, start, end int) error {
	if start < 0 || end > len(bytesValue) || end <= start {
		return fail("ANCHOR_RANGE_INVALID")
	}
	if start > 0 && !utf8.RuneStart(bytesValue[start]) {
		return fail("ANCHOR_UTF8_BOUNDARY_INVALID")
	}
	if end < len(bytesValue) && !utf8.RuneStart(bytesValue[end]) {
		return fail("ANCHOR_UTF8_BOUNDARY_INVALID")
	}
	if !utf8.Valid(bytesValue[start:end]) {
		return fail("ANCHOR_UTF8_BOUNDARY_INVALID")
	}
	return nil
}

func exactBytesEqual(left, right []byte) bool {
	return bytes.Equal(left, right)
}
