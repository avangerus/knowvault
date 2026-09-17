package question

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// sourceQuote permits whitespace reflow, then returns the original contiguous
// source bytes. No word, punctuation, Markdown marker or gap is repaired. The
// stored excerpt and its hash therefore always refer to the actual artifact.
func sourceQuote(text, quote string) (string, bool) {
	if strings.TrimSpace(quote) == "" {
		return "", false
	}
	if strings.Contains(text, quote) {
		return quote, true
	}
	wanted := strings.Join(strings.Fields(quote), " ")
	var normalized strings.Builder
	var starts, ends []int
	space := false
	for index, r := range text {
		end := index + utf8.RuneLen(r)
		if unicode.IsSpace(r) {
			if space {
				ends[len(ends)-1] = end
				continue
			}
			normalized.WriteByte(' ')
			space = true
		} else {
			normalized.WriteRune(r)
			space = false
		}
		starts = append(starts, index)
		ends = append(ends, end)
	}
	value := normalized.String()
	offset := strings.Index(value, wanted)
	if offset < 0 {
		return "", false
	}
	first := utf8.RuneCountInString(value[:offset])
	last := first + utf8.RuneCountInString(wanted) - 1
	actual := text[starts[first]:ends[last]]
	if len(actual) > 8192 {
		return "", false
	}
	return actual, true
}
