package workspacecontext

import (
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// TermMatch is one glossary term recognized inside a piece of text (normally
// the user's question). MatchedText is the exact substring of text that
// matched, in its original casing, which may be the term itself or one of
// its synonyms.
type TermMatch struct {
	TermID      string
	Term        string
	MatchedText string
}

// MatchTerms finds every doc.Glossary term (by its own name or a synonym)
// that occurs in text on a whole-token boundary: case-insensitive, NFC
// normalized, with ё folded to е on both sides, and never matching inside a
// longer word (an abbreviation "МНО" must not match inside "МНОГО"). Each
// term is reported at most once, in glossary order, using its first matching
// occurrence.
func MatchTerms(doc Document, text string) []TermMatch {
	textRunes := []rune(norm.NFC.String(text))
	foldedText := foldRunes(textRunes)

	matches := make([]TermMatch, 0, len(doc.Glossary))
	for _, term := range doc.Glossary {
		candidates := make([]string, 0, len(term.Synonyms)+1)
		candidates = append(candidates, term.Term)
		candidates = append(candidates, term.Synonyms...)

		for _, candidate := range candidates {
			candidateRunes := []rune(norm.NFC.String(candidate))
			if len(candidateRunes) == 0 {
				continue
			}
			foldedCandidate := foldRunes(candidateRunes)
			start, ok := findWordBounded(foldedText, foldedCandidate)
			if !ok {
				continue
			}
			matches = append(matches, TermMatch{
				TermID: term.ID, Term: term.Term,
				MatchedText: string(textRunes[start : start+len(foldedCandidate)]),
			})
			break
		}
	}
	return matches
}

// foldRunes lower-cases every rune and folds ё/Ё onto е, rune for rune, so
// the folded slice has exactly the same length (and therefore the same
// index alignment) as its input.
func foldRunes(runes []rune) []rune {
	folded := make([]rune, len(runes))
	for i, r := range runes {
		lower := unicode.ToLower(r)
		if lower == 'ё' {
			lower = 'е'
		}
		folded[i] = lower
	}
	return folded
}

// findWordBounded returns the rune index of the first occurrence of pattern
// in haystack whose neighbors (if any) are not themselves word runes, so a
// short pattern can never match as a strict substring of a longer token.
func findWordBounded(haystack, pattern []rune) (int, bool) {
	n, m := len(haystack), len(pattern)
	if m == 0 || m > n {
		return 0, false
	}
	for i := 0; i+m <= n; i++ {
		if !runesEqual(haystack[i:i+m], pattern) {
			continue
		}
		if i > 0 && isWordRune(haystack[i-1]) {
			continue
		}
		if i+m < n && isWordRune(haystack[i+m]) {
			continue
		}
		return i, true
	}
	return 0, false
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
