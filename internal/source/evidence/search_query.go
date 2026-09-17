package evidence

import (
	"strings"
	"unicode"
)

// LexicalSearchQuery removes one leading definition-question envelope from a
// lexical query. It does not remove words from the subject, unquote literals,
// rewrite identifiers or interpret negation. Unrecognized queries are returned
// byte-for-byte unchanged. Callers keep the original query for semantic search.
// An envelope without a subject returns empty; it must never become match-all.
func LexicalSearchQuery(query string) string {
	for _, prefix := range [][]string{
		{"\u0447\u0442\u043e", "\u044d\u0442\u043e", "\u0437\u0430"},
		{"\u0447\u0442\u043e", "\u0442\u0430\u043a\u043e\u0435"}, {"\u0447\u0442\u043e", "\u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442"}, {"\u0447\u0442\u043e", "\u0437\u043d\u0430\u0447\u0438\u0442"},
		{"\u043a\u0442\u043e", "\u0442\u0430\u043a\u043e\u0439"}, {"\u043a\u0442\u043e", "\u0442\u0430\u043a\u0430\u044f"}, {"\u043a\u0442\u043e", "\u0442\u0430\u043a\u0438\u0435"},
		{"what", "is"}, {"what", "are"}, {"who", "is"}, {"who", "are"},
	} {
		if subject, ok := cutSearchQuestionPrefix(query, prefix); ok {
			return subject
		}
	}
	return query
}

func cutSearchQuestionPrefix(query string, prefix []string) (string, bool) {
	rest := strings.TrimLeftFunc(query, unicode.IsSpace)
	for index, word := range prefix {
		end := strings.IndexFunc(rest, unicode.IsSpace)
		if end < 0 {
			end = len(rest)
		}
		token := rest[:end]
		// A terminal question mark is also accepted for a subject-less
		// envelope, but punctuation inside an identifier is never a boundary.
		if index == len(prefix)-1 && strings.TrimSpace(rest[end:]) == "" &&
			strings.EqualFold(strings.TrimRight(token, "?!.…"), word) {
			return "", true
		}
		if !strings.EqualFold(token, word) {
			return "", false
		}
		rest = strings.TrimLeftFunc(rest[end:], unicode.IsSpace)
	}
	if strings.TrimFunc(rest, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("?!.…", r)
	}) == "" {
		return "", true
	}
	return rest, true
}
