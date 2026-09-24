package proposer

// stopWords is heuristic-v1's fixed, closed stop-word list for the NEW_TERM
// signal: common Russian and English function words that must never be
// proposed as a new glossary term regardless of how often they recur. Every
// entry is written already fold-normalized (lower-case, no Ё) so a direct
// map lookup with foldToken's own output is exact; init verifies this once
// per process rather than trusting every literal by hand.
var stopWords = buildStopWords(
	// Russian: pronouns, prepositions, conjunctions, particles, common verbs.
	"и", "в", "во", "не", "что", "он", "на", "я", "с", "со", "как", "а",
	"то", "все", "она", "так", "его", "но", "да", "ты", "к", "у", "же",
	"вы", "за", "бы", "по", "только", "ее", "мне", "было", "вот", "от",
	"меня", "еще", "нет", "о", "из", "ему", "теперь", "когда", "даже",
	"ну", "вдруг", "ли", "если", "уже", "или", "ни", "быть", "был",
	"него", "до", "вас", "нибудь", "опять", "уж", "вам", "сказал", "ведь",
	"там", "потом", "себя", "ничего", "ей", "может", "они", "тут", "где",
	"есть", "надо", "ней", "для", "мы", "тебя", "их", "чем", "была",
	"сам", "чтоб", "без", "будто", "человек", "чего", "раз", "тоже",
	"себе", "под", "будет", "ж", "тогда", "кто", "этот", "того", "потому",
	"этого", "какой", "совсем", "ним", "здесь", "этом", "один", "почти",
	"мой", "тем", "чтобы", "нее", "кажется", "сейчас", "были",
	"куда", "зачем", "всех", "никогда", "можно", "при", "наконец", "два",
	"об", "другой", "хоть", "после", "над", "больше", "тот", "через",
	"эти", "нас", "про", "всего", "них", "какая", "много", "разве",
	"три", "эту", "моя", "впрочем", "хорошо", "свою", "этой", "перед",
	"иногда", "лучше", "чуть", "том", "нельзя", "такой", "им", "более",
	"всегда", "конечно", "всю", "между", "это", "эта", "эту", "которая",
	"которые", "который", "которых", "которую", "также",
	// English: articles, pronouns, prepositions, conjunctions, auxiliaries.
	"a", "an", "the", "and", "or", "but", "if", "of", "at", "by", "for",
	"with", "about", "against", "between", "into", "through", "during",
	"before", "after", "above", "below", "to", "from", "up", "down", "in",
	"out", "on", "off", "over", "under", "again", "further", "then",
	"once", "here", "there", "all", "any", "both", "each", "few", "more",
	"most", "other", "some", "such", "no", "nor", "not", "only", "own",
	"same", "so", "than", "too", "very", "is", "are", "was", "were", "be",
	"been", "being", "have", "has", "had", "having", "do", "does", "did",
	"doing", "this", "that", "these", "those", "it", "its", "as", "we",
	"you", "he", "she", "they", "i", "me", "him", "her", "them", "my",
	"your", "his", "our", "their",
)

func buildStopWords(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[foldToken(word)] = true
	}
	return set
}
