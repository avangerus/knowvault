package proposer

import (
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// maxProposalsPerRun is S2-MODEL-CONTEXT-DESIGN.md's "Proposer" bound: "at
// most 3 proposals per run". It applies across every kind together, so
// Detect caps its own (SYNONYM + DEFINITION_CORRECTION) Candidates at 3, and
// Store — the only place NEW_TERM's cross-run promotion can be decided —
// counts any NEW_TERM promotion against the same per-run budget of 3 after
// Candidates.
const maxProposalsPerRun = 3

// DetectorVersion is heuristic-v1's fixed, recorded identifier
// (S2-MODEL-CONTEXT-DESIGN.md "Proposer (heuristic-v1, no model calls)").
// Store stamps it onto every proposal it creates.
const DetectorVersion = "heuristic-v1"

// maxCandidateTermRunes mirrors workspacecontext's own maxTermChars (glossary
// term length bound): a candidate this package proposes must already fit a
// Term.Term or a synonym, so an over-length candidate is dropped rather than
// truncated (truncating free text silently would change its meaning).
const maxCandidateTermRunes = 80

// maxSuggestedTextRunes mirrors workspacecontext's own suggested_text bound
// (Proposal.Valid). Unlike a candidate term, a derived correction sentence is
// safe to clip: it is already a heuristic excerpt, not a literal token.
const maxSuggestedTextRunes = 300

// abbreviationPattern is S2-MODEL-CONTEXT-DESIGN.md's SYNONYM token shape: an
// abbreviation of two to six letters, each uppercase Latin or Cyrillic
// (including Ё). It is matched against one already-tokenized word, never
// against raw text, so no separate word-boundary handling is needed here —
// Go's regexp \b is ASCII-only and would misjudge a Cyrillic boundary.
var abbreviationPattern = regexp.MustCompile(`^[A-ZА-ЯЁ]{2,6}$`)

// quotePairs is heuristic-v1's closed set of quotation marks a "quoted
// phrase" candidate may be wrapped in: Russian guillemets and straight/curly
// double quotes.
var quotePairs = [][2]rune{
	{'«', '»'},
	{'"', '"'},
	{'“', '”'}, // “ ”
}

// definitionCorrectionUnder matches "под X понимается Y", anchored at the
// start of the (trimmed) turn text.
var definitionCorrectionUnder = regexp.MustCompile(`(?is)^под\s+(.+?)\s+понимается\s+(.+?)\s*$`)

// definitionCorrectionIsThis matches "X — это Y" (em dash or en dash),
// anchored at the start of the (trimmed) turn text.
var definitionCorrectionIsThis = regexp.MustCompile(`(?is)^(.+?)\s+[—–]\s+это\s+(.+?)\s*$`)

// definitionCorrectionBareMarker matches a bare correction marker
// ("нет", "не так", "я имел(а) в виду"), optionally followed by the
// correction itself.
var definitionCorrectionBareMarker = regexp.MustCompile(`(?is)^(?:нет|не так|я имел[а]?\s+в\s+виду)\s*[,:\-–—]?\s*(.*)$`)

// Candidate is one SYNONYM or DEFINITION_CORRECTION detection: it carries
// everything Store needs to record or dedup-bump a proposal directly. A
// NEW_TERM candidate is different — it needs the cross-run distinct-run
// count only Store's own persisted bookkeeping (workspace_context_term_
// sighting) can resolve — so it surfaces through Detection.NewTermTokens
// instead.
type Candidate struct {
	Kind          workspacecontext.ProposalKind
	CandidateTerm string
	TargetTermID  string
	SuggestedText string
}

// Detection is heuristic-v1's complete, pure output for one completed run.
type Detection struct {
	// Candidates are in detection order: every SYNONYM candidate (in the
	// order its token first appears in the question), then every
	// DEFINITION_CORRECTION candidate. Store applies the 3-proposals-per-run
	// bound over this order, followed by any NEW_TERM promotion.
	Candidates []Candidate
	// NewTermTokens are unknown, non-stop-list, single-word tokens
	// (original casing of their first occurrence, deduplicated within this
	// call) eligible for NEW_TERM's cross-run tracking. A token already
	// emitted as a SYNONYM candidate in this same run is excluded.
	NewTermTokens []string
}

// Detect runs every heuristic-v1 signal against event. It makes no model
// call, opens no database connection and mutates nothing: event's own
// MatchedTerms (the glossary terms the run's search arguments used) and
// SearchArgumentText are read, never written, and QuestionText is the
// current turn's own text (for a DEFINITION_CORRECTION run, the follow-up
// turn).
func Detect(event workspacecontext.RunEvent) Detection {
	var detection Detection

	synonymTokens := map[string]bool{}
	for _, candidate := range detectSynonyms(event) {
		detection.Candidates = append(detection.Candidates, candidate)
		synonymTokens[foldToken(candidate.CandidateTerm)] = true
	}

	if correction, ok := detectDefinitionCorrection(event); ok {
		detection.Candidates = append(detection.Candidates, correction)
	}

	if len(detection.Candidates) > maxProposalsPerRun {
		detection.Candidates = detection.Candidates[:maxProposalsPerRun]
	}

	detection.NewTermTokens = detectNewTermTokens(event, synonymTokens)

	return detection
}

// detectSynonyms implements SYNONYM: "An unknown token U (an abbreviation
// [A-ZА-ЯЁ]{2,6} or a quoted phrase) is in the question, and the model's
// search arguments in the same run contain glossary term T but not U."
// event.MatchedTerms is exactly "the model's search arguments['] glossary
// terms" (workspacecontext.RunEvent's own doc comment): the terms already
// recognized in the search arguments this run sent. A candidate already
// equal (case/ё-folded) to one of those matches is not "unknown" and is
// skipped.
func detectSynonyms(event workspacecontext.RunEvent) []Candidate {
	if len(event.MatchedTerms) == 0 {
		return nil
	}

	matchedFold := make(map[string]bool, len(event.MatchedTerms))
	for _, match := range event.MatchedTerms {
		matchedFold[foldToken(match.MatchedText)] = true
	}

	var candidates []Candidate
	seen := map[string]bool{}
	for _, raw := range candidateTokens(event.QuestionText) {
		if len(raw) == 0 || utf8RuneCount(raw) > maxCandidateTermRunes {
			continue
		}
		key := foldToken(raw)
		if matchedFold[key] || seen[key] {
			continue
		}
		target := event.MatchedTerms[0]
		for _, match := range event.MatchedTerms {
			if foldToken(match.MatchedText) != key {
				target = match
				break
			}
		}
		if foldToken(target.MatchedText) == key {
			// Every matched term folds to the same key as the candidate
			// (degenerate input); there is no distinct T to pair with U.
			continue
		}
		seen[key] = true
		candidates = append(candidates, Candidate{
			Kind:          workspacecontext.ProposalKindSynonym,
			CandidateTerm: raw,
			TargetTermID:  target.TermID,
		})
	}
	return candidates
}

// candidateTokens returns every SYNONYM candidate substring of text, in
// order of first appearance: an abbreviation-shaped single word, or a
// quoted phrase (quotePairs), with its original casing and surrounding
// whitespace trimmed.
func candidateTokens(text string) []string {
	var out []string
	for _, word := range wordTokens(text) {
		if abbreviationPattern.MatchString(word) {
			out = append(out, word)
		}
	}
	out = append(out, quotedPhrases(text)...)
	return out
}

// quotedPhrases extracts every non-empty substring wrapped in one of
// quotePairs.
func quotedPhrases(text string) []string {
	var out []string
	runes := []rune(text)
	for i := 0; i < len(runes); i++ {
		for _, pair := range quotePairs {
			if runes[i] != pair[0] {
				continue
			}
			for j := i + 1; j < len(runes); j++ {
				if runes[j] != pair[1] {
					continue
				}
				inner := strings.TrimSpace(string(runes[i+1 : j]))
				if inner != "" {
					out = append(out, inner)
				}
				i = j
				break
			}
			break
		}
	}
	return out
}

// detectDefinitionCorrection implements DEFINITION_CORRECTION: "A follow-up
// turn starts with a correction marker". The target term is resolved only
// among event.MatchedTerms (the terms this run already recognized): for
// "под X понимается Y" / "X — это Y", X is compared (case/ё-folded) against
// each matched term's own name; for a bare marker, the run's first matched
// term stands in for "the term this turn is about" since the marker itself
// names no term. A correction that cannot be tied to a known term is
// skipped — S2-MODEL-CONTEXT-DESIGN.md's document model requires a
// DEFINITION_CORRECTION proposal to carry a target_term_id
// (workspacecontext.Proposal's kind-shape invariant).
func detectDefinitionCorrection(event workspacecontext.RunEvent) (Candidate, bool) {
	trimmed := strings.TrimSpace(event.QuestionText)
	if trimmed == "" {
		return Candidate{}, false
	}

	if match := definitionCorrectionUnder.FindStringSubmatch(trimmed); match != nil {
		if target, ok := resolveTarget(event.MatchedTerms, match[1]); ok {
			if text, ok := clippedSuggestedText(match[2]); ok {
				return Candidate{
					Kind: workspacecontext.ProposalKindDefinitionCorrection,
					TargetTermID: target.TermID, CandidateTerm: target.Term, SuggestedText: text,
				}, true
			}
		}
	}
	if match := definitionCorrectionIsThis.FindStringSubmatch(trimmed); match != nil {
		if target, ok := resolveTarget(event.MatchedTerms, match[1]); ok {
			if text, ok := clippedSuggestedText(match[2]); ok {
				return Candidate{
					Kind: workspacecontext.ProposalKindDefinitionCorrection,
					TargetTermID: target.TermID, CandidateTerm: target.Term, SuggestedText: text,
				}, true
			}
		}
	}
	if match := definitionCorrectionBareMarker.FindStringSubmatch(trimmed); match != nil {
		if len(event.MatchedTerms) == 0 {
			return Candidate{}, false
		}
		target := event.MatchedTerms[0]
		if text, ok := clippedSuggestedText(match[1]); ok {
			return Candidate{
				Kind: workspacecontext.ProposalKindDefinitionCorrection,
				TargetTermID: target.TermID, CandidateTerm: target.Term, SuggestedText: text,
			}, true
		}
	}
	return Candidate{}, false
}

// resolveTarget finds the first matched term whose own name folds equal to
// candidate.
func resolveTarget(matches []workspacecontext.TermMatch, candidate string) (workspacecontext.TermMatch, bool) {
	key := foldToken(strings.TrimSpace(candidate))
	if key == "" {
		return workspacecontext.TermMatch{}, false
	}
	for _, match := range matches {
		if foldToken(match.Term) == key {
			return match, true
		}
	}
	return workspacecontext.TermMatch{}, false
}

// clippedSuggestedText trims text, rejects an empty result, and clips to
// maxSuggestedTextRunes on a rune boundary.
func clippedSuggestedText(text string) (string, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "", false
	}
	runes := []rune(trimmed)
	if len(runes) > maxSuggestedTextRunes {
		runes = runes[:maxSuggestedTextRunes]
	}
	return string(runes), true
}

// detectNewTermTokens implements NEW_TERM's per-run half: "an unknown
// non-stop-list token" — every single-word, letters-only token in the
// question that is not a stop word, not already a matched glossary term, and
// not already claimed by a SYNONYM candidate this same run. The cross-run
// "queued after at least two distinct runs" half lives in Store, which is
// the only part of this package with persisted state.
func detectNewTermTokens(event workspacecontext.RunEvent, excludeFolded map[string]bool) []string {
	matchedFold := make(map[string]bool, len(event.MatchedTerms))
	for _, match := range event.MatchedTerms {
		matchedFold[foldToken(match.MatchedText)] = true
	}

	var out []string
	seen := map[string]bool{}
	for _, word := range wordTokens(event.QuestionText) {
		runeCount := utf8RuneCount(word)
		if runeCount < 2 || runeCount > maxCandidateTermRunes || !allLetters(word) {
			continue
		}
		key := foldToken(word)
		if seen[key] || excludeFolded[key] || matchedFold[key] || stopWords[key] {
			continue
		}
		seen[key] = true
		out = append(out, word)
	}
	return out
}

// wordTokens splits text into maximal runs of "word runes" (letters, digits,
// underscore — the same definition workspacecontext.MatchTerms uses for its
// own word-boundary check), preserving original order and casing. It never
// uses Go's ASCII-only \b, which would misjudge a Cyrillic boundary.
func wordTokens(text string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, string(current))
			current = nil
		}
	}
	for _, r := range text {
		if isWordRune(r) {
			current = append(current, r)
			continue
		}
		flush()
	}
	flush()
	return tokens
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func allLetters(word string) bool {
	for _, r := range word {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func utf8RuneCount(s string) int {
	return len([]rune(s))
}

// foldToken NFC-normalizes, lower-cases and ё/Ё-folds value, exactly
// mirroring workspacecontext.MatchTerms's own (unexported) folding so a
// candidate token and a glossary term compare equal under the same rule the
// chat/MCP rendering already uses.
func foldToken(value string) string {
	normalized := norm.NFC.String(value)
	folded := make([]rune, 0, len(normalized))
	for _, r := range normalized {
		lower := unicode.ToLower(r)
		if lower == 'ё' {
			lower = 'е'
		}
		folded = append(folded, lower)
	}
	return string(folded)
}
