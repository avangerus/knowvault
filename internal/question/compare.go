package question

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// A fact is admitted only when the Evidence fragment contains a complete,
// line-oriented equality assertion.  This is intentionally narrower than a
// natural-language claim extractor: a comparison must never turn arbitrary
// prose or co-occurrence into a fact.
var explicitFactPattern = regexp.MustCompile(`^([\p{L}][\p{L}\p{N}_.:-]{1,127}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n\]]{1,192}\])?)\s*=\s*(.{1,256})$`)

// Keep this grammar local to the comparison adapter.  The planner's term
// grammar is intentionally unexported and may evolve independently; facts
// admitted here must nevertheless follow the same bounded identifier shape
// plus an optional RFC-6901 JSON pointer used by structured SQL cells.
var explicitFactKeyPattern = regexp.MustCompile(`^[\p{L}][\p{L}\p{N}_.:-]{1,127}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n\]]{1,192}\])?$`)

const (
	maxCompareFacts       = 32
	maxCompareValueBytes  = 256
	maxCompareExcerptByte = 512
)

type explicitFact struct {
	key       string
	value     string
	normalKey string
	normalVal string
	item      candidate
	excerpt   string
}

type comparedFact struct {
	key    string
	values map[string][]explicitFact
}

func normalizeFactPart(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCompareValueBytes || !utf8.ValidString(value) {
		return "", false
	}
	// Equality is case/whitespace insensitive for comparison, while the
	// displayed value remains the exact bounded Evidence line.
	normalized := strings.ToLower(strings.Join(strings.Fields(value), " "))
	if normalized == "" || len([]rune(normalized)) > 256 {
		return "", false
	}
	return normalized, true
}

// normalizeFactKey keeps the SQL column portion case-insensitive while
// preserving the case of an RFC-6901 JSON pointer.  Structured SQL cells use
// the same field identity as the aggregate adapter; accepting a malformed
// pointer here would let a comparison bypass the source-owned anchor contract.
func normalizeFactKey(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !explicitFactKeyPattern.MatchString(value) {
		return "", false
	}
	if open := strings.IndexByte(value, '['); open >= 0 {
		path := strings.TrimSuffix(value[open+1:], "]")
		if !validJSONPointer(path) {
			return "", false
		}
		return strings.ToLower(value[:open]) + value[open:], true
	}
	return strings.ToLower(value), true
}

// factKeyLeaf returns the source-owned field leaf used by a structured fact.
// It is a retrieval hint only: the Evidence line and immutable PostgreSQL
// anchor remain the authority.  Keeping this helper source-neutral lets a
// natural comparison question such as "compare status" resolve the same
// field across arbitrary SQL projections without naming a business entity or
// source in code.
func factKeyLeaf(key string) string {
	key = strings.TrimSpace(key)
	if open := strings.IndexByte(key, '['); open >= 0 && strings.HasSuffix(key, "]") {
		path := strings.TrimSuffix(key[open+1:], "]")
		if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
			path = path[slash+1:]
		}
		path = strings.ReplaceAll(strings.ReplaceAll(path, "~1", "/"), "~0", "~")
		return strings.ToLower(strings.TrimSpace(path))
	}
	return strings.ToLower(key)
}

func extractExplicitFacts(selected []candidate) []explicitFact {
	facts := make([]explicitFact, 0, len(selected))
	for _, item := range selected {
		if len(item.Text) == 0 || !validOpaque(item.ID) {
			continue
		}
		for _, rawLine := range strings.Split(string(item.Text), "\n") {
			excerpt := strings.TrimSpace(rawLine)
			line := excerpt
			match := explicitFactPattern.FindStringSubmatch(line)
			// Source-code extractors preserve line comments in their canonical
			// text.  An explicit equality assertion in a comment is still a
			// source-owned fact, but only the narrowly supported comment forms
			// are admitted and only when immutable code metadata classifies the
			// Evidence as source code.  Keep the original line as the citation
			// excerpt so the answer remains verifiable against the source.
			if len(match) != 3 && sourceClass(item) == traceSourceCode {
				for _, prefix := range []string{"//", "#", "--"} {
					if !strings.HasPrefix(line, prefix) {
						continue
					}
					candidateLine := strings.TrimSpace(strings.TrimPrefix(line, prefix))
					if candidateLine == line {
						continue
					}
					if candidateMatch := explicitFactPattern.FindStringSubmatch(candidateLine); len(candidateMatch) == 3 {
						line, match = candidateLine, candidateMatch
						break
					}
				}
			}
			if len(match) != 3 {
				continue
			}
			key, ok := normalizeFactKey(match[1])
			if !ok || strings.IndexFunc(key, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= '\u0430' && r <= '\u044f' || r >= '0' && r <= '9' }) < 0 {
				continue
			}
			value, ok := normalizeFactPart(match[2])
			if !ok {
				continue
			}
			if len(line) > maxCompareExcerptByte {
				continue
			}
			facts = append(facts, explicitFact{
				key: match[1], value: match[2],
				normalKey: key, normalVal: value, item: item, excerpt: excerpt,
			})
			if len(facts) >= maxCompareFacts*4 {
				return facts
			}
		}
	}
	return facts
}

func compareFacts(selected []candidate) []comparedFact {
	grouped := make(map[string]*comparedFact)
	for _, fact := range extractExplicitFacts(selected) {
		group := grouped[fact.normalKey]
		if group == nil {
			// Use the canonical key in the result as well as in the map. This keeps
			// Compare deterministic when two providers differ only in key casing.
			group = &comparedFact{key: fact.normalKey, values: make(map[string][]explicitFact)}
			grouped[fact.normalKey] = group
		}
		group.values[fact.normalVal] = append(group.values[fact.normalVal], fact)
	}
	result := make([]comparedFact, 0, len(grouped))
	for _, group := range grouped {
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(result[i].key)) < strings.ToLower(strings.TrimSpace(result[j].key))
	})
	if len(result) > maxCompareFacts {
		result = result[:maxCompareFacts]
	}
	return result
}

func compareConflicts(selected []candidate) []Conflict {
	conflicts := make([]Conflict, 0)
	for _, group := range compareFacts(selected) {
		if len(group.values) < 2 {
			continue
		}
		ids := make([]string, 0)
		seen := make(map[string]struct{})
		valueKeys := make([]string, 0, len(group.values))
		for value := range group.values {
			valueKeys = append(valueKeys, value)
		}
		sort.Strings(valueKeys)
		for _, value := range valueKeys {
			for _, fact := range group.values[value] {
				if _, exists := seen[fact.item.ID]; exists {
					continue
				}
				seen[fact.item.ID] = struct{}{}
				ids = append(ids, fact.item.ID)
			}
		}
		if len(ids) >= 2 {
			conflicts = append(conflicts, Conflict{Code: "CONFLICT_FACT_VALUE", EvidenceIDs: ids})
		}
	}
	return conflicts
}

func citationForFact(workspaceID string, number int64, fact explicitFact) Citation {
	return Citation{
		Number: number, EvidenceFragment: fact.item.ID, Excerpt: fact.excerpt,
		Anchor:          string(fact.item.Anchor),
		DeepLink:        "/api/v1/workspaces/" + workspaceID + "/evidence/" + fact.item.ID,
		SourceVersionID: fact.item.SourceVersionID, ExtractionID: fact.item.ExtractionID,
		SourceObjectID: fact.item.SourceObjectID, EvidenceTextHash: fact.item.TextHash,
		ExcerptHash: canon.Hash([]byte(fact.excerpt)),
	}
}

// renderCompareFacts gives the Compare operation a generic, deterministic
// answer path.  It only reports explicit equality facts and returns the exact
// source lines as citations; it cannot invent a key, value, SQL or source link.
func renderCompareFacts(workspaceID string, planned planner.Plan, selected []candidate) (string, []Citation) {
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		return "", nil
	}
	groups := compareFacts(selected)
	if len(groups) == 0 {
		return "", nil
	}
	citations := make([]Citation, 0, maxCitations)
	seenCitation := make(map[string]struct{})
	appendCitation := func(fact explicitFact) (int64, bool) {
		if len(citations) >= maxCitations {
			return 0, false
		}
		if _, exists := seenCitation[fact.item.ID]; exists {
			for _, citation := range citations {
				if citation.EvidenceFragment == fact.item.ID {
					return citation.Number, true
				}
			}
		}
		number := int64(len(citations) + 1)
		citations = append(citations, citationForFact(workspaceID, number, fact))
		seenCitation[fact.item.ID] = struct{}{}
		return number, true
	}

	var answer strings.Builder
	hasConflict := false
	for _, group := range groups {
		if len(group.values) < 2 {
			continue
		}
		values := make([]string, 0, len(group.values))
		for value := range group.values {
			values = append(values, value)
		}
		sort.Strings(values)
		parts := make([]string, 0, len(values))
		for _, value := range values {
			facts := group.values[value]
			sort.SliceStable(facts, func(i, j int) bool { return facts[i].item.ID < facts[j].item.ID })
			number, ok := appendCitation(facts[0])
			if !ok {
				break
			}
			parts = append(parts, fmt.Sprintf("%s [%d]", strings.TrimSpace(facts[0].value), number))
		}
		if len(parts) < 2 {
			continue
		}
		hasConflict = true
		if answer.Len() > 0 {
			answer.WriteString("\n")
		}
		answer.WriteString(fmt.Sprintf("Conflict for %s: %s", strings.TrimSpace(group.key), strings.Join(parts, " versus ")))
	}
	if hasConflict {
		return answer.String(), citations
	}
	// Multiple sources reporting the same explicit value are enough for a
	// bounded negative comparison.  Without that corroboration, remain silent.
	for _, group := range groups {
		if len(group.values) != 1 {
			continue
		}
		for _, facts := range group.values {
			uniqueIDs := make(map[string]struct{}, len(facts))
			for _, fact := range facts {
				uniqueIDs[fact.item.ID] = struct{}{}
			}
			if len(uniqueIDs) < 2 {
				continue
			}
			sort.SliceStable(facts, func(i, j int) bool { return facts[i].item.ID < facts[j].item.ID })
			for _, fact := range facts {
				number, ok := appendCitation(fact)
				if !ok {
					break
				}
				if answer.Len() == 0 {
					answer.WriteString("No explicit conflicts were found in the verified facts")
				}
				answer.WriteString(fmt.Sprintf(" [%d]", number))
			}
		}
	}
	if answer.Len() == 0 {
		return "", nil
	}
	return answer.String(), citations
}
