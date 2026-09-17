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

// An explicit definition is the smallest safe Explain primitive: the line
// itself must assert the relationship, and the answer cites that exact line.
// This parser is source/entity agnostic; it never maps a business noun to a
// special answer branch or invents a definition from co-occurrence.
var explicitDefinitionPattern = regexp.MustCompile("(?i)^([\\p{L}\\p{N}][\\p{L}\\p{N}_-]{1,63})\\s+(?:(?:\u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442|means|is\\s+called|\u043d\u0430\u0437\u044b\u0432\u0430\u0435\u0442\u0441\u044f)\\s+|(?:\u2014|\u2013)\\s*(?:\u044d\u0442\u043e\\s+)?)(.{1,256})$")

const maxExplainDefinitions = 32

type explicitDefinition struct {
	term       string
	value      string
	normalTerm string
	normalVal  string
	item       candidate
	excerpt    string
}

func extractExplicitDefinitions(planned planner.Plan, selected []candidate) []explicitDefinition {
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Explain {
		return nil
	}
	questionTerms := make(map[string]struct{}, len(planned.SubjectTerms))
	for _, term := range planned.SubjectTerms {
		normal := strings.ToLower(strings.TrimSpace(term))
		if normal != "" {
			questionTerms[normal] = struct{}{}
		}
	}
	definitions := make([]explicitDefinition, 0, len(selected))
	seen := make(map[string]struct{})
	for _, item := range selected {
		if !validOpaque(item.ID) || len(item.Text) == 0 {
			continue
		}
		for _, rawLine := range strings.Split(string(item.Text), "\n") {
			line := strings.TrimSpace(rawLine)
			match := explicitDefinitionPattern.FindStringSubmatch(line)
			if len(match) != 3 || len(line) > maxCompareExcerptByte || !utf8.ValidString(line) {
				continue
			}
			term := strings.ToLower(strings.TrimSpace(match[1]))
			value := strings.TrimSpace(match[2])
			if _, wanted := questionTerms[term]; !wanted || value == "" {
				continue
			}
			normalValue := strings.ToLower(strings.Join(strings.Fields(value), " "))
			if normalValue == "" || len([]byte(normalValue)) > maxCompareValueBytes {
				continue
			}
			key := item.ID + "\x00" + term + "\x00" + normalValue
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			definitions = append(definitions, explicitDefinition{
				term: match[1], value: value, normalTerm: term, normalVal: normalValue,
				item: item, excerpt: line,
			})
			if len(definitions) >= maxExplainDefinitions {
				return definitions
			}
		}
	}
	sort.SliceStable(definitions, func(i, j int) bool {
		if definitions[i].normalTerm != definitions[j].normalTerm {
			return definitions[i].normalTerm < definitions[j].normalTerm
		}
		if definitions[i].normalVal != definitions[j].normalVal {
			return definitions[i].normalVal < definitions[j].normalVal
		}
		return definitions[i].item.ID < definitions[j].item.ID
	})
	return definitions
}

func citationForDefinition(workspaceID string, number int64, definition explicitDefinition) Citation {
	return Citation{
		Number: number, EvidenceFragment: definition.item.ID, Excerpt: definition.excerpt,
		Anchor:          string(definition.item.Anchor),
		DeepLink:        "/api/v1/workspaces/" + workspaceID + "/evidence/" + definition.item.ID,
		SourceVersionID: definition.item.SourceVersionID, ExtractionID: definition.item.ExtractionID,
		SourceObjectID: definition.item.SourceObjectID, EvidenceTextHash: definition.item.TextHash,
		ExcerptHash: canon.Hash([]byte(definition.excerpt)),
	}
}

// renderExplainDefinitions reports only explicit definitions whose term is in
// the server-owned plan. If no definition is present, the caller may retain
// the ordinary extractive Explain path; no unsupported fact is synthesized.
func renderExplainDefinitions(workspaceID string, planned planner.Plan, selected []candidate) (string, []Citation) {
	definitions := extractExplicitDefinitions(planned, selected)
	if len(definitions) == 0 {
		return "", nil
	}
	citations := make([]Citation, 0, maxCitations)
	seen := make(map[string]int64)
	var answer strings.Builder
	for _, definition := range definitions {
		if len(citations) >= maxCitations {
			break
		}
		number, exists := seen[definition.item.ID]
		if !exists {
			number = int64(len(citations) + 1)
			seen[definition.item.ID] = number
			citations = append(citations, citationForDefinition(workspaceID, number, definition))
		}
		if answer.Len() > 0 {
			answer.WriteString("\n")
		}
		answer.WriteString(fmt.Sprintf("%s means: %s [%d]", strings.TrimSpace(definition.term), definition.value, number))
	}
	return answer.String(), citations
}

// explainConflicts reports competing explicit definitions for the same
// planned term. The values remain opaque to the signal itself; every returned
// Evidence ID points at one exact definition line.
func explainConflicts(planned planner.Plan, selected []candidate) []Conflict {
	definitions := extractExplicitDefinitions(planned, selected)
	byTerm := make(map[string]map[string]map[string]struct{})
	for _, definition := range definitions {
		values := byTerm[definition.normalTerm]
		if values == nil {
			values = make(map[string]map[string]struct{})
			byTerm[definition.normalTerm] = values
		}
		ids := values[definition.normalVal]
		if ids == nil {
			ids = make(map[string]struct{})
			values[definition.normalVal] = ids
		}
		ids[definition.item.ID] = struct{}{}
	}
	terms := make([]string, 0, len(byTerm))
	for term := range byTerm {
		terms = append(terms, term)
	}
	sort.Strings(terms)
	conflicts := make([]Conflict, 0, len(terms))
	for _, term := range terms {
		values := byTerm[term]
		if len(values) < 2 {
			continue
		}
		valueKeys := make([]string, 0, len(values))
		for value := range values {
			valueKeys = append(valueKeys, value)
		}
		sort.Strings(valueKeys)
		ids := make([]string, 0, len(values))
		seen := make(map[string]struct{})
		for _, value := range valueKeys {
			for id := range values[value] {
				if _, exists := seen[id]; exists {
					continue
				}
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		conflicts = append(conflicts, Conflict{Code: "CONFLICT_DEFINITION_VALUE", EvidenceIDs: ids})
	}
	return conflicts
}
