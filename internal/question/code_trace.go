package question

import (
	"fmt"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// CodeTrace deliberately reports only an explicit assertion that is present in
// both a trusted source-code extraction and a non-code extraction.  It does not
// infer implementation from a filename, a keyword, or model prose.  The
// parser/metadata boundary is source-agnostic: future Git commits and code
// symbols can use the same CODE class without adding a question branch.
type traceSource string

const (
	traceSourceUnknown traceSource = ""
	traceSourceCode    traceSource = "CODE"
	traceSourceOther   traceSource = "OTHER"
	maxCodeTraceGroups             = 32
)

type tracedFact struct {
	fact   explicitFact
	source traceSource
}

type codeTraceGroup struct {
	key   string
	code  []explicitFact
	other []explicitFact
}

// sourceClass is derived only from immutable catalog metadata returned by the
// authorized Evidence viewer.  SOURCE_CODE currently uses text-v1 bytes with
// the dedicated source-code-v1 parser profile; the object-type cases reserve
// the same boundary for qualified Git projections.
func sourceClass(item candidate) traceSource {
	if strings.EqualFold(strings.TrimSpace(item.CanonicalFormat), "SOURCE_CODE") ||
		strings.EqualFold(strings.TrimSpace(item.ParserProfileRevision), "source-code-v1") ||
		strings.EqualFold(strings.TrimSpace(item.ParserProfileRevision), canon.TextLayoutParserRevision("source-code-v1")) ||
		strings.EqualFold(strings.TrimSpace(item.ObjectType), "GIT_COMMIT") ||
		strings.EqualFold(strings.TrimSpace(item.ObjectType), "CODE_SYMBOL") {
		return traceSourceCode
	}
	if strings.TrimSpace(item.CanonicalFormat) != "" || strings.TrimSpace(item.ParserProfileRevision) != "" || strings.TrimSpace(item.ObjectType) != "" {
		return traceSourceOther
	}
	// Missing classification is not evidence of either side.  Keeping it
	// unknown prevents a legacy/forged candidate from manufacturing a cross-
	// source conclusion.
	return traceSourceUnknown
}

func codeTraceGroups(planned planner.Plan, selected []candidate) []codeTraceGroup {
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.CodeTrace {
		return nil
	}
	grouped := make(map[string]*codeTraceGroup)
	for _, fact := range extractExplicitFacts(selected) {
		kind := sourceClass(fact.item)
		if kind == traceSourceUnknown {
			continue
		}
		group := grouped[fact.normalKey]
		if group == nil {
			group = &codeTraceGroup{key: fact.normalKey}
			grouped[fact.normalKey] = group
		}
		if kind == traceSourceCode {
			group.code = append(group.code, fact)
		} else {
			group.other = append(group.other, fact)
		}
	}
	result := make([]codeTraceGroup, 0, len(grouped))
	for _, group := range grouped {
		if len(group.code) == 0 || len(group.other) == 0 {
			continue
		}
		sort.SliceStable(group.code, func(i, j int) bool {
			if group.code[i].normalVal != group.code[j].normalVal {
				return group.code[i].normalVal < group.code[j].normalVal
			}
			return group.code[i].item.ID < group.code[j].item.ID
		})
		sort.SliceStable(group.other, func(i, j int) bool {
			if group.other[i].normalVal != group.other[j].normalVal {
				return group.other[i].normalVal < group.other[j].normalVal
			}
			return group.other[i].item.ID < group.other[j].item.ID
		})
		result = append(result, *group)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].key < result[j].key })
	if len(result) > maxCodeTraceGroups {
		result = result[:maxCodeTraceGroups]
	}
	return result
}

func appendTraceFacts(values []explicitFact, citations *[]Citation, seen map[string]int64, workspaceID string) ([]string, bool) {
	parts := make([]string, 0, len(values))
	for _, fact := range values {
		number, exists := seen[fact.item.ID]
		if !exists {
			if len(*citations) >= maxCitations {
				return parts, false
			}
			number = int64(len(*citations) + 1)
			seen[fact.item.ID] = number
			*citations = append(*citations, citationForFact(workspaceID, number, fact))
		}
		parts = append(parts, fmt.Sprintf("%s [%d]", strings.TrimSpace(fact.value), number))
	}
	return parts, true
}

// renderCodeTrace returns a bounded source comparison, not a semantic claim
// about whether a process really works.  Every displayed value is an exact
// equality line and every line is backed by a current Evidence citation.
func renderCodeTrace(workspaceID string, planned planner.Plan, selected []candidate) (string, []Citation) {
	groups := codeTraceGroups(planned, selected)
	if len(groups) == 0 {
		return "", nil
	}
	citations := make([]Citation, 0, maxCitations)
	seen := make(map[string]int64)
	var answer strings.Builder
	for _, group := range groups {
		codeValues, ok := appendTraceFacts(group.code, &citations, seen, workspaceID)
		if !ok || len(codeValues) == 0 {
			break
		}
		otherValues, ok := appendTraceFacts(group.other, &citations, seen, workspaceID)
		if !ok || len(otherValues) == 0 {
			break
		}
		if answer.Len() > 0 {
			answer.WriteString("\n")
		}
		answer.WriteString(fmt.Sprintf("%s: code — %s; documents/data — %s", group.key,
			strings.Join(codeValues, ", "), strings.Join(otherValues, ", ")))
	}
	if answer.Len() == 0 {
		return "", nil
	}
	return answer.String(), citations
}

// codeTraceConflicts signals a disagreement between explicit code and
// non-code values for the same key.  Equal values are corroboration, not a
// conflict.  IDs are sorted by normalizeSignals before persistence.
func codeTraceConflicts(planned planner.Plan, selected []candidate) []Conflict {
	conflicts := make([]Conflict, 0)
	for _, group := range codeTraceGroups(planned, selected) {
		codeValues := make(map[string]struct{})
		otherValues := make(map[string]struct{})
		ids := make(map[string]struct{})
		for _, fact := range group.code {
			codeValues[fact.normalVal] = struct{}{}
			ids[fact.item.ID] = struct{}{}
		}
		for _, fact := range group.other {
			otherValues[fact.normalVal] = struct{}{}
			ids[fact.item.ID] = struct{}{}
		}
		if len(codeValues) == 0 || len(otherValues) == 0 {
			continue
		}
		// Multiple values on either side are also unresolved conflict: the
		// authority cannot select one by score.
		if len(codeValues) == 1 && len(otherValues) == 1 {
			var codeValue, otherValue string
			for value := range codeValues {
				codeValue = value
			}
			for value := range otherValues {
				otherValue = value
			}
			if codeValue == otherValue {
				continue
			}
		}
		if len(ids) >= 2 {
			ordered := make([]string, 0, len(ids))
			for id := range ids {
				ordered = append(ordered, id)
			}
			sort.Strings(ordered)
			conflicts = append(conflicts, Conflict{Code: "CONFLICT_CODE_TRACE_VALUE", EvidenceIDs: ordered})
		}
	}
	return conflicts
}
