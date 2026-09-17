package question

import (
	"fmt"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/planner"
)

// Audit is a source-neutral compliance assertion reducer.  It admits only an
// explicit `control = status` line from authorized Evidence and requires an
// independently classified code and non-code source.  A filename, keyword or
// model statement is never enough to mark a control as confirmed.
const (
	auditPositive  = "POSITIVE"
	auditNegative  = "NEGATIVE"
	maxAuditGroups = 32
)

type auditAssertion struct {
	fact  explicitFact
	class string
}

type auditGroup struct {
	key   string
	code  []auditAssertion
	other []auditAssertion
}

// auditOutcome maps a deliberately small, server-owned status vocabulary to a
// polarity.  Unknown status values are ignored rather than interpreted.  The
// exact source value remains in the rendered answer and citation.
func auditOutcome(value string) (string, bool) {
	switch strings.ToLower(strings.Join(strings.Fields(value), " ")) {
	case "confirmed", "compliant", "pass", "passed", "true", "yes", "implemented", "approved", "active", "enabled":
		return auditPositive, true
	case "not confirmed", "unconfirmed", "noncompliant", "non-compliant", "fail", "failed", "false", "no", "missing", "not implemented", "not_implemented", "described", "pending", "disabled":
		return auditNegative, true
	default:
		return "", false
	}
}

func auditSourceIndependent(code, other candidate) bool {
	if code.SourceObjectID != "" && other.SourceObjectID != "" {
		return code.SourceObjectID != other.SourceObjectID
	}
	return code.ID != other.ID
}

func auditGroups(planned planner.Plan, selected []candidate) []auditGroup {
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Audit {
		return nil
	}
	grouped := make(map[string]*auditGroup)
	for _, fact := range extractExplicitFacts(selected) {
		outcome, ok := auditOutcome(fact.normalVal)
		if !ok {
			continue
		}
		kind := sourceClass(fact.item)
		if kind != traceSourceCode && kind != traceSourceOther {
			continue
		}
		group := grouped[fact.normalKey]
		if group == nil {
			group = &auditGroup{key: fact.normalKey}
			grouped[fact.normalKey] = group
		}
		assertion := auditAssertion{fact: fact, class: outcome}
		if kind == traceSourceCode {
			group.code = append(group.code, assertion)
		} else {
			group.other = append(group.other, assertion)
		}
	}
	result := make([]auditGroup, 0, len(grouped))
	for _, group := range grouped {
		if !auditGroupHasIndependentPair(*group) {
			continue
		}
		sort.SliceStable(group.code, func(i, j int) bool {
			if group.code[i].class != group.code[j].class {
				return group.code[i].class < group.code[j].class
			}
			return group.code[i].fact.item.ID < group.code[j].fact.item.ID
		})
		sort.SliceStable(group.other, func(i, j int) bool {
			if group.other[i].class != group.other[j].class {
				return group.other[i].class < group.other[j].class
			}
			return group.other[i].fact.item.ID < group.other[j].fact.item.ID
		})
		result = append(result, *group)
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].key < result[j].key })
	if len(result) > maxAuditGroups {
		result = result[:maxAuditGroups]
	}
	return result
}

func auditGroupHasIndependentPair(group auditGroup) bool {
	for _, code := range group.code {
		for _, other := range group.other {
			if auditSourceIndependent(code.fact.item, other.fact.item) {
				return true
			}
		}
	}
	return false
}

func auditClasses(assertions []auditAssertion) map[string]struct{} {
	classes := make(map[string]struct{}, len(assertions))
	for _, assertion := range assertions {
		classes[assertion.class] = struct{}{}
	}
	return classes
}

func firstIndependentAuditPair(group auditGroup, codeClass, otherClass string) (auditAssertion, auditAssertion, bool) {
	for _, code := range group.code {
		if codeClass != "" && code.class != codeClass {
			continue
		}
		for _, other := range group.other {
			if otherClass != "" && other.class != otherClass {
				continue
			}
			if auditSourceIndependent(code.fact.item, other.fact.item) {
				return code, other, true
			}
		}
	}
	return auditAssertion{}, auditAssertion{}, false
}

func appendAuditCitation(workspaceID string, assertion auditAssertion, citations *[]Citation, seen map[string]int64) (int64, bool) {
	if number, ok := seen[assertion.fact.item.ID]; ok {
		return number, true
	}
	if len(*citations) >= maxCitations {
		return 0, false
	}
	number := int64(len(*citations) + 1)
	seen[assertion.fact.item.ID] = number
	*citations = append(*citations, citationForFact(workspaceID, number, assertion.fact))
	return number, true
}

// renderAuditControls reports only controls that have matching, explicit
// status assertions on both sides of the source boundary.  Differing polarity
// (or an internally mixed side) is rendered as a conflict, never resolved by
// score or recency.
func renderAuditControls(workspaceID string, planned planner.Plan, selected []candidate) (string, []Citation) {
	groups := auditGroups(planned, selected)
	if len(groups) == 0 {
		return "", nil
	}
	citations := make([]Citation, 0, maxCitations)
	seen := make(map[string]int64)
	var answer strings.Builder
	for _, group := range groups {
		codeClasses := auditClasses(group.code)
		otherClasses := auditClasses(group.other)
		if len(codeClasses) == 0 || len(otherClasses) == 0 {
			continue
		}
		class := ""
		if len(codeClasses) == 1 && len(otherClasses) == 1 {
			for value := range codeClasses {
				class = value
			}
			for value := range otherClasses {
				if value != class {
					class = "CONFLICT"
				}
			}
		} else {
			class = "CONFLICT"
		}
		code, other, ok := firstIndependentAuditPair(group, "", "")
		if !ok {
			continue
		}
		codeNumber, ok := appendAuditCitation(workspaceID, code, &citations, seen)
		if !ok {
			break
		}
		otherNumber, ok := appendAuditCitation(workspaceID, other, &citations, seen)
		if !ok {
			break
		}
		if answer.Len() > 0 {
			answer.WriteString("\n")
		}
		label := "Conflict"
		switch class {
		case auditPositive:
			label = "Confirmed"
		case auditNegative:
			label = "Unverified"
		}
		answer.WriteString(fmt.Sprintf("%s for %s: code — %s [%d]; documents/data — %s [%d]",
			label, group.key, strings.TrimSpace(code.fact.value), codeNumber,
			strings.TrimSpace(other.fact.value), otherNumber))
	}
	if answer.Len() == 0 {
		return "", nil
	}
	return answer.String(), citations
}

func auditConflicts(planned planner.Plan, selected []candidate) []Conflict {
	conflicts := make([]Conflict, 0)
	for _, group := range auditGroups(planned, selected) {
		codeClasses := auditClasses(group.code)
		otherClasses := auditClasses(group.other)
		if len(codeClasses) == 1 && len(otherClasses) == 1 {
			var codeClass, otherClass string
			for value := range codeClasses {
				codeClass = value
			}
			for value := range otherClasses {
				otherClass = value
			}
			if codeClass == otherClass {
				continue
			}
		}
		ids := make(map[string]struct{})
		for _, assertion := range append(append([]auditAssertion(nil), group.code...), group.other...) {
			if validOpaque(assertion.fact.item.ID) {
				ids[assertion.fact.item.ID] = struct{}{}
			}
		}
		if len(ids) < 2 {
			continue
		}
		ordered := make([]string, 0, len(ids))
		for id := range ids {
			ordered = append(ordered, id)
		}
		sort.Strings(ordered)
		conflicts = append(conflicts, Conflict{Code: "CONFLICT_AUDIT_CONTROL_STATUS", EvidenceIDs: ordered})
	}
	return conflicts
}
