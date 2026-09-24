package workspacecontext

import (
	"encoding/json"
	"fmt"
)

// RenderTrace is Render's side channel: whether the block had to be cut to
// fit budgetBytes, and which glossary terms the question matched. Terms is
// always computed from the full, untruncated document, so it reflects real
// recognition even when a matched term's own content was later trimmed to
// make room. It is the source for ToolLoopRecord.WorkspaceContext in
// S2-MODEL-CONTEXT-DESIGN.md "Chat".
type RenderTrace struct {
	Truncated bool
	Terms     []MatchedTerm
}

// MatchedTerm augments a TermMatch with the term's own data_locations,
// rendered as compact "relation" / "relation.column" strings, for
// ToolLoopRecord.WorkspaceContext.terms[].locations.
type MatchedTerm struct {
	TermID      string
	Term        string
	MatchedText string
	Locations   []string
}

type renderRule struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type renderDataLocation struct {
	SourceConnectionID string `json:"source_connection_id"`
	Relation           string `json:"relation"`
	Column             string `json:"column,omitempty"`
	Hint               string `json:"hint,omitempty"`
}

type renderTerm struct {
	ID            string               `json:"id"`
	Term          string               `json:"term"`
	Synonyms      []string             `json:"synonyms,omitempty"`
	Definition    string               `json:"definition,omitempty"`
	DataLocations []renderDataLocation `json:"data_locations,omitempty"`
}

type renderColumn struct {
	Name string `json:"name"`
	Note string `json:"note,omitempty"`
}

type renderTable struct {
	Relation string         `json:"relation"`
	Note     string         `json:"note,omitempty"`
	Columns  []renderColumn `json:"columns,omitempty"`
}

type renderSource struct {
	SourceConnectionID string        `json:"source_connection_id"`
	Description        string        `json:"description,omitempty"`
	Tables             []renderTable `json:"tables,omitempty"`
}

type renderedDocument struct {
	Description string         `json:"description,omitempty"`
	Rules       []renderRule   `json:"rules,omitempty"`
	Glossary    []renderTerm   `json:"glossary,omitempty"`
	Sources     []renderSource `json:"sources,omitempty"`
	Truncated   bool           `json:"truncated,omitempty"`
}

// Render produces the exact delimited block S2-MODEL-CONTEXT-DESIGN.md
// "Chat" and "MCP" both send: `WORKSPACE_CONTEXT_JSON (version N): {...}`.
// It is the single shared renderer ADR-0098 requires the chat and MCP paths
// to call so their output is byte-for-byte identical (a parity test compares
// them). Standard JSON string escaping (applied to every field by
// encoding/json) keeps any content — including an injected `"}` or
// "ignore previous instructions" — inside its JSON string, unable to close
// the surrounding object early.
//
// version is the pinned Version.Number the caller read doc under (Document
// itself carries no version). question is the current turn's text, used
// only to find which glossary terms are already relevant (MatchTerms) so
// they are the last thing cut under budget pressure. budgetBytes bounds the
// returned string's total byte length, including the
// "WORKSPACE_CONTEXT_JSON (version N): " prefix; the caller computes it as
// min(16 KiB, MaxInputBytes/8) per the design.
//
// When doc does not fit budgetBytes, content is dropped in the design's
// exact priority order, least important first: source notes, then
// non-matched glossary terms (first reduced to bare id/term, then removed),
// then matched glossary terms, then rules, then finally the description
// itself (truncated to what remains). The returned JSON then carries
// "truncated": true.
func Render(doc Document, version int64, question string, budgetBytes int) (string, RenderTrace) {
	doc = normalizeForHash(doc)
	matches := MatchTerms(doc, question)
	matchedSet := make(map[string]bool, len(matches))
	for _, match := range matches {
		matchedSet[match.TermID] = true
	}
	var trace RenderTrace
	for _, match := range matches {
		trace.Terms = append(trace.Terms, MatchedTerm{
			TermID: match.TermID, Term: match.Term, MatchedText: match.MatchedText,
			Locations: locationStrings(doc, match.TermID),
		})
	}

	working := buildRenderedDocument(doc)
	if full := renderBlock(working, version); len(full) <= budgetBytes {
		return full, trace
	}
	trace.Truncated = true
	working.Truncated = true

	attempt := func() (string, bool) {
		rendered := renderBlock(working, version)
		return rendered, len(rendered) <= budgetBytes
	}

	// 5. source notes, tail first.
	for len(working.Sources) > 0 {
		working.Sources = working.Sources[:len(working.Sources)-1]
		if rendered, ok := attempt(); ok {
			return rendered, trace
		}
	}

	// 4. other (non-matched) term names: first strip to bare id/term, then
	// drop entirely, tail first.
	for i := range working.Glossary {
		if matchedSet[working.Glossary[i].ID] {
			continue
		}
		working.Glossary[i].Synonyms = nil
		working.Glossary[i].Definition = ""
		working.Glossary[i].DataLocations = nil
	}
	if rendered, ok := attempt(); ok {
		return rendered, trace
	}
	for i := len(working.Glossary) - 1; i >= 0; i-- {
		if matchedSet[working.Glossary[i].ID] {
			continue
		}
		working.Glossary = append(working.Glossary[:i], working.Glossary[i+1:]...)
		if rendered, ok := attempt(); ok {
			return rendered, trace
		}
	}

	// 3. terms matched in the question, tail first.
	for len(working.Glossary) > 0 {
		working.Glossary = working.Glossary[:len(working.Glossary)-1]
		if rendered, ok := attempt(); ok {
			return rendered, trace
		}
	}

	// 2. rules, tail first.
	for len(working.Rules) > 0 {
		working.Rules = working.Rules[:len(working.Rules)-1]
		if rendered, ok := attempt(); ok {
			return rendered, trace
		}
	}

	// 1. description: binary search the longest rune-prefix that still fits.
	descriptionRunes := []rune(working.Description)
	low, high := 0, len(descriptionRunes)
	for low < high {
		mid := (low + high + 1) / 2
		trial := working
		trial.Description = string(descriptionRunes[:mid])
		if len(renderBlock(trial, version)) <= budgetBytes {
			low = mid
		} else {
			high = mid - 1
		}
	}
	working.Description = string(descriptionRunes[:low])
	return renderBlock(working, version), trace
}

func renderBlock(doc renderedDocument, version int64) string {
	body, err := json.Marshal(doc)
	if err != nil {
		// renderedDocument is built entirely from already-validated strings
		// and slices; json.Marshal on it cannot fail.
		body = []byte(`{}`)
	}
	return fmt.Sprintf("WORKSPACE_CONTEXT_JSON (version %d): %s", version, body)
}

func buildRenderedDocument(doc Document) renderedDocument {
	rules := make([]renderRule, len(doc.Rules))
	for i, rule := range doc.Rules {
		rules[i] = renderRule{ID: rule.ID, Text: rule.Text}
	}
	glossary := make([]renderTerm, len(doc.Glossary))
	for i, term := range doc.Glossary {
		locations := make([]renderDataLocation, len(term.DataLocations))
		for j, location := range term.DataLocations {
			locations[j] = renderDataLocation{
				SourceConnectionID: location.SourceConnectionID, Relation: location.Relation,
				Column: location.Column, Hint: location.Hint,
			}
		}
		synonyms := make([]string, len(term.Synonyms))
		copy(synonyms, term.Synonyms)
		glossary[i] = renderTerm{
			ID: term.ID, Term: term.Term, Synonyms: synonyms,
			Definition: term.Definition, DataLocations: locations,
		}
	}
	sources := make([]renderSource, len(doc.Sources))
	for i, source := range doc.Sources {
		tables := make([]renderTable, len(source.Tables))
		for j, table := range source.Tables {
			columns := make([]renderColumn, len(table.Columns))
			for k, column := range table.Columns {
				columns[k] = renderColumn{Name: column.Name, Note: column.Note}
			}
			tables[j] = renderTable{Relation: table.Relation, Note: table.Note, Columns: columns}
		}
		sources[i] = renderSource{
			SourceConnectionID: source.SourceConnectionID, Description: source.Description, Tables: tables,
		}
	}
	return renderedDocument{Description: doc.Description, Rules: rules, Glossary: glossary, Sources: sources}
}

func locationStrings(doc Document, termID string) []string {
	for _, term := range doc.Glossary {
		if term.ID != termID {
			continue
		}
		locations := make([]string, len(term.DataLocations))
		for i, location := range term.DataLocations {
			if location.Column == "" {
				locations[i] = location.Relation
			} else {
				locations[i] = location.Relation + "." + location.Column
			}
		}
		return locations
	}
	return nil
}
