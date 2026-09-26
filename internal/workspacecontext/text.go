package workspacecontext

import "strings"

// The owner's card W-2 decision: the workspace description, the instructions
// for the assistant (the structured Rules before this card) and the glossary
// (the structured Glossary before this card) are each one plain-text field.
// Rules and Glossary are still stored and still travel to the model, but the
// screen the administrator edits shows one text block per section. These
// helpers are the single migration source for that block: a document whose
// text field is empty renders the structured records it already holds, so
// nothing an administrator entered before this card disappears from the
// field, and saving that same text back does not duplicate it.

// DerivedInstructions renders the structured Rules as the plain-text
// instructions block, one rule per line, in their stored order. An empty rule
// text is skipped rather than producing a blank line.
func DerivedInstructions(rules []Rule) string {
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		if strings.TrimSpace(rule.Text) == "" {
			continue
		}
		lines = append(lines, rule.Text)
	}
	return strings.Join(lines, "\n")
}

// EffectiveInstructions is the instructions text the screen shows and the
// model is offered: the administrator's own Instructions when they wrote one,
// otherwise the plain-text rendering of the structured Rules.
func EffectiveInstructions(doc Document) string {
	if doc.Instructions != "" {
		return doc.Instructions
	}
	return DerivedInstructions(doc.Rules)
}

// TermLine renders one glossary term as a readable line: the term, its
// synonyms in parentheses, its definition after a dash, and its data
// locations in square brackets. It deliberately does not print the
// source_connection_id or the term id: those are server identifiers, and the
// owner asked the glossary field to show readable text, not ids.
func TermLine(term Term) string {
	line := term.Term
	if len(term.Synonyms) > 0 {
		line += " (" + strings.Join(term.Synonyms, ", ") + ")"
	}
	if strings.TrimSpace(term.Definition) != "" {
		line += " — " + term.Definition
	}
	if len(term.DataLocations) > 0 {
		addresses := make([]string, 0, len(term.DataLocations))
		for _, location := range term.DataLocations {
			address := location.Relation
			if location.Column != "" {
				address += "." + location.Column
			}
			if strings.TrimSpace(location.Hint) != "" {
				address += " (" + location.Hint + ")"
			}
			addresses = append(addresses, address)
		}
		line += " [" + strings.Join(addresses, ", ") + "]"
	}
	return line
}

// DerivedGlossaryText renders the structured Glossary as the plain-text
// glossary block, one term per line, in their stored order.
func DerivedGlossaryText(glossary []Term) string {
	lines := make([]string, 0, len(glossary))
	for _, term := range glossary {
		if strings.TrimSpace(term.Term) == "" {
			continue
		}
		lines = append(lines, TermLine(term))
	}
	return strings.Join(lines, "\n")
}

// EffectiveGlossaryText is the glossary text the screen shows and the model is
// offered: the administrator's own GlossaryText when they wrote one, otherwise
// the plain-text rendering of the structured Glossary.
func EffectiveGlossaryText(doc Document) string {
	if doc.GlossaryText != "" {
		return doc.GlossaryText
	}
	return DerivedGlossaryText(doc.Glossary)
}

// clearDerivedText drops a text field that is byte-identical to the rendering
// of the structured records it was migrated from. The screen sends the shown
// (derived) text back on every save, so without this an untouched field would
// be stored a second time and reach the model twice. A field the
// administrator actually edited differs from the rendering and is kept.
func clearDerivedText(doc Document) Document {
	if doc.Instructions != "" && doc.Instructions == DerivedInstructions(doc.Rules) {
		doc.Instructions = ""
	}
	if doc.GlossaryText != "" && doc.GlossaryText == DerivedGlossaryText(doc.Glossary) {
		doc.GlossaryText = ""
	}
	return doc
}
