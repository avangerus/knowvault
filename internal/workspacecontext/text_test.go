package workspacecontext

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEffectiveTextDerivesFromStructuredRecords(t *testing.T) {
	t.Parallel()
	doc := Document{
		Rules: []Rule{{ID: "rule_a", Text: "Prefer the latest quarter."}, {ID: "rule_b", Text: "Answer in RUB."}},
		Glossary: []Term{{
			ID: "term_a", Term: "МНО", Synonyms: []string{"месторождение"},
			Definition: "Единица учёта.",
			DataLocations: []DataLocation{{
				SourceConnectionID: "conn_1", Relation: "public.orders", Column: "status", Hint: "current",
			}},
		}},
	}

	instructions := EffectiveInstructions(doc)
	if instructions != "Prefer the latest quarter.\nAnswer in RUB." {
		t.Fatalf("derived instructions = %q", instructions)
	}
	glossary := EffectiveGlossaryText(doc)
	for _, want := range []string{"МНО", "месторождение", "Единица учёта.", "public.orders.status", "current"} {
		if !strings.Contains(glossary, want) {
			t.Fatalf("derived glossary %q missing %q", glossary, want)
		}
	}
	if strings.Contains(glossary, "conn_1") || strings.Contains(glossary, "term_a") {
		t.Fatalf("derived glossary leaked an identifier: %q", glossary)
	}
}

func TestEffectiveTextPrefersTheAdministratorsOwnWords(t *testing.T) {
	t.Parallel()
	doc := Document{
		Instructions: "Always answer in one sentence.",
		GlossaryText: "МНО — площадка.",
		Rules:        []Rule{{ID: "rule_a", Text: "Old rule text."}},
		Glossary:     []Term{{ID: "term_a", Term: "Old term"}},
	}

	if got := EffectiveInstructions(doc); got != "Always answer in one sentence." {
		t.Fatalf("EffectiveInstructions = %q", got)
	}
	if got := EffectiveGlossaryText(doc); got != "МНО — площадка." {
		t.Fatalf("EffectiveGlossaryText = %q", got)
	}
}

func TestValidateAcceptsMultiLinePlainText(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Instructions = "First rule.\nSecond rule."
	doc.GlossaryText = "МНО — площадка.\nДоговор — agreement."

	normalized, err := Validate(doc, known)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if normalized.Instructions != doc.Instructions || normalized.GlossaryText != doc.GlossaryText {
		t.Fatalf("plain text was not preserved: %#v", normalized)
	}
}

func TestValidateRejectsOverlongPlainText(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Instructions = strings.Repeat("a", maxInstructionsChars+1)
	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("oversize instructions: code=%v", CodeOf(err))
	}
	doc, known = validDoc(t)
	doc.GlossaryText = strings.Repeat("b", maxGlossaryTextChars+1)
	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("oversize glossary text: code=%v", CodeOf(err))
	}
}

// clearDerivedText is what keeps an untouched save from storing the derived
// rendering a second time.
func TestClearDerivedTextDropsOnlyTheUnchangedRendering(t *testing.T) {
	t.Parallel()
	doc := Document{
		Rules:    []Rule{{ID: "rule_a", Text: "Rule one."}},
		Glossary: []Term{{ID: "term_a", Term: "МНО", Definition: "Площадка."}},
	}
	doc.Instructions = DerivedInstructions(doc.Rules)
	doc.GlossaryText = DerivedGlossaryText(doc.Glossary)

	cleared := clearDerivedText(doc)
	if cleared.Instructions != "" || cleared.GlossaryText != "" {
		t.Fatalf("unchanged rendering was not cleared: %#v", cleared)
	}
	if EffectiveInstructions(cleared) != "Rule one." || !strings.Contains(EffectiveGlossaryText(cleared), "МНО") {
		t.Fatalf("clearing changed the effective text: %#v", cleared)
	}

	edited := doc
	edited.Instructions = "Rule one.\nRule two."
	kept := clearDerivedText(edited)
	if kept.Instructions != "Rule one.\nRule two." {
		t.Fatalf("edited instructions were cleared: %q", kept.Instructions)
	}
}

func TestRenderCarriesPlainTextFieldsToTheModel(t *testing.T) {
	t.Parallel()
	const instructions = "INSTRUCTIONS-SENTINEL-7391"
	const glossary = "GLOSSARY-SENTINEL-8254"
	doc := Document{Instructions: instructions, GlossaryText: glossary}

	rendered, _ := Render(doc, 4, "", 64*1024)
	prefix := "WORKSPACE_CONTEXT_JSON (version 4): "
	if !strings.HasPrefix(rendered, prefix) {
		t.Fatalf("missing fixed prefix: %q", rendered)
	}
	var decoded struct {
		Instructions string `json:"instructions"`
		GlossaryText string `json:"glossary_text"`
	}
	if err := json.Unmarshal([]byte(rendered[len(prefix):]), &decoded); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v\nbody: %s", err, rendered)
	}
	if decoded.Instructions != instructions || decoded.GlossaryText != glossary {
		t.Fatalf("plain text did not reach the model block: %#v", decoded)
	}
}

func TestRenderOmitsEmptyPlainTextFields(t *testing.T) {
	t.Parallel()
	doc := Document{Description: "Short.", Rules: []Rule{{ID: "rule_a", Text: "Rule."}}}

	rendered, _ := Render(doc, 1, "", 16*1024)
	if strings.Contains(rendered, "instructions") || strings.Contains(rendered, "glossary_text") {
		t.Fatalf("empty plain-text fields should be omitted entirely: %q", rendered)
	}
}
