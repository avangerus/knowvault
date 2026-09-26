package workspacecontext

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/ids"
)

func mustID(t *testing.T, prefix string) string {
	t.Helper()
	value, err := ids.New(prefix)
	if err != nil {
		t.Fatalf("ids.New(%q): %v", prefix, err)
	}
	return value
}

func validDoc(t *testing.T) (Document, []KnownProjection) {
	t.Helper()
	doc := Document{
		Description: "Workspace answers use RUB and Moscow time.",
		Rules:       []Rule{{ID: mustID(t, "rule"), Text: "Prefer the latest fiscal quarter."}},
		Glossary: []Term{{
			ID: mustID(t, "term"), Term: "МНО", Synonyms: []string{"Мониторинг налоговых обязательств"},
			Definition: "Единица учёта задолженности.",
			DataLocations: []DataLocation{
				{SourceConnectionID: "conn_pg1", Relation: "invoices", Column: "status", Hint: "current status code"},
			},
		}},
		Sources: []Source{{
			SourceConnectionID: "conn_pg1", Description: "Primary billing database.",
			Tables: []Table{{
				Relation: "invoices", Note: "One row per invoice.",
				Columns: []Column{{Name: "status", Note: "Lifecycle status code."}},
			}},
		}},
	}
	known := []KnownProjection{{SourceConnectionID: "conn_pg1", Relation: "invoices", Columns: []string{"status", "amount"}}}
	return doc, known
}

func TestValidateAcceptsValidDocumentAndNormalizesNFC(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Description = "Café" // NFD form of "Café" (e + combining acute accent).

	normalized, err := Validate(doc, known)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if normalized.Description != "Café" {
		t.Fatalf("description not NFC-normalized: %q", normalized.Description)
	}
	if len(normalized.Glossary) != 1 || normalized.Glossary[0].Term != "МНО" {
		t.Fatalf("unexpected normalized glossary: %#v", normalized.Glossary)
	}
}

func TestValidateRejectsOversizeDescription(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Description = strings.Repeat("a", maxDescriptionChars+1)

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for oversize description, got %v (%v)", CodeOf(err), err)
	}
}

func TestValidateRejectsOversizeGlossary(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Glossary = make([]Term, maxGlossaryTerms+1)
	for i := range doc.Glossary {
		doc.Glossary[i] = Term{ID: mustID(t, "term"), Term: "T"}
	}

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for oversize glossary, got %v", CodeOf(err))
	}
}

func TestValidateRejectsControlCharacters(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Rules[0].Text = "Prefer the latest\x07 fiscal quarter."

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for a control character, got %v", CodeOf(err))
	}
}

func TestValidateRejectsUnknownColumn(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Glossary[0].DataLocations[0].Column = "ssn"

	if _, err := Validate(doc, known); CodeOf(err) != CodeUnknownLocation {
		t.Fatalf("expected CodeUnknownLocation for an unregistered column, got %v", CodeOf(err))
	}
}

func TestValidateRejectsUnknownRelation(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Sources[0].Tables[0].Relation = "secret_table"

	if _, err := Validate(doc, known); CodeOf(err) != CodeUnknownLocation {
		t.Fatalf("expected CodeUnknownLocation for an unregistered relation, got %v", CodeOf(err))
	}
}

func TestValidateRejectsUnknownSource(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Sources[0].SourceConnectionID = "conn_other"

	if _, err := Validate(doc, known); CodeOf(err) != CodeUnknownLocation {
		t.Fatalf("expected CodeUnknownLocation for a disabled/unknown source, got %v", CodeOf(err))
	}
}

func TestValidateRejectsMalformedServerAssignedID(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Glossary[0].ID = "term-not-a-ulid"

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for a malformed id, got %v", CodeOf(err))
	}
}

func TestValidateRejectsWrongPrefixID(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	// A syntactically valid assigned id, but minted for the wrong entity kind.
	doc.Glossary[0].ID = mustID(t, "rule")

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for a wrong-prefix id, got %v", CodeOf(err))
	}
}

func TestValidateRejectsDuplicateIDs(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Glossary = append(doc.Glossary, Term{ID: doc.Glossary[0].ID, Term: "Дубль"})

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for duplicate glossary ids, got %v", CodeOf(err))
	}
}

func TestValidateRejectsDocumentOverByteBudget(t *testing.T) {
	t.Parallel()
	doc, known := validDoc(t)
	doc.Description = strings.Repeat("a", maxDescriptionChars)
	for i := 0; i < maxRules; i++ {
		doc.Rules = append(doc.Rules, Rule{ID: mustID(t, "rule"), Text: strings.Repeat("b", maxRuleTextChars)})
	}
	doc.Rules = doc.Rules[:maxRules]
	for i := 0; i < maxGlossaryTerms-1; i++ {
		doc.Glossary = append(doc.Glossary, Term{
			ID: mustID(t, "term"), Term: strings.Repeat("c", maxTermChars),
			Definition: strings.Repeat("d", maxDefinitionChars),
		})
	}

	if _, err := Validate(doc, known); CodeOf(err) != CodeInvalidDocument {
		t.Fatalf("expected CodeInvalidDocument for exceeding the 256 KiB document bound, got %v", CodeOf(err))
	}
}
