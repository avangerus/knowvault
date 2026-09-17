package knowledgegraph

import (
	"strings"
	"testing"
	"time"
)

func graphProvenance() SourceProvenance {
	return SourceProvenance{
		WorkspaceID: "ws_demo", WorkspaceRevision: 1,
		SourceScopeID: "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV", SourceScopeRevision: 1,
		SourceObjectID:     "object_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SourceVersionID:    "version_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		EvidenceFragmentID: "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ObservedAt:         time.Unix(1, 0).UTC(), FreshnessAt: time.Unix(1, 0).UTC(),
	}
}

func graphHash(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func TestEntityValidationRequiresEvidenceBackedCanonicalIdentity(t *testing.T) {
	entity := Entity{
		OrganizationID: "org_demo", ID: "entity_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		EntityType: "PROCESS", CanonicalKeyHash: graphHash("a"),
		DisplayNameHash: graphHash("b"), AttributesJSON: []byte(`{"kind":"process"}`),
		SourceProvenance: graphProvenance(),
	}
	if err := entity.Validate("org_demo"); err != nil {
		t.Fatalf("valid entity rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Entity){
		"foreign tenant":  func(value *Entity) { value.OrganizationID = "org_other" },
		"unknown type":    func(value *Entity) { value.EntityType = "UNKNOWN" },
		"bad evidence id": func(value *Entity) { value.EvidenceFragmentID = "" },
		"raw attributes":  func(value *Entity) { value.AttributesJSON = []byte(`[]`) },
		"bad hash":        func(value *Entity) { value.CanonicalKeyHash = "sha256:bad" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := entity
			mutate(&mutated)
			if CodeOf(mutated.Validate("org_demo")) != CodeInvalid {
				t.Fatal("invalid entity passed validation")
			}
		})
	}
}

func TestRelationAndTermValidationStayGeneric(t *testing.T) {
	provenance := graphProvenance()
	relation := Relation{
		OrganizationID: "org_demo", ID: "relation_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SubjectEntityID: "entity_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Predicate:       "process.implemented_by", ObjectEntityID: "entity_01BX5ZZKBKACTAV9WEVGEMMVRZ",
		Confidence: 0.75, AttributesJSON: []byte(`{"source":"code"}`), SourceProvenance: provenance,
	}
	if err := relation.Validate("org_demo"); err != nil {
		t.Fatalf("valid relation rejected: %v", err)
	}
	term := SemanticTerm{
		OrganizationID: "org_demo", ID: "term_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CanonicalEntityID: "entity_01ARZ3NDEKTSV4RRFFQ69G5FAV", TermKind: "SYNONYM",
		Language: "ru", TermHash: graphHash("c"), ContextHash: graphHash("d"),
		Confidence: 1, AttributesJSON: []byte(`{"context":"kafka"}`), SourceProvenance: provenance,
	}
	if err := term.Validate("org_demo"); err != nil {
		t.Fatalf("valid semantic term rejected: %v", err)
	}
	for name, mutate := range map[string]func(*SemanticTerm){
		"bad language":              func(value *SemanticTerm) { value.Language = "RU" },
		"bad term kind":             func(value *SemanticTerm) { value.TermKind = "FREE_TEXT" },
		"bad confidence":            func(value *SemanticTerm) { value.Confidence = 2 },
		"bad predicate is separate": func(value *SemanticTerm) { value.TermHash = "sha256:bad" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := term
			mutate(&mutated)
			if CodeOf(mutated.Validate("org_demo")) != CodeInvalid {
				t.Fatal("invalid semantic term passed validation")
			}
		})
	}
	badRelation := relation
	badRelation.Predicate = "CrewWasteBranch"
	if CodeOf(badRelation.Validate("org_demo")) != CodeInvalid {
		t.Fatal("business-specific predicate escaped the closed generic predicate grammar")
	}
}

func TestSemanticTermHashIsDeterministicAndNormalized(t *testing.T) {
	left, err := SemanticTermHash("  Kafka ")
	if err != nil {
		t.Fatal(err)
	}
	right, err := SemanticTermHash("kAfKa")
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("normalized term hashes differ: %s != %s", left, right)
	}
	if _, err := SemanticTermHash("\n"); err == nil {
		t.Fatal("control-only semantic term accepted")
	}
}
