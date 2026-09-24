package workspacecontext

import "testing"

func TestHashIsDeterministicAndNFCInsensitive(t *testing.T) {
	t.Parallel()
	base := Document{
		Description: "Café", // NFD
		Rules:       []Rule{{ID: "rule_01ARZ3NDEKTSV4RRFFQ69G5FAV", Text: "Answer in RUB."}},
		Glossary: []Term{{
			ID: "term_01ARZ3NDEKTSV4RRFFQ69G5FAV", Term: "МНО", Synonyms: []string{"Мониторинг"},
			Definition: "Единица учёта.",
		}},
	}
	nfc := base
	nfc.Description = "Café" // already NFC

	firstHash, err := Hash(base)
	if err != nil {
		t.Fatalf("Hash(base): %v", err)
	}
	secondHash, err := Hash(base)
	if err != nil {
		t.Fatalf("Hash(base) again: %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("Hash is not deterministic: %q vs %q", firstHash, secondHash)
	}

	nfcHash, err := Hash(nfc)
	if err != nil {
		t.Fatalf("Hash(nfc): %v", err)
	}
	if firstHash != nfcHash {
		t.Fatalf("Hash is sensitive to Unicode normalization form: %q vs %q", firstHash, nfcHash)
	}
	if len(firstHash) != len("sha256:")+64 || firstHash[:7] != "sha256:" {
		t.Fatalf("Hash does not have the sha256:<hex> shape: %q", firstHash)
	}
}

func TestHashChangesWithContent(t *testing.T) {
	t.Parallel()
	first := Document{Description: "A"}
	second := Document{Description: "B"}

	firstHash, err := Hash(first)
	if err != nil {
		t.Fatalf("Hash(first): %v", err)
	}
	secondHash, err := Hash(second)
	if err != nil {
		t.Fatalf("Hash(second): %v", err)
	}
	if firstHash == secondHash {
		t.Fatal("Hash did not change when document content changed")
	}
}

func TestHashIsOrderSensitiveForArrays(t *testing.T) {
	t.Parallel()
	first := Document{Rules: []Rule{{ID: "rule_a", Text: "one"}, {ID: "rule_b", Text: "two"}}}
	second := Document{Rules: []Rule{{ID: "rule_b", Text: "two"}, {ID: "rule_a", Text: "one"}}}

	firstHash, err := Hash(first)
	if err != nil {
		t.Fatalf("Hash(first): %v", err)
	}
	secondHash, err := Hash(second)
	if err != nil {
		t.Fatalf("Hash(second): %v", err)
	}
	if firstHash == secondHash {
		t.Fatal("Hash treated ordered rules as an unordered set")
	}
}
