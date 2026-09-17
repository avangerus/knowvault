package retrieval

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

func TestExecutorQueryBounds(t *testing.T) {
	if !validQuery("\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f?") {
		t.Fatal("valid natural-language query rejected")
	}
	for _, query := range []string{"", "   ", strings.Repeat("q", maximumQueryBytes+1)} {
		if validQuery(query) {
			t.Fatalf("invalid query accepted: %q", query)
		}
	}
}

func TestSearchTermsForAggregateUseDeclaredFieldsAndTemporalHints(t *testing.T) {
	planned, err := planner.Default().Plan("aggregate entity records metric_field=payload[/kilograms] group_by=payload[/crew] top=3 order=desc 2026-09-01 \u043f\u043e 2026-09-04")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Aggregate {
		t.Fatalf("aggregate plan: %#v %v", planned, err)
	}
	terms := searchTermsForPlan(planned)
	joined := strings.Join(terms, "\x00")
	for _, want := range []string{"kilograms", "crew", "last_updated_at", "observed_at"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("aggregate retrieval terms=%v missing %q", terms, want)
		}
	}
	for _, forbidden := range []string{"payload", "entity", "records", "2026"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("aggregate retrieval terms=%v leaked broad term %q", terms, forbidden)
		}
	}
}

func TestSearchTermsForCompareDropStructuredEnvelopeNoise(t *testing.T) {
	planned, err := planner.Default().Plan("\u0441\u0440\u0430\u0432\u043d\u0438 payload[/status] \u043c\u0435\u0436\u0434\u0443 contracts \u0438 dispatches")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Compare {
		t.Fatalf("compare plan: %#v %v", planned, err)
	}
	terms := searchTermsForPlan(planned)
	joined := strings.Join(terms, "\x00")
	if strings.Contains(joined, "payload") {
		t.Fatalf("compare retrieval leaked structural payload term: %v", terms)
	}
	for _, want := range []string{"status", "contracts", "dispatches"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("compare retrieval terms=%v missing %q", terms, want)
		}
	}
	for _, forbidden := range []string{"\u0441\u0440\u0430\u0432\u043d\u0438", "\u043c\u0435\u0436\u0434\u0443"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("compare retrieval leaked operation noise %q: %v", forbidden, terms)
		}
	}
}

func TestSearchTermsForAuditRetainControlIdentifier(t *testing.T) {
	planned, err := planner.Default().Plan("\u043f\u0440\u043e\u0432\u0435\u0440\u044c audit control_c17 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b \u0438 \u043a\u043e\u0434")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Audit {
		t.Fatalf("audit plan: %#v %v", planned, err)
	}
	terms := searchTermsForPlan(planned)
	joined := strings.Join(terms, "\x00")
	if !strings.Contains(joined, "control_c17") {
		t.Fatalf("audit retrieval dropped control identifier: %v", terms)
	}
	for _, forbidden := range []string{"audit", "\u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b", "\u043a\u043e\u0434", "\u043f\u0440\u043e\u0432\u0435\u0440\u044c"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("audit retrieval leaked operation noise %q: %v", forbidden, terms)
		}
	}
}

func TestExpandPhraseTermsKeepsStableSinglesAndNGrams(t *testing.T) {
	terms := expandPhraseTerms([]string{"Event", "streaming", "bus", "Kafka"})
	want := []string{
		"event", "streaming", "bus", "kafka",
		"event streaming", "streaming bus", "bus kafka",
		"event streaming bus", "streaming bus kafka",
	}
	if len(terms) != len(want) {
		t.Fatalf("expanded terms=%v, want=%v", terms, want)
	}
	for index := range want {
		if terms[index] != want[index] {
			t.Fatalf("expanded terms[%d]=%q, want %q (all=%v)", index, terms[index], want[index], terms)
		}
	}
	if got := expandPhraseTerms([]string{"Event", "streaming", "bus", "Kafka"}); strings.Join(got, "\x00") != strings.Join(terms, "\x00") {
		t.Fatalf("phrase expansion is not deterministic: first=%v second=%v", terms, got)
	}
}

func TestExpandPhraseTermsDeduplicatesAndCapsUntrustedInput(t *testing.T) {
	input := make([]string, 0, 48)
	for index := 0; index < 48; index++ {
		input = append(input, "Term"+string(rune('A'+index%26)))
	}
	input = append([]string{"Event", "EVENT", "bad\nterm", ""}, input...)
	terms := expandPhraseTerms(input)
	if len(terms) > maximumExpandedTerms {
		t.Fatalf("expanded terms exceeded cap: %d > %d", len(terms), maximumExpandedTerms)
	}
	seen := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		if term == "" || strings.ContainsAny(term, "\r\n\x00") {
			t.Fatalf("unsafe term escaped expansion: %q", term)
		}
		if _, exists := seen[term]; exists {
			t.Fatalf("duplicate term escaped expansion: %q in %v", term, terms)
		}
		seen[term] = struct{}{}
	}
	if terms[0] != "event" {
		t.Fatalf("stable first term changed: %v", terms)
	}
	bridged := expandPhraseTerms([]string{"event", "bad\nterm", "bus"})
	for _, term := range bridged {
		if term == "event bus" {
			t.Fatalf("invalid input bridged two lexical terms: %v", bridged)
		}
	}
}

func TestExpandPhraseTermsRetainsSuppliedPhraseWithoutCrossConcatenation(t *testing.T) {
	terms := expandPhraseTerms([]string{"event streaming bus", "kafka"})
	want := []string{"event streaming bus", "kafka"}
	if strings.Join(terms, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("supplied phrase was cross-concatenated: got=%v want=%v", terms, want)
	}
}

func TestExecutorRequiresExactEvidenceLineage(t *testing.T) {
	document := search.IndexDocument{
		OrganizationID: "org-a", SourceObjectID: "object-a", SourceVersionID: "version-a",
		ExtractionID: "extraction-a", ContentHash: "sha256:" + strings.Repeat("a", 64),
		TextHash:   "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash: "hmac-sha256:k1:" + strings.Repeat("c", 64),
	}
	fragment := evidence.Fragment{
		FragmentID: "fragment-a", SourceObjectID: "object-a", SourceVersionID: "version-a",
		ExtractionID: "extraction-a", ContentHash: document.ContentHash,
		EvidenceTextHash: document.TextHash, AnchorHash: document.AnchorHash,
	}
	if !matches(document, fragment, fragment.FragmentID, "org-a") {
		t.Fatal("exact lineage rejected")
	}
	fragment.AnchorHash = "hmac-sha256:k1:" + strings.Repeat("d", 64)
	if matches(document, fragment, fragment.FragmentID, "org-a") {
		t.Fatal("anchor drift accepted")
	}
	fragment.AnchorHash = document.AnchorHash
	fragment.SourceVersionID = "version-other"
	if matches(document, fragment, fragment.FragmentID, "org-a") {
		t.Fatal("version drift accepted")
	}
	fragment.SourceVersionID = document.SourceVersionID
	if matches(document, fragment, fragment.FragmentID, "org-b") {
		t.Fatal("cross-tenant lineage accepted")
	}
}

func TestExecutorResolvesEachMultiFragmentHashByEvidenceID(t *testing.T) {
	firstTextHash := "hmac-sha256:k1:" + strings.Repeat("b", 64)
	firstAnchorHash := "hmac-sha256:k1:" + strings.Repeat("c", 64)
	secondTextHash := "hmac-sha256:k1:" + strings.Repeat("d", 64)
	secondAnchorHash := "hmac-sha256:k1:" + strings.Repeat("e", 64)
	document := search.IndexDocument{
		OrganizationID:       "org-a",
		SourceObjectID:       "object-a",
		SourceVersionID:      "version-a",
		ExtractionID:         "extraction-a",
		EvidenceFragmentID:   "fragment-a",
		EvidenceFragmentIDs:  []string{"fragment-a", "fragment-b"},
		EvidenceTextHashes:   []string{firstTextHash, secondTextHash},
		EvidenceAnchorHashes: []string{firstAnchorHash, secondAnchorHash},
		ContentHash:          "sha256:" + strings.Repeat("a", 64),
		TextHash:             firstTextHash,
		AnchorHash:           firstAnchorHash,
	}
	fragment := evidence.Fragment{
		FragmentID: "fragment-b", SourceObjectID: "object-a", SourceVersionID: "version-a",
		ExtractionID: "extraction-a", ContentHash: document.ContentHash,
		EvidenceTextHash: secondTextHash, AnchorHash: secondAnchorHash,
	}
	if !matches(document, fragment, fragment.FragmentID, "org-a") {
		t.Fatal("second multi-fragment Evidence hash was not resolved by id")
	}
	fragment.AnchorHash = firstAnchorHash
	if matches(document, fragment, fragment.FragmentID, "org-a") {
		t.Fatal("second multi-fragment anchor drift accepted")
	}
}
