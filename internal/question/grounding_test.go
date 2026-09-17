package question

import (
	"strings"
	"testing"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// R1 outcome 1 negative controls: similarity is never a proof and a claim is
// confirmed only when its SOURCE_QUOTE span text is present in the stored
// extraction with a matching span hash.

func TestBindSourceQuoteConfirmsAnExactSpan(t *testing.T) {
	text := []byte("\u041f\u0440\u0430\u0432\u0438\u043b\u0430: \u0441\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439.\n\u0411\u043e\u043b\u0435\u0435 \u043f\u043e\u0437\u0434\u043d\u044f\u044f \u0441\u0442\u0440\u043e\u043a\u0430.")
	excerpt := "\u0411\u043e\u043b\u0435\u0435 \u043f\u043e\u0437\u0434\u043d\u044f\u044f \u0441\u0442\u0440\u043e\u043a\u0430"
	quote, status := bindSourceQuote(text, excerpt, "sv_1", "ext_1", "anchor_1")
	if status != GroundingConfirmedByFragment || quote == nil {
		t.Fatalf("an exact span must be confirmed, got status=%q quote=%#v", status, quote)
	}
	runes := []rune(string(text))
	start := int64(utf8.RuneCountInString(string(text)[:strings.Index(string(text), excerpt)]))
	end := start + int64(utf8.RuneCountInString(excerpt))
	if quote.Start != start || quote.End != end {
		t.Fatalf("offsets must address the exact span: got [%d,%d) want [%d,%d)", quote.Start, quote.End, start, end)
	}
	if quote.SourceVersionID != "sv_1" || quote.ExtractionID != "ext_1" || quote.Anchor != "anchor_1" {
		t.Fatalf("quote must carry the binding identifiers, got %#v", quote)
	}
	if want := canon.Hash([]byte(string(runes[quote.Start:quote.End]))); quote.TextHash != want {
		t.Fatalf("text_hash must be the hash of exactly the span: got %q want %q", quote.TextHash, want)
	}
}

func TestSpanHashMismatchIsUnbound(t *testing.T) {
	text := []byte("\u041f\u0440\u0430\u0432\u0438\u043b\u0430: \u0441\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439.")
	excerpt := "\u0441\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439"
	quote, status := bindSourceQuote(text, excerpt, "sv_1", "ext_1", "anchor_1")
	if status != GroundingConfirmedByFragment || quote == nil {
		t.Fatalf("fixture span should be bound, got status=%q", status)
	}
	// The guard: a quote whose span hash is not the hash of the stored span is
	// unbound, even though start/end are inside the text.
	tampered := *quote
	tampered.TextHash = canon.Hash([]byte("a different span"))
	if got := evaluateSourceQuote(&tampered, text, "sv_1", "ext_1"); got != GroundingUnconfirmed {
		t.Fatalf("a span-hash mismatch must be UNCONFIRMED, got %q", got)
	}
	// An end offset past the stored extraction is equally unbound.
	outOfRange := *quote
	outOfRange.End = int64(utf8.RuneCountInString(string(text))) + 1
	outOfRange.TextHash = canon.Hash([]byte("whatever"))
	if got := evaluateSourceQuote(&outOfRange, text, "sv_1", "ext_1"); got != GroundingUnconfirmed {
		t.Fatalf("an out-of-range span must be UNCONFIRMED, got %q", got)
	}
	// A quote bound to a different extraction is not a binding for this one.
	if got := evaluateSourceQuote(quote, text, "sv_1", "ext_other"); got != GroundingUnconfirmed {
		t.Fatalf("a foreign extraction id must be UNCONFIRMED, got %q", got)
	}
	// Sanity: the untouched quote still confirms.
	if got := evaluateSourceQuote(quote, text, "sv_1", "ext_1"); got != GroundingConfirmedByFragment {
		t.Fatalf("the untampered quote must remain confirmed, got %q", got)
	}
}

func TestHighSimilarityParaphraseWithoutASpanIsUnconfirmed(t *testing.T) {
	text := []byte("\u0421\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 \u0437\u0430\u044f\u0432\u043b\u0435\u043d\u0438\u044f \u0441\u043e\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442 \u0447\u0435\u0442\u044b\u0440\u043d\u0430\u0434\u0446\u0430\u0442\u044c \u043a\u0430\u043b\u0435\u043d\u0434\u0430\u0440\u043d\u044b\u0445 \u0434\u043d\u0435\u0439 \u0441 \u043c\u043e\u043c\u0435\u043d\u0442\u0430 \u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u0438.")
	// A paraphrase with near-total lexical overlap but no verbatim span: the
	// exact substring is absent, so no SOURCE_QUOTE can be bound. Similarity is
	// never consulted here, so no threshold can promote this to confirmed.
	paraphrase := "\u041f\u043e\u0434\u0430\u0447\u0430 \u0437\u0430\u044f\u0432\u043b\u0435\u043d\u0438\u044f \u2014 \u0447\u0435\u0442\u044b\u0440\u043d\u0430\u0434\u0446\u0430\u0442\u044c \u043a\u0430\u043b\u0435\u043d\u0434\u0430\u0440\u043d\u044b\u0445 \u0434\u043d\u0435\u0439 \u043f\u043e\u0441\u043b\u0435 \u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u0438."
	if strings.Contains(string(text), paraphrase) {
		t.Fatal("fixture is not a paraphrase; it must not be a verbatim span")
	}
	quote, status := bindSourceQuote(text, paraphrase, "sv_1", "ext_1", "anchor_1")
	if quote != nil || status != GroundingUnconfirmed {
		t.Fatalf("a paraphrase without a span must be UNCONFIRMED, got status=%q quote=%#v", status, quote)
	}
}

func TestAnswerWithOneUnboundClaimIsUnconfirmed(t *testing.T) {
	bound := Citation{Number: 1, Excerpt: "\u0441\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439", GroundingStatus: GroundingConfirmedByFragment,
		SourceQuote: &SourceQuote{SourceVersionID: "sv_1", ExtractionID: "ext_1", Anchor: "a", Start: 0, End: 4, TextHash: "sha256:x"}}
	unbound := Citation{Number: 2, Excerpt: "\u0441\u0432\u043e\u0431\u043e\u0434\u043d\u044b\u0439 \u043f\u0435\u0440\u0435\u0441\u043a\u0430\u0437", GroundingStatus: GroundingUnconfirmed}
	if got := answerGroundingStatus([]Citation{bound}); got != GroundingConfirmedByFragment {
		t.Fatalf("every claim bound must confirm the answer, got %q", got)
	}
	if got := answerGroundingStatus([]Citation{bound, unbound}); got != GroundingUnconfirmed {
		t.Fatalf("one unbound claim must make the answer UNCONFIRMED, got %q", got)
	}
	if got := answerGroundingStatus(nil); got != GroundingUnconfirmed {
		t.Fatalf("a citation-free answer must be UNCONFIRMED, got %q", got)
	}
}

func TestStructuredGroundingReverifiesTheDisclosedExcerpt(t *testing.T) {
	span := "\u0441\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439"
	quote := &SourceQuote{
		SourceVersionID: "sv_1", ExtractionID: "ext_1", Anchor: "anchor_1",
		Start: 12, End: 12 + int64(utf8.RuneCountInString(span)),
		TextHash: canon.Hash([]byte(span)),
	}
	confirmed := Citation{Excerpt: span}
	applyStructuredGrounding(&confirmed, Citation{SourceQuote: quote, GroundingStatus: GroundingConfirmedByFragment})
	if confirmed.GroundingStatus != GroundingConfirmedByFragment || confirmed.SourceQuote == nil {
		t.Fatalf("a self-consistent quote must stay confirmed, got %#v", confirmed)
	}
	// A sealed record whose text_hash is not the hash of the disclosed excerpt
	// is unbound on read, even though it claims the confirmed state.
	tamperedQuote := *quote
	tamperedQuote.TextHash = canon.Hash([]byte("\u0434\u0440\u0443\u0433\u043e\u0439 \u0442\u0435\u043a\u0441\u0442"))
	tampered := Citation{Excerpt: span}
	applyStructuredGrounding(&tampered, Citation{SourceQuote: &tamperedQuote, GroundingStatus: GroundingConfirmedByFragment})
	if tampered.GroundingStatus != GroundingUnconfirmed || tampered.SourceQuote != nil {
		t.Fatalf("a span-hash mismatch must be demoted on read, got %#v", tampered)
	}
	// A range whose length is not the excerpt's length is unbound too.
	wrongRange := *quote
	wrongRange.End = wrongRange.Start + 3
	misranged := Citation{Excerpt: span}
	applyStructuredGrounding(&misranged, Citation{SourceQuote: &wrongRange, GroundingStatus: GroundingConfirmedByFragment})
	if misranged.GroundingStatus != GroundingUnconfirmed || misranged.SourceQuote != nil {
		t.Fatalf("a range/excerpt length mismatch must be demoted on read, got %#v", misranged)
	}
}

func TestLegacyCitationWithoutOffsetsStaysReadableAndUnbound(t *testing.T) {
	citation := Citation{Number: 3, CitationID: "cit_3", Excerpt: "\u0441\u0442\u0430\u0440\u0430\u044f \u0446\u0438\u0442\u0430\u0442\u0430 \u0431\u0435\u0437 \u0441\u043c\u0435\u0449\u0435\u043d\u0438\u0439", Anchor: "anchor_3"}
	normalizeCitationGrounding(&citation)
	if citation.GroundingStatus != GroundingUnconfirmed || citation.SourceQuote != nil {
		t.Fatalf("a legacy citation must stay readable and unbound, got %#v", citation)
	}
	if citation.Excerpt != "\u0441\u0442\u0430\u0440\u0430\u044f \u0446\u0438\u0442\u0430\u0442\u0430 \u0431\u0435\u0437 \u0441\u043c\u0435\u0449\u0435\u043d\u0438\u0439" {
		t.Fatalf("the excerpt must remain readable, got %q", citation.Excerpt)
	}
	// A structured artifact that claims CONFIRMED without a quote is demoted.
	lying := Citation{Number: 4, Excerpt: "x", GroundingStatus: GroundingConfirmedByFragment}
	normalizeCitationGrounding(&lying)
	if lying.GroundingStatus != GroundingUnconfirmed {
		t.Fatalf("a quote-less CONFIRMED citation must be demoted, got %q", lying.GroundingStatus)
	}
}

func TestBindCitationGroundingUsesStoredCandidateText(t *testing.T) {
	text := []byte("\u041f\u0435\u0440\u0432\u0430\u044f \u0441\u0442\u0440\u043e\u043a\u0430.\n\u0421\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439.\n\u0422\u0440\u0435\u0442\u044c\u044f \u0441\u0442\u0440\u043e\u043a\u0430.")
	selected := []candidate{{
		ID: "ev_1", SourceVersionID: "sv_1", ExtractionID: "ext_1",
		Text: text, Anchor: []byte("anchor_1"),
	}}
	citations := []Citation{
		{Number: 1, EvidenceFragment: "ev_1", Excerpt: "\u0421\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439"},
		{Number: 2, EvidenceFragment: "ev_1", Excerpt: "\u043f\u0435\u0440\u0435\u0441\u043a\u0430\u0437 \u0431\u0435\u0437 \u0442\u043e\u0447\u043d\u043e\u0433\u043e \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0430"},
		{Number: 3, EvidenceFragment: "ev_missing", Excerpt: "\u0421\u0440\u043e\u043a \u043f\u043e\u0434\u0430\u0447\u0438 14 \u0434\u043d\u0435\u0439"},
	}
	bindCitationGrounding(citations, selected)
	if citations[0].GroundingStatus != GroundingConfirmedByFragment || citations[0].SourceQuote == nil {
		t.Fatalf("the exact excerpt must be bound, got %#v", citations[0])
	}
	if citations[1].GroundingStatus != GroundingUnconfirmed || citations[1].SourceQuote != nil {
		t.Fatalf("the paraphrase must stay unbound, got %#v", citations[1])
	}
	if citations[2].GroundingStatus != GroundingUnconfirmed || citations[2].SourceQuote != nil {
		t.Fatalf("a citation with no candidate lineage must stay unbound, got %#v", citations[2])
	}
	if got := answerGroundingStatus(citations); got != GroundingUnconfirmed {
		t.Fatalf("the mixed answer must be UNCONFIRMED, got %q", got)
	}
}
