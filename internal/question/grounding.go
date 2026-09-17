// R1 outcome 1: honest grounding.
//
// A claim is «confirmed by fragment» (CONFIRMED_BY_FRAGMENT) only when it is
// bound to an exact SOURCE_QUOTE span whose text is present in the stored
// extraction and whose text_hash is the hash of exactly that span. Similarity
// is never a proof: the embedding verifier stays a ranking hint and is not an
// input here. A missing span, a hash mismatch, a legacy citation without
// offsets, or a paraphrase whose only support is embedding similarity all stay
// UNCONFIRMED («unconfirmed»).

package question

import (
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// GroundingStatus is the closed two-value R1 grounding vocabulary exposed by
// REST and MCP on both a citation and the answer-level run projection.
type GroundingStatus string

const (
	// GroundingConfirmedByFragment is «confirmed by fragment»: the claim is
	// bound to a SOURCE_QUOTE whose [start,end) span text is present in the
	// stored extraction and whose text_hash matches that exact span.
	GroundingConfirmedByFragment GroundingStatus = "CONFIRMED_BY_FRAGMENT"
	// GroundingUnconfirmed is «unconfirmed»: anything else, including a
	// legacy citation without offsets and a paraphrase supported only by
	// embedding similarity.
	GroundingUnconfirmed GroundingStatus = "UNCONFIRMED"
)

// normalized collapses every value outside the closed vocabulary (including
// the zero value of an older structured artifact) to UNCONFIRMED. It never
// promotes an unknown value into the confirmed state.
func (status GroundingStatus) normalized() GroundingStatus {
	if status == GroundingConfirmedByFragment {
		return GroundingConfirmedByFragment
	}
	return GroundingUnconfirmed
}

// SourceQuote is the SOURCE_QUOTE binding required for a confirmed citation:
// {source_version_id, extraction_id, anchor, start, end, text_hash}. start/end
// are 0-based, end-exclusive character (rune) offsets into the stored
// extraction's normalized text; text_hash is sha256 over exactly that span.
type SourceQuote struct {
	SourceVersionID string `json:"source_version_id"`
	ExtractionID    string `json:"extraction_id"`
	Anchor          string `json:"anchor"`
	Start           int64  `json:"start"`
	End             int64  `json:"end"`
	TextHash        string `json:"text_hash"`
}

// bindSourceQuote locates excerpt as a contiguous verbatim span of text and
// returns the SOURCE_QUOTE plus its grounding state. It returns nil and
// UNCONFIRMED whenever the excerpt is not an exact span (for example a model
// paraphrase) or the binding identifiers are absent. The produced quote is
// re-evaluated through evaluateSourceQuote before it is accepted, so the
// returned state is always the same decision the read path reports.
func bindSourceQuote(text []byte, excerpt, sourceVersionID, extractionID, anchor string) (*SourceQuote, GroundingStatus) {
	if excerpt == "" || len(text) == 0 || sourceVersionID == "" || extractionID == "" || anchor == "" {
		return nil, GroundingUnconfirmed
	}
	value := string(text)
	byteStart := strings.Index(value, excerpt)
	if byteStart < 0 {
		return nil, GroundingUnconfirmed
	}
	start := int64(utf8.RuneCountInString(value[:byteStart]))
	end := start + int64(utf8.RuneCountInString(excerpt))
	span := value[byteStart : byteStart+len(excerpt)]
	quote := &SourceQuote{
		SourceVersionID: sourceVersionID,
		ExtractionID:    extractionID,
		Anchor:          anchor,
		Start:           start,
		End:             end,
		TextHash:        canon.Hash([]byte(span)),
	}
	if status := evaluateSourceQuote(quote, text, sourceVersionID, extractionID); status != GroundingConfirmedByFragment {
		return nil, GroundingUnconfirmed
	}
	return quote, GroundingConfirmedByFragment
}

// evaluateSourceQuote is the pure grounding decision. It confirms only when
// every part of the SOURCE_QUOTE binding holds against the stored extraction
// text: the identifiers match, start/end address a valid span of the runes,
// and text_hash is the hash of exactly that span. It never consults a cosine
// similarity or any threshold.
func evaluateSourceQuote(quote *SourceQuote, text []byte, sourceVersionID, extractionID string) GroundingStatus {
	if quote == nil || quote.TextHash == "" || quote.Anchor == "" {
		return GroundingUnconfirmed
	}
	if sourceVersionID == "" || extractionID == "" ||
		quote.SourceVersionID != sourceVersionID || quote.ExtractionID != extractionID {
		return GroundingUnconfirmed
	}
	if quote.Start < 0 || quote.End < quote.Start {
		return GroundingUnconfirmed
	}
	runes := []rune(string(text))
	if quote.End > int64(len(runes)) {
		return GroundingUnconfirmed
	}
	span := string(runes[quote.Start:quote.End])
	if canon.Hash([]byte(span)) != quote.TextHash {
		return GroundingUnconfirmed
	}
	return GroundingConfirmedByFragment
}

// bindCitationGrounding binds every citation to its authorized candidate's
// stored normalized text. A citation whose excerpt is an exact span becomes
// CONFIRMED_BY_FRAGMENT with its SOURCE_QUOTE; anything else (a paraphrase, a
// missing lineage row, an anchor-less citation) stays UNCONFIRMED with no
// quote. It is deterministic and never consults a similarity score.
func bindCitationGrounding(citations []Citation, selected []candidate) {
	for index := range citations {
		citations[index].SourceQuote = nil
		citations[index].GroundingStatus = GroundingUnconfirmed
		item, found := candidateForCitation(selected, citations[index].EvidenceFragment)
		if !found {
			continue
		}
		quote, status := bindSourceQuote(item.Text, citations[index].Excerpt,
			item.SourceVersionID, item.ExtractionID, string(item.Anchor))
		citations[index].SourceQuote = quote
		citations[index].GroundingStatus = status
	}
}

// normalizeCitationGrounding enforces the closed vocabulary on a citation
// decoded from an older artifact or carrying no quote at all. Legacy citations
// without offsets remain readable and are reported UNCONFIRMED.
func normalizeCitationGrounding(citation *Citation) {
	citation.GroundingStatus = citation.GroundingStatus.normalized()
	if citation.SourceQuote == nil {
		citation.GroundingStatus = GroundingUnconfirmed
	}
}

// answerGroundingStatus reduces the per-citation states to the answer-level
// state: CONFIRMED only when there is at least one claim and every claim is
// bound. One unbound claim makes the whole answer «unconfirmed».
func answerGroundingStatus(citations []Citation) GroundingStatus {
	if len(citations) == 0 {
		return GroundingUnconfirmed
	}
	for index := range citations {
		if citations[index].GroundingStatus.normalized() != GroundingConfirmedByFragment {
			return GroundingUnconfirmed
		}
	}
	return GroundingConfirmedByFragment
}

// quoteMatchesSpan re-verifies a persisted quote against the exact disclosed
// span text: the half-open rune range must be exactly the span length and the
// text hash must be the hash of that span. It is the read-path half of the
// span-hash guard, so a corrupted or mismatched quote is demoted even if the
// sealed artifact labelled it confirmed.
func quoteMatchesSpan(quote *SourceQuote, span string) bool {
	if quote == nil || span == "" {
		return false
	}
	if quote.End-quote.Start != int64(utf8.RuneCountInString(span)) {
		return false
	}
	return canon.Hash([]byte(span)) == quote.TextHash
}

// applyStructuredGrounding copies the R1 fields persisted in the server-owned
// structured answer artifact onto the citation rebuilt from the question
// citation table, but only after re-checking the persisted quote against the
// disclosed excerpt's exact bytes. Only the grounding projection is copied; the
// wire excerpt, anchor and deep link keep coming from their own gated artifacts.
func applyStructuredGrounding(citation *Citation, structured Citation) {
	citation.SourceQuote = nil
	citation.GroundingStatus = GroundingUnconfirmed
	if structured.GroundingStatus.normalized() != GroundingConfirmedByFragment {
		return
	}
	if !quoteMatchesSpan(structured.SourceQuote, citation.Excerpt) {
		return
	}
	citation.SourceQuote = structured.SourceQuote
	citation.GroundingStatus = GroundingConfirmedByFragment
}
