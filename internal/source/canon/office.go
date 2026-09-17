package canon

// The OOXML office anchor builders and the derived DOCX paragraph identity. Each
// returns the canonical JCS bytes of its anchor exactly as source-anchor.schema.json
// (kinds DOCX/PPTX/XLSX) defines it. canon is the SINGLE canonicalization authority:
// the isolated document-parser worker (ADR-0062) observes structure and reports raw
// text only — it never normalizes, hashes, offsets or anchors — so every anchor and
// every hash below is computed here, by the Go re-validator on ingestion and by the
// terminal resolver on citation. Correctness therefore cannot depend on a second
// implementation of Unicode normalization.
// DOCX and PPTX index a half-open UTF-8 byte range into a single structural node's
// text-v1 canonical text; XLSX identifies a sheet cell/range and carries no text
// offsets (the A1 range is the unit).

// DocxAnchorBytes returns the canonical JCS of a DOCX anchor: the OOXML section
// path (package part + structural position), the paragraph id (a POI-native
// "native:<id>" or the deterministic "derived:sha256:<64hex>" of CANONICALIZATION),
// and a half-open UTF-8 byte range into that paragraph's text-v1 canonical text.
func DocxAnchorBytes(sectionPath []string, paragraphID string, textStart, textEnd int) ([]byte, error) {
	return canonicalJSON(struct {
		Kind                 string   `json:"kind"`
		SectionPath          []string `json:"section_path"`
		ParagraphID          string   `json:"paragraph_id"`
		TextStart            int      `json:"text_start"`
		TextEnd              int      `json:"text_end"`
		OffsetUnit           string   `json:"offset_unit"`
		RangeSemantics       string   `json:"range_semantics"`
		NormalizationVersion string   `json:"normalization_version"`
	}{
		Kind: "DOCX", SectionPath: sectionPath, ParagraphID: paragraphID,
		TextStart: textStart, TextEnd: textEnd,
		OffsetUnit: "UTF8_BYTE", RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE",
		NormalizationVersion: NormalizationVersion,
	})
}

// PptxAnchorBytes returns the canonical JCS of a PPTX anchor: the 1-based slide
// number, the shape id taken from the exact slide shape tree (never visual order),
// and a half-open UTF-8 byte range into that shape's text-v1 canonical text.
func PptxAnchorBytes(slide int, shapeID string, textStart, textEnd int) ([]byte, error) {
	return canonicalJSON(struct {
		Kind                 string `json:"kind"`
		Slide                int    `json:"slide"`
		ShapeID              string `json:"shape_id"`
		TextStart            int    `json:"text_start"`
		TextEnd              int    `json:"text_end"`
		OffsetUnit           string `json:"offset_unit"`
		RangeSemantics       string `json:"range_semantics"`
		NormalizationVersion string `json:"normalization_version"`
	}{
		Kind: "PPTX", Slide: slide, ShapeID: shapeID,
		TextStart: textStart, TextEnd: textEnd,
		OffsetUnit: "UTF8_BYTE", RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE",
		NormalizationVersion: NormalizationVersion,
	})
}

// DerivedParagraphID returns the deterministic DOCX paragraph identity of
// CANONICALIZATION.md s3 for a paragraph that carries no native OOXML id:
// "derived:" + sha256 of the JCS object
// {"normalization_version","paragraph_ordinal","paragraph_text_hash","section_path"}.
// paragraphTextHash must be the canon.Hash of the paragraph's own text-v1 canonical
// bytes. The derived id is a function of canonicalized text, so it is canon's
// authority and never the worker's: a worker-supplied "derived:" id is refused by
// the re-validator, which recomputes the id here from the text it canonicalized.
func DerivedParagraphID(sectionPath []string, paragraphOrdinal int, paragraphTextHash string) (string, error) {
	raw, err := canonicalJSON(struct {
		NormalizationVersion string   `json:"normalization_version"`
		ParagraphOrdinal     int      `json:"paragraph_ordinal"`
		ParagraphTextHash    string   `json:"paragraph_text_hash"`
		SectionPath          []string `json:"section_path"`
	}{
		NormalizationVersion: NormalizationVersion,
		ParagraphOrdinal:     paragraphOrdinal,
		ParagraphTextHash:    paragraphTextHash,
		SectionPath:          sectionPath,
	})
	if err != nil {
		return "", err
	}
	return "derived:" + Hash(raw), nil
}

// XlsxAnchorBytes returns the canonical JCS of an XLSX anchor: the sheet identity
// and an A1 cell or cell range. The XLSX anchor carries no text offsets — the A1
// range is the citeable unit and the fragment's canonical text is that range's
// deterministic content (PARSER_CONTRACTS.md §3).
func XlsxAnchorBytes(sheet, cellRange string) ([]byte, error) {
	return canonicalJSON(struct {
		Kind  string `json:"kind"`
		Sheet string `json:"sheet"`
		Range string `json:"range"`
	}{Kind: "XLSX", Sheet: sheet, Range: cellRange})
}
