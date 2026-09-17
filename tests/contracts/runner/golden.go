package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

var spreadsheetCellPattern = regexp.MustCompile(`^([A-Z]+)([1-9][0-9]*)$`)

func validateSourceAnchor(anchor map[string]any, canonicalText, exactExcerpt []byte) error {
	kind := stringValue(anchor["kind"])
	switch kind {
	case "PDF", "DOCX", "PPTX", "EMAIL", "HTML":
		if stringValue(anchor["offset_unit"]) != "UTF8_BYTE" ||
			stringValue(anchor["range_semantics"]) != "START_INCLUSIVE_END_EXCLUSIVE" ||
			stringValue(anchor["normalization_version"]) != "text-v1" {
			return fail("ANCHOR_OFFSET_CONTRACT_INVALID")
		}
		start, end := intValue(anchor["text_start"]), intValue(anchor["text_end"])
		if err := validateUTF8Range(canonicalText, start, end); err != nil {
			return err
		}
		if exactExcerpt != nil && !bytes.Equal(canonicalText[start:end], exactExcerpt) {
			return fail("CITED_EXCERPT_SLICE_MISMATCH")
		}
		if kind == "HTML" {
			canonicalURL, err := canonicalWebURL(stringValue(anchor["canonical_url"]))
			if err != nil || canonicalURL != stringValue(anchor["canonical_url"]) {
				return fail("ANCHOR_URL_NOT_CANONICAL")
			}
		}
		if kind == "PDF" {
			for _, rawBox := range array(anchor["bounding_boxes"]) {
				box := object(rawBox)
				if floatValue(box["x"]) < 0 || floatValue(box["y"]) < 0 || floatValue(box["width"]) <= 0 || floatValue(box["height"]) <= 0 {
					return fail("ANCHOR_PDF_BOX_INVALID")
				}
			}
		}
	case "TEXT", "GIT":
		start, end := intValue(anchor["line_start"]), intValue(anchor["line_end"])
		lines := strings.Split(strings.TrimSuffix(string(canonicalText), "\n"), "\n")
		if start < 1 || end < start || end > len(lines) {
			return fail("ANCHOR_RANGE_INVALID")
		}
		if kind == "GIT" {
			if _, err := canonicalSourcePath(stringValue(anchor["path"])); err != nil {
				return err
			}
		}
		if exactExcerpt != nil && strings.Join(lines[start-1:end], "\n") != string(exactExcerpt) {
			return fail("CITED_EXCERPT_SLICE_MISMATCH")
		}
	case "XLSX":
		parts := strings.Split(stringValue(anchor["range"]), ":")
		startColumn, startRow, ok := parseSpreadsheetCell(parts[0])
		if !ok {
			return fail("ANCHOR_XLSX_RANGE_INVALID")
		}
		endColumn, endRow := startColumn, startRow
		if len(parts) == 2 {
			var endOK bool
			endColumn, endRow, endOK = parseSpreadsheetCell(parts[1])
			if !endOK {
				return fail("ANCHOR_XLSX_RANGE_INVALID")
			}
		} else if len(parts) != 1 {
			return fail("ANCHOR_XLSX_RANGE_INVALID")
		}
		if endColumn < startColumn || endRow < startRow {
			return fail("ANCHOR_XLSX_RANGE_REVERSED")
		}
		if exactExcerpt != nil && !bytes.Equal(canonicalText, exactExcerpt) {
			return fail("CITED_EXCERPT_SLICE_MISMATCH")
		}
	case "OCR":
		if stringValue(anchor["coordinate_unit"]) != "NORMALIZED_0_1" || stringValue(anchor["coordinate_origin"]) != "TOP_LEFT" || len(array(anchor["bounding_boxes"])) == 0 {
			return fail("ANCHOR_OCR_BOX_INVALID")
		}
		start, end := intValue(anchor["token_start_ordinal"]), intValue(anchor["token_end_ordinal"])
		if stringValue(anchor["range_semantics"]) != "START_INCLUSIVE_END_EXCLUSIVE" || end <= start {
			return fail("ANCHOR_OCR_TOKEN_RANGE_INVALID")
		}
		if len(array(anchor["bounding_boxes"])) != end-start {
			return fail("ANCHOR_OCR_TOKEN_BOX_COUNT_MISMATCH")
		}
		for _, rawBox := range array(anchor["bounding_boxes"]) {
			box := object(rawBox)
			x, y := floatValue(box["x"]), floatValue(box["y"])
			width, height := floatValue(box["width"]), floatValue(box["height"])
			if x < 0 || y < 0 || width <= 0 || height <= 0 || x+width > 1 || y+height > 1 {
				return fail("ANCHOR_OCR_BOX_OUT_OF_BOUNDS")
			}
		}
		if exactExcerpt != nil && !bytes.Equal(canonicalText, exactExcerpt) {
			return fail("CITED_EXCERPT_SLICE_MISMATCH")
		}
	default:
		return fail("ANCHOR_KIND_UNKNOWN")
	}
	return nil
}

func validateOCRAnchorTokens(anchor map[string]any, tokens []any, expectedText []byte) error {
	if err := validateSourceAnchor(anchor, expectedText, expectedText); err != nil {
		return err
	}
	start, end := intValue(anchor["token_start_ordinal"]), intValue(anchor["token_end_ordinal"])
	if start < 0 || end > len(tokens) {
		return fail("ANCHOR_OCR_TOKEN_RANGE_INVALID")
	}
	boxes := array(anchor["bounding_boxes"])
	var builder strings.Builder
	for ordinal := start; ordinal < end; ordinal++ {
		token := object(tokens[ordinal])
		if intValue(token["page"]) != intValue(anchor["page"]) || intValue(token["ordinal"]) != ordinal {
			return fail("ANCHOR_OCR_TOKEN_SEQUENCE_INVALID")
		}
		text := stringValue(token["canonical_token_text"])
		if text != canonicalTextV1(text) {
			return fail("ANCHOR_OCR_TOKEN_TEXT_INVALID")
		}
		if !canonicalObjectsEqual(object(boxes[ordinal-start]), object(token["bounding_box"])) {
			return fail("ANCHOR_OCR_TOKEN_BOX_MISMATCH")
		}
		builder.WriteString(text)
		if ordinal < end-1 {
			switch stringValue(token["join_after"]) {
			case "NONE":
			case "SPACE":
				builder.WriteByte(' ')
			case "LINE_BREAK":
				builder.WriteByte('\n')
			default:
				return fail("ANCHOR_OCR_JOIN_INVALID")
			}
		}
	}
	if builder.String() != string(expectedText) {
		return fail("ANCHOR_OCR_TOKEN_TEXT_MISMATCH")
	}
	return nil
}

func applyOCRAnchorMutation(value map[string]any, mutation string) {
	anchor := object(value["anchor"])
	tokens := array(value["tokens"])
	switch mutation {
	case "", "NONE":
	case "OCR_BOX_TOKEN_COUNT":
		anchor["bounding_boxes"] = array(anchor["bounding_boxes"])[:2]
	case "OCR_REVERSED_RANGE":
		anchor["token_start_ordinal"] = float64(2)
		anchor["token_end_ordinal"] = float64(1)
	case "OCR_GEOMETRY_ONLY":
		value["tokens"] = []any{}
	case "OCR_TOKEN_GAP":
		object(tokens[2])["ordinal"] = float64(3)
	case "OCR_TOKEN_TEXT_MISMATCH":
		value["expected_text"] = "Alpha \u0434\u0440\u0443\u0433\u043e\u0439\n\u0433\u043e\u0442\u043e\u0432"
	case "OCR_TOKEN_BOX_MISMATCH":
		object(object(tokens[1])["bounding_box"])["x"] = float64(0.7)
	}
}

func validateOCRAnchorFixture(value map[string]any) error {
	if len(array(value["tokens"])) == 0 {
		return fail("ANCHOR_OCR_TOKEN_SET_MISSING")
	}
	return validateOCRAnchorTokens(object(value["anchor"]), array(value["tokens"]), []byte(stringValue(value["expected_text"])))
}

func parseSpreadsheetCell(cell string) (int, int, bool) {
	matches := spreadsheetCellPattern.FindStringSubmatch(cell)
	if len(matches) != 3 {
		return 0, 0, false
	}
	column := 0
	for _, r := range matches[1] {
		column = column*26 + int(r-'A'+1)
	}
	row, err := strconv.Atoi(matches[2])
	return column, row, err == nil
}

func validateAnchorFixture(anchor map[string]any, canonicalText []byte) error {
	if unit, exists := anchor["offset_unit"]; exists && stringValue(unit) != "UTF8_BYTE" {
		return fail("ANCHOR_OFFSET_UNIT_INVALID")
	}
	return validateSourceAnchor(anchor, canonicalText, nil)
}

func validateAnchorCollection(value map[string]any) error {
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = "0123456789"
	}
	canonicalText := []byte(strings.Join(lines, "\n"))
	for _, rawVector := range array(value["vectors"]) {
		vector := object(rawVector)
		anchor := object(vector["anchor"])
		if err := validateSourceAnchor(anchor, canonicalText, nil); err != nil {
			return err
		}
		if stringValue(anchor["kind"]) == "DOCX" && strings.HasPrefix(stringValue(anchor["paragraph_id"]), "derived:sha256:") {
			derivation := object(vector["paragraph_derivation"])
			paragraphText := canonicalTextV1(stringValue(derivation["paragraph_text"]))
			textHash := sha256String([]byte(paragraphText))
			if textHash != stringValue(derivation["paragraph_text_hash"]) {
				return fail("DOCX_PARAGRAPH_TEXT_HASH_MISMATCH")
			}
			input := map[string]any{
				"normalization_version": derivation["normalization_version"],
				"paragraph_ordinal":     derivation["paragraph_ordinal"],
				"paragraph_text_hash":   derivation["paragraph_text_hash"],
				"section_path":          derivation["section_path"],
			}
			canonical, err := canonicalValue(input)
			if err != nil {
				return err
			}
			if string(canonical) != stringValue(derivation["derivation_jcs"]) {
				return fail("DOCX_PARAGRAPH_DERIVATION_JCS_MISMATCH")
			}
			if stringValue(anchor["paragraph_id"]) != "derived:"+sha256String(canonical) {
				return fail("DOCX_PARAGRAPH_ID_MISMATCH")
			}
			if !deepStringArrayEqual(array(anchor["section_path"]), array(derivation["section_path"])) {
				return fail("DOCX_SECTION_PATH_MISMATCH")
			}
		}
	}
	return nil
}

func validateAnchorCompatibilityCollection(value map[string]any) error {
	for _, rawVector := range array(value["vectors"]) {
		vector := object(rawVector)
		anchor := object(vector["anchor"])
		canonicalText := []byte(stringValue(vector["canonical_text"]))
		excerpt := []byte(stringValue(vector["excerpt"]))
		if err := validateSourceAnchor(anchor, canonicalText, excerpt); err != nil {
			return fail("ANCHOR_COMPATIBILITY_VECTOR_INVALID", stringValue(vector["id"])+":"+errorCode(err))
		}
		if err := validateAnchorSourceCompatibility(object(vector["extraction"]), anchor); err != nil {
			return err
		}
	}
	return nil
}

func deepStringArrayEqual(left, right []any) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if stringValue(left[i]) != stringValue(right[i]) {
			return false
		}
	}
	return true
}

func validateRendererGolden(value map[string]any) error {
	input := object(value["input"])
	expected := object(value["expected"])
	markdown, spans, err := renderAnswer(array(input["claims"]), array(input["sections"]))
	if err != nil {
		return err
	}
	if string(markdown) != stringValue(expected["canonical_markdown"]) {
		return fail("GOLDEN_RENDERER_MARKDOWN_MISMATCH")
	}
	if len(markdown) != intValue(expected["utf8_length"]) || hex.EncodeToString(markdown) != stringValue(expected["utf8_hex"]) {
		return fail("GOLDEN_RENDERER_UTF8_MISMATCH")
	}
	if sha256String(markdown) != stringValue(expected["answer_hash"]) {
		return fail("GOLDEN_RENDERER_HASH_MISMATCH")
	}
	expectedSpans := array(expected["claim_spans"])
	if len(spans) != len(expectedSpans) {
		return fail("GOLDEN_RENDERER_SPAN_MISMATCH")
	}
	for i, span := range spans {
		declared := object(expectedSpans[i])
		if span.ClaimID != stringValue(declared["claim_id"]) || span.Start != intValue(declared["start"]) || span.End != intValue(declared["end"]) || span.Escaped != stringValue(declared["escaped_text"]) {
			return fail("GOLDEN_RENDERER_SPAN_MISMATCH")
		}
	}
	for _, rawForbidden := range array(expected["must_not_contain"]) {
		if bytes.Contains(markdown, []byte(stringValue(rawForbidden))) {
			return fail("GOLDEN_RENDERER_UNSAFE_OUTPUT")
		}
	}
	return nil
}

func validateQuestionJCSGolden(value map[string]any) error {
	canonical, err := canonicalValue(value["input"])
	if err != nil {
		return err
	}
	if string(canonical) != stringValue(value["canonical_jcs"]) || hex.EncodeToString(canonical) != stringValue(value["canonical_utf8_hex"]) || sha256String(canonical) != stringValue(value["canonical_request_hash"]) {
		return fail("GOLDEN_QUESTION_JCS_MISMATCH")
	}
	return nil
}

func validateSignatureEnvelopeGolden(value map[string]any) error {
	publicKey, err := base64.StdEncoding.DecodeString(stringValue(value["public_key_base64"]))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fail("GOLDEN_SIGNATURE_PUBLIC_KEY_INVALID")
	}
	manifest := object(value["manifest"])
	manifestJCS, err := canonicalValue(manifest["expected_signing_object"])
	if err != nil {
		return err
	}
	if string(manifestJCS) != stringValue(manifest["expected_signing_jcs"]) {
		return fail("GOLDEN_MANIFEST_ENVELOPE_MISMATCH")
	}
	manifestSignature, err := base64.StdEncoding.DecodeString(stringValue(manifest["signature_base64"]))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), manifestJCS, manifestSignature) {
		return fail("GOLDEN_MANIFEST_SIGNATURE_INVALID")
	}
	connector := object(value["connector"])
	connectorJCS, err := canonicalValue(connector["expected_signing_object"])
	if err != nil {
		return err
	}
	if string(connectorJCS) != stringValue(connector["expected_signing_jcs"]) {
		return fail("GOLDEN_CONNECTOR_ENVELOPE_MISMATCH")
	}
	connectorSignature, err := base64.StdEncoding.DecodeString(stringValue(connector["signature_base64"]))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), connectorJCS, connectorSignature) {
		return fail("GOLDEN_CONNECTOR_SIGNATURE_INVALID")
	}
	return nil
}
