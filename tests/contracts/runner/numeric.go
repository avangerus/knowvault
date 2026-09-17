package contracts

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

type numericLiteral struct {
	Start  int
	End    int
	Text   string
	Class  string
	Reason string
}

type indexedRune struct {
	Value     rune
	ByteStart int
	ByteEnd   int
}

var currencyCodes = []string{"USD", "EUR", "RUB", "GBP", "CNY", "JPY", "KZT", "UAH"}
var currencyWords = []string{"rub", "rub.", "\u0440\u0443\u0431", "\u0440\u0443\u0431.", "\u0440\u0443\u0431\u043b\u044c", "\u0440\u0443\u0431\u043b\u044f", "\u0440\u0443\u0431\u043b\u0435\u0439", "dollar", "dollars", "euro"}
var monthUnits = []string{
	"\u044f\u043d\u0432\u0430\u0440\u044c", "\u044f\u043d\u0432\u0430\u0440\u044f", "\u0444\u0435\u0432\u0440\u0430\u043b\u044c", "\u0444\u0435\u0432\u0440\u0430\u043b\u044f", "\u043c\u0430\u0440\u0442", "\u043c\u0430\u0440\u0442\u0430", "\u0430\u043f\u0440\u0435\u043b\u044c", "\u0430\u043f\u0440\u0435\u043b\u044f", "\u043c\u0430\u0439", "\u043c\u0430\u044f", "\u0438\u044e\u043d\u044c", "\u0438\u044e\u043d\u044f",
	"\u0438\u044e\u043b\u044c", "\u0438\u044e\u043b\u044f", "\u0430\u0432\u0433\u0443\u0441\u0442", "\u0430\u0432\u0433\u0443\u0441\u0442\u0430", "\u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044c", "\u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f", "\u043e\u043a\u0442\u044f\u0431\u0440\u044c", "\u043e\u043a\u0442\u044f\u0431\u0440\u044f", "\u043d\u043e\u044f\u0431\u0440\u044c", "\u043d\u043e\u044f\u0431\u0440\u044f", "\u0434\u0435\u043a\u0430\u0431\u0440\u044c", "\u0434\u0435\u043a\u0430\u0431\u0440\u044f",
	"jan", "january", "feb", "february", "mar", "march", "apr", "april", "may", "jun", "june", "jul", "july", "aug", "august",
	"sep", "sept", "september", "oct", "october", "nov", "november", "dec", "december",
}
var quantityUnits = []string{
	"%", "‰", "ms", "s", "sec", "sec.", "min", "min.", "h", "hr", "day", "days", "week", "weeks", "month", "months", "year", "years",
	"\u043c\u0441", "\u0441", "\u0441\u0435\u043a", "\u0441\u0435\u043a.", "\u043c\u0438\u043d", "\u043c\u0438\u043d.", "\u0447", "\u0447.", "\u0447\u0430\u0441", "\u0447\u0430\u0441\u0430", "\u0447\u0430\u0441\u043e\u0432", "\u0434\u0435\u043d\u044c", "\u0434\u043d\u044f", "\u0434\u043d\u0435\u0439", "\u043d\u0435\u0434\u0435\u043b\u044f", "\u043d\u0435\u0434\u0435\u043b\u0438", "\u043d\u0435\u0434\u0435\u043b\u044c",
	"\u043c\u0435\u0441\u044f\u0446", "\u043c\u0435\u0441\u044f\u0446\u0430", "\u043c\u0435\u0441\u044f\u0446\u0435\u0432", "\u0433\u043e\u0434", "\u0433\u043e\u0434\u0430", "\u043b\u0435\u0442", "B", "KB", "MB", "GB", "TB", "KiB", "MiB", "GiB", "TiB", "\u0431\u0430\u0439\u0442", "\u0431\u0430\u0439\u0442\u0430", "\u0431\u0430\u0439\u0442\u043e\u0432",
	"\u041a\u0411", "\u041c\u0411", "\u0413\u0411", "\u0422\u0411", "mm", "cm", "m", "km", "mg", "g", "kg", "t", "\u043c\u043c", "\u0441\u043c", "\u043c", "\u043a\u043c", "\u043c\u0433", "\u0433", "\u043a\u0433", "\u0442", "°C", "°F", "\u0448\u0442", "\u0448\u0442.", "pcs",
}

func runeIndex(text string) []indexedRune {
	result := make([]indexedRune, 0, utf8.RuneCountInString(text))
	for byteStart, value := range text {
		result = append(result, indexedRune{Value: value, ByteStart: byteStart, ByteEnd: byteStart + utf8.RuneLen(value)})
	}
	return result
}

func isASCIIPrimaryDigit(value rune) bool { return value >= '0' && value <= '9' }

func isPrimaryBase(value rune) bool {
	return isASCIIPrimaryDigit(value) || value == '_' || unicode.IsLetter(value) || unicode.IsMark(value)
}

func isPrimaryJoin(value rune) bool {
	return strings.ContainsRune(".,:/-+−", value)
}

func isCurrencySymbol(value rune) bool { return strings.ContainsRune("$€£¥₽₴₸", value) }
func isQuantitySuffix(value rune) bool { return strings.ContainsRune("%‰°", value) }
func isJoinSeparator(value rune) bool  { return value == ' ' || value == '\u00a0' || value == '\u202f' }

func equalFoldAny(value string, dictionary []string) bool {
	for _, candidate := range dictionary {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func scanWordToken(runes []indexedRune, start int) int {
	end := start
	for end < len(runes) && (unicode.IsLetter(runes[end].Value) || unicode.IsMark(runes[end].Value)) {
		end++
	}
	if end < len(runes) && runes[end].Value == '.' {
		end++
	}
	return end
}

func scanFourDigitYear(runes []indexedRune, start int) (int, bool) {
	end := start
	for end < len(runes) && isASCIIPrimaryDigit(runes[end].Value) && end-start < 4 {
		end++
	}
	if end-start != 4 || (end < len(runes) && isASCIIPrimaryDigit(runes[end].Value)) {
		return start, false
	}
	return end, true
}

func extendCompoundDateYear(runes []indexedRune, start int, commaAllowed bool) (int, bool) {
	position := start
	if commaAllowed && position < len(runes) && runes[position].Value == ',' {
		position++
	}
	if position >= len(runes) || !isJoinSeparator(runes[position].Value) {
		return start, false
	}
	position++
	return scanFourDigitYear(runes, position)
}

func previousWordToken(text string, runes []indexedRune, primaryStart int) (int, string, bool) {
	if primaryStart < 2 || !isJoinSeparator(runes[primaryStart-1].Value) {
		return 0, "", false
	}
	end := primaryStart - 1
	start := end
	if start > 0 && runes[start-1].Value == '.' {
		start--
	}
	for start > 0 && (unicode.IsLetter(runes[start-1].Value) || unicode.IsMark(runes[start-1].Value)) {
		start--
	}
	if start == end {
		return 0, "", false
	}
	token := text[runes[start].ByteStart:runes[end-1].ByteEnd]
	return start, token, equalFoldAny(token, currencyCodes)
}

func unitClass(token string) string {
	switch {
	case equalFoldAny(token, currencyCodes) || equalFoldAny(token, currencyWords):
		return "CURRENCY"
	case token == "%" || token == "‰":
		return "PERCENT"
	case equalFoldAny(token, monthUnits):
		return "DATE_TIME"
	case equalFoldAny(token, quantityUnits):
		return "VALUE_WITH_UNIT"
	default:
		return ""
	}
}

func classifyPrimary(text string, precedingCurrency bool, followingUnit string) string {
	if precedingCurrency {
		return "CURRENCY"
	}
	if class := unitClass(followingUnit); class != "" {
		return class
	}
	trimmed := strings.TrimLeft(text, "+-−$€£¥₽₴₸")
	if len(trimmed) < len(text) && len(text)-len(trimmed) > 0 {
		prefix := text[:len(text)-len(trimmed)]
		for _, value := range prefix {
			if isCurrencySymbol(value) {
				return "CURRENCY"
			}
		}
	}
	if strings.HasSuffix(text, "%") || strings.HasSuffix(text, "‰") {
		return "PERCENT"
	}
	if len(text) > 0 {
		last, _ := utf8.DecodeLastRuneInString(text)
		if isCurrencySymbol(last) {
			return "CURRENCY"
		}
	}
	textRunes := []rune(text)
	firstDigit, lastDigit := -1, -1
	for index, value := range textRunes {
		if isASCIIPrimaryDigit(value) {
			if firstDigit < 0 {
				firstDigit = index
			}
			lastDigit = index
		}
	}
	if firstDigit > 0 && equalFoldAny(string(textRunes[:firstDigit]), currencyCodes) {
		return "CURRENCY"
	}
	if lastDigit >= 0 && lastDigit+1 < len(textRunes) {
		if class := unitClass(string(textRunes[lastDigit+1:])); class != "" {
			return class
		}
	}
	dateSeparators := strings.Count(text, ".") + strings.Count(text, "-")
	if strings.ContainsAny(text, ":/") || strings.ContainsRune(text, 'T') || dateSeparators >= 2 {
		return "DATE_TIME"
	}
	return "NUMBER"
}

func deriveNumericLiterals(text string) []numericLiteral {
	runes := runeIndex(text)
	result := make([]numericLiteral, 0)
	for index := 0; index < len(runes); {
		value := runes[index].Value
		if unicode.IsDigit(value) && !isASCIIPrimaryDigit(value) {
			result = append(result, numericLiteral{
				Start: runes[index].ByteStart, End: runes[index].ByteEnd,
				Text: text[runes[index].ByteStart:runes[index].ByteEnd], Class: "NUMBER", Reason: "UNSUPPORTED_NUMERAL_SCRIPT",
			})
			index++
			continue
		}
		primaryStart := index
		scanStart := index
		if (value == '+' || value == '-' || value == '−' || isCurrencySymbol(value)) && index+1 < len(runes) && isASCIIPrimaryDigit(runes[index+1].Value) {
			scanStart++
		} else if !isPrimaryBase(value) {
			index++
			continue
		}
		end := scanStart
		hasASCIIDigit := false
		for end < len(runes) {
			if isPrimaryBase(runes[end].Value) {
				hasASCIIDigit = hasASCIIDigit || isASCIIPrimaryDigit(runes[end].Value)
				end++
				continue
			}
			if isPrimaryJoin(runes[end].Value) && end > scanStart && end+1 < len(runes) && isPrimaryBase(runes[end-1].Value) && isPrimaryBase(runes[end+1].Value) {
				end++
				continue
			}
			break
		}
		if !hasASCIIDigit {
			if end <= index {
				index++
			} else {
				index = end
			}
			continue
		}
		if end < len(runes) && (isCurrencySymbol(runes[end].Value) || isQuantitySuffix(runes[end].Value)) {
			end++
		}
		precedingStart, precedingToken, precedingCurrency := previousWordToken(text, runes, primaryStart)
		precedingMonth := unitClass(precedingToken) == "DATE_TIME"
		literalStart := primaryStart
		if precedingCurrency {
			literalStart = precedingStart
		} else if precedingMonth {
			literalStart = precedingStart
		}
		followingUnit := ""
		if end+1 < len(runes) && isJoinSeparator(runes[end].Value) {
			unitEnd := scanWordToken(runes, end+1)
			if unitEnd > end+1 {
				candidate := text[runes[end+1].ByteStart:runes[unitEnd-1].ByteEnd]
				if unitClass(candidate) == "" && strings.HasSuffix(candidate, ".") {
					candidate = strings.TrimSuffix(candidate, ".")
					unitEnd--
				}
				if unitClass(candidate) != "" {
					followingUnit = candidate
					end = unitEnd
				}
			}
		}
		if precedingMonth {
			if compoundEnd, ok := extendCompoundDateYear(runes, end, true); ok {
				end = compoundEnd
			}
		} else if unitClass(followingUnit) == "DATE_TIME" {
			if compoundEnd, ok := extendCompoundDateYear(runes, end, false); ok {
				end = compoundEnd
			}
		}
		byteStart := runes[literalStart].ByteStart
		byteEnd := runes[end-1].ByteEnd
		literalText := text[byteStart:byteEnd]
		class := classifyPrimary(literalText, precedingCurrency, followingUnit)
		if precedingMonth {
			class = "DATE_TIME"
		}
		result = append(result, numericLiteral{Start: byteStart, End: byteEnd, Text: literalText, Class: class})
		index = end
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Start < result[j].Start })
	return result
}

func exactCitationNumbers(text string, citations map[int]string) []any {
	numbers := make([]int, 0)
	for number, excerpt := range citations {
		if strings.Contains(excerpt, text) {
			numbers = append(numbers, number)
		}
	}
	sort.Ints(numbers)
	result := make([]any, len(numbers))
	for index, number := range numbers {
		result[index] = float64(number)
	}
	return result
}

func literalComponents(literal numericLiteral) (string, string) {
	runes := []rune(literal.Text)
	firstDigit, lastDigit := -1, -1
	for index, value := range runes {
		if isASCIIPrimaryDigit(value) {
			if firstDigit < 0 {
				firstDigit = index
			}
			lastDigit = index
		}
	}
	if firstDigit < 0 {
		return literal.Text, ""
	}
	numeric := string(runes[firstDigit : lastDigit+1])
	unit := strings.TrimSpace(string(runes[lastDigit+1:]))
	if unit == "" && firstDigit > 0 {
		unit = strings.TrimSpace(string(runes[:firstDigit]))
	}
	return numeric, unit
}

func unsupportedReason(literal numericLiteral, citations map[int]string) string {
	if literal.Reason != "" {
		return literal.Reason
	}
	if literal.Class == "CURRENCY" || literal.Class == "PERCENT" || literal.Class == "VALUE_WITH_UNIT" {
		number, unit := literalComponents(literal)
		numberSeen, unitSeen := false, false
		for _, excerpt := range citations {
			numberSeen = numberSeen || (number != "" && strings.Contains(excerpt, number))
			unitSeen = unitSeen || (unit != "" && strings.Contains(excerpt, unit))
		}
		if numberSeen && unitSeen {
			return "INCOMPLETE_VALUE_UNIT"
		}
	}
	if literal.Class == "DATE_TIME" {
		pieces := strings.FieldsFunc(literal.Text, func(r rune) bool {
			return unicode.IsSpace(r) || r == ',' || r == '.'
		})
		if len(pieces) >= 2 {
			allSeen := true
			contributing := map[int]bool{}
			for _, piece := range pieces {
				pieceSeen := false
				for number, excerpt := range citations {
					if strings.Contains(excerpt, piece) {
						pieceSeen = true
						contributing[number] = true
					}
				}
				allSeen = allSeen && pieceSeen
			}
			if allSeen && len(contributing) > 1 {
				return "INCOMPLETE_VALUE_UNIT"
			}
		}
	}
	return "NOT_IN_CITED_EXCERPT"
}

func expectedNumericOutput(claimID, validationInputHash, text string, citations map[int]string) map[string]any {
	supported := []any{}
	unsupported := []any{}
	for _, literal := range deriveNumericLiterals(text) {
		citationNumbers := exactCitationNumbers(literal.Text, citations)
		if literal.Reason == "" && len(citationNumbers) > 0 {
			supported = append(supported, map[string]any{
				"claim_start": float64(literal.Start), "claim_end": float64(literal.End), "text": literal.Text, "class": literal.Class, "citation_numbers": citationNumbers,
			})
		} else {
			unsupported = append(unsupported, map[string]any{
				"claim_start": float64(literal.Start), "claim_end": float64(literal.End), "text": literal.Text, "class": literal.Class, "reason": unsupportedReason(literal, citations),
			})
		}
	}
	outcome := "PASSED"
	if len(unsupported) > 0 {
		outcome = "FAILED"
	}
	return map[string]any{
		"schema_version": "1.0", "claim_id": claimID, "validation_input_hash": validationInputHash,
		"material_literals": supported, "unsupported_literals": unsupported, "outcome": outcome,
	}
}

func validateNumericLexerGolden(value map[string]any) error {
	for _, rawVector := range array(value["vectors"]) {
		vector := object(rawVector)
		derived := deriveNumericLiterals(stringValue(vector["text"]))
		actual := make([]any, len(derived))
		for index, literal := range derived {
			actual[index] = map[string]any{
				"claim_start": float64(literal.Start), "claim_end": float64(literal.End), "text": literal.Text, "class": literal.Class,
			}
		}
		expected := array(vector["expected"])
		actualHash, err := hashCanonical(actual)
		if err != nil {
			return err
		}
		expectedHash, err := hashCanonical(expected)
		if err != nil {
			return err
		}
		if actualHash != expectedHash {
			return fail("NUMERIC_LEXER_GOLDEN_MISMATCH", stringValue(vector["id"]))
		}
	}
	return nil
}

func validateNumericOutput(output, context map[string]any) error {
	claim := object(context["claim"])
	verificationInput := object(context["verification_input"])
	if stringValue(output["claim_id"]) != stringValue(claim["claim_id"]) || stringValue(verificationInput["claim_id"]) != stringValue(claim["claim_id"]) || stringValue(verificationInput["kind"]) != stringValue(claim["kind"]) {
		return fail("NUMERIC_VALIDATION_INPUT_MISMATCH")
	}
	claimText := canonicalTextV1(stringValue(claim["text"]))
	expectedClaimHash := sha256String([]byte(claimText))
	if claimText != stringValue(claim["text"]) || stringValue(verificationInput["claim_text_hash"]) != expectedClaimHash {
		return fail("NUMERIC_VALIDATION_INPUT_MISMATCH", expectedClaimHash)
	}
	inputHash, err := hashCanonical(verificationInput)
	if err != nil {
		return err
	}
	if stringValue(output["validation_input_hash"]) != inputHash {
		return fail("NUMERIC_VALIDATION_INPUT_MISMATCH", inputHash)
	}
	citations := map[int]string{}
	for _, rawCitation := range array(context["citations"]) {
		citation := object(rawCitation)
		number := intValue(citation["citation_number"])
		if number < 1 || citations[number] != "" {
			return fail("NUMERIC_CITATION_SET_INVALID")
		}
		citations[number] = canonicalTextV1(stringValue(citation["cited_excerpt"]))
	}
	supportingFacts := make([]map[string]any, 0)
	if stringValue(claim["kind"]) == "INFERENCE" {
		allowed := map[int]bool{}
		directFacts := map[string]map[string]any{}
		for _, rawFact := range array(context["direct_supporting_facts"]) {
			fact := object(rawFact)
			directFacts[stringValue(fact["claim_id"])] = fact
		}
		for _, rawSupport := range array(verificationInput["supporting_claims"]) {
			supportID := stringValue(object(rawSupport)["claim_id"])
			fact := directFacts[supportID]
			if fact == nil || stringValue(fact["kind"]) != "FACT" || stringValue(fact["deterministic_outcome"]) != "PASSED" {
				return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", supportID)
			}
			if stringValue(object(rawSupport)["claim_text_hash"]) != stringValue(fact["claim_text_hash"]) {
				return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", supportID)
			}
			if err := validateDirectSupportingNumericFact(fact); err != nil {
				return err
			}
			supportingFacts = append(supportingFacts, fact)
			for _, rawNumber := range array(fact["citation_numbers"]) {
				allowed[intValue(rawNumber)] = true
			}
		}
		for number := range citations {
			if !allowed[number] {
				delete(citations, number)
			}
		}
	}
	expected := expectedNumericOutput(stringValue(claim["claim_id"]), inputHash, claimText, citations)
	if stringValue(claim["kind"]) == "INFERENCE" {
		for _, rawLiteral := range array(expected["material_literals"]) {
			if !inferenceLiteralSupportedByFact(object(rawLiteral), supportingFacts) {
				return fail("NUMERIC_INFERENCE_LITERAL_NOT_IN_SUPPORTING_FACT", stringValue(object(rawLiteral)["text"]))
			}
		}
	}
	if !canonicalObjectsEqual(output, expected) {
		canonical, _ := canonicalValue(expected)
		return fail("NUMERIC_VALIDATOR_OUTPUT_MISMATCH", string(canonical))
	}
	if stringValue(output["outcome"]) != "PASSED" {
		return fail("NUMERIC_VALIDATION_FAILED")
	}
	return nil
}

func validateDirectSupportingNumericFact(fact map[string]any) error {
	claimText := canonicalTextV1(stringValue(fact["claim_text"]))
	if claimText == "" || claimText != stringValue(fact["claim_text"]) || stringValue(fact["claim_text_hash"]) != sha256String([]byte(claimText)) {
		return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", stringValue(fact["claim_id"]))
	}
	output := object(fact["numeric_output"])
	outputHash, err := hashCanonical(output)
	if err != nil {
		return err
	}
	if stringValue(fact["numeric_output_hash"]) != outputHash || stringValue(output["claim_id"]) != stringValue(fact["claim_id"]) ||
		stringValue(output["outcome"]) != "PASSED" || len(array(output["unsupported_literals"])) != 0 {
		return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", stringValue(fact["claim_id"]))
	}
	allowedCitations := map[int]bool{}
	for _, rawNumber := range array(fact["citation_numbers"]) {
		allowedCitations[intValue(rawNumber)] = true
	}
	for _, rawLiteral := range array(output["material_literals"]) {
		literal := object(rawLiteral)
		start, end := intValue(literal["claim_start"]), intValue(literal["claim_end"])
		if start < 0 || end <= start || end > len(claimText) || claimText[start:end] != stringValue(literal["text"]) {
			return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", stringValue(fact["claim_id"]))
		}
		for _, rawNumber := range array(literal["citation_numbers"]) {
			if !allowedCitations[intValue(rawNumber)] {
				return fail("NUMERIC_INFERENCE_SUPPORT_NOT_PASSED", stringValue(fact["claim_id"]))
			}
		}
	}
	return nil
}

func inferenceLiteralSupportedByFact(inferenceLiteral map[string]any, facts []map[string]any) bool {
	inferenceCitations := map[int]bool{}
	for _, rawNumber := range array(inferenceLiteral["citation_numbers"]) {
		inferenceCitations[intValue(rawNumber)] = true
	}
	for _, fact := range facts {
		for _, rawLiteral := range array(object(fact["numeric_output"])["material_literals"]) {
			factLiteral := object(rawLiteral)
			if stringValue(factLiteral["text"]) != stringValue(inferenceLiteral["text"]) || stringValue(factLiteral["class"]) != stringValue(inferenceLiteral["class"]) {
				continue
			}
			for _, rawNumber := range array(factLiteral["citation_numbers"]) {
				if inferenceCitations[intValue(rawNumber)] {
					return true
				}
			}
		}
	}
	return false
}

func directNumericFact(claimID, claimText string, citationNumbers []any, outcome string) map[string]any {
	output := map[string]any{
		"schema_version": "1.0", "claim_id": claimID,
		"validation_input_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"material_literals":     []any{}, "unsupported_literals": []any{}, "outcome": "PASSED",
	}
	outputHash, _ := hashCanonical(output)
	return map[string]any{
		"claim_id": claimID, "kind": "FACT", "deterministic_outcome": outcome, "citation_numbers": citationNumbers,
		"claim_text": claimText, "claim_text_hash": sha256String([]byte(canonicalTextV1(claimText))),
		"numeric_output": output, "numeric_output_hash": outputHash,
	}
}

func refreshNumericInput(output, context map[string]any) error {
	claim := object(context["claim"])
	verificationInput := object(context["verification_input"])
	verificationInput["claim_text_hash"] = sha256String([]byte(canonicalTextV1(stringValue(claim["text"]))))
	inputHash, err := hashCanonical(verificationInput)
	if err != nil {
		return err
	}
	output["validation_input_hash"] = inputHash
	return nil
}

func applyNumericMutation(output, context map[string]any, mutation string) error {
	claim := object(context["claim"])
	switch mutation {
	case "", "NONE":
		return nil
	case "NUMERIC_LITERAL_MISMATCH":
		claim["text"] = "Budget 1200 USD, readiness 76% at 2026-07-25."
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{
			map[string]any{"claim_start": float64(7), "claim_end": float64(15), "text": "1200 USD", "class": "CURRENCY", "citation_numbers": []any{float64(1)}},
			map[string]any{"claim_start": float64(27), "claim_end": float64(30), "text": "76%", "class": "PERCENT", "citation_numbers": []any{float64(1)}},
			map[string]any{"claim_start": float64(34), "claim_end": float64(44), "text": "2026-07-25", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}},
		}
	case "NUMERIC_UNCITED_LITERAL":
		claim["text"] = "Budget 1200 USD, readiness 50% at 2026-07-25."
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{
			map[string]any{"claim_start": float64(7), "claim_end": float64(15), "text": "1200 USD", "class": "CURRENCY", "citation_numbers": []any{float64(1)}},
			map[string]any{"claim_start": float64(27), "claim_end": float64(30), "text": "50%", "class": "PERCENT", "citation_numbers": []any{float64(1)}},
			map[string]any{"claim_start": float64(34), "claim_end": float64(44), "text": "2026-07-25", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}},
		}
	case "NUMERIC_DERIVED_ARITHMETIC":
		claim["text"] = "Total 30 kg."
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "First part is 10 kg."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "Second part is 20 kg."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(6), "claim_end": float64(11), "text": "30 kg", "class": "VALUE_WITH_UNIT", "citation_numbers": []any{float64(1), float64(2)}}}
	case "NUMERIC_VALIDATION_TOCTOU":
		claim["text"] = "Budget 1200 USD, readiness 76% at 2026-07-25."
	case "NUMERIC_CURRENCY_MISMATCH":
		object(array(context["citations"])[0])["cited_excerpt"] = "Budget 1200 EUR, readiness 75% at 2026-07-25."
	case "NUMERIC_UNIT_SPLIT":
		claim["text"] = "Budget 1200 USD."
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "Budget 1200."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "Currency USD."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(7), "claim_end": float64(15), "text": "1200 USD", "class": "CURRENCY", "citation_numbers": []any{float64(1), float64(2)}}}
	case "NUMERIC_DATE_SPLIT":
		claim["text"] = "Date 2026-07-25."
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "Year 2026, month 07, day 25."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(5), "claim_end": float64(15), "text": "2026-07-25", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}}}
	case "NUMERIC_LONG_SPAN":
		object(array(output["material_literals"])[0])["claim_end"] = float64(len(stringValue(claim["text"])))
		object(array(output["material_literals"])[0])["text"] = stringValue(claim["text"])[7:]
	case "NUMERIC_NON_ASCII_ND":
		claim["text"] = "Value ١٢."
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "Value ١٢."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_CLASS_TAMPER":
		object(array(output["material_literals"])[0])["class"] = "NUMBER"
	case "NUMERIC_COMPOUND_DATE_SPLIT_RU":
		claim["text"] = "\u0421\u0440\u043e\u043a \u2014 15 \u0438\u044e\u043b\u044f 2026."
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "\u0421\u0440\u043e\u043a \u2014 15 \u0438\u044e\u043b\u044f."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "\u0413\u043e\u0434 \u2014 2026."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(11), "claim_end": float64(27), "text": "15 \u0438\u044e\u043b\u044f 2026", "class": "DATE_TIME", "citation_numbers": []any{float64(1), float64(2)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_COMPOUND_DATE_SPLIT_REASON":
		claim["text"] = "\u0421\u0440\u043e\u043a \u2014 15 \u0438\u044e\u043b\u044f 2026."
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "\u0421\u0440\u043e\u043a \u2014 15 \u0438\u044e\u043b\u044f."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "\u0413\u043e\u0434 \u2014 2026."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{}
		output["unsupported_literals"] = []any{map[string]any{
			"claim_start": float64(13), "claim_end": float64(29), "text": "15 \u0438\u044e\u043b\u044f 2026", "class": "DATE_TIME", "reason": "INCOMPLETE_VALUE_UNIT",
		}}
		output["outcome"] = "FAILED"
	case "NUMERIC_COMPOUND_DATE_SPLIT_EN":
		claim["text"] = "Due July 15, 2026."
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "Due July 15."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "Year 2026."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(4), "claim_end": float64(17), "text": "July 15, 2026", "class": "DATE_TIME", "citation_numbers": []any{float64(1), float64(2)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_COMPOUND_LOCALE_MISMATCH":
		claim["text"] = "Due July 15, 2026."
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "\u0421\u0440\u043e\u043a \u2014 15 \u0438\u044e\u043b\u044f 2026."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(4), "claim_end": float64(17), "text": "July 15, 2026", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_COMPOUND_SEPARATOR_MIX":
		claim["text"] = "Due July 15,  2026."
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "Due July 15,  2026."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(4), "claim_end": float64(19), "text": "July 15,  2026", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_INFERENCE_UNRELATED_CITATION":
		claim["kind"] = "INFERENCE"
		claim["text"] = "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."
		verification := object(context["verification_input"])
		verification["kind"] = "INFERENCE"
		fact := directNumericFact("C10", "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0444\u0430\u043a\u0442 \u0431\u0435\u0437 \u0434\u0430\u0442\u044b.", []any{float64(1)}, "PASSED")
		verification["supporting_claims"] = []any{map[string]any{"claim_id": "C10", "claim_text_hash": fact["claim_text_hash"]}}
		context["direct_supporting_facts"] = []any{fact}
		context["citations"] = []any{
			map[string]any{"citation_number": float64(1), "cited_excerpt": "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0444\u0430\u043a\u0442 \u0431\u0435\u0437 \u0434\u0430\u0442\u044b."},
			map[string]any{"citation_number": float64(2), "cited_excerpt": "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."},
		}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(25), "claim_end": float64(41), "text": "15 \u0438\u044e\u043b\u044f 2026", "class": "DATE_TIME", "citation_numbers": []any{float64(2)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	case "NUMERIC_INFERENCE_FAILED_FACT":
		claim["kind"] = "INFERENCE"
		claim["text"] = "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."
		verification := object(context["verification_input"])
		verification["kind"] = "INFERENCE"
		fact := directNumericFact("C10", "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0444\u0430\u043a\u0442 \u0431\u0435\u0437 \u0434\u0430\u0442\u044b.", []any{float64(1)}, "FAILED")
		verification["supporting_claims"] = []any{map[string]any{"claim_id": "C10", "claim_text_hash": fact["claim_text_hash"]}}
		context["direct_supporting_facts"] = []any{fact}
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
	case "NUMERIC_INFERENCE_CITATION_ONLY_LITERAL":
		claim["kind"] = "INFERENCE"
		claim["text"] = "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."
		verification := object(context["verification_input"])
		verification["kind"] = "INFERENCE"
		fact := directNumericFact("C10", "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0439 \u0444\u0430\u043a\u0442 \u0431\u0435\u0437 \u0434\u0430\u0442\u044b.", []any{float64(1)}, "PASSED")
		verification["supporting_claims"] = []any{map[string]any{"claim_id": "C10", "claim_text_hash": fact["claim_text_hash"]}}
		context["direct_supporting_facts"] = []any{fact}
		context["citations"] = []any{map[string]any{"citation_number": float64(1), "cited_excerpt": "\u0421\u0440\u043e\u043a \u0441\u0434\u0432\u0438\u043d\u0443\u0442 \u043d\u0430 15 \u0438\u044e\u043b\u044f 2026."}}
		if err := refreshNumericInput(output, context); err != nil {
			return err
		}
		output["material_literals"] = []any{map[string]any{"claim_start": float64(29), "claim_end": float64(45), "text": "15 \u0438\u044e\u043b\u044f 2026", "class": "DATE_TIME", "citation_numbers": []any{float64(1)}}}
		output["unsupported_literals"] = []any{}
		output["outcome"] = "PASSED"
	}
	return nil
}
