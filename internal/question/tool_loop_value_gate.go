package question

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Value gate: the defect this file closes is the run where
// knowvault_source_sql returned expiration_date 2040-12-31 and the answer
// told the user "31.12.2024", citing that very result. ClaimEvidence v1 (see
// the comment above ToolLoopRecord) binds a claim to the tool result it
// cites but never checks that the claim's own words agree with that result's
// cells -- it proves the claim looked at the result, not that it read it
// correctly. This file adds that check for the one class of value a claim can
// misreport in a way a machine can verify without understanding the
// question: a calendar date, or a number of four digits or more. A document-
// only claim (no live_reads) is never in scope here; a value that also
// appears literally in the user's own question, or that is simply today's
// date, is never a violation.

// valueGateMinNumberDigits is the smallest digit count a plain number needs
// before this gate checks it; a two- or three-digit figure is ordinary prose
// ("3 источника", "12 строк") and is never flagged.
const valueGateMinNumberDigits = 4

// submitAnswerValueMismatchCode is the closed rejection code for a claim
// whose own text states a calendar date or a large number that its cited
// live result never produced.
const submitAnswerValueMismatchCode = "SUBMIT_ANSWER_VALUE_MISMATCH"

// valueGateDottedDate matches day.month.year, e.g. "31.12.2024".
var valueGateDottedDate = regexp.MustCompile(`\b([0-3]?\d)\.(0?[1-9]|1[0-2])\.(\d{4})\b`)

// valueGateISODate matches year-month-day, e.g. "2024-12-31".
var valueGateISODate = regexp.MustCompile(`\b(\d{4})-(0[1-9]|1[0-2])-([0-3]\d)\b`)

// valueGateWrittenDayMonthYear matches a day, a month name (Russian or
// English) and a year, e.g. "31 декабря 2040" or "31 December 2040". A
// trailing Russian "года"/"году" is not part of the match; it is left in the
// text and never consumed.
var valueGateWrittenDayMonthYear = regexp.MustCompile(`(?i)\b([0-3]?\d)\s+([\p{L}]+)\s+(\d{4})\b`)

// valueGateWrittenMonthDayYear matches the English month-first form, e.g.
// "December 31, 2040".
var valueGateWrittenMonthDayYear = regexp.MustCompile(`(?i)\b([\p{L}]+)\s+([0-3]?\d),?\s+(\d{4})\b`)

// valueGateGroupedNumber matches a number written with thousands separators:
// an ordinary space, a comma (the English convention) or a non-breaking
// space between groups of three digits.
var valueGateGroupedNumber = regexp.MustCompile("\\b\\d{1,3}(?:[ , ]\\d{3})+\\b")

// valueGatePlainNumber matches a run of digits with no separator at all.
var valueGatePlainNumber = regexp.MustCompile(`\b\d+\b`)

// valueGateDate is a normalized calendar date: year, month and day only,
// never a time of day or a time zone.
type valueGateDate struct {
	year, month, day int
}

func (d valueGateDate) key() string {
	return time.Date(d.year, time.Month(d.month), d.day, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
}

// valueGateNormalizeDate rejects a calendar date that does not round-trip,
// such as 30 February, instead of silently rolling it over into March.
func valueGateNormalizeDate(year, month, day int) (valueGateDate, bool) {
	if year < 1000 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 {
		return valueGateDate{}, false
	}
	candidate := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if candidate.Year() != year || int(candidate.Month()) != month || candidate.Day() != day {
		return valueGateDate{}, false
	}
	return valueGateDate{year: year, month: month, day: day}, true
}

// valueGateDateMatch is one calendar date found in a piece of text, together
// with its byte span (so a number extractor never re-flags the same digits)
// and the exact substring the model wrote (for the repair hint).
type valueGateDateMatch struct {
	date valueGateDate
	span [2]int
	text string
}

func valueGateAtoi(value string) int {
	parsed, _ := strconv.Atoi(value)
	return parsed
}

// valueGateExtractDates finds every calendar date in text, in every format
// this gate recognizes: ДД.ММ.ГГГГ, ГГГГ-ММ-ДД, a written day-month-year (Russian
// or English month name, with or without a trailing "года"/"году") and the
// English month-day, year form.
func valueGateExtractDates(text string) []valueGateDateMatch {
	matches := make([]valueGateDateMatch, 0)
	for _, span := range valueGateDottedDate.FindAllStringSubmatchIndex(text, -1) {
		if date, ok := valueGateNormalizeDate(valueGateAtoi(text[span[6]:span[7]]), valueGateAtoi(text[span[4]:span[5]]), valueGateAtoi(text[span[2]:span[3]])); ok {
			matches = append(matches, valueGateDateMatch{date: date, span: [2]int{span[0], span[1]}, text: text[span[0]:span[1]]})
		}
	}
	for _, span := range valueGateISODate.FindAllStringSubmatchIndex(text, -1) {
		if date, ok := valueGateNormalizeDate(valueGateAtoi(text[span[2]:span[3]]), valueGateAtoi(text[span[4]:span[5]]), valueGateAtoi(text[span[6]:span[7]])); ok {
			matches = append(matches, valueGateDateMatch{date: date, span: [2]int{span[0], span[1]}, text: text[span[0]:span[1]]})
		}
	}
	for _, span := range valueGateWrittenDayMonthYear.FindAllStringSubmatchIndex(text, -1) {
		month := comparisonMonth(strings.ToLower(text[span[4]:span[5]]))
		if month == 0 {
			continue
		}
		if date, ok := valueGateNormalizeDate(valueGateAtoi(text[span[6]:span[7]]), month, valueGateAtoi(text[span[2]:span[3]])); ok {
			matches = append(matches, valueGateDateMatch{date: date, span: [2]int{span[0], span[1]}, text: text[span[0]:span[1]]})
		}
	}
	for _, span := range valueGateWrittenMonthDayYear.FindAllStringSubmatchIndex(text, -1) {
		month := comparisonMonth(strings.ToLower(text[span[2]:span[3]]))
		if month == 0 {
			continue
		}
		if date, ok := valueGateNormalizeDate(valueGateAtoi(text[span[6]:span[7]]), month, valueGateAtoi(text[span[4]:span[5]])); ok {
			matches = append(matches, valueGateDateMatch{date: date, span: [2]int{span[0], span[1]}, text: text[span[0]:span[1]]})
		}
	}
	return matches
}

// valueGateNumberMatch is one number of four or more digits found in a piece
// of text, together with the exact substring the model wrote.
type valueGateNumberMatch struct {
	value float64
	text  string
}

func valueGateDigitCount(value string) int {
	count := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			count++
		}
	}
	return count
}

func valueGateParseNumberLiteral(raw string) (float64, bool) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ',', ' ':
			return -1
		default:
			return r
		}
	}, raw)
	value, err := strconv.ParseFloat(cleaned, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func valueGateSpansOverlap(a, b [2]int) bool {
	return a[0] < b[1] && a[1] > b[0]
}

// valueGateExtractNumbers finds every number of four or more digits in text
// that is not part of a date already matched by dateSpans (so the year in a
// date is never re-flagged as a bare number), grouped (space, comma or
// non-breaking-space thousands separators) or plain.
func valueGateExtractNumbers(text string, dateSpans [][2]int) []valueGateNumberMatch {
	matches := make([]valueGateNumberMatch, 0)
	claimed := append([][2]int(nil), dateSpans...)
	overlaps := func(span [2]int) bool {
		for _, other := range claimed {
			if valueGateSpansOverlap(span, other) {
				return true
			}
		}
		return false
	}
	for _, span := range valueGateGroupedNumber.FindAllStringIndex(text, -1) {
		point := [2]int{span[0], span[1]}
		skip := overlaps(point)
		claimed = append(claimed, point)
		if skip {
			continue
		}
		raw := text[span[0]:span[1]]
		if value, ok := valueGateParseNumberLiteral(raw); ok {
			matches = append(matches, valueGateNumberMatch{value: value, text: raw})
		}
	}
	for _, span := range valueGatePlainNumber.FindAllStringIndex(text, -1) {
		point := [2]int{span[0], span[1]}
		if overlaps(point) {
			continue
		}
		raw := text[span[0]:span[1]]
		if valueGateDigitCount(raw) < valueGateMinNumberDigits {
			continue
		}
		if value, ok := valueGateParseNumberLiteral(raw); ok {
			matches = append(matches, valueGateNumberMatch{value: value, text: raw})
		}
	}
	return matches
}

// valueGateCellDateLayouts are the layouts a live-data or SQL result cell's
// raw postgres text representation can take: a bare date and a timestamp,
// with or without a time zone. The date is read from the layout's own
// year/month/day fields, never converted to another time zone first, so a
// timestamp's calendar date is compared exactly as printed.
var valueGateCellDateLayouts = []string{
	"2006-01-02",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999Z07:00",
}

// valueGateParseCellDate reads the calendar date out of a raw result cell,
// whether it is a bare date or a timestamp, or reports that the cell is not a
// date at all.
func valueGateParseCellDate(cell string) (valueGateDate, bool) {
	trimmed := strings.TrimSpace(cell)
	if trimmed == "" {
		return valueGateDate{}, false
	}
	for _, layout := range valueGateCellDateLayouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			year, month, day := parsed.Date()
			return valueGateDate{year: year, month: int(month), day: day}, true
		}
	}
	return valueGateDate{}, false
}

// valueGateParseCellNumber reads a plain numeric value out of a raw result
// cell, or reports that the cell is not a plain number (a date, a label, an
// identifier).
func valueGateParseCellNumber(cell string) (float64, bool) {
	trimmed := strings.TrimSpace(cell)
	if trimmed == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// valueGateCellSets collects every calendar date and every plain number
// found in the cells of the given executions' result rows.
func valueGateCellSets(executions []liveDataExecution) (dates map[string]struct{}, numbers map[float64]struct{}) {
	dates = map[string]struct{}{}
	numbers = map[float64]struct{}{}
	for _, execution := range executions {
		for _, row := range execution.projection.Rows {
			for _, cell := range row {
				if cell == nil {
					continue
				}
				if date, ok := valueGateParseCellDate(*cell); ok {
					dates[date.key()] = struct{}{}
				}
				if number, ok := valueGateParseCellNumber(*cell); ok {
					numbers[number] = struct{}{}
				}
			}
		}
	}
	return dates, numbers
}

// toolLoopValueGateExemptDates returns the calendar dates that this gate
// never flags for a run: the day the run started (the "current date" a model
// may mention descriptively) and every date the user's own question spelled
// out, as "YYYY-MM-DD" keys.
func toolLoopValueGateExemptDates(questionText string, requestedAt time.Time) map[string]struct{} {
	exempt := map[string]struct{}{requestedAt.UTC().Format("2006-01-02"): {}}
	for _, match := range valueGateExtractDates(questionText) {
		exempt[match.date.key()] = struct{}{}
	}
	return exempt
}

// toolLoopValueGateViolation returns the first calendar date or 4+ digit
// number in claimText that is not exempt and not found among the cell values
// its citer's live results actually returned, together with its kind ("date"
// or "number"), or two empty strings when the claim's values all check out.
func toolLoopValueGateViolation(claimText string, exemptDates map[string]struct{}, cellDates map[string]struct{}, cellNumbers map[float64]struct{}) (value, kind string) {
	dateMatches := valueGateExtractDates(claimText)
	dateSpans := make([][2]int, 0, len(dateMatches))
	for _, match := range dateMatches {
		dateSpans = append(dateSpans, match.span)
		key := match.date.key()
		if _, ok := exemptDates[key]; ok {
			continue
		}
		if _, ok := cellDates[key]; !ok {
			return match.text, "date"
		}
	}
	for _, match := range valueGateExtractNumbers(claimText, dateSpans) {
		if _, ok := cellNumbers[match.value]; !ok {
			return match.text, "number"
		}
	}
	return "", ""
}

// toolLoopClaimValueGateViolation is toolLoopValueGateViolation scoped to one
// submitted claim: it resolves the claim's own live_reads to the run's actual
// tool executions (the same cryptographic binding the citation-binding pass
// uses) and checks the claim's text against exactly those results' cells. A
// claim with no live_reads (a document-only claim) or whose live_reads do not
// bind is never checked here -- the latter is already dropped or unconfirmed
// by the existing binding check regardless of this gate.
func toolLoopClaimValueGateViolation(claim toolClaim, questionRunID string, executions []liveDataExecution, exemptDates map[string]struct{}) (value, kind string) {
	if len(claim.LiveReads) == 0 {
		return "", ""
	}
	_, ordinals, bound := bindToolLiveReadReferences(questionRunID, claim.LiveReads, executions)
	if !bound || len(ordinals) == 0 {
		return "", ""
	}
	cited := make([]liveDataExecution, 0, len(ordinals))
	for _, ordinal := range ordinals {
		cited = append(cited, executions[ordinal-1])
	}
	cellDates, cellNumbers := valueGateCellSets(cited)
	return toolLoopValueGateViolation(claim.Text, exemptDates, cellDates, cellNumbers)
}

// toolLoopValueGateRepairInstruction tells the model, in the question's own
// language, which value its rejected submission stated that the cited result
// never produced. It asks for the value from the result or a SQL-computed
// figure, never a sum the model adds up itself from result rows.
func toolLoopValueGateRepairInstruction(language, value, kind string) string {
	kindWord := localizedText(language, "число", "number")
	if kind == "date" {
		kindWord = localizedText(language, "дата", "date")
	}
	return localizedText(language,
		"В утверждении есть "+kindWord+" «"+value+"», которого нет среди значений процитированного результата запроса. Возьмите значение из результата или, если это сумма/подсчёт по строкам, вычислите его отдельным SQL-запросом (не складывайте строки результата вручную и не выдумывайте значение). Перепишите текст утверждений, сохранив те же факты, ссылки и live_reads.",
		"The claim states a "+kindWord+" \""+value+"\" that is not among the values of its cited query result. Use the value from the result, or, if it is a sum or count over rows, compute it with a separate SQL statement (do not add up result rows by hand and do not invent the value). Rewrite the claim wording only, keeping the same facts, citations and live_reads.")
}
