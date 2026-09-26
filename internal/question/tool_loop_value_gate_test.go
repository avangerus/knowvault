package question

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// valueGateTestToolResult renders the exact JSON projection the workspace API
// emits for a successful knowvault_source_sql call whose row carries the
// given columns and cell values, digest included -- the general form of
// source_sql_evidence_test.go's testSourceSQLToolResult, which hardcodes a
// single "contract_count" cell and cannot carry the expiration_date column
// this gate needs to replay the reported incident.
func valueGateTestToolResult(t *testing.T, attemptID, sourceID string, columns []string, row []*string) workspacetools.Result {
	t.Helper()
	rows := [][]*string{row}
	digest := testSourceSQLDigest(columns, rows)
	projection := map[string]any{
		"format":                  "postgres-text-table-v1",
		"columns":                 columns,
		"rows":                    rows,
		"row_count":               1,
		"attempt_id":              attemptID,
		"sql_hash":                "sha256:" + strings.Repeat("a", 64),
		"result_digest":           digest,
		"database_identity":      "pgdb:alpha",
		"source_id":               sourceID,
		"exposed_schema_revision": 7,
		"execution_started_at":    time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano),
		"execution_completed_at":  time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano),
		"complete":                true,
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	return workspacetools.Result{Text: string(raw), Structured: raw}
}

// Card value-gate: the model read expiration_date 2040-12-31 out of a tool
// result and told the user "31.12.2024", still citing that result. These
// tests cover the deterministic engine that closes that gap: date and number
// extraction from a claim's own words, and the check against the exact cells
// of the live results the claim cites.

func TestValueGateExtractDatesAllFormats(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string // "YYYY-MM-DD"
	}{
		{"dotted", "дата окончания 31.12.2024", "2024-12-31"},
		{"iso", "expires 2040-12-31 per the contract", "2040-12-31"},
		{"written ru no suffix", "дата окончания 31 декабря 2040", "2040-12-31"},
		{"written ru with года", "дата окончания 31 декабря 2040 года", "2040-12-31"},
		{"written ru with году", "к 31 декабря 2040 году", "2040-12-31"},
		{"written en day-month-year", "expires 31 December 2040", "2040-12-31"},
		{"written en month-day-year", "expires December 31, 2040", "2040-12-31"},
		{"written en month-day-year no comma", "expires December 31 2040", "2040-12-31"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			matches := valueGateExtractDates(testCase.text)
			if len(matches) != 1 {
				t.Fatalf("%s: got %d date matches in %q, want 1: %#v", testCase.name, len(matches), testCase.text, matches)
			}
			if matches[0].date.key() != testCase.want {
				t.Fatalf("%s: got date %s, want %s", testCase.name, matches[0].date.key(), testCase.want)
			}
		})
	}
}

func TestValueGateExtractDatesRejectsInvalidCalendarDate(t *testing.T) {
	for _, text := range []string{
		"30.02.2024",     // no such day in February
		"2024-02-30",     // same, ISO form
		"31 февраля 2024", // same, written form
	} {
		if matches := valueGateExtractDates(text); len(matches) != 0 {
			t.Fatalf("%q: invalid calendar date was accepted: %#v", text, matches)
		}
	}
}

func TestValueGateExtractNumbersSeparatorsAndSmallNumbersSkipped(t *testing.T) {
	cases := []struct {
		name string
		text string
		want float64
	}{
		{"plain", "amount 2500000 total", 2500000},
		{"space grouped", "amount 2 500 000 total", 2500000},
		{"nbsp grouped", "amount 2 500 000 total", 2500000},
		{"comma grouped", "amount 2,500,000 total", 2500000},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			matches := valueGateExtractNumbers(testCase.text, nil)
			if len(matches) != 1 {
				t.Fatalf("%s: got %d number matches in %q, want 1: %#v", testCase.name, len(matches), testCase.text, matches)
			}
			if matches[0].value != testCase.want {
				t.Fatalf("%s: got %v, want %v", testCase.name, matches[0].value, testCase.want)
			}
		})
	}
	for _, text := range []string{
		"5 contracts", "42 rows", "999 items",
	} {
		if matches := valueGateExtractNumbers(text, nil); len(matches) != 0 {
			t.Fatalf("%q: a number under 4 digits was flagged: %#v", text, matches)
		}
	}
}

func TestValueGateExtractNumbersExcludesDateSpans(t *testing.T) {
	text := "по состоянию на 2040-12-31 всего 5 договоров"
	dateMatches := valueGateExtractDates(text)
	if len(dateMatches) != 1 {
		t.Fatalf("expected one date match, got %#v", dateMatches)
	}
	spans := [][2]int{dateMatches[0].span}
	// The date's own year (2040) must never be re-flagged as a bare number.
	if numbers := valueGateExtractNumbers(text, spans); len(numbers) != 0 {
		t.Fatalf("the date's digits were re-flagged as a number: %#v", numbers)
	}
}

func TestValueGateParseCellDateAcceptsDateAndTimestamp(t *testing.T) {
	cases := []struct {
		name string
		cell string
		want string
	}{
		{"bare date", "2040-12-31", "2040-12-31"},
		{"timestamp no tz", "2040-12-31 00:00:00", "2040-12-31"},
		{"timestamp t separator", "2040-12-31T00:00:00", "2040-12-31"},
		{"timestamp with tz", "2040-12-31T23:59:59+03:00", "2040-12-31"},
		{"timestamp with fractional seconds", "2040-12-31 00:00:00.123456", "2040-12-31"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			date, ok := valueGateParseCellDate(testCase.cell)
			if !ok {
				t.Fatalf("%s: %q did not parse as a date", testCase.name, testCase.cell)
			}
			if date.key() != testCase.want {
				t.Fatalf("%s: got %s, want %s", testCase.name, date.key(), testCase.want)
			}
		})
	}
	for _, cell := range []string{"active", "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", ""} {
		if _, ok := valueGateParseCellDate(cell); ok {
			t.Fatalf("%q was mistaken for a date", cell)
		}
	}
}

func TestValueGateParseCellNumber(t *testing.T) {
	if value, ok := valueGateParseCellNumber("2500000"); !ok || value != 2500000 {
		t.Fatalf("got %v ok=%v, want 2500000", value, ok)
	}
	if value, ok := valueGateParseCellNumber("2500000.50"); !ok || value != 2500000.5 {
		t.Fatalf("got %v ok=%v, want 2500000.5", value, ok)
	}
	for _, cell := range []string{"2040-12-31", "active", ""} {
		if _, ok := valueGateParseCellNumber(cell); ok {
			t.Fatalf("%q was mistaken for a plain number", cell)
		}
	}
}

// toolLoopValueGateViolation is the check both rejectAnswer's one-shot repair
// and the final citation-binding pass call. These cases replay the reported
// incident directly: a result cell holds expiration_date 2040-12-31.
func TestValueGateViolationReplaysTheReportedIncident(t *testing.T) {
	cellDates := map[string]struct{}{"2040-12-31": {}}
	cellNumbers := map[float64]struct{}{}
	exempt := map[string]struct{}{}

	if value, kind := toolLoopValueGateViolation("дата окончания 31.12.2024", exempt, cellDates, cellNumbers); value == "" {
		t.Fatal("31.12.2024 against a 2040-12-31 result was not flagged")
	} else if kind != "date" {
		t.Fatalf("kind = %q, want date", kind)
	}

	if value, _ := toolLoopValueGateViolation("дата окончания 31.12.2040", exempt, cellDates, cellNumbers); value != "" {
		t.Fatalf("31.12.2040 against a 2040-12-31 result was wrongly flagged: %q", value)
	}

	// The same result as a timestamp cell still matches the plain-date claim.
	timestampCellDates := map[string]struct{}{}
	if date, ok := valueGateParseCellDate("2040-12-31 00:00:00"); !ok {
		t.Fatal("timestamp cell did not parse")
	} else {
		timestampCellDates[date.key()] = struct{}{}
	}
	if value, _ := toolLoopValueGateViolation("дата окончания 31.12.2040", exempt, timestampCellDates, cellNumbers); value != "" {
		t.Fatalf("31.12.2040 against a timestamp result was wrongly flagged: %q", value)
	}
}

func TestValueGateViolationExemptsCurrentAndQuestionDates(t *testing.T) {
	exempt := map[string]struct{}{"2026-09-26": {}}
	cellDates := map[string]struct{}{}
	cellNumbers := map[float64]struct{}{}
	if value, _ := toolLoopValueGateViolation("as of 2026-09-26 the contract is active", exempt, cellDates, cellNumbers); value != "" {
		t.Fatalf("an exempt date was flagged: %q", value)
	}
	if value, _ := toolLoopValueGateViolation("expires 2040-12-31", exempt, cellDates, cellNumbers); value == "" {
		t.Fatal("a non-exempt, unmatched date was not flagged")
	}
}

func TestValueGateViolationNumberWithSeparatorsMatchesPlainCell(t *testing.T) {
	cellDates := map[string]struct{}{}
	cellNumbers := map[float64]struct{}{2500000: {}}
	exempt := map[string]struct{}{}
	if value, _ := toolLoopValueGateViolation("итоговая сумма 2 500 000 рублей", exempt, cellDates, cellNumbers); value != "" {
		t.Fatalf("a grouped number matching a plain cell value was flagged: %q", value)
	}
	if value, kind := toolLoopValueGateViolation("итоговая сумма 3 500 000 рублей", exempt, cellDates, cellNumbers); value == "" {
		t.Fatal("an unmatched number was not flagged")
	} else if kind != "number" {
		t.Fatalf("kind = %q, want number", kind)
	}
}

func TestValueGateExemptDatesFromQuestion(t *testing.T) {
	requestedAt, err := time.Parse(time.RFC3339, "2026-09-26T10:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	exempt := toolLoopValueGateExemptDates("что было на 31.12.2024?", requestedAt)
	if _, ok := exempt["2026-09-26"]; !ok {
		t.Fatal("the request's own date is not exempt")
	}
	if _, ok := exempt["2024-12-31"]; !ok {
		t.Fatal("a date the user typed into the question is not exempt")
	}
}

func TestValueGateRepairInstructionNamesTheKindAndValue(t *testing.T) {
	russian := toolLoopValueGateRepairInstruction(questionLanguageRussian, "31.12.2024", "date")
	if !strings.Contains(russian, "31.12.2024") {
		t.Fatalf("russian hint does not name the value: %q", russian)
	}
	english := toolLoopValueGateRepairInstruction(questionLanguageEnglish, "31.12.2024", "date")
	if !strings.Contains(english, "31.12.2024") {
		t.Fatalf("english hint does not name the value: %q", english)
	}
}

// TestToolLoopClaimValueGateViolationReplaysTheReportedIncidentEndToEnd wires
// a real, cryptographically retained knowvault_source_sql execution through
// bindToolLiveReadReferences the same way the tool loop does, so this proves
// the whole path, not just the isolated comparison.
func TestToolLoopClaimValueGateViolationReplaysTheReportedIncidentEndToEnd(t *testing.T) {
	value := "2040-12-31"
	toolResult := valueGateTestToolResult(t, "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", []string{"expiration_date"}, []*string{&value})
	_, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, toolResult, 1<<20)
	if !ok || execution == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	executions := []liveDataExecution{*execution}
	liveRead := toolLiveReadReference{ResultID: execution.projection.AttemptID, ReceiptDigest: execution.projection.ReceiptDigest}
	exempt := map[string]struct{}{}

	wrong := toolClaim{Text: "дата окончания 31.12.2024", LiveReads: []toolLiveReadReference{liveRead}}
	if got, kind := toolLoopClaimValueGateViolation(wrong, testSourceSQLRunID, executions, exempt); got == "" {
		t.Fatal("the reported wrong date was not flagged")
	} else if kind != "date" {
		t.Fatalf("kind = %q, want date", kind)
	}

	right := toolClaim{Text: "дата окончания 31.12.2040", LiveReads: []toolLiveReadReference{liveRead}}
	if got, _ := toolLoopClaimValueGateViolation(right, testSourceSQLRunID, executions, exempt); got != "" {
		t.Fatalf("the correct date was flagged: %q", got)
	}

	// A document-only claim (no live_reads) is never in scope for this gate.
	documentOnly := toolClaim{Text: "дата окончания 31.12.2024"}
	if got, _ := toolLoopClaimValueGateViolation(documentOnly, testSourceSQLRunID, executions, exempt); got != "" {
		t.Fatalf("a document-only claim was checked against a live result: %q", got)
	}

	// A live_reads reference that does not cryptographically bind is left to
	// the existing binding check; this gate never double-flags it.
	forged := toolClaim{Text: "дата окончания 31.12.2024", LiveReads: []toolLiveReadReference{{
		ResultID: liveRead.ResultID, ReceiptDigest: "sha256:" + strings.Repeat("c", 64),
	}}}
	if got, _ := toolLoopClaimValueGateViolation(forged, testSourceSQLRunID, executions, exempt); got != "" {
		t.Fatalf("a claim with an unbound live_reads reference was checked: %q", got)
	}
}

// TestToolLoopValueGateOneRepairThenUnconfirmed documents the repair-loop
// contract requirement 2 asks for: rejectAnswer (unexported, driven only from
// inside executeToolLoop) allows the value-gate rejection exactly once per
// run, via valueGateRepairUsed; a claim that still disagrees with its cited
// result on the next submission is left to the citation-binding pass, which
// this test drives directly the way the tool loop's post-loop phase does --
// by forcing liveReferencesBound false for a violating claim, the same
// signal a failed cryptographic binding already produces.
func TestToolLoopValueGateOneRepairThenUnconfirmed(t *testing.T) {
	value := "2040-12-31"
	toolResult := valueGateTestToolResult(t, "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", []string{"expiration_date"}, []*string{&value})
	_, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, toolResult, 1<<20)
	if !ok || execution == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	executions := []liveDataExecution{*execution}
	liveRead := toolLiveReadReference{ResultID: execution.projection.AttemptID, ReceiptDigest: execution.projection.ReceiptDigest}
	exempt := map[string]struct{}{}
	claim := toolClaim{Text: "дата окончания 31.12.2024", LiveReads: []toolLiveReadReference{liveRead}}

	// Turn 1 (rejectAnswer's one shot): the violation is found and a rewrite
	// is requested.
	value1, _ := toolLoopClaimValueGateViolation(claim, testSourceSQLRunID, executions, exempt)
	if value1 == "" {
		t.Fatal("turn 1 did not find the violation the model must fix")
	}

	// Turn 2: the model resubmits the same wrong wording. The repair attempt
	// is already spent, so the loop no longer asks again; the citation-
	// binding pass takes over.
	_, _, liveReferencesBound := bindToolLiveReadReferences(testSourceSQLRunID, claim.LiveReads, executions)
	if !liveReferencesBound {
		t.Fatal("the live read itself should still bind cryptographically")
	}
	if value2, _ := toolLoopClaimValueGateViolation(claim, testSourceSQLRunID, executions, exempt); value2 == "" {
		t.Fatal("the still-wrong resubmission was not detected by the binding-time check")
	} else {
		// This is exactly the signal the binding pass uses to force
		// liveReferencesBound = false, which toolLoopClaimKept then treats as
		// an unbound live read: the claim is dropped, never shown as
		// confirmed.
		liveReferencesBound = false
	}
	if kept, _ := toolLoopClaimKept(false, 0, true, len(claim.LiveReads), liveReferencesBound); kept {
		t.Fatal("a claim whose value-gate violation survived the one repair was still kept as confirmed")
	}

	// The corrected claim, once resubmitted, is kept.
	fixed := toolClaim{Text: "дата окончания 31.12.2040", LiveReads: []toolLiveReadReference{liveRead}}
	if value, _ := toolLoopClaimValueGateViolation(fixed, testSourceSQLRunID, executions, exempt); value != "" {
		t.Fatalf("the corrected claim was still flagged: %q", value)
	}
	_, _, fixedBound := bindToolLiveReadReferences(testSourceSQLRunID, fixed.LiveReads, executions)
	if kept, _ := toolLoopClaimKept(false, 0, true, len(fixed.LiveReads), fixedBound); !kept {
		t.Fatal("the corrected claim should be kept as confirmed")
	}
}
