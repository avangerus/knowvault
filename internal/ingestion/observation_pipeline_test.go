package ingestion

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/format"
	"knowvault.local/verified-workspace/internal/source/observation"
)

func TestObservationVersionKeyRequiresTypedNativeOrExactHash(t *testing.T) {
	contentHash := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]bool{
		"hash:" + contentHash:              true,
		"native:uidvalidity:2;uid:9":       true,
		"native:":                          false,
		"native:bad\nvalue":                false,
		"hash:sha256:aaaaaaaaaaaaaaaaaaaa": false,
		"uidvalidity:2;uid:9":              false,
		"hash:" + contentHash + "-other":   false,
		"observation:" + contentHash + ":version_01ARZ3NDEKTSV4RRFFQ69G5FAV": false,
	}
	for value, want := range cases {
		if got := validSourceVersionKey(value, contentHash); got != want {
			t.Errorf("validSourceVersionKey(%q)=%v, want %v", value, got, want)
		}
	}
}

func TestCatalogObjectTypeDoesNotCollapseRemoteObjects(t *testing.T) {
	if got := catalogObjectType(&observation.Object{Kind: observation.KindDocument, ObjectType: "DOCUMENT"}); got != "FILE" {
		t.Fatalf("folder object type=%q", got)
	}
	for _, objectType := range []string{"GIT_FILE", "EMAIL", "EMAIL_ATTACHMENT"} {
		if got := catalogObjectType(&observation.Object{Kind: observation.KindGit, ObjectType: objectType}); got != objectType {
			t.Fatalf("remote object type %q collapsed to %q", objectType, got)
		}
	}
}

// TestFormatDeterminationReasonIsSourceKindSpecific proves the KV-A02 r6
// finding is fixed: when format determination fails after the bytes are read,
// the carried skip reason comes from the object's own source kind. A git object
// with an unadmitted/absent extension reports GIT_UNSUPPORTED_MEDIA_TYPE and a
// mail attachment with an unmapped media type reports
// MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE, never FOLDER_UNSUPPORTED_TYPE, while a
// folder/document object keeps FOLDER_UNSUPPORTED_TYPE. Every case first drives
// the real format decision into its quarantine branch, then asserts the reason.
func TestFormatDeterminationReasonIsSourceKindSpecific(t *testing.T) {
	allowed := map[string]bool{"TXT": true}
	cases := []struct {
		name       string
		objectType string
		externalID string
		mediaType  string
		wantReason string
	}{
		{"git file absent extension", "GIT_FILE", "src/module", "", quarantineReasonGitFormatNotAdmitted},
		{"mail attachment unmapped media type", "EMAIL_ATTACHMENT", "attachment-1", "application/x-not-admitted", quarantineReasonMailFormatNotAdmitted},
		{"folder document unadmitted extension", "FILE", "notes.bin", "", quarantineReasonFormatNotAdmitted},
	}
	for _, tc := range cases {
		if _, _, ok := format.DetermineObservation(tc.objectType, tc.externalID, tc.mediaType, allowed); ok {
			t.Fatalf("%s: format determination unexpectedly admitted the object", tc.name)
		}
		reason := formatNotAdmittedReason(tc.objectType)
		if reason != tc.wantReason {
			t.Fatalf("%s: reason=%q want %q", tc.name, reason, tc.wantReason)
		}
		if tc.objectType != "FILE" && reason == quarantineReasonFormatNotAdmitted {
			t.Fatalf("%s: non-folder object collapsed to folder code %q", tc.name, quarantineReasonFormatNotAdmitted)
		}
	}
}

// TestFormatNotAdmittedLedgerRowCarriesSourceKindReason drives a non-folder
// object through the real format-determination skip branch and then through
// skipForResult, the production ledger-row builder invoked at
// internal/ingestion/handler.go:468. It proves the persisted reason_code is the
// object's own source-kind code and never FOLDER_UNSUPPORTED_TYPE (the r6
// finding), and that a source-neutral extraction skip keeps its existing code.
func TestFormatNotAdmittedLedgerRowCarriesSourceKindReason(t *testing.T) {
	allowed := map[string]bool{"TXT": true}
	cases := []struct {
		name       string
		objectType string
		externalID string
		mediaType  string
		wantReason string
	}{
		{"git file absent extension", "GIT_FILE", "src/module", "", quarantineReasonGitFormatNotAdmitted},
		{"mail attachment unmapped media type", "EMAIL_ATTACHMENT", "attachment-1", "application/x-not-admitted", quarantineReasonMailFormatNotAdmitted},
		{"folder document unadmitted extension", "FILE", "notes.bin", "", quarantineReasonFormatNotAdmitted},
	}
	for _, tc := range cases {
		if _, _, ok := format.DetermineObservation(tc.objectType, tc.externalID, tc.mediaType, allowed); ok {
			t.Fatalf("%s: format determination unexpectedly admitted the object", tc.name)
		}
		// Reproduce the pipeline skip branch (pipeline.go:274-276) and pass the
		// carried reason through the production ledger-row builder, so the
		// assertion is on the row that reaches public.source_object_skip.
		result := ingestResult{quarantineReason: formatNotAdmittedReason(tc.objectType)}
		row := skipForResult(tc.externalID, result)
		if row.ReasonCode != tc.wantReason {
			t.Fatalf("%s: ledger reason=%q want %q", tc.name, row.ReasonCode, tc.wantReason)
		}
		if row.ExternalID != tc.externalID {
			t.Fatalf("%s: ledger external id=%q want %q", tc.name, row.ExternalID, tc.externalID)
		}
		if tc.objectType != "FILE" && row.ReasonCode == quarantineReasonFormatNotAdmitted {
			t.Fatalf("%s: ledger row collapsed to folder code %q", tc.name, quarantineReasonFormatNotAdmitted)
		}
	}
	neutral := skipForResult("notes.docx", ingestResult{quarantineReason: sourceObjectSkipReasonExtraction})
	if neutral.ReasonCode != sourceObjectSkipReasonExtraction {
		t.Fatalf("source-neutral extraction skip reason=%q want %q", neutral.ReasonCode, sourceObjectSkipReasonExtraction)
	}
}

// TestExtractionQuarantineReasonsStayTypedAndDistinct proves the KV-A02 typed
// skip ledger: two different quarantine causes in one run carry two different
// reason codes, every quarantined object carries a non-empty typed reason, a
// connector code surfaces verbatim and an out-of-set code is normalized to the
// closed fallback instead of reaching the ledger raw.
func TestExtractionQuarantineReasonsStayTypedAndDistinct(t *testing.T) {
	// One sync run accumulates the typed ledger row of every skipped object:
	// two distinct extraction causes, a connector code, and an out-of-set code.
	names := []string{"path", "format", "refused", "connector", "unknown"}
	runResults := []ingestResult{
		{quarantineReason: quarantineReasonPathRejected},
		{quarantineReason: quarantineReasonFormatNotAdmitted},
		{quarantineReason: sourceObjectSkipReasonExtraction},
		{quarantineReason: "FOLDER_OBJECT_OVERSIZED"},
		{quarantineReason: "NOT_A_CLOSED_CODE"},
	}
	ledger := make([]sourceObjectSkip, 0, len(runResults))
	for index, result := range runResults {
		ledger = append(ledger, skipForResult("object-"+names[index], result))
	}
	for index, row := range ledger {
		if row.ReasonCode == "" || row.ExternalID == "" {
			t.Fatalf("run row %d carried an empty reason or id: %+v", index, row)
		}
	}
	if ledger[0].ReasonCode != quarantineReasonPathRejected || ledger[1].ReasonCode != quarantineReasonFormatNotAdmitted {
		t.Fatalf("extraction causes lost their typed code: %+v", ledger[:2])
	}
	if ledger[0].ReasonCode == ledger[1].ReasonCode || ledger[1].ReasonCode == ledger[2].ReasonCode {
		t.Fatalf("distinct causes collapsed in one run: %+v", ledger[:3])
	}
	if ledger[2].ReasonCode != sourceObjectSkipReasonExtraction {
		t.Fatalf("parser-refusal reason=%q want %q", ledger[2].ReasonCode, sourceObjectSkipReasonExtraction)
	}
	if ledger[3].ReasonCode != "FOLDER_OBJECT_OVERSIZED" {
		t.Fatalf("connector code=%q want verbatim FOLDER_OBJECT_OVERSIZED", ledger[3].ReasonCode)
	}
	if ledger[4].ReasonCode != sourceObjectSkipReasonUnknown {
		t.Fatalf("out-of-set code=%q want closed fallback %q", ledger[4].ReasonCode, sourceObjectSkipReasonUnknown)
	}
}

// TestSourceObjectSkipReasonSetMirrorsMigrationCheck proves the Go reason set
// and the database CHECK set are the same closed taxonomy, so a carried code
// accepted by Go is accepted by public.source_object_skip and vice versa.
func TestSourceObjectSkipReasonSetMirrorsMigrationCheck(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", "000095_stage3_source_object_skip.sql"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "reason_code IN ("
	sql := string(raw)
	start := strings.Index(sql, marker)
	if start < 0 {
		t.Fatalf("migration does not declare the %s CHECK", marker)
	}
	tail := sql[start+len(marker):]
	end := strings.Index(tail, "))")
	if end < 0 {
		t.Fatalf("migration %s CHECK is not closed", marker)
	}
	matches := regexp.MustCompile(`'([A-Z0-9_]+)'`).FindAllStringSubmatch(tail[:end], -1)
	databaseCodes := make([]string, 0, len(matches))
	for _, match := range matches {
		databaseCodes = append(databaseCodes, match[1])
	}
	if len(databaseCodes) != len(sourceObjectSkipReasonCodes) {
		t.Fatalf("database codes=%d Go codes=%d", len(databaseCodes), len(sourceObjectSkipReasonCodes))
	}
	for _, code := range sourceObjectSkipReasonCodes {
		if !slices.Contains(databaseCodes, code) {
			t.Fatalf("Go reason %q is absent from the database CHECK", code)
		}
	}
}
