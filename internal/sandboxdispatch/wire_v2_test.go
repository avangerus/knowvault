package sandboxdispatch

import (
	"strings"
	"testing"
	"time"
)

func TestParserRequestV1AcceptsOnlyClosedTuples(t *testing.T) {
	t.Parallel()
	request := func(parserType, operation, media, sandbox, renderer, ocr, output string) ParserRequestV1 {
		return ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: parserType, Operation: operation, MediaFamily: media, SandboxProfileRevision: sandbox, ObservationProfileRevision: "observe-v1", RendererProfileRevision: renderer, OCRProfileRevision: ocr, MaxInputBytes: 1, MaxOutputBytes: 1, MaxUnits: 1, MaxPages: 1, MaxDecodedPixels: 1, OutputContract: output}
	}
	for _, request := range []ParserRequestV1{
		request(ParserTypeOffice, OperationObserveStructure, "DOCX", "poi-v1", "", "", "document-parser-result-v1"),
		request(ParserTypePDF, OperationObservePDFText, "PDF", "pdf-observer-v1", "", "", "pdf-parser-result-v1"),
		request(ParserTypePDF, OperationRenderPDFPages, "PDF", "render-v1", "renderer-v1", "", "pdf-render-result-v1"),
		request(ParserTypeOCR, OperationObserveOCRTokens, "PNG", "ocr-sandbox-v1", "", "ocr-profile-v1", "ocr-result-v1"),
		request(ParserTypeOCR, OperationObserveOCRTokens, "JPEG", "ocr-sandbox-v1", "", "ocr-profile-v1", "ocr-result-v1"),
	} {
		if err := request.Validate(); err != nil {
			t.Fatalf("valid tuple rejected: %#v: %v", request, err)
		}
	}
	invalid := request(ParserTypeOCR, OperationObserveOCRTokens, "PDF", "ocr-sandbox-v1", "", "ocr-profile-v1", "ocr-result-v1")
	if err := invalid.Validate(); err == nil {
		t.Fatal("scanned PDF bypassed deterministic render boundary")
	}
	missingProfile := request(ParserTypeOCR, OperationObserveOCRTokens, "PNG", "ocr-sandbox-v1", "", "", "ocr-result-v1")
	if err := missingProfile.Validate(); err == nil {
		t.Fatal("OCR request without OCR profile accepted")
	}
	missingProfile = request(ParserTypePDF, OperationRenderPDFPages, "PDF", "render-v1", "", "", "pdf-render-result-v1")
	if err := missingProfile.Validate(); err == nil {
		t.Fatal("render request without renderer profile accepted")
	}
	smuggled := request(ParserTypeOCR, OperationObserveOCRTokens, "PNG", "ocr-sandbox-v1", "renderer-v1", "ocr-profile-v1", "ocr-result-v1")
	if err := smuggled.Validate(); err == nil {
		t.Fatal("OCR request with irrelevant renderer profile accepted")
	}
	smuggled = request(ParserTypeOffice, OperationObserveStructure, "DOCX", "poi-v1", "", "ocr-v1", "document-parser-result-v1")
	if err := smuggled.Validate(); err == nil {
		t.Fatal("Office request with irrelevant OCR profile accepted")
	}
	quoted := request(ParserTypeOCR, OperationObserveOCRTokens, "PNG", "ocr-sandbox-\"v1", "", "ocr-profile-v1", "ocr-result-v1")
	if err := quoted.Validate(); err == nil {
		t.Fatal("non-canonical profile revision accepted")
	}
}

func TestParserRequestV1RejectsNumbersOutsideJSONSafeIntegerRange(t *testing.T) {
	base := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypePDF, Operation: OperationObservePDFText, MediaFamily: "PDF", SandboxProfileRevision: "pdf-v1", ObservationProfileRevision: "observe-v1", MaxInputBytes: 1, MaxOutputBytes: 1, MaxUnits: 1, MaxPages: 1, MaxDecodedPixels: 1, OutputContract: "pdf-parser-result-v1"}
	for name, mutate := range map[string]func(*ParserRequestV1){
		"input":  func(r *ParserRequestV1) { r.MaxInputBytes = maxJSONSafeInteger + 1 },
		"output": func(r *ParserRequestV1) { r.MaxOutputBytes = maxJSONSafeInteger + 1 },
		"units":  func(r *ParserRequestV1) { r.MaxUnits = maxJSONSafeInteger + 1 },
		"pages":  func(r *ParserRequestV1) { r.MaxPages = maxJSONSafeInteger + 1 },
		"pixels": func(r *ParserRequestV1) { r.MaxDecodedPixels = maxJSONSafeInteger + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe integer accepted")
			}
		})
	}
}

func TestJobV2BindsMediaFamilyToExactInputMediaType(t *testing.T) {
	now := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	request := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypePDF, Operation: OperationObservePDFText, MediaFamily: "PDF", SandboxProfileRevision: "pdf-v1", ObservationProfileRevision: "observe-v1", MaxInputBytes: 1, MaxOutputBytes: 1, MaxUnits: 1, MaxPages: 1, MaxDecodedPixels: 1, OutputContract: "pdf-parser-result-v1"}
	job := JobV2{SchemaVersion: JobVersionV2, JobID: "j1", LeaseID: "l1", ParserRequest: request, InputArtifact: InputArtifact{ArtifactID: "opaque", ContentDigest: "sha256:" + strings.Repeat("a", 64), MediaType: "application/pdf"}, SubmittedAt: "2026-08-28T09:59:00Z", DeadlineAt: "2026-08-28T10:01:00Z", WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN"}
	if _, _, err := job.Validate(now); err != nil {
		t.Fatalf("valid PDF media rejected: %v", err)
	}
	job.InputArtifact.MediaType = "application/octet-stream"
	if _, _, err := job.Validate(now); err == nil {
		t.Fatal("PDF capability accepted mismatched media type")
	}
}

func TestJobV2AndOutcomeV2FailClosed(t *testing.T) {
	t.Parallel()
	request := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypeOCR, Operation: OperationObserveOCRTokens, MediaFamily: "PNG", SandboxProfileRevision: "ocr-sandbox-v1", ObservationProfileRevision: "observe-v1", OCRProfileRevision: "ocr-v1", MaxInputBytes: 1, MaxOutputBytes: 1, MaxUnits: 1, MaxPages: 1, MaxDecodedPixels: 1, OutputContract: "ocr-result-v1"}
	now := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	job := JobV2{SchemaVersion: JobVersionV2, JobID: "j1", LeaseID: "l1", ParserRequest: request, InputArtifact: InputArtifact{ArtifactID: "opaque-1", ContentDigest: "sha256:" + strings.Repeat("a", 64), MediaType: "image/png"}, SubmittedAt: "2026-08-28T09:59:00Z", DeadlineAt: "2026-08-28T10:01:00Z", WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN"}
	if _, _, err := job.Validate(now); err != nil {
		t.Fatalf("valid v2 job rejected: %v", err)
	}
	job.ParserRequest.OutputContract = "document-parser-result-v1"
	if _, _, err := job.Validate(now); err == nil {
		t.Fatal("wrong tuple output contract accepted")
	}
	job = JobV2{SchemaVersion: JobVersionV2, JobID: "j1", LeaseID: "l1", ParserRequest: request, InputArtifact: InputArtifact{ArtifactID: "opaque-1", ContentDigest: "sha256:" + strings.Repeat("a", 64), MediaType: "image/png"}, SubmittedAt: "2026-08-28T09:59:00Z", DeadlineAt: "2026-08-28T10:01:00Z", WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN"}
	job.ParserRequest.MaxDecodedPixels = 0
	if _, _, err := job.Validate(now); err == nil {
		t.Fatal("unbounded decoded-pixel request accepted")
	}
	identity := "sha256:" + strings.Repeat("b", 64)
	runtime := RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, Limits{CPUMillis: 1, MemoryBytes: 1, PIDsMax: 1, WallClockMS: 1})
	execution := "sha256:" + strings.Repeat("c", 64)
	worker := "w1"
	confirmed := OutcomeV2{SchemaVersion: OutcomeVersionV2, LeaseID: "l1", JobID: "j1", WorkerID: &worker, ParserRequest: request, OutputContract: request.OutputContract, Handoff: Handoff{TransferConfirmed, execution}, Status: StatusSucceeded, ReportedAt: "2026-08-28T10:00:10Z", ResultDigest: &identity, RuntimeProfileHash: &runtime, ExecutionConfirmationID: &execution}
	if err := confirmed.Validate(); err != nil {
		t.Fatalf("valid confirmed v2 outcome rejected: %v", err)
	}
	retry := OutcomeV2{SchemaVersion: OutcomeVersionV2, LeaseID: "l1", JobID: "j1", WorkerID: nil, ParserRequest: request, OutputContract: request.OutputContract, Handoff: Handoff{TransferRetry, "pre-transfer"}, Status: StatusFailed, ReportedAt: "2026-08-28T10:00:10Z", ResultDigest: nil, RuntimeProfileHash: nil, ExecutionConfirmationID: nil}
	if err := retry.Validate(); err != nil {
		t.Fatalf("valid retry v2 outcome rejected: %v", err)
	}
	quarantined := OutcomeV2{SchemaVersion: OutcomeVersionV2, LeaseID: "l1", JobID: "j1", WorkerID: &worker, ParserRequest: request, OutputContract: request.OutputContract, Handoff: Handoff{TransferQuarantine, execution}, Status: StatusQuarantine, ReportedAt: "2026-08-28T10:00:10Z", ResultDigest: nil, RuntimeProfileHash: &runtime, ExecutionConfirmationID: &execution}
	if err := quarantined.Validate(); err != nil {
		t.Fatalf("valid quarantined v2 outcome rejected: %v", err)
	}
	confirmed.ResultDigest = nil
	if err := confirmed.Validate(); err == nil {
		t.Fatal("confirmed result without digest accepted")
	}
	retry.WorkerID = &worker
	if err := retry.Validate(); err == nil {
		t.Fatal("pre-transfer retry with worker accepted")
	}
	quarantined.Handoff.ConfirmationID = "different-confirmation"
	if err := quarantined.Validate(); err == nil {
		t.Fatal("quarantine without execution binding accepted")
	}
}

func TestLimitConfirmationV2BindsStableAndExecutionIdentities(t *testing.T) {
	t.Parallel()
	request := ParserRequestV1{SchemaVersion: ParserRequestVersionV1, ParserType: ParserTypeOCR, Operation: OperationObserveOCRTokens, MediaFamily: "JPEG", SandboxProfileRevision: "ocr-sandbox-v1", ObservationProfileRevision: "observe-v1", OCRProfileRevision: "ocr-v1", MaxInputBytes: 1, MaxOutputBytes: 1, MaxUnits: 1, MaxPages: 1, MaxDecodedPixels: 1, OutputContract: "ocr-result-v1"}
	limits := Limits{CPUMillis: 500, MemoryBytes: 536870912, PIDsMax: 64, WallClockMS: 60000}
	observed := time.Date(2026, time.August, 28, 10, 0, 0, 0, time.UTC)
	runtime := RuntimeProfileHash(request.ParserType, request.SandboxProfileRevision, limits)
	confirmation := LimitConfirmationV2{LimitsVersionV2, "l1", "j1", "w1", observed.Format(time.RFC3339), "KERNEL_CGROUP_NAMESPACE", request, limits, runtime, ExecutionConfirmationID(runtime, "l1", "j1", "w1", observed), true}
	if err := confirmation.Validate(); err != nil {
		t.Fatalf("valid v2 confirmation rejected: %v", err)
	}
	confirmation.JobID = "j2"
	if err := confirmation.Validate(); err == nil {
		t.Fatal("execution confirmation did not bind job")
	}
}
