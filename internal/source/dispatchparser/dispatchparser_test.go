package dispatchparser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
)

type recordingTransport struct {
	job       sandboxdispatch.JobV2
	payload   []byte
	terminal  sandboxdispatch.SubmitResultV2
	retryable bool
	err       error
}

func (r *recordingTransport) SubmitV2(_ context.Context, job sandboxdispatch.JobV2, payload []byte) (sandboxdispatch.SubmitResultV2, bool, error) {
	r.job = job
	r.payload = append([]byte(nil), payload...)
	return r.terminal, r.retryable, r.err
}

func successTerminal(raw []byte) sandboxdispatch.SubmitResultV2 {
	return sandboxdispatch.SubmitResultV2{
		Outcome: sandboxdispatch.OutcomeV2{Status: sandboxdispatch.StatusSucceeded},
		Result:  raw, Confirmation: &sandboxdispatch.LimitConfirmationV2{
			RuntimeProfileHash: "sha256:" + fmt.Sprintf("%064d", 2),
		},
	}
}

func fixedShared(transport transport) shared {
	next := 0
	return shared{
		transport: transport,
		now:       func() time.Time { return time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC) },
		newID: func() (string, error) {
			next++
			return fmt.Sprintf("id_%d", next), nil
		},
		timeout: time.Minute,
	}
}

func officeResult(artifactHash string) []byte {
	return []byte(fmt.Sprintf(`{"result_version":"document-parser-result-v1","observed_format":"DOCX","parser":{"name":"knowvault-office-observer","version":"2.0.0","artifact_hash":"%s","observation_profile_revision":"office-obs-v1"},"text_units":[{"ordinal":1,"locator":{"kind":"DOCX","section_path":["word/document.xml","body"],"paragraph_ordinal":1,"paragraph_native_id":"native:p1"},"raw_text":"Waste: 12.5 t"}],"warnings":[]}`, artifactHash))
}

func pdfResult(artifactHash string) []byte {
	return []byte(fmt.Sprintf(`{"result_version":"pdf-parser-result-v1","observed_format":"PDF","parser":{"name":"knowvault-pdf-observer","version":"2.0.0","artifact_hash":"%s","observation_profile_revision":"pdf-obs-v1"},"text_units":[{"ordinal":1,"locator":{"kind":"PDF","page":1,"page_width":612,"page_height":792,"rotation":0,"bounding_boxes":[{"x":72,"y":100,"width":80,"height":12,"coordinate_unit":"PDF_POINT","coordinate_origin":"TOP_LEFT"}]},"raw_text":"Waste: 12.5 t"}],"warnings":[]}`, artifactHash))
}

func TestOfficeSubmitsClosedV2CapabilityAndPinsWorkerIdentity(t *testing.T) {
	transport := &recordingTransport{terminal: successTerminal(officeResult(QualifiedArtifactHash))}
	office := &Office{shared: fixedShared(transport)}
	document := []byte("real-docx-carrier")
	result, err := office.Extract(context.Background(), docparser.FormatDOCX, document)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if string(result.Fragments[0].CanonicalText) != "Waste: 12.5 t" || !bytes.Equal(transport.payload, document) {
		t.Fatalf("result/payload mismatch")
	}
	request := transport.job.ParserRequest
	if transport.job.SchemaVersion != sandboxdispatch.JobVersionV2 || !transport.job.WorkerPullOnly || transport.job.ContainerCreationCap != "FORBIDDEN" ||
		request.ParserType != sandboxdispatch.ParserTypeOffice || request.Operation != sandboxdispatch.OperationObserveStructure || request.MediaFamily != docparser.FormatDOCX ||
		request.OutputContract != docparser.ResultVersion || request.SandboxProfileRevision != SandboxProfileRevision || request.ObservationProfileRevision != OfficeObservationRevision {
		t.Fatalf("unexpected job: %+v", transport.job)
	}
	if transport.job.JobID != "id_1" || transport.job.LeaseID != "id_2" || transport.job.InputArtifact.ArtifactID != "id_3" {
		t.Fatalf("business identity leaked or IDs not dispatcher-local: %+v", transport.job)
	}
}

func TestPDFSubmitsSeparateCapabilityAndBuildsExactAnchor(t *testing.T) {
	transport := &recordingTransport{terminal: successTerminal(pdfResult(QualifiedArtifactHash))}
	pdf := &PDF{shared: fixedShared(transport)}
	result, err := pdf.Extract(context.Background(), pdfparser.FormatPDF, []byte("%PDF-live"))
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	request := transport.job.ParserRequest
	if request.ParserType != sandboxdispatch.ParserTypePDF || request.Operation != sandboxdispatch.OperationObservePDFText || request.OutputContract != pdfparser.ResultVersion || len(result.Fragments) != 1 || result.Fragments[0].Anchor.Page != 1 {
		t.Fatalf("unexpected PDF result/job: request=%+v result=%+v", request, result)
	}
}

func TestDispatcherFailureRetryAndIdentityMismatchAreContentFree(t *testing.T) {
	for name, transport := range map[string]*recordingTransport{
		"transport": {err: errors.New("secret source diagnostic")},
		"identity":  {terminal: successTerminal(officeResult("sha256:" + fmt.Sprintf("%064d", 1)))},
	} {
		t.Run(name, func(t *testing.T) {
			office := &Office{shared: fixedShared(transport)}
			if _, err := office.Extract(context.Background(), docparser.FormatDOCX, []byte("carrier")); !errors.Is(err, ErrExtractionFailed) || err.Error() != ErrExtractionFailed.Error() {
				t.Fatalf("failure leaked detail: %v", err)
			}
		})
	}
	retry := &Office{shared: fixedShared(&recordingTransport{retryable: true})}
	if _, err := retry.Extract(context.Background(), docparser.FormatDOCX, []byte("carrier")); !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) || err.Error() != sandboxdispatch.ErrRetryBeforeTransfer.Error() {
		t.Fatalf("retry semantics leaked or collapsed: %v", err)
	}
}

func TestProductionUnavailableDispatcherDoesNotQuarantineOfficeOrPDF(t *testing.T) {
	office, pdf, err := NewProduction(filepath.Join(t.TempDir(), "absent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if result, err := office.Extract(ctx, docparser.FormatDOCX, []byte("opaque office document")); result != nil || !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
		t.Fatalf("unavailable Office dispatcher: result=%v error=%v", result != nil, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if result, err := pdf.Extract(ctx, pdfparser.FormatPDF, []byte("opaque PDF document")); result != nil || !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
		t.Fatalf("unavailable PDF dispatcher: result=%v error=%v", result != nil, err)
	}
}

func TestExtractRejectsEmptyWrongFormatAndExpiredContextBeforeSubmit(t *testing.T) {
	transport := &recordingTransport{}
	office := &Office{shared: fixedShared(transport)}
	ctx, cancel := context.WithDeadline(context.Background(), time.Date(2026, 8, 28, 11, 59, 59, 0, time.UTC))
	defer cancel()
	for name, run := range map[string]func() error{
		"empty":   func() error { _, err := office.Extract(context.Background(), docparser.FormatDOCX, nil); return err },
		"wrong":   func() error { _, err := office.Extract(context.Background(), "PDF", []byte("x")); return err },
		"expired": func() error { _, err := office.Extract(ctx, docparser.FormatDOCX, []byte("x")); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrExtractionFailed) {
				t.Fatalf("rejection=%v", err)
			}
		})
	}
	if transport.job.JobID != "" {
		t.Fatalf("invalid input reached dispatcher")
	}
}
