// Package dispatchparser is the production Office/PDF extraction boundary.
// It submits opaque source bytes to the independently supervised sandbox
// dispatcher and turns only a fully confirmed v2 result into Go-owned canonical
// Evidence material. It has no process, container-runtime, database or secret
// capability.
package dispatchparser

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
)

const (
	SandboxProfileRevision    = sandboxdispatch.ProductionSandboxProfileRevision
	OfficeObservationRevision = sandboxdispatch.ProductionOfficeObservationRev
	PDFObservationRevision    = sandboxdispatch.ProductionPDFObservationRevision
	PDFRendererRevision       = sandboxdispatch.ProductionPDFRendererRevision
	QualifiedArtifactHash     = sandboxdispatch.ProductionParserArtifactHash
	maxInputBytes             = sandboxdispatch.ProductionMaxInputBytes
	maxOutputBytes            = sandboxdispatch.ProductionMaxOutputBytes
	maxPages                  = sandboxdispatch.ProductionMaxPages
	maxDecodedPixels          = sandboxdispatch.ProductionMaxDecodedPixels
	productionTimeout         = 120 * time.Second
)

var (
	ErrExtractionFailed = errors.New("dispatchparser: extraction failed")
	ErrInvalidConfig    = errors.New("dispatchparser: invalid configuration")
)

type transport interface {
	SubmitV2(context.Context, sandboxdispatch.JobV2, []byte) (sandboxdispatch.SubmitResultV2, bool, error)
}

type idSource func() (string, error)

type shared struct {
	transport transport
	now       func() time.Time
	newID     idSource
	timeout   time.Duration
	ready     func(context.Context) error
}

// Office implements ingestion.OfficeExtractor over dispatcher v2.
type Office struct{ shared shared }

// PDF implements ingestion.PDFExtractor over dispatcher v2.
type PDF struct{ shared shared }

// NewProduction constructs the only production adapters. The caller supplies a
// previously canonicalized Unix socket path from worker composition; all parser
// profiles, bounds and the qualified artifact identity are code-locked here.
func NewProduction(socketPath string) (*Office, *PDF, error) {
	if socketPath == "" {
		return nil, nil, ErrInvalidConfig
	}
	submitter := &sandboxdispatch.Submitter{
		V2SubmitSocketPath: socketPath,
		MaxPayloadBytes:    int(maxInputBytes),
		FrameTimeout:       5 * time.Second,
	}
	base := shared{transport: submitter, now: time.Now, newID: randomID, timeout: productionTimeout, ready: submitter.CheckNativeReadiness}
	return &Office{shared: base}, &PDF{shared: base}, nil
}
func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", ErrExtractionFailed
	}
	return hex.EncodeToString(raw[:]), nil
}

func (o *Office) Extract(ctx context.Context, format string, document []byte) (*docparser.Result, error) {
	var mediaType string
	switch format {
	case docparser.FormatDOCX:
		mediaType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case docparser.FormatPPTX:
		mediaType = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case docparser.FormatXLSX:
		mediaType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return nil, ErrExtractionFailed
	}
	request := sandboxdispatch.ParserRequestV1{
		SchemaVersion: sandboxdispatch.ParserRequestVersionV1, ParserType: sandboxdispatch.ParserTypeOffice,
		Operation: sandboxdispatch.OperationObserveStructure, MediaFamily: format,
		SandboxProfileRevision: SandboxProfileRevision, ObservationProfileRevision: OfficeObservationRevision,
		MaxInputBytes: maxInputBytes, MaxOutputBytes: maxOutputBytes, MaxUnits: sandboxdispatch.ProductionMaxUnits,
		MaxPages: maxPages, MaxDecodedPixels: maxDecodedPixels, OutputContract: sandboxdispatch.ProductionOfficeOutputContract,
	}
	raw, runtimeProfileHash, err := o.shared.submit(ctx, request, mediaType, document)
	if err != nil {
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return nil, sandboxdispatch.ErrRetryBeforeTransfer
		}
		return nil, ErrExtractionFailed
	}
	result, err := docparser.Parse(raw, format)
	if err != nil || result.Parser.ArtifactHash != QualifiedArtifactHash || result.Parser.ObservationProfileRevision != OfficeObservationRevision {
		return nil, ErrExtractionFailed
	}
	result.Parser.RuntimeProfileHash = runtimeProfileHash
	return result, nil
}

func (p *PDF) Extract(ctx context.Context, format string, document []byte) (*pdfparser.Result, error) {
	if format != pdfparser.FormatPDF {
		return nil, ErrExtractionFailed
	}
	request := sandboxdispatch.ParserRequestV1{
		SchemaVersion: sandboxdispatch.ParserRequestVersionV1, ParserType: sandboxdispatch.ParserTypePDF,
		Operation: sandboxdispatch.OperationObservePDFText, MediaFamily: pdfparser.FormatPDF,
		SandboxProfileRevision: SandboxProfileRevision, ObservationProfileRevision: PDFObservationRevision,
		MaxInputBytes: maxInputBytes, MaxOutputBytes: maxOutputBytes, MaxUnits: sandboxdispatch.ProductionMaxUnits,
		MaxPages: maxPages, MaxDecodedPixels: maxDecodedPixels, OutputContract: sandboxdispatch.ProductionPDFOutputContract,
	}
	raw, runtimeProfileHash, err := p.shared.submit(ctx, request, "application/pdf", document)
	if err != nil {
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return nil, sandboxdispatch.ErrRetryBeforeTransfer
		}
		return nil, ErrExtractionFailed
	}
	result, err := pdfparser.Parse(raw, format)
	if errors.Is(err, pdfparser.ErrScannedOrMixedPDF) {
		return nil, pdfparser.ErrScannedOrMixedPDF
	}
	if err != nil || result.Parser.ArtifactHash != QualifiedArtifactHash || result.Parser.ObservationProfileRevision != PDFObservationRevision {
		return nil, ErrExtractionFailed
	}
	result.Parser.RuntimeProfileHash = runtimeProfileHash
	return result, nil
}

// Render submits a PDF to the deterministic isolated renderer. It is deliberately
// a method on the PDF adapter rather than a generic parser fallback: callers
// must first receive ErrScannedOrMixedPDF from Extract before invoking it.
func (p *PDF) Render(ctx context.Context, format string, document []byte) (*pdfrenderparser.Result, error) {
	if format != pdfparser.FormatPDF {
		return nil, ErrExtractionFailed
	}
	request := sandboxdispatch.ParserRequestV1{
		SchemaVersion: sandboxdispatch.ParserRequestVersionV1, ParserType: sandboxdispatch.ParserTypePDF,
		Operation: sandboxdispatch.OperationRenderPDFPages, MediaFamily: pdfrenderparser.FormatPDF,
		SandboxProfileRevision: SandboxProfileRevision, ObservationProfileRevision: PDFObservationRevision,
		RendererProfileRevision: PDFRendererRevision,
		MaxInputBytes:           maxInputBytes, MaxOutputBytes: maxOutputBytes, MaxUnits: sandboxdispatch.ProductionMaxUnits,
		MaxPages: maxPages, MaxDecodedPixels: sandboxdispatch.ProductionRenderMaxDecodedPixels, OutputContract: sandboxdispatch.ProductionPDFRenderOutputContract,
	}
	raw, _, err := p.shared.submit(ctx, request, "application/pdf", document)
	if err != nil {
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return nil, sandboxdispatch.ErrRetryBeforeTransfer
		}
		return nil, ErrExtractionFailed
	}
	result, err := pdfrenderparser.Parse(raw, PDFRendererRevision, QualifiedArtifactHash)
	if err != nil || result.Renderer.ArtifactHash != QualifiedArtifactHash || result.Renderer.ProfileRevision != PDFRendererRevision {
		return nil, ErrExtractionFailed
	}
	return result, nil
}

func (s shared) submit(ctx context.Context, request sandboxdispatch.ParserRequestV1, mediaType string, document []byte) ([]byte, string, error) {
	raw, profile, err := s.submitOnce(ctx, request, mediaType, document)
	if s.ready == nil || !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
		return raw, profile, err
	}
	// Each parser is one-shot. A folder can reach its next Office file before
	// the supervisor finishes replacing the previous peer. Wait here only after
	// the dispatcher has proven no transfer, instead of restarting the entire
	// folder job and repeatedly consuming peers for its already-published files.
	// Polling readiness sends no document bytes; admission still decides whether
	// a ready peer remains available when the next fresh job arrives.
	waitContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	for {
		ready := s.ready(waitContext)
		if waitContext.Err() != nil {
			return nil, "", sandboxdispatch.ErrRetryBeforeTransfer
		}
		if ready == nil {
			raw, profile, err = s.submitOnce(ctx, request, mediaType, document)
			if !errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
				return raw, profile, err
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return nil, "", sandboxdispatch.ErrRetryBeforeTransfer
		case <-timer.C:
		}
	}
}

func (s shared) submitOnce(ctx context.Context, request sandboxdispatch.ParserRequestV1, mediaType string, document []byte) ([]byte, string, error) {
	if ctx == nil || s.transport == nil || s.now == nil || s.newID == nil || s.timeout <= 0 || len(document) == 0 || int64(len(document)) > maxInputBytes {
		return nil, "", ErrExtractionFailed
	}
	now := s.now().UTC()
	deadline := now.Add(s.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline.UTC()
	}
	if !deadline.After(now) {
		return nil, "", ErrExtractionFailed
	}
	jobID, err := s.newID()
	if err != nil {
		return nil, "", ErrExtractionFailed
	}
	leaseID, err := s.newID()
	if err != nil {
		return nil, "", ErrExtractionFailed
	}
	artifactID, err := s.newID()
	if err != nil {
		return nil, "", ErrExtractionFailed
	}
	digest := sha256.Sum256(document)
	job := sandboxdispatch.JobV2{
		SchemaVersion: sandboxdispatch.JobVersionV2,
		JobID:         jobID, LeaseID: leaseID, ParserRequest: request,
		InputArtifact: sandboxdispatch.InputArtifact{ArtifactID: artifactID, ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), MediaType: mediaType},
		SubmittedAt:   now.Format(time.RFC3339), DeadlineAt: deadline.Format(time.RFC3339),
		WorkerPullOnly: true, ContainerCreationCap: "FORBIDDEN",
	}
	terminal, retryable, err := s.transport.SubmitV2(ctx, job, document)
	if err != nil {
		return nil, "", ErrExtractionFailed
	}
	if retryable {
		return nil, "", sandboxdispatch.ErrRetryBeforeTransfer
	}
	if terminal.Confirmation == nil || terminal.Outcome.Status != sandboxdispatch.StatusSucceeded || len(terminal.Result) == 0 || terminal.Confirmation.RuntimeProfileHash == "" {
		return nil, "", ErrExtractionFailed
	}
	return terminal.Result, terminal.Confirmation.RuntimeProfileHash, nil
}
