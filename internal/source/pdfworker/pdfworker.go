// Package pdfworker is a qualification/test-only facade for the isolated text-PDF
// sandbox. It deliberately does not import a third-party PDF library or choose an
// image: the qualification harness supplies a pinned command. Production composition
// must not call this facade or pass application argv directly; ADR-0068 requires the
// production dispatcher submitter to own that boundary. This package only binds the
// PDF protocol to sandbox.KindPDFText and re-validates the returned observation
// through pdfparser.
package pdfworker

import (
	"context"
	"errors"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/sandbox"
)

// ErrExtractionFailed is the single content-free failure returned to the caller.
var ErrExtractionFailed = errors.New("pdfworker: extraction failed")

// ErrInvalidConfig means the sandbox was not fully pinned before use.
var ErrInvalidConfig = errors.New("pdfworker: invalid sandbox configuration")

// Config pins one qualification-only text-PDF sandbox. Command is the exact argv
// of a test/qualification runtime plus its digest-addressed image and hardening
// flags; this package never constructs it from document data or passes it through
// a shell. Production submits a dispatcher job instead of constructing this facade.
type Config struct {
	Command                    []string
	ArtifactHash               string
	ObservationProfileRevision string
	Timeout                    time.Duration
	MaxPDFPages                int
	MaxPDFRectangles           int
	MaxPDFObjects              int
	MaxPagePoints              int
	MaxOutputBytes             int
}

const (
	maxConfigPDFPages      = 10000
	maxConfigPDFRectangles = 4096
	maxConfigPDFObjects    = 1000000
	maxConfigPagePoints    = 14400
	maxConfigOutputBytes   = 16 << 20
)

// Invoker holds no mutable extraction state, so concurrent PDF observations cannot
// affect one another.
type Invoker struct {
	runner                     *sandbox.Runner
	observationProfileRevision string
	maxPDFPages                int
	maxPDFRectangles           int
	maxPDFObjects              int
	maxPagePoints              int
	maxOutputBytes             int
}

// New validates all pinning before a document can reach the PDF sandbox.
func New(config Config) (*Invoker, error) {
	if config.ObservationProfileRevision == "" || config.MaxPDFPages <= 0 ||
		config.MaxPDFPages > maxConfigPDFPages || config.MaxPDFRectangles <= 0 ||
		config.MaxPDFRectangles > maxConfigPDFRectangles || config.MaxPDFObjects <= 0 ||
		config.MaxPDFObjects > maxConfigPDFObjects || config.MaxPagePoints <= 0 ||
		config.MaxPagePoints > maxConfigPagePoints || config.MaxOutputBytes <= 0 ||
		config.MaxOutputBytes > maxConfigOutputBytes {
		return nil, ErrInvalidConfig
	}
	runner, err := sandbox.New(sandbox.Config{
		Kind:           sandbox.KindPDFText,
		Command:        config.Command,
		ArtifactHash:   config.ArtifactHash,
		Timeout:        config.Timeout,
		MaxResultBytes: config.MaxOutputBytes,
	})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Invoker{
		runner: runner, observationProfileRevision: config.ObservationProfileRevision,
		maxPDFPages: config.MaxPDFPages, maxPDFRectangles: config.MaxPDFRectangles,
		maxPDFObjects: config.MaxPDFObjects, maxPagePoints: config.MaxPagePoints,
		maxOutputBytes: config.MaxOutputBytes,
	}, nil
}

// Extract sends exactly one transient PDF to a text-PDF sandbox. Other formats,
// including Office and OCR, are refused at this boundary; there is no parser
// fallback or render/OCR cascade here.
func (i *Invoker) Extract(ctx context.Context, format string, document []byte) (*pdfparser.Result, error) {
	if format != pdfparser.FormatPDF {
		return nil, ErrExtractionFailed
	}
	raw, err := i.runner.Run(ctx, sandbox.KindPDFText, []string{
		"--format=" + pdfparser.FormatPDF,
		"--observation-profile-revision=" + i.observationProfileRevision,
		"--max-input-bytes=" + strconv.Itoa(len(document)),
		"--max-units=" + strconv.Itoa(pdfparser.MaxTextUnits),
		"--max-unit-bytes=" + strconv.Itoa(pdfparser.MaxUnitRawBytes),
		"--max-total-text-bytes=" + strconv.Itoa(pdfparser.MaxObjectTextBytes),
		"--max-pdf-pages=" + strconv.Itoa(i.maxPDFPages),
		"--max-pdf-boxes=" + strconv.Itoa(i.maxPDFRectangles),
		"--max-pdf-objects=" + strconv.Itoa(i.maxPDFObjects),
		"--max-page-points=" + strconv.Itoa(i.maxPagePoints),
		"--max-output-bytes=" + strconv.Itoa(i.maxOutputBytes),
	}, document)
	if err != nil {
		return nil, ErrExtractionFailed
	}
	result, err := pdfparser.Parse(raw, format)
	if err != nil {
		return nil, ErrExtractionFailed
	}
	// A result from another image/profile is never published under this invoker's
	// identity. The worker cannot mint identity; it can only echo its own artifact
	// declaration, which is checked against the pinned sandbox.
	if result.Parser.ArtifactHash != i.runner.ArtifactHash() ||
		result.Parser.ObservationProfileRevision != i.observationProfileRevision {
		return nil, ErrExtractionFailed
	}
	return result, nil
}
