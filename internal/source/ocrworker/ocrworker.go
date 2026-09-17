// Package ocrworker is the typed Go façade over the isolated OCR worker. It
// submits one transient PNG/JPEG to the shared sandbox and accepts only a
// strictly re-validated ocr-result-v1 response whose image, profile and model
// identities match the immutable composition snapshot.
package ocrworker

import (
	"context"
	"errors"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/internal/source/sandbox"
)

var (
	ErrExtractionFailed = errors.New("ocrworker: extraction failed")
	ErrInvalidConfig    = errors.New("ocrworker: invalid sandbox configuration")
)

const (
	MaxInputBytes  = 64 << 20
	MaxOutputBytes = 16 << 20
	MaxPages       = 1
	MaxTokens      = ocrparser.MaxTokensPerPage
)

type Config struct {
	Command                    []string
	ArtifactHash               string
	ObservationProfileRevision string
	OCRProfileRevision         string
	ModelID                    string
	ModelRevision              string
	ModelArtifactHash          string
	Timeout                    time.Duration
	MaxInputBytes              int
	MaxOutputBytes             int
}

type Invoker struct {
	runner                     *sandbox.Runner
	observationProfileRevision string
	ocrProfileRevision         string
	modelID                    string
	modelRevision              string
	modelArtifactHash          string
	maxInputBytes              int
	maxOutputBytes             int
}

func New(config Config) (*Invoker, error) {
	if config.ObservationProfileRevision == "" || config.OCRProfileRevision == "" || config.ModelID == "" || config.ModelRevision == "" || !sandbox.ValidArtifactHash(config.ModelArtifactHash) || config.MaxInputBytes < 1 || config.MaxInputBytes > MaxInputBytes || config.MaxOutputBytes < 1 || config.MaxOutputBytes > MaxOutputBytes {
		return nil, ErrInvalidConfig
	}
	runner, err := sandbox.New(sandbox.Config{Kind: sandbox.KindOCR, Command: config.Command, ArtifactHash: config.ArtifactHash, Timeout: config.Timeout, MaxResultBytes: config.MaxOutputBytes})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Invoker{runner: runner, observationProfileRevision: config.ObservationProfileRevision, ocrProfileRevision: config.OCRProfileRevision, modelID: config.ModelID, modelRevision: config.ModelRevision, modelArtifactHash: config.ModelArtifactHash, maxInputBytes: config.MaxInputBytes, maxOutputBytes: config.MaxOutputBytes}, nil
}

func (i *Invoker) Extract(ctx context.Context, format string, document []byte) (*ocrparser.Result, error) {
	if i == nil || i.runner == nil || (format != ocrparser.FormatPNG && format != ocrparser.FormatJPEG) || len(document) == 0 || len(document) > i.maxInputBytes {
		return nil, ErrExtractionFailed
	}
	raw, err := i.runner.Run(ctx, sandbox.KindOCR, []string{
		"--format=" + format,
		"--observation-profile-revision=" + i.observationProfileRevision,
		"--ocr-profile-revision=" + i.ocrProfileRevision,
		"--model-id=" + i.modelID,
		"--model-revision=" + i.modelRevision,
		"--model-artifact-hash=" + i.modelArtifactHash,
		"--max-input-bytes=" + strconv.Itoa(i.maxInputBytes),
		"--max-output-bytes=" + strconv.Itoa(i.maxOutputBytes),
		"--max-pages=" + strconv.Itoa(MaxPages),
		"--max-tokens=" + strconv.Itoa(MaxTokens),
	}, document)
	if err != nil {
		return nil, ErrExtractionFailed
	}
	result, err := ocrparser.Parse(raw, format)
	if err != nil || result.Parser.ArtifactHash != i.runner.ArtifactHash() || result.Parser.ObservationProfileRevision != i.observationProfileRevision || result.OCR.ProfileRevision != i.ocrProfileRevision || result.OCR.ModelID != i.modelID || result.OCR.ModelRevision != i.modelRevision || result.OCR.ArtifactHash != i.modelArtifactHash {
		return nil, ErrExtractionFailed
	}
	return result, nil
}
