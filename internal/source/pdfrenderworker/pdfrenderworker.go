// Package pdfrenderworker is a typed qualification façade for the isolated
// Isolated PDF renderer. Production composition must submit the same closed
// dispatcher request through DispatcherV2; this package owns no persistence,
// tenant or source authority and is useful for exercising the result boundary.
package pdfrenderworker

import (
	"context"
	"errors"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
	"knowvault.local/verified-workspace/internal/source/sandbox"
)

var (
	ErrExtractionFailed = errors.New("pdfrenderworker: render failed")
	ErrInvalidConfig    = errors.New("pdfrenderworker: invalid sandbox configuration")
)

const (
	MaxInputBytes  = 64 << 20
	MaxOutputBytes = 16 << 20
	MaxPages       = 10000
	MaxPixels      = 50_000_000
)

type Config struct {
	Command                 []string
	ArtifactHash            string
	RendererProfileRevision string
	Timeout                 time.Duration
	MaxInputBytes           int
	MaxOutputBytes          int
	MaxPages                int
	MaxDecodedPixels        int
}

type Invoker struct {
	runner           *sandbox.Runner
	profileRevision  string
	maxInputBytes    int
	maxOutputBytes   int
	maxPages         int
	maxDecodedPixels int
}

func New(config Config) (*Invoker, error) {
	if config.RendererProfileRevision == "" || config.MaxInputBytes < 1 || config.MaxInputBytes > MaxInputBytes || config.MaxOutputBytes < 1 || config.MaxOutputBytes > MaxOutputBytes || config.MaxPages < 1 || config.MaxPages > MaxPages || config.MaxDecodedPixels < 1 || config.MaxDecodedPixels > MaxPixels {
		return nil, ErrInvalidConfig
	}
	runner, err := sandbox.New(sandbox.Config{Kind: sandbox.KindPDFRender, Command: config.Command, ArtifactHash: config.ArtifactHash, Timeout: config.Timeout, MaxResultBytes: config.MaxOutputBytes})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Invoker{runner: runner, profileRevision: config.RendererProfileRevision, maxInputBytes: config.MaxInputBytes, maxOutputBytes: config.MaxOutputBytes, maxPages: config.MaxPages, maxDecodedPixels: config.MaxDecodedPixels}, nil
}

func (i *Invoker) Extract(ctx context.Context, format string, document []byte) (*pdfrenderparser.Result, error) {
	if i == nil || i.runner == nil || format != pdfrenderparser.FormatPDF || len(document) == 0 || len(document) > i.maxInputBytes {
		return nil, ErrExtractionFailed
	}
	raw, err := i.runner.Run(ctx, sandbox.KindPDFRender, []string{
		"--format=" + pdfrenderparser.FormatPDF,
		"--renderer-profile-revision=" + i.profileRevision,
		"--max-input-bytes=" + strconv.Itoa(i.maxInputBytes),
		"--max-output-bytes=" + strconv.Itoa(i.maxOutputBytes),
		"--max-pages=" + strconv.Itoa(i.maxPages),
		"--max-decoded-pixels=" + strconv.Itoa(i.maxDecodedPixels),
	}, document)
	if err != nil {
		return nil, ErrExtractionFailed
	}
	result, err := pdfrenderparser.Parse(raw, i.profileRevision, i.runner.ArtifactHash())
	if err != nil {
		return nil, ErrExtractionFailed
	}
	return result, nil
}
