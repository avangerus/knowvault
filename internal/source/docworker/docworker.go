// Package docworker invokes the isolated office parser sandbox (ADR-0062) for one
// transient document and returns a re-validated extraction.
//
// It is a thin typed façade over internal/source/sandbox, which owns the hardened
// process boundary shared by every isolated parser. What lives here is only what is
// specific to Office: the closed set of formats this sandbox answers for, the flag
// set of the document-parser protocol, and the re-validation of the returned bytes
// through docparser. Nothing about the environment, the wall clock or the stream
// bounds is restated — a second copy is a second thing that can drift.
//
// The capability narrowness is unchanged: Extract takes a format and a byte slice
// and nothing else, so no tenant id, database handle, secret or job authority can
// reach the sandbox. Every failure collapses to the single content-free
// ErrExtractionFailed and the caller quarantines the object with no fallback.
package docworker

import (
	"context"
	"errors"
	"strconv"
	"time"

	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/sandbox"
)

// ErrExtractionFailed is the single content-free sentinel for every failure mode.
var ErrExtractionFailed = errors.New("docworker: extraction failed")

// ErrInvalidConfig is returned when a sandbox configuration is not fully pinned.
var ErrInvalidConfig = errors.New("docworker: invalid sandbox configuration")

// Config pins one office sandbox. Command is the exact argv of the container runtime
// plus its pinned, digest-addressed image and hardening flags; it is supplied by
// composition, never assembled from source data, and never passed through a shell.
type Config struct {
	Command                    []string
	ArtifactHash               string
	ObservationProfileRevision string
	Timeout                    time.Duration
	MaxResultBytes             int
}

// Invoker runs one pinned office sandbox. It holds no mutable state, so concurrent
// extractions cannot influence one another.
type Invoker struct {
	runner                     *sandbox.Runner
	observationProfileRevision string
}

// New validates that the sandbox is fully pinned before any document can be sent to
// it: an unpinned command, an unpinned artifact identity, an unpinned observation
// profile or an unbounded timeout/result size is a configuration error, not a
// runtime surprise.
func New(config Config) (*Invoker, error) {
	if config.ObservationProfileRevision == "" {
		return nil, ErrInvalidConfig
	}
	runner, err := sandbox.New(sandbox.Config{
		Kind:           sandbox.KindOffice,
		Command:        config.Command,
		ArtifactHash:   config.ArtifactHash,
		Timeout:        config.Timeout,
		MaxResultBytes: config.MaxResultBytes,
	})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Invoker{runner: runner, observationProfileRevision: config.ObservationProfileRevision}, nil
}

// Extract sends exactly one transient document to the sandbox and returns the
// canonicalized, re-validated result. format is the canonical format the runtime
// dispatched; the sandbox must answer for that format and no other.
func (i *Invoker) Extract(ctx context.Context, format string, document []byte) (*docparser.Result, error) {
	switch format {
	case docparser.FormatDOCX, docparser.FormatPPTX, docparser.FormatXLSX:
	default:
		return nil, ErrExtractionFailed
	}

	raw, err := i.runner.Run(ctx, sandbox.KindOffice, []string{
		"--format=" + format,
		"--observation-profile-revision=" + i.observationProfileRevision,
		"--max-input-bytes=" + strconv.Itoa(len(document)),
		"--max-units=" + strconv.Itoa(docparser.MaxTextUnits),
		"--max-unit-bytes=" + strconv.Itoa(docparser.MaxUnitRawBytes),
		"--max-total-text-bytes=" + strconv.Itoa(docparser.MaxObjectTextBytes),
	}, document)
	if err != nil {
		return nil, ErrExtractionFailed
	}

	result, err := docparser.Parse(raw, format)
	if err != nil {
		return nil, ErrExtractionFailed
	}
	// The sandbox must be the exact pinned artifact and profile. A different build
	// would produce a different observation and therefore a different Extraction
	// identity; it is refused rather than published under the pinned profile.
	if result.Parser.ArtifactHash != i.runner.ArtifactHash() ||
		result.Parser.ObservationProfileRevision != i.observationProfileRevision {
		return nil, ErrExtractionFailed
	}
	return result, nil
}
