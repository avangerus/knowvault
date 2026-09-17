// Package sandbox is the one hardened process boundary every isolated parser runs
// behind (ADR-0062 §2a/§2d, ADR-0063 §2). Office, text-PDF, PDF rendering and OCR
// share this implementation rather than each carrying its own copy, so a hardening
// property cannot hold for one parser and quietly lapse for another: there is a
// single place where the environment is emptied, the wall clock is enforced and both
// streams are bounded, and the architecture checker asserts those properties there.
//
// It is the capability boundary expressed as a type. Run takes a pinned argv, a few
// bounded flags and a byte slice, and nothing else. There is no parameter, field or
// method through which a tenant id, workspace id, scope id, source-version id,
// database handle, secret, credential, audit sink or job authority could reach the
// sandbox, so the sandbox cannot receive one no matter what a caller intends. The
// package imports no database, audit, jobs or network package, and the checker
// enforces that import list as a closed allowlist.
//
// What crosses outward is equally narrow: stdout is read under a hard byte cap and
// returned as raw bytes for the caller's re-validator to canonicalize. stderr is
// bounded and discarded — a parser diagnostic could carry a fragment of the document,
// and no such fragment may reach a log, an error value or a durable sink. Every
// failure — spawn failure, non-zero exit, timeout, oversized output, a kind that does
// not match the configured one — collapses to the single content-free ErrRunFailed.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// ErrRunFailed is the single content-free sentinel for every failure mode. A caller
// maps it to its own sentinel and quarantines the object; nothing about why the
// sandbox failed, and therefore nothing about the document, escapes.
var ErrRunFailed = errors.New("sandbox: run failed")

// ErrInvalidConfig is returned when a sandbox configuration is not fully pinned.
var ErrInvalidConfig = errors.New("sandbox: invalid sandbox configuration")

// maxStderrBytes bounds the diagnostic stream we drain and drop. It exists only so a
// sandbox that writes endlessly cannot block on a full pipe.
const maxStderrBytes = 4096

// Kind names what a pinned sandbox is allowed to do. It is part of the config and is
// re-asserted on every Run, so a configuration built for one parser cannot be handed
// a different parser's work — an OCR image cannot be asked to observe a DOCX, and a
// renderer cannot be asked to return an observation result.
type Kind string

const (
	KindOffice    Kind = "OFFICE"
	KindPDFText   Kind = "PDF_TEXT"
	KindPDFRender Kind = "PDF_RENDER"
	KindOCR       Kind = "OCR"
)

func (k Kind) valid() bool {
	switch k {
	case KindOffice, KindPDFText, KindPDFRender, KindOCR:
		return true
	}
	return false
}

// Config pins one sandbox. Command is the exact argv of the container runtime plus
// its pinned, digest-addressed image and hardening flags; it is supplied by
// composition, never assembled from source data, and it is never passed through a
// shell.
type Config struct {
	Kind           Kind
	Command        []string
	ArtifactHash   string
	Timeout        time.Duration
	MaxResultBytes int
}

// Runner runs one pinned sandbox. It holds no mutable state, so concurrent runs
// cannot influence one another.
type Runner struct {
	config Config
}

// New validates that the sandbox is fully pinned before any document can be sent to
// it: an unpinned command, an unpinned artifact identity, an unknown kind or an
// unbounded timeout/result size is a configuration error, not a runtime surprise.
func New(config Config) (*Runner, error) {
	if !config.Kind.valid() {
		return nil, ErrInvalidConfig
	}
	if len(config.Command) == 0 || config.Command[0] == "" {
		return nil, ErrInvalidConfig
	}
	if !ValidArtifactHash(config.ArtifactHash) {
		return nil, ErrInvalidConfig
	}
	if config.Timeout <= 0 || config.MaxResultBytes <= 0 {
		return nil, ErrInvalidConfig
	}
	command := make([]string, len(config.Command))
	copy(command, config.Command)
	config.Command = command
	return &Runner{config: config}, nil
}

// Kind reports what this sandbox is pinned to do.
func (r *Runner) Kind() Kind { return r.config.Kind }

// ArtifactHash reports the pinned artifact identity. A caller re-checks the identity
// the sandbox declares in its result against this value, so a different build is
// refused rather than published under the pinned profile.
func (r *Runner) ArtifactHash() string { return r.config.ArtifactHash }

// Run sends exactly one transient input to the sandbox and returns its raw stdout.
// kind must equal the configured kind. args are the already-validated flags the
// caller's protocol defines; they are appended to the pinned argv and never
// interpreted by a shell.
func (r *Runner) Run(ctx context.Context, kind Kind, args []string, stdin []byte) ([]byte, error) {
	if kind != r.config.Kind || len(stdin) == 0 {
		return nil, ErrRunFailed
	}

	runCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	argv := append([]string{}, r.config.Command...)
	argv = append(argv, args...)

	command := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	command.Stdin = bytes.NewReader(stdin)
	// The environment is emptied rather than inherited: an inherited variable could
	// carry a credential or an endpoint into a hostile data-plane component.
	command.Env = []string{}
	command.WaitDelay = time.Second

	var stdout bytes.Buffer
	// The result stream is capped and a breach aborts: an oversized result is a
	// refusal, not something to truncate into a shorter "valid" result. The
	// diagnostic stream is capped and drained: a chatty sandbox must not be able to
	// fail an otherwise correct run, and nothing it writes there is retained.
	command.Stdout = &boundedWriter{limit: r.config.MaxResultBytes, into: &stdout}
	command.Stderr = &boundedWriter{limit: maxStderrBytes, discardOverflow: true}

	if err := command.Run(); err != nil {
		return nil, ErrRunFailed
	}
	if runCtx.Err() != nil {
		return nil, ErrRunFailed
	}
	return stdout.Bytes(), nil
}

// ValidArtifactHash reports whether value is an exact lowercase sha256 identity. Every
// isolated component's identity is pinned in this one form, so a caller cannot accept
// a shorter or differently-cased value by writing its own check.
func ValidArtifactHash(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || value[:len(prefix)] != prefix {
		return false
	}
	for _, c := range value[len(prefix):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// boundedWriter keeps a stream under a hard cap. With into nil the bytes are counted
// and dropped, which is how the diagnostic stream is drained without ever being
// retained: nothing the sandbox writes there can reach an error value or a log. With
// discardOverflow set the cap is enforced silently (the stream keeps draining);
// otherwise a breach is reported so the run fails closed.
type boundedWriter struct {
	limit           int
	written         int
	discardOverflow bool
	into            *bytes.Buffer
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.written
	chunk := p
	if len(chunk) > remaining {
		chunk = chunk[:max(remaining, 0)]
	}
	w.written += len(chunk)
	if w.into != nil && len(chunk) > 0 {
		w.into.Write(chunk)
	}
	if len(chunk) < len(p) && !w.discardOverflow {
		return len(chunk), io.ErrShortWrite
	}
	return len(p), nil
}
