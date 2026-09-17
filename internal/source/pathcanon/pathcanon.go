// Package pathcanon is the one normative canonicalization for source paths and
// scope-glob patterns. The same relative-root, separator, Unicode-NFC,
// dot-segment, Windows-special-name and per-platform case semantics are used by
// the scope-glob matcher (server-side validation and the connector), by the
// folder connector's read path, and by the catalog object identity. A single
// implementation is what makes a durable SourceObject identity canonical rather
// than "equivalent by convention": the same bytes are accepted or rejected, and
// canonicalized identically, no matter which layer computes them.
package pathcanon

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Case selects the platform-appropriate segment rules. Git, POSIX and
// S3-compatible sources are case-sensitive; Windows adds simple-fold reserved
// device names, an ADS-colon ban and trailing dot/space rejection.
type Case uint8

const (
	CaseSensitive Case = iota + 1
	CaseWindows
)

// MaxBytes and MaxSegments bound a single path or pattern. They match the
// scope-glob limits so a path accepted by the matcher, the connector and the
// catalog is the same set of paths.
const (
	MaxBytes    = 4096
	MaxSegments = 256
)

// ErrInvalidPath is the single sentinel every caller maps to its own typed code.
var ErrInvalidPath = errors.New("pathcanon: path is not canonical")

func (mode Case) valid() bool { return mode == CaseSensitive || mode == CaseWindows }

// Path validates a relative path (no glob structure) and returns its canonical
// slash-separated segments. The input is already the canonical form when it
// passes: pathcanon does not rewrite, it validates and splits.
func Path(raw string, mode Case) ([]string, error) { return canonicalSegments(raw, mode, false) }

// Pattern validates a scope-glob pattern and returns its canonical segments. It
// permits `*` and `?` as metacharacters and rejects extglob and trailing
// whitespace, but is otherwise identical to Path.
func Pattern(raw string, mode Case) ([]string, error) { return canonicalSegments(raw, mode, true) }

func canonicalSegments(raw string, mode Case, pattern bool) ([]string, error) {
	if !mode.valid() || raw == "" || !utf8.ValidString(raw) || len(raw) > MaxBytes ||
		strings.ContainsRune(raw, '\\') || strings.HasPrefix(raw, "/") || strings.HasSuffix(raw, "/") ||
		raw != norm.NFC.String(raw) ||
		(pattern && strings.TrimRightFunc(raw, unicode.IsSpace) != raw) ||
		(mode == CaseWindows && strings.ContainsRune(raw, ':')) {
		return nil, ErrInvalidPath
	}
	segments := strings.Split(raw, "/")
	if len(segments) == 0 || len(segments) > MaxSegments {
		return nil, ErrInvalidPath
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return nil, ErrInvalidPath
		}
		if mode == CaseWindows && !validWindowsSegment(segment, pattern) {
			return nil, ErrInvalidPath
		}
		if pattern && (strings.Contains(segment, "@(") || strings.Contains(segment, "+(") ||
			strings.Contains(segment, "?(") || strings.Contains(segment, "*(") || strings.Contains(segment, "!(")) {
			return nil, ErrInvalidPath
		}
		for _, character := range segment {
			if character == 0 || unicode.IsControl(character) {
				return nil, ErrInvalidPath
			}
		}
	}
	return segments, nil
}

// validWindowsSegment rejects a trailing dot or space, the forbidden character
// set, and the reserved device names with any extension. For a pattern segment
// `*` and `?` remain valid metacharacters.
func validWindowsSegment(segment string, pattern bool) bool {
	if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
		return false
	}
	forbidden := `<>"|`
	if !pattern {
		forbidden += `*?`
	}
	if strings.ContainsAny(segment, forbidden) {
		return false
	}
	base, _, _ := strings.Cut(segment, ".")
	if strings.ContainsAny(base, "*?") {
		return true
	}
	for _, name := range []string{"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"} {
		if strings.EqualFold(base, name) {
			return false
		}
	}
	return true
}
