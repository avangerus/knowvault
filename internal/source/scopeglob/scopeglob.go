// Package scopeglob implements the single bounded scope-glob-v1 matcher shared
// by source control-plane validation and connector runtimes.
package scopeglob

import (
	"errors"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/pathcanon"
)

const (
	Version           = "scope-glob-v1"
	maximumPatterns   = 128
	maximumBytes      = pathcanon.MaxBytes
	maximumSegments   = pathcanon.MaxSegments
	maximumMatchSteps = 4 << 20
)

type CaseMode uint8

const (
	CaseSensitive CaseMode = iota
	CaseWindows
)

type ErrorCode string

const (
	CodeConfigInvalid  ErrorCode = "SCOPE_GLOB_CONFIG_INVALID"
	CodePatternInvalid ErrorCode = "SCOPE_GLOB_PATTERN_INVALID"
	CodePathInvalid    ErrorCode = "SCOPE_GLOB_PATH_INVALID"
	CodeMatchLimit     ErrorCode = "SCOPE_GLOB_MATCH_LIMIT"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string {
	if value == nil || value.code == "" {
		return string(CodeConfigInvalid)
	}
	return string(value.code)
}

func (Error) String() string   { return "scopeglob.Error{[REDACTED]}" }
func (Error) GoString() string { return "scopeglob.Error{[REDACTED]}" }

func CodeOf(err error) ErrorCode {
	var scopeError *Error
	if errors.As(err, &scopeError) && scopeError != nil {
		return scopeError.code
	}
	return CodeConfigInvalid
}

type atomKind uint8

const (
	literalAtom atomKind = iota + 1
	starAtom
	questionAtom
)

type atom struct {
	kind    atomKind
	literal rune
}

type compiledSegment struct {
	globstar bool
	atoms    []atom
}

type compiledPattern []compiledSegment

// Matcher is immutable after Compile. Its private representation prevents a
// caller from changing validated patterns or substituting another glob engine.
type Matcher struct {
	include  []compiledPattern
	exclude  []compiledPattern
	mode     CaseMode
	compiled bool
}

func (Matcher) String() string   { return "scopeglob.Matcher{[REDACTED]}" }
func (Matcher) GoString() string { return "scopeglob.Matcher{[REDACTED]}" }

func Compile(include, exclude []string, mode CaseMode) (*Matcher, error) {
	if mode != CaseSensitive && mode != CaseWindows || len(include) > maximumPatterns || len(exclude) > maximumPatterns {
		return nil, newError(CodeConfigInvalid)
	}
	compiledIncludes, err := compilePatterns(include, mode)
	if err != nil {
		return nil, err
	}
	compiledExcludes, err := compilePatterns(exclude, mode)
	if err != nil {
		return nil, err
	}
	return &Matcher{include: compiledIncludes, exclude: compiledExcludes, mode: mode, compiled: true}, nil
}

func (matcher *Matcher) Match(path string) (bool, error) {
	if matcher == nil || !matcher.compiled || (matcher.mode != CaseSensitive && matcher.mode != CaseWindows) {
		return false, newError(CodeConfigInvalid)
	}
	segments, err := canonicalSegments(path, CodePathInvalid, false, matcher.mode)
	if err != nil {
		return false, err
	}
	budget := matchBudget{remaining: maximumMatchSteps}
	for _, pattern := range matcher.exclude {
		matched, withinLimit := matchPattern(pattern, segments, matcher.mode, &budget)
		if !withinLimit {
			return false, newError(CodeMatchLimit)
		}
		if matched {
			return false, nil
		}
	}
	if len(matcher.include) == 0 {
		return true, nil
	}
	for _, pattern := range matcher.include {
		matched, withinLimit := matchPattern(pattern, segments, matcher.mode, &budget)
		if !withinLimit {
			return false, newError(CodeMatchLimit)
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func compilePatterns(patterns []string, mode CaseMode) ([]compiledPattern, error) {
	result := make([]compiledPattern, 0, len(patterns))
	for _, raw := range patterns {
		segments, err := canonicalSegments(raw, CodePatternInvalid, true, mode)
		if err != nil {
			return nil, err
		}
		pattern := make(compiledPattern, 0, len(segments))
		for _, segment := range segments {
			if segment == "**" {
				pattern = append(pattern, compiledSegment{globstar: true})
				continue
			}
			if strings.Contains(segment, "**") {
				return nil, newError(CodePatternInvalid)
			}
			atoms := make([]atom, 0, utf8.RuneCountInString(segment))
			for _, character := range segment {
				switch character {
				case '*':
					atoms = append(atoms, atom{kind: starAtom})
				case '?':
					atoms = append(atoms, atom{kind: questionAtom})
				case '\\', '!', '[', ']', '{', '}':
					return nil, newError(CodePatternInvalid)
				default:
					atoms = append(atoms, atom{kind: literalAtom, literal: character})
				}
			}
			pattern = append(pattern, compiledSegment{atoms: atoms})
		}
		result = append(result, pattern)
	}
	return result, nil
}

// canonicalSegments delegates to the single normative pathcanon implementation
// so the matcher, the folder connector and the catalog share one path/pattern
// semantics; it only maps the shared sentinel to this package's typed code.
func canonicalSegments(raw string, code ErrorCode, pattern bool, mode CaseMode) ([]string, error) {
	var segments []string
	var err error
	if pattern {
		segments, err = pathcanon.Pattern(raw, pathcanonCase(mode))
	} else {
		segments, err = pathcanon.Path(raw, pathcanonCase(mode))
	}
	if err != nil {
		return nil, newError(code)
	}
	return segments, nil
}

func pathcanonCase(mode CaseMode) pathcanon.Case {
	if mode == CaseWindows {
		return pathcanon.CaseWindows
	}
	return pathcanon.CaseSensitive
}

type matchBudget struct{ remaining int }

func (budget *matchBudget) take() bool {
	if budget == nil || budget.remaining <= 0 {
		return false
	}
	budget.remaining--
	return true
}

func matchPattern(pattern compiledPattern, path []string, mode CaseMode, budget *matchBudget) (bool, bool) {
	rows, columns := len(pattern)+1, len(path)+1
	dp := make([]bool, rows*columns)
	dp[0] = true
	index := func(row, column int) int { return row*columns + column }
	for row := 0; row < len(pattern); row++ {
		for column := 0; column <= len(path); column++ {
			if !budget.take() {
				return false, false
			}
			if !dp[index(row, column)] {
				continue
			}
			segment := pattern[row]
			if segment.globstar {
				dp[index(row+1, column)] = true
				if column < len(path) {
					dp[index(row, column+1)] = true
				}
				continue
			}
			if column < len(path) {
				matched, withinLimit := matchSegment(segment.atoms, path[column], mode, budget)
				if !withinLimit {
					return false, false
				}
				if matched {
					dp[index(row+1, column+1)] = true
				}
			}
		}
	}
	return dp[index(len(pattern), len(path))], true
}

func matchSegment(pattern []atom, value string, mode CaseMode, budget *matchBudget) (bool, bool) {
	characters := []rune(value)
	patternIndex, valueIndex := 0, 0
	starIndex, starValueIndex := -1, 0
	for valueIndex < len(characters) {
		if !budget.take() {
			return false, false
		}
		if patternIndex < len(pattern) && pattern[patternIndex].kind == questionAtom {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex].kind == literalAtom &&
			equalRune(pattern[patternIndex].literal, characters[valueIndex], mode) {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex].kind == starAtom {
			starIndex = patternIndex
			starValueIndex = valueIndex
			patternIndex++
			continue
		}
		if starIndex < 0 {
			return false, true
		}
		starValueIndex++
		valueIndex = starValueIndex
		patternIndex = starIndex + 1
	}
	for patternIndex < len(pattern) && pattern[patternIndex].kind == starAtom {
		if !budget.take() {
			return false, false
		}
		patternIndex++
	}
	return patternIndex == len(pattern), true
}

func equalRune(left, right rune, mode CaseMode) bool {
	if mode == CaseSensitive {
		return left == right
	}
	return strings.EqualFold(string(left), string(right))
}

func newError(code ErrorCode) error { return &Error{code: code} }
