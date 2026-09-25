package governedquery

// staticgate.go is cards S3.2d and S3.2e's deterministic pre-EXPLAIN refusal
// gate. The least-privilege role and the read-only transaction remain the
// security boundary (ADR-0089 §3, ADR-0097 §3); this gate exists because two
// classes of statement are dangerous even for a role that holds only SELECT:
//
//   - a statement that can change a session setting while it runs
//     (`set_config`), which would let an agent-authored statement widen the
//     server-owned resource bounds of its own transaction;
//   - a statement that inspects or signals other sessions, reads server files
//     or large objects, or executes a query recursively (`pg_stat_*`,
//     `pg_locks`, `pg_blocking_pids`, `pg_safe_snapshot_*`, `pg_cancel_backend`,
//     `pg_sleep*`, `lo_*`, `pg_read_*`, `pg_ls_*`, `query_to_xml` and its
//     siblings).
//
// Card S3.2e makes the gate exact in both directions:
//
//   - every lexical form the gate does not model is refused before EXPLAIN:
//     a dollar-quoted literal, any `$` outside a quoted identifier, an E''
//     escape string, a backslash inside a string literal and the U& Unicode
//     escape introducer. After those refusals the token stream is the one
//     PostgreSQL sees, so a name is matched only where PostgreSQL names it;
//   - a forbidden function family is refused only where the identifier is a
//     call (the name immediately followed by an open parenthesis). A column or
//     alias that merely shares a spelling (`set`, `reset`, `lo_amount`,
//     `lo_bound`) is ordinary SQL, and the benign JSON builders
//     (`row_to_json`, `array_to_json`, `json_agg`) are not the XML
//     query-executor's family.
//
// The gate is still deliberately conservative: session- and server-inspection
// names that are relations as often as functions (`pg_stat_*`, `pg_locks`) are
// refused wherever they appear, because a bare name cannot tell a view from a
// function. A false refusal is a cheap closed error; a false admission would
// not be, because the plan walk cannot see a side effect the planner does not
// print.

import "strings"

// forbiddenIdentifierPrefixes is the closed list of name prefixes refused as an
// identifier anywhere in the statement. Every pg_stat_ name is refused: the
// family is as much a set of inspection views (pg_stat_activity) as it is a set
// of functions (pg_stat_get_*), and a view cannot be told from a function by the
// bare name. pg_lock covers the pg_locks view and its pg_lock_status() support
// function; pg_safe_snapshot_ covers the snapshot-blocking inspection helpers.
var forbiddenIdentifierPrefixes = []string{
	"pg_stat_",
	"pg_lock",
	"pg_safe_snapshot_",
}

// forbiddenIdentifiers is the closed exact-name list refused as an identifier
// anywhere in the statement.
var forbiddenIdentifiers = map[string]struct{}{
	"pg_blocking_pids": {},
}

// forbiddenFunctionPrefixes is the closed function-name prefix deny-list. It is
// matched only against an identifier that names a call (the identifier
// immediately followed by an open parenthesis).
var forbiddenFunctionPrefixes = []string{
	// Cross-session signalling and identity.
	"pg_cancel_backend", "pg_terminate_backend", "pg_backend_pid",
	// Advisory locks.
	"pg_advisory_", "pg_try_advisory_",
	// Delays.
	"pg_sleep",
	// Large objects.
	"lo_",
	// Server files and directories.
	"pg_read_", "pg_ls_",
}

// forbiddenFunctionExact is the closed exact-name deny-list for calls. It is
// checked in addition to the prefixes so a spelling that shares a prefix with a
// benign name is still refused.
var forbiddenFunctionExact = map[string]struct{}{
	"set_config": {},
}

// forbiddenFunctionSubstrings catches the query-executing XML family and its
// `_and_xmlschema` siblings wherever the family token appears in a call. The
// `_to_json` spelling is deliberately absent: it is not a PostgreSQL function
// and it refused the benign JSON builders.
var forbiddenFunctionSubstrings = []string{"_to_xml", "_and_xmlschema"}

// staticGate scans one already-shape-checked statement and refuses an unmodeled
// lexical form, a setting change or a forbidden session/file/query family. It
// returns the package's static refusal (CodeInvalid); the scoped entry point
// maps it to SQL_REJECTED_STATIC.
func staticGate(sqlText string) error {
	tokens, err := sqlTokenize(sqlText)
	if err != nil {
		return err
	}
	for index, token := range tokens {
		if token.kind != sqlTokenIdentifier {
			continue
		}
		name := token.text
		if _, forbidden := forbiddenIdentifiers[name]; forbidden {
			return &Error{code: CodeInvalid}
		}
		for _, prefix := range forbiddenIdentifierPrefixes {
			if strings.HasPrefix(name, prefix) {
				return &Error{code: CodeInvalid}
			}
		}
		// Everything below is a function family: the name must actually name a
		// call, which is the identifier token immediately followed by "(".
		if !identifierIsCall(tokens, index) {
			continue
		}
		if _, forbidden := forbiddenFunctionExact[name]; forbidden {
			return &Error{code: CodeInvalid}
		}
		for _, prefix := range forbiddenFunctionPrefixes {
			if strings.HasPrefix(name, prefix) {
				return &Error{code: CodeInvalid}
			}
		}
		for _, fragment := range forbiddenFunctionSubstrings {
			if strings.Contains(name, fragment) {
				return &Error{code: CodeInvalid}
			}
		}
	}
	return nil
}

// identifierIsCall reports whether the identifier at index is a function call:
// the next token must be the open parenthesis. Whitespace and string literals
// produce no token, so `lo_import (` and `lo_import('x')` are both calls while a
// bare column named `lo_amount` is not.
func identifierIsCall(tokens []sqlToken, index int) bool {
	return index+1 < len(tokens) &&
		tokens[index+1].kind == sqlTokenPunctuation &&
		tokens[index+1].text == "("
}

// sqlTokenKind distinguishes the two tokens the deny rules need: an identifier
// (already decoded and case-folded) and a single punctuation byte.
type sqlTokenKind uint8

const (
	sqlTokenIdentifier sqlTokenKind = iota
	sqlTokenPunctuation
)

// sqlToken is one lexed token. String literals and whitespace produce no token:
// a value can never name a function, a setting or a relation.
type sqlToken struct {
	kind sqlTokenKind
	text string
}

// sqlTokenize lexes one accepted statement. It returns the identifier tokens
// (quoted identifiers decoded, every identifier case-folded) and the
// punctuation tokens. Every lexical form the gate does not model is a refusal,
// so the returned stream is the one PostgreSQL sees:
//
//   - a dollar-quoted literal and any `$` outside a quoted identifier;
//   - an E'' or e'' escape-string literal;
//   - a backslash or a `$` inside a string literal;
//   - the U& Unicode escape introducer;
//   - an unterminated string literal or quoted identifier.
func sqlTokenize(sqlText string) ([]sqlToken, error) {
	tokens := make([]sqlToken, 0, 16)
	index := 0
	for index < len(sqlText) {
		character := sqlText[index]
		switch {
		case isSQLSpace(character):
			index++
		case character == '\'':
			next, err := skipStringLiteral(sqlText, index)
			if err != nil {
				return nil, err
			}
			index = next
		case character == '"':
			value, next, err := readQuotedIdentifier(sqlText, index)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, sqlToken{kind: sqlTokenIdentifier, text: value})
			index = next
		case character == '$':
			// A dollar sign is modelled only inside a quoted identifier
			// (handled above): anywhere else it starts a dollar-quoted literal
			// or a parameter placeholder.
			return nil, &Error{code: CodeInvalid}
		case isIdentifierStart(character):
			start := index
			for index < len(sqlText) && isIdentifierByte(sqlText[index]) {
				index++
			}
			name := strings.ToLower(sqlText[start:index])
			if name == "e" && index < len(sqlText) && sqlText[index] == '\'' {
				// An E'' escape string applies its own backslash rules, which
				// the gate does not model.
				return nil, &Error{code: CodeInvalid}
			}
			if name == "u" && index < len(sqlText) && sqlText[index] == '&' {
				// The U& Unicode escape introducer (U&'...' / U&"...") decodes
				// escapes the gate must not try to model.
				return nil, &Error{code: CodeInvalid}
			}
			tokens = append(tokens, sqlToken{kind: sqlTokenIdentifier, text: name})
		default:
			tokens = append(tokens, sqlToken{kind: sqlTokenPunctuation, text: string(character)})
			index++
		}
	}
	return tokens, nil
}

// skipStringLiteral returns the index just past a single-quoted literal,
// handling the doubled '' escape. A backslash or a `$` inside the literal is
// refused: the gate does not model escape processing, and a dollar sign is
// admitted only inside a quoted identifier. An unterminated literal is refused
// rather than guessed at.
func skipStringLiteral(sqlText string, start int) (int, error) {
	index := start + 1
	for index < len(sqlText) {
		switch sqlText[index] {
		case '\\', '$':
			return 0, &Error{code: CodeInvalid}
		case '\'':
			if index+1 < len(sqlText) && sqlText[index+1] == '\'' {
				index += 2
				continue
			}
			return index + 1, nil
		}
		index++
	}
	return 0, &Error{code: CodeInvalid}
}

// readQuotedIdentifier decodes one double-quoted identifier. It returns the
// lowercased content and the index just past the closing quote, or a refusal
// when the quoting is unbalanced. A `$` is ordinary content here, which is the
// one place PostgreSQL admits it in a name.
func readQuotedIdentifier(sqlText string, start int) (string, int, error) {
	var builder strings.Builder
	index := start + 1
	for index < len(sqlText) {
		if sqlText[index] == '"' {
			if index+1 < len(sqlText) && sqlText[index+1] == '"' {
				builder.WriteByte('"')
				index += 2
				continue
			}
			return strings.ToLower(builder.String()), index + 1, nil
		}
		builder.WriteByte(sqlText[index])
		index++
	}
	return "", 0, &Error{code: CodeInvalid}
}

func isSQLSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == '\v'
}

func isIdentifierStart(value byte) bool {
	return value == '_' || (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

// isIdentifierByte deliberately excludes `$`: PostgreSQL admits it in an
// unquoted identifier, but the card refuses every `$` outside a quoted
// identifier, so the lexer stops there and the main loop refuses it.
func isIdentifierByte(value byte) bool {
	return isIdentifierStart(value) || (value >= '0' && value <= '9')
}
