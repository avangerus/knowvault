package governedquery

// staticgate.go is card S3.2d's deterministic pre-EXPLAIN refusal gate. The
// least-privilege role and the read-only transaction remain the security
// boundary (ADR-0089 §3, ADR-0097 §3); this gate exists because two classes of
// statement are dangerous even for a role that holds only SELECT:
//
//   - a statement that can change a session setting while it runs
//     (`set_config`, or any `SET` form), which would let an agent-authored
//     statement widen the server-owned resource bounds of its own transaction;
//   - a statement that inspects or signals other sessions, reads server files
//     or large objects, or executes a query recursively (`pg_stat_get_*`,
//     `pg_cancel_backend`, `pg_sleep*`, `lo_*`, `pg_read_*`, `pg_ls_*`,
//     `query_to_xml` and its siblings).
//
// The gate is deterministic and deliberately conservative: it tokenizes the
// statement, case-folds every identifier, strips double quotes and schema
// qualifiers, and refuses a match anywhere. A false refusal is a cheap closed
// error; a false admission would not be, because the plan walk cannot see a
// side effect the planner does not print.
//
// Unicode-escaped identifiers (`U&"..."`, `U&'...'`) are refused outright:
// their decoding rules are exactly the kind of spelling game the gate must not
// try to play.

import "strings"

// forbiddenFunctionPrefixes is the closed function-name prefix deny-list. It is
// matched against the case-folded, unquoted, schema-stripped identifier.
var forbiddenFunctionPrefixes = []string{
	// Session observation: every pg_stat_get_* function and the
	// pg_stat_activity-style helpers and views.
	"pg_stat_",
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

// forbiddenFunctionExact is the closed exact-name deny-list. It is checked in
// addition to the prefixes so a spelling that shares a prefix with a benign
// name is still refused.
var forbiddenFunctionExact = map[string]struct{}{
	"set_config": {},
}

// forbiddenFunctionSubstrings catches the query-executing XML/JSON family and
// its `_and_xmlschema` siblings wherever the family token appears.
var forbiddenFunctionSubstrings = []string{"_to_xml", "_to_json", "_and_xmlschema"}

// forbiddenSettingTokens refuses any statement that can change a setting while
// it runs. `set` covers SET, SET LOCAL and SET SESSION in every spelling,
// including a quoted `"set"` identifier; `reset` is included because RESET is
// the other spelling of the same capability.
var forbiddenSettingTokens = map[string]struct{}{
	"set": {}, "reset": {},
}

// staticGate scans one already-shape-checked statement and refuses a setting
// change or a forbidden function family. It returns the package's static
// refusal (CodeInvalid); the scoped entry point maps it to SQL_REJECTED_STATIC.
func staticGate(sqlText string) error {
	if strings.ContainsAny(sqlText, "\x00") || strings.Contains(sqlText, "u&") || strings.Contains(sqlText, "U&") {
		return &Error{code: CodeInvalid}
	}
	for _, token := range sqlIdentifiers(sqlText) {
		if _, forbidden := forbiddenSettingTokens[token]; forbidden {
			return &Error{code: CodeInvalid}
		}
		if _, forbidden := forbiddenFunctionExact[token]; forbidden {
			return &Error{code: CodeInvalid}
		}
		for _, prefix := range forbiddenFunctionPrefixes {
			if strings.HasPrefix(token, prefix) {
				return &Error{code: CodeInvalid}
			}
		}
		for _, fragment := range forbiddenFunctionSubstrings {
			if strings.Contains(token, fragment) {
				return &Error{code: CodeInvalid}
			}
		}
	}
	return nil
}

// sqlIdentifiers returns every identifier the statement names: an unquoted
// [A-Za-z_][A-Za-z0-9_$]* token, or the decoded content of a double-quoted
// identifier (`""` unescaped), each case-folded. Single-quoted string literals
// are skipped because a value can never name a function or a setting; a schema
// qualifier is simply another identifier in the returned stream, so
// `pg_catalog.set_config` and `"pg_catalog"."set_config"` both yield the
// forbidden `set_config` token. Any statement that does not lex cleanly falls
// back to the whole lowercased text, which can only add refusals, never remove
// them.
func sqlIdentifiers(sqlText string) []string {
	tokens := make([]string, 0, 16)
	index := 0
	for index < len(sqlText) {
		character := sqlText[index]
		switch {
		case character == '\'':
			index = skipSingleQuoted(sqlText, index)
		case character == '"':
			value, next := readQuotedIdentifier(sqlText, index)
			if next < 0 {
				return []string{strings.ToLower(sqlText)}
			}
			tokens = append(tokens, value)
			index = next
		case isIdentifierStart(character):
			start := index
			for index < len(sqlText) && isIdentifierByte(sqlText[index]) {
				index++
			}
			tokens = append(tokens, strings.ToLower(sqlText[start:index]))
		default:
			index++
		}
	}
	return tokens
}

// skipSingleQuoted returns the index just past a single-quoted literal,
// handling the doubled ” escape. An unterminated literal consumes the rest of
// the statement.
func skipSingleQuoted(sqlText string, start int) int {
	index := start + 1
	for index < len(sqlText) {
		if sqlText[index] == '\'' {
			if index+1 < len(sqlText) && sqlText[index+1] == '\'' {
				index += 2
				continue
			}
			return index + 1
		}
		index++
	}
	return len(sqlText)
}

// readQuotedIdentifier decodes one double-quoted identifier. It returns the
// lowercased content and the index just past the closing quote, or next < 0
// when the quoting is unbalanced.
func readQuotedIdentifier(sqlText string, start int) (string, int) {
	var builder strings.Builder
	index := start + 1
	for index < len(sqlText) {
		if sqlText[index] == '"' {
			if index+1 < len(sqlText) && sqlText[index+1] == '"' {
				builder.WriteByte('"')
				index += 2
				continue
			}
			return strings.ToLower(builder.String()), index + 1
		}
		builder.WriteByte(sqlText[index])
		index++
	}
	return "", -1
}

func isIdentifierStart(value byte) bool {
	return value == '_' || (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func isIdentifierByte(value byte) bool {
	return isIdentifierStart(value) || (value >= '0' && value <= '9') || value == '$'
}
