package question

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Card D-6a: the answer the user reads is only the answer. A self-label at the
// start of a line ("Ответ:", "Уточнение:", "Ограничение охвата:", "Answer:")
// and the technical location of a read (connection or source id, file path,
// version id, observation timestamp, raw relation or column name) are
// presentation, never content. The model is asked to rewrite an answer that
// carries them; when the forced final turn cannot rewrite any more, the
// submission is cleaned instead of being thrown away, so a form problem never
// costs the user the answer that was already gathered.
//
// The rule holds for every question, including one about the data structure
// itself ("which tables, columns or fields exist", "what data is in the
// database"): there the person expects business words too, and the registered
// relation and column names belong to the citations, not to the prose.
// Everything here is derived from this run's own workspace context and tool
// results, so it holds for any workspace and never quotes one question set's
// wording or its synthetic data.

// toolLoopAnswerLabelPrefix matches a short self-label at the start of a line:
// two to forty letters, digits, spaces or hyphens followed by a colon. It is
// the general form of the question set's own no_label_prefix rule and never
// matches a colon in the middle of a sentence.
var toolLoopAnswerLabelPrefix = regexp.MustCompile(`(?m)^[ \t]*[\p{L}\p{N}_][\p{L}\p{N}_ \-]{1,39}:[ \t]*`)

// toolLoopAnswerPathMarker matches a file path: at least one directory
// separator and a dotted file name.
var toolLoopAnswerPathMarker = regexp.MustCompile(`\b[A-Za-z0-9_.\-]+(?:[/\\][A-Za-z0-9_.\-]+)+\.[A-Za-z0-9]{1,8}\b`)

// toolLoopAnswerFileNameMarker matches a bare document file name: an ASCII name
// with a document extension and no directory separator. A path is already
// removed whole by toolLoopAnswerPathMarker; this catches the short form a
// model uses when it lists an object by its file name instead of by its human
// name. The extension whitelist keeps ordinary prose and decimal numbers out.
var toolLoopAnswerFileNameMarker = regexp.MustCompile(`(?i)\b[A-Za-z0-9][A-Za-z0-9_.\-]*\.(?:md|txt|json|csv|tsv|pdf|docx?|xlsx?|pptx?|rtf|odt|ods|odp|html?|xml|ya?ml|log|zip)\b`)

// toolLoopAnswerTimestampMarker matches an observation timestamp (an RFC3339
// date-time), never a plain business date such as a contract's signing day.
var toolLoopAnswerTimestampMarker = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b`)

// toolLoopAnswerIdentifierMarker matches any server-minted typed identifier
// such as conn_..., object_... or sv_...: a lowercase prefix, an underscore and
// a 26-character Crockford base32 ULID.
var toolLoopAnswerIdentifierMarker = regexp.MustCompile(`\b[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}\b`)

// toolLoopAnswerShapedIdentifier matches a bare snake_case identifier: the
// shape of a registered relation or column name. It is flagged without knowing
// the workspace's schema, so a leak cannot hide behind a missing vocabulary.
var toolLoopAnswerShapedIdentifier = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9_]+\b`)

// toolLoopSchemaWord marks a word that turns a nearby name into a
// data-structure reference: "таблица contract", "колонка code",
// "status field", "the contract table".
var toolLoopSchemaWord = regexp.MustCompile(`(?i)(?:таблиц|колонк|столбц|пол[еяю]|схем|запис|строк|relation|table|column|field|schema|record)`)

// toolLoopAnswerPartMarkers are the internal identifiers the presentation
// scrub removes from a user-visible answer. The prefix markers are the
// historical short forms; the typed-identifier, path, file-name and timestamp
// markers are card D-6a's general forms.
var toolLoopAnswerPartMarkers = []*regexp.Regexp{
	toolLoopAnswerIdentifierMarker,
	toolLoopAnswerPathMarker,
	toolLoopAnswerFileNameMarker,
	toolLoopAnswerTimestampMarker,
	regexp.MustCompile(`\bconn_[0-9A-Za-z]+\b`),
	regexp.MustCompile(`\brule_[0-9A-Za-z]+\b`),
	regexp.MustCompile(`\bterm_[0-9A-Za-z]+\b`),
	regexp.MustCompile(`\bbinding_[0-9A-Za-z]+\b`),
	regexp.MustCompile(`observed_at`),
	regexp.MustCompile(`paraphrase`),
	regexp.MustCompile(`inbox/`),
}

// toolLoopAnswerVerificationMarker removes the internal verification vocabulary
// from a scrubbed answer, so the forced final turn's cleaning also covers the
// restriction the loop already enforces.
var toolLoopAnswerVerificationMarker = regexp.MustCompile(`(?i)(?:verified|verification|провер\w*)`)

// toolLoopAnswerSelfLabelSpans returns the byte spans of the self-labels that
// start a line. A line that is itself a question is a clarification, not a
// label: "Сколько чего нужно узнать: массу или число?" asks the user something
// and its colon is ordinary punctuation, so it is never stripped.
func toolLoopAnswerSelfLabelSpans(text string) [][2]int {
	spans := make([][2]int, 0)
	for _, match := range toolLoopAnswerLabelPrefix.FindAllStringIndex(text, -1) {
		lineStart := strings.LastIndexByte(text[:match[0]], '\n') + 1
		lineEnd := strings.IndexByte(text[match[0]:], '\n')
		if lineEnd < 0 {
			lineEnd = len(text)
		} else {
			lineEnd += match[0]
		}
		if strings.Contains(text[lineStart:lineEnd], "?") {
			continue
		}
		spans = append(spans, [2]int{match[0], match[1]})
	}
	return spans
}

// toolLoopAnswerSelfLabel returns the self-label that starts a line, or the
// empty string.
func toolLoopAnswerSelfLabel(text string) string {
	spans := toolLoopAnswerSelfLabelSpans(text)
	if len(spans) == 0 {
		return ""
	}
	return strings.TrimSpace(text[spans[0][0]:spans[0][1]])
}

// toolLoopAnswerPartMarker returns the first internal identifier in a
// user-visible answer text, or the empty string. It extends the historical
// prefix check with the general typed-identifier, path and timestamp forms.
func toolLoopAnswerPartMarker(text string) string {
	for _, pattern := range toolLoopAnswerPartMarkers {
		if match := pattern.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

// toolLoopTechnicalVocabulary collects the registered relation and column names
// this run actually saw: every glossary term's own data locations, every
// knowvault_source_schema table and column, every knowvault_sources registered
// relation, and the relations and columns named by the run's own SQL
// statements. It reads only this run's workspace context and tool results, so
// it needs no second copy of the source metadata and no question-set data.
func toolLoopTechnicalVocabulary(record *ToolLoopRecord) map[string]struct{} {
	names := map[string]struct{}{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		value = strings.Trim(value, "`\"'")
		if index := strings.LastIndexByte(value, '.'); index >= 0 {
			value = value[index+1:]
		}
		value = strings.TrimSpace(value)
		// A two-character registered name such as "id" is still a raw column
		// name; the schema-word guard in toolLoopTechnicalNameAt keeps an
		// ordinary short word from being mistaken for it.
		if len(value) < 2 || toolLoopSQLKeyword(value) {
			return
		}
		names[value] = struct{}{}
	}
	if record == nil {
		return names
	}
	if record.WorkspaceContext != nil {
		for _, term := range record.WorkspaceContext.Terms {
			for _, location := range term.Locations {
				add(location.Relation)
				add(location.Column)
			}
		}
	}
	for _, call := range record.Calls {
		if call.Outcome != "SUCCEEDED" || len(call.Result.Structured) == 0 {
			continue
		}
		switch call.Name {
		case "knowvault_source_schema":
			var envelope struct {
				Tables []struct {
					Name    string `json:"name"`
					Columns []struct {
						Name string `json:"name"`
					} `json:"columns"`
				} `json:"tables"`
			}
			if json.Unmarshal(call.Result.Structured, &envelope) == nil {
				for _, table := range envelope.Tables {
					add(table.Name)
					for _, column := range table.Columns {
						add(column.Name)
					}
				}
			}
		case "knowvault_sources", "knowvault_sources_list":
			var envelope struct {
				Sources []struct {
					RelationName string `json:"postgresql_relation_name"`
					SchemaName   string `json:"postgresql_schema_name"`
				} `json:"sources"`
			}
			if json.Unmarshal(call.Result.Structured, &envelope) == nil {
				for _, source := range envelope.Sources {
					add(source.RelationName)
					add(source.SchemaName)
				}
			}
		case sourceSQLToolName:
			var arguments struct {
				SQL string `json:"sql"`
			}
			if json.Unmarshal(call.Arguments, &arguments) == nil {
				for _, name := range toolLoopSQLNames(arguments.SQL) {
					add(name)
				}
			}
		}
	}
	return names
}

// toolLoopSQLQuotedLiteral strips string literals so a business value such as
// the status 'active' is never mistaken for a registered column name.
var toolLoopSQLQuotedLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)

// toolLoopSQLIdentifierToken matches one identifier-shaped token in a SQL
// statement.
var toolLoopSQLIdentifierToken = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// toolLoopSQLKeywords are the statement words, functions and schema names that
// are never a relation or column name.
var toolLoopSQLKeywords = map[string]struct{}{
	"select": {}, "from": {}, "where": {}, "as": {}, "and": {}, "or": {}, "not": {},
	"null": {}, "is": {}, "in": {}, "like": {}, "ilike": {}, "count": {}, "sum": {},
	"avg": {}, "min": {}, "max": {}, "distinct": {}, "case": {}, "when": {}, "then": {},
	"else": {}, "end": {}, "asc": {}, "desc": {}, "having": {}, "union": {}, "all": {},
	"with": {}, "over": {}, "partition": {}, "cast": {}, "coalesce": {}, "public": {},
	"pg_catalog": {}, "information_schema": {}, "current_date": {}, "current_timestamp": {},
	"true": {}, "false": {}, "between": {}, "exists": {}, "using": {}, "join": {},
	"left": {}, "right": {}, "inner": {}, "outer": {}, "full": {}, "cross": {}, "on": {},
	"group": {}, "order": {}, "by": {}, "limit": {}, "offset": {}, "insert": {},
	"update": {}, "delete": {}, "into": {}, "values": {}, "set": {}, "returning": {},
	"interval": {}, "extract": {}, "date_trunc": {}, "now": {}, "round": {}, "abs": {},
	"bigint": {}, "integer": {}, "int": {}, "text": {}, "numeric": {}, "timestamptz": {},
	"to_char": {}, "to_date": {}, "filter": {}, "row_number": {}, "rank": {},
}

func toolLoopSQLKeyword(value string) bool {
	_, ok := toolLoopSQLKeywords[strings.ToLower(value)]
	return ok
}

// toolLoopSQLNames extracts the identifier tokens a SELECT names, so a run that
// never read the schema still knows the relation and column names it used.
func toolLoopSQLNames(sql string) []string {
	if strings.TrimSpace(sql) == "" {
		return nil
	}
	cleaned := toolLoopSQLQuotedLiteral.ReplaceAllString(sql, " ")
	tokens := toolLoopSQLIdentifierToken.FindAllString(cleaned, -1)
	names := make([]string, 0, len(tokens))
	for _, token := range tokens {
		if len(token) < 3 || toolLoopSQLKeyword(token) {
			continue
		}
		names = append(names, token)
	}
	return names
}

// toolLoopTechnicalNamePattern builds one case-insensitive word-boundary
// alternation over the run's technical names, longest first so a longer name is
// never shadowed by its own prefix.
func toolLoopTechnicalNamePattern(names map[string]struct{}) *regexp.Regexp {
	if len(names) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})
	escaped := make([]string, 0, len(ordered))
	for _, name := range ordered {
		escaped = append(escaped, regexp.QuoteMeta(name))
	}
	return regexp.MustCompile(`(?i)\b(?:` + strings.Join(escaped, "|") + `)\b`)
}

// toolLoopAnswerRawName returns the first technical name reference in the text,
// or the empty string. A name is technical when it is part of a schema-qualified
// or snake_case identifier, or when a data-structure word sits next to it.
func toolLoopAnswerRawName(text string, pattern *regexp.Regexp) string {
	if pattern == nil {
		return ""
	}
	for _, match := range pattern.FindAllStringIndex(text, -1) {
		if toolLoopTechnicalNameAt(text, match[0], match[1]) {
			return text[match[0]:match[1]]
		}
	}
	return ""
}

// toolLoopTechnicalNameAt reports whether the name at [start,end) is a
// data-structure reference rather than an ordinary business word: it carries a
// dot or an underscore, or a schema word shares its sentence. The sentence
// scope, not a fixed window, keeps a column name that ends a long list
// ("... status, signed_on and amount") covered by the schema word that
// introduced the list. A dot only qualifies the name when an identifier
// character sits on its other side, so a sentence-ending period never turns a
// business word into a schema reference.
func toolLoopTechnicalNameAt(text string, start, end int) bool {
	if start >= 2 && text[start-1] == '.' && isASCIIWordByte(text[start-2]) {
		return true
	}
	if end+1 < len(text) && text[end] == '.' && isASCIIWordByte(text[end+1]) {
		return true
	}
	return toolLoopSchemaWord.MatchString(text[toolLoopSentenceStart(text, start):toolLoopSentenceEnd(text, end)])
}

// toolLoopSentenceStart returns the offset just after the last sentence
// terminator before position.
func toolLoopSentenceStart(text string, position int) int {
	if position > len(text) {
		position = len(text)
	}
	if index := strings.LastIndexAny(text[:position], ".!?\n"); index >= 0 {
		return index + 1
	}
	return 0
}

// toolLoopSentenceEnd returns the offset just before the first sentence
// terminator after position.
func toolLoopSentenceEnd(text string, position int) int {
	if position > len(text) {
		position = len(text)
	}
	if index := strings.IndexAny(text[position:], ".!?\n"); index >= 0 {
		return position + index
	}
	return len(text)
}

func isASCIIWordByte(value byte) bool {
	return value == '_' || (value >= '0' && value <= '9') || (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

// toolLoopAnswerPresentationIssue returns the closed code of the first
// presentation problem in a user-visible answer text, or the empty string. A
// self-label and a raw relation or column name are presentation problems for
// every question, including one about the data structure.
func toolLoopAnswerPresentationIssue(text string, pattern *regexp.Regexp) string {
	if label := toolLoopAnswerSelfLabel(text); label != "" {
		return "SUBMIT_ANSWER_SELF_LABEL"
	}
	if toolLoopAnswerShapedIdentifier.MatchString(text) {
		return "SUBMIT_ANSWER_TECHNICAL_NAME"
	}
	if name := toolLoopAnswerRawName(text, pattern); name != "" {
		return "SUBMIT_ANSWER_TECHNICAL_NAME"
	}
	return ""
}

// toolLoopPresentationRepairInstruction tells the model, in the question's own
// language, which presentation rule its rejected submission broke.
func toolLoopPresentationRepairInstruction(language string) string {
	return localizedText(language,
		"В ответе есть служебная подпись или техническое имя. Уберите подписи вида «Ответ:», «Уточнение:», «Ограничение охвата:» и не называйте таблицы, колонки, идентификаторы подключений, пути к файлам, версии и время наблюдения — в том числе когда вопрос о том, какие данные хранятся в источнике. Назовите источник по человеческому имени и опишите данные деловыми словами: техническое расположение несут ссылки. Перепишите только формулировки, сохранив те же факты, ссылки и live_reads.",
		"The answer contains a service label or a technical name. Remove labels such as \"Answer:\", \"Note:\" or \"Scope:\" and do not name tables, columns, connection identifiers, file paths, versions or observation times, including when the question is about which data a source holds. Name a source by its human name and describe the data in business words: the citations carry the technical location. Rewrite the wording only and keep the same facts, citations and live_reads.")
}

// toolLoopPresentText removes the presentation-only parts of one answer text:
// self-label prefixes, internal identifiers, file paths and file names,
// observation timestamps, the verification vocabulary and raw relation and
// column names. It never invents content.
func toolLoopPresentText(text string, pattern *regexp.Regexp) string {
	labelSpans := toolLoopAnswerSelfLabelSpans(text)
	presented := toolLoopRemoveSpans(text, labelSpans)
	for _, marker := range toolLoopAnswerPartMarkers {
		presented = marker.ReplaceAllString(presented, " ")
	}
	presented = toolLoopAnswerVerificationMarker.ReplaceAllString(presented, " ")
	spans := toolLoopPresentationSpans(presented, pattern)
	presented = toolLoopRemoveSpans(presented, spans)
	return toolLoopNormalizePresentation(presented)
}

// toolLoopQualifierSuffix matches a dotted schema qualification immediately
// before an identifier, so a schema-qualified name is removed whole.
var toolLoopQualifierSuffix = regexp.MustCompile(`(?:[A-Za-z_][A-Za-z0-9_]*\.)+$`)

// toolLoopPresentationSpans finds the byte spans of every technical name
// reference to remove: a schema-qualified identifier, a bare snake_case
// identifier, or a registered name next to a data-structure word, together with
// the schema qualification that introduced it.
func toolLoopPresentationSpans(text string, pattern *regexp.Regexp) [][2]int {
	spans := make([][2]int, 0)
	if pattern != nil {
		for _, match := range pattern.FindAllStringIndex(text, -1) {
			if !toolLoopTechnicalNameAt(text, match[0], match[1]) {
				continue
			}
			start := match[0]
			if qualifier := toolLoopQualifierSuffix.FindStringIndex(text[:start]); qualifier != nil {
				start = qualifier[0]
			}
			spans = append(spans, [2]int{start, match[1]})
		}
	}
	for _, match := range toolLoopAnswerShapedIdentifier.FindAllStringIndex(text, -1) {
		start := match[0]
		if qualifier := toolLoopQualifierSuffix.FindStringIndex(text[:start]); qualifier != nil {
			start = qualifier[0]
		}
		spans = append(spans, [2]int{start, match[1]})
	}
	return spans
}

// toolLoopRemoveSpans removes non-overlapping byte spans from the end, so the
// earlier offsets stay valid.
func toolLoopRemoveSpans(text string, spans [][2]int) string {
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] > spans[j][0] })
	lastStart := len(text) + 1
	for _, span := range spans {
		if span[0] < 0 || span[1] > len(text) || span[0] >= span[1] || span[1] > lastStart {
			continue
		}
		text = text[:span[0]] + text[span[1]:]
		lastStart = span[0]
	}
	return text
}

// toolLoopNormalizePresentation tidies the whitespace and punctuation left by a
// removal without touching textual content or the inline citation markers.
func toolLoopNormalizePresentation(text string) string {
	text = regexp.MustCompile(`[ \t]+`).ReplaceAllString(text, " ")
	text = regexp.MustCompile(`[ \t]+([,.;:!?])`).ReplaceAllString(text, "$1")
	text = regexp.MustCompile(`([,;:])[ \t]*([,.;:!?])`).ReplaceAllString(text, "$1")
	lines := strings.Split(text, "\n")
	for index := range lines {
		lines[index] = strings.TrimSpace(lines[index])
	}
	text = strings.Join(lines, "\n")
	text = regexp.MustCompile(`\n{3,}`).ReplaceAllString(text, "\n\n")
	return strings.TrimSpace(text)
}

// toolLoopPresentAnswer is the forced final turn's last resort: the answer the
// model already submitted, with the presentation-only parts removed, instead of
// the failure text. A claim that cannot be cleaned at all is dropped; a claim
// that survives keeps its citations and live reads untouched.
func toolLoopPresentAnswer(answer toolAnswer, names map[string]struct{}) (toolAnswer, bool) {
	presented := toolAnswer{NoData: answer.NoData, Claims: []toolClaim{}, Clarification: answer.Clarification}
	pattern := toolLoopTechnicalNamePattern(names)
	changed := false
	for _, claim := range answer.Claims {
		text := toolLoopPresentText(claim.Text, pattern)
		if text == "" || toolLoopAnswerPresentationIssue(text, pattern) != "" {
			changed = true
			continue
		}
		if text != claim.Text {
			changed = true
		}
		claim.Text = text
		presented.Claims = append(presented.Claims, claim)
	}
	if presented.Clarification != "" {
		text := toolLoopPresentText(presented.Clarification, pattern)
		if text != presented.Clarification {
			changed = true
		}
		presented.Clarification = text
	}
	if !changed {
		return answer, false
	}
	return presented, true
}
