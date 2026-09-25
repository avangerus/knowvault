package question

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// Card D-5 requirement 3. Questions about the workspace as a whole («что ты
// знаешь?», «что тут есть?», «что ты умеешь?») and greetings are answered
// immediately: the first model turn already carries a compact, citable
// workspace overview -- one line per source with its type, status and object
// counts, plus a few inventory rows with the exact canonical address of the
// document's first fragment, plus the workspace context description. Ordinary
// data questions keep the full tool loop untouched.
const (
	toolLoopOverviewObjects  = 3
	toolLoopOverviewSrcBytes = 1500
	// toolLoopOverviewFragmentBytes bounds each overview fragment read. The
	// overview is orientation, not evidence: enough text to cite and describe
	// the document, never the whole document.
	toolLoopOverviewFragmentBytes = 2048
	// toolLoopOverviewResearchToolCalls is the hard ceiling on knowledge-tool
	// calls for a question that already received the overview. It is a call
	// limit, not a turn limit: the citation-verification reserve below it stays
	// available, so a cited overview answer can still be verified.
	toolLoopOverviewResearchToolCalls = 2
)

// toolLoopOverview is the compact workspace overview one run reads before its
// first model turn: the rendered text the model sees and may cite.
type toolLoopOverview struct {
	Text string
}

// overviewQuestionCue is a date, a number or an explicit field/metric
// reference. Its presence means the question names something concrete, so the
// ordinary full tool loop owns it regardless of any overview-sounding phrase.
// Words like "документ" deliberately stay out: "какие документы есть" is an
// overview question, while "что написано в документе X" is caught by the
// quoted/named object rather than by the noun alone.
var overviewQuestionCue = regexp.MustCompile(`\d|` +
	`\b(?:[0-3]?\d)\s+[\p{L}]+\s+20\d{2}\b|` +
	`\b20\d{2}-\d{2}-\d{2}\b|` +
	`таблиц|колонк|пол[ея]|строк|запис|метрик|показател|рейс|отход|компан|договор|` +
	`table|column|field|row|record|metric|report|contract|revenue`)

// overviewQuestionPattern is the paraphrase-tolerant half of the overview
// class: an interrogative about the workspace itself (что/чем/какие/what) whose
// predicate is about knowing, having, being able, or being available. It is
// deliberately paired with overviewQuestionCue, which wins first, so a question
// that names a concrete subject keeps the ordinary full tool loop no matter how
// it is worded. The card names the class, not one sentence; a user who asks the
// same thing in other words must still get the quick overview.
var overviewQuestionPattern = regexp.MustCompile(`(?i)(?:^|[^а-яёa-z])(?:что|чем|какие|какая|каков|what)(?:[^?]{0,80}?)` +
	`(?:есть|знаешь|умеешь|можешь|доступн|имеетс|хранитс|расскаж|покаж|обзор|` +
	`do you|can you|are there|is there|available|there)`)

// Card D-8 gave a hypothetical/counterfactual question and a "what changed"
// question their own regex cues, matched against the question text ahead of
// the concrete-subject cue below. ADR-0099 (card D-11) removes both: the kind
// of answer for these two questions is now recognized by the answering
// model's own reading of the question's meaning, guided by the generic,
// wording-independent rules in toolLoopInstructions (tool_loop.go), not by a
// server-side word or stem match. The two classes these cues fed
// (toolLoopOverviewClassCounterfactual, toolLoopOverviewClassRecency) are
// removed with them; such a question now takes the ordinary full tool loop,
// or, when it also matches the source or database word below, that class's
// overview -- toolLoopInstructions' rule takes priority over that overview's
// own framing when the question is actually one of these two kinds.

// overviewSourceWord names the workspace's registered sources themselves --
// "источник"/"source" -- as opposed to a source's content. Card D-7
// requirement 1: a question built on this word gets the sources' human names
// alone, never their internal state, type or counts.
// Go's regexp \b is ASCII-only (RE2), so it never marks a boundary against a
// Cyrillic letter; the Russian stem below relies on being specific enough as
// a bare substring instead, matching the rest of this file's convention (see
// e.g. toolLoopSchemaWord in tool_loop_presentation.go).
var overviewSourceWord = regexp.MustCompile(`(?i)источник|\bsources?\b`)

// overviewBusinessTermsCue is an explicit request for the business-words
// answer shape itself, regardless of the sentence's mood: it already names
// the answer it wants, so it commits to card D-7 requirement 2's class even
// as an imperative ("расскажи бизнес-терминами...") rather than a question.
var overviewBusinessTermsCue = regexp.MustCompile(`(?i)бизнес[- ]?терминами|деловыми словами|простыми словами|` +
	`in business terms|plain (?:business )?words`)

// overviewDatabaseWord names the database as a whole -- "база"/"базе
// данных"/"database" -- as opposed to a specific table, column or field
// (already excluded upstream by overviewQuestionCue). Card D-7 requirement 2.
// See the note on overviewSourceWord above: no \b around the Cyrillic case
// forms, only around the ASCII word.
var overviewDatabaseWord = regexp.MustCompile(`(?i)(?:база|базе|базы|базу|базой|базах|базам|базами)|\bdatabase\b`)

// toolLoopGreetingQuestion reports whether the question is only a greeting.
// A greeting is also an overview question (card D-5 requirement 3 gives it the
// same overview), but it is told to answer with a short reply instead of an
// inventory, so the greeting is recognized separately.
func toolLoopGreetingQuestion(question string) bool {
	normalized := strings.ToLower(strings.TrimSpace(question))
	trimmed := strings.Trim(normalized, " \t\r\n?!.,;:«»\"'")
	if trimmed == "" {
		return false
	}
	for _, greeting := range []string{
		"привет", "здравствуй", "здравствуйте", "добрый день", "добрый вечер", "доброе утро",
		"hello", "hi", "hey", "good morning", "good afternoon", "good evening",
	} {
		if trimmed == greeting {
			return true
		}
	}
	return false
}

// toolLoopOverviewClass is the compact, no-tool-call answer shape a question
// calls for. classNone means the ordinary full tool loop answers it.
type toolLoopOverviewClass int

const (
	toolLoopOverviewClassNone toolLoopOverviewClass = iota
	// toolLoopOverviewClassGreeting is card D-5 requirement 3's greeting: one
	// short reply, no source or document enumeration.
	toolLoopOverviewClassGreeting
	// toolLoopOverviewClassOverview is card D-5 requirement 3's broad
	// workspace overview: source names with their state, plus a document
	// sample with citable excerpts.
	toolLoopOverviewClassOverview
	// toolLoopOverviewClassSources is card D-7 requirement 1: which sources
	// exist. The answer is their human names alone, nothing else.
	toolLoopOverviewClassSources
	// toolLoopOverviewClassDatabase is card D-7 requirement 2: what the
	// database holds, in business words. The answer names no table, column
	// or other technical identifier.
	toolLoopOverviewClassDatabase
)

// overviewShapePhrases are the generic phrasings of the broad workspace
// overview and greeting class that overviewQuestionPattern's regex does not
// already cover paraphrase-tolerantly. A phrase belonging to the narrower
// source or database-business classes moved out to their own word/cue
// matches above, so it is recognized by any wording, not by one fixed phrase.
var overviewShapePhrases = []string{
	"что ты знаешь", "что ты умеешь", "что ты можешь", "что тут есть", "что здесь есть",
	"что у тебя есть", "что есть в рабочей области", "что в рабочей области",
	"какие данные есть", "какие данные доступны", "какие документы есть",
	"расскажи о рабочей области", "расскажи что знаешь", "обзор рабочей области",
	"what do you know", "what can you do", "what do you have", "what is here", "what's here",
	"what is in the workspace", "what data do you have", "what documents are there",
	"workspace overview", "overview of the workspace", "tell me about the workspace",
}

// toolLoopOverviewQuestionClass classifies a question into one of the compact
// answer shapes above, or classNone for the ordinary full tool loop. It is
// deliberately narrow: a question that names a concrete subject -- a date, a
// number, a document or a field -- keeps the ordinary full tool loop, so this
// never turns a data question into a one-turn guess. A "did it change" or a
// hypothetical question is no longer classified here at all (ADR-0099, card
// D-11): it takes the ordinary full tool loop, or, when it also matches one
// of the classes below, that class's overview, and the answering model itself
// recognizes and answers it by the generic rule in toolLoopInstructions.
func toolLoopOverviewQuestionClass(question string) toolLoopOverviewClass {
	normalized := strings.ToLower(strings.TrimSpace(question))
	trimmed := strings.Trim(normalized, " \t\r\n?!.,;:«»\"'")
	if trimmed == "" {
		return toolLoopOverviewClassNone
	}
	if toolLoopGreetingQuestion(question) {
		return toolLoopOverviewClassGreeting
	}
	if overviewQuestionCue.MatchString(normalized) {
		return toolLoopOverviewClassNone
	}
	// Card D-7 requirement 1: a question built on "источник"/"source" is
	// about the source list itself, whatever else it also says.
	if overviewSourceWord.MatchString(normalized) {
		return toolLoopOverviewClassSources
	}
	// Card D-7 requirement 2: an explicit business-terms request, or a
	// reference to the database as a whole, is about its content in business
	// words, not its structure.
	if overviewBusinessTermsCue.MatchString(normalized) || overviewDatabaseWord.MatchString(normalized) {
		return toolLoopOverviewClassDatabase
	}
	for _, phrase := range overviewShapePhrases {
		if strings.Contains(normalized, phrase) {
			return toolLoopOverviewClassOverview
		}
	}
	if overviewQuestionPattern.MatchString(normalized) {
		return toolLoopOverviewClassOverview
	}
	return toolLoopOverviewClassNone
}

// toolLoopOverviewQuestion reports whether the question takes any of the
// compact, no-tool-call answer shapes above, greeting included.
func toolLoopOverviewQuestion(question string) bool {
	return toolLoopOverviewQuestionClass(question) != toolLoopOverviewClassNone
}

// buildToolLoopOverview reads the compact workspace overview. Every read goes
// through the same authorized workspace tools runtime the loop itself uses, so
// admission, audit and the read-only guarantee are exactly the existing ones;
// the reads are recorded in record.Calls as system calls. A failure of the
// optional inventory degrades to a smaller overview rather than failing the
// run, and a changed or cancelled scope leaves the overview absent so the
// ordinary loop takes over.
//
// class picks the opening instruction and, for toolLoopOverviewClassSources
// and toolLoopOverviewClassDatabase, replaces the rest of the read entirely
// (card D-7): those two answer from the source list alone, so no document is
// inventoried or read for them. For toolLoopOverviewClassGreeting and
// toolLoopOverviewClassOverview the read is unchanged from card D-5: every
// source line carries the source's human name, its source connection id (the
// identifier knowvault_source_schema and knowvault_source_sql require) and
// its type, status and object counts, plus a document sample.
func (service *Service) buildToolLoopOverview(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, language string, workspaceContextDocument string, class toolLoopOverviewClass) (*toolLoopOverview, error) {
	if service == nil || service.tools == nil || record == nil || class == toolLoopOverviewClassNone {
		return nil, nil
	}
	overview := &toolLoopOverview{}
	sourcesArgs := json.RawMessage(`{}`)
	sourcesResult, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_sources", sourcesArgs)
	if err != nil {
		return nil, err
	}
	sources := toolLoopOverviewSourcesFromResult(sourcesResult.Structured)

	if class == toolLoopOverviewClassSources || class == toolLoopOverviewClassDatabase {
		names := toolLoopOverviewSourceNames(sources)
		if class == toolLoopOverviewClassSources {
			overview.Text = toolLoopSourcesOverviewText(language, names)
		} else {
			overview.Text = toolLoopDatabaseOverviewText(language, names, workspaceContextDocument)
		}
		if overview.Text == "" {
			return nil, nil
		}
		return overview, nil
	}
	greeting := class == toolLoopOverviewClassGreeting

	objectsArgs, _ := json.Marshal(map[string]any{"limit": toolLoopOverviewObjects})
	objectsResult, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_list_objects", objectsArgs)
	if err != nil {
		return nil, err
	}
	documents := []toolLoopOverviewDocument{}
	if !objectsResult.IsError {
		documents = toolLoopOverviewObjectsFromResult(objectsResult.Structured)
	}
	documents = service.readToolLoopOverviewFragments(ctx, scope, record, documents)

	var builder strings.Builder
	// The heading is always the overview heading: the overview answer and the
	// greeting share the same orientation block, and every reader (model or
	// test) can recognize it by this line.
	if language == questionLanguageRussian {
		builder.WriteString("Обзор рабочей области, прочитанный сервером для этого вопроса. Это ориентир, а не замена чтению.\n")
		if greeting {
			builder.WriteString("Это приветствие. Ответьте ровно одним коротким предложением (можно начать с «Здравствуйте»), не перечисляйте источники и документы; при необходимости предложите, что можно найти. Такой ответ не содержит утверждений о содержимом рабочей области: отправьте его вариантом clarification с пустым списком claims и не добавляйте искусственную цитату.\n")
		} else {
			builder.WriteString("Начните ответ предложением, в котором перечислены точные имена не менее двух источников из списка ниже: скопируйте эти имена в кавычках-ёлочках, как в списке, а не пересказывайте их общими словами. Затем одним или двумя предложениями опишите содержание прочитанных фрагментов и завершите предложением о том, что обзор охватывает только прочитанные фрагменты. Весь ответ — менее 1000 символов. Пишите обычными предложениями: не начинайте строку подписью с двоеточием («Границы обзора:», «Документы:» и подобные запрещены). Каждое утверждение должно ссылаться хотя бы на один прочитанный фрагмент — утверждение без ссылки не принимается и отменяет весь ответ.\n")
		}
	} else {
		builder.WriteString("Workspace overview read by the server for this question. It is orientation, not a substitute for reading.\n")
		if greeting {
			builder.WriteString("This is a greeting. Reply with exactly one short sentence (you may start with a greeting), do not enumerate sources or documents, and offer what can be looked up if useful. Such an answer states nothing about the workspace content: submit it as the clarification variant with an empty claims list and do not add an artificial citation.\n")
		} else {
			builder.WriteString("Begin the answer with a sentence that lists the exact names of at least two sources from the list below, copied verbatim from that list; a paraphrase or a generic phrase does not count. Then describe what the read fragments support in one or two sentences and state the overview's boundaries. The whole answer is under 1000 characters and at most 8 lines. Do not begin a line with a short label followed by a colon.\n")
		}
	}
	if description := singleLine(workspaceContextDocument); description != "" {
		builder.WriteString(localizedText(language, "Описание рабочей области: ", "Workspace description: "))
		builder.WriteString(description)
		builder.WriteString("\n")
	}
	if len(sources) > 0 {
		builder.WriteString(localizedText(language,
			"Источники (имя; source_id — идентификатор подключения для knowvault_source_schema и knowvault_source_sql; тип; состояние; объектов):\n",
			"Sources (name; source_id is the connection identifier knowvault_source_schema and knowvault_source_sql need; type; status; objects):\n"))
		for _, source := range sources {
			builder.WriteString("- ")
			builder.WriteString(toolLoopOverviewSourceLine(language, source))
			builder.WriteString("\n")
		}
		if !greeting {
			// Card D-5: the source list is the one place the exact names live,
			// so the requirement is repeated immediately after it; a model that
			// summarizes content instead of naming sources misses the rule.
			builder.WriteString(localizedText(language,
				"В ответе обязательно назовите точные имена не менее двух источников из этого списка, скопировав их как есть.\n",
				"The answer must name at least two sources from this list by their exact names, copied as they are.\n"))
		}
	} else if sourceCount := overviewSourceCount(sourcesResult.Text); sourceCount > 0 {
		builder.WriteString(localizedText(language, "Всего источников: ", "Total sources: "))
		builder.WriteString(strconv.Itoa(sourceCount))
		builder.WriteString("\n")
	}
	if len(documents) > 0 {
		builder.WriteString(localizedText(language, "Документы (адрес можно цитировать):\n", "Documents (the address can be cited):\n"))
		for _, document := range documents {
			address := document.CanonicalAddress
			if address == "" {
				address = document.FragmentID
			}
			builder.WriteString("- ")
			builder.WriteString(address)
			builder.WriteString(document.PathSuffix())
			if document.ObjectType != "" {
				builder.WriteString(" [")
				builder.WriteString(document.ObjectType)
				builder.WriteString("]")
			}
			if document.Excerpt != "" {
				builder.WriteString(": ")
				builder.WriteString(singleLineLimit(document.Excerpt, toolLoopOverviewFragmentBytes))
			} else {
				builder.WriteString(localizedText(language, " (не прочитан)", " (not read)"))
			}
			builder.WriteString("\n")
		}
	}
	overview.Text = strings.TrimRight(builder.String(), "\n")
	if overview.Text == "" {
		return nil, nil
	}
	return overview, nil
}

// toolLoopOverviewSourceNames returns each source's human display name,
// deduplicated and in the order knowvault_sources returned them. It is the
// only projection of a source that toolLoopOverviewClassSources and
// toolLoopOverviewClassDatabase ever see: no connection id, type, status,
// sync state or object count.
func toolLoopOverviewSourceNames(sources []toolLoopOverviewSource) []string {
	names := make([]string, 0, len(sources))
	seen := make(map[string]bool, len(sources))
	for _, source := range sources {
		name := singleLine(source.Name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// toolLoopSourcesOverviewText renders card D-7 requirement 1's answer shape:
// the sources' exact human names and nothing else. The answer is submitted as
// the clarification variant (card D-5's escape for an answer that needs no
// document citation), because the source list is the workspace's own
// registration, not a claim that needs verifying against document content.
func toolLoopSourcesOverviewText(language string, names []string) string {
	var builder strings.Builder
	if language == questionLanguageRussian {
		builder.WriteString("Обзор рабочей области, прочитанный сервером для этого вопроса. Это ориентир, а не замена чтению.\n")
		builder.WriteString("Если по смыслу вопрос на самом деле о том, менялся ли документ или актуален ли он, или это гипотетический вопрос о другом, воображаемом виде деятельности рабочей области, — следуйте общему правилу об этих двух видах вопроса из инструкций выше, а не описанному ниже.\n")
		builder.WriteString("Вопрос — про список источников, а не про их содержимое или состояние. Ответьте коротким списком точных имён источников из списка ниже (каждое имя в кавычках-ёлочках, скопированное как есть), без статусов, типов, количества объектов и без пояснений, если о них отдельно не спросили. Не добавляйте предложение об ограничениях ответа. Этот перечень не требует отдельной цитаты — отправьте ответ вариантом clarification с пустым списком claims. Весь ответ — не больше 6 строк.\n")
	} else {
		builder.WriteString("Workspace overview read by the server for this question. It is orientation, not a substitute for reading.\n")
		builder.WriteString("If the question, by its meaning, actually asks whether a document changed or is still current, or is a hypothetical about a different, imagined activity than the one this workspace's data covers, follow the general rule for those two question kinds given earlier in these instructions instead of the shape below.\n")
		builder.WriteString("The question is about the list of sources, not their content or state. Reply with a short list of the exact source names below (each copied as it is), without status, type, object counts or explanation unless asked separately. Do not add a sentence about the answer's boundaries. This list needs no separate citation -- submit the answer as the clarification variant with an empty claims list. The whole answer is at most 6 lines.\n")
	}
	if len(names) == 0 {
		return strings.TrimRight(builder.String(), "\n")
	}
	builder.WriteString(localizedText(language, "Источники:\n", "Sources:\n"))
	for _, name := range names {
		builder.WriteString("- «")
		builder.WriteString(name)
		builder.WriteString("»\n")
	}
	return strings.TrimRight(builder.String(), "\n")
}

// toolLoopDatabaseOverviewText renders card D-7 requirement 2's answer shape:
// what the workspace's data is about and what one can ask of it, in business
// words, grounded only in the sources' human names and the workspace's own
// description -- never a table, column, schema or other technical name. Like
// the sources-only answer above, it is submitted as the clarification
// variant: the description rests on the workspace's own registration, not on
// a document claim that needs a citation.
func toolLoopDatabaseOverviewText(language string, names []string, workspaceContextDocument string) string {
	var builder strings.Builder
	if language == questionLanguageRussian {
		builder.WriteString("Обзор рабочей области, прочитанный сервером для этого вопроса. Это ориентир, а не замена чтению.\n")
		builder.WriteString("Если по смыслу вопрос на самом деле о том, менялся ли документ или актуален ли он, или это гипотетический вопрос о другом, воображаемом виде деятельности рабочей области, — следуйте общему правилу об этих двух видах вопроса из инструкций выше, а не описанному ниже.\n")
		builder.WriteString("Вопрос — про то, что можно узнать из данных рабочей области, деловыми словами. Опишите в нескольких предложениях, о чём эти данные (например, о договорах, о клиентах, о местах хранения — своими словами по именам источников ниже, а не техническими терминами) и что по ним в целом можно спросить (количество, статус, детали). Не называйте таблицы, колонки, схемы, идентификаторы подключений и другие технические имена. Не пересказывайте документы, которые не упоминались в вопросе. Не добавляйте предложение об ограничениях ответа. Описание опирается на список источников рабочей области и не требует отдельной цитаты — отправьте ответ вариантом clarification с пустым списком claims. Весь ответ — не больше 6 строк.\n")
	} else {
		builder.WriteString("Workspace overview read by the server for this question. It is orientation, not a substitute for reading.\n")
		builder.WriteString("If the question, by its meaning, actually asks whether a document changed or is still current, or is a hypothetical about a different, imagined activity than the one this workspace's data covers, follow the general rule for those two question kinds given earlier in these instructions instead of the shape below.\n")
		builder.WriteString("The question is about what can be learned from the workspace's data, in business words. Describe in a few sentences what the data is about (for example contracts, clients, storage locations -- in your own words, from the source names below, not technical terms) and what one can generally ask about it (counts, status, detail). Do not name any table, column, schema, connection identifier or other technical name. Do not retell a document the question did not name. Do not add a sentence about the answer's boundaries. The description rests on the workspace's own source list and needs no separate citation -- submit the answer as the clarification variant with an empty claims list. The whole answer is at most 6 lines.\n")
	}
	if description := singleLine(workspaceContextDocument); description != "" {
		builder.WriteString(localizedText(language, "Описание рабочей области: ", "Workspace description: "))
		builder.WriteString(description)
		builder.WriteString("\n")
	}
	if len(names) == 0 {
		return strings.TrimRight(builder.String(), "\n")
	}
	builder.WriteString(localizedText(language, "Источники:\n", "Sources:\n"))
	for _, name := range names {
		builder.WriteString("- «")
		builder.WriteString(name)
		builder.WriteString("»\n")
	}
	return strings.TrimRight(builder.String(), "\n")
}

// toolLoopOverviewSource is one row of knowvault_sources'
// knowvault_sources structured envelope. Name is the human display name the
// answer must use; ConnectionID is the identifier the schema and SQL tools
// require, which the content-text channel of knowvault_sources does not carry.
type toolLoopOverviewSource struct {
	Name             string
	ConnectionID     string
	SourceType       string
	Schema           string
	Relation         string
	Enabled          bool
	ActivationStatus string
	SyncStatus       string
	FreshnessState   string
	ObjectsSeen      *int64
	ObjectsIngested  *int64
}

// toolLoopOverviewSourcesFromResult decodes the same structured source
// inventory the text channel is built from. An absent or unexpected shape
// degrades to no lines; the caller then falls back to the text count.
func toolLoopOverviewSourcesFromResult(raw json.RawMessage) []toolLoopOverviewSource {
	if len(raw) == 0 {
		return nil
	}
	var envelope struct {
		Sources []struct {
			ConnectionID           string `json:"connection_id"`
			ConnectionName         string `json:"connection_name"`
			SourceType             string `json:"source_type"`
			PostgreSQLSchemaName   string `json:"postgresql_schema_name"`
			PostgreSQLRelationName string `json:"postgresql_relation_name"`
			Enabled                bool   `json:"enabled"`
			ActivationStatus       string `json:"activation_status"`
			SyncStatus             string `json:"sync_status"`
			FreshnessState         string `json:"freshness_state"`
			ObjectsSeen            *int64 `json:"objects_seen"`
			ObjectsIngested        *int64 `json:"objects_ingested"`
		} `json:"sources"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil
	}
	sources := make([]toolLoopOverviewSource, 0, len(envelope.Sources))
	for _, source := range envelope.Sources {
		if source.ConnectionID == "" && source.ConnectionName == "" {
			continue
		}
		name := source.ConnectionName
		if name == "" {
			name = source.ConnectionID
		}
		sources = append(sources, toolLoopOverviewSource{
			Name: name, ConnectionID: source.ConnectionID, SourceType: source.SourceType,
			Schema: source.PostgreSQLSchemaName, Relation: source.PostgreSQLRelationName,
			Enabled: source.Enabled, ActivationStatus: source.ActivationStatus,
			SyncStatus: source.SyncStatus, FreshnessState: source.FreshnessState,
			ObjectsSeen: source.ObjectsSeen, ObjectsIngested: source.ObjectsIngested,
		})
	}
	return sources
}

// toolLoopOverviewSourceLine renders one compact, model-readable source line:
// its human name, the connection id the source tools need, its type and
// registered relation, an honest status and the observed object counts when the
// source reports them.
func toolLoopOverviewSourceLine(language string, source toolLoopOverviewSource) string {
	var builder strings.Builder
	builder.WriteString("\u00ab")
	builder.WriteString(singleLine(source.Name))
	builder.WriteString("\u00bb")
	if source.ConnectionID != "" {
		builder.WriteString(localizedText(language, ", source_id=", ", source_id="))
		builder.WriteString(source.ConnectionID)
	}
	if source.SourceType != "" {
		builder.WriteString(localizedText(language, ", тип ", ", type "))
		builder.WriteString(source.SourceType)
	}
	if relation := singleLine(strings.Trim(strings.Join([]string{source.Schema, source.Relation}, "."), ".")); relation != "" {
		builder.WriteString(localizedText(language, ", таблица ", ", relation "))
		builder.WriteString(relation)
	}
	if source.ActivationStatus != "" {
		builder.WriteString(localizedText(language, ", состояние ", ", status "))
		builder.WriteString(source.ActivationStatus)
	} else if source.Enabled {
		builder.WriteString(localizedText(language, ", включён", ", enabled"))
	}
	if source.SyncStatus != "" {
		builder.WriteString(", sync_status=")
		builder.WriteString(source.SyncStatus)
	}
	if source.FreshnessState != "" {
		builder.WriteString(localizedText(language, ", свежесть ", ", freshness "))
		builder.WriteString(source.FreshnessState)
	}
	if source.ObjectsSeen != nil || source.ObjectsIngested != nil {
		builder.WriteString(localizedText(language, ", объектов ", ", objects "))
		builder.WriteString(int64PointerText(source.ObjectsIngested))
		builder.WriteString("/")
		builder.WriteString(int64PointerText(source.ObjectsSeen))
	}
	return builder.String()
}

func int64PointerText(value *int64) string {
	if value == nil {
		return "?"
	}
	return strconv.FormatInt(*value, 10)
}

// invokeOverviewTool performs one overview read and records it in the run trace
// as a system call, exactly like the automatic citation binding read. A scope
// change is returned unchanged so the caller fails closed; every other failure
// degrades to an empty result.
func (service *Service) invokeOverviewTool(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, name string, args json.RawMessage) (workspacetools.Result, error) {
	if err := ctx.Err(); err != nil {
		return workspacetools.Result{}, err
	}
	result, err := service.tools.Invoke(ctx, scope, name, args)
	if err != nil {
		if errors.Is(err, workspacetools.ErrScopeChanged) {
			return workspacetools.Result{}, err
		}
		return workspacetools.Result{IsError: true}, nil
	}
	record.Calls = append(record.Calls, ToolCallRecord{
		ID: name + "-overview", Name: name, Arguments: append(json.RawMessage(nil), args...),
		System: true, Outcome: "SUCCEEDED", Result: result,
	})
	return result, nil
}

var overviewSourceCountPattern = regexp.MustCompile(`knowvault_sources:\s*(\d+)\s+source`)

// overviewSourceCount reads the source count from the sources tool's own text
// channel, which is the only channel knowvault_sources fills for a workspace
// with no structured source projection. The count is informational: the full
// source line (type and status) is what the overview renders.
func overviewSourceCount(text string) int {
	match := overviewSourceCountPattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	count, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}
	return count
}

type toolLoopOverviewDocument struct {
	FragmentID       string
	CanonicalAddress string
	ObjectType       string
	Excerpt          string
	Path             string
}

func (document toolLoopOverviewDocument) PathSuffix() string {
	if document.Path == "" {
		return ""
	}
	return " (" + document.Path + ")"
}

func toolLoopOverviewObjectsFromResult(raw json.RawMessage) []toolLoopOverviewDocument {
	if len(raw) == 0 {
		return nil
	}
	var envelope struct {
		Objects []struct {
			ObjectType string `json:"object_type"`
			SourcePath string `json:"source_path"`
			Address    struct {
				Object struct {
					FirstFragmentID string `json:"first_fragment_id"`
				} `json:"object"`
			} `json:"address"`
		} `json:"objects"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil
	}
	documents := make([]toolLoopOverviewDocument, 0, len(envelope.Objects))
	for _, object := range envelope.Objects {
		// The inventory addresses an object, not a fragment. Only the object's
		// own first fragment is citable, so the overview reads that fragment.
		if object.Address.Object.FirstFragmentID == "" {
			continue
		}
		documents = append(documents, toolLoopOverviewDocument{
			FragmentID: object.Address.Object.FirstFragmentID,
			ObjectType: object.ObjectType,
			Path:       object.SourcePath,
		})
	}
	return documents
}

var overviewReadAddressPattern = regexp.MustCompile(`canonical_address=(kv1:[^\s]+)`)

// readToolLoopOverviewFragments reads the first fragment of each inventoried
// document so the overview carries a citable canonical address and its text.
// The reads are recorded as system calls by invokeOverviewTool, exactly like
// the automatic citation binding read, so a citation to one verifies through
// the ordinary path. A failed read leaves the document listed without an
// excerpt, never silently dropping it.
func (service *Service) readToolLoopOverviewFragments(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, documents []toolLoopOverviewDocument) []toolLoopOverviewDocument {
	resolved := make([]toolLoopOverviewDocument, 0, len(documents))
	for _, document := range documents {
		readArgs, _ := json.Marshal(map[string]any{"fragment_id": document.FragmentID, "limit": toolLoopOverviewFragmentBytes})
		result, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_read", readArgs)
		if err != nil || result.IsError {
			resolved = append(resolved, document)
			continue
		}
		var page struct {
			Text      string `json:"text"`
			Canonical string `json:"canonical_address"`
		}
		if json.Unmarshal(result.Structured, &page) != nil || page.Text == "" {
			resolved = append(resolved, document)
			continue
		}
		document.CanonicalAddress = page.Canonical
		if document.CanonicalAddress == "" {
			if match := overviewReadAddressPattern.FindStringSubmatch(result.Text); len(match) == 2 {
				document.CanonicalAddress = match[1]
			}
		}
		document.Excerpt = page.Text
		resolved = append(resolved, document)
	}
	return resolved
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func singleLineLimit(value string, limit int) string {
	value = singleLine(value)
	if limit > 0 && len(value) > limit {
		value = strings.ToValidUTF8(value[:limit], "")
	}
	return value
}

// observeToolLoopOverview feeds every overview read into the same transient
// observation state the loop's own invoke uses, so a citation to an overview
// address resolves and verifies exactly like a citation to a model-requested
// read. Overview reads are system calls: they never spend the model's own
// research-call budget (which card D-5 caps separately for an overview answer).
func observeToolLoopOverview(record *ToolLoopRecord, observed map[string]bool,
	citationObservations *citationObservationIndex, readPages map[string]string, pageFragments map[string][]string) {
	if record == nil {
		return
	}
	for _, call := range record.Calls {
		if !call.System || call.Outcome != "SUCCEEDED" || len(call.Result.Structured) == 0 {
			continue
		}
		collectToolAddresses(call.Result.Structured, observed)
		page, ok := collectCitationObservations(call.Name, call.Result.Structured, citationObservations)
		if !ok {
			continue
		}
		readPages[page.Address] += "\n" + page.Text
		for _, part := range page.Parts {
			readPages[part.Address] += "\n" + page.Text[part.Offset:part.Offset+part.Length]
			pageFragments[part.Address] = append(pageFragments[part.Address], part.Address)
		}
	}
}
