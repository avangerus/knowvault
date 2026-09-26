package question

// ADR-0099 amendment 1, decision 5: each kind has its own deterministic route,
// "a server-rendered answer, or a kind-specific prompt with only the tools that
// kind needs". Card D-17 gives the recognised off_topic and vague kinds the
// server-rendered answer.
//
// Both kinds need nothing read: an off_topic question is outside what the
// workspace holds and a vague request names nothing to work on. There is
// therefore no answering model call at all and no tool is mounted, so the run
// can make no SQL query, no live-data read and no document search -- not even
// by mistake. The answer is rendered from the workspace's own registration:
// the human names of its registered sources, which are the concrete things the
// workspace really holds. Nothing in this file matches words against the user's
// question: the kind comes from the separate recognition step (answer_kind.go)
// and the text is a fixed template around the workspace's own source names.
//
// Card D-17 result 1: an off_topic answer says in at most two sentences that
// the question is outside what the workspace holds and what one can ask about
// instead, naming at least one thing the workspace really holds.
//
// Card D-17 result 2: a vague answer is exactly one clarifying question of at
// most 400 characters that offers concrete options from what the workspace
// really holds.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	// shortKindVagueMaxRunes is card D-17 result 2's hard limit on the whole
	// clarifying question.
	shortKindVagueMaxRunes = 400
	// shortKindMaxNameRunes bounds one source name copied into the rendered
	// answer. The names are human display names and are normally short; the
	// bound keeps a pathological name from making the answer unreadable.
	shortKindMaxNameRunes = 80
	// shortKindMaxNameRunesEnglish is the tighter bound for an English answer.
	// A copied Cyrillic name must stay a small share of the answer, so a name
	// longer than this is not offered at all.
	shortKindMaxNameRunesEnglish = 24
	// shortKindMaxOptionsRussian and shortKindMaxOptionsEnglish bound how many
	// concrete options the answer offers. The Russian limit is three because
	// the synthetic workspace's three human source names are all useful; the
	// English limit is two so the copied Cyrillic names stay a small share of
	// an English answer.
	shortKindMaxOptionsRussian = 3
	shortKindMaxOptionsEnglish = 2
)

// shortKindSubjectNames reads the workspace's own registration through the same
// authorized workspace tools runtime every other read uses. The read is a
// system call in the run trace, never a model step: it lists the registered
// sources' human names and reaches no database value and no document content.
func (service *Service) shortKindSubjectNames(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord) ([]string, error) {
	if service == nil || service.tools == nil || record == nil {
		return nil, nil
	}
	result, err := service.invokeOverviewTool(ctx, scope, record, "knowvault_sources", json.RawMessage(`{}`))
	if err != nil {
		return nil, err
	}
	return toolLoopOverviewSourceNames(toolLoopOverviewSourcesFromResult(result.Structured)), nil
}

// completeShortKindRun persists the server-rendered answer of an off_topic or
// vague run. The run records its recognised kind, its language and the
// ANSWER stop reason; it carries no citations, no live result and no model
// call. The persistence context mirrors the loop's own: the record travels
// with the context so the stored tool loop trace carries the kind.
func (service *Service) completeShortKindRun(parent context.Context, access database.AccessContext,
	run Run, questionText string, record *ToolLoopRecord, kind AnswerKind, subjects []string) error {
	language := questionLanguage(questionText)
	record.AnswerKind = string(kind)
	record.AnswerLanguage = language
	record.StopReason = "ANSWER"
	record.AllClaimsBound = false
	answer := renderShortKindAnswer(kind, language, subjects)
	finishCtx, finishCancel := modelAttemptPersistenceContext(parent)
	defer finishCancel()
	finishCtx = context.WithValue(finishCtx, toolLoopContextKey{}, record)
	persistErr := service.persistTerminalRun(finishCtx, access, run.ID, run.WorkspaceID, answer,
		[]Citation{}, []candidate{}, "COMPLETED", run.CorpusStatus != "COMPLETE",
		[]Uncertainty{}, []Conflict{}, nil)
	service.observeWorkspaceContextRun(finishCtx, access, run, questionText, record, persistErr)
	return persistErr
}

// renderShortKindAnswer renders the whole user-visible answer for one short
// kind. kind is one of the two kinds this file owns; any other kind renders
// nothing, so a caller that reaches the renderer with a full question cannot
// accidentally get a short-answer template.
func renderShortKindAnswer(kind AnswerKind, language string, subjects []string) string {
	switch kind {
	case AnswerKindOffTopic:
		return renderOffTopicAnswer(language, shortKindOptionNames(subjects, language))
	case AnswerKindVague:
		return renderVagueAnswer(language, shortKindOptionNames(subjects, language))
	}
	return ""
}

// shortKindOptionNames renders the workspace's own source names as a short
// list of concrete options, in the question's language: three names joined by
// "или" for Russian and two joined by "or" for English. Each name is copied
// exactly, in guillemets, and never translated. An English answer copies
// Cyrillic source names, so it prefers the shortest ones and rejects an
// overlong name outright: the question set's own language rule requires an
// English answer to stay at most 30 % Cyrillic. An empty list renders nothing
// and the caller falls back to its no-options wording.
func shortKindOptionNames(subjects []string, language string) string {
	maxNameRunes := shortKindMaxNameRunes
	limit, conjunction := shortKindMaxOptionsRussian, " или "
	if language != questionLanguageRussian {
		limit, conjunction = shortKindMaxOptionsEnglish, " or "
		maxNameRunes = shortKindMaxNameRunesEnglish
	}
	names := make([]string, 0, len(subjects))
	seen := make(map[string]bool, len(subjects))
	for _, subject := range subjects {
		name := strings.TrimSpace(singleLine(subject))
		if name == "" || seen[name] || len([]rune(name)) > maxNameRunes {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if language != questionLanguageRussian {
		sort.SliceStable(names, func(i, j int) bool {
			return len([]rune(names[i])) < len([]rune(names[j]))
		})
	}
	if len(names) > limit {
		names = names[:limit]
	}
	var builder strings.Builder
	for index, name := range names {
		switch {
		case index == 0:
		case index == len(names)-1:
			builder.WriteString(conjunction)
		default:
			builder.WriteString(", ")
		}
		builder.WriteString("\u00ab")
		builder.WriteString(name)
		builder.WriteString("\u00bb")
	}
	return builder.String()
}

// renderOffTopicAnswer is card D-17 result 1's two-sentence reply: the question
// is outside what the workspace holds, and here is what one can ask about
// instead, naming the workspace's own registered subjects.
func renderOffTopicAnswer(language, options string) string {
	if language == questionLanguageRussian {
		if options == "" {
			return "Это не относится к тому, что есть в рабочей области. Спросите лучше о том, что в ней есть."
		}
		return "Это не относится к тому, что есть в рабочей области. Спросите лучше о том, что в ней есть, — " + options + "."
	}
	if options == "" {
		return "This is outside what this workspace holds. Ask instead about what it does hold."
	}
	return "This is outside what this workspace holds. Ask instead about what it does hold, for example data about " + options + "."
}

// renderVagueAnswer is card D-17 result 2's one clarifying question: exactly one
// question mark, at most shortKindVagueMaxRunes characters, offering the
// workspace's own registered subjects as concrete options. options is produced
// by shortKindOptionNames, which is bounded so the rendered question is always
// within the length limit; the limit is asserted here as the last line of
// defence.
func renderVagueAnswer(language, options string) string {
	question := ""
	if language == questionLanguageRussian {
		if options == "" {
			question = "Что именно показать?"
		} else {
			question = "Что именно показать — " + options + "?"
		}
	} else {
		if options == "" {
			question = "What exactly should I show you?"
		} else {
			question = "What exactly should I show you — for example, data about " + options + "?"
		}
	}
	if len([]rune(question)) <= shortKindVagueMaxRunes {
		return question
	}
	// The bounded option list makes this unreachable; if a future edit ever
	// breaks that bound, drop the options rather than emit an overlong answer.
	return renderVagueAnswer(language, "")
}
