package question

// Card D-18: a question about data held in a database of the workspace that
// cannot be read right now gets one plain, server-rendered answer that names
// the database and what makes it readable, instead of an empty or confused
// answer built from refused queries. The route is decided before the answering
// model runs and before any tool is mounted, so such a run records no
// knowvault_source_sql call and presents no empty result.
//
// The route is not a new question kind. ADR-0099 amendment 1 keeps kinds
// independent of the workspace's state, so the recognised kind is unchanged
// whichever state the database is in and only the answer route differs. What
// decides the route is the workspace's own registration -- which of its
// PostgreSQL sources cannot be read right now (a binding whose tables await
// confirmation, a source that is not enabled, ready or trust-verified, or one
// whose connection no longer answers) -- together with whether the question
// names that source by its own registered human name. Nothing here matches a
// word list against the question: the names and the state come from the
// workspace's own source inventory at run time, read through the same
// authorized workspace tools runtime every other read uses.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// The three reasons a workspace database cannot be read right now. They select
// the remedy the plain answer names: confirming the tables, making the database
// reachable, or waiting until the database's shared load limit frees up.
const (
	unreadableSourceReasonTablesUnconfirmed = "TABLES_UNCONFIRMED"
	unreadableSourceReasonNotReachable      = "NOT_REACHABLE"
	unreadableSourceReasonBusy              = "SOURCE_BUSY"
)

// unreadableDatabase is one workspace PostgreSQL source the question names and
// the reason it cannot be read right now. Name is the source's own human
// display name, which the renderer puts in the answer.
type unreadableDatabase struct {
	Name         string
	ConnectionID string
	Reason       string
}

// sourceReadabilityProbe is the optional capability the workspace tools
// runtime may carry: it answers whether one PostgreSQL source can actually be
// read right now, opening the source's own connection once. The production
// handler implements it by delegation to the mounted source service; a runtime
// that does not carry it leaves the live check unknown, so the deterministic
// state check above still decides on its own and no source is contacted.
type sourceReadabilityProbe interface {
	ProbeSourceReadable(ctx context.Context, access database.AccessContext, workspaceID, connectionID string) error
}

// unreadableDatabaseForQuestion returns the database the question names that
// cannot be read right now, or nil when the question names none. The stored
// state is checked first (it needs no external connection); only a source that
// looks readable there is probed live, so a healthy workspace costs one
// readiness read at most and the answer of a healthy question is unchanged.
func (service *Service) unreadableDatabaseForQuestion(ctx context.Context, scope workspacetools.Scope,
	record *ToolLoopRecord, questionText string) (*unreadableDatabase, error) {
	if service == nil || service.tools == nil || record == nil || strings.TrimSpace(questionText) == "" {
		return nil, nil
	}
	result, err := service.readSourceInventory(ctx, scope)
	if err != nil {
		// A changed scope is returned unchanged so the caller fails closed; the
		// inventory reader folds every other failure into an empty result, which
		// simply leaves this route off.
		return nil, err
	}
	if result.IsError {
		return nil, nil
	}
	named := namedPostgreSQLSources(questionText, toolLoopOverviewSourcesFromResult(result.Structured))
	if len(named) == 0 {
		return nil, nil
	}
	for _, source := range named {
		if reason, unreadable := unreadableSourceReason(source); unreadable {
			return &unreadableDatabase{Name: source.Name, ConnectionID: source.ConnectionID, Reason: reason}, nil
		}
	}
	for _, source := range named {
		reason, unreadable, probeErr := service.probeSourceReadable(ctx, scope, source.ConnectionID)
		if probeErr != nil {
			return nil, probeErr
		}
		if unreadable {
			return &unreadableDatabase{Name: source.Name, ConnectionID: source.ConnectionID, Reason: reason}, nil
		}
	}
	return nil, nil
}

// namedPostgreSQLSources keeps the workspace's PostgreSQL sources whose own
// registered human name the question uses. A document folder or another
// non-database source is never a database the question can ask about, so it is
// never a candidate here.
func namedPostgreSQLSources(questionText string, sources []toolLoopOverviewSource) []toolLoopOverviewSource {
	named := make([]toolLoopOverviewSource, 0, len(sources))
	for _, source := range sources {
		if source.SourceType != "POSTGRESQL_QUERY" {
			continue
		}
		if questionNamesSource(questionText, source.Name) {
			named = append(named, source)
		}
	}
	return named
}

// unreadableSourceReason classifies one source's stored state: the reason it
// cannot be read right now, or false when its stored state permits reading. An
// absent member is treated as "no information" and never as a failure, so an
// older inventory shape cannot turn a readable source into an unreadable one.
// A source that passes this check may still be unreachable; the live probe
// decides that. A source with no query access configured is deliberately not
// classified here: that is a different state with a different remedy from the
// two this route speaks about (confirm the tables, make the database
// reachable), and the live probe is what decides whether the database answers.
func unreadableSourceReason(source toolLoopOverviewSource) (string, bool) {
	if source.SourceType != "POSTGRESQL_QUERY" {
		return "", false
	}
	if !source.Enabled {
		return unreadableSourceReasonNotReachable, true
	}
	if source.Confirmed != nil && !*source.Confirmed {
		return unreadableSourceReasonTablesUnconfirmed, true
	}
	if source.ActivationStatus != "" && source.ActivationStatus != "READY" {
		return unreadableSourceReasonNotReachable, true
	}
	if source.TrustVerified != nil && !*source.TrustVerified {
		return unreadableSourceReasonNotReachable, true
	}
	return "", false
}

// readSourceInventory performs the workspace's own source-inventory read that
// decides this route. Unlike the overview orientation it is not part of the
// run's answer and is never recorded in the run's tool trace: it is a
// pre-answer check, and a failed read ("no inventory here") must not leave a
// failed system call in a run whose answer the model itself produces. The read
// still goes through the same authorized workspace tools runtime, so its
// admission, audit and read-only guarantees are exactly the existing ones. A
// scope change is returned unchanged so the caller fails closed; every other
// failure degrades to an empty result.
func (service *Service) readSourceInventory(ctx context.Context, scope workspacetools.Scope) (workspacetools.Result, error) {
	if err := ctx.Err(); err != nil {
		return workspacetools.Result{}, err
	}
	result, err := service.tools.Invoke(ctx, scope, "knowvault_sources", json.RawMessage(`{}`))
	if err != nil {
		if errors.Is(err, workspacetools.ErrScopeChanged) {
			return workspacetools.Result{}, err
		}
		return workspacetools.Result{IsError: true}, nil
	}
	return result, nil
}

// probeSourceReadable runs the optional live readiness check for one source and
// returns the reason it cannot be read right now. The empty reason with
// readable=false means "no failure known": a runtime that does not carry the
// probe capability, or whose mount reports the capability unavailable, leaves
// the stored-state decision alone and never turns an unknown into "cannot be
// read". A check the shared load limit refused is reported as busy, so the
// plain answer names the taken limit rather than claiming the database is
// unreachable.
func (service *Service) probeSourceReadable(ctx context.Context, scope workspacetools.Scope, connectionID string) (reason string, unreadable bool, err error) {
	probe, ok := service.tools.(sourceReadabilityProbe)
	if !ok || connectionID == "" {
		return "", false, nil
	}
	probeErr := probe.ProbeSourceReadable(ctx, scope.Access, scope.WorkspaceID, connectionID)
	if probeErr == nil {
		return "", false, nil
	}
	if errors.Is(probeErr, workspacetools.ErrScopeChanged) {
		return "", false, probeErr
	}
	if errors.Is(probeErr, workspacetools.ErrUnavailable) {
		return "", false, nil
	}
	if errors.Is(probeErr, workspacetools.ErrSourceBusy) {
		return unreadableSourceReasonBusy, true, nil
	}
	return unreadableSourceReasonNotReachable, true, nil
}

// completeUnreadableDatabaseRun persists the server-rendered answer of a run
// whose question names a database that cannot be read. Like the short-kind
// route it records the run's already-recognised kind and language, carries no
// citations and no live result, and makes no answering model call.
func (service *Service) completeUnreadableDatabaseRun(parent context.Context, access database.AccessContext,
	run Run, questionText string, record *ToolLoopRecord, unreadable unreadableDatabase) error {
	language := questionLanguage(questionText)
	record.AnswerLanguage = language
	record.StopReason = "ANSWER"
	record.AllClaimsBound = false
	answer := renderUnreadableDatabaseAnswer(language, unreadable.Name, unreadable.Reason)
	finishCtx, finishCancel := modelAttemptPersistenceContext(parent)
	defer finishCancel()
	finishCtx = context.WithValue(finishCtx, toolLoopContextKey{}, record)
	persistErr := service.persistTerminalRun(finishCtx, access, run.ID, run.WorkspaceID, answer,
		[]Citation{}, []candidate{}, "COMPLETED", run.CorpusStatus != "COMPLETE",
		[]Uncertainty{}, []Conflict{}, nil)
	service.observeWorkspaceContextRun(finishCtx, access, run, questionText, record, persistErr)
	return persistErr
}

// renderUnreadableDatabaseAnswer is the whole user-visible answer for a
// database that cannot be read: at most two sentences, naming the database by
// its own human name and naming what makes it readable (the tables confirmed,
// the database reachable, or the taken load limit freeing up). It contains no
// count, no empty result and no technical identifier.
func renderUnreadableDatabaseAnswer(language, name, reason string) string {
	name = singleLine(name)
	if language == questionLanguageRussian {
		switch reason {
		case unreadableSourceReasonTablesUnconfirmed:
			return "База «" + name + "» пока не читается, потому что её таблицы ещё не подтверждены. " +
				"Подтвердите её таблицы, и база станет доступна для чтения."
		case unreadableSourceReasonBusy:
			return "База «" + name + "» сейчас занята — её предел одновременных обращений исчерпан. " +
				"Повторите вопрос чуть позже."
		default:
			return "База «" + name + "» пока не читается — она не отвечает. " +
				"Чтобы её читать, база данных должна быть доступна."
		}
	}
	switch reason {
	case unreadableSourceReasonTablesUnconfirmed:
		return "The database «" + name + "» cannot be read yet, because its tables have not been confirmed. " +
			"Confirm its tables and the database will become readable."
	case unreadableSourceReasonBusy:
		return "The database «" + name + "» is busy right now — its limit of simultaneous reads is taken. " +
			"Ask the question again a little later."
	default:
		return "The database «" + name + "» cannot be read yet — it is not reachable. " +
			"The database must be reachable before its data can be read."
	}
}

// questionNamesSource reports whether the question uses a source's own human
// name. The comparison folds case and writes ё as е, and it also accepts the
// name's common Russian case forms through the name's own stem, so a question
// that says «база заявок» is about «Заявки» just as much as one that copies the
// registered name. Only the workspace's own name is used; no question word is
// listed here.
func questionNamesSource(questionText, name string) bool {
	folded := questionFold(questionText)
	if folded == "" {
		return false
	}
	for _, form := range sourceNameForms(questionFold(name)) {
		if form != "" && strings.Contains(folded, form) {
			return true
		}
	}
	return false
}

// questionFold normalizes the text a name is matched against: lower case, ё
// written as е, leading and trailing space removed.
func questionFold(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.ReplaceAll(value, "ё", "е")
}

// sourceNameForms returns the name and the stem forms of a single-word Russian
// name so a question's own case form still matches. A multi-word name is
// matched by its registered spelling alone; a short name has no stem worth
// matching.
func sourceNameForms(name string) []string {
	forms := []string{name}
	if name == "" || strings.ContainsAny(name, " \t") {
		return forms
	}
	runes := []rune(name)
	if len(runes) < 5 {
		return forms
	}
	if !strings.ContainsRune("аеиоуыэюя", runes[len(runes)-1]) {
		return forms
	}
	stem := string(runes[:len(runes)-1])
	forms = append(forms, stem)
	// A stem ending in к has the fleeting-vowel genitive plural (заявка ->
	// заявок), which keeps the stem's own letters but not its ending.
	stemRunes := []rune(stem)
	if len(stemRunes) >= 5 && stemRunes[len(stemRunes)-1] == 'к' {
		forms = append(forms, string(stemRunes[:len(stemRunes)-1])+"ок")
	}
	return forms
}
