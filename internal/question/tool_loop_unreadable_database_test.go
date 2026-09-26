package question

// Card D-18 unit tests for the deterministic readability route: the stored
// state classification, the registered-name match, the live probe outcome and
// the rendered answer. Recognition by meaning is measured by real-model runs
// (tests/integration/postgres); these tests pin the deterministic parts.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func boolPointer(value bool) *bool { return &value }

func d18Source(overrides func(*toolLoopOverviewSource)) toolLoopOverviewSource {
	source := toolLoopOverviewSource{
		Name: "Заявки", ConnectionID: "conn_request", SourceType: "POSTGRESQL_QUERY",
		Enabled: true, ActivationStatus: "READY",
		Confirmed: boolPointer(true), TrustVerified: boolPointer(true), SQLAvailable: boolPointer(true),
	}
	if overrides != nil {
		overrides(&source)
	}
	return source
}

func TestUnreadableSourceReason(t *testing.T) {
	cases := []struct {
		name   string
		source toolLoopOverviewSource
		want   string
		unread bool
	}{
		{name: "readable", source: d18Source(nil), unread: false},
		{name: "tables await confirmation", source: d18Source(func(s *toolLoopOverviewSource) { s.Confirmed = boolPointer(false) }), want: unreadableSourceReasonTablesUnconfirmed, unread: true},
		{name: "disabled", source: d18Source(func(s *toolLoopOverviewSource) { s.Enabled = false }), want: unreadableSourceReasonNotReachable, unread: true},
		{name: "not ready", source: d18Source(func(s *toolLoopOverviewSource) { s.ActivationStatus = "FAILED" }), want: unreadableSourceReasonNotReachable, unread: true},
		{name: "draft", source: d18Source(func(s *toolLoopOverviewSource) { s.ActivationStatus = "DRAFT" }), want: unreadableSourceReasonNotReachable, unread: true},
		{name: "untrusted", source: d18Source(func(s *toolLoopOverviewSource) { s.TrustVerified = boolPointer(false) }), want: unreadableSourceReasonNotReachable, unread: true},
		{name: "no query access", source: d18Source(func(s *toolLoopOverviewSource) { s.SQLAvailable = boolPointer(false) }), want: unreadableSourceReasonNotReachable, unread: true},
		{name: "absent facts are not a failure", source: d18Source(func(s *toolLoopOverviewSource) {
			s.Confirmed, s.TrustVerified, s.SQLAvailable = nil, nil, nil
		}), unread: false},
		{name: "a document folder is never a database", source: d18Source(func(s *toolLoopOverviewSource) {
			s.SourceType, s.Confirmed = "FOLDER", boolPointer(false)
		}), unread: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reason, unread := unreadableSourceReason(test.source)
			if unread != test.unread || reason != test.want {
				t.Fatalf("reason=%q unread=%t, want %q/%t", reason, unread, test.want, test.unread)
			}
		})
	}
}

// TestToolLoopOverviewClassForRun pins ADR-0099 amendment 1 decision 5 for the
// orientation block: with the separate recognition step on, only the shape that
// belongs to the recognised kind is used, so a full count question that merely
// says "база" is not handed another kind's rule. With recognition off the
// deterministic classifier is unchanged.
func TestToolLoopOverviewClassForRun(t *testing.T) {
	const databaseCountQuestion = "Сколько заявок в базе «Заявки»?"
	if !toolLoopOverviewQuestion(databaseCountQuestion) {
		t.Fatalf("the deterministic classifier no longer recognises %q; the test's premise is gone", databaseCountQuestion)
	}
	cases := []struct {
		name          string
		recognitionOn bool
		kind          AnswerKind
		question      string
		want          toolLoopOverviewClass
	}{
		{"recognition off keeps the deterministic class", false, "", databaseCountQuestion, toolLoopOverviewClassDatabase},
		{"a full count question gets no other kind's rule", true, AnswerKindFull, databaseCountQuestion, toolLoopOverviewClassNone},
		{"a full overview-sounding question keeps the ordinary loop too", true, AnswerKindFull, "что есть в базе?", toolLoopOverviewClassNone},
		{"a workspace overview keeps its deterministic shape", true, AnswerKindWorkspaceOverview, "что ты знаешь?", toolLoopOverviewClassOverview},
		{"a sources overview keeps its deterministic shape", true, AnswerKindSourcesOverview, "какие есть источники?", toolLoopOverviewClassSources},
		{"a greeting keeps its deterministic shape", true, AnswerKindGreeting, "привет", toolLoopOverviewClassGreeting},
		{"a database overview word is still the deterministic shape for another kind", true, AnswerKindWorkspaceOverview, databaseCountQuestion, toolLoopOverviewClassDatabase},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := toolLoopOverviewClassForRun(test.recognitionOn, test.kind, test.question); got != test.want {
				t.Fatalf("class=%v, want %v", got, test.want)
			}
		})
	}
}

func TestQuestionNamesSource(t *testing.T) {
	cases := []struct {
		question string
		name     string
		want     bool
	}{
		{"Сколько заявок в базе «Заявки»?", "Заявки", true},
		{"Посчитай число заявок в базе «Заявки».", "Заявки", true},
		{"Сколько всего заявок?", "Заявки", true},
		{"Сколько заявкам присвоено номеров?", "Заявки", true},
		{"Сколько заявках записей?", "Заявки", true},
		{"Сколько договоров действует?", "Заявки", false},
		{"Что в регламенте сказано про сроки вывоза?", "Заявки", false},
		{"Регламенты и договоры обновляли?", "Регламенты и договоры", true},
		{"Обновляли ли регламенты и договоры?", "Регламенты и договоры", true},
		{"Сколько клиентов?", "Клиенты", true},
		{"Что написано в документе?", "МНО", false},
	}
	for _, test := range cases {
		if got := questionNamesSource(test.question, test.name); got != test.want {
			t.Fatalf("questionNamesSource(%q, %q)=%t, want %t", test.question, test.name, got, test.want)
		}
	}
}

func TestRenderUnreadableDatabaseAnswer(t *testing.T) {
	cases := []struct {
		language string
		reason   string
		contains []string
	}{
		{questionLanguageRussian, unreadableSourceReasonTablesUnconfirmed,
			[]string{"Заявки", "подтвержд", "таблиц", "не чита"}},
		{questionLanguageRussian, unreadableSourceReasonNotReachable,
			[]string{"Заявки", "не отвеча", "доступна"}},
		{questionLanguageEnglish, unreadableSourceReasonTablesUnconfirmed,
			[]string{"Заявки", "cannot be read", "confirmed", "tables"}},
		{questionLanguageEnglish, unreadableSourceReasonNotReachable,
			[]string{"Заявки", "cannot be read", "reachable"}},
	}
	for _, test := range cases {
		answer := renderUnreadableDatabaseAnswer(test.language, "Заявки", test.reason)
		if sentences := shortKindTestSentenceCount(answer); sentences > 2 {
			t.Fatalf("%s/%s answer has %d sentences: %q", test.language, test.reason, sentences, answer)
		}
		if strings.ContainsAny(answer, "0123456789") {
			t.Fatalf("%s/%s answer carries a number: %q", test.language, test.reason, answer)
		}
		lowered := strings.ToLower(answer)
		for _, want := range test.contains {
			if !strings.Contains(lowered, strings.ToLower(want)) {
				t.Fatalf("%s/%s answer %q does not contain %q", test.language, test.reason, answer, want)
			}
		}
	}
}

// d18Runtime is a closed fake workspace tools runtime: it serves one source
// inventory and reports the live probe outcome the test chose.
type d18Runtime struct {
	envelope json.RawMessage
	probeErr error
	probed   []string
}

func (runtime *d18Runtime) Catalog(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
	return nil, nil
}

func (runtime *d18Runtime) Invoke(_ context.Context, _ workspacetools.Scope, name string, _ json.RawMessage) (workspacetools.Result, error) {
	if name != "knowvault_sources" {
		return workspacetools.Result{IsError: true, Text: `{"error":"UNKNOWN_TOOL"}`}, nil
	}
	return workspacetools.Result{Structured: runtime.envelope}, nil
}

func (runtime *d18Runtime) ProbeSourceReadable(_ context.Context, _ database.AccessContext, _ string, connectionID string) error {
	runtime.probed = append(runtime.probed, connectionID)
	return runtime.probeErr
}

func d18Envelope(t *testing.T, sources ...toolLoopOverviewSource) json.RawMessage {
	t.Helper()
	type wireSource struct {
		ConnectionID     string `json:"connection_id"`
		ConnectionName   string `json:"connection_name"`
		SourceType       string `json:"source_type"`
		Enabled          bool   `json:"enabled"`
		ActivationStatus string `json:"activation_status"`
		TrustVerified    *bool  `json:"trust_verified"`
		Confirmed        *bool  `json:"confirmed"`
		SQLAvailable     *bool  `json:"sql_available"`
	}
	wire := struct {
		Sources []wireSource `json:"sources"`
	}{}
	for _, source := range sources {
		wire.Sources = append(wire.Sources, wireSource{
			ConnectionID: source.ConnectionID, ConnectionName: source.Name, SourceType: source.SourceType,
			Enabled: source.Enabled, ActivationStatus: source.ActivationStatus,
			TrustVerified: source.TrustVerified, Confirmed: source.Confirmed, SQLAvailable: source.SQLAvailable,
		})
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestUnreadableDatabaseForQuestion(t *testing.T) {
	t.Run("a named database awaiting confirmation is found without a probe", func(t *testing.T) {
		runtime := &d18Runtime{envelope: d18Envelope(t, d18Source(func(s *toolLoopOverviewSource) { s.Confirmed = boolPointer(false) }))}
		service := &Service{tools: runtime}
		found, err := service.unreadableDatabaseForQuestion(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{}, "Сколько заявок в базе «Заявки»?")
		if err != nil || found == nil {
			t.Fatalf("found=%+v err=%v, want the unconfirmed database", found, err)
		}
		if found.Name != "Заявки" || found.Reason != unreadableSourceReasonTablesUnconfirmed {
			t.Fatalf("found=%+v, want Заявки/%s", found, unreadableSourceReasonTablesUnconfirmed)
		}
		if len(runtime.probed) != 0 {
			t.Fatalf("stored-state route probed %v, want no probe", runtime.probed)
		}
	})

	t.Run("a healthy named database is probed and kept readable", func(t *testing.T) {
		runtime := &d18Runtime{envelope: d18Envelope(t, d18Source(nil))}
		service := &Service{tools: runtime}
		found, err := service.unreadableDatabaseForQuestion(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{}, "Сколько заявок в базе «Заявки»?")
		if err != nil || found != nil {
			t.Fatalf("found=%+v err=%v, want no unreadable database", found, err)
		}
		if len(runtime.probed) != 1 || runtime.probed[0] != "conn_request" {
			t.Fatalf("probed=%v, want one probe of conn_request", runtime.probed)
		}
	})

	t.Run("a named database that does not answer is found by the probe", func(t *testing.T) {
		runtime := &d18Runtime{envelope: d18Envelope(t, d18Source(nil)), probeErr: context.DeadlineExceeded}
		service := &Service{tools: runtime}
		found, err := service.unreadableDatabaseForQuestion(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{}, "Сколько заявок в базе «Заявки»?")
		if err != nil || found == nil || found.Reason != unreadableSourceReasonNotReachable {
			t.Fatalf("found=%+v err=%v, want the unreachable database", found, err)
		}
	})

	t.Run("a question about another source is untouched", func(t *testing.T) {
		runtime := &d18Runtime{envelope: d18Envelope(t, d18Source(func(s *toolLoopOverviewSource) { s.Confirmed = boolPointer(false) }))}
		service := &Service{tools: runtime}
		found, err := service.unreadableDatabaseForQuestion(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{}, "Сколько договоров действует?")
		if err != nil || found != nil {
			t.Fatalf("found=%+v err=%v, want no unreadable database for another source", found, err)
		}
		if len(runtime.probed) != 0 {
			t.Fatalf("unrelated question probed %v, want no probe", runtime.probed)
		}
	})

	t.Run("a runtime without the probe capability keeps the stored-state decision", func(t *testing.T) {
		runtime := &d18Runtime{envelope: d18Envelope(t, d18Source(nil))}
		service := &Service{tools: d18CatalogOnlyRuntime{runtime}}
		found, err := service.unreadableDatabaseForQuestion(context.Background(), workspacetools.Scope{}, &ToolLoopRecord{}, "Сколько заявок в базе «Заявки»?")
		if err != nil || found != nil {
			t.Fatalf("found=%+v err=%v, want no unreadable database without a probe", found, err)
		}
	})
}

// d18CatalogOnlyRuntime hides the probe capability: it is a runtime that
// serves the inventory but cannot open a source.
type d18CatalogOnlyRuntime struct{ inner *d18Runtime }

func (runtime d18CatalogOnlyRuntime) Catalog(ctx context.Context, scope workspacetools.Scope) ([]workspacetools.Definition, error) {
	return runtime.inner.Catalog(ctx, scope)
}

func (runtime d18CatalogOnlyRuntime) Invoke(ctx context.Context, scope workspacetools.Scope, name string, args json.RawMessage) (workspacetools.Result, error) {
	return runtime.inner.Invoke(ctx, scope, name, args)
}
