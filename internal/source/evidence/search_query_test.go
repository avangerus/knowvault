package evidence

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestLexicalSearchQueryDefinitionEnvelope(t *testing.T) {
	for _, test := range []struct{ query, want string }{
		{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0426\u0423\u0418\u0422?", "\u0426\u0423\u0418\u0422?"},
		{"\u0427\u0442\u041e\t\u0422\u0430\u041a\u043e\u0415\u00a0SVC-CORE", "SVC-CORE"},
		{"  \u0447\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 payload/customer_id = 42", "payload/customer_id = 42"},
		{"\u0447\u0442\u043e \u0437\u043d\u0430\u0447\u0438\u0442 \u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0451\u043d", "\u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0451\u043d"},
		{"\u0447\u0442\u043e \u044d\u0442\u043e \u0437\u0430 \u043f\u043e\u043b\u0435 account_id", "\u043f\u043e\u043b\u0435 account_id"},
		{"\u043a\u0442\u043e \u0442\u0430\u043a\u043e\u0439 \u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440", "\u0430\u0434\u043c\u0438\u043d\u0438\u0441\u0442\u0440\u0430\u0442\u043e\u0440"},
		{"\u043a\u0442\u043e \u0442\u0430\u043a\u0430\u044f \u0432\u043b\u0430\u0434\u0435\u043b\u0438\u0446\u0430", "\u0432\u043b\u0430\u0434\u0435\u043b\u0438\u0446\u0430"},
		{"\u043a\u0442\u043e \u0442\u0430\u043a\u0438\u0435 \u043e\u043f\u0435\u0440\u0430\u0442\u043e\u0440\u044b", "\u043e\u043f\u0435\u0440\u0430\u0442\u043e\u0440\u044b"},
		{"What is SVC-CORE?", "SVC-CORE?"},
		{"WHAT ARE retry_count and last_seen_at", "retry_count and last_seen_at"},
		{"who is on-call", "on-call"},
		{"who are not owners", "not owners"},
		{"what is not NULL", "not NULL"},
		{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435\"", "\"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435\""},
		{"what is `what is code`", "`what is code`"},
		{"what is what is love", "what is love"},
		{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435", ""}, {"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435?", ""}, {"\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 ?!\t", ""},
		{"what is", ""}, {"WHAT IS...?", ""}, {"what are \u00a0?", ""},
		{"\u0447\u0442\u043e \u044d\u0442\u043e \u0437\u0430?", ""},
	} {
		t.Run(test.query, func(t *testing.T) {
			if got := LexicalSearchQuery(test.query); got != test.want {
				t.Fatalf("query=%q got=%q want=%q", test.query, got, test.want)
			}
		})
	}
}

func TestLexicalSearchQueryPreservesLiteralsCodeIdentifiersAndBounds(t *testing.T) {
	for _, query := range []string{
		"\u0426\u0423\u0418\u0422", "SVC-CORE", "public.customer_id", "payload/account_id = 0042",
		"what_is", "what is_id", "what island", "what isnot NULL", "what is(42)",
		"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435_\u043f\u043e\u043b\u0435", "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435-\u0442\u043e", "\u043d\u0435 \u0432\u043b\u0430\u0434\u0435\u043b\u044c\u0446\u044b", "NOT deleted", "42 2026-09",
		"\"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435\"", "'what is'", "\u00ab\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435\u00bb", "`what is null`",
		"SELECT customer_id FROM accounts WHERE deleted IS NOT NULL",
		"  exact literal\t  ", "\u0447\u0442\u043e-\u043d\u0438\u0431\u0443\u0434\u044c", "whatis", "", "???",
		strings.Repeat("x", 4096), strings.Repeat("what_is ", 512),
	} {
		if got := LexicalSearchQuery(query); got != query {
			t.Fatalf("plain query changed: %q -> %q", query, got)
		}
	}
	subject := strings.Repeat("A_0042-", 4096)
	if got := LexicalSearchQuery("what is " + subject); got != subject {
		t.Fatal("long subject was truncated or rewritten")
	}
}

func TestDefinitionQuestionLexicalMatchRequiresSubject(t *testing.T) {
	for _, test := range []struct{ query, noise, subject string }{
		{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0426\u0423\u0418\u0422?", "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u043e\u0431\u0449\u0435\u0441\u0442\u0432\u043e \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043f\u0443\u0431\u043b\u0438\u0447\u043d\u044b\u043c; \u0447\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 \u0434\u043e\u0433\u043e\u0432\u043e\u0440", "\u0426\u0423\u0418\u0422"},
		{"what is SVC-CORE?", "what is a public company; what is a contract", "SVC-CORE"},
		{"what is customer_id", "what is an account", "customer_id"},
	} {
		// This control demonstrates the previous any-term false positive.
		if _, _, ok := viewerLexicalMatch([]byte(test.noise), viewerSearchTerms(test.query)); !ok {
			t.Fatal("fixture no longer demonstrates question-word noise")
		}
		terms := viewerSearchTerms(LexicalSearchQuery(test.query))
		if _, _, ok := viewerLexicalMatch([]byte(test.noise), terms); ok {
			t.Fatalf("question words alone supported %q", test.query)
		}
		text := []byte(test.noise + strings.Repeat(" unrelated filler", 40) + " " + test.subject + " = exact value")
		before := append([]byte(nil), text...)
		if _, excerpt, ok := viewerLexicalMatch(text, terms); !ok || !strings.Contains(excerpt, test.subject) {
			t.Fatalf("subject or its excerpt missing: %q", excerpt)
		}
		if excerpt := Excerpt(text, test.query); !strings.Contains(excerpt, test.subject) {
			t.Fatalf("public excerpt centered question words: %q", excerpt)
		}
		if !bytes.Equal(text, before) {
			t.Fatal("ranking mutated canonical evidence bytes")
		}
	}
}

func TestSearchWithoutQuestionSubjectAdmitsBeforeEmptyPage(t *testing.T) {
	for _, query := range []string{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435?", "WHAT IS", "what are ?"} {
		for _, allowed := range []bool{true, false} {
			sink := &recordingSink{}
			// The store has no pool: a corpus scan would fail this test. Empty
			// subject handling must end after live authorization and admission.
			viewer := &Viewer{db: &database.Store{}, audit: sink,
				authorizeWorkspaceFn: func(context.Context, database.AccessContext, string) (bool, error) { return allowed, nil }}
			page, err := viewer.SearchFragments(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", query, false, 0, 10)
			if (err == nil) != allowed || len(page.Hits) != 0 || page.HasMore || page.NextOffset != 0 || len(sink.appended) != 1 {
				t.Fatalf("query=%q allowed=%v page=%+v error=%v events=%d", query, allowed, page, err, len(sink.appended))
			}
			if !allowed && (!errors.Is(err, ErrNotFound) || sink.appended[0].WorkspaceID != nil || sink.appended[0].Outcome != audit.OutcomeDenied) {
				t.Fatal("empty subject bypassed the opaque denial gate")
			}
		}
	}
	viewer := &Viewer{db: &database.Store{}, audit: failingSink{},
		authorizeWorkspaceFn: func(context.Context, database.AccessContext, string) (bool, error) { return true, nil }}
	if _, err := viewer.SearchFragments(context.Background(), evidenceAccess(database.ActorKindHuman), "ws_0001", "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435", false, 0, 10); !errors.Is(err, ErrNotFound) {
		t.Fatal("failed journal returned a successful empty page")
	}
}
