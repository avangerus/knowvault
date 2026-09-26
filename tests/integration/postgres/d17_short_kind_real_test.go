package postgres_test

// Card D-17 result 1 and 2 on the real model. This test runs the question
// set's H1 and H2 and the executor's own rewordings three times each against
// DeepSeek, through the real question service, the real synthetic proving
// workspace and the real recognition step. It requires the DeepSeek key file
// and starts (and removes) the card's own PostgreSQL container.
//
// The four rewordings are the executor's own: D17A and D17B are off-topic
// questions, D17C and D17D are vague requests. Neither pair is added to
// tests/e2e/questions/questions.json; they exist only in this test's in-memory
// set copy.

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/question"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// d17Rewordings are the executor's own off-topic and vague phrasings. The
// expected kind of each is asserted against the real recognition step.
var d17Rewordings = []questions.Question{
	{
		ID: "D17A", Text: "какой курс доллара сегодня?", Language: "ru",
		MaxSteps: 1, TimeLimitS: 20, MaxChars: 700,
		Expectation: "Коротко: вопрос вне рабочей области; что можно спросить вместо.",
		Checks: []questions.Check{
			{ID: "d17a_sentences", Type: "max_sentences", Hard: true, Max: 2},
			{ID: "d17a_no_sql", Type: "max_sql_calls", Hard: true, Max: 0},
			{ID: "d17a_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"договор", "клиент", "МНО"}},
		},
	},
	{
		ID: "D17B", Text: "посоветуй фильм на вечер", Language: "ru",
		MaxSteps: 1, TimeLimitS: 20, MaxChars: 700,
		Expectation: "Коротко: вопрос вне рабочей области; что можно спросить вместо.",
		Checks: []questions.Check{
			{ID: "d17b_sentences", Type: "max_sentences", Hard: true, Max: 2},
			{ID: "d17b_no_sql", Type: "max_sql_calls", Hard: true, Max: 0},
			{ID: "d17b_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"договор", "клиент", "МНО"}},
		},
	},
	{
		ID: "D17C", Text: "ну покажи", Language: "ru",
		MaxSteps: 1, TimeLimitS: 20, MaxChars: 400,
		Expectation: "Один уточняющий вопрос с вариантами из того, что есть в рабочей области.",
		Checks: []questions.Check{
			{ID: "d17c_question", Type: "question_marks", Hard: true, Min: 1, Max: 1},
			{ID: "d17c_chars", Type: "max_chars", Hard: true, Max: 400},
			{ID: "d17c_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"договор", "клиент", "МНО"}},
		},
	},
	{
		ID: "D17D", Text: "выведи данные", Language: "ru",
		MaxSteps: 1, TimeLimitS: 20, MaxChars: 400,
		Expectation: "Один уточняющий вопрос с вариантами из того, что есть в рабочей области.",
		Checks: []questions.Check{
			{ID: "d17d_question", Type: "question_marks", Hard: true, Min: 1, Max: 1},
			{ID: "d17d_chars", Type: "max_chars", Hard: true, Max: 400},
			{ID: "d17d_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"договор", "клиент", "МНО"}},
		},
	},
}

// d17RealModelQuestions are the question ids the real-model run covers.
var d17RealModelQuestions = "H1,H2,D17A,D17B,D17C,D17D"

// d17ExpectedKinds is the kind each covered question must be recognised as.
var d17ExpectedKinds = map[string]question.AnswerKind{
	"H1": question.AnswerKindOffTopic, "D17A": question.AnswerKindOffTopic, "D17B": question.AnswerKindOffTopic,
	"H2": question.AnswerKindVague, "D17C": question.AnswerKindVague, "D17D": question.AnswerKindVague,
}

// d17ForbiddenRunTools are the tools a short-kind run may never reach. A system
// source-list read is allowed and is not a step.
var d17ForbiddenRunTools = map[string]bool{
	"knowvault_search": true, "knowvault_read": true, "knowvault_grep": true,
	"knowvault_evidence_read": true, "knowvault_list_objects": true, "knowvault_related": true,
	"knowvault_source_sql": true, "knowvault_source_schema": true,
	"knowvault_ask_live_data": true, "knowvault_compare_metric": true, "knowvault_analyze": true,
}

// TestD17ShortKindRealModel is the card's real-model run for result 1 and 2.
func TestD17ShortKindRealModel(t *testing.T) {
	keyFile := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_API_KEY_FILE"))
	if keyFile == "" {
		t.Skip("set KNOWVAULT_QUESTION_SET_API_KEY_FILE to the DeepSeek key file to run the real question set")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read DeepSeek key file: %v", err)
	}
	apiKey := strings.TrimSpace(string(key))
	if apiKey == "" {
		t.Fatal("the DeepSeek key file is empty")
	}

	ctx := t.Context()
	set := loadE1aSet(t)
	// The rewordings live only in this copy; questions.json is unchanged.
	set.Questions = append(set.Questions, d17Rewordings...)

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		t.Fatalf("system certificate pool: %v", err)
	}
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion,
		Endpoint:      set.Model.Endpoint, ModelID: set.Model.ModelID,
		APIKey: apiKey, MaxOutputTokens: 16384, InsecureLabMode: true,
		ThinkingMode: modelgateway.ThinkingModeDisabled, TrustRoots: pool,
		ExternalRuntimeWorkspaceIDs: []string{set.Environment.WorkspaceID},
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "d17-real", MaxTurns: 10, MaxToolCalls: 10, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 16384, TimeoutSeconds: 240,
		},
	})
	if err != nil {
		t.Fatalf("real adapter: %v", err)
	}
	defer adapter.Close()

	// The card's own product database, named and ported by the brief. It is
	// started here and removed with its volumes by the harness cleanup.
	productURL := "postgres://postgres:postgres@localhost:55618/knowvault_test?sslmode=disable"
	t.Setenv("KNOWVAULT_TEST_POSTGRES_URL", productURL)
	e1aEnsureContainer(t, ctx, "kv-card-d-17-pg", 55618, "knowvault_test")

	admin := resetStage1Database(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d17-real"})
	env.Questions.EnableGeneration(adapter, nil)

	only := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_ONLY"))
	if only == "" {
		only = d17RealModelQuestions
	}
	t.Setenv("KNOWVAULT_QUESTION_SET_ONLY", only)
	started := time.Now()
	runs := e1aRunQuestionSet(t, ctx, env, func(questions.Question) string { return "" })
	fmt.Printf("D17 REAL RUN seconds=%.2f runs=%d\n", time.Since(started).Seconds(), len(runs))

	byID := map[string][]questions.RunReport{}
	for _, run := range runs {
		byID[run.QuestionID] = append(byID[run.QuestionID], run)
		names := make([]string, 0, len(run.ToolCalls))
		for _, call := range run.ToolCalls {
			names = append(names, call.Name)
		}
		fmt.Printf("D17 RUN %s run=%d kind=%s steps=%d stop=%s status=%s tools=%v sql_calls=%d answer=%q\n",
			run.QuestionID, run.Run, run.Kind, run.Steps, run.StopReason, run.Status, names, len(run.SQLTexts), run.Answer)
	}
	for _, id := range strings.Split(only, ",") {
		id = strings.TrimSpace(id)
		if len(byID[id]) != 3 {
			t.Fatalf("question %s ran %d times, want 3", id, len(byID[id]))
		}
	}
	for _, id := range strings.Split(only, ",") {
		id = strings.TrimSpace(id)
		wantKind, covered := d17ExpectedKinds[id]
		if !covered {
			continue
		}
		for _, run := range byID[id] {
			if run.Kind != string(wantKind) {
				t.Fatalf("%s run %d recognised as %q, want %s (answer %q)", id, run.Run, run.Kind, wantKind, run.Answer)
			}
			if run.Steps != 0 {
				t.Fatalf("%s run %d took %d steps, want 0 (answer %q)", id, run.Run, run.Steps, run.Answer)
			}
			if len(run.SQLTexts) != 0 {
				t.Fatalf("%s run %d made a SQL query: %v", id, run.Run, run.SQLTexts)
			}
			for _, call := range run.ToolCalls {
				if d17ForbiddenRunTools[call.Name] {
					t.Fatalf("%s run %d reached the tool %s", id, run.Run, call.Name)
				}
			}
			if run.LiveResultKind != "" {
				t.Fatalf("%s run %d carries a live-data result %q", id, run.Run, run.LiveResultKind)
			}
			if !d17AnswerNamesWorkspaceSubject(run.Answer) {
				t.Fatalf("%s run %d names nothing the workspace holds: %q", id, run.Run, run.Answer)
			}
			if !run.Passed {
				failed := []string{}
				for _, verdict := range run.Verdicts {
					if !verdict.Passed {
						failed = append(failed, fmt.Sprintf("%s (%s)", verdict.ID, verdict.Detail))
					}
				}
				t.Fatalf("%s run %d failed the question set's own rules: %s; answer %q", id, run.Run, strings.Join(failed, ", "), run.Answer)
			}
			switch wantKind {
			case question.AnswerKindOffTopic:
				if sentences := d17SentenceCount(run.Answer); sentences > 2 {
					t.Fatalf("%s run %d off_topic answer has %d sentences: %q", id, run.Run, sentences, run.Answer)
				}
				if !strings.Contains(run.Answer, "не относится") {
					t.Fatalf("%s run %d off_topic answer is not the off-topic wording: %q", id, run.Run, run.Answer)
				}
			case question.AnswerKindVague:
				if marks := strings.Count(run.Answer, "?"); marks != 1 {
					t.Fatalf("%s run %d vague answer has %d question marks: %q", id, run.Run, marks, run.Answer)
				}
				if length := len([]rune(run.Answer)); length > 400 {
					t.Fatalf("%s run %d vague answer has %d characters: %q", id, run.Run, length, run.Answer)
				}
			}
		}
	}
}

// d17AnswerNamesWorkspaceSubject reports whether the answer names at least one
// subject the synthetic workspace's own registration holds.
func d17AnswerNamesWorkspaceSubject(answer string) bool {
	lower := strings.ToLower(answer)
	for _, subject := range []string{"договор", "клиент", "мно", "регламент"} {
		if strings.Contains(lower, subject) {
			return true
		}
	}
	return false
}
