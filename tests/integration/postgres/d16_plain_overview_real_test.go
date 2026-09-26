package postgres_test

// Card D-16 result 1 and 2 on the real model. This test runs the question
// set's Q13 and the executor's own rewordings three times each against
// DeepSeek, through the real question service, the real synthetic proving
// workspace and the real recognition step. It requires the DeepSeek key file
// and the pinned product database, and it is skipped without the key.
//
// The two rewordings are the executor's own: D16A keeps the contracts subject
// with another verb, D16B asks about a subject the synthetic workspace holds
// nothing about. Neither is added to tests/e2e/questions/questions.json; they
// exist only in this test's in-memory set copy.

import (
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/question"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// d16Rewordings are the executor's own rewordings of Q13. D16A keeps the
// contracts subject with another verb, D16B asks about a subject the synthetic
// workspace holds nothing about.
var d16Rewordings = []questions.Question{
	{
		ID: "D16A", Text: "растолкуй по-человечески, что у нас есть по договорам", Language: "ru",
		MaxSteps: 3, TimeLimitS: 40, MaxChars: 700,
		Expectation: "Короткое деловое описание того, что рабочая область содержит о договорах, с вопросом в конце.",
		Checks: []questions.Check{{ID: "d16a_topic", Type: "mentions_terms", Hard: true, Min: 1,
			Texts: []string{"договор"}}},
	},
	{
		ID: "D16B", Text: "объясни простыми словами, что у нас есть про пироги", Language: "ru",
		MaxSteps: 3, TimeLimitS: 40, MaxChars: 700,
		Expectation: "Коротко: данных о пирогах нет; без описания данных рабочей области.",
	},
}

// d16RealModelQuestions are the question ids the real-model run covers.
var d16RealModelQuestions = "Q13,D16A,D16B"

// d16SQLAndLiveTools are the tools a plain_overview run may never reach.
var d16SQLAndLiveTools = map[string]bool{
	"knowvault_source_sql": true, "knowvault_source_schema": true,
	"knowvault_ask_live_data": true, "knowvault_compare_metric": true, "knowvault_analyze": true,
}

// d16TechnicalAnswerTerms lists the synthetic workspace's registered relation
// and column names. A plain_overview answer must contain none of them.
func d16TechnicalAnswerTerms(set *questions.Set) []string {
	terms := []string{}
	for _, source := range set.Environment.Sources {
		terms = append(terms, source.Table)
		for _, column := range source.Columns {
			terms = append(terms, column)
		}
	}
	return terms
}

func TestD16PlainOverviewRealModel(t *testing.T) {
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
	set.Questions = append(set.Questions, d16Rewordings...)

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
			ID: "d16-real", MaxTurns: 10, MaxToolCalls: 10, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 16384, TimeoutSeconds: 240,
		},
	})
	if err != nil {
		t.Fatalf("real adapter: %v", err)
	}
	defer adapter.Close()

	admin := resetStage1Database(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d16-real"})
	env.Questions.EnableGeneration(adapter, nil)

	only := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_ONLY"))
	if only == "" {
		only = d16RealModelQuestions
	}
	t.Setenv("KNOWVAULT_QUESTION_SET_ONLY", only)
	started := time.Now()
	runs := e1aRunQuestionSet(t, ctx, env, func(questions.Question) string { return "" })
	fmt.Printf("D16 REAL RUN seconds=%.2f runs=%d\n", time.Since(started).Seconds(), len(runs))

	technical := d16TechnicalAnswerTerms(set)
	byID := map[string][]questions.RunReport{}
	for _, run := range runs {
		byID[run.QuestionID] = append(byID[run.QuestionID], run)
		names := make([]string, 0, len(run.ToolCalls))
		for _, call := range run.ToolCalls {
			names = append(names, call.Name)
		}
		fmt.Printf("D16 RUN %s run=%d kind=%s stop=%s status=%s tools=%v sql_calls=%d answer=%q\n",
			run.QuestionID, run.Run, run.Kind, run.StopReason, run.Status, names, len(run.SQLTexts), run.Answer)
	}
	for _, id := range strings.Split(only, ",") {
		id = strings.TrimSpace(id)
		if len(byID[id]) != 3 {
			t.Fatalf("question %s ran %d times, want 3", id, len(byID[id]))
		}
	}
	for _, id := range strings.Split(only, ",") {
		id = strings.TrimSpace(id)
		for _, run := range byID[id] {
			if run.Kind != string(question.AnswerKindPlainOverview) {
				t.Fatalf("%s run %d recognised as %q, want plain_overview (answer %q)", id, run.Run, run.Kind, run.Answer)
			}
			if len(run.SQLTexts) != 0 {
				t.Fatalf("%s run %d made a SQL query: %v", id, run.Run, run.SQLTexts)
			}
			for _, call := range run.ToolCalls {
				if d16SQLAndLiveTools[call.Name] {
					t.Fatalf("%s run %d reached the data tool %s", id, run.Run, call.Name)
				}
			}
			if run.LiveResultKind != "" {
				t.Fatalf("%s run %d carries a live-data result %q", id, run.Run, run.LiveResultKind)
			}
			if !toolLoopAnswerEndsWithQuestion(run.Answer) {
				t.Fatalf("%s run %d does not end with a next question: %q", id, run.Run, run.Answer)
			}
			lower := strings.ToLower(run.Answer)
			for _, term := range technical {
				if strings.Contains(lower, strings.ToLower(term)) {
					t.Fatalf("%s run %d names the technical term %q: %q", id, run.Run, term, run.Answer)
				}
			}
			if run.QuestionID == "D16B" {
				if regexp.MustCompile(`\d`).MatchString(run.Answer) {
					t.Fatalf("D16B run %d states a value about a subject the workspace does not hold: %q", run.Run, run.Answer)
				}
				if !regexp.MustCompile(`(?i)(нет|не |ничего|отсутств)`).MatchString(run.Answer) {
					t.Fatalf("D16B run %d does not say the workspace holds nothing: %q", run.Run, run.Answer)
				}
				continue
			}
			if !strings.Contains(lower, "договор") {
				t.Fatalf("%s run %d names nothing the workspace holds about contracts: %q", id, run.Run, run.Answer)
			}
		}
	}
}
