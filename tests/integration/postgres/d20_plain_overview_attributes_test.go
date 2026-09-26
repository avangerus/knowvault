package postgres_test

// Card D-20 results 1 and 2 on the real model. This test runs the question
// set's Q2, Q11 and Q13 and the executor's own two questions about other
// subjects the synthetic database holds (D20A clients, D20B container sites)
// three times each against DeepSeek, through the real question service, the
// real synthetic proving workspace and the real recognition step.
//
// It starts its own product database container (kv-card-d-20-pg on 55624, the
// card's own container) and removes it with its volumes when the test ends. It
// requires the DeepSeek key file and is skipped without it.
//
// The two own questions exist only in this test's in-memory copy of the set:
// tests/e2e/questions/questions.json is unchanged, and no check type is added
// to it. The recorded-attribute expectations below are this test's own reading
// of the synthetic database's structure.

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

// Card D-20's own product container and the questions this run covers.
const (
	d20ProductContainer = "kv-card-d-20-pg"
	d20ProductPort      = 55624
	d20ProductDatabase  = "knowvault_test"
	d20QuestionIDs      = "Q2,Q11,Q13,D20A,D20B"
)

// d20OwnQuestions are the executor's own rewordings about two subjects the
// synthetic database holds besides contracts: its clients and its container
// sites. They live only in this test's copy; questions.json is unchanged.
var d20OwnQuestions = []questions.Question{
	{
		ID: "D20A", Text: "что база хранит про клиентов, расскажи деловыми словами", Language: "ru",
		MaxSteps: 3, TimeLimitS: 45, MaxChars: 700,
		Expectation: "Деловое описание записанных сведений о клиентах, с вопросом в конце.",
		Checks: []questions.Check{
			{ID: "d20a_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"клиент"}},
			{ID: "d20a_lines", Type: "max_nonempty_lines", Hard: true, Max: 6},
		},
	},
	{
		ID: "D20B", Text: "объясни простыми словами, какие сведения есть про места накопления отходов", Language: "ru",
		MaxSteps: 3, TimeLimitS: 45, MaxChars: 700,
		Expectation: "Деловое описание записанных сведений о площадках, с вопросом в конце.",
		Checks: []questions.Check{
			{ID: "d20b_topic", Type: "mentions_terms", Hard: true, Min: 1, Texts: []string{"площадк", "мест", "мно"}},
			{ID: "d20b_lines", Type: "max_nonempty_lines", Hard: true, Max: 6},
		},
	},
}

// d20TopicSource maps a question to the one synthetic database subject it is
// about. Q11 is about the whole database and is judged by result 2 only.
var d20TopicSource = map[string]string{
	"Q2": "contract", "Q13": "contract", "D20A": "client", "D20B": "container_group",
}

// d20RecordedTerms is this test's own reading of the synthetic database's
// structure: for each registered column of a subject's relation, the business
// words that name what the column really records.
var d20RecordedTerms = map[string]map[string][]string{
	"contract": {
		"number":    {"номер"},
		"client_id": {"клиент"},
		"status":    {"статус"},
		"signed_on": {"дат"},
		"amount":    {"сумм", "стоимост"},
	},
	"client": {
		"id":   {"идентификатор", "номер"},
		"name": {"назван", "имя", "наименован"},
		"inn":  {"инн"},
	},
	"container_group": {
		"id":          {"идентификатор", "номер"},
		"contract_id": {"договор"},
		"code":        {"код"},
		"address":     {"адрес"},
	},
}

// TestD20PlainOverviewNamesRecordedAttributes is card D-20's real-model proof.
func TestD20PlainOverviewNamesRecordedAttributes(t *testing.T) {
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
	productURL := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable",
		d20ProductPort, d20ProductDatabase)
	t.Setenv("KNOWVAULT_TEST_POSTGRES_URL", productURL)
	e1aEnsureContainer(t, ctx, d20ProductContainer, d20ProductPort, d20ProductDatabase)

	set := loadE1aSet(t)
	// The two own questions live only in this copy; questions.json is unchanged.
	set.Questions = append(set.Questions, d20OwnQuestions...)

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
			ID: "d20-real", MaxTurns: 10, MaxToolCalls: 10, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 16384, TimeoutSeconds: 240,
		},
	})
	if err != nil {
		t.Fatalf("real adapter: %v", err)
	}
	defer adapter.Close()

	admin := resetStage1Database(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d20-real"})
	env.Questions.EnableGeneration(adapter, nil)

	t.Setenv("KNOWVAULT_QUESTION_SET_ONLY", d20QuestionIDs)
	started := time.Now()
	runs := e1aRunQuestionSet(t, ctx, env, func(questions.Question) string { return "" })
	fmt.Printf("D20 REAL RUN seconds=%.2f runs=%d\n", time.Since(started).Seconds(), len(runs))

	technical := d16TechnicalAnswerTerms(set)
	documentCorpus := d20DocumentCorpus(set)
	byID := map[string][]questions.RunReport{}
	for _, run := range runs {
		byID[run.QuestionID] = append(byID[run.QuestionID], run)
	}

	fmt.Printf("D20 TABLE question | run | kind | stop | lines | recorded-attributes | verdict\n")
	failures := []string{}
	for _, id := range strings.Split(d20QuestionIDs, ",") {
		id = strings.TrimSpace(id)
		if len(byID[id]) != 3 {
			t.Fatalf("question %s ran %d times, want 3", id, len(byID[id]))
		}
		for _, run := range byID[id] {
			lines := d20NonEmptyLines(run.Answer)
			var green bool
			detail := ""
			if run.QuestionID == "Q11" {
				green = run.Kind == string(question.AnswerKindPlainOverview) &&
					len(run.SQLTexts) == 0 && run.LiveResultKind == "" &&
					lines <= 6 && toolLoopAnswerEndsWithQuestion(run.Answer) &&
					d20NoTechnicalTerm(run.Answer, technical)
				detail = "whole-database overview"
			} else {
				sourceID := d20TopicSource[run.QuestionID]
				matched := d20RecordedAttributes(set, sourceID, run.Answer)
				schemaOnly := d20SchemaOnlyAttributes(set, sourceID, matched, documentCorpus)
				green = run.Kind == string(question.AnswerKindPlainOverview) &&
					len(run.SQLTexts) == 0 && run.LiveResultKind == "" &&
					lines <= 6 && toolLoopAnswerEndsWithQuestion(run.Answer) &&
					len(matched) >= 3 && len(schemaOnly) >= 1 && d20NoTechnicalTerm(run.Answer, technical)
				detail = fmt.Sprintf("%s: %s (schema-only: %s)", sourceID, strings.Join(matched, ","), strings.Join(schemaOnly, ","))
			}
			// The visible question set's own hard rules (length, language,
			// steps and the per-question checks) must also pass: acceptance
			// judges the same questions with them.
			green = green && run.Passed
			verdictText := "RED"
			if green {
				verdictText = "GREEN"
			} else {
				failures = append(failures, fmt.Sprintf("%s run %d", id, run.Run))
			}
			fmt.Printf("D20 TABLE %s | %d | %s | %s | %d | %d chars | %s | %s\n",
				id, run.Run, run.Kind, run.StopReason, lines, len([]rune(run.Answer)), detail, verdictText)
			fmt.Printf("D20 ANSWER %s run=%d %q\n", id, run.Run, run.Answer)
			for _, verdict := range run.Verdicts {
				if !verdict.Passed {
					fmt.Printf("D20 VERDICT %s run=%d %s passed=%t hard=%t %s\n",
						id, run.Run, verdict.ID, verdict.Passed, verdict.Hard, verdict.Detail)
				}
			}
		}
	}
	if len(failures) > 0 {
		t.Fatalf("card D-20 red runs: %v", failures)
	}
}

// d20RecordedAttributes returns the registered columns of one subject's source
// whose recorded meaning the answer names in business words.
func d20RecordedAttributes(set *questions.Set, sourceID, answer string) []string {
	var source questions.SourceSpec
	found := false
	for _, candidate := range set.Environment.Sources {
		if candidate.ID == sourceID {
			source, found = candidate, true
			break
		}
	}
	if !found {
		return nil
	}
	terms := d20RecordedTerms[sourceID]
	lower := strings.ToLower(answer)
	matched := []string{}
	for _, column := range source.Columns {
		for _, term := range terms[column] {
			if term != "" && strings.Contains(lower, strings.ToLower(term)) {
				matched = append(matched, column)
				break
			}
		}
	}
	return matched
}

// d20SchemaOnlyAttributes returns the matched columns whose business words
// appear nowhere in the synthetic documents or dictionary: features the answer
// can name only by knowing what the database itself records.
func d20SchemaOnlyAttributes(set *questions.Set, sourceID string, matched []string, documentCorpus string) []string {
	terms := d20RecordedTerms[sourceID]
	schemaOnly := []string{}
	for _, column := range matched {
		documented := false
		for _, term := range terms[column] {
			if term != "" && strings.Contains(documentCorpus, strings.ToLower(term)) {
				documented = true
				break
			}
		}
		if !documented {
			schemaOnly = append(schemaOnly, column)
		}
	}
	return schemaOnly
}

// d20DocumentCorpus is the lower-cased text of every synthetic document, rule
// and glossary definition: the material a document-only answer can draw on.
func d20DocumentCorpus(set *questions.Set) string {
	var builder strings.Builder
	for _, document := range set.Environment.Documents {
		builder.WriteString(strings.ToLower(document.Text))
		builder.WriteString("\n")
	}
	builder.WriteString(strings.ToLower(set.Environment.Dictionary.Description))
	for _, rule := range set.Environment.Dictionary.Rules {
		builder.WriteString(strings.ToLower(rule.Text))
	}
	for _, term := range set.Environment.Dictionary.Terms {
		builder.WriteString(strings.ToLower(term.Definition))
	}
	return builder.String()
}

// d20NoTechnicalTerm reports whether the answer names no registered relation or
// column of the synthetic database.
func d20NoTechnicalTerm(answer string, technical []string) bool {
	lower := strings.ToLower(answer)
	for _, term := range technical {
		if term == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(term)) {
			return false
		}
	}
	return true
}

// d20NonEmptyLines counts the non-empty lines of an answer.
func d20NonEmptyLines(answer string) int {
	count := 0
	for _, line := range strings.Split(answer, "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}
