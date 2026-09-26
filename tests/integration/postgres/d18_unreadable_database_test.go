package postgres_test

// Card D-18: a question about data held in a workspace database that cannot be
// read right now gets one plain answer naming the database and what makes it
// readable, with no SQL tool call and no empty result; the same database once
// it is confirmed and answering is answered as before, and the rest of the
// workspace is untouched while it cannot be read.
//
// The test runs the real DeepSeek channel against the real product database and
// real synthetic source databases, because the card's answers are judged by
// reading them. It skips without the key file.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/ids"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// d18Container and d18Port are the card's own PostgreSQL container: the product
// database, the synthetic shared source database and the H5 database live in it
// as three separate databases. The environment variables let a second run (the
// card's "before" measurement) use its own container and port.
func d18Container() string {
	if value := strings.TrimSpace(os.Getenv("KNOWVAULT_D18_CONTAINER")); value != "" {
		return value
	}
	return "kv-card-d-18-pg"
}

func d18Port() int {
	if value := strings.TrimSpace(os.Getenv("KNOWVAULT_D18_PORT")); value != "" {
		if port, err := strconv.Atoi(value); err == nil && port > 0 {
			return port
		}
	}
	return 55620
}

// d18ClosedPort is a host port nothing listens on: the H5 source's credential
// is pointed at it, so the product's own connection points at a closed port.
const d18ClosedPort = 55629

// d18Question is one question of the card's run table.
type d18Question struct {
	ID    string
	Text  string
	// WantsSentence is true for a question about the database that cannot be
	// read: the answer must be the plain sentence and make no SQL call.
	WantsSentence bool
	// WantTables is true when the expected remedy is confirming the tables
	// rather than making the database reachable.
	WantTables bool
	// WantNumber, when set, is the exact value the answer must state.
	WantNumber string
	// WantSQL is true when every run must have made at least one SQL call.
	WantSQL bool
	// MinNumberRuns and MinSQLRuns are the aggregate tolerances for a question
	// whose real-model answer is stochastic: how many of the three runs must
	// state the value and make an SQL call. Zero means all three.
	MinNumberRuns int
	MinSQLRuns    int
}

// d18Scenario is one workspace state the questions are asked in.
type d18Scenario struct {
	Name string
	// ConfirmH5 mints the H5 database's table confirmation.
	ConfirmH5 bool
	// H5Credential is "", "reachable" or "closed".
	H5Credential string
	Questions    []d18Question
}

// d18OwnCountQuestion returns one of the card's own two count questions about
// the H5 database; the question set's own H5 text is used unchanged for H5.
func d18OwnCountQuestions() []string {
	return []string{
		"Посчитай, сколько всего заявок в «Заявки».",
		"Сколько заявок зарегистрировано в «Заявки»?",
	}
}

func TestD18UnreadableDatabaseRealModel(t *testing.T) {
	keyFile := os.Getenv("KNOWVAULT_QUESTION_SET_API_KEY_FILE")
	if keyFile == "" {
		t.Skip("set KNOWVAULT_QUESTION_SET_API_KEY_FILE to the DeepSeek key file to run the card D-18 answer runs")
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read DeepSeek key file: %v", err)
	}
	apiKey := string(trimSpaceBytes(key))
	if apiKey == "" {
		t.Fatal("the DeepSeek key file is empty")
	}

	ctx := context.Background()
	set := loadE1aSet(t)
	container, port := d18Container(), d18Port()
	productURL := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, "knowvault_test")
	t.Setenv("KNOWVAULT_TEST_POSTGRES_URL", productURL)
	remove := e1aEnsureContainer(t, ctx, container, port, "knowvault_test")
	defer remove()

	adminURL := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, "knowvault_test")
	adminConnection, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect product admin: %v", err)
	}
	defer adminConnection.Close(ctx)
	for _, databaseName := range []string{"knowvault_source", "knowvault_h5"} {
		if _, err := adminConnection.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
			t.Fatalf("create database %s: %v", databaseName, err)
		}
	}

	certDir := t.TempDir()
	roots := e1aGenerateSourceCerts(t, certDir)
	e1aEnableSourceTLS(t, ctx, container, port, "knowvault_test", certDir)

	sourceAdminDSN := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, "knowvault_source")
	sourceAdmin := e1aOpenSourceAdmin(t, ctx, sourceAdminDSN)
	e1aSeedSourceDatabase(t, ctx, sourceAdmin, set.Environment.SourceSQL)

	h5 := set.Environment.UnconfirmedDatabase
	h5AdminDSN := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, "knowvault_h5")
	h5Admin := e1aOpenSourceAdmin(t, ctx, h5AdminDSN)
	e1aSeedSourceDatabase(t, ctx, h5Admin, h5.SQL)

	// The source credential DSN carries only sslmode=verify-full: the trusted
	// CA is the executor's mounted TrustRoots, exactly as the question set wires
	// it. A DSN that also names sslrootcert is refused by the governed URL
	// policy. The admin identity DSN is a separate, direct pgx connection and
	// may name the CA file.
	queryDSN := func(role, password, databaseName string) string {
		return fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=verify-full",
			role, password, port, databaseName)
	}
	identityDSN := func(role, password, databaseName string) string {
		return queryDSN(role, password, databaseName) + "&sslrootcert=" + filepath.Join(certDir, "ca.crt")
	}
	contractSource := set.Environment.Sources[0]
	sourceIdentity := e1aSourceIdentity(t, ctx, identityDSN(contractSource.QueryRole, contractSource.QueryPassword, "knowvault_source"))
	h5Identity := e1aSourceIdentity(t, ctx, h5AdminDSN)

	credentials := map[string]string{}
	for _, source := range set.Environment.Sources {
		credentials[source.ID] = queryDSN(source.QueryRole, source.QueryPassword, "knowvault_source")
	}
	sqlExecutor := &e1aSourceSQL{credentials: map[string]string{}, roots: roots}

	registry, err := e1aModelRegistry(set, apiKey)
	if err != nil {
		t.Fatalf("model profile registry: %v", err)
	}
	defer registry.Close()

	ownCounts := d18OwnCountQuestions()
	sentenceTables := d18Question{ID: "H5", Text: h5QuestionText(set), WantsSentence: true, WantTables: true}
	sentenceReachable := d18Question{ID: "H5", Text: h5QuestionText(set), WantsSentence: true}
	ownSentenceTables := func() []d18Question {
		return []d18Question{
			{ID: "A1", Text: ownCounts[0], WantsSentence: true, WantTables: true},
			{ID: "A2", Text: ownCounts[1], WantsSentence: true, WantTables: true},
		}
	}
	ownSentenceReachable := func() []d18Question {
		return []d18Question{
			{ID: "A1", Text: ownCounts[0], WantsSentence: true},
			{ID: "A2", Text: ownCounts[1], WantsSentence: true},
		}
	}
	scenarios := []d18Scenario{
		{
			Name: "tables await confirmation",
			Questions: append([]d18Question{
				sentenceTables,
				// While the H5 database cannot be read, another source and a
				// document question are answered as today, including one whose
				// true answer about another source is zero.
				{ID: "B1", Text: "Сколько МНО закреплено за договорами?", WantNumber: "5", MinNumberRuns: 2, MinSQLRuns: 2},
				{ID: "B2", Text: "Что в регламенте сказано про сроки вывоза?"},
				{ID: "B3", Text: "Сколько договоров заключено в 2019 году?", WantNumber: "0", MinNumberRuns: 2, MinSQLRuns: 2},
			}, ownSentenceTables()...),
		},
		{
			Name:         "confirmed and answering",
			ConfirmH5:    true,
			H5Credential: "reachable",
			Questions: append([]d18Question{
				{ID: "H5", Text: h5QuestionText(set), WantNumber: "4", MinNumberRuns: 2, MinSQLRuns: 2},
				{ID: "C1", Text: "Сколько заявок в базе «Заявки» создано в 2020 году?", WantNumber: "0", MinNumberRuns: 2, MinSQLRuns: 2},
			}, func() []d18Question {
				// The card's own count questions with a confirmed, answering
				// database keep the ordinary full route and are answered as
				// before: the query runs and the counted value is stated.
				return []d18Question{
					{ID: "A1", Text: ownCounts[0], WantNumber: "4", MinNumberRuns: 2, MinSQLRuns: 2},
					{ID: "A2", Text: ownCounts[1], WantNumber: "4", MinNumberRuns: 2, MinSQLRuns: 2},
				}
			}()...),
		},
		{
			Name:         "database does not answer",
			ConfirmH5:    true,
			H5Credential: "closed",
			Questions: append([]d18Question{
				sentenceReachable,
			}, ownSentenceReachable()...),
		},
	}

	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			admin := resetStage1Database(t)
			env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
				SourceIdentity: sourceIdentity, Credentials: credentials, Roots: roots, SourceSQL: sqlExecutor,
				H5Source: &h5.Source, H5SourceIdentity: h5Identity, ConfirmH5Source: scenario.ConfirmH5,
			})
			env.e1aBindH5Source(t, ctx)
			if scenario.H5Credential != "" {
				reference, referenceErr := ids.New("cred")
				if referenceErr != nil {
					t.Fatal(referenceErr)
				}
				dsn := queryDSN(h5.Source.QueryRole, h5.Source.QueryPassword, "knowvault_h5")
				if scenario.H5Credential == "closed" {
					// The same credential shape, but the host port nothing
					// listens on: the product's own connection points at a
					// closed port.
					dsn = queryDSN(h5.Source.QueryRole, h5.Source.QueryPassword, "knowvault_h5")
					dsn = strings.Replace(dsn, fmt.Sprintf(":%d/", port), fmt.Sprintf(":%d/", d18ClosedPort), 1)
				}
				sqlExecutor.credentials[reference] = dsn
				if err := env.Authority.SetSourceQueryCredential(ctx, regOwnerAccess("req_d18_cred_"+d18ID(scenario.Name)),
					regWorkspace, env.H5SourceID, reference); err != nil {
					t.Fatalf("configure H5 query credential: %v", err)
				}
			}
			env.Questions.EnableGeneration(registry.Default(), nil)
			env.Questions.EnableGenerationProfiles(registry)
			env.Questions.EnableAnswerKindRecognition()

			for _, item := range scenario.Questions {
				if only := d18Only(); len(only) > 0 && !only[item.ID] {
					continue
				}
				outcomes := make([]d18Outcome, 0, 3)
				for runIndex := 1; runIndex <= 3; runIndex++ {
					access := database.AccessContext{
						OrganizationID: regOrg, PrincipalID: regOwner,
						RequestID: fmt.Sprintf("req_d18_%s_%s_%d", d18ID(scenario.Name), item.ID, runIndex),
					}
					key := e1aIdempotencyKey(fmt.Sprintf("d18-%s-%s-%d", scenario.Name, item.ID, runIndex))
					started := time.Now()
					run, createErr := env.Questions.Create(ctx, access, question.CreateRequest{
						WorkspaceID: regWorkspace, Question: item.Text, ModelProfileID: "steps-4", IdempotencyKey: key,
					})
					elapsed := time.Since(started).Seconds()
					outcome := d18Observe(item, runIndex, run, createErr, elapsed)
					outcomes = append(outcomes, outcome)
					t.Logf("D18 RUN scenario=%q question=%s run=%d kind=%s steps=%d sql_calls=%d seconds=%.2f answer=%q",
						scenario.Name, item.ID, runIndex, outcome.Kind, outcome.Steps, outcome.SQLCalls, elapsed, outcome.Answer)
					if os.Getenv("KNOWVAULT_D18_DEBUG_CALLS") != "" && run.ToolLoop != nil {
						for _, call := range run.ToolLoop.Calls {
							if call.System || call.Name == "submit_answer" {
								continue
							}
							t.Logf("D18 CALL question=%s run=%d name=%s outcome=%s args=%s result=%.160s",
								item.ID, runIndex, call.Name, call.Outcome, d18Truncate(string(call.Arguments), 200), call.Result.Text)
						}
					}
				}
				d18Judge(t, scenario.Name, item, outcomes)
			}
		})
	}
}

// h5QuestionText returns the question set's own H5 text, so the card's visible
// question runs in exactly its set wording.
func h5QuestionText(set *questions.Set) string {
	for _, item := range set.Questions {
		if item.ID == "H5" {
			return item.Text
		}
	}
	return ""
}

// d18ID turns a scenario name into an opaque request-id fragment: the access
// context rejects whitespace in its request id.
func d18ID(name string) string {
	return strings.ReplaceAll(name, " ", "-")
}

// d18Only returns the comma-separated question ids a debugging run limits
// itself to; an empty set means every question.
func d18Only() map[string]bool {
	value := strings.TrimSpace(os.Getenv("KNOWVAULT_D18_ONLY"))
	if value == "" {
		return nil
	}
	only := map[string]bool{}
	for _, id := range strings.Split(value, ",") {
		only[strings.TrimSpace(id)] = true
	}
	return only
}

// d18Truncate shortens a debug value to a bounded prefix.
func d18Truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.ToValidUTF8(value[:limit], "") + "…"
}

// d18Outcome is one run's judgeable facts: the answer text, the recognised
// kind, the model-requested step count and the SQL tool calls among them.
type d18Outcome struct {
	RunIndex int
	Answer   string
	Kind     string
	Steps    int
	SQLCalls int
	Err      error
}

// d18Observe projects one run into its judgeable facts.
func d18Observe(item d18Question, runIndex int, run question.Run, createErr error, elapsed float64) d18Outcome {
	outcome := d18Outcome{RunIndex: runIndex, Err: createErr}
	if createErr != nil {
		outcome.Answer = "RUN_ERROR:" + e1aRunFailureText(createErr)
		return outcome
	}
	if run.ToolLoop != nil {
		outcome.Answer = run.Answer
		outcome.Kind = run.ToolLoop.AnswerKind
		for _, call := range run.ToolLoop.Calls {
			if call.System || call.Name == "submit_answer" {
				continue
			}
			outcome.Steps++
			if call.Name == "knowvault_source_sql" {
				outcome.SQLCalls++
			}
		}
	}
	return outcome
}

// d18Judge checks one question's three runs. A question about a database that
// cannot be read is judged strictly per run (the card's result 1). Every other
// question must keep the full kind and never receive the cannot-be-read
// sentence; a value the real model states on some runs is required on at least
// as many runs as the question asks for, because a single real-model run is
// stochastic and the question set's own value rules tolerate one miss in three.
func d18Judge(t *testing.T, scenario string, item d18Question, outcomes []d18Outcome) {
	t.Helper()
	for _, outcome := range outcomes {
		if outcome.Err != nil {
			t.Errorf("%s/%s run %d failed: %v", scenario, item.ID, outcome.RunIndex, outcome.Err)
			continue
		}
		if outcome.Kind != string(question.AnswerKindFull) {
			t.Errorf("%s/%s run %d kind=%q, want full", scenario, item.ID, outcome.RunIndex, outcome.Kind)
		}
		if item.WantsSentence {
			d18JudgeUnreadable(t, scenario, item, outcome)
			continue
		}
		if d18HasUnreadableSentence(outcome.Answer) {
			t.Errorf("%s/%s run %d got the cannot-be-read sentence: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
		}
		if item.WantSQL && outcome.SQLCalls == 0 {
			t.Errorf("%s/%s run %d made no SQL call, want at least one", scenario, item.ID, outcome.RunIndex)
		}
	}
	if item.WantsSentence || item.WantNumber == "" {
		return
	}
	numberRuns, sqlRuns := 0, 0
	for _, outcome := range outcomes {
		if d18HasStandaloneNumber(outcome.Answer, item.WantNumber) {
			numberRuns++
		}
		if outcome.SQLCalls > 0 {
			sqlRuns++
		}
	}
	wantNumberRuns := item.MinNumberRuns
	if wantNumberRuns <= 0 {
		wantNumberRuns = len(outcomes)
	}
	wantSQLRuns := item.MinSQLRuns
	if wantSQLRuns <= 0 {
		wantSQLRuns = len(outcomes)
	}
	if numberRuns < wantNumberRuns {
		t.Errorf("%s/%s stated %s in %d of %d runs, want at least %d", scenario, item.ID, item.WantNumber, numberRuns, len(outcomes), wantNumberRuns)
	}
	if sqlRuns < wantSQLRuns {
		t.Errorf("%s/%s made an SQL call in %d of %d runs, want at least %d", scenario, item.ID, sqlRuns, len(outcomes), wantSQLRuns)
	}
}

// d18JudgeUnreadable checks one run of a question about a database that cannot
// be read: the plain sentence, no SQL call, no empty result.
func d18JudgeUnreadable(t *testing.T, scenario string, item d18Question, outcome d18Outcome) {
	t.Helper()
	if outcome.SQLCalls != 0 {
		t.Errorf("%s/%s run %d made %d SQL calls, want 0", scenario, item.ID, outcome.RunIndex, outcome.SQLCalls)
	}
	if !d18ContainsFold(outcome.Answer, "Заявки") {
		t.Errorf("%s/%s run %d answer does not name the database: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
	}
	if !d18SentenceCountAtMost(outcome.Answer, 2) {
		t.Errorf("%s/%s run %d answer is longer than two sentences: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
	}
	if d18HasStandaloneZero(outcome.Answer) {
		t.Errorf("%s/%s run %d presents an empty result: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
	}
	if item.WantTables {
		if !d18ContainsFold(outcome.Answer, "подтвер") || !d18ContainsFold(outcome.Answer, "таблиц") {
			t.Errorf("%s/%s run %d answer does not speak of confirming the tables: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
		}
		return
	}
	if !d18ContainsFold(outcome.Answer, "доступна") && !d18ContainsFold(outcome.Answer, "отвеча") {
		t.Errorf("%s/%s run %d answer does not speak of the database being reachable: %q", scenario, item.ID, outcome.RunIndex, outcome.Answer)
	}
}

// TestD18UnreadableDatabaseStub proves the route's plumbing deterministically,
// with the scripted model channel and the real product database: an
// unconfirmed H5 database gets the plain sentence, the run records no SQL tool
// call and the workspace is not asked anything about the database. It needs
// only KNOWVAULT_TEST_POSTGRES_URL; the real-model answer behavior is the test
// above.
func TestD18UnreadableDatabaseStub(t *testing.T) {
	if strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL")) == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for card D-18's deterministic route proof")
	}
	ctx := context.Background()
	set := loadE1aSet(t)
	stub := questions.NewStubModel()
	server := httptest.NewServer(stub)
	defer server.Close()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "d18-stub",
		MaxOutputTokens: 4096, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "steps-4", MaxTurns: 7, MaxToolCalls: 7, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 4096, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("stub adapter: %v", err)
	}
	defer adapter.Close()

	admin := resetStage1Database(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
		SourceIdentity: "pgdb-d18-stub", H5Source: &set.Environment.UnconfirmedDatabase.Source,
		H5SourceIdentity: "pgdb-d18-stub-h5",
	})
	env.e1aBindH5Source(t, ctx)
	env.Questions.EnableGeneration(adapter, nil)

	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_d18_stub"}
	run, err := env.Questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: h5QuestionText(set),
		IdempotencyKey: e1aIdempotencyKey("d18-stub-h5"),
	})
	if err != nil {
		t.Fatalf("ask H5 with the stub model: %v", err)
	}
	sqlCalls := 0
	if run.ToolLoop != nil {
		for _, call := range run.ToolLoop.Calls {
			if !call.System && call.Name == "knowvault_source_sql" {
				sqlCalls++
			}
		}
	}
	if sqlCalls != 0 {
		t.Fatalf("H5 made %d SQL calls, want 0", sqlCalls)
	}
	if !d18ContainsFold(run.Answer, "Заявки") || !d18ContainsFold(run.Answer, "таблиц") {
		t.Fatalf("H5 answer is not the plain sentence: %q", run.Answer)
	}
}

func d18ContainsFold(value, needle string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(needle))
}

// d18HasUnreadableSentence reports the card D-18 answer shape itself, not the
// words "did not read" in an ordinary sentence: only the two plain sentences
// the renderer produces.
func d18HasUnreadableSentence(answer string) bool {
	return d18ContainsFold(answer, "не читается") || d18ContainsFold(answer, "не отвечает")
}

// d18SentenceCountAtMost counts sentence-ending punctuation, ignoring an
// ellipsis and a decimal point.
func d18SentenceCountAtMost(value string, limit int) bool {
	count := 0
	runes := []rune(value)
	for index, character := range runes {
		if character != '.' && character != '!' && character != '?' {
			continue
		}
		if character == '.' && index > 0 && index+1 < len(runes) && runes[index-1] >= '0' && runes[index-1] <= '9' && runes[index+1] >= '0' && runes[index+1] <= '9' {
			continue
		}
		count++
	}
	return count <= limit
}

// d18HasStandaloneZero reports a zero count presented as an answer.
func d18HasStandaloneZero(answer string) bool {
	fields := strings.FieldsFunc(answer, func(r rune) bool {
		return !(r >= '0' && r <= '9')
	})
	for _, field := range fields {
		if field == "0" {
			return true
		}
	}
	return false
}

// d18HasStandaloneNumber reports whether the answer states exactly number as a
// standalone numeric token, tolerating its thousands separator. A zero the
// model writes as the Russian word «нулю»/«ноль» counts as zero.
func d18HasStandaloneNumber(answer, number string) bool {
	want, err := strconv.Atoi(number)
	if err != nil {
		return strings.Contains(answer, number)
	}
	if want == 0 && (d18ContainsFold(answer, "нулю") || d18ContainsFold(answer, "ноль")) {
		return true
	}
	tokens := strings.FieldsFunc(answer, func(r rune) bool {
		return !(r >= '0' && r <= '9')
	})
	for _, token := range tokens {
		got, convErr := strconv.Atoi(token)
		if convErr == nil && got == want {
			return true
		}
	}
	return false
}
