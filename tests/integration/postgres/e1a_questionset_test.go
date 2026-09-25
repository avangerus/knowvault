package postgres_test

// Card E-1a: one command runs the question set on a synthetic proving
// environment with the real DeepSeek model channel and judges every answer by
// the fixed rules in tests/e2e/questions/questions.json.
//
//   - TestQuestionSetRealModel requires KNOWVAULT_QUESTION_SET_API_KEY_FILE
//     (the DeepSeek key file, read only at run time), starts the card's two
//     PostgreSQL containers, builds the synthetic workspace and the real
//     governed SQL source, runs every question three times against
//     deepseek-flash, writes report.md/report.json, and fails when any
//     question fails.
//   - TestQuestionSetSmoke runs the same runner against a stub
//     OpenAI-compatible endpoint, so CI exercises the pipeline without a key.

import (
	"context"
	"crypto/x509"
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

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

func loadE1aSet(t *testing.T) *questions.Set {
	t.Helper()
	path := filepath.Join(repositoryRoot(t), "tests", "e2e", "questions", "questions.json")
	set, err := questions.LoadSet(path)
	if err != nil {
		t.Fatalf("load question set %s: %v", path, err)
	}
	// KNOWVAULT_QUESTION_SET_INSTANCE (1..9) lets two worktrees run the set
	// at the same time: container names get the instance suffix and both
	// host ports move by ten per instance.
	if value := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_INSTANCE")); value != "" {
		instance, convErr := strconv.Atoi(value)
		if convErr != nil || instance < 1 || instance > 9 {
			t.Fatalf("KNOWVAULT_QUESTION_SET_INSTANCE=%q, want 1..9", value)
		}
		set.Environment.ProductContainer += fmt.Sprintf("-%d", instance)
		set.Environment.SourceContainer += fmt.Sprintf("-%d", instance)
		set.Environment.ProductPort += 10 * instance
		set.Environment.SourcePort += 10 * instance
	}
	return set
}

// TestQuestionSetSmoke proves the runner end to end against a stub model
// endpoint and the real product database, without a DeepSeek key.
func TestQuestionSetSmoke(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)
	stub := questions.NewStubModel()
	server := httptest.NewServer(stub)
	defer server.Close()

	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "e1a-stub",
		MaxOutputTokens: 4096, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "steps-2", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 4096, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("stub adapter: %v", err)
	}
	defer adapter.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-stub-e1a"})
	env.Questions.EnableGeneration(adapter, nil)

	runs := e1aRunQuestionSet(t, ctx, env, func(questions.Question) string { return "" })
	report := questions.NewReport(set, "stub", "go test ./tests/integration/postgres -run TestQuestionSetSmoke", runs, time.Now())
	if len(runs) != 3*len(set.Questions) {
		t.Fatalf("runner produced %d runs, want 3 per question (%d)", len(runs), 3*len(set.Questions))
	}
	for _, question := range set.Questions {
		count := 0
		for _, run := range runs {
			if run.QuestionID == question.ID {
				count++
			}
		}
		if count != 3 {
			t.Fatalf("question %s ran %d times, want 3", question.ID, count)
		}
	}
	if report.InputTokens <= 0 || report.OutputTokens <= 0 {
		t.Fatalf("stub token usage was not accumulated: %+v", report.Cost)
	}
	toolCalls := 0
	for _, run := range runs {
		toolCalls += len(run.ToolCalls)
	}
	if toolCalls == 0 {
		t.Fatal("the stub run recorded no tool call, so the tool runtime was never exercised")
	}
	if len(report.Questions) != len(set.Questions) {
		t.Fatalf("report has %d question verdicts, want %d", len(report.Questions), len(set.Questions))
	}
	dir := t.TempDir()
	markdownPath, jsonPath, err := questions.WriteReport(dir, report)
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	for _, path := range []string{markdownPath, jsonPath} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() == 0 {
			t.Fatalf("report file %s is missing or empty: %v", path, statErr)
		}
	}
}

// TestQuestionSetRealModel is the card's one command. It requires the DeepSeek
// key file and Docker; it is skipped, never silently passed, without the key.
func TestQuestionSetRealModel(t *testing.T) {
	keyFile := os.Getenv("KNOWVAULT_QUESTION_SET_API_KEY_FILE")
	if keyFile == "" {
		t.Skip("set KNOWVAULT_QUESTION_SET_API_KEY_FILE to the DeepSeek key file to run the real question set")
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
	reportDir := os.Getenv("KNOWVAULT_QUESTION_SET_REPORT_DIR")
	if reportDir == "" {
		reportDir = filepath.Join(repositoryRoot(t), "tests", "e2e", "questions", "baseline")
	}

	// The card's two containers. The harness owns and removes both.
	productURL := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable",
		set.Environment.ProductPort, set.Environment.ProductDatabase)
	t.Setenv("KNOWVAULT_TEST_POSTGRES_URL", productURL)
	e1aEnsureContainer(t, ctx, set.Environment.ProductContainer, set.Environment.ProductPort, set.Environment.ProductDatabase)
	e1aEnsureContainer(t, ctx, set.Environment.SourceContainer, set.Environment.SourcePort, set.Environment.SourceDatabase)

	sourceAdminDSN := fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=disable",
		set.Environment.SourceAdminUser, set.Environment.SourceAdminPass, set.Environment.SourcePort, set.Environment.SourceDatabase)
	sourceAdmin := e1aOpenSourceAdmin(t, ctx, sourceAdminDSN)
	e1aSeedSourceDatabase(t, ctx, sourceAdmin, set.Environment.SourceSQL)

	certDir := t.TempDir()
	roots := e1aGenerateSourceCerts(t, certDir)
	e1aEnableSourceTLS(t, ctx, set.Environment.SourceContainer, set.Environment.SourcePort, set.Environment.SourceDatabase, certDir)

	queryDSNFor := func(source questions.SourceSpec) string {
		return fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=verify-full",
			source.QueryRole, source.QueryPassword, set.Environment.SourcePort, set.Environment.SourceDatabase)
	}
	contractSource := set.Environment.Sources[0]
	probeDSN := queryDSNFor(contractSource) + "&sslrootcert=" + filepath.Join(certDir, "ca.crt")
	identity := e1aSourceIdentity(t, ctx, probeDSN)

	credentials := map[string]string{}
	for _, source := range set.Environment.Sources {
		credentials[source.ID] = queryDSNFor(source)
	}
	sqlExecutor := &e1aSourceSQL{credentials: map[string]string{}, roots: roots}
	contractChecksum := e1aContractChecksumProbe(t, ctx, sourceAdminDSN)

	admin := resetStage1Database(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
		SourceIdentity: identity, Credentials: credentials, Roots: roots, SourceSQL: sqlExecutor,
		ContractChecksum: contractChecksum,
	})

	registry, err := e1aModelRegistry(set, apiKey)
	if err != nil {
		t.Fatalf("model profile registry: %v", err)
	}
	defer registry.Close()
	env.Questions.EnableGeneration(registry.Default(), nil)
	env.Questions.EnableGenerationProfiles(registry)

	started := time.Now()
	runs := e1aRunQuestionSet(t, ctx, env, e1aQuestionProfile)
	report := questions.NewReport(set, "real", "tests/e2e/questions/run-question-set.sh", runs, started)
	markdownPath, jsonPath, err := questions.WriteReport(reportDir, report)
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	fmt.Printf("E1A REPORT %s\nE1A REPORT %s\n", markdownPath, jsonPath)
	fmt.Printf("E1A TOTAL seconds=%.2f input_tokens=%d output_tokens=%d cost=%.6f %s\n",
		report.TotalSeconds, report.InputTokens, report.OutputTokens, report.Cost.Total, report.Cost.Currency)
	if report.Failed {
		failed := []string{}
		for _, question := range report.Questions {
			if !question.Passed {
				failed = append(failed, question.QuestionID)
			}
		}
		t.Fatalf("question set failed: %v (see %s)", failed, markdownPath)
	}
}

// e1aModelRegistry mounts one profile per distinct step budget, all pointing at
// the real DeepSeek endpoint.
func e1aModelRegistry(set *questions.Set, apiKey string) (*modelgateway.ProfileRegistry, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return nil, fmt.Errorf("system certificate pool: %w", err)
	}
	limits := map[int]bool{}
	for _, question := range set.Questions {
		limit := question.MaxSteps
		if limit < 2 {
			limit = 2
		}
		limits[limit] = true
	}
	ordered := []int{}
	for limit := range limits {
		ordered = append(ordered, limit)
	}
	sortInts(ordered)
	configs := make([]modelgateway.ProfileConfig, 0, len(ordered))
	for _, limit := range ordered {
		// The mounted budget is the question's own step limit plus the
		// product's finalization reserve (toolLoopResearchCallLimit), so the
		// model may spend exactly `limit` research calls and the judge, not the
		// profile ceiling, decides whether the answer exceeded the limit.
		budget := limit + 3
		timeout := limit * 60
		if timeout < 60 {
			timeout = 60
		}
		if timeout > 240 {
			timeout = 240
		}
		configs = append(configs, modelgateway.ProfileConfig{
			ID:    fmt.Sprintf("steps-%d", limit),
			Label: fmt.Sprintf("DeepSeek flash, up to %d steps", limit),
			Config: modelgateway.LabAdapterConfig{
				SchemaVersion: modelgateway.LabAdapterSchemaVersion,
				Endpoint:      set.Model.Endpoint, ModelID: set.Model.ModelID,
				APIKey: apiKey, MaxOutputTokens: 16384, InsecureLabMode: true,
				ThinkingMode: modelgateway.ThinkingModeDisabled, TrustRoots: pool,
				ExternalRuntimeWorkspaceIDs: []string{set.Environment.WorkspaceID},
				ToolLoop: &modelgateway.ToolLoopProfile{
					ID: fmt.Sprintf("steps-%d", limit), MaxTurns: budget, MaxToolCalls: budget,
					MaxInputBytes: 262144, MaxToolResultBytes: 65536,
					MaxOutputTokens: 16384, TimeoutSeconds: timeout,
				},
			},
		})
	}
	return modelgateway.NewProfileRegistry("steps-2", configs)
}

// e1aContractChecksumProbe returns a row-count and content checksum of the
// synthetic contract table, so H4 can prove a delete request changed nothing.
func e1aContractChecksumProbe(t *testing.T, ctx context.Context, dsn string) func(context.Context) (string, error) {
	t.Helper()
	return func(checksumCtx context.Context) (string, error) {
		connection, err := pgx.Connect(checksumCtx, dsn)
		if err != nil {
			return "", err
		}
		defer connection.Close(checksumCtx)
		var count int64
		var digest string
		if err := connection.QueryRow(checksumCtx, `
			SELECT count(*), coalesce(md5(string_agg(number || '|' || status || '|' || amount::text, ',' ORDER BY id)), '')
			FROM public.contract`).Scan(&count, &digest); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d:%s", count, digest), nil
	}
}

func trimSpaceBytes(raw []byte) []byte {
	start, end := 0, len(raw)
	for start < end && (raw[start] == ' ' || raw[start] == '\n' || raw[start] == '\r' || raw[start] == '\t') {
		start++
	}
	for end > start && (raw[end-1] == ' ' || raw[end-1] == '\n' || raw[end-1] == '\r' || raw[end-1] == '\t') {
		end--
	}
	return raw[start:end]
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
