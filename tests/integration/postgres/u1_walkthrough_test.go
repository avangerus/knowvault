package postgres_test

// Card U-1: a robot walks through the product's screens before the owner does.
//
// TestU1Walkthrough starts a local synthetic stand, signs a test user in, and
// drives the real web interface in a real headless browser (Playwright) through
// the card's scenario: sign in, Sources, confirm the tables of the synthetic
// database source, save a change in the model settings, ask «что ты знаешь?»
// in the chat and open the evidence behind the answer. It then writes the
// per-step report with screenshots, timings, every HTTP response >= 500 and
// every browser console error.
//
// The stand is the real product HTTP surface: the web/dist application bundle
// served through the production dispatcher, the production workspaceapi
// handler, the real registration/confirmation authority over real PostgreSQL,
// and the real question tool loop. Two things are test substitutes, exactly as
// the card requires a local synthetic stand: the identity provider (the login
// route mints the same session cookie httpauth validates instead of an OIDC
// redirect) and the model channel (a deterministic scripted OpenAI-compatible
// endpoint instead of DeepSeek). No customer data and no external service is
// involved.
//
// The test only runs when KNOWVAULT_WALKTHROUGH=1 is set, so an ordinary
// `go test ./...` neither needs Docker nor a browser. The one command is
// tests/e2e/walkthrough/run-walkthrough.sh.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/apphttp"
	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/systemapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacecontext/proposer"
)

const (
	u1DefaultProductPort = 55470
	u1DefaultAppPort     = 55471
	u1ContainerPrefix    = "kv-card-u-1-"
	// u1Question is the owner's question from the card.
	u1Question = "что ты знаешь?"
)

// u1ModelStub is a deterministic OpenAI-compatible chat-completions endpoint
// that plays one grounded tool-loop turn: search, read, then submit an answer
// citing the read fragment. It is the model channel substitute of the local
// stand, never product code.
type u1ModelStub struct {
	mu          sync.Mutex
	readAddress string
}

func (stub *u1ModelStub) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	var input struct {
		Messages []modelgateway.Message        `json:"messages"`
		Tools    []modelgateway.ToolDefinition `json:"tools"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil || len(input.Messages) == 0 {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	searchSeen, readSeen := false, false
	readAddress := ""
	for _, message := range input.Messages {
		if message.Role != "tool" {
			continue
		}
		switch message.ToolCallID {
		case "u1-search":
			searchSeen = true
			if address := u1FragmentAddress(message.Content); address != "" {
				readAddress = address
			}
		case "u1-read":
			readSeen = true
		}
	}
	if readAddress == "" {
		readAddress = stub.readAddress
	}
	message := map[string]any{"role": "assistant"}
	finish := "stop"
	switch {
	case !searchSeen:
		arguments, _ := json.Marshal(map[string]any{"query": "отход"})
		message["tool_calls"] = []any{u1ToolCall("u1-search", "knowvault_search", string(arguments))}
		finish = "tool_calls"
	case !readSeen:
		stub.mu.Lock()
		stub.readAddress = readAddress
		stub.mu.Unlock()
		arguments, _ := json.Marshal(map[string]any{"address": readAddress})
		message["tool_calls"] = []any{u1ToolCall("u1-read", "knowvault_read", string(arguments))}
		finish = "tool_calls"
	default:
		content, _ := json.Marshal(map[string]any{
			"no_data": false,
			"claims": []any{map[string]any{
				"text": "Вывоз твёрдых коммунальных отходов с места накопления отходов " +
					"выполняется не позднее 24 часов с момента заполнения контейнера.",
				"citations": []any{map[string]any{"address": readAddress}},
			}},
		})
		message["tool_calls"] = []any{u1ToolCall("u1-submit", "submit_answer", string(content))}
		finish = "tool_calls"
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"model": "u1-walkthrough-stub",
		"choices": []any{map[string]any{
			"message": message, "finish_reason": finish,
		}},
		"usage": map[string]any{"prompt_tokens": 120, "completion_tokens": 24, "total_tokens": 144},
	})
}

func u1ToolCall(id, name, arguments string) map[string]any {
	return map[string]any{"id": id, "type": "function", "function": map[string]any{"name": name, "arguments": arguments}}
}

var u1FragmentAddressPattern = regexp.MustCompile(`kv1:[^\s")\]]+`)

// u1FragmentAddress returns the first canonical fragment address a knowledge
// tool returned.
func u1FragmentAddress(result string) string {
	return u1FragmentAddressPattern.FindString(result)
}

// u1SessionToken mints the canonical 32-byte session token the synthetic login
// route hands the browser. httpauth validates its shape; the stand's static
// session resolver accepts it as the one test user.
func u1SessionToken() string {
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// u1AuthHandler is the local stand's sign-in substitute. It implements the
// exact three /auth paths the dispatcher reserves: login and callback mint the
// session cookie and return the user to the application, logout clears it.
func u1AuthHandler(token string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/auth/login", "/auth/callback":
			http.SetCookie(writer, &http.Cookie{
				Name: httpauth.SessionCookieName, Value: token, Path: "/",
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600,
			})
			writer.Header().Set("Cache-Control", "no-store")
			http.Redirect(writer, request, "/", http.StatusSeeOther)
		case "/auth/logout":
			http.SetCookie(writer, &http.Cookie{
				Name: httpauth.SessionCookieName, Value: "", Path: "/",
				Secure: true, HttpOnly: true, MaxAge: -1,
			})
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	})
}

// u1SPAHandler serves the built web application with the client-side deep-link
// fallback the production webui component implements, from the repository's
// web/dist directory.
func u1SPAHandler(root string) http.Handler {
	files := http.FileServer(http.Dir(root))
	serveIndex := func(writer http.ResponseWriter, request *http.Request) {
		body, err := os.ReadFile(filepath.Join(root, "index.html"))
		if err != nil {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		if request.Method != http.MethodHead {
			_, _ = writer.Write(body)
		}
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		clean := strings.TrimPrefix(path.Clean("/"+request.URL.Path), "/")
		if clean == "" || clean == "." {
			serveIndex(writer, request)
			return
		}
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(clean))); err == nil && !info.IsDir() {
			files.ServeHTTP(writer, request)
			return
		}
		if strings.HasPrefix(clean, "assets/") {
			http.NotFound(writer, request)
			return
		}
		serveIndex(writer, request)
	})
}

// u1Ports resolves the stand's two host ports and container name. An optional
// KNOWVAULT_WALKTHROUGH_INSTANCE (1..9) shifts both ports and the container
// suffix, so two walkthrough runs can share one machine without touching each
// other. The defaults stay inside the card's reserved 55470-55479 range.
func u1Ports(t *testing.T) (productPort, appPort int, container string) {
	t.Helper()
	productPort, appPort = u1DefaultProductPort, u1DefaultAppPort
	container = u1ContainerPrefix + "pg"
	value := strings.TrimSpace(os.Getenv("KNOWVAULT_WALKTHROUGH_INSTANCE"))
	if value == "" {
		return productPort, appPort, container
	}
	instance, err := strconv.Atoi(value)
	if err != nil || instance < 1 || instance > 9 {
		t.Fatalf("KNOWVAULT_WALKTHROUGH_INSTANCE=%q, want 1..9", value)
	}
	productPort += instance
	appPort += instance
	return productPort, appPort, container + "-" + strconv.Itoa(instance)
}

func TestU1Walkthrough(t *testing.T) {
	if strings.TrimSpace(os.Getenv("KNOWVAULT_WALKTHROUGH")) != "1" {
		t.Skip("set KNOWVAULT_WALKTHROUGH=1 (or run tests/e2e/walkthrough/run-walkthrough.sh) to drive the browser walkthrough")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker CLI is required for the synthetic stand: %v", err)
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required to drive the headless browser: %v", err)
	}

	ctx := context.Background()
	productPort, appPort, container := u1Ports(t)
	dsn := fmt.Sprintf("postgres://postgres:postgres@localhost:%d/knowvault_test?sslmode=disable", productPort)
	t.Setenv("KNOWVAULT_TEST_POSTGRES_URL", dsn)
	e1aEnsureContainer(t, ctx, container, productPort, "knowvault_test")
	admin := resetStage1Database(t)

	// The listener fixes the stand's public origin before the environment is
	// built, because the production authenticator compares the browser's real
	// Origin header against the tenant security origin.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", appPort))
	if err != nil {
		t.Fatalf("listen on the stand port: %v", err)
	}
	origin := "https://" + listener.Addr().String()

	set := loadE1aSet(t)
	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
		SourceIdentity: "pgdb-u1-walkthrough",
		Origin:         origin,
		// The Sources screen must offer the table confirmation action, so the
		// synthetic database sources are bound but left unconfirmed.
		LeaveSourcesUnconfirmed: true,
		// The web interface asks its questions over the real HTTP route.
		WireHTTPQuestions: true,
	})
	env.Handler.EnableModelContext(env.ContextStore)
	env.Handler.EnableWorkspaceContext(env.ContextStore)
	// Production wires the proposal review queue beside the document store;
	// the stand does the same so the Settings screen's
	// GET .../model-context/proposals?status=PROPOSED is a real 200 rather
	// than a stand-only SERVICE_UNAVAILABLE.
	proposals := proposer.NewStore(env.AppStore, env.ContextStore,
		&u1ProposalVersionMinter{database: env.AppStore, context: env.ContextStore},
		&u1RunExcerptReader{questions: env.Questions})
	env.Handler.EnableModelContextProposals(proposals)
	// The chat tool runtime emits canonical addresses with the same keyed span
	// digest the production composition installs; without it a search hit has
	// no citable address.
	env.Handler.EnableSpanDigest(address.NewSpanDigestKey(s1dDigestKey, 1))

	modelStub := &u1ModelStub{}
	modelServer := httptest.NewServer(modelStub)
	defer modelServer.Close()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: modelServer.URL, ModelID: "u1-walkthrough-stub",
		MaxOutputTokens: 4096, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "u1-steps", MaxTurns: 12, MaxToolCalls: 12, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 4096, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("scripted model adapter: %v", err)
	}
	defer adapter.Close()
	env.Questions.EnableGeneration(adapter, nil)

	// Probe the scripted model channel once through the same service the HTTP
	// route uses. It makes a stand-side model/retrieval failure visible in the
	// test log instead of only as the browser's generic failure card.
	probe, probeErr := env.Questions.Create(ctx, database.AccessContext{
		OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_u1_probe",
	}, question.CreateRequest{WorkspaceID: regWorkspace, Question: u1Question, IdempotencyKey: e1aIdempotencyKey("u1-probe")})
	fmt.Printf("U1 PROBE err=%v code=%s status=%q answer=%q citations=%d\n", probeErr, question.CodeOf(probeErr), probe.ResultStatus, probe.Answer, len(probe.Citations))
	if probe.ToolLoop != nil {
		fmt.Printf("U1 PROBE stop=%s calls=%d\n", probe.ToolLoop.StopReason, len(probe.ToolLoop.Calls))
		for _, call := range probe.ToolLoop.Calls {
			result := ""
			if call.Result.Text != "" {
				result = call.Result.Text
				if len(result) > 300 {
					result = result[:300]
				}
			}
			fmt.Printf("U1 PROBE CALL name=%s outcome=%v args=%s result=%q\n", call.Name, call.Outcome, string(call.Arguments), result)
		}
		for index, message := range probe.ToolLoop.Messages {
			if message.Role != "user" {
				continue
			}
			content := message.Content
			if strings.Contains(content, "format") || strings.Contains(content, "формат") {
				if len(content) > 400 {
					content = content[:400]
				}
				fmt.Printf("U1 PROBE REPAIR %d %q\n", index, content)
			}
		}
		for _, diagnostic := range probe.ToolLoop.FormatDiagnostics {
			fmt.Printf("U1 PROBE DIAG %+v\n", diagnostic)
		}
	}

	dispatcher, err := apphttp.New(
		u1AuthHandler(u1SessionToken()),
		systemapi.New(buildinfo.Info{}),
		env.Handler,
		u1SPAHandler(filepath.Join(repositoryRoot(t), "web", "dist")),
	)
	if err != nil {
		t.Fatalf("stand dispatcher: %v", err)
	}
	// Probe two of the read routes the web interface calls, so a stand-side
	// wiring gap appears in the test log with its exact status.
	{
		probeRequest := httptest.NewRequest(http.MethodGet,
			origin+"/api/v1/workspaces/"+regWorkspace+"/model-context/proposals?status=PROPOSED", nil)
		probeRequest.Header.Set("Cookie", httpauth.SessionCookieName+"="+u1SessionToken())
		probeRecorder := httptest.NewRecorder()
		dispatcher.ServeHTTP(probeRecorder, probeRequest)
		fmt.Printf("U1 PROBE proposals status=%d body=%.200s\n", probeRecorder.Code, probeRecorder.Body.String())
	}
	server := httptest.NewUnstartedServer(apphttp.WithSecurityHeaders(dispatcher))
	server.Listener = listener
	server.StartTLS()
	defer server.Close()
	if server.URL != origin {
		t.Fatalf("stand URL %q does not match the configured origin %q", server.URL, origin)
	}

	reportDir := strings.TrimSpace(os.Getenv("KNOWVAULT_WALKTHROUGH_REPORT_DIR"))
	if reportDir == "" {
		reportDir = filepath.Join(repositoryRoot(t), "tests", "e2e", "walkthrough", "baseline")
	}
	driver := filepath.Join(repositoryRoot(t), "tests", "e2e", "walkthrough", "walkthrough.mjs")

	command := exec.CommandContext(ctx, node, driver)
	command.Dir = repositoryRoot(t)
	command.Env = append(os.Environ(),
		"KNOWVAULT_WALKTHROUGH_BASE_URL="+origin,
		"KNOWVAULT_WALKTHROUGH_REPORT_DIR="+reportDir,
		"KNOWVAULT_WALKTHROUGH_QUESTION="+u1Question,
	)
	output, runErr := command.CombinedOutput()
	fmt.Printf("U1 WALKTHROUGH DRIVER\n%s\n", output)
	if runErr != nil {
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			t.Fatalf("the walkthrough reported a failed step; see %s", filepath.Join(reportDir, "report.md"))
		}
		t.Fatalf("run the walkthrough driver: %v", runErr)
	}
	markdownPath := filepath.Join(reportDir, "report.md")
	jsonPath := filepath.Join(reportDir, "report.json")
	for _, candidate := range []string{markdownPath, jsonPath} {
		info, statErr := os.Stat(candidate)
		if statErr != nil || info.Size() == 0 {
			t.Fatalf("walkthrough report %s is missing or empty: %v", candidate, statErr)
		}
	}
	fmt.Printf("U1 REPORT %s\nU1 REPORT %s\nU1 SHOTS %s\n", markdownPath, jsonPath, filepath.Join(reportDir, "screenshots"))
}

// u1ProposalVersionMinter is the stand's VersionMinter seam: the production
// composition wires the identical adapter (proposalVersionMinter), and the
// queue only needs the seam to exist and be atomic, so the stand reuses the
// same workspacecontext.Store call without the composition-only audit append.
type u1ProposalVersionMinter struct {
	database *database.Store
	context  *workspacecontext.Store
}

func (minter *u1ProposalVersionMinter) MintAcceptedVersion(
	ctx context.Context, access workspacecontext.Access, workspaceID, ifMatchHash string,
	document workspacecontext.Document, proposalID string,
	decideProposal func(ctx context.Context, tx database.Transaction, mintedVersion int64) error,
) (workspacecontext.Version, error) {
	dbAccess := database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID}
	knownProjections, err := minter.context.KnownProjections(ctx, dbAccess, workspaceID)
	if err != nil {
		return workspacecontext.Version{}, err
	}
	var minted workspacecontext.Version
	err = minter.database.Write(ctx, dbAccess, func(ctx context.Context, tx database.Transaction) error {
		version, acceptErr := minter.context.AcceptProposalVersion(ctx, tx, dbAccess, workspaceID, document, knownProjections, ifMatchHash, proposalID)
		if acceptErr != nil {
			return acceptErr
		}
		if decideErr := decideProposal(ctx, tx, version.Number); decideErr != nil {
			return decideErr
		}
		minted = version
		return nil
	})
	if err != nil {
		return workspacecontext.Version{}, err
	}
	return minted, nil
}

// u1RunExcerptReader is the stand's RunExcerptReader seam over the real
// question service, mirroring composition's questionRunExcerptReader.
type u1RunExcerptReader struct {
	questions *question.Service
}

func (reader *u1RunExcerptReader) GetBatch(ctx context.Context, access workspacecontext.Access, workspaceID string, runIDs []string) ([]proposer.RunExcerpt, error) {
	runs, err := reader.questions.GetBatch(ctx, database.AccessContext{
		OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID,
	}, workspaceID, runIDs)
	if err != nil {
		return nil, err
	}
	excerpts := make([]proposer.RunExcerpt, 0, len(runIDs))
	for _, runID := range runIDs {
		run, ok := runs[runID]
		if !ok {
			continue
		}
		excerpts = append(excerpts, proposer.RunExcerpt{
			QuestionRunID: run.ID, ConversationID: run.ConversationID, QuestionExcerpt: run.Question,
		})
	}
	return excerpts, nil
}
