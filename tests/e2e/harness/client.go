//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// apiClient drives the product HTTP surface exactly the way a browser would:
// one cookie jar across the login redirect chain, the CSRF proof fetched from
// the session endpoint, and every unsafe request carrying the exact public
// Origin plus the CSRF header. TLS trusts only the e2e CA.
type apiClient struct {
	base string
	http *http.Client
	csrf string
}

// idemKey derives one opaque 32-byte idempotency key per e2e label. The keys
// are deterministic so the whole harness is reproducible.
func idemKey(label string) string {
	digest := sha256.Sum256([]byte("knowvault-e2e-idempotency\x00" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// harnessHTTPClient is the shared stateless TLS client for readiness probes;
// it carries no cookie jar and trusts only the e2e CA.
var harnessTransport *http.Transport

func harnessHTTPClient() *http.Client {
	if harnessTransport == nil {
		caPEM, err := os.ReadFile(certificateFile())
		if err != nil {
			return nil
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil
		}
		harnessTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	return &http.Client{Transport: harnessTransport, Timeout: 10 * time.Second}
}

func httpNewRequest(ctx context.Context, method, target string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, target, nil)
}

func newAPIClient(cfg config) (*apiClient, error) {
	caPEM, err := os.ReadFile(filepath.Join(cfg.caDir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca pool: no certificates")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &apiClient{
		base: cfg.publicOrigin,
		http: &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second},
	}, nil
}

// login walks the full browser flow one hop at a time with the shared cookie
// jar: /auth/login redirects to the static IdP, the IdP redirects back to
// /auth/callback, the server exchanges the code, verifies the id_token and
// issues the session cookie. Each 303 is followed explicitly instead of
// relying on http.Client's CheckRedirect loop, because the redirect hook runs
// before the jar's cookies are attached to the next request and therefore
// cannot show (or debug) which cookies actually travelled. Success is the
// presence of the session cookie in the jar afterwards. On failure the
// diagnostic carries every hop with its status and Set-Cookie header and the
// final error envelope, so a missing browser-proof cookie on the callback is
// distinguishable from an IdP-side or token-side rejection.
func (client *apiClient) login(ctx context.Context) error {
	// Follow each redirect explicitly: ErrUseLastResponse makes http.Client
	// return the 303 instead of chasing it, while the shared jar still sends
	// and stores cookies on every hop exactly as the browser would.
	browser := &http.Client{
		Transport: client.http.Transport,
		Jar:       client.http.Jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var hops []string
	location := client.base + "/auth/login"
	for step := 0; step < 8; step++ {
		response, err := browser.Get(location)
		if err != nil {
			return fmt.Errorf("login flow hop %d (%s): %w\nhops:\n  %s",
				step, location, err, strings.Join(hops, "\n  "))
		}
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		_ = response.Body.Close()
		// Only cookie names travel into the failure diagnostic; values are
		// session secrets and never leave the jar.
		cookieNames := response.Header.Values("Set-Cookie")
		for index := range cookieNames {
			if split := strings.IndexByte(cookieNames[index], '='); split >= 0 {
				cookieNames[index] = cookieNames[index][:split]
			}
		}
		hops = append(hops, fmt.Sprintf("%d %s -> %d [set-cookie=%s]",
			step, location, response.StatusCode, strings.Join(cookieNames, ",")))
		if response.StatusCode == http.StatusSeeOther {
			next := response.Header.Get("Location")
			if next == "" {
				return fmt.Errorf("login flow: 303 without Location at %s\nhops:\n  %s",
					location, strings.Join(hops, "\n  "))
			}
			nextURL, parseErr := response.Request.URL.Parse(next)
			if parseErr != nil {
				return fmt.Errorf("login flow: bad Location %q at %s: %w\nhops:\n  %s",
					next, location, parseErr, strings.Join(hops, "\n  "))
			}
			location = nextURL.String()
			continue
		}
		origin, err := url.Parse(client.base)
		if err != nil {
			return err
		}
		for _, cookie := range client.http.Jar.Cookies(origin) {
			if cookie.Name == "__Host-knowvault_session" && cookie.Value != "" {
				return nil
			}
		}
		return fmt.Errorf("no session cookie after login (final status %d at %s: %s)\nhops:\n  %s",
			response.StatusCode, location, strings.TrimSpace(string(raw)), strings.Join(hops, "\n  "))
	}
	return fmt.Errorf("login flow: redirect chain exceeds 8 hops\nhops:\n  %s", strings.Join(hops, "\n  "))
}

// fetchCSRF obtains the derived CSRF proof for the session.
func (client *apiClient) fetchCSRF(ctx context.Context) error {
	var body struct {
		Token string `json:"csrf_token"`
	}
	if err := client.get(ctx, "/api/v1/session/csrf", &body); err != nil {
		return err
	}
	if body.Token == "" {
		return fmt.Errorf("csrf endpoint returned no token")
	}
	client.csrf = body.Token
	return nil
}

// get performs an authenticated safe request.
func (client *apiClient) get(ctx context.Context, path string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.base+path, nil)
	if err != nil {
		return err
	}
	return client.do(request, out)
}

// post performs an authenticated unsafe request with the CSRF contract.
// idemKeyValue is the Idempotency-Key header; an empty string means the
// header must be absent (the source registration route rejects it). body may
// be nil for an empty-body request.
func (client *apiClient) post(ctx context.Context, path, idemKeyValue string, body any, out any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Origin", client.base)
	request.Header.Set("X-KnowVault-CSRF", client.csrf)
	if idemKeyValue != "" {
		request.Header.Set("Idempotency-Key", idemKeyValue)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	return client.do(request, out)
}

// do runs one request and decodes the expected JSON envelope, surfacing the
// server error envelope on any non-2xx status.
func (client *apiClient) do(request *http.Request, out any) error {
	response, err := client.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", request.Method, request.URL.Path, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope struct {
			Error struct {
				Code      string `json:"code"`
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &envelope)
		return fmt.Errorf("%s %s: status %d code=%s request_id=%s", request.Method, request.URL.Path,
			response.StatusCode, envelope.Error.Code, envelope.Error.RequestID)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: decode response: %w", request.Method, request.URL.Path, err)
		}
	}
	return nil
}

// rawPost is do's header surface for the one case where the response headers
// (the workspace ETag) matter.
func (client *apiClient) rawPost(ctx context.Context, path, idemKeyValue string, body any) (*http.Response, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Origin", client.base)
	request.Header.Set("X-KnowVault-CSRF", client.csrf)
	if idemKeyValue != "" {
		request.Header.Set("Idempotency-Key", idemKeyValue)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", request.Method, request.URL.Path, err)
	}
	return response, nil
}

type workspaceCreated struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision int64  `json:"revision"`
}

type systemCapability struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
}

type systemCapabilities struct {
	SchemaVersion   string             `json:"schema_version"`
	Component       string             `json:"component"`
	ReleaseEligible bool               `json:"release_eligible"`
	Capabilities    []systemCapability `json:"capabilities"`
}

func (client *apiClient) getSystemCapabilities(ctx context.Context) (systemCapabilities, error) {
	var report systemCapabilities
	if err := client.get(ctx, "/api/v1/system/capabilities", &report); err != nil {
		return systemCapabilities{}, err
	}
	return report, nil
}

type sourceRegistered struct {
	ConnectionID      string `json:"connection_id"`
	SourceScopeID     string `json:"source_scope_id"`
	DiscoveredScopeID string `json:"discovered_scope_id"`
	Revision          int64  `json:"revision"`
	Created           bool   `json:"created"`
}

type activationResponse struct {
	JobID string `json:"job_id"`
}

type sourceStatus struct {
	SourceScopeID       string     `json:"source_scope_id"`
	SourceScopeRevision int64      `json:"source_scope_revision"`
	AccessMode          string     `json:"access_mode"`
	Enabled             bool       `json:"enabled"`
	ScopeConfigHash     string     `json:"scope_config_hash"`
	ConnectionID        string     `json:"connection_id"`
	ConnectionName      string     `json:"connection_name"`
	ActivationStatus    string     `json:"activation_status"`
	TrustVerified       bool       `json:"trust_verified"`
	SyncStatus          *string    `json:"sync_status"`
	SyncErrorCode       *string    `json:"sync_error_code"`
	SyncStartedAt       *time.Time `json:"sync_started_at"`
	ObjectsSeen         *int64     `json:"objects_seen"`
	ObjectsIngested     *int64     `json:"objects_ingested"`
	VersionsCreated     *int64     `json:"versions_created"`
	EvidencePublished   *int64     `json:"evidence_published"`
	Quarantined         *int64     `json:"quarantined"`
	SyncCompletedAt     *time.Time `json:"sync_completed_at"`
}

type evidenceFragment struct {
	FragmentID string `json:"fragment_id"`
	Text       string `json:"text"`
	Anchor     string `json:"anchor"`
	Provenance struct {
		SourceObjectID string `json:"source_object_id"`
		ConnectionID   string `json:"connection_id"`
	} `json:"provenance"`
}

// questionProjection is the transport-neutral subset exposed by both the
// REST Question Run route and MCP structuredContent. Keeping this projection
// in the live harness makes parity fail on any drift in status, plan,
// uncertainty, conflict or Evidence/citation fields, rather than comparing
// only the answer string.
type questionProjection struct {
	ID                 string             `json:"question_run_id"`
	WorkspaceID        string             `json:"workspace_id"`
	WorkspaceRevision  int64              `json:"workspace_revision"`
	ConversationID     string             `json:"conversation_id,omitempty"`
	ConversationTurnID string             `json:"conversation_turn_id,omitempty"`
	Question           string             `json:"question,omitempty"`
	AnswerMode         string             `json:"answer_mode"`
	VerificationMethod string             `json:"verification_method"`
	ResultStatus       string             `json:"status"`
	CorpusStatus       string             `json:"corpus_status"`
	Freshness          questionFreshness  `json:"freshness"`
	StartedAt          time.Time          `json:"started_at"`
	CompletedAt        *time.Time         `json:"completed_at,omitempty"`
	Answer             string             `json:"answer,omitempty"`
	AnswerHash         string             `json:"answer_hash,omitempty"`
	ContextPackHash    string             `json:"context_pack_hash,omitempty"`
	ManifestHash       string             `json:"manifest_hash,omitempty"`
	ManifestStatus     string             `json:"manifest_status"`
	Citations          []questionCitation `json:"citations"`
	FailureCode        string             `json:"failure_code,omitempty"`
	PlanningStatus     string             `json:"planning_status"`
	PlanningOperation  string             `json:"planning_operation"`
	PlanningConfidence string             `json:"planning_confidence"`
	PlanHash           string             `json:"plan_hash,omitempty"`
	Clarification      string             `json:"clarification,omitempty"`
	Uncertainties      []questionSignal   `json:"uncertainties"`
	Conflicts          []questionSignal   `json:"conflicts"`
}

type questionFreshness struct {
	State                string     `json:"state"`
	CapturedAt           *time.Time `json:"captured_at,omitempty"`
	LastSuccessfulSyncAt *time.Time `json:"last_successful_sync_at,omitempty"`
}

type questionCitation struct {
	Number           int64  `json:"number"`
	CitationID       string `json:"citation_id"`
	EvidenceFragment string `json:"evidence_fragment_id"`
	Excerpt          string `json:"excerpt"`
	Anchor           string `json:"anchor"`
	DeepLink         string `json:"deep_link"`
	SourceVersionID  string `json:"source_version_id"`
	ExtractionID     string `json:"extraction_id"`
	SourceObjectID   string `json:"source_object_id"`
	EvidenceTextHash string `json:"evidence_text_hash"`
	ExcerptHash      string `json:"excerpt_hash"`
}

type questionSignal struct {
	Code        string   `json:"code"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type mcpQuestionProjection struct {
	StructuredContent questionProjection `json:"structuredContent"`
	IsError           bool               `json:"isError"`
	Error             *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// conversationProjection is the transport-neutral lifecycle projection
// returned by REST and MCP. It deliberately contains only server-owned
// metadata plus the already-authorized Question Run projection; no plaintext
// conversation history is accepted by this harness.
type conversationProjection struct {
	ConversationID    string                       `json:"conversation_id"`
	WorkspaceID       string                       `json:"workspace_id"`
	WorkspaceRevision int64                        `json:"workspace_revision"`
	CreatedBy         string                       `json:"created_by"`
	CreatedAt         time.Time                    `json:"created_at"`
	ArchivedAt        *time.Time                   `json:"archived_at,omitempty"`
	Turns             []conversationTurnProjection `json:"turns"`
}

type conversationTurnProjection struct {
	TurnID        string              `json:"turn_id"`
	QuestionRunID string              `json:"question_run_id"`
	TurnIndex     int64               `json:"turn_index"`
	CreatedAt     time.Time           `json:"created_at"`
	QuestionRun   *questionProjection `json:"question_run,omitempty"`
}

type conversationListProjection struct {
	Conversations []conversationProjection `json:"conversations"`
}

type mcpConversationResult struct {
	StructuredContent json.RawMessage `json:"structuredContent"`
	IsError           bool            `json:"isError"`
}

// createQuestion drives the authenticated REST Question Run route.
func (client *apiClient) createQuestion(ctx context.Context, workspaceID, question, idempotencyKey string) (questionProjection, error) {
	return client.createQuestionInConversation(ctx, workspaceID, "", question, idempotencyKey)
}

func (client *apiClient) createQuestionInConversation(ctx context.Context, workspaceID, conversationID, question, idempotencyKey string) (questionProjection, error) {
	var projection questionProjection
	body := map[string]any{"question": question, "answer_mode": "EXTRACTIVE"}
	if conversationID != "" {
		body["conversation_id"] = conversationID
	}
	err := client.post(ctx, "/api/v1/workspaces/"+workspaceID+"/questions", idempotencyKey,
		body, &projection)
	return projection, err
}

// archiveWorkspace exercises the conditional workspace lifecycle boundary used
// by the denied-question parity check. The server requires the exact ETag and
// an idempotency key; the helper intentionally does not accept a caller-
// supplied body or workspace metadata beyond the server-issued hash.
func (client *apiClient) archiveWorkspace(ctx context.Context, workspaceID, configurationHash, idempotencyKey string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.base+"/api/v1/workspaces/"+workspaceID+":archive", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Origin", client.base)
	request.Header.Set("X-KnowVault-CSRF", client.csrf)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("If-Match", `"`+configurationHash+`"`)
	return client.do(request, nil)
}

// workspaceConfigurationHash re-reads the current snapshot immediately
// before a conditional lifecycle mutation. This keeps the ETag provenance
// explicit and makes the helper robust to any server-side revision advance
// between create and archive.
func (client *apiClient) workspaceConfigurationHash(ctx context.Context, workspaceID string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.base+"/api/v1/workspaces/"+workspaceID, nil)
	if err != nil {
		return "", err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(response.Body, 1<<12))
		return "", fmt.Errorf("GET %s: status %d: %s", request.URL.Path, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	hash := stringsTrimQuotes(response.Header.Get("ETag"))
	if hash == "" {
		return "", fmt.Errorf("GET %s: no ETag", request.URL.Path)
	}
	return hash, nil
}

// mcpQuestion drives the authenticated MCP tools/call route. MCP reuses the
// exact idempotency key so the test can prove that its structuredContent is a
// replay of the REST-created run, not a second authority or data path.
func (client *apiClient) mcpQuestion(ctx context.Context, workspaceID, question, idempotencyKey string) (questionProjection, bool, error) {
	return client.mcpQuestionInConversation(ctx, workspaceID, "", question, idempotencyKey)
}

func (client *apiClient) mcpQuestionInConversation(ctx context.Context, workspaceID, conversationID, question, idempotencyKey string) (questionProjection, bool, error) {
	var envelope struct {
		JSONRPC string                 `json:"jsonrpc"`
		ID      any                    `json:"id"`
		Result  *mcpQuestionProjection `json:"result,omitempty"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	arguments := map[string]any{
		"workspace_id": workspaceID, "question": question, "answer_mode": "EXTRACTIVE",
	}
	if conversationID != "" {
		arguments["conversation_id"] = conversationID
	}
	err := client.post(ctx, "/api/v1/mcp", idempotencyKey, map[string]any{
		"jsonrpc": "2.0", "id": "e2e-parity", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_question", "arguments": arguments},
	}, &envelope)
	if err != nil {
		return questionProjection{}, false, err
	}
	if envelope.Error != nil || envelope.Result == nil {
		return questionProjection{}, false, fmt.Errorf("mcp question error code=%d", func() int {
			if envelope.Error == nil {
				return 0
			}
			return envelope.Error.Code
		}())
	}
	return envelope.Result.StructuredContent, envelope.Result.IsError, nil
}

func sameQuestionProjection(left, right questionProjection) bool {
	return reflect.DeepEqual(left, right)
}

func sameConversationProjection(left, right conversationProjection) bool {
	return reflect.DeepEqual(left, right)
}

// listConversations and getConversation exercise the live REST lifecycle
// surface. Both return the same projection shape used by the MCP wrappers
// below, so parity compares metadata, turn ordering and linked Question Runs.
func (client *apiClient) listConversations(ctx context.Context, workspaceID string) ([]conversationProjection, error) {
	var body conversationListProjection
	if err := client.get(ctx, "/api/v1/workspaces/"+workspaceID+"/conversations", &body); err != nil {
		return nil, err
	}
	return body.Conversations, nil
}

func (client *apiClient) getConversation(ctx context.Context, workspaceID, conversationID string) (conversationProjection, error) {
	var body conversationProjection
	if err := client.get(ctx, "/api/v1/workspaces/"+workspaceID+"/conversations/"+conversationID, &body); err != nil {
		return conversationProjection{}, err
	}
	return body, nil
}

func (client *apiClient) archiveConversation(ctx context.Context, workspaceID, conversationID, idempotencyKey string) (conversationProjection, error) {
	var body conversationProjection
	err := client.post(ctx, "/api/v1/workspaces/"+workspaceID+"/conversations/"+conversationID+":archive", idempotencyKey, nil, &body)
	return body, err
}

func (client *apiClient) mcpConversationCall(ctx context.Context, name, workspaceID, conversationID, idempotencyKey string) (json.RawMessage, bool, error) {
	var envelope struct {
		JSONRPC string                 `json:"jsonrpc"`
		ID      any                    `json:"id"`
		Result  *mcpConversationResult `json:"result,omitempty"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	arguments := map[string]any{"workspace_id": workspaceID}
	if conversationID != "" {
		arguments["conversation_id"] = conversationID
	}
	err := client.post(ctx, "/api/v1/mcp", idempotencyKey, map[string]any{
		"jsonrpc": "2.0", "id": "e2e-conversation", "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": arguments},
	}, &envelope)
	if err != nil {
		return nil, false, err
	}
	if envelope.Error != nil || envelope.Result == nil {
		if envelope.Error == nil {
			return nil, false, fmt.Errorf("mcp %s returned no result", name)
		}
		return nil, false, fmt.Errorf("mcp %s error code=%d message=%s", name, envelope.Error.Code, envelope.Error.Message)
	}
	return envelope.Result.StructuredContent, envelope.Result.IsError, nil
}

func (client *apiClient) mcpListConversations(ctx context.Context, workspaceID string) ([]conversationProjection, bool, error) {
	raw, isError, err := client.mcpConversationCall(ctx, "knowvault_conversations_list", workspaceID, "", "")
	if err != nil {
		return nil, isError, err
	}
	var body conversationListProjection
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, isError, fmt.Errorf("decode MCP conversation list: %w", err)
	}
	return body.Conversations, isError, nil
}

func (client *apiClient) mcpGetConversation(ctx context.Context, workspaceID, conversationID string) (conversationProjection, bool, error) {
	raw, isError, err := client.mcpConversationCall(ctx, "knowvault_conversation_get", workspaceID, conversationID, "")
	if err != nil {
		return conversationProjection{}, isError, err
	}
	var body conversationProjection
	if err := json.Unmarshal(raw, &body); err != nil {
		return conversationProjection{}, isError, fmt.Errorf("decode MCP conversation: %w", err)
	}
	return body, isError, nil
}

func (client *apiClient) mcpArchiveConversation(ctx context.Context, workspaceID, conversationID, idempotencyKey string) (conversationProjection, bool, error) {
	raw, isError, err := client.mcpConversationCall(ctx, "knowvault_conversation_archive", workspaceID, conversationID, idempotencyKey)
	if err != nil {
		return conversationProjection{}, isError, err
	}
	var body conversationProjection
	if err := json.Unmarshal(raw, &body); err != nil {
		return conversationProjection{}, isError, fmt.Errorf("decode MCP archived conversation: %w", err)
	}
	return body, isError, nil
}

// createWorkspace posts the create mutation and returns the new workspace id,
// its revision and the configuration hash the ETag carried.
func (client *apiClient) createWorkspace(ctx context.Context) (workspaceCreated, string, error) {
	response, err := client.rawPost(ctx, "/api/v1/workspaces", idemKey("create-workspace"), map[string]any{
		"name":                "E2E pilot",
		"description":         "R3 end-to-end pilot workspace",
		"retention_policy_id": "ret_default",
	})
	if err != nil {
		return workspaceCreated{}, "", err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return workspaceCreated{}, "", err
	}
	if response.StatusCode != http.StatusOK {
		return workspaceCreated{}, "", fmt.Errorf("create workspace: status %d: %s", response.StatusCode, string(raw))
	}
	var created workspaceCreated
	if err := json.Unmarshal(raw, &created); err != nil {
		return workspaceCreated{}, "", err
	}
	etag := stringsTrimQuotes(response.Header.Get("ETag"))
	if etag == "" {
		return workspaceCreated{}, "", fmt.Errorf("create workspace: no ETag")
	}
	return created, etag, nil
}

func stringsTrimQuotes(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return value[1 : len(value)-1]
	}
	return value
}

// registerSource posts the source registration. It must not carry an
// Idempotency-Key header: the route rejects it by contract.
func (client *apiClient) registerSource(ctx context.Context) (sourceRegistered, error) {
	var registered sourceRegistered
	err := client.post(ctx, "/api/v1/sources", "", map[string]any{
		"name":           "E2E corpus",
		"root_alias":     "e2e-root",
		"root_identity":  "e2e-root-id",
		"relative_root":  "inbox",
		"kind":           "documents",
		"recursive":      true,
		"include_globs":  []string{"**/*"},
		"exclude_globs":  []string{},
		"max_file_bytes": 1048576,
		"ocr_mode":       "OFF",
		"formats":        []string{"TXT", "HTML", "EML"},
	}, &registered)
	return registered, err
}

// activateSource posts the activation mutation and returns the durable job id.
func (client *apiClient) activateSource(ctx context.Context, sourceScopeID string) (activationResponse, error) {
	var activated activationResponse
	err := client.post(ctx, "/api/v1/sources/"+sourceScopeID+":activate", idemKey("activate-scope"), nil, &activated)
	return activated, err
}

// listSources returns the status of every source bound to the workspace.
func (client *apiClient) listSources(ctx context.Context, workspaceID string) ([]sourceStatus, error) {
	var body struct {
		Sources []sourceStatus `json:"sources"`
	}
	if err := client.get(ctx, "/api/v1/workspaces/"+workspaceID+"/sources", &body); err != nil {
		return nil, err
	}
	return body.Sources, nil
}

// readEvidence fetches one fragment through the fail-closed viewer route.
func (client *apiClient) readEvidence(ctx context.Context, workspaceID, fragmentID string) (evidenceFragment, error) {
	var fragment evidenceFragment
	err := client.get(ctx, "/api/v1/workspaces/"+workspaceID+"/evidence/"+fragmentID, &fragment)
	return fragment, err
}

// auditJournalEvent is the chain-bearing subset of one workspace-scoped audit
// journal entry. The harness deliberately names only the fields its chain
// check reads (identity, order and the two hashes); content-free metadata and
// evidence references are never decoded into this projection.
type auditJournalEvent struct {
	EventID           string `json:"event_id"`
	Sequence          int64  `json:"sequence"`
	Action            string `json:"action"`
	PreviousEventHash string `json:"previous_event_hash"`
	EventHash         string `json:"event_hash"`
}

// auditJournalResponse is the transport envelope the audit-events route
// returns: the organization chain head plus the latest workspace page.
type auditJournalResponse struct {
	WorkspaceID  string              `json:"workspace_id"`
	HeadSequence int64               `json:"head_sequence"`
	HeadHash     string              `json:"head_hash"`
	Events       []auditJournalEvent `json:"events"`
	Truncated    bool                `json:"truncated"`
}

// getAuditEvents drives the authenticated audit-events GET exactly as a
// browser would open the journal: one safe request on the logged-in session
// with no CSRF proof, because the route is read-only by contract.
func (client *apiClient) getAuditEvents(ctx context.Context, workspaceID string) (auditJournalResponse, error) {
	var journal auditJournalResponse
	if err := client.get(ctx, "/api/v1/workspaces/"+workspaceID+"/audit-events", &journal); err != nil {
		return auditJournalResponse{}, err
	}
	return journal, nil
}

// verifyAuditHashChain proves the journal answered a non-empty stream that is
// anchored to a live hash chain. Because every lawful journal read appends its
// own audit.viewed event, the harness reads twice and validates the second
// page: the newest returned event (the prior read's audit.viewed) must carry
// the exact event_hash the response reports as the organization chain head.
// That equality is the surface-level proof that the returned events are linked
// to the chain head by hash, not a disconnected list. Each returned event must
// also carry well-formed event_hash and previous_event_hash (the sha256 digest
// form the chain uses, genesis included), and the page must stay in strictly
// descending sequence order. The page is workspace-scoped while the chain is
// organization-wide, so consecutive workspace rows may legitimately skip
// interleaving non-workspace events; the head-anchor equality above is the
// deterministic cross-window linkage, not per-row adjacency.
func verifyAuditHashChain(journal auditJournalResponse) error {
	if len(journal.Events) == 0 {
		return fmt.Errorf("audit journal returned no events")
	}
	if journal.HeadSequence < 1 {
		return fmt.Errorf("audit journal chain head has no sequence: %d", journal.HeadSequence)
	}
	if !validAuditHash(journal.HeadHash) {
		return fmt.Errorf("audit journal head hash %q is not a sha256 digest", journal.HeadHash)
	}
	newest := journal.Events[0]
	if newest.Sequence != journal.HeadSequence {
		return fmt.Errorf("audit journal newest event sequence %d does not match chain head %d", newest.Sequence, journal.HeadSequence)
	}
	if newest.EventHash != journal.HeadHash {
		return fmt.Errorf("audit journal newest event %s is not anchored to the chain head", newest.EventID)
	}
	previousSequence := int64(0)
	for index, event := range journal.Events {
		if !validAuditHash(event.EventHash) {
			return fmt.Errorf("audit event %s carries invalid event_hash %q", event.EventID, event.EventHash)
		}
		if !validAuditHash(event.PreviousEventHash) {
			return fmt.Errorf("audit event %s carries invalid previous_event_hash %q", event.EventID, event.PreviousEventHash)
		}
		if index > 0 && event.Sequence >= previousSequence {
			return fmt.Errorf("audit journal page is not strictly descending by sequence at event %s", event.EventID)
		}
		previousSequence = event.Sequence
	}
	return nil
}

// validAuditHash reports whether value is the "sha256:"-prefixed 64-hex digest
// the audit chain uses for both event hashes and the genesis zero hash.
func validAuditHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
