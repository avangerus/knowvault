package postgres_test

// KV-A01 (R3a-1 Outcome 1): the negative controls of the paged Evidence read,
// proved end to end against real PostgreSQL through the production workspaceapi
// MCP adapter.
//
// The surface under test is the existing, unmodified knowvault_evidence_read
// MCP tool over POST /api/v1/mcp. It resolves through the same authorized
// internal/source/evidence.Viewer.Read the REST evidenceGet route uses, so
// this suite drives the real viewer bound to a real worker-synced evidence
// chain (no fake EvidenceService and no raw fragment forgery):
//
//  1. page reassembly — a fragment whose canonical text is larger than the
//     4096-byte default page is read page by page following next_offset until
//     has_more is false; concatenating the exact page bytes reproduces the
//     stored canonical text byte for byte and the reported whole-fragment
//     text_hash equals evidence_fragment.text_hash.
//  2. tamper refusal — a caller-supplied expected_span_hash that does not equal
//     the stored text_hash is refused with the typed, content-free -32005 and
//     returns no page text and no address metadata.
//  3. cross-workspace denial — a real fragment requested under a real workspace
//     the caller is not a member of is refused with the existing content-free
//     -32004, with no content, no address and no requested-workspace echo, and
//     the audit journal records a content-free DENIED admission with a class.
//
// The last clause is the R1 admission-before-data mechanism. The fragment read
// path itself stays no-oracle: Viewer.Read collapses every denial to one
// ErrNotFound before it appends anything (internal/source/evidence/viewer.go,
// proved by TestReadDenialAppendsNothingAndNeverReads), so its denial carries no
// journal event to leak an existence oracle. This suite therefore asserts the
// denial for the fragment address is content-free AND proves that the same
// denied workspace is journalled as a content-free DENIED admission with a
// class through the workspace-scoped inventory read (knowvault_workspace_list,
// WORKSPACE_OBJECTS_DENIED) that shares the viewer's audit journal. No
// production semantics, route, contract, migration or dependency changes.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	kvA01Origin = "https://workspace.example"
	// kvA01ForeignWorkspace is a real workspace in the same organization that
	// the caller s1dViewer is not a member of: the cross-workspace address.
	kvA01ForeignWorkspace = "ws_s1d_foreign"
)

// --- minimal MCP transport helpers (real workspaceapi handler, real auth) ---

type kvA01TenantResolver struct {
	organizationID string
	// origin overrides the enforced HTTPS origin. Empty keeps kvA01Origin, so
	// every existing caller is unchanged; the card U-1 walkthrough passes the
	// origin of its own local stand so the browser's real Origin header is the
	// one httpauth compares against.
	origin string
}

func (resolver kvA01TenantResolver) Resolve(context.Context) (httpauth.TenantSecurityContext, error) {
	origin := resolver.origin
	if origin == "" {
		origin = kvA01Origin
	}
	return httpauth.TenantSecurityContext{
		OrganizationID: identity.OrganizationID(resolver.organizationID),
		Origin:         origin,
		Digestor:       kvA01Digestor{},
	}, nil
}

type kvA01Digestor struct{}

func (kvA01Digestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	if purpose != "session_token" && purpose != "csrf" {
		return identity.KeyedDigest{}, errors.New("unsupported digest purpose")
	}
	digest := sha256.Sum256([]byte(purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + hex.EncodeToString(digest[:]))
}

type kvA01SessionResolver struct {
	organizationID string
	principalID    string
	claims         identity.Claims
}

func (resolver kvA01SessionResolver) ResolveSession(_ context.Context, request identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	return identityrepository.AuthenticatedSession{
		SessionID: "ses_kva01_controls",
		Claims:    resolver.claims,
		Access: database.AccessContext{
			OrganizationID: resolver.organizationID,
			PrincipalID:    resolver.principalID,
			RequestID:      request.RequestID,
		},
	}, nil
}

func kvA01Claims(t *testing.T, organizationID, principal string) identity.Claims {
	t.Helper()
	claims, err := identity.NewClaims(identity.OrganizationID(organizationID), identity.PrincipalID(principal),
		1, identity.ProviderID("idp_kva01"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("kv-a01 claims: %v", err)
	}
	return claims
}

// kvA01SourceService is the non-nil SourceService dependency the handler
// constructor requires. The evidence read tools under test never dispatch to
// it; every method fails closed so a stray dispatch is a visible test failure
// rather than a silent no-op.
type kvA01SourceService struct{}

func (kvA01SourceService) Register(context.Context, database.AccessContext, registration.RegisterRequest) (registration.RegisterResult, error) {
	return registration.RegisterResult{}, errors.New("kv-a01: source registration not composed for the evidence read test")
}

func (kvA01SourceService) Activate(context.Context, database.AccessContext, registration.ActivateRequest) (registration.ActivateResult, error) {
	return registration.ActivateResult{}, errors.New("kv-a01: source activation not composed for the evidence read test")
}

func (kvA01SourceService) Sync(context.Context, database.AccessContext, registration.SyncRequest) (registration.SyncResult, error) {
	return registration.SyncResult{}, errors.New("kv-a01: source sync not composed for the evidence read test")
}

func (kvA01SourceService) ListSources(context.Context, database.AccessContext, string) ([]workspacerepository.SourceStatus, error) {
	return nil, errors.New("kv-a01: source listing not composed for the evidence read test")
}

func (kvA01SourceService) ConfirmationContext(context.Context, database.AccessContext, string) (workspacerepository.ConfirmationContext, error) {
	return workspacerepository.ConfirmationContext{}, errors.New("kv-a01: confirmation context not composed for the evidence read test")
}

func (kvA01SourceService) UploadDocuments(context.Context, database.AccessContext, registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return registration.UploadDocumentsResult{}, errors.New("kv-a01: upload not composed for the evidence read test")
}

// kvA01Handler composes the real workspaceapi handler against the real
// workspace repository and the real evidence viewer, authenticated as one
// principal of one organization through the same httpauth OIDC/Keycloak
// transport the deployment uses (a verified session cookie plus the tenant's
// CSRF proof). It returns the handler, the session cookie token and the CSRF
// proof the caller must present.
func kvA01Handler(t *testing.T, organizationID, principal string,
	viewer *evidence.Viewer, authority *workspacerepository.Store) (*workspaceapi.Handler, string, string) {
	t.Helper()
	authenticator, err := httpauth.New(
		kvA01TenantResolver{organizationID: organizationID},
		kvA01SessionResolver{organizationID: organizationID, principalID: principal, claims: kvA01Claims(t, organizationID, principal)},
	)
	if err != nil {
		t.Fatalf("kv-a01 authenticator: %v", err)
	}
	appStore := openStore(t, context.Background(), appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(authenticator, authority, kvA01SourceService{}, viewer, nil, conversations)
	if err != nil {
		t.Fatalf("kv-a01 workspace handler: %v", err)
	}
	rawToken := make([]byte, sha256.Size)
	for index := range rawToken {
		rawToken[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	proof, err := (kvA01Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("kv-a01 csrf proof: %v", err)
	}
	return handler, token, proof.Value()
}

type kvA01MCPEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured jsontext.Value   `json:"structuredContent"`
		IsError    bool             `json:"isError"`
	} `json:"result"`
	Error *kvA01MCPError `json:"error"`
}

type kvA01MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// kvA01ReadResult is the closed structuredContent projection of
// knowvault_evidence_read.
type kvA01ReadResult struct {
	FragmentID  string         `json:"fragment_id"`
	Text        string         `json:"text"`
	TextBase64  string         `json:"text_base64"`
	Offset      int64          `json:"offset"`
	Length      int64          `json:"length"`
	NextOffset  *int64         `json:"next_offset"`
	HasMore     bool           `json:"has_more"`
	Limit       int64          `json:"limit"`
	TotalLength int64          `json:"total_length"`
	TextHash    string         `json:"text_hash"`
	PageHash    string         `json:"page_hash"`
	Address     map[string]any `json:"address"`
}

func kvA01ToolCallBody(id, tool, arguments string) string {
	return `{"jsonrpc":"2.0","id":` + strconv.Quote(id) + `,"method":"tools/call","params":{"name":` +
		strconv.Quote(tool) + `,"arguments":` + arguments + `}}`
}

// kvA01Call issues one authenticated tools/call against the real handler and
// returns the raw body and decoded envelope.
func kvA01Call(t *testing.T, handler *workspaceapi.Handler, token, csrf, body string) (string, kvA01MCPEnvelope) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, kvA01Origin+"/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", kvA01Origin)
	request.Header.Set(httpauth.CSRFHeader, csrf)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("kv-a01 MCP status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope kvA01MCPEnvelope
	if err := jsonv2.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("kv-a01 MCP decode: %v body=%s", err, response.Body.String())
	}
	return response.Body.String(), envelope
}

// kvA01ReadClaims issues one knowvault_evidence_read tools/call and decodes its
// structured read result.
func kvA01ReadClaims(t *testing.T, handler *workspaceapi.Handler, token, csrf, arguments string) (string, kvA01MCPEnvelope, kvA01ReadResult) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-read", "knowvault_evidence_read", arguments))
	var result kvA01ReadResult
	if envelope.Error == nil && len(envelope.Result.Structured) > 0 {
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &result); err != nil {
			t.Fatalf("kv-a01 read structuredContent decode: %v body=%s", err, body)
		}
	}
	return body, envelope, result
}

// seedKVA01ForeignWorkspace creates a real ACTIVE workspace of the same
// organization, owned by the same owner but with no membership for the caller
// s1dViewer, so a cross-workspace request names a workspace that genuinely
// exists rather than an unknown id.
func seedKVA01ForeignWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, ownerID string) {
	t.Helper()
	wsConfigHash := "sha256:" + strings.Repeat("f", 64)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin foreign workspace seed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		if _, execErr := tx.Exec(ctx, sql, args...); execErr != nil {
			t.Fatalf("foreign workspace seed: %v\n%s", execErr, sql)
		}
	}
	exec(`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
		VALUES ($1,$2,$1,'ACTIVE',$3,1)`, workspaceID, organizationID, ownerID)
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1,$2,1,$3,$4)`, organizationID, workspaceID, wsConfigHash, ownerID)
	exec(`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1,$2,1,$3,decode('7b7d','hex'))`, organizationID, workspaceID, wsConfigHash)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_kva01_foreign_owner', $1, $2, $3, 'OWNER', 1, $3)`, organizationID, workspaceID, ownerID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit foreign workspace seed: %v", err)
	}
}

// TestKVA01EvidenceReadOutcomeOneControls proves the three Outcome 1 negative
// controls end to end on the real MCP surface.
func TestKVA01EvidenceReadOutcomeOneControls(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	// A single logical line larger than the 4096-byte default page: the
	// extractor never splits a line, so the file yields exactly one fragment
	// whose canonical text exceeds the default page and must be paged.
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("\u043d\u043e\u0440\u043c\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442 ", 640)
	writeS1dFile(t, filepath.Join(dir, "long.txt"), longLine)

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)
	seedKVA01ForeignWorkspace(t, ctx, admin, s1dOrg, kvA01ForeignWorkspace, s1dOwner)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, ingest, queue, workerAccess(t, s1dOrg), "kva01-controls")

	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("worker sync produced no evidence fragments")
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	authority := newAuthorityRuntime(t, ctx)
	handler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, authority)

	// Positive control and independent original: the production viewer serves
	// the authorized fragment, and its whole-fragment hash is the stored catalog
	// hash (ADR-0077 org-keyed HMAC). The long single-line document yields a
	// fragment larger than the 4096-byte default page, so it must be paged.
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_kva01_controls"}
	var fragmentID string
	var original evidence.Fragment
	for _, candidate := range fragments {
		frag, readErr := viewer.Read(ctx, viewerAccess, s1dWorkspace, candidate.id)
		if readErr != nil {
			t.Fatalf("authorized viewer read of %s failed: %v", candidate.id, readErr)
		}
		if int64(len(frag.Text)) > 4096 {
			fragmentID, original = candidate.id, frag
			break
		}
	}
	if fragmentID == "" {
		t.Fatal("fixture has no fragment larger than the 4096-byte default page")
	}
	var storedHash string
	if err := admin.QueryRow(ctx, `SELECT text_hash FROM public.evidence_fragment
		WHERE organization_id=$1 AND id=$2`, s1dOrg, fragmentID).Scan(&storedHash); err != nil {
		t.Fatalf("read stored evidence_fragment.text_hash: %v", err)
	}
	if original.EvidenceTextHash != storedHash {
		t.Fatalf("viewer hash %q != evidence_fragment.text_hash %q", original.EvidenceTextHash, storedHash)
	}

	t.Run("pages reassemble byte for byte to the stored original hash", func(t *testing.T) {
		var assembled []byte
		offset := int64(0)
		pages := 0
		for {
			if pages > 128 {
				t.Fatal("paged read did not terminate")
			}
			arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(fragmentID) + `,"include_text_base64":true`
			if offset > 0 {
				arguments += `,"offset":` + strconv.FormatInt(offset, 10)
			}
			arguments += `}`
			body, envelope, page := kvA01ReadClaims(t, handler, token, csrf, arguments)
			if envelope.Error != nil {
				t.Fatalf("page at offset %d refused: %#v body=%s", offset, envelope.Error, body)
			}
			if page.FragmentID != fragmentID {
				t.Fatalf("page fragment_id=%q want %q", page.FragmentID, fragmentID)
			}
			if page.Offset != offset {
				t.Fatalf("page offset=%d want %d (the effective window must be echoed)", page.Offset, offset)
			}
			if page.TextHash != storedHash {
				t.Fatalf("page text_hash=%q want evidence_fragment.text_hash %q", page.TextHash, storedHash)
			}
			if page.TotalLength != int64(len(original.Text)) {
				t.Fatalf("page total_length=%d want %d", page.TotalLength, len(original.Text))
			}
			pageBytes, err := base64.StdEncoding.DecodeString(page.TextBase64)
			if err != nil {
				t.Fatalf("page text_base64 did not decode: %v", err)
			}
			sum := sha256.Sum256(pageBytes)
			if page.PageHash != "sha256:"+hex.EncodeToString(sum[:]) {
				t.Fatalf("page_hash=%q does not name the returned page", page.PageHash)
			}
			if page.Text != string(pageBytes) {
				t.Fatalf("page text member does not equal the page bytes")
			}
			assembled = append(assembled, pageBytes...)
			pages++
			if !page.HasMore {
				if page.NextOffset != nil {
					t.Fatalf("final page offered next_offset=%d", *page.NextOffset)
				}
				break
			}
			if page.NextOffset == nil || *page.NextOffset <= offset {
				t.Fatalf("non-progressing next_offset at offset=%d: %v", offset, page.NextOffset)
			}
			offset = *page.NextOffset
		}
		if pages < 2 {
			t.Fatalf("expected a multi-page read, got %d page(s)", pages)
		}
		if !bytes.Equal(assembled, original.Text) {
			t.Fatalf("reassembled %d bytes != stored original %d bytes", len(assembled), len(original.Text))
		}
	})

	t.Run("tampered span hash is refused without content or address", func(t *testing.T) {
		tampered := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(fragmentID) +
			`,"expected_span_hash":"sha256:` + strings.Repeat("0", 64) + `"}`
		body, envelope, _ := kvA01ReadClaims(t, handler, token, csrf, tampered)
		if envelope.Error == nil || envelope.Error.Code != -32005 || envelope.Error.Message != "evidence span hash mismatch" {
			t.Fatalf("tampered span hash not refused with -32005: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 {
			t.Fatalf("tampered refusal leaked content or address: %s", body)
		}
		if strings.Contains(body, s1dWorkspace) {
			t.Fatalf("tampered refusal echoed the workspace: %s", body)
		}

		matching := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(fragmentID) +
			`,"expected_span_hash":` + strconv.Quote(storedHash) + `}`
		_, matchEnvelope, match := kvA01ReadClaims(t, handler, token, csrf, matching)
		if matchEnvelope.Error != nil {
			t.Fatalf("matching span hash was refused: %#v", matchEnvelope.Error)
		}
		if match.TextHash != storedHash || match.TotalLength != int64(len(original.Text)) {
			t.Fatalf("matching span hash served the wrong object: hash=%q total_length=%d", match.TextHash, match.TotalLength)
		}
	})

	t.Run("cross-workspace address is denied without content and journalled as DENIED", func(t *testing.T) {
		var openedBefore int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='citation.opened' AND referenced_evidence_ids_json ? $2`,
			s1dOrg, fragmentID).Scan(&openedBefore); err != nil {
			t.Fatalf("count pre-denial citation.opened: %v", err)
		}

		foreign := `{"workspace_id":` + strconv.Quote(kvA01ForeignWorkspace) + `,"fragment_id":` + strconv.Quote(fragmentID) + `}`
		body, envelope, read := kvA01ReadClaims(t, handler, token, csrf, foreign)
		if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "evidence not found" {
			t.Fatalf("cross-workspace read not the content-free not-found: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 || read.TextHash != "" || len(read.Address) != 0 {
			t.Fatalf("cross-workspace denial leaked content or address: %s", body)
		}
		if strings.Contains(body, fragmentID) || strings.Contains(body, kvA01ForeignWorkspace) {
			t.Fatalf("cross-workspace denial echoed the fragment or requested workspace: %s", body)
		}
		// The viewer denial is the same no-oracle ErrNotFound the REST route
		// returns.
		if _, err := viewer.Read(ctx, viewerAccess, kvA01ForeignWorkspace, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("direct viewer cross-workspace err=%v, want ErrNotFound", err)
		}

		// The denied address disclosed nothing: no citation.opened event names
		// the fragment.
		var openedAfter int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='citation.opened' AND referenced_evidence_ids_json ? $2`,
			s1dOrg, fragmentID).Scan(&openedAfter); err != nil {
			t.Fatalf("count post-denial citation.opened: %v", err)
		}
		if openedAfter != openedBefore {
			t.Fatalf("a denied cross-workspace read opened %d citation(s)", openedAfter-openedBefore)
		}

		// R1 admission-before-data journalling: the same denied workspace read
		// through the workspace inventory tool records a content-free DENIED
		// admission with its closed class and a NULL workspace (never a foreign
		// key failure and never an existence oracle).
		listBody := kvA01ToolCallBody("kva01-list", "knowvault_workspace_list",
			`{"workspace_id":`+strconv.Quote(kvA01ForeignWorkspace)+`}`)
		raw, listEnvelope := kvA01Call(t, handler, token, csrf, listBody)
		if listEnvelope.Error == nil || listEnvelope.Error.Code != -32004 || listEnvelope.Error.Message != "workspace objects not found" {
			t.Fatalf("cross-workspace inventory not the content-free not-found: %#v body=%s", listEnvelope.Error, raw)
		}
		if len(listEnvelope.Result.Structured) != 0 || len(listEnvelope.Result.Content) != 0 {
			t.Fatalf("cross-workspace inventory leaked content: %s", raw)
		}

		var outcome, errorCode string
		var workspaceID *string
		if err := admin.QueryRow(ctx, `SELECT outcome, error_code, workspace_id FROM public.audit_event
			WHERE organization_id=$1 AND action='evidence.read.admitted' AND outcome='DENIED'
			  AND resource_id=$2
			ORDER BY occurred_at DESC, id DESC LIMIT 1`,
			s1dOrg, kvA01ForeignWorkspace).Scan(&outcome, &errorCode, &workspaceID); err != nil {
			t.Fatalf("load the denial journal event: %v", err)
		}
		if outcome != "DENIED" || errorCode != "WORKSPACE_OBJECTS_DENIED" {
			t.Fatalf("denial event = (%s, %s), want DENIED/WORKSPACE_OBJECTS_DENIED", outcome, errorCode)
		}
		if workspaceID != nil {
			t.Fatalf("denial event recorded workspace %q, want NULL", *workspaceID)
		}
	})
}
