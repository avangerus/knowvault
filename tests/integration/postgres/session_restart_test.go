package postgres_test

// Card D-3: a signed-in user stays signed in across a server restart.
//
// The browser session is server-side persistence, not process memory: the login
// callback writes one identity_session row whose only session secret is the
// keyed digest of the opaque cookie, and every later request resolves that
// cookie through the same mounted session key. A restart therefore only has to
// rebuild the composition over the SAME database and the SAME mounted keys.
//
// These tests drive the REAL oidcweb login handler end to end against real
// PostgreSQL -- a test identity-provider protocol adapter supplies the verified
// subject, exactly as the reviewed oidc.Protocol boundary does in production --
// then build a SECOND, fully independent composition (new database pool, new
// digestor handles, new codec, new cookie issuer, new authenticator and handler)
// over the same database and the same key bytes to simulate the restarted
// process. No session state is carried between the two compositions except the
// browser cookie and the database row.
//
// Covered: the same cookie still authenticates and still satisfies CSRF after
// the restart; logout and expiry are rejected by the restarted instance too;
// revoking the member invalidates the persisted session's access; the raw
// cookie value is never the stored material; and a foreign organization context
// cannot read the session row.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/browserauth"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/oidctransport"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	d3OrganizationID = "org_d3"
	d3ProviderID     = "idp_d3"
	d3OwnerID        = "usr_d3_owner"
	d3MemberID       = "usr_d3_member"
	d3WorkspaceID    = "ws_d3"
	d3Origin         = "https://workspace.example"
	d3SubjectRaw     = "subject_d3_member"

	// The three fixed deployment keys. The restart is only real if the second
	// composition sees byte-identical identity, session and transport keys.
	d3IdentityKeyVersion = 1
	d3SessionKeyVersion  = 2
)

// d3Protocol is the test identity-provider harness. It produces one real OIDC
// attempt through the reviewed constructor and returns one already-verified
// subject digest, so the handler performs exactly the production sequencing
// (durable BeginLogin, sealed browser cookie, CompleteLogin, cookie issuance)
// without any network call.
type d3Protocol struct {
	subject identity.KeyedDigest
	attempt oidc.Attempt
}

func (protocol *d3Protocol) NewAttempt(digestor oidc.Digestor) (oidc.Attempt, error) {
	attempt, err := oidc.NewSecureAttempt(digestor)
	if err == nil {
		protocol.attempt = attempt
	}
	return attempt, err
}

func (protocol *d3Protocol) Discover(context.Context, *oidc.HardenedHTTPClient, oidc.ProviderConfiguration, oidc.Digestor) (oidcweb.ProtocolClient, error) {
	return d3ProtocolClient{subject: protocol.subject}, nil
}

type d3ProtocolClient struct{ subject identity.KeyedDigest }

func (d3ProtocolClient) AuthorizationURL(oidc.Attempt) (string, error) {
	return "https://identity.d3.example/authorize", nil
}

func (client d3ProtocolClient) ExchangeAndVerify(context.Context, string, string, oidc.Attempt) (oidc.Subject, error) {
	return oidc.Subject{Digest: client.subject, ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
}

// d3Secrets is the test client-secret resolver. The seeded provider revision
// carries a non-secret reference; the exchange never leaves this process.
type d3Secrets struct{}

func (d3Secrets) Resolve(context.Context, oidcweb.ClientSecretRequest) (string, error) {
	return "d3-client-secret", nil
}

// d3Composition is one complete server composition: everything a running
// server holds, bound to one database pool and one set of mounted keys.
type d3Composition struct {
	security      tenantsecurity.Context
	handler       *oidcweb.Handler
	authenticator *httpauth.Authenticator
	store         *identityrepository.Store
	database      *database.Store
	audit         *audit.Store
	protocol      *d3Protocol

	closers []func()
}

// d3NewComposition builds a fresh server composition over the shared database
// and the shared key bytes. Calling it twice is exactly what a process restart
// does: nothing but the database and the mounted secrets is common.
func d3NewComposition(t *testing.T, ctx context.Context, subject identity.KeyedDigest) *d3Composition {
	t.Helper()

	identityKey := bytes.Repeat([]byte{0x11}, 32)
	sessionKey := bytes.Repeat([]byte{0x22}, 32)
	transportKey := bytes.Repeat([]byte{0x33}, 32)

	identityDigestor, err := oidc.NewHMACDigestor(d3IdentityKeyVersion, identityKey)
	if err != nil {
		t.Fatalf("d3 identity digestor: %v", err)
	}
	sessionDigestor, err := oidc.NewHMACDigestor(d3SessionKeyVersion, sessionKey)
	if err != nil {
		t.Fatalf("d3 session digestor: %v", err)
	}
	security, err := tenantsecurity.NewContext(
		d3OrganizationID, d3ProviderID, d3Origin,
		"key_identity_d3", identityDigestor, "key_session_d3", sessionDigestor,
	)
	if err != nil {
		t.Fatalf("d3 tenant security: %v", err)
	}
	tenantResolver, err := tenantsecurity.NewStaticResolver(security)
	if err != nil {
		t.Fatalf("d3 tenant resolver: %v", err)
	}
	httpSecurityResolver, err := tenantsecurity.NewHTTPAuthResolver(tenantResolver)
	if err != nil {
		t.Fatalf("d3 http security resolver: %v", err)
	}

	databaseConfig := database.DefaultConfig()
	databaseConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, databaseConfig)
	if err != nil {
		t.Fatalf("d3 open application store: %v", err)
	}
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("d3 audit store: %v", err)
	}
	identityStore, err := identityrepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("d3 identity repository: %v", err)
	}

	codec, err := oidctransport.NewCodec(security, "key_transport_d3", "kid_transport_d3", transportKey)
	if err != nil {
		t.Fatalf("d3 transport codec: %v", err)
	}
	browser, err := oidctransport.NewBrowserTransport(codec)
	if err != nil {
		t.Fatalf("d3 browser transport: %v", err)
	}
	sessions := browserauth.NewCookieIssuer()
	authenticator, err := httpauth.NewWithRenewer(httpSecurityResolver, identityStore, sessions)
	if err != nil {
		t.Fatalf("d3 authenticator: %v", err)
	}
	hardened, err := oidc.NewHardenedHTTPClient(&http.Transport{})
	if err != nil {
		t.Fatalf("d3 hardened http client: %v", err)
	}
	protocol := &d3Protocol{subject: subject}
	handler, err := oidcweb.New(oidcweb.Dependencies{
		TenantResolver: tenantResolver,
		Store:          identityStore,
		Protocol:       protocol,
		Secrets:        d3Secrets{},
		Browser:        browser,
		Sessions:       sessions,
		Authenticator:  authenticator,
		HTTPClient:     hardened,
	})
	if err != nil {
		t.Fatalf("d3 oidc handler: %v", err)
	}

	composition := &d3Composition{
		security: security, handler: handler, authenticator: authenticator,
		store: identityStore, database: databaseStore, audit: auditStore, protocol: protocol,
	}
	composition.closers = append(composition.closers,
		func() { databaseStore.Close() },
		func() { _ = codec.Close() },
		identityDigestor.Close,
		sessionDigestor.Close,
	)
	t.Cleanup(func() {
		for index := len(composition.closers) - 1; index >= 0; index-- {
			composition.closers[index]()
		}
	})
	return composition
}

// d3NewCompositions builds count independent compositions over one database.
func d3NewCompositions(t *testing.T, ctx context.Context, subject identity.KeyedDigest, count int) []*d3Composition {
	t.Helper()
	compositions := make([]*d3Composition, 0, count)
	for index := 0; index < count; index++ {
		compositions = append(compositions, d3NewComposition(t, ctx, subject))
	}
	return compositions
}

// d3SignIn performs the real browser login through composition's handler and
// returns the exact session cookie the browser would hold.
func d3SignIn(t *testing.T, composition *d3Composition) *http.Cookie {
	t.Helper()

	loginResponse := httptest.NewRecorder()
	composition.handler.ServeHTTP(loginResponse, httptest.NewRequest(http.MethodGet, d3Origin+"/auth/login", nil))
	if loginResponse.Code != http.StatusSeeOther {
		t.Fatalf("d3 login status=%d body=%q", loginResponse.Code, loginResponse.Body.String())
	}
	transportCookie := d3Cookie(t, loginResponse, oidctransport.CookieName)

	state, _, _, _, ok := composition.protocol.attempt.TransportMaterial()
	if !ok {
		t.Fatal("d3 login did not produce a fresh attempt")
	}
	callbackRequest := httptest.NewRequest(http.MethodGet, d3Origin+"/auth/callback?code=d3-code&state="+state, nil)
	callbackRequest.AddCookie(transportCookie)
	callbackResponse := httptest.NewRecorder()
	composition.handler.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusSeeOther {
		t.Fatalf("d3 callback status=%d body=%q", callbackResponse.Code, callbackResponse.Body.String())
	}
	return d3Cookie(t, callbackResponse, httpauth.SessionCookieName)
}

func d3Cookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("d3 cookie %q not set: %v", name, response.Header().Values("Set-Cookie"))
	return nil
}

// d3Authenticate resolves one cookie against a composition exactly as the HTTP
// boundary does.
func d3Authenticate(t *testing.T, composition *d3Composition, cookie *http.Cookie, requestID string) (httpauth.Authentication, error) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, d3Origin+"/api/v1/workspaces", nil)
	request.AddCookie(cookie)
	return composition.authenticator.Authenticate(request, requestID)
}

// TestSessionSurvivesServerRestart is the card's central proof. After a full
// sign-in on composition one, a completely independent composition two -- new
// pool, new key handles, new codec, new authenticator -- authenticates the very
// same cookie, derives the same CSRF proof, and serves a real workspace read.
func TestSessionSurvivesServerRestart(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	subjectDigest := d3SeedOrganization(t, ctx, admin)
	compositions := d3NewCompositions(t, ctx, subjectDigest, 2)

	cookie := d3SignIn(t, compositions[0])

	// The restart must not have changed the reviewed cookie profile
	// (ADR-0030): host-only, Secure, HttpOnly, Lax, Path=/.
	if cookie.Name != httpauth.SessionCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" ||
		cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge < 1 {
		t.Fatalf("d3 session cookie profile changed: %+v", cookie)
	}

	// The stored material must never be the raw cookie value.
	var storedDigest string
	if err := admin.QueryRow(ctx, `
		SELECT session_token_digest FROM public.identity_session WHERE organization_id = $1
	`, d3OrganizationID).Scan(&storedDigest); err != nil {
		t.Fatalf("d3 read stored session material: %v", err)
	}
	if storedDigest == cookie.Value || !bytes.HasPrefix([]byte(storedDigest), []byte("hmac-sha256:k")) {
		t.Fatalf("d3 stored session material is not a keyed digest: %q", storedDigest)
	}

	// Composition two is the "restarted server".
	authentication, err := d3Authenticate(t, compositions[1], cookie, "req_d3_restart")
	if err != nil {
		t.Fatalf("d3 cookie rejected after restart: %v", err)
	}
	if authentication.Session().Access.PrincipalID != d3MemberID || authentication.Session().SessionID == "" {
		t.Fatalf("d3 restarted session=%+v", authentication.Session())
	}

	// The restarted instance still enforces CSRF on unsafe requests with the
	// proof derived from the persisted session, not from process memory.
	unsafeRequest := httptest.NewRequest(http.MethodPost, d3Origin+"/api/v1/mcp", nil)
	unsafeRequest.AddCookie(cookie)
	unsafeRequest.Header.Set("Origin", d3Origin)
	unsafeRequest.Header.Set(httpauth.CSRFHeader, authentication.CSRFToken())
	if err := compositions[1].authenticator.VerifyCSRF(unsafeRequest, authentication); err != nil {
		t.Fatalf("d3 csrf proof rejected after restart: %v", err)
	}

	// The persisted session still authorizes a real workspace read.
	workspaces, err := workspacerepository.New(compositions[1].database, compositions[1].audit)
	if err != nil {
		t.Fatalf("d3 workspace repository: %v", err)
	}
	if _, err := workspaces.Get(ctx, authentication.Session().Access, d3WorkspaceID); err != nil {
		t.Fatalf("d3 persisted session cannot read its workspace: %v", err)
	}
}

// TestSessionLogoutAndExpiryHoldOnRestartedInstance proves the restart does not
// weaken termination: logout on the original composition revokes the row that
// the restarted composition reads, and an expired row is rejected by a fresh
// composition exactly as before.
func TestSessionLogoutAndExpiryHoldOnRestartedInstance(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	subjectDigest := d3SeedOrganization(t, ctx, admin)
	compositions := d3NewCompositions(t, ctx, subjectDigest, 4)

	t.Run("logout", func(t *testing.T) {
		cookie := d3SignIn(t, compositions[0])
		authentication, err := d3Authenticate(t, compositions[1], cookie, "req_d3_logout_auth")
		if err != nil {
			t.Fatalf("d3 resolve before logout: %v", err)
		}
		logoutRequest := httptest.NewRequest(http.MethodPost, d3Origin+"/auth/logout", nil)
		logoutRequest.AddCookie(cookie)
		logoutRequest.Header.Set("Origin", d3Origin)
		logoutRequest.Header.Set(httpauth.CSRFHeader, authentication.CSRFToken())
		logoutResponse := httptest.NewRecorder()
		compositions[1].handler.ServeHTTP(logoutResponse, logoutRequest)
		if logoutResponse.Code != http.StatusNoContent {
			t.Fatalf("d3 logout status=%d body=%q", logoutResponse.Code, logoutResponse.Body.String())
		}
		if _, err := d3Authenticate(t, compositions[2], cookie, "req_d3_after_logout"); err == nil {
			t.Fatal("d3 logged-out cookie authenticated on a later composition")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		token := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
		digest, err := compositions[0].security.SessionDigestor().Digest("session_token", token)
		if err != nil {
			t.Fatalf("d3 expiry digest: %v", err)
		}
		now := time.Now().UTC()
		d3SeedIdentitySession(t, ctx, admin, "login_d3_expired", "sess_d3_expired", digest.Value(),
			now.Add(-2*time.Hour), now.Add(-time.Hour))
		expiredCookie := &http.Cookie{Name: httpauth.SessionCookieName, Value: token, Path: "/"}
		if _, err := d3Authenticate(t, compositions[3], expiredCookie, "req_d3_expired"); err == nil {
			t.Fatal("d3 expired persisted session authenticated on a fresh composition")
		}
	})

	t.Run("logout everywhere", func(t *testing.T) {
		cookie := d3SignIn(t, compositions[0])
		before := d3NewComposition(t, ctx, subjectDigest)
		if _, err := d3Authenticate(t, before, cookie, "req_d3_before_revision"); err != nil {
			t.Fatalf("d3 resolve before principal revision bump: %v", err)
		}
		// One monotonic principal revision bump is the durable
		// "logout everywhere" primitive: the database revokes every active
		// session of the principal, and the restarted composition must deny
		// the old cookie because the row is gone from the live read path.
		if _, err := admin.Exec(ctx, `
			UPDATE public.principal SET session_revision = session_revision + 1
			WHERE organization_id = $1 AND id = $2
		`, d3OrganizationID, d3MemberID); err != nil {
			t.Fatalf("d3 bump principal session revision: %v", err)
		}
		after := d3NewComposition(t, ctx, subjectDigest)
		if _, err := d3Authenticate(t, after, cookie, "req_d3_after_revision"); err == nil {
			t.Fatal("d3 session authenticated after the principal revision bump")
		}
	})
}

// TestRevokedMembershipInvalidatesPersistedSession proves the persisted session
// is only as strong as the live authorization behind it: after the member is
// removed from the workspace, the very same restarted session can no longer
// read that workspace.
func TestRevokedMembershipInvalidatesPersistedSession(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	subjectDigest := d3SeedOrganization(t, ctx, admin)
	compositions := d3NewCompositions(t, ctx, subjectDigest, 1)

	cookie := d3SignIn(t, compositions[0])
	restarted := d3NewComposition(t, ctx, subjectDigest)
	authentication, err := d3Authenticate(t, restarted, cookie, "req_d3_member_before")
	if err != nil {
		t.Fatalf("d3 resolve before membership revocation: %v", err)
	}
	workspaces, err := workspacerepository.New(restarted.database, restarted.audit)
	if err != nil {
		t.Fatalf("d3 workspace repository: %v", err)
	}
	if _, err := workspaces.Get(ctx, authentication.Session().Access, d3WorkspaceID); err != nil {
		t.Fatalf("d3 member cannot read workspace before revocation: %v", err)
	}

	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member
		SET removed_at = transaction_timestamp(), valid_to_revision = 2
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3
	`, d3OrganizationID, d3WorkspaceID, d3MemberID); err != nil {
		t.Fatalf("d3 revoke workspace membership: %v", err)
	}

	if _, err := workspaces.Get(ctx, authentication.Session().Access, d3WorkspaceID); err == nil {
		t.Fatal("d3 revoked member still read the workspace through the persisted session")
	}
}

// TestPersistedSessionIsNeverReadableFromAnotherOrganization proves the RLS
// boundary at both the SQL and the repository path: a foreign organization
// context sees no session row, cannot target it, and cannot resolve the cookie
// digest through ResolveSession.
func TestPersistedSessionIsNeverReadableFromAnotherOrganization(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	subjectDigest := d3SeedOrganization(t, ctx, admin)
	compositions := d3NewCompositions(t, ctx, subjectDigest, 1)

	cookie := d3SignIn(t, compositions[0])
	digest, err := compositions[0].security.SessionDigestor().Digest("session_token", cookie.Value)
	if err != nil {
		t.Fatalf("d3 cookie digest: %v", err)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	foreign, err := app.Begin(ctx)
	if err != nil {
		t.Fatalf("d3 foreign transaction: %v", err)
	}
	setAccessContext(t, ctx, foreign, "org_d3_foreign")
	var visible int
	if err := foreign.QueryRow(ctx, "SELECT count(*) FROM public.identity_session").Scan(&visible); err != nil {
		t.Fatalf("d3 foreign count: %v", err)
	}
	if visible != 0 {
		t.Fatalf("d3 foreign organization saw %d session rows", visible)
	}
	var targeted string
	if err := foreign.QueryRow(ctx, `
		UPDATE public.identity_session SET revoked_at = transaction_timestamp(), revocation_code = 'D3_FOREIGN'
		WHERE organization_id = $1 RETURNING id
	`, d3OrganizationID).Scan(&targeted); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("d3 foreign organization could target the session: id=%q err=%v", targeted, err)
	}
	_ = foreign.Rollback(ctx)

	// The repository path must deny the foreign organization outright.
	if _, err := compositions[0].store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_d3_foreign", RequestID: "req_d3_foreign", SessionTokenDigest: digest,
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("d3 foreign ResolveSession err=%v code=%q, want CodeDenied", err, identityrepository.CodeOf(err))
	}
}

// d3SeedOrganization creates one organization, one workspace owned by
// d3OwnerID, one session principal (d3MemberID) with a live workspace
// membership and an ACTIVE external identity bound to the harness subject. It
// returns the subject digest the test identity provider must report.
func d3SeedOrganization(t *testing.T, ctx context.Context, admin *pgxpool.Pool) identity.KeyedDigest {
	t.Helper()
	seedOrganization(t, ctx, admin, d3OrganizationID, d3OwnerID, d3WorkspaceID)
	seedOIDCProvider(t, ctx, admin, d3OrganizationID, d3OwnerID, d3ProviderID, "https://identity.d3.example")

	subjectDigestor, err := oidc.NewHMACDigestor(d3IdentityKeyVersion, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("d3 subject digestor: %v", err)
	}
	defer subjectDigestor.Close()
	subjectDigest, err := subjectDigestor.Digest("subject", d3SubjectRaw)
	if err != nil {
		t.Fatalf("d3 subject digest: %v", err)
	}

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')
	`, d3MemberID, d3OrganizationID); err != nil {
		t.Fatalf("d3 seed member principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (
			id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
		) VALUES ($1, $2, $3, $4, 'MEMBER', 1, $5)
	`, "wsm_"+d3MemberID, d3OrganizationID, d3WorkspaceID, d3MemberID, d3OwnerID); err != nil {
		t.Fatalf("d3 seed member workspace membership: %v", err)
	}
	seedExternalIdentity(t, ctx, admin, d3OrganizationID, d3MemberID, d3ProviderID, "eid_d3_member", subjectDigest.Value())
	return subjectDigest
}

// d3SeedIdentitySession inserts one already-expired consumed login/session pair
// with a caller-provided keyed digest, so an expiry test never has to mutate a
// live row past the identity_session guard.
func d3SeedIdentitySession(t *testing.T, ctx context.Context, admin *pgxpool.Pool, loginAttemptID, sessionID, digest string, issuedAt, expiresAt time.Time) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("d3 seed session transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_login_attempt (
			id, organization_id, provider_id, provider_revision, state_digest,
			browser_binding_digest, nonce_digest, pkce_verifier_digest, expires_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, transaction_timestamp() + interval '5 minutes')
	`, loginAttemptID, d3OrganizationID, d3ProviderID,
		labelDigest(loginAttemptID+":state"), labelDigest(loginAttemptID+":binding"),
		labelDigest(loginAttemptID+":nonce"), labelDigest(loginAttemptID+":pkce")); err != nil {
		t.Fatalf("d3 seed login attempt: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt SET status = 'CLAIMED', claimed_at = transaction_timestamp() WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatalf("d3 claim login attempt: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.identity_session (
			id, organization_id, principal_id, provider_id, external_identity_id, login_attempt_id,
			session_token_digest, principal_session_revision, provider_revision, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, 'eid_d3_member', $5, $6, 1, 1, $7, $8)
	`, sessionID, d3OrganizationID, d3MemberID, d3ProviderID, loginAttemptID, digest, issuedAt.UTC(), expiresAt.UTC()); err != nil {
		t.Fatalf("d3 seed identity session: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt SET status = 'CONSUMED', completed_at = transaction_timestamp() WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatalf("d3 consume login attempt: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("d3 commit seeded session: %v", err)
	}
}
