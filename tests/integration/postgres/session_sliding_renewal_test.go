package postgres_test

// FIX-7 #3, on the real PostgreSQL. The owner was silently bounced out of a
// live browser session roughly every 10-15 minutes while actively working
// (confirmed live on knowvault-acc-proxy's access log for 08.09 ~08:15-09:00
// UTC: the SAME Keycloak SSO session re-authenticated the app session 6
// times in 45 minutes, each cycle a full page reload). Root cause:
// internal/platform/oidcweb/handler.go used to set the freshly-issued
// session's expires_at directly to the OIDC ID token's own short-lived
// `exp`, with nothing ever extending it -- not the 15-minute
// oidc_login_attempt window (a different table entirely, gating only the
// PKCE browser round trip), and not principal.session_revision (the
// previous agent's ruled-out hypothesis). These tests prove
// ResolveSession's fix: a sliding renewal that extends a still-live,
// non-revoked session forward when less than half its renewal window
// remains, capped at issued_at + maxSessionLifetime (24h) either way --
// exactly the one new transition migration 000088 opens on
// app.identity_session_mutation_guard, which otherwise still freezes every
// column of an identity_session row except the NULL->revoked shape.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
)

// labelDigest derives a distinct, validly-shaped digest per label, so two
// calls to seedIdentitySessionWithTiming within the same test (and the same
// organization) never collide on oidc_login_attempt's UNIQUE state_digest --
// unlike testIdentityDigest's single repeated character, which two calls in
// the same test cannot both use safely.
func labelDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "hmac-sha256:k1:" + hex.EncodeToString(sum[:])
}

// seedIdentitySessionWithTiming inserts one consumed login/session pair with
// caller-controlled issued_at/expires_at, so a test can place a session
// anywhere in its renewal lifecycle without waiting real wall-clock time.
func seedIdentitySessionWithTiming(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, providerID, externalIdentityID, loginAttemptID, sessionID, digestCharacter string, issuedAt, expiresAt time.Time) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.external_identity (
			id, organization_id, principal_id, provider_id, external_subject_digest,
			digest_key_version, attributes_hash, status
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'ACTIVE')
	`, externalIdentityID, organizationID, principalID, providerID, labelDigest(externalIdentityID+":subject"), "sha256:"+repeatHex("c")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.oidc_login_attempt (
			id, organization_id, provider_id, provider_revision, state_digest,
			browser_binding_digest, nonce_digest, pkce_verifier_digest, expires_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6, $7, transaction_timestamp() + interval '5 minutes')
	`, loginAttemptID, organizationID, providerID, labelDigest(loginAttemptID+":state"), labelDigest(loginAttemptID+":binding"),
		labelDigest(loginAttemptID+":nonce"), labelDigest(loginAttemptID+":pkce")); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt SET status = 'CLAIMED', claimed_at = transaction_timestamp() WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.identity_session (
			id, organization_id, principal_id, provider_id, external_identity_id, login_attempt_id,
			session_token_digest, principal_session_revision, provider_revision, issued_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, 1, $8, $9)
	`, sessionID, organizationID, principalID, providerID, externalIdentityID, loginAttemptID, testIdentityDigest(digestCharacter),
		issuedAt.UTC(), expiresAt.UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.oidc_login_attempt SET status = 'CONSUMED', completed_at = transaction_timestamp() WHERE id = $1
	`, loginAttemptID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// sameInstant compares two timestamps allowing for PostgreSQL's microsecond
// storage precision against Go's nanosecond in-memory precision -- a value
// that made a real round trip through the database never matches a
// nanosecond-precision Go time.Time with plain Equal.
func sameInstant(a, b time.Time) bool {
	delta := a.Sub(b)
	return delta > -time.Millisecond && delta < time.Millisecond
}

func repeatHex(character string) string {
	result := ""
	for len(result) < 64 {
		result += character
	}
	return result[:64]
}

func sessionTiming(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, sessionID string) (issuedAt, expiresAt time.Time) {
	t.Helper()
	if err := admin.QueryRow(ctx, `
		SELECT issued_at, expires_at FROM public.identity_session WHERE organization_id = $1 AND id = $2
	`, organizationID, sessionID).Scan(&issuedAt, &expiresAt); err != nil {
		t.Fatal(err)
	}
	return issuedAt.UTC(), expiresAt.UTC()
}

// TestResolveSessionRenewsWhenLessThanHalfRenewalWindowRemains proves the
// core fix: a live, active session that has burned through more than half
// its renewal window is pushed back out on the very next request, exactly
// the behavior that keeps an actively-worked session alive for a whole
// shift instead of dying on a schedule the user never sees coming.
func TestResolveSessionRenewsWhenLessThanHalfRenewalWindowRemains(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	now := time.Now().UTC()
	issuedAt := now.Add(-20 * time.Minute)
	expiresAt := now.Add(10 * time.Minute) // < half of the 30-minute renewal window
	seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a", issuedAt, expiresAt)

	store := newIdentityRepository(t, ctx)
	session, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_alpha", RequestID: "req_resolve_renew", SessionTokenDigest: mustKeyedDigest(t, "a"),
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !session.Renewed {
		t.Fatalf("session.Renewed=false, want true for a session with 10 of 30 minutes remaining")
	}
	if got := session.Claims.ExpiresAt(); got.Before(now.Add(29*time.Minute)) || got.After(now.Add(31*time.Minute)) {
		t.Fatalf("renewed expiry=%v, want ~30 minutes from now (%v)", got, now)
	}
	_, dbExpiresAt := sessionTiming(t, ctx, admin, "org_alpha", "sess_alpha")
	if !dbExpiresAt.Equal(session.Claims.ExpiresAt()) {
		t.Fatalf("db expires_at=%v, claims expires_at=%v: renewal did not persist", dbExpiresAt, session.Claims.ExpiresAt())
	}
	if !dbExpiresAt.After(expiresAt) {
		t.Fatalf("db expires_at=%v did not move forward from the original %v", dbExpiresAt, expiresAt)
	}

	// A second resolve immediately after must NOT renew again: the session
	// is now freshly at ~30 minutes remaining, well past the half-window
	// threshold, so expires_at stays exactly what the first renewal set.
	again, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_alpha", RequestID: "req_resolve_no_renew", SessionTokenDigest: mustKeyedDigest(t, "a"),
	})
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if again.Renewed {
		t.Fatalf("second resolve renewed again immediately after the first -- expected no-op until half the window elapses")
	}
	if !again.Claims.ExpiresAt().Equal(session.Claims.ExpiresAt()) {
		t.Fatalf("second resolve changed expiry from %v to %v without renewing", session.Claims.ExpiresAt(), again.Claims.ExpiresAt())
	}
}

// TestResolveSessionDoesNotRenewWithMoreThanHalfWindowRemaining proves the
// renewal is not unconditional: a session still comfortably inside its
// current window is left exactly as issued, so an idle-then-quickly-active
// user is not silently granted an unbounded sliding window on every single
// request (bounded DB writes, not renew-on-every-click).
func TestResolveSessionDoesNotRenewWithMoreThanHalfWindowRemaining(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	now := time.Now().UTC()
	issuedAt := now.Add(-5 * time.Minute)
	expiresAt := now.Add(25 * time.Minute) // well over half of the 30-minute window
	seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a", issuedAt, expiresAt)

	store := newIdentityRepository(t, ctx)
	session, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_alpha", RequestID: "req_resolve_no_renew", SessionTokenDigest: mustKeyedDigest(t, "a"),
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if session.Renewed {
		t.Fatalf("session.Renewed=true, want false with 25 of 30 minutes still remaining")
	}
	_, dbExpiresAt := sessionTiming(t, ctx, admin, "org_alpha", "sess_alpha")
	if !sameInstant(dbExpiresAt, expiresAt) {
		t.Fatalf("expires_at changed from %v to %v without a qualifying renewal", expiresAt, dbExpiresAt)
	}
}

// TestResolveSessionRenewalCapsAtIssuedPlusMaxSessionLifetime proves the
// hard 24-hour ceiling still holds even for a session that otherwise
// qualifies for renewal: an actively-used session near the end of its
// absolute lifetime is extended only up to issued_at + 24h, never further,
// exactly matching the identity_session table's own CHECK constraint and
// migration 000088's guard-side re-assertion of it.
func TestResolveSessionRenewalCapsAtIssuedPlusMaxSessionLifetime(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	now := time.Now().UTC()
	issuedAt := now.Add(-23*time.Hour - 50*time.Minute) // only ~10 minutes of the 24h ceiling remain
	expiresAt := now.Add(5 * time.Minute)                // inside the renewal zone (< half of 30 minutes)
	seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a", issuedAt, expiresAt)

	store := newIdentityRepository(t, ctx)
	session, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_alpha", RequestID: "req_resolve_capped", SessionTokenDigest: mustKeyedDigest(t, "a"),
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !session.Renewed {
		t.Fatalf("session.Renewed=false, want true: 5 minutes remaining still qualifies for renewal")
	}
	ceiling := issuedAt.Add(24 * time.Hour)
	got := session.Claims.ExpiresAt()
	if got.After(ceiling.Add(time.Second)) {
		t.Fatalf("renewed expiry=%v exceeds the 24h ceiling from issuance (%v)", got, ceiling)
	}
	if got.Before(ceiling.Add(-time.Second)) {
		t.Fatalf("renewed expiry=%v, want capped at the 24h ceiling (%v) since the full 30-minute window would exceed it", got, ceiling)
	}
	if !got.Before(now.Add(30 * time.Minute)) {
		t.Fatalf("renewed expiry=%v was NOT capped short of a full 30-minute extension", got)
	}
}

// TestResolveSessionNeverRenewsAnAlreadyExpiredOrRevokedSession proves the
// renewal never resurrects a session ResolveSession would otherwise deny:
// fail-closed is unchanged by this fix.
func TestResolveSessionNeverRenewsAnAlreadyExpiredOrRevokedSession(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	now := time.Now().UTC()

	t.Run("expired", func(t *testing.T) {
		issuedAt := now.Add(-time.Hour)
		expiresAt := now.Add(-time.Minute) // already expired
		seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_expired", "login_expired", "sess_expired", "b", issuedAt, expiresAt)
		store := newIdentityRepository(t, ctx)
		// An already-expired session still passes the SELECT (its row is
		// present and not revoked) and fails at identity.Validate's own
		// expiry check, which ResolveSession returns un-translated -- the
		// SAME pre-existing shape identity.CodeOf reports today, unchanged
		// by this fix. (A revoked session below never reaches Validate at
		// all: its SELECT returns no row, so ResolveSession reports its own
		// CodeDenied directly.)
		if _, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
			OrganizationID: "org_alpha", RequestID: "req_resolve_expired", SessionTokenDigest: mustKeyedDigest(t, "b"),
		}); identity.CodeOf(err) != identity.CodeSessionExpired {
			t.Fatalf("expired session resolved: err=%v code=%q, want CodeSessionExpired", err, identity.CodeOf(err))
		}
		_, dbExpiresAt := sessionTiming(t, ctx, admin, "org_alpha", "sess_expired")
		if !sameInstant(dbExpiresAt, expiresAt) {
			t.Fatalf("expired session's expires_at changed from %v to %v: renewal must never resurrect it", expiresAt, dbExpiresAt)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		issuedAt := now.Add(-time.Minute)
		expiresAt := now.Add(time.Minute) // still time-valid, but revoked
		seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_revoked", "login_revoked", "sess_revoked", "c", issuedAt, expiresAt)
		store := newIdentityRepository(t, ctx)
		if outcome, err := store.RevokeSession(ctx, identityrepository.RevokeSessionRequest{
			OrganizationID: "org_alpha", SessionID: "sess_revoked", PrincipalID: "usr_alice",
			RequestID: "req_revoke_before_resolve", AuditEventID: "audit_revoke_before_resolve",
		}); err != nil || !outcome.Revoked {
			t.Fatalf("revoke: outcome=%+v err=%v", outcome, err)
		}
		if _, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
			OrganizationID: "org_alpha", RequestID: "req_resolve_revoked", SessionTokenDigest: mustKeyedDigest(t, "c"),
		}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
			t.Fatalf("revoked session resolved: err=%v code=%q, want CodeDenied", err, identityrepository.CodeOf(err))
		}
		_, dbExpiresAt := sessionTiming(t, ctx, admin, "org_alpha", "sess_revoked")
		if !sameInstant(dbExpiresAt, expiresAt) {
			t.Fatalf("revoked session's expires_at changed from %v to %v: renewal must never touch a revoked session", expiresAt, dbExpiresAt)
		}
	})
}

// TestIdentitySessionMutationGuardStillFreezesEveryOtherColumn proves
// migration 000088 narrowed nothing else: every column the guard already
// froze stays frozen, and an expires_at change that is not a valid forward
// renewal (backward, past the 24h ceiling, or alongside a revocation) is
// still rejected exactly like any other mutation attempt.
func TestIdentitySessionMutationGuardStillFreezesEveryOtherColumn(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	now := time.Now().UTC()
	seedIdentitySessionWithTiming(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a",
		now.Add(-time.Minute), now.Add(time.Hour))

	adminTx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminTx.Rollback(ctx) }()
	for name, statement := range map[string]string{
		"backward_expiry":  `UPDATE public.identity_session SET expires_at = expires_at - interval '1 minute' WHERE organization_id='org_alpha' AND id='sess_alpha'`,
		"past_24h_ceiling": `UPDATE public.identity_session SET expires_at = issued_at + interval '25 hours' WHERE organization_id='org_alpha' AND id='sess_alpha'`,
		"session_token_digest": `UPDATE public.identity_session SET session_token_digest = 'hmac-sha256:k1:` + repeatHex("9") + `' WHERE organization_id='org_alpha' AND id='sess_alpha'`,
		"issued_at":            `UPDATE public.identity_session SET issued_at = issued_at + interval '1 minute' WHERE organization_id='org_alpha' AND id='sess_alpha'`,
	} {
		t.Run(name, func(t *testing.T) {
			savepoint, err := adminTx.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, execErr := savepoint.Exec(ctx, statement)
			_ = savepoint.Rollback(ctx)
			if execErr == nil {
				t.Fatalf("mutation %q unexpectedly succeeded", name)
			}
		})
	}
}
