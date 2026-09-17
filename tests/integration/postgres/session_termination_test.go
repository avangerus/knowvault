package postgres_test

// ADR-0075 repository layer on the real PostgreSQL: RevokeSession performs the
// one-shot NULL→revoked transition of the exact session together with its
// SUCCESS audit event, a revoked session fails the read path, the repeated
// logout is an idempotent no-op without a duplicated event, a principal
// mismatch rolls back, and RecordSessionTerminationFailure writes the single
// closed FAILED event in both the unknown-session and authenticated branches.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
)

type sessionTerminationEvent struct {
	actorType        string
	actorPrincipalID string
	action           string
	resourceType     string
	resourceID       string
	requestID        string
	outcome          string
	errorCode        string
}

func sessionTerminationEvents(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org string) []sessionTerminationEvent {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT actor_type, COALESCE(actor_principal_id, ''), action, resource_type,
			resource_id, request_id, outcome, COALESCE(error_code, '')
		FROM public.audit_event WHERE organization_id = $1 AND action = 'session.terminated' ORDER BY sequence`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []sessionTerminationEvent
	for rows.Next() {
		var event sessionTerminationEvent
		if err := rows.Scan(&event.actorType, &event.actorPrincipalID, &event.action, &event.resourceType,
			&event.resourceID, &event.requestID, &event.outcome, &event.errorCode); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

func sessionRevocation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, sessionID string) (revokedAt *time.Time, revocationCode string) {
	t.Helper()
	if err := admin.QueryRow(ctx, `SELECT revoked_at, COALESCE(revocation_code, '')
		FROM public.identity_session WHERE organization_id = $1 AND id = $2`,
		org, sessionID).Scan(&revokedAt, &revocationCode); err != nil {
		t.Fatal(err)
	}
	return revokedAt, revocationCode
}

// TestRevokeSessionRevokesExactSessionWithSingleAuditEvent proves the success
// path: the exact session transitions into the revoked shape with the closed
// revocation code, exactly one SUCCESS session.terminated event commits in the
// same transaction, and the revoked token fails the read path.
func TestRevokeSessionRevokesExactSessionWithSingleAuditEvent(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	createConsumedIdentitySession(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a")

	store := newIdentityRepository(t, ctx)
	outcome, err := store.RevokeSession(ctx, identityrepository.RevokeSessionRequest{
		OrganizationID: "org_alpha", SessionID: "sess_alpha", PrincipalID: "usr_alice",
		RequestID: "req_logout_001", AuditEventID: "audit_001",
	})
	if err != nil || !outcome.Revoked {
		t.Fatalf("revoke: outcome=%+v err=%v", outcome, err)
	}

	revokedAt, code := sessionRevocation(t, ctx, admin, "org_alpha", "sess_alpha")
	if revokedAt == nil || code != identityrepository.SessionTerminationRevocationCode {
		t.Fatalf("session revocation: revoked_at=%v code=%q", revokedAt, code)
	}

	events := sessionTerminationEvents(t, ctx, admin, "org_alpha")
	if len(events) != 1 {
		t.Fatalf("termination events=%d want 1: %+v", len(events), events)
	}
	if events[0] != (sessionTerminationEvent{
		actorType: "HUMAN", actorPrincipalID: "usr_alice", action: "session.terminated",
		resourceType: "IDENTITY", resourceID: "sess_alpha", requestID: "req_logout_001",
		outcome: "SUCCESS", errorCode: "",
	}) {
		t.Fatalf("termination event=%+v", events[0])
	}

	// The revoked token no longer authenticates: the read path filters on
	// revoked_at IS NULL.
	if _, err := store.ResolveSession(ctx, identityrepository.ResolveSessionRequest{
		OrganizationID: "org_alpha", RequestID: "req_resolve_001", SessionTokenDigest: mustKeyedDigest(t, "a"),
	}); identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("revoked session resolved: err=%v code=%q, want CodeDenied", err, identityrepository.CodeOf(err))
	}
}

// TestRevokeSessionIsIdempotentWithoutEventDuplication proves ADR-0075 §6: the
// repeated logout reports the already-revoked outcome, the state does not
// change and the success event is not duplicated.
func TestRevokeSessionIsIdempotentWithoutEventDuplication(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	createConsumedIdentitySession(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a")

	store := newIdentityRepository(t, ctx)
	request := identityrepository.RevokeSessionRequest{
		OrganizationID: "org_alpha", SessionID: "sess_alpha", PrincipalID: "usr_alice",
		RequestID: "req_logout_001", AuditEventID: "audit_001",
	}
	if outcome, err := store.RevokeSession(ctx, request); err != nil || !outcome.Revoked {
		t.Fatalf("first revoke: outcome=%+v err=%v", outcome, err)
	}

	request.RequestID = "req_logout_002"
	request.AuditEventID = "audit_002"
	outcome, err := store.RevokeSession(ctx, request)
	if err != nil || outcome.Revoked {
		t.Fatalf("second revoke: outcome=%+v err=%v, want Revoked=false", outcome, err)
	}
	if events := sessionTerminationEvents(t, ctx, admin, "org_alpha"); len(events) != 1 {
		t.Fatalf("repeated logout duplicated events: %+v", events)
	}
}

// TestRevokeSessionRefusesPrincipalMismatch proves the defensive rollback: a
// call that names a different principal than the session's owner is denied,
// leaves the session active and writes no event.
func TestRevokeSessionRefusesPrincipalMismatch(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOIDCProvider(t, ctx, admin, "org_alpha", "usr_alice", "idp_alpha", "https://id.alpha.example")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_other', 'org_alpha', 'USER', 'usr_other', 'ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	createConsumedIdentitySession(t, ctx, app, "org_alpha", "usr_alice", "idp_alpha", "eid_alpha", "login_alpha", "sess_alpha", "a")

	store := newIdentityRepository(t, ctx)
	outcome, err := store.RevokeSession(ctx, identityrepository.RevokeSessionRequest{
		OrganizationID: "org_alpha", SessionID: "sess_alpha", PrincipalID: "usr_other",
		RequestID: "req_logout_001", AuditEventID: "audit_001",
	})
	if identityrepository.CodeOf(err) != identityrepository.CodeDenied {
		t.Fatalf("principal mismatch: outcome=%+v err=%v code=%q, want CodeDenied", outcome, err, identityrepository.CodeOf(err))
	}
	if revokedAt, _ := sessionRevocation(t, ctx, admin, "org_alpha", "sess_alpha"); revokedAt != nil {
		t.Fatalf("principal mismatch still revoked the session: %v", revokedAt)
	}
	if events := sessionTerminationEvents(t, ctx, admin, "org_alpha"); len(events) != 0 {
		t.Fatalf("principal mismatch wrote events: %+v", events)
	}
}

// TestRecordSessionTerminationFailureBothBranches proves the closed failure
// record: an unresolved session yields a SYSTEM event on the request id and an
// authenticated failure yields a HUMAN event on the session id, both with the
// shared error code (no validity oracle).
func TestRecordSessionTerminationFailureBothBranches(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	store := newIdentityRepository(t, ctx)

	if err := store.RecordSessionTerminationFailure(ctx, identityrepository.RecordSessionTerminationFailureRequest{
		OrganizationID: "org_alpha", RequestID: "req_logout_001", AuditEventID: "audit_001",
	}); err != nil {
		t.Fatalf("record unknown-session failure: %v", err)
	}
	principal := identity.PrincipalID("usr_alice")
	sessionID := "sess_alpha"
	if err := store.RecordSessionTerminationFailure(ctx, identityrepository.RecordSessionTerminationFailureRequest{
		OrganizationID: "org_alpha", SessionID: &sessionID, PrincipalID: &principal,
		RequestID: "req_logout_002", AuditEventID: "audit_002",
	}); err != nil {
		t.Fatalf("record authenticated failure: %v", err)
	}

	events := sessionTerminationEvents(t, ctx, admin, "org_alpha")
	if len(events) != 2 {
		t.Fatalf("termination failure events=%d want 2: %+v", len(events), events)
	}
	if events[0] != (sessionTerminationEvent{
		actorType: "SYSTEM", actorPrincipalID: "", action: "session.terminated",
		resourceType: "IDENTITY", resourceID: "req_logout_001", requestID: "req_logout_001",
		outcome: "FAILED", errorCode: "SESSION_TERMINATION_FAILED",
	}) {
		t.Fatalf("unknown-session failure event=%+v", events[0])
	}
	if events[1] != (sessionTerminationEvent{
		actorType: "HUMAN", actorPrincipalID: "usr_alice", action: "session.terminated",
		resourceType: "IDENTITY", resourceID: "sess_alpha", requestID: "req_logout_002",
		outcome: "FAILED", errorCode: "SESSION_TERMINATION_FAILED",
	}) {
		t.Fatalf("authenticated failure event=%+v", events[1])
	}
}

func newIdentityRepository(t *testing.T, ctx context.Context) *identityrepository.Store {
	t.Helper()
	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	identityStore, err := identityrepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create identity repository: %v", err)
	}
	return identityStore
}
