package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	discoveryAlphaOrg   = "org_sdr_alpha"
	discoveryAlphaOwner = "usr_sdr_alpha_owner"
	discoveryBetaOrg    = "org_sdr_beta"
	discoveryBetaOwner  = "usr_sdr_beta_owner"
	discoveryMember     = "usr_sdr_member"
)

type sourceDiscoveryConnectionFixture struct {
	organizationID string
	ownerID        string
	connectionID   string
	trustHash      string
	connectionRev  int64
}

type sourceDiscoveryRequestInput struct {
	requestID            string
	connectionID         string
	connectionRevision   int64
	trustProfileHash     string
	maxViews             int
	maxColumns           int
	maxCommentBytes      int
	statementTimeoutMS   int
	transactionTimeoutMS int
	idempotencyKeyHash   string
}

func TestSourceDiscoveryStorageAuthorityAndLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	ensureSourceDiscoveryMigration(t, ctx, admin)
	seedOrganization(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "ws_sdr_alpha")
	seedOrganization(t, ctx, admin, discoveryBetaOrg, discoveryBetaOwner, "ws_sdr_beta")
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, discoveryMember, discoveryAlphaOrg); err != nil {
		t.Fatalf("seed non-owner principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
			(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_sdr_member', $1, $2, 'MEMBER', 1, $3)`,
		discoveryAlphaOrg, discoveryMember, discoveryAlphaOwner); err != nil {
		t.Fatalf("seed non-owner role: %v", err)
	}
	alpha := seedSourceDiscoveryConnection(t, ctx, admin, discoveryAlphaOrg, discoveryAlphaOwner, "alpha")
	beta := seedSourceDiscoveryConnection(t, ctx, admin, discoveryBetaOrg, discoveryBetaOwner, "beta")
	assertSourceDiscoveryStoragePrivileges(t, ctx, admin)

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))
	assertSourceDiscoveryDirectInsertDenied(t, ctx, app, worker)
	assertSourceDiscoveryJobPayloadCheck(t, ctx, app)

	request := sourceDiscoveryRequestInput{
		requestID:            "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		connectionID:         alpha.connectionID,
		connectionRevision:   alpha.connectionRev,
		trustProfileHash:     alpha.trustHash,
		maxViews:             16,
		maxColumns:           32,
		maxCommentBytes:      4096,
		statementTimeoutMS:   5000,
		transactionTimeoutMS: 10000,
		idempotencyKeyHash:   "sha256:" + strings.Repeat("1", 64),
	}
	assertSourceDiscoveryNonOwnerDenied(t, ctx, app, request)
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, request); err != nil {
		t.Fatalf("owner enqueue: %v", err)
	}
	replayID, replayJobID, replayCreated, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, request)
	if err != nil {
		t.Fatalf("owner enqueue replay: %v", err)
	}
	if replayID != request.requestID || replayJobID != request.requestID || replayCreated {
		t.Fatalf("enqueue replay = (%q, %q, %v), want exact request/job and created=false", replayID, replayJobID, replayCreated)
	}
	conflicting := request
	conflicting.maxViews++
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, conflicting); err == nil {
		t.Fatal("enqueue replay with a different immutable tuple succeeded")
	}

	// Tenant and actor context are authoritative. A beta owner cannot use an
	// alpha connection, and a status poll across tenants returns no row.
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryBetaOrg, discoveryBetaOwner, request); err == nil {
		t.Fatal("cross-tenant source discovery enqueue succeeded")
	}
	if _, err := sourceDiscoveryStatus(t, ctx, app, discoveryBetaOrg, discoveryBetaOwner, request.requestID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant status error = %v, want pgx.ErrNoRows", err)
	}
	if got := sourceDiscoveryRequestCount(t, ctx, admin, discoveryBetaOrg, request.requestID); got != 0 {
		t.Fatalf("beta saw alpha request through admin-scoped check: %d", got)
	}

	issuedAt, expiresAt := sourceDiscoveryRequestTimes(t, ctx, admin, request.requestID, discoveryAlphaOrg)
	if got := expiresAt.Sub(issuedAt); got != 15*time.Minute {
		t.Fatalf("request expiry duration = %s, want 15m", got)
	}
	var securityEpoch int64
	if err := admin.QueryRow(ctx, `
		SELECT security_epoch FROM public.source_discovery_request
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, request.requestID).Scan(&securityEpoch); err != nil {
		t.Fatal(err)
	}
	if securityEpoch < 1 {
		t.Fatalf("security_epoch = %d, want >= 1", securityEpoch)
	}

	jobID, leaseEpoch := claimSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, request.requestID)
	assertSourceDiscoverySecurityEpochFencing(t, ctx, admin, app, worker, request, jobID, leaseEpoch)
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, request.requestID, jobID, leaseEpoch); err != nil {
		t.Fatalf("start source discovery after security epoch restoration: %v", err)
	}
	resultID := "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAW"
	databaseIdentityHash := "sha256:" + strings.Repeat("2", 64)
	privilegeDigest := "sha256:" + strings.Repeat("3", 64)
	metadataHash := "sha256:" + strings.Repeat("4", 64)
	resultHash := "sha256:" + strings.Repeat("5", 64)
	artifactID := "artifact_sdr_metadata"
	assertSourceDiscoveryDigestRecheck(t, ctx, admin, worker, discoveryAlphaOrg, discoveryAlphaOwner,
		request, jobID, leaseEpoch)
	completeSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner,
		request, jobID, leaseEpoch, resultID, databaseIdentityHash, privilegeDigest, metadataHash, resultHash, artifactID)

	var requestStatus, resultStatus, storedResultHash string
	var storedResultID string
	if err := admin.QueryRow(ctx, `
		SELECT request.status, request.result_id, request.result_hash, result.status
		FROM public.source_discovery_request AS request
		JOIN public.source_discovery_result AS result
		  ON result.organization_id = request.organization_id AND result.id = request.result_id
		WHERE request.organization_id = $1 AND request.id = $2`, discoveryAlphaOrg, request.requestID).
		Scan(&requestStatus, &storedResultID, &storedResultHash, &resultStatus); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "SUCCEEDED" || resultStatus != "NEEDS_INTERPRETATION" || storedResultID != resultID || storedResultHash != resultHash {
		t.Fatalf("terminal request/result = (%s, %s, %s, %s), want SUCCEEDED/NEEDS_INTERPRETATION/%s/%s", requestStatus, resultStatus, storedResultID, storedResultHash, resultID, resultHash)
	}
	var storedActor, storedConnection, storedTrust, storedDatabase, storedPrivilege string
	var storedRevision, storedEpoch int64
	if err := admin.QueryRow(ctx, `
		SELECT actor_principal_id, connection_id, connection_revision,
		       trust_profile_hash, security_epoch, database_identity_hash, privilege_digest
		FROM public.source_discovery_result
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, resultID).
		Scan(&storedActor, &storedConnection, &storedRevision, &storedTrust, &storedEpoch, &storedDatabase, &storedPrivilege); err != nil {
		t.Fatal(err)
	}
	if storedActor != discoveryAlphaOwner || storedConnection != alpha.connectionID || storedRevision != alpha.connectionRev || storedTrust != alpha.trustHash || storedEpoch != securityEpoch || storedDatabase != databaseIdentityHash || storedPrivilege != privilegeDigest {
		t.Fatalf("result control tuple was not copied exactly: actor=%q connection=%q revision=%d trust=%q epoch=%d database=%q privilege=%q", storedActor, storedConnection, storedRevision, storedTrust, storedEpoch, storedDatabase, storedPrivilege)
	}
	var resultCreatedAt, resultExpiresAt time.Time
	if err := admin.QueryRow(ctx, `
		SELECT created_at, expires_at FROM public.source_discovery_result
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, resultID).Scan(&resultCreatedAt, &resultExpiresAt); err != nil {
		t.Fatal(err)
	}
	if got := resultExpiresAt.Sub(resultCreatedAt); got != 15*time.Minute {
		t.Fatalf("result expiry duration = %s, want 15m", got)
	}
	status := sourceDiscoveryStatusValue(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, request.requestID)
	if status.requestStatus != "SUCCEEDED" || status.resultStatus != "NEEDS_INTERPRETATION" || status.viewCount != 1 || status.preparedViewCount != 0 || status.needsViewCount != 1 {
		t.Fatalf("sanitized owner status = %#v", status)
	}
	assertSourceDiscoveryMetadataRead(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, resultID, artifactID, metadataHash)

	// A terminal request/result cannot be replayed or rewritten, even by the
	// privileged migration role through the trigger path.
	if err := replaySourceDiscoveryCompletion(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, request, jobID, leaseEpoch, resultID, databaseIdentityHash, privilegeDigest, resultHash); err == nil {
		t.Fatal("terminal source discovery completion replay succeeded")
	}
	if _, err := admin.Exec(ctx, `
		UPDATE public.source_discovery_request SET max_views = max_views + 1
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, request.requestID); err == nil {
		t.Fatal("terminal source discovery request was mutable")
	}
	if _, err := admin.Exec(ctx, `
		UPDATE public.source_discovery_result SET view_count = view_count + 1
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, resultID); err == nil {
		t.Fatal("terminal source discovery result was mutable")
	}

	assertSourceDiscoveryExpiryLifecycle(t, ctx, admin, app, worker, request)

	// A wrong fencing epoch is rejected while the job is live. After the lease
	// deadline is made stale, the same exact request is rejected again.
	staleRequest := request
	staleRequest.requestID = "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAX"
	staleRequest.idempotencyKeyHash = "sha256:" + strings.Repeat("6", 64)
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, staleRequest); err != nil {
		t.Fatalf("stale-lease fixture enqueue: %v", err)
	}
	staleJobID, staleEpoch := claimSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, staleRequest.requestID)
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, staleRequest.requestID, staleJobID, staleEpoch+1); err == nil {
		t.Fatal("stale fencing epoch was accepted")
	}
	if _, err := admin.Exec(ctx, `
		UPDATE public.job SET lease_deadline = transaction_timestamp() - interval '1 second'
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, staleJobID); err != nil {
		t.Fatalf("expire source discovery lease fixture: %v", err)
	}
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, staleRequest.requestID, staleJobID, staleEpoch); err == nil {
		t.Fatal("lost source discovery lease was accepted")
	}

	// Result binding compares the worker-supplied plaintext digest with the
	// immutable result digest; a mismatched artifact cannot be persisted.
	invalidRequest := request
	invalidRequest.requestID = "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAY"
	invalidRequest.idempotencyKeyHash = "sha256:" + strings.Repeat("7", 64)
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, invalidRequest); err != nil {
		t.Fatalf("invalid-artifact fixture enqueue: %v", err)
	}
	invalidJobID, invalidEpoch := claimAndStartSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, invalidRequest.requestID)
	invalidResultID := "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	invalidMetadataHash := "sha256:" + strings.Repeat("8", 64)
	invalidResultHash := "sha256:" + strings.Repeat("9", 64)
	invalidTx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, invalidTx, discoveryAlphaOrg, discoveryAlphaOwner)
	if _, err := invalidTx.Exec(ctx, `
		SELECT app.source_discovery_result_begin($1, $2, $3, $4, $5, 'SUCCEEDED', 1, 1, 0, $6, $7, $8, $9)`,
		invalidRequest.requestID, invalidResultID, invalidJobID, "worker_sdr_5FAY", invalidEpoch,
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), invalidMetadataHash, invalidResultHash); err != nil {
		_ = invalidTx.Rollback(ctx)
		t.Fatalf("begin invalid-artifact result: %v", err)
	}
	if _, err := invalidTx.Exec(ctx, `
		SELECT app.source_discovery_result_bind_metadata(
			$1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, 1, $12, $13)`,
		invalidRequest.requestID, invalidResultID, invalidJobID, "worker_sdr_5FAY", invalidEpoch,
		"artifact_sdr_invalid", []byte(strings.Repeat("n", 12)), []byte(strings.Repeat("c", 17)), []byte("wrapped"),
		"sha256:"+strings.Repeat("c", 64), "kms://sdr", "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)); err == nil {
		_ = invalidTx.Rollback(ctx)
		t.Fatal("mismatched result artifact plaintext hash was accepted")
	}
	_ = invalidTx.Rollback(ctx)
	if err := failSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, invalidRequest.requestID, invalidJobID, invalidEpoch); err != nil {
		t.Fatalf("cleanup failed source discovery request: %v", err)
	}

	assertSourceDiscoveryTrustInvalidation(t, ctx, admin, app, worker, beta)

	_ = beta // Keep the beta source fixture live for the cross-tenant checks above.
}

func assertSourceDiscoverySecurityEpochFencing(t *testing.T, ctx context.Context, admin, app, worker *pgxpool.Pool, request sourceDiscoveryRequestInput, jobID string, leaseEpoch int64) {
	t.Helper()
	const replacementPrincipalID = "usr_sdr_alpha_epoch2"
	const replacementAssignmentID = "ora_sdr_alpha_epoch2"

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var originalAssignmentID string
	if err := tx.QueryRow(ctx, `
		SELECT id
		FROM public.organization_role_assignment
		WHERE organization_id = $1 AND principal_id = $2
		  AND role = 'OWNER' AND revoked_at IS NULL`, discoveryAlphaOrg, discoveryAlphaOwner).Scan(&originalAssignmentID); err != nil {
		t.Fatalf("read original owner assignment: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, replacementPrincipalID, discoveryAlphaOrg); err != nil {
		t.Fatalf("seed replacement owner principal: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.organization
		SET owner_principal_id = $2, role_revision = 2
		WHERE id = $1`, discoveryAlphaOrg, replacementPrincipalID); err != nil {
		t.Fatalf("bump organization owner epoch: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.organization_role_assignment
		SET valid_to_revision = 2, revoked_at = transaction_timestamp(), revoked_by = $2
		WHERE id = $1`, originalAssignmentID, discoveryAlphaOwner); err != nil {
		t.Fatalf("revoke original owner window: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
			(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ($1, $2, $3, 'OWNER', 2, $4)`, replacementAssignmentID, discoveryAlphaOrg, replacementPrincipalID, discoveryAlphaOwner); err != nil {
		t.Fatalf("seed replacement owner assignment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit owner epoch fixture: %v", err)
	}

	restored := false
	defer func() {
		if !restored {
			if err := restoreSourceDiscoveryOwnerEpoch(t, ctx, admin, originalAssignmentID, replacementPrincipalID, replacementAssignmentID); err != nil {
				t.Errorf("restore owner epoch fixture after failure: %v", err)
			}
		}
	}()

	var requestEpoch, organizationEpoch int64
	if err := admin.QueryRow(ctx, `
		SELECT request.security_epoch, organization.role_revision
		FROM public.source_discovery_request AS request
		JOIN public.organization AS organization ON organization.id = request.organization_id
		WHERE request.organization_id = $1 AND request.id = $2`, discoveryAlphaOrg, request.requestID).
		Scan(&requestEpoch, &organizationEpoch); err != nil {
		t.Fatal(err)
	}
	if requestEpoch != 1 || organizationEpoch != 2 {
		t.Fatalf("security epoch fixture = request:%d organization:%d, want request:1 organization:2", requestEpoch, organizationEpoch)
	}
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, request.requestID, jobID, leaseEpoch); err == nil {
		t.Fatal("worker started a request after its owner security epoch was revoked")
	}
	statusTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, statusTx, discoveryAlphaOrg, discoveryAlphaOwner)
	var statusCount int
	statusErr := statusTx.QueryRow(ctx, `
		SELECT count(*) FROM app.source_discovery_request_status($1)`, request.requestID).Scan(&statusCount)
	_ = statusTx.Rollback(ctx)
	if statusErr == nil {
		t.Fatalf("revoked owner status returned %d row(s)", statusCount)
	}
	var requestStatus, jobStatus string
	if err := admin.QueryRow(ctx, `
		SELECT request.status, job.status
		FROM public.source_discovery_request AS request
		JOIN public.job AS job
		  ON job.organization_id = request.organization_id AND job.id = request.id
		WHERE request.organization_id = $1 AND request.id = $2`, discoveryAlphaOrg, request.requestID).
		Scan(&requestStatus, &jobStatus); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "PENDING" || jobStatus != "RUNNING" {
		t.Fatalf("security epoch rejection changed live state = request:%s job:%s", requestStatus, jobStatus)
	}

	if err := restoreSourceDiscoveryOwnerEpoch(t, ctx, admin, originalAssignmentID, replacementPrincipalID, replacementAssignmentID); err != nil {
		t.Fatalf("restore owner epoch fixture: %v", err)
	}
	restored = true
	var restoredOwner, activeOwner string
	var restoredEpoch int64
	if err := admin.QueryRow(ctx, `
		SELECT organization.owner_principal_id, organization.role_revision,
		       assignment.principal_id
		FROM public.organization AS organization
		JOIN public.organization_role_assignment AS assignment
		  ON assignment.organization_id = organization.id
		 AND assignment.role = 'OWNER' AND assignment.revoked_at IS NULL
		WHERE organization.id = $1`, discoveryAlphaOrg).
		Scan(&restoredOwner, &restoredEpoch, &activeOwner); err != nil {
		t.Fatal(err)
	}
	if restoredOwner != discoveryAlphaOwner || activeOwner != discoveryAlphaOwner || restoredEpoch != 1 {
		t.Fatalf("owner epoch fixture was not restored = owner:%q active:%q epoch:%d", restoredOwner, activeOwner, restoredEpoch)
	}
}

func restoreSourceDiscoveryOwnerEpoch(t *testing.T, ctx context.Context, admin *pgxpool.Pool, originalAssignmentID, replacementPrincipalID, replacementAssignmentID string) error {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		UPDATE public.organization
		SET owner_principal_id = $2, role_revision = 1
		WHERE id = $1`, discoveryAlphaOrg, discoveryAlphaOwner); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM public.organization_role_assignment
		WHERE id = $1`, replacementAssignmentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.organization_role_assignment
		SET valid_to_revision = NULL, revoked_at = NULL, revoked_by = NULL
		WHERE id = $1`, originalAssignmentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM public.principal
		WHERE organization_id = $1 AND id = $2`, discoveryAlphaOrg, replacementPrincipalID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func assertSourceDiscoveryExpiryLifecycle(t *testing.T, ctx context.Context, admin, app, worker *pgxpool.Pool, template sourceDiscoveryRequestInput) {
	t.Helper()
	beforeClaim := template
	beforeClaim.requestID = "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FB0"
	beforeClaim.idempotencyKeyHash = "sha256:" + strings.Repeat("a", 64)
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, beforeClaim); err != nil {
		t.Fatalf("expiry-before-claim fixture enqueue: %v", err)
	}
	forceSourceDiscoveryRequestExpiry(t, ctx, admin, discoveryAlphaOrg, beforeClaim.requestID)
	beforeJobID, beforeLeaseEpoch := claimSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, beforeClaim.requestID)
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, beforeClaim.requestID, beforeJobID, beforeLeaseEpoch); err == nil {
		t.Fatal("worker started a request that expired before queue claim")
	}
	if err := expireSourceDiscoveryAsApp(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, beforeClaim.requestID, beforeJobID, beforeLeaseEpoch); err == nil {
		t.Fatal("application role invoked source discovery expiration")
	}
	if err := expireSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, beforeClaim.requestID, beforeJobID, beforeLeaseEpoch); err != nil {
		t.Fatalf("expire request after pre-claim expiry: %v", err)
	}
	assertSourceDiscoveryExpired(t, ctx, admin, discoveryAlphaOrg, beforeClaim.requestID, beforeJobID)

	afterClaim := template
	afterClaim.requestID = "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FB1"
	afterClaim.idempotencyKeyHash = "sha256:" + strings.Repeat("b", 64)
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, discoveryAlphaOrg, discoveryAlphaOwner, afterClaim); err != nil {
		t.Fatalf("expiry-after-claim fixture enqueue: %v", err)
	}
	afterJobID, afterLeaseEpoch := claimSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, afterClaim.requestID)
	forceSourceDiscoveryRequestExpiry(t, ctx, admin, discoveryAlphaOrg, afterClaim.requestID)
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, afterClaim.requestID, afterJobID, afterLeaseEpoch); err == nil {
		t.Fatal("worker started a request that expired after queue claim")
	}
	if err := expireSourceDiscovery(t, ctx, worker, discoveryAlphaOrg, discoveryAlphaOwner, afterClaim.requestID, afterJobID, afterLeaseEpoch); err != nil {
		t.Fatalf("expire request after post-claim expiry: %v", err)
	}
	assertSourceDiscoveryExpired(t, ctx, admin, discoveryAlphaOrg, afterClaim.requestID, afterJobID)
}

func forceSourceDiscoveryRequestExpiry(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, requestID string) {
	t.Helper()
	triggerDisabled := false
	defer func() {
		if triggerDisabled {
			if _, err := admin.Exec(ctx, `ALTER TABLE public.source_discovery_request ENABLE TRIGGER source_discovery_request_state_guard`); err != nil {
				t.Errorf("restore request state trigger after expiry fixture failure: %v", err)
			}
		}
	}()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// This is a trusted test-only clock fixture. PostgreSQL cannot re-enable a
	// row trigger in the same transaction after its UPDATE has queued events, so
	// the trigger is restored in the next autocommit command. No runtime role can
	// obtain ALTER privilege on this table, and the deferred cleanup restores it
	// if this test fails while the fixture transaction is committed.
	if _, err := tx.Exec(ctx, `ALTER TABLE public.source_discovery_request DISABLE TRIGGER source_discovery_request_state_guard`); err != nil {
		t.Fatalf("disable request state trigger for expiry fixture: %v", err)
	}
	triggerDisabled = true
	commandTag, err := tx.Exec(ctx, `
		UPDATE public.source_discovery_request
		SET issued_at = transaction_timestamp() - interval '16 minutes',
		    expires_at = transaction_timestamp() - interval '1 minute'
		WHERE organization_id = $1 AND id = $2
		  AND status IN ('PENDING', 'RUNNING')`, organizationID, requestID)
	if err != nil {
		t.Fatalf("force request expiry fixture: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatalf("force request expiry affected %d rows, want 1", commandTag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit request expiry fixture: %v", err)
	}
	if _, err := admin.Exec(ctx, `ALTER TABLE public.source_discovery_request ENABLE TRIGGER source_discovery_request_state_guard`); err != nil {
		t.Fatalf("re-enable request state trigger after expiry fixture: %v", err)
	}
	triggerDisabled = false
}

func expireSourceDiscovery(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, requestID, jobID string, leaseEpoch int64) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + requestID[len(requestID)-4:]
	if _, err := tx.Exec(ctx, `SELECT app.source_discovery_request_expire($1, $2, $3, $4)`, requestID, jobID, workerID, leaseEpoch); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func expireSourceDiscoveryAsApp(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, requestID, jobID string, leaseEpoch int64) error {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + requestID[len(requestID)-4:]
	_, err = tx.Exec(ctx, `SELECT app.source_discovery_request_expire($1, $2, $3, $4)`, requestID, jobID, workerID, leaseEpoch)
	_ = tx.Rollback(ctx)
	return err
}

func assertSourceDiscoveryExpired(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, requestID, jobID string) {
	t.Helper()
	var requestStatus, failureCode, jobStatus, attemptOutcome string
	var requestStarted, requestCompleted, jobLeaseReleased, jobCompleted, attemptCompleted bool
	if err := admin.QueryRow(ctx, `
		SELECT request.status, request.failure_code,
		       request.started_at IS NOT NULL, request.completed_at IS NOT NULL,
		       job.status, job.lease_owner IS NULL, job.completed_at IS NOT NULL,
		       attempt.outcome, attempt.completed_at IS NOT NULL
		FROM public.source_discovery_request AS request
		JOIN public.job AS job
		  ON job.organization_id = request.organization_id AND job.id = request.id
		JOIN public.job_attempt AS attempt
		  ON attempt.organization_id = job.organization_id
		 AND attempt.job_id = job.id AND attempt.attempt_number = job.attempt_count
		WHERE request.organization_id = $1 AND request.id = $2 AND job.id = $3`, organizationID, requestID, jobID).
		Scan(&requestStatus, &failureCode, &requestStarted, &requestCompleted, &jobStatus, &jobLeaseReleased, &jobCompleted, &attemptOutcome, &attemptCompleted); err != nil {
		t.Fatalf("read expired source discovery lifecycle: %v", err)
	}
	if requestStatus != "EXPIRED" || failureCode != "DISCOVERY_EXPIRED" || requestStarted || !requestCompleted || jobStatus != "SUCCEEDED" || !jobLeaseReleased || !jobCompleted || attemptOutcome != "SUCCEEDED" || !attemptCompleted {
		t.Fatalf("expired source discovery lifecycle = request:%s/%s started:%v completed:%v job:%s released:%v completed:%v attempt:%s completed:%v", requestStatus, failureCode, requestStarted, requestCompleted, jobStatus, jobLeaseReleased, jobCompleted, attemptOutcome, attemptCompleted)
	}
	assertSourceDiscoveryNoResultOrArtifact(t, ctx, admin, organizationID, requestID)
}

func assertSourceDiscoveryNoResultOrArtifact(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, requestID string) {
	t.Helper()
	var resultCount, artifactCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.source_discovery_result
		WHERE organization_id = $1 AND request_id = $2`, organizationID, requestID).Scan(&resultCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id = $1 AND owner_table = 'source_discovery_result'
		  AND resource_type = 'SOURCE_DISCOVERY_RESULT' AND resource_id = $2`, organizationID, requestID).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if resultCount != 0 || artifactCount != 0 {
		t.Fatalf("source discovery failure left result/artifact rows = %d/%d", resultCount, artifactCount)
	}
}

func assertSourceDiscoveryTrustInvalidation(t *testing.T, ctx context.Context, admin, app, worker *pgxpool.Pool, fixture sourceDiscoveryConnectionFixture) {
	t.Helper()
	request := sourceDiscoveryRequestInput{
		requestID:            "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FB2",
		connectionID:         fixture.connectionID,
		connectionRevision:   fixture.connectionRev,
		trustProfileHash:     fixture.trustHash,
		maxViews:             16,
		maxColumns:           32,
		maxCommentBytes:      4096,
		statementTimeoutMS:   5000,
		transactionTimeoutMS: 10000,
		idempotencyKeyHash:   "sha256:" + strings.Repeat("c", 64),
	}
	if _, _, _, err := enqueueSourceDiscovery(t, ctx, app, fixture.organizationID, fixture.ownerID, request); err != nil {
		t.Fatalf("trust invalidation fixture enqueue: %v", err)
	}
	jobID, leaseEpoch := claimSourceDiscovery(t, ctx, worker, fixture.organizationID, fixture.ownerID, request.requestID)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	commandTag, err := tx.Exec(ctx, `
		UPDATE public.source_connection_trust_projection AS projection
		SET status = 'EXPIRED', changed_at = transaction_timestamp()
		FROM public.source_connection_trust_record AS record
		WHERE projection.organization_id = $1
		  AND projection.trust_record_id = record.id
		  AND projection.revision = record.connection_revision
		  AND record.organization_id = $1
		  AND record.connection_id = $2
		  AND record.connection_revision = $3`, fixture.organizationID, fixture.connectionID, fixture.connectionRev)
	if err != nil {
		t.Fatalf("expire source trust projection fixture: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatalf("expire source trust projection affected %d rows, want 1", commandTag.RowsAffected())
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit source trust projection expiry fixture: %v", err)
	}
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, fixture.organizationID, fixture.ownerID, request.requestID, jobID, leaseEpoch); err == nil {
		t.Fatal("worker started a request after its trust projection expired")
	}
	assertSourceDiscoveryNoResultOrArtifact(t, ctx, admin, fixture.organizationID, request.requestID)
	forceSourceDiscoveryRequestExpiry(t, ctx, admin, fixture.organizationID, request.requestID)
	if err := expireSourceDiscovery(t, ctx, worker, fixture.organizationID, fixture.ownerID, request.requestID, jobID, leaseEpoch); err != nil {
		t.Fatalf("content-free expiry cleanup after trust invalidation: %v", err)
	}
	assertSourceDiscoveryExpired(t, ctx, admin, fixture.organizationID, request.requestID, jobID)
}

func ensureSourceDiscoveryMigration(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	var present bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.source_discovery_request') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		return
	}
	raw, err := os.ReadFile(filepath.Join(repositoryRoot(t), "db", "migrations", "000090_stage4_source_discovery.sql"))
	if err != nil {
		t.Fatalf("read source discovery migration: %v", err)
	}
	if _, err := admin.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("apply source discovery migration: %v", err)
	}
}

func seedSourceDiscoveryConnection(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, suffix string) sourceDiscoveryConnectionFixture {
	t.Helper()
	connectionIDs := map[string]string{
		"alpha": "conn_01ARZ3NDEKTSV4RRFFQ69G5FAA",
		"beta":  "conn_01ARZ3NDEKTSV4RRFFQ69G5FAB",
	}
	connectionID, ok := connectionIDs[suffix]
	if !ok {
		t.Fatalf("unsupported source discovery fixture suffix %q", suffix)
	}
	trustBytes, err := canon.PostgreSQLQueryTrustBytes(connectionID, "database_sdr_"+suffix, "lineage_sdr_"+suffix)
	if err != nil {
		t.Fatalf("build PG trust config: %v", err)
	}
	fixture := sourceDiscoveryConnectionFixture{
		organizationID: organizationID,
		ownerID:        ownerID,
		connectionID:   connectionID,
		connectionRev:  1,
	}
	profileID := "cap_sdr_" + suffix
	profileHash := "sha256:" + strings.Repeat("a", 64)
	connectorBuildID := "pg-sdr-build-" + suffix
	connectorVersion := "1.0.0"
	connectorArtifactHash := "sha256:" + strings.Repeat("b", 64)
	contractSuiteHash := "sha256:" + strings.Repeat("c", 64)
	trustArtifactID := "artifact_sdr_trust_" + suffix
	trustRecordID := "trust_sdr_" + suffix
	verifiedAt := time.Now().UTC().Truncate(time.Microsecond)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (
			id, profile_hash, connector_build_id, connector_type, connector_version,
			connector_artifact_hash, stable_object_ids, native_versions,
			incremental_cursor, webhooks, item_level_acl, acl_refresh,
			historical_versions, deep_links, deletion_events, local_extraction,
			contract_suite_hash, verified_at
		) VALUES ($1, $2, $3, 'POSTGRESQL_QUERY', $4, $5, true, true, true, false,
			true, true, true, true, true, true, $6, $7)`,
		profileID, profileHash, connectorBuildID, connectorVersion,
		connectorArtifactHash, contractSuiteHash, verifiedAt); err != nil {
		t.Fatalf("seed PG capability profile: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection (
			organization_id, id, type, name, latest_revision, active_revision, status, created_by
		) VALUES ($1, $2, 'POSTGRESQL_QUERY', $2, 1, NULL, 'DRAFT', $3)`,
		organizationID, fixture.connectionID, ownerID); err != nil {
		t.Fatalf("seed PG connection: %v", err)
	}
	var resourceID string
	if err := tx.QueryRow(ctx, `
		SELECT app.source_connection_revision_resource_id($1, $2, 1)`, organizationID, fixture.connectionID).Scan(&resourceID); err != nil {
		t.Fatal(err)
	}
	fixture.trustHash = sealArtifactTx(t, ctx, tx, s1dCodec(t, organizationID),
		artifactcrypto.SourceConnectionTrustConfig, organizationID, trustArtifactID, resourceID,
		"source_connection_revision", "trust_profile_artifact_id", "SOURCE_TRUST_CONFIG", "TRUST_CONFIG", trustBytes)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_revision (
			organization_id, connection_id, revision, credential_reference,
			connector_build_id, connector_type, capability_profile_id,
			capability_profile_hash, connector_agent_id, execution_target,
			trust_record_id, trust_profile_artifact_id, trust_profile_hash,
			connector_version, connector_artifact_hash, connector_contract_suite_hash,
			connector_verified_at, allowed_access_modes_json, max_scope_objects,
			max_scope_bytes, max_object_bytes, created_by
		) VALUES ($1, $2, 1, $3, $4, 'POSTGRESQL_QUERY', $5, $6, NULL,
			'CENTRAL_WORKER', $7, $8, $9, $10, $11, $12, $13,
			'["WORKSPACE_MANAGED"]', 10000000, 100000000000, 1000000000, $14)`,
		organizationID, fixture.connectionID, testCredentialRef, connectorBuildID,
		profileID, profileHash, trustRecordID, trustArtifactID, fixture.trustHash,
		connectorVersion, connectorArtifactHash, contractSuiteHash, verifiedAt, ownerID); err != nil {
		t.Fatalf("seed PG connection revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_record (
			organization_id, id, connection_id, connection_revision, connector_agent_id,
			execution_target, trust_profile_artifact_id, trust_profile_hash,
			verified_at, expires_at
		) VALUES ($1, $2, $3, 1, NULL, 'CENTRAL_WORKER', $4, $5, $6::timestamptz, $6::timestamptz + interval '1 day')`,
		organizationID, trustRecordID, fixture.connectionID, trustArtifactID, fixture.trustHash, verifiedAt); err != nil {
		t.Fatalf("seed PG trust record: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_projection
			(organization_id, trust_record_id, revision, status)
		VALUES ($1, $2, 1, 'VERIFIED')`, organizationID, trustRecordID); err != nil {
		t.Fatalf("seed verified PG trust projection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit PG source fixture: %v", err)
	}
	return fixture
}

func assertSourceDiscoveryStoragePrivileges(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"source_discovery_request", "source_discovery_result"} {
		var forced, appInsert, appUpdate, appDelete, workerInsert, workerUpdate, workerDelete bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity,
				has_table_privilege('knowvault_app', $1, 'INSERT'),
				has_table_privilege('knowvault_app', $1, 'UPDATE'),
				has_table_privilege('knowvault_app', $1, 'DELETE'),
				has_table_privilege('knowvault_worker', $1, 'INSERT'),
				has_table_privilege('knowvault_worker', $1, 'UPDATE'),
				has_table_privilege('knowvault_worker', $1, 'DELETE')
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $2`, "public."+table, table).
			Scan(&forced, &appInsert, &appUpdate, &appDelete, &workerInsert, &workerUpdate, &workerDelete); err != nil {
			t.Fatalf("inspect %s privileges: %v", table, err)
		}
		if !forced || appInsert || appUpdate || appDelete || workerInsert || workerUpdate || workerDelete {
			t.Fatalf("%s privilege boundary = forced:%v app(insert/update/delete):%v/%v/%v worker:%v/%v/%v", table, forced, appInsert, appUpdate, appDelete, workerInsert, workerUpdate, workerDelete)
		}
	}
	var appEnqueue, workerEnqueue, publicEnqueue bool
	if err := admin.QueryRow(ctx, `
		SELECT has_function_privilege('knowvault_app', 'app.source_discovery_request_enqueue(text,text,bigint,text,integer,integer,integer,integer,integer,text)', 'EXECUTE'),
		       has_function_privilege('knowvault_worker', 'app.source_discovery_request_enqueue(text,text,bigint,text,integer,integer,integer,integer,integer,text)', 'EXECUTE'),
		       has_function_privilege('public', 'app.source_discovery_request_enqueue(text,text,bigint,text,integer,integer,integer,integer,integer,text)', 'EXECUTE')`).
		Scan(&appEnqueue, &workerEnqueue, &publicEnqueue); err != nil {
		t.Fatal(err)
	}
	if !appEnqueue || workerEnqueue || publicEnqueue {
		t.Fatalf("enqueue function privileges = app:%v worker:%v public:%v", appEnqueue, workerEnqueue, publicEnqueue)
	}
	var workerMetadataRead, appMetadataRead, publicMetadataRead bool
	if err := admin.QueryRow(ctx, `
		SELECT has_function_privilege('knowvault_worker', 'app.source_discovery_result_read_metadata(text)', 'EXECUTE'),
		       has_function_privilege('knowvault_app', 'app.source_discovery_result_read_metadata(text)', 'EXECUTE'),
		       has_function_privilege('public', 'app.source_discovery_result_read_metadata(text)', 'EXECUTE')`).
		Scan(&workerMetadataRead, &appMetadataRead, &publicMetadataRead); err != nil {
		t.Fatal(err)
	}
	if !workerMetadataRead || appMetadataRead || publicMetadataRead {
		t.Fatalf("metadata read function privileges = worker:%v app:%v public:%v", workerMetadataRead, appMetadataRead, publicMetadataRead)
	}
	var requestHasPrivilegeDigest bool
	if err := admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = 'source_discovery_request'
			  AND column_name IN ('privilege_digest', 'database_identity_hash'))`).Scan(&requestHasPrivilegeDigest); err != nil {
		t.Fatal(err)
	}
	if requestHasPrivilegeDigest {
		t.Fatal("request persists a worker-derived database or privilege digest")
	}
}

func assertSourceDiscoveryDirectInsertDenied(t *testing.T, ctx context.Context, app, worker *pgxpool.Pool) {
	t.Helper()
	for name, pool := range map[string]*pgxpool.Pool{"app": app, "worker": worker} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		setAccessContextForPrincipal(t, ctx, tx, discoveryAlphaOrg, discoveryAlphaOwner)
		_, err = tx.Exec(ctx, `INSERT INTO public.source_discovery_request (organization_id, id) VALUES ($1, $2)`, discoveryAlphaOrg, "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAZ")
		if err == nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s direct source discovery request INSERT succeeded", name)
		}
		_ = tx.Rollback(ctx)
	}
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, discoveryAlphaOrg, discoveryAlphaOwner)
	_, err = tx.Exec(ctx, `
		INSERT INTO public.source_discovery_result (organization_id, id, request_id)
		VALUES ($1, $2, $3)`, discoveryAlphaOrg,
		"sdr_01ARZ3NDEKTSV4RRFFQ69G5FAZ", "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("worker direct source discovery result INSERT succeeded")
	}
	_ = tx.Rollback(ctx)
}

func assertSourceDiscoveryJobPayloadCheck(t *testing.T, ctx context.Context, app *pgxpool.Pool) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, discoveryAlphaOrg, discoveryAlphaOwner)
	_, err = tx.Exec(ctx, `
		SELECT app.enqueue_job(
			'job_01ARZ3NDEKTSV4RRFFQ69G5FAZ', 'SOURCE_SCOPE_SYNC',
			jsonb_build_object('source_discovery_request_id', $1),
			'sdr-payload-old-type', 100, 1, 0)`, "sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("old job type accepted a source discovery request payload key")
	}
	_ = tx.Rollback(ctx)

	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, discoveryAlphaOrg, discoveryAlphaOwner)
	_, err = tx.Exec(ctx, `
		SELECT app.enqueue_job(
			'job_01ARZ3NDEKTSV4RRFFQ69G5FAX', 'SOURCE_DISCOVERY',
			jsonb_build_object('source_discovery_request_id', $1, 'content_hash', $2),
			'sdr-payload-extra-key', 100, 1, 0)`,
		"sdrq_01ARZ3NDEKTSV4RRFFQ69G5FAV", "sha256:"+strings.Repeat("a", 64))
	if err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("SOURCE_DISCOVERY accepted a payload with an extra key")
	}
	_ = tx.Rollback(ctx)
}

func assertSourceDiscoveryNonOwnerDenied(t *testing.T, ctx context.Context, app *pgxpool.Pool, request sourceDiscoveryRequestInput) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, discoveryAlphaOrg, discoveryMember)
	_, err = tx.Exec(ctx, `
		SELECT app.source_discovery_request_enqueue($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		request.requestID, request.connectionID, request.connectionRevision, request.trustProfileHash,
		request.maxViews, request.maxColumns, request.maxCommentBytes,
		request.statementTimeoutMS, request.transactionTimeoutMS, request.idempotencyKeyHash)
	if err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("non-owner source discovery enqueue succeeded")
	}
	_ = tx.Rollback(ctx)
}

func enqueueSourceDiscovery(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID string, request sourceDiscoveryRequestInput) (string, string, bool, error) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var requestID, jobID string
	var created bool
	err = tx.QueryRow(ctx, `
		SELECT request_id, job_id, created
		FROM app.source_discovery_request_enqueue($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		request.requestID, request.connectionID, request.connectionRevision, request.trustProfileHash,
		request.maxViews, request.maxColumns, request.maxCommentBytes,
		request.statementTimeoutMS, request.transactionTimeoutMS, request.idempotencyKeyHash).
		Scan(&requestID, &jobID, &created)
	if err != nil {
		_ = tx.Rollback(ctx)
		return "", "", false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", false, err
	}
	return requestID, jobID, created, nil
}

func claimAndStartSourceDiscovery(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, requestID string) (string, int64) {
	t.Helper()
	jobID, leaseEpoch := claimSourceDiscovery(t, ctx, worker, organizationID, principalID, requestID)
	if err := startSourceDiscoveryWithEpoch(t, ctx, worker, organizationID, principalID, requestID, jobID, leaseEpoch); err != nil {
		t.Fatalf("start source discovery: %v", err)
	}
	return jobID, leaseEpoch
}

func claimSourceDiscovery(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, requestID string) (string, int64) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var jobID, jobType string
	var payload []byte
	var leaseEpoch int64
	var attempt, maxAttempts int
	err = tx.QueryRow(ctx, `SELECT job_id, job_type, payload_json, lease_epoch, attempt_number, max_attempts FROM app.claim_next_job($1, 60)`, "worker_sdr_"+requestID[len(requestID)-4:]).
		Scan(&jobID, &jobType, &payload, &leaseEpoch, &attempt, &maxAttempts)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("claim source discovery: %v", err)
	}
	if jobType != "SOURCE_DISCOVERY" || strings.ReplaceAll(string(payload), " ", "") != `{"source_discovery_request_id":"`+requestID+`"}` || leaseEpoch < 1 || attempt < 1 || maxAttempts != 3 {
		_ = tx.Rollback(ctx)
		t.Fatalf("claimed source discovery job = type:%q payload:%s epoch:%d attempt:%d max:%d", jobType, payload, leaseEpoch, attempt, maxAttempts)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return jobID, leaseEpoch
}

func startSourceDiscoveryWithEpoch(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, requestID, jobID string, leaseEpoch int64) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	_, err = tx.Exec(ctx, `SELECT app.source_discovery_request_start($1, $2, $3, $4)`, requestID, jobID, "worker_sdr_"+requestID[len(requestID)-4:], leaseEpoch)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func completeSourceDiscovery(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID string, request sourceDiscoveryRequestInput, jobID string, leaseEpoch int64, resultID, databaseIdentityHash, privilegeDigest, metadataHash, resultHash, artifactID string) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + request.requestID[len(request.requestID)-4:]
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_result_begin($1, $2, $3, $4, $5, 'NEEDS_INTERPRETATION', 1, 0, 1, $6, $7, $8, $9)`,
		request.requestID, resultID, jobID, workerID, leaseEpoch,
		databaseIdentityHash, privilegeDigest, metadataHash, resultHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("begin source discovery result: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_result_bind_metadata(
			$1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, 1, $12, $13)`,
		request.requestID, resultID, jobID, workerID, leaseEpoch, artifactID,
		[]byte(strings.Repeat("q", 12)), []byte(strings.Repeat("c", 17)), []byte("wrapped"),
		"sha256:"+strings.Repeat("e", 64), "kms://sdr", "sha256:"+strings.Repeat("f", 64), metadataHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("bind source discovery metadata: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_request_complete($1, $2, $3, $4, $5, $6, $7, $8)`,
		request.requestID, resultID, jobID, workerID, leaseEpoch,
		databaseIdentityHash, privilegeDigest, resultHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("complete source discovery: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit source discovery result: %v", err)
	}
}

func assertSourceDiscoveryDigestRecheck(t *testing.T, ctx context.Context, admin, worker *pgxpool.Pool, organizationID, principalID string, request sourceDiscoveryRequestInput, jobID string, leaseEpoch int64) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + request.requestID[len(request.requestID)-4:]
	probeResultID := "sdr_01ARZ3NDEKTSV4RRFFQ69G5FAT"
	probeDatabaseHash := "sha256:" + strings.Repeat("a", 64)
	probePrivilegeDigest := "sha256:" + strings.Repeat("b", 64)
	probeMetadataHash := "sha256:" + strings.Repeat("c", 64)
	probeResultHash := "sha256:" + strings.Repeat("d", 64)
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_result_begin($1, $2, $3, $4, $5, 'NEEDS_INTERPRETATION', 1, 0, 1, $6, $7, $8, $9)`,
		request.requestID, probeResultID, jobID, workerID, leaseEpoch,
		probeDatabaseHash, probePrivilegeDigest, probeMetadataHash, probeResultHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("begin digest recheck result: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_result_bind_metadata(
			$1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10, $11, 1, $12, $13)`,
		request.requestID, probeResultID, jobID, workerID, leaseEpoch, "artifact_sdr_digest_probe",
		[]byte(strings.Repeat("q", 12)), []byte(strings.Repeat("c", 17)), []byte("wrapped"),
		"sha256:"+strings.Repeat("e", 64), "kms://sdr", "sha256:"+strings.Repeat("f", 64), probeMetadataHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("bind digest recheck metadata: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		SELECT app.source_discovery_request_complete($1, $2, $3, $4, $5, $6, $7, $8)`,
		request.requestID, probeResultID, jobID, workerID, leaseEpoch,
		probeDatabaseHash, "sha256:"+strings.Repeat("0", 64), probeResultHash); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("completion accepted a different second privilege digest observation")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback digest recheck transaction: %v", err)
	}
	var resultCount, artifactCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.source_discovery_result
		WHERE organization_id = $1 AND id = $2`, organizationID, probeResultID).Scan(&resultCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id = $1 AND id = $2`, organizationID, "artifact_sdr_digest_probe").Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if resultCount != 0 || artifactCount != 0 {
		t.Fatalf("digest mismatch left durable rows: result=%d artifact=%d", resultCount, artifactCount)
	}
}

type sourceDiscoveryStatusResult struct {
	requestStatus     string
	resultID          string
	resultStatus      string
	viewCount         int
	preparedViewCount int
	needsViewCount    int
	failureCode       *string
}

func sourceDiscoveryStatus(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, requestID string) (sourceDiscoveryStatusResult, error) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var result sourceDiscoveryStatusResult
	err = tx.QueryRow(ctx, `
		SELECT request_id, request_status, result_id, result_status,
		       view_count, prepared_view_count, needs_interpretation_view_count, failure_code
		FROM app.source_discovery_request_status($1)`, requestID).
		Scan(new(string), &result.requestStatus, &result.resultID, &result.resultStatus,
			&result.viewCount, &result.preparedViewCount, &result.needsViewCount, &result.failureCode)
	_ = tx.Rollback(ctx)
	return result, err
}

func sourceDiscoveryStatusValue(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, requestID string) sourceDiscoveryStatusResult {
	t.Helper()
	result, err := sourceDiscoveryStatus(t, ctx, app, organizationID, principalID, requestID)
	if err != nil {
		t.Fatalf("source discovery status: %v", err)
	}
	return result
}

func assertSourceDiscoveryMetadataRead(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, resultID, artifactID, plaintextHash string) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var gotResultID, gotArtifactID, gotPlaintextHash string
	var ciphertext []byte
	if err := tx.QueryRow(ctx, `
		SELECT result_id, artifact_id, ciphertext, plaintext_hash
		FROM app.source_discovery_result_read_metadata($1)`, resultID).
		Scan(&gotResultID, &gotArtifactID, &ciphertext, &gotPlaintextHash); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("read source discovery metadata envelope: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if gotResultID != resultID || gotArtifactID != artifactID || len(ciphertext) != 17 || gotPlaintextHash != plaintextHash {
		t.Fatalf("metadata envelope = result:%q artifact:%q ciphertext:%d plaintext:%q", gotResultID, gotArtifactID, len(ciphertext), gotPlaintextHash)
	}
}

func replaySourceDiscoveryCompletion(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID string, request sourceDiscoveryRequestInput, jobID string, leaseEpoch int64, resultID, databaseIdentityHash, privilegeDigest, resultHash string) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + request.requestID[len(request.requestID)-4:]
	_, err = tx.Exec(ctx, `SELECT app.source_discovery_request_complete($1, $2, $3, $4, $5, $6, $7, $8)`, request.requestID, resultID, jobID, workerID, leaseEpoch, databaseIdentityHash, privilegeDigest, resultHash)
	_ = tx.Rollback(ctx)
	return err
}

func failSourceDiscovery(t *testing.T, ctx context.Context, worker *pgxpool.Pool, organizationID, principalID, requestID, jobID string, leaseEpoch int64) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	workerID := "worker_sdr_" + requestID[len(requestID)-4:]
	var status string
	err = tx.QueryRow(ctx, `SELECT app.source_discovery_request_fail($1, $2, $3, $4, $5, 0)`, requestID, jobID, workerID, leaseEpoch, "DISCOVERY_METADATA_INVALID").Scan(&status)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if status != "PENDING" {
		_ = tx.Rollback(ctx)
		return errors.New("unexpected source discovery retry state: " + status)
	}
	return tx.Commit(ctx)
}

func sourceDiscoveryRequestCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, requestID string) int {
	t.Helper()
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_discovery_request WHERE organization_id = $1 AND id = $2`, organizationID, requestID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func sourceDiscoveryRequestTimes(t *testing.T, ctx context.Context, admin *pgxpool.Pool, requestID, organizationID string) (time.Time, time.Time) {
	t.Helper()
	var issuedAt, expiresAt time.Time
	if err := admin.QueryRow(ctx, `SELECT issued_at, expires_at FROM public.source_discovery_request WHERE organization_id = $1 AND id = $2`, organizationID, requestID).Scan(&issuedAt, &expiresAt); err != nil {
		t.Fatal(err)
	}
	return issuedAt, expiresAt
}
