package postgres_test

// ADR-0070 Go-layer tests: the rotation Coordinator (begin/complete with the
// audit contract) and the rotation Handler (fenced KEK re-wrap and digest
// re-projection passes) drive the two-phase state machine on the real
// PostgreSQL exactly as the worker runtime dispatches them. A full batch
// re-enqueues the next pass; a short batch closes the rotation atomically; a
// refused or failed precondition leaves its closed audit event.

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/rotation"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// rotationActiveKEK is the version-2 wrap key of the rotation window; the S1d
// seed pair is ref kms://tenant, version 1 (s1dKEKRef/s1dKEK).
var rotationActiveKEK = bytes.Repeat([]byte{0x33}, 32)

// newRotationHandler wires the handler, queue and coordinator over the worker
// role, with the rotating provider carrying the active pair plus the previous
// pair of the in-flight rotation — the exact composition of the worker
// runtime (ADR-0070 §1.3).
func newRotationHandler(t *testing.T, ctx context.Context, org string, digestVersion int) (*rotation.Handler, *jobs.Queue, *rotation.Coordinator, *artifactcrypto.Codec) {
	t.Helper()
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := artifactcrypto.NewRotatingMountedProvider(org, rotationActiveRef, 2, rotationActiveKEK,
		rotationPrevRef, 1, s1dKEK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	codec, err := artifactcrypto.NewCodec(provider)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := rotation.NewHandler(store, queue, provider, codec,
		rotation.Digester{Key: s1dDigestKey, KeyVersion: digestVersion}, s1dWorkerID, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := rotation.NewCoordinator(store, queue, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	return handler, queue, coordinator, codec
}

// runRotationPass enqueues-and-claims nothing itself: begin already placed the
// first job, so this claims and runs one pass.
func runRotationPass(t *testing.T, ctx context.Context, handler *rotation.Handler, queue *jobs.Queue,
	access database.AccessContext, wantType jobs.Type) error {
	t.Helper()
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim rotation job: %v ok=%v", err, ok)
	}
	if claimed.Type != wantType {
		t.Fatalf("claimed %s, want %s", claimed.Type, wantType)
	}
	switch wantType {
	case jobs.TypeKEKRewrap:
		return handler.HandleKEKRewrap(ctx, access, claimed)
	case jobs.TypeDigestRecompute:
		return handler.HandleDigestRecompute(ctx, access, claimed)
	}
	t.Fatalf("unsupported rotation type %s", wantType)
	return nil
}

type rotationAuditRow struct {
	action     string
	outcome    string
	errorCode  string
	resourceID string
	occurredAt time.Time
	metadata   map[string]any
}

func rotationAuditEvents(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, action string) []rotationAuditRow {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT action, outcome, COALESCE(error_code, ''), resource_id, occurred_at, metadata_json
		FROM public.audit_event WHERE organization_id = $1 AND action = $2 ORDER BY sequence`, org, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []rotationAuditRow
	for rows.Next() {
		var event rotationAuditRow
		var metadataRaw []byte
		if err := rows.Scan(&event.action, &event.outcome, &event.errorCode, &event.resourceID, &event.occurredAt, &metadataRaw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(metadataRaw, &event.metadata); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return events
}

// TestRotationHandlerKekFullCycle drives the whole KEK cycle through the Go
// layer: coordinator begin (which also places the first pass), one fenced
// re-wrap pass that covers every wrapper and closes the rotation, and the
// exact begin/complete audit trail.
func TestRotationHandlerKekFullCycle(t *testing.T) {
	ctx, admin, _, _, _ := rotationSetup(t)
	before := rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1)
	if before == 0 {
		t.Fatal("no artifacts sealed under the previous pair")
	}

	handler, queue, coordinator, _ := newRotationHandler(t, ctx, s1dOrg, 1)
	access := workerAccess(t, s1dOrg)
	if err := coordinator.Begin(ctx, access, rotation.DomainKEK, rotationPrevRef, 1, rotationActiveRef, 2); err != nil {
		t.Fatalf("begin: %v", err)
	}

	// Begin must have placed the driver job in the same transaction.
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim driver job: %v ok=%v", err, ok)
	}
	if claimed.Type != jobs.TypeKEKRewrap {
		t.Fatalf("driver job is %s, want KEK_REWRAP", claimed.Type)
	}
	if err := handler.HandleKEKRewrap(ctx, access, claimed); err != nil {
		t.Fatalf("handle: %v", err)
	}

	state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.phase != "COMPLETE" || state.watermark != before {
		t.Fatalf("state after pass: %+v", state)
	}
	if remaining := rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1); remaining != 0 {
		t.Fatalf("%d wrappers still under the previous pair", remaining)
	}

	// The audit contract: SUCCESS begin and complete, resource id is the
	// active reference, metadata carries the exact triple.
	begins := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.begin")
	if len(begins) != 1 || begins[0].outcome != "SUCCESS" || begins[0].errorCode != "" ||
		begins[0].resourceID != rotationActiveRef ||
		begins[0].metadata["rotation_domain"] != "KEK" ||
		begins[0].metadata["key_reference"] != rotationActiveRef {
		t.Fatalf("begin audit events: %+v", begins)
	}
	version, _ := begins[0].metadata["key_version"].(float64)
	if version != 2 {
		t.Fatalf("begin audit key_version=%v, want 2", begins[0].metadata["key_version"])
	}
	completes := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.complete")
	if len(completes) != 1 || completes[0].outcome != "SUCCESS" || completes[0].errorCode != "" ||
		completes[0].resourceID != rotationActiveRef ||
		completes[0].metadata["rotation_domain"] != "KEK" ||
		completes[0].metadata["key_reference"] != rotationActiveRef {
		t.Fatalf("complete audit events: %+v", completes)
	}
	completeVersion, _ := completes[0].metadata["key_version"].(float64)
	if completeVersion != 2 {
		t.Fatalf("complete audit key_version=%v, want 2", completes[0].metadata["key_version"])
	}
}

// TestRotationHandlerDigestFullCycle drives the digest rotation through the Go
// layer and proves the re-projection is a genuine re-keying: the stored
// anchor digest of every fragment equals an independent HMAC over the opened
// canonical anchor bytes under the active digest version.
func TestRotationHandlerDigestFullCycle(t *testing.T) {
	ctx, admin, _, _, extractionID := rotationSetup(t)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}

	handler, queue, coordinator, codec := newRotationHandler(t, ctx, s1dOrg, 2)
	access := workerAccess(t, s1dOrg)
	if err := coordinator.Begin(ctx, access, rotation.DomainDigest, "source-digest", 1, "source-digest", 2); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := runRotationPass(t, ctx, handler, queue, access, jobs.TypeDigestRecompute); err != nil {
		t.Fatalf("handle: %v", err)
	}

	state := rotationStateOf(t, ctx, admin, s1dOrg, "DIGEST")
	if state.phase != "COMPLETE" || state.watermark != int64(len(fragments)) {
		t.Fatalf("state after pass: %+v", state)
	}
	if remaining := digestRemainingCount(t, ctx, admin, s1dOrg, 1); remaining != 0 {
		t.Fatalf("remaining=%d after pass, want 0", remaining)
	}

	// Independent re-derivation: open each anchor and text artifact through the
	// worker's activated branch (session_user = knowvault_worker) under the
	// workspace authority context a viewer read would carry, and re-key the
	// canonical bytes ourselves.
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	repo := mustRepo(t)
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_rotation_verify"}
	rows, err := admin.Query(ctx, `SELECT id, anchor_hash, anchor_digest_key_version, text_hash, text_digest_key_version
		FROM public.evidence_fragment
		WHERE organization_id = $1 AND extraction_id = $2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	type fragmentDigest struct {
		id       string
		hash     string
		version  int64
		textHash string
		textVer  int64
	}
	var fragmentDigests []fragmentDigest
	for rows.Next() {
		var row fragmentDigest
		if err := rows.Scan(&row.id, &row.hash, &row.version, &row.textHash, &row.textVer); err != nil {
			t.Fatal(err)
		}
		fragmentDigests = append(fragmentDigests, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragmentDigests {
		var wantAnchor, wantText string
		if err := store.Read(ctx, viewerAccess, func(readCtx context.Context, tx database.Transaction) error {
			// The artifact reads gate on the workspace membership of the acting
			// principal (000017): bind the workspace like the viewer path does.
			if _, setErr := tx.Exec(readCtx, `SELECT set_config('app.workspace_id', $1, true)`, s1dWorkspace); setErr != nil {
				return setErr
			}
			anchorOwner, anchorEnvelope, fetchErr := repo.Fetch(readCtx, tx, viewerAccess, artifactcrypto.EvidenceAnchor, fragment.id)
			if fetchErr != nil {
				return fetchErr
			}
			anchorBytes, openErr := codec.Open(anchorOwner, anchorEnvelope)
			if openErr != nil {
				return openErr
			}
			wantAnchor = canon.HMACDigest(s1dDigestKey, 2, anchorBytes)
			clear(anchorBytes)

			textOwner, textEnvelope, fetchErr := repo.Fetch(readCtx, tx, viewerAccess, artifactcrypto.EvidenceNormalizedText, fragment.id)
			if fetchErr != nil {
				return fetchErr
			}
			textBytes, openErr := codec.Open(textOwner, textEnvelope)
			if openErr != nil {
				return openErr
			}
			wantText = canon.HMACDigest(s1dDigestKey, 2, textBytes)
			clear(textBytes)
			return nil
		}); err != nil {
			t.Fatalf("open fragment artifacts %s: %v", fragment.id, err)
		}
		if fragment.version != 2 || fragment.hash != wantAnchor {
			t.Fatalf("fragment %s: version=%d hash=%q, want version=2 hash=%q", fragment.id, fragment.version, fragment.hash, wantAnchor)
		}
		if fragment.textVer != 2 || fragment.textHash != wantText {
			t.Fatalf("fragment %s: text version=%d hash=%q, want version=2 hash=%q", fragment.id, fragment.textVer, fragment.textHash, wantText)
		}
	}
}

// TestRotationHandlerEmptyBatchCompletesImmediately proves the short-batch
// close: a rotation with no wrappers under the previous pair completes in the
// first pass without leaving a dangling job.
func TestRotationHandlerEmptyBatchCompletesImmediately(t *testing.T) {
	ctx, admin, _, _, _ := rotationSetup(t)
	seedOrganization(t, ctx, admin, "org_rotation_empty", "usr_rotation_empty", "ws_rotation_empty")

	handler, queue, coordinator, _ := newRotationHandler(t, ctx, "org_rotation_empty", 1)
	access := workerAccess(t, "org_rotation_empty")
	if err := coordinator.Begin(ctx, access, rotation.DomainKEK, rotationPrevRef, 1, rotationActiveRef, 2); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := runRotationPass(t, ctx, handler, queue, access, jobs.TypeKEKRewrap); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if state := rotationStateOf(t, ctx, admin, "org_rotation_empty", "KEK"); state.phase != "COMPLETE" {
		t.Fatalf("state after empty pass: %+v", state)
	}
	// No follow-on pass was placed: the queue is drained.
	if _, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60); err != nil || ok {
		t.Fatalf("unexpected follow-on job: ok=%v err=%v", ok, err)
	}
}

// TestRotationHandlerRefusesWithoutBegin proves the handler fails closed when
// a pass job runs with no rotation in progress: no state, no completion.
func TestRotationHandlerRefusesWithoutBegin(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)
	_ = admin
	leased := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "KEK_REWRAP", 20)
	claimed := jobs.ClaimedJob{ID: leased.id, Type: jobs.TypeKEKRewrap, LeaseEpoch: leased.leaseEpoch}

	handler, _, _, _ := newRotationHandler(t, ctx, s1dOrg, 1)
	access := workerAccess(t, s1dOrg)
	if err := handler.HandleKEKRewrap(ctx, access, claimed); err == nil {
		t.Fatal("pass succeeded without a rotation in progress")
	}
	if state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK"); state.phase != "" {
		t.Fatalf("rotation appeared without begin: %+v", state)
	}
}

// TestRotationCoordinatorRefusalAudit proves the closed audit trail of a
// refused begin (a different pair while a rotation is in progress) and a
// failed complete (zero-wrappers precondition): exactly the domain in
// metadata, no key pair named, the closed error code.
func TestRotationCoordinatorRefusalAudit(t *testing.T) {
	ctx, admin, _, _, _ := rotationSetup(t)
	handler, queue, coordinator, _ := newRotationHandler(t, ctx, s1dOrg, 1)
	access := workerAccess(t, s1dOrg)

	if err := coordinator.Begin(ctx, access, rotation.DomainKEK, rotationPrevRef, 1, rotationActiveRef, 2); err != nil {
		t.Fatalf("begin: %v", err)
	}

	// A different pair while the rotation is in progress is refused.
	err := coordinator.Begin(ctx, access, rotation.DomainKEK, "kms://another", 1, "kms://another-v2", 2)
	if err == nil || rotation.CodeOf(err) != rotation.CodeFailed {
		t.Fatalf("conflicting begin: err=%v code=%s, want CodeFailed", err, rotation.CodeOf(err))
	}

	// Complete while wrappers remain under the previous pair fails closed.
	if err := coordinator.Complete(ctx, access, rotation.DomainKEK); err == nil {
		t.Fatal("complete succeeded while wrappers remained")
	}

	denied := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.begin")
	if len(denied) != 2 || denied[1].outcome != "FAILED" || denied[1].errorCode != "ROTATION_FAILED" {
		t.Fatalf("refusal begin audit: %+v", denied)
	}
	if len(denied[1].metadata) != 1 || denied[1].metadata["rotation_domain"] != "KEK" {
		t.Fatalf("refusal metadata names more than the domain: %+v", denied[1].metadata)
	}

	failed := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.complete")
	if len(failed) != 1 || failed[0].outcome != "FAILED" || failed[0].errorCode != "ROTATION_FAILED" {
		t.Fatalf("failed complete audit: %+v", failed)
	}
	if len(failed[0].metadata) != 1 || failed[0].metadata["rotation_domain"] != "KEK" {
		t.Fatalf("failed metadata names more than the domain: %+v", failed[0].metadata)
	}

	// The rotation is untouched by the refusals and still completes via the
	// handler (the driver job placed by begin is still the live pass); the
	// closing pass writes the SUCCESS complete event next to the earlier
	// refusal.
	if err := runRotationPass(t, ctx, handler, queue, access, jobs.TypeKEKRewrap); err != nil {
		t.Fatalf("pass after refusals: %v", err)
	}
	if state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK"); state.phase != "COMPLETE" {
		t.Fatalf("state after refusals and pass: %+v", state)
	}
	completes := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.complete")
	if len(completes) != 2 || completes[0].outcome != "FAILED" || completes[1].outcome != "SUCCESS" {
		t.Fatalf("complete audit after refusals and pass: %+v", completes)
	}
}

// TestRotationWindowWithinNfrB1 proves the NFR-B1 contract of the rotation
// window (ADR-0070 §1.3, D8-10: ≤15 min of lost updates): a write that lands
// while the window is open seals under the active pair from its first moment,
// survives the close, and the begin→complete window — measured on the wall
// clock and on the audit trail — fits inside the B1 bound, so the audit stream
// makes the window observable.
func TestRotationWindowWithinNfrB1(t *testing.T) {
	ctx, admin, _, _, _ := rotationSetup(t)

	handler, queue, coordinator, codec := newRotationHandler(t, ctx, s1dOrg, 1)
	access := workerAccess(t, s1dOrg)

	windowStart := time.Now()
	if err := coordinator.Begin(ctx, access, rotation.DomainKEK, rotationPrevRef, 1, rotationActiveRef, 2); err != nil {
		t.Fatalf("begin: %v", err)
	}

	// A write lands while the window is open. The active pair of the mounted
	// keys is live before begin, so the seal already names the active pair:
	// the write is not a re-wrap candidate and cannot fall behind the window.
	windowArtifact := "artifact_window_s1d"
	var scopeResourceID string
	if err := admin.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1, $2, 1)`, s1dOrg, s1dScopeID).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}
	windowPlaintext := []byte(`{"schema_version":"source-scope-config-v1","window_write":true}`)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeConfig, s1dOrg,
		windowArtifact, scopeResourceID, "source_scope_revision", "scope_config_artifact_id",
		"SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", windowPlaintext)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if ref, version := artifactPair(t, ctx, admin, s1dOrg, windowArtifact); ref != rotationActiveRef || version != 2 {
		t.Fatalf("window write sealed under %s/%d, want active pair %s/2", ref, version, rotationActiveRef)
	}

	if err := runRotationPass(t, ctx, handler, queue, access, jobs.TypeKEKRewrap); err != nil {
		t.Fatalf("re-wrap pass: %v", err)
	}
	if state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK"); state.phase != "COMPLETE" {
		t.Fatalf("state after pass: %+v", state)
	}
	windowEnd := time.Now()

	// NFR-B1: the whole window fits inside the bound.
	window := windowEnd.Sub(windowStart)
	t.Logf("NFR-B1 rotation window begin→complete: %s (bound 15m)", window)
	if window > 15*time.Minute {
		t.Fatalf("rotation window %s exceeds the NFR-B1 15m bound", window)
	}

	// The window write survived the close: it still exists, still seals under
	// the active pair, and still opens to its exact plaintext through the
	// rotating codec.
	if ref, version := artifactPair(t, ctx, admin, s1dOrg, windowArtifact); ref != rotationActiveRef || version != 2 {
		t.Fatalf("window write after close: %s/%d, want active pair %s/2", ref, version, rotationActiveRef)
	}
	opened := openWindowArtifact(t, ctx, admin, codec, s1dOrg, windowArtifact, scopeResourceID)
	if !bytes.Equal(opened, windowPlaintext) {
		t.Fatalf("window write opened to %q, want %q", opened, windowPlaintext)
	}
	if remaining := rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1); remaining != 0 {
		t.Fatalf("%d wrappers still under the previous pair after close", remaining)
	}

	// The audit trail makes the window observable: the SUCCESS begin and
	// complete events carry their occurred_at, ordered begin→complete, and the
	// audit-derived window also fits inside the B1 bound.
	begins := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.begin")
	completes := rotationAuditEvents(t, ctx, admin, s1dOrg, "key.rotation.complete")
	if len(begins) != 1 || len(completes) != 1 {
		t.Fatalf("window audit: %d begin, %d complete events, want exactly one each", len(begins), len(completes))
	}
	auditWindow := completes[0].occurredAt.Sub(begins[0].occurredAt)
	if auditWindow <= 0 {
		t.Fatalf("audit window %s is not ordered begin→complete", auditWindow)
	}
	t.Logf("NFR-B1 audit-observable rotation window: %s (bound 15m)", auditWindow)
	if auditWindow > 15*time.Minute {
		t.Fatalf("audit rotation window %s exceeds the NFR-B1 15m bound", auditWindow)
	}
}

// openWindowArtifact reads an artifact sealed during the rotation window
// straight from the encrypted_artifact row and opens it with the rotating
// codec. The repository read path derives the artifact from its trusted owning
// row, which cannot name the window write, so the proof opens the sealed
// envelope directly — the envelope is still the production storage shape.
func openWindowArtifact(t *testing.T, ctx context.Context, admin *pgxpool.Pool, codec *artifactcrypto.Codec,
	org, artifactID, resourceID string) []byte {
	t.Helper()
	var ciphertext, nonce, wrappedDEK []byte
	var wrappedDEKHash, aadHash, plaintextHash string
	var ref string
	var version int64
	var sizeBytes int
	if err := admin.QueryRow(ctx, `SELECT ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
			kek_reference, kek_version, aad_hash, plaintext_hash
		FROM public.encrypted_artifact WHERE organization_id = $1 AND id = $2`,
		org, artifactID).Scan(&ciphertext, &sizeBytes, &nonce, &wrappedDEK, &wrappedDEKHash,
		&ref, &version, &aadHash, &plaintextHash); err != nil {
		t.Fatalf("read window artifact: %v", err)
	}
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceScopeConfig, org, resourceID)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	envelope := artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM,
		ciphertext, sizeBytes, nonce, wrappedDEK, wrappedDEKHash, ref, version, aadHash, plaintextHash)
	if !envelope.Valid() {
		t.Fatal("window artifact envelope is invalid")
	}
	plaintext, err := codec.Open(owner, envelope)
	if err != nil {
		t.Fatalf("open window artifact: %v", err)
	}
	return plaintext
}
