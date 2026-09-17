package postgres_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// The three tests in this file are the real-PostgreSQL Outcome-2 negative
// controls for audit-before-data on the governed question-run path. They run in
// the existing POSTGRES_INTEGRATION suite, use the same real database, worker
// ingestion, encrypted artifacts and Evidence reader as the rest of the suite,
// and add no dependency, role, permission model or migration.
//
// 1. TestAuditBeforeDataAdmissionFailureReturnsNoRows: with the audit journal
//    append unavailable, a governed question read/Create fails closed with the
//    existing typed unavailable error, returns zero rows and no partial result,
//    and appends nothing further.
// 2. TestAuditBeforeDataRevokeRaceReturnsNoData: a revocation committed while a
//    governed read is in flight (held after its admission) makes the read
//    return no data, while the journal keeps the admission plus its matching
//    failure outcome.
// 3. TestAuditBeforeDataReadFailureLeavesAdmissionAndOutcome: a read that fails
//    after a durable admission leaves admission + matching failure outcome,
//    never admission alone and never an outcome without admission.

// auditBeforeDataFixture is one seeded organization, workspace, ingested source
// and completed evidence-backed question run, plus the production Question
// authority wired exactly as composition wires it.
type auditBeforeDataFixture struct {
	ctx         context.Context
	admin       *pgxpool.Pool
	questions   *question.Service
	access      database.AccessContext
	workspaceID string
	run         question.Run
}

func seedAuditBeforeDataRun(t *testing.T) auditBeforeDataFixture {
	return seedAuditBeforeDataRunAs(t, s1dOwner)
}

func seedAuditBeforeDataRunAs(t *testing.T, principal string) auditBeforeDataFixture {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "waste.txt"),
		[]byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"grant_audit_before_data", "confirmation_audit_before_data")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "audit-before-data")

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}

	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: principal, RequestID: "req_audit_before_data"}
	run, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	})
	if err != nil {
		t.Fatalf("seed governed question run: %v (code=%s)", err, question.CodeOf(err))
	}
	if run.ResultStatus != "COMPLETED" || len(run.Citations) == 0 {
		t.Fatalf("seed run is not evidence-backed: status=%s citations=%d", run.ResultStatus, len(run.Citations))
	}
	return auditBeforeDataFixture{
		ctx: ctx, admin: admin, questions: questions, access: access,
		workspaceID: s1dWorkspace, run: run,
	}
}

// TestAuditBeforeDataAdmissionFailureReturnsNoRows proves the first negative
// control: when the admission/audit append cannot be recorded, the governed
// question read and Create both fail closed with the existing typed unavailable
// error, return zero rows / no partial result, and append no further event.
func TestAuditBeforeDataAdmissionFailureReturnsNoRows(t *testing.T) {
	fixture := seedAuditBeforeDataRun(t)
	ctx, admin := fixture.ctx, fixture.admin

	// Precondition: the same governed access returns the stored run while the
	// journal is writable, so the denial below is attributable to the admission
	// step and not to an unreadable run.
	before, err := fixture.questions.Get(ctx, fixture.access, fixture.workspaceID, fixture.run.ID)
	if err != nil || before.ID != fixture.run.ID {
		t.Fatalf("precondition Get: id=%q err=%v", before.ID, err)
	}

	var eventsBefore int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = $1`, s1dOrg).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.Exec(ctx, `REVOKE INSERT ON TABLE public.audit_event FROM knowvault_app`); err != nil {
		t.Fatalf("revoke audit append privilege: %v", err)
	}
	defer func() {
		if _, restoreErr := admin.Exec(context.Background(), `GRANT INSERT ON TABLE public.audit_event TO knowvault_app`); restoreErr != nil {
			t.Errorf("restore audit append privilege: %v", restoreErr)
		}
	}()

	got, err := fixture.questions.Get(ctx, fixture.access, fixture.workspaceID, fixture.run.ID)
	if question.CodeOf(err) != question.CodeUnavailable {
		t.Fatalf("admission failure code=%q err=%v, want %q", question.CodeOf(err), err, question.CodeUnavailable)
	}
	if got.ID != "" || got.Answer != "" || got.ResultStatus != "" || len(got.Citations) != 0 {
		t.Fatalf("admission failure leaked a partial result: %+v", got)
	}

	created, err := fixture.questions.Create(ctx, fixture.access, question.CreateRequest{
		WorkspaceID: fixture.workspaceID, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210")),
	})
	if question.CodeOf(err) != question.CodeUnavailable {
		t.Fatalf("Create admission failure code=%q err=%v, want %q", question.CodeOf(err), err, question.CodeUnavailable)
	}
	if created.ID != "" || created.Answer != "" || created.ResultStatus != "" || len(created.Citations) != 0 {
		t.Fatalf("Create admission failure leaked a partial run: %+v", created)
	}

	var eventsAfter int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = $1`, s1dOrg).Scan(&eventsAfter); err != nil {
		t.Fatal(err)
	}
	if eventsAfter != eventsBefore {
		t.Fatalf("failed admission appended audit events: before=%d after=%d", eventsBefore, eventsAfter)
	}
}

// TestAuditBeforeDataRevokeRaceReturnsNoData proves the revoke-race control: a
// membership revocation is committed in a separate transaction while the
// governed Get is provably in flight -- held after its admission on a
// test-owned gate -- and the read then returns no data. The admission and its
// matching failure outcome both remain in the journal.
func TestAuditBeforeDataRevokeRaceReturnsNoData(t *testing.T) {
	// Revoke an ordinary member. Removing the declared owner's membership
	// violates the workspace invariant and would never reach the read race.
	fixture := seedAuditBeforeDataRunAs(t, s1dViewer)
	ctx, admin := fixture.ctx, fixture.admin
	var beforeSequence int64
	if err := admin.QueryRow(ctx, `SELECT COALESCE(max(sequence),0) FROM public.audit_event WHERE organization_id=$1`, s1dOrg).Scan(&beforeSequence); err != nil {
		t.Fatal(err)
	}

	// Precondition: the run is readable before the race.
	if _, err := fixture.questions.Get(ctx, fixture.access, fixture.workspaceID, fixture.run.ID); err != nil {
		t.Fatalf("precondition Get: %v", err)
	}

	installAuditBeforeDataAdmissionGate(t, ctx, admin)

	gateConn, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gateConn.Release()
	if _, err := gateConn.Exec(ctx, `SELECT pg_advisory_lock(918273645)`); err != nil {
		t.Fatalf("hold admission gate: %v", err)
	}
	unlocked := false
	defer func() {
		if !unlocked {
			_, _ = gateConn.Exec(context.Background(), `SELECT pg_advisory_unlock(918273645)`)
		}
	}()

	type governedRead struct {
		run question.Run
		err error
	}
	resultCh := make(chan governedRead, 1)
	go func() {
		run, readErr := fixture.questions.Get(ctx, fixture.access, fixture.workspaceID, fixture.run.ID)
		resultCh <- governedRead{run: run, err: readErr}
	}()

	waitForAdmissionGateWait(t, ctx, admin)

	// The revocation commits while the governed read is in flight. Both the
	// closing revision and removed_at move together (000001 CHECK), and only
	// the closing revision is legal at the workspace's current revision.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member
		SET removed_at = transaction_timestamp(), valid_to_revision = 2
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, s1dOrg, fixture.workspaceID, fixture.access.PrincipalID); err != nil {
		t.Fatalf("commit revocation during governed read: %v", err)
	}

	if _, err := gateConn.Exec(ctx, `SELECT pg_advisory_unlock(918273645)`); err != nil {
		t.Fatalf("release admission gate: %v", err)
	}
	unlocked = true

	var got governedRead
	select {
	case got = <-resultCh:
	case <-time.After(15 * time.Second):
		t.Fatal("governed read did not finish after the revocation committed")
	}
	if got.err == nil || question.CodeOf(got.err) != question.CodeNotFound {
		t.Fatalf("revoked governed read code=%q err=%v, want %q", question.CodeOf(got.err), got.err, question.CodeNotFound)
	}
	if got.run.ID != "" || got.run.Answer != "" || len(got.run.Citations) != 0 {
		t.Fatalf("revoked governed read returned data: %+v", got.run)
	}

	// One admission for the precondition read and one for the raced read; the
	// raced read's matching failure outcome. Admission is never left alone.
	var admissions, failures int64
	if err := admin.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE action = 'question.run.admitted' AND outcome = 'SUCCESS'),
			count(*) FILTER (WHERE action = 'question.failed' AND outcome = 'FAILED')
		FROM public.audit_event
		WHERE organization_id = $1 AND metadata_json->>'question_run_id' = $2 AND sequence > $3
	`, s1dOrg, fixture.run.ID, beforeSequence).Scan(&admissions, &failures); err != nil {
		t.Fatal(err)
	}
	if admissions != 2 || failures != 1 {
		t.Fatalf("revoke race journal admissions=%d failures=%d, want 2 admissions and 1 matching failure outcome", admissions, failures)
	}
}

// TestAuditBeforeDataReadFailureLeavesAdmissionAndOutcome proves the third
// control: a governed read that fails after admission leaves admission plus its
// matching failure outcome, never admission alone and never an outcome without
// admission.
func TestAuditBeforeDataReadFailureLeavesAdmissionAndOutcome(t *testing.T) {
	fixture := seedAuditBeforeDataRun(t)
	ctx, admin := fixture.ctx, fixture.admin

	// A syntactically valid, never-created run id: admission is durable first,
	// then the governed read resolves no readable run.
	const missingRunID = "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	got, err := fixture.questions.Get(ctx, fixture.access, fixture.workspaceID, missingRunID)
	if err == nil || question.CodeOf(err) != question.CodeNotFound {
		t.Fatalf("missing governed run code=%q err=%v, want %q", question.CodeOf(err), err, question.CodeNotFound)
	}
	if got.ID != "" || got.Answer != "" || len(got.Citations) != 0 {
		t.Fatalf("missing governed run leaked data: %+v", got)
	}

	var admissions, failures, outcomesWithoutAdmission int64
	if err := admin.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE action = 'question.run.admitted' AND outcome = 'SUCCESS'),
			count(*) FILTER (WHERE action = 'question.failed' AND outcome = 'FAILED')
		FROM public.audit_event
		WHERE organization_id = $1 AND metadata_json->>'question_run_id' = $2
	`, s1dOrg, missingRunID).Scan(&admissions, &failures); err != nil {
		t.Fatal(err)
	}
	if admissions != 1 || failures != 1 {
		t.Fatalf("post-admission failure journal admissions=%d failures=%d, want 1 admission and 1 matching failure outcome", admissions, failures)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event outcome
		WHERE outcome.organization_id = $1
		  AND outcome.action = 'question.failed'
		  AND outcome.metadata_json->>'question_run_id' = $2
		  AND NOT EXISTS (
		      SELECT 1 FROM public.audit_event admission
		      WHERE admission.organization_id = outcome.organization_id
		        AND admission.action = 'question.run.admitted'
		        AND admission.metadata_json->>'question_run_id' = outcome.metadata_json->>'question_run_id'
		  )
	`, s1dOrg, missingRunID).Scan(&outcomesWithoutAdmission); err != nil {
		t.Fatal(err)
	}
	if outcomesWithoutAdmission != 0 {
		t.Fatalf("failure outcome without admission = %d", outcomesWithoutAdmission)
	}
}

// installAuditBeforeDataAdmissionGate installs a BEFORE INSERT trigger on the
// audit journal that blocks the next question.run.admitted admission on a
// test-held session advisory lock. It is removed on test cleanup. Any other
// audit action (including the matching failure outcome) passes untouched.
func installAuditBeforeDataAdmissionGate(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
CREATE OR REPLACE FUNCTION public.audit_before_data_admission_gate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.action = 'question.run.admitted' THEN
        PERFORM pg_advisory_xact_lock(918273645);
    END IF;
    RETURN NEW;
END;
$$;

GRANT EXECUTE ON FUNCTION public.audit_before_data_admission_gate() TO knowvault_app;

CREATE TRIGGER audit_before_data_admission_gate
BEFORE INSERT ON public.audit_event
FOR EACH ROW EXECUTE FUNCTION public.audit_before_data_admission_gate();
`); err != nil {
		t.Fatalf("install admission gate trigger: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, `
DROP TRIGGER IF EXISTS audit_before_data_admission_gate ON public.audit_event;
DROP FUNCTION IF EXISTS public.audit_before_data_admission_gate();
`); err != nil {
			t.Errorf("remove admission gate trigger: %v", err)
		}
	})
}

// waitForAdmissionGateWait blocks until the gated governed read is waiting on
// the admission advisory lock, so the revocation below provably commits while
// the governed read is in flight rather than before it starts.
func waitForAdmissionGateWait(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatalf("poll admission gate: %v", err)
		}
		if waiting > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the governed read to block on the admission gate")
}
