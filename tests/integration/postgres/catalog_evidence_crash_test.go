package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// faultOnce returns a hook that injects one failure the first time the named
// boundary is reached, then lets everything through.
func faultOnce(stage string) func(string) error {
	fired := false
	return func(s string) error {
		if s == stage && !fired {
			fired = true
			return errors.New("injected fault at " + s)
		}
		return nil
	}
}

// TestS1dCrashResumeIsAtomic proves publication atomicity across every crash
// boundary: a failure inside a per-object transaction commits nothing, and a
// failure after publication leaves a fully-active Evidence set. In both cases a
// reclaimed re-run converges to exactly one fully-active set — never
// half-published, duplicated or resurrected.
func TestS1dCrashResumeIsAtomic(t *testing.T) {
	// Boundaries inside the per-object transaction: a fault must roll the whole
	// object back (nothing committed).
	inTransaction := []string{"after_object", "after_version", "after_extraction", "inside_evidence", "before_publication"}
	for _, stage := range inTransaction {
		t.Run("rolls back at "+stage, func(t *testing.T) {
			ctx, admin, handler, queue, access := s1dCrashSetup(t)
			faulty := handler.WithFault(faultOnce(stage))
			runSyncExpectingFailure(t, ctx, faulty, queue, access, "fault-"+stage)

			if c := s1dCounts(t, ctx, admin); c.objects != 0 || c.versions != 0 || c.extractions != 0 || c.fragments != 0 {
				t.Fatalf("fault at %s committed a partial object: %+v", stage, c)
			}
			// A clean reclaimed re-run resumes to exactly one fully-active set.
			runSync(t, ctx, handler, queue, access, "resume-"+stage)
			assertSingleActiveSet(t, ctx, admin)
		})
	}

	// Between-transaction boundaries.
	t.Run("rolls back after discovery", func(t *testing.T) {
		ctx, admin, handler, queue, access := s1dCrashSetup(t)
		runSyncExpectingFailure(t, ctx, handler.WithFault(faultOnce("after_discovery")), queue, access, "fault-disc")
		if c := s1dCounts(t, ctx, admin); c.objects != 0 {
			t.Fatalf("fault after discovery committed objects: %+v", c)
		}
		runSync(t, ctx, handler, queue, access, "resume-disc")
		assertSingleActiveSet(t, ctx, admin)
	})

	t.Run("after publication the set is fully active and resume adds no duplicate", func(t *testing.T) {
		ctx, admin, handler, queue, access := s1dCrashSetup(t)
		// The object commits, then the job faults before acknowledgement.
		runSyncExpectingFailure(t, ctx, handler.WithFault(faultOnce("after_publication")), queue, access, "fault-pub")
		// The committed Evidence is already fully active (not half-published).
		assertSingleActiveSet(t, ctx, admin)
		before := s1dCounts(t, ctx, admin)
		// The reclaimed re-run is idempotent: still exactly one set, no duplicate.
		runSync(t, ctx, handler, queue, access, "resume-pub")
		if after := s1dCounts(t, ctx, admin); after != before {
			t.Fatalf("resume after publication changed counts: before=%+v after=%+v", before, after)
		}
		assertSingleActiveSet(t, ctx, admin)
	})
}

func s1dCrashSetup(t *testing.T) (context.Context, *pgxpool.Pool, *ingestion.Handler, *jobs.Queue, database.AccessContext) {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "resilient line one\nresilient line two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	return ctx, admin, handler, queue, workerAccess(t, s1dOrg)
}

func runSyncExpectingFailure(t *testing.T, ctx context.Context, handler *ingestion.Handler, queue *jobs.Queue, access database.AccessContext, label string) {
	t.Helper()
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: label + "-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if err := handler.Handle(ctx, access, claimed); err == nil {
		t.Fatalf("%s: handler unexpectedly succeeded under injected fault", label)
	}
}

// assertSingleActiveSet asserts exactly one object/version/extraction/evidence
// exists, the version is CURRENT and its active extraction resolves — one fully
// active Evidence set, no half-published or duplicate rows.
func assertSingleActiveSet(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	c := s1dCounts(t, ctx, admin)
	if c.objects != 1 || c.versions != 1 || c.extractions != 1 || c.fragments < 1 {
		t.Fatalf("expected exactly one active set, got %+v", c)
	}
	objectID, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	if objectID == "" || extractionID == "" {
		t.Fatal("active Evidence did not resolve")
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT v.state FROM public.source_version v
		JOIN public.source_object o ON o.organization_id=v.organization_id AND o.current_version_id=v.id
		WHERE v.organization_id=$1`, s1dOrg).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "CURRENT" {
		t.Fatalf("current version state=%s, want CURRENT", state)
	}
}
