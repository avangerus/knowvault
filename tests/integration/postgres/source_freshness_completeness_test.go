package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const freshnessOriginalText = "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"

// Real ingestion keeps the prior immutable version readable when an update is
// rejected. Both the source projection and a newly captured Question Run must
// describe that incomplete update, without changing already captured history.
func TestSourceFreshnessQuarantinedUpdate(t *testing.T) {
	for _, control := range []string{"oversized", "malformed"} {
		t.Run(control, func(t *testing.T) {
			f := newExactEvidenceFixture(t, freshnessOriginalText)
			questions, sources := freshnessServices(t, f)
			_, version, extraction := s1dTargetEvidence(t, f.ctx, f.admin, exactEvidencePath)
			fragment := s1dFragments(t, f.ctx, f.admin, extraction)[0].id
			before := assertFreshnessRun(t, f, questions, sources, "before", "FRESH", "COMPLETE")

			bad := strings.Repeat("a", 1100000)
			if control == "malformed" {
				bad = "\x00\x01\x02not-readable-text\xff\xfe"
			}
			writeS1dFile(t, f.target, bad)
			runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-rejected")
			var complete bool
			var quarantined int64
			if err := f.admin.QueryRow(f.ctx, `SELECT coverage_complete, quarantined FROM public.sync_run
				WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1
				ORDER BY started_at DESC,id DESC LIMIT 1`, s1dOrg, s1dScopeID).Scan(&complete, &quarantined); err != nil {
				t.Fatal(err)
			}
			if !complete || quarantined != 1 {
				t.Fatalf("control must be a complete enumeration with one rejected update: %v/%d", complete, quarantined)
			}
			assertFreshnessOldBytes(t, f, fragment, version)
			degraded := assertFreshnessRun(t, f, questions, sources, "rejected", "STALE", "PARTIAL")

			// A later incremental success with no new skips must not erase an
			// unresolved skip from the prior full observation. This isolates the
			// ledger from the last-run quarantined counter and coverage flag.
			freshnessAppendSync(t, f, s1dScopeID, "INCREMENTAL", true)
			status := freshnessSourceStatus(t, f, sources)
			if status.Quarantined == nil || *status.Quarantined != 0 {
				t.Fatal("incremental fixture did not isolate the old unresolved skip")
			}
			assertFreshnessRun(t, f, questions, sources, "pending-ledger", "STALE", "PARTIAL")

			writeS1dFile(t, f.target, freshnessOriginalText)
			failing := f.handler.WithFault(func(stage string) error {
				if stage == "after_publication" {
					return errors.New("stop before successful sync commits recovery")
				}
				return nil
			})
			runSyncExpectingFailure(t, f.ctx, failing, f.queue, workerAccess(t, s1dOrg), "freshness-failed-recovery")
			if status := freshnessSourceStatus(t, f, sources); status.FreshnessState != "STALE" {
				t.Fatalf("failed recovery cleared degradation: %+v", status)
			}
			assertFreshnessOldBytes(t, f, fragment, version)

			runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-recovery")
			assertFreshnessOldBytes(t, f, fragment, version)
			assertFreshnessRun(t, f, questions, sources, "recovered", "FRESH", "COMPLETE")
			for _, prior := range []question.Run{before, degraded} {
				stored, err := questions.Get(f.ctx, freshnessOwnerAccess(), s1dWorkspace, prior.ID)
				if err != nil || stored.Freshness.State != prior.Freshness.State || stored.CorpusStatus != prior.CorpusStatus ||
					stored.Answer != prior.Answer || !sameFreshnessTime(stored.Freshness.CapturedAt, prior.Freshness.CapturedAt) ||
					!sameFreshnessTime(stored.Freshness.LastSuccessfulSyncAt, prior.Freshness.LastSuccessfulSyncAt) {
					t.Fatalf("source recovery rewrote captured run %s: %v", prior.ID, err)
				}
			}
		})
	}
}

// An empty scan is deliberately non-authoritative (it may be an unmounted
// source). No skip row is necessary for the incomplete scan to degrade health.
func TestSourceFreshnessIncompleteScan(t *testing.T) {
	f := newExactEvidenceFixture(t, freshnessOriginalText)
	questions, sources := freshnessServices(t, f)
	_, version, extraction := s1dTargetEvidence(t, f.ctx, f.admin, exactEvidencePath)
	fragment := s1dFragments(t, f.ctx, f.admin, extraction)[0].id
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-empty-scan")
	status := freshnessSourceStatus(t, f, sources)
	if status.SyncErrorCode == nil || *status.SyncErrorCode != "INGEST_EMPTY_SCAN_UNCORROBORATED" || status.Quarantined == nil || *status.Quarantined != 0 {
		t.Fatalf("empty scan fixture did not isolate incomplete coverage: %+v", status)
	}
	assertFreshnessOldBytes(t, f, fragment, version)
	assertFreshnessRun(t, f, questions, sources, "incomplete-scan", "STALE", "PARTIAL")
	writeS1dFile(t, f.target, freshnessOriginalText)
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-complete-scan")
	assertFreshnessRun(t, f, questions, sources, "complete-scan", "FRESH", "COMPLETE")
}

func TestSourceFreshnessScopeIsolation(t *testing.T) {
	f := newExactEvidenceFixture(t, freshnessOriginalText)
	questions, sources := freshnessServices(t, f)
	otherScope, _ := seedS1dSecondScope(t, f.ctx, f.admin, s1dCodec(t, s1dOrg), s1dOrg, s1dOwner)
	// A newer incomplete success in another scope must not poison the
	// workspace's bound source, even when it shares the same connection.
	freshnessAppendSync(t, f, otherScope, "FULL", false)
	assertFreshnessRun(t, f, questions, sources, "other-scope", "FRESH", "COMPLETE")
	outsider := freshnessOwnerAccess()
	outsider.PrincipalID = "usr_freshness_outsider"
	rows, err := sources.ListSources(f.ctx, outsider, s1dWorkspace)
	if workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound || len(rows) != 0 {
		t.Fatalf("freshness projection changed the metadata admission boundary: %v", err)
	}
	if _, err := questions.Create(f.ctx, outsider, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: authorityIdempotencyKey("freshness-outsider"),
	}); err == nil {
		t.Fatal("freshness projection admitted an unauthorized question")
	}
}

func TestSourceFreshnessClosedRevisionSkipsDoNotDegradeCurrent(t *testing.T) {
	f := newExactEvidenceFixture(t, freshnessOriginalText)
	questions, sources := freshnessServices(t, f)
	writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "pending.txt"), strings.Repeat("a", 1100000))
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-old-revision-skip")
	assertFreshnessRun(t, f, questions, sources, "old-revision-skip", "STALE", "PARTIAL")

	// The new authorized scope revision deliberately excludes the rejected
	// file. Its complete sync closes revision 1, without deleting that old
	// revision's immutable skip history or manufacturing a skip resolution.
	seedS1dScopeRevision2(t, f.ctx, f.admin, s1dCodec(t, s1dOrg), s1dOrg, s1dOwner, `"pending.txt"`)
	seedS1dScopeBinding(t, f.ctx, f.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_freshness_r2", "confirmation_freshness_r2")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "freshness-new-revision")
	if got := activationStatus(t, f.ctx, f.admin, 1); got != "REVOKED" {
		t.Fatalf("old scope revision did not close: %s", got)
	}
	var oldSkips int
	store := openStore(t, f.ctx, appRole, "knowvault_app")
	if err := store.Read(f.ctx, freshnessOwnerAccess(), func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM app.source_object_current_skips()
			WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, s1dOrg, s1dScopeID).Scan(&oldSkips)
	}); err != nil || oldSkips != 1 {
		t.Fatalf("old-revision skip must remain to prove exact revision isolation: %d %v", oldSkips, err)
	}
	// The existing cutover helper deliberately seeds an inert canonical
	// snapshot. Check the two database projection contracts directly here;
	// ordinary valid-snapshot service/Question Run behavior is covered above.
	var revision int64
	var freshness, health string
	if err := store.Read(f.ctx, freshnessOwnerAccess(), func(ctx context.Context, tx database.Transaction) error {
		if err := tx.QueryRow(ctx, `SELECT source_scope_revision,freshness_state
			FROM app.workspace_source_status_v3($1) WHERE source_scope_id=$2`, s1dWorkspace, s1dScopeID).Scan(&revision, &freshness); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT health FROM app.question_corpus_source_status($1,$2,2)`, s1dWorkspace, s1dScopeID).Scan(&health)
	}); err != nil || revision != 2 || freshness != "FRESH" || health != "HEALTHY" {
		t.Fatalf("closed old scope degraded current revision: %d %s %s %v", revision, freshness, health, err)
	}
}

func freshnessServices(t *testing.T, f *exactEvidenceFixture) (*question.Service, *workspacerepository.Store) {
	t.Helper()
	store := openStore(t, f.ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(store)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(store, auditStore, s1dCodec(t, s1dOrg), f.viewer)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := workspacerepository.New(store, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	return questions, sources
}

func freshnessOwnerAccess() database.AccessContext {
	return database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_freshness_completeness"}
}

func freshnessSourceStatus(t *testing.T, f *exactEvidenceFixture, sources *workspacerepository.Store) workspacerepository.SourceStatus {
	t.Helper()
	rows, err := sources.ListSources(f.ctx, freshnessOwnerAccess(), s1dWorkspace)
	if err != nil || len(rows) != 1 {
		t.Fatalf("source status: %d %v", len(rows), err)
	}
	return rows[0]
}

func assertFreshnessRun(t *testing.T, f *exactEvidenceFixture, questions *question.Service, sources *workspacerepository.Store,
	label, freshness, corpus string) question.Run {
	t.Helper()
	status := freshnessSourceStatus(t, f, sources)
	if status.FreshnessState != freshness || status.SyncStatus == nil || *status.SyncStatus != "SUCCEEDED" || status.LastSuccessfulSyncAt == nil {
		t.Fatalf("%s source freshness: %+v", label, status)
	}
	run, err := questions.Create(f.ctx, freshnessOwnerAccess(), question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: authorityIdempotencyKey("freshness-" + label),
	})
	if err != nil || run.Freshness.State != freshness || run.CorpusStatus != corpus || run.ResultStatus != "COMPLETED" || len(run.Citations) == 0 {
		t.Fatalf("%s question freshness=%+v corpus=%s status=%s citations=%d: %v", label, run.Freshness, run.CorpusStatus, run.ResultStatus, len(run.Citations), err)
	}
	return run
}

func assertFreshnessOldBytes(t *testing.T, f *exactEvidenceFixture, fragment, version string) {
	t.Helper()
	for _, exact := range []bool{false, true} {
		var text string
		var gotVersion string
		var err error
		if exact {
			whole, readErr := f.viewer.ReadObjectExactVersion(f.ctx, f.access, s1dWorkspace, fragment, version)
			text, gotVersion, err = string(whole.Text), whole.Fragment.SourceVersionID, readErr
		} else {
			whole, readErr := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, fragment)
			text, gotVersion, err = string(whole.Text), whole.Fragment.SourceVersionID, readErr
		}
		if err != nil || text != freshnessOriginalText || gotVersion != version {
			t.Fatalf("prior immutable bytes exact=%v version=%s text=%q error=%v", exact, gotVersion, text, err)
		}
	}
}

func freshnessAppendSync(t *testing.T, f *exactEvidenceFixture, scope, mode string, complete bool) {
	t.Helper()
	// Synthetic status-only control in the isolated test database. Actual file
	// updates and recoveries above always use the production ingestion path.
	_, err := f.admin.Exec(f.ctx, `INSERT INTO public.sync_run
		(organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status,started_at,completed_at,coverage_complete,quarantined)
		SELECT organization_id,$3,$4,1,job_id,$5,'SUCCEEDED',clock_timestamp(),clock_timestamp(),$6,0
		FROM public.sync_run WHERE organization_id=$1 AND source_scope_id=$2
		ORDER BY started_at DESC,id DESC LIMIT 1`, s1dOrg, s1dScopeID, mustID(t, "syncrun"), scope, mode, complete)
	if err != nil {
		t.Fatal(err)
	}
}

func sameFreshnessTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}
