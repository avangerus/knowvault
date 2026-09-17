package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
)

// TestSearchProfileRevisionLifecycle proves migration 000072 against live
// PostgreSQL: the retrieval profile is an append-only revision sequence, the
// runtime role may only ever append a revision nothing reads, and the cutover
// is a one-way worker transition that never leaves the tenant without a
// readable profile.
func TestSearchProfileRevisionLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	access := workerAccess(t, s1dOrg)

	// 1. The first revision is provisioned straight from the mount and is born
	//    ACTIVE: there is no earlier corpus to re-index.
	for attempt := 0; attempt < 2; attempt++ {
		if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
			return repository.EnsureMountedLexicalProfile(txCtx, transaction, access, 1, 1)
		}); err != nil {
			t.Fatalf("bootstrap revision (attempt %d): %v (sqlstate=%s)", attempt, err, database.SQLStateCode(err))
		}
	}
	assertRevisions(t, ctx, admin, [][2]string{{"lexical-only-v1", "ACTIVE"}})

	// 2. The runtime role stages the deployment's mounted vector profile through
	//    the one typed command. It is idempotent.
	vectorProfileID := "multilingual-e5-small-cpu-v1"
	vectorProfileHash := "sha256:" + strings.Repeat("a", 64)
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	stage := func(t *testing.T, profileID, profileHash string) (int64, error) {
		t.Helper()
		transaction, beginErr := app.Begin(ctx)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		defer func() { _ = transaction.Rollback(ctx) }()
		setAccessContext(t, ctx, transaction, s1dOrg)
		var revision int64
		if scanErr := transaction.QueryRow(ctx,
			`SELECT app.stage_search_profile_revision($1,$2,$3,$4)`,
			profileID, profileHash, int64(1), int64(1)).Scan(&revision); scanErr != nil {
			return 0, scanErr
		}
		return revision, transaction.Commit(ctx)
	}
	revision, stageErr := stage(t, vectorProfileID, vectorProfileHash)
	if stageErr != nil || revision != 2 {
		t.Fatalf("stage_search_profile_revision = %d, %v; want revision 2", revision, stageErr)
	}
	repeat, repeatErr := stage(t, vectorProfileID, vectorProfileHash)
	if repeatErr != nil || repeat != 2 {
		t.Fatalf("repeated staging = %d, %v; want the same revision 2", repeat, repeatErr)
	}
	assertRevisions(t, ctx, admin, [][2]string{{"lexical-only-v1", "ACTIVE"}, {vectorProfileID, "STAGING"}})

	// 3. A second, different vector space cannot be staged behind the first.
	if _, err := stage(t, "another-profile-v1", "sha256:"+strings.Repeat("b", 64)); err == nil {
		t.Fatal("a second concurrent staged revision was accepted")
	}

	// 4. The runtime role may not write a readable revision, only a staged one.
	if err := insertProfileRevisionAsApp(ctx, app, t, 3, "ACTIVE"); err == nil {
		t.Fatal("the runtime role inserted an ACTIVE profile revision")
	}

	// 5. The cutover is the worker's: the staged revision becomes ACTIVE and the
	//    previous one SUPERSEDED, in one transaction.
	if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		return repository.ActivateRevision(txCtx, transaction, access, 2, time.Now().UTC())
	}); err != nil {
		t.Fatalf("activate revision: %v (sqlstate=%s)", err, database.SQLStateCode(err))
	}
	assertRevisions(t, ctx, admin, [][2]string{{"lexical-only-v1", "SUPERSEDED"}, {vectorProfileID, "ACTIVE"}})

	// 6. The active revision is what a reader resolves, and re-activating is not
	//    a way to move a tenant back.
	if err := workerStore.Read(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		active, found, readErr := repository.ReadRevision(txCtx, transaction, access, search.RevisionActive)
		if readErr != nil {
			return readErr
		}
		if !found || active.ProfileID != vectorProfileID || active.ActivationRevision != 2 || !active.Vector() {
			t.Fatalf("active revision = %+v", active)
		}
		return nil
	}); err != nil {
		t.Fatalf("read active revision: %v", err)
	}
	if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		return repository.ActivateRevision(txCtx, transaction, access, 2, time.Now().UTC())
	}); err == nil {
		t.Fatal("an already-activated revision was activated a second time")
	}

	// 7. The bootstrap path never resurrects a superseded profile: a worker
	//    mounting the lexical descriptor again finds the tenant already has a
	//    revision sequence and appends nothing. Only the operator command moves a
	//    tenant between vector spaces.
	if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		return repository.EnsureMountedLexicalProfile(txCtx, transaction, access, 1, 1)
	}); err != nil {
		t.Fatalf("bootstrap on an existing tenant must be a no-op, got: %v", err)
	}
	assertRevisions(t, ctx, admin, [][2]string{{"lexical-only-v1", "SUPERSEDED"}, {vectorProfileID, "ACTIVE"}})
}

func insertProfileRevisionAsApp(ctx context.Context, app *pgxpool.Pool, t *testing.T, revision int64, status string) error {
	t.Helper()
	transaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setAccessContext(t, ctx, transaction, s1dOrg)
	_, execErr := transaction.Exec(ctx, `
		INSERT INTO public.organization_search_profile
			(organization_id, embedding_profile_id, embedding_profile_hash,
			 index_generation, activation_revision, generation_fence,
			 catalog_snapshot_watermark, outbox_applied_sequence, status, activated_at)
		VALUES ($1,$2,$3,1,$4,1,0,0,$5, transaction_timestamp())`,
		s1dOrg, "runtime-written-v1", "sha256:"+strings.Repeat("c", 64), revision, status)
	return execErr
}

func assertRevisions(t *testing.T, ctx context.Context, admin *pgxpool.Pool, want [][2]string) {
	t.Helper()
	rows, err := admin.Query(ctx, `
		SELECT embedding_profile_id, status
		  FROM public.organization_search_profile
		 WHERE organization_id=$1
		 ORDER BY activation_revision`, s1dOrg)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got [][2]string
	for rows.Next() {
		var profileID, status string
		if scanErr := rows.Scan(&profileID, &status); scanErr != nil {
			t.Fatal(scanErr)
		}
		got = append(got, [2]string{profileID, status})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("revisions = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("revisions = %v, want %v", got, want)
		}
	}
}
