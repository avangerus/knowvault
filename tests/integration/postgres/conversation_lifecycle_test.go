package postgres_test

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func openConversationPurgerPool(t *testing.T, ctx context.Context, adminURL string) *pgxpool.Pool {
	t.Helper()
	parsed, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(purgerRole, appPassword)
	purger, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatalf("open conversation purger: %v", err)
	}
	t.Cleanup(purger.Close)
	return purger
}

func TestConversationWorkspaceLifecycleAndRetention(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_conv_alpha", "usr_conv_alice", "ws_conv_alpha")
	seedOrganization(t, ctx, admin, "org_conv_beta", "usr_conv_bob", "ws_conv_beta")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	// A Question Run is the only durable content authority.  The conversation
	// and turn rows below carry opaque ids and the server-owned run reference;
	// no user text is inserted into either table.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_conv_alpha", "usr_conv_alice")
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.question_run (
			organization_id, id, workspace_id, workspace_revision, created_by,
			question_hash, answer_mode, verification_method, workspace_scope_hash,
			policy_revision
		) VALUES ($1, $2, $3, 1, $4, $5, 'EXTRACTIVE', 'BYTE_EXACT_CITATION', $5, 'policy-v1')
	`, "org_conv_alpha", "qr_conv_1", "ws_conv_alpha", "usr_conv_alice", "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation (
			organization_id, id, workspace_id, workspace_revision, created_by
		) VALUES ($1, $2, $3, 1, $4)
	`, "org_conv_alpha", "conv_alpha_1", "ws_conv_alpha", "usr_conv_alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation_retention (
			organization_id, conversation_id, workspace_id, workspace_revision
		) VALUES ($1, $2, $3, 1)
	`, "org_conv_alpha", "conv_alpha_1", "ws_conv_alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation_turn (
			organization_id, id, conversation_id, workspace_id, workspace_revision,
			turn_index, question_run_id
		) VALUES ($1, $2, $3, $4, 1, 1, $5)
	`, "org_conv_alpha", "turn_alpha_1", "conv_alpha_1", "ws_conv_alpha", "qr_conv_1"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var conversations, turns int
	tx, err = app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_conv_alpha", "usr_conv_alice")
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.conversation").Scan(&conversations); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.conversation_turn").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if conversations != 1 || turns != 1 {
		t.Fatalf("authorized workspace saw conversations=%d turns=%d, want 1/1", conversations, turns)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The other organization is not visible even when the principal supplies
	// its id in a query; tenant and workspace predicates are server-owned.
	tx, err = app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_conv_beta", "usr_conv_bob")
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.conversation").Scan(&conversations); err != nil {
		t.Fatal(err)
	}
	if conversations != 0 {
		t.Fatalf("foreign organization leaked %d conversations", conversations)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// An app principal may not advance the retention lifecycle.  This is a
	// privilege boundary, not merely a convention in a repository.
	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_conv_alpha", "usr_conv_alice")
	if _, err := tx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state = 'PURGING', disclosure_allowed = false,
		       retention_fence = 1, purge_started_at = clock_timestamp()
		 WHERE organization_id = 'org_conv_alpha' AND conversation_id = 'conv_alpha_1'
	`); err == nil {
		t.Fatal("application role advanced conversation retention")
	}
	_ = tx.Rollback(ctx)

	purger := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
	tx, err = purger.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.organization_id', 'org_conv_alpha', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state = 'PURGING', disclosure_allowed = false,
		       retention_fence = 1, purge_started_at = clock_timestamp()
		 WHERE organization_id = 'org_conv_alpha' AND conversation_id = 'conv_alpha_1'
	`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The disclosure fence takes effect before physical cleanup: both the
	// conversation and its turn disappear from the app-facing RLS view.
	tx, err = app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_conv_alpha", "usr_conv_alice")
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.conversation").Scan(&conversations); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.conversation_turn").Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if conversations != 0 || turns != 0 {
		t.Fatalf("PURGING disclosure fence leaked conversations=%d turns=%d", conversations, turns)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	tx, err = purger.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.organization_id', 'org_conv_alpha', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state = 'PURGED', disclosure_allowed = false,
		       retention_fence = 2, purged_at = clock_timestamp()
		 WHERE organization_id = 'org_conv_alpha' AND conversation_id = 'conv_alpha_1'
	`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// PURGED is terminal; an attempted resurrection must fail even for the
	// privileged purger role.
	tx, err = purger.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.organization_id', 'org_conv_alpha', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state = 'ACTIVE', disclosure_allowed = true
		 WHERE organization_id = 'org_conv_alpha' AND conversation_id = 'conv_alpha_1'
	`); err == nil {
		t.Fatal("purged conversation retention resurrected")
	}
	_ = tx.Rollback(ctx)
}

func TestConversationTurnHasNoPlaintextContentColumns(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	rows, err := admin.Query(ctx, `
		SELECT column_name
		  FROM information_schema.columns
		 WHERE table_schema = 'public' AND table_name = 'conversation_turn'
		 ORDER BY ordinal_position
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"organization_id", "id", "conversation_id", "workspace_id", "workspace_revision", "turn_index", "question_run_id", "created_at"}
	if !sameStringSet(columns, want) {
		t.Fatalf("conversation_turn columns=%v, want exact server-owned set %v", columns, want)
	}
	for _, column := range columns {
		lower := strings.ToLower(column)
		if column != "question_run_id" && (strings.Contains(lower, "message") || strings.Contains(lower, "content") || strings.Contains(lower, "body") || strings.Contains(lower, "answer") || strings.Contains(lower, "text")) {
			t.Fatalf("conversation_turn contains plaintext-looking column %q", column)
		}
	}

	for _, table := range []string{"conversation", "conversation_turn", "conversation_retention"} {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			  FROM pg_class AS c
			  JOIN pg_namespace AS n ON n.oid = c.relnamespace
			 WHERE n.nspname = 'public' AND c.relname = $1
		`, table).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s does not FORCE ROW LEVEL SECURITY", table)
		}
	}
}

func sameStringSet(left, right []string) bool {
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	if len(leftCopy) != len(rightCopy) {
		return false
	}
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}
