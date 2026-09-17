package postgres_test

import (
	"context"
	"strings"
	"testing"
)

// TestQuestionRunConversationBindingIsPairedAndImmutable exercises the new
// database boundary directly. A client may use the legacy all-null pair, but
// once a run is conversation-aware both opaque references are server-owned and
// cannot be edited or half-bound by raw SQL.
func TestQuestionRunConversationBindingIsPairedAndImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_qconv", "usr_qconv", "ws_qconv")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_qconv", "usr_qconv")
	questionHash := "sha256:" + strings.Repeat("b", 64)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.question_run (
			organization_id, id, workspace_id, workspace_revision, created_by,
			conversation_id, conversation_turn_id, question_hash, answer_mode,
			verification_method, workspace_scope_hash, policy_revision
		) VALUES ($1,$2,$3,1,$4,$5,$6,$7,'EXTRACTIVE','BYTE_EXACT_CITATION',$7,'policy-v1')
	`, "org_qconv", "qr_qconv_1", "ws_qconv", "usr_qconv", "conv_qconv_1", "turn_qconv_1", questionHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation (
			organization_id, id, workspace_id, workspace_revision, created_by
		) VALUES ($1,$2,$3,1,$4)
	`, "org_qconv", "conv_qconv_1", "ws_qconv", "usr_qconv"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation_retention (
			organization_id, conversation_id, workspace_id, workspace_revision
		) VALUES ($1,$2,$3,1)
	`, "org_qconv", "conv_qconv_1", "ws_qconv"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.conversation_turn (
			organization_id, id, conversation_id, workspace_id, workspace_revision,
			turn_index, question_run_id
		) VALUES ($1,$2,$3,$4,1,1,$5)
	`, "org_qconv", "turn_qconv_1", "conv_qconv_1", "ws_qconv", "qr_qconv_1"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_qconv", "usr_qconv")
	if _, err := tx.Exec(ctx, `
		UPDATE public.question_run SET conversation_turn_id = NULL
		 WHERE organization_id='org_qconv' AND id='qr_qconv_1'
	`); err == nil {
		t.Fatal("question run accepted a half-cleared conversation pair")
	}
	_ = tx.Rollback(ctx)

	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_qconv", "usr_qconv")
	if _, err := tx.Exec(ctx, `
		UPDATE public.question_run SET conversation_id = 'conv_qconv_other'
		 WHERE organization_id='org_qconv' AND id='qr_qconv_1'
	`); err == nil {
		t.Fatal("question run conversation binding was mutable")
	}
	_ = tx.Rollback(ctx)

	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_qconv", "usr_qconv")
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.question_run (
			organization_id, id, workspace_id, workspace_revision, created_by,
			conversation_id, question_hash, answer_mode, verification_method,
			workspace_scope_hash, policy_revision
		) VALUES ('org_qconv','qr_qconv_half','ws_qconv',1,'usr_qconv',
			'conv_qconv_1',$1,'EXTRACTIVE','BYTE_EXACT_CITATION',$1,'policy-v1')
	`, questionHash); err == nil {
		t.Fatal("question run accepted a conversation without a turn")
	}
	_ = tx.Rollback(ctx)

	var pairConstraint string
	if err := admin.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid='public.question_run'::regclass
		   AND conname='question_run_conversation_pair_check'
	`).Scan(&pairConstraint); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pairConstraint, "conversation_id") || !strings.Contains(pairConstraint, "conversation_turn_id") {
		t.Fatalf("pair constraint=%q does not cover both references", pairConstraint)
	}

	// The all-null form remains valid for historical runs created before the
	// conversation substrate. This compatibility is intentional and bounded.
	tx, err = app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_qconv", "usr_qconv")
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.question_run (
			organization_id, id, workspace_id, workspace_revision, created_by,
			question_hash, answer_mode, verification_method, workspace_scope_hash,
			policy_revision
		) VALUES ('org_qconv','qr_qconv_legacy','ws_qconv',1,'usr_qconv',
			$1,'EXTRACTIVE','BYTE_EXACT_CITATION',$1,'policy-v1')
	`, "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
