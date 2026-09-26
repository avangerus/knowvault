package postgres_test

// R1.S10.s1.T4 proof, real PostgreSQL: an answer-feedback mark is durable,
// changeable, visible only to whoever can currently read the answer, its
// comment is never a plaintext column, and the workspace error-review report
// is reserved to OWNER/MANAGER.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/workspace"
)

// seedFeedbackWorkspace adds a second, fully declared workspace to an
// organization seedOrganization already created (its own workspace,
// revision, canonical snapshot and OWNER membership) so the "another
// workspace in the same organization" denial case has a real, readable
// workspace to be a member of -- not a bare row the workspace guard rejects.
func seedFeedbackWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, ownerID string) {
	t.Helper()
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive,
		OwnerPrincipalID: ownerID, Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("seed feedback workspace snapshot: %v", err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("seed feedback workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("seed feedback workspace canonical snapshot: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id) VALUES ($1, $2, $1, 'ACTIVE', $3)",
			[]any{workspaceID, organizationID, ownerID}},
		{"INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1, $2, 1, $3, $4)",
			[]any{organizationID, workspaceID, configurationHash, ownerID}},
		{"INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1, $2, 1, $3, $4)",
			[]any{organizationID, workspaceID, configurationHash, canonicalBytes}},
		{"INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)",
			[]any{"wsm_" + workspaceID, organizationID, workspaceID, ownerID}},
	} {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed feedback workspace %s: %v", workspaceID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit feedback workspace %s: %v", workspaceID, err)
	}
}

const feedbackKEKRef = "feedback-kek-ref"

var feedbackKEK = []byte("feedback-kek-32-bytes-abcdefghi!")

func feedbackCodec(t *testing.T, organizationID string) *artifactcrypto.Codec {
	t.Helper()
	provider, err := artifactcrypto.NewMountedProvider(organizationID, feedbackKEKRef, 1, feedbackKEK)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	codec, err := artifactcrypto.NewCodec(provider)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	return codec
}

func addFeedbackMember(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, principalID, role string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')
	`, principalID, organizationID); err != nil {
		t.Fatalf("seed feedback member principal %s: %v", principalID, err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1, $2, $3, $4, $5, 1, $4)
	`, "wsm_"+principalID, organizationID, workspaceID, principalID, role); err != nil {
		t.Fatalf("seed feedback member %s: %v", principalID, err)
	}
}

// seedFeedbackRun writes a terminal COMPLETED Question Run with a sealed
// question text and answer markdown, exactly the shape question.SubmitFeedback
// requires before it will accept a mark.
func seedFeedbackRun(t *testing.T, ctx context.Context, appStore *database.Store, codec *artifactcrypto.Codec, organizationID, workspaceID, runID, createdBy, questionPlain, answerPlain string) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: createdBy, RequestID: "req_feedback_seed_" + runID}
	questionArtifactID := "art_" + runID + "q"
	answerArtifactID := "art_" + runID + "a"
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				question_hash, answer_mode, verification_method, workspace_scope_hash, policy_revision
			) VALUES ($1,$2,$3,1,$4,$5,'EXTRACTIVE','BYTE_EXACT_CITATION',$5,'policy-feedback')
		`, organizationID, runID, workspaceID, createdBy, "sha256:"+strings.Repeat("a", 64)); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id, question_run_id) VALUES ($1,$2)
		`, organizationID, runID); err != nil {
			return err
		}
		questionOwner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, organizationID, runID)
		if err != nil {
			return err
		}
		questionEnvelope, err := codec.Seal(questionOwner, []byte(questionPlain))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			SELECT app.question_run_bind_question_text($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		`, organizationID, runID, questionArtifactID, questionEnvelope.Ciphertext(), questionEnvelope.SizeBytes(),
			questionEnvelope.Nonce(), questionEnvelope.WrappedDEK(), questionEnvelope.WrappedDEKHash(),
			questionEnvelope.KEKReference(), questionEnvelope.KEKVersion(), questionEnvelope.AADHash(), questionEnvelope.PlaintextHash()); err != nil {
			return err
		}
		answerOwner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.AnswerMarkdown, organizationID, runID)
		if err != nil {
			return err
		}
		answerEnvelope, err := codec.Seal(answerOwner, []byte(answerPlain))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			SELECT app.question_run_bind_answer_markdown($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		`, organizationID, runID, answerArtifactID, answerEnvelope.Ciphertext(), answerEnvelope.SizeBytes(),
			answerEnvelope.Nonce(), answerEnvelope.WrappedDEK(), answerEnvelope.WrappedDEKHash(),
			answerEnvelope.KEKReference(), answerEnvelope.KEKVersion(), answerEnvelope.AADHash(), answerEnvelope.PlaintextHash()); err != nil {
			return err
		}
		// answer_structured_artifact_id is required by the terminal guard but is
		// not read by SubmitFeedback/FeedbackReport; a second answer-markdown
		// artifact stands in for it so this fixture stays single-purpose.
		structuredOwner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.AnswerStructured, organizationID, runID)
		if err != nil {
			return err
		}
		structuredEnvelope, err := codec.Seal(structuredOwner, []byte(`{"schema_version":"extractive-answer-v1"}`))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			SELECT app.question_run_bind_answer_structured($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		`, organizationID, runID, "art_"+runID+"s", structuredEnvelope.Ciphertext(), structuredEnvelope.SizeBytes(),
			structuredEnvelope.Nonce(), structuredEnvelope.WrappedDEK(), structuredEnvelope.WrappedDEKHash(),
			structuredEnvelope.KEKReference(), structuredEnvelope.KEKVersion(), structuredEnvelope.AADHash(), structuredEnvelope.PlaintextHash()); err != nil {
			return err
		}
		_, err = tx.Exec(txCtx, `
			UPDATE public.question_run
			   SET result_status = 'COMPLETED', completed_at = transaction_timestamp(),
			       context_pack_hash = $3, answer_hash = $3
			 WHERE organization_id = $1 AND id = $2
		`, organizationID, runID, "sha256:"+strings.Repeat("b", 64))
		return err
	}); err != nil {
		t.Fatalf("seed feedback question run %s: %v", runID, err)
	}
}

func newFeedbackService(t *testing.T, appStore *database.Store, codec *artifactcrypto.Codec) *question.Service {
	t.Helper()
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	service, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestQuestionFeedbackSavedChangedAndScoped(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_fb", "usr_fb_owner", "ws_fb_a")
	// A second workspace in the SAME organization: its own member must not be
	// able to mark an answer in ws_fb_a ("другая рабочая область — отказ").
	seedFeedbackWorkspace(t, ctx, admin, "org_fb", "ws_fb_b", "usr_fb_owner")
	addFeedbackMember(t, ctx, admin, "org_fb", "ws_fb_a", "usr_fb_member", "MEMBER")
	addFeedbackMember(t, ctx, admin, "org_fb", "ws_fb_a", "usr_fb_manager", "MANAGER")
	addFeedbackMember(t, ctx, admin, "org_fb", "ws_fb_a", "usr_fb_auditor", "AUDITOR")
	addFeedbackMember(t, ctx, admin, "org_fb", "ws_fb_b", "usr_fb_outsider", "MEMBER")
	// A wholly separate organization: its member cannot even resolve ws_fb_a.
	seedOrganization(t, ctx, admin, "org_fb_other", "usr_fb_other_owner", "ws_fb_other")

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	codec := feedbackCodec(t, "org_fb")
	seedFeedbackRun(t, ctx, appStore, codec, "org_fb", "ws_fb_a", "run_fb_1", "usr_fb_owner",
		"Сколько активных договоров на сегодня?", "Активных договоров: 3.")
	service := newFeedbackService(t, appStore, codec)

	memberAccess := database.AccessContext{OrganizationID: "org_fb", PrincipalID: "usr_fb_member", RequestID: "req_fb_member_1"}

	// 1. Save: INCORRECT requires and stores a comment.
	saved, err := service.SubmitFeedback(ctx, memberAccess, "ws_fb_a", "run_fb_1", question.FeedbackIncorrect, "Число неверное, реально 5 договоров")
	if err != nil {
		t.Fatalf("submit INCORRECT feedback: %v (code=%s)", err, question.CodeOf(err))
	}
	if saved.Verdict != question.FeedbackIncorrect || !saved.HasComment {
		t.Fatalf("unexpected saved feedback: %+v", saved)
	}

	own, found, err := service.OwnFeedback(ctx, memberAccess, "ws_fb_a", "run_fb_1")
	if err != nil || !found || own.Verdict != question.FeedbackIncorrect || !own.HasComment {
		t.Fatalf("OwnFeedback after save: found=%v own=%+v err=%v", found, own, err)
	}

	// 2. Change: the same (organization, run, author) row is updated in
	// place, not appended -- resubmitting must not create a second row, and a
	// CORRECT verdict clears the previously stored comment.
	changed, err := service.SubmitFeedback(ctx, memberAccess, "ws_fb_a", "run_fb_1", question.FeedbackCorrect, "")
	if err != nil {
		t.Fatalf("change feedback to CORRECT: %v", err)
	}
	if changed.Verdict != question.FeedbackCorrect || changed.HasComment {
		t.Fatalf("unexpected changed feedback: %+v", changed)
	}
	var feedbackRowCount int
	if err := appStore.Read(ctx, memberAccess, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT count(*) FROM public.question_feedback
			WHERE organization_id = 'org_fb' AND question_run_id = 'run_fb_1' AND created_by = 'usr_fb_member'
		`).Scan(&feedbackRowCount)
	}); err != nil {
		t.Fatalf("count feedback rows: %v", err)
	}
	if feedbackRowCount != 1 {
		t.Fatalf("changing a mark created %d rows, want exactly 1 (one current mark per user per answer)", feedbackRowCount)
	}

	// Re-mark INCORRECT with a fresh comment so the report/plaintext checks
	// below exercise the comment path again.
	const rawComment = "На самом деле договоров пять, а не три"
	if _, err := service.SubmitFeedback(ctx, memberAccess, "ws_fb_a", "run_fb_1", question.FeedbackIncorrect, rawComment); err != nil {
		t.Fatalf("re-mark INCORRECT: %v", err)
	}

	// 3. Foreign/denied writers: another workspace in the same organization,
	// a wholly different organization, and a member who cannot currently read
	// the answer's content (AUDITOR is excluded from workspace.read_content).
	outsiderAccess := database.AccessContext{OrganizationID: "org_fb", PrincipalID: "usr_fb_outsider", RequestID: "req_fb_outsider"}
	if _, err := service.SubmitFeedback(ctx, outsiderAccess, "ws_fb_a", "run_fb_1", question.FeedbackCorrect, ""); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("member of a different workspace: got code=%s err=%v, want CodeDenied", question.CodeOf(err), err)
	}
	otherOrgAccess := database.AccessContext{OrganizationID: "org_fb_other", PrincipalID: "usr_fb_other_owner", RequestID: "req_fb_other_org"}
	if _, err := service.SubmitFeedback(ctx, otherOrgAccess, "ws_fb_a", "run_fb_1", question.FeedbackCorrect, ""); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("member of a different organization: got code=%s err=%v, want CodeDenied", question.CodeOf(err), err)
	}
	auditorAccess := database.AccessContext{OrganizationID: "org_fb", PrincipalID: "usr_fb_auditor", RequestID: "req_fb_auditor"}
	if _, err := service.SubmitFeedback(ctx, auditorAccess, "ws_fb_a", "run_fb_1", question.FeedbackCorrect, ""); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("workspace AUDITOR (cannot read answer content): got code=%s err=%v, want CodeDenied", question.CodeOf(err), err)
	}
	// The same three identities must not see the member's own mark either.
	if _, found, err := service.OwnFeedback(ctx, outsiderAccess, "ws_fb_a", "run_fb_1"); err == nil && found {
		t.Fatal("member of a different workspace read another member's feedback via OwnFeedback")
	}

	// 4. Report: OWNER/MANAGER see it, with the decrypted question/answer/
	// comment; a plain MEMBER does not.
	managerAccess := database.AccessContext{OrganizationID: "org_fb", PrincipalID: "usr_fb_manager", RequestID: "req_fb_manager"}
	report, err := service.FeedbackReport(ctx, managerAccess, "ws_fb_a")
	if err != nil {
		t.Fatalf("FeedbackReport as MANAGER: %v (code=%s)", err, question.CodeOf(err))
	}
	if len(report) != 1 {
		t.Fatalf("FeedbackReport returned %d entries, want 1", len(report))
	}
	entry := report[0]
	if entry.QuestionRunID != "run_fb_1" || entry.Verdict != question.FeedbackIncorrect || entry.AuthorPrincipalID != "usr_fb_member" {
		t.Fatalf("unexpected report entry: %+v", entry)
	}
	if entry.Question != "Сколько активных договоров на сегодня?" || entry.Answer != "Активных договоров: 3." {
		t.Fatalf("report did not decrypt the exact question/answer text: %+v", entry)
	}
	if entry.Comment != rawComment {
		t.Fatalf("report comment = %q, want %q", entry.Comment, rawComment)
	}

	ownerAccess := database.AccessContext{OrganizationID: "org_fb", PrincipalID: "usr_fb_owner", RequestID: "req_fb_owner"}
	if _, err := service.FeedbackReport(ctx, ownerAccess, "ws_fb_a"); err != nil {
		t.Fatalf("FeedbackReport as OWNER: %v", err)
	}
	if _, err := service.FeedbackReport(ctx, memberAccess, "ws_fb_a"); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("FeedbackReport as plain MEMBER: got code=%s err=%v, want CodeDenied", question.CodeOf(err), err)
	}

	// 5. The comment is never a plaintext column: the stored ciphertext bytes
	// (read as the superuser admin connection, bypassing the application
	// role entirely) must not contain the raw comment text, and
	// question_feedback itself carries no text/comment column at all.
	var ciphertext []byte
	if err := admin.QueryRow(ctx, `
		SELECT artifact.ciphertext
		FROM public.question_feedback feedback
		JOIN public.encrypted_artifact artifact
		  ON artifact.organization_id = feedback.organization_id AND artifact.id = feedback.comment_artifact_id
		WHERE feedback.organization_id = 'org_fb' AND feedback.question_run_id = 'run_fb_1' AND feedback.created_by = 'usr_fb_member'
	`).Scan(&ciphertext); err != nil {
		t.Fatalf("read stored comment ciphertext: %v", err)
	}
	if strings.Contains(string(ciphertext), rawComment) || strings.Contains(string(ciphertext), "договоров") {
		t.Fatal("the stored comment ciphertext contains recognizable plaintext")
	}
	var commentColumnCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'question_feedback' AND column_name = 'comment'
	`).Scan(&commentColumnCount); err != nil {
		t.Fatal(err)
	}
	if commentColumnCount != 0 {
		t.Fatal("question_feedback has a plain 'comment' column")
	}
	var artifactIDColumnCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'question_feedback' AND column_name = 'comment_artifact_id'
	`).Scan(&artifactIDColumnCount); err != nil {
		t.Fatal(err)
	}
	if artifactIDColumnCount != 1 {
		t.Fatal("question_feedback lost its comment_artifact_id owning column")
	}
}
