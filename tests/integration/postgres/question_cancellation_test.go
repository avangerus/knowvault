package postgres_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

const questionCancellationAdvisoryKey int64 = 91312012

// TestQuestionRunCancellationPersistsCancellation proves that a request cancellation
// after the run is committed still leaves a terminal cancellation and one failure
// audit event. The test-only trigger gates the terminal update, while
// LISTEN/NOTIFY synchronizes cancellation with the committed run without a
// polling loop or a timing assumption.
func TestQuestionRunCancellationPersistsCancellation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_cancel", "confirmation_s1d_cancel")
	installQuestionCancellationHooks(t, ctx, admin)

	listener, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire notification connection: %v", err)
	}
	t.Cleanup(func() { listener.Release() })
	if _, err := listener.Exec(ctx, `LISTEN p12a_question_run_started`); err != nil {
		t.Fatalf("listen for question run: %v", err)
	}
	if _, err := listener.Exec(ctx, `SELECT pg_advisory_lock($1)`, questionCancellationAdvisoryKey); err != nil {
		t.Fatalf("hold question run terminal update: %v", err)
	}
	advisoryLockHeld := true

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

	requestCtx, cancelRequest := context.WithCancel(ctx)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	created := make(chan struct {
		run question.Run
		err error
	}, 1)
	createDone := make(chan struct{})
	go func() {
		defer close(createDone)
		run, createErr := questions.Create(requestCtx, database.AccessContext{
			OrganizationID: s1dOrg,
			PrincipalID:    s1dOwner,
			RequestID:      "req_question_cancel",
		}, question.CreateRequest{
			WorkspaceID:    s1dWorkspace,
			Question:       "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?",
			AnswerMode:     "EXTRACTIVE",
			IdempotencyKey: key,
		})
		created <- struct {
			run question.Run
			err error
		}{run: run, err: createErr}
	}()

	t.Cleanup(func() {
		cancelRequest()
		if advisoryLockHeld {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			var unlocked bool
			if err := listener.QueryRow(cleanupCtx, `SELECT pg_advisory_unlock($1)`, questionCancellationAdvisoryKey).Scan(&unlocked); err != nil {
				t.Errorf("release question run terminal update during cleanup: %v", err)
			} else if !unlocked {
				t.Errorf("question run terminal update advisory lock was not held during cleanup")
			}
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		select {
		case <-createDone:
		case <-cleanupCtx.Done():
			t.Errorf("wait for question Create goroutine cleanup: %v", cleanupCtx.Err())
		}
	})
	waitCtx, cancelWait := context.WithTimeout(ctx, 15*time.Second)
	waitResult, waitDone := waitForQuestionRunNotification(listener, waitCtx)
	t.Cleanup(func() {
		cancelWait()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		select {
		case <-waitDone:
		case <-cleanupCtx.Done():
			t.Errorf("wait for notification goroutine cleanup: %v", cleanupCtx.Err())
		}
	})
	var notification *pgconn.Notification
	select {
	case result := <-created:
		t.Fatalf("question run returned before synchronized cancellation: status=%s error_code=%s", result.run.ResultStatus, question.CodeOf(result.err))
	case <-waitCtx.Done():
		t.Fatalf("question run start notification: %v", waitCtx.Err())
	case notificationResult := <-waitResult:
		if notificationResult.err != nil {
			t.Fatalf("wait for question run notification: %v", notificationResult.err)
		}
		notification = notificationResult.notification
	}
	if notification == nil || notification.Payload == "" {
		t.Fatal("question run start notification had no run id")
	}
	cancelRequest()
	var unlocked bool
	if err := listener.QueryRow(ctx, `SELECT pg_advisory_unlock($1)`, questionCancellationAdvisoryKey).Scan(&unlocked); err != nil {
		t.Fatalf("release question run terminal update: %v", err)
	}
	advisoryLockHeld = false
	if !unlocked {
		t.Fatal("question run terminal update advisory lock was not held")
	}

	select {
	case result := <-created:
		if result.err == nil {
			t.Fatalf("canceled question unexpectedly succeeded: status=%s", result.run.ResultStatus)
		}
		if question.CodeOf(result.err) != question.CodeUnavailable {
			t.Fatalf("canceled question error code=%s err=%v, want QUESTION_UNAVAILABLE", question.CodeOf(result.err), result.err)
		}
	case <-waitCtx.Done():
		t.Fatalf("wait for canceled question: %v", waitCtx.Err())
	}
	cancelWait()

	var status string
	var failureCode *string
	var completedAt *time.Time
	if err := admin.QueryRow(ctx, `
		SELECT result_status, failure_code, completed_at
		  FROM public.question_run
		 WHERE organization_id=$1 AND id=$2
	`, s1dOrg, notification.Payload).Scan(&status, &failureCode, &completedAt); err != nil {
		t.Fatalf("read canceled question run: %v", err)
	}
	if status != "CANCELLED" || failureCode == nil || *failureCode != "QUESTION_CANCELLED" || completedAt == nil {
		t.Fatalf("canceled question terminal state=%s/%v/%v, want CANCELLED/QUESTION_CANCELLED/non-null", status, failureCode, completedAt)
	}

	var failedAuditCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		  FROM public.audit_event
		 WHERE organization_id=$1 AND resource_type='QUESTION_RUN' AND resource_id=$2
		   AND action=$3 AND outcome='FAILED' AND error_code=$4
	`, s1dOrg, notification.Payload, string(audit.ActionQuestionFailed), "QUESTION_CANCELLED").Scan(&failedAuditCount); err != nil {
		t.Fatalf("count canceled question failure audit: %v", err)
	}
	if failedAuditCount != 1 {
		t.Fatalf("canceled question failure audit count=%d, want exactly one", failedAuditCount)
	}

	// A replay of the same idempotency key returns the terminal run and must not
	// append another failure event.
	replay, err := questions.Create(ctx, database.AccessContext{
		OrganizationID: s1dOrg,
		PrincipalID:    s1dOwner,
		RequestID:      "req_question_cancel_replay",
	}, question.CreateRequest{
		WorkspaceID:    s1dWorkspace,
		Question:       "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?",
		AnswerMode:     "EXTRACTIVE",
		IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("replay canceled question: %v", err)
	}
	if replay.ID != notification.Payload || replay.ResultStatus != "CANCELLED" {
		t.Fatalf("replay projection=%s/%s, want %s/CANCELLED", replay.ID, replay.ResultStatus, notification.Payload)
	}
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		  FROM public.audit_event
		 WHERE organization_id=$1 AND resource_type='QUESTION_RUN' AND resource_id=$2
		   AND action=$3 AND outcome='FAILED' AND error_code=$4
	`, s1dOrg, notification.Payload, string(audit.ActionQuestionFailed), "QUESTION_CANCELLED").Scan(&failedAuditCount); err != nil {
		t.Fatalf("recount canceled question failure audit: %v", err)
	}
	if failedAuditCount != 1 {
		t.Fatalf("replayed question failure audit count=%d, want exactly one", failedAuditCount)
	}
}

type questionRunNotificationResult struct {
	notification *pgconn.Notification
	err          error
}

func waitForQuestionRunNotification(listener *pgxpool.Conn, ctx context.Context) (<-chan questionRunNotificationResult, <-chan struct{}) {
	result := make(chan questionRunNotificationResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		notification, err := listener.Conn().WaitForNotification(ctx)
		result <- questionRunNotificationResult{notification: notification, err: err}
	}()
	return result, done
}

func installQuestionCancellationHooks(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	_, err := admin.Exec(ctx, `
CREATE OR REPLACE FUNCTION app.p12a_question_run_started()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('p12a_question_run_started', NEW.id);
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION app.p12a_question_run_update_gate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(91312012);
    RETURN NEW;
END;
$$;

CREATE TRIGGER p12a_question_run_started
AFTER INSERT ON public.question_run
FOR EACH ROW EXECUTE FUNCTION app.p12a_question_run_started();

CREATE TRIGGER p12a_question_run_update_gate
BEFORE UPDATE OF result_status ON public.question_run
FOR EACH ROW EXECUTE FUNCTION app.p12a_question_run_update_gate();
`)
	if err != nil {
		t.Fatalf("install question cancellation hooks: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, cleanupErr := admin.Exec(cleanupCtx, `
DROP TRIGGER IF EXISTS p12a_question_run_update_gate ON public.question_run;
DROP TRIGGER IF EXISTS p12a_question_run_started ON public.question_run;
DROP FUNCTION IF EXISTS app.p12a_question_run_update_gate();
DROP FUNCTION IF EXISTS app.p12a_question_run_started();
`); cleanupErr != nil {
			t.Errorf("remove question cancellation hooks: %v", cleanupErr)
		}
	})
}
