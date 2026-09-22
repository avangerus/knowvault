package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// B2-S4C3c3c: a COMPLETED run whose encrypted structured answer carries a
// present-but-malformed analytic scalar dependency must fail closed on every
// reopen. The legacy no-pair control proves the refusal is specific to the
// malformed dependency, not to the structured-answer artifact itself.
const (
	scalarReopenOrganization = "org_scalar_reopen"
	scalarReopenOwner        = "usr_scalar_reopen"
	scalarReopenWorkspace    = "ws_scalar_reopen"
	scalarReopenControlRun   = "qrun_scalar_reopen_control"
	scalarReopenMalformedRun = "qrun_scalar_reopen_malformed"

	scalarReopenQuestionSentinel    = "question-sentinel-scalar-reopen"
	scalarReopenAnswerSentinel      = "answer-sentinel-scalar-reopen"
	scalarReopenScalarSentinel      = "metric-sentinel-scalar-reopen"
	scalarReopenScalarValueSentinel = "3888"
	scalarReopenDependencySentinel  = "dependency-sentinel-scalar-reopen"

	scalarReopenQuestionHash = "sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	scalarReopenScopeHash    = "sha256:" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	scalarReopenContextHash  = "sha256:" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	scalarReopenAnswerHash   = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// scalarReopenSentinels is every secret-bearing marker written into the fixture.
// Neither a returned error nor any audit textual column may echo one.
var scalarReopenSentinels = []string{
	scalarReopenQuestionSentinel,
	scalarReopenAnswerSentinel,
	scalarReopenScalarSentinel,
	scalarReopenScalarValueSentinel,
	scalarReopenDependencySentinel,
	base64.StdEncoding.EncodeToString([]byte(scalarReopenDependencySentinel)),
}

// TestQuestionScalarMalformedArtifactBlocksGetAndReplay seeds two COMPLETED
// question runs directly against real PostgreSQL. The control carries the
// legacy pairless structured answer; the malformed fixture carries a valid
// analytic scalar beside a canonical base64 dependency whose decoded bytes the
// analyticsource decoder rejects. The real Service.Get and the real idempotent
// replay Create must both refuse the malformed run with the content-free
// CodeUnavailable, disclose no content, leave a durable admitted plus
// QUESTION_READ_FAILED audit pair, and mint no new run.
func TestQuestionScalarMalformedArtifactBlocksGetAndReplay(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, scalarReopenOrganization, scalarReopenOwner, scalarReopenWorkspace)

	codec := s1dCodec(t, scalarReopenOrganization)
	_ = openApplicationPool(t, ctx, testDatabaseURL(t))
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
	access := database.AccessContext{OrganizationID: scalarReopenOrganization, PrincipalID: scalarReopenOwner, RequestID: "req_scalar_reopen"}

	controlQuestion := scalarReopenQuestionSentinel
	malformedQuestion := scalarReopenQuestionSentinel + " malformed"
	controlAnswer := scalarReopenAnswerSentinel
	malformedAnswer := scalarReopenAnswerSentinel + " malformed"
	controlKey := scalarReopenIdempotencyKey(t, "scalar-reopen-control")
	malformedKey := scalarReopenIdempotencyKey(t, "scalar-reopen-malformed")

	// Admin writes only the immutable encrypted_artifact rows. The application
	// role, under a real access context, writes the run, its retention row and
	// its idempotency row so the production triggers and RLS stay in force.
	seedScalarReopenRun(t, ctx, admin, appStore, codec, access, scalarReopenControlRun,
		controlQuestion, controlAnswer, scalarReopenControlStructured(scalarReopenControlRun),
		controlKey, scalarReopenRequestHash(t, controlQuestion))
	seedScalarReopenRun(t, ctx, admin, appStore, codec, access, scalarReopenMalformedRun,
		malformedQuestion, malformedAnswer, scalarReopenMalformedStructured(t, scalarReopenMalformedRun),
		malformedKey, scalarReopenRequestHash(t, malformedQuestion))

	control, err := questions.Get(ctx, access, scalarReopenWorkspace, scalarReopenControlRun)
	if err != nil {
		t.Fatalf("legacy control Get: %v (code=%s)", err, question.CodeOf(err))
	}
	if control.ResultStatus != "COMPLETED" || control.Question != controlQuestion || control.Answer != controlAnswer {
		t.Fatalf("legacy control projection status=%q question=%q answer=%q", control.ResultStatus, control.Question, control.Answer)
	}

	refused, refusedErr := questions.Get(ctx, access, scalarReopenWorkspace, scalarReopenMalformedRun)
	if question.CodeOf(refusedErr) != question.CodeUnavailable {
		t.Fatalf("malformed Get code=%s err=%v, want %s", question.CodeOf(refusedErr), refusedErr, question.CodeUnavailable)
	}
	if !reflect.DeepEqual(refused, question.Run{}) {
		t.Fatalf("malformed Get disclosed a non-zero run: %+v", refused)
	}
	assertScalarReopenErrorSentinelFree(t, refusedErr)

	replayedControl, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: scalarReopenWorkspace, Question: controlQuestion, AnswerMode: "EXTRACTIVE", IdempotencyKey: controlKey,
	})
	if err != nil {
		t.Fatalf("legacy control replay Create: %v (code=%s)", err, question.CodeOf(err))
	}
	if replayedControl.ID != scalarReopenControlRun || replayedControl.Answer != controlAnswer {
		t.Fatalf("legacy control replay minted different result id=%q answer=%q", replayedControl.ID, replayedControl.Answer)
	}

	replayedMalformed, replayErr := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: scalarReopenWorkspace, Question: malformedQuestion, AnswerMode: "EXTRACTIVE", IdempotencyKey: malformedKey,
	})
	if question.CodeOf(replayErr) != question.CodeUnavailable {
		t.Fatalf("malformed replay Create code=%s err=%v, want %s", question.CodeOf(replayErr), replayErr, question.CodeUnavailable)
	}
	if !reflect.DeepEqual(replayedMalformed, question.Run{}) {
		t.Fatalf("malformed replay disclosed a non-zero run: %+v", replayedMalformed)
	}
	assertScalarReopenErrorSentinelFree(t, replayErr)

	var runCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.question_run WHERE organization_id=$1`, scalarReopenOrganization).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 2 {
		t.Fatalf("question_run count=%d after replay, want the two seeded runs unchanged", runCount)
	}

	// Every Get/Create above admitted before reading; the two malformed reads
	// each left their matching QUESTION_READ_FAILED outcome. Both must be
	// durable and content-free.
	var admittedCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action=$2 AND resource_id=$3 AND outcome='SUCCESS'`,
		scalarReopenOrganization, string(audit.ActionQuestionRunAdmitted), scalarReopenWorkspace).Scan(&admittedCount); err != nil {
		t.Fatal(err)
	}
	if admittedCount != 6 {
		t.Fatalf("question.run.admitted count=%d, want 6 (Get control, Get malformed, two replay admissions each)", admittedCount)
	}
	var readFailedCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action=$2 AND resource_id=$3 AND outcome='FAILED'
		  AND error_code='QUESTION_READ_FAILED' AND metadata_json->>'question_run_id'=$4`,
		scalarReopenOrganization, string(audit.ActionQuestionFailed), scalarReopenWorkspace, scalarReopenMalformedRun).Scan(&readFailedCount); err != nil {
		t.Fatal(err)
	}
	if readFailedCount != 2 {
		t.Fatalf("QUESTION_READ_FAILED outcome count=%d for the malformed run, want 2", readFailedCount)
	}
	assertScalarReopenAuditSentinelFree(t, ctx, admin)
}

// seedScalarReopenRun inserts one COMPLETED question run with its three sealed
// owned artifacts and its retention and idempotency rows. The artifact rows
// are the only writes performed by the admin fixture role; the owning run,
// retention and idempotency rows are written by the application role under a
// real access context so the question-run trigger and RLS policies execute.
func seedScalarReopenRun(t *testing.T, ctx context.Context, admin *pgxpool.Pool, appStore *database.Store,
	codec *artifactcrypto.Codec, access database.AccessContext, runID, questionPlain, answerPlain string,
	structuredPlain []byte, idempotencyKey, requestHash string) {
	t.Helper()
	if !jsontext.Value(structuredPlain).IsValid(jsontext.AllowDuplicateNames(false)) {
		t.Fatalf("structured answer fixture for run %s is not syntactically valid JSON", runID)
	}
	artifactIDs := []string{mustID(t, "artifact"), mustID(t, "artifact"), mustID(t, "artifact")}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.QuestionText, access.OrganizationID, artifactIDs[0], runID,
		"question_run", "question_text_artifact_id", "QUESTION_RUN", "QUESTION_TEXT", []byte(questionPlain))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.AnswerMarkdown, access.OrganizationID, artifactIDs[1], runID,
		"question_run", "answer_markdown_artifact_id", "QUESTION_RUN", "ANSWER_MARKDOWN", []byte(answerPlain))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.AnswerStructured, access.OrganizationID, artifactIDs[2], runID,
		"question_run", "answer_structured_artifact_id", "QUESTION_RUN", "ANSWER_STRUCTURED", structuredPlain)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				question_text_artifact_id, question_hash, answer_mode, verification_method,
				result_status, workspace_scope_hash, policy_revision
			) VALUES ($1,$2,$3,1,$4,$5,$6,'EXTRACTIVE','BYTE_EXACT_CITATION','RUNNING',$7,'policy-scalar-reopen')
		`, access.OrganizationID, runID, scalarReopenWorkspace, access.PrincipalID,
			artifactIDs[0], scalarReopenQuestionHash, scalarReopenScopeHash); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id, question_run_id)
			VALUES ($1,$2)
		`, access.OrganizationID, runID); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_idempotency (
				organization_id, actor_principal_id, idempotency_key,
				canonical_request_hash, workspace_id, question_run_id
			) VALUES ($1,$2,$3,$4,$5,$6)
		`, access.OrganizationID, access.PrincipalID, idempotencyKey, requestHash, scalarReopenWorkspace, runID); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			UPDATE public.question_run
			   SET result_status='COMPLETED', completed_at=transaction_timestamp(),
			       answer_markdown_artifact_id=$3, answer_structured_artifact_id=$4,
			       context_pack_hash=$5, answer_hash=$6
			 WHERE organization_id=$1 AND id=$2
		`, access.OrganizationID, runID, artifactIDs[1], artifactIDs[2], scalarReopenContextHash, scalarReopenAnswerHash)
		return err
	}); err != nil {
		t.Fatalf("seed question run %s: %v", runID, err)
	}
}

// scalarReopenControlStructured is the legacy pairless structured answer: both
// scalar member names are absent, which the strict decoder accepts.
func scalarReopenControlStructured(runID string) []byte {
	return []byte(fmt.Sprintf(
		`{"schema_version":"extractive-answer-v1","question_run_id":%q,"answer_mode":"EXTRACTIVE",`+
			`"verification_method":"BYTE_EXACT_CITATION","answer_hash":%q,"claims":[],"citations":[]}`,
		runID, scalarReopenAnswerHash))
}

// scalarReopenMalformedStructured binds one valid analytic scalar observation
// to the exact run beside a canonical base64 dependency whose decoded bytes are
// the dependency sentinel. The observation itself passes every closed scalar
// rule, so the refusal can only come from DecodeScalarDependency.
func scalarReopenMalformedStructured(t *testing.T, runID string) []byte {
	t.Helper()
	observation := fmt.Sprintf(
		`{"receipt_schema":"knowvault.analyticsource.live-scalar-receipt.v1","receipt_kind":"LIVE_OBSERVATION",`+
			`"window_basis":"CLIENT_READ_CALL","dataset_id":"gm_assignments","profile_version":3,"profile_hash":%q,`+
			`"metric_id":%q,"metric_reducer":"SUM","metric_unit":"tasks","metric_null_policy":"EXCLUDE_AND_REPORT",`+
			`"value":%q,"period_time_kind":"BUSINESS_DATE","period_logical_type":"DATE",`+
			`"period_start":"2026-09-10","period_end_exclusive":"2026-09-11",`+
			`"period_reporting_timezone":"UTC","period_source_timezone":"Europe/Moscow","period_calendar":"GREGORIAN",`+
			`"contributing_rows":407,"coverage_complete":true,`+
			`"observed_started_at":"2026-09-10T00:00:01Z","observed_completed_at":"2026-09-10T00:00:02Z",`+
			`"receipt_digest":%q}`,
		"sha256:"+strings.Repeat("b", 64), scalarReopenScalarSentinel, scalarReopenScalarValueSentinel, "sha256:"+strings.Repeat("a", 64))
	dependency := base64.StdEncoding.EncodeToString([]byte(scalarReopenDependencySentinel))
	return []byte(fmt.Sprintf(
		`{"schema_version":"extractive-answer-v1","question_run_id":%q,"answer_mode":"EXTRACTIVE",`+
			`"verification_method":"BYTE_EXACT_CITATION","answer_hash":%q,"claims":[],"citations":[],`+
			`"analytic_scalar":%s,"analytic_scalar_dependency":%q}`,
		runID, scalarReopenAnswerHash, observation, dependency))
}

// scalarReopenRequestHash reproduces the private question.RequestHash from the
// exported canonicalizer alone: the exact v2 domain, EXTRACTIVE mode, an empty
// conversation and the canonical question text.
func scalarReopenRequestHash(t *testing.T, questionText string) string {
	t.Helper()
	canonical, err := canon.Canonicalize([]byte(strings.TrimSpace(questionText)))
	if err != nil || len(canonical) == 0 {
		t.Fatalf("canonicalize question %q: %v", questionText, err)
	}
	return canon.Hash([]byte("question-request-v2\x00EXTRACTIVE\x00\x00" + string(canonical)))
}

// scalarReopenIdempotencyKey mints one valid 32-byte raw-URL idempotency key.
func scalarReopenIdempotencyKey(t *testing.T, marker string) string {
	t.Helper()
	raw := make([]byte, 32)
	copy(raw, marker)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// assertScalarReopenErrorSentinelFree walks the whole unwrap chain of a refusal
// and fails if any layer echoes a fixture sentinel.
func assertScalarReopenErrorSentinelFree(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal error, got nil")
	}
	for current := err; current != nil; current = errors.Unwrap(current) {
		for _, sentinel := range scalarReopenSentinels {
			if strings.Contains(current.Error(), sentinel) {
				t.Fatalf("question error leaked sentinel %q: %q", sentinel, current.Error())
			}
		}
	}
}

// assertScalarReopenAuditSentinelFree proves no audit textual column written by
// this fixture echoes question, answer, scalar or dependency content.
func assertScalarReopenAuditSentinelFree(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT action, resource_type, resource_id, request_id, outcome,
		coalesce(error_code,''), coalesce(actor_principal_id,''), metadata_json::text,
		referenced_evidence_ids_json::text
		FROM public.audit_event WHERE organization_id=$1`, scalarReopenOrganization)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, resourceType, resourceID, requestID, outcome, errorCode, actor, metadata, evidence string
		if err := rows.Scan(&action, &resourceType, &resourceID, &requestID, &outcome, &errorCode, &actor, &metadata, &evidence); err != nil {
			t.Fatal(err)
		}
		columns := []string{action, resourceType, resourceID, requestID, outcome, errorCode, actor, metadata, evidence}
		for _, sentinel := range scalarReopenSentinels {
			for _, value := range columns {
				if strings.Contains(value, sentinel) {
					t.Fatalf("audit event leaked sentinel %q in column value %q", sentinel, value)
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
