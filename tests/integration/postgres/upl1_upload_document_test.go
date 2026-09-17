package postgres_test

// End-to-end proof of UPL-1 (browser document upload) against real
// PostgreSQL 18.4: an owner registers a "documents" source with no
// root_alias/root_identity/contract of their own (the web client always
// sends the fixed, reserved browser-upload pair), uploads a file through
// registration.Service.UploadDocuments exactly like the REST handler does,
// a real worker SOURCE_SCOPE_SYNC ingests it from
// public.source_uploaded_document instead of a mounted directory, and the
// product Question authority answers with a citation into that exact
// uploaded document.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// upl1NoMounts always fails resolution. The browser-upload sentinel
// (root_alias/root_identity = "browser-uploads"/"managed") never reaches
// ingestion's mount registry (internal/ingestion/handler.go resolves it
// before ever calling MountRegistry.Resolve), so a real deployment's worker
// mount manifest need not describe it either -- proving that here with a
// registry that resolves nothing is the point, not an oversight.
type upl1NoMounts struct{}

func (upl1NoMounts) Resolve(string, string) (string, bool) { return "", false }

func upl1RegisterRequest() registration.RegisterRequest {
	return registration.RegisterRequest{
		Name: "\u041c\u043e\u0438 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b", RootAlias: "browser-uploads", RootIdentity: "managed",
		RelativeRoot: "documents", Kind: "documents", Recursive: true,
		IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
		OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN", "PDF", "DOCX", "PPTX", "XLSX", "HTML", "CSV"},
	}
}

func TestUploadDocumentEndToEndCitation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)

	registered, err := service.Register(ctx, regOwnerAccess("req_upl1_register"), upl1RegisterRequest())
	if err != nil {
		t.Fatalf("register documents source: %v (code=%s)", err, registration.CodeOf(err))
	}
	scopeID := registered.SourceScopeID

	if _, err := admin.Exec(ctx, `UPDATE public.source_connection_trust_projection p
		SET status='VERIFIED' WHERE p.organization_id=$1 AND p.trust_record_id=(
			SELECT trust_record_id FROM public.source_connection_revision
			WHERE organization_id=$1 AND connection_id=$2 AND revision=1)`,
		regOrg, registered.ConnectionID); err != nil {
		t.Fatalf("verify trust: %v", err)
	}

	fixture := seedRegistrationWorkspaceBinding(t, ctx, admin, scopeID, registered.ScopeConfigHash, mustID(t, "binding"))
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, fixture, "upl1-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_upl1_confirm"),
		confirmRuntimeRequest(fixture, grant, "upl1-confirm")); err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	if _, err := service.Activate(ctx, regOwnerAccess("req_upl1_activate"), registration.ActivateRequest{
		IdempotencyKey: "upl1-activate-1", SourceScopeID: scopeID,
	}); err != nil {
		t.Fatalf("activate: %v (code=%s)", err, registration.CodeOf(err))
	}

	// The owner drags one file onto the "documents" source from the browser --
	// no root_alias/root_identity/contract typed anywhere by them.
	content := "\u0428\u0442\u0440\u0430\u0444 \u0437\u0430 \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u043a\u0443 \u0441\u043e\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442 15000 \u0440\u0443\u0431\u043b\u0435\u0439.\n\u0412\u0442\u043e\u0440\u0430\u044f \u0441\u0442\u0440\u043e\u043a\u0430 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430.\n"
	uploadResult, err := service.UploadDocuments(ctx, regOwnerAccess("req_upl1_upload"), registration.UploadDocumentsRequest{
		SourceScopeID: scopeID,
		Files:         []registration.UploadFile{{Name: "penalty.txt", Content: []byte(content)}},
	})
	if err != nil {
		t.Fatalf("upload documents: %v (code=%s)", err, registration.CodeOf(err))
	}
	if uploadResult.ConnectionID != registered.ConnectionID || len(uploadResult.Uploaded) != 1 ||
		uploadResult.Uploaded[0].ObjectKey != "penalty.txt" || uploadResult.Uploaded[0].Version != 1 {
		t.Fatalf("upload result: %#v", uploadResult)
	}

	t.Run("a non-owner cannot upload", func(t *testing.T) {
		_, err := service.UploadDocuments(ctx,
			database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_upl1_upload_viewer"},
			registration.UploadDocumentsRequest{SourceScopeID: scopeID, Files: []registration.UploadFile{{Name: "x.txt", Content: []byte("hi")}}})
		if registration.CodeOf(err) != registration.CodeDenied {
			t.Fatalf("viewer upload: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	// The worker's SOURCE_SCOPE_SYNC reads public.source_uploaded_document
	// instead of a mounted directory (the reserved root_alias/root_identity
	// sentinel), never touching the mount registry.
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, upl1NoMounts{}, regWorkerID, time.Now, ids.New)
	access := workerAccess(t, regOrg)
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": scopeID}, IdempotencyKey: "upl1-sync-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatalf("enqueue sync: %v", err)
	}
	claimed, ok, err := queue.Claim(ctx, access, regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim sync: %v ok=%v", err, ok)
	}
	if err := handler.Handle(ctx, access, claimed); err != nil {
		t.Fatalf("handle sync: %v (code=%s)", err, ingestion.CodeOf(err))
	}

	var objects, fragments int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1 AND connection_id=$2`,
		regOrg, registered.ConnectionID).Scan(&objects); err != nil || objects != 1 {
		t.Fatalf("objects=%d err=%v", objects, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment f
		JOIN public.source_version v ON v.organization_id=f.organization_id AND v.id=f.source_version_id
		JOIN public.source_object o ON o.organization_id=v.organization_id AND o.id=v.source_object_id
		WHERE f.organization_id=$1 AND o.connection_id=$2`, regOrg, registered.ConnectionID).Scan(&fragments); err != nil || fragments == 0 {
		t.Fatalf("fragments=%d err=%v", fragments, err)
	}

	t.Run("re-upload of the same name is a new version, not a duplicate object", func(t *testing.T) {
		second, err := service.UploadDocuments(ctx, regOwnerAccess("req_upl1_upload_2"), registration.UploadDocumentsRequest{
			SourceScopeID: scopeID,
			Files:         []registration.UploadFile{{Name: "penalty.txt", Content: []byte(content + "third line.\n")}},
		})
		if err != nil {
			t.Fatalf("re-upload: %v", err)
		}
		if second.Uploaded[0].Version != 2 {
			t.Fatalf("re-upload version=%d, want 2", second.Uploaded[0].Version)
		}
		var afterUpload int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_uploaded_document WHERE organization_id=$1 AND connection_id=$2`,
			regOrg, registered.ConnectionID).Scan(&afterUpload); err != nil || afterUpload != 1 {
			t.Fatalf("uploaded rows=%d err=%v, want exactly 1 (same object key, new version)", afterUpload, err)
		}
	})

	// The whole point of UPL-1: a browser upload becomes a real, citable
	// Evidence fragment the product Question authority can answer from.
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
	answer, err := questions.Create(ctx, regOwnerAccess("req_upl1_question"), question.CreateRequest{
		WorkspaceID: fixture.workspaceID, Question: "\u0428\u0442\u0440\u0430\u0444 \u0437\u0430 \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u043a\u0443 \u0441\u043e\u0441\u0442\u0430\u0432\u043b\u044f\u0435\u0442 15000 \u0440\u0443\u0431\u043b\u0435\u0439?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("question over uploaded document: %v (code=%s)", err, question.CodeOf(err))
	}
	if answer.ResultStatus != "COMPLETED" || len(answer.Citations) == 0 {
		t.Fatalf("uploaded-document question answer=%q status=%s citations=%d", answer.Answer, answer.ResultStatus, len(answer.Citations))
	}
	if !strings.Contains(answer.Answer, "15000") {
		t.Fatalf("answer does not quote the uploaded document: %q", answer.Answer)
	}
}
