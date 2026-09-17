package postgres_test

// ADR-0076 protected answer-document amendment layer on the real PostgreSQL.
//
// Published answer versions are immutable: an amendment is a separate
// superseding version inserted only through the owner path with an exact
// hash-chain link and a closed amendment class, and every successful amendment
// commits one answer.document.amended audit event in the same transaction.
// The open path re-checks fragment access on every open: a version whose cited
// fragment was purged or whose source scope left the workspace does not open
// as proof, a retracted/redacted statement is never published, and a foreign
// tenant answers the same closed denial.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	answerrepository "knowvault.local/verified-workspace/internal/answer/repository"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
)

const (
	ansDocOrg = s1dOrg
	ansDocWS  = s1dWorkspace
	ansDocID  = "ansdoc_s1d"
)

// answerManifestHash derives a deterministic per-version manifest hash so the
// hash chain the repository asserts is exact and readable.
func answerManifestHash(version int64) string {
	return "sha256:" + strings.Repeat(string(rune('0')+rune(version)), 64)
}

// answerDocumentFixture seeds the S1d catalog with one active Evidence version
// and opens the answer repository bound to the runtime application role.
func answerDocumentFixture(t *testing.T) (context.Context, *pgxpool.Pool, *answerrepository.Store, string, []fragmentRow, *purge.Purger) {
	t.Helper()
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}
	store := newAnswerRepository(t, ctx)
	return ctx, admin, store, versionID, fragments, purger
}

func newAnswerRepository(t *testing.T, ctx context.Context) *answerrepository.Store {
	t.Helper()
	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	answerStore, err := answerrepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create answer repository: %v", err)
	}
	return answerStore
}

// amendAnswer builds one repository amendment call. The amendment shape is
// derived from the version number: version 1 is the initial publication,
// version >= 2 is a superseding amendment chained to the previous version.
func amendAnswer(version int64, fragmentID string) answerrepository.AmendDocumentRequest {
	request := answerrepository.AmendDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID,
		Version:          version,
		ManifestHash:     answerManifestHash(version),
		ActorPrincipalID: s1dOwner,
		RequestID:        fmt.Sprintf("req_ans_%d", version),
		AuditEventID:     fmt.Sprintf("audit_ans_%d", version),
		Citations:        []answerrepository.CitationRef{{Number: 1, EvidenceFragmentID: fragmentID}},
	}
	if version >= 2 {
		request.PreviousVersionHash = pointerToString(answerManifestHash(version - 1))
		request.AmendmentClass = pointerToString(string(answerrepository.AmendmentSupersede))
		request.AmendmentReason = pointerToString("\u0421\u0432\u0435\u0436\u0430\u044f \u0432\u0435\u0440\u0441\u0438\u044f \u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u0438.")
	}
	return request
}

func pointerToString(value string) *string { return &value }

// answerServiceAccess builds the service-to-service read context the runtime
// open uses: a service principal that is not a workspace member.
func answerServiceAccess(t *testing.T, organizationID, requestID string) database.AccessContext {
	t.Helper()
	access, err := database.NewOIDCServiceAccess(organizationID, requestID)
	if err != nil {
		t.Fatalf("create answer service access: %v", err)
	}
	return access
}

func answerAuditCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id = $1 AND action = 'answer.document.amended'`, org).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func answerVersionCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.answer_document_version
		WHERE organization_id = $1 AND answer_document_id = $2`, org, ansDocID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// TestAnswerDocumentPublishAndSupersedeWithAudit proves the publication path:
// the initial version opens as proof, a superseding version replaces it as the
// latest provable statement, and every accepted amendment commits exactly one
// answer.document.amended audit event.
func TestAnswerDocumentPublishAndSupersedeWithAudit(t *testing.T) {
	ctx, admin, store, _, fragments, _ := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	outcome, err := store.OpenDocument(ctx, answerServiceAccess(t, ansDocOrg, "req_open_001"), answerrepository.OpenDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_001",
	})
	if err != nil {
		t.Fatalf("open v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if outcome.Version != 1 || outcome.AmendmentClass != nil || outcome.ManifestHash != answerManifestHash(1) {
		t.Fatalf("open v1 outcome=%+v, want version 1 without amendment class", outcome)
	}

	if err := store.AmendDocument(ctx, amendAnswer(2, fragments[0].id)); err != nil {
		t.Fatalf("supersede v2: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	outcome, err = store.OpenDocument(ctx, answerServiceAccess(t, ansDocOrg, "req_open_002"), answerrepository.OpenDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_002",
	})
	if err != nil {
		t.Fatalf("open v2: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if outcome.Version != 2 || outcome.AmendmentClass == nil || *outcome.AmendmentClass != "SUPERSEDE" {
		t.Fatalf("open v2 outcome=%+v, want version 2 SUPERSEDE", outcome)
	}

	if count := answerVersionCount(t, ctx, admin, ansDocOrg); count != 2 {
		t.Fatalf("version count=%d, want 2", count)
	}
	if count := answerAuditCount(t, ctx, admin, ansDocOrg); count != 2 {
		t.Fatalf("amendment audit events=%d, want 2", count)
	}

	// The latest amendment event must carry the ADR-0076 projection itself:
	// the server-owned version, the closed amendment class and the workspace,
	// never the amended content.
	var latestMetadata []byte
	var latestWorkspaceID *string
	if err := admin.QueryRow(ctx, `SELECT metadata_json, workspace_id FROM public.audit_event
		WHERE organization_id = $1 AND action = 'answer.document.amended'
		ORDER BY sequence DESC LIMIT 1`, ansDocOrg).Scan(&latestMetadata, &latestWorkspaceID); err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(latestMetadata, &projection); err != nil {
		t.Fatalf("decode amendment event metadata: %v", err)
	}
	if projection["answer_document_version"] != float64(2) || projection["amendment_class"] != "SUPERSEDE" {
		t.Fatalf("amendment event projection=%v, want version 2 SUPERSEDE", projection)
	}
	if latestWorkspaceID == nil || *latestWorkspaceID != ansDocWS {
		t.Fatalf("amendment event workspace=%v, want %q", latestWorkspaceID, ansDocWS)
	}
}

// TestAnswerDocumentVersionImmutability proves no UPDATE or DELETE may touch a
// published version, even from a privileged database role: the trigger fence
// answers the closed immutability violation before the row changes.
func TestAnswerDocumentVersionImmutability(t *testing.T) {
	ctx, admin, store, _, fragments, _ := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := admin.Exec(ctx, `UPDATE public.answer_document_version
		SET manifest_hash = $1 WHERE organization_id = $2 AND answer_document_id = $3`,
		answerManifestHash(9), ansDocOrg, ansDocID); err == nil {
		t.Fatal("a published version accepted UPDATE")
	} else {
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "55000" {
			t.Fatalf("UPDATE rejected for the wrong reason: %v", err)
		}
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.answer_document_version
		WHERE organization_id = $1 AND answer_document_id = $2`, ansDocOrg, ansDocID); err == nil {
		t.Fatal("a published version accepted DELETE")
	} else {
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "55000" {
			t.Fatalf("DELETE rejected for the wrong reason: %v", err)
		}
	}
	var manifestHash string
	if err := admin.QueryRow(ctx, `SELECT manifest_hash FROM public.answer_document_version
		WHERE organization_id = $1 AND answer_document_id = $2`, ansDocOrg, ansDocID).Scan(&manifestHash); err != nil {
		t.Fatal(err)
	}
	if manifestHash != answerManifestHash(1) {
		t.Fatalf("manifest hash changed to %q despite the immutability fence", manifestHash)
	}
}

// TestAnswerDocumentAmendmentOwnerPathRequired proves a workspace member who is
// not the owner cannot amend the document, that a rejected amendment leaves no
// version and no audit event behind, and that a database role outside the
// runtime application cannot insert a version at all.
func TestAnswerDocumentAmendmentOwnerPathRequired(t *testing.T) {
	ctx, admin, store, _, fragments, _ := answerDocumentFixture(t)

	request := amendAnswer(1, fragments[0].id)
	request.ActorPrincipalID = s1dViewer
	if err := store.AmendDocument(ctx, request); answerrepository.CodeOf(err) != answerrepository.CodeNotOwner {
		t.Fatalf("viewer amendment: err=%v code=%q, want CodeNotOwner", err, answerrepository.CodeOf(err))
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.answer_document_version
		(organization_id, workspace_id, answer_document_id, version, manifest_hash, actor_principal_id, request_id)
		VALUES ($1, $2, $3, 1, $4, $5, $6)`,
		ansDocOrg, ansDocWS, ansDocID, answerManifestHash(1), s1dOwner, "req_ans_direct"); err == nil {
		t.Fatal("a database role outside the runtime application inserted a version")
	} else {
		var pgError *pgconn.PgError
		if !errors.As(err, &pgError) || pgError.Code != "42501" {
			t.Fatalf("direct INSERT rejected for the wrong reason: %v", err)
		}
	}
	if count := answerVersionCount(t, ctx, admin, ansDocOrg); count != 0 {
		t.Fatalf("rejected amendments left %d versions behind", count)
	}
	if count := answerAuditCount(t, ctx, admin, ansDocOrg); count != 0 {
		t.Fatalf("rejected amendments left %d audit events behind", count)
	}
}

// TestAnswerDocumentAmendmentRejectsChainBreakAndSkip proves a superseding
// version must link to the exact published previous hash and must be the exact
// successor number: a wrong hash and a version skip both answer the closed
// amendment rejection and leave only the published version behind.
func TestAnswerDocumentAmendmentRejectsChainBreakAndSkip(t *testing.T) {
	ctx, admin, store, _, fragments, _ := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}

	broken := amendAnswer(2, fragments[0].id)
	broken.PreviousVersionHash = pointerToString(answerManifestHash(9))
	if err := store.AmendDocument(ctx, broken); answerrepository.CodeOf(err) != answerrepository.CodeAmendmentRejected {
		t.Fatalf("chain break: err=%v code=%q, want CodeAmendmentRejected", err, answerrepository.CodeOf(err))
	}
	skipped := amendAnswer(3, fragments[0].id)
	skipped.PreviousVersionHash = pointerToString(answerManifestHash(1))
	if err := store.AmendDocument(ctx, skipped); answerrepository.CodeOf(err) != answerrepository.CodeAmendmentRejected {
		t.Fatalf("version skip: err=%v code=%q, want CodeAmendmentRejected", err, answerrepository.CodeOf(err))
	}
	if count := answerVersionCount(t, ctx, admin, ansDocOrg); count != 1 {
		t.Fatalf("rejected amendments left %d versions behind", count)
	}
	if count := answerAuditCount(t, ctx, admin, ansDocOrg); count != 1 {
		t.Fatalf("rejected amendments left %d audit events behind", count)
	}
}

// TestAnswerDocumentRetractRedactCloseOpen proves a retracted or redacted
// statement is never published as proof while the amendment chain stays alive:
// the latest superseding version reopens the document.
func TestAnswerDocumentRetractRedactCloseOpen(t *testing.T) {
	ctx, _, store, _, fragments, _ := answerDocumentFixture(t)

	openRequest := answerrepository.OpenDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_001",
	}
	openAccess := answerServiceAccess(t, ansDocOrg, "req_open_001")
	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	retract := amendAnswer(2, fragments[0].id)
	retract.AmendmentClass = pointerToString(string(answerrepository.AmendmentRetract))
	retract.AmendmentReason = pointerToString("\u0421\u043d\u044f\u0442\u0438\u0435 \u043f\u0443\u0431\u043b\u0438\u043a\u0430\u0446\u0438\u0438.")
	if err := store.AmendDocument(ctx, retract); err != nil {
		t.Fatalf("retract v2: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); answerrepository.CodeOf(err) != answerrepository.CodeDenied {
		t.Fatalf("open after retract: err=%v code=%q, want CodeDenied", err, answerrepository.CodeOf(err))
	}
	redact := amendAnswer(3, fragments[0].id)
	redact.AmendmentClass = pointerToString(string(answerrepository.AmendmentRedact))
	redact.AmendmentReason = pointerToString("\u0421\u043e\u043a\u0440\u044b\u0442\u0438\u0435 \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0430.")
	if err := store.AmendDocument(ctx, redact); err != nil {
		t.Fatalf("redact v3: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); answerrepository.CodeOf(err) != answerrepository.CodeDenied {
		t.Fatalf("open after redact: err=%v code=%q, want CodeDenied", err, answerrepository.CodeOf(err))
	}
	if err := store.AmendDocument(ctx, amendAnswer(4, fragments[0].id)); err != nil {
		t.Fatalf("supersede v4: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	outcome, err := store.OpenDocument(ctx, openAccess, openRequest)
	if err != nil {
		t.Fatalf("open v4: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if outcome.Version != 4 || outcome.AmendmentClass == nil || *outcome.AmendmentClass != "SUPERSEDE" {
		t.Fatalf("open v4 outcome=%+v, want version 4 SUPERSEDE", outcome)
	}
}

// TestAnswerDocumentOpenRechecksRetentionPurge proves the open path re-checks
// fragment access on every open: once the cited fragment's retention enters a
// purge state, the published version no longer opens as proof.
func TestAnswerDocumentOpenRechecksRetentionPurge(t *testing.T) {
	ctx, _, store, versionID, fragments, purger := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	openRequest := answerrepository.OpenDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_001",
	}
	openAccess := answerServiceAccess(t, ansDocOrg, "req_open_001")
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); err != nil {
		t.Fatalf("open before purge: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin purge: %v", err)
	}
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); answerrepository.CodeOf(err) != answerrepository.CodeDenied {
		t.Fatalf("open after purge: err=%v code=%q, want CodeDenied", err, answerrepository.CodeOf(err))
	}
}

// TestAnswerDocumentOpenRechecksScopeUnbinding proves the open path denies a
// version whose cited source scope left the workspace, even though the
// fragment itself is intact.
func TestAnswerDocumentOpenRechecksScopeUnbinding(t *testing.T) {
	ctx, admin, store, versionID, fragments, _ := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	openRequest := answerrepository.OpenDocumentRequest{
		OrganizationID: ansDocOrg, WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_001",
	}
	openAccess := answerServiceAccess(t, ansDocOrg, "req_open_001")
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); err != nil {
		t.Fatalf("open before unbinding: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_object_scope
		SET membership_state = 'REMOVED', removed_at = now()
		WHERE organization_id = $1
		  AND source_object_id = (SELECT source_object_id FROM public.source_version
		                          WHERE organization_id = $1 AND id = $2)
		  AND membership_state = 'ACTIVE'`, s1dOrg, versionID); err != nil {
		t.Fatalf("remove scope membership: %v", err)
	}
	if _, err := store.OpenDocument(ctx, openAccess, openRequest); answerrepository.CodeOf(err) != answerrepository.CodeDenied {
		t.Fatalf("open after unbinding: err=%v code=%q, want CodeDenied", err, answerrepository.CodeOf(err))
	}
}

// TestAnswerDocumentOpenCrossTenantDenied proves the open path answers the same
// closed denial for a foreign tenant: no version of another organization is
// ever visible, with no distinction between missing and forbidden.
func TestAnswerDocumentOpenCrossTenantDenied(t *testing.T) {
	ctx, _, store, _, fragments, _ := answerDocumentFixture(t)

	if err := store.AmendDocument(ctx, amendAnswer(1, fragments[0].id)); err != nil {
		t.Fatalf("publish v1: err=%v code=%q", err, answerrepository.CodeOf(err))
	}
	if _, err := store.OpenDocument(ctx, answerServiceAccess(t, "org_other", "req_open_001"), answerrepository.OpenDocumentRequest{
		OrganizationID: "org_other", WorkspaceID: ansDocWS, AnswerDocumentID: ansDocID, RequestID: "req_open_001",
	}); answerrepository.CodeOf(err) != answerrepository.CodeDenied {
		t.Fatalf("cross-tenant open: err=%v code=%q, want CodeDenied", err, answerrepository.CodeOf(err))
	}
}
