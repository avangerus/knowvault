package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const s1dWorkspace = "ws_s1d"
const s1dViewer = "usr_s1d_viewer"

// TestS1dAuthorizedEvidenceRead proves the full positive authorized path
// (workspace membership -> current binding -> access mode -> live confirmation ->
// current SourceVersion -> active Extraction -> owner-bound Evidence -> plaintext
// only to the permitted viewer) and the deny matrix, every deny returning the
// identical not-found with no existence oracle.
func TestS1dAuthorizedEvidenceRead(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "line one\nline two\n"
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), content)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	scopeConfigHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)

	// Full WORKSPACE_MANAGED authority chain, real authority model: the seed mints
	// the actor grant and the confirmation through the production repository
	// (correct command receipts and canonical projections), bound to the real S1d
	// scope. The chain must exist before the worker claims the sync: the
	// claim-time liveness re-check (000018 s5) demands a live confirmation on the
	// exact tuple.
	fixture := seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, scopeConfigHash)
	authorityStore := newAuthorityRuntime(t, ctx)
	// The revocation under test operates on the seeded confirmation: resolve its
	// canonical id/hash from the database, the repository layer only trusts the
	// stored projection.
	var confirmationID, confirmationHash string
	if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_source_id=$2`, s1dOrg, fixture.workspaceSourceID).
		Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatalf("resolve seeded confirmation: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "sync")

	_, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	fragmentID := fragments[0].id

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_view"}

	// Positive: the authorized member reads the exact canonical Evidence bytes
	// and the non-content provenance chain (ADR-0073 §1.2): immutable catalog
	// identifiers that place the fragment in the source lineage without adding
	// any source content to the permitted surface.
	t.Run("authorized member opens Evidence", func(t *testing.T) {
		fragment, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID)
		if err != nil {
			t.Fatalf("authorized read failed: %v", err)
		}
		canonical, _ := canon.Canonicalize([]byte(content))
		want, _ := canon.Slice(canonical, 1, 2)
		if string(fragment.Text) != string(want) {
			t.Fatalf("Evidence text = %q, want %q", fragment.Text, want)
		}
		if len(fragment.Anchor) == 0 {
			t.Fatal("anchor not returned")
		}
		if fragment.ExtractionID != extractionID || fragment.SourceVersionID != versionID {
			t.Fatalf("provenance extraction/version = %q/%q, want %q/%q",
				fragment.ExtractionID, fragment.SourceVersionID, extractionID, versionID)
		}
		if fragment.Ordinal != 1 || fragment.SourceObjectID == "" || fragment.ConnectionID == "" {
			t.Fatalf("provenance fields incomplete: %+v", fragment)
		}
		var externalVersionKey, contentHash string
		if err := admin.QueryRow(ctx, `SELECT external_version_key, content_hash FROM public.source_version
			WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).
			Scan(&externalVersionKey, &contentHash); err != nil {
			t.Fatal(err)
		}
		if fragment.ExternalVersionKey != externalVersionKey || fragment.ContentHash != contentHash {
			t.Fatalf("provenance version key/hash = %q/%q, want %q/%q",
				fragment.ExternalVersionKey, fragment.ContentHash, externalVersionKey, contentHash)
		}
		if fragment.ObservedAt.IsZero() {
			t.Fatal("provenance observed_at is zero")
		}
		if !fragment.IsCurrentVersion {
			t.Fatal("authorized current version was reported as historical")
		}
	})

	assertDenied := func(t *testing.T, access database.AccessContext, workspace, fragment, label string) {
		t.Helper()
		if _, err := viewer.Read(ctx, access, workspace, fragment); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("%s: err=%v, want ErrNotFound", label, err)
		}
	}

	// Deny, no oracle: a principal who is not a workspace member (this also covers
	// "knows the Evidence ID but has no right").
	t.Run("non-member is denied", func(t *testing.T) {
		outsider := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: "usr_s1d_nonmember", RequestID: "req"}
		assertDenied(t, outsider, s1dWorkspace, fragmentID, "non-member")
	})

	// Deny: another tenant.
	t.Run("cross-tenant is denied", func(t *testing.T) {
		other := database.AccessContext{OrganizationID: "org_other", PrincipalID: "usr_x", RequestID: "req"}
		assertDenied(t, other, s1dWorkspace, fragmentID, "cross-tenant")
	})

	// Deny: a stale workspace revision (confirmation is bound to revision 1).
	t.Run("stale workspace revision is denied", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.workspace SET current_revision=2 WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
			t.Fatal(err)
		}
		assertDenied(t, viewerAccess, s1dWorkspace, fragmentID, "stale-revision")
		if _, err := admin.Exec(ctx, `UPDATE public.workspace SET current_revision=1 WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
			t.Fatal(err)
		}
	})

	// Deny: an inactive (non-queryable) SourceVersion.
	t.Run("inactive version is denied", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
			t.Fatal(err)
		}
		assertDenied(t, viewerAccess, s1dWorkspace, fragmentID, "inactive-version")
		if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
			t.Fatal(err)
		}
	})

	// Deny: a removed workspace member.
	t.Run("removed member is denied", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.workspace_member SET removed_at=now(), valid_to_revision=2
			WHERE organization_id=$1 AND workspace_id=$2 AND principal_id=$3`, s1dOrg, s1dWorkspace, s1dViewer); err != nil {
			t.Fatal(err)
		}
		assertDenied(t, viewerAccess, s1dWorkspace, fragmentID, "removed-member")
		if _, err := admin.Exec(ctx, `UPDATE public.workspace_member SET removed_at=NULL, valid_to_revision=NULL
			WHERE organization_id=$1 AND workspace_id=$2 AND principal_id=$3`, s1dOrg, s1dWorkspace, s1dViewer); err != nil {
			t.Fatal(err)
		}
	})

	// Deny: revoking the confirmation removes source authority (terminal), through
	// the real authority runtime so the revocation carries its command receipt.
	t.Run("revoked confirmation is denied", func(t *testing.T) {
		if _, err := authorityStore.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_s1d_confirm_revoke"),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey: authorityIdempotencyKey("s1d-confirm-revoke"), OrganizationID: s1dOrg,
				WorkspaceID: s1dWorkspace, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
				ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("revoke confirmation: %v", err)
		}
		assertDenied(t, viewerAccess, s1dWorkspace, fragmentID, "revoked-confirmation")
	})
}
