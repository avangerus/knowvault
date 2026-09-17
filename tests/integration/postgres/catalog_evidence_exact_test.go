package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const exactEvidencePath = "projects/alpha/exact-history.txt"

type exactEvidenceFixture struct {
	ctx       context.Context
	admin     *pgxpool.Pool
	target    string
	handler   *ingestion.Handler
	queue     *jobs.Queue
	viewer    *evidence.Viewer
	access    database.AccessContext
	authority authorityOpsFixture
}

func newExactEvidenceFixture(t *testing.T, content string) *exactEvidenceFixture {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, filepath.Base(exactEvidencePath))
	writeS1dFile(t, target, content)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	scopeHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	authority := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, scopeHash, 1, neighborsStableWorkspaceSourceID(s1dOrg, s1dWorkspace, s1dScopeID),
		"grant_s1d_admin", "confirmation_s1d_admin", true)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "exact-v1")

	viewer, err := evidence.NewViewer(openStore(t, ctx, appRole, "knowvault_app"), codec)
	if err != nil {
		t.Fatal(err)
	}
	return &exactEvidenceFixture{
		ctx: ctx, admin: admin, target: target, handler: handler, queue: queue, viewer: viewer,
		access:    database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_exact_history"},
		authority: authority,
	}
}

func assertExactReadDenied(t *testing.T, fixture *exactEvidenceFixture, access database.AccessContext, workspaceID, fragmentID, versionID, label string) {
	t.Helper()
	fragment, err := fixture.viewer.ReadExactVersion(fixture.ctx, access, workspaceID, fragmentID, versionID)
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("%s exact fragment read error=%v, want ErrNotFound", label, err)
	}
	if fragment.FragmentID != "" || fragment.SourceVersionID != "" || fragment.ExtractionID != "" ||
		fragment.SourcePath != "" || len(fragment.Text) != 0 || len(fragment.Anchor) != 0 {
		t.Fatalf("%s exact fragment denial disclosed content or provenance: %+v", label, fragment)
	}
	whole, err := fixture.viewer.ReadObjectExactVersion(fixture.ctx, access, workspaceID, fragmentID, versionID)
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("%s exact object read error=%v, want ErrNotFound", label, err)
	}
	if whole.Fragment.FragmentID != "" || whole.Fragment.SourceVersionID != "" || whole.Fragment.ExtractionID != "" ||
		whole.Fragment.SourcePath != "" || len(whole.Fragment.Text) != 0 || len(whole.Text) != 0 ||
		whole.FragmentCount != 0 || len(whole.Fragments) != 0 {
		t.Fatalf("%s exact object denial disclosed content or provenance: %+v", label, whole)
	}
}

func assertCurrentReadDenied(t *testing.T, fixture *exactEvidenceFixture, workspaceID, fragmentID, label string) {
	t.Helper()
	fragment, err := fixture.viewer.Read(fixture.ctx, fixture.access, workspaceID, fragmentID)
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("%s current fragment read error=%v, want ErrNotFound", label, err)
	}
	if len(fragment.Text) != 0 || len(fragment.Anchor) != 0 || fragment.SourcePath != "" {
		t.Fatalf("%s current fragment denial disclosed content: %+v", label, fragment)
	}
	whole, err := fixture.viewer.ReadObject(fixture.ctx, fixture.access, workspaceID, fragmentID)
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("%s current object read error=%v, want ErrNotFound", label, err)
	}
	if len(whole.Text) != 0 || whole.FragmentCount != 0 || whole.Fragment.FragmentID != "" {
		t.Fatalf("%s current object denial disclosed content: %+v", label, whole)
	}
}

func assertExactArtifactReadersFailClosed(t *testing.T, fixture *exactEvidenceFixture, fragmentID, wrongVersionID string) {
	t.Helper()
	store := openStore(t, fixture.ctx, appRole, "knowvault_app")
	readers := [...]string{
		"app.evidence_fragment_read_exact_normalized_text",
		"app.evidence_fragment_read_exact_anchor",
		"app.evidence_fragment_read_exact_metadata",
	}
	err := store.Read(fixture.ctx, fixture.access, func(ctx context.Context, tx database.Transaction) error {
		var gucsAbsent bool
		if err := tx.QueryRow(ctx, `SELECT current_setting('app.workspace_id', true) IS NULL
			AND current_setting('app.evidence_source_version_id', true) IS NULL`).Scan(&gucsAbsent); err != nil {
			return err
		}
		if !gucsAbsent {
			return fmt.Errorf("exact reader test connection unexpectedly has workspace/version GUCs")
		}
		assertNoArtifacts := func(label string) error {
			for _, reader := range readers {
				var count int64
				query := fmt.Sprintf("SELECT count(*) FROM %s($1)", reader)
				if err := tx.QueryRow(ctx, query, fragmentID).Scan(&count); err != nil {
					return fmt.Errorf("%s %s: %w", label, reader, err)
				}
				if count != 0 {
					return fmt.Errorf("%s %s returned %d artifact rows", label, reader, count)
				}
			}
			return nil
		}
		if err := assertNoArtifacts("unset exact GUCs"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, s1dWorkspace); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.evidence_source_version_id', $1, true)`, wrongVersionID); err != nil {
			return err
		}
		return assertNoArtifacts("wrong expected version GUC")
	})
	if err != nil {
		t.Fatalf("exact artifact readers did not fail closed: %v", err)
	}
}

func assertSameExactFragment(t *testing.T, before, after evidence.Fragment, wantCurrent bool) {
	t.Helper()
	if before.FragmentID != after.FragmentID || before.SourceVersionID != after.SourceVersionID ||
		before.ExtractionID != after.ExtractionID || before.SourceObjectID != after.SourceObjectID ||
		before.ConnectionID != after.ConnectionID || before.SourcePath == "" || before.SourcePath != after.SourcePath ||
		before.ExternalVersionKey != after.ExternalVersionKey || before.ContentHash != after.ContentHash ||
		before.EvidenceTextHash != after.EvidenceTextHash || before.AnchorHash != after.AnchorHash ||
		before.Ordinal != after.Ordinal || before.CanonicalFormat != after.CanonicalFormat ||
		before.ParserProfileRevision != after.ParserProfileRevision || !before.ObservedAt.Equal(after.ObservedAt) ||
		string(before.Text) != string(after.Text) || string(before.Anchor) != string(after.Anchor) ||
		after.IsCurrentVersion != wantCurrent {
		t.Fatalf("exact historical tuple changed: before=%+v after=%+v wantCurrent=%v", before, after, wantCurrent)
	}
}

func assertExactObjectMatchesExtraction(t *testing.T, whole evidence.WholeObject, sourceVersionID, extractionID, anchorID string,
	expectedText []byte, extractionFragments []fragmentRow) {
	t.Helper()
	if whole.Fragment.FragmentID != anchorID || whole.Fragment.SourceVersionID != sourceVersionID ||
		whole.Fragment.ExtractionID != extractionID {
		t.Fatalf("exact object anchor tuple=%+v, want fragment/version/extraction=%s/%s/%s",
			whole.Fragment, anchorID, sourceVersionID, extractionID)
	}
	if string(whole.Text) != string(expectedText) {
		t.Fatalf("exact object assembled %d bytes, want retained baseline %d bytes", len(whole.Text), len(expectedText))
	}
	if whole.FragmentCount != int64(len(extractionFragments)) || len(whole.Fragments) != len(extractionFragments) {
		t.Fatalf("exact object contains %d spans / count %d, want extraction spans %d",
			len(whole.Fragments), whole.FragmentCount, len(extractionFragments))
	}
	for index, span := range whole.Fragments {
		want := extractionFragments[index]
		if span.FragmentID != want.id || span.Ordinal != int64(want.ordinal) {
			t.Fatalf("exact object span %d=%+v, want extraction fragment %s ordinal %d",
				index, span, want.id, want.ordinal)
		}
	}
}

// Canonical fidelity is deliberately independent of historical authorization.
// It remains a release requirement even if the retained-version matrix passes.
// In particular, passing history stability must not hide lost LF separators.
func TestEvidenceExactVersionCanonicalTextFidelity(t *testing.T) {
	input := strings.Repeat("retainedneedle historical source line 0123456789\n", 1000)
	canonical, err := canon.Canonicalize([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	fixture := newExactEvidenceFixture(t, input)
	_, versionID, extractionID := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	fragments := s1dFragments(t, fixture.ctx, fixture.admin, extractionID)
	if len(fragments) < 3 {
		t.Fatal("canonical fidelity fixture must cross multiple fragments")
	}
	anchorID := fragments[len(fragments)/2].id
	for _, mode := range []string{"current", "exact"} {
		t.Run(mode, func(t *testing.T) {
			var whole evidence.WholeObject
			var readErr error
			if mode == "current" {
				whole, readErr = fixture.viewer.ReadObject(fixture.ctx, fixture.access, s1dWorkspace, anchorID)
			} else {
				whole, readErr = fixture.viewer.ReadObjectExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, versionID)
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(whole.Text) != string(canonical) {
				t.Fatalf("whole canonical body: got %d bytes, want %d (source whitespace must be preserved)", len(whole.Text), len(canonical))
			}
		})
	}
}

func TestEvidenceExactVersionReadRetainsHistoricalVersionAndExtraction(t *testing.T) {
	v1Text := strings.Repeat("retainedneedle historical source line 0123456789\n", 1000)
	v2Text := strings.Repeat("currentneedle replacement source line 9876543210\n", 1000)
	fixture := newExactEvidenceFixture(t, v1Text)

	objectID, v1ID, v1Extraction := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	v1Fragments := s1dFragments(t, fixture.ctx, fixture.admin, v1Extraction)
	if len(v1Fragments) < 3 {
		t.Fatalf("initial extraction has %d fragments, want multiple fragments", len(v1Fragments))
	}
	anchorID := v1Fragments[len(v1Fragments)/2].id
	// This test checks stability of the already published representation.
	// Byte equality to the original canonical input is a separate test above.
	retainedBaseline, err := fixture.viewer.ReadObject(fixture.ctx, fixture.access, s1dWorkspace, anchorID)
	if err != nil {
		t.Fatal(err)
	}
	retainedV1 := append([]byte(nil), retainedBaseline.Text...)
	initial, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact current v1 read: %v", err)
	}
	if !initial.IsCurrentVersion || initial.SourcePath == "" || initial.ContentHash == "" || initial.ExternalVersionKey == "" {
		t.Fatalf("initial exact read omitted current catalog provenance: %+v", initial)
	}
	initialWhole, err := fixture.viewer.ReadObjectExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact current v1 whole-object read: %v", err)
	}
	assertExactObjectMatchesExtraction(t, initialWhole, v1ID, v1Extraction, anchorID, retainedV1, v1Fragments)

	// Re-extraction switches the active extraction on the same immutable SourceVersion.
	runSync(t, fixture.ctx, fixture.handler.WithParserRevision("text-v1-b"), fixture.queue,
		workerAccess(t, s1dOrg), "exact-reextract-v1")
	activeObject, activeVersion, activeExtraction := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	if activeObject != objectID || activeVersion != v1ID || activeExtraction == v1Extraction {
		t.Fatalf("re-extraction did not switch only the active extraction: object/version/extraction=%s/%s/%s",
			activeObject, activeVersion, activeExtraction)
	}
	reextracted, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact old extraction read after active pointer switch: %v", err)
	}
	assertSameExactFragment(t, initial, reextracted, true)
	oldWhole, err := fixture.viewer.ReadObjectExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact old extraction assembly after active pointer switch: %v", err)
	}
	assertExactObjectMatchesExtraction(t, oldWhole, v1ID, v1Extraction, anchorID, retainedV1, v1Fragments)
	assertCurrentReadDenied(t, fixture, s1dWorkspace, anchorID, "superseded extraction on current version")

	// A retained fragment is still gated by its own Extraction retention projection.
	if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_extraction_retention SET queryable=false
		WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, v1Extraction); err != nil {
		t.Fatal(err)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "non-queryable old extraction")
	if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_extraction_retention SET queryable=true
		WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, v1Extraction); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID); err != nil {
		t.Fatalf("exact read did not recover after restoring ACTIVE extraction queryability: %v", err)
	}

	// The current workspace still has to contain the exact source tuple. This
	// mutation removes its current-revision binding; it does not test or require
	// confirmation.workspace_revision to equal the workspace's current revision.
	func() {
		if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.workspace SET current_revision=2
			WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.workspace SET current_revision=1
				WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
				t.Errorf("restore current workspace revision: %v", err)
			}
		}()
		assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "missing current workspace binding")
	}()

	// A removed member and a non-member cannot read by knowing the old address.
	func() {
		if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.workspace_member
			SET removed_at=now(), valid_to_revision=2
			WHERE organization_id=$1 AND workspace_id=$2 AND principal_id=$3`, s1dOrg, s1dWorkspace, s1dViewer); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.workspace_member
				SET removed_at=NULL, valid_to_revision=NULL
				WHERE organization_id=$1 AND workspace_id=$2 AND principal_id=$3`, s1dOrg, s1dWorkspace, s1dViewer); err != nil {
				t.Errorf("restore workspace member: %v", err)
			}
		}()
		assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "removed member")
	}()
	outsider := fixture.access
	outsider.PrincipalID = "usr_exact_nonmember"
	assertExactReadDenied(t, fixture, outsider, s1dWorkspace, anchorID, v1ID, "non-member")
	foreignTenant := fixture.access
	foreignTenant.OrganizationID = "org_exact_foreign"
	foreignTenant.PrincipalID = "usr_exact_foreign"
	assertExactReadDenied(t, fixture, foreignTenant, s1dWorkspace, anchorID, v1ID, "foreign tenant")
	assertExactReadDenied(t, fixture, fixture.access, "ws_exact_foreign", anchorID, v1ID, "foreign workspace")
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, "frag_exact_missing", v1ID, "missing fragment")

	// Disable and restore the real workspace source binding through the authority repository.
	authority := newAuthorityRuntime(t, fixture.ctx)
	disabled, err := authority.RemoveSource(fixture.ctx,
		authorityAccess(fixture.authority, fixture.authority.ownerID, "req_exact_scope_disable"),
		workspacerepository.RemoveSourceRequest{
			IdempotencyKey: authorityIdempotencyKey("exact-scope-disable"), WorkspaceID: fixture.authority.workspaceID,
			ExpectedWorkspaceRevision: fixture.authority.workspaceRevision,
			ExpectedConfigurationHash: fixture.authority.workspaceConfHash,
			WorkspaceSourceID:         fixture.authority.workspaceSourceID, SourceScopeID: fixture.authority.sourceScopeID,
			SourceScopeRevision: fixture.authority.sourceScopeRevision, ScopeConfigHash: fixture.authority.scopeConfigHash,
			AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
		})
	if err != nil {
		t.Fatalf("disable source binding: %v", err)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "disabled workspace source binding")
	disabledHash, err := workspace.ConfigurationHash(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AddSource(fixture.ctx,
		authorityAccess(fixture.authority, fixture.authority.ownerID, "req_exact_scope_reenable"),
		workspacerepository.AddSourceRequest{
			IdempotencyKey: authorityIdempotencyKey("exact-scope-reenable"), WorkspaceID: fixture.authority.workspaceID,
			ExpectedWorkspaceRevision: disabled.Revision, ExpectedConfigurationHash: disabledHash,
			SourceScopeID: fixture.authority.sourceScopeID, SourceScopeRevision: fixture.authority.sourceScopeRevision,
			ScopeConfigHash: fixture.authority.scopeConfigHash, AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
		}); err != nil {
		t.Fatalf("re-enable source binding: %v", err)
	}
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID); err != nil {
		t.Fatalf("exact read after real source re-enable: %v", err)
	}

	// Object-level queryability also closes both exact surfaces while the rest of
	// the authority chain and retained version remain live.
	func() {
		if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_object SET queryable=false
			WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_object SET queryable=true
				WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID); err != nil {
				t.Errorf("restore source object queryability: %v", err)
			}
		}()
		assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "non-queryable source object")
	}()

	writeS1dFile(t, fixture.target, v2Text)
	runSync(t, fixture.ctx, fixture.handler, fixture.queue, workerAccess(t, s1dOrg), "exact-v2")
	v2Object, v2ID, v2Extraction := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	if v2Object != objectID || v2ID == v1ID {
		t.Fatalf("replacement sync did not preserve object and create a new version: %s/%s want %s/different", v2Object, v2ID, objectID)
	}
	var v1State string
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT state FROM public.source_version
		WHERE organization_id=$1 AND id=$2`, s1dOrg, v1ID).Scan(&v1State); err != nil {
		t.Fatal(err)
	}
	if v1State != "SUPERSEDED" {
		t.Fatalf("old SourceVersion state=%s, want SUPERSEDED", v1State)
	}
	v1AfterReplacement, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact superseded v1 read: %v", err)
	}
	assertSameExactFragment(t, initial, v1AfterReplacement, false)
	wholeV1AfterReplacement, err := fixture.viewer.ReadObjectExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID)
	if err != nil {
		t.Fatalf("exact superseded v1 object read: %v", err)
	}
	assertExactObjectMatchesExtraction(t, wholeV1AfterReplacement, v1ID, v1Extraction, anchorID, retainedV1, v1Fragments)
	assertCurrentReadDenied(t, fixture, s1dWorkspace, anchorID, "superseded source version")

	v2Fragments := s1dFragments(t, fixture.ctx, fixture.admin, v2Extraction)
	if len(v2Fragments) == 0 {
		t.Fatal("replacement version has no fragments")
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v2ID, "fragment paired with wrong version")
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, v2Fragments[0].id, v1ID, "wrong fragment for old version")

	currentFragment, err := fixture.viewer.Read(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id)
	if err != nil {
		t.Fatalf("default current read v2: %v", err)
	}
	if currentFragment.SourceVersionID != v2ID || !currentFragment.IsCurrentVersion {
		t.Fatalf("default current read returned non-current version: %+v", currentFragment)
	}
	currentWhole, err := fixture.viewer.ReadObject(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id)
	if err != nil {
		t.Fatalf("default current whole-object read v2: %v", err)
	}
	exactV2, err := fixture.viewer.ReadObjectExactVersion(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id, v2ID)
	if err != nil {
		t.Fatal(err)
	}
	assertExactObjectMatchesExtraction(t, exactV2, v2ID, v2Extraction, v2Fragments[0].id, currentWhole.Text, v2Fragments)

	inventory, err := fixture.viewer.ListObjects(fixture.ctx, fixture.access, s1dWorkspace, false, 0, 20)
	if err != nil {
		t.Fatalf("default current inventory: %v", err)
	}
	if len(inventory.Items) != 1 || inventory.Items[0].SourceVersionID != v2ID || !inventory.Items[0].Current {
		t.Fatalf("default inventory includes a non-current version: %+v", inventory.Items)
	}
	oldSearch, err := fixture.viewer.SearchFragments(fixture.ctx, fixture.access, s1dWorkspace, "retainedneedle", false, 0, 100)
	if err != nil {
		t.Fatalf("default search for historical-only term: %v", err)
	}
	if len(oldSearch.Hits) != 0 {
		t.Fatalf("default search returned %d historical-only hits", len(oldSearch.Hits))
	}
	currentSearch, err := fixture.viewer.SearchFragments(fixture.ctx, fixture.access, s1dWorkspace, "currentneedle", false, 0, 100)
	if err != nil {
		t.Fatalf("default search for current term: %v", err)
	}
	if len(currentSearch.Hits) == 0 {
		t.Fatal("default search missed the current version")
	}
	for _, hit := range currentSearch.Hits {
		if hit.Fragment.SourceVersionID != v2ID {
			t.Fatalf("default search returned version %s, want only %s", hit.Fragment.SourceVersionID, v2ID)
		}
	}

	// A version-retention fence removes access even while bytes still exist.
	func() {
		if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_version_retention SET queryable=false
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, v1ID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_version_retention SET queryable=true
				WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, v1ID); err != nil {
				t.Errorf("restore version queryability: %v", err)
			}
		}()
		assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "non-queryable superseded version")
	}()
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, anchorID, v1ID); err != nil {
		t.Fatalf("exact read did not recover after restoring version queryability: %v", err)
	}
	assertExactArtifactReadersFailClosed(t, fixture, anchorID, v2ID)

	// Revoke the real confirmation as a terminal authority change; both exact
	// surfaces must return the same content-free denial afterward.
	var confirmationID, confirmationHash string
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT c.confirmation_id, c.confirmation_hash
		FROM public.workspace_managed_grant_confirmation c
		JOIN public.workspace w ON w.organization_id=c.organization_id AND w.id=c.workspace_id
		JOIN public.workspace_revision_source wrs ON wrs.organization_id=w.organization_id
		 AND wrs.workspace_id=w.id AND wrs.workspace_revision=w.current_revision
		 AND wrs.workspace_source_id=c.workspace_source_id AND wrs.source_scope_id=c.source_scope_id
		 AND wrs.source_scope_revision=c.source_scope_revision AND wrs.scope_config_hash=c.scope_config_hash
		 AND wrs.access_mode=c.access_mode AND wrs.enabled
		WHERE c.organization_id=$1 AND c.workspace_id=$2 AND c.workspace_source_id=$3
		  AND NOT EXISTS (SELECT 1 FROM public.workspace_managed_grant_revocation gr
		      WHERE gr.organization_id=c.organization_id AND gr.confirmation_id=c.confirmation_id)
		  AND NOT EXISTS (SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
		      WHERE ar.organization_id=c.organization_id AND ar.grant_id=c.confirmation_actor_grant_id)
		ORDER BY c.confirmation_id DESC LIMIT 1`,
		s1dOrg, fixture.authority.workspaceID, fixture.authority.workspaceSourceID).Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatalf("resolve current source confirmation for revocation: %v", err)
	}
	authority = newAuthorityRuntime(t, fixture.ctx)
	if _, err := authority.RevokeManagedConfirmation(fixture.ctx,
		authorityAccess(fixture.authority, fixture.authority.ownerID, "req_exact_confirmation_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("exact-confirmation-revoke"), OrganizationID: s1dOrg,
			WorkspaceID: fixture.authority.workspaceID, ConfirmationID: confirmationID,
			ConfirmationHash: confirmationHash, ExpectedPolicyRevision: fixture.authority.policyID,
		}); err != nil {
		t.Fatalf("revoke source confirmation: %v", err)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, anchorID, v1ID, "revoked confirmation")
}

func TestEvidenceExactVersionReadDeniesDeletedSourceObject(t *testing.T) {
	content := strings.Repeat("deleted-object historical text line 0123456789\n", 100)
	fixture := newExactEvidenceFixture(t, content)
	objectID, versionID, extractionID := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	fragmentID := s1dFragments(t, fixture.ctx, fixture.admin, extractionID)[0].id
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, fragmentID, versionID); err != nil {
		t.Fatalf("exact read before object deletion: %v", err)
	}
	var objectState, versionState, versionRetention, extractionRetention string
	var objectQueryable, versionQueryable, extractionQueryable bool
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT o.lifecycle_state, o.queryable, v.state,
		vr.state, vr.queryable, er.state, er.queryable
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_retention vr ON vr.organization_id=v.organization_id AND vr.source_version_id=v.id
		JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id
		JOIN public.source_extraction_retention er ON er.organization_id=ae.organization_id AND er.extraction_id=ae.extraction_id
		WHERE o.organization_id=$1 AND o.id=$2`, s1dOrg, objectID).
		Scan(&objectState, &objectQueryable, &versionState, &versionRetention, &versionQueryable, &extractionRetention, &extractionQueryable); err != nil {
		t.Fatal(err)
	}
	if objectState != "ACTIVE" || !objectQueryable || versionState != "CURRENT" || versionRetention != "ACTIVE" ||
		!versionQueryable || extractionRetention != "ACTIVE" || !extractionQueryable {
		t.Fatalf("precondition not live before object deletion: object=%s/%v version=%s retention=%s/%v extraction=%s/%v",
			objectState, objectQueryable, versionState, versionRetention, versionQueryable, extractionRetention, extractionQueryable)
	}
	if _, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_object SET lifecycle_state='DELETED', queryable=false
		WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID); err != nil {
		t.Fatalf("mark source object deleted: %v", err)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, fragmentID, versionID, "deleted source object")
}

func TestEvidenceExactVersionReadDeniesRemovedSourceObjectScopeMembership(t *testing.T) {
	content := strings.Repeat("removed-membership retained text line 0123456789\n", 100)
	fixture := newExactEvidenceFixture(t, content)
	objectID, versionID, extractionID := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	fragmentID := s1dFragments(t, fixture.ctx, fixture.admin, extractionID)[0].id
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, fragmentID, versionID); err != nil {
		t.Fatalf("exact read before removing source-object membership: %v", err)
	}

	var activeMemberships int
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3
		  AND membership_state='ACTIVE'`, s1dOrg, objectID, s1dScopeID).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 1 {
		t.Fatalf("fixture has %d ACTIVE source-object memberships for its scope, want 1", activeMemberships)
	}
	removed, err := fixture.admin.Exec(fixture.ctx, `UPDATE public.source_object_scope
		SET membership_state='REMOVED', removed_at=now()
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3
		  AND membership_state='ACTIVE'`, s1dOrg, objectID, s1dScopeID)
	if err != nil {
		t.Fatalf("remove source-object scope membership: %v", err)
	}
	if removed.RowsAffected() != 1 {
		t.Fatalf("source-object membership update affected %d rows, want 1", removed.RowsAffected())
	}

	var objectState, versionState, versionRetention string
	var objectQueryable, versionQueryable bool
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT o.lifecycle_state, o.queryable, v.state,
		vr.state, vr.queryable
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_retention vr ON vr.organization_id=v.organization_id AND vr.source_version_id=v.id
		WHERE o.organization_id=$1 AND o.id=$2`, s1dOrg, objectID).
		Scan(&objectState, &objectQueryable, &versionState, &versionRetention, &versionQueryable); err != nil {
		t.Fatal(err)
	}
	if objectState != "ACTIVE" || !objectQueryable || versionState != "CURRENT" ||
		versionRetention != "ACTIVE" || !versionQueryable {
		t.Fatalf("membership denial fixture also changed object/version availability: object=%s/%v version=%s retention=%s/%v",
			objectState, objectQueryable, versionState, versionRetention, versionQueryable)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, fragmentID, versionID, "removed source-object scope membership")
}

func TestEvidenceExactVersionHistoricalPurgeErasesOldBytesAndKeepsCurrentReadable(t *testing.T) {
	v1Text := strings.Repeat("purged-history-only source line 0123456789\n", 500)
	v2Text := strings.Repeat("purge-current source line 9876543210\n", 500)
	fixture := newExactEvidenceFixture(t, v1Text)
	_, v1ID, v1Extraction := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	v1Fragments := s1dFragments(t, fixture.ctx, fixture.admin, v1Extraction)
	if len(v1Fragments) == 0 {
		t.Fatal("initial version has no fragments")
	}
	oldAnchorID := v1Fragments[0].id
	writeS1dFile(t, fixture.target, v2Text)
	runSync(t, fixture.ctx, fixture.handler, fixture.queue, workerAccess(t, s1dOrg), "exact-purge-v2")
	_, v2ID, v2Extraction := s1dActiveEvidence(t, fixture.ctx, fixture.admin)
	if v1ID == v2ID {
		t.Fatal("replacement sync did not create a new version")
	}
	v2Fragments := s1dFragments(t, fixture.ctx, fixture.admin, v2Extraction)
	if len(v2Fragments) == 0 {
		t.Fatal("replacement version has no fragments")
	}
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, oldAnchorID, v1ID); err != nil {
		t.Fatalf("historical exact read before purge: %v", err)
	}
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id, v2ID); err != nil {
		t.Fatalf("current exact read before historical purge: %v", err)
	}

	purger, err := purge.NewPurger(openStore(t, fixture.ctx, purgerRole, "knowvault_purger"), time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(fixture.ctx, purgerAccess(), v1ID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin historical purge: %v", err)
	}
	var versionPurgeState, extractionPurgeState string
	var versionPurgeQueryable, extractionPurgeQueryable bool
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT vr.state, vr.queryable, er.state, er.queryable
		FROM public.source_version_retention vr
		JOIN public.source_extraction_retention er ON er.organization_id=vr.organization_id
		 AND er.extraction_id=$3
		WHERE vr.organization_id=$1 AND vr.source_version_id=$2`, s1dOrg, v1ID, v1Extraction).
		Scan(&versionPurgeState, &versionPurgeQueryable, &extractionPurgeState, &extractionPurgeQueryable); err != nil {
		t.Fatal(err)
	}
	if versionPurgeState != "PURGING" || versionPurgeQueryable || extractionPurgeState != "PURGING" || extractionPurgeQueryable {
		t.Fatalf("begin purge retention=%s/%v extraction=%s/%v, want both PURGING and non-queryable",
			versionPurgeState, versionPurgeQueryable, extractionPurgeState, extractionPurgeQueryable)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, oldAnchorID, v1ID, "PURGING historical version")
	var liveBefore int
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='evidence_fragment' AND purged_at IS NULL
		  AND resource_id IN (SELECT id FROM public.evidence_fragment WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, v1ID).Scan(&liveBefore); err != nil {
		t.Fatal(err)
	}
	if liveBefore == 0 {
		t.Fatal("begin purge removed historical bytes before cleanup")
	}
	if _, err := purger.Cleanup(fixture.ctx, purgerAccess(), v1ID); err != nil {
		t.Fatalf("cleanup historical version: %v", err)
	}
	var liveAfter int
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='evidence_fragment' AND purged_at IS NULL
		  AND resource_id IN (SELECT id FROM public.evidence_fragment WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, v1ID).Scan(&liveAfter); err != nil {
		t.Fatal(err)
	}
	if liveAfter != 0 {
		t.Fatalf("historical cleanup left %d live evidence artifacts", liveAfter)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, oldAnchorID, v1ID, "purged bytes while version is PURGING")
	if err := purger.CompletePurge(fixture.ctx, purgerAccess(), v1ID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("complete historical purge: %v", err)
	}
	var finalVersionState, finalExtractionState string
	if err := fixture.admin.QueryRow(fixture.ctx, `SELECT vr.state, er.state
		FROM public.source_version_retention vr
		JOIN public.source_extraction_retention er ON er.organization_id=vr.organization_id
		 AND er.extraction_id=$3
		WHERE vr.organization_id=$1 AND vr.source_version_id=$2`, s1dOrg, v1ID, v1Extraction).
		Scan(&finalVersionState, &finalExtractionState); err != nil {
		t.Fatal(err)
	}
	if finalVersionState != "PURGED" || finalExtractionState != "PURGED" {
		t.Fatalf("completed purge state version=%s extraction=%s, want PURGED", finalVersionState, finalExtractionState)
	}
	assertExactReadDenied(t, fixture, fixture.access, s1dWorkspace, oldAnchorID, v1ID, "PURGED historical version")
	if _, err := fixture.viewer.ReadExactVersion(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id, v2ID); err != nil {
		t.Fatalf("current v2 exact read after historical purge: %v", err)
	}
	current, err := fixture.viewer.Read(fixture.ctx, fixture.access, s1dWorkspace, v2Fragments[0].id)
	if err != nil {
		t.Fatalf("current v2 default read after historical purge: %v", err)
	}
	if current.SourceVersionID != v2ID || !current.IsCurrentVersion {
		t.Fatalf("historical purge disturbed current version read: %+v", current)
	}
}
