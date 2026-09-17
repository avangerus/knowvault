package postgres_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestEvidenceReadNeighborsUsesTheAuthorizedActiveTuple proves that adjacent
// metadata comes from the same active extraction and remains behind the normal
// fragment readability gate. The source is deliberately long enough to yield
// several complete fragments, so both boundaries and a middle pair are real.
func TestEvidenceReadNeighborsUsesTheAuthorizedActiveTuple(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "neighbors.txt"), strings.Repeat("navigation evidence line 0123456789\n", 1000))

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	bindingID := neighborsStableWorkspaceSourceID(s1dOrg, s1dWorkspace, s1dScopeID)
	fixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, bindingID, "grant_s1d_admin", "confirmation_s1d_admin", true)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, ingest, queue, workerAccess(t, s1dOrg), "neighbors")

	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	rows := s1dFragments(t, ctx, admin, extractionID)
	if len(rows) < 3 {
		t.Fatalf("navigation fixture yielded %d fragments, want at least 3", len(rows))
	}

	viewer, err := evidence.NewViewer(openStore(t, ctx, appRole, "knowvault_app"), codec)
	if err != nil {
		t.Fatal(err)
	}
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_neighbors"}
	middle := rows[len(rows)/2]
	current, err := viewer.Read(ctx, access, s1dWorkspace, middle.id)
	if err != nil {
		t.Fatalf("read middle fragment: %v", err)
	}
	citationOpened := func(fragmentID string) int64 {
		var count int64
		if err := admin.QueryRow(ctx, `SELECT count(*)
			FROM public.audit_event
			WHERE organization_id=$1 AND action='citation.opened'
			  AND referenced_evidence_ids_json ? $2`, s1dOrg, fragmentID).Scan(&count); err != nil {
			t.Fatalf("count citation.opened for %s: %v", fragmentID, err)
		}
		return count
	}
	previousOpenedBefore := citationOpened(rows[len(rows)/2-1].id)
	nextOpenedBefore := citationOpened(rows[len(rows)/2+1].id)
	neighbors, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, current)
	if err != nil {
		t.Fatalf("read middle neighbors: %v", err)
	}
	if previousOpenedAfter, nextOpenedAfter := citationOpened(rows[len(rows)/2-1].id), citationOpened(rows[len(rows)/2+1].id); previousOpenedAfter <= previousOpenedBefore || nextOpenedAfter <= nextOpenedBefore {
		t.Fatalf("neighbor Read did not append citation.opened: previous %d->%d next %d->%d", previousOpenedBefore, previousOpenedAfter, nextOpenedBefore, nextOpenedAfter)
	}
	if neighbors.Previous == nil || neighbors.Next == nil {
		t.Fatalf("middle neighbors = %#v, want both sides", neighbors)
	}
	if neighbors.Previous.FragmentID != rows[len(rows)/2-1].id || neighbors.Next.FragmentID != rows[len(rows)/2+1].id {
		t.Fatalf("middle neighbors = (%s,%s), want (%s,%s)", neighbors.Previous.FragmentID, neighbors.Next.FragmentID,
			rows[len(rows)/2-1].id, rows[len(rows)/2+1].id)
	}
	if neighbors.Previous.Ordinal >= current.Ordinal || neighbors.Next.Ordinal <= current.Ordinal ||
		neighbors.Previous.ExtractionID != current.ExtractionID || neighbors.Next.ExtractionID != current.ExtractionID ||
		neighbors.Previous.SourceVersionID != current.SourceVersionID || neighbors.Next.SourceVersionID != current.SourceVersionID ||
		neighbors.Previous.SourceObjectID != current.SourceObjectID || neighbors.Next.SourceObjectID != current.SourceObjectID {
		t.Fatalf("neighbor tuple mismatch: current=%+v neighbors=%+v", current, neighbors)
	}

	first, err := viewer.Read(ctx, access, s1dWorkspace, rows[0].id)
	if err != nil {
		t.Fatalf("read first fragment: %v", err)
	}
	firstNeighbors, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, first)
	if err != nil {
		t.Fatalf("read first neighbors: %v", err)
	}
	if firstNeighbors.Previous != nil || firstNeighbors.Next == nil {
		t.Fatalf("first neighbors = %#v, want no predecessor and a successor", firstNeighbors)
	}
	last, err := viewer.Read(ctx, access, s1dWorkspace, rows[len(rows)-1].id)
	if err != nil {
		t.Fatalf("read last fragment: %v", err)
	}
	lastNeighbors, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, last)
	if err != nil {
		t.Fatalf("read last neighbors: %v", err)
	}
	if lastNeighbors.Previous == nil || lastNeighbors.Next != nil {
		t.Fatalf("last neighbors = %#v, want a predecessor and no successor", lastNeighbors)
	}

	for name, deniedWorkspace := range map[string]string{
		"foreign workspace": "ws_neighbors_foreign",
		"foreign tenant":    s1dWorkspace,
	} {
		deniedAccess := access
		if name == "foreign tenant" {
			deniedAccess.OrganizationID = "org_neighbors_other"
		}
		if _, err := viewer.ReadNeighbors(ctx, deniedAccess, deniedWorkspace, current); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("%s neighbors error=%v, want ErrNotFound", name, err)
		}
	}
	for _, testCase := range []struct {
		name   string
		mutate func(*evidence.Fragment)
	}{
		{name: "ordinal", mutate: func(fragment *evidence.Fragment) { fragment.Ordinal++ }},
		{name: "version", mutate: func(fragment *evidence.Fragment) { fragment.SourceVersionID = "version_neighbors_other" }},
		{name: "extraction", mutate: func(fragment *evidence.Fragment) { fragment.ExtractionID = "extraction_neighbors_other" }},
		{name: "object", mutate: func(fragment *evidence.Fragment) { fragment.SourceObjectID = "object_neighbors_other" }},
	} {
		forged := current
		testCase.mutate(&forged)
		if _, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, forged); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("forged %s anchor tuple error=%v, want ErrNotFound", testCase.name, err)
		}
	}

	staleAnchor := current
	oldExtractionID := staleAnchor.ExtractionID
	reextracted := ingest.WithParserRevision("text-v1-b")
	runSync(t, ctx, reextracted, queue, workerAccess(t, s1dOrg), "neighbors-reextract")
	_, _, activeExtractionID := s1dActiveEvidence(t, ctx, admin)
	if activeExtractionID == oldExtractionID {
		t.Fatalf("active extraction did not change: %s", activeExtractionID)
	}
	if _, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, staleAnchor); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("stale extraction anchor error=%v, want ErrNotFound", err)
	}
	activeRows := s1dFragments(t, ctx, admin, activeExtractionID)
	if len(activeRows) < 3 {
		t.Fatalf("re-extracted navigation fixture yielded %d fragments, want at least 3", len(activeRows))
	}
	current, err = viewer.Read(ctx, access, s1dWorkspace, activeRows[len(activeRows)/2].id)
	if err != nil {
		t.Fatalf("read active extraction middle fragment: %v", err)
	}
	activeNeighbors, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, current)
	if err != nil || activeNeighbors.Previous == nil || activeNeighbors.Next == nil {
		t.Fatalf("active extraction neighbors=%#v err=%v, want both sides", activeNeighbors, err)
	}

	authority := newAuthorityRuntime(t, ctx)
	disabled, err := authority.RemoveSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_neighbors_disable"), workspacerepository.RemoveSourceRequest{
		IdempotencyKey: authorityIdempotencyKey("neighbors-disable"), WorkspaceID: fixture.workspaceID,
		ExpectedWorkspaceRevision: fixture.workspaceRevision, ExpectedConfigurationHash: fixture.workspaceConfHash,
		WorkspaceSourceID: fixture.workspaceSourceID, SourceScopeID: fixture.sourceScopeID,
		SourceScopeRevision: fixture.sourceScopeRevision, ScopeConfigHash: fixture.scopeConfigHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("disable source binding: %v", err)
	}
	if _, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, current); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("disabled source neighbors error=%v, want ErrNotFound", err)
	}

	disabledHash, err := workspace.ConfigurationHash(disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AddSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_neighbors_reenable"), workspacerepository.AddSourceRequest{
		IdempotencyKey: authorityIdempotencyKey("neighbors-reenable"), WorkspaceID: fixture.workspaceID,
		ExpectedWorkspaceRevision: disabled.Revision, ExpectedConfigurationHash: disabledHash,
		SourceScopeID: fixture.sourceScopeID, SourceScopeRevision: fixture.sourceScopeRevision,
		ScopeConfigHash: fixture.scopeConfigHash, AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	}); err != nil {
		t.Fatalf("re-enable source binding: %v", err)
	}
	restoredCurrent, err := viewer.Read(ctx, access, s1dWorkspace, current.FragmentID)
	if err != nil {
		t.Fatalf("read after source re-enable: %v", err)
	}
	restoredNeighbors, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, restoredCurrent)
	if err != nil || restoredNeighbors.Previous == nil || restoredNeighbors.Next == nil {
		t.Fatalf("neighbors after source re-enable=%#v err=%v, want both sides", restoredNeighbors, err)
	}

	var confirmationID, confirmationHash string
	if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_source_id=$2`, fixture.organizationID, fixture.workspaceSourceID).
		Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_neighbors_revoke"), workspacerepository.RevokeConfirmationRequest{
		IdempotencyKey: authorityIdempotencyKey("neighbors-revoke"), OrganizationID: fixture.organizationID,
		WorkspaceID: fixture.workspaceID, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
		ExpectedPolicyRevision: fixture.policyID,
	}); err != nil {
		t.Fatalf("revoke source confirmation: %v", err)
	}
	if _, err := viewer.ReadNeighbors(ctx, access, s1dWorkspace, current); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("revoked source neighbors error=%v, want ErrNotFound", err)
	}
}

func neighborsStableWorkspaceSourceID(organizationID, workspaceID, sourceScopeID string) string {
	digest := sha256.Sum256([]byte("workspace-source-lineage-v1\x00" + organizationID + "\x00" + workspaceID + "\x00" + sourceScopeID))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	encoded := make([]byte, 0, 26)
	var accumulator uint32
	bits := uint(2)
	for _, value := range digest[:16] {
		accumulator = (accumulator << 8) | uint32(value)
		bits += 8
		for bits >= 5 {
			bits -= 5
			encoded = append(encoded, alphabet[(accumulator>>bits)&31])
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= (1 << bits) - 1
			}
		}
	}
	return "binding_" + string(encoded)
}
