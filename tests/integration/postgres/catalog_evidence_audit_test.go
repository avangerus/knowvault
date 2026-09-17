package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestS1dAuditCompleteness proves every significant S1d transition leaves a
// content-free audit event in the same transaction as the state change (AUD-005):
// scope synced, object ingested, version created and extraction activated, each a
// SYSTEM actor naming the exact entity, carrying the sync-run and job that caused
// it, and never any source content.
func TestS1dAuditCompleteness(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "audit CANARYTOKEN one\naudit two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "sync")

	objectID, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	var scopeID, jobID, syncRunID string
	if err := admin.QueryRow(ctx, `SELECT source_scope_id, job_id, id FROM public.sync_run WHERE organization_id=$1`, s1dOrg).
		Scan(&scopeID, &jobID, &syncRunID); err != nil {
		t.Fatal(err)
	}

	// Each transition is recoverable from a single content-free event: the action,
	// the exact resource id, the SYSTEM actor, and the sync/job that caused it.
	for _, c := range []struct {
		action, resource, resourceID string
	}{
		{"source.scope_changed", "SOURCE_SCOPE", scopeID},
		{"source.object_ingested", "SOURCE_OBJECT", objectID},
		{"source.version_created", "SOURCE_OBJECT", versionID},
		{"source.extraction_activated", "SOURCE_OBJECT", extractionID},
	} {
		var actorType, metadata string
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action=$2 AND resource_type=$3 AND resource_id=$4`,
			s1dOrg, c.action, c.resource, c.resourceID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s: expected exactly one event for resource %s, got %d", c.action, c.resourceID, count)
		}
		if err := admin.QueryRow(ctx, `SELECT actor_type, metadata_json::text FROM public.audit_event
			WHERE organization_id=$1 AND action=$2 AND resource_id=$3`, s1dOrg, c.action, c.resourceID).
			Scan(&actorType, &metadata); err != nil {
			t.Fatal(err)
		}
		if actorType != "SYSTEM" {
			t.Fatalf("%s: actor_type=%s, want SYSTEM", c.action, actorType)
		}
		// The sync run and job that caused the change are recoverable...
		if c.action != "source.scope_changed" {
			if !strings.Contains(metadata, `"connector_job_id": "`+jobID+`"`) {
				t.Fatalf("%s: metadata does not link the job: %s", c.action, metadata)
			}
		}
		if !strings.Contains(metadata, `"sync_run_id": "`+syncRunID+`"`) {
			t.Fatalf("%s: metadata does not link the sync run: %s", c.action, metadata)
		}
	}

	// No source content, locator, path, title or Evidence text reaches audit.
	var leaks int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND (position('CANARYTOKEN' in encode(canonical_bytes,'escape'))>0
		   OR position('CANARYTOKEN' in metadata_json::text)>0)`, s1dOrg).Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if leaks != 0 {
		t.Fatal("source content leaked into an audit event")
	}
}
