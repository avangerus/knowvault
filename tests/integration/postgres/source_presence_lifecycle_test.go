package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func missingPresenceFixture(t *testing.T) (*exactEvidenceFixture, string, string, string) {
	t.Helper()
	f := newExactEvidenceFixture(t, "presence original immutable bytes\n")
	object, version, extraction := s1dActiveEvidence(t, f.ctx, f.admin)
	fragment := s1dFragments(t, f.ctx, f.admin, extraction)[0].id
	writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "sentinel.txt"), "stable sentinel\n")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "presence-sentinel")
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "presence-absent")
	assertExactReadDenied(t, f, f.access, s1dWorkspace, fragment, version, "fixture missing")
	return f, object, version, fragment
}

func revokePresenceConfirmation(t *testing.T, f *exactEvidenceFixture) {
	t.Helper()
	var id, hash string
	if err := f.admin.QueryRow(f.ctx, `SELECT confirmation_id,confirmation_hash FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_id=$2 AND workspace_source_id=$3 ORDER BY confirmation_id DESC LIMIT 1`, s1dOrg, f.authority.workspaceID, f.authority.workspaceSourceID).Scan(&id, &hash); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuthorityRuntime(t, f.ctx).RevokeManagedConfirmation(f.ctx,
		authorityAccess(f.authority, f.authority.ownerID, "req_presence_revoke"), workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("presence-revoke"), OrganizationID: s1dOrg, WorkspaceID: f.authority.workspaceID,
			ConfirmationID: id, ConfirmationHash: hash, ExpectedPolicyRevision: f.authority.policyID,
		}); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePresenceReturnCannotBypassClosedAuthority(t *testing.T) {
	for _, control := range []string{"revoked_confirmation", "retention_not_queryable", "purging", "terminal_scope", "revoked_after_read"} {
		t.Run(control, func(t *testing.T) {
			f, object, version, fragment := missingPresenceFixture(t)
			switch control {
			case "revoked_confirmation":
				revokePresenceConfirmation(t, f)
			case "retention_not_queryable":
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_version_retention SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, version); err != nil {
					t.Fatal(err)
				}
			case "purging":
				purger, err := purge.NewPurger(openStore(t, f.ctx, purgerRole, "knowvault_purger"), time.Now, ids.New)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := purger.BeginPurge(f.ctx, purgerAccess(), version, "OPERATOR_REQUEST"); err != nil {
					t.Fatal(err)
				}
			case "terminal_scope":
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object_scope SET membership_state='REMOVED',removed_at=now(),missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2`, s1dOrg, object); err != nil {
					t.Fatal(err)
				}
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object SET lifecycle_state='DELETED' WHERE organization_id=$1 AND id=$2`, s1dOrg, object); err != nil {
					t.Fatal(err)
				}
			case "revoked_after_read":
				revoked := false
				f.handler = f.handler.WithFault(func(stage string) error {
					if stage == "after_version" && !revoked {
						revoked = true
						revokePresenceConfirmation(t, f)
					}
					return nil
				})
			}
			writeS1dFile(t, f.target, "presence original immutable bytes\n")
			// Claim admission itself may reject a revoked source. The normal
			// worker outcome is checked rather than bypassing the queue gate.
			if control == "revoked_confirmation" {
				// The fenced publisher must independently reject even a captured
				// old run tuple after terminal confirmation revocation.
				assertPresenceCapturedRunDenied(t, f, object, version)
			} else {
				runSyncExpectingFailure(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "presence-closed-"+control)
			}
			assertCurrentReadDenied(t, f, s1dWorkspace, fragment, control)
			assertExactReadDenied(t, f, f.access, s1dWorkspace, fragment, version, control)
			var state string
			var queryable bool
			if err := f.admin.QueryRow(f.ctx, `SELECT lifecycle_state,queryable FROM public.source_object WHERE organization_id=$1 AND id=$2`, s1dOrg, object).Scan(&state, &queryable); err != nil {
				t.Fatal(err)
			}
			if state == "ACTIVE" || queryable {
				t.Fatalf("closed authority reopened: %s/%v", state, queryable)
			}
		})
	}
}

func assertPresenceCapturedRunDenied(t *testing.T, f *exactEvidenceFixture, object, version string) {
	t.Helper()
	var run, job, worker string
	var epoch int64
	if err := f.admin.QueryRow(f.ctx, `SELECT r.id,r.job_id,COALESCE(j.lease_owner,$3),j.lease_epoch FROM public.sync_run r JOIN public.job j ON j.organization_id=r.organization_id AND j.id=r.job_id WHERE r.organization_id=$1 AND r.source_scope_id=$2 ORDER BY r.started_at DESC LIMIT 1`, s1dOrg, s1dScopeID, s1dWorkerID).Scan(&run, &job, &worker, &epoch); err != nil {
		t.Fatal(err)
	}
	store := openStore(t, f.ctx, workerRole, "knowvault_worker")
	err := store.Write(f.ctx, workerAccess(t, s1dOrg), func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT * FROM app.source_object_observation_publish($1,$2,1,$3,$4,$5,$6,$7)`, object, s1dScopeID, version, run, job, worker, epoch)
		return err
	})
	if err == nil {
		t.Fatal("captured completed lease/run restored missing object")
	}
}

func TestSourcePresencePublicationRejectsStaleLeaseAndWrongRun(t *testing.T) {
	f, object, version, fragment := missingPresenceFixture(t)
	assertPresenceCapturedRunDenied(t, f, object, version)
	access := workerAccess(t, s1dOrg)
	if _, err := f.queue.Enqueue(f.ctx, access, jobs.Spec{JobID: mustID(t, "job"), Type: jobs.TypeSourceScopeSync, Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "presence-fencing", Priority: 100, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := f.queue.Claim(f.ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	store := openStore(t, f.ctx, workerRole, "knowvault_worker")
	run := mustID(t, "syncrun")
	if err := store.Write(f.ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,1,$2,$3,$4)`, s1dScopeID, claimed.ID, s1dWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run(organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES($1,$2,$3,1,$4,'FULL','RUNNING')`, s1dOrg, run, s1dScopeID, claimed.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, control := range []string{"wrong_epoch", "wrong_worker", "wrong_run", "wrong_scope", "wrong_version"} {
		epoch, workerID, runID, scopeID, versionID := claimed.LeaseEpoch, s1dWorkerID, run, s1dScopeID, version
		switch control {
		case "wrong_epoch":
			epoch++
		case "wrong_worker":
			workerID = "worker_unrelated"
		case "wrong_run":
			runID = mustID(t, "syncrun")
		case "wrong_scope":
			scopeID = mustID(t, "scope")
		case "wrong_version":
			versionID = mustID(t, "version")
		}
		err := store.Write(f.ctx, access, func(ctx context.Context, tx database.Transaction) error {
			_, err := tx.Exec(ctx, `SELECT * FROM app.source_object_observation_publish($1,$2,1,$3,$4,$5,$6,$7)`, object, scopeID, versionID, runID, claimed.ID, workerID, epoch)
			return err
		})
		if err == nil {
			t.Fatalf("presence publication accepted %s", control)
		}
	}
	assertExactReadDenied(t, f, f.access, s1dWorkspace, fragment, version, "failed publication fences")
}

func TestSourcePresenceScopeCutoverClosesMissingMembership(t *testing.T) {
	f, object, version, fragment := missingPresenceFixture(t)
	seedS1dScopeRevision2(t, f.ctx, f.admin, s1dCodec(t, s1dOrg), s1dOrg, s1dOwner, `"exact-history.txt"`)
	seedS1dScopeBinding(t, f.ctx, f.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_presence_r2", "confirmation_presence_r2")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "presence-cutover")
	var state, membership string
	if err := f.admin.QueryRow(f.ctx, `SELECT o.lifecycle_state,m.membership_state FROM public.source_object o JOIN public.source_object_scope m ON m.organization_id=o.organization_id AND m.source_object_id=o.id WHERE o.organization_id=$1 AND o.id=$2`, s1dOrg, object).Scan(&state, &membership); err != nil {
		t.Fatal(err)
	}
	if state != "DELETED" || membership != "REMOVED" {
		t.Fatalf("scope cutover left recoverable old authority: %s/%s", state, membership)
	}
	writeS1dFile(t, f.target, "presence original immutable bytes\n")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "presence-excluded-return")
	assertExactReadDenied(t, f, f.access, s1dWorkspace, fragment, version, "scope-excluded return")
}

// This is a legacy-data migration fixture: current ingestion provides genuine
// objects, immutable bytes and complete scan evidence; the terminal states and
// old deletion action are then reproduced explicitly. It never rewrites audit.
func TestSourcePresenceLegacyBackfillRequiresCompleteProvenance(t *testing.T) {
	for _, control := range []string{"proven_absence", "no_deletion_event", "wrong_job", "latest_wrong_job", "revoked_confirmation", "blocked_retention", "closed_scope", "timestamp_outside_run"} {
		t.Run(control, func(t *testing.T) {
			f, object, version, fragment := missingPresenceFixture(t)
			var run, job string
			var occurred time.Time
			if err := f.admin.QueryRow(f.ctx, `SELECT metadata_json->>'sync_run_id',metadata_json->>'connector_job_id',occurred_at FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2 AND action='source.object_missing' ORDER BY sequence DESC LIMIT 1`, s1dOrg, object).Scan(&run, &job, &occurred); err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object_scope SET membership_state='REMOVED',removed_at=missing_at,missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2`, s1dOrg, object); err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object SET lifecycle_state='DELETED' WHERE organization_id=$1 AND id=$2`, s1dOrg, object); err != nil {
				t.Fatal(err)
			}
			store := openStore(t, f.ctx, workerRole, "knowvault_worker")
			auditStore, err := audit.NewStore(store)
			if err != nil {
				t.Fatal(err)
			}
			appendDeletion := func(jobID string) {
				t.Helper()
				access := workerAccess(t, s1dOrg)
				if _, err := auditStore.Append(f.ctx, access, audit.EventInput{EventID: mustID(t, "audit"), ActorType: audit.ActorSystem, Action: audit.ActionSourceObjectDeleted, ResourceType: audit.ResourceSourceObject, ResourceID: object, RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: occurred, Metadata: audit.Metadata{SyncRunID: &run, ConnectorJobID: &jobID}}); err != nil {
					t.Fatal(err)
				}
			}
			if control != "no_deletion_event" {
				if control == "wrong_job" {
					appendDeletion(mustID(t, "job"))
				} else {
					appendDeletion(job)
				}
			}
			switch control {
			case "latest_wrong_job":
				appendDeletion(mustID(t, "job"))
			case "revoked_confirmation":
				revokePresenceConfirmation(t, f)
			case "blocked_retention":
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_version_retention SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, version); err != nil {
					t.Fatal(err)
				}
			case "closed_scope":
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_scope_activation SET status='REVOKED' WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1 AND revision=1`, s1dOrg, s1dScopeID); err != nil {
					t.Fatal(err)
				}
			case "timestamp_outside_run":
				if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_object_scope SET removed_at=removed_at-interval '1 hour' WHERE organization_id=$1 AND source_object_id=$2`, s1dOrg, object); err != nil {
					t.Fatal(err)
				}
			}
			migration, err := readMigrationFile(t, "000107_stage2_source_observed_presence.sql")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.admin.Exec(f.ctx, migration); err != nil {
				t.Fatalf("legacy classification: %v", err)
			}
			var state, membership string
			var queryable bool
			if err := f.admin.QueryRow(f.ctx, `SELECT o.lifecycle_state,o.queryable,m.membership_state FROM public.source_object o JOIN public.source_object_scope m ON m.organization_id=o.organization_id AND m.source_object_id=o.id WHERE o.organization_id=$1 AND o.id=$2`, s1dOrg, object).Scan(&state, &queryable, &membership); err != nil {
				t.Fatal(err)
			}
			wantObject, wantMember := "DELETED", "REMOVED"
			if control == "proven_absence" {
				wantObject, wantMember = "MISSING", "MISSING"
			}
			if state != wantObject || membership != wantMember || queryable {
				t.Fatalf("legacy classification %s/%s/%v want %s/%s/false", state, membership, queryable, wantObject, wantMember)
			}
			assertExactReadDenied(t, f, f.access, s1dWorkspace, fragment, version, "legacy never immediately opens bytes")
			if control == "proven_absence" {
				writeS1dFile(t, f.target, "presence original immutable bytes\n")
				runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "legacy-return")
				read, err := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, fragment)
				if err != nil || string(read.Text) != "presence original immutable bytes\n" {
					t.Fatalf("proved legacy absence did not return: %v", err)
				}
			}
		})
	}
}
