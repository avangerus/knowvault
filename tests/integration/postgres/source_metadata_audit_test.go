package postgres_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// These probes execute the production source repository under knowvault_app.
// SQL fault injection and assertions use only the dedicated synthetic test DB.
type sourceMetadataFixture struct {
	ctx    context.Context
	admin  *pgxpool.Pool
	store  *workspacerepository.Store
	access database.AccessContext
}

func seedSourceMetadataFixture(t *testing.T) sourceMetadataFixture {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	db, journal, store := newServiceAccessCodeStores(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_metadata_setup"}
	snapshot, err := store.Get(ctx, owner, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddSource(ctx, owner, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("metadata-source"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: snapshot.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, snapshot),
		SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1, ScopeConfigHash: repositoryTestScopeHash,
		AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}); err != nil {
		t.Fatal(err)
	}
	codes, err := serviceprincipal.New(db, journal, store)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := codes.Issue(ctx, owner, serviceprincipal.IssueRequest{Name: "metadata-agent", WorkspaceIDs: []string{"ws_alpha"},
		TTLSeconds: 3600, IdempotencyKey: workspaceIdempotencyKey("metadata-code")})
	if err != nil {
		t.Fatal(err)
	}
	access, err := codes.Authenticate(ctx, "org_alpha", issued.Code, "req_metadata")
	if err != nil {
		t.Fatal(err)
	}
	if access.EffectiveActorKind() != database.ActorKindService {
		t.Fatal("fixture did not authenticate a SERVICE")
	}
	return sourceMetadataFixture{ctx: ctx, admin: admin, store: store, access: access}
}

func (f sourceMetadataFixture) read(kind, workspaceID, requestID string) (any, error) {
	access := f.access
	access.RequestID = requestID
	if kind == "SOURCE_STATUS_LIST" {
		return f.store.ListSources(f.ctx, access, workspaceID)
	}
	return f.store.ConfirmationContext(f.ctx, access, workspaceID)
}

func assertNoSourceMetadata(t *testing.T, value any, err error, want workspacerepository.ErrorCode) {
	t.Helper()
	if workspacerepository.CodeOf(err) != want {
		t.Fatalf("error code=%s want=%s err=%v", workspacerepository.CodeOf(err), want, err)
	}
	switch v := value.(type) {
	case []workspacerepository.SourceStatus:
		if len(v) != 0 {
			t.Fatal("failed source read returned metadata")
		}
	case workspacerepository.ConfirmationContext:
		if !reflect.DeepEqual(v, workspacerepository.ConfirmationContext{}) {
			t.Fatal("failed confirmation read returned metadata")
		}
	default:
		t.Fatalf("unexpected result type %T", value)
	}
}

func assertSourceMetadataEvents(t *testing.T, f sourceMetadataFixture, requestID, kind, resourceID, workspaceID string, want ...string) {
	t.Helper()
	rows, err := f.admin.Query(f.ctx, `SELECT action, outcome, actor_type, actor_principal_id, COALESCE(workspace_id,''), resource_type, resource_id,
		metadata_json, referenced_evidence_ids_json, canonical_bytes FROM public.audit_event
		WHERE organization_id=$1 AND request_id=$2 ORDER BY sequence`, f.access.OrganizationID, requestID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := []string{}
	for rows.Next() {
		var action, outcome, actor, principal, workspace, resourceType, resource string
		var metadata, refs, canonical []byte
		if err := rows.Scan(&action, &outcome, &actor, &principal, &workspace, &resourceType, &resource, &metadata, &refs, &canonical); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.TrimPrefix(action, "source.metadata.read.")+":"+outcome)
		if actor != "SERVICE" || principal != f.access.PrincipalID || workspace != workspaceID || resourceType != "WORKSPACE" || resource != resourceID {
			t.Fatalf("incorrect audit identity/scope: %s %s %s %s %s", actor, principal, workspace, resourceType, resource)
		}
		var fields map[string]any
		if err := json.Unmarshal(metadata, &fields); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(fields, map[string]any{"reason_codes": []any{kind}}) || string(refs) != "[]" {
			t.Fatalf("non-exact source metadata audit: %s references=%s", metadata, refs)
		}
		for _, forbidden := range []string{repositoryTestScopeID, "connection_name", "metadata-agent", "kva_"} {
			if strings.Contains(string(canonical), forbidden) {
				t.Fatalf("audit contains protected field %q", forbidden)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
		t.Fatalf("journal %s: got=%v want=%v", requestID, got, want)
	}
}

func TestSourceMetadataReadAuditsServiceSuccessAndDenial(t *testing.T) {
	f := seedSourceMetadataFixture(t)
	seedSecondWorkspaceOwnedByAnotherPrincipal(t, f.ctx, f.admin, "org_alpha", "usr_bob", "ws_other")
	seedOrganization(t, f.ctx, f.admin, "org_beta", "usr_beta", "ws_beta")
	for _, kind := range []string{"SOURCE_STATUS_LIST", "SOURCE_CONFIRMATION_CONTEXT"} {
		requestID := "req_metadata_success_" + kind
		value, err := f.read(kind, "ws_alpha", requestID)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if statuses, ok := value.([]workspacerepository.SourceStatus); ok && (len(statuses) != 1 || statuses[0].SourceScopeID != repositoryTestScopeID) {
			t.Fatal("success did not return the bound source")
		}
		if confirmation, ok := value.(workspacerepository.ConfirmationContext); ok && confirmation.ViewerPrincipalID != f.access.PrincipalID {
			t.Fatal("success did not return the authorized confirmation context")
		}
		assertSourceMetadataEvents(t, f, requestID, kind, "ws_alpha", "ws_alpha", "admitted:SUCCESS", "completed:SUCCESS")
		for _, target := range []struct{ id, auditWorkspace string }{{"ws_other", "ws_other"}, {"ws_beta", ""}, {"ws_missing", ""}} {
			requestID := "req_metadata_denied_" + kind + "_" + target.id
			value, err := f.read(kind, target.id, requestID)
			assertNoSourceMetadata(t, value, err, workspacerepository.CodeNotFound)
			assertSourceMetadataEvents(t, f, requestID, kind, target.id, target.auditWorkspace, "admitted:DENIED", "failed:DENIED")
		}
	}
}

func TestSourceMetadataReadFailsClosedWhenAuditOrProjectionFails(t *testing.T) {
	f := seedSourceMetadataFixture(t)
	for _, kind := range []string{"SOURCE_STATUS_LIST", "SOURCE_CONFIRMATION_CONTEXT"} {
		t.Run(kind, func(t *testing.T) {
			t.Run("admission_unavailable", func(t *testing.T) {
				if _, err := f.admin.Exec(f.ctx, `REVOKE INSERT ON public.audit_event FROM knowvault_app`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := f.admin.Exec(f.ctx, `GRANT INSERT ON public.audit_event TO knowvault_app`); err != nil {
						t.Error(err)
					}
				}()
				requestID := "req_metadata_admission_fail_" + kind
				value, err := f.read(kind, "ws_alpha", requestID)
				assertNoSourceMetadata(t, value, err, workspacerepository.CodePersistence)
				assertSourceMetadataEvents(t, f, requestID, kind, "ws_alpha", "ws_alpha")
			})
			t.Run("projection_unavailable_after_admission", func(t *testing.T) {
				// Authorization admission reads only workspace/member facts. Both
				// original source reads load the source projection afterwards.
				if _, err := f.admin.Exec(f.ctx, `REVOKE SELECT ON public.workspace_revision_source FROM knowvault_app`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := f.admin.Exec(f.ctx, `GRANT SELECT ON public.workspace_revision_source TO knowvault_app`); err != nil {
						t.Error(err)
					}
				}()
				requestID := "req_metadata_projection_fail_" + kind
				value, err := f.read(kind, "ws_alpha", requestID)
				assertNoSourceMetadata(t, value, err, workspacerepository.CodePersistence)
				assertSourceMetadataEvents(t, f, requestID, kind, "ws_alpha", "ws_alpha", "admitted:SUCCESS", "failed:FAILED")
			})
			t.Run("completion_unavailable", func(t *testing.T) {
				installSourceMetadataTrigger(t, f, `IF NEW.action = 'source.metadata.read.completed' THEN RAISE EXCEPTION 'synthetic completion failure'; END IF;`)
				requestID := "req_metadata_completion_fail_" + kind
				value, err := f.read(kind, "ws_alpha", requestID)
				assertNoSourceMetadata(t, value, err, workspacerepository.CodePersistence)
				assertSourceMetadataEvents(t, f, requestID, kind, "ws_alpha", "ws_alpha", "admitted:SUCCESS", "failed:FAILED")
			})
		})
	}
}

func TestSourceMetadataReadRechecksDisabledServiceAfterAdmission(t *testing.T) {
	f := seedSourceMetadataFixture(t)
	installSourceMetadataTrigger(t, f, `IF NEW.action = 'source.metadata.read.admitted' THEN PERFORM pg_advisory_xact_lock(918273646); END IF;`)
	gate, err := f.admin.Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Release()
	if _, err := gate.Exec(f.ctx, `SELECT pg_advisory_lock(918273646)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = gate.Exec(context.Background(), `SELECT pg_advisory_unlock(918273646)`) }()
	ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
	defer cancel()
	f.ctx = ctx
	type readResult struct {
		value any
		err   error
	}
	done := make(chan readResult, 1)
	go func() {
		value, err := f.read("SOURCE_STATUS_LIST", "ws_alpha", "req_metadata_disable_race")
		done <- readResult{value, err}
	}()
	waitForAdmissionGateWait(t, ctx, f.admin)
	// The in-flight request has passed its authorization check, while the
	// durable admission is still blocked. Disable the SERVICE before release.
	if _, err := f.admin.Exec(ctx, `UPDATE public.principal SET status='DISABLED', session_revision=session_revision+1 WHERE organization_id=$1 AND id=$2`, f.access.OrganizationID, f.access.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_unlock(918273646)`); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		assertNoSourceMetadata(t, result.value, result.err, workspacerepository.CodeNotFound)
	case <-ctx.Done():
		t.Fatal("source read did not finish after admission gate released")
	}
	assertSourceMetadataEvents(t, f, "req_metadata_disable_race", "SOURCE_STATUS_LIST", "ws_alpha", "ws_alpha", "admitted:SUCCESS", "failed:DENIED")
}

func installSourceMetadataTrigger(t *testing.T, f sourceMetadataFixture, body string) {
	t.Helper()
	// body consists only of the fixed synthetic SQL literals above.
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION public.source_metadata_audit_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` RETURN NEW; END; $$;
		CREATE TRIGGER source_metadata_audit_probe BEFORE INSERT ON public.audit_event FOR EACH ROW EXECUTE FUNCTION public.source_metadata_audit_probe();`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), `DROP TRIGGER source_metadata_audit_probe ON public.audit_event; DROP FUNCTION public.source_metadata_audit_probe();`); err != nil {
			t.Error(err)
		}
	})
}

func TestSourceMetadataReadCancellationKeepsBoundedFailureOutcome(t *testing.T) {
	f := seedSourceMetadataFixture(t)
	for _, kind := range []string{"SOURCE_STATUS_LIST", "SOURCE_CONFIRMATION_CONTEXT"} {
		t.Run(kind, func(t *testing.T) {
			// Admission needs no source projection lock. The original read will
			// block here only after that admission commits.
			blocker, err := f.admin.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blocker.Rollback(context.Background()) }()
			if _, err := blocker.Exec(f.ctx, `LOCK TABLE public.workspace_revision_source IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			readFixture := f
			readFixture.ctx = ctx
			requestID := "req_metadata_cancel_" + kind
			type readResult struct {
				value any
				err   error
			}
			done := make(chan readResult, 1)
			go func() { value, err := readFixture.read(kind, "ws_alpha", requestID); done <- readResult{value, err} }()
			deadline := time.Now().Add(5 * time.Second)
			admitted := false
			for time.Now().Before(deadline) {
				if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS (SELECT 1 FROM public.audit_event WHERE request_id=$1 AND action='source.metadata.read.admitted' AND outcome='SUCCESS')`, requestID).Scan(&admitted); err != nil {
					t.Fatal(err)
				}
				if admitted {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !admitted {
				t.Fatal("no durable admission before blocked source projection")
			}
			cancel()
			select {
			case result := <-done:
				assertNoSourceMetadata(t, result.value, result.err, workspacerepository.CodePersistence)
			case <-time.After(7 * time.Second):
				t.Fatal("cancelled source read exceeded bounded failure cleanup")
			}
			assertSourceMetadataEvents(t, f, requestID, kind, "ws_alpha", "ws_alpha", "admitted:SUCCESS", "failed:FAILED")
		})
	}
}
