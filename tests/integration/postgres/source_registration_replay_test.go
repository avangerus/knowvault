package postgres_test

// Dedicated regression proof (demo1 FAIL cause 2) that an exact re-registration
// of an already-registered FOLDER (WORKSPACE_MANAGED) source lineage converges
// on created=false with the existing connection_id/source_scope_id instead of
// answering 409 SOURCE_CONFLICT, while a genuine lineage collision (same scope
// identity, different registration content) still fails closed as a typed
// conflict. The replay appends no duplicate source_scope/connection rows, no
// duplicate sealed artifacts and no second audit record.

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/source/registration"
)

func TestSourceRegistrationReplayConvergesOnCreatedFalse(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)

	first, err := service.Register(ctx, regOwnerAccess("req_replay_first"), regRequest())
	if err != nil {
		t.Fatalf("first register: %v (code=%s)", err, registration.CodeOf(err))
	}
	if !first.Created || first.Revision != 1 {
		t.Fatalf("first register did not create: %#v", first)
	}

	// An exact re-registration of the same lineage is an idempotent replay: it
	// must converge on created=false and return the SAME registration ids.
	second, err := service.Register(ctx, regOwnerAccess("req_replay_second"), regRequest())
	if err != nil {
		t.Fatalf("re-register must not be a SOURCE_CONFLICT: %v (code=%s)", err, registration.CodeOf(err))
	}
	if second.Created {
		t.Fatal("exact re-registration reported created=true")
	}
	if second.ConnectionID != first.ConnectionID ||
		second.SourceScopeID != first.SourceScopeID ||
		second.DiscoveredScopeID != first.DiscoveredScopeID {
		t.Fatalf("re-registration diverged ids: first=%#v second=%#v", first, second)
	}
	if second.Revision != 1 || second.AccessMode != first.AccessMode {
		t.Fatalf("re-registration diverged revision/access: first=%#v second=%#v", first, second)
	}

	// The replay is content-free and idempotent: it mints no duplicate
	// source_scope/connection rows, sealed artifacts or audit records.
	var connections, scopes, artifacts, auditEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1`,
		regOrg).Scan(&connections); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_scope WHERE organization_id=$1`,
		regOrg).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact WHERE organization_id=$1`,
		regOrg).Scan(&artifacts); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1`,
		regOrg).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if connections != 1 || scopes != 1 || artifacts != 4 || auditEvents != 1 {
		t.Fatalf("replay added rows: connections=%d scopes=%d artifacts=%d audit=%d (want 1/1/4/1)",
			connections, scopes, artifacts, auditEvents)
	}
}

// TestSourceRegistrationReplayConvergesOnCreatedFalseAfterActivation is the
// regression proof for the S2 defect measured on knowvault-acc: replaying an
// exact registration once the lineage's revision-1 activation had already
// left DRAFT (the very first successful :activate moves it DRAFT -> SYNCING
// -> READY) answered 409 SOURCE_CONFLICT instead of the idempotent
// created:false the registration package's own doc comment promises. The
// three *_registration_begin SQL functions (000018/000025/000042) required
// the scope's revision-1 source_scope_activation row to still read status =
// 'DRAFT' as part of the "exact same configuration" replay check; that
// column is activation LIFECYCLE state, not configuration, so it can never
// stay DRAFT past a source's first activation. This drives the activation
// row through the exact DRAFT -> SYNCING -> READY transition the production
// worker uses (app.source_scope_activation_guard enforces that sequence for
// every session, so the test cannot jump straight to READY) and then
// replays the identical registration request.
func TestSourceRegistrationReplayConvergesOnCreatedFalseAfterActivation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)

	first, err := service.Register(ctx, regOwnerAccess("req_replay_activated_first"), regRequest())
	if err != nil {
		t.Fatalf("first register: %v (code=%s)", err, registration.CodeOf(err))
	}

	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET status='SYNCING' WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1 AND revision=1`,
		regOrg, first.SourceScopeID); err != nil {
		t.Fatalf("advance activation to SYNCING: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET status='READY' WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1 AND revision=1`,
		regOrg, first.SourceScopeID); err != nil {
		t.Fatalf("advance activation to READY: %v", err)
	}

	second, err := service.Register(ctx, regOwnerAccess("req_replay_activated_second"), regRequest())
	if err != nil {
		t.Fatalf("re-register of an activated lineage must not be a SOURCE_CONFLICT: %v (code=%s)", err, registration.CodeOf(err))
	}
	if second.Created {
		t.Fatal("re-registration of an activated lineage reported created=true")
	}
	if second.ConnectionID != first.ConnectionID || second.SourceScopeID != first.SourceScopeID ||
		second.DiscoveredScopeID != first.DiscoveredScopeID {
		t.Fatalf("re-registration diverged ids: first=%#v second=%#v", first, second)
	}

	var scopes, auditEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_scope WHERE organization_id=$1`,
		regOrg).Scan(&scopes); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1`,
		regOrg).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if scopes != 1 || auditEvents != 1 {
		t.Fatalf("replay of an activated lineage added rows: scopes=%d audit=%d (want 1/1)", scopes, auditEvents)
	}
}

func TestSourceRegistrationReplayKeepsLineageCollisionGuard(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)

	if _, err := service.Register(ctx, regOwnerAccess("req_collision_first"), regRequest()); err != nil {
		t.Fatalf("first register: %v (code=%s)", err, registration.CodeOf(err))
	}

	// A genuine lineage collision — the same scope identity (mount + relative
	// root) but a different registration content (display name here) — must
	// still fail closed as a typed conflict; the collision guard is never
	// weakened by the replay path.
	conflicting := regRequest()
	conflicting.Name = "A different display name"
	_, err := service.Register(ctx, regOwnerAccess("req_collision_conflict"), conflicting)
	if registration.CodeOf(err) != registration.CodeConflict {
		t.Fatalf("collision register: err=%v code=%s (want SOURCE_CONFLICT)", err, registration.CodeOf(err))
	}

	var connections, auditEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1`,
		regOrg).Scan(&connections); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1`,
		regOrg).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if connections != 1 || auditEvents != 1 {
		t.Fatalf("collision mutated rows: connections=%d audit=%d (want 1/1)", connections, auditEvents)
	}
}
