package postgres_test

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// recordingApprovalAudit is the R1 approval boundary the store owns during the
// test: it records exactly the events the store hands it, in the store's own
// write transaction.
type recordingApprovalAudit struct {
	events []metricdef.ApprovalEvent
	err    error
}

func (recorder *recordingApprovalAudit) RecordApproval(_ context.Context, _ database.AccessContext,
	_ database.Transaction, event metricdef.ApprovalEvent) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.events = append(recorder.events, event)
	return nil
}

func metricDefinitionSpec(name, connectionID string, projectionVersion int64) metricdef.Spec {
	return metricdef.Spec{
		Name:           name,
		Source:         metricdef.SourceConnection{ConnectionID: connectionID, ProjectionVersion: projectionVersion},
		EntityKey:      "order_id",
		Grain:          metricdef.GrainMonth,
		Unit:           "RUB",
		AllowedFilters: []string{"region", "channel", "region"},
	}
}

// TestMetricDefinitionStoreIsDurableMonotonicAndOwnerApproved is the
// database-side proof of R2 Outcome 1 storage: a durable round-trip, a
// cross-workspace read denial, a non-owner write refusal, owner-only audited
// approval, monotonic versions and approved-version immutability, without
// editing any protected test.
func TestMetricDefinitionStoreIsDurableMonotonicAndOwnerApproved(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")

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
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}

	recorder := &recordingApprovalAudit{}
	definitions, err := metricdef.New(databaseStore, workspaceStore, recorder)
	if err != nil {
		t.Fatalf("create metric definition store: %v", err)
	}

	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_metricdef_alice"}
	created, err := definitions.CreateDraft(ctx, alice, "ws_alpha", "metric_revenue",
		metricDefinitionSpec("Net revenue", "conn_orders", 3))
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	if created.Version() != 1 || created.Status() != metricdef.StatusDraft {
		t.Fatalf("created version/status=%d/%q", created.Version(), created.Status())
	}

	listed, err := definitions.List(ctx, alice, "ws_alpha")
	if err != nil || len(listed) != 1 || listed[0].ID() != "metric_revenue" {
		t.Fatalf("list definitions=%v err=%v", listed, err)
	}
	loaded, err := definitions.GetVersion(ctx, alice, "ws_alpha", "metric_revenue", 1)
	if err != nil || loaded.Name() != "Net revenue" || loaded.Source() != (metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3}) {
		t.Fatalf("get version=%+v err=%v", loaded, err)
	}
	if _, err := definitions.GetVersion(ctx, alice, "ws_alpha", "metric_revenue", 99); !errors.Is(err, metricdef.ErrDefinitionNotFound) {
		t.Fatalf("unknown version error=%v", err)
	}

	// Cross-workspace: another tenant can neither list nor read the definition.
	bob := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_bob", RequestID: "req_metricdef_bob"}
	if _, err := definitions.List(ctx, bob, "ws_alpha"); !errors.Is(err, metricdef.ErrAccessDenied) {
		t.Fatalf("cross-workspace list error=%v", err)
	}
	if _, err := definitions.GetVersion(ctx, bob, "ws_alpha", "metric_revenue", 1); !errors.Is(err, metricdef.ErrAccessDenied) {
		t.Fatalf("cross-workspace get error=%v", err)
	}

	// A non-owner member may neither draft nor approve.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_carol', 'org_alpha', 'USER', 'Carol', 'ACTIVE')`); err != nil {
		t.Fatalf("insert carol principal: %v", err)
	}
	current, err := workspaceStore.Get(ctx, alice, "ws_alpha")
	if err != nil {
		t.Fatalf("load workspace before adding member: %v", err)
	}
	if _, err := workspaceStore.AddMember(ctx, alice, workspacerepository.AddMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("metricdef-add-carol"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, current),
		PrincipalID:               "usr_carol",
		Role:                      workspace.RoleMember,
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_metricdef_carol"}
	if _, err := definitions.CreateDraft(ctx, carol, "ws_alpha", "metric_revenue",
		metricDefinitionSpec("Carol edit", "conn_orders", 3)); metricdef.CodeOf(err) != metricdef.CodeNotWorkspaceOwner {
		t.Fatalf("non-owner draft code=%q err=%v", metricdef.CodeOf(err), err)
	}
	if _, err := definitions.Approve(ctx, carol, "ws_alpha", "metric_revenue"); metricdef.CodeOf(err) != metricdef.CodeNotWorkspaceOwner {
		t.Fatalf("non-owner approve code=%q err=%v", metricdef.CodeOf(err), err)
	}
	if len(recorder.events) != 0 {
		t.Fatalf("refused approvals recorded %d audit events", len(recorder.events))
	}

	// Owner approval emits exactly one event and freezes version 1.
	approved, err := definitions.Approve(ctx, alice, "ws_alpha", "metric_revenue")
	if err != nil || approved.Version() != 1 || approved.Status() != metricdef.StatusApproved {
		t.Fatalf("approve=%+v err=%v", approved, err)
	}
	if len(recorder.events) != 1 {
		t.Fatalf("approval audit events=%d, want 1", len(recorder.events))
	}
	event := recorder.events[0]
	if event.DefinitionID != "metric_revenue" || event.WorkspaceID != "ws_alpha" ||
		event.Version != 1 || event.ActorPrincipalID != "usr_alice" {
		t.Fatalf("approval event=%+v", event)
	}

	// An edited APPROVED version is a new DRAFT version, and version 1 is
	// untouched.
	edited, err := definitions.CreateDraft(ctx, alice, "ws_alpha", "metric_revenue",
		metricDefinitionSpec("Net revenue revised", "conn_orders", 4))
	if err != nil || edited.Version() != 2 || edited.Status() != metricdef.StatusDraft {
		t.Fatalf("edited draft=%+v err=%v", edited, err)
	}
	frozen, err := definitions.GetVersion(ctx, alice, "ws_alpha", "metric_revenue", 1)
	if err != nil || frozen.Status() != metricdef.StatusApproved || frozen.Name() != "Net revenue" {
		t.Fatalf("approved version mutated=%+v err=%v", frozen, err)
	}
	if len(recorder.events) != 1 {
		t.Fatalf("edit of an approved version recorded an approval: %d", len(recorder.events))
	}
	if _, err := definitions.Approve(ctx, alice, "ws_alpha", "metric_revenue"); err != nil {
		t.Fatalf("approve revised version: %v", err)
	}
	if len(recorder.events) != 2 {
		t.Fatalf("second approval audit events=%d, want 2", len(recorder.events))
	}
}
