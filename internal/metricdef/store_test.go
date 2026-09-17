package metricdef_test

import (
	"context"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
)

// The store is the production implementation of both transport capabilities.
// A signature drift breaks this compile-time assertion instead of the running
// REST/MCP surface.
var (
	_ workspaceapi.MetricDefinitionCatalog   = (*metricdef.Store)(nil)
	_ workspaceapi.MetricDefinitionAuthoring = (*metricdef.Store)(nil)
)

// A denial must reach the transport's existing errors.Is mapping as
// ErrMetricDefinitionDenied (non-enumerating 404), and absence as
// ErrMetricDefinitionNotFound. The store keeps its dependency one-way, so it
// mirrors the transport's sentinels by their canonical message.
func TestStoreRefusalsMatchTheTransportSentinels(t *testing.T) {
	if !errors.Is(metricdef.ErrAccessDenied, workspaceapi.ErrMetricDefinitionDenied) {
		t.Fatal("access denial does not match workspaceapi.ErrMetricDefinitionDenied")
	}
	if !errors.Is(metricdef.ErrDefinitionNotFound, workspaceapi.ErrMetricDefinitionNotFound) {
		t.Fatal("absence does not match workspaceapi.ErrMetricDefinitionNotFound")
	}
}

// A store without its database or workspace authority must not be constructible,
// so composition can never mount a capability that cannot re-check access.
func TestNewRequiresDatabaseAndWorkspaceAuthority(t *testing.T) {
	if _, err := metricdef.New(nil, nil, nil); metricdef.CodeOf(err) != metricdef.CodeInvalidDefinition {
		t.Fatalf("nil dependencies code=%q err=%v, want invalid definition", metricdef.CodeOf(err), err)
	}
}

// A zero-value store fails closed on every entry point instead of panicking.
func TestZeroStoreFailsClosed(t *testing.T) {
	var store *metricdef.Store
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_zero"}
	if _, err := store.List(context.Background(), access, "ws_alpha"); err == nil {
		t.Fatal("zero store List returned nil error")
	}
	if _, err := store.GetVersion(context.Background(), access, "ws_alpha", "metric", 1); err == nil {
		t.Fatal("zero store GetVersion returned nil error")
	}
	if _, err := store.CreateDraft(context.Background(), access, "ws_alpha", "metric", metricdef.Spec{}); err == nil {
		t.Fatal("zero store CreateDraft returned nil error")
	}
	if _, err := store.Approve(context.Background(), access, "ws_alpha", "metric"); err == nil {
		t.Fatal("zero store Approve returned nil error")
	}
}
