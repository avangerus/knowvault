package question

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestObserveWorkspaceContextReadIsNilSafeByDefault(t *testing.T) {
	workspaceContextReadAuditHook = nil
	// Must not panic when no hook was installed.
	ObserveWorkspaceContextRead(context.Background(), database.AccessContext{OrganizationID: "org_1", PrincipalID: "user_1"}, "ws_1", 3)
}

func TestObserveWorkspaceContextReadInvokesInstalledHook(t *testing.T) {
	t.Cleanup(func() { SetWorkspaceContextReadAuditHook(nil) })

	var invoked bool
	var gotAccess database.AccessContext
	var gotTrace WorkspaceContextReadTrace
	SetWorkspaceContextReadAuditHook(func(ctx context.Context, access database.AccessContext, trace WorkspaceContextReadTrace) {
		invoked = true
		gotAccess = access
		gotTrace = trace
	})

	access := database.AccessContext{OrganizationID: "org_1", PrincipalID: "user_1", RequestID: "req_1"}
	ObserveWorkspaceContextRead(context.Background(), access, "ws_1", 3)

	if !invoked {
		t.Fatal("installed hook was not invoked")
	}
	if gotAccess != access {
		t.Fatalf("access = %+v, want %+v", gotAccess, access)
	}
	if gotTrace != (WorkspaceContextReadTrace{WorkspaceID: "ws_1", Version: 3}) {
		t.Fatalf("trace = %+v, want {WorkspaceID: ws_1, Version: 3}", gotTrace)
	}
}

func TestSetWorkspaceContextReadAuditHookNilRestoresNoOp(t *testing.T) {
	invoked := false
	SetWorkspaceContextReadAuditHook(func(context.Context, database.AccessContext, WorkspaceContextReadTrace) { invoked = true })
	SetWorkspaceContextReadAuditHook(nil)

	ObserveWorkspaceContextRead(context.Background(), database.AccessContext{}, "ws_1", 1)

	if invoked {
		t.Fatal("hook should have been cleared by a nil install")
	}
}
