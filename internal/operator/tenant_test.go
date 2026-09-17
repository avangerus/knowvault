package operator

import (
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/workspace"
)

func validTenantProvisionRequest() TenantProvisionRequest {
	return TenantProvisionRequest{
		OrganizationID:       "org_tenant_001",
		OrganizationName:     "Tenant 001",
		Region:               "ru",
		OwnerPrincipalID:     "usr_owner_001",
		OwnerDisplayName:     "Owner",
		WorkspaceID:          "ws_tenant_001",
		WorkspaceName:        "Knowledge",
		WorkspaceDescription: "",
	}
}

func TestPrepareTenantProvisionUsesCanonicalWorkspaceDomain(t *testing.T) {
	request := validTenantProvisionRequest()
	request.WorkspaceName = "Cafe\u0301"
	payload, err := prepareTenantProvision(request)
	if err != nil {
		t.Fatalf("prepareTenantProvision: %v", err)
	}
	if payload.snapshot.Name != "Café" {
		t.Fatalf("workspace name=%q, want NFC-normalized name", payload.snapshot.Name)
	}
	if payload.snapshot.Status != workspace.StatusActive || payload.snapshot.Revision != 1 ||
		len(payload.snapshot.Members) != 1 || payload.snapshot.Members[0].Role != workspace.RoleOwner {
		t.Fatalf("snapshot=%+v, want active revision-one owner snapshot", payload.snapshot)
	}
	hash, err := workspace.ConfigurationHash(payload.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := workspace.CanonicalSnapshot(payload.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if payload.configurationHash != hash || string(payload.canonicalBytes) != string(canonical) {
		t.Fatal("tenant payload does not retain the canonical workspace hash/bytes")
	}
}

func TestPrepareTenantProvisionRequiresSchemaInputs(t *testing.T) {
	base := validTenantProvisionRequest()
	for name, mutate := range map[string]func(*TenantProvisionRequest){
		"organization id":    func(request *TenantProvisionRequest) { request.OrganizationID = "bad id" },
		"organization name":  func(request *TenantProvisionRequest) { request.OrganizationName = "" },
		"owner display name": func(request *TenantProvisionRequest) { request.OwnerDisplayName = "" },
		"region":             func(request *TenantProvisionRequest) { request.Region = "" },
		"workspace id":       func(request *TenantProvisionRequest) { request.WorkspaceID = "bad id" },
		"workspace name":     func(request *TenantProvisionRequest) { request.WorkspaceName = "" },
		"region alias drift": func(request *TenantProvisionRequest) { request.WorkspaceRegion = "us" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := prepareTenantProvision(request); err == nil {
				t.Fatal("invalid tenant input was accepted")
			}
		})
	}
}

func TestTenantDerivedIDsStayWithinDatabaseShape(t *testing.T) {
	long := strings.Repeat("x", 128)
	for _, prefix := range []string{"ora_", "wsm_", "aud_tenant_", "req_tenant_"} {
		value := tenantDerivedID(prefix, long)
		if len(value) > 128 || !validOpaqueID(value) {
			t.Fatalf("derived %q id=%q is not a valid database identifier", prefix, value)
		}
	}
	if tenantDerivedID("ora_", "org_001") != "ora_org_001" {
		t.Fatal("short role id lost its stable readable form")
	}
}

func TestBuildTenantAuditEventUsesProductAuditCanonicalization(t *testing.T) {
	payload, err := prepareTenantProvision(validTenantProvisionRequest())
	if err != nil {
		t.Fatal(err)
	}
	event, err := buildTenantAuditEvent(payload, 0, "sha256:"+strings.Repeat("0", 64), fixedTenantAuditTime())
	if err != nil {
		t.Fatalf("buildTenantAuditEvent: %v", err)
	}
	if event.Action != audit.ActionWorkspaceCreated || event.ResourceType != audit.ResourceWorkspace ||
		event.Sequence != 1 || event.PreviousEventHash != "sha256:"+strings.Repeat("0", 64) || event.EventHash == "" {
		t.Fatalf("event=%+v, want canonical workspace.created event", event)
	}
	if len(event.CanonicalBytes) == 0 {
		t.Fatal("audit event has no canonical bytes")
	}
}

func TestTenantAuditExactReplayRequiresGenesis(t *testing.T) {
	zero := "sha256:" + strings.Repeat("0", 64)
	if !tenantAuditIsGenesis(persistedTenantAudit{sequence: 1, previousEventHash: zero}) {
		t.Fatal("exact genesis event was rejected")
	}
	for _, event := range []persistedTenantAudit{
		{sequence: 2, previousEventHash: "sha256:" + strings.Repeat("a", 64)},
		{sequence: 1, previousEventHash: "sha256:" + strings.Repeat("a", 64)},
		{sequence: 0, previousEventHash: zero},
	} {
		if tenantAuditIsGenesis(event) {
			t.Fatalf("non-genesis audit lookalike accepted: sequence=%d previous=%s", event.sequence, event.previousEventHash)
		}
	}
}

func fixedTenantAuditTime() (value time.Time) {
	return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
}
