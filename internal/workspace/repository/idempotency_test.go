package repository

import (
	"encoding/base64"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/workspace"
)

func TestWorkspaceCommandHashesAreTypedCanonicalAndUnicodeNormalized(t *testing.T) {
	t.Parallel()

	first, err := createCommandHash(CreateRequest{Name: "Cafe\u0301", Description: "\u0421\u0432\u043e\u0434\u043a\u0430", RetentionPolicyID: "ret_default"})
	if err != nil {
		t.Fatalf("first create command hash: %v", err)
	}
	second, err := createCommandHash(CreateRequest{Name: "Café", Description: "\u0421\u0432\u043e\u0434\u043a\u0430", RetentionPolicyID: "ret_default"})
	if err != nil {
		t.Fatalf("second create command hash: %v", err)
	}
	changed, err := createCommandHash(CreateRequest{Name: "Café", Description: "\u0414\u0440\u0443\u0433\u0430\u044f \u0441\u0432\u043e\u0434\u043a\u0430", RetentionPolicyID: "ret_default"})
	if err != nil {
		t.Fatalf("changed create command hash: %v", err)
	}
	if first != second || first == changed || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("canonical command hashes=%q/%q/%q", first, second, changed)
	}

	update, err := canonicalCommandHash(operationUpdate, createCommandPayload{Name: "Café", Description: "\u0421\u0432\u043e\u0434\u043a\u0430", RetentionPolicyID: "ret_default"})
	if err != nil {
		t.Fatalf("typed operation hash: %v", err)
	}
	if update == first {
		t.Fatal("different command operation reused the same request hash")
	}
}

func TestIdempotencyKeyRequiresCanonical256BitBase64URL(t *testing.T) {
	t.Parallel()

	key := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	hash, err := idempotencyKeyHash(key)
	if err != nil || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("valid idempotency key hash=%q err=%v", hash, err)
	}
	for _, invalid := range []string{"", "short", key + "=", strings.Repeat("a", 43)} {
		if _, err := idempotencyKeyHash(invalid); CodeOf(err) != CodeRequestInvalid {
			t.Fatalf("invalid key %q code=%q err=%v", invalid, CodeOf(err), err)
		}
	}
}

func TestCommandIntentRequiresEveryImmutableReceiptFieldToMatch(t *testing.T) {
	t.Parallel()

	intent := commandIntent{
		Operation: operationMemberRoleChange, WorkspaceID: "ws_alpha",
		TargetPrincipalID: "usr_carol", TargetRole: workspace.RoleManager,
		ResourceType: audit.ResourceWorkspaceMember, ResourceID: "wsm_alpha",
	}
	workspaceID := "ws_alpha"
	targetPrincipalID := "usr_carol"
	targetRole := string(workspace.RoleManager)
	resourceType := string(audit.ResourceWorkspaceMember)
	resourceID := "wsm_alpha"
	operation := string(operationMemberRoleChange)
	if !intent.matches(1, operation, &workspaceID, &targetPrincipalID, &targetRole, &resourceType, &resourceID, sourceCommandReceiptProjection{}) {
		t.Fatal("exact immutable receipt intent did not match")
	}

	for name, mutate := range map[string]func(){
		"operation":        func() { operation = string(operationMemberAdd) },
		"workspace":        func() { workspaceID = "ws_beta" },
		"target principal": func() { targetPrincipalID = "usr_dan" },
		"target role":      func() { targetRole = string(workspace.RoleViewer) },
		"resource type":    func() { resourceType = string(audit.ResourceWorkspace) },
		"resource ID":      func() { resourceID = "ws_alpha" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			operation = string(operationMemberRoleChange)
			workspaceID = "ws_alpha"
			targetPrincipalID = "usr_carol"
			targetRole = string(workspace.RoleManager)
			resourceType = string(audit.ResourceWorkspaceMember)
			resourceID = "wsm_alpha"
			mutate()
			if intent.matches(1, operation, &workspaceID, &targetPrincipalID, &targetRole, &resourceType, &resourceID, sourceCommandReceiptProjection{}) {
				t.Fatalf("intent accepted changed %s", name)
			}
		})
	}

	noTarget := commandIntent{
		Operation: operationUpdate, WorkspaceID: "ws_alpha",
		ResourceType: audit.ResourceWorkspace, ResourceID: "ws_alpha",
	}
	if !noTarget.matches(1, string(operationUpdate), commandIntentStringPointer("ws_alpha"), nil, nil, commandIntentStringPointer(string(audit.ResourceWorkspace)), commandIntentStringPointer("ws_alpha"), sourceCommandReceiptProjection{}) {
		t.Fatal("nil target fields did not round-trip canonically")
	}
	empty := ""
	if noTarget.matches(1, string(operationUpdate), commandIntentStringPointer("ws_alpha"), &empty, nil, commandIntentStringPointer(string(audit.ResourceWorkspace)), commandIntentStringPointer("ws_alpha"), sourceCommandReceiptProjection{}) {
		t.Fatal("empty target principal was accepted in place of SQL NULL")
	}
}

func TestCommandResourceIDIsStableAndActorScoped(t *testing.T) {
	t.Parallel()

	first := commandResourceID("wsm_", "org_alpha", "usr_alice", "sha256:"+strings.Repeat("a", 64), operationMemberAdd)
	if first != commandResourceID("wsm_", "org_alpha", "usr_alice", "sha256:"+strings.Repeat("a", 64), operationMemberAdd) {
		t.Fatal("same command did not derive the same resource ID")
	}
	if first == commandResourceID("wsm_", "org_alpha", "usr_bob", "sha256:"+strings.Repeat("a", 64), operationMemberAdd) {
		t.Fatal("resource ID did not bind the actor-scoped idempotency namespace")
	}
	if first == commandResourceID("wsm_", "org_alpha", "usr_alice", "sha256:"+strings.Repeat("a", 64), operationMemberRoleChange) {
		t.Fatal("resource ID did not bind the command operation")
	}
	if !validID(first) {
		t.Fatalf("derived resource ID is not a valid opaque ID: %q", first)
	}
}

func commandIntentStringPointer(value string) *string { return &value }
