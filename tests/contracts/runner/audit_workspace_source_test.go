package contracts

import "testing"

func TestWorkspaceSourceAuditProjectionAcceptsEveryTerminalOutcome(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		name        string
		outcome     string
		errorCode   any
		workspaceID any
	}{
		{name: "success", outcome: "SUCCESS", errorCode: nil, workspaceID: "ws_alpha"},
		{name: "denied hidden workspace", outcome: "DENIED", errorCode: "WORKSPACE_SOURCE_DENIED", workspaceID: nil},
		{name: "denied known workspace", outcome: "DENIED", errorCode: "WORKSPACE_SOURCE_DENIED", workspaceID: "ws_alpha"},
		{name: "failed missing workspace", outcome: "FAILED", errorCode: "WORKSPACE_SOURCE_NOT_FOUND", workspaceID: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			event := map[string]any{
				"schema_version": "audit-event-v1", "event_id": "aud_source_" + testCase.name,
				"organization_id": "org_alpha", "sequence": 1, "workspace_id": testCase.workspaceID,
				"actor_type": "HUMAN", "actor_principal_id": "usr_alice", "on_behalf_of_principal_id": nil,
				"action": "workspace.source_added", "resource_type": "WORKSPACE_SOURCE",
				"resource_id": "wsrc_alpha_docs", "request_id": "req_source_" + testCase.name,
				"policy_decision_id": nil, "outcome": testCase.outcome, "error_code": testCase.errorCode,
				"referenced_evidence_ids": []any{},
				"metadata": map[string]any{
					"workspace_revision": 7, "workspace_source_id": "wsrc_alpha_docs",
					"source_scope_id": "scope_docs", "source_scope_revision": 3,
					"scope_config_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"access_mode":       "WORKSPACE_MANAGED", "enabled": true,
				},
				"previous_event_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"event_hash":          nil, "occurred_at": "2026-07-15T12:00:00Z",
			}
			hash, err := hashCanonical(auditEventContent(event))
			if err != nil {
				t.Fatal(err)
			}
			event["event_hash"] = hash
			if err := validateAuditEventAgainst(event, "org_alpha", event["previous_event_hash"].(string), 1); err != nil {
				t.Fatalf("terminal source audit outcome rejected: %v", err)
			}
		})
	}
}
