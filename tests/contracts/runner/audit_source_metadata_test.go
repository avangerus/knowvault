package contracts

import "testing"

func TestSourceMetadataAuditRejectsRehashedPollutedProjection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{"valid", func(map[string]any) {}, true},
		{"source_content", func(e map[string]any) { object(e["metadata"])["source_scope_id"] = "scope_secret" }, false},
		{"invented_reason", func(e map[string]any) { object(e["metadata"])["reason_codes"] = []any{"SOURCE_CONTENT"} }, false},
		{"evidence_reference", func(e map[string]any) { e["referenced_evidence_ids"] = []any{"ev_secret"} }, false},
		{"wrong_workspace", func(e map[string]any) { e["workspace_id"] = "ws_beta" }, false},
		{"missing_workspace", func(e map[string]any) { e["workspace_id"] = nil }, false},
		{"failed_success", func(e map[string]any) { e["action"] = "source.metadata.read.failed" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := map[string]any{
				"schema_version": "audit-event-v1", "event_id": "aud_metadata", "organization_id": "org_alpha", "sequence": 1,
				"workspace_id": "ws_alpha", "actor_type": "SERVICE", "actor_principal_id": "svcp_agent", "on_behalf_of_principal_id": nil,
				"action": "source.metadata.read.completed", "resource_type": "WORKSPACE", "resource_id": "ws_alpha", "request_id": "req_metadata",
				"policy_decision_id": nil, "outcome": "SUCCESS", "error_code": nil, "referenced_evidence_ids": []any{},
				"metadata":            map[string]any{"reason_codes": []any{"SOURCE_STATUS_LIST"}},
				"previous_event_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				"event_hash":          nil, "occurred_at": "2026-09-14T12:00:00Z",
			}
			test.edit(event)
			hash, err := hashCanonical(auditEventContent(event))
			if err != nil {
				t.Fatal(err)
			}
			event["event_hash"] = hash
			err = validateAuditEventAgainst(event, "org_alpha", event["previous_event_hash"].(string), 1)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}
