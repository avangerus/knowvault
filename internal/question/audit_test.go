package question

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/planner"
)

func auditPlan(t *testing.T) planner.Plan {
	t.Helper()
	planned, err := planner.Default().Plan("\u041f\u0440\u043e\u0432\u0435\u0440\u044c, \u043a\u0430\u043a\u0438\u0435 compliance-\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u044b \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u043c\u0438 \u0438 \u043a\u043e\u0434\u043e\u043c?")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Status != planner.Ready || planned.Operation != planner.Audit {
		t.Fatalf("plan=%+v, want ready AUDIT", planned)
	}
	return planned
}

func auditCandidate(id, object, profile, text string) candidate {
	return candidate{ID: id, SourceObjectID: object, ParserProfileRevision: profile, Text: []byte(text)}
}

func TestRenderAuditControlsRequiresAgreementAcrossSources(t *testing.T) {
	planned := auditPlan(t)
	selected := []candidate{
		auditCandidate("audit_code_01", "object_code", "source-code-v1", "retention_control = confirmed\n"),
		auditCandidate("audit_doc_01", "object_doc", "text-v1", "retention_control = confirmed\n"),
	}
	answer, citations := renderAuditControls("workspace-a", planned, selected)
	if !strings.Contains(answer, "Confirmed for retention_control") || !strings.Contains(answer, "confirmed") {
		t.Fatalf("answer=%q", answer)
	}
	if len(citations) != 2 || citations[0].EvidenceFragment == citations[1].EvidenceFragment {
		t.Fatalf("citations=%+v, want both source Evidence IDs", citations)
	}
	_, conflicts, err := deriveSignals(planned, selected, citations, false)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("conflicts=%+v err=%v", conflicts, err)
	}
}

func TestRenderAuditControlsReportsGenericConflict(t *testing.T) {
	planned := auditPlan(t)
	selected := []candidate{
		auditCandidate("audit_code_02", "object_code_02", "source-code-v1", "backup_control = pass\n"),
		auditCandidate("audit_doc_02", "object_doc_02", "text-v1", "backup_control = failed\n"),
	}
	answer, citations := renderAuditControls("workspace-a", planned, selected)
	if !strings.Contains(answer, "Conflict for backup_control") || !strings.Contains(answer, "pass") || !strings.Contains(answer, "failed") {
		t.Fatalf("answer=%q", answer)
	}
	if len(citations) != 2 {
		t.Fatalf("citations=%+v", citations)
	}
	_, conflicts, err := deriveSignals(planned, selected, citations, false)
	if err != nil || len(conflicts) != 1 || conflicts[0].Code != "CONFLICT_AUDIT_CONTROL_STATUS" || len(conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("conflicts=%+v err=%v", conflicts, err)
	}
}

func TestRenderAuditControlsDoesNotInterpretUnknownStatusOrMissingSource(t *testing.T) {
	planned := auditPlan(t)
	cases := []struct {
		name     string
		selected []candidate
	}{
		{
			name: "unknown status",
			selected: []candidate{
				auditCandidate("audit_code_03", "object_code_03", "source-code-v1", "identity_control = maybe\n"),
				auditCandidate("audit_doc_03", "object_doc_03", "text-v1", "identity_control = maybe\n"),
			},
		},
		{
			name: "missing source class",
			selected: []candidate{
				auditCandidate("audit_unknown_04", "object_unknown_04", "", "retention_control = confirmed\n"),
				auditCandidate("audit_doc_04", "object_doc_04", "text-v1", "retention_control = confirmed\n"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if answer, citations := renderAuditControls("workspace-a", planned, tc.selected); answer != "" || len(citations) != 0 {
				t.Fatalf("unsupported audit evidence promoted: answer=%q citations=%+v", answer, citations)
			}
		})
	}
}

func TestAuditSupportsQualifiedGitObjectType(t *testing.T) {
	planned := auditPlan(t)
	selected := []candidate{
		auditCandidate("audit_commit_05", "object_commit_05", "", "access_control = compliant\n"),
		{ID: "audit_doc_05", SourceObjectID: "object_doc_05", CanonicalFormat: "TEXT", Text: []byte("access_control = compliant\n")},
	}
	selected[0].ObjectType = "GIT_COMMIT"
	answer, citations := renderAuditControls("workspace-a", planned, selected)
	if !strings.Contains(answer, "Confirmed for access_control") || len(citations) != 2 {
		t.Fatalf("git audit answer=%q citations=%+v", answer, citations)
	}
}

func TestRenderAuditControlsStructuredControlFixture(t *testing.T) {
	planned, err := planner.Default().Plan("\u043f\u0440\u043e\u0432\u0435\u0440\u044c audit control_c17 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b \u0438 \u043a\u043e\u0434")
	if err != nil || planned.Status != planner.Ready || planned.Operation != planner.Audit {
		t.Fatalf("plan=%+v err=%v", planned, err)
	}
	selected := []candidate{
		auditCandidate("fragment_01M1PF6RW6NWN5KQ0GTN7DQ1S0", "object_01M1PF6RVZ146VF5YM9S6DYWFB", "text-v1", "# \u041a\u043e\u043d\u0442\u0440\u043e\u043b\u044c C-17: \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u0432\u044b\u0432\u043e\u0437\u0430 \u0422\u041a\u041e\n\ncontrol_c17 = confirmed\n"),
		auditCandidate("fragment_01M1PF6RWZZF93ENS6QDH0TZ8Y", "object_01M1PF6RWW73KNHRJYEDMAB89J", "source-code-v1", "package dispatch\n\n// control_c17 = implemented\n\nfunc ConfirmControlC17() bool { return true }\n"),
	}
	answer, citations := renderAuditControls("tko-operations", planned, selected)
	if !strings.Contains(answer, "Confirmed for control_c17") || len(citations) != 2 {
		t.Fatalf("answer=%q citations=%+v", answer, citations)
	}
}
