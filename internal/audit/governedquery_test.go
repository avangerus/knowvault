package audit

import (
	"testing"
	"time"
)

func governedQueryBaseInput(outcome string) EventInput {
	workspace := "ws_alpha"
	actor := "usr_alice"
	connection := "gq_conn_01"
	revision := int64(1)
	sqlHash := "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	outcomeValue := outcome
	return EventInput{
		EventID: "aud_gq_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionGovernedQueryAttempted, ResourceType: ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: "req_gq_001", Outcome: OutcomeSuccess,
		Metadata: Metadata{
			GovernedQueryConnectionID: &connection, GovernedQueryExposedSchemaRevision: &revision,
			GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcomeValue,
		},
		OccurredAt: time.Date(2026, time.September, 7, 10, 0, 0, 0, time.UTC),
	}
}

func TestGovernedQueryAttemptSucceeded(t *testing.T) {
	cost := int64(120)
	rows := int64(2)
	digest := "sha256:0000000000000000000000000000000000000000000000000000000000000002"
	input := governedQueryBaseInput(GovernedQueryOutcomeSucceeded)
	input.Metadata.GovernedQueryCostEstimate = &cost
	input.Metadata.GovernedQueryRowCount = &rows
	input.Metadata.GovernedQueryResultDigest = &digest

	if _, err := Build("org_alpha", input, 0, ""); err != nil {
		t.Fatalf("expected a valid SUCCEEDED governed-query event, got %v", err)
	}
}

func TestGovernedQueryAttemptRejectedStaticNeedsNoCost(t *testing.T) {
	input := governedQueryBaseInput(GovernedQueryOutcomeRejectedStatic)
	if _, err := Build("org_alpha", input, 0, ""); err != nil {
		t.Fatalf("expected a valid REJECTED_STATIC governed-query event without cost/row/digest, got %v", err)
	}
}

func TestGovernedQueryAttemptSucceededRequiresCostRowDigest(t *testing.T) {
	input := governedQueryBaseInput(GovernedQueryOutcomeSucceeded)
	if _, err := Build("org_alpha", input, 0, ""); err == nil {
		t.Fatalf("expected a SUCCEEDED event missing cost/row/digest to be rejected")
	}
}

func TestGovernedQueryMetadataNeverLeaksOntoOtherActions(t *testing.T) {
	workspace := "ws_alpha"
	actor := "usr_alice"
	connection := "gq_conn_01"
	input := EventInput{
		EventID: "aud_leak_001", WorkspaceID: &workspace, ActorType: ActorHuman, ActorPrincipalID: &actor,
		Action: ActionQuestionCreated, ResourceType: ResourceQuestionRun, ResourceID: "qr_001",
		RequestID: "req_leak_001", Outcome: OutcomeSuccess,
		Metadata:   Metadata{GovernedQueryConnectionID: &connection},
		OccurredAt: time.Date(2026, time.September, 7, 10, 0, 0, 0, time.UTC),
	}
	if _, err := Build("org_alpha", input, 0, ""); err == nil {
		t.Fatalf("expected governed-query metadata on an unrelated action to be rejected")
	}
}

func TestGovernedQueryOutcomeMustBeClosed(t *testing.T) {
	bogus := "MAYBE"
	input := governedQueryBaseInput(GovernedQueryOutcomeRejectedStatic)
	input.Metadata.GovernedQueryOutcome = &bogus
	if _, err := Build("org_alpha", input, 0, ""); err == nil {
		t.Fatalf("expected a non-closed outcome value to be rejected")
	}
}
