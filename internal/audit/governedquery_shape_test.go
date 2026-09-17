package audit

import (
	"testing"
	"time"
)

// The governed-query attempt event is appended by a caller that discards the
// append error (ADR-0089 §4's audit is best-effort at the call site), so a shape
// the validator rejects disappears without a trace. This pins the exact shape
// internal/governedask emits for a successful attempt.
func TestGovernedQueryAttemptEventBuilds(t *testing.T) {
	workspaceID := "tko-operations"
	actorID := "demo-admin"
	connectionID := "demo-ops-govquery"
	sqlHash := "sha256:" + "12d33c57c0edc6d090342ac262001e699e23ebd7884c6dc2c31882239770f02a"
	digest := "sha256:" + "22d33c57c0edc6d090342ac262001e699e23ebd7884c6dc2c31882239770f02a"
	revision := int64(1)
	cost := int64(12)
	rows := int64(1)
	outcome := GovernedQueryOutcomeSucceeded
	input := EventInput{
		EventID: "gqa_01M1WZZGSWJCM36MJ3KCXAD0AS", WorkspaceID: &workspaceID,
		ActorType: ActorHuman, ActorPrincipalID: &actorID,
		Action: ActionGovernedQueryAttempted, ResourceType: ResourceGovernedQueryAttempt,
		ResourceID: sqlHash, RequestID: "gqa_01M1WZZGSWJCM36MJ3KCXAD0AS", Outcome: OutcomeSuccess,
		Metadata: Metadata{
			GovernedQueryConnectionID: &connectionID, GovernedQueryExposedSchemaRevision: &revision,
			GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcome,
			GovernedQueryCostEstimate: &cost, GovernedQueryRowCount: &rows, GovernedQueryResultDigest: &digest,
		},
		OccurredAt: time.Unix(1757000000, 0).UTC(),
	}
	if _, err := Build("knowvault-demo", input, 0, ""); err != nil {
		t.Fatalf("governed query attempt event does not build: %v", err)
	}
}
