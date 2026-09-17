package governedquery

import (
	"context"
	"testing"
)

func executedAttempt(sqlText string) ExecutedAttempt {
	return ExecutedAttempt{
		AttemptID: "gqat_01J000000000000000000000", ConnectionID: "demo-ops-govquery",
		ExposedSchemaRevision: 1, SQLText: sqlText, SQLHash: sha256Hex(sqlText),
	}
}

func TestPromoteToProjectionRecordsTheExecutedAttempt(t *testing.T) {
	attempt := executedAttempt("SELECT count(*) FROM fleet_trips")
	result, err := PromoteToProjection(context.Background(), PromotionRequest{
		ConnectionID: "demo-ops-govquery", PrincipalID: "principal_01",
		ExpectedSQLHash: attempt.SQLHash, Attempt: attempt,
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result.Status != PromotionRecordedPendingIntegration {
		t.Fatalf("expected RECORDED_PENDING_INTEGRATION, got %v", result.Status)
	}
	if result.AttemptID != attempt.AttemptID || result.SQLHash != attempt.SQLHash {
		t.Fatalf("expected the executed attempt's identity, got %+v", result)
	}
}

// The whole point of the correction: the operator confirms an attempt by
// reference and hash. A hash that does not match what is stored is refused
// content-free, so a caller can neither substitute a different statement nor
// learn anything from the refusal.
func TestPromoteToProjectionRejectsHashMismatch(t *testing.T) {
	attempt := executedAttempt("SELECT count(*) FROM fleet_trips")
	_, err := PromoteToProjection(context.Background(), PromotionRequest{
		ConnectionID: "demo-ops-govquery", PrincipalID: "principal_01",
		ExpectedSQLHash: sha256Hex("SELECT count(*) FROM other_table"), Attempt: attempt,
	})
	if err == nil {
		t.Fatalf("expected a refusal when the confirmed hash is not the attempt's hash")
	}
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("expected a content-free CodeInvalid refusal, got %v", CodeOf(err))
	}
}

// A stored hash that does not describe the stored text means the record was
// tampered with; the promotion must fail closed rather than trust the column.
func TestPromoteToProjectionRejectsTamperedAttemptRecord(t *testing.T) {
	attempt := executedAttempt("SELECT count(*) FROM fleet_trips")
	attempt.SQLText = "SELECT count(*) FROM payroll"
	_, err := PromoteToProjection(context.Background(), PromotionRequest{
		ConnectionID: "demo-ops-govquery", PrincipalID: "principal_01",
		ExpectedSQLHash: attempt.SQLHash, Attempt: attempt,
	})
	if err == nil {
		t.Fatalf("expected a refusal when the stored hash does not describe the stored text")
	}
}

func TestPromoteToProjectionRejectsAttemptFromAnotherConnection(t *testing.T) {
	attempt := executedAttempt("SELECT count(*) FROM fleet_trips")
	attempt.ConnectionID = "other-connection"
	_, err := PromoteToProjection(context.Background(), PromotionRequest{
		ConnectionID: "demo-ops-govquery", PrincipalID: "principal_01",
		ExpectedSQLHash: attempt.SQLHash, Attempt: attempt,
	})
	if err == nil {
		t.Fatalf("expected a refusal when the attempt belongs to another connection")
	}
}

func TestPromoteToProjectionRejectsUnsafeSQL(t *testing.T) {
	attempt := executedAttempt("DELETE FROM fleet_trips")
	_, err := PromoteToProjection(context.Background(), PromotionRequest{
		ConnectionID: "demo-ops-govquery", PrincipalID: "principal_01",
		ExpectedSQLHash: attempt.SQLHash, Attempt: attempt,
	})
	if err == nil {
		t.Fatalf("expected rejection of a non-SELECT promotion candidate")
	}
}
