package governedquery

import (
	"context"
	"testing"
)

func TestStaticPrecheck(t *testing.T) {
	valid := []string{
		"SELECT count(*) FROM fleet_trips WHERE driver = '\u0418\u0432\u0430\u043d\u043e\u0432'",
		"select vehicle, driver from fleet_trips",
		"WITH t AS (SELECT 1) SELECT * FROM t",
		"SELECT count(*) FROM fleet_trips;",
	}
	for _, sqlText := range valid {
		if err := staticPrecheck(sqlText); err != nil {
			t.Fatalf("expected %q to pass static precheck, got %v", sqlText, err)
		}
	}
	invalid := []string{
		"",
		"   ",
		"DELETE FROM fleet_trips",
		"INSERT INTO fleet_trips VALUES (1)",
		"DROP TABLE fleet_trips",
		"SELECT * FROM fleet_trips; DROP TABLE fleet_trips",
		"SELECT * FROM fleet_trips -- ; DROP TABLE fleet_trips",
		"SELECT * FROM fleet_trips /* comment */",
		"UPDATE fleet_trips SET status='DONE'",
		"COPY fleet_trips TO '/tmp/x'",
		"GRANT SELECT ON fleet_trips TO PUBLIC",
		"SET statement_timeout = 0",
		"CALL some_procedure()",
		"vehicle_selection", // does not start with SELECT/WITH
	}
	for _, sqlText := range invalid {
		if err := staticPrecheck(sqlText); err == nil {
			t.Fatalf("expected %q to be rejected by static precheck", sqlText)
		}
	}
}

func TestExecuteRejectsInvalidInput(t *testing.T) {
	config := Config{
		ConnectionID: "demo-ops-govquery", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN: "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
	_, attempt, err := Execute(context.Background(), config, ExecuteParams{SQLText: "DELETE FROM fleet_trips", ExposedSchemaRevision: 1})
	if err == nil {
		t.Fatalf("expected rejection")
	}
	if attempt.Outcome != OutcomeRejectedStatic {
		t.Fatalf("expected REJECTED_STATIC outcome, got %v", attempt.Outcome)
	}
	if attempt.SQLHash == "" {
		t.Fatalf("expected a content-free SQL hash to still be recorded")
	}

	_, _, err = Execute(context.Background(), config, ExecuteParams{SQLText: "SELECT 1", ExposedSchemaRevision: 0})
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("expected CodeInvalid for a missing exposed schema revision, got %v", CodeOf(err))
	}
}

func TestContainsWord(t *testing.T) {
	if !containsWord("select 1; drop table x", "drop") {
		t.Fatalf("expected to find whole word 'drop'")
	}
	if containsWord("select dropdown from x", "drop") {
		t.Fatalf("did not expect 'drop' inside 'dropdown' to match")
	}
}
