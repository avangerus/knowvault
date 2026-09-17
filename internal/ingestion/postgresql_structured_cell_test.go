package ingestion

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// TestStructuredCellPlansCarryDeclaredTitleAndPeriodRoles is FIX-3 #1's
// ingestion-side guard: the worker's typed projection (structuredCellPlan,
// db/migrations/000073 title_role and 000081 period_role) must carry the
// operator's own TITLE and PERIOD declarations from the column contract
// (internal/source/postgresqlquery/contract.go) through to the row the
// reducer (internal/question/snapshot_aggregate.go) later reads -- neither
// role is ever inferred from column order or name.
func TestStructuredCellPlansCarryDeclaredTitleAndPeriodRoles(t *testing.T) {
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "fleet_trips",
		Revision: 1, ContractHash: "sha256:" + strings.Repeat("a", 64),
		SchemaName: "reporting", RelationName: "fleet_trips_v", RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "trip_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "vehicle", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence, postgresqlquery.RoleTitle}, MaxBytes: 128},
			{Ordinal: 3, Name: "started_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence, postgresqlquery.RolePeriod}, Precision: 3, MaxBytes: 64},
			{Ordinal: 4, Name: "logged_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 3, MaxBytes: 64},
			{Ordinal: 5, Name: "status", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence, postgresqlquery.RoleStatus}, MaxBytes: 32},
		},
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("test fixture projection must validate: %v", err)
	}
	row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000", "V-101", "2026-09-07T08:00:00Z", "2026-09-07T08:05:00Z", "IN_TRANSIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := "hmac-sha256:k1:" + strings.Repeat("b", 64)
	plans, err := structuredCellPlans(PostgreSQLSnapshotRequest{Projection: projection}, identity, row)
	if err != nil {
		t.Fatal(err)
	}
	byColumn := make(map[string]structuredCellPlan, len(plans))
	for _, plan := range plans {
		if plan.columnName != "" {
			byColumn[plan.columnName] = plan
		}
	}
	vehicle, ok := byColumn["vehicle"]
	if !ok || !vehicle.titleRole || vehicle.periodRole {
		t.Fatalf("vehicle plan=%+v ok=%v, want titleRole=true periodRole=false", vehicle, ok)
	}
	startedAt, ok := byColumn["started_at"]
	if !ok || startedAt.titleRole || !startedAt.periodRole {
		t.Fatalf("started_at plan=%+v ok=%v, want titleRole=false periodRole=true", startedAt, ok)
	}
	loggedAt, ok := byColumn["logged_at"]
	if !ok || loggedAt.titleRole || loggedAt.periodRole {
		t.Fatalf("logged_at plan=%+v ok=%v, want titleRole=false periodRole=false (undeclared temporal column)", loggedAt, ok)
	}
	// SEED-3 #1: the declared STATUS role (contract.go RoleStatus) must reach
	// the plan the same way TITLE/PERIOD already do -- the overdue reducer
	// (snapshot_aggregate.go) reads it to tell a genuinely overdue row from
	// one whose due date passed but is already closed.
	status, ok := byColumn["status"]
	if !ok || !status.statusRole || status.titleRole || status.periodRole {
		t.Fatalf("status plan=%+v ok=%v, want statusRole=true titleRole=false periodRole=false", status, ok)
	}
}
