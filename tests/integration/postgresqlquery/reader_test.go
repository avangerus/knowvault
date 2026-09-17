package postgresqlquery_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestReadProjectionAgainstExternalPostgreSQL18(t *testing.T) {
	url := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if url == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the real external-cluster proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("%v cause=%v", err, errors.Unwrap(err))
	}
	defer connection.Close(context.Background())
	const schema = "kv_pgq_acceptance"
	_, err = connection.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_acceptance" CASCADE;
		CREATE SCHEMA "kv_pgq_acceptance";
		CREATE TABLE "kv_pgq_acceptance"."waste_daily_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
		INSERT INTO "kv_pgq_acceptance"."waste_daily_data" VALUES
			('550e8400-e29b-41d4-a716-446655440000', '2026-08-29T09:34:56.789Z', 12.345, 'North route'),
			('550e8400-e29b-41d4-a716-446655440001', '2026-08-29T10:34:56.789Z', 7.125, 'South route');
		CREATE VIEW "kv_pgq_acceptance"."waste_daily" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_acceptance"."waste_daily_data";
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = connection.Exec(context.Background(), `DROP SCHEMA "kv_pgq_acceptance" CASCADE`) }()

	projection := postgresqlquery.Projection{
		ConnectionID: "conn_external", DatabaseIdentity: "cluster_external", LineageID: "lineage_waste",
		Revision: 1, ContractHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchemaName: schema, RelationName: "waste_daily", RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "collected_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint}, Precision: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "tonnes", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 4, Name: "note", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("projection validate: %v", err)
	}
	limits := postgresqlquery.DefaultLimits()
	limits.MaxRows = 2
	limits.MaxFieldBytes = 4096
	limits.MaxRowBytes = 1 << 20
	limits.MaxTotalBytes = 1 << 20
	snapshot, err := postgresqlquery.ReadProjection(ctx, connection, projection, limits)
	if err != nil {
		t.Fatalf("%v cause=%v", err, errors.Unwrap(err))
	}
	if !snapshot.CoverageComplete || snapshot.RowCount != 2 || snapshot.SnapshotHash == "" {
		t.Fatalf("unexpected complete snapshot: %#v", snapshot)
	}
	if len(snapshot.Rows) != 2 || snapshot.Rows[0].Hash == snapshot.Rows[1].Hash {
		t.Fatal("distinct external rows collapsed to one canonical version")
	}

	limits.MaxRows = 1
	if _, err := postgresqlquery.ReadProjection(ctx, connection, projection, limits); postgresqlquery.CodeOf(err) != postgresqlquery.CodeLimitExceeded {
		t.Fatalf("row cap did not fail closed: err=%v code=%s", err, postgresqlquery.CodeOf(err))
	}
}
