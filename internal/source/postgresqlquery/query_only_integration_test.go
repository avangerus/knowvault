package postgresqlquery

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestQueryOnlyPartitionedTableAgainstRealPostgreSQL is S3 card 4's real-server
// proof for a partitioned parent relation:
//
//   - discovery lists the partitioned parent once, as one PREPARED relation,
//     and never lists its individually-created partition child;
//   - the query-only projection derived from it keeps the same column contract
//     (so the relation stays addressable by knowvault_source_sql) and the
//     generated read SQL runs against the real table;
//   - the least-privilege query role that holds SELECT only on the projected
//     columns can query the relation, and PostgreSQL itself refuses the column
//     the administrator excluded.
func TestQueryOnlyPartitionedTableAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the query-only partitioned-table proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("admin PostgreSQL connection: %v", err)
	}
	var reader *pgx.Conn
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if reader != nil {
			_ = reader.Close(closeCtx)
		}
		_, _ = admin.Exec(closeCtx, `DROP SCHEMA IF EXISTS "kv_s34_query_only" CASCADE`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_s34_query_only_reader"`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_s34_query_only_query"`)
		_ = admin.Close(closeCtx)
	}()

	_, err = admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_s34_query_only" CASCADE;
		DROP ROLE IF EXISTS "kv_s34_query_only_reader";
		DROP ROLE IF EXISTS "kv_s34_query_only_query";
		CREATE SCHEMA "kv_s34_query_only";
		CREATE TABLE "kv_s34_query_only"."trips" (
			trip_id uuid NOT NULL,
			started_at timestamptz NOT NULL,
			carrier text NOT NULL,
			driver_phone text NOT NULL,
			PRIMARY KEY (trip_id, started_at)
		) PARTITION BY RANGE (started_at);
		CREATE TABLE "kv_s34_query_only"."trips_2026" PARTITION OF "kv_s34_query_only"."trips"
			FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
		INSERT INTO "kv_s34_query_only"."trips" (trip_id, started_at, carrier, driver_phone) VALUES
			('550e8400-e29b-41d4-a716-4466554400a1', '2026-03-01T08:00:00Z', 'Northwind', '+1-555-0100-0001'),
			('550e8400-e29b-41d4-a716-4466554400a2', '2026-03-02T09:00:00Z', 'Northwind', '+1-555-0100-0002');
		CREATE ROLE "kv_s34_query_only_reader" LOGIN PASSWORD 'kv-s34-query-only-reader';
		ALTER ROLE "kv_s34_query_only_reader" SET temp_file_limit = '256MB';
		ALTER ROLE "kv_s34_query_only_reader" SET default_transaction_read_only = 'on';
		GRANT USAGE ON SCHEMA "kv_s34_query_only" TO "kv_s34_query_only_reader";
		GRANT SELECT ON "kv_s34_query_only"."trips" TO "kv_s34_query_only_reader";
		ANALYZE "kv_s34_query_only"."trips";
	`)
	if err != nil {
		t.Fatalf("seed partitioned source table: %v", err)
	}

	readerURL, err := queryOnlyReaderURL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = pgx.Connect(ctx, readerURL)
	if err != nil {
		t.Fatalf("read-only discovery role connection: %v", err)
	}
	views, err := discoverViewsForConnection(ctx, reader, "conn_s34_query_only", DefaultDiscoveryLimits())
	if err != nil {
		t.Fatalf("discover partitioned catalog: %v (code=%s)", err, CodeOf(err))
	}
	byName := make(map[string]ViewDiscovery, len(views))
	for _, view := range views {
		byName[view.RelationName] = view
	}
	trips, ok := byName["trips"]
	if !ok || trips.RelationKind != "PARTITIONED_TABLE" || trips.Status != DiscoveryPrepared || trips.Projection == nil {
		t.Fatalf("partitioned parent discovery=%#v", trips)
	}
	if _, listed := byName["trips_2026"]; listed {
		t.Fatalf("the partition child was independently listed: %#v", views)
	}

	// The administrator excludes the personal-data column at registration and
	// registers the relation query-only. The mode and the exclusion are both
	// part of the immutable contract.
	var phoneOrdinal int
	for _, column := range trips.Columns {
		if column.Name == "driver_phone" {
			phoneOrdinal = column.Ordinal
		}
	}
	if phoneOrdinal == 0 {
		t.Fatalf("driver_phone column not discovered: %#v", trips.Columns)
	}
	narrowed, err := NarrowProjection(*trips.Projection, map[int]bool{phoneOrdinal: true})
	if err != nil {
		t.Fatalf("narrow partitioned projection: %v", err)
	}
	queryOnly, err := WithQueryOnly(narrowed, true)
	if err != nil {
		t.Fatalf("query-only partitioned projection: %v", err)
	}
	if !queryOnly.QueryOnly || queryOnly.RelationKind != "PARTITIONED_TABLE" {
		t.Fatalf("query-only projection=%#v", queryOnly)
	}
	if len(queryOnly.Columns) != 3 {
		t.Fatalf("query-only columns=%#v, want the three projected columns", queryOnly.Columns)
	}
	for _, column := range queryOnly.Columns {
		if column.Name == "driver_phone" {
			t.Fatalf("excluded column leaked into the query-only projection: %#v", queryOnly.Columns)
		}
	}

	// The registered projection's own generated SELECT runs over the real
	// partitioned parent and reads only the projected columns.
	snapshot, err := ReadProjection(ctx, admin, queryOnly, DefaultLimits())
	if err != nil {
		t.Fatalf("read query-only partitioned projection: %v", err)
	}
	if snapshot.RowCount != 2 || len(snapshot.Rows) != 2 {
		t.Fatalf("query-only partitioned snapshot=%#v, want 2 rows", snapshot)
	}

	// The least-privilege query role proves the same boundary
	// knowvault_source_sql relies on: the table is queryable, the excluded
	// column is refused by PostgreSQL itself.
	if _, err := admin.Exec(ctx, `
		CREATE ROLE "kv_s34_query_only_query" LOGIN PASSWORD 'kv-s34-query-only-query';
		GRANT USAGE ON SCHEMA "kv_s34_query_only" TO "kv_s34_query_only_query";
		GRANT SELECT (trip_id, started_at, carrier) ON "kv_s34_query_only"."trips" TO "kv_s34_query_only_query";
	`); err != nil {
		t.Fatalf("grant least-privilege query role: %v", err)
	}
	queryConn, err := queryOnlyRoleURL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close(ctx)
	reader, err = pgx.Connect(ctx, queryConn)
	if err != nil {
		t.Fatalf("query role connection: %v", err)
	}
	var count int
	if err := reader.QueryRow(ctx, `SELECT count(*) FROM "kv_s34_query_only"."trips"`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("query role count=%d err=%v, want the partitioned relation to be queryable", count, err)
	}
	if err := reader.QueryRow(ctx, `SELECT driver_phone FROM "kv_s34_query_only"."trips" LIMIT 1`).Scan(new(string)); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("excluded column read = %v, want a permission denial", err)
	}
}

func queryOnlyReaderURL(raw string) (string, error) {
	return queryOnlyURLWithRole(raw, "kv_s34_query_only_reader", "kv-s34-query-only-reader")
}

func queryOnlyRoleURL(raw string) (string, error) {
	return queryOnlyURLWithRole(raw, "kv_s34_query_only_query", "kv-s34-query-only-query")
}

func queryOnlyURLWithRole(raw, role, password string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "postgres" {
		return "", err
	}
	parsed.User = url.UserPassword(role, password)
	parsed.RawQuery = "sslmode=disable"
	return parsed.String(), nil
}
