package postgresqlquery

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestDiscoveryCatalogAgainstRealPostgreSQL proves catalog-only discovery on
// a real PostgreSQL server. The local CI database is intentionally non-TLS,
// so this test exercises the unexported catalog transaction after the
// production LiveConnector's trusted resolver/TLS opener; callers cannot use
// this seam outside the source package.
func TestDiscoveryCatalogAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL discovery proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		_, _ = admin.Exec(closeCtx, `DROP SCHEMA IF EXISTS "kv_pgq_discovery" CASCADE`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_pgq_discovery_reader"`)
		_ = admin.Close(closeCtx)
	}()

	_, err = admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_discovery" CASCADE;
		DROP ROLE IF EXISTS "kv_pgq_discovery_reader";
		CREATE SCHEMA "kv_pgq_discovery";
		CREATE TABLE "kv_pgq_discovery"."prepared_rows" (
			entity_id uuid NOT NULL,
			entity_version text NOT NULL,
			last_updated_at timestamptz NOT NULL,
			payload jsonb NOT NULL,
			payload_format text NOT NULL,
			amount numeric(12,3) NOT NULL,
			negative_amount numeric(3,-2) NOT NULL
		);
		CREATE VIEW "kv_pgq_discovery"."prepared_view" AS
			SELECT entity_id, entity_version, last_updated_at, payload, payload_format, amount
			FROM "kv_pgq_discovery"."prepared_rows";
		COMMENT ON VIEW "kv_pgq_discovery"."prepared_view" IS 'prepared business-object source';
		COMMENT ON COLUMN "kv_pgq_discovery"."prepared_view"."amount" IS 'amount in tonnes';
		CREATE VIEW "kv_pgq_discovery"."unknown_view" AS
			SELECT entity_id AS id, last_updated_at::date AS due_at, payload_format AS status
			FROM "kv_pgq_discovery"."prepared_rows";
		CREATE VIEW "kv_pgq_discovery"."malformed_view" AS
			SELECT entity_id, entity_version, last_updated_at, amount AS payload, payload_format
			FROM "kv_pgq_discovery"."prepared_rows";
		CREATE VIEW "kv_pgq_discovery"."quoted_column_view" AS
			SELECT entity_id, entity_version, last_updated_at, payload, payload_format,
				amount AS "gross amount"
			FROM "kv_pgq_discovery"."prepared_rows";
		CREATE VIEW "kv_pgq_discovery"."negative_scale_view" AS
			SELECT entity_id, entity_version, last_updated_at, payload, payload_format, negative_amount
			FROM "kv_pgq_discovery"."prepared_rows";
		CREATE VIEW "kv_pgq_discovery"."hidden_view" AS
			SELECT entity_id, entity_version, last_updated_at, payload, payload_format
			FROM "kv_pgq_discovery"."prepared_rows";
		CREATE VIEW "kv_pgq_discovery"."oversized_view" AS
			SELECT entity_id, entity_version, last_updated_at, payload, payload_format
			FROM "kv_pgq_discovery"."prepared_rows";
		DO $comment$
		BEGIN
			EXECUTE pg_catalog.format('COMMENT ON VIEW %I.%I IS %L', 'kv_pgq_discovery', 'oversized_view', pg_catalog.repeat('x', 5000));
		END
		$comment$;
		CREATE ROLE "kv_pgq_discovery_reader" LOGIN PASSWORD 'kv-pg-discovery-reader';
		ALTER ROLE "kv_pgq_discovery_reader" SET temp_file_limit = '256MB';
		ALTER ROLE "kv_pgq_discovery_reader" SET default_transaction_read_only = 'on';
		GRANT USAGE ON SCHEMA "kv_pgq_discovery" TO "kv_pgq_discovery_reader";
		GRANT SELECT ON "kv_pgq_discovery"."prepared_view", "kv_pgq_discovery"."unknown_view", "kv_pgq_discovery"."malformed_view", "kv_pgq_discovery"."quoted_column_view", "kv_pgq_discovery"."negative_scale_view" TO "kv_pgq_discovery_reader";
	`)
	if err != nil {
		t.Fatalf("seed discovery catalog: %v", err)
	}
	readerURL, err := discoveryReaderURL(dsn)
	if err != nil {
		t.Fatal(err)
	}
	reader, err = pgx.Connect(ctx, readerURL)
	if err != nil {
		t.Fatalf("read-only discovery role connection: %v", err)
	}
	limits := DefaultDiscoveryLimits()
	views, err := discoverViewsForConnection(ctx, reader, "conn_pg_discovery", limits)
	if err != nil {
		t.Fatalf("discover visible views: %v (code=%s)", err, CodeOf(err))
	}
	byName := make(map[string]ViewDiscovery, len(views))
	for _, view := range views {
		byName[view.RelationName] = view
	}
	prepared, ok := byName["prepared_view"]
	if !ok {
		t.Fatalf("prepared view was not visible: %#v", byName)
	}
	if prepared.Status != DiscoveryPrepared || prepared.Projection == nil || prepared.RelationOID == 0 || prepared.DatabaseOID == 0 || prepared.Comment != "prepared business-object source" {
		t.Fatalf("prepared discovery=%#v", prepared)
	}
	if prepared.Columns[5].TypeOID != 1700 || prepared.Columns[5].Precision != 12 || prepared.Columns[5].Scale != 3 || prepared.Columns[5].TypeFingerprint != "oid:1700:p:12:s:3" || prepared.Columns[5].Comment != "amount in tonnes" {
		t.Fatalf("numeric/native metadata=%#v", prepared.Columns[5])
	}
	if prepared.Projection.ConnectionID != "conn_pg_discovery" || prepared.Projection.ContractHash == "" {
		t.Fatalf("server projection identity=%#v", prepared.Projection)
	}
	if _, err := prepared.Projection.SelectSQL(); err != nil {
		t.Fatalf("generated projection SQL contract: %v", err)
	}
	snapshot, err := discoverCatalogSnapshot(ctx, reader, "conn_pg_discovery", "", "", limits)
	if err != nil {
		t.Fatalf("discover catalog snapshot: %v (code=%s)", err, CodeOf(err))
	}
	if snapshot.DatabaseOID == 0 || snapshot.DatabaseName == "" || len(snapshot.Views) != len(views) || !strings.HasPrefix(snapshot.PrivilegeDigest, "sha256:") {
		t.Fatalf("catalog snapshot identity/digest = %#v", snapshot)
	}
	repeatedSnapshot, err := discoverCatalogSnapshot(ctx, reader, "conn_pg_discovery", "", "", limits)
	if err != nil {
		t.Fatalf("repeat catalog snapshot: %v (code=%s)", err, CodeOf(err))
	}
	if snapshot.DatabaseOID != repeatedSnapshot.DatabaseOID || snapshot.DatabaseName != repeatedSnapshot.DatabaseName || snapshot.PrivilegeDigest != repeatedSnapshot.PrivilegeDigest {
		t.Fatalf("catalog snapshot changed without catalog mutation: first=%#v second=%#v", snapshot, repeatedSnapshot)
	}
	unknown, ok := byName["unknown_view"]
	if !ok || unknown.Status != DiscoveryNeedsInterpretation || unknown.Interpretation != InterpretationUnrecognizedFormat || unknown.Projection != nil {
		t.Fatalf("unknown view was interpreted: %#v", unknown)
	}
	malformed, ok := byName["malformed_view"]
	if !ok || malformed.Status != DiscoveryNeedsInterpretation || malformed.Interpretation != InterpretationMalformedContract || malformed.Projection != nil {
		t.Fatalf("malformed view result=%#v", malformed)
	}
	quoted, ok := byName["quoted_column_view"]
	if !ok || quoted.Status != DiscoveryNeedsInterpretation || quoted.Interpretation != InterpretationInvalidIdentifier || quoted.Projection != nil || len(quoted.Columns) != 6 || quoted.Columns[5].Name != "gross amount" {
		t.Fatalf("quoted-column view result=%#v", quoted)
	}
	negative, ok := byName["negative_scale_view"]
	if !ok || negative.Status != DiscoveryNeedsInterpretation || negative.Interpretation != InterpretationUnsupportedType || negative.Projection != nil || len(negative.Columns) != 6 {
		t.Fatalf("negative-scale view result=%#v", negative)
	}
	negativeColumn := negative.Columns[5]
	if negativeColumn.TypeOID != 1700 || negativeColumn.Precision != 3 || negativeColumn.Scale != -2 || negativeColumn.TypeFingerprint != "oid:1700:p:3:s:-2" {
		t.Fatalf("negative-scale metadata=%#v", negativeColumn)
	}

	if _, err := admin.Exec(ctx, `GRANT SELECT ON "kv_pgq_discovery"."oversized_view" TO "kv_pgq_discovery_reader"`); err != nil {
		t.Fatalf("grant oversized test view: %v", err)
	}
	if _, err := discoverViewForConnection(ctx, reader, "conn_pg_discovery", "kv_pgq_discovery", "oversized_view", limits); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("oversized native comment code=%s err=%v", CodeOf(err), err)
	}
	if _, err := discoverViewForConnection(ctx, reader, "conn_pg_discovery", "kv_pgq_discovery", "hidden_view", limits); CodeOf(err) != CodeDiscoveryUnavailable {
		t.Fatalf("hidden view code=%s err=%v", CodeOf(err), err)
	}
}

// TestDiscoveryCatalogTablesAgainstRealPostgreSQL is the S1 real-server
// counterpart of TestDiscoveryCatalogAgainstRealPostgreSQL: a base table with
// a primary key is PREPARED with IDENTITY on the key column(s) and an
// approximate row count; a table without one is NO_PRIMARY_KEY; a partitioned
// table follows the same primary-key rule and its individual partition child
// is not independently discovered; and a column this role cannot itself
// SELECT (a customer's own column-level REVOKE) is dropped from that table's
// discovered columns instead of hiding the whole table.
func TestDiscoveryCatalogTablesAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL table discovery proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		_, _ = admin.Exec(closeCtx, `DROP SCHEMA IF EXISTS "kv_pgq_discovery_table" CASCADE`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_pgq_discovery_table_reader"`)
		_ = admin.Close(closeCtx)
	}()

	_, err = admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_discovery_table" CASCADE;
		DROP ROLE IF EXISTS "kv_pgq_discovery_table_reader";
		CREATE SCHEMA "kv_pgq_discovery_table";
		CREATE TABLE "kv_pgq_discovery_table"."accounts" (
			account_id uuid PRIMARY KEY,
			display_name text NOT NULL,
			phone text NOT NULL
		);
		COMMENT ON TABLE "kv_pgq_discovery_table"."accounts" IS 'customer accounts';
		CREATE TABLE "kv_pgq_discovery_table"."events_log" (
			occurred_at timestamptz NOT NULL,
			message text NOT NULL
		);
		CREATE TABLE "kv_pgq_discovery_table"."measurements" (
			measurement_id uuid NOT NULL,
			taken_at timestamptz NOT NULL,
			value numeric(10,2) NOT NULL,
			PRIMARY KEY (measurement_id, taken_at)
		) PARTITION BY RANGE (taken_at);
		CREATE TABLE "kv_pgq_discovery_table"."measurements_2026" PARTITION OF "kv_pgq_discovery_table"."measurements"
			FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');
		CREATE ROLE "kv_pgq_discovery_table_reader" LOGIN PASSWORD 'kv-pg-discovery-table-reader';
		ALTER ROLE "kv_pgq_discovery_table_reader" SET temp_file_limit = '256MB';
		ALTER ROLE "kv_pgq_discovery_table_reader" SET default_transaction_read_only = 'on';
		GRANT USAGE ON SCHEMA "kv_pgq_discovery_table" TO "kv_pgq_discovery_table_reader";
		GRANT SELECT ON "kv_pgq_discovery_table"."events_log", "kv_pgq_discovery_table"."measurements" TO "kv_pgq_discovery_table_reader";
		-- A whole-relation GRANT and a later column-level REVOKE do not
		-- compose: the whole-relation grant keeps covering every column
		-- regardless of a later per-column REVOKE. A DBA who wants the role
		-- to see only some columns must GRANT exactly those columns instead,
		-- which is also the realistic shape of a customer's own pre-existing
		-- column lockdown that this test proves discovery degrades to.
		GRANT SELECT (account_id, display_name) ON "kv_pgq_discovery_table"."accounts" TO "kv_pgq_discovery_table_reader";
		ANALYZE "kv_pgq_discovery_table"."accounts";
	`)
	if err != nil {
		t.Fatalf("seed table discovery catalog: %v", err)
	}
	readerURL, err := discoveryReaderURLAs(dsn, "kv_pgq_discovery_table_reader", "kv-pg-discovery-table-reader")
	if err != nil {
		t.Fatal(err)
	}
	reader, err = pgx.Connect(ctx, readerURL)
	if err != nil {
		t.Fatalf("read-only table discovery role connection: %v", err)
	}
	limits := DefaultDiscoveryLimits()
	views, err := discoverViewsForConnection(ctx, reader, "conn_pg_discovery_table", limits)
	if err != nil {
		t.Fatalf("discover visible tables: %v (code=%s)", err, CodeOf(err))
	}
	byName := make(map[string]ViewDiscovery, len(views))
	for _, view := range views {
		byName[view.RelationName] = view
	}

	accounts, ok := byName["accounts"]
	if !ok {
		t.Fatalf("accounts table was not visible: %#v", byName)
	}
	if accounts.RelationKind != "TABLE" || accounts.Status != DiscoveryPrepared || accounts.Projection == nil ||
		accounts.Comment != "customer accounts" || accounts.ApproxRowCount < -1 {
		t.Fatalf("accounts table discovery=%#v", accounts)
	}
	// The column-REVOKEd "phone" attribute must be entirely absent, not just
	// unreadable: the whole table stays discoverable with its remaining
	// columns instead of vanishing.
	if len(accounts.Columns) != 2 {
		t.Fatalf("accounts columns=%#v, want account_id+display_name only (phone column-REVOKEd)", accounts.Columns)
	}
	var sawKey bool
	for _, column := range accounts.Columns {
		if column.Name == "phone" {
			t.Fatalf("column-REVOKEd phone attribute leaked into discovery: %#v", accounts.Columns)
		}
		if column.Name == "account_id" {
			sawKey = true
			if !column.PrimaryKey {
				t.Fatalf("account_id not reported primary key: %#v", column)
			}
		}
		if column.Name == "display_name" && column.PrimaryKey {
			t.Fatalf("display_name incorrectly reported primary key: %#v", column)
		}
	}
	if !sawKey {
		t.Fatalf("account_id column missing from accounts discovery: %#v", accounts.Columns)
	}
	if !hasRole(accounts.Projection.Columns[0].Roles, RoleIdentity) {
		t.Fatalf("accounts projection identity role=%#v", accounts.Projection.Columns)
	}
	if _, err := accounts.Projection.SelectSQL(); err != nil {
		t.Fatalf("accounts projection SQL: %v", err)
	}

	eventsLog, ok := byName["events_log"]
	if !ok || eventsLog.RelationKind != "TABLE" || eventsLog.Status != DiscoveryNeedsInterpretation ||
		eventsLog.Interpretation != InterpretationNoPrimaryKey || eventsLog.Projection != nil {
		t.Fatalf("keyless events_log table discovery=%#v", eventsLog)
	}

	measurements, ok := byName["measurements"]
	if !ok || measurements.RelationKind != "PARTITIONED_TABLE" || measurements.Status != DiscoveryPrepared || measurements.Projection == nil {
		t.Fatalf("partitioned measurements table discovery=%#v", measurements)
	}
	identityCount := 0
	for _, column := range measurements.Projection.Columns {
		if hasRole(column.Roles, RoleIdentity) {
			identityCount++
		}
	}
	if identityCount != 2 {
		t.Fatalf("composite-key measurements identity columns=%d, want 2: %#v", identityCount, measurements.Projection.Columns)
	}

	// The individually-created partition child is not itself a discovery
	// candidate this connector registers: only the partitioned root is.
	if child, ok := byName["measurements_2026"]; ok {
		t.Fatalf("partition child relation was independently discovered: %#v", child)
	}
}

// TestDiscoveryCatalogManyRelationsAgainstRealPostgreSQL is the S1 fix proof
// for DISCOVERY_LIMIT_EXCEEDED (the GM customer catalog exposes 645
// tables/views in schema public) at the connector's own real-SQL layer: it
// creates 300 real base tables, each with a declared primary key, discovers
// them through the same unexported catalog transaction the production
// LiveConnector uses after its trusted TLS opener, and proves every one of
// the 300 comes back PREPARED under the new 1024-relation durable ceiling
// (DefaultDiscoveryLimits, widened from the old 64). A profile narrower than
// the real relation count still fails closed with CodeLimitExceeded, exactly
// as it always did above the old 64-relation bound.
func TestDiscoveryCatalogManyRelationsAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL many-relation discovery proof")
	}
	const relationCount = 300
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
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
		_, _ = admin.Exec(closeCtx, `DROP SCHEMA IF EXISTS "kv_pgq_discovery_many" CASCADE`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_pgq_discovery_many_reader"`)
		_ = admin.Close(closeCtx)
	}()

	var seed strings.Builder
	seed.WriteString(`
		DROP SCHEMA IF EXISTS "kv_pgq_discovery_many" CASCADE;
		DROP ROLE IF EXISTS "kv_pgq_discovery_many_reader";
		CREATE SCHEMA "kv_pgq_discovery_many";
	`)
	for index := 0; index < relationCount; index++ {
		suffix := strconv.Itoa(index)
		seed.WriteString(`CREATE TABLE "kv_pgq_discovery_many"."t_` + suffix + `" (` +
			`id uuid PRIMARY KEY, display_name text NOT NULL, amount numeric(10,2) NOT NULL);` + "\n")
	}
	seed.WriteString(`
		CREATE ROLE "kv_pgq_discovery_many_reader" LOGIN PASSWORD 'kv-pg-discovery-many-reader';
		ALTER ROLE "kv_pgq_discovery_many_reader" SET temp_file_limit = '256MB';
		ALTER ROLE "kv_pgq_discovery_many_reader" SET default_transaction_read_only = 'on';
		GRANT USAGE ON SCHEMA "kv_pgq_discovery_many" TO "kv_pgq_discovery_many_reader";
		GRANT SELECT ON ALL TABLES IN SCHEMA "kv_pgq_discovery_many" TO "kv_pgq_discovery_many_reader";
	`)
	if _, err := admin.Exec(ctx, seed.String()); err != nil {
		t.Fatalf("seed %d real relations: %v", relationCount, err)
	}

	readerURL, err := discoveryReaderURLAs(dsn, "kv_pgq_discovery_many_reader", "kv-pg-discovery-many-reader")
	if err != nil {
		t.Fatal(err)
	}
	reader, err = pgx.Connect(ctx, readerURL)
	if err != nil {
		t.Fatalf("read-only many-relation discovery role connection: %v", err)
	}

	limits := DefaultDiscoveryLimits()
	if limits.MaxViews != 1024 {
		t.Fatalf("default discovery limits MaxViews = %d, want 1024", limits.MaxViews)
	}
	views, err := discoverViewsForConnection(ctx, reader, "conn_pg_discovery_many", limits)
	if err != nil {
		t.Fatalf("discover %d real relations: %v (code=%s)", relationCount, err, CodeOf(err))
	}
	if len(views) != relationCount {
		t.Fatalf("discovered %d relations, want %d", len(views), relationCount)
	}
	for _, view := range views {
		if view.RelationKind != "TABLE" || view.Status != DiscoveryPrepared || view.Projection == nil {
			t.Fatalf("relation %s.%s discovery=%#v, want PREPARED TABLE", view.SchemaName, view.RelationName, view)
		}
	}

	snapshot, err := discoverCatalogSnapshot(ctx, reader, "conn_pg_discovery_many", "", "", limits)
	if err != nil {
		t.Fatalf("discover %d-relation catalog snapshot: %v (code=%s)", relationCount, err, CodeOf(err))
	}
	if len(snapshot.Views) != relationCount {
		t.Fatalf("catalog snapshot returned %d relations, want %d", len(snapshot.Views), relationCount)
	}

	narrow := limits
	narrow.MaxViews = relationCount - 1
	if _, err := discoverViewsForConnection(ctx, reader, "conn_pg_discovery_many", narrow); CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("narrower-than-actual profile code=%s err=%v, want %s", CodeOf(err), err, CodeLimitExceeded)
	}
}

// TestDiscoveryCatalogUnsupportedColumnExclusionAgainstRealPostgreSQL is
// card D-1's real-server proof: a base table whose only obstacle is one column
// type the query connector cannot project (a PostGIS-style `point` here, any
// unlisted type in production) is PREPARED with that column dropped from the
// sealed projection -- so it can never appear in a read, a search document,
// the schema tool or generated SQL -- and reported back with its own reason.
// A table whose primary key is unsupported, and a table with nothing
// projectable left, stay blocked with UNSUPPORTED_TYPE.
func TestDiscoveryCatalogUnsupportedColumnExclusionAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL unsupported-column discovery proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
		_, _ = admin.Exec(closeCtx, `DROP SCHEMA IF EXISTS "kv_pgq_discovery_excl" CASCADE`)
		_, _ = admin.Exec(closeCtx, `DROP ROLE IF EXISTS "kv_pgq_discovery_excl_reader"`)
		_ = admin.Close(closeCtx)
	}()

	_, err = admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_discovery_excl" CASCADE;
		DROP ROLE IF EXISTS "kv_pgq_discovery_excl_reader";
		CREATE SCHEMA "kv_pgq_discovery_excl";
		CREATE TABLE "kv_pgq_discovery_excl"."sites" (
			site_id uuid PRIMARY KEY,
			site_name text NOT NULL,
			location inet NOT NULL
		);
		CREATE TABLE "kv_pgq_discovery_excl"."shapes" (
			shape_id inet PRIMARY KEY,
			label text NOT NULL
		);
		CREATE TABLE "kv_pgq_discovery_excl"."tiles" (
			tile_id inet PRIMARY KEY,
			raster macaddr NOT NULL
		);
		CREATE ROLE "kv_pgq_discovery_excl_reader" LOGIN PASSWORD 'kv-pg-discovery-excl-reader';
		ALTER ROLE "kv_pgq_discovery_excl_reader" SET temp_file_limit = '256MB';
		ALTER ROLE "kv_pgq_discovery_excl_reader" SET default_transaction_read_only = 'on';
		GRANT USAGE ON SCHEMA "kv_pgq_discovery_excl" TO "kv_pgq_discovery_excl_reader";
		GRANT SELECT ON ALL TABLES IN SCHEMA "kv_pgq_discovery_excl" TO "kv_pgq_discovery_excl_reader";
	`)
	if err != nil {
		t.Fatalf("seed unsupported-column catalog: %v", err)
	}
	readerURL, err := discoveryReaderURLAs(dsn, "kv_pgq_discovery_excl_reader", "kv-pg-discovery-excl-reader")
	if err != nil {
		t.Fatal(err)
	}
	reader, err = pgx.Connect(ctx, readerURL)
	if err != nil {
		t.Fatalf("read-only unsupported-column discovery role connection: %v", err)
	}

	views, err := discoverViewsForConnection(ctx, reader, "conn_pg_discovery_excl", DefaultDiscoveryLimits())
	if err != nil {
		t.Fatalf("discover unsupported-column catalog: %v (code=%s)", err, CodeOf(err))
	}
	byName := make(map[string]ViewDiscovery, len(views))
	for _, view := range views {
		byName[view.RelationName] = view
	}

	sites, ok := byName["sites"]
	if !ok {
		t.Fatalf("sites table was not visible: %#v", byName)
	}
	if sites.Status != DiscoveryPrepared || sites.Interpretation != "" || sites.Projection == nil {
		t.Fatalf("sites table with one unsupported column was not prepared: %#v", sites)
	}
	if len(sites.Columns) != 2 || sites.Columns[0].Name != "site_id" || sites.Columns[1].Name != "site_name" {
		t.Fatalf("sites surviving columns=%#v", sites.Columns)
	}
	if len(sites.ExcludedColumns) != 1 || sites.ExcludedColumns[0].Name != "location" ||
		sites.ExcludedColumns[0].Reason != InterpretationUnsupportedType {
		t.Fatalf("sites excluded column metadata=%#v", sites.ExcludedColumns)
	}
	statement, err := sites.Projection.SelectSQL()
	if err != nil {
		t.Fatalf("sites projection SQL: %v", err)
	}
	if strings.Contains(statement, "location") {
		t.Fatalf("unsupported column leaked into generated SQL: %q", statement)
	}
	for _, column := range sites.Projection.Columns {
		if column.Name == "location" {
			t.Fatalf("unsupported column leaked into the projection: %#v", sites.Projection.Columns)
		}
	}

	shapes, ok := byName["shapes"]
	if !ok || shapes.Status != DiscoveryNeedsInterpretation || shapes.Interpretation != InterpretationUnsupportedType || shapes.Projection != nil {
		t.Fatalf("unsupported-primary-key table discovery=%#v", shapes)
	}
	if len(shapes.ExcludedColumns) != 1 || shapes.ExcludedColumns[0].Name != "shape_id" || !shapes.ExcludedColumns[0].PrimaryKey {
		t.Fatalf("unsupported primary key was not reported: %#v", shapes.ExcludedColumns)
	}

	tiles, ok := byName["tiles"]
	if !ok || tiles.Status != DiscoveryNeedsInterpretation || tiles.Interpretation != InterpretationUnsupportedType || tiles.Projection != nil {
		t.Fatalf("all-unsupported table discovery=%#v", tiles)
	}
}

func discoveryReaderURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "postgres" {
		return "", errors.New("test PostgreSQL URL is invalid")
	}
	parsed.User = url.UserPassword("kv_pgq_discovery_reader", "kv-pg-discovery-reader")
	parsed.RawQuery = "sslmode=disable"
	return parsed.String(), nil
}

func discoveryReaderURLAs(raw, role, password string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Scheme != "postgres" {
		return "", errors.New("test PostgreSQL URL is invalid")
	}
	parsed.User = url.UserPassword(role, password)
	parsed.RawQuery = "sslmode=disable"
	return parsed.String(), nil
}
