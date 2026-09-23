package postgresqlquery

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func filteredTestProjection() Projection {
	return Projection{
		ConnectionID: "conn_filtered", DatabaseIdentity: "db_filtered", LineageID: "lineage_filtered",
		Revision: 1, ContractHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		SchemaName: "reporting", RelationName: "orders_view", RelationKind: "VIEW",
		EmptySnapshotPolicy: "AUTHORITATIVE",
		Columns: []Column{
			{Ordinal: 1, Name: "service_date", TypeFingerprint: "oid:1082", LogicalType: TypeDate, Roles: []Role{RolePeriod, RoleEvidence}, MaxBytes: 32},
			{Ordinal: 2, Name: "order_id", TypeFingerprint: "oid:2950", LogicalType: TypeUUID, Roles: []Role{RoleIdentity}, MaxBytes: 64},
			{Ordinal: 3, Name: "status", TypeFingerprint: "oid:25", LogicalType: TypeText, Roles: []Role{RoleEvidence}, MaxBytes: 64},
			{Ordinal: 4, Name: "quantity", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: TypeNumeric, Roles: []Role{RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 5, Name: "note", TypeFingerprint: "oid:25", LogicalType: TypeText, Roles: []Role{RoleEvidence}, Nullable: true, MaxBytes: 64},
		},
	}
}

func filteredTestLimits() Limits {
	return Limits{
		MaxRows: 1000, MaxColumns: 32, MaxFieldBytes: 1 << 20, MaxRowBytes: 2 << 20,
		MaxTotalBytes: 8 << 20, StatementTimeout: 5 * time.Second, TransactionTimeout: 10 * time.Second,
	}
}

func filteredTestRequest() FilteredProjectionRequest {
	return FilteredProjectionRequest{
		Projection: filteredTestProjection(),
		Selection: ScalarReadSelection{
			OutputOrdinals: []int{1, 3}, IdentityOrdinals: []int{2}, MeasureOrdinal: 4,
		},
		Equalities: []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeText, Text: "assigned"}}},
		Period:     &HalfOpenPeriod{Ordinal: 1, LogicalType: TypeDate, Start: "2026-09-10", EndExclusive: "2026-09-11"},
	}
}

// TestBuildFilteredProjectionSQLShapeOrderAndArguments pins the only
// parameterized SELECT this package emits: approved identifiers only, source
// order selected columns, identity ordering, a server-owned literal cap+1 LIMIT
// and one placeholder per canonicalized argument.
func TestBuildFilteredProjectionSQLShapeOrderAndArguments(t *testing.T) {
	query, err := buildFilteredProjectionQuery(filteredTestRequest(), filteredTestLimits())
	if err != nil {
		t.Fatalf("valid request refused: %v (code=%s)", err, CodeOf(err))
	}
	want := `SELECT "service_date","order_id","status","quantity" FROM "reporting"."orders_view" WHERE "status" = $1 AND "service_date" >= $2 AND "service_date" < $3 ORDER BY "order_id" LIMIT 1001`
	if query.statement != want {
		t.Fatalf("statement = %q, want %q", query.statement, want)
	}
	if strings.Contains(query.statement, "note") {
		t.Fatalf("unselected column reached the statement: %q", query.statement)
	}
	if len(query.args) != 3 || query.args[0] != "assigned" || query.args[1] != "2026-09-10" || query.args[2] != "2026-09-11" {
		t.Fatalf("arguments = %#v", query.args)
	}
	if len(query.columns) != 4 {
		t.Fatalf("selected columns = %#v", query.columns)
	}
	for index, column := range query.columns {
		if column.Ordinal != index+1 {
			t.Fatalf("column %d was not renumbered 1..N for CanonicalizeRow: %#v", index, query.columns)
		}
	}
	if query.columns[0].Name != "service_date" || query.columns[1].Name != "order_id" ||
		query.columns[2].Name != "status" || query.columns[3].Name != "quantity" {
		t.Fatalf("selected columns not in source order: %#v", query.columns)
	}
}

// TestBuildFilteredProjectionHostileValuesStayInArguments proves a value
// carrying SQL metacharacters is canonicalized into an argument and never
// becomes statement text.
func TestBuildFilteredProjectionHostileValuesStayInArguments(t *testing.T) {
	hostile := `assigned'); DROP TABLE "reporting"."orders_view";--`
	request := filteredTestRequest()
	request.Equalities = []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeText, Text: hostile}}}
	query, err := buildFilteredProjectionQuery(request, filteredTestLimits())
	if err != nil {
		t.Fatalf("hostile value refused before the boundary: %v", err)
	}
	if strings.Contains(query.statement, "DROP") || strings.Contains(query.statement, hostile) {
		t.Fatalf("hostile value reached the statement: %q", query.statement)
	}
	if len(query.args) != 3 || query.args[0] != hostile {
		t.Fatalf("hostile value not retained verbatim as an argument: %#v", query.args)
	}
	if strings.Count(query.statement, "$") != 3 {
		t.Fatalf("expected three placeholders, got %q", query.statement)
	}
}

type filteredRefusalCase struct {
	name   string
	mutate func(*FilteredProjectionRequest, *Limits)
	code   ErrorCode
}

func filteredRefusalCases() []filteredRefusalCase {
	return []filteredRefusalCase{
		{name: "output ordinal missing", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.OutputOrdinals = []int{1, 99} }},
		{name: "output ordinal zero", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.OutputOrdinals = []int{0, 1} }},
		{name: "output ordinal duplicate", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.OutputOrdinals = []int{3, 3} }},
		{name: "identity ordinal missing", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.IdentityOrdinals = []int{99} }},
		{name: "identity ordinal duplicate", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.IdentityOrdinals = []int{2, 2} }},
		{name: "identity lacks identity role", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.IdentityOrdinals = []int{3} }},
		{name: "identity nullable", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.IdentityOrdinals = []int{5} }},
		{name: "identity absent", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.IdentityOrdinals = nil }},
		{name: "measure lacks evidence role", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.MeasureOrdinal = 2 }},
		{name: "measure ordinal missing", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.MeasureOrdinal = 99 }},
		{name: "measure ordinal zero", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.MeasureOrdinal = 0 }},
		{name: "equality ordinal missing", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 99, Value: ScalarArgument{LogicalType: TypeText, Text: "x"}}}
			}},
		{name: "equality ordinal duplicate", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{
					{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeText, Text: "a"}},
					{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeText, Text: "b"}},
				}
			}},
		{name: "equality ordinal not selected", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 5, Value: ScalarArgument{LogicalType: TypeText, Text: "x"}}}
			}},
		{name: "equality declared type mismatch", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeBool, Bool: true}}}
			}},
		{name: "equality json column", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Projection.Columns[2].LogicalType = TypeJSON
				r.Projection.Columns[2].TypeFingerprint = "oid:114"
				r.Equalities = []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeJSON, Text: "{}"}}}
			}},
		{name: "equality jsonb column", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Projection.Columns[2].LogicalType = TypeJSONB
				r.Projection.Columns[2].TypeFingerprint = "oid:3802"
				r.Equalities = []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: TypeJSONB, Text: "{}"}}}
			}},
		{name: "equality unsupported argument type", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 3, Value: ScalarArgument{LogicalType: LogicalType("FLOAT8"), Text: "1"}}}
			}},
		{name: "equality numeric scale mismatch", code: CodeInvalidValue,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 4, Value: ScalarArgument{LogicalType: TypeNumeric, Text: "1.00"}}}
			}},
		{name: "equality invalid uuid", code: CodeInvalidValue,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Equalities = []EqualityPredicate{{Ordinal: 2, Value: ScalarArgument{LogicalType: TypeUUID, Text: "not-a-uuid"}}}
			}},
		{name: "period ordinal missing", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Period.Ordinal = 99 }},
		{name: "period ordinal not selected", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Selection.OutputOrdinals = []int{3} }},
		{name: "period lacks period role", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Period.Ordinal = 3
				r.Period.LogicalType = TypeText
			}},
		{name: "period declared type mismatch", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Period.LogicalType = TypeTimestamp }},
		{name: "period non-temporal declaration", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Period.LogicalType = TypeText
			}},
		{name: "period start after end", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Period.Start = "2026-09-11"
				r.Period.EndExclusive = "2026-09-10"
			}},
		{name: "period start equals end", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) {
				r.Period.Start = "2026-09-10"
				r.Period.EndExclusive = "2026-09-10"
			}},
		{name: "period invalid bound", code: CodeInvalidValue,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Period.Start = "2026-13-40" }},
		{name: "invalid projection", code: CodeInvalidProjection,
			mutate: func(r *FilteredProjectionRequest, _ *Limits) { r.Projection.RelationKind = "TABLE" }},
		{name: "invalid limits", code: CodeInvalidProjection,
			mutate: func(_ *FilteredProjectionRequest, l *Limits) { l.MaxRows = 0 }},
	}
}

// TestBuildFilteredProjectionRefusalMatrix proves every malformed request is
// refused before any connection is touched, with the existing content-free code
// and a zero query/result.
func TestBuildFilteredProjectionRefusalMatrix(t *testing.T) {
	for _, test := range filteredRefusalCases() {
		t.Run(test.name, func(t *testing.T) {
			request := filteredTestRequest()
			limits := filteredTestLimits()
			test.mutate(&request, &limits)

			query, err := buildFilteredProjectionQuery(request, limits)
			if CodeOf(err) != test.code {
				t.Fatalf("builder code = %s, want %s (err=%v)", CodeOf(err), test.code, err)
			}
			if query.statement != "" || query.args != nil || query.columns != nil {
				t.Fatalf("refused request produced a query: %#v", query)
			}

			snapshot, err := ReadFilteredProjection(context.Background(), nil, request, limits)
			if CodeOf(err) != test.code {
				t.Fatalf("reader code = %s, want %s (err=%v)", CodeOf(err), test.code, err)
			}
			if snapshot.RowCount != 0 || snapshot.Rows != nil || snapshot.DecodedBytes != 0 ||
				snapshot.CoverageComplete || snapshot.SnapshotHash != "" {
				t.Fatalf("refused request produced a partial snapshot: %#v", snapshot)
			}
		})
	}
}

// TestReadFilteredProjectionRequiresAConnection keeps the zero-result failure
// contract for a valid request that reaches the connection boundary.
func TestReadFilteredProjectionRequiresAConnection(t *testing.T) {
	snapshot, err := ReadFilteredProjection(context.Background(), nil, filteredTestRequest(), filteredTestLimits())
	if CodeOf(err) != CodeExternalFailure {
		t.Fatalf("nil connection code = %s, want %s", CodeOf(err), CodeExternalFailure)
	}
	if snapshot.RowCount != 0 || snapshot.Rows != nil || snapshot.CoverageComplete || snapshot.SnapshotHash != "" {
		t.Fatalf("nil connection produced a snapshot: %#v", snapshot)
	}
}

// TestFilteredProjectionAgainstRealPostgreSQL uses the existing env-gated
// PostgreSQL fixture to prove one success read and the cap+1 refusal. It skips
// when no database is configured; it adds no new infrastructure.
func TestFilteredProjectionAgainstRealPostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL filtered-read proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("admin PostgreSQL connection: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()
	if _, err := admin.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_filtered" CASCADE;
		CREATE SCHEMA "kv_pgq_filtered";
		CREATE TABLE "kv_pgq_filtered"."rows" (
			service_date date NOT NULL,
			order_id uuid NOT NULL,
			status text NOT NULL,
			quantity numeric(12,3) NOT NULL,
			note text
		);
		INSERT INTO "kv_pgq_filtered"."rows" VALUES
			('2026-09-10', '550e8400-e29b-41d4-a716-446655440000', 'assigned', 1.000, NULL),
			('2026-09-10', '550e8400-e29b-41d4-a716-446655440001', 'assigned', 2.000, NULL),
			('2026-09-11', '550e8400-e29b-41d4-a716-446655440002', 'assigned', 3.000, NULL);
		CREATE VIEW "kv_pgq_filtered"."orders_view" AS
			SELECT service_date, order_id, status, quantity, note FROM "kv_pgq_filtered"."rows";
	`); err != nil {
		t.Fatalf("seed filtered-read fixture: %v", err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, `DROP SCHEMA IF EXISTS "kv_pgq_filtered" CASCADE`)
	}()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("reader PostgreSQL connection: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()

	request := filteredTestRequest()
	request.Projection.SchemaName = "kv_pgq_filtered"
	request.Projection.RelationName = "orders_view"
	limits := filteredTestLimits()
	snapshot, err := ReadFilteredProjection(ctx, connection, request, limits)
	if err != nil {
		t.Fatalf("filtered read: %v (code=%s)", err, CodeOf(err))
	}
	if snapshot.RowCount != 2 || !snapshot.CoverageComplete || !strings.HasPrefix(snapshot.SnapshotHash, "sha256:") {
		t.Fatalf("filtered snapshot = %#v", snapshot)
	}

	capped := limits
	capped.MaxRows = 1
	partial, err := ReadFilteredProjection(ctx, connection, request, capped)
	if CodeOf(err) != CodeLimitExceeded {
		t.Fatalf("cap+1 code = %s, want %s (err=%v)", CodeOf(err), CodeLimitExceeded, err)
	}
	if partial.RowCount != 0 || partial.Rows != nil || partial.CoverageComplete {
		t.Fatalf("cap+1 produced partial data: %#v", partial)
	}
}
