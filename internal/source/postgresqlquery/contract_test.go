package postgresqlquery

import (
	"strings"
	"testing"
	"time"
)

func testProjection() Projection {
	return Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "lineage_demo",
		Revision: 1, ContractHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchemaName: "reporting", RelationName: "waste_daily", RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: TypeUUID, Roles: []Role{RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "collected_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: TypeTimestamptz, Roles: []Role{RoleVersionHint}, Precision: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "tonnes", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: TypeNumeric, Roles: []Role{RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 4, Name: "note", TypeFingerprint: "oid:25", LogicalType: TypeText, Roles: []Role{RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
}

func TestProjectionGeneratesOnlyValidatedSelect(t *testing.T) {
	p := testProjection()
	sql, err := p.SelectSQL()
	if err != nil {
		t.Fatal(err)
	}
	want := `SELECT "route_id","collected_at","tonnes","note" FROM "reporting"."waste_daily" ORDER BY "route_id"`
	if sql != want {
		t.Fatalf("generated SQL = %q, want %q", sql, want)
	}
	for _, mutate := range []func(*Projection){
		func(value *Projection) { value.RelationKind = "TABLE" },
		func(value *Projection) { value.RelationName = `waste_daily"; DROP TABLE x;--` },
		func(value *Projection) { value.Columns[0].Roles = nil },
		func(value *Projection) { value.Columns[0].Nullable = true },
		func(value *Projection) { value.Columns[2].Scale = 13 },
	} {
		mutated := p
		mutated.Columns = append([]Column(nil), p.Columns...)
		mutate(&mutated)
		if _, err := mutated.SelectSQL(); CodeOf(err) != CodeInvalidProjection {
			t.Fatalf("mutation accepted: err=%v code=%s", err, CodeOf(err))
		}
	}
}

// TestProjectionAcceptsPeriodRoleOnlyOnceAndOnlyOnATemporalColumn is FIX-3
// #1's contract-level guard: RolePeriod is the owner's own declaration of
// "this is the one column that answers a period-scoped question over this
// projection", so a projection may declare it on at most one column, and only
// a DATE/TIMESTAMP/TIMESTAMPTZ column may carry it.
func TestProjectionAcceptsPeriodRoleOnlyOnceAndOnlyOnATemporalColumn(t *testing.T) {
	withPeriod := testProjection()
	withPeriod.Columns = append([]Column(nil), withPeriod.Columns...)
	withPeriod.Columns[1].Roles = []Role{RoleVersionHint, RolePeriod}
	if err := withPeriod.Validate(); err != nil {
		t.Fatalf("expected PERIOD on a TIMESTAMPTZ column to validate, got %v", err)
	}

	onNonTemporal := testProjection()
	onNonTemporal.Columns = append([]Column(nil), onNonTemporal.Columns...)
	onNonTemporal.Columns[3].Roles = []Role{RoleEvidence, RolePeriod}
	if err := onNonTemporal.Validate(); CodeOf(err) != CodeInvalidProjection {
		t.Fatalf("expected PERIOD on a TEXT column to be rejected, got %v", err)
	}

	declaredTwice := testProjection()
	declaredTwice.Columns = append([]Column(nil), declaredTwice.Columns...)
	declaredTwice.Columns[1].Roles = []Role{RoleVersionHint, RolePeriod}
	declaredTwice.Columns = append(declaredTwice.Columns, Column{
		Ordinal: 5, Name: "due_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: TypeTimestamptz,
		Roles: []Role{RolePeriod}, Precision: 3, MaxBytes: 64,
	})
	if err := declaredTwice.Validate(); CodeOf(err) != CodeInvalidProjection {
		t.Fatalf("expected two PERIOD columns in one projection to be rejected, got %v", err)
	}
}

// TestProjectionAcceptsStatusRoleOnlyOnce is SEED-3 #1's contract-level guard
// for RoleStatus: the owner may declare it on at most one column (unlike
// PERIOD, STATUS carries no logical-type restriction -- a lifecycle status is
// as often TEXT as it is anything else), and the reducer's "overdue"
// condition uses it, when declared, to exclude already-closed rows.
func TestProjectionAcceptsStatusRoleOnlyOnce(t *testing.T) {
	withStatus := testProjection()
	withStatus.Columns = append([]Column(nil), withStatus.Columns...)
	withStatus.Columns[3].Roles = []Role{RoleEvidence, RoleStatus}
	if err := withStatus.Validate(); err != nil {
		t.Fatalf("expected STATUS on a TEXT column to validate, got %v", err)
	}

	declaredTwice := testProjection()
	declaredTwice.Columns = append([]Column(nil), declaredTwice.Columns...)
	declaredTwice.Columns[3].Roles = []Role{RoleEvidence, RoleStatus}
	declaredTwice.Columns = append(declaredTwice.Columns, Column{
		Ordinal: 5, Name: "review_status", TypeFingerprint: "oid:25", LogicalType: TypeText,
		Roles: []Role{RoleStatus}, Nullable: true, MaxBytes: 32,
	})
	if err := declaredTwice.Validate(); CodeOf(err) != CodeInvalidProjection {
		t.Fatalf("expected two STATUS columns in one projection to be rejected, got %v", err)
	}
}

func TestCanonicalizeRowTypedValuesAndIdentity(t *testing.T) {
	p := testProjection()
	row, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000",
		"2026-08-29T12:34:56.789+03:00",
		"12.345",
		"Cafe\u0301\r\nroute",
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.Hash == "" || !strings.Contains(string(row.Canonical), "Café") {
		t.Fatalf("canonical row did not preserve typed canonical values: %s", row.Canonical)
	}
	digestA, err := IdentityDigest([]byte("test-key"), 1, p, row)
	if err != nil {
		t.Fatal(err)
	}
	rowB, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T09:34:56.789Z", "12.345", "Café\nroute",
	})
	if err != nil {
		t.Fatal(err)
	}
	digestB, err := IdentityDigest([]byte("test-key"), 1, p, rowB)
	if err != nil {
		t.Fatal(err)
	}
	if digestA != digestB {
		t.Fatalf("timezone/text normalization changed stable identity: %q != %q", digestA, digestB)
	}
	rowC, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440001", "2026-08-29T09:34:56.789Z", "12.345", "Café\nroute",
	})
	if err != nil {
		t.Fatal(err)
	}
	digestC, err := IdentityDigest([]byte("test-key"), 1, p, rowC)
	if err != nil {
		t.Fatal(err)
	}
	if digestA == digestC {
		t.Fatal("identity value mutation reused the same digest")
	}
}

func TestCanonicalizeRowRejectsAmbiguousOrUnsupportedValues(t *testing.T) {
	p := testProjection()
	cases := []struct {
		name   string
		values []any
		code   ErrorCode
	}{
		{"bad uuid", []any{"not-a-uuid", "2026-08-29T12:00:00Z", "1.000", "ok"}, CodeInvalidValue},
		{"numeric scale", []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", "1.00", "ok"}, CodeInvalidValue},
		{"negative zero", []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", "-0.000", "ok"}, CodeInvalidValue},
		{"null identity", []any{nil, "2026-08-29T12:00:00Z", "1.000", "ok"}, CodeInvalidValue},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := CanonicalizeRow(p.Columns, test.values); CodeOf(err) != test.code {
				t.Fatalf("error code = %s, want %s (err=%v)", CodeOf(err), test.code, err)
			}
		})
	}
	unsupported := p
	unsupported.Columns = append([]Column(nil), p.Columns...)
	unsupported.Columns[2].LogicalType = LogicalType("FLOAT8")
	if _, err := CanonicalizeRow(unsupported.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", float64(1), "ok"}); CodeOf(err) != CodeUnsupportedType {
		t.Fatalf("unsupported type was accepted: %v", err)
	}
}

func TestCanonicalizeLocalTimestampAcceptsDateSeparatorsAndRejectsZone(t *testing.T) {
	p := testProjection()
	p.Columns[1] = Column{Ordinal: 2, Name: "collected_at", TypeFingerprint: "oid:1114:p:3", LogicalType: TypeTimestamp, Roles: []Role{RoleVersionHint}, Precision: 3, MaxBytes: 64}
	row, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:34:56.789", "1.000", "ok",
	})
	if err != nil {
		t.Fatalf("local timestamp rejected: %v", err)
	}
	if got := row.Values[1].Value; got != "2026-08-29T12:34:56.789" {
		t.Fatalf("local timestamp canonical value = %v", got)
	}
	if _, err := CanonicalizeRow(p.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:34:56.789Z", "1.000", "ok",
	}); CodeOf(err) != CodeInvalidValue {
		t.Fatalf("zone-bearing local timestamp accepted: %v", err)
	}
}

func TestJSONCanonicalizationAndSnapshotOrder(t *testing.T) {
	p := testProjection()
	p.Columns = append([]Column(nil), p.Columns...)
	p.Columns[3] = Column{Ordinal: 4, Name: "payload", TypeFingerprint: "oid:3802", LogicalType: TypeJSONB, Roles: []Role{RoleEvidence}, MaxBytes: 4096}
	rowA, err := CanonicalizeRow(p.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", "1.000", `{"b":2,"a":1}`})
	if err != nil {
		t.Fatal(err)
	}
	rowB, err := CanonicalizeRow(p.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", "1.000", `{"a":1,"b":2}`})
	if err != nil {
		t.Fatal(err)
	}
	if string(rowA.Canonical) != string(rowB.Canonical) {
		t.Fatalf("JSON key order changed canonical row: %s != %s", rowA.Canonical, rowB.Canonical)
	}
	hashA, err := SnapshotSetHash([]Row{rowA, rowB})
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := SnapshotSetHash([]Row{rowB, rowA})
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatal("snapshot hash depends on physical row order")
	}
	if _, err := CanonicalizeRow(p.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "2026-08-29T12:00:00Z", "1.000", `{"a":1,"a":2}`}); CodeOf(err) != CodeInvalidValue {
		t.Fatalf("duplicate JSON keys were accepted: err=%v code=%s", err, CodeOf(err))
	}
}

func TestLimitsRejectInvalidServerBounds(t *testing.T) {
	limits := DefaultLimits()
	if err := limits.Validate(); err != nil {
		t.Fatalf("default limits rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Limits){
		"zero rows":                    func(value *Limits) { value.MaxRows = 0 },
		"row cap too high":             func(value *Limits) { value.MaxRows = 10_000_001 },
		"timeout too short":            func(value *Limits) { value.StatementTimeout = 0 },
		"transaction before statement": func(value *Limits) { value.TransactionTimeout = value.StatementTimeout - time.Millisecond },
	} {
		t.Run(name, func(t *testing.T) {
			value := limits
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid limits passed validation")
			}
		})
	}
}
