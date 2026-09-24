package postgresqlquery

import (
	"strings"
	"testing"
)

func TestDiscoveryBuildsPreparedProjectionFromExplicitEnvelope(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 24576, schemaName: "prepared", relationName: "objects", relationKind: "VIEW",
		comment: "prepared business-object view",
	}, []catalogColumn{
		{ordinal: 1, name: "entity_id", typeOID: 2950, typeName: "uuid", nullable: false},
		{ordinal: 2, name: "entity_version", typeOID: 25, typeName: "text", nullable: false},
		{ordinal: 3, name: "last_updated_at", typeOID: 1184, typeName: "timestamptz", typmod: 3, nullable: false},
		{ordinal: 4, name: "payload", typeOID: 3802, typeName: "jsonb", nullable: false},
		{ordinal: 5, name: "payload_format", typeOID: 25, typeName: "text", nullable: false},
		{ordinal: 6, name: "amount", typeOID: 1700, typeName: "numeric", typmod: 4 + (12 << 16) + 3, nullable: false, comment: "amount in tonnes"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryPrepared || view.Interpretation != "" || view.Projection == nil {
		t.Fatalf("prepared discovery=%#v", view)
	}
	projection := view.Projection
	if projection.ConnectionID != "conn_discovery" || projection.ContractHash == "" || projection.LineageID == "" {
		t.Fatalf("server-owned projection identities=%#v", projection)
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("generated projection invalid: %v", err)
	}
	amount := projection.Columns[5]
	if amount.TypeFingerprint != "oid:1700:p:12:s:3" || amount.Precision != 12 || amount.Scale != 3 {
		t.Fatalf("numeric metadata=%#v", amount)
	}
	if !strings.Contains(amount.TypeFingerprint, "oid:1700") {
		t.Fatalf("numeric fingerprint omitted server OID: %q", amount.TypeFingerprint)
	}
	if !hasRole(projection.Columns[0].Roles, RoleIdentity) || projection.Columns[0].Nullable {
		t.Fatalf("identity column was not server-owned and non-null: %#v", projection.Columns[0])
	}
	if hasRole(projection.Columns[5].Roles, RolePeriod) || hasRole(projection.Columns[5].Roles, RoleStatus) {
		t.Fatalf("business role was guessed for amount: %#v", projection.Columns[5].Roles)
	}

	view.Comment = "changed native comment"
	changed, err := buildDiscoveredProjection(view)
	if err != nil {
		t.Fatal(err)
	}
	if changed.ContractHash == projection.ContractHash {
		t.Fatal("native comment change did not change server contract hash")
	}
}

func TestDiscoveryLeavesUnknownAndMalformedViewsForInterpretation(t *testing.T) {
	unknown, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 24577, schemaName: "prepared", relationName: "unknown", relationKind: "VIEW",
	}, []catalogColumn{
		{ordinal: 1, name: "id", typeOID: 2950, typeName: "uuid"},
		{ordinal: 2, name: "due_at", typeOID: 1082, typeName: "date"},
		{ordinal: 3, name: "status", typeOID: 25, typeName: "text"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Status != DiscoveryNeedsInterpretation || unknown.Interpretation != InterpretationUnrecognizedFormat || unknown.Projection != nil {
		t.Fatalf("unknown discovery=%#v", unknown)
	}
	malformed, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 24578, schemaName: "prepared", relationName: "malformed", relationKind: "VIEW",
	}, []catalogColumn{
		{ordinal: 1, name: "entity_id", typeOID: 2950, typeName: "uuid"},
		{ordinal: 2, name: "entity_version", typeOID: 25, typeName: "text"},
		{ordinal: 3, name: "last_updated_at", typeOID: 1184, typeName: "timestamptz"},
		{ordinal: 4, name: "payload", typeOID: 23, typeName: "int4"},
		{ordinal: 5, name: "payload_format", typeOID: 25, typeName: "text"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if malformed.Status != DiscoveryNeedsInterpretation || malformed.Interpretation != InterpretationMalformedContract || malformed.Projection != nil {
		t.Fatalf("malformed discovery=%#v", malformed)
	}
}

func TestDiscoveryLimitsRejectOversizedProfile(t *testing.T) {
	limits := DefaultDiscoveryLimits()
	limits.MaxCommentBytes = 64<<10 + 1
	if CodeOf(limits.Validate()) != CodeDiscoveryInvalid {
		t.Fatalf("oversized comment profile code=%s", CodeOf(limits.Validate()))
	}
}

// TestDiscoveryLimitsAllowUpTo1024RelationsFailClosedAbove proves the
// DISCOVERY_LIMIT_EXCEEDED fix end to end at the limits layer: the durable
// request bound (ValidateDurable, mirrored by migration 000111's CHECK
// constraints) and the server default both now reach 1024 relations -- the
// GM catalog's 645 tables/views fit comfortably -- while a profile above
// 1024 is still rejected fail-closed, exactly as one above the old 64 bound
// always was.
func TestDiscoveryLimitsAllowUpTo1024RelationsFailClosedAbove(t *testing.T) {
	def := DefaultDiscoveryLimits()
	if def.MaxViews != 1024 {
		t.Fatalf("default MaxViews = %d, want 1024", def.MaxViews)
	}
	if err := def.ValidateDurable(); err != nil {
		t.Fatalf("default discovery limits rejected as durable: %v", err)
	}
	atLimit := def
	atLimit.MaxViews = 1024
	if err := atLimit.ValidateDurable(); err != nil {
		t.Fatalf("1024-relation profile rejected as durable: %v", err)
	}
	overLimit := def
	overLimit.MaxViews = 1025
	if CodeOf(overLimit.ValidateDurable()) != CodeDiscoveryInvalid {
		t.Fatalf("1025-relation profile code=%s, want %s", CodeOf(overLimit.ValidateDurable()), CodeDiscoveryInvalid)
	}
}

// TestDiscoveryTableWithPrimaryKeyIsPreparedWithIdentityOnKeyColumns is the
// ADR-0097 S1 counterpart of the view envelope test above: an ordinary base
// table needs no business-object contract, only a declared primary key. Its
// key column(s) become IDENTITY, every other column becomes EVIDENCE, and a
// composite key puts RoleIdentity on every key column.
func TestDiscoveryTableWithPrimaryKeyIsPreparedWithIdentityOnKeyColumns(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30001, schemaName: "public", relationName: "accounts", relationKind: "TABLE",
		comment: "customer accounts", approxRowCount: 4200,
	}, []catalogColumn{
		{ordinal: 1, name: "account_id", typeOID: 2950, typeName: "uuid", nullable: false, primaryKey: true},
		{ordinal: 2, name: "region", typeOID: 25, typeName: "text", nullable: false, primaryKey: true},
		{ordinal: 3, name: "display_name", typeOID: 25, typeName: "text", nullable: false},
		{ordinal: 4, name: "phone", typeOID: 25, typeName: "text", nullable: true, comment: "personal data"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryPrepared || view.Interpretation != "" || view.Projection == nil {
		t.Fatalf("prepared table discovery=%#v", view)
	}
	if view.ApproxRowCount != 4200 {
		t.Fatalf("approx row count=%d, want 4200", view.ApproxRowCount)
	}
	if !view.Columns[0].PrimaryKey || !view.Columns[1].PrimaryKey || view.Columns[2].PrimaryKey || view.Columns[3].PrimaryKey {
		t.Fatalf("discovered primary-key flags=%#v", view.Columns)
	}
	projection := view.Projection
	if err := projection.Validate(); err != nil {
		t.Fatalf("table projection invalid: %v", err)
	}
	if projection.RelationKind != "TABLE" {
		t.Fatalf("projection relation kind=%q, want TABLE", projection.RelationKind)
	}
	if !hasRole(projection.Columns[0].Roles, RoleIdentity) || projection.Columns[0].Nullable {
		t.Fatalf("account_id was not server-owned identity: %#v", projection.Columns[0])
	}
	if !hasRole(projection.Columns[1].Roles, RoleIdentity) || projection.Columns[1].Nullable {
		t.Fatalf("region was not part of the composite identity: %#v", projection.Columns[1])
	}
	if !hasRole(projection.Columns[2].Roles, RoleEvidence) || hasRole(projection.Columns[2].Roles, RoleIdentity) {
		t.Fatalf("display_name was not evidence-only: %#v", projection.Columns[2])
	}
	if !hasRole(projection.Columns[3].Roles, RoleEvidence) || hasRole(projection.Columns[3].Roles, RoleIdentity) {
		t.Fatalf("phone was not evidence-only: %#v", projection.Columns[3])
	}
	if _, err := projection.SelectSQL(); err != nil {
		t.Fatalf("generated table projection SQL: %v", err)
	}
}

// TestDiscoveryTableWithoutPrimaryKeyNeedsInterpretation is ADR-0097's fail-
// closed rule: a table this connector cannot key never becomes PREPARED, and
// it never receives an invented ordinal identity.
func TestDiscoveryTableWithoutPrimaryKeyNeedsInterpretation(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30002, schemaName: "public", relationName: "events_log", relationKind: "TABLE",
	}, []catalogColumn{
		{ordinal: 1, name: "occurred_at", typeOID: 1184, typeName: "timestamptz", nullable: false},
		{ordinal: 2, name: "message", typeOID: 25, typeName: "text", nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryNeedsInterpretation || view.Interpretation != InterpretationNoPrimaryKey || view.Projection != nil {
		t.Fatalf("keyless table discovery=%#v", view)
	}
}

// TestDiscoveryPartitionedTableWithPrimaryKeyIsPrepared proves the second
// widened relation kind (pg_class.relkind = 'p') follows the same table rule
// as an ordinary base table.
func TestDiscoveryPartitionedTableWithPrimaryKeyIsPrepared(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30003, schemaName: "public", relationName: "measurements", relationKind: "PARTITIONED_TABLE",
	}, []catalogColumn{
		{ordinal: 1, name: "measurement_id", typeOID: 2950, typeName: "uuid", nullable: false, primaryKey: true},
		{ordinal: 2, name: "value", typeOID: 1700, typeName: "numeric", typmod: 4 + (10 << 16) + 2, nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryPrepared || view.Projection == nil || view.Projection.RelationKind != "PARTITIONED_TABLE" {
		t.Fatalf("partitioned table discovery=%#v", view)
	}
}

func TestNumericTypmodDecodesSignedElevenBitScale(t *testing.T) {
	precision, scale, ok := numericTypmod(4 + (3 << 16) + 0x7fe)
	if !ok || precision != 3 || scale != -2 {
		t.Fatalf("numeric typmod=(%d,%d,%t), want (3,-2,true)", precision, scale, ok)
	}
}

// TestDiscoveryTableWithOneUnsupportedColumnIsPreparedAndExcludesIt is D-1's
// central discovery result: a base table whose only obstacle is one column the
// query connector cannot project (a PostGIS geometry, an enum, ...) becomes
// ready to register, that column is dropped from the sealed projection exactly
// like an administrator-chosen excluded_columns ordinal, and it is reported
// back with its own reason. The surviving columns are renumbered contiguously,
// so the browser's column ordinals and the registration-time exclusion
// ordinals always name the same projection column.
func TestDiscoveryTableWithOneUnsupportedColumnIsPreparedAndExcludesIt(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30010, schemaName: "public", relationName: "waste_site", relationKind: "TABLE",
	}, []catalogColumn{
		{ordinal: 1, name: "site_id", typeOID: 2950, typeName: "uuid", nullable: false, primaryKey: true},
		{ordinal: 2, name: "geom", typeOID: 90001, typeName: "geometry", nullable: true},
		{ordinal: 3, name: "site_name", typeOID: 25, typeName: "text", nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryPrepared || view.Interpretation != "" || view.Projection == nil {
		t.Fatalf("table with one unsupported column was not prepared: %#v", view)
	}
	if len(view.Columns) != 2 || view.Columns[0].Name != "site_id" || view.Columns[1].Name != "site_name" {
		t.Fatalf("surviving columns=%#v", view.Columns)
	}
	if view.Columns[0].Ordinal != 1 || view.Columns[1].Ordinal != 2 {
		t.Fatalf("surviving columns were not renumbered contiguously: %#v", view.Columns)
	}
	if len(view.ExcludedColumns) != 1 || view.ExcludedColumns[0].Name != "geom" ||
		view.ExcludedColumns[0].Ordinal != 2 || view.ExcludedColumns[0].Reason != InterpretationUnsupportedType {
		t.Fatalf("excluded column metadata=%#v", view.ExcludedColumns)
	}
	if len(view.Projection.Columns) != 2 {
		t.Fatalf("projection columns=%#v", view.Projection.Columns)
	}
	for _, column := range view.Projection.Columns {
		if column.Name == "geom" {
			t.Fatalf("unsupported column leaked into the projection: %#v", view.Projection.Columns)
		}
	}
	statement, err := view.Projection.SelectSQL()
	if err != nil {
		t.Fatalf("generated projection SQL: %v", err)
	}
	if strings.Contains(statement, "geom") {
		t.Fatalf("unsupported column leaked into the generated SQL: %q", statement)
	}
}

// TestDiscoveryTableWithUnsupportedPrimaryKeyStaysBlocked and
// TestDiscoveryTableWithOnlyUnsupportedColumnsStaysBlocked pin the two
// fail-closed halves of the same rule: auto-exclusion may narrow a table's
// EVIDENCE set, never remove the identity it is keyed by, and a table with
// nothing projectable left is not a source at all.
func TestDiscoveryTableWithUnsupportedPrimaryKeyStaysBlocked(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30011, schemaName: "public", relationName: "shape_index", relationKind: "TABLE",
	}, []catalogColumn{
		{ordinal: 1, name: "geom", typeOID: 90001, typeName: "geometry", nullable: false, primaryKey: true},
		{ordinal: 2, name: "label", typeOID: 25, typeName: "text", nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryNeedsInterpretation || view.Interpretation != InterpretationUnsupportedType || view.Projection != nil {
		t.Fatalf("unsupported-primary-key table discovery=%#v", view)
	}
	if len(view.ExcludedColumns) != 1 || view.ExcludedColumns[0].Name != "geom" || !view.ExcludedColumns[0].PrimaryKey {
		t.Fatalf("excluded primary key was not reported: %#v", view.ExcludedColumns)
	}
}

func TestDiscoveryTableWithOnlyUnsupportedColumnsStaysBlocked(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30012, schemaName: "public", relationName: "tiles", relationKind: "TABLE",
	}, []catalogColumn{
		{ordinal: 1, name: "geom", typeOID: 90001, typeName: "geometry", nullable: false, primaryKey: true},
		{ordinal: 2, name: "rast", typeOID: 90002, typeName: "raster", nullable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryNeedsInterpretation || view.Interpretation != InterpretationUnsupportedType || view.Projection != nil {
		t.Fatalf("all-unsupported table discovery=%#v", view)
	}
	if len(view.ExcludedColumns) != 2 {
		t.Fatalf("all-unsupported table excluded columns=%#v", view.ExcludedColumns)
	}
}

// TestDiscoveryViewWithUnsupportedColumnStillNeedsInterpretation proves the
// auto-exclusion is a base/partitioned-table rule only: the five-column
// business-object view contract is DBA-reviewed and unchanged, so a view with
// one unsupported column is still surfaced as NEEDS_INTERPRETATION rather
// than silently narrowed.
func TestDiscoveryViewWithUnsupportedColumnStillNeedsInterpretation(t *testing.T) {
	view, err := newViewDiscovery("conn_discovery", 16384, "knowvault_test", catalogRelation{
		relationOID: 30013, schemaName: "public", relationName: "v_objects", relationKind: "VIEW",
	}, []catalogColumn{
		{ordinal: 1, name: "entity_id", typeOID: 2950, typeName: "uuid", nullable: false},
		{ordinal: 2, name: "entity_version", typeOID: 25, typeName: "text", nullable: false},
		{ordinal: 3, name: "last_updated_at", typeOID: 1184, typeName: "timestamptz", nullable: false},
		{ordinal: 4, name: "payload", typeOID: 3802, typeName: "jsonb", nullable: false},
		{ordinal: 5, name: "payload_format", typeOID: 25, typeName: "text", nullable: false},
		{ordinal: 6, name: "geom", typeOID: 90001, typeName: "geometry", nullable: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Status != DiscoveryNeedsInterpretation || view.Interpretation != InterpretationUnsupportedType || view.Projection != nil {
		t.Fatalf("view with unsupported column discovery=%#v", view)
	}
	if len(view.ExcludedColumns) != 0 {
		t.Fatalf("view auto-excluded a column: %#v", view.ExcludedColumns)
	}
}

func hasRole(roles []Role, wanted Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}
