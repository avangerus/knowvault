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

func TestNumericTypmodDecodesSignedElevenBitScale(t *testing.T) {
	precision, scale, ok := numericTypmod(4 + (3 << 16) + 0x7fe)
	if !ok || precision != 3 || scale != -2 {
		t.Fatalf("numeric typmod=(%d,%d,%t), want (3,-2,true)", precision, scale, ok)
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
