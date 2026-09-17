package governedquery

import "testing"

// ADR-0089 §1 annotates each exposed column with an operator description and,
// where the column carries a quantity, a unit. The unit is optional: a text
// column such as a driver name has none, and the wire field is `omitempty`.
// Validating it as if it were mandatory rejected every realistic exposed
// schema, and the caller saw that as 409 GOVERNED_QUERY_UNAVAILABLE.
func TestExposedSchemaAcceptsColumnsWithoutAUnit(t *testing.T) {
	schema := ExposedSchema{Revision: 1, Objects: []ExposedObject{{
		SchemaName: "public", TableName: "fleet_trips",
		Description: "\u0420\u0435\u0439\u0441\u044b \u0430\u0432\u0442\u043e\u043f\u0430\u0440\u043a\u0430.",
		Columns: []ExposedColumn{
			{Name: "driver", DataType: "text", Description: "\u0424\u0418\u041e \u0432\u043e\u0434\u0438\u0442\u0435\u043b\u044f."},
			{Name: "started_at", DataType: "timestamp with time zone", Description: "\u0412\u0440\u0435\u043c\u044f \u043d\u0430\u0447\u0430\u043b\u0430 \u0440\u0435\u0439\u0441\u0430.", Unit: "timestamptz"},
		},
	}}}
	if err := schema.Validate(); err != nil {
		t.Fatalf("Validate rejected an exposed schema whose non-quantity column has no unit: %v", err)
	}
}

// A unit the operator DID write is still bounded and content-checked.
func TestExposedSchemaRejectsAnInvalidUnit(t *testing.T) {
	oversized := make([]rune, maxUnitRunes+1)
	for index := range oversized {
		oversized[index] = 'x'
	}
	schema := ExposedSchema{Revision: 1, Objects: []ExposedObject{{
		SchemaName: "public", TableName: "fleet_trips", Description: "\u0420\u0435\u0439\u0441\u044b \u0430\u0432\u0442\u043e\u043f\u0430\u0440\u043a\u0430.",
		Columns: []ExposedColumn{{Name: "started_at", DataType: "timestamptz", Description: "\u041d\u0430\u0447\u0430\u043b\u043e.", Unit: string(oversized)}},
	}}}
	if err := schema.Validate(); CodeOf(err) != CodeInvalid {
		t.Fatalf("Validate accepted an oversized unit: %v", err)
	}
	control := ExposedSchema{Revision: 1, Objects: []ExposedObject{{
		SchemaName: "public", TableName: "fleet_trips", Description: "\u0420\u0435\u0439\u0441\u044b \u0430\u0432\u0442\u043e\u043f\u0430\u0440\u043a\u0430.",
		Columns: []ExposedColumn{{Name: "started_at", DataType: "timestamptz", Description: "\u041d\u0430\u0447\u0430\u043b\u043e.", Unit: "ok\x01"}},
	}}}
	if err := control.Validate(); CodeOf(err) != CodeInvalid {
		t.Fatalf("Validate accepted a control character in a unit: %v", err)
	}
	// The column description itself stays mandatory.
	missingDescription := ExposedSchema{Revision: 1, Objects: []ExposedObject{{
		SchemaName: "public", TableName: "fleet_trips", Description: "\u0420\u0435\u0439\u0441\u044b \u0430\u0432\u0442\u043e\u043f\u0430\u0440\u043a\u0430.",
		Columns: []ExposedColumn{{Name: "driver", DataType: "text"}},
	}}}
	if err := missingDescription.Validate(); CodeOf(err) != CodeInvalid {
		t.Fatalf("Validate accepted a column without an operator description: %v", err)
	}
}
