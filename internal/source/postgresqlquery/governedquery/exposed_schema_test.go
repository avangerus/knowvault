package governedquery

import "testing"

func TestExposedSchemaValidate(t *testing.T) {
	schema := ExposedSchema{
		Revision: 1,
		Objects: []ExposedObject{{
			SchemaName: "public", TableName: "fleet_trips", Description: "Vehicle trip log.",
			Columns: []ExposedColumn{
				{Name: "driver", DataType: "text", Description: "Driver full name.", Unit: "n/a"},
				{Name: "started_at", DataType: "timestamptz", Description: "Trip start.", Unit: "timestamp"},
			},
		}},
	}
	if err := schema.Validate(); err != nil {
		t.Fatalf("expected valid schema, got %v", err)
	}

	empty := ExposedSchema{Revision: 1}
	if err := empty.Validate(); err == nil {
		t.Fatalf("expected an empty exposed schema to be rejected")
	}

	duplicateColumn := schema
	duplicateColumn.Objects = append([]ExposedObject(nil), schema.Objects...)
	duplicateColumn.Objects[0].Columns = append(duplicateColumn.Objects[0].Columns, duplicateColumn.Objects[0].Columns[0])
	if err := duplicateColumn.Validate(); err == nil {
		t.Fatalf("expected a duplicate column to be rejected")
	}
}

func TestExposedSchemaPromptText(t *testing.T) {
	schema := ExposedSchema{
		Revision: 1,
		Objects: []ExposedObject{{
			SchemaName: "public", TableName: "fleet_trips", Description: "Vehicle trip log.",
			Columns: []ExposedColumn{{Name: "driver", DataType: "text", Description: "Driver full name."}},
		}},
	}
	texts := schema.PromptText()
	if len(texts) != 1 {
		t.Fatalf("expected one prompt text per object, got %d", len(texts))
	}
	if texts[0] == "" {
		t.Fatalf("expected non-empty prompt text")
	}
}

func TestValidIdentifier(t *testing.T) {
	for _, value := range []string{"fleet_trips", "public", "a1"} {
		if !validIdentifier(value) {
			t.Fatalf("expected %q to be a valid identifier", value)
		}
	}
	for _, value := range []string{"", "Fleet_Trips", "fleet-trips", "1table", "fleet;drop"} {
		if validIdentifier(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}
