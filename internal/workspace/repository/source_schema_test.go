package repository

// S3 card 1's exclusion invariant: the reported columns are always the
// projection's own columns_json (already narrowed at registration), and a
// catalog row can only enrich them -- never add a column the projection does
// not carry. A stale or hostile catalog entry naming an excluded column is
// silently dropped rather than widening the contract.

import "testing"

const sourceSchemaProjectionJSON = `[
  {"ordinal":1,"name":"id","type_fingerprint":"oid:2950","logical_type":"UUID","roles":["IDENTITY"],"nullable":false,"precision":0,"scale":0,"max_bytes":64},
  {"ordinal":2,"name":"amount","type_fingerprint":"oid:1700:p:12:s:2","logical_type":"NUMERIC","roles":["EVIDENCE"],"nullable":true,"precision":12,"scale":2,"max_bytes":44}
]`

const sourceSchemaCatalogJSON = `[
  {"name":"id","type_name":"uuid","comment":"surrogate key","primary_key":true},
  {"name":"amount","type_name":"numeric","comment":"contract sum","primary_key":false},
  {"name":"passport","type_name":"text","comment":"excluded personal data","primary_key":false}
]`

func TestSourceSchemaColumnsNeverWidenPastTheProjection(t *testing.T) {
	columns, err := sourceSchemaColumns([]byte(sourceSchemaProjectionJSON), []byte(sourceSchemaCatalogJSON))
	if err != nil {
		t.Fatalf("sourceSchemaColumns: %v", err)
	}
	if len(columns) != 2 {
		t.Fatalf("columns = %#v, want exactly the two projected columns", columns)
	}
	for _, column := range columns {
		if column.Name == "passport" {
			t.Fatalf("an excluded column was reported: %#v", columns)
		}
	}
	if columns[0].Name != "id" || columns[0].Type != "uuid" || columns[0].PrimaryKey != true || columns[0].Note != "surrogate key" {
		t.Fatalf("id column = %#v, want the catalog type/comment/key", columns[0])
	}
	if columns[1].Name != "amount" || columns[1].Type != "numeric" || columns[1].Nullable != true || columns[1].PrimaryKey != false || columns[1].Note != "contract sum" {
		t.Fatalf("amount column = %#v", columns[1])
	}
}

func TestSourceSchemaColumnsFallBackToTheProjectionWithoutCatalog(t *testing.T) {
	columns, err := sourceSchemaColumns([]byte(sourceSchemaProjectionJSON), nil)
	if err != nil {
		t.Fatalf("sourceSchemaColumns: %v", err)
	}
	if len(columns) != 2 {
		t.Fatalf("columns = %#v, want 2", columns)
	}
	if columns[0].Type != "UUID" || columns[0].PrimaryKey != true || columns[0].Note != "" {
		t.Fatalf("id column = %#v, want the logical type and the IDENTITY key", columns[0])
	}
	if columns[1].Type != "NUMERIC" || columns[1].PrimaryKey != false {
		t.Fatalf("amount column = %#v", columns[1])
	}
}

func TestSourceSchemaSelectorSplitsOnlyTheFirstSeparator(t *testing.T) {
	if schema, relation := sourceSchemaSelector(""); schema != "" || relation != "" {
		t.Fatalf("empty selector = %q/%q", schema, relation)
	}
	if schema, relation := sourceSchemaSelector("public.contract"); schema != "public" || relation != "contract" {
		t.Fatalf("public.contract = %q/%q", schema, relation)
	}
}
