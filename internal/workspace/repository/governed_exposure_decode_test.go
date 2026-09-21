package repository

// Acceptance corpus for the pure governed-exposure normalization boundary
// (B2.3a). Every case drives decodeGovernedExposure directly: no database, no
// transaction and no clock participates, so the whole corpus is a pure unit
// proof of the persisted-artifact decode, the full-artifact hash rule and the
// relation projection.
//
// The fixture wires below are a second, independent copy of the persisted
// exposed-schema member names. They are deliberately not the decoder's own
// types: if the decoder's JSON tags, the unit omitempty or the canonical
// convention drifted, the pinned JCS literal and the golden hash in
// TestDecodeGovernedExposureAcceptsEquivalentWireEncodings would stop matching.
//
// Wire and hash compatibility with the governed-query registration path is what
// those pinned bytes prove, and the primary fixture is kept in a shape that path
// could actually have produced. Identifier acceptance is a separate, wider
// contract: the decoder follows the typed-analytics shape
// ^[A-Za-z_][A-Za-z0-9_$]{0,62}$, not registration's lowercase identifier
// validator, and syntheticTypedAnalyticsFixture is the explicitly synthetic
// proof of that difference.

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// exposureTestColumn and exposureTestObject mirror the registration wire
// (governedquery.ExposedColumn/ExposedObject) member for member.
type exposureTestColumn struct {
	Name        string `json:"name"`
	DataType    string `json:"data_type"`
	Description string `json:"description"`
	Unit        string `json:"unit,omitempty"`
}

type exposureTestObject struct {
	SchemaName  string               `json:"schema_name"`
	TableName   string               `json:"table_name"`
	Description string               `json:"description"`
	Columns     []exposureTestColumn `json:"columns"`
}

const (
	// governedExposureGoldenRevision is the persisted revision ordinal of the
	// fixture artifact.
	governedExposureGoldenRevision = int64(7)

	// governedExposureGoldenHash is the SHA-256 of the exact JCS bytes below:
	// the hash the registration path persists for this inventory
	// (canon.Hash(canon.CanonicalJSON(schema.Objects)) over the sorted objects).
	// A matching hash proves only that this fixture agrees with the decoder's
	// re-derivation; it proves neither registration provenance nor authority.
	governedExposureGoldenHash = "sha256:8881776408326a6164636f8999d6bdb3071940e6d70a841794aa319a0a9c99a0"
)

// governedExposureGoldenCanonical is the exact RFC 8785/JCS rendering of
// exposureFixture: objects in the registration order (schema_name + "." +
// table_name), members sorted, no whitespace, and the absent unit of
// "signed_on" omitted rather than sent as an empty string.
const governedExposureGoldenCanonical = `[{"columns":[{"data_type":"text","description":"Trip id","name":"trip_id"},` +
	`{"data_type":"numeric","description":"Trip distance","name":"distance_km","unit":"km"}],"description":"Approved facts view","schema_name":"analytics_approved","table_name":"_facts_2"},` +
	`{"columns":[{"data_type":"numeric","description":"Contract id","name":"id","unit":"count"},` +
	`{"data_type":"numeric","description":"Contract amount","name":"amount","unit":"EUR"},` +
	`{"data_type":"date","description":"Signature date","name":"signed_on"}],"description":"Contracts registry","schema_name":"reporting","table_name":"contracts"},` +
	`{"columns":[{"data_type":"text","description":"Invoice id","name":"invoice_id"}],"description":"Invoice ledger","schema_name":"reporting","table_name":"invoices"}]`

// governedExposureJSONBStyle holds the same inventory as PostgreSQL renders
// jsonb: members reordered by jsonb's own (length, byte order) rule and ", "
// separators. Decoding it must yield the identical canonical artifact and
// therefore the identical hash.
const governedExposureJSONBStyle = `[` + `
{"columns": [{"name": "trip_id", "data_type": "text", "description": "Trip id"}, {"name": "distance_km", "unit": "km", "data_type": "numeric", "description": "Trip distance"}], "table_name": "_facts_2", "description": "Approved facts view", "schema_name": "analytics_approved"},` + `
{"columns": [{"name": "id", "unit": "count", "data_type": "numeric", "description": "Contract id"}, {"name": "amount", "unit": "EUR", "data_type": "numeric", "description": "Contract amount"}, {"name": "signed_on", "data_type": "date", "description": "Signature date"}], "table_name": "contracts", "description": "Contracts registry", "schema_name": "reporting"},` + `
{"columns": [{"name": "invoice_id", "data_type": "text", "description": "Invoice id"}], "table_name": "invoices", "description": "Invoice ledger", "schema_name": "reporting"}]`

// exposureFixture builds a fresh three-object inventory in exactly the shape
// the governed-query registration path can produce
// (governedquery.DiscoverExposedSchema): every identifier is lowercase and
// registration-valid, and the objects are ordered by the registration sort key
// schema_name + "." + table_name, so analytics_approved._facts_2 precedes the
// two reporting objects. Two objects share one schema; the third exists so the
// multi-object selection is proved with three distinct identities.
func exposureFixture() []exposureTestObject {
	return []exposureTestObject{
		{
			SchemaName: "analytics_approved", TableName: "_facts_2", Description: "Approved facts view",
			Columns: []exposureTestColumn{
				{Name: "trip_id", DataType: "text", Description: "Trip id"},
				{Name: "distance_km", DataType: "numeric", Description: "Trip distance", Unit: "km"},
			},
		},
		{
			SchemaName: "reporting", TableName: "contracts", Description: "Contracts registry",
			Columns: []exposureTestColumn{
				{Name: "id", DataType: "numeric", Description: "Contract id", Unit: "count"},
				{Name: "amount", DataType: "numeric", Description: "Contract amount", Unit: "EUR"},
				{Name: "signed_on", DataType: "date", Description: "Signature date"},
			},
		},
		{
			SchemaName: "reporting", TableName: "invoices", Description: "Invoice ledger",
			Columns: []exposureTestColumn{
				{Name: "invoice_id", DataType: "text", Description: "Invoice id"},
			},
		},
	}
}

// syntheticTypedAnalyticsFixture is one explicitly synthetic artifact. It is
// NOT a registration-produced inventory and must never be described as one: its
// uppercase letters and dollar signs are exactly what the registration
// validator (governedquery.validIdentifier, lowercase letters/digits/underscore)
// refuses, so registration could not persist these names. It exists only to
// prove that the decoder deliberately follows the typed-analytics identifier
// contract ^[A-Za-z_][A-Za-z0-9_$]{0,62}$ -- the shape
// analytic.SourceProjectionSpec.Valid and analyticsource's column set validate
// with -- which is wider than the registration validator.
func syntheticTypedAnalyticsFixture() []exposureTestObject {
	return []exposureTestObject{
		{
			SchemaName: "Analytics$Approved", TableName: "_Facts$2", Description: "Synthetic typed-analytics view",
			Columns: []exposureTestColumn{
				{Name: "TripID", DataType: "text", Description: "Trip id"},
				{Name: "Distance$KM", DataType: "numeric", Description: "Trip distance", Unit: "km"},
			},
		},
	}
}

// cloneExposureFixture deep-copies the fixture so one table case can never
// mutate another's columns.
func cloneExposureFixture() []exposureTestObject {
	objects := exposureFixture()
	cloned := make([]exposureTestObject, len(objects))
	for index, object := range objects {
		cloned[index] = object
		cloned[index].Columns = append([]exposureTestColumn(nil), object.Columns...)
	}
	return cloned
}

// exposureArtifact returns the persisted jsonb text and revision hash exactly
// as the registration path writes them for a registration-shaped inventory
// (canon.CanonicalJSON of the sorted objects, then canon.Hash of those bytes).
func exposureArtifact(t *testing.T, objects []exposureTestObject) ([]byte, string) {
	t.Helper()
	raw, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatalf("canonicalize fixture: %v", err)
	}
	return raw, canon.Hash(raw)
}

// exposureHash returns only the persisted hash of one inventory, for cases
// that hand-write the wire text and must therefore pin the hash of the content
// a correct decoder derives from it. Passing that hash means the hash
// comparison cannot be the reason for the refusal under test.
func exposureHash(t *testing.T, objects []exposureTestObject) string {
	t.Helper()
	_, hash := exposureArtifact(t, objects)
	return hash
}

// exposureFixtureWithObjects builds exactly count single-column objects, so a
// test can sit on either side of the 1..32 object bound.
func exposureFixtureWithObjects(count int) []exposureTestObject {
	objects := make([]exposureTestObject, 0, count)
	for index := 0; index < count; index++ {
		objects = append(objects, exposureTestObject{
			SchemaName: "reporting", TableName: fmt.Sprintf("relation_%d", index),
			Description: "Bounded relation",
			Columns:     []exposureTestColumn{{Name: "id", DataType: "numeric", Description: "Row id"}},
		})
	}
	return objects
}

// exposureFixtureWithColumns builds one object with exactly count columns, so a
// test can sit on either side of the 1..64 column bound.
func exposureFixtureWithColumns(count int) []exposureTestObject {
	columns := make([]exposureTestColumn, 0, count)
	for index := 0; index < count; index++ {
		columns = append(columns, exposureTestColumn{
			Name: fmt.Sprintf("column_%d", index), DataType: "numeric", Description: "Bounded column",
		})
	}
	return []exposureTestObject{{
		SchemaName: "reporting", TableName: "wide", Description: "Wide relation", Columns: columns,
	}}
}

func assertGovernedExposureZero(t *testing.T, facts governedExposureFacts) {
	t.Helper()
	if facts.revision != 0 || facts.artifactHash != "" || facts.schemaName != "" ||
		facts.relationName != "" || facts.columns != nil {
		t.Fatalf("refusal returned non-zero facts: %+v", facts)
	}
}

// assertGovernedExposureRefused pins the whole refusal contract: the exact
// repository code, its exact code-only text, no unwrap chain, zero facts and
// no content or identifier in the message.
func assertGovernedExposureRefused(t *testing.T, facts governedExposureFacts, err error, want ErrorCode, content ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s refusal, got success with %+v", want, facts)
	}
	if got := CodeOf(err); got != want {
		t.Fatalf("code = %q, want %q", got, want)
	}
	if err.Error() != string(want) {
		t.Fatalf("error text = %q, want the exact code text %q", err.Error(), string(want))
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("refusal unwraps to %v; every refusal must be cause-free", unwrapped)
	}
	for _, secret := range content {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatalf("refusal leaked %q: %q", secret, err.Error())
		}
	}
	assertGovernedExposureZero(t, facts)
}

func assertGovernedExposureColumns(t *testing.T, facts governedExposureFacts, want ...string) {
	t.Helper()
	if len(facts.columns) != len(want) {
		t.Fatalf("columns = %v, want %v", facts.columns, want)
	}
	for index := range want {
		if facts.columns[index] != want[index] {
			t.Fatalf("columns = %v, want %v", facts.columns, want)
		}
	}
}

// 1. Valid multi-object artifact selects only the exact requested relation.
func TestDecodeGovernedExposureSelectsExactRequestedRelation(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())
	if hash != governedExposureGoldenHash {
		t.Fatalf("fixture hash = %q, want the pinned %q", hash, governedExposureGoldenHash)
	}

	facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "invoices")
	if err != nil {
		t.Fatalf("valid artifact refused: %v", err)
	}
	if facts.revision != governedExposureGoldenRevision {
		t.Fatalf("revision = %d, want %d", facts.revision, governedExposureGoldenRevision)
	}
	if facts.artifactHash != hash {
		t.Fatalf("artifact hash = %q, want %q", facts.artifactHash, hash)
	}
	if facts.schemaName != "reporting" || facts.relationName != "invoices" {
		t.Fatalf("selection = %s.%s, want reporting.invoices", facts.schemaName, facts.relationName)
	}
	// Exactly the selected relation's own columns, in artifact order, and none
	// of the other objects' columns.
	assertGovernedExposureColumns(t, facts, "invoice_id")

	facts, err = decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "analytics_approved", "_facts_2")
	if err != nil {
		t.Fatalf("analytic relation refused: %v", err)
	}
	assertGovernedExposureColumns(t, facts, "trip_id", "distance_km")

	// Selection is exact and case-sensitive: the registration-shaped artifact's
	// schema/table names are lowercase, so a case-folded request is a genuine
	// miss, not a match.
	facts, err = decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "Reporting", "Invoices")
	assertGovernedExposureRefused(t, facts, err, CodeNotFound, "reporting", "invoices")
}

// 1b. The decoder deliberately follows the typed-analytics identifier contract,
// which is wider than the registration validator: an explicitly synthetic
// artifact carrying uppercase letters and dollar signs is accepted exactly, and
// case-folding it is still not a match. The artifact is never registration
// output -- registration could not persist these names -- so this case proves
// identifier acceptance only, never wire or hash compatibility with
// registration.
func TestDecodeGovernedExposureAcceptsTypedAnalyticsIdentifiers(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, syntheticTypedAnalyticsFixture())
	facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "Analytics$Approved", "_Facts$2")
	if err != nil {
		t.Fatalf("synthetic typed-analytics identifiers refused: %v", err)
	}
	assertGovernedExposureColumns(t, facts, "TripID", "Distance$KM")
	if facts.schemaName != "Analytics$Approved" || facts.relationName != "_Facts$2" {
		t.Fatalf("selection = %s.%s, want Analytics$Approved._Facts$2", facts.schemaName, facts.relationName)
	}

	facts, err = decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "analytics$approved", "_facts$2")
	assertGovernedExposureRefused(t, facts, err, CodeNotFound)
}

// 2. Equivalent PostgreSQL-style whitespace and member ordering are accepted
// with the same expected canonical hash.
func TestDecodeGovernedExposureAcceptsEquivalentWireEncodings(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())
	if canon.Hash([]byte(governedExposureGoldenCanonical)) != governedExposureGoldenHash {
		t.Fatal("the pinned golden literal no longer hashes to the pinned golden hash")
	}
	if string(artifact) != governedExposureGoldenCanonical {
		t.Fatalf("canonical artifact = %s\nwant %s", artifact, governedExposureGoldenCanonical)
	}
	if hash != governedExposureGoldenHash {
		t.Fatalf("artifact hash = %q, want %q", hash, governedExposureGoldenHash)
	}

	for _, wire := range []struct {
		name string
		text string
	}{
		{"canonical bytes", governedExposureGoldenCanonical},
		{"jsonb rendering", governedExposureJSONBStyle},
		{"canonical bytes with trailing whitespace", governedExposureGoldenCanonical + "\n\t "},
	} {
		facts, err := decodeGovernedExposure([]byte(wire.text), governedExposureGoldenRevision, governedExposureGoldenHash, "reporting", "contracts")
		if err != nil {
			t.Fatalf("%s refused: %v", wire.name, err)
		}
		if facts.artifactHash != governedExposureGoldenHash {
			t.Fatalf("%s hash = %q, want %q", wire.name, facts.artifactHash, governedExposureGoldenHash)
		}
		assertGovernedExposureColumns(t, facts, "id", "amount", "signed_on")
	}
}

// 3. Changing any description, unit, data type, column or unrelated object
// while keeping the old hash fails with CodePersistence — and each mutated
// artifact is itself decodable under its own hash, so the old hash is
// demonstrably the only reason for the refusal.
func TestDecodeGovernedExposureRejectsTamperedContentUnderOldHash(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func([]exposureTestObject)
	}{
		// The fixture is in registration order, so the contracts object is
		// objects[1] (analytics_approved._facts_2 sorts first) and the unrelated
		// object is objects[0].
		{"object description", func(objects []exposureTestObject) { objects[1].Description = "Contracts registry." }},
		{"column unit", func(objects []exposureTestObject) { objects[1].Columns[0].Unit = "rows" }},
		{"column data type", func(objects []exposureTestObject) { objects[1].Columns[1].DataType = "text" }},
		{"column description", func(objects []exposureTestObject) { objects[2].Columns[0].Description = "Invoice identifier" }},
		{"added column", func(objects []exposureTestObject) {
			objects[1].Columns = append(objects[1].Columns, exposureTestColumn{Name: "note", DataType: "text", Description: "Note"})
		}},
		{"removed column", func(objects []exposureTestObject) { objects[1].Columns = objects[1].Columns[:2] }},
		{"unrelated object column unit", func(objects []exposureTestObject) { objects[0].Columns[1].Unit = "mi" }},
		{"unrelated object description", func(objects []exposureTestObject) { objects[0].Description = "Approved facts" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			objects := cloneExposureFixture()
			test.mutate(objects)
			mutated, mutatedHash := exposureArtifact(t, objects)
			if mutatedHash == governedExposureGoldenHash {
				t.Fatal("mutation did not change the artifact hash")
			}
			facts, err := decodeGovernedExposure(mutated, governedExposureGoldenRevision, governedExposureGoldenHash, "reporting", "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence, "reporting", "contracts", "registry")
			if _, err := decodeGovernedExposure(mutated, governedExposureGoldenRevision, mutatedHash, "reporting", "contracts"); err != nil {
				t.Fatalf("mutated artifact is not decodable under its own hash: %v", err)
			}
		})
	}
}

// 4. Reordering the object array or a column array changes the required hash
// and fails under the old hash, while the new order is preserved exactly.
func TestDecodeGovernedExposureBindsArrayOrder(t *testing.T) {
	t.Parallel()

	t.Run("object array", func(t *testing.T) {
		t.Parallel()
		objects := cloneExposureFixture()
		objects[0], objects[1] = objects[1], objects[0]
		reordered, reorderedHash := exposureArtifact(t, objects)
		if reorderedHash == governedExposureGoldenHash {
			t.Fatal("reordering objects left the artifact hash unchanged")
		}
		facts, err := decodeGovernedExposure(reordered, governedExposureGoldenRevision, governedExposureGoldenHash, "reporting", "contracts")
		assertGovernedExposureRefused(t, facts, err, CodePersistence)
		facts, err = decodeGovernedExposure(reordered, governedExposureGoldenRevision, reorderedHash, "reporting", "contracts")
		if err != nil {
			t.Fatalf("reordered artifact refused under its own hash: %v", err)
		}
		assertGovernedExposureColumns(t, facts, "id", "amount", "signed_on")
	})

	t.Run("column array", func(t *testing.T) {
		t.Parallel()
		objects := cloneExposureFixture()
		// objects[1] is the selected contracts object in registration order.
		objects[1].Columns[0], objects[1].Columns[1] = objects[1].Columns[1], objects[1].Columns[0]
		reordered, reorderedHash := exposureArtifact(t, objects)
		if reorderedHash == governedExposureGoldenHash {
			t.Fatal("reordering columns left the artifact hash unchanged")
		}
		facts, err := decodeGovernedExposure(reordered, governedExposureGoldenRevision, governedExposureGoldenHash, "reporting", "contracts")
		assertGovernedExposureRefused(t, facts, err, CodePersistence)
		facts, err = decodeGovernedExposure(reordered, governedExposureGoldenRevision, reorderedHash, "reporting", "contracts")
		if err != nil {
			t.Fatalf("reordered artifact refused under its own hash: %v", err)
		}
		// The projection preserves the artifact's order; it never re-sorts.
		assertGovernedExposureColumns(t, facts, "amount", "id", "signed_on")
	})
}

// 5. Missing relation returns only CodeNotFound; duplicate object identity and
// duplicate column names are malformed and return only CodePersistence.
func TestDecodeGovernedExposureRefusesMissingAndDuplicateIdentity(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())
	for _, request := range []struct{ schema, relation string }{
		{"reporting", "ledger"},
		{"reporting", "contract"},
		{"public", "contracts"},
	} {
		facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, request.schema, request.relation)
		assertGovernedExposureRefused(t, facts, err, CodeNotFound, request.schema, request.relation)
	}

	t.Run("duplicate object identity", func(t *testing.T) {
		t.Parallel()
		objects := cloneExposureFixture()
		objects = append(objects, exposureTestObject{
			SchemaName: "reporting", TableName: "contracts", Description: "Contracts registry copy",
			Columns: []exposureTestColumn{{Name: "id", DataType: "numeric", Description: "Contract id", Unit: "count"}},
		})
		duplicated, duplicatedHash := exposureArtifact(t, objects)
		facts, err := decodeGovernedExposure(duplicated, governedExposureGoldenRevision, duplicatedHash, "reporting", "contracts")
		assertGovernedExposureRefused(t, facts, err, CodePersistence)
		// The duplicate is refused artifact-wide, never only for the relation
		// it happens to duplicate.
		facts, err = decodeGovernedExposure(duplicated, governedExposureGoldenRevision, duplicatedHash, "reporting", "invoices")
		assertGovernedExposureRefused(t, facts, err, CodePersistence)
	})

	t.Run("duplicate column name", func(t *testing.T) {
		t.Parallel()
		objects := cloneExposureFixture()
		// objects[1] is the contracts object: renaming its second column to the
		// first column's name makes that one object hold "id" twice.
		objects[1].Columns[1].Name = "id"
		duplicated, duplicatedHash := exposureArtifact(t, objects)
		facts, err := decodeGovernedExposure(duplicated, governedExposureGoldenRevision, duplicatedHash, "reporting", "invoices")
		assertGovernedExposureRefused(t, facts, err, CodePersistence)
	})
}

// 6. Unknown members, duplicate JSON keys, malformed/trailing JSON, null or
// empty collections, 33 objects, 65 columns and input over 8 MiB fail closed.
func TestDecodeGovernedExposureRefusesMalformedWire(t *testing.T) {
	t.Parallel()

	nullColumns := cloneExposureFixture()
	nullColumns[1].Columns = nil
	emptyColumns := cloneExposureFixture()
	emptyColumns[0].Columns = []exposureTestColumn{}
	nullDescription := cloneExposureFixture()
	nullDescription[0].Description = ""
	nullDataType := cloneExposureFixture()
	nullDataType[0].Columns[0].DataType = ""
	missingDescription := cloneExposureFixture()
	missingDescription[0].Description = ""
	missingColumns := cloneExposureFixture()
	missingColumns[1].Columns = nil
	nullName := cloneExposureFixture()
	nullName[0].Columns[0].Name = ""

	for _, test := range []struct {
		name string
		text string
		hash string
	}{
		{
			"unknown object member",
			strings.Replace(governedExposureGoldenCanonical, `"table_name":"contracts"`, `"table_name":"contracts","owner":"ops"`, 1),
			governedExposureGoldenHash,
		},
		{
			"unknown column member",
			strings.Replace(governedExposureGoldenCanonical, `"name":"id"`, `"name":"id","sql_type":"bigint"`, 1),
			governedExposureGoldenHash,
		},
		{
			"duplicate member name",
			strings.Replace(governedExposureGoldenCanonical, `"description":"Contracts registry"`, `"description":"Contracts registry","description":"Contracts registry"`, 1),
			governedExposureGoldenHash,
		},
		{
			"null member name",
			strings.Replace(governedExposureGoldenCanonical, `"name":"id"`, `"name":null`, 1),
			exposureHash(t, nullName),
		},
		{
			"null columns",
			strings.Replace(governedExposureGoldenCanonical, `"columns":[{"data_type":"text","description":"Invoice id","name":"invoice_id"}]`, `"columns":null`, 1),
			exposureHash(t, nullColumns),
		},
		{
			"empty columns",
			strings.Replace(governedExposureGoldenCanonical, `"columns":[{"data_type":"numeric","description":"Contract id","name":"id","unit":"count"},{"data_type":"numeric","description":"Contract amount","name":"amount","unit":"EUR"},{"data_type":"date","description":"Signature date","name":"signed_on"}]`, `"columns":[]`, 1),
			exposureHash(t, emptyColumns),
		},
		{
			"missing columns member",
			strings.Replace(governedExposureGoldenCanonical, `"columns":[{"data_type":"text","description":"Invoice id","name":"invoice_id"}],`, ``, 1),
			exposureHash(t, missingColumns),
		},
		{
			"null description",
			strings.Replace(governedExposureGoldenCanonical, `"description":"Contracts registry"`, `"description":null`, 1),
			exposureHash(t, nullDescription),
		},
		{
			"missing description member",
			strings.Replace(governedExposureGoldenCanonical, `"description":"Contracts registry",`, ``, 1),
			exposureHash(t, missingDescription),
		},
		{
			"null data type",
			strings.Replace(governedExposureGoldenCanonical, `"data_type":"numeric","description":"Contract id"`, `"data_type":null,"description":"Contract id"`, 1),
			exposureHash(t, nullDataType),
		},
		{
			"wrong scalar type for schema name",
			strings.Replace(governedExposureGoldenCanonical, `"schema_name":"reporting"`, `"schema_name":5`, 1),
			governedExposureGoldenHash,
		},
		{
			"wrong scalar type for columns",
			strings.Replace(governedExposureGoldenCanonical, `"columns":[{"data_type":"text","description":"Invoice id","name":"invoice_id"}]`, `"columns":"invoice_id"`, 1),
			governedExposureGoldenHash,
		},
		{"truncated document", governedExposureGoldenCanonical[:len(governedExposureGoldenCanonical)-8], governedExposureGoldenHash},
		{"trailing array", governedExposureGoldenCanonical + `[]`, governedExposureGoldenHash},
		{"trailing text", governedExposureGoldenCanonical + ` null`, governedExposureGoldenHash},
		{"document is an object", `{"objects":[]}`, governedExposureGoldenHash},
		{"document is null", `null`, governedExposureGoldenHash},
		{"document is empty array", `[]`, governedExposureGoldenHash},
		{"empty input", ``, governedExposureGoldenHash},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts, err := decodeGovernedExposure([]byte(test.text), governedExposureGoldenRevision, test.hash, "reporting", "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence)
		})
	}
}

// 7. Invalid requested and persisted identifiers, revision 0/negative/unsafe
// and a malformed or uppercase hash all fail closed.
func TestDecodeGovernedExposureRefusesInvalidScalars(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())

	t.Run("requested identifiers", func(t *testing.T) {
		t.Parallel()
		for _, invalid := range []string{
			"", "bad.name", "9leading", "trailing ", " leading", `"quoted"`, "semi;colon",
			"dash-name", "ümlaut", strings.Repeat("a", 64),
		} {
			facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", invalid)
			assertGovernedExposureRefused(t, facts, err, CodePersistence, invalid)
			facts, err = decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, invalid, "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence, invalid)
		}
		// The 63-byte boundary itself is a valid identifier shape; it simply
		// matches nothing here.
		facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", strings.Repeat("a", 63))
		assertGovernedExposureRefused(t, facts, err, CodeNotFound)
	})

	t.Run("persisted identifiers", func(t *testing.T) {
		t.Parallel()
		for _, test := range []struct {
			name   string
			mutate func([]exposureTestObject)
		}{
			// The fixture is in registration order: objects[0] is the analytics
			// object, objects[1] contracts, objects[2] invoices.
			{"dotted schema", func(objects []exposureTestObject) { objects[1].SchemaName = "reporting.public" }},
			{"dotted table", func(objects []exposureTestObject) { objects[2].TableName = "public.invoices" }},
			{"leading digit table", func(objects []exposureTestObject) { objects[2].TableName = "9invoices" }},
			{"leading digit column", func(objects []exposureTestObject) { objects[2].Columns[0].Name = "9invoice_id" }},
			{"quoted column", func(objects []exposureTestObject) { objects[2].Columns[0].Name = `"invoice_id"` }},
			{"oversized column", func(objects []exposureTestObject) { objects[2].Columns[0].Name = strings.Repeat("c", 64) }},
			{"oversized table", func(objects []exposureTestObject) { objects[2].TableName = strings.Repeat("t", 64) }},
			{"empty schema", func(objects []exposureTestObject) { objects[2].SchemaName = "" }},
		} {
			objects := cloneExposureFixture()
			test.mutate(objects)
			malformed, malformedHash := exposureArtifact(t, objects)
			facts, err := decodeGovernedExposure(malformed, governedExposureGoldenRevision, malformedHash, "reporting", "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence)
		}
	})

	t.Run("uppercase persisted identity stays distinct", func(t *testing.T) {
		t.Parallel()
		// Synthetic identifiers again: the typed-analytics contract accepts
		// uppercase, but nothing is trimmed or case-folded, so the uppercase
		// identity and its lowercase spelling stay two different relations.
		upper, upperHash := exposureArtifact(t, syntheticTypedAnalyticsFixture())
		facts, err := decodeGovernedExposure(upper, governedExposureGoldenRevision, upperHash, "Analytics$Approved", "_Facts$2")
		if err != nil {
			t.Fatalf("unquoted uppercase identifiers refused: %v", err)
		}
		assertGovernedExposureColumns(t, facts, "TripID", "Distance$KM")
		facts, err = decodeGovernedExposure(upper, governedExposureGoldenRevision, upperHash, "analytics$approved", "_facts$2")
		assertGovernedExposureRefused(t, facts, err, CodeNotFound)
	})

	t.Run("revision bounds", func(t *testing.T) {
		t.Parallel()
		for _, revision := range []int64{0, -1, maxSafeInteger + 1, -maxSafeInteger - 1} {
			facts, err := decodeGovernedExposure(artifact, revision, hash, "reporting", "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence, strconv.FormatInt(revision, 10))
		}
		for _, revision := range []int64{1, maxSafeInteger} {
			facts, err := decodeGovernedExposure(artifact, revision, hash, "reporting", "contracts")
			if err != nil {
				t.Fatalf("safe revision %d refused: %v", revision, err)
			}
			if facts.revision != revision {
				t.Fatalf("revision = %d, want %d", facts.revision, revision)
			}
		}
	})

	t.Run("revision hash form", func(t *testing.T) {
		t.Parallel()
		for _, malformed := range []string{
			"", "sha256:", "sha256:short", "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65),
			"sha256:" + strings.Repeat("A", 64), "SHA256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("g", 64),
			"md5:" + strings.Repeat("a", 64), strings.Repeat("a", 64),
		} {
			facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, malformed, "reporting", "contracts")
			assertGovernedExposureRefused(t, facts, err, CodePersistence, malformed)
		}
	})
}

// 8. Inventory and prose bounds are inclusive at their edges: the boundary
// value is accepted, one past it is refused with the matching hash, so only
// the bound itself can be the reason.
func TestDecodeGovernedExposureBoundsInventoryAndProse(t *testing.T) {
	t.Parallel()

	for _, objects := range []int{1, maxGovernedExposureObjects} {
		artifact, hash := exposureArtifact(t, exposureFixtureWithObjects(objects))
		facts, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "relation_0")
		if err != nil {
			t.Fatalf("%d objects refused: %v", objects, err)
		}
		if len(facts.columns) != 1 {
			t.Fatalf("%d-object projection columns = %v", objects, facts.columns)
		}
	}
	oversized, oversizedHash := exposureArtifact(t, exposureFixtureWithObjects(maxGovernedExposureObjects+1))
	facts, err := decodeGovernedExposure(oversized, governedExposureGoldenRevision, oversizedHash, "reporting", "relation_0")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)

	for _, columns := range []int{1, maxGovernedExposureColumns} {
		artifact, hash := exposureArtifact(t, exposureFixtureWithColumns(columns))
		if _, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "wide"); err != nil {
			t.Fatalf("%d columns refused: %v", columns, err)
		}
	}
	wide, wideHash := exposureArtifact(t, exposureFixtureWithColumns(maxGovernedExposureColumns+1))
	facts, err = decodeGovernedExposure(wide, governedExposureGoldenRevision, wideHash, "reporting", "wide")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)

	// Description: 512 runes accepted, 513 refused. Unit: 64 accepted, 65
	// refused. Both use the artifact's own hash, so only the prose bound can
	// produce the refusal.
	atDescriptionLimit := cloneExposureFixture()
	atDescriptionLimit[0].Description = strings.Repeat("d", maxGovernedExposureDescriptionRunes)
	bounded, boundedHash := exposureArtifact(t, atDescriptionLimit)
	if _, err := decodeGovernedExposure(bounded, governedExposureGoldenRevision, boundedHash, "reporting", "contracts"); err != nil {
		t.Fatalf("description at the rune bound refused: %v", err)
	}
	overDescription := cloneExposureFixture()
	overDescription[0].Description = strings.Repeat("d", maxGovernedExposureDescriptionRunes+1)
	over, overHash := exposureArtifact(t, overDescription)
	facts, err = decodeGovernedExposure(over, governedExposureGoldenRevision, overHash, "reporting", "contracts")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)

	atUnitLimit := cloneExposureFixture()
	atUnitLimit[0].Columns[0].Unit = strings.Repeat("u", maxGovernedExposureUnitRunes)
	bounded, boundedHash = exposureArtifact(t, atUnitLimit)
	if _, err := decodeGovernedExposure(bounded, governedExposureGoldenRevision, boundedHash, "reporting", "contracts"); err != nil {
		t.Fatalf("unit at the rune bound refused: %v", err)
	}
	overUnit := cloneExposureFixture()
	overUnit[0].Columns[0].Unit = strings.Repeat("u", maxGovernedExposureUnitRunes+1)
	over, overHash = exposureArtifact(t, overUnit)
	facts, err = decodeGovernedExposure(over, governedExposureGoldenRevision, overHash, "reporting", "contracts")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)

	// A control character that is not a newline is not prose.
	control := cloneExposureFixture()
	control[0].Description = "Contracts\u0000registry"
	over, overHash = exposureArtifact(t, control)
	facts, err = decodeGovernedExposure(over, governedExposureGoldenRevision, overHash, "reporting", "contracts")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)
}

// 9. The fixed 8 MiB cap is a pre-decode boundary: exactly at the cap the
// artifact still decodes to the same hash, one byte past it is refused.
func TestDecodeGovernedExposureCapsArtifactBytes(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())

	atCap := append([]byte(nil), artifact...)
	atCap = append(atCap, bytes.Repeat([]byte(" "), maxGovernedExposureArtifactBytes-len(atCap))...)
	if len(atCap) != maxGovernedExposureArtifactBytes {
		t.Fatalf("padded artifact = %d bytes, want %d", len(atCap), maxGovernedExposureArtifactBytes)
	}
	// Trailing jsonb whitespace is not part of the decoded artifact, so the
	// hash must be unchanged: scanned bytes are never hashed.
	facts, err := decodeGovernedExposure(atCap, governedExposureGoldenRevision, hash, "reporting", "contracts")
	if err != nil {
		t.Fatalf("artifact exactly at the 8 MiB cap refused: %v", err)
	}
	if facts.artifactHash != hash {
		t.Fatalf("padded artifact hash = %q, want %q", facts.artifactHash, hash)
	}

	overCap := append(atCap, ' ')
	facts, err = decodeGovernedExposure(overCap, governedExposureGoldenRevision, hash, "reporting", "contracts")
	assertGovernedExposureRefused(t, facts, err, CodePersistence)
}

// 10. Returned columns are detached from the decoded artifact, from the input
// bytes and from another result.
func TestDecodeGovernedExposureResultsAreDetached(t *testing.T) {
	t.Parallel()

	pristine, hash := exposureArtifact(t, exposureFixture())
	artifact := append([]byte(nil), pristine...)

	first, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "contracts")
	if err != nil {
		t.Fatalf("valid artifact refused: %v", err)
	}
	second, err := decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "contracts")
	if err != nil {
		t.Fatalf("valid artifact refused: %v", err)
	}

	// Trashing the caller's input bytes after the call cannot reach either
	// result: nothing in the facts aliases the scanned document.
	for index := range artifact {
		artifact[index] = 'x'
	}
	assertGovernedExposureColumns(t, first, "id", "amount", "signed_on")
	assertGovernedExposureColumns(t, second, "id", "amount", "signed_on")

	first.columns[0] = "tampered"
	if second.columns[0] != "id" {
		t.Fatalf("mutating one result changed another: %v", second.columns)
	}
	third, err := decodeGovernedExposure(pristine, governedExposureGoldenRevision, hash, "reporting", "contracts")
	if err != nil {
		t.Fatalf("re-decode refused: %v", err)
	}
	assertGovernedExposureColumns(t, third, "id", "amount", "signed_on")
}

// 11. Every failure returns the true zero result and a content-free repository
// error, whatever the defect was.
func TestDecodeGovernedExposureFailuresAreContentFree(t *testing.T) {
	t.Parallel()

	artifact, hash := exposureArtifact(t, exposureFixture())

	type refusal struct {
		name string
		call func() (governedExposureFacts, error)
		want ErrorCode
	}
	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)-2] = '0'
	for _, test := range []refusal{
		{"empty input", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(nil, governedExposureGoldenRevision, hash, "reporting", "contracts")
		}, CodePersistence},
		{"unsafe revision", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(artifact, maxSafeInteger+1, hash, "reporting", "contracts")
		}, CodePersistence},
		{"malformed hash", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(artifact, governedExposureGoldenRevision, "sha256:UPPER", "reporting", "contracts")
		}, CodePersistence},
		{"invalid requested identifier", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "bad.name")
		}, CodePersistence},
		{"undecodable wire", func() (governedExposureFacts, error) {
			return decodeGovernedExposure([]byte(`{"objects":[]}`), governedExposureGoldenRevision, hash, "reporting", "contracts")
		}, CodePersistence},
		{"content hash mismatch", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(tampered, governedExposureGoldenRevision, hash, "reporting", "contracts")
		}, CodePersistence},
		{"missing relation", func() (governedExposureFacts, error) {
			return decodeGovernedExposure(artifact, governedExposureGoldenRevision, hash, "reporting", "ledger")
		}, CodeNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts, err := test.call()
			assertGovernedExposureRefused(t, facts, err, test.want,
				"reporting", "contracts", "invoices", "Contracts registry", "invoice_id", string(tampered))
		})
	}
}

// 12. The decode stays pure and unprivileged: no governedquery/governedask
// import (the architecture guard's single-owner rule for the governed
// execution capability) and no mutable package-level state.
func TestGovernedExposureDecodeStaysPureAndUnprivileged(t *testing.T) {
	t.Parallel()

	source := "governed_exposure_decode.go"
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, source, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	if parsed.Name.Name != "repository" {
		t.Fatalf("package = %q, want repository", parsed.Name.Name)
	}
	allowed := map[string]bool{
		"encoding/json/jsontext": true,
		"encoding/json/v2":       true,
		"knowvault.local/verified-workspace/internal/source/canon": true,
		"knowvault.local/verified-workspace/internal/workspace":    true,
	}
	for _, imported := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatalf("unquote import %s: %v", imported.Path.Value, unquoteErr)
		}
		if !allowed[path] {
			t.Fatalf("unexpected import %q: the decode must not gain a governed-capability or I/O dependency", path)
		}
	}
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		t.Fatalf("package-level var at %s: the decode must hold no mutable package state", files.Position(general.Pos()))
	}
}
