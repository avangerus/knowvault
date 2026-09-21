package repository

// Acceptance corpus for the governed-exposure lookup/result shape (B2.3b1a).
// Every case drives the shape directly: no database, no transaction, no policy
// and no clock participates, so the whole corpus is a pure unit proof of the
// neutral value. The result is always built from one internal literal in this
// package because the constructor is deliberately the next card; the detached
// slice is copied explicitly here for exactly the same reason.

import (
	jsonv2 "encoding/json/v2"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

const (
	governedExposureResultTestWorkspaceID       = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestWorkspaceSourceID = "src_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestSourceScopeID     = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestConnectionID      = "con_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestDatabaseIdentity  = "pgdb:fixture-identity"
	governedExposureResultTestArtifactHash      = "sha256:8881776408326a6164636f8999d6bdb3071940e6d70a841794aa319a0a9c99a0"

	governedExposureResultTestSchema   = "reporting"
	governedExposureResultTestRelation = "contracts"
)

// governedExposureResultTestColumns returns a fresh source slice on every call,
// so one table case can never mutate another's columns.
func governedExposureResultTestColumns() []string {
	return []string{"id", "amount", "signed_on"}
}

// governedExposureResultTestResolved builds the one internal literal this
// corpus observes: every scalar set to a distinct recognizable value. The
// columns are copied on construction, exactly as the constructor will copy
// them, so the returned result owns its own slice.
func governedExposureResultTestResolved() GovernedExposureResult {
	source := governedExposureResultTestColumns()
	columns := make([]string, len(source))
	copy(columns, source)
	return GovernedExposureResult{
		workspaceID:                  governedExposureResultTestWorkspaceID,
		workspaceRevision:            7,
		workspaceConfigurationHash:   "sha256:workspace-configuration-hash",
		workspaceSourceID:            governedExposureResultTestWorkspaceSourceID,
		sourceScopeID:                governedExposureResultTestSourceScopeID,
		sourceScopeRevision:          11,
		sourceScopeConfigurationHash: "sha256:source-scope-configuration-hash",
		connectionID:                 governedExposureResultTestConnectionID,
		connectionRevision:           13,
		databaseIdentity:             governedExposureResultTestDatabaseIdentity,
		liveQueryEnabled:             true,
		exposureRevision:             17,
		exposureArtifactHash:         governedExposureResultTestArtifactHash,
		schemaName:                   governedExposureResultTestSchema,
		relationName:                 governedExposureResultTestRelation,
		columns:                      columns,
		resolved:                     true,
	}
}

// assertGovernedExposureResultScalars proves every scalar accessor returns the
// exact literal value, never a derived or defaulted one.
func assertGovernedExposureResultScalars(t *testing.T, result GovernedExposureResult) {
	t.Helper()
	if got := result.WorkspaceID(); got != governedExposureResultTestWorkspaceID {
		t.Fatalf("WorkspaceID = %q, want %q", got, governedExposureResultTestWorkspaceID)
	}
	if got := result.WorkspaceRevision(); got != 7 {
		t.Fatalf("WorkspaceRevision = %d, want 7", got)
	}
	if got := result.WorkspaceConfigurationHash(); got != "sha256:workspace-configuration-hash" {
		t.Fatalf("WorkspaceConfigurationHash = %q", got)
	}
	if got := result.WorkspaceSourceID(); got != governedExposureResultTestWorkspaceSourceID {
		t.Fatalf("WorkspaceSourceID = %q, want %q", got, governedExposureResultTestWorkspaceSourceID)
	}
	if got := result.SourceScopeID(); got != governedExposureResultTestSourceScopeID {
		t.Fatalf("SourceScopeID = %q, want %q", got, governedExposureResultTestSourceScopeID)
	}
	if got := result.SourceScopeRevision(); got != 11 {
		t.Fatalf("SourceScopeRevision = %d, want 11", got)
	}
	if got := result.SourceScopeConfigurationHash(); got != "sha256:source-scope-configuration-hash" {
		t.Fatalf("SourceScopeConfigurationHash = %q", got)
	}
	if got := result.ConnectionID(); got != governedExposureResultTestConnectionID {
		t.Fatalf("ConnectionID = %q, want %q", got, governedExposureResultTestConnectionID)
	}
	if got := result.ConnectionRevision(); got != 13 {
		t.Fatalf("ConnectionRevision = %d, want 13", got)
	}
	if got := result.DatabaseIdentity(); got != governedExposureResultTestDatabaseIdentity {
		t.Fatalf("DatabaseIdentity = %q, want %q", got, governedExposureResultTestDatabaseIdentity)
	}
	if got := result.LiveQueryEnabled(); !got {
		t.Fatal("LiveQueryEnabled = false, want true")
	}
	if got := result.ExposureRevision(); got != 17 {
		t.Fatalf("ExposureRevision = %d, want 17", got)
	}
	if got := result.ExposureArtifactHash(); got != governedExposureResultTestArtifactHash {
		t.Fatalf("ExposureArtifactHash = %q, want %q", got, governedExposureResultTestArtifactHash)
	}
	if got := result.SchemaName(); got != governedExposureResultTestSchema {
		t.Fatalf("SchemaName = %q, want %q", got, governedExposureResultTestSchema)
	}
	if got := result.RelationName(); got != governedExposureResultTestRelation {
		t.Fatalf("RelationName = %q, want %q", got, governedExposureResultTestRelation)
	}
}

func assertGovernedExposureResultColumns(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("columns = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("columns = %v, want %v", got, want)
		}
	}
}

// 1. The true zero value is invalid, every scalar accessor is its zero value and
// Columns stays nil. The resolved bit is the only thing Valid reports, so a
// literal carrying every other field but resolved is still invalid.
func TestGovernedExposureResultZeroIsInvalidAndScalarFree(t *testing.T) {
	t.Parallel()

	var zero GovernedExposureResult
	if zero.Valid() {
		t.Fatal("zero result reports Valid")
	}
	if zero.WorkspaceID() != "" || zero.WorkspaceRevision() != 0 ||
		zero.WorkspaceConfigurationHash() != "" || zero.WorkspaceSourceID() != "" ||
		zero.SourceScopeID() != "" || zero.SourceScopeRevision() != 0 ||
		zero.SourceScopeConfigurationHash() != "" || zero.ConnectionID() != "" ||
		zero.ConnectionRevision() != 0 || zero.DatabaseIdentity() != "" ||
		zero.LiveQueryEnabled() || zero.ExposureRevision() != 0 ||
		zero.ExposureArtifactHash() != "" || zero.SchemaName() != "" ||
		zero.RelationName() != "" {
		t.Fatalf("zero result has a non-zero scalar accessor: %+v", zero)
	}
	if columns := zero.Columns(); columns != nil {
		t.Fatalf("zero Columns() = %v, want nil", columns)
	}

	unresolved := governedExposureResultTestResolved()
	unresolved.resolved = false
	if unresolved.Valid() {
		t.Fatal("a literal with the resolved bit cleared reports Valid")
	}
}

// 2. One resolved literal preserves every exact scalar value and the exact
// column order, and reports Valid.
func TestGovernedExposureResultResolvedLiteralPreservesEveryExactValue(t *testing.T) {
	t.Parallel()

	result := governedExposureResultTestResolved()
	if !result.Valid() {
		t.Fatal("resolved literal reports invalid")
	}
	assertGovernedExposureResultScalars(t, result)
	assertGovernedExposureResultColumns(t, result.Columns(), "id", "amount", "signed_on")
}

// 3. Mutating the source slice after construction cannot reach the result: the
// constructor is the next card, so the explicit copy is made here and proves the
// shape itself retains nothing of the caller's slice.
func TestGovernedExposureResultRetainsNoSourceSlice(t *testing.T) {
	t.Parallel()

	source := governedExposureResultTestColumns()
	result := governedExposureResultTestResolved()

	// Trashing the caller's whole slice after construction changes nothing.
	for index := range source {
		source[index] = "tampered"
	}
	source = append(source, "forged")
	assertGovernedExposureResultScalars(t, result)
	assertGovernedExposureResultColumns(t, result.Columns(), "id", "amount", "signed_on")

	// A source slice captured before construction is equally detached.
	shared := governedExposureResultTestColumns()
	copied := make([]string, len(shared))
	copy(copied, shared)
	literal := GovernedExposureResult{
		schemaName: governedExposureResultTestSchema, relationName: governedExposureResultTestRelation,
		columns: copied, resolved: true,
	}
	shared[0] = "tampered"
	assertGovernedExposureResultColumns(t, literal.Columns(), "id", "amount", "signed_on")
}

// 4. Every Columns call is detached: rewriting or extending one returned slice
// leaves the result and every other returned slice exactly as they were.
func TestGovernedExposureResultColumnsAreDetachedPerCall(t *testing.T) {
	t.Parallel()

	result := governedExposureResultTestResolved()
	first := result.Columns()
	if len(first) == 0 {
		t.Fatal("resolved Columns() is empty")
	}
	first[0] = "tampered"
	first = append(first, "forged")

	second := result.Columns()
	assertGovernedExposureResultColumns(t, second, "id", "amount", "signed_on")
	if &first[0] == &second[0] {
		t.Fatal("two Columns() calls alias the same backing array")
	}
	third := result.Columns()
	assertGovernedExposureResultColumns(t, third, "id", "amount", "signed_on")
}

// 5. JSON for both the zero and the resolved result is exactly the opaque empty
// object: no private exposure value can leak through generic JSON logging.
func TestGovernedExposureResultMarshalsToExactlyEmptyObject(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		value GovernedExposureResult
	}{
		{"zero", GovernedExposureResult{}},
		{"resolved", governedExposureResultTestResolved()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := jsonv2.Marshal(test.value)
			if err != nil {
				t.Fatalf("Marshal(%s): %v", test.name, err)
			}
			if string(encoded) != "{}" {
				t.Fatalf("Marshal(%s) = %s, want {}", test.name, encoded)
			}
		})
	}
}

// 6. AST surface: the lookup is exactly the five required exported string
// fields, the result has no exported fields at all, there is no exported
// top-level constructor or function, and the file has no imports and no
// package-level variable.
func TestGovernedExposureResultASTSurfaceIsClosed(t *testing.T) {
	t.Parallel()

	const source = "governed_exposure_result.go"
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
	if len(parsed.Imports) != 0 {
		t.Fatalf("the shape must import nothing, found %d import(s)", len(parsed.Imports))
	}

	wantLookupFields := []string{"WorkspaceID", "SourceScopeID", "ConnectionID", "SchemaName", "RelationName"}
	lookupFields := []string{}
	sawLookup := false
	sawResult := false
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		if general.Tok == token.VAR {
			t.Fatalf("package-level var at %s: the shape must hold no mutable package state", files.Position(general.Pos()))
		}
		if general.Tok != token.TYPE {
			continue
		}
		for _, specification := range general.Specs {
			typeSpec, ok := specification.(*ast.TypeSpec)
			if !ok {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				t.Fatalf("%s is not a struct", typeSpec.Name.Name)
			}
			switch typeSpec.Name.Name {
			case "GovernedExposureLookup":
				sawLookup = true
				for _, field := range structure.Fields.List {
					if len(field.Names) != 1 {
						t.Fatalf("lookup field is not exactly one named field: %s", files.Position(field.Pos()))
					}
					identifier, ok := field.Type.(*ast.Ident)
					if !ok || identifier.Name != "string" {
						t.Fatalf("lookup field %s is not a plain string", field.Names[0].Name)
					}
					lookupFields = append(lookupFields, field.Names[0].Name)
				}
			case "GovernedExposureResult":
				sawResult = true
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							t.Fatalf("result exposes an exported field: %s", name.Name)
						}
					}
				}
			}
		}
	}
	if !sawLookup || !sawResult {
		t.Fatalf("missing type: lookup=%t result=%t", sawLookup, sawResult)
	}
	if len(lookupFields) != len(wantLookupFields) {
		t.Fatalf("lookup fields = %v, want exactly %v", lookupFields, wantLookupFields)
	}
	for index, want := range wantLookupFields {
		if lookupFields[index] != want {
			t.Fatalf("lookup fields = %v, want exactly %v", lookupFields, wantLookupFields)
		}
	}

	// The only exported declarations in the file are the two types and the
	// methods on them. A top-level exported function would be a constructor the
	// next card is supposed to add instead.
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if function.Recv == nil && function.Name.IsExported() {
			t.Fatalf("exported top-level function %s: the shape has no public constructor", function.Name.Name)
		}
		if function.Name.Name == "String" || function.Name.Name == "GoString" {
			t.Fatalf("the result must not define %s", function.Name.Name)
		}
	}

	// No rune of the source may name SQL or a credential-bearing field. The
	// intent is the surface, not the prose: the scan is case-sensitive, so the
	// comments above (which say "no SQL" and "no secret material") are not what
	// this proves.
	for _, forbidden := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "credential", "token"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the shape file mentions forbidden surface %q", forbidden)
		}
	}
}
