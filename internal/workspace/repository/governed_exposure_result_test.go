package repository

// Acceptance corpus for the governed-exposure lookup/result shape (B2.3b1a) and
// its private validation/construction boundary (B2.3b1b). Every case drives the
// shape directly: no database, no transaction, no policy and no clock
// participates, so the whole corpus is a pure unit proof of the neutral value.
// Every resolved result is built through newGovernedExposureResult; the only
// literal formed directly is the true zero value, whose bits the corpus also
// asserts whenever a representative fact is invalid.

import (
	jsonv2 "encoding/json/v2"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	governedExposureResultTestWorkspaceID       = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestWorkspaceSourceID = "src_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestSourceScopeID     = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestConnectionID      = "con_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureResultTestDatabaseIdentity  = "pgdb:Fixture-Identity"

	governedExposureResultTestWorkspaceConfigurationHash   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	governedExposureResultTestSourceScopeConfigurationHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	governedExposureResultTestArtifactHash                 = "sha256:8881776408326a6164636f8999d6bdb3071940e6d70a841794aa319a0a9c99a0"

	// The schema, relation and column spellings are deliberately mixed-case and
	// dollar-bearing: the boundary accepts the typed-analytics identifier shape
	// and must retain every exact spelling and its exact order.
	governedExposureResultTestSchema   = "Reporting$2024"
	governedExposureResultTestRelation = "Contracts_$Q3"

	governedExposureResultTestWorkspaceRevision   = 7
	governedExposureResultTestSourceScopeRevision = 11
	governedExposureResultTestConnectionRevision  = 13
	governedExposureResultTestExposureRevision    = 17
)

// governedExposureResultTestColumns returns a fresh source slice on every call,
// so one case can never mutate another's columns.
func governedExposureResultTestColumns() []string {
	return []string{"ID", "amount$Total", "Signed_On"}
}

// governedExposureResultTestWideColumns returns count distinct valid column
// names in a fixed order, so a bounds case can exceed the column cap without
// tripping any other rule.
func governedExposureResultTestWideColumns(count int) []string {
	columns := make([]string, count)
	for index := range columns {
		columns[index] = "column_" + strconv.Itoa(index)
	}
	return columns
}

// governedExposureResultTestInput returns one fully valid input whose every fact
// is exactly recognizable.
func governedExposureResultTestInput() governedExposureResultInput {
	return governedExposureResultInput{
		workspaceID:                  governedExposureResultTestWorkspaceID,
		workspaceRevision:            governedExposureResultTestWorkspaceRevision,
		workspaceConfigurationHash:   governedExposureResultTestWorkspaceConfigurationHash,
		workspaceSourceID:            governedExposureResultTestWorkspaceSourceID,
		sourceScopeID:                governedExposureResultTestSourceScopeID,
		sourceScopeRevision:          governedExposureResultTestSourceScopeRevision,
		sourceScopeConfigurationHash: governedExposureResultTestSourceScopeConfigurationHash,
		connectionID:                 governedExposureResultTestConnectionID,
		connectionRevision:           governedExposureResultTestConnectionRevision,
		databaseIdentity:             governedExposureResultTestDatabaseIdentity,
		liveQueryEnabled:             true,
		exposureRevision:             governedExposureResultTestExposureRevision,
		exposureArtifactHash:         governedExposureResultTestArtifactHash,
		schemaName:                   governedExposureResultTestSchema,
		relationName:                 governedExposureResultTestRelation,
		columns:                      governedExposureResultTestColumns(),
	}
}

// governedExposureResultTestResolved builds the one valid result this corpus
// observes, through the private constructor only.
func governedExposureResultTestResolved() GovernedExposureResult {
	return newGovernedExposureResult(governedExposureResultTestInput())
}

// assertGovernedExposureResultScalars proves every scalar accessor returns the
// exact literal value, never a derived or defaulted one.
func assertGovernedExposureResultScalars(t *testing.T, result GovernedExposureResult) {
	t.Helper()
	if got := result.WorkspaceID(); got != governedExposureResultTestWorkspaceID {
		t.Fatalf("WorkspaceID = %q, want %q", got, governedExposureResultTestWorkspaceID)
	}
	if got := result.WorkspaceRevision(); got != governedExposureResultTestWorkspaceRevision {
		t.Fatalf("WorkspaceRevision = %d, want %d", got, governedExposureResultTestWorkspaceRevision)
	}
	if got := result.WorkspaceConfigurationHash(); got != governedExposureResultTestWorkspaceConfigurationHash {
		t.Fatalf("WorkspaceConfigurationHash = %q", got)
	}
	if got := result.WorkspaceSourceID(); got != governedExposureResultTestWorkspaceSourceID {
		t.Fatalf("WorkspaceSourceID = %q, want %q", got, governedExposureResultTestWorkspaceSourceID)
	}
	if got := result.SourceScopeID(); got != governedExposureResultTestSourceScopeID {
		t.Fatalf("SourceScopeID = %q, want %q", got, governedExposureResultTestSourceScopeID)
	}
	if got := result.SourceScopeRevision(); got != governedExposureResultTestSourceScopeRevision {
		t.Fatalf("SourceScopeRevision = %d, want %d", got, governedExposureResultTestSourceScopeRevision)
	}
	if got := result.SourceScopeConfigurationHash(); got != governedExposureResultTestSourceScopeConfigurationHash {
		t.Fatalf("SourceScopeConfigurationHash = %q", got)
	}
	if got := result.ConnectionID(); got != governedExposureResultTestConnectionID {
		t.Fatalf("ConnectionID = %q, want %q", got, governedExposureResultTestConnectionID)
	}
	if got := result.ConnectionRevision(); got != governedExposureResultTestConnectionRevision {
		t.Fatalf("ConnectionRevision = %d, want %d", got, governedExposureResultTestConnectionRevision)
	}
	if got := result.DatabaseIdentity(); got != governedExposureResultTestDatabaseIdentity {
		t.Fatalf("DatabaseIdentity = %q, want %q", got, governedExposureResultTestDatabaseIdentity)
	}
	if got := result.LiveQueryEnabled(); !got {
		t.Fatal("LiveQueryEnabled = false, want true")
	}
	if got := result.ExposureRevision(); got != governedExposureResultTestExposureRevision {
		t.Fatalf("ExposureRevision = %d, want %d", got, governedExposureResultTestExposureRevision)
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

// assertGovernedExposureResultIsTrueZero proves a refused construction returned
// the exact zero result: invalid, every scalar accessor empty, Columns nil and
// both private zero bits untouched. A partial or best-effort value would fail
// here even if it reported Valid() == false.
func assertGovernedExposureResultIsTrueZero(t *testing.T, result GovernedExposureResult) {
	t.Helper()
	if result.Valid() {
		t.Fatalf("refused input produced a valid result: %+v", result)
	}
	if result.WorkspaceID() != "" || result.WorkspaceRevision() != 0 ||
		result.WorkspaceConfigurationHash() != "" || result.WorkspaceSourceID() != "" ||
		result.SourceScopeID() != "" || result.SourceScopeRevision() != 0 ||
		result.SourceScopeConfigurationHash() != "" || result.ConnectionID() != "" ||
		result.ConnectionRevision() != 0 || result.DatabaseIdentity() != "" ||
		result.LiveQueryEnabled() || result.ExposureRevision() != 0 ||
		result.ExposureArtifactHash() != "" || result.SchemaName() != "" ||
		result.RelationName() != "" {
		t.Fatalf("refused input produced a non-zero scalar: %+v", result)
	}
	if columns := result.Columns(); columns != nil {
		t.Fatalf("refused input Columns() = %v, want nil", columns)
	}
	if result.columns != nil || result.resolved {
		t.Fatalf("refused input left a private bit set: %+v", result)
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

// 2. Every valid mixed-case and dollar-bearing fact survives construction
// exactly: all scalars, the exact case of every identifier and the exact column
// order are retained, and the result reports Valid.
func TestGovernedExposureResultConstructsEveryExactMixedCaseDollarFact(t *testing.T) {
	t.Parallel()

	result := governedExposureResultTestResolved()
	if !result.Valid() {
		t.Fatal("fully valid facts were refused")
	}
	assertGovernedExposureResultScalars(t, result)
	assertGovernedExposureResultColumns(t, result.Columns(), "ID", "amount$Total", "Signed_On")
}

// 3. Mutating the source slice after construction cannot reach the result, and
// the result's own internal slice is unreachable through Columns as well.
func TestGovernedExposureResultRetainsNoSourceSlice(t *testing.T) {
	t.Parallel()

	input := governedExposureResultTestInput()
	source := governedExposureResultTestColumns()
	input.columns = source
	result := newGovernedExposureResult(input)
	if !result.Valid() {
		t.Fatal("fully valid facts were refused")
	}

	// Trashing the caller's slice — and the input's own view of it — after
	// construction changes nothing.
	for index := range source {
		source[index] = "tampered"
	}
	input.columns[0] = "tampered"
	assertGovernedExposureResultScalars(t, result)
	assertGovernedExposureResultColumns(t, result.Columns(), "ID", "amount$Total", "Signed_On")

	// A returned copy is detached from the result's internal slice too.
	detached := result.Columns()
	detached[0] = "tampered"
	detached = append(detached, "forged")
	assertGovernedExposureResultColumns(t, result.Columns(), "ID", "amount$Total", "Signed_On")
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
	assertGovernedExposureResultColumns(t, second, "ID", "amount$Total", "Signed_On")
	if &first[0] == &second[0] {
		t.Fatal("two Columns() calls alias the same backing array")
	}
	third := result.Columns()
	assertGovernedExposureResultColumns(t, third, "ID", "amount$Total", "Signed_On")
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

// 6. One representative invalid fact per validation class returns the exact
// zero result: no ID, revision, hash, database identity, live flag, schema,
// relation or column class may survive construction, and no failure may leave a
// partially filled value behind.
func TestGovernedExposureResultRejectsRepresentativeInvalidFacts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*governedExposureResultInput)
	}{
		{"workspace ID empty", func(input *governedExposureResultInput) { input.workspaceID = "" }},
		{"workspace ID too short", func(input *governedExposureResultInput) { input.workspaceID = "ws" }},
		{"workspace ID leading space", func(input *governedExposureResultInput) {
			input.workspaceID = " " + governedExposureResultTestWorkspaceID
		}},
		{"workspace ID invalid character", func(input *governedExposureResultInput) { input.workspaceID = "ws/01ARZ3NDEKTSV4RRFFQ69G5FAV" }},
		{"workspace source ID empty", func(input *governedExposureResultInput) { input.workspaceSourceID = "" }},
		{"source scope ID too long", func(input *governedExposureResultInput) {
			input.sourceScopeID = "scope_" + strings.Repeat("s", 128)
		}},
		{"source scope ID invalid character", func(input *governedExposureResultInput) { input.sourceScopeID = "scope id" }},
		{"connection ID empty", func(input *governedExposureResultInput) { input.connectionID = "" }},
		{"connection ID trailing space", func(input *governedExposureResultInput) {
			input.connectionID = governedExposureResultTestConnectionID + " "
		}},
		{"workspace revision zero", func(input *governedExposureResultInput) { input.workspaceRevision = 0 }},
		{"workspace revision negative", func(input *governedExposureResultInput) { input.workspaceRevision = -1 }},
		{"workspace revision past safe integer", func(input *governedExposureResultInput) { input.workspaceRevision = maxSafeInteger + 1 }},
		{"source scope revision zero", func(input *governedExposureResultInput) { input.sourceScopeRevision = 0 }},
		{"source scope revision negative", func(input *governedExposureResultInput) { input.sourceScopeRevision = -maxSafeInteger }},
		{"connection revision past safe integer", func(input *governedExposureResultInput) { input.connectionRevision = maxSafeInteger + 1 }},
		{"exposure revision zero", func(input *governedExposureResultInput) { input.exposureRevision = 0 }},
		{"exposure revision negative", func(input *governedExposureResultInput) { input.exposureRevision = -1 }},
		{"workspace configuration hash empty", func(input *governedExposureResultInput) { input.workspaceConfigurationHash = "" }},
		{"workspace configuration hash short", func(input *governedExposureResultInput) { input.workspaceConfigurationHash = "sha256:short" }},
		{"source scope configuration hash uppercase digest", func(input *governedExposureResultInput) {
			input.sourceScopeConfigurationHash = "sha256:" + strings.Repeat("A", 64)
		}},
		{"exposure artifact hash not sha256", func(input *governedExposureResultInput) {
			input.exposureArtifactHash = "md5:" + strings.Repeat("a", 64)
		}},
		{"database identity empty", func(input *governedExposureResultInput) { input.databaseIdentity = "" }},
		{"database identity oversized", func(input *governedExposureResultInput) {
			input.databaseIdentity = strings.Repeat("d", 129)
		}},
		{"database identity invalid UTF-8", func(input *governedExposureResultInput) { input.databaseIdentity = "pgdb:\xff" }},
		{"database identity leading unicode space", func(input *governedExposureResultInput) { input.databaseIdentity = "\u00a0pgdb:x" }},
		{"database identity trailing unicode space", func(input *governedExposureResultInput) { input.databaseIdentity = "pgdb:x\u00a0" }},
		{"database identity invalid character", func(input *governedExposureResultInput) { input.databaseIdentity = "pgdb/x" }},
		{"live query disabled", func(input *governedExposureResultInput) { input.liveQueryEnabled = false }},
		{"schema empty", func(input *governedExposureResultInput) { input.schemaName = "" }},
		{"schema leading digit", func(input *governedExposureResultInput) { input.schemaName = "9reporting" }},
		{"schema quoted", func(input *governedExposureResultInput) { input.schemaName = `"reporting"` }},
		{"schema dotted", func(input *governedExposureResultInput) { input.schemaName = "reporting.public" }},
		{"schema oversized", func(input *governedExposureResultInput) { input.schemaName = strings.Repeat("s", 64) }},
		{"relation empty", func(input *governedExposureResultInput) { input.relationName = "" }},
		{"relation leading dollar", func(input *governedExposureResultInput) { input.relationName = "$contracts" }},
		{"relation invalid character", func(input *governedExposureResultInput) { input.relationName = "contracts-x" }},
		{"relation oversized", func(input *governedExposureResultInput) { input.relationName = strings.Repeat("r", 64) }},
		{"columns nil", func(input *governedExposureResultInput) { input.columns = nil }},
		{"columns empty", func(input *governedExposureResultInput) { input.columns = []string{} }},
		{"columns oversized", func(input *governedExposureResultInput) {
			input.columns = governedExposureResultTestWideColumns(maxGovernedExposureColumns + 1)
		}},
		{"columns duplicate", func(input *governedExposureResultInput) { input.columns = []string{"ID", "ID"} }},
		{"column empty", func(input *governedExposureResultInput) { input.columns = []string{"ID", ""} }},
		{"column leading digit", func(input *governedExposureResultInput) { input.columns = []string{"1ID"} }},
		{"column quoted", func(input *governedExposureResultInput) { input.columns = []string{`"ID"`} }},
		{"column invalid character", func(input *governedExposureResultInput) { input.columns = []string{"amount total"} }},
		{"column oversized", func(input *governedExposureResultInput) { input.columns = []string{strings.Repeat("c", 64)} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := governedExposureResultTestInput()
			test.mutate(&input)
			assertGovernedExposureResultIsTrueZero(t, newGovernedExposureResult(input))
		})
	}
}

// 7. The revision and column bounds are inclusive at their edges: 1 and
// maxSafeInteger, and 1 and maxGovernedExposureColumns, are accepted; one past
// each bound is refused with the true zero result.
func TestGovernedExposureResultBoundsRevisionsAndColumns(t *testing.T) {
	t.Parallel()

	for _, revision := range []int64{1, maxSafeInteger} {
		input := governedExposureResultTestInput()
		input.workspaceRevision = revision
		input.sourceScopeRevision = revision
		input.connectionRevision = revision
		input.exposureRevision = revision
		result := newGovernedExposureResult(input)
		if !result.Valid() {
			t.Fatalf("safe revision %d refused", revision)
		}
		if result.WorkspaceRevision() != revision || result.SourceScopeRevision() != revision ||
			result.ConnectionRevision() != revision || result.ExposureRevision() != revision {
			t.Fatalf("safe revision %d was rewritten", revision)
		}
	}

	for _, count := range []int{1, maxGovernedExposureColumns} {
		input := governedExposureResultTestInput()
		input.columns = governedExposureResultTestWideColumns(count)
		result := newGovernedExposureResult(input)
		if !result.Valid() {
			t.Fatalf("%d columns refused", count)
		}
		columns := result.Columns()
		if len(columns) != count {
			t.Fatalf("%d columns constructed %d", count, len(columns))
		}
		for index := range columns {
			if want := "column_" + strconv.Itoa(index); columns[index] != want {
				t.Fatalf("column %d = %q, want %q: order was not retained", index, columns[index], want)
			}
		}
	}

	input := governedExposureResultTestInput()
	input.columns = governedExposureResultTestWideColumns(maxGovernedExposureColumns + 1)
	assertGovernedExposureResultIsTrueZero(t, newGovernedExposureResult(input))
}

// 8. The database identity bound is 1..128 bytes and the accepted class is the
// existing PostgreSQL value semantics: mixed case and '_', '-', '.', ':' are
// retained, while an over-long value, Unicode whitespace at either edge and an
// invalid byte are refused.
func TestGovernedExposureResultBoundsDatabaseIdentity(t *testing.T) {
	t.Parallel()

	for _, identity := range []string{
		"d",
		strings.Repeat("d", 128),
		"PgDb:Fixture-Identity_2",
		"a-b.c:d",
	} {
		input := governedExposureResultTestInput()
		input.databaseIdentity = identity
		result := newGovernedExposureResult(input)
		if !result.Valid() {
			t.Fatalf("database identity %q refused", identity)
		}
		if got := result.DatabaseIdentity(); got != identity {
			t.Fatalf("DatabaseIdentity = %q, want %q", got, identity)
		}
	}

	for _, identity := range []string{
		strings.Repeat("d", 129),
		"\u00a0pgdb:x",
		"pgdb:x\u00a0",
		"pgdb:x\n",
		"pgdb:\xff",
		"pgdb/x",
	} {
		input := governedExposureResultTestInput()
		input.databaseIdentity = identity
		assertGovernedExposureResultIsTrueZero(t, newGovernedExposureResult(input))
	}
}

// 9. Column uniqueness is exact and case-sensitive: two spellings that differ
// only in case are two distinct columns and are retained in order, while a
// repeated exact spelling is refused. Schema and relation identifiers are exact
// in the same way.
func TestGovernedExposureResultColumnUniquenessIsExactAndCaseSensitive(t *testing.T) {
	t.Parallel()

	for _, columns := range [][]string{
		{"ID", "id"},
		{"amount$Total", "amount$total"},
		{"Signed_On", "signed_on", "SIGNED_ON"},
	} {
		input := governedExposureResultTestInput()
		input.columns = columns
		result := newGovernedExposureResult(input)
		if !result.Valid() {
			t.Fatalf("case-distinct columns %v refused", columns)
		}
		assertGovernedExposureResultColumns(t, result.Columns(), columns...)
	}

	for _, columns := range [][]string{
		{"ID", "ID"},
		{"amount$Total", "ID", "amount$Total"},
	} {
		input := governedExposureResultTestInput()
		input.columns = columns
		assertGovernedExposureResultIsTrueZero(t, newGovernedExposureResult(input))
	}

	// A 63-byte identifier is accepted, 64 bytes is not, and nothing is folded:
	// the lowercase spelling of the schema is a different identity, not an alias.
	input := governedExposureResultTestInput()
	input.schemaName = strings.Repeat("S", 63)
	input.relationName = "_"
	result := newGovernedExposureResult(input)
	if !result.Valid() {
		t.Fatal("63-byte identifier refused")
	}
	if result.SchemaName() != strings.Repeat("S", 63) || result.RelationName() != "_" {
		t.Fatalf("identifiers were rewritten: %q %q", result.SchemaName(), result.RelationName())
	}
	if result.SchemaName() == strings.Repeat("s", 63) {
		t.Fatal("uppercase identifier was case-folded")
	}
}

// 10. AST surface: the lookup is exactly the five required exported string
// fields, the result has no exported fields at all, the private input mirrors
// every result fact except resolved, the only constructor is the private
// newGovernedExposureResult with its exact signature, imports are exactly the
// allowlist validation genuinely needs, and the file has no package-level
// variable.
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

	// Imports are pinned to exactly the ones validation needs: the Unicode-aware
	// whitespace trim and UTF-8 check for the database identity, and the existing
	// configuration-hash representation. Any other import is a new dependency
	// this boundary has no reason to carry.
	allowedImports := map[string]bool{
		"strings":      true,
		"unicode/utf8": true,
		"knowvault.local/verified-workspace/internal/workspace": true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the shape file: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	wantLookupFields := []string{"WorkspaceID", "SourceScopeID", "ConnectionID", "SchemaName", "RelationName"}
	lookupFields := []string{}
	resultFields := []string{}
	inputFields := []string{}
	sawLookup := false
	sawResult := false
	sawInput := false
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
						resultFields = append(resultFields, name.Name)
					}
				}
			case "governedExposureResultInput":
				sawInput = true
				for _, field := range structure.Fields.List {
					for _, name := range field.Names {
						if name.IsExported() {
							t.Fatalf("input exposes an exported field: %s", name.Name)
						}
						inputFields = append(inputFields, name.Name)
					}
				}
			}
		}
	}
	if !sawLookup || !sawResult || !sawInput {
		t.Fatalf("missing type: lookup=%t result=%t input=%t", sawLookup, sawResult, sawInput)
	}
	if len(lookupFields) != len(wantLookupFields) {
		t.Fatalf("lookup fields = %v, want exactly %v", lookupFields, wantLookupFields)
	}
	for index, want := range wantLookupFields {
		if lookupFields[index] != want {
			t.Fatalf("lookup fields = %v, want exactly %v", lookupFields, wantLookupFields)
		}
	}

	// The input mirrors every result fact except the private resolved bit, field
	// for field and in order, so no fact can bypass validation and none is
	// silently dropped.
	wantInputFields := []string{}
	for _, field := range resultFields {
		if field == "resolved" {
			continue
		}
		wantInputFields = append(wantInputFields, field)
	}
	if len(inputFields) != len(wantInputFields) {
		t.Fatalf("input fields = %v, want exactly %v", inputFields, wantInputFields)
	}
	for index, want := range wantInputFields {
		if inputFields[index] != want {
			t.Fatalf("input fields = %v, want exactly %v", inputFields, wantInputFields)
		}
	}

	// The only exported declarations in the file are the two types and the
	// methods on them, and the one constructor is exactly the private boundary
	// newGovernedExposureResult(input governedExposureResultInput)
	// GovernedExposureResult.
	sawConstructor := false
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
		if function.Name.Name != "newGovernedExposureResult" {
			continue
		}
		sawConstructor = true
		if function.Recv != nil {
			t.Fatal("newGovernedExposureResult must not be a method")
		}
		if function.Type.Params == nil || len(function.Type.Params.List) != 1 {
			t.Fatal("newGovernedExposureResult must take exactly one parameter")
		}
		parameter := function.Type.Params.List[0]
		if len(parameter.Names) != 1 || parameter.Names[0].Name != "input" {
			t.Fatalf("newGovernedExposureResult parameter = %v, want input", parameter.Names)
		}
		if identifier, ok := parameter.Type.(*ast.Ident); !ok || identifier.Name != "governedExposureResultInput" {
			t.Fatalf("newGovernedExposureResult parameter type = %v, want governedExposureResultInput", parameter.Type)
		}
		if function.Type.Results == nil || len(function.Type.Results.List) != 1 {
			t.Fatal("newGovernedExposureResult must return exactly one value")
		}
		if identifier, ok := function.Type.Results.List[0].Type.(*ast.Ident); !ok || identifier.Name != "GovernedExposureResult" {
			t.Fatalf("newGovernedExposureResult result type = %v, want GovernedExposureResult", function.Type.Results.List[0].Type)
		}
	}
	if !sawConstructor {
		t.Fatal("missing private constructor newGovernedExposureResult")
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
