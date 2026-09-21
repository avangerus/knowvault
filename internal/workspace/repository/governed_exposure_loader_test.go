package repository

// B2.3b2a: admission-boundary unit proof for the scope-bound governed-exposure
// loader. Every case drives ResolveGovernedExposure directly against a boundary
// store whose database has no pool: no transaction, no policy row and no
// PostgreSQL server participates, so this corpus proves the admission boundary,
// the cause-free failure shape and the source-file contour without a database
// fixture. Query, cardinality, denial and malformed-server-fact cases belong to
// the next card's PostgreSQL acceptance.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	governedExposureLoaderTestWorkspaceID  = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureLoaderTestScopeID      = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	governedExposureLoaderTestConnectionID = "con_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	// The schema and relation spellings are deliberately mixed-case and
	// dollar-bearing: the loader follows the typed-analytics identifier shape
	// and must admit them unchanged rather than folding or repairing them.
	governedExposureLoaderTestSchema   = "Reporting$2024"
	governedExposureLoaderTestRelation = "Contracts_$Q3"
)

func governedExposureLoaderTestAccess() database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PrincipalID:    "prn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		RequestID:      "req_01ARZ3NDEKTSV4RRFFQ69G5FAV",
	}
}

func governedExposureLoaderTestLookup() GovernedExposureLookup {
	return GovernedExposureLookup{
		WorkspaceID:   governedExposureLoaderTestWorkspaceID,
		SourceScopeID: governedExposureLoaderTestScopeID,
		ConnectionID:  governedExposureLoaderTestConnectionID,
		SchemaName:    governedExposureLoaderTestSchema,
		RelationName:  governedExposureLoaderTestRelation,
	}
}

// assertGovernedExposureLoaderFailure proves one refused lookup returns the
// exact zero result and a content-free repository error: the exact safe code as
// its whole string form, no unwrap chain, no retained cause and no observable
// resolved or JSON-projected value.
func assertGovernedExposureLoaderFailure(t *testing.T, store *Store, ctx context.Context, access database.AccessContext, lookup GovernedExposureLookup, wantCode ErrorCode) {
	t.Helper()
	result, err := store.ResolveGovernedExposure(ctx, access, lookup)
	assertGovernedExposureResultIsTrueZero(t, result)
	encoded, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil || string(encoded) != "{}" {
		t.Fatalf("failure result JSON = %q err=%v, want the opaque empty object", encoded, marshalErr)
	}
	if err == nil {
		t.Fatal("expected a content-free repository error")
	}
	if got := err.Error(); got != string(wantCode) {
		t.Fatalf("error string = %q, want %q", got, string(wantCode))
	}
	if got := CodeOf(err); got != wantCode {
		t.Fatalf("error code = %q, want %q", got, wantCode)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("error retains an unwrap chain: %v", unwrapped)
	}
	var repositoryError *Error
	if !errors.As(err, &repositoryError) || repositoryError.cause != nil {
		t.Fatalf("error is not a content-free repository error: %#v", err)
	}
}

// 1. An invalid store, database, context or access context is refused before
// any read with the exact zero result and the content-free request-invalid code.
func TestResolveGovernedExposureRejectsInvalidAdmission(t *testing.T) {
	t.Parallel()

	boundaryStore := &Store{database: &database.Store{}}
	emptyAccess := database.AccessContext{}
	unknownActorKind := governedExposureLoaderTestAccess()
	unknownActorKind.ActorKind = database.ActorKind("ROBOT")
	paddedPrincipal := governedExposureLoaderTestAccess()
	paddedPrincipal.PrincipalID = governedExposureLoaderTestAccess().PrincipalID + " "
	controlRequestID := governedExposureLoaderTestAccess()
	controlRequestID.RequestID = "req_\x00control"
	oversizedOrganization := governedExposureLoaderTestAccess()
	oversizedOrganization.OrganizationID = strings.Repeat("o", 129)
	tests := []struct {
		name   string
		store  *Store
		ctx    context.Context
		access database.AccessContext
	}{
		{name: "nil store", store: nil, ctx: context.Background(), access: governedExposureLoaderTestAccess()},
		{name: "nil database", store: &Store{}, ctx: context.Background(), access: governedExposureLoaderTestAccess()},
		{name: "nil context", store: boundaryStore, ctx: nil, access: governedExposureLoaderTestAccess()},
		{name: "empty access", store: boundaryStore, ctx: context.Background(), access: emptyAccess},
		{name: "unknown actor kind", store: boundaryStore, ctx: context.Background(), access: unknownActorKind},
		{name: "padded principal", store: boundaryStore, ctx: context.Background(), access: paddedPrincipal},
		{name: "control request id", store: boundaryStore, ctx: context.Background(), access: controlRequestID},
		{name: "oversized organization", store: boundaryStore, ctx: context.Background(), access: oversizedOrganization},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assertGovernedExposureLoaderFailure(t, test.store, test.ctx, test.access, governedExposureLoaderTestLookup(), CodeRequestInvalid)
		})
	}
}

// 2. Every lookup identity field rejects the empty, short, oversized, padded,
// control, non-UTF-8, non-ASCII and forbidden forms at admission. The schema and
// relation additionally reject everything outside the typed-analytics exact
// shape, so a quoted, dotted, hyphenated, numeric-leading or dollar-leading
// spelling can never reach the database.
func TestResolveGovernedExposureRejectsEveryMalformedLookupField(t *testing.T) {
	t.Parallel()

	boundaryStore := &Store{database: &database.Store{}}
	malformedIdentity := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "too short", value: "ab"},
		{name: "too long", value: strings.Repeat("a", 129)},
		{name: "leading whitespace", value: " " + governedExposureLoaderTestWorkspaceID},
		{name: "trailing whitespace", value: governedExposureLoaderTestWorkspaceID + " "},
		{name: "embedded whitespace", value: "ws alpha"},
		{name: "tab", value: "ws\talpha"},
		{name: "null control character", value: "ws_\x00alpha"},
		{name: "newline control character", value: "ws_al\npha"},
		{name: "invalid utf8", value: "ws_\xffalpha"},
		{name: "non ascii letter", value: "ws_alph\u00e4"},
		{name: "forbidden character", value: "ws_al/pha"},
	}
	identityFields := []struct {
		name string
		set  func(*GovernedExposureLookup, string)
	}{
		{name: "workspace", set: func(lookup *GovernedExposureLookup, value string) { lookup.WorkspaceID = value }},
		{name: "source scope", set: func(lookup *GovernedExposureLookup, value string) { lookup.SourceScopeID = value }},
		{name: "connection", set: func(lookup *GovernedExposureLookup, value string) { lookup.ConnectionID = value }},
	}
	for _, field := range identityFields {
		for _, value := range malformedIdentity {
			t.Run(field.name+" id "+value.name, func(t *testing.T) {
				t.Parallel()
				lookup := governedExposureLoaderTestLookup()
				field.set(&lookup, value.value)
				assertGovernedExposureLoaderFailure(t, boundaryStore, context.Background(), governedExposureLoaderTestAccess(), lookup, CodeRequestInvalid)
			})
		}
	}

	malformedIdentifier := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "too long", value: strings.Repeat("s", 64)},
		{name: "leading digit", value: "9facts"},
		{name: "leading dollar", value: "$facts"},
		{name: "quoted", value: `"facts"`},
		{name: "leading whitespace", value: " facts"},
		{name: "trailing whitespace", value: "facts "},
		{name: "embedded whitespace", value: "fact table"},
		{name: "tab", value: "fact\ttable"},
		{name: "null control character", value: "fact\x00table"},
		{name: "invalid utf8", value: "fact\xfftable"},
		{name: "non ascii letter", value: "fakten\u00e4"},
		{name: "dotted", value: "reporting.facts"},
		{name: "hyphenated", value: "fact-table"},
	}
	identifierFields := []struct {
		name string
		set  func(*GovernedExposureLookup, string)
	}{
		{name: "schema", set: func(lookup *GovernedExposureLookup, value string) { lookup.SchemaName = value }},
		{name: "relation", set: func(lookup *GovernedExposureLookup, value string) { lookup.RelationName = value }},
	}
	for _, field := range identifierFields {
		for _, value := range malformedIdentifier {
			t.Run(field.name+" "+value.name, func(t *testing.T) {
				t.Parallel()
				lookup := governedExposureLoaderTestLookup()
				field.set(&lookup, value.value)
				assertGovernedExposureLoaderFailure(t, boundaryStore, context.Background(), governedExposureLoaderTestAccess(), lookup, CodeRequestInvalid)
			})
		}
	}
}

// 3. The typed-analytics identifier shape is admitted exactly: a 63-byte
// identifier, the underscore-only identity, the mixed-case/dollar spellings and
// even a SQL keyword identity all pass admission — the shape is purely lexical —
// and therefore reach the empty database boundary, while the 64th byte is
// refused at admission. Nothing is trimmed, folded or quoted.
func TestResolveGovernedExposureSchemaAndRelationFollowTypedAnalyticsExactShape(t *testing.T) {
	t.Parallel()

	boundaryStore := &Store{database: &database.Store{}}
	for _, identifiers := range [][2]string{
		{"Reporting$2024", "Contracts_$Q3"},
		{"_", "a"},
		{"Facts", "facts"},
		{"select", "from"},
		{strings.Repeat("S", 63), "_" + strings.Repeat("9", 62)},
		{"Z" + strings.Repeat("$", 62), "_"},
	} {
		lookup := governedExposureLoaderTestLookup()
		lookup.SchemaName = identifiers[0]
		lookup.RelationName = identifiers[1]
		assertGovernedExposureLoaderFailure(t, boundaryStore, context.Background(), governedExposureLoaderTestAccess(), lookup, CodePersistence)
	}

	for _, identifiers := range [][2]string{
		{strings.Repeat("s", 64), "facts"},
		{"facts", strings.Repeat("t", 64)},
	} {
		lookup := governedExposureLoaderTestLookup()
		lookup.SchemaName = identifiers[0]
		lookup.RelationName = identifiers[1]
		assertGovernedExposureLoaderFailure(t, boundaryStore, context.Background(), governedExposureLoaderTestAccess(), lookup, CodeRequestInvalid)
	}
}

// 4. A fully valid lookup is never rejected by admission itself: it reaches the
// database boundary. A zero-value database store has no pool, so that read can
// only fail closed with the content-free persistence error, which also proves no
// driver cause is wrapped and no result is fabricated.
func TestResolveGovernedExposureAdmitsValidLookupToTheDatabaseBoundary(t *testing.T) {
	t.Parallel()

	assertGovernedExposureLoaderFailure(t, &Store{database: &database.Store{}}, context.Background(), governedExposureLoaderTestAccess(), governedExposureLoaderTestLookup(), CodePersistence)
}

// 5. The loader source stays on the trusted read boundary: only the context and
// the reviewed database/policy/workspace packages are imported, the file holds
// exactly one database read and one single-row query, it never executes SQL and
// it pulls in no governed-execution, credential or transport capability.
func TestResolveGovernedExposureSourceFileStaysOnTheReadOnlyBoundary(t *testing.T) {
	t.Parallel()

	const source = "governed_exposure_loader.go"
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
	allowedImports := map[string]bool{
		"context": true,
		"knowvault.local/verified-workspace/internal/platform/database": true,
		"knowvault.local/verified-workspace/internal/policy":            true,
		"knowvault.local/verified-workspace/internal/workspace":         true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import %s: the loader may reach only the trusted read boundary", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	content := string(raw)
	lowered := strings.ToLower(content)
	for _, forbidden := range []string{
		"governedquery", "credential", "secretmount", "jackc/pgx",
		"database/sql", "net/http", "os/exec", "postgresqlquery",
	} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("loader source contains a forbidden capability reference %q", forbidden)
		}
	}
	for _, call := range []string{"store.database.Read(", "transaction.QueryRow("} {
		if count := strings.Count(content, call); count != 1 {
			t.Fatalf("%q occurrences = %d, want exactly 1", call, count)
		}
	}
	for _, call := range []string{"store.database.Write(", "transaction.Exec("} {
		if strings.Contains(content, call) {
			t.Fatalf("loader source performs a write or executes SQL: %q", call)
		}
	}
	for _, anchor := range []string{
		"policy.OperationWorkspaceAsk",
		"validGovernedExposureResultBase(base)",
		"decodeGovernedExposure(",
		"newGovernedExposureResult(",
		"WHERE admission_organization.id=$2",
		"AND admission_organization.status='ACTIVE'",
	} {
		if !strings.Contains(content, anchor) {
			t.Fatalf("loader source lost the required admission/construction anchor %q", anchor)
		}
	}
	baseValidation := strings.Index(content, "validGovernedExposureResultBase(base)")
	decode := strings.Index(content, "decodeGovernedExposure(")
	if baseValidation == -1 || decode == -1 || baseValidation > decode {
		t.Fatal("loader must validate base facts before decoding the exposure artifact")
	}
}
