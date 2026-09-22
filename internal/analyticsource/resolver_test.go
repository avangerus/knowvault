package analyticsource

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// resolverWorkspaceID deliberately differs from every identity the sealed
// fixture profile and its catalog carry, so a lookup filled from a profile or
// catalog identity instead of the request fails the exact expectations below.
const resolverWorkspaceID = "resolver_workspace"

// resolverFixture pairs one resolver holding a sealed single-entry catalog with
// the exact request that names it.
type resolverFixture struct {
	resolver *Resolver
	catalog  analytic.DatasetProfileCatalog
	profile  analytic.DatasetProfile
	request  ResolveRequest
}

// resolverFixtureFor seals one profile into a single-entry catalog, binds it to
// a store that owns no database, and derives the exact request that names the
// catalog revision and one profile version. The store proves the no-I/O
// boundary: any repository read would reach a nil database and fail instead of
// returning errMismatch.
func resolverFixtureFor(t *testing.T, profile analytic.DatasetProfile, state analytic.ProfileState) resolverFixture {
	t.Helper()
	catalog := repositoryCatalog(t, profile, state)
	store := new(repository.Store)
	resolver, err := NewResolver(store, catalog)
	if err != nil {
		t.Fatalf("fixture store and catalog refused: %v", err)
	}
	return resolverFixture{
		resolver: resolver,
		catalog:  catalog,
		profile:  profile,
		request: ResolveRequest{
			WorkspaceID: resolverWorkspaceID, CatalogID: catalog.ID(),
			CatalogRevision: catalog.Revision(), CatalogHash: catalog.Hash(),
			ProfileKey: profile.Key(), ProfileHash: profile.Hash(),
		},
	}
}

// assertPlanLookups requires the plan's two lookups to name exactly the request
// workspace and the approved source identities of profile, so a value copied
// from the wrong member is visible.
func assertPlanLookups(t *testing.T, plan resolutionPlan, profile analytic.DatasetProfile) {
	t.Helper()
	approved := profile.Source().Values()
	wantAuthority := repository.PostgreSQLAuthorityLookup{
		WorkspaceID: resolverWorkspaceID, SourceScopeID: approved.SourceScopeID,
		ConnectionID: approved.ConnectionID,
	}
	if plan.authority != wantAuthority {
		t.Fatalf("authority lookup = %+v, want %+v", plan.authority, wantAuthority)
	}
	wantExposure := repository.GovernedExposureLookup{
		WorkspaceID: resolverWorkspaceID, SourceScopeID: approved.SourceScopeID,
		ConnectionID: approved.ConnectionID, SchemaName: approved.SchemaName,
		RelationName: approved.RelationName,
	}
	if plan.exposure != wantExposure {
		t.Fatalf("exposure lookup = %+v, want %+v", plan.exposure, wantExposure)
	}
}

// assertResolutionPlanRefusal requires the exact zero plan and the one
// content-free sentinel. reflect.DeepEqual is required because the retained
// immutable DatasetProfile carries slices, so a plan value is not comparable.
func assertResolutionPlanRefusal(t *testing.T, value resolutionPlan, err error) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refused planning returned %v, want errMismatch", err)
	}
	if !reflect.DeepEqual(value, resolutionPlan{}) {
		t.Fatalf("refusal did not return the exact zero resolutionPlan: %+v", value)
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
}

// assertPublicResolveRefusal requires one public Resolve refusal to return the
// exact zero Resolution and the one content-free sentinel, with no wrapped
// cause, no JSON rendering of a retained value, and none of the supplied
// values in the message. reflect.DeepEqual is required because the retained
// binding carries slices, so a Resolution value is not comparable.
func assertPublicResolveRefusal(t *testing.T, value Resolution, err error, disclosures []string) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refused resolution returned %v, want errMismatch", err)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("refusal wraps %v, want the exact unwrapped errMismatch", unwrapped)
	}
	if !reflect.DeepEqual(value, Resolution{}) {
		t.Fatalf("refusal did not return the exact zero Resolution: %+v", value)
	}
	if value.Valid() {
		t.Fatal("the refused Resolution reports Valid")
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		t.Fatalf("marshal the refused Resolution: %v", marshalErr)
	}
	if string(encoded) != "{}" {
		t.Fatalf("refused Resolution marshaled to %s, want {}", encoded)
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
	for _, disclosure := range disclosures {
		if disclosure == "" {
			continue
		}
		if strings.Contains(err.Error(), disclosure) {
			t.Fatalf("the refusal disclosed %q", disclosure)
		}
	}
}

// resolverRefusalCase is one refused planning attempt: the resolver to call and
// the request to pass it.
type resolverRefusalCase struct {
	name     string
	resolver *Resolver
	request  ResolveRequest
}

// resolverRefusalCases builds every refusal this card owns: each malformed
// request member, each catalog identity drift, an unusable profile selection,
// and a nil or zero resolver.
func resolverRefusalCases(t *testing.T, fixture resolverFixture) []resolverRefusalCase {
	t.Helper()
	alternate := alternateFixtureProfile(t, fixture.profile)
	retired := resolverFixtureFor(t, fixture.profile, analytic.ProfileRetired)
	missingKey, err := analytic.NewProfileKey(fixture.profile.Key().DatasetID(), fixture.profile.Key().Version()+1)
	if err != nil {
		t.Fatalf("missing fixture key rejected: %v", err)
	}
	mutated := func(mutate func(*ResolveRequest)) ResolveRequest {
		request := fixture.request
		mutate(&request)
		return request
	}

	cases := []resolverRefusalCase{
		{"zero request", fixture.resolver, ResolveRequest{}},
		{"nil resolver", nil, fixture.request},
		{"zero resolver", &Resolver{}, fixture.request},
		{"retired profile", retired.resolver, retired.request},
		{"zero profile key", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.ProfileKey = analytic.ProfileKey{}
		})},
		{"missing profile version", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.ProfileKey = missingKey
		})},
		{"wrong profile hash", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.ProfileHash = alternate.Hash()
		})},
		{"catalog identity drift", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.CatalogID = alternateIdentity
		})},
		{"catalog revision drift", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.CatalogRevision = fixture.request.CatalogRevision + 1
		})},
		{"catalog hash drift", fixture.resolver, mutated(func(request *ResolveRequest) {
			request.CatalogHash = validHash("9")
		})},
	}
	for name, value := range map[string]string{
		"empty": "", "untrimmed": resolverWorkspaceID + " ",
		"control bearing": resolverWorkspaceID + "\x00", "overlong": strings.Repeat("w", 257),
	} {
		cases = append(cases,
			resolverRefusalCase{"workspace " + name, fixture.resolver, mutated(func(request *ResolveRequest) {
				request.WorkspaceID = value
			})},
			resolverRefusalCase{"catalog " + name, fixture.resolver, mutated(func(request *ResolveRequest) {
				request.CatalogID = value
			})},
		)
	}
	for name, value := range map[string]int64{"zero": 0, "negative": -1, "unsafe": maxBindingRevision + 1} {
		cases = append(cases, resolverRefusalCase{"catalog revision " + name, fixture.resolver,
			mutated(func(request *ResolveRequest) { request.CatalogRevision = value })})
	}
	for name, value := range map[string]string{
		"empty": "", "prefix only": "sha256:", "uppercase": strings.ToUpper(validHash("a")),
		"short":      validHash("a")[:len("sha256:")+63],
		"unprefixed": strings.Repeat("a", 64),
	} {
		cases = append(cases,
			resolverRefusalCase{"catalog hash " + name, fixture.resolver, mutated(func(request *ResolveRequest) {
				request.CatalogHash = value
			})},
			resolverRefusalCase{"profile hash " + name, fixture.resolver, mutated(func(request *ResolveRequest) {
				request.ProfileHash = value
			})},
		)
	}
	return cases
}

// resolverDisclosures lists every request, catalog and profile value the
// fixtures hand a resolver; no refusal may disclose one.
func resolverDisclosures(fixture resolverFixture) []string {
	approved := fixture.profile.Source().Values()
	values := []string{
		fixture.request.WorkspaceID, fixture.request.CatalogID, fixture.request.CatalogHash,
		fixture.request.ProfileHash, fixture.request.ProfileKey.DatasetID(),
		strconv.FormatInt(fixture.request.CatalogRevision, 10),
		fixture.catalog.ID(), fixture.catalog.Hash(), strconv.FormatInt(fixture.catalog.Revision(), 10),
		approved.SourceScopeID, approved.ConnectionID, approved.DatabaseIdentity,
		approved.ProjectionLineageID, approved.ProjectionContractHash, approved.ExposedSchemaHash,
		approved.SchemaName, approved.RelationName,
		alternateIdentity, alternateIdentifier, validHash("9"),
	}
	return append(values, fixtureDisclosures(fixture.profile)...)
}

func TestNewResolverRetainsConcreteStoreAndCatalog(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	catalog := repositoryCatalog(t, profile, analytic.ProfileActive)
	store := new(repository.Store)
	resolver, err := NewResolver(store, catalog)
	if err != nil {
		t.Fatalf("a nil-database store and a valid catalog were refused: %v", err)
	}
	if resolver.store != store {
		t.Fatal("the resolver did not retain the exact store pointer")
	}
	if !resolver.catalog.Valid() || resolver.catalog.ID() != catalog.ID() ||
		resolver.catalog.Revision() != catalog.Revision() || resolver.catalog.Hash() != catalog.Hash() {
		t.Fatal("the resolver did not retain the immutable catalog identity")
	}
	for name, refuse := range map[string]struct {
		store   *repository.Store
		catalog analytic.DatasetProfileCatalog
	}{
		"nil store":             {nil, catalog},
		"zero catalog":          {store, analytic.DatasetProfileCatalog{}},
		"nil with zero catalog": {nil, analytic.DatasetProfileCatalog{}},
	} {
		value, refusal := NewResolver(refuse.store, refuse.catalog)
		if value != nil {
			t.Fatalf("%s returned a resolver instead of nil", name)
		}
		if refusal != errMismatch || !errors.Is(refusal, errMismatch) {
			t.Fatalf("%s returned %v, want errMismatch", name, refusal)
		}
	}
}

func TestResolverPlanPreparesExactLookups(t *testing.T) {
	fixture := resolverFixtureFor(t, sealedFixtureProfile(t, false), analytic.ProfileActive)
	approved := fixture.profile.Source().Values()
	for name, value := range map[string]string{
		"source scope": approved.SourceScopeID, "connection": approved.ConnectionID,
		"database": approved.DatabaseIdentity, "lineage": approved.ProjectionLineageID,
		"schema": approved.SchemaName, "relation": approved.RelationName,
		"dataset": fixture.profile.Key().DatasetID(), "catalog": fixture.catalog.ID(),
	} {
		if value == resolverWorkspaceID {
			t.Fatalf("the %s fixture identity equals the request workspace, so a copying mistake would be invisible", name)
		}
	}
	plan, err := fixture.resolver.plan(fixture.request)
	if err != nil {
		t.Fatalf("the exact request was refused: %v", err)
	}
	if !plan.profile.Valid() || plan.profile.Key() != fixture.profile.Key() ||
		plan.profile.Hash() != fixture.profile.Hash() {
		t.Fatal("the plan did not retain the exact active profile")
	}
	assertPlanLookups(t, plan, fixture.profile)
}

func TestResolverPlanDerivesEverySourceValueFromTheSealedProfile(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	original := profile.Source().Values()
	variants := []struct {
		name   string
		mutate func(*analytic.SourceProjectionInput)
		read   func(analytic.SourceProjectionInput) string
	}{
		{"source scope", func(input *analytic.SourceProjectionInput) { input.SourceScopeID = "variant_scope" },
			func(input analytic.SourceProjectionInput) string { return input.SourceScopeID }},
		{"connection", func(input *analytic.SourceProjectionInput) { input.ConnectionID = "variant_connection" },
			func(input analytic.SourceProjectionInput) string { return input.ConnectionID }},
		{"schema", func(input *analytic.SourceProjectionInput) { input.SchemaName = "variant_schema" },
			func(input analytic.SourceProjectionInput) string { return input.SchemaName }},
		{"relation", func(input *analytic.SourceProjectionInput) { input.RelationName = "variant_relation" },
			func(input analytic.SourceProjectionInput) string { return input.RelationName }},
	}
	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			input := original
			variant.mutate(&input)
			source, err := analytic.NewSourceProjectionSpec(input)
			if err != nil {
				t.Fatalf("the variant projection was rejected: %v", err)
			}
			spec := profile.Spec()
			spec.Source = source
			changed, err := analytic.NewDatasetProfile(spec)
			if err != nil {
				t.Fatalf("the variant profile was rejected: %v", err)
			}
			if variant.read(changed.Source().Values()) == variant.read(original) {
				t.Fatal("the variant did not change the sealed source value")
			}
			fixture := resolverFixtureFor(t, changed, analytic.ProfileActive)
			plan, err := fixture.resolver.plan(fixture.request)
			if err != nil {
				t.Fatalf("the variant request was refused: %v", err)
			}
			assertPlanLookups(t, plan, changed)
		})
	}
}

func TestResolverPlanRefusesEveryMalformedOrDriftingSelection(t *testing.T) {
	fixture := resolverFixtureFor(t, sealedFixtureProfile(t, false), analytic.ProfileActive)
	cases := resolverRefusalCases(t, fixture)
	if len(cases) < 20 {
		t.Fatalf("the refusal table carries only %d cases", len(cases))
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.resolver.plan(test.request)
			assertResolutionPlanRefusal(t, value, err)
		})
	}
}

func TestResolverRefusalsDiscloseNoRequestCatalogOrProfileValue(t *testing.T) {
	fixture := resolverFixtureFor(t, sealedFixtureProfile(t, false), analytic.ProfileActive)
	disclosures := resolverDisclosures(fixture)
	for _, test := range resolverRefusalCases(t, fixture) {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.resolver.plan(test.request)
			assertResolutionPlanRefusal(t, value, err)
			for _, disclosure := range disclosures {
				if disclosure == "" {
					continue
				}
				if strings.Contains(err.Error(), disclosure) {
					t.Fatalf("the refusal disclosed %q", disclosure)
				}
			}
		})
	}
}

// TestResolverResolveRefusesEveryPlanningRefusal proves the public entry point
// returns exactly the normalized refusal for every selection the shared refusal
// table already refuses. The table remains the one malformed-input matrix; the
// nil context and zero access context passed here mean no call could return a
// usable Resolution even if planning accepted it, and
// TestResolverPlanRefusesEveryMalformedOrDriftingSelection owns the proof that
// planning refuses every one of these cases before any repository read.
func TestResolverResolveRefusesEveryPlanningRefusal(t *testing.T) {
	fixture := resolverFixtureFor(t, sealedFixtureProfile(t, false), analytic.ProfileActive)
	cases := resolverRefusalCases(t, fixture)
	if len(cases) < 20 {
		t.Fatalf("the refusal table carries only %d cases", len(cases))
	}
	disclosures := resolverDisclosures(fixture)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value, err := test.resolver.Resolve(nil, database.AccessContext{}, test.request)
			assertPublicResolveRefusal(t, value, err, disclosures)
		})
	}
}

// TestResolverResolveRefusesAtTheRepositoryBoundary proves the public entry
// point returns the same normalized refusal when an otherwise valid selection
// passes planning and the retained store refuses the call itself: a nil call
// context, a zero and an invalid access context, and the nil-database store the
// fixture retains. AccessContext is an exported struct with exported fields and
// an exported Validate, so the valid value below is an ordinary literal that
// needs no production seam, and the retained store's database field is nil, so
// every call stops at the store's own admission guard without a database and
// without a mock.
func TestResolverResolveRefusesAtTheRepositoryBoundary(t *testing.T) {
	fixture := resolverFixtureFor(t, sealedFixtureProfile(t, false), analytic.ProfileActive)
	valid := database.AccessContext{
		OrganizationID: "resolver_org", PrincipalID: "resolver_principal", RequestID: "resolver_request",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("the fixture access context is not valid: %v", err)
	}
	invalid := valid
	invalid.RequestID = " " + valid.RequestID
	if invalid.Validate() == nil {
		t.Fatal("the padded access context is valid, want an invalid one")
	}

	// The exact fixture request passes planning, so each refusal below belongs
	// to the retained store and not to the plan.
	plan, err := fixture.resolver.plan(fixture.request)
	if err != nil {
		t.Fatalf("the exact valid request did not reach the repository: %v", err)
	}
	assertPlanLookups(t, plan, fixture.profile)

	disclosures := slices.Concat(resolverDisclosures(fixture), []string{
		valid.OrganizationID, valid.PrincipalID, valid.RequestID, invalid.RequestID,
	})
	for _, test := range []struct {
		name   string
		ctx    context.Context
		access database.AccessContext
	}{
		{"nil context with valid access", nil, valid},
		{"zero access with a live context", context.Background(), database.AccessContext{}},
		{"invalid access with a live context", context.Background(), invalid},
		{"valid call context and access over the nil-database store", context.Background(), valid},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := fixture.resolver.Resolve(test.ctx, test.access, fixture.request)
			assertPublicResolveRefusal(t, value, err, disclosures)
		})
	}
}

func TestResolverProductionSurfaceIsPrivateAndClosed(t *testing.T) {
	const filename = "resolver.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	if parsed.Name.Name != "analyticsource" {
		t.Fatalf("package = %q, want analyticsource", parsed.Name.Name)
	}

	// Imports are pinned to exactly the four packages the plan and the three
	// separately authorized reads need, so no SQL, transport, execution,
	// logging or configuration package can enter here.
	allowedImports := map[string]bool{
		"context": true,
		"knowvault.local/verified-workspace/internal/analytic":             true,
		"knowvault.local/verified-workspace/internal/platform/database":    true,
		"knowvault.local/verified-workspace/internal/workspace/repository": true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the resolver: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	wantStructs := map[string][][2]string{
		"Resolver": {
			{"store", "*repository.Store"}, {"catalog", "analytic.DatasetProfileCatalog"},
		},
		"ResolveRequest": {
			{"WorkspaceID", "string"}, {"CatalogID", "string"}, {"CatalogRevision", "int64"},
			{"CatalogHash", "string"}, {"ProfileKey", "analytic.ProfileKey"}, {"ProfileHash", "string"},
		},
		"resolutionPlan": {
			{"profile", "analytic.DatasetProfile"},
			{"authority", "repository.PostgreSQLAuthorityLookup"},
			{"exposure", "repository.GovernedExposureLookup"},
		},
	}
	structs := map[string][][2]string{}
	functions := map[string]*ast.FuncDecl{}
	methods := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			for _, specification := range typed.Specs {
				declared, ok := specification.(*ast.TypeSpec)
				if !ok {
					t.Fatalf("resolver.go declares package-level state at %s", files.Position(specification.Pos()))
				}
				inner, ok := declared.Type.(*ast.StructType)
				if !ok {
					t.Fatalf("resolver.go declares non-struct type %s: no interface, callback or alias seam", declared.Name.Name)
				}
				structs[declared.Name.Name] = astFieldInventory(inner.Fields)
			}
		case *ast.FuncDecl:
			if typed.Recv == nil {
				functions[typed.Name.Name] = typed
				continue
			}
			methods[typed.Name.Name] = typed
		}
	}
	if !reflect.DeepEqual(structs, wantStructs) {
		t.Fatalf("resolver.go structs = %v, want %v", structs, wantStructs)
	}

	declaredFunctions := make([]string, 0, len(functions))
	for name := range functions {
		declaredFunctions = append(declaredFunctions, name)
	}
	slices.Sort(declaredFunctions)
	if !slices.Equal(declaredFunctions, []string{"NewResolver"}) {
		t.Fatalf("declared functions = %v, want exactly [NewResolver]", declaredFunctions)
	}
	constructor := functions["NewResolver"]
	wantConstructorParameters := [][2]string{
		{"store", "*repository.Store"}, {"catalog", "analytic.DatasetProfileCatalog"},
	}
	if parameters := astFieldInventory(constructor.Type.Params); !slices.Equal(parameters, wantConstructorParameters) {
		t.Fatalf("NewResolver parameters = %v, want %v", parameters, wantConstructorParameters)
	}
	wantConstructorResults := [][2]string{{"", "*Resolver"}, {"", "error"}}
	if results := astFieldInventory(constructor.Type.Results); !slices.Equal(results, wantConstructorResults) {
		t.Fatalf("NewResolver results = %v, want %v", results, wantConstructorResults)
	}
	// The constructor is exactly one refusal guard and one composite literal
	// retaining the two accepted parameters: no setter or replacement seam can
	// be added without failing here.
	if len(constructor.Body.List) != 2 {
		t.Fatal("NewResolver must be exactly one guard and one return")
	}
	if _, ok := constructor.Body.List[0].(*ast.IfStmt); !ok {
		t.Fatal("NewResolver must guard before it retains anything")
	}
	returned, ok := constructor.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 {
		t.Fatal("NewResolver must end with one accepted resolver and one error")
	}
	if accepted, ok := returned.Results[1].(*ast.Ident); !ok || accepted.Name != "nil" {
		t.Fatalf("NewResolver returns %v as its error, want nil", returned.Results[1])
	}
	address, ok := returned.Results[0].(*ast.UnaryExpr)
	if !ok || address.Op != token.AND {
		t.Fatal("NewResolver must return a pointer to the retained resolver")
	}
	literal, ok := address.X.(*ast.CompositeLit)
	if !ok || astTypeName(literal.Type) != "Resolver" {
		t.Fatalf("NewResolver returns %v, want one Resolver literal", returned.Results[0])
	}
	wantRetained := [][2]string{{"store", "store"}, {"catalog", "catalog"}}
	if retained := resolverRetention(literal); !slices.Equal(retained, wantRetained) {
		t.Fatalf("NewResolver retains %v, want exactly %v", retained, wantRetained)
	}

	declaredMethods := make([]string, 0, len(methods))
	for name := range methods {
		declaredMethods = append(declaredMethods, name)
	}
	slices.Sort(declaredMethods)
	// Resolve is the one callable entry point the resolver exposes; planning
	// stays private, so no second name reaches a caller.
	if !slices.Equal(declaredMethods, []string{"Resolve", "plan"}) {
		t.Fatalf("declared methods = %v, want exactly [Resolve plan]", declaredMethods)
	}
	resolver := methods["Resolve"]
	if receiver := astFieldInventory(resolver.Recv); len(receiver) != 1 || receiver[0][1] != "*Resolver" {
		t.Fatalf("Resolve receiver = %v, want one *Resolver", receiver)
	}
	wantResolveParameters := [][2]string{
		{"ctx", "context.Context"}, {"access", "database.AccessContext"}, {"request", "ResolveRequest"},
	}
	if parameters := astFieldInventory(resolver.Type.Params); !slices.Equal(parameters, wantResolveParameters) {
		t.Fatalf("Resolve parameters = %v, want %v", parameters, wantResolveParameters)
	}
	wantResolveResults := [][2]string{{"", "Resolution"}, {"", "error"}}
	if results := astFieldInventory(resolver.Type.Results); !slices.Equal(results, wantResolveResults) {
		t.Fatalf("Resolve results = %v, want %v", results, wantResolveResults)
	}
	assertResolveBody(t, resolver.Body)

	planner := methods["plan"]
	if receiver := astFieldInventory(planner.Recv); len(receiver) != 1 || receiver[0][1] != "*Resolver" {
		t.Fatalf("plan receiver = %v, want one *Resolver", receiver)
	}
	wantPlanParameters := [][2]string{{"request", "ResolveRequest"}}
	if parameters := astFieldInventory(planner.Type.Params); !slices.Equal(parameters, wantPlanParameters) {
		t.Fatalf("plan parameters = %v, want %v", parameters, wantPlanParameters)
	}
	wantPlanResults := [][2]string{{"", "resolutionPlan"}, {"", "error"}}
	if results := astFieldInventory(planner.Type.Results); !slices.Equal(results, wantPlanResults) {
		t.Fatalf("plan results = %v, want %v", results, wantPlanResults)
	}
}

func TestResolverValuesRetainOnlyTheAcceptedMembers(t *testing.T) {
	wantFields := map[reflect.Type][][2]string{
		reflect.TypeOf(Resolver{}): {
			{"store", "*repository.Store"}, {"catalog", "analytic.DatasetProfileCatalog"},
		},
		reflect.TypeOf(ResolveRequest{}): {
			{"WorkspaceID", "string"}, {"CatalogID", "string"}, {"CatalogRevision", "int64"},
			{"CatalogHash", "string"}, {"ProfileKey", "analytic.ProfileKey"}, {"ProfileHash", "string"},
		},
		reflect.TypeOf(resolutionPlan{}): {
			{"profile", "analytic.DatasetProfile"},
			{"authority", "repository.PostgreSQLAuthorityLookup"},
			{"exposure", "repository.GovernedExposureLookup"},
		},
	}
	for value, want := range wantFields {
		fields := make([][2]string, 0, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			fields = append(fields, [2]string{field.Name, field.Type.String()})
		}
		if !reflect.DeepEqual(fields, want) {
			t.Fatalf("%s fields = %v, want %v", value, fields, want)
		}
	}
	// Only the pointer carries the callable entry points: a copied resolver
	// value exposes no method at all. Reflection lists the methods in Go
	// method order, so ReauthorizeScalarDependency precedes Resolve.
	if reflect.TypeOf(Resolver{}).NumMethod() != 0 {
		t.Fatal("Resolver observes an exported method; only *Resolver may expose ReauthorizeScalarDependency and Resolve")
	}
	pointer := reflect.TypeOf(&Resolver{})
	exposed := make([]string, 0, pointer.NumMethod())
	for index := 0; index < pointer.NumMethod(); index++ {
		exposed = append(exposed, pointer.Method(index).Name)
	}
	if !slices.Equal(exposed, []string{"ReauthorizeScalarDependency", "Resolve"}) {
		t.Fatalf("*Resolver methods = %v, want exactly [ReauthorizeScalarDependency Resolve]", exposed)
	}
	if reflect.TypeOf(ResolveRequest{}).NumMethod() != 0 {
		t.Fatal("ResolveRequest observes a method")
	}
	if reflect.TypeOf(resolutionPlan{}).Comparable() {
		t.Fatal("resolutionPlan must not be Go-comparable: the retained profile carries slices, so exact-zero checks use reflect.DeepEqual")
	}
}

// astFieldInventory returns the declared name and resolved type of every struct
// field, parameter or result in declaration order.
func astFieldInventory(list *ast.FieldList) [][2]string {
	fields := [][2]string{}
	if list == nil {
		return fields
	}
	for _, field := range list.List {
		name := ""
		if len(field.Names) == 1 {
			name = field.Names[0].Name
		}
		fields = append(fields, [2]string{name, astResolvedTypeName(field.Type)})
	}
	return fields
}

// astResolvedTypeName renders one declared type expression with its pointer
// indirection, which the concrete store field needs.
func astResolvedTypeName(expression ast.Expr) string {
	if pointer, ok := expression.(*ast.StarExpr); ok {
		return "*" + astResolvedTypeName(pointer.X)
	}
	return astTypeName(expression)
}

// resolverRetention returns the field/identifier pairs of one composite
// literal, so retention of anything but the accepted parameters is visible.
func resolverRetention(literal *ast.CompositeLit) [][2]string {
	retained := make([][2]string, 0, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return nil
		}
		key, keyOK := pair.Key.(*ast.Ident)
		value, valueOK := pair.Value.(*ast.Ident)
		if !keyOK || !valueOK {
			return nil
		}
		retained = append(retained, [2]string{key.Name, value.Name})
	}
	return retained
}

// resolveStep is one call the Resolve body performs as the whole right-hand
// side of a short variable declaration, with the identifiers that declaration
// binds.
type resolveStep struct {
	callee string
	names  []string
	call   *ast.CallExpr
}

// assertResolveBody pins the fail-closed body of Resolve: the plan runs before
// every repository read, the candidate the authority lookup returns is passed
// to the authority resolver unchanged, the governed exposure read uses the
// planned lookup, the binding is bound exactly once from the accepted request,
// the authority result and the exposure result, and every failure — and only a
// failure — returns the exact zero Resolution and the exact errMismatch.
func assertResolveBody(t *testing.T, body *ast.BlockStmt) {
	t.Helper()
	wantSteps := []struct {
		callee string
		names  [2]string
		args   []string
	}{
		{"resolver.plan", [2]string{"plan", "err"}, []string{"request"}},
		{"resolver.store.ResolvePostgreSQLAuthorityRequest", [2]string{"candidate", "err"},
			[]string{"ctx", "access", "plan.authority"}},
		{"resolver.store.ResolvePostgreSQLAuthority", [2]string{"authority", "err"},
			[]string{"ctx", "access", "candidate"}},
		{"resolver.store.ResolveGovernedExposure", [2]string{"exposure", "err"},
			[]string{"ctx", "access", "plan.exposure"}},
		{"bindRepositoryResults", [2]string{"binding", "err"}, nil},
	}
	if len(body.List) != 2*len(wantSteps)+1 {
		t.Fatalf("Resolve holds %d statements, want one guarded call per step plus the final return", len(body.List))
	}
	steps := make([]resolveStep, 0, len(wantSteps))
	for index, want := range wantSteps {
		step, ok := astCallAssignment(body.List[index*2])
		if !ok {
			t.Fatalf("Resolve step %d is not one call bound to two identifiers", index)
		}
		if step.callee != want.callee {
			t.Fatalf("Resolve step %d calls %s, want %s", index, step.callee, want.callee)
		}
		if !slices.Equal(step.names, want.names[:]) {
			t.Fatalf("Resolve step %d binds %v, want %v", index, step.names, want.names)
		}
		if want.args != nil {
			args, ok := astCallArguments(step.call)
			if !ok || !slices.Equal(args, want.args) {
				t.Fatalf("Resolve step %d passes %v, want %v", index, args, want.args)
			}
		}
		assertFailureGuard(t, index, body.List[index*2+1])
		steps = append(steps, step)
	}

	// The binding is bound exactly once, from the expectation, the retained
	// catalog, and the two results this body itself resolved.
	binding := steps[len(steps)-1]
	if len(binding.call.Args) != 4 {
		t.Fatalf("bindRepositoryResults takes %d arguments, want the expectation, catalog, authority result and exposure result",
			len(binding.call.Args))
	}
	for index, want := range []string{"resolver.catalog", "authority", "exposure"} {
		text, ok := astExpressionText(binding.call.Args[index+1])
		if !ok || text != want {
			t.Fatalf("bindRepositoryResults argument %d = %q, want %s", index+1, text, want)
		}
	}
	expectation, ok := binding.call.Args[0].(*ast.CompositeLit)
	if !ok || astTypeName(expectation.Type) != "repositoryBindingExpectation" {
		t.Fatal("bindRepositoryResults must receive one repositoryBindingExpectation literal")
	}
	wantExpectation := [][2]string{
		{"workspaceID", "request.WorkspaceID"},
		{"workspaceRevision", "authority.WorkspaceRevision()"},
		{"workspaceConfigurationHash", "authority.WorkspaceConfigurationHash()"},
		{"catalogID", "request.CatalogID"},
		{"catalogRevision", "request.CatalogRevision"},
		{"catalogHash", "request.CatalogHash"},
		{"profileKey", "request.ProfileKey"},
		{"profileHash", "request.ProfileHash"},
	}
	gotExpectation := make([][2]string, 0, len(expectation.Elts))
	for _, element := range expectation.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("the binding expectation holds a positional element")
		}
		key, keyOK := pair.Key.(*ast.Ident)
		value, valueOK := astExpressionText(pair.Value)
		if !keyOK || !valueOK {
			t.Fatalf("the binding expectation holds one unsupported member %v", element)
		}
		gotExpectation = append(gotExpectation, [2]string{key.Name, value})
	}
	if !slices.Equal(gotExpectation, wantExpectation) {
		t.Fatalf("binding expectation = %v, want %v", gotExpectation, wantExpectation)
	}

	final, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(final.Results) != 2 {
		t.Fatal("Resolve must end with one two-result return")
	}
	sealed, ok := final.Results[0].(*ast.CompositeLit)
	if !ok || astTypeName(sealed.Type) != "Resolution" {
		t.Fatalf("Resolve returns %v, want one Resolution literal", final.Results[0])
	}
	if retained := resolverRetention(sealed); !slices.Equal(retained, [][2]string{{"binding", "binding"}, {"authority", "authority"}}) {
		t.Fatalf("Resolve seals %v, want exactly the binding and authority it resolved", retained)
	}
	if accepted, ok := final.Results[1].(*ast.Ident); !ok || accepted.Name != "nil" {
		t.Fatalf("Resolve returns %v as its error, want nil", final.Results[1])
	}
}

// assertFailureGuard requires one statement to be exactly `if err != nil {
// return Resolution{}, errMismatch }`: no initializer, no else, no second
// branch, no wrapped or distinct error value.
func assertFailureGuard(t *testing.T, step int, statement ast.Stmt) {
	t.Helper()
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil {
		t.Fatalf("Resolve step %d is not one plain failure guard", step)
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ {
		t.Fatalf("Resolve step %d guard condition is not a != comparison", step)
	}
	left, leftOK := condition.X.(*ast.Ident)
	right, rightOK := condition.Y.(*ast.Ident)
	if !leftOK || !rightOK || left.Name != "err" || right.Name != "nil" {
		t.Fatalf("Resolve step %d guard does not compare err with nil", step)
	}
	if len(guard.Body.List) != 1 {
		t.Fatalf("Resolve step %d guard holds %d statements, want exactly one refusal return",
			step, len(guard.Body.List))
	}
	returned, ok := guard.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 2 {
		t.Fatalf("Resolve step %d guard must return one zero resolution and one error", step)
	}
	zero, ok := returned.Results[0].(*ast.CompositeLit)
	if !ok || astTypeName(zero.Type) != "Resolution" || len(zero.Elts) != 0 {
		t.Fatalf("Resolve step %d returns %v, want the exact zero Resolution{}", step, returned.Results[0])
	}
	refusal, ok := returned.Results[1].(*ast.Ident)
	if !ok || refusal.Name != "errMismatch" {
		t.Fatalf("Resolve step %d returns %v, want the exact errMismatch", step, returned.Results[1])
	}
}

// astCallAssignment returns the one call a statement performs as the whole
// right-hand side of a short variable declaration, with the identifiers that
// declaration binds.
func astCallAssignment(statement ast.Stmt) (resolveStep, bool) {
	assigned, ok := statement.(*ast.AssignStmt)
	if !ok || assigned.Tok != token.DEFINE || len(assigned.Rhs) != 1 {
		return resolveStep{}, false
	}
	call, ok := assigned.Rhs[0].(*ast.CallExpr)
	if !ok {
		return resolveStep{}, false
	}
	callee, ok := astExpressionText(call.Fun)
	if !ok {
		return resolveStep{}, false
	}
	names := make([]string, 0, len(assigned.Lhs))
	for _, target := range assigned.Lhs {
		identifier, ok := target.(*ast.Ident)
		if !ok {
			return resolveStep{}, false
		}
		names = append(names, identifier.Name)
	}
	return resolveStep{callee: callee, names: names, call: call}, true
}

// astCallArguments renders every call argument as text, so an argument the
// resolver body changed is visible in the expectation comparison.
func astCallArguments(call *ast.CallExpr) ([]string, bool) {
	args := make([]string, 0, len(call.Args))
	for _, argument := range call.Args {
		text, ok := astExpressionText(argument)
		if !ok {
			return nil, false
		}
		args = append(args, text)
	}
	return args, true
}

// astExpressionText renders the identifier, selector and no-argument call forms
// the resolver body is allowed to use.
func astExpressionText(expression ast.Expr) (string, bool) {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name, true
	case *ast.SelectorExpr:
		owner, ok := astExpressionText(typed.X)
		if !ok {
			return "", false
		}
		return owner + "." + typed.Sel.Name, true
	case *ast.CallExpr:
		callee, ok := astExpressionText(typed.Fun)
		if !ok || len(typed.Args) != 0 {
			return "", false
		}
		return callee + "()", true
	default:
		return "", false
	}
}
