package analyticsource

import (
	"context"
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

// scalarDependencyReauthorizationRunID is the exact safe Question Run id the
// dependency fixture is bound to, so the current caller can name it freshly.
const scalarDependencyReauthorizationRunID = "run_scalar_01"

// scalarDependencyReauthorizationFixture pairs one dependency built from the
// controlled 407-row live observation with the current caller, the mounted
// catalog and the fresh resolution binding that reproduce every retained fact.
// The store owns no database: any repository read reaches a nil database and
// refuses instead of silently succeeding, which is the no-I/O boundary the
// local refusal tests rely on.
type scalarDependencyReauthorizationFixture struct {
	resolver       *Resolver
	catalog        analytic.DatasetProfileCatalog
	profile        analytic.DatasetProfile
	binding        eligibilityBinding
	dependency     ScalarDependency
	access         database.AccessContext
	originalAccess database.AccessContext
	workspaceID    string
	runID          string
}

// scalarDependencyReauthorizationFixtureFor builds the exact fixture the
// acceptance tests share: it completes the controlled live read, binds its
// observation to the fixed Question Run id, and pairs the fresh binding with
// the mounted catalog and a current caller whose principal and request
// deliberately differ from the original receipt.
func scalarDependencyReauthorizationFixtureFor(t *testing.T) scalarDependencyReauthorizationFixture {
	t.Helper()
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	dependency, err := BindScalarDependency(scalarDependencyReauthorizationRunID, observation)
	if err != nil {
		t.Fatalf("fixture dependency refused: %v", err)
	}
	binding := read.context.binding
	catalog := scalarPlanCatalog(t, binding.profile)
	resolver, err := NewResolver(new(repository.Store), catalog)
	if err != nil {
		t.Fatalf("fixture resolver refused: %v", err)
	}
	return scalarDependencyReauthorizationFixture{
		resolver:   resolver,
		catalog:    catalog,
		profile:    binding.profile,
		binding:    binding,
		dependency: dependency,
		access: database.AccessContext{
			OrganizationID: dependency.payload.OrganizationID,
			PrincipalID:    "current_principal",
			RequestID:      "current_request",
		},
		originalAccess: read.context.access,
		workspaceID:    dependency.payload.WorkspaceID,
		runID:          scalarDependencyReauthorizationRunID,
	}
}

// assertReauthorizeScalarDependencyRefusal requires one refusal to be the exact
// unwrapped, content-free errMismatch.
func assertReauthorizeScalarDependencyRefusal(t *testing.T, err error) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refusal returned %v, want errMismatch", err)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("refusal wraps %v, want the exact unwrapped errMismatch", unwrapped)
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
}

// scalarDependencyReauthorizationDisclosures lists every dependency and caller
// value the fixture hands the production code; no refusal may disclose one.
func scalarDependencyReauthorizationDisclosures(fixture scalarDependencyReauthorizationFixture) []string {
	payload := fixture.dependency.payload
	values := []string{
		payload.Schema, payload.Kind, payload.ReceiptSchema, payload.ReceiptDigest, payload.QuestionRunID,
		payload.OrganizationID,
		payload.WorkspaceID, strconv.FormatInt(payload.WorkspaceRevision, 10),
		payload.WorkspaceConfigurationHash, payload.WorkspaceSourceID,
		payload.CatalogID, strconv.FormatInt(payload.CatalogRevision, 10), payload.CatalogHash,
		payload.DatasetID, strconv.FormatInt(payload.ProfileVersion, 10), payload.ProfileHash,
		payload.SourceScopeID, strconv.FormatInt(payload.SourceScopeRevision, 10),
		payload.SourceScopeConfigurationHash,
		payload.ConnectionID, strconv.FormatInt(payload.ConnectionRevision, 10), payload.DatabaseIdentity,
		payload.ProjectionLineageID, strconv.FormatInt(payload.ProjectionRevision, 10),
		payload.ProjectionContractHash,
		strconv.FormatInt(payload.ExposedSchemaRevision, 10), payload.ExposedSchemaHash,
		fixture.workspaceID, fixture.runID,
		fixture.access.OrganizationID, fixture.access.PrincipalID, fixture.access.RequestID,
		alternateIdentity, alternateIdentifier, validHash("9"),
	}
	return append(values, fixtureDisclosures(fixture.profile)...)
}

// TestReauthorizeScalarDependencyPreparesExactRequestAndMatchesExactResolution
// proves the pure accepted path: the exact current access, workspace, run and
// dependency prepare exactly the derived request, and one exact trusted fresh
// Resolution matches every retained neutral authority fact.
func TestReauthorizeScalarDependencyPreparesExactRequestAndMatchesExactResolution(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	if err := fixture.access.Validate(); err != nil {
		t.Fatalf("fixture current access is not valid: %v", err)
	}
	request, err := fixture.resolver.prepareScalarDependencyReauthorization(
		fixture.access, fixture.workspaceID, fixture.runID, fixture.dependency)
	if err != nil {
		t.Fatalf("the exact current authority was refused: %v", err)
	}
	key, err := analytic.NewProfileKey(
		fixture.dependency.payload.DatasetID, fixture.dependency.payload.ProfileVersion)
	if err != nil {
		t.Fatalf("the dependency profile key was refused: %v", err)
	}
	want := ResolveRequest{
		WorkspaceID:     fixture.dependency.payload.WorkspaceID,
		CatalogID:       fixture.dependency.payload.CatalogID,
		CatalogRevision: fixture.dependency.payload.CatalogRevision,
		CatalogHash:     fixture.dependency.payload.CatalogHash,
		ProfileKey:      key,
		ProfileHash:     fixture.dependency.payload.ProfileHash,
	}
	if !reflect.DeepEqual(request, want) {
		t.Fatalf("prepared request = %+v, want the exact dependency-derived %+v", request, want)
	}
	if !fixture.binding.valid() {
		t.Fatal("the fresh fixture binding is not valid")
	}
	if !scalarDependencyResolutionMatches(
		fixture.dependency.payload, fixture.catalog, Resolution{binding: fixture.binding}) {
		t.Fatal("the exact trusted fresh resolution was refused")
	}
}

// TestReauthorizeScalarDependencyUsesCurrentCallerNotOriginalReceipt proves the
// current principal and request may differ from the original receipt and still
// succeed when current authority permits it: the dependency carries no
// principal or request, so only the current caller is ever consulted.
func TestReauthorizeScalarDependencyUsesCurrentCallerNotOriginalReceipt(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	if fixture.originalAccess.PrincipalID == fixture.access.PrincipalID ||
		fixture.originalAccess.RequestID == fixture.access.RequestID {
		t.Fatal("the fixture current caller must differ from the original receipt caller")
	}
	if _, err := fixture.resolver.prepareScalarDependencyReauthorization(
		fixture.access, fixture.workspaceID, fixture.runID, fixture.dependency); err != nil {
		t.Fatalf("a different current caller was refused: %v", err)
	}
	if !scalarDependencyResolutionMatches(
		fixture.dependency.payload, fixture.catalog, Resolution{binding: fixture.binding}) {
		t.Fatal("a different current caller did not match the exact fresh resolution")
	}
}

// TestReauthorizeScalarDependencyRefusesLocallyBeforeRepositoryIO proves every
// locally knowable refusal — nil or zero resolver, an invalid context or
// access, a malformed workspace or run id, a zero or tampered dependency, and
// every exact-mismatch — returns errMismatch before any repository call. The
// store owns no database, yet the preparation helper refuses each one itself.
func TestReauthorizeScalarDependencyRefusesLocallyBeforeRepositoryIO(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	valid := fixture.access
	wrongOrganization := valid
	wrongOrganization.OrganizationID = alternateIdentity
	invalid := valid
	invalid.RequestID = " " + valid.RequestID
	if invalid.Validate() == nil {
		t.Fatal("the padded access context is valid, want an invalid one")
	}
	tampered := fixture.dependency
	tampered.payload.Kind = "OTHER"
	tamperedWorkspace := fixture.dependency
	tamperedWorkspace.payload.WorkspaceID = alternateIdentity

	cases := []struct {
		name        string
		resolver    *Resolver
		access      database.AccessContext
		workspaceID string
		runID       string
		dependency  ScalarDependency
	}{
		{"nil resolver", nil, valid, fixture.workspaceID, fixture.runID, fixture.dependency},
		{"zero resolver", &Resolver{}, valid, fixture.workspaceID, fixture.runID, fixture.dependency},
		{"zero access", fixture.resolver, database.AccessContext{}, fixture.workspaceID, fixture.runID, fixture.dependency},
		{"invalid access", fixture.resolver, invalid, fixture.workspaceID, fixture.runID, fixture.dependency},
		{"wrong organization", fixture.resolver, wrongOrganization, fixture.workspaceID, fixture.runID, fixture.dependency},
		{"wrong workspace", fixture.resolver, valid, alternateIdentity, fixture.runID, fixture.dependency},
		{"wrong run", fixture.resolver, valid, fixture.workspaceID, "other_run", fixture.dependency},
		{"zero dependency", fixture.resolver, valid, fixture.workspaceID, fixture.runID, ScalarDependency{}},
		{"tampered dependency kind", fixture.resolver, valid, fixture.workspaceID, fixture.runID, tampered},
		{"tampered dependency workspace", fixture.resolver, valid, fixture.workspaceID, fixture.runID, tamperedWorkspace},
	}
	for _, malformed := range []string{"", fixture.workspaceID + " ", fixture.workspaceID + "\x00",
		strings.Repeat("w", 257)} {
		cases = append(cases, struct {
			name        string
			resolver    *Resolver
			access      database.AccessContext
			workspaceID string
			runID       string
			dependency  ScalarDependency
		}{"malformed workspace", fixture.resolver, valid, malformed, fixture.runID, fixture.dependency})
	}
	for _, malformed := range []string{"", fixture.runID + " ", fixture.runID + "\x00",
		strings.Repeat("r", 257)} {
		cases = append(cases, struct {
			name        string
			resolver    *Resolver
			access      database.AccessContext
			workspaceID string
			runID       string
			dependency  ScalarDependency
		}{"malformed run", fixture.resolver, valid, fixture.workspaceID, malformed, fixture.dependency})
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request, err := test.resolver.prepareScalarDependencyReauthorization(
				test.access, test.workspaceID, test.runID, test.dependency)
			assertReauthorizeScalarDependencyRefusal(t, err)
			if request != (ResolveRequest{}) {
				t.Fatalf("refused preparation returned %+v, want the exact zero request", request)
			}
			assertReauthorizeScalarDependencyRefusal(t, test.resolver.ReauthorizeScalarDependency(
				context.Background(), test.access, test.workspaceID, test.runID, test.dependency))
		})
	}
}

// TestReauthorizeScalarDependencyMapsConcreteResolverRefusalToMismatch proves
// one exact current-authority call reaches the concrete resolver exactly once
// and maps its real repository refusal to the same content-free errMismatch.
// The fixture store owns no database, so the concrete read refuses at its own
// admission guard without a mock or a production seam.
func TestReauthorizeScalarDependencyMapsConcreteResolverRefusalToMismatch(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	if _, err := fixture.resolver.prepareScalarDependencyReauthorization(
		fixture.access, fixture.workspaceID, fixture.runID, fixture.dependency); err != nil {
		t.Fatalf("the exact current authority did not prepare before the repository: %v", err)
	}
	err := fixture.resolver.ReauthorizeScalarDependency(
		context.Background(), fixture.access, fixture.workspaceID, fixture.runID, fixture.dependency)
	assertReauthorizeScalarDependencyRefusal(t, err)
}

// TestReauthorizeScalarDependencyRefusesNilContextBeforeResolve proves a nil
// context is refused with the exact unwrapped errMismatch, and that the refusal
// is the first statement of the public body, ahead of the one concrete
// resolver.Resolve call and every repository read it would reach.
func TestReauthorizeScalarDependencyRefusesNilContextBeforeResolve(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	assertReauthorizeScalarDependencyRefusal(t, fixture.resolver.ReauthorizeScalarDependency(
		nil, fixture.access, fixture.workspaceID, fixture.runID, fixture.dependency))

	const filename = "scalar_dependency_authorization.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var body *ast.BlockStmt
	for _, declaration := range parsed.Decls {
		method, ok := declaration.(*ast.FuncDecl)
		if !ok || method.Recv == nil || method.Name.Name != "ReauthorizeScalarDependency" {
			continue
		}
		body = method.Body
	}
	if body == nil || len(body.List) == 0 {
		t.Fatal("ReauthorizeScalarDependency holds no body to inspect")
	}
	assertReauthorizeScalarDependencyNilContextGuard(t, body.List[0])
	resolveIndex := -1
	for index, statement := range body.List {
		if step, ok := astCallAssignment(statement); ok && step.callee == "resolver.Resolve" {
			resolveIndex = index
			break
		}
	}
	if resolveIndex <= 0 {
		t.Fatalf("the nil context guard at statement 0 does not precede resolver.Resolve at statement %d", resolveIndex)
	}
}

// TestReauthorizeScalarDependencyResolutionMatchesRefusesEveryRetainedFactDrift
// drifts every neutral authority fact the dependency retained, one member at a
// time, and requires the pure comparison to refuse each one. Every mutated
// payload stays valid, so the refusal genuinely rests on the comparison and not
// on malformed input.
func TestReauthorizeScalarDependencyResolutionMatchesRefusesEveryRetainedFactDrift(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	resolution := Resolution{binding: fixture.binding}
	drifts := []struct {
		name   string
		mutate func(*scalarDependencyPayload)
	}{
		{"catalog id", func(payload *scalarDependencyPayload) { payload.CatalogID = alternateIdentity }},
		{"catalog revision", func(payload *scalarDependencyPayload) { payload.CatalogRevision++ }},
		{"catalog hash", func(payload *scalarDependencyPayload) { payload.CatalogHash = validHash("9") }},
		{"workspace id", func(payload *scalarDependencyPayload) { payload.WorkspaceID = alternateIdentity }},
		{"workspace revision", func(payload *scalarDependencyPayload) { payload.WorkspaceRevision++ }},
		{"workspace configuration hash", func(payload *scalarDependencyPayload) {
			payload.WorkspaceConfigurationHash = validHash("9")
		}},
		{"workspace source id", func(payload *scalarDependencyPayload) { payload.WorkspaceSourceID = alternateIdentity }},
		{"dataset id", func(payload *scalarDependencyPayload) { payload.DatasetID = alternateIdentity }},
		{"profile version", func(payload *scalarDependencyPayload) { payload.ProfileVersion++ }},
		{"profile hash", func(payload *scalarDependencyPayload) { payload.ProfileHash = validHash("9") }},
		{"source scope id", func(payload *scalarDependencyPayload) { payload.SourceScopeID = alternateIdentity }},
		{"source scope revision", func(payload *scalarDependencyPayload) { payload.SourceScopeRevision++ }},
		{"source scope configuration hash", func(payload *scalarDependencyPayload) {
			payload.SourceScopeConfigurationHash = validHash("9")
		}},
		{"connection id", func(payload *scalarDependencyPayload) { payload.ConnectionID = alternateIdentity }},
		{"connection revision", func(payload *scalarDependencyPayload) { payload.ConnectionRevision++ }},
		{"database identity", func(payload *scalarDependencyPayload) { payload.DatabaseIdentity = alternateIdentity }},
		{"projection lineage", func(payload *scalarDependencyPayload) { payload.ProjectionLineageID = alternateIdentity }},
		{"projection revision", func(payload *scalarDependencyPayload) { payload.ProjectionRevision++ }},
		{"projection contract hash", func(payload *scalarDependencyPayload) {
			payload.ProjectionContractHash = validHash("9")
		}},
		{"exposed schema revision", func(payload *scalarDependencyPayload) { payload.ExposedSchemaRevision++ }},
		{"exposed schema hash", func(payload *scalarDependencyPayload) { payload.ExposedSchemaHash = validHash("9") }},
	}
	if len(drifts) != 21 {
		t.Fatalf("the retained drift table carries %d members, want all 21 retained authority facts", len(drifts))
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			payload := fixture.dependency.payload
			drift.mutate(&payload)
			if !payload.valid() {
				t.Fatal("the drifted payload is invalid, so the refusal would not prove the comparison")
			}
			if scalarDependencyResolutionMatches(payload, fixture.catalog, resolution) {
				t.Fatalf("drifted retained %s was accepted", drift.name)
			}
		})
	}

	t.Run("zero dependency", func(t *testing.T) {
		if scalarDependencyResolutionMatches(scalarDependencyPayload{}, fixture.catalog, resolution) {
			t.Fatal("the zero dependency was accepted")
		}
	})
	t.Run("zero mounted catalog", func(t *testing.T) {
		if scalarDependencyResolutionMatches(fixture.dependency.payload, analytic.DatasetProfileCatalog{}, resolution) {
			t.Fatal("the zero mounted catalog was accepted")
		}
	})
	t.Run("zero resolution", func(t *testing.T) {
		if scalarDependencyResolutionMatches(fixture.dependency.payload, fixture.catalog, Resolution{}) {
			t.Fatal("the zero fresh resolution was accepted")
		}
	})
}

// TestReauthorizeScalarDependencyResolutionMatchesRefusesFreshResolutionDrift
// proves fresh drift and revocation refuse in the pure comparison: a resealed
// but drifted workspace, a valid resolution under alternate profile semantics,
// and a broken seal each refuse without disclosing which fact failed. The real
// PostgreSQL revocation round trip stays with the later activation card.
func TestReauthorizeScalarDependencyResolutionMatchesRefusesFreshResolutionDrift(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)

	t.Run("valid resealed workspace drift", func(t *testing.T) {
		drifts := []struct {
			name   string
			mutate func(*eligibilityBinding)
		}{
			{"workspace id", func(fresh *eligibilityBinding) { fresh.binding.workspaceID = alternateIdentity }},
			{"workspace revision", func(fresh *eligibilityBinding) {
				fresh.binding.workspaceRevision = alternateRevision
			}},
			{"workspace configuration hash", func(fresh *eligibilityBinding) {
				fresh.binding.workspaceConfigurationHash = validHash("9")
			}},
			{"workspace source id", func(fresh *eligibilityBinding) {
				fresh.binding.workspaceSourceID = alternateIdentity
			}},
		}
		for _, drift := range drifts {
			t.Run(drift.name, func(t *testing.T) {
				fresh := fixture.binding
				drift.mutate(&fresh)
				fresh.seal = eligibilityBindingSeal(fresh.profile, fresh.binding, fresh.execution)
				if !fresh.valid() {
					t.Fatal("the drifted fresh binding is not valid, so comparison would not be what refuses it")
				}
				if scalarDependencyResolutionMatches(
					fixture.dependency.payload, fixture.catalog, Resolution{binding: fresh}) {
					t.Fatalf("fresh %s drift was accepted", drift.name)
				}
			})
		}
	})

	t.Run("alternate valid profile semantics", func(t *testing.T) {
		columns, err := requiredColumns(fixture.profile)
		if err != nil {
			t.Fatalf("fixture inventory refused: %v", err)
		}
		facts := governedMatchFixture(t, fixture.profile, columns)
		alternate := alternateFixtureProfile(t, fixture.profile)
		fresh, err := newEligibilityBinding(alternate, facts.source, facts.exposure)
		if err != nil {
			t.Fatalf("the alternate profile binding was refused: %v", err)
		}
		if !fresh.valid() {
			t.Fatal("the alternate profile binding is not valid")
		}
		if fresh.profile.Hash() == fixture.binding.profile.Hash() {
			t.Fatal("the alternate profile carries the same hash")
		}
		if scalarDependencyResolutionMatches(
			fixture.dependency.payload, fixture.catalog, Resolution{binding: fresh}) {
			t.Fatal("a fresh resolution under alternate profile semantics was accepted")
		}
	})

	t.Run("broken seal", func(t *testing.T) {
		fresh := fixture.binding
		fresh.seal[0] ^= 0xff
		if scalarDependencyResolutionMatches(
			fixture.dependency.payload, fixture.catalog, Resolution{binding: fresh}) {
			t.Fatal("a fresh resolution with a broken seal was accepted")
		}
	})
}

// TestReauthorizeScalarDependencyRefusalsDiscloseNothing proves every refusal
// path returns the exact content-free errMismatch and reveals none of the
// dependency, caller, workspace, run or profile facts.
func TestReauthorizeScalarDependencyRefusalsDiscloseNothing(t *testing.T) {
	fixture := scalarDependencyReauthorizationFixtureFor(t)
	valid := fixture.access
	wrongOrganization := valid
	wrongOrganization.OrganizationID = alternateIdentity
	invalid := valid
	invalid.RequestID = " " + valid.RequestID
	tampered := fixture.dependency
	tampered.payload.Kind = "OTHER"

	refusals := map[string]error{
		"nil resolver": func() error {
			var resolver *Resolver
			return resolver.ReauthorizeScalarDependency(
				context.Background(), valid, fixture.workspaceID, fixture.runID, fixture.dependency)
		}(),
		"zero resolver": (&Resolver{}).ReauthorizeScalarDependency(
			context.Background(), valid, fixture.workspaceID, fixture.runID, fixture.dependency),
		"invalid access": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), invalid, fixture.workspaceID, fixture.runID, fixture.dependency),
		"wrong organization": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), wrongOrganization, fixture.workspaceID, fixture.runID, fixture.dependency),
		"wrong workspace": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), valid, alternateIdentity, fixture.runID, fixture.dependency),
		"wrong run": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), valid, fixture.workspaceID, "other_run", fixture.dependency),
		"zero dependency": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), valid, fixture.workspaceID, fixture.runID, ScalarDependency{}),
		"tampered dependency": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), valid, fixture.workspaceID, fixture.runID, tampered),
		"concrete resolver refusal": fixture.resolver.ReauthorizeScalarDependency(
			context.Background(), valid, fixture.workspaceID, fixture.runID, fixture.dependency),
	}
	disclosures := scalarDependencyReauthorizationDisclosures(fixture)
	for name, err := range refusals {
		t.Run(name, func(t *testing.T) {
			assertReauthorizeScalarDependencyRefusal(t, err)
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

// TestReauthorizeScalarDependencyProductionSurface proves, by AST and by
// reflection, that the new production file exposes exactly the one public
// method over *Resolver, derives its request only from the private dependency
// payload, calls the concrete resolver.Resolve exactly once, routes that result
// into the pure comparison, and holds no loop, store call or type seam.
func TestReauthorizeScalarDependencyProductionSurface(t *testing.T) {
	const filename = "scalar_dependency_authorization.go"
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

	allowedImports := map[string]bool{
		"context": true,
		"knowvault.local/verified-workspace/internal/analytic":          true,
		"knowvault.local/verified-workspace/internal/platform/database": true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the reauthorization: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	functions := map[string]*ast.FuncDecl{}
	methods := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			t.Fatalf("the reauthorization declares package-level state at %s", files.Position(typed.Pos()))
		case *ast.FuncDecl:
			if typed.Recv == nil {
				functions[typed.Name.Name] = typed
				continue
			}
			methods[typed.Name.Name] = typed
		}
	}
	declaredFunctions := make([]string, 0, len(functions))
	for name := range functions {
		declaredFunctions = append(declaredFunctions, name)
	}
	slices.Sort(declaredFunctions)
	if !slices.Equal(declaredFunctions, []string{"scalarDependencyResolutionMatches"}) {
		t.Fatalf("declared functions = %v, want exactly [scalarDependencyResolutionMatches]", declaredFunctions)
	}
	declaredMethods := make([]string, 0, len(methods))
	for name := range methods {
		declaredMethods = append(declaredMethods, name)
	}
	slices.Sort(declaredMethods)
	wantMethods := []string{"ReauthorizeScalarDependency", "prepareScalarDependencyReauthorization"}
	if !slices.Equal(declaredMethods, wantMethods) {
		t.Fatalf("declared methods = %v, want %v", declaredMethods, wantMethods)
	}

	public := methods["ReauthorizeScalarDependency"]
	if receiver := astFieldInventory(public.Recv); !slices.Equal(receiver, [][2]string{{"resolver", "*Resolver"}}) {
		t.Fatalf("ReauthorizeScalarDependency receiver = %v, want one *Resolver", receiver)
	}
	wantParameters := [][2]string{
		{"ctx", "context.Context"}, {"currentAccess", "database.AccessContext"},
		{"workspaceID", "string"}, {"questionRunID", "string"}, {"dependency", "ScalarDependency"},
	}
	if parameters := astFieldInventory(public.Type.Params); !slices.Equal(parameters, wantParameters) {
		t.Fatalf("ReauthorizeScalarDependency parameters = %v, want %v", parameters, wantParameters)
	}
	wantResults := [][2]string{{"", "error"}}
	if results := astFieldInventory(public.Type.Results); !slices.Equal(results, wantResults) {
		t.Fatalf("ReauthorizeScalarDependency results = %v, want %v", results, wantResults)
	}
	assertReauthorizeScalarDependencyBody(t, public.Body)
	assertReauthorizeScalarDependencyPreparationBody(t, methods["prepareScalarDependencyReauthorization"].Body)
}

// assertReauthorizeScalarDependencyBody pins the fail-closed public body: the
// nil context guard first, then one preparation, exactly one concrete
// resolver.Resolve call, exactly one pure comparison that receives that fresh
// resolution, no loop, no direct store call, and errMismatch on every refusal.
func assertReauthorizeScalarDependencyBody(t *testing.T, body *ast.BlockStmt) {
	t.Helper()
	if len(body.List) != 7 {
		t.Fatalf("ReauthorizeScalarDependency holds %d statements, want the nil context guard, the two guarded steps, the comparison guard and the final return",
			len(body.List))
	}
	// The nil context guard is statement 0, so it runs before the preparation
	// call and the one concrete resolver.Resolve call that follow it.
	assertReauthorizeScalarDependencyNilContextGuard(t, body.List[0])
	steps := []struct {
		callee string
		names  []string
		args   []string
	}{
		{"resolver.prepareScalarDependencyReauthorization", []string{"request", "err"},
			[]string{"currentAccess", "workspaceID", "questionRunID", "dependency"}},
		{"resolver.Resolve", []string{"resolution", "err"}, []string{"ctx", "currentAccess", "request"}},
	}
	for index, want := range steps {
		step, ok := astCallAssignment(body.List[1+index*2])
		if !ok {
			t.Fatalf("step %d is not one call bound to two identifiers", index)
		}
		if step.callee != want.callee {
			t.Fatalf("step %d calls %s, want %s", index, step.callee, want.callee)
		}
		if !slices.Equal(step.names, want.names) {
			t.Fatalf("step %d binds %v, want %v", index, step.names, want.names)
		}
		args, ok := astCallArguments(step.call)
		if !ok || !slices.Equal(args, want.args) {
			t.Fatalf("step %d passes %v, want %v", index, args, want.args)
		}
		assertReauthorizeScalarDependencyFailureGuard(t, body.List[1+index*2+1])
	}

	comparison, ok := body.List[5].(*ast.IfStmt)
	if !ok || comparison.Init != nil || comparison.Else != nil {
		t.Fatal("the comparison is not one plain fail-closed guard")
	}
	negated, ok := comparison.Cond.(*ast.UnaryExpr)
	if !ok || negated.Op != token.NOT {
		t.Fatal("the comparison guard is not a negated predicate")
	}
	call, ok := negated.X.(*ast.CallExpr)
	if !ok {
		t.Fatal("the comparison guard does not call a predicate")
	}
	if callee, ok := astExpressionText(call.Fun); !ok || callee != "scalarDependencyResolutionMatches" {
		t.Fatalf("the comparison calls %q, want scalarDependencyResolutionMatches", callee)
	}
	args, ok := astCallArguments(call)
	if !ok || !slices.Equal(args, []string{"dependency.payload", "resolver.catalog", "resolution"}) {
		t.Fatalf("the comparison receives %v, want the dependency payload, mounted catalog and fresh resolution", args)
	}
	if len(comparison.Body.List) != 1 {
		t.Fatalf("the comparison guard holds %d statements, want exactly one refusal return", len(comparison.Body.List))
	}
	assertReauthorizeScalarDependencyRefusalReturn(t, comparison.Body.List[0])

	final, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(final.Results) != 1 {
		t.Fatal("ReauthorizeScalarDependency must end with one single-result return")
	}
	if accepted, ok := final.Results[0].(*ast.Ident); !ok || accepted.Name != "nil" {
		t.Fatalf("ReauthorizeScalarDependency returns %v as its error, want nil", final.Results[0])
	}

	resolveCalls, comparisonCalls, storeCalls, loops := 0, 0, 0, 0
	ast.Inspect(body, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			loops++
		case *ast.CallExpr:
			callee, ok := astExpressionText(typed.Fun)
			if !ok {
				return true
			}
			switch {
			case callee == "resolver.Resolve":
				resolveCalls++
			case callee == "scalarDependencyResolutionMatches":
				comparisonCalls++
			case strings.HasPrefix(callee, "resolver.store."):
				storeCalls++
			}
		}
		return true
	})
	if loops != 0 {
		t.Fatal("ReauthorizeScalarDependency holds a loop: no retry or source read is allowed")
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver.Resolve is called %d times, want exactly once", resolveCalls)
	}
	if comparisonCalls != 1 {
		t.Fatalf("the pure comparison is called %d times, want exactly once", comparisonCalls)
	}
	if storeCalls != 0 {
		t.Fatalf("ReauthorizeScalarDependency calls the store directly %d times, want only the one resolver.Resolve", storeCalls)
	}
}

// assertReauthorizeScalarDependencyNilContextGuard requires one statement to be
// exactly `if ctx == nil { return errMismatch }`: the fail-closed first guard
// that refuses a nil context before preparation and any repository I/O or
// concrete Resolve.
func assertReauthorizeScalarDependencyNilContextGuard(t *testing.T, statement ast.Stmt) {
	t.Helper()
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil {
		t.Fatal("the nil context refusal is not one plain guard")
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.EQL {
		t.Fatal("the nil context guard condition is not an == comparison")
	}
	left, leftOK := condition.X.(*ast.Ident)
	right, rightOK := condition.Y.(*ast.Ident)
	if !leftOK || !rightOK || left.Name != "ctx" || right.Name != "nil" {
		t.Fatal("the nil context guard does not compare ctx with nil")
	}
	if len(guard.Body.List) != 1 {
		t.Fatalf("the nil context guard holds %d statements, want exactly one refusal return",
			len(guard.Body.List))
	}
	assertReauthorizeScalarDependencyRefusalReturn(t, guard.Body.List[0])
}

// assertReauthorizeScalarDependencyFailureGuard requires one statement to be
// exactly `if err != nil { return errMismatch }`.
func assertReauthorizeScalarDependencyFailureGuard(t *testing.T, statement ast.Stmt) {
	t.Helper()
	guard, ok := statement.(*ast.IfStmt)
	if !ok || guard.Init != nil || guard.Else != nil {
		t.Fatal("a call is not followed by one plain failure guard")
	}
	condition, ok := guard.Cond.(*ast.BinaryExpr)
	if !ok || condition.Op != token.NEQ {
		t.Fatal("the failure guard condition is not a != comparison")
	}
	left, leftOK := condition.X.(*ast.Ident)
	right, rightOK := condition.Y.(*ast.Ident)
	if !leftOK || !rightOK || left.Name != "err" || right.Name != "nil" {
		t.Fatal("the failure guard does not compare err with nil")
	}
	if len(guard.Body.List) != 1 {
		t.Fatalf("the failure guard holds %d statements, want exactly one refusal return", len(guard.Body.List))
	}
	assertReauthorizeScalarDependencyRefusalReturn(t, guard.Body.List[0])
}

// assertReauthorizeScalarDependencyRefusalReturn requires one statement to be
// exactly `return errMismatch`.
func assertReauthorizeScalarDependencyRefusalReturn(t *testing.T, statement ast.Stmt) {
	t.Helper()
	returned, ok := statement.(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		t.Fatal("a refusal must be one single-result return")
	}
	refusal, ok := returned.Results[0].(*ast.Ident)
	if !ok || refusal.Name != "errMismatch" {
		t.Fatalf("the refusal returns %v, want the exact errMismatch", returned.Results[0])
	}
}

// assertReauthorizeScalarDependencyPreparationBody proves the preparation
// derives its one ResolveRequest only from the private dependency payload: no
// caller-supplied source identity can enter the request.
func assertReauthorizeScalarDependencyPreparationBody(t *testing.T, body *ast.BlockStmt) {
	t.Helper()
	final, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(final.Results) != 2 {
		t.Fatal("the preparation must end with one request and one error")
	}
	literal, ok := final.Results[0].(*ast.CompositeLit)
	if !ok || astTypeName(literal.Type) != "ResolveRequest" {
		t.Fatalf("the preparation returns %v, want one ResolveRequest literal", final.Results[0])
	}
	want := [][2]string{
		{"WorkspaceID", "payload.WorkspaceID"},
		{"CatalogID", "payload.CatalogID"},
		{"CatalogRevision", "payload.CatalogRevision"},
		{"CatalogHash", "payload.CatalogHash"},
		{"ProfileKey", "profileKey"},
		{"ProfileHash", "payload.ProfileHash"},
	}
	got := make([][2]string, 0, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("the prepared request holds a positional member")
		}
		key, keyOK := pair.Key.(*ast.Ident)
		text, textOK := astExpressionText(pair.Value)
		if !keyOK || !textOK {
			t.Fatalf("the prepared request holds one unsupported member %v", element)
		}
		got = append(got, [2]string{key.Name, text})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("prepared request = %v, want the exact dependency-derived %v", got, want)
	}
	if accepted, ok := final.Results[1].(*ast.Ident); !ok || accepted.Name != "nil" {
		t.Fatalf("the preparation returns %v as its error, want nil", final.Results[1])
	}
}
