package analyticsource

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// resolutionAuthorityViewConcreteSignature pins the private authority view to
// the one concrete repository result the helper must accept. A repository
// accessor rename or type change breaks this file's build instead of silently
// relaxing what the compatibility helper re-proves.
var resolutionAuthorityViewConcreteSignature resolutionAuthorityView = repository.PostgreSQLAuthorityResult{}

// fakeResolutionAuthority extends the existing fake repository source view with
// the server-owned connector limits, so the pure compatibility helper can be
// exercised against one exact authority view without touching repository private
// state.
type fakeResolutionAuthority struct {
	fakeRepositorySource
	limits postgresqlquery.Limits
}

func (view fakeResolutionAuthority) Limits() postgresqlquery.Limits { return view.limits }

// resolutionAuthorityFixtureFor builds the exact fake authority view that
// reproduces one sealed binding: the retained common tuple and connection
// revision on the source accessors, the discovery-shaped projection for the
// sealed profile, the one managed access mode, and valid default limits.
func resolutionAuthorityFixtureFor(t *testing.T, binding eligibilityBinding) fakeResolutionAuthority {
	t.Helper()
	columns, err := requiredColumns(binding.profile)
	if err != nil {
		t.Fatalf("fixture inventory refused: %v", err)
	}
	return fakeResolutionAuthority{
		fakeRepositorySource: fakeRepositorySource{
			workspaceID:                binding.binding.workspaceID,
			workspaceRevision:          binding.binding.workspaceRevision,
			workspaceConfigurationHash: binding.binding.workspaceConfigurationHash,
			workspaceSourceID:          binding.binding.workspaceSourceID,
			sourceScopeID:              binding.binding.sourceScopeID,
			sourceScopeRevision:        binding.binding.sourceScopeRevision,
			scopeConfigHash:            binding.binding.sourceScopeConfigurationHash,
			accessMode:                 repositoryManagedAccessMode,
			connectionRevision:         binding.binding.connectionRevision,
			projection:                 repositoryProjection(t, binding.profile, columns),
		},
		limits: postgresqlquery.DefaultLimits(),
	}
}

func TestResolutionValidRequiresBothRetainedValues(t *testing.T) {
	if (Resolution{}).Valid() {
		t.Fatal("the zero Resolution is valid")
	}
	binding, _, _ := sealedEligibility(t)
	if (Resolution{binding: binding}).Valid() {
		t.Fatal("a valid binding with a zero authority is valid")
	}
	broken := binding
	broken.seal = [32]byte{}
	if (Resolution{binding: broken}).Valid() {
		t.Fatal("a Resolution retaining a broken binding is valid")
	}
}

func TestCompatibleResolutionAuthorityAcceptsExactFakeViewAndRefusesDrift(t *testing.T) {
	binding, _, _ := sealedEligibility(t)
	if !compatibleResolutionAuthority(resolutionAuthorityFixtureFor(t, binding), binding) {
		t.Fatal("the exact fake authority view was refused")
	}

	drifts := []struct {
		name   string
		mutate func(*fakeResolutionAuthority)
	}{
		{"zero authority", func(view *fakeResolutionAuthority) { *view = fakeResolutionAuthority{} }},
		{"access mode source enforced", func(view *fakeResolutionAuthority) { view.accessMode = "SOURCE_ENFORCED" }},
		{"access mode lowered", func(view *fakeResolutionAuthority) { view.accessMode = "workspace_managed" }},
		{"access mode empty", func(view *fakeResolutionAuthority) { view.accessMode = "" }},
		{"zero limits", func(view *fakeResolutionAuthority) { view.limits = postgresqlquery.Limits{} }},
		{"tampered row limit", func(view *fakeResolutionAuthority) { view.limits.MaxRows = 0 }},
		{"tampered timeout", func(view *fakeResolutionAuthority) { view.limits.StatementTimeout = 0 }},
		{"zero projection", func(view *fakeResolutionAuthority) { view.projection = postgresqlquery.Projection{} }},
		{"missing required column", func(view *fakeResolutionAuthority) {
			view.projection.Columns = withoutProjectionColumn(view.projection.Columns, "grain_two_column")
		}},
		{"workspace id", func(view *fakeResolutionAuthority) { view.workspaceID = alternateIdentity }},
		{"workspace revision", func(view *fakeResolutionAuthority) { view.workspaceRevision = alternateRevision }},
		{"workspace configuration hash", func(view *fakeResolutionAuthority) {
			view.workspaceConfigurationHash = validHash("9")
		}},
		{"workspace source id", func(view *fakeResolutionAuthority) { view.workspaceSourceID = alternateIdentity }},
		{"source scope id", func(view *fakeResolutionAuthority) { view.sourceScopeID = alternateIdentity }},
		{"source scope revision", func(view *fakeResolutionAuthority) { view.sourceScopeRevision = alternateRevision }},
		{"source scope configuration hash", func(view *fakeResolutionAuthority) { view.scopeConfigHash = validHash("9") }},
		{"connection revision", func(view *fakeResolutionAuthority) { view.connectionRevision = alternateRevision }},
		{"projection connection id", func(view *fakeResolutionAuthority) { view.projection.ConnectionID = alternateIdentity }},
		{"projection database identity", func(view *fakeResolutionAuthority) { view.projection.DatabaseIdentity = alternateIdentity }},
		{"projection schema", func(view *fakeResolutionAuthority) { view.projection.SchemaName = alternateIdentifier }},
		{"projection relation", func(view *fakeResolutionAuthority) { view.projection.RelationName = alternateIdentifier }},
		{"projection lineage", func(view *fakeResolutionAuthority) { view.projection.LineageID = alternateIdentity }},
		{"projection revision", func(view *fakeResolutionAuthority) { view.projection.Revision++ }},
		{"projection contract hash", func(view *fakeResolutionAuthority) { view.projection.ContractHash = validHash("9") }},
		{"relation kind", func(view *fakeResolutionAuthority) { view.projection.RelationKind = "TABLE" }},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			view := resolutionAuthorityFixtureFor(t, binding)
			drift.mutate(&view)
			if compatibleResolutionAuthority(view, binding) {
				t.Fatalf("drifted authority view %q was accepted", drift.name)
			}
		})
	}
}

func TestResolutionRetainsOnlyTheSealedBinding(t *testing.T) {
	binding, facts, profile := sealedEligibility(t)
	value := Resolution{binding: binding}
	seal, retained, hash := value.binding.seal, value.binding.binding, value.binding.profile.Hash()
	for index := range facts.source.columns {
		facts.source.columns[index] = alternateIdentifier
	}
	for index := range facts.exposure.columns {
		facts.exposure.columns[index] = alternateIdentifier
	}
	for index := range facts.required {
		facts.required[index] = alternateIdentifier
	}
	spec := profile.Spec()
	slices.Reverse(spec.Fields)
	slices.Reverse(spec.Measures)
	if value.binding.seal != seal || value.binding.binding != retained || value.binding.profile.Hash() != hash {
		t.Fatal("Resolution retained caller-owned fixture state")
	}
	if value.binding.profile.Hash() != profile.Hash() || value.binding.profile.Key() != profile.Key() {
		t.Fatal("Resolution retained a caller-owned profile")
	}
}

func TestResolutionMarshalsOpaqueEmptyObject(t *testing.T) {
	binding, _, _ := sealedEligibility(t)
	for name, value := range map[string]Resolution{"zero": {}, "sealed": {binding: binding}} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s Resolution failed to marshal: %v", name, err)
		}
		if string(encoded) != "{}" {
			t.Fatalf("%s Resolution marshaled as %s, want {}", name, encoded)
		}
	}
}

func TestResolutionSurfaceIsClosed(t *testing.T) {
	value := reflect.TypeOf(Resolution{})
	if value.NumField() != 2 {
		t.Fatalf("Resolution has %d fields, want exactly two", value.NumField())
	}
	bindingField := value.Field(0)
	if bindingField.Name != "binding" || bindingField.PkgPath == "" ||
		bindingField.Type.String() != "analyticsource.eligibilityBinding" {
		t.Fatalf("Resolution field 0 = %s %s, want one unexported eligibilityBinding", bindingField.Name, bindingField.Type)
	}
	authorityField := value.Field(1)
	if authorityField.Name != "authority" || authorityField.PkgPath == "" ||
		authorityField.Type != reflect.TypeOf(repository.PostgreSQLAuthorityResult{}) {
		t.Fatalf("Resolution field 1 = %s %s, want one unexported repository.PostgreSQLAuthorityResult",
			authorityField.Name, authorityField.Type)
	}
	methods := make([]string, 0, value.NumMethod())
	for index := 0; index < value.NumMethod(); index++ {
		methods = append(methods, value.Method(index).Name)
	}
	if !slices.Equal(methods, []string{"MarshalJSON", "Valid"}) {
		t.Fatalf("Resolution methods = %v, want exactly [MarshalJSON Valid]", methods)
	}
	if !value.Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) {
		t.Fatal("Resolution does not implement json.Marshaler")
	}

	const filename = "resolution.go"
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
		"knowvault.local/verified-workspace/internal/source/postgresqlquery": true,
		"knowvault.local/verified-workspace/internal/workspace/repository":   true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the resolution: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}
	declaredTypes := []string{}
	declaredMethods := []string{}
	declaredFunctions := []string{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			for _, specification := range typed.Specs {
				declared, ok := specification.(*ast.TypeSpec)
				if !ok {
					t.Fatalf("resolution.go declares package-level state at %s", files.Position(specification.Pos()))
				}
				declaredTypes = append(declaredTypes, declared.Name.Name)
			}
		case *ast.FuncDecl:
			if typed.Recv == nil {
				declaredFunctions = append(declaredFunctions, typed.Name.Name)
				continue
			}
			declaredMethods = append(declaredMethods, typed.Name.Name)
		}
	}
	if !slices.Equal(declaredTypes, []string{"Resolution", "resolutionAuthorityView"}) {
		t.Fatalf("resolution.go types = %v, want exactly [Resolution resolutionAuthorityView]", declaredTypes)
	}
	if !slices.Equal(declaredFunctions, []string{"compatibleResolutionAuthority"}) {
		t.Fatalf("resolution.go functions = %v, want exactly [compatibleResolutionAuthority]", declaredFunctions)
	}
	slices.Sort(declaredMethods)
	if !slices.Equal(declaredMethods, []string{"MarshalJSON", "Valid"}) {
		t.Fatalf("resolution.go methods = %v, want exactly [MarshalJSON Valid]", declaredMethods)
	}
}
