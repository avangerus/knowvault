package analyticsource

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"testing"
)

func TestResolutionValidReportsTheRetainedBinding(t *testing.T) {
	if (Resolution{}).Valid() {
		t.Fatal("the zero Resolution is valid")
	}
	binding, _, _ := sealedEligibility(t)
	if !(Resolution{binding: binding}).Valid() {
		t.Fatal("a sealed fixture binding wrapped in Resolution is not valid")
	}
	broken := Resolution{binding: binding}
	broken.binding.seal = [32]byte{}
	if broken.Valid() {
		t.Fatal("a Resolution retaining a broken seal is valid")
	}
}

func TestResolutionRetainsNoCallerSlices(t *testing.T) {
	binding, facts, profile := sealedEligibility(t)
	value := Resolution{binding: binding}
	if !value.Valid() {
		t.Fatal("a sealed fixture binding wrapped in Resolution is not valid")
	}
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
	if !value.Valid() {
		t.Fatal("Resolution lost validity after the caller fixture slices were mutated")
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
	if value.NumField() != 1 {
		t.Fatalf("Resolution has %d fields, want exactly one", value.NumField())
	}
	field := value.Field(0)
	if field.Name != "binding" || field.PkgPath == "" || field.Type.String() != "analyticsource.eligibilityBinding" {
		t.Fatalf("Resolution field = %s %s, want one unexported eligibilityBinding", field.Name, field.Type)
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
	if len(parsed.Imports) != 0 {
		t.Fatalf("resolution.go imports %d packages, want none", len(parsed.Imports))
	}
	declaredTypes := []string{}
	declaredMethods := []string{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				declared, ok := specification.(*ast.TypeSpec)
				if !ok {
					t.Fatalf("resolution.go declares package-level state at %s", files.Position(specification.Pos()))
				}
				if _, ok := declared.Type.(*ast.StructType); !ok {
					t.Fatalf("resolution.go declares non-struct type %s", declared.Name.Name)
				}
				declaredTypes = append(declaredTypes, declared.Name.Name)
			}
		case *ast.FuncDecl:
			if typed.Recv == nil {
				t.Fatalf("resolution.go declares top-level function %s: Resolution has no constructor", typed.Name.Name)
			}
			declaredMethods = append(declaredMethods, typed.Name.Name)
		}
	}
	if !slices.Equal(declaredTypes, []string{"Resolution"}) {
		t.Fatalf("resolution.go types = %v, want exactly [Resolution]", declaredTypes)
	}
	slices.Sort(declaredMethods)
	if !slices.Equal(declaredMethods, []string{"MarshalJSON", "Valid"}) {
		t.Fatalf("resolution.go methods = %v, want exactly [MarshalJSON Valid]", declaredMethods)
	}
}
