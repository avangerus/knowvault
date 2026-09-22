package question

import (
	"bytes"
	"encoding/base64"
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analyticsource"
)

// analyticScalarPairRunID is the exact safe Question Run id every pair fixture
// is bound to.
const analyticScalarPairRunID = "run_scalar_pair"

// analyticScalarPairFixturePath is the source-owned synthetic canonical
// dependency fixture. The Question package never names or rebuilds the
// dependency schema, members or wire format: it reads these opaque bytes and
// decodes them only through the analyticsource boundary.
const analyticScalarPairFixturePath = "../analyticsource/testdata/scalar_dependency_run_scalar_pair.json"

// analyticScalarPairFixtureDigest is the exact synthetic receipt digest the
// source-owned fixture binds. It equals the local observation fixture digest, so
// the accepted pair needs no substitution.
var analyticScalarPairFixtureDigest = "sha256:" + strings.Repeat("a", 64)

// analyticScalarPairFixture builds the one accepted in-package pair from an
// approved local observation and a canonical dependency decoded through the
// public opaque decoder. The Question package cannot construct a valid sealed
// analyticsource.ScalarObservation, so the real sealed-source constructor
// success is covered later by the PostgreSQL integration card.
func analyticScalarPairFixture(t *testing.T) analyticScalarPair {
	t.Helper()
	observation := analyticScalarObservationFixture(t)
	dependency := analyticScalarPairDependency(t, analyticScalarPairRunID, observation.ReceiptDigest)
	return analyticScalarPair{observation: observation, dependency: dependency}
}

// analyticScalarPairDependency returns the sealed dependency bound to the
// supplied Question Run and receipt digest by decoding the source-owned canonical
// fixture bytes through the public opaque decoder. Cross-run and cross-receipt
// variants replace only the unique synthetic run and digest byte values in a copy
// of those bytes, so the Question package never reconstructs a dependency member,
// field or schema.
func analyticScalarPairDependency(t *testing.T, questionRunID, receiptDigest string) analyticsource.ScalarDependency {
	t.Helper()
	raw, err := os.ReadFile(analyticScalarPairFixturePath)
	if err != nil {
		t.Fatalf("read source-owned scalar dependency fixture: %v", err)
	}
	raw = bytes.Replace(raw, []byte(analyticScalarPairRunID), []byte(questionRunID), 1)
	raw = bytes.Replace(raw, []byte(analyticScalarPairFixtureDigest), []byte(receiptDigest), 1)
	dependency, err := analyticsource.DecodeScalarDependency(raw)
	if err != nil {
		t.Fatalf("decode scalar dependency fixture: %v", err)
	}
	return dependency
}

// analyticScalarPairJSONString renders one Go string as the exact canonical
// JSON string artifact member the pair encoder emits.
func analyticScalarPairJSONString(t *testing.T, value string) jsontext.Value {
	t.Helper()
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON string fixture: %v", err)
	}
	return jsontext.Value(raw)
}

// TestAnalyticScalarPairEncodesAndDecodesExactly proves the accepted fixture
// encodes to one canonical JSON string holding the standard padded base64 of the
// exact encoded dependency, decodes back to an equal pair, and re-encodes
// byte-identically. The returned observation keeps the controlled GM value 3888,
// 407 contributing rows and complete coverage, and the artifact never carries a
// dependency member as raw text.
func TestAnalyticScalarPairEncodesAndDecodesExactly(t *testing.T) {
	pair := analyticScalarPairFixture(t)

	observation, encoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair: %v", err)
	}
	if observation != pair.observation {
		t.Fatalf("encoded observation = %+v, want the owned %+v", observation, pair.observation)
	}
	if observation.Value != "3888" || observation.ContributingRows != 407 || !observation.CoverageComplete {
		t.Fatalf("encoded observation = %+v, want value 3888 with 407 complete rows", observation)
	}

	raw, err := analyticsource.EncodeScalarDependency(pair.dependency)
	if err != nil {
		t.Fatalf("encode dependency fixture: %v", err)
	}
	want := analyticScalarPairJSONString(t, base64.StdEncoding.EncodeToString(raw))
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded artifact = %s, want the canonical JSON string %s", encoded, want)
	}
	if bytes.Contains(encoded, []byte("question_run_id")) || bytes.Contains(encoded, []byte("workspace_id")) {
		t.Fatalf("encoded artifact discloses a dependency member: %s", encoded)
	}

	decoded, err := decodeAnalyticScalarPair(analyticScalarPairRunID, &observation, encoded)
	if err != nil {
		t.Fatalf("decode accepted artifact: %v", err)
	}
	if decoded == nil {
		t.Fatal("decode returned a nil pair for a present artifact")
	}
	if decoded.observation != pair.observation {
		t.Fatalf("decoded observation = %+v, want %+v", decoded.observation, pair.observation)
	}
	if decoded.dependency != pair.dependency {
		t.Fatalf("decoded dependency = %+v, want %+v", decoded.dependency, pair.dependency)
	}

	_, reencoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, *decoded)
	if err != nil {
		t.Fatalf("re-encode decoded pair: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("re-encoded artifact = %s, want the byte-identical %s", reencoded, encoded)
	}
}

// TestAnalyticScalarPairLegacyAbsenceDecodesNil proves both halves absent is the
// sole legacy absence and decodes to (nil, nil) rather than a refusal.
func TestAnalyticScalarPairLegacyAbsenceDecodesNil(t *testing.T) {
	pair, err := decodeAnalyticScalarPair(analyticScalarPairRunID, nil, nil)
	if err != nil {
		t.Fatalf("legacy absence refusal = %v, want nil", err)
	}
	if pair != nil {
		t.Fatalf("legacy absence pair = %+v, want nil", pair)
	}
}

// TestAnalyticScalarPairDecodeRefusesClosedArtifacts proves every artifact
// outside the accepted pairing returns a nil pair plus the content-free
// CodeUnavailable: missing halves, explicit null, an empty string, non-string
// JSON, invalid and noncanonical base64, empty bytes, malformed and noncanonical
// dependency bytes, an invalid scalar, and cross-run and cross-receipt
// transplantation.
func TestAnalyticScalarPairDecodeRefusesClosedArtifacts(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	observation, encoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair: %v", err)
	}
	raw, err := analyticsource.EncodeScalarDependency(pair.dependency)
	if err != nil {
		t.Fatalf("encode dependency fixture: %v", err)
	}

	alternateDigest := "sha256:" + strings.Repeat("c", 64)
	alternateObservation := pair.observation
	alternateObservation.ReceiptDigest = alternateDigest
	_, alternateEncoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, analyticScalarPair{
		observation: alternateObservation,
		dependency:  analyticScalarPairDependency(t, analyticScalarPairRunID, alternateDigest),
	})
	if err != nil {
		t.Fatalf("encode alternate-receipt pair: %v", err)
	}

	invalidObservation := pair.observation
	invalidObservation.Value = "03888"

	for _, testCase := range []struct {
		name        string
		runID       string
		observation *analyticScalarObservation
		encoded     jsontext.Value
	}{
		{name: "missing observation", runID: analyticScalarPairRunID, encoded: encoded},
		{name: "missing dependency", runID: analyticScalarPairRunID, observation: &observation},
		{name: "explicit null", runID: analyticScalarPairRunID, observation: &observation,
			encoded: jsontext.Value("null")},
		{name: "empty string", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, "")},
		{name: "non-string JSON number", runID: analyticScalarPairRunID, observation: &observation,
			encoded: jsontext.Value("407")},
		{name: "non-string JSON object", runID: analyticScalarPairRunID, observation: &observation,
			encoded: jsontext.Value("{}")},
		{name: "invalid base64", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, "!!!not-base64!!!")},
		{name: "noncanonical base64", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, base64.RawStdEncoding.EncodeToString(raw))},
		{name: "empty dependency bytes", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, base64.StdEncoding.EncodeToString([]byte{}))},
		{name: "malformed dependency bytes", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, base64.StdEncoding.EncodeToString([]byte(`{"schema":`)))},
		{name: "noncanonical dependency bytes", runID: analyticScalarPairRunID, observation: &observation,
			encoded: analyticScalarPairJSONString(t, base64.StdEncoding.EncodeToString(append(append([]byte{}, raw...), ' ')))},
		{name: "padded JSON string", runID: analyticScalarPairRunID, observation: &observation,
			encoded: jsontext.Value(append(append([]byte{}, ' '), encoded...))},
		{name: "invalid scalar", runID: analyticScalarPairRunID, observation: &invalidObservation,
			encoded: encoded},
		{name: "cross-run binding", runID: "run_scalar_other", observation: &observation,
			encoded: encoded},
		{name: "cross-receipt binding", runID: analyticScalarPairRunID, observation: &observation,
			encoded: alternateEncoded},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := decodeAnalyticScalarPair(testCase.runID, testCase.observation, testCase.encoded)
			assertAnalyticScalarPairDecodeRefusal(t, decoded, err)
		})
	}
}

// TestAnalyticScalarPairEncodeRefusesMismatch proves the encoding boundary
// refuses a pair whose observation or opaque binding does not match the supplied
// Question Run with the exact zero observation and the content-free CodeInvalid.
func TestAnalyticScalarPairEncodeRefusesMismatch(t *testing.T) {
	pair := analyticScalarPairFixture(t)

	invalid := pair
	invalid.observation.Value = "03888"
	observation, encoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, invalid)
	assertAnalyticScalarPairEncodeRefusal(t, observation, encoded, err)

	observation, encoded, err = encodeAnalyticScalarPair("run_scalar_other", pair)
	assertAnalyticScalarPairEncodeRefusal(t, observation, encoded, err)

	observation, encoded, err = encodeAnalyticScalarPair(analyticScalarPairRunID, analyticScalarPair{})
	assertAnalyticScalarPairEncodeRefusal(t, observation, encoded, err)
}

// TestAnalyticScalarPairConstructorRefusesSealedSource proves the only
// constructor refuses the zero sealed source the Question package can name with
// the exact zero pair and the content-free CodeInvalid, and that an invalid run
// id is refused identically.
func TestAnalyticScalarPairConstructorRefusesSealedSource(t *testing.T) {
	pair, err := newAnalyticScalarPairFrom(analyticScalarPairRunID, analyticsource.ScalarObservation{})
	assertAnalyticScalarPairConstructorRefusal(t, pair, err)

	refused, err := newAnalyticScalarPairFrom("  spaced", analyticsource.ScalarObservation{})
	assertAnalyticScalarPairConstructorRefusal(t, refused, err)
}

// TestAnalyticScalarPairSurfaceIsSealed proves by AST and reflection that the
// pair is exactly one private type with two private fields and no method, that
// the file declares only the three private functions, that the constructor takes
// the concrete sealed analyticsource.ScalarObservation and calls the mapper,
// BindScalarDependency and VerifyScalarDependencyBinding, and that no generic
// JSON call ever serializes the dependency or duplicates its schema.
func TestAnalyticScalarPairSurfaceIsSealed(t *testing.T) {
	const filename = "analytic_scalar_pair.go"
	rawFile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Recv != nil {
				t.Fatalf("%s declares the method %s", filename, typed.Name.Name)
			}
			if typed.Name.IsExported() {
				t.Fatalf("%s declares the exported function %s", filename, typed.Name.Name)
			}
			functions[typed.Name.Name] = typed
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch named := specification.(type) {
				case *ast.TypeSpec:
					if named.Name.IsExported() || named.Name.Name != "analyticScalarPair" {
						t.Fatalf("%s declares the type %s, want only the private analyticScalarPair", filename, named.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range named.Names {
						if name.IsExported() {
							t.Fatalf("%s declares the exported value %s", filename, name.Name)
						}
					}
				}
			}
		}
	}
	wantFunctions := []string{"newAnalyticScalarPairFrom", "encodeAnalyticScalarPair", "decodeAnalyticScalarPair"}
	if len(functions) != len(wantFunctions) {
		t.Fatalf("%s functions = %v, want exactly %v", filename, functionNames(functions), wantFunctions)
	}
	for _, name := range wantFunctions {
		if functions[name] == nil {
			t.Fatalf("%s does not declare %s", filename, name)
		}
	}

	constructor := functions["newAnalyticScalarPairFrom"]
	if constructor.Type.Params == nil || len(constructor.Type.Params.List) != 2 {
		t.Fatalf("the constructor must accept exactly two parameters")
	}
	parameter := constructor.Type.Params.List[1]
	selector, ok := parameter.Type.(*ast.SelectorExpr)
	if !ok {
		t.Fatalf("the constructor source parameter = %T, want the concrete analyticsource.ScalarObservation selector", parameter.Type)
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok || qualifier.Name != "analyticsource" || selector.Sel.Name != "ScalarObservation" {
		t.Fatalf("the constructor source parameter = %s, want analyticsource.ScalarObservation", expressionText(selector))
	}
	calls := analyticScalarPairCallNames(constructor)
	for _, required := range []string{
		"newAnalyticScalarObservationFrom",
		"analyticsource.BindScalarDependency",
		"analyticsource.VerifyScalarDependencyBinding",
	} {
		if !containsText(calls, required) {
			t.Fatalf("the constructor calls %v, want %s", calls, required)
		}
	}

	encode := functions["encodeAnalyticScalarPair"]
	if encode.Type.Results == nil || len(encode.Type.Results.List) != 3 {
		t.Fatalf("encodeAnalyticScalarPair must return exactly three results")
	}
	if result, ok := encode.Type.Results.List[0].Type.(*ast.Ident); !ok || result.Name != "analyticScalarObservation" {
		t.Fatalf("encode first result = %T, want analyticScalarObservation", encode.Type.Results.List[0].Type)
	}
	if result, ok := encode.Type.Results.List[1].Type.(*ast.SelectorExpr); !ok ||
		expressionText(result) != "jsontext.Value" {
		t.Fatalf("encode second result = %T, want jsontext.Value", encode.Type.Results.List[1].Type)
	}

	decode := functions["decodeAnalyticScalarPair"]
	if decode.Type.Params == nil || len(decode.Type.Params.List) != 3 {
		t.Fatalf("decodeAnalyticScalarPair must accept exactly three parameters")
	}
	if parameter, ok := decode.Type.Params.List[2].Type.(*ast.SelectorExpr); !ok ||
		expressionText(parameter) != "jsontext.Value" {
		t.Fatalf("decode third parameter = %T, want jsontext.Value", decode.Type.Params.List[2].Type)
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.BasicLit:
			if strings.Contains(typed.Value, "scalar-dependency") {
				t.Fatalf("%s duplicates the dependency schema literal %s", filename, typed.Value)
			}
		case *ast.CallExpr:
			name := expressionText(typed.Fun)
			if name != "jsonv2.Marshal" && name != "json.Marshal" && name != "jsonv2.MarshalEncode" {
				return true
			}
			for _, argument := range typed.Args {
				if strings.Contains(expressionText(argument), "dependency") {
					t.Fatalf("%s serializes the dependency through generic JSON: %s(%s)", filename, name, expressionText(argument))
				}
			}
		}
		return true
	})

	pairType := reflect.TypeOf(analyticScalarPair{})
	if pairType.NumField() != 2 {
		t.Fatalf("analyticScalarPair fields = %d, want the two private fields", pairType.NumField())
	}
	for index := 0; index < pairType.NumField(); index++ {
		field := pairType.Field(index)
		if field.IsExported() {
			t.Fatalf("analyticScalarPair exposes the exported field %q", field.Name)
		}
	}
	if pairType.NumMethod() != 0 {
		t.Fatalf("analyticScalarPair methods = %d, want no method, getter or exported surface", pairType.NumMethod())
	}
}

// analyticScalarPairCallNames returns the rendered callee of every call in one
// declaration body.
func analyticScalarPairCallNames(declaration *ast.FuncDecl) []string {
	names := []string{}
	ast.Inspect(declaration, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		names = append(names, expressionText(call.Fun))
		return true
	})
	return names
}

// functionNames renders the declared function names for a failure message.
func functionNames(functions map[string]*ast.FuncDecl) []string {
	names := make([]string, 0, len(functions))
	for name := range functions {
		names = append(names, name)
	}
	return names
}

// containsText reports whether one rendered call name equals want.
func containsText(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// assertAnalyticScalarPairEncodeRefusal proves one encoding refusal returns the
// exact zero observation, no artifact bytes and the content-free CodeInvalid.
func assertAnalyticScalarPairEncodeRefusal(t *testing.T, observation analyticScalarObservation, encoded jsontext.Value, err error) {
	t.Helper()
	if observation != (analyticScalarObservation{}) {
		t.Fatalf("refused observation = %+v, want the exact zero observation", observation)
	}
	if encoded != nil {
		t.Fatalf("refused artifact = %s, want nil", encoded)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}

// assertAnalyticScalarPairConstructorRefusal proves one constructor refusal
// returns the exact zero pair plus the content-free CodeInvalid.
func assertAnalyticScalarPairConstructorRefusal(t *testing.T, pair analyticScalarPair, err error) {
	t.Helper()
	if pair != (analyticScalarPair{}) {
		t.Fatalf("refused pair = %+v, want the exact zero pair", pair)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}

// assertAnalyticScalarPairDecodeRefusal proves one decode refusal returns a nil
// pair plus the content-free CodeUnavailable, whose unwrap chain is empty.
func assertAnalyticScalarPairDecodeRefusal(t *testing.T, pair *analyticScalarPair, err error) {
	t.Helper()
	if pair != nil {
		t.Fatalf("refused pair = %+v, want nil", pair)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeUnavailable || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeUnavailable)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}
