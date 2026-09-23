package question

import (
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
)

// analyticScalarPersistenceBase returns the minimal run-bound structured answer
// every pair-boundary fixture starts from.
func analyticScalarPersistenceBase() structuredAnswer {
	return structuredAnswer{
		SchemaVersion: "extractive-answer-v1", QuestionRunID: analyticScalarPairRunID,
		Claims: []structuredClaim{}, Citations: []Citation{},
	}
}

// analyticScalarPersistenceMarshal renders one structured answer fixture exactly
// as the artifact writer would.
func analyticScalarPersistenceMarshal(t *testing.T, structured structuredAnswer) []byte {
	t.Helper()
	raw, err := jsonv2.Marshal(structured)
	if err != nil {
		t.Fatalf("marshal structured answer fixture: %v", err)
	}
	return raw
}

// TestDecodeStructuredAnswerAnalyticScalarPairRoundTrips proves the strict,
// run-aware decoder accepts the exact trusted run and returns the controlled GM
// scalar plus its opaque dependency: value 3888, 407 contributing rows, complete
// coverage, a nonempty encoded dependency and the retained private pair.
func TestDecodeStructuredAnswerAnalyticScalarPairRoundTrips(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	observation, encodedDependency, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair fixture: %v", err)
	}

	artifact := analyticScalarPersistenceBase()
	artifact.AnalyticScalar = &observation
	artifact.AnalyticScalarDependency = encodedDependency
	raw := analyticScalarPersistenceMarshal(t, artifact)

	decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, raw)
	if err != nil {
		t.Fatalf("decode accepted pair artifact: %v", err)
	}
	if decoded.AnalyticScalar == nil {
		t.Fatalf("decoded analytic scalar observation is nil")
	}
	if *decoded.AnalyticScalar != observation {
		t.Fatalf("decoded observation = %+v, want %+v", *decoded.AnalyticScalar, observation)
	}
	if decoded.AnalyticScalar.Value != "3888" || decoded.AnalyticScalar.ContributingRows != 407 || !decoded.AnalyticScalar.CoverageComplete {
		t.Fatalf("decoded observation = %+v, want value 3888 with 407 complete rows", decoded.AnalyticScalar)
	}
	if len(decoded.AnalyticScalarDependency) == 0 {
		t.Fatalf("decoded artifact carries no encoded dependency")
	}
	if decoded.analyticScalarPair == nil {
		t.Fatalf("decoded artifact retains no private pair")
	}
	if decoded.analyticScalarPair.dependency != pair.dependency {
		t.Fatalf("retained dependency = %+v, want %+v", decoded.analyticScalarPair.dependency, pair.dependency)
	}
}

// TestDecodeStructuredAnswerSupportsLegacyAbsence proves the sole legacy absence
// is both pair members absent: it decodes successfully with no projection and no
// retained pair.
func TestDecodeStructuredAnswerSupportsLegacyAbsence(t *testing.T) {
	raw := analyticScalarPersistenceMarshal(t, analyticScalarPersistenceBase())

	decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, raw)
	if err != nil {
		t.Fatalf("decode legacy artifact: %v", err)
	}
	if decoded.AnalyticScalar != nil || decoded.analyticScalarPair != nil || len(decoded.AnalyticScalarDependency) != 0 {
		t.Fatalf("legacy artifact decoded a pair: %+v", decoded)
	}
}

// TestDecodeStructuredAnswerDistinguishesLegacyAbsenceFromExplicitNull proves
// the strict decoder's presence rule exactly: only both scalar member names
// absent is the accepted legacy absence, while either member present as the
// JSON null literal - alone, opposite a valid partner, or together - is refused
// with the exact zero structured answer plus the content-free CodeUnavailable.
func TestDecodeStructuredAnswerDistinguishesLegacyAbsenceFromExplicitNull(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	_, encodedDependency, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair fixture: %v", err)
	}

	legacy := analyticScalarPersistenceMarshal(t, analyticScalarPersistenceBase())
	if _, err := decodeStructuredAnswer(analyticScalarPairRunID, legacy); err != nil {
		t.Fatalf("both member names absent must stay readable legacy, got %v", err)
	}

	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{name: "analytic_scalar null alone", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null}`)},
		{name: "dependency null alone", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar_dependency":null}`)},
		{name: "both null", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null,"analytic_scalar_dependency":null}`)},
		{name: "null scalar beside valid dependency", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null,"analytic_scalar_dependency":` + string(encodedDependency) + `}`)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, testCase.raw)
			assertAnalyticScalarDecodeRefusal(t, decoded, err)
		})
	}
}

// TestDecodeStructuredAnswerClearedWithholdsPlaintext proves the governed-reader
// boundary both readers share clears the decrypted artifact bytes on the
// accepted and the refused path, and that a refusal yields the exact zero
// structured answer plus the content-free CodeUnavailable. The existing focused
// tests have no database harness for readStoredRun/readStoredRunBatch, so this
// pins the one seam both of them call.
func TestDecodeStructuredAnswerClearedWithholdsPlaintext(t *testing.T) {
	legacy := analyticScalarPersistenceMarshal(t, analyticScalarPersistenceBase())
	acceptedPlain := append([]byte(nil), legacy...)
	decoded, err := decodeStructuredAnswerCleared(analyticScalarPairRunID, acceptedPlain)
	if err != nil {
		t.Fatalf("cleared decode of legacy artifact: %v", err)
	}
	if decoded.QuestionRunID != analyticScalarPairRunID {
		t.Fatalf("cleared decode run = %q, want %q", decoded.QuestionRunID, analyticScalarPairRunID)
	}
	assertAnalyticScalarPlaintextCleared(t, acceptedPlain)

	refusedPlain := []byte(`{"question_run_id":"` + analyticScalarPairRunID + `","analytic_scalar":null}`)
	decoded, err = decodeStructuredAnswerCleared(analyticScalarPairRunID, refusedPlain)
	assertAnalyticScalarDecodeRefusal(t, decoded, err)
	assertAnalyticScalarPlaintextCleared(t, refusedPlain)
}

// assertAnalyticScalarPlaintextCleared proves every byte of one decrypted
// structured-answer buffer is zero after the governed-reader boundary returns.
func assertAnalyticScalarPlaintextCleared(t *testing.T, plain []byte) {
	t.Helper()
	for index, value := range plain {
		if value != 0 {
			t.Fatalf("plaintext byte %d = %d, want zeroed buffer", index, value)
		}
	}
}

// TestDecodeStructuredAnswerRefusesUnpairedArtifacts proves every artifact that
// does not carry one exact, run-bound, valid pair is refused with the exact zero
// structured answer plus the content-free CodeUnavailable: scalar-only,
// dependency-only, explicit null on either half, malformed and non-string
// dependency, cross-run and cross-receipt transplantation, and an invalid
// scalar.
func TestDecodeStructuredAnswerRefusesUnpairedArtifacts(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	observation, encodedDependency, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair fixture: %v", err)
	}

	otherRunID := "run_scalar_other"
	otherDependency := analyticScalarPairDependency(t, otherRunID, observation.ReceiptDigest)
	_, crossRunEncoded, err := encodeAnalyticScalarPair(otherRunID, analyticScalarPair{
		observation: observation, dependency: otherDependency,
	})
	if err != nil {
		t.Fatalf("encode cross-run pair: %v", err)
	}

	alternateDigest := "sha256:" + strings.Repeat("c", 64)
	alternateObservation := observation
	alternateObservation.ReceiptDigest = alternateDigest
	_, alternateEncoded, err := encodeAnalyticScalarPair(analyticScalarPairRunID, analyticScalarPair{
		observation: alternateObservation,
		dependency:  analyticScalarPairDependency(t, analyticScalarPairRunID, alternateDigest),
	})
	if err != nil {
		t.Fatalf("encode cross-receipt pair: %v", err)
	}

	invalidObservation := observation
	invalidObservation.Value = "03888"

	withScalar := func() structuredAnswer {
		artifact := analyticScalarPersistenceBase()
		artifact.AnalyticScalar = &observation
		return artifact
	}
	withDependency := func() structuredAnswer {
		artifact := analyticScalarPersistenceBase()
		artifact.AnalyticScalarDependency = encodedDependency
		return artifact
	}

	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{name: "scalar only", raw: analyticScalarPersistenceMarshal(t, withScalar())},
		{name: "dependency only", raw: analyticScalarPersistenceMarshal(t, withDependency())},
		{name: "explicit null dependency", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := withScalar()
			artifact.AnalyticScalarDependency = jsontext.Value("null")
			return artifact
		}())},
		{name: "explicit null scalar", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null,"analytic_scalar_dependency":` + string(encodedDependency) + `}`)},
		{name: "explicit null scalar alone", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null}`)},
		{name: "explicit null dependency alone", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar_dependency":null}`)},
		{name: "both explicit null", raw: []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","analytic_scalar":null,"analytic_scalar_dependency":null}`)},
		{name: "malformed dependency", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := withScalar()
			artifact.AnalyticScalarDependency = analyticScalarPairJSONString(t, "!!!not-base64!!!")
			return artifact
		}())},
		{name: "non-string dependency", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := withScalar()
			artifact.AnalyticScalarDependency = jsontext.Value("407")
			return artifact
		}())},
		{name: "cross-run binding", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := withScalar()
			artifact.AnalyticScalarDependency = crossRunEncoded
			return artifact
		}())},
		{name: "cross-receipt binding", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := withScalar()
			artifact.AnalyticScalarDependency = alternateEncoded
			return artifact
		}())},
		{name: "invalid scalar", raw: analyticScalarPersistenceMarshal(t, func() structuredAnswer {
			artifact := analyticScalarPersistenceBase()
			artifact.AnalyticScalar = &invalidObservation
			artifact.AnalyticScalarDependency = encodedDependency
			return artifact
		}())},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, testCase.raw)
			assertAnalyticScalarDecodeRefusal(t, decoded, err)
		})
	}
}

// TestDecodeStructuredAnswerIsRunAware proves the decoder accepts the exact
// trusted run and refuses both a different trusted run and a malformed or absent
// expected run id, always with the exact zero structured answer plus the
// content-free CodeUnavailable.
func TestDecodeStructuredAnswerIsRunAware(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	observation, encodedDependency, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair fixture: %v", err)
	}
	artifact := analyticScalarPersistenceBase()
	artifact.AnalyticScalar = &observation
	artifact.AnalyticScalarDependency = encodedDependency
	raw := analyticScalarPersistenceMarshal(t, artifact)

	if _, err := decodeStructuredAnswer(analyticScalarPairRunID, raw); err != nil {
		t.Fatalf("decode with the exact trusted run: %v", err)
	}

	for _, testCase := range []struct {
		name        string
		expectedRun string
		raw         []byte
	}{
		{name: "different trusted run", expectedRun: "run_scalar_other", raw: raw},
		{name: "empty expected run", expectedRun: "", raw: raw},
		{name: "padded expected run", expectedRun: " " + analyticScalarPairRunID, raw: raw},
		{name: "missing artifact run", expectedRun: analyticScalarPairRunID,
			raw: []byte(`{"schema_version":"extractive-answer-v1"}`)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := decodeStructuredAnswer(testCase.expectedRun, testCase.raw)
			assertAnalyticScalarDecodeRefusal(t, decoded, err)
		})
	}
}

// TestDecodeStructuredAnswerRejectsFabricatedLegacyMembers proves the strict
// decoder refuses an artifact whose analytic scalar still carries the retired
// covered_subjects or dependency_id member, an unknown top-level member, or a
// duplicate member name: unknown and duplicate members are rejected rather than
// silently ignored, so a fabricated legacy claim can never re-enter the
// projection.
func TestDecodeStructuredAnswerRejectsFabricatedLegacyMembers(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	observation, encodedDependency, err := encodeAnalyticScalarPair(analyticScalarPairRunID, pair)
	if err != nil {
		t.Fatalf("encode accepted pair fixture: %v", err)
	}
	artifact := analyticScalarPersistenceBase()
	artifact.AnalyticScalar = &observation
	artifact.AnalyticScalarDependency = encodedDependency
	raw := analyticScalarPersistenceMarshal(t, artifact)

	tamperedWith := func(mutate func(artifact map[string]any)) []byte {
		t.Helper()
		var decoded map[string]any
		if err := jsonv2.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("unmarshal structured answer for tampering: %v", err)
		}
		mutate(decoded)
		tampered, err := jsonv2.Marshal(decoded)
		if err != nil {
			t.Fatalf("marshal tampered structured answer: %v", err)
		}
		return tampered
	}

	for _, testCase := range []struct {
		name string
		raw  []byte
	}{
		{name: "covered_subjects", raw: tamperedWith(func(decoded map[string]any) {
			decoded["analytic_scalar"].(map[string]any)["covered_subjects"] = 407
		})},
		{name: "dependency_id", raw: tamperedWith(func(decoded map[string]any) {
			decoded["analytic_scalar"].(map[string]any)["dependency_id"] = "live_observation_01"
		})},
		{name: "unknown top-level member", raw: tamperedWith(func(decoded map[string]any) {
			decoded["unknown_member"] = true
		})},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, testCase.raw)
			assertAnalyticScalarDecodeRefusal(t, decoded, err)
		})
	}

	t.Run("duplicate member", func(t *testing.T) {
		duplicate := []byte(`{"question_run_id":"` + analyticScalarPairRunID +
			`","question_run_id":"` + analyticScalarPairRunID + `"}`)
		decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, duplicate)
		assertAnalyticScalarDecodeRefusal(t, decoded, err)
	})
}

// TestStructuredAnswerPairPersistenceSurfaceIsClosed proves by AST and
// reflection that no scalar-only marshal or persist seam remains, that both
// replacements accept only the private pair, and that the opaque dependency is
// never copied into any Run field.
func TestStructuredAnswerPairPersistenceSurfaceIsClosed(t *testing.T) {
	const filename = "service.go"
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
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	for _, removed := range []string{
		"marshalStructuredAnswerWithAnalyticScalar",
		"persistTerminalRunWithAnalyticScalar",
	} {
		if functions[removed] != nil {
			t.Fatalf("%s still declares the scalar-only seam %s", filename, removed)
		}
	}
	for _, required := range []string{
		"marshalStructuredAnswerWithAnalyticScalarPair",
		"persistTerminalRunWithAnalyticScalarPair",
	} {
		function := functions[required]
		if function == nil {
			t.Fatalf("%s does not declare %s", filename, required)
		}
		if !declaresPointerParameter(function, "analyticScalarPair") {
			t.Fatalf("%s does not accept the private *analyticScalarPair", required)
		}
	}
	for name, function := range functions {
		if !strings.Contains(name, "marshalStructuredAnswer") && !strings.Contains(name, "persistTerminalRunWithAnalyticScalar") {
			continue
		}
		if function.Type.Params == nil {
			continue
		}
		for _, parameter := range function.Type.Params.List {
			if expressionText(parameter.Type) == "*analyticScalarObservation" {
				t.Fatalf("%s still accepts *analyticScalarObservation for live persistence", name)
			}
		}
	}
	if functions["marshalStructuredAnswer"] == nil {
		t.Fatalf("%s does not preserve the scalar-free marshalStructuredAnswer wrapper", filename)
	}

	runType := reflect.TypeOf(Run{})
	if runType.Kind() != reflect.Struct {
		t.Fatalf("Run kind = %s, want struct", runType.Kind())
	}
	pairPointer := reflect.TypeOf(&analyticScalarPair{})
	dependencyValue := reflect.TypeOf(jsontext.Value(nil))
	for index := 0; index < runType.NumField(); index++ {
		field := runType.Field(index)
		if strings.Contains(strings.ToLower(field.Name), "dependency") ||
			strings.Contains(strings.ToLower(field.Tag.Get("json")), "dependency") {
			t.Fatalf("Run carries the dependency field %q", field.Name)
		}
		if field.Type == dependencyValue || field.Type == pairPointer {
			t.Fatalf("Run carries the artifact-only dependency through field %q", field.Name)
		}
	}
}

// declaresPointerParameter reports whether one declaration accepts a pointer
// parameter with the exact named type.
func declaresPointerParameter(function *ast.FuncDecl, name string) bool {
	if function.Type.Params == nil {
		return false
	}
	for _, parameter := range function.Type.Params.List {
		if expressionText(parameter.Type) == "*"+name {
			return true
		}
	}
	return false
}

// assertAnalyticScalarDecodeRefusal proves one refused strict decode returns the
// exact zero structured answer plus the content-free CodeUnavailable, whose
// unwrap chain is empty.
func assertAnalyticScalarDecodeRefusal(t *testing.T, decoded structuredAnswer, err error) {
	t.Helper()
	if !reflect.DeepEqual(decoded, structuredAnswer{}) {
		t.Fatalf("refused decode = %+v want the exact zero structured answer", decoded)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeUnavailable || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeUnavailable)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}
