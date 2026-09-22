package analyticsource

import (
	"bytes"
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// scalarDependencyPayloadSurface is the exact closed field surface of the
// private canonical dependency payload. Anything added here is a deliberate
// widening of what may be persisted, so the test fails on any extra field.
var scalarDependencyPayloadSurface = [][2]string{
	{"Schema", "string"},
	{"Kind", "string"},
	{"ReceiptSchema", "string"},
	{"ReceiptDigest", "string"},
	{"QuestionRunID", "string"},
	{"OrganizationID", "string"},
	{"WorkspaceID", "string"},
	{"WorkspaceRevision", "int64"},
	{"WorkspaceConfigurationHash", "string"},
	{"WorkspaceSourceID", "string"},
	{"CatalogID", "string"},
	{"CatalogRevision", "int64"},
	{"CatalogHash", "string"},
	{"DatasetID", "string"},
	{"ProfileVersion", "int64"},
	{"ProfileHash", "string"},
	{"SourceScopeID", "string"},
	{"SourceScopeRevision", "int64"},
	{"SourceScopeConfigurationHash", "string"},
	{"ConnectionID", "string"},
	{"ConnectionRevision", "int64"},
	{"DatabaseIdentity", "string"},
	{"ProjectionLineageID", "string"},
	{"ProjectionRevision", "int64"},
	{"ProjectionContractHash", "string"},
	{"ExposedSchemaRevision", "int64"},
	{"ExposedSchemaHash", "string"},
}

// scalarDependencyMemberNames is the exact closed wire member set in canonical
// (sorted) order.
var scalarDependencyMemberNames = []string{
	"catalog_hash", "catalog_id", "catalog_revision", "connection_id",
	"connection_revision", "database_identity", "dataset_id", "exposed_schema_hash",
	"exposed_schema_revision", "kind", "organization_id", "profile_hash",
	"profile_version", "projection_contract_hash", "projection_lineage_id",
	"projection_revision", "question_run_id", "receipt_digest", "receipt_schema",
	"schema", "source_scope_configuration_hash", "source_scope_id",
	"source_scope_revision", "workspace_configuration_hash", "workspace_id",
	"workspace_revision", "workspace_source_id",
}

// scalarDependencyFixture binds the controlled 407-row 3888 observation to the
// exact safe Question Run id used by every dependency test.
func scalarDependencyFixture(t *testing.T) (ScalarDependency, ScalarObservation) {
	t.Helper()
	observation, err := CompleteScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	dependency, err := BindScalarDependency("run_scalar_01", observation)
	if err != nil {
		t.Fatalf("BindScalarDependency refused the approved observation: %v", err)
	}
	return dependency, observation
}

// TestScalarDependencyBindsApprovedObservation proves the controlled 3888
// observation binds to one dependency whose payload copies every neutral receipt
// authority fact and the exact receipt digest, that Encode is canonical, and
// that Decode round-trips and re-encodes byte-identically.
func TestScalarDependencyBindsApprovedObservation(t *testing.T) {
	dependency, observation := scalarDependencyFixture(t)
	if dependency == (ScalarDependency{}) {
		t.Fatal("BindScalarDependency published the zero dependency")
	}
	values, ok := observation.Values()
	if !ok || values.Value != "3888" || values.ContributingRows != 407 {
		t.Fatalf("fixture projection = %+v ok=%v, want the approved 3888 over 407 rows", values, ok)
	}

	receipt := observation.completion.receipt
	envelope := receipt.envelope
	payload := dependency.payload

	if payload.Schema != scalarDependencySchema || payload.Kind != scalarDependencyKind {
		t.Fatalf("dependency identity = %q/%q, want the v1 GOVERNED_PROJECTION",
			payload.Schema, payload.Kind)
	}
	if payload.QuestionRunID != "run_scalar_01" {
		t.Fatalf("dependency run id = %q, want run_scalar_01", payload.QuestionRunID)
	}
	if payload.ReceiptSchema != envelope.Schema || payload.ReceiptSchema != scalarReceiptSchema {
		t.Fatalf("dependency receipt schema = %q, want %q", payload.ReceiptSchema, envelope.Schema)
	}
	if payload.ReceiptDigest != receipt.digest || !validBindingHash(payload.ReceiptDigest) {
		t.Fatalf("dependency receipt digest = %q, want the retained valid %q",
			payload.ReceiptDigest, receipt.digest)
	}
	if payload.OrganizationID != envelope.Access.OrganizationID {
		t.Fatalf("dependency organization = %q, want %q", payload.OrganizationID, envelope.Access.OrganizationID)
	}
	if payload.WorkspaceID != envelope.Workspace.WorkspaceID ||
		payload.WorkspaceRevision != envelope.Workspace.WorkspaceRevision ||
		payload.WorkspaceConfigurationHash != envelope.Workspace.WorkspaceConfigurationHash ||
		payload.WorkspaceSourceID != envelope.Workspace.WorkspaceSourceID {
		t.Fatalf("dependency workspace = %+v, want %+v", payload, envelope.Workspace)
	}
	if payload.CatalogID != envelope.Catalog.CatalogID ||
		payload.CatalogRevision != envelope.Catalog.CatalogRevision ||
		payload.CatalogHash != envelope.Catalog.CatalogHash {
		t.Fatalf("dependency catalog does not match the retained receipt catalog")
	}
	if payload.DatasetID != envelope.Profile.DatasetID ||
		payload.ProfileVersion != envelope.Profile.Version ||
		payload.ProfileHash != envelope.Profile.ProfileHash {
		t.Fatalf("dependency profile does not match the retained receipt profile")
	}
	if payload.SourceScopeID != envelope.Source.SourceScopeID ||
		payload.SourceScopeRevision != envelope.Source.SourceScopeRevision ||
		payload.SourceScopeConfigurationHash != envelope.Source.SourceScopeConfigurationHash {
		t.Fatalf("dependency source scope does not match the retained receipt source scope")
	}
	if payload.ConnectionID != envelope.Source.ConnectionID ||
		payload.ConnectionRevision != envelope.Source.ConnectionRevision ||
		payload.DatabaseIdentity != envelope.Source.DatabaseIdentity {
		t.Fatalf("dependency connection does not match the retained receipt connection")
	}
	if payload.ProjectionLineageID != envelope.Source.ProjectionLineageID ||
		payload.ProjectionRevision != envelope.Source.ProjectionRevision ||
		payload.ProjectionContractHash != envelope.Source.ProjectionContractHash {
		t.Fatalf("dependency projection does not match the retained receipt projection")
	}
	if payload.ExposedSchemaRevision != envelope.Source.ExposedSchemaRevision ||
		payload.ExposedSchemaHash != envelope.Source.ExposedSchemaHash {
		t.Fatalf("dependency exposure does not match the retained receipt exposure")
	}

	raw, err := EncodeScalarDependency(dependency)
	if err != nil {
		t.Fatalf("EncodeScalarDependency refused the bound dependency: %v", err)
	}
	canonical, err := canon.CanonicalJSON(payload)
	if err != nil || !bytes.Equal(canonical, raw) {
		t.Fatalf("encoded dependency is not the canonical payload: err=%v", err)
	}
	recannonicalized := jsontext.Value(append([]byte(nil), raw...))
	if err := recannonicalized.Canonicalize(); err != nil || !bytes.Equal(recannonicalized, raw) {
		t.Fatalf("encoded dependency is not byte-for-byte canonical: err=%v", err)
	}

	decoded, err := DecodeScalarDependency(raw)
	if err != nil {
		t.Fatalf("DecodeScalarDependency refused its own canonical bytes: %v", err)
	}
	if decoded.payload != payload {
		t.Fatalf("decoded payload = %+v, want the bound %+v", decoded.payload, payload)
	}
	reencoded, err := EncodeScalarDependency(decoded)
	if err != nil || !bytes.Equal(reencoded, raw) {
		t.Fatalf("re-encoded dependency = %q err=%v, want the exact %q", reencoded, err, raw)
	}
}

// TestScalarDependencyEncodedPayloadIsNeutral proves the encoded dependency has
// exactly the closed neutral member set, that no member names a forbidden family,
// and that the bytes disclose no principal, request, actor, metric, value,
// period, window, limit, coverage, SQL, credential or physical name.
func TestScalarDependencyEncodedPayloadIsNeutral(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	dependency, err := BindScalarDependency("run_scalar_01", observation)
	if err != nil {
		t.Fatalf("BindScalarDependency refused the approved observation: %v", err)
	}
	raw, err := EncodeScalarDependency(dependency)
	if err != nil {
		t.Fatalf("EncodeScalarDependency refused the bound dependency: %v", err)
	}

	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(raw, &members, jsontext.AllowDuplicateNames(false)); err != nil {
		t.Fatalf("encoded dependency is not one strict object: %v", err)
	}
	keys := make([]string, 0, len(members))
	for name := range members {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, scalarDependencyMemberNames) {
		t.Fatalf("dependency members = %v, want the closed set %v", keys, scalarDependencyMemberNames)
	}
	forbiddenFamilies := []string{"principal", "request", "actor", "metric", "value",
		"period", "count", "snapshot", "limit", "window", "row", "sql", "credential",
		"secret", "token", "relation", "column", "schema_name"}
	for _, key := range keys {
		for _, forbidden := range forbiddenFamilies {
			if strings.Contains(key, forbidden) {
				t.Fatalf("dependency member %q names forbidden family %q", key, forbidden)
			}
		}
	}

	receipt := observation.completion.receipt
	envelope := receipt.envelope
	forbiddenFacts := []string{
		read.context.access.PrincipalID, read.context.access.RequestID,
		string(read.context.access.EffectiveActorKind()),
		envelope.Metric.MeasureID, envelope.Metric.Unit, envelope.Metric.NullPolicy, envelope.Metric.Reducer,
		envelope.Period.TimeKind, envelope.Period.LogicalType,
		envelope.Period.ReportingTimezone, envelope.Period.Calendar,
		envelope.Period.Start, envelope.Period.EndExclusive,
		envelope.Window.StartedAt, envelope.Window.CompletedAt,
		"plan_schema", "plan_relation", "note_phys", "business_day_phys", "order_total_phys",
		"coverage_complete", "matched_rows", "contributing_rows",
		"max_rows", "statement_timeout_ns", "CLIENT_READ_CALL", "LIVE_OBSERVATION",
	}
	for _, forbidden := range forbiddenFacts {
		if forbidden == "" {
			t.Fatalf("the leakage fixture is missing an expected forbidden fact")
		}
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("the encoded dependency discloses the forbidden fact %q", forbidden)
		}
	}
}

// TestScalarDependencyRefusesClosedInput proves every dependency outside the
// accepted shape returns the exact zero ScalarDependency and the exact unwrapped
// errMismatch: a zero observation, malformed run ids, a tampered observation, a
// zero or drifted dependency for Encode, and empty, malformed, unknown,
// duplicate, noncanonical or drifted documents for Decode.
func TestScalarDependencyRefusesClosedInput(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	dependency, err := BindScalarDependency("run_scalar_01", observation)
	if err != nil {
		t.Fatalf("BindScalarDependency refused the approved observation: %v", err)
	}
	raw, err := EncodeScalarDependency(dependency)
	if err != nil {
		t.Fatalf("EncodeScalarDependency refused the bound dependency: %v", err)
	}

	assertZeroDependency := func(t *testing.T, name string, got ScalarDependency, err error) {
		t.Helper()
		if err != errMismatch {
			t.Fatalf("%s refusal = %v, want the exact unwrapped errMismatch", name, err)
		}
		if got != (ScalarDependency{}) {
			t.Fatalf("%s refusal = %+v, want the exact zero ScalarDependency", name, got)
		}
	}

	zeroDependency, zeroErr := BindScalarDependency("run_scalar_01", ScalarObservation{})
	assertZeroDependency(t, "zero observation", zeroDependency, zeroErr)
	for _, runID := range []string{"", "  run_scalar_01", "run_scalar_01 ", "run\n01", strings.Repeat("a", 257)} {
		badRunDependency, badRunErr := BindScalarDependency(runID, observation)
		assertZeroDependency(t, "malformed run id", badRunDependency, badRunErr)
	}

	tampered := observation
	tampered.completion.receipt.envelope.Result.Value = "0"
	tamperedDependency, tamperedErr := BindScalarDependency("run_scalar_01", tampered)
	assertZeroDependency(t, "tampered observation", tamperedDependency, tamperedErr)

	if refused, err := EncodeScalarDependency(ScalarDependency{}); err != errMismatch || refused != nil {
		t.Fatalf("zero dependency Encode = %q err=%v, want nil and the exact errMismatch", refused, err)
	}
	drifted := dependency
	drifted.payload.Kind = "OTHER"
	if refused, err := EncodeScalarDependency(drifted); err != errMismatch || refused != nil {
		t.Fatalf("drifted dependency Encode = %q err=%v, want nil and the exact errMismatch", refused, err)
	}

	drift := func(mutate func(*scalarDependencyPayload)) []byte {
		changed := dependency.payload
		mutate(&changed)
		encoded, encodeErr := canon.CanonicalJSON(changed)
		if encodeErr != nil {
			t.Fatalf("drifted payload refused canonicalization: %v", encodeErr)
		}
		return encoded
	}
	duplicate := append([]byte(`{"schema":"`+scalarDependencySchema+`",`), raw[1:]...)
	unknown := append([]byte(`{"unknown_member":1,`), raw[1:]...)
	noncanonical := append([]byte("{ "), raw[1:]...)

	decodeCases := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"malformed", []byte(`{"schema":`)},
		{"unknown member", unknown},
		{"duplicate member", duplicate},
		{"noncanonical whitespace", noncanonical},
		{"schema drift", drift(func(value *scalarDependencyPayload) {
			value.Schema = "knowvault.analyticsource.scalar-dependency.v2"
		})},
		{"kind drift", drift(func(value *scalarDependencyPayload) { value.Kind = "LIVE_OBSERVATION" })},
		{"receipt schema drift", drift(func(value *scalarDependencyPayload) {
			value.ReceiptSchema = "knowvault.analyticsource.live-scalar-receipt.v2"
		})},
		{"question run empty", drift(func(value *scalarDependencyPayload) { value.QuestionRunID = "" })},
		{"identity drift", drift(func(value *scalarDependencyPayload) { value.OrganizationID = "bad\torg" })},
		{"workspace identity empty", drift(func(value *scalarDependencyPayload) { value.WorkspaceID = "" })},
		{"revision zero", drift(func(value *scalarDependencyPayload) { value.WorkspaceRevision = 0 })},
		{"revision negative", drift(func(value *scalarDependencyPayload) { value.ProjectionRevision = -1 })},
		{"hash malformed", drift(func(value *scalarDependencyPayload) { value.CatalogHash = "sha256:short" })},
		{"hash uppercase", drift(func(value *scalarDependencyPayload) {
			value.ExposedSchemaHash = "sha256:" + strings.Repeat("A", 64)
		})},
		{"receipt digest malformed", drift(func(value *scalarDependencyPayload) { value.ReceiptDigest = "sha256:0" })},
	}
	for _, test := range decodeCases {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := DecodeScalarDependency(test.raw)
			assertZeroDependency(t, test.name, decoded, err)
		})
	}
}

// TestScalarDependencyGenericJSONIsOpaque proves generic JSON of one sealed
// dependency is exactly the empty object and never renders a retained fact.
func TestScalarDependencyGenericJSONIsOpaque(t *testing.T) {
	dependency, _ := scalarDependencyFixture(t)
	for name, value := range map[string]any{
		"dependency":         dependency,
		"zero dependency":    ScalarDependency{},
		"dependency pointer": &dependency,
	} {
		encoded, err := jsonv2.Marshal(value)
		if err != nil {
			t.Fatalf("%s failed to marshal: %v", name, err)
		}
		if string(encoded) != "{}" {
			t.Fatalf("%s marshaled as %s, want the opaque {}", name, encoded)
		}
	}
}

// TestScalarDependencySurfaceIsSealed proves, by reflection and by AST, that the
// dependency exposes only the private payload and the opaque MarshalJSON method,
// that the payload is exactly the closed neutral field set, and that the source
// declares no other exported function, type or value.
func TestScalarDependencySurfaceIsSealed(t *testing.T) {
	fields := [][2]string{}
	for index := 0; index < reflect.TypeOf(ScalarDependency{}).NumField(); index++ {
		field := reflect.TypeOf(ScalarDependency{}).Field(index)
		if field.IsExported() {
			t.Fatalf("ScalarDependency exposes the exported field %q", field.Name)
		}
		fields = append(fields, [2]string{field.Name, field.Type.String()})
	}
	if !reflect.DeepEqual(fields, [][2]string{{"payload", "analyticsource.scalarDependencyPayload"}}) {
		t.Fatalf("ScalarDependency fields = %v, want only the private payload", fields)
	}

	payloadFields := [][2]string{}
	for index := 0; index < reflect.TypeOf(scalarDependencyPayload{}).NumField(); index++ {
		field := reflect.TypeOf(scalarDependencyPayload{}).Field(index)
		payloadFields = append(payloadFields, [2]string{field.Name, field.Type.String()})
	}
	if !reflect.DeepEqual(payloadFields, scalarDependencyPayloadSurface) {
		t.Fatalf("scalarDependencyPayload fields = %v, want %v", payloadFields, scalarDependencyPayloadSurface)
	}
	forbiddenFamilies := []string{"principal", "request", "actor", "metric", "value",
		"period", "count", "snapshot", "limit", "window", "row", "sql", "credential",
		"secret", "token", "relation", "column", "schema_name"}
	for index := 0; index < reflect.TypeOf(scalarDependencyPayload{}).NumField(); index++ {
		field := reflect.TypeOf(scalarDependencyPayload{}).Field(index)
		tag := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
		for _, forbidden := range forbiddenFamilies {
			if strings.Contains(tag, forbidden) {
				t.Fatalf("scalarDependencyPayload member %q names forbidden family %q", tag, forbidden)
			}
		}
	}

	methods := []string{}
	for index := 0; index < reflect.TypeOf(ScalarDependency{}).NumMethod(); index++ {
		methods = append(methods, reflect.TypeOf(ScalarDependency{}).Method(index).Name)
	}
	slices.Sort(methods)
	if !slices.Equal(methods, []string{"MarshalJSON"}) {
		t.Fatalf("ScalarDependency methods = %v, want exactly [MarshalJSON]", methods)
	}

	const filename = "scalar_dependency.go"
	rawFile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	functions := []string{}
	exportedFunctions := []string{}
	exportedMethods := []string{}
	types := []string{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Recv != nil {
				if typed.Name.IsExported() {
					exportedMethods = append(exportedMethods, typed.Name.Name)
				}
				continue
			}
			functions = append(functions, typed.Name.Name)
			if typed.Name.IsExported() {
				exportedFunctions = append(exportedFunctions, typed.Name.Name)
			}
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch named := specification.(type) {
				case *ast.TypeSpec:
					if named.Name.IsExported() {
						types = append(types, named.Name.Name)
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
	slices.Sort(functions)
	wantFunctions := []string{"BindScalarDependency", "DecodeScalarDependency",
		"EncodeScalarDependency", "VerifyScalarDependencyBinding", "validSealedScalarObservation"}
	if !slices.Equal(functions, wantFunctions) {
		t.Fatalf("%s functions = %v, want %v", filename, functions, wantFunctions)
	}
	slices.Sort(exportedFunctions)
	wantExportedFunctions := []string{"BindScalarDependency", "DecodeScalarDependency",
		"EncodeScalarDependency", "VerifyScalarDependencyBinding"}
	if !slices.Equal(exportedFunctions, wantExportedFunctions) {
		t.Fatalf("%s exported functions = %v, want %v", filename, exportedFunctions, wantExportedFunctions)
	}
	slices.Sort(types)
	if !slices.Equal(types, []string{"ScalarDependency"}) {
		t.Fatalf("%s exported types = %v, want exactly [ScalarDependency]", filename, types)
	}
	slices.Sort(exportedMethods)
	if !slices.Equal(exportedMethods, []string{"MarshalJSON"}) {
		t.Fatalf("%s exported methods = %v, want exactly [MarshalJSON]", filename, exportedMethods)
	}
}

// TestScalarDependencyBindingVerifiesExactProof proves the structural binding
// verifier accepts exactly the approved Question Run/schema/digest tuple beside
// the dependency, that a decoded canonical dependency verifies identically to the
// original, and that verification discloses no private fact: generic JSON stays
// the opaque empty object and the refusal stays the content-free errMismatch.
func TestScalarDependencyBindingVerifiesExactProof(t *testing.T) {
	dependency, observation := scalarDependencyFixture(t)
	receipt := observation.completion.receipt
	schema := receipt.envelope.Schema
	digest := receipt.digest

	if schema != scalarReceiptSchema {
		t.Fatalf("fixture receipt schema = %q, want %q", schema, scalarReceiptSchema)
	}
	if err := VerifyScalarDependencyBinding("run_scalar_01", schema, digest, dependency); err != nil {
		t.Fatalf("VerifyScalarDependencyBinding refused the approved dependency: %v", err)
	}

	raw, err := EncodeScalarDependency(dependency)
	if err != nil {
		t.Fatalf("EncodeScalarDependency refused the bound dependency: %v", err)
	}
	decoded, err := DecodeScalarDependency(raw)
	if err != nil {
		t.Fatalf("DecodeScalarDependency refused its own canonical bytes: %v", err)
	}
	if err := VerifyScalarDependencyBinding("run_scalar_01", schema, digest, decoded); err != nil {
		t.Fatalf("VerifyScalarDependencyBinding refused the decoded canonical dependency: %v", err)
	}

	genericJSON, err := jsonv2.Marshal(dependency)
	if err != nil || string(genericJSON) != "{}" {
		t.Fatalf("generic JSON = %s err=%v, want the opaque {}", genericJSON, err)
	}

	refusalErr := VerifyScalarDependencyBinding("run_scalar_02", schema, digest, dependency)
	if refusalErr != errMismatch || errors.Unwrap(refusalErr) != nil {
		t.Fatalf("mismatched run refusal = %v, want the exact unwrapped errMismatch", refusalErr)
	}
	if refusalErr.Error() != errMismatch.Error() {
		t.Fatalf("refusal message = %q, want the content-free %q", refusalErr.Error(), errMismatch.Error())
	}
	for _, private := range []string{"run_scalar_02", digest, dependency.payload.QuestionRunID} {
		if private != "" && strings.Contains(refusalErr.Error(), private) {
			t.Fatalf("refusal discloses the private fact %q", private)
		}
	}
}

// TestScalarDependencyBindingRefusesMismatch proves every dependency and tuple
// outside the accepted shape returns the exact unwrapped errMismatch: a zero
// dependency, malformed and wrong valid run ids, malformed and wrong valid
// schemas, and malformed and wrong valid digests.
func TestScalarDependencyBindingRefusesMismatch(t *testing.T) {
	dependency, observation := scalarDependencyFixture(t)
	receipt := observation.completion.receipt
	schema := receipt.envelope.Schema
	digest := receipt.digest

	alternateDigest := digest[:len(digest)-1] + "0"
	if alternateDigest == digest {
		alternateDigest = digest[:len(digest)-1] + "1"
	}

	assertRefusal := func(t *testing.T, name, runID, receiptSchema, receiptDigest string,
		got ScalarDependency) {
		t.Helper()
		err := VerifyScalarDependencyBinding(runID, receiptSchema, receiptDigest, got)
		if err != errMismatch {
			t.Fatalf("%s refusal = %v, want the exact unwrapped errMismatch", name, err)
		}
		if errors.Unwrap(err) != nil {
			t.Fatalf("%s refusal wraps %v, want the exact unwrapped errMismatch", name, err)
		}
	}

	assertRefusal(t, "zero dependency", "run_scalar_01", schema, digest, ScalarDependency{})
	for _, runID := range []string{"", "  run_scalar_01", "run_scalar_01 ", "run\n01", strings.Repeat("a", 257)} {
		assertRefusal(t, "malformed run id", runID, schema, digest, dependency)
	}
	assertRefusal(t, "wrong valid run id", "run_scalar_02", schema, digest, dependency)
	for _, receiptSchema := range []string{"", "knowvault.analyticsource.live-scalar-receipt.v2", "LIVE"} {
		assertRefusal(t, "malformed or wrong schema", "run_scalar_01", receiptSchema, digest, dependency)
	}
	for _, receiptDigest := range []string{"", "sha256:0", "sha256:" + strings.Repeat("A", 64)} {
		assertRefusal(t, "malformed digest", "run_scalar_01", schema, receiptDigest, dependency)
	}
	assertRefusal(t, "wrong valid digest", "run_scalar_01", schema, alternateDigest, dependency)
}
