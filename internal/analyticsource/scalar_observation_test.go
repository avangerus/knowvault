package analyticsource

import (
	jsonv2 "encoding/json/v2"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// scalarObservationValuesSurface is the exact closed field surface of the
// detached projection. Anything added here is a deliberate widening of what may
// cross the analyticsource package boundary, so the test fails on any extra
// field.
var scalarObservationValuesSurface = [][2]string{
	{"ReceiptSchema", "string"},
	{"ReceiptKind", "string"},
	{"WindowBasis", "string"},
	{"DatasetID", "string"},
	{"ProfileVersion", "int64"},
	{"ProfileHash", "string"},
	{"MetricID", "string"},
	{"MetricReducer", "string"},
	{"MetricUnit", "string"},
	{"MetricNullPolicy", "string"},
	{"Value", "string"},
	{"PeriodTimeKind", "string"},
	{"PeriodLogicalType", "string"},
	{"PeriodStart", "string"},
	{"PeriodEndExclusive", "string"},
	{"PeriodReportingTimezone", "string"},
	{"PeriodSourceTimezone", "string"},
	{"PeriodCalendar", "string"},
	{"ContributingRows", "int64"},
	{"CoverageComplete", "bool"},
	{"ObservedStartedAt", "string"},
	{"ObservedCompletedAt", "string"},
	{"ReceiptDigest", "string"},
}

// TestScalarObservationProjectsApprovedRead proves the controlled 407-row
// approved fixture completes to one sealed observation whose detached projection
// carries the exact value 3888, 407 contributing rows, complete coverage, the
// exact typed period and read window, the sealed profile and metric semantics
// and the same valid canonical receipt digest.
func TestScalarObservationProjectsApprovedRead(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())

	completion, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("exact 407-row read refused: %v", err)
	}
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("CompleteScalarRead refused the exact 407-row read: %v", err)
	}
	if observation == (ScalarObservation{}) {
		t.Fatal("CompleteScalarRead published the zero observation")
	}

	values, ok := observation.Values()
	if !ok {
		t.Fatal("Values refused a completed observation")
	}
	if values.Value != "3888" {
		t.Fatalf("projected value = %q, want the exact 3888", values.Value)
	}
	if values.ContributingRows != 407 {
		t.Fatalf("projected contributing rows = %d, want 407", values.ContributingRows)
	}
	if !values.CoverageComplete {
		t.Fatal("projected coverage is not complete")
	}
	if values.ReceiptSchema != scalarReceiptSchema || values.ReceiptKind != scalarReceiptKind ||
		values.WindowBasis != scalarReceiptWindowBasis {
		t.Fatalf("projected receipt identity = %q/%q/%q, want the v1 LIVE_OBSERVATION CLIENT_READ_CALL",
			values.ReceiptSchema, values.ReceiptKind, values.WindowBasis)
	}
	if values.DatasetID != "scooter_orders" || values.ProfileVersion != 3 || values.ProfileHash == "" {
		t.Fatalf("projected profile = %q/%d/%q, want the sealed scooter_orders profile",
			values.DatasetID, values.ProfileVersion, values.ProfileHash)
	}
	if values.MetricID != "assigned_orders" || values.MetricReducer != "SUM" ||
		values.MetricUnit != "count" || values.MetricNullPolicy != "EXCLUDE_AND_REPORT" {
		t.Fatalf("projected metric = %+v, want the sealed SUM count measure with EXCLUDE_AND_REPORT",
			values)
	}
	if values.PeriodTimeKind != "BUSINESS_DATE" || values.PeriodLogicalType != "DATE" ||
		values.PeriodStart != "2026-09-10" || values.PeriodEndExclusive != "2026-09-11" ||
		values.PeriodReportingTimezone != "UTC" || values.PeriodCalendar != "GREGORIAN" {
		t.Fatalf("projected period = %+v, want the resolved BUSINESS_DATE half-open day", values)
	}
	if values.PeriodSourceTimezone != completion.receipt.envelope.Period.SourceTimezone {
		t.Fatal("projected source timezone does not match the retained time policy")
	}
	if values.ObservedStartedAt != "2026-09-10T00:00:00Z" ||
		values.ObservedCompletedAt != "2026-09-10T00:00:02Z" {
		t.Fatalf("projected window = %q/%q, want the UTC CLIENT_READ_CALL window",
			values.ObservedStartedAt, values.ObservedCompletedAt)
	}
	if values.ReceiptDigest != completion.receipt.digest ||
		!scalarSumHashPattern.MatchString(values.ReceiptDigest) {
		t.Fatalf("projected digest = %q, want the retained valid digest %q",
			values.ReceiptDigest, completion.receipt.digest)
	}
}

// TestScalarObservationRefusesClosedInput proves every read outside the accepted
// shape returns the exact zero ScalarObservation and the exact unwrapped,
// content-free errMismatch: a zero read, a tampered snapshot and incomplete
// coverage.
func TestScalarObservationRefusesClosedInput(t *testing.T) {
	cases := []struct {
		name   string
		build  func(t *testing.T) ScalarRead
		mutate func(*ScalarRead)
	}{
		{"zero read", func(*testing.T) ScalarRead { return ScalarRead{} }, nil},
		{"tampered snapshot", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.snapshot.Rows[0].Canonical[0] ^= 0xff }},
		{"incomplete coverage", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.snapshot.CoverageComplete = false }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			read := test.build(t)
			if test.mutate != nil {
				test.mutate(&read)
			}
			observation, err := CompleteScalarRead(read)
			if err != errMismatch {
				t.Fatalf("refusal = %v, want the exact unwrapped errMismatch", err)
			}
			if observation != (ScalarObservation{}) {
				t.Fatalf("refusal = %+v, want the exact zero ScalarObservation", observation)
			}
		})
	}
}

// TestScalarObservationZeroValues proves the zero observation and a
// tampered-but-schema-valid sealed state both refuse with the exact zero
// projection.
func TestScalarObservationZeroValues(t *testing.T) {
	values, ok := (ScalarObservation{}).Values()
	if ok {
		t.Fatal("the zero observation published a projection")
	}
	if values != (ScalarObservationValues{}) {
		t.Fatalf("the zero observation projection = %+v, want the exact zero value", values)
	}

	observation, err := CompleteScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fixture completion refused: %v", err)
	}
	tampered := observation
	tampered.completion.receipt.envelope.Result.Value = "0"
	values, ok = tampered.Values()
	if ok {
		t.Fatal("a tampered sealed state published a projection")
	}
	if values != (ScalarObservationValues{}) {
		t.Fatalf("a tampered sealed state projection = %+v, want the exact zero value", values)
	}
}

// TestScalarObservationGenericJSONIsOpaque proves generic JSON of one sealed
// observation is exactly the empty object and never renders a retained fact.
func TestScalarObservationGenericJSONIsOpaque(t *testing.T) {
	observation, err := CompleteScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fixture completion refused: %v", err)
	}
	for name, value := range map[string]any{
		"observation":         observation,
		"zero observation":    ScalarObservation{},
		"observation pointer": &observation,
	} {
		encoded, marshalErr := jsonv2.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("%s failed to marshal: %v", name, marshalErr)
		}
		if string(encoded) != "{}" {
			t.Fatalf("%s marshaled as %s, want the opaque {}", name, encoded)
		}
	}
}

// TestScalarObservationSurfaceIsSealed proves, by reflection and by AST, that the
// projection is exactly the closed immutable-by-copy semantic field set, that the
// observation exposes only the opaque MarshalJSON and Values methods, that the
// source declares no other exported function, type or decoder, and that none of
// the read's private identities, internals or forbidden facts appear in the
// serialized projection.
func TestScalarObservationSurfaceIsSealed(t *testing.T) {
	resultFields := [][2]string{}
	for index := 0; index < reflect.TypeOf(ScalarObservation{}).NumField(); index++ {
		field := reflect.TypeOf(ScalarObservation{}).Field(index)
		if field.IsExported() {
			t.Fatalf("ScalarObservation exposes the exported field %q", field.Name)
		}
		resultFields = append(resultFields, [2]string{field.Name, field.Type.String()})
	}
	if !reflect.DeepEqual(resultFields, [][2]string{{"completion", "analyticsource.scalarCompletion"}}) {
		t.Fatalf("ScalarObservation fields = %v, want only the private completion", resultFields)
	}

	surface := reflect.TypeOf(ScalarObservationValues{})
	fields := [][2]string{}
	for index := 0; index < surface.NumField(); index++ {
		field := surface.Field(index)
		if !field.IsExported() {
			t.Fatalf("ScalarObservationValues has the unexported field %q", field.Name)
		}
		switch field.Type.Kind() {
		case reflect.String, reflect.Int64, reflect.Bool:
		default:
			t.Fatalf("ScalarObservationValues field %s is %s, want an immutable-by-copy scalar",
				field.Name, field.Type)
		}
		fields = append(fields, [2]string{field.Name, field.Type.String()})
	}
	if !reflect.DeepEqual(fields, scalarObservationValuesSurface) {
		t.Fatalf("ScalarObservationValues fields = %v, want %v", fields, scalarObservationValuesSurface)
	}

	forbiddenNames := []string{"subject", "depend", "workspace", "connection", "snapshot", "lineage",
		"database", "principal", "organization", "credential", "secret", "token", "sql", "envelope"}
	for _, field := range fields {
		name := strings.ToLower(field[0])
		for _, forbidden := range forbiddenNames {
			if strings.Contains(name, forbidden) {
				t.Fatalf("ScalarObservationValues field %s names forbidden member %q", field[0], forbidden)
			}
		}
	}

	methods := []string{}
	for index := 0; index < reflect.TypeOf(ScalarObservation{}).NumMethod(); index++ {
		methods = append(methods, reflect.TypeOf(ScalarObservation{}).Method(index).Name)
	}
	slices.Sort(methods)
	if !slices.Equal(methods, []string{"MarshalJSON", "Values"}) {
		t.Fatalf("ScalarObservation methods = %v, want exactly [MarshalJSON Values]", methods)
	}

	read := scalarReceiptRead(t, scalarReceipt407Raw())
	completion, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("fixture completion refused: %v", err)
	}
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	values, ok := observation.Values()
	if !ok {
		t.Fatal("fixture observation refused to publish a projection")
	}
	encoded, err := jsonv2.Marshal(values)
	if err != nil {
		t.Fatalf("projection failed to marshal: %v", err)
	}
	forbiddenFacts := []string{
		read.context.access.OrganizationID, read.context.access.PrincipalID, read.context.access.RequestID,
		completion.receipt.envelope.Workspace.WorkspaceID,
		completion.receipt.envelope.Workspace.WorkspaceSourceID,
		completion.receipt.envelope.Catalog.CatalogID,
		completion.receipt.envelope.Source.SourceScopeID,
		completion.receipt.envelope.Source.ConnectionID,
		completion.receipt.envelope.Source.DatabaseIdentity,
		completion.receipt.envelope.Source.ProjectionLineageID,
		completion.receipt.envelope.Source.ExposedSchemaHash,
		completion.receipt.envelope.Snapshot.SnapshotHash,
		"fixture_workspace", "fixture_workspace_source", "plan_schema", "plan_relation",
		"note_phys", "business_day_phys", "order_total_phys", "receipt_org", "receipt_principal",
		"receipt_request", "subject", "dependency",
	}
	for _, forbidden := range forbiddenFacts {
		if forbidden == "" {
			t.Fatalf("the leakage fixture is missing an expected forbidden fact")
		}
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("the projection discloses the forbidden fact %q", forbidden)
		}
	}

	const filename = "scalar_observation.go"
	rawFile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	functions := []string{}
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
			if typed.Name.IsExported() {
				functions = append(functions, typed.Name.Name)
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
	if !slices.Equal(functions, []string{"CompleteScalarRead"}) {
		t.Fatalf("%s exported functions = %v, want exactly [CompleteScalarRead]", filename, functions)
	}
	slices.Sort(types)
	if !slices.Equal(types, []string{"ScalarObservation", "ScalarObservationValues"}) {
		t.Fatalf("%s exported types = %v, want exactly [ScalarObservation ScalarObservationValues]", filename, types)
	}
	slices.Sort(exportedMethods)
	if !slices.Equal(exportedMethods, []string{"MarshalJSON", "Values"}) {
		t.Fatalf("%s exported methods = %v, want exactly [MarshalJSON Values]", filename, exportedMethods)
	}
}

// TestScalarObservationValuesAreDetached proves the projection is rebuilt from
// the sealed state on every call: mutating a returned Values, mutating the
// observation's private state, and mutating the original read after completion
// all leave a later projection unchanged.
func TestScalarObservationValuesAreDetached(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	observation, err := CompleteScalarRead(read)
	if err != nil {
		t.Fatalf("fixture observation refused: %v", err)
	}
	first, ok := observation.Values()
	if !ok {
		t.Fatal("fixture observation refused to publish a projection")
	}

	first.Value = "0"
	first.ContributingRows = 0
	first.CoverageComplete = false
	first.ReceiptDigest = "sha256:" + strings.Repeat("0", 64)

	read.snapshot.Rows[0].Canonical[0] ^= 0xff
	read.snapshot.SnapshotHash = ""
	read.measureOrdinal = 1
	read.identityOrdinals = nil

	later, ok := observation.Values()
	if !ok {
		t.Fatal("Values refused after mutating the returned value and the original read")
	}
	second, ok := observation.Values()
	if !ok {
		t.Fatal("Values refused the repeated projection")
	}
	fresh, err := CompleteScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fresh observation refused: %v", err)
	}
	expected, ok := fresh.Values()
	if !ok {
		t.Fatal("fresh observation refused a projection")
	}
	if later != second || later != expected {
		t.Fatal("a mutation of the returned Values or the original read altered a later projection")
	}
	if expected.Value != "3888" || expected.ContributingRows != 407 {
		t.Fatalf("fresh projection = %+v, want the exact 3888 over 407 rows", expected)
	}
}
