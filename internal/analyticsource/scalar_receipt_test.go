package analyticsource

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// scalarReceiptRead builds one fully valid ScalarRead whose retained intent,
// profile, binding, access context, limits and window all cohere: the sealed
// intent is validated against the exact profile the eligibility binding was
// sealed from, and the snapshot carries the plan's identity ordinal 1 and
// measure ordinal 2. It uses the canonical scale-6 NUMERIC snapshot columns.
func scalarReceiptRead(t *testing.T, raw [][]any) ScalarRead {
	t.Helper()
	return scalarReceiptReadWithColumns(t, scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6), raw)
}

// scalarReceiptReadWithColumns is scalarReceiptRead with caller-selected
// snapshot columns, so a test can prove the exact arithmetic at another scale.
func scalarReceiptReadWithColumns(t *testing.T, columns []postgresqlquery.Column, raw [][]any) ScalarRead {
	t.Helper()
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	inventory, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("receipt fixture inventory refused: %v", err)
	}
	facts := governedMatchFixture(t, profile, inventory)
	binding, err := newEligibilityBinding(profile, facts.source, facts.exposure)
	if err != nil {
		t.Fatalf("receipt fixture binding refused: %v", err)
	}
	catalog := scalarPlanCatalog(t, profile)
	intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))
	access := database.AccessContext{
		OrganizationID: "receipt_org", PrincipalID: "receipt_principal", RequestID: "receipt_request",
		ActorKind: database.ActorKindService,
	}
	snapshot := scalarSumBuildSnapshot(t, columns, raw)
	read, err := newScalarRead(intent, binding, access, postgresqlquery.DefaultLimits(),
		time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC), time.Date(2026, 9, 10, 0, 0, 2, 0, time.UTC),
		snapshot, 2, []int{1})
	if err != nil {
		t.Fatalf("receipt fixture read refused: %v", err)
	}
	return read
}

// scalarReceipt407Raw is the controlled 407-row NUMERIC fixture: 406 rows of
// 9.552000 and one row of 9.888000, which is exactly 3888.
func scalarReceipt407Raw() [][]any {
	raw := make([][]any, 0, 407)
	for index := 0; index < 406; index++ {
		raw = append(raw, []any{fmt.Sprintf("grain-%03d", index), "9.552000"})
	}
	return append(raw, []any{"grain-406", "9.888000"})
}

// TestScalarReceiptRealisticLiveObservation proves the controlled 407-row
// snapshot completes to value 3888 and a stable canonical v1 LIVE_OBSERVATION
// receipt with 407 matched and 407 contributing rows, and that mutating the
// read's snapshot after completion cannot alter the retained receipt.
func TestScalarReceiptRealisticLiveObservation(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())

	completion, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("exact 407-row read refused: %v", err)
	}
	if completion.sum.value != "3888" || completion.sum.contributingRows != 407 {
		t.Fatalf("reducer proof = %+v, want value 3888 and 407 rows", completion.sum)
	}
	if !completion.receipt.valid() {
		t.Fatal("completion published a receipt that does not validate")
	}

	envelope := completion.receipt.envelope
	if envelope.Schema != scalarReceiptSchema || envelope.Kind != "LIVE_OBSERVATION" ||
		envelope.WindowBasis != "CLIENT_READ_CALL" {
		t.Fatalf("receipt identity = %q/%q/%q, want the v1 LIVE_OBSERVATION CLIENT_READ_CALL",
			envelope.Schema, envelope.Kind, envelope.WindowBasis)
	}
	if envelope.Snapshot.SnapshotHash != read.snapshot.SnapshotHash || !envelope.Snapshot.CoverageComplete {
		t.Fatal("receipt does not retain the exact complete snapshot")
	}
	if envelope.Snapshot.MatchedRows != 407 || envelope.Snapshot.ContributingRows != 407 {
		t.Fatalf("receipt rows = matched %d contributing %d, want 407/407",
			envelope.Snapshot.MatchedRows, envelope.Snapshot.ContributingRows)
	}
	if envelope.Result.Value != "3888" {
		t.Fatalf("receipt value = %q, want 3888", envelope.Result.Value)
	}
	if envelope.Profile.DatasetID != "scooter_orders" || envelope.Profile.Version != 3 ||
		envelope.Metric.MeasureID != "assigned_orders" || envelope.Metric.Reducer != "SUM" {
		t.Fatalf("receipt identity = %+v/%+v, want the sealed dataset and SUM measure",
			envelope.Profile, envelope.Metric)
	}
	if envelope.Period.Start != "2026-09-10" || envelope.Period.EndExclusive != "2026-09-11" ||
		envelope.Period.TimeKind != "BUSINESS_DATE" || envelope.Period.ReportingTimezone != "UTC" {
		t.Fatalf("receipt period = %+v, want the resolved BUSINESS_DATE half-open day", envelope.Period)
	}
	if envelope.Window.StartedAt != "2026-09-10T00:00:00Z" || envelope.Window.CompletedAt != "2026-09-10T00:00:02Z" {
		t.Fatalf("receipt window = %+v, want the UTC read window", envelope.Window)
	}
	if envelope.Access.OrganizationID != "receipt_org" || envelope.Access.ActorKind != "SERVICE" {
		t.Fatalf("receipt access = %+v, want the exact caller and effective actor kind", envelope.Access)
	}
	if envelope.Source.DatabaseIdentity == "" || envelope.Source.ProjectionLineageID == "" {
		t.Fatal("receipt does not retain the neutral source binding and execution facts")
	}

	repeated, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("repeated completion refused: %v", err)
	}
	if repeated.receipt.digest != completion.receipt.digest {
		t.Fatal("the same read produced two different receipt digests")
	}
	recomputed, err := scalarReceiptDigest(envelope)
	if err != nil || recomputed != completion.receipt.digest {
		t.Fatalf("recomputed digest = %q err=%v, want %q", recomputed, err, completion.receipt.digest)
	}

	retained := completion.receipt
	read.snapshot.Rows[0].Canonical[0] ^= 0xff
	read.snapshot.SnapshotHash = ""
	read.measureOrdinal = 1
	if completion.receipt != retained || !completion.receipt.valid() {
		t.Fatal("mutating the read after completion altered the retained receipt")
	}
}

// TestScalarCompletionUsesExactReducerArithmetic proves completion calls the
// exact integer/decimal reducer itself: 0.1+0.2 is exactly 0.3 through
// completeScalarRead and the published value is the canonical decimal.
func TestScalarCompletionUsesExactReducerArithmetic(t *testing.T) {
	columns := scalarSumNumericColumns("oid:1700:p:6:s:1", 6, 1)
	read := scalarReceiptReadWithColumns(t, columns, [][]any{{"grain-a", "0.1"}, {"grain-b", "0.2"}})
	completion, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("decimal read refused: %v", err)
	}
	if completion.sum.value != "0.3" || completion.receipt.envelope.Result.Value != "0.3" {
		t.Fatalf("0.1 + 0.2 = %q, want the exact 0.3", completion.sum.value)
	}
	if completion.sum.contributingRows != 2 {
		t.Fatalf("contributing rows = %d, want 2", completion.sum.contributingRows)
	}
}

// TestScalarReceiptLimitsRetainExactNanoseconds proves the receipt envelope
// retains the executed server limits as their exact signed 64-bit nanoseconds:
// it starts from the ordinary valid read, replaces the connector limits with
// valid sub-millisecond-distinct values, completes the read and requires the
// envelope timeout fields to equal the exact int64(time.Duration). A future
// Milliseconds() truncation or a swap of the two timeout fields fails here.
func TestScalarReceiptLimitsRetainExactNanoseconds(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	limits := postgresqlquery.DefaultLimits()
	limits.StatementTimeout += time.Nanosecond
	limits.TransactionTimeout += 2 * time.Nanosecond
	if limits.StatementTimeout.Milliseconds() != read.context.limits.StatementTimeout.Milliseconds() ||
		limits.TransactionTimeout.Milliseconds() != read.context.limits.TransactionTimeout.Milliseconds() {
		t.Fatal("the limit drift must stay below millisecond resolution to prove exact nanoseconds")
	}
	read.context.limits = limits

	completion, err := completeScalarRead(read)
	if err != nil {
		t.Fatalf("sub-millisecond-distinct limits read refused: %v", err)
	}
	envelope := completion.receipt.envelope
	if envelope.Limits.StatementTimeoutNS != int64(limits.StatementTimeout) {
		t.Fatalf("receipt statement timeout = %d ns, want the exact %d ns",
			envelope.Limits.StatementTimeoutNS, int64(limits.StatementTimeout))
	}
	if envelope.Limits.TransactionTimeoutNS != int64(limits.TransactionTimeout) {
		t.Fatalf("receipt transaction timeout = %d ns, want the exact %d ns",
			envelope.Limits.TransactionTimeoutNS, int64(limits.TransactionTimeout))
	}
	if envelope.Limits.StatementTimeoutNS == envelope.Limits.TransactionTimeoutNS {
		t.Fatal("receipt collapsed the two distinct timeout fields into one value")
	}
}

// TestScalarCompletionRefusesClosedInput proves every read outside the accepted
// shape returns the exact zero scalarCompletion and the exact unwrapped
// errMismatch: a zero read, a tampered snapshot, duplicate grain, a drifted
// binding profile, a foreign sealed intent, a mismatched measure or identity
// ordinal, and an invalid access context, limits or read window.
func TestScalarCompletionRefusesClosedInput(t *testing.T) {
	foreignProfile := scalarPlanProfile(t, "other_orders", 3)
	foreignCatalog := scalarPlanCatalog(t, foreignProfile)
	foreignIntent := scalarPlanSeal(t, foreignCatalog, scalarPlanAggregateProposal(t, foreignProfile, "assigned_orders",
		scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))

	cases := []struct {
		name   string
		build  func(t *testing.T) ScalarRead
		mutate func(*ScalarRead)
	}{
		{"zero read", func(*testing.T) ScalarRead { return ScalarRead{} }, nil},
		{"duplicate grain", func(t *testing.T) ScalarRead {
			return scalarReceiptRead(t, [][]any{{"grain-a", "1.000000"}, {"grain-a", "2.000000"}})
		}, nil},
		{"tampered snapshot", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.snapshot.Rows[0].Canonical[0] ^= 0xff }},
		{"incomplete coverage", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.snapshot.CoverageComplete = false }},
		{"binding profile drift", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.binding.profile = foreignProfile }},
		{"foreign sealed intent", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.intent = foreignIntent }},
		{"measure ordinal mismatch", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.measureOrdinal = 1 }},
		{"identity ordinal mismatch", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.identityOrdinals = []int{2} }},
		{"zero access", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.access = database.AccessContext{} }},
		{"zero limits", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.limits = postgresqlquery.Limits{} }},
		{"zero started window", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.startedAt = time.Time{} }},
		{"reversed window", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) { read.context.completedAt = read.context.startedAt.Add(-time.Second) }},
		{"non-UTC ordered window", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) {
				zone := time.FixedZone("UTC+02:00", 2*60*60)
				read.context.startedAt = read.context.startedAt.In(zone)
				read.context.completedAt = read.context.completedAt.In(zone)
			}},
		{"non-UTC completed window", func(t *testing.T) ScalarRead { return scalarReceiptRead(t, scalarReceipt407Raw()) },
			func(read *ScalarRead) {
				read.context.completedAt = read.context.completedAt.In(time.FixedZone("UTC-05:00", -5*60*60))
			}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			read := test.build(t)
			if test.mutate != nil {
				test.mutate(&read)
			}
			completion, err := completeScalarRead(read)
			if err != errMismatch {
				t.Fatalf("refusal = %v, want the exact unwrapped errMismatch", err)
			}
			if completion != (scalarCompletion{}) {
				t.Fatalf("refusal = %+v, want the exact zero scalarCompletion", completion)
			}
		})
	}
}

// TestScalarSumMatchesSnapshotGate proves the explicit sum/snapshot coherence
// gate: a reducer proof that names a different snapshot hash or a different row
// count is refused, while the exact proof is accepted.
func TestScalarSumMatchesSnapshotGate(t *testing.T) {
	read := scalarReceiptRead(t, scalarReceipt407Raw())
	sum, err := reduceScalarSum(read)
	if err != nil {
		t.Fatalf("fixture reduction refused: %v", err)
	}
	if !scalarSumMatchesSnapshot(sum, read) {
		t.Fatal("the exact reducer proof was refused")
	}
	hashDrift := sum
	hashDrift.snapshotHash = ""
	if scalarSumMatchesSnapshot(hashDrift, read) {
		t.Fatal("a snapshot hash mismatch was accepted")
	}
	countDrift := sum
	countDrift.contributingRows++
	if scalarSumMatchesSnapshot(countDrift, read) {
		t.Fatal("a contributing-row mismatch was accepted")
	}
}

// TestScalarReceiptDigestBindsEverySemanticFamily proves a mutation of any
// major semantic receipt family changes the canonical digest, while the mutated
// receipt still validates against its own recomputed digest.
func TestScalarReceiptDigestBindsEverySemanticFamily(t *testing.T) {
	completion, err := completeScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fixture completion refused: %v", err)
	}
	base := completion.receipt

	// The schema is both the envelope version and the digest domain, so a
	// different schema changes the digest and is deliberately not a valid v1
	// receipt.
	schemaDrift := base.envelope
	schemaDrift.Schema = "knowvault.analyticsource.live-scalar-receipt.v2"
	schemaDigest, err := scalarReceiptDigest(schemaDrift)
	if err != nil {
		t.Fatalf("schema-drifted envelope refused: %v", err)
	}
	if schemaDigest == base.digest {
		t.Fatal("a schema mutation did not change the digest")
	}

	mutations := []struct {
		name   string
		mutate func(*scalarReceiptEnvelope)
	}{
		{"kind", func(value *scalarReceiptEnvelope) { value.Kind = "OTHER" }},
		{"window basis", func(value *scalarReceiptEnvelope) { value.WindowBasis = "OTHER" }},
		{"access organization", func(value *scalarReceiptEnvelope) { value.Access.OrganizationID = "other" }},
		{"access actor kind", func(value *scalarReceiptEnvelope) { value.Access.ActorKind = "HUMAN" }},
		{"workspace revision", func(value *scalarReceiptEnvelope) { value.Workspace.WorkspaceRevision++ }},
		{"workspace config hash", func(value *scalarReceiptEnvelope) { value.Workspace.WorkspaceConfigurationHash = "sha256:0" }},
		{"catalog revision", func(value *scalarReceiptEnvelope) { value.Catalog.CatalogRevision++ }},
		{"catalog hash", func(value *scalarReceiptEnvelope) { value.Catalog.CatalogHash = "sha256:0" }},
		{"profile version", func(value *scalarReceiptEnvelope) { value.Profile.Version++ }},
		{"profile hash", func(value *scalarReceiptEnvelope) { value.Profile.ProfileHash = "sha256:0" }},
		{"metric id", func(value *scalarReceiptEnvelope) { value.Metric.MeasureID = "other" }},
		{"metric reducer", func(value *scalarReceiptEnvelope) { value.Metric.Reducer = "COUNT_ROWS" }},
		{"metric unit", func(value *scalarReceiptEnvelope) { value.Metric.Unit = "other" }},
		{"metric null policy", func(value *scalarReceiptEnvelope) { value.Metric.NullPolicy = "REQUIRE_COMPLETE" }},
		{"source scope revision", func(value *scalarReceiptEnvelope) { value.Source.SourceScopeRevision++ }},
		{"connection id", func(value *scalarReceiptEnvelope) { value.Source.ConnectionID = "other" }},
		{"database identity", func(value *scalarReceiptEnvelope) { value.Source.DatabaseIdentity = "other" }},
		{"projection lineage", func(value *scalarReceiptEnvelope) { value.Source.ProjectionLineageID = "other" }},
		{"projection revision", func(value *scalarReceiptEnvelope) { value.Source.ProjectionRevision++ }},
		{"projection contract hash", func(value *scalarReceiptEnvelope) { value.Source.ProjectionContractHash = "sha256:0" }},
		{"exposed schema hash", func(value *scalarReceiptEnvelope) { value.Source.ExposedSchemaHash = "sha256:0" }},
		{"limits max rows", func(value *scalarReceiptEnvelope) { value.Limits.MaxRows++ }},
		{"limits statement timeout +1ns", func(value *scalarReceiptEnvelope) { value.Limits.StatementTimeoutNS++ }},
		{"limits transaction timeout +1ns", func(value *scalarReceiptEnvelope) { value.Limits.TransactionTimeoutNS++ }},
		{"snapshot hash", func(value *scalarReceiptEnvelope) { value.Snapshot.SnapshotHash = "sha256:0" }},
		{"snapshot coverage", func(value *scalarReceiptEnvelope) { value.Snapshot.CoverageComplete = false }},
		{"matched rows", func(value *scalarReceiptEnvelope) { value.Snapshot.MatchedRows++ }},
		{"contributing rows", func(value *scalarReceiptEnvelope) { value.Snapshot.ContributingRows++ }},
		{"result value", func(value *scalarReceiptEnvelope) { value.Result.Value = "3889" }},
		{"period time kind", func(value *scalarReceiptEnvelope) { value.Period.TimeKind = "ZONED_TIMESTAMP" }},
		{"period timezone", func(value *scalarReceiptEnvelope) { value.Period.ReportingTimezone = "Europe/Berlin" }},
		{"period start", func(value *scalarReceiptEnvelope) { value.Period.Start = "2026-09-09" }},
		{"period end", func(value *scalarReceiptEnvelope) { value.Period.EndExclusive = "2026-09-12" }},
		{"window started", func(value *scalarReceiptEnvelope) { value.Window.StartedAt = "2026-09-10T00:00:01Z" }},
		{"window completed", func(value *scalarReceiptEnvelope) { value.Window.CompletedAt = "2026-09-10T00:00:03Z" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := base.envelope
			mutation.mutate(&changed)
			digest, err := scalarReceiptDigest(changed)
			if err != nil {
				t.Fatalf("mutated envelope refused: %v", err)
			}
			if digest == base.digest {
				t.Fatal("a semantic envelope mutation did not change the digest")
			}
			mutated := scalarReceipt{envelope: changed, digest: digest}
			if !mutated.valid() {
				t.Fatal("the mutated receipt does not validate against its recomputed digest")
			}
		})
	}
}

// TestScalarReceiptSurfaceIsPrivate proves the receipt and its envelope expose
// no exported field on the result values, no subject count, credential or raw
// row type, no exported constructor or accessor method other than the opaque
// MarshalJSON, and that generic JSON renders both values as the empty object.
func TestScalarReceiptSurfaceIsPrivate(t *testing.T) {
	resultFields := [][2]string{}
	for index := 0; index < reflect.TypeOf(scalarCompletion{}).NumField(); index++ {
		field := reflect.TypeOf(scalarCompletion{}).Field(index)
		if field.IsExported() {
			t.Fatalf("scalarCompletion exposes the exported field %q", field.Name)
		}
		resultFields = append(resultFields, [2]string{field.Name, field.Type.String()})
	}
	wantFields := [][2]string{{"sum", "analyticsource.scalarSum"}, {"receipt", "analyticsource.scalarReceipt"}}
	if !reflect.DeepEqual(resultFields, wantFields) {
		t.Fatalf("scalarCompletion fields = %v, want %v", resultFields, wantFields)
	}

	forbiddenNames := []string{"subject", "credential", "secret", "dsn", "sql", "token"}
	deniedTypes := []reflect.Type{
		reflect.TypeOf(postgresqlquery.Row{}), reflect.TypeOf([]postgresqlquery.Row{}),
	}
	for _, surface := range []reflect.Type{reflect.TypeOf(scalarReceipt{}), reflect.TypeOf(scalarReceiptEnvelope{})} {
		for index := 0; index < surface.NumField(); index++ {
			field := surface.Field(index)
			name := strings.ToLower(field.Name)
			for _, forbidden := range forbiddenNames {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s field %s names forbidden member %q", surface, field.Name, forbidden)
				}
			}
			for _, denied := range deniedTypes {
				if field.Type == denied {
					t.Fatalf("%s field %s retains the raw row type %s", surface, field.Name, denied)
				}
			}
		}
	}
	methods := make([]string, 0, reflect.TypeOf(scalarReceipt{}).NumMethod())
	for index := 0; index < reflect.TypeOf(scalarReceipt{}).NumMethod(); index++ {
		methods = append(methods, reflect.TypeOf(scalarReceipt{}).Method(index).Name)
	}
	if !slices.Equal(methods, []string{"MarshalJSON"}) {
		t.Fatalf("scalarReceipt methods = %v, want exactly the opaque [MarshalJSON]", methods)
	}

	completion, err := completeScalarRead(scalarReceiptRead(t, scalarReceipt407Raw()))
	if err != nil {
		t.Fatalf("fixture completion refused: %v", err)
	}
	for name, value := range map[string]any{"completion": completion, "receipt": completion.receipt} {
		encoded, marshalErr := jsonv2.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("%s failed to marshal: %v", name, marshalErr)
		}
		if string(encoded) != "{}" {
			t.Fatalf("%s marshaled as %s, want the opaque {}", name, encoded)
		}
	}

	const filename = "scalar_receipt.go"
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
				t.Fatalf("scalar_receipt.go declares the exported function %s", typed.Name.Name)
			}
			functions = append(functions, typed.Name.Name)
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				if named, ok := specification.(*ast.TypeSpec); ok && named.Name.IsExported() {
					t.Fatalf("scalar_receipt.go declares the exported type %s", named.Name)
				}
			}
		}
	}
	slices.Sort(functions)
	wantFunctions := []string{"completeScalarRead", "newScalarReceipt", "scalarReceiptDigest", "scalarSumMatchesSnapshot"}
	if !slices.Equal(functions, wantFunctions) {
		t.Fatalf("scalar_receipt.go functions = %v, want %v", functions, wantFunctions)
	}
	slices.Sort(exportedMethods)
	if !slices.Equal(exportedMethods, []string{"MarshalJSON", "MarshalJSON"}) {
		t.Fatalf("scalar_receipt.go exported methods = %v, want only the two opaque MarshalJSON", exportedMethods)
	}
}
