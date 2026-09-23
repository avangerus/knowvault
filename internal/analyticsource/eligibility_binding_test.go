package analyticsource

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// eligibilityFixture pairs the sealed fixture profile with its derived required
// inventory and the exact trusted facts that satisfy the matcher.
func eligibilityFixture(t *testing.T) (analytic.DatasetProfile, matchFixture) {
	t.Helper()
	profile := sealedFixtureProfile(t, false)
	columns, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("fixture inventory refused: %v", err)
	}
	return profile, governedMatchFixture(t, profile, columns)
}

// sealedEligibility constructs the eligibility binding for the exact fixture
// facts.
func sealedEligibility(t *testing.T) (eligibilityBinding, matchFixture, analytic.DatasetProfile) {
	t.Helper()
	profile, facts := eligibilityFixture(t)
	value, err := newEligibilityBinding(profile, facts.source, facts.exposure)
	if err != nil {
		t.Fatalf("exact fixture facts refused: %v", err)
	}
	return value, facts, profile
}

// assertEligibilityRefusal requires the exact zero eligibilityBinding and the
// one content-free sentinel.
func assertEligibilityRefusal(t *testing.T, value eligibilityBinding, err error) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refused construction returned %v, want errMismatch", err)
	}
	if value.profile.Hash() != "" || value.binding != (bindingFacts{}) ||
		value.execution != (executionFacts{}) || value.seal != ([32]byte{}) {
		t.Fatal("refusal did not return the exact zero eligibilityBinding")
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
}

// retainedDrift writes a value the governed fixture cannot already carry into
// one retained common tuple field, using the matcher's own field inventory.
func retainedDrift(field commonBindingField, binding *bindingFacts) {
	switch field.kind {
	case kindRevision:
		field.setRevision(binding, maxBindingRevision)
	case kindHash:
		field.setText(binding, validHash("0"))
	case kindIdentifier:
		field.setText(binding, "eligibility_drift")
	default:
		field.setText(binding, "eligibility-drift")
	}
}

// alternateFixtureProfile reseals the fixture under the same key and source
// with different business semantics, so only the profile hash changes.
func alternateFixtureProfile(t *testing.T, profile analytic.DatasetProfile) analytic.DatasetProfile {
	t.Helper()
	spec := profile.Spec()
	semantics := spec.Semantics.Values()
	semantics.DatasetLabel = "Alternate fixture dataset"
	changed, err := analytic.NewProfileSemantics(semantics)
	if err != nil {
		t.Fatalf("alternate semantics rejected: %v", err)
	}
	spec.Semantics = changed
	alternate, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("alternate profile rejected: %v", err)
	}
	return alternate
}

// reversedColumns returns the inventory in the opposite order without sharing a
// backing array with the input.
func reversedColumns(columns []string) []string {
	flipped := make([]string, 0, len(columns))
	for index := len(columns) - 1; index >= 0; index-- {
		flipped = append(flipped, columns[index])
	}
	return flipped
}

func TestEligibilityBindingConstructsFromExactFacts(t *testing.T) {
	value, facts, profile := sealedEligibility(t)
	if !value.profile.Valid() {
		t.Fatal("stored profile is not valid")
	}
	if value.profile.Key() != profile.Key() || value.profile.Hash() != profile.Hash() {
		t.Fatal("stored profile key or hash differs from the input profile")
	}
	if value.binding != facts.source.binding {
		t.Fatal("stored tuple is not the matched common binding")
	}
	wantExecution := executionFacts{
		projectionLineageID:    facts.source.projectionLineageID,
		projectionRevision:     facts.source.projectionRevision,
		projectionContractHash: facts.source.projectionContractHash,
		exposedSchemaRevision:  facts.exposure.exposedSchemaRevision,
		exposedSchemaHash:      facts.exposure.exposedSchemaHash,
	}
	if value.execution != wantExecution {
		t.Fatalf("execution = %+v, want the exact five retained execution facts", value.execution)
	}
	if value.seal == ([32]byte{}) {
		t.Fatal("constructed binding carries a zero seal")
	}
	if !value.valid() {
		t.Fatal("constructed binding does not validate")
	}
}

func TestEligibilityBindingRefusesMismatchedFacts(t *testing.T) {
	profile, exact := eligibilityFixture(t)
	commonDrift := exact
	commonDrift.source.binding.connectionID = alternateIdentity
	commonDrift.exposure.binding.connectionID = alternateIdentity
	projectionDrift := exact
	projectionDrift.source.projectionRevision++
	exposureDrift := exact
	exposureDrift.exposure.exposedSchemaHash = validHash("0")
	exposureDisabled := exact
	exposureDisabled.exposure.liveEnabled = false
	missingHidden := exact
	missingHidden.source.columns = withoutColumn(missingHidden.source.columns, "numerator_column")
	refusals := []struct {
		name    string
		fixture matchFixture
	}{
		{"common tuple mismatch", commonDrift},
		{"projection drift", projectionDrift},
		{"exposure drift", exposureDrift},
		{"exposure disabled", exposureDisabled},
		{"missing hidden required column", missingHidden},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name, func(t *testing.T) {
			value, err := newEligibilityBinding(profile, refusal.fixture.source, refusal.fixture.exposure)
			assertEligibilityRefusal(t, value, err)
			for _, disclosure := range fixtureDisclosures(profile) {
				if strings.Contains(err.Error(), disclosure) {
					t.Fatalf("refusal discloses %q", disclosure)
				}
			}
		})
	}
	t.Run("zero profile", func(t *testing.T) {
		value, err := newEligibilityBinding(analytic.DatasetProfile{}, exact.source, exact.exposure)
		assertEligibilityRefusal(t, value, err)
	})
}

func TestEligibilityBindingDetectsRetainedFieldDrift(t *testing.T) {
	fields := commonBindingFields()
	if len(fields) != bindingFieldCount {
		t.Fatalf("common binding inventory has %d fields, want %d", len(fields), bindingFieldCount)
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			value, _, _ := sealedEligibility(t)
			retainedDrift(field, &value.binding)
			if value.valid() {
				t.Fatal("changed retained common tuple field still validates")
			}
			if value.equal(value) {
				t.Fatal("changed retained common tuple field is still self-equal")
			}
		})
	}
}

func TestEligibilityBindingDetectsRetainedExecutionDrift(t *testing.T) {
	drifts := []struct {
		name   string
		mutate func(*executionFacts)
	}{
		{"projection lineage", func(execution *executionFacts) {
			execution.projectionLineageID = "eligibility-execution-drift"
		}},
		{"projection revision", func(execution *executionFacts) { execution.projectionRevision++ }},
		{"projection contract hash", func(execution *executionFacts) {
			execution.projectionContractHash = validHash("0")
		}},
		{"exposed schema revision", func(execution *executionFacts) { execution.exposedSchemaRevision++ }},
		{"exposed schema hash", func(execution *executionFacts) { execution.exposedSchemaHash = validHash("0") }},
	}
	for _, drift := range drifts {
		t.Run(drift.name, func(t *testing.T) {
			value, _, _ := sealedEligibility(t)
			drift.mutate(&value.execution)
			// A self-consistent seal proves the refusal cannot rest on the seal alone.
			value.seal = eligibilityBindingSeal(value.profile, value.binding, value.execution)
			if value.valid() {
				t.Fatal("changed retained execution fact still validates")
			}
			if value.equal(value) {
				t.Fatal("changed retained execution fact is still self-equal")
			}
		})
	}
}

func TestEligibilityBindingDetectsStoredProfileSubstitution(t *testing.T) {
	value, _, profile := sealedEligibility(t)
	substituted := alternateFixtureProfile(t, profile)
	if substituted.Key() != profile.Key() || substituted.Source() != profile.Source() ||
		substituted.Hash() == profile.Hash() {
		t.Fatal("alternate profile is not a same-key same-source reseal")
	}
	value.profile = substituted
	if value.valid() {
		t.Fatal("substituted profile still validates")
	}
}

func TestEligibilityBindingValidRejectsForgedMembers(t *testing.T) {
	forgeries := []struct {
		name  string
		forge func(*eligibilityBinding)
	}{
		{"zero profile", func(value *eligibilityBinding) { value.profile = analytic.DatasetProfile{} }},
		{"malformed binding", func(value *eligibilityBinding) { value.binding.workspaceID = "" }},
		{"source scope id", func(value *eligibilityBinding) { value.binding.sourceScopeID = "forged-scope" }},
		{"connection id", func(value *eligibilityBinding) { value.binding.connectionID = "forged-connection" }},
		{"database identity", func(value *eligibilityBinding) { value.binding.databaseIdentity = "forged-database" }},
		{"schema", func(value *eligibilityBinding) { value.binding.schemaName = "forged_schema" }},
		{"relation", func(value *eligibilityBinding) { value.binding.relationName = "forged_relation" }},
	}
	for _, forgery := range forgeries {
		t.Run(forgery.name, func(t *testing.T) {
			value, _, _ := sealedEligibility(t)
			forgery.forge(&value)
			// A self-consistent seal proves the refusal cannot rest on the seal alone.
			value.seal = eligibilityBindingSeal(value.profile, value.binding, value.execution)
			if value.valid() {
				t.Fatal("forged binding still validates")
			}
		})
	}
}

func TestEligibilityBindingDetectsSealByteMutation(t *testing.T) {
	checked := 0
	for index := 0; index < len(eligibilityBinding{}.seal); index++ {
		value, _, _ := sealedEligibility(t)
		value.seal[index] ^= 0xff
		if value.valid() {
			t.Fatalf("seal byte %d mutation still validates", index)
		}
		checked++
	}
	if checked != 32 {
		t.Fatalf("checked %d seal bytes, want 32", checked)
	}
}

func TestEligibilityBindingEqualityRequiresValidExactValues(t *testing.T) {
	first, facts, profile := sealedEligibility(t)
	second, _, _ := sealedEligibility(t)
	if first.seal != second.seal {
		t.Fatal("identical facts produced different seals")
	}
	if !first.equal(second) || !second.equal(first) {
		t.Fatal("independently constructed identical values are not equal")
	}

	alternateValue, err := newEligibilityBinding(alternateFixtureProfile(t, profile), facts.source, facts.exposure)
	if err != nil || !alternateValue.valid() {
		t.Fatalf("same-key alternate profile refused: %v", err)
	}
	if alternateValue.profile.Hash() == first.profile.Hash() {
		t.Fatal("alternate profile carries the same hash")
	}
	if first.equal(alternateValue) || alternateValue.equal(first) {
		t.Fatal("same-key different-semantics profile compared equal")
	}

	changedRevision := facts
	changedRevision.source.binding.workspaceRevision = maxBindingRevision
	changedRevision.exposure.binding = changedRevision.source.binding
	revisionValue, err := newEligibilityBinding(profile, changedRevision.source, changedRevision.exposure)
	if err != nil || !revisionValue.valid() {
		t.Fatalf("changed revision facts refused: %v", err)
	}
	if first.equal(revisionValue) || revisionValue.equal(first) {
		t.Fatal("changed binding revision compared equal")
	}

	changedHash := facts
	changedHash.source.binding.workspaceConfigurationHash = validHash("0")
	changedHash.exposure.binding = changedHash.source.binding
	hashValue, err := newEligibilityBinding(profile, changedHash.source, changedHash.exposure)
	if err != nil || !hashValue.valid() {
		t.Fatalf("changed hash facts refused: %v", err)
	}
	if first.equal(hashValue) || hashValue.equal(first) {
		t.Fatal("changed binding hash compared equal")
	}

	// Independently constructed exact execution facts compare equal, while
	// projection and exposure execution drift never does.
	executionDrift := first
	executionDrift.execution.projectionRevision++
	executionDrift.seal = eligibilityBindingSeal(executionDrift.profile, executionDrift.binding, executionDrift.execution)
	if executionDrift.valid() {
		t.Fatal("drifted projection revision still validates")
	}
	if first.equal(executionDrift) || executionDrift.equal(first) {
		t.Fatal("drifted projection revision compared equal")
	}
	exposureDrift := first
	exposureDrift.execution.exposedSchemaHash = validHash("0")
	exposureDrift.seal = eligibilityBindingSeal(exposureDrift.profile, exposureDrift.binding, exposureDrift.execution)
	if exposureDrift.valid() {
		t.Fatal("drifted exposure hash still validates")
	}
	if first.equal(exposureDrift) || exposureDrift.equal(first) {
		t.Fatal("drifted exposure hash compared equal")
	}

	var zero eligibilityBinding
	if zero.equal(zero) || first.equal(zero) || zero.equal(first) {
		t.Fatal("zero binding compared equal")
	}
	invalid := first
	invalid.seal[0] ^= 0xff
	if invalid.equal(invalid) || first.equal(invalid) || invalid.equal(first) {
		t.Fatal("invalid binding compared equal")
	}
}

func TestEligibilityBindingIgnoresExtraColumnsAndInventoryOrder(t *testing.T) {
	reference, facts, profile := sealedEligibility(t)

	extended := facts
	extended.source.columns = append(extended.source.columns, "internal_note", "_audit$1")
	extended.exposure.columns = append(extended.exposure.columns, "unapproved_extra")
	extraValue, err := newEligibilityBinding(profile, extended.source, extended.exposure)
	if err != nil {
		t.Fatalf("extra valid fact columns refused: %v", err)
	}
	if !extraValue.equal(reference) {
		t.Fatal("extra valid fact columns changed the binding")
	}

	reordered := facts
	reordered.source.columns = reversedColumns(reordered.source.columns)
	reordered.exposure.columns = reversedColumns(reordered.exposure.columns)
	orderedValue, err := newEligibilityBinding(profile, reordered.source, reordered.exposure)
	if err != nil {
		t.Fatalf("reordered fact inventory refused: %v", err)
	}
	if !orderedValue.equal(reference) {
		t.Fatal("fact inventory order changed the binding")
	}
}

func TestEligibilityBindingRetainsNoCallerState(t *testing.T) {
	value, facts, profile := sealedEligibility(t)
	seal, binding, execution, hash := value.seal, value.binding, value.execution, value.profile.Hash()
	profileHash := profile.Hash()

	facts.source.binding.workspaceID = "mutated_workspace"
	facts.exposure.binding.workspaceID = "mutated_workspace"
	facts.source.columns[0] = "mutated_column"
	facts.exposure.columns[0] = "mutated_column"
	facts.required[0] = "mutated_column"
	detachedFields := profile.Fields()
	detachedFields[0], detachedFields[1] = detachedFields[1], detachedFields[0]
	detachedMeasures := profile.Measures()
	detachedMeasures[0] = detachedMeasures[len(detachedMeasures)-1]
	spec := profile.Spec()
	spec.Fields[0], spec.Measures[0] = spec.Fields[1], spec.Measures[1]
	ownedFields := value.profile.Fields()
	ownedFields[0] = ownedFields[1]
	ownedSpec := value.profile.Spec()
	ownedSpec.Fields[0] = ownedSpec.Fields[1]

	if value.seal != seal || value.binding != binding || value.execution != execution || value.profile.Hash() != hash {
		t.Fatal("caller mutation changed the stored binding")
	}
	if !value.valid() {
		t.Fatal("caller mutation invalidated the stored binding")
	}
	if profile.Hash() != profileHash || !profile.Valid() {
		t.Fatal("returned DTO mutation changed the sealed input profile")
	}
}

func TestEligibilityBindingPrivateSurfaceIsClosed(t *testing.T) {
	valueType := reflect.TypeOf(eligibilityBinding{})
	expected := []struct {
		name string
		kind reflect.Type
	}{
		{"profile", reflect.TypeOf(analytic.DatasetProfile{})},
		{"binding", reflect.TypeOf(bindingFacts{})},
		{"execution", reflect.TypeOf(executionFacts{})},
		{"seal", reflect.TypeOf([32]byte{})},
	}
	if valueType.NumField() != len(expected) {
		t.Fatalf("eligibilityBinding has %d fields, want %d", valueType.NumField(), len(expected))
	}
	for index, want := range expected {
		field := valueType.Field(index)
		if field.Name != want.name || field.Type != want.kind {
			t.Fatalf("field %d is %s %s, want %s %s", index, field.Name, field.Type, want.name, want.kind)
		}
		if field.PkgPath == "" {
			t.Fatalf("field %s is exported", field.Name)
		}
	}
	if valueType.NumMethod() != 0 {
		t.Fatalf("eligibilityBinding exposes %d exported methods", valueType.NumMethod())
	}
	var value any = eligibilityBinding{}
	if _, ok := value.(json.Marshaler); ok {
		t.Fatal("eligibilityBinding implements json.Marshaler")
	}
	if _, ok := value.(encoding.TextMarshaler); ok {
		t.Fatal("eligibilityBinding implements encoding.TextMarshaler")
	}
	if _, ok := value.(fmt.Stringer); ok {
		t.Fatal("eligibilityBinding implements fmt.Stringer")
	}
	if _, ok := value.(error); ok {
		t.Fatal("eligibilityBinding implements error")
	}
	forbidden := []string{
		"credential", "secret", "dsn", "sql", "row", "result", "token",
		"capability", "authorization", "envelope",
	}
	for index, want := range expected {
		member := strings.ToLower(want.name + " " + valueType.Field(index).Type.String())
		for _, text := range forbidden {
			if strings.Contains(member, text) {
				t.Fatalf("field %s carries a forbidden member: %s", want.name, text)
			}
		}
	}
}
