package metricdef

import (
	"reflect"
	"testing"
	"time"
)

// R1-C2.6b-1 RED/GREEN tests: the optional v2 dataset binding must be an
// immutable value that the pure Series lifecycle carries and detaches
// everywhere. The zero binding stays the explicit legacy/unbound state.

func testBindingInput() DatasetBindingInput {
	return DatasetBindingInput{
		DatasetID:      "dataset-orders",
		ProfileVersion: 4,
		ProfileHash:    "sha256:" + repeatHex("a", 64),
		MeasureID:      "measure-net-revenue",
		Mode:           BindingModeLive,
	}
}

func boundSpec() Spec {
	spec := testSpec()
	binding, err := NewDatasetBinding(testBindingInput())
	if err != nil {
		panic(err)
	}
	spec.Binding = binding
	return spec
}

func repeatHex(ch string, count int) string {
	out := ""
	for i := 0; i < count; i++ {
		out += ch
	}
	return out
}

func approveFor(t *testing.T, series Series) Series {
	t.Helper()
	approved, err := series.Approve("owner-1", &fakeAuditor{}, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return approved
}

func TestDatasetBindingBoundConstructionCarriesEveryAccessor(t *testing.T) {
	input := testBindingInput()
	binding, err := NewDatasetBinding(input)
	if err != nil {
		t.Fatalf("NewDatasetBinding: %v", err)
	}

	if !binding.Bound() || binding.IsZero() || !binding.Valid() {
		t.Fatalf("a fully populated binding must be bound and valid: %+v", binding)
	}
	if binding.DatasetID() != "dataset-orders" {
		t.Fatalf("dataset id mismatch: %q", binding.DatasetID())
	}
	if binding.ProfileVersion() != 4 {
		t.Fatalf("profile version mismatch: %d", binding.ProfileVersion())
	}
	if binding.ProfileHash() != input.ProfileHash {
		t.Fatalf("profile hash mismatch: %q", binding.ProfileHash())
	}
	if binding.MeasureID() != "measure-net-revenue" {
		t.Fatalf("measure id mismatch: %q", binding.MeasureID())
	}
	if binding.Mode() != BindingModeLive || BindingModeLive != DatasetBindingMode("LIVE") {
		t.Fatalf("mode must be LIVE only: %q", binding.Mode())
	}
	if !ValidBindingMode(binding.Mode()) {
		t.Fatalf("LIVE must be a valid mode")
	}
	if ValidBindingMode(DatasetBindingMode("REPLAY")) || ValidBindingMode("") {
		t.Fatalf("the binding mode set must be closed to LIVE")
	}
}

func TestDatasetBindingZeroIsExplicitlyUnbound(t *testing.T) {
	var zero DatasetBinding
	if zero.Bound() || !zero.IsZero() || !zero.Valid() {
		t.Fatalf("zero binding must report unbound and valid: %+v", zero)
	}
	if zero.DatasetID() != "" || zero.ProfileVersion() != 0 || zero.ProfileHash() != "" ||
		zero.MeasureID() != "" || zero.Mode() != "" {
		t.Fatalf("zero binding accessors must stay zero: %+v", zero)
	}

	// The unbound zero value must survive the value round-trip and be accepted
	// by existing MetricDefinition specs so v1 rows stay representable.
	unbound, err := NewDatasetBinding(DatasetBindingInput{})
	if err != nil {
		t.Fatalf("zero input must be accepted as the legacy state: %v", err)
	}
	if unbound.Bound() {
		t.Fatalf("zero input must stay unbound")
	}

	series, err := NewSeries("metric-revenue", "ws-1", "owner-1", testSpec())
	if err != nil {
		t.Fatalf("unbound legacy spec must remain valid: %v", err)
	}
	if series.Current().Binding().Bound() {
		t.Fatalf("a legacy definition must report an unbound binding")
	}
}

func TestDatasetBindingRejectsIncompleteAndMalformedInput(t *testing.T) {
	valid := testBindingInput()

	missingDataset := valid
	missingDataset.DatasetID = ""
	if _, err := NewDatasetBinding(missingDataset); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("missing dataset id must be refused, got %v", err)
	}
	missingMeasure := valid
	missingMeasure.MeasureID = ""
	if _, err := NewDatasetBinding(missingMeasure); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("missing measure id must be refused, got %v", err)
	}
	for _, version := range []int64{0, -1} {
		badVersion := valid
		badVersion.ProfileVersion = version
		if _, err := NewDatasetBinding(badVersion); CodeOf(err) != CodeInvalidDefinition {
			t.Fatalf("profile version %d must be refused, got %v", version, err)
		}
	}
	partial := valid
	partial.Mode = ""
	if _, err := NewDatasetBinding(partial); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("a partially populated binding must be fully valid, got %v", err)
	}
	unknownMode := valid
	unknownMode.Mode = "REPLAY"
	if _, err := NewDatasetBinding(unknownMode); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("non-LIVE mode must be refused, got %v", err)
	}
	lowerMode := valid
	lowerMode.Mode = "live"
	if _, err := NewDatasetBinding(lowerMode); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("mode must be exactly LIVE, got %v", err)
	}

	for _, hash := range []string{
		"",
		"a" + repeatHex("b", 63),
		"sha256:" + repeatHex("a", 63),
		"sha256:" + repeatHex("a", 65),
		"sha256:" + repeatHex("A", 64),
		"sha512:" + repeatHex("a", 64),
		"sha256:" + repeatHex("a", 63) + "\xff",
		"sha256:" + "\xff" + repeatHex("a", 63),
	} {
		badHash := valid
		badHash.ProfileHash = hash
		if _, err := NewDatasetBinding(badHash); CodeOf(err) != CodeInvalidDefinition {
			t.Fatalf("hash %q must be refused, got %v", hash, err)
		}
	}

	for _, field := range []string{"dataset", "measure"} {
		for _, bad := range []string{"dataset\torders", " dataset", "dataset\x7f", "dataset\xff"} {
			broken := valid
			if field == "dataset" {
				broken.DatasetID = bad
			} else {
				broken.MeasureID = bad
			}
			if _, err := NewDatasetBinding(broken); CodeOf(err) != CodeInvalidDefinition {
				t.Fatalf("%s id %q must be refused, got %v", field, bad, err)
			}
		}
	}
}

func TestDatasetBindingIsImmutableAndDetachedFromConstruction(t *testing.T) {
	input := testBindingInput()
	binding, err := NewDatasetBinding(input)
	if err != nil {
		t.Fatalf("NewDatasetBinding: %v", err)
	}

	// Mutating the construction input must not reach the bound value.
	input.DatasetID = "dataset-other"
	input.ProfileVersion = 99
	input.ProfileHash = "sha256:" + repeatHex("f", 64)
	input.MeasureID = "measure-other"
	input.Mode = "REPLAY"

	if binding.DatasetID() != "dataset-orders" || binding.ProfileVersion() != 4 ||
		binding.ProfileHash() != testBindingInput().ProfileHash || binding.MeasureID() != "measure-net-revenue" ||
		binding.Mode() != BindingModeLive {
		t.Fatalf("binding must not alias the construction input: %+v", binding)
	}

	copied := binding
	if !reflect.DeepEqual(copied, binding) {
		t.Fatalf("binding must be comparable by value")
	}
}

func TestSeriesLifecycleCarriesAndDetachesBinding(t *testing.T) {
	series, err := NewSeries("metric-revenue", "ws-1", "owner-1", boundSpec())
	if err != nil {
		t.Fatalf("NewSeries with a bound spec: %v", err)
	}
	if !series.Current().Binding().Bound() {
		t.Fatalf("NewSeries must carry the binding, got %+v", series.Current().Binding())
	}
	if series.Current().Binding().ProfileHash() != testBindingInput().ProfileHash {
		t.Fatalf("carried binding mismatch: %+v", series.Current().Binding())
	}

	edited, err := series.Supersede(boundSpec())
	if err != nil {
		t.Fatalf("DRAFT Supersede: %v", err)
	}
	if edited.Highest() != 1 || edited.Current().Version() != 1 {
		t.Fatalf("a draft edit must stay version 1, got %d", edited.Highest())
	}
	if !edited.Current().Binding().Bound() {
		t.Fatalf("a draft edit must preserve the binding")
	}
	if !reflect.DeepEqual(edited.Current().Binding(), series.Current().Binding()) {
		t.Fatalf("a draft edit must not change the binding")
	}

	// Detaching the binding inside a returned version must not reach the series.
	detached := edited.Versions()
	detached[0].binding = DatasetBinding{}
	again, _ := edited.Version(1)
	if !again.Binding().Bound() {
		t.Fatalf("Versions() must return a detached binding")
	}

	// A binding change on an APPROVED version must issue a new version and
	// leave the approved binding untouched.
	approved := approveFor(t, series)
	if !approved.Current().Binding().Bound() || approved.Current().Status() != StatusApproved {
		t.Fatalf("approval must keep the binding on the approved version")
	}
	changed := boundSpec()
	changed.Binding, err = NewDatasetBinding(DatasetBindingInput{
		DatasetID:      "dataset-invoices",
		ProfileVersion: 7,
		ProfileHash:    "sha256:" + repeatHex("b", 64),
		MeasureID:      "measure-gross-revenue",
		Mode:           BindingModeLive,
	})
	if err != nil {
		t.Fatalf("NewDatasetBinding changed: %v", err)
	}

	superseded, err := approved.Supersede(changed)
	if err != nil {
		t.Fatalf("APPROVED Supersede: %v", err)
	}
	if superseded.Highest() != 2 || superseded.Current().Version() != 2 || superseded.Current().Status() != StatusDraft {
		t.Fatalf("changing an approved binding must create DRAFT version 2, got %+v", superseded.Current())
	}
	if superseded.Current().Binding().DatasetID() != "dataset-invoices" ||
		superseded.Current().Binding().ProfileVersion() != 7 {
		t.Fatalf("new draft must carry the changed binding: %+v", superseded.Current().Binding())
	}
	original, ok := superseded.Version(1)
	if !ok {
		t.Fatalf("approved version 1 must remain addressable")
	}
	if original.Status() != StatusApproved || original.Binding().DatasetID() != "dataset-orders" ||
		original.Binding().ProfileVersion() != 4 || original.Binding().ProfileHash() != testBindingInput().ProfileHash {
		t.Fatalf("approved binding must never change: %+v", original.Binding())
	}

	// ImportVersion must carry and detach the binding too.
	imported, err := superseded.ImportVersion(5, changed)
	if err != nil {
		t.Fatalf("ImportVersion(5): %v", err)
	}
	versionFive, ok := imported.Version(5)
	if !ok || versionFive.Binding().DatasetID() != "dataset-invoices" || !versionFive.Binding().Bound() {
		t.Fatalf("ImportVersion must carry the binding: %+v", versionFive.Binding())
	}
	importedVersions := imported.Versions()
	for index := range importedVersions {
		importedVersions[index].binding = DatasetBinding{}
	}
	stillFive, _ := imported.Version(5)
	if !stillFive.Binding().Bound() {
		t.Fatalf("ImportVersion binding must be detached in Versions()")
	}

	// Approving an unbound legacy value must still work: no approval rule
	// change in this card.
	legacy, err := NewSeries("metric-legacy", "ws-1", "owner-1", testSpec())
	if err != nil {
		t.Fatalf("NewSeries legacy: %v", err)
	}
	legacyApproved, err := legacy.Approve("owner-1", &fakeAuditor{}, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC))
	if err != nil {
		t.Fatalf("approving an unbound legacy value must still succeed: %v", err)
	}
	if legacyApproved.Current().Binding().Bound() || !legacyApproved.Current().Approved() {
		t.Fatalf("unbound legacy approval must not invent a binding")
	}
}
