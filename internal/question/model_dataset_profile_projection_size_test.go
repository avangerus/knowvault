package question

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// TestProjectModelDatasetProfileRespectsCanonicalSize freezes the model-facing
// projection boundary at 256 KiB, including its projection digest. The
// oversized profile is constructed through the public analytic constructors so
// that the rejection belongs to the projection boundary rather than profile
// validation.
func TestProjectModelDatasetProfileRespectsCanonicalSize(t *testing.T) {
	normal, err := projectModelDatasetProfile(newProjectionFixtureProfile(t))
	if err != nil {
		t.Fatalf("projectModelDatasetProfile(normal) returned error: %v", err)
	}
	normalCanonical, err := canon.CanonicalJSON(normal)
	if err != nil {
		t.Fatalf("canonicalize normal projection: %v", err)
	}
	if !strings.Contains(string(normalCanonical), `"projection_digest"`) {
		t.Fatalf("canonical normal projection does not include projection_digest: %s", normalCanonical)
	}
	if len(normalCanonical) > modelDatasetProfileMaxBytes {
		t.Fatalf("normal canonical projection bytes = %d, want <= %d", len(normalCanonical), modelDatasetProfileMaxBytes)
	}

	oversizedProfile := newOversizedProjectionProfile(t)
	if !oversizedProfile.Valid() {
		t.Fatal("oversized projection fixture is not a valid analytic profile")
	}
	oversized, err := projectModelDatasetProfile(oversizedProfile)
	if !reflect.DeepEqual(oversized, modelDatasetProfile{}) {
		t.Fatalf("oversized projection = %+v, want zero DTO", oversized)
	}
	if err == nil {
		t.Fatal("projectModelDatasetProfile(oversized) returned nil error")
	}
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", CodeOf(err), CodeInvalid)
	}
	if err.Error() != string(CodeInvalid) {
		t.Fatalf("err.Error() = %q, want %q", err.Error(), string(CodeInvalid))
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}

// newOversizedProjectionProfile creates the largest permitted field set and
// fills every human-facing field with valid bounded content. Eight distinct
// aliases per field make the complete model projection materially exceed the
// fixed cap while retaining a small, deterministic fixture construction.
func newOversizedProjectionProfile(t *testing.T) analytic.DatasetProfile {
	t.Helper()

	spec := newProjectionFixtureProfile(t).Spec()
	const fieldCount = 256
	fields := make([]analytic.FieldSpec, 0, fieldCount)
	semanticsFields := make([]analytic.FieldSemanticsInput, 0, fieldCount)
	longDescription := strings.Repeat("D", 1024)
	longNullMeaning := strings.Repeat("N", 1024)
	for index := 0; index < fieldCount; index++ {
		token := projectionSizeFieldToken(index)
		physical := projectionSizePhysicalName(index)
		field := newProjectionFixtureField(
			t, token, physical, index+1, analytic.ScalarNumeric, analytic.PhysicalPGNumeric,
			false, true, true, true,
		)
		fields = append(fields, field)

		label := projectionSizeFieldLabel(index)
		aliases := make([]string, 0, 8)
		for aliasIndex := 0; aliasIndex < 8; aliasIndex++ {
			aliases = append(aliases, projectionSizeAlias(index, aliasIndex))
		}
		semanticsFields = append(semanticsFields, analytic.FieldSemanticsInput{
			Token:       token,
			Label:       label,
			Description: longDescription,
			NullMeaning: longNullMeaning,
			Aliases:     aliases,
		})
	}

	measureInput := spec.Measures[0].Values()
	measureInput.NumeratorField = projectionSizeFieldToken(0)
	measure, err := analytic.NewMeasureSpec(measureInput)
	if err != nil {
		t.Fatalf("rebuild oversized measure: %v", err)
	}

	semanticsInput := spec.Semantics.Values()
	semanticsInput.DatasetLabel = "Oversized projection fixture"
	semanticsInput.DatasetDescription = strings.Repeat("S", 1024)
	semanticsInput.Fields = semanticsFields
	semanticsInput.Measures = []analytic.MeasureSemanticsInput{{
		ID:          measureInput.ID,
		Label:       strings.Repeat("M", 160),
		Description: strings.Repeat("Q", 1024),
		Aliases: []string{
			"measure_alias_00", "measure_alias_01", "measure_alias_02", "measure_alias_03",
			"measure_alias_04", "measure_alias_05", "measure_alias_06", "measure_alias_07",
		},
	}}
	semantics, err := analytic.NewProfileSemantics(semanticsInput)
	if err != nil {
		t.Fatalf("build oversized semantics: %v", err)
	}

	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description:     strings.Repeat("G", 1024),
		KeyFields:       []string{projectionSizeFieldToken(0)},
		DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatalf("build oversized grain: %v", err)
	}

	spec.Fields = fields
	spec.Measures = []analytic.MeasureSpec{measure}
	spec.Semantics = semantics
	spec.Grain = grain
	profile, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("build oversized profile: %v", err)
	}
	return profile
}

func projectionSizeFieldToken(index int) string {
	return "field_" + threeDigit(index)
}

func projectionSizePhysicalName(index int) string {
	return "field_" + threeDigit(index) + "_physical"
}

func projectionSizeFieldLabel(index int) string {
	return "Field label " + threeDigit(index)
}

func projectionSizeAlias(fieldIndex, aliasIndex int) string {
	return "alias_" + threeDigit(fieldIndex) + "_" + threeDigit(aliasIndex) + "_" + strings.Repeat("a", 140)
}

func threeDigit(value int) string {
	if value < 10 {
		return "00" + string(rune('0'+value))
	}
	if value < 100 {
		return "0" + string(rune('0'+value/10)) + string(rune('0'+value%10))
	}
	return string(rune('0'+value/100)) + string(rune('0'+(value/10)%10)) + string(rune('0'+value%10))
}
