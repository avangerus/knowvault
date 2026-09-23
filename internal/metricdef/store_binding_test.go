package metricdef

import (
	"strings"
	"testing"
)

// R1-C2.6b-2b RED/GREEN tests: the unexported bindingFromColumns decoder is the
// single SQL-to-DatasetBinding gate. It must recognise exactly the all-NULL
// legacy shape, and fail closed with the one content-free persistence error for
// any other ill-shaped row, including the all-present zero value that
// NewDatasetBinding would otherwise accept as "legacy zero".

// Local pointer helpers keep the decoder matrix readable; the tests import
// neither pgx nor database, so they exercise the pure column decoder directly.

func bindingStringPtr(value string) *string { return &value }

func bindingInt64Ptr(value int64) *int64 { return &value }

func testBindingFromColumns(datasetID *string, profileVersion *int64, profileHash, measureID, executionMode *string) (DatasetBinding, error) {
	return bindingFromColumns(datasetID, profileVersion, profileHash, measureID, executionMode)
}

// bindingErrorIsContentFree asserts err is exactly the fixed persistence
// sentinel, so no persisted value can leak through the error text.
func bindingErrorIsContentFree(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("bindingFromColumns error = nil, want content-free persistence error")
	}
	if err.Error() != "METRICDEFINITION_PERSISTENCE_INVALID" {
		t.Fatalf("bindingFromColumns error = %q, want %q", err.Error(), "METRICDEFINITION_PERSISTENCE_INVALID")
	}
	if err != errMetricDefinitionPersistenceInvalid {
		t.Fatalf("bindingFromColumns error identity = %v, want the shared persistence sentinel", err)
	}
}

func TestBindingFromColumnsAllNullIsLegacyZero(t *testing.T) {
	binding, err := testBindingFromColumns(nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("all-NULL bindingFromColumns error = %v, want nil", err)
	}
	if !binding.IsZero() {
		t.Fatalf("all-NULL bindingFromColumns = %+v, want zero binding", binding)
	}
}

func TestBindingFromColumnsAllPresentValidIsExact(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	binding, err := testBindingFromColumns(
		bindingStringPtr("dataset_unit"),
		bindingInt64Ptr(7),
		bindingStringPtr(hash),
		bindingStringPtr("measure_unit"),
		bindingStringPtr("LIVE"),
	)
	if err != nil {
		t.Fatalf("valid bindingFromColumns error = %v, want nil", err)
	}
	if binding.IsZero() {
		t.Fatalf("valid bindingFromColumns = zero, want populated binding")
	}
	if binding.DatasetID() != "dataset_unit" {
		t.Fatalf("DatasetID = %q, want %q", binding.DatasetID(), "dataset_unit")
	}
	if binding.ProfileVersion() != 7 {
		t.Fatalf("ProfileVersion = %d, want 7", binding.ProfileVersion())
	}
	if binding.ProfileHash() != hash {
		t.Fatalf("ProfileHash = %q, want %q", binding.ProfileHash(), hash)
	}
	if binding.MeasureID() != "measure_unit" {
		t.Fatalf("MeasureID = %q, want %q", binding.MeasureID(), "measure_unit")
	}
	if binding.Mode() != BindingModeLive {
		t.Fatalf("Mode = %q, want %q", binding.Mode(), BindingModeLive)
	}
}

func TestBindingFromColumnsAllPresentZeroIsRejected(t *testing.T) {
	binding, err := testBindingFromColumns(
		bindingStringPtr(""),
		bindingInt64Ptr(0),
		bindingStringPtr(""),
		bindingStringPtr(""),
		bindingStringPtr(""),
	)
	bindingErrorIsContentFree(t, err)
	if !binding.IsZero() {
		t.Fatalf("rejected all-present zero = %+v, want zero binding", binding)
	}
}

func TestBindingFromColumnsPartialNullIsRejected(t *testing.T) {
	hash := "sha256:" + strings.Repeat("b", 64)
	partials := []struct {
		name string
		call func() (DatasetBinding, error)
	}{
		{"dataset-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(nil, bindingInt64Ptr(7), bindingStringPtr(hash), bindingStringPtr("measure_unit"), bindingStringPtr("LIVE"))
		}},
		{"version-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(bindingStringPtr("dataset_unit"), nil, bindingStringPtr(hash), bindingStringPtr("measure_unit"), bindingStringPtr("LIVE"))
		}},
		{"hash-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(bindingStringPtr("dataset_unit"), bindingInt64Ptr(7), nil, bindingStringPtr("measure_unit"), bindingStringPtr("LIVE"))
		}},
		{"measure-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(bindingStringPtr("dataset_unit"), bindingInt64Ptr(7), bindingStringPtr(hash), nil, bindingStringPtr("LIVE"))
		}},
		{"mode-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(bindingStringPtr("dataset_unit"), bindingInt64Ptr(7), bindingStringPtr(hash), bindingStringPtr("measure_unit"), nil)
		}},
		{"dataset-and-version-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(nil, nil, bindingStringPtr(hash), bindingStringPtr("measure_unit"), bindingStringPtr("LIVE"))
		}},
		{"measure-and-mode-null", func() (DatasetBinding, error) {
			return testBindingFromColumns(bindingStringPtr("dataset_unit"), bindingInt64Ptr(7), bindingStringPtr(hash), nil, nil)
		}},
	}
	for _, tc := range partials {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			binding, err := tc.call()
			bindingErrorIsContentFree(t, err)
			if !binding.IsZero() {
				t.Fatalf("partial-NULL %s = %+v, want zero binding", tc.name, binding)
			}
		})
	}
}

func TestBindingFromColumnsMalformedAllPresentIsRejected(t *testing.T) {
	malformed := []struct {
		name           string
		datasetID      string
		profileVersion int64
		profileHash    string
		measureID      string
		mode           string
	}{
		{"bad-hash", "dataset_unit", 7, "sha256:" + strings.Repeat("a", 63), "measure_unit", "LIVE"},
		{"bad-hash-prefix", "dataset_unit", 7, "sha512:" + strings.Repeat("a", 64), "measure_unit", "LIVE"},
		{"bad-mode", "dataset_unit", 7, "sha256:" + strings.Repeat("a", 64), "measure_unit", "REPLAY"},
		{"zero-version", "dataset_unit", 0, "sha256:" + strings.Repeat("a", 64), "measure_unit", "LIVE"},
		{"empty-dataset", "", 7, "sha256:" + strings.Repeat("a", 64), "measure_unit", "LIVE"},
	}
	for _, tc := range malformed {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			binding, err := testBindingFromColumns(
				bindingStringPtr(tc.datasetID),
				bindingInt64Ptr(tc.profileVersion),
				bindingStringPtr(tc.profileHash),
				bindingStringPtr(tc.measureID),
				bindingStringPtr(tc.mode),
			)
			bindingErrorIsContentFree(t, err)
			if !binding.IsZero() {
				t.Fatalf("malformed %s = %+v, want zero binding", tc.name, binding)
			}
		})
	}
}
