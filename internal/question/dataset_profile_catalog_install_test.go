package question

import (
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// TestEnableDatasetProfileCatalogInstallsFirstValidValue is the valid-install
// arm: the first valid catalog is stored sealed and returns no error.
func TestEnableDatasetProfileCatalogInstallsFirstValidValue(t *testing.T) {
	service := &Service{}
	catalog := datasetProfileCatalogInstallFixture(t, 1)

	if err := service.EnableDatasetProfileCatalog(catalog); err != nil {
		t.Fatalf("first valid install refused: %v", err)
	}
	installed := service.datasetProfileCatalog
	if !installed.Valid() || installed.ID() != catalog.ID() ||
		installed.Revision() != catalog.Revision() || installed.Hash() != catalog.Hash() {
		t.Fatalf("installed catalog = %q/%d/%q want %q/%d/%q", installed.ID(), installed.Revision(),
			installed.Hash(), catalog.ID(), catalog.Revision(), catalog.Hash())
	}
}

// TestEnableDatasetProfileCatalogRejectsZeroCatalogAndLeavesUnset proves the
// zero catalog is refused content-free and the slot stays the zero value.
func TestEnableDatasetProfileCatalogRejectsZeroCatalogAndLeavesUnset(t *testing.T) {
	service := &Service{}

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(analytic.DatasetProfileCatalog{}))
	if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
		t.Fatalf("refused zero catalog changed the slot: %q/%d", service.datasetProfileCatalog.ID(), service.datasetProfileCatalog.Revision())
	}
}

// TestEnableDatasetProfileCatalogRejectsSecondInstallAndPreservesFirst proves
// the one-shot install rule: the refused second call cannot replace the first.
func TestEnableDatasetProfileCatalogRejectsSecondInstallAndPreservesFirst(t *testing.T) {
	service := &Service{}
	first := datasetProfileCatalogInstallFixture(t, 1)
	if err := service.EnableDatasetProfileCatalog(first); err != nil {
		t.Fatalf("first valid install refused: %v", err)
	}

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 2)))
	if !reflect.DeepEqual(service.datasetProfileCatalog, first) {
		t.Fatalf("second install replaced the first: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision(), first.ID(), first.Revision())
	}
}

// TestEnableDatasetProfileCatalogRejectsNilService proves a nil receiver is a
// content-free refusal rather than a panic.
func TestEnableDatasetProfileCatalogRejectsNilService(t *testing.T) {
	var service *Service

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 1)))
}

// datasetProfileCatalogInstallFixture seals one catalog over the existing
// projection fixture profile.
func datasetProfileCatalogInstallFixture(t *testing.T, revision int64) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog("catalog.operations", revision, []analytic.CatalogEntryInput{
		{Profile: newProjectionFixtureProfile(t), State: analytic.ProfileActive},
	})
	if err != nil {
		t.Fatalf("build dataset profile catalog: %v", err)
	}
	return catalog
}

func assertDatasetProfileCatalogInstallRefusal(t *testing.T, err error) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
}
