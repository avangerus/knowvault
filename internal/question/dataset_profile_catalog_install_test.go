package question

import (
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestEnableDatasetProfileCatalogInstallsFirstValidValue is the valid-install
// arm: the first valid catalog and a concrete store install the exact catalog
// and a non-nil resolver together and return no error.
func TestEnableDatasetProfileCatalogInstallsFirstValidValue(t *testing.T) {
	service := &Service{}
	catalog := datasetProfileCatalogInstallFixture(t, 1)

	if err := service.EnableDatasetProfileCatalog(catalog, &workspacerepository.Store{}); err != nil {
		t.Fatalf("first valid install refused: %v", err)
	}
	installed := service.datasetProfileCatalog
	if !reflect.DeepEqual(installed, catalog) {
		t.Fatalf("installed catalog = %q/%d/%q want the exact received %q/%d/%q", installed.ID(), installed.Revision(),
			installed.Hash(), catalog.ID(), catalog.Revision(), catalog.Hash())
	}
	if service.analyticSourceResolver == nil {
		t.Fatal("installed resolver is nil")
	}
}

// TestEnableDatasetProfileCatalogRejectsZeroCatalogAndLeavesUnset proves the
// zero catalog is refused content-free and both slots stay empty.
func TestEnableDatasetProfileCatalogRejectsZeroCatalogAndLeavesUnset(t *testing.T) {
	service := &Service{}

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(analytic.DatasetProfileCatalog{}, &workspacerepository.Store{}))
	assertDatasetProfileCatalogInstallSlotsEmpty(t, service)
}

// TestEnableDatasetProfileCatalogRejectsNilStoreAndLeavesUnset proves a valid
// catalog without its concrete store is refused content-free and both slots
// stay empty.
func TestEnableDatasetProfileCatalogRejectsNilStoreAndLeavesUnset(t *testing.T) {
	service := &Service{}

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 1), nil))
	assertDatasetProfileCatalogInstallSlotsEmpty(t, service)
}

// TestEnableDatasetProfileCatalogRejectsSecondInstallAndPreservesFirst proves
// the one-shot install rule: the refused second call cannot replace the first
// catalog value or the first resolver pointer.
func TestEnableDatasetProfileCatalogRejectsSecondInstallAndPreservesFirst(t *testing.T) {
	service := &Service{}
	first := datasetProfileCatalogInstallFixture(t, 1)
	if err := service.EnableDatasetProfileCatalog(first, &workspacerepository.Store{}); err != nil {
		t.Fatalf("first valid install refused: %v", err)
	}
	installedResolver := service.analyticSourceResolver

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 2), &workspacerepository.Store{}))
	if !reflect.DeepEqual(service.datasetProfileCatalog, first) {
		t.Fatalf("second install replaced the first: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision(), first.ID(), first.Revision())
	}
	if service.analyticSourceResolver != installedResolver {
		t.Fatalf("second install replaced the resolver: %p want %p", service.analyticSourceResolver, installedResolver)
	}
}

// TestEnableDatasetProfileCatalogRejectsNilService proves a nil receiver is a
// content-free refusal rather than a panic.
func TestEnableDatasetProfileCatalogRejectsNilService(t *testing.T) {
	var service *Service

	assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 1), &workspacerepository.Store{}))
}

// TestEnableDatasetProfileCatalogRejectsPartialInstallState proves a service
// already holding exactly one of the two slots refuses a fresh install and
// keeps that state: a partial pair is neither repaired nor overwritten.
func TestEnableDatasetProfileCatalogRejectsPartialInstallState(t *testing.T) {
	t.Run("catalog only", func(t *testing.T) {
		service := &Service{datasetProfileCatalog: datasetProfileCatalogInstallFixture(t, 1)}
		held := service.datasetProfileCatalog

		assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 2), &workspacerepository.Store{}))
		if !reflect.DeepEqual(service.datasetProfileCatalog, held) {
			t.Fatalf("refused install overwrote the held catalog: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision(), held.ID(), held.Revision())
		}
		if service.analyticSourceResolver != nil {
			t.Fatalf("refused install completed the pair: resolver = %p", service.analyticSourceResolver)
		}
	})

	t.Run("resolver only", func(t *testing.T) {
		held, err := analyticsource.NewResolver(&workspacerepository.Store{}, datasetProfileCatalogInstallFixture(t, 1))
		if err != nil {
			t.Fatalf("build held resolver: %v", err)
		}
		service := &Service{analyticSourceResolver: held}

		assertDatasetProfileCatalogInstallRefusal(t, service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 2), &workspacerepository.Store{}))
		if service.analyticSourceResolver != held {
			t.Fatalf("refused install overwrote the held resolver: %p want %p", service.analyticSourceResolver, held)
		}
		if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
			t.Fatalf("refused install completed the pair: catalog = %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision())
		}
	})
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

// assertDatasetProfileCatalogInstallSlotsEmpty proves a refused install left
// both service slots exactly empty.
func assertDatasetProfileCatalogInstallSlotsEmpty(t *testing.T, service *Service) {
	t.Helper()
	if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
		t.Fatalf("refused install changed the catalog slot: %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision())
	}
	if service.analyticSourceResolver != nil {
		t.Fatalf("refused install changed the resolver slot: %p", service.analyticSourceResolver)
	}
}

func assertDatasetProfileCatalogInstallRefusal(t *testing.T, err error) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
}
