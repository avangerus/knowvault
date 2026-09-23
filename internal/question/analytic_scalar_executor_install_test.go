package question

import (
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// analyticScalarExecutorInstallSlots is the observable state of the three
// capability slots the scalar executor install and the catalog install share.
type analyticScalarExecutorInstallSlots struct {
	catalog  analytic.DatasetProfileCatalog
	resolver *analyticsource.Resolver
	executor *analyticsource.ScalarExecutor
}

// analyticScalarExecutorInstallFixture builds a Service whose catalog/resolver
// pair is installed exactly as EnableDatasetProfileCatalog leaves it.
func analyticScalarExecutorInstallFixture(t *testing.T) *Service {
	t.Helper()
	catalog := datasetProfileCatalogInstallFixture(t, 1)
	resolver, err := analyticsource.NewResolver(&workspacerepository.Store{}, catalog)
	if err != nil {
		t.Fatalf("build retained resolver: %v", err)
	}
	return &Service{datasetProfileCatalog: catalog, analyticSourceResolver: resolver}
}

// analyticScalarExecutorInstallSlotsOf reads the current capability slots.
func analyticScalarExecutorInstallSlotsOf(service *Service) analyticScalarExecutorInstallSlots {
	if service == nil {
		return analyticScalarExecutorInstallSlots{}
	}
	return analyticScalarExecutorInstallSlots{
		catalog:  service.datasetProfileCatalog,
		resolver: service.analyticSourceResolver,
		executor: service.analyticScalarExecutor,
	}
}

// assertAnalyticScalarExecutorInstallRefusal proves one refused install is the
// content-free CodeInvalid with no wrapped cause or clarification and that all
// three capability slots still hold exactly the retained state.
func assertAnalyticScalarExecutorInstallRefusal(t *testing.T, service *Service, held analyticScalarExecutorInstallSlots, err error) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil || typed.clarification != "" {
		t.Fatalf("refusal = %#v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
	if got := analyticScalarExecutorInstallSlotsOf(service); !reflect.DeepEqual(got, held) {
		t.Fatalf("refused install changed the capability slots: %+v want %+v", got, held)
	}
}

// TestInstallAnalyticScalarExecutorBindsInstalledCapability is the valid-install
// arm: an installed catalog/resolver pair and a concrete reader fill the empty
// executor slot without replacing the retained catalog or resolver.
func TestInstallAnalyticScalarExecutorBindsInstalledCapability(t *testing.T) {
	service := analyticScalarExecutorInstallFixture(t)
	held := analyticScalarExecutorInstallSlotsOf(service)

	if err := service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)); err != nil {
		t.Fatalf("valid install refused: %v", err)
	}
	if service.analyticScalarExecutor == nil {
		t.Fatal("valid install left the executor slot empty")
	}
	if !reflect.DeepEqual(service.datasetProfileCatalog, held.catalog) {
		t.Fatalf("install changed the installed catalog: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision(), held.catalog.ID(), held.catalog.Revision())
	}
	if service.analyticSourceResolver != held.resolver {
		t.Fatalf("install replaced the retained resolver: %p want %p", service.analyticSourceResolver, held.resolver)
	}
}

// TestInstallAnalyticScalarExecutorRefusesEveryClosedInput proves each input
// outside the accepted shape is a content-free CodeInvalid refusal that leaves
// all three capability slots exactly as they were, including the second install
// over an already occupied executor slot.
func TestInstallAnalyticScalarExecutorRefusesEveryClosedInput(t *testing.T) {
	t.Run("nil service", func(t *testing.T) {
		var service *Service
		assertAnalyticScalarExecutorInstallRefusal(t, service, analyticScalarExecutorInstallSlots{},
			service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)))
	})

	t.Run("absent capability", func(t *testing.T) {
		service := &Service{}
		assertAnalyticScalarExecutorInstallRefusal(t, service, analyticScalarExecutorInstallSlots{},
			service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)))
	})

	t.Run("resolver without catalog", func(t *testing.T) {
		resolver, err := analyticsource.NewResolver(&workspacerepository.Store{}, datasetProfileCatalogInstallFixture(t, 1))
		if err != nil {
			t.Fatalf("build retained resolver: %v", err)
		}
		service := &Service{analyticSourceResolver: resolver}
		assertAnalyticScalarExecutorInstallRefusal(t, service, analyticScalarExecutorInstallSlots{resolver: resolver},
			service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)))
	})

	t.Run("catalog without resolver", func(t *testing.T) {
		service := &Service{datasetProfileCatalog: datasetProfileCatalogInstallFixture(t, 1)}
		assertAnalyticScalarExecutorInstallRefusal(t, service,
			analyticScalarExecutorInstallSlots{catalog: service.datasetProfileCatalog},
			service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)))
	})

	t.Run("nil reader", func(t *testing.T) {
		service := analyticScalarExecutorInstallFixture(t)
		assertAnalyticScalarExecutorInstallRefusal(t, service, analyticScalarExecutorInstallSlotsOf(service),
			service.installAnalyticScalarExecutor(nil))
	})

	t.Run("second install", func(t *testing.T) {
		service := analyticScalarExecutorInstallFixture(t)
		if err := service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)); err != nil {
			t.Fatalf("first valid install refused: %v", err)
		}
		held := analyticScalarExecutorInstallSlotsOf(service)
		if held.executor == nil {
			t.Fatal("first install left the executor slot empty")
		}
		assertAnalyticScalarExecutorInstallRefusal(t, service, held,
			service.installAnalyticScalarExecutor(new(workspacerepository.PostgreSQLAuthorizedReader)))
	})
}

// TestAnalyticScalarExecutorOnlyStateBlocksCatalogInstall proves the executor
// slot participates in EnableDatasetProfileCatalog's occupied-state guard: an
// executor without either half of the catalog/resolver pair is a malformed
// partial state that refuses a fresh catalog install and is never repaired.
func TestAnalyticScalarExecutorOnlyStateBlocksCatalogInstall(t *testing.T) {
	heldExecutor := &analyticsource.ScalarExecutor{}
	service := &Service{analyticScalarExecutor: heldExecutor}

	assertDatasetProfileCatalogInstallRefusal(t,
		service.EnableDatasetProfileCatalog(datasetProfileCatalogInstallFixture(t, 1), &workspacerepository.Store{}))
	if service.analyticScalarExecutor != heldExecutor {
		t.Fatalf("refused catalog install replaced the held executor: %p want %p", service.analyticScalarExecutor, heldExecutor)
	}
	if service.analyticSourceResolver != nil {
		t.Fatalf("refused catalog install completed the pair: resolver = %p", service.analyticSourceResolver)
	}
	if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
		t.Fatalf("refused catalog install completed the pair: catalog = %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision())
	}
}
