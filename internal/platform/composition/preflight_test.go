package composition

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
)

func TestOIDCProviderPreflightLoadsAndValidatesExactCurrentBinding(t *testing.T) {
	config := validPreflightConfiguration(t)
	current := validCurrentProvider(config)
	loader := &fakeProviderLoader{current: current}
	bindings := &fakeBindingValidator{}
	const requestID = "req_startup_01"
	if err := preflightOIDCProviderWithIDSource(context.Background(), config, loader, bindings, func() (string, error) { return requestID, nil }); err != nil {
		t.Fatalf("preflight failed: %v", err)
	}
	if loader.calls != 1 || loader.organizationID != config.OrganizationID() || loader.providerID != config.ProviderID() || loader.requestID != requestID {
		t.Fatalf("loader call=%d organization=%q provider=%q request=%q", loader.calls, loader.organizationID, loader.providerID, loader.requestID)
	}
	wantBinding := oidcweb.ClientSecretRequest{
		OrganizationID: config.OrganizationID(), ProviderID: config.ProviderID(), ProviderRevision: current.Revision, Reference: current.ClientSecretReference,
	}
	if bindings.calls != 1 || bindings.request != wantBinding {
		t.Fatalf("binding calls=%d request=%#v", bindings.calls, bindings.request)
	}
}

func TestOIDCProviderPreflightRejectsEveryCurrentProjectionMismatchBeforeSecretLookup(t *testing.T) {
	config := validPreflightConfiguration(t)
	tests := map[string]func(*identityrepository.ProviderConfiguration){
		"organization":       func(value *identityrepository.ProviderConfiguration) { value.OrganizationID = "org_other" },
		"provider":           func(value *identityrepository.ProviderConfiguration) { value.ProviderID = "idp_other" },
		"zero revision":      func(value *identityrepository.ProviderConfiguration) { value.Revision = 0 },
		"invalid secret ref": func(value *identityrepository.ProviderConfiguration) { value.ClientSecretReference = "secret/ref" },
		"wrong callback": func(value *identityrepository.ProviderConfiguration) {
			value.RedirectURL = config.PublicOrigin() + "/other"
		},
		"HTTP issuer":   func(value *identityrepository.ProviderConfiguration) { value.IssuerURL = "http://identity.example" },
		"empty client":  func(value *identityrepository.ProviderConfiguration) { value.ClientID = "" },
		"no algorithms": func(value *identityrepository.ProviderConfiguration) { value.SigningAlgorithms = nil },
		"unordered algorithms": func(value *identityrepository.ProviderConfiguration) {
			value.SigningAlgorithms = []string{"RS256", "ES256"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			current := validCurrentProvider(config)
			mutate(&current)
			bindings := &fakeBindingValidator{}
			err := preflightOIDCProviderWithIDSource(context.Background(), config, &fakeProviderLoader{current: current}, bindings, fixedStartupID)
			if CodeOf(err) != CodeOIDCPreflightFailed || bindings.calls != 0 {
				t.Fatalf("mismatch err=%v binding calls=%d", err, bindings.calls)
			}
		})
	}
}

func TestOIDCProviderPreflightRejectsZeroInvalidAndTypedNilInputsWithoutCalls(t *testing.T) {
	config := validPreflightConfiguration(t)
	current := validCurrentProvider(config)
	validLoader := &fakeProviderLoader{current: current}
	validBindings := &fakeBindingValidator{}
	var typedNilLoader *fakeProviderLoader
	var typedNilBindings *fakeBindingValidator
	tests := map[string]func() error{
		"nil context": func() error {
			return preflightOIDCProviderWithIDSource(nil, config, validLoader, validBindings, fixedStartupID)
		},
		"zero config": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), Config{}, validLoader, validBindings, fixedStartupID)
		},
		"invalid address": func() error {
			invalid := config
			invalid.httpAddress = "8080"
			return preflightOIDCProviderWithIDSource(context.Background(), invalid, validLoader, validBindings, fixedStartupID)
		},
		"nil loader": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, nil, validBindings, fixedStartupID)
		},
		"typed nil loader": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, typedNilLoader, validBindings, fixedStartupID)
		},
		"nil bindings": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, validLoader, nil, fixedStartupID)
		},
		"typed nil bindings": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, validLoader, typedNilBindings, fixedStartupID)
		},
		"nil ID source": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, validLoader, validBindings, nil)
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			loaderCalls, bindingCalls := validLoader.calls, validBindings.calls
			if err := run(); CodeOf(err) != CodeOIDCPreflightFailed || validLoader.calls != loaderCalls || validBindings.calls != bindingCalls {
				t.Fatalf("invalid input err=%v loader=%d binding=%d", err, validLoader.calls, validBindings.calls)
			}
		})
	}
}

func TestOIDCProviderPreflightHonorsCancellationBeforeAndDuringDependencies(t *testing.T) {
	config := validPreflightConfiguration(t)
	current := validCurrentProvider(config)
	t.Run("before request ID", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		idCalls := 0
		err := preflightOIDCProviderWithIDSource(ctx, config, &fakeProviderLoader{current: current}, &fakeBindingValidator{}, func() (string, error) {
			idCalls++
			return "req_never", nil
		})
		if CodeOf(err) != CodeOIDCPreflightFailed || idCalls != 0 {
			t.Fatalf("cancelled preflight err=%v ID calls=%d", err, idCalls)
		}
	})
	t.Run("during provider load", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		loader := &fakeProviderLoader{current: current, onCall: cancel}
		bindings := &fakeBindingValidator{}
		if err := preflightOIDCProviderWithIDSource(ctx, config, loader, bindings, fixedStartupID); CodeOf(err) != CodeOIDCPreflightFailed || bindings.calls != 0 {
			t.Fatalf("cancelled load err=%v binding calls=%d", err, bindings.calls)
		}
	})
	t.Run("during binding validation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		bindings := &fakeBindingValidator{onCall: cancel}
		if err := preflightOIDCProviderWithIDSource(ctx, config, &fakeProviderLoader{current: current}, bindings, fixedStartupID); CodeOf(err) != CodeOIDCPreflightFailed || bindings.calls != 1 {
			t.Fatalf("cancelled binding err=%v calls=%d", err, bindings.calls)
		}
	})
}

func TestOIDCProviderPreflightFailsClosedOnIDLoaderAndBindingErrors(t *testing.T) {
	config := validPreflightConfiguration(t)
	current := validCurrentProvider(config)
	tests := map[string]func() error{
		"ID failure": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, &fakeProviderLoader{current: current}, &fakeBindingValidator{}, func() (string, error) {
				return "", errors.New("entropy details")
			})
		},
		"invalid ID": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, &fakeProviderLoader{current: current}, &fakeBindingValidator{}, func() (string, error) { return "bad id", nil })
		},
		"loader failure": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, &fakeProviderLoader{err: errors.New("database details")}, &fakeBindingValidator{}, fixedStartupID)
		},
		"binding failure": func() error {
			return preflightOIDCProviderWithIDSource(context.Background(), config, &fakeProviderLoader{current: current}, &fakeBindingValidator{err: errors.New("secret details")}, fixedStartupID)
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			err := run()
			formatted := fmt.Sprintf("%v|%#v", err, err)
			if CodeOf(err) != CodeOIDCPreflightFailed || strings.Contains(formatted, "entropy details") ||
				strings.Contains(formatted, "database details") || strings.Contains(formatted, "secret details") || !strings.Contains(formatted, "REDACTED") {
				t.Fatalf("unsafe failure: %s", formatted)
			}
		})
	}
}

func TestStartupRequestIDUsesCanonicalFreshCSPRNGMaterial(t *testing.T) {
	first, err := newStartupRequestID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newStartupRequestID()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{first, second} {
		if !strings.HasPrefix(value, "req_") || !validOpaqueID(value) {
			t.Fatalf("invalid startup request ID: %q", value)
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "req_"))
		if decodeErr != nil || len(decoded) != startupRequestIDBytes {
			t.Fatalf("invalid startup entropy encoding: %q", value)
		}
	}
	if first == second {
		t.Fatal("two startup request IDs unexpectedly matched")
	}
}

type fakeProviderLoader struct {
	current        identityrepository.ProviderConfiguration
	err            error
	onCall         func()
	calls          int
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	requestID      string
}

func (loader *fakeProviderLoader) LoadProviderConfiguration(_ context.Context, organizationID identity.OrganizationID, providerID identity.ProviderID, requestID string) (identityrepository.ProviderConfiguration, error) {
	loader.calls++
	loader.organizationID, loader.providerID, loader.requestID = organizationID, providerID, requestID
	if loader.onCall != nil {
		loader.onCall()
	}
	return loader.current, loader.err
}

type fakeBindingValidator struct {
	err     error
	onCall  func()
	calls   int
	request oidcweb.ClientSecretRequest
}

func (validator *fakeBindingValidator) ValidateClientBinding(_ context.Context, request oidcweb.ClientSecretRequest) error {
	validator.calls++
	validator.request = request
	if validator.onCall != nil {
		validator.onCall()
	}
	return validator.err
}

func validPreflightConfiguration(t *testing.T) Config {
	t.Helper()
	config, err := loadProduction([]string{
		organizationIDEnvironment + "=org_alpha", providerIDEnvironment + "=idp_primary",
		publicOriginEnvironment + "=https://workspace.example", httpAddressEnvironment + "=:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func validCurrentProvider(config Config) identityrepository.ProviderConfiguration {
	return identityrepository.ProviderConfiguration{
		OrganizationID: config.OrganizationID(), ProviderID: config.ProviderID(), Revision: 7,
		IssuerURL: "https://identity.example", ClientID: "client_001", ClientSecretReference: "oidc-client-primary",
		RedirectURL: config.PublicOrigin() + oidcCallbackPath, SigningAlgorithms: []string{"ES256", "RS256"},
	}
}

func fixedStartupID() (string, error) { return "req_startup_01", nil }
