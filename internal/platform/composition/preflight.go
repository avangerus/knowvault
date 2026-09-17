package composition

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"reflect"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
)

const (
	CodeOIDCPreflightFailed ErrorCode = "COMPOSITION_OIDC_PREFLIGHT_FAILED"
	startupRequestIDBytes             = 16
	oidcCallbackPath                  = "/auth/callback"
)

// providerConfigurationLoader is fulfilled directly by the identity
// repository. It exposes no discovery client or general database operation.
type providerConfigurationLoader interface {
	LoadProviderConfiguration(context.Context, identity.OrganizationID, identity.ProviderID, string) (identityrepository.ProviderConfiguration, error)
}

// clientBindingValidator proves that the mounted provider/revision/reference
// tuple exists without returning or copying its client secret.
type clientBindingValidator interface {
	ValidateClientBinding(context.Context, oidcweb.ClientSecretRequest) error
}

type startupRequestIDSource func() (string, error)

// preflightOIDCProvider validates the complete local/current provider
// projection. It intentionally performs no OIDC discovery or other network
// operation; the only I/O is the injected tenant-scoped repository read and
// mounted-secret tuple validation.
func preflightOIDCProvider(ctx context.Context, config Config, loader providerConfigurationLoader, bindings clientBindingValidator) error {
	return preflightOIDCProviderWithIDSource(ctx, config, loader, bindings, newStartupRequestID)
}

func preflightOIDCProviderWithIDSource(
	ctx context.Context,
	config Config,
	loader providerConfigurationLoader,
	bindings clientBindingValidator,
	newRequestID startupRequestIDSource,
) error {
	if ctx == nil || ctx.Err() != nil || !validPreflightConfig(config) || unavailableDependency(loader) || unavailableDependency(bindings) || newRequestID == nil {
		return preflightError()
	}
	requestID, err := newRequestID()
	if err != nil || !validOpaqueID(requestID) {
		return preflightError()
	}
	current, err := loader.LoadProviderConfiguration(ctx, config.OrganizationID(), config.ProviderID(), requestID)
	if err != nil || ctx.Err() != nil || current.OrganizationID != config.OrganizationID() || current.ProviderID != config.ProviderID() ||
		current.Revision < 1 || !validOpaqueID(current.ClientSecretReference) || current.RedirectURL != config.PublicOrigin()+oidcCallbackPath {
		return preflightError()
	}
	projection := oidc.ProviderConfiguration{
		IssuerURL: current.IssuerURL, ClientID: current.ClientID, RedirectURL: current.RedirectURL,
		SigningAlgorithms: append([]string(nil), current.SigningAlgorithms...),
	}
	if oidc.ValidateProviderConfiguration(projection) != nil {
		return preflightError()
	}
	binding := oidcweb.ClientSecretRequest{
		OrganizationID: current.OrganizationID, ProviderID: current.ProviderID,
		ProviderRevision: current.Revision, Reference: current.ClientSecretReference,
	}
	if bindings.ValidateClientBinding(ctx, binding) != nil || ctx.Err() != nil {
		return preflightError()
	}
	return nil
}

func newStartupRequestID() (string, error) {
	raw := make([]byte, startupRequestIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", preflightError()
	}
	return "req_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validPreflightConfig(config Config) bool {
	return validOpaqueID(string(config.OrganizationID())) && validOpaqueID(string(config.ProviderID())) &&
		validPublicOrigin(config.PublicOrigin()) && validHTTPAddress(config.HTTPAddress())
}

func unavailableDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func preflightError() error { return &Error{code: CodeOIDCPreflightFailed} }

// GoString prevents repository/provider details from appearing through %#v in
// startup diagnostics. Error already provides the fixed content-free %v form.
func (value *Error) GoString() string {
	if value == nil {
		return "composition.Error{[REDACTED]}"
	}
	return fmt.Sprintf("composition.Error{code:%s, details:[REDACTED]}", value.code)
}
