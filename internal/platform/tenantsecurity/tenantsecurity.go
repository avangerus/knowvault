// Package tenantsecurity owns the deployment-trusted, single-tenant security
// context. It never derives tenant identity, public origin, or key selection
// from an HTTP request.
package tenantsecurity

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
)

// ErrorCode is content-free and safe for startup diagnostics.
type ErrorCode string

const (
	CodeConfigurationInvalid ErrorCode = "TENANT_SECURITY_CONFIGURATION_INVALID"
	CodeResolutionFailed     ErrorCode = "TENANT_SECURITY_RESOLUTION_FAILED"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	var value *Error
	if errors.As(err, &value) {
		return value.code
	}
	return CodeResolutionFailed
}

// Digestor is implemented by a tenant-scoped, purpose-separated HMAC adapter.
type Digestor interface {
	Digest(purpose, raw string) (identity.KeyedDigest, error)
	// KeyMaterialFingerprint is SHA-256 of the exact high-entropy key bytes.
	// It is startup attestation metadata, never a request-selected identifier.
	KeyMaterialFingerprint() [32]byte
}

// Context can only be built by NewContext so identity and browser-session key
// selections cannot silently collapse into one rotation domain.
type Context struct {
	organizationID   identity.OrganizationID
	providerID       identity.ProviderID
	publicOrigin     string
	identityKeyRef   string
	identityKeyProof [32]byte
	identityDigestor Digestor
	sessionKeyRef    string
	sessionKeyProof  [32]byte
	sessionDigestor  Digestor
}

func (Context) String() string   { return "tenantsecurity.Context{[REDACTED]}" }
func (Context) GoString() string { return "tenantsecurity.Context{[REDACTED]}" }

func NewContext(
	organizationID identity.OrganizationID,
	providerID identity.ProviderID,
	publicOrigin string,
	identityKeyReference string,
	identityDigestor Digestor,
	sessionKeyReference string,
	sessionDigestor Digestor,
) (Context, error) {
	if !digestorAvailable(identityDigestor) || !digestorAvailable(sessionDigestor) || sameDigestorInstance(identityDigestor, sessionDigestor) {
		return Context{}, &Error{code: CodeConfigurationInvalid}
	}
	result := Context{
		organizationID: organizationID, providerID: providerID, publicOrigin: publicOrigin,
		identityKeyRef: identityKeyReference, identityKeyProof: identityDigestor.KeyMaterialFingerprint(), identityDigestor: redactedDigestor{delegate: identityDigestor, scope: digestorScopeIdentity},
		sessionKeyRef: sessionKeyReference, sessionKeyProof: sessionDigestor.KeyMaterialFingerprint(), sessionDigestor: redactedDigestor{delegate: sessionDigestor, scope: digestorScopeSession},
	}
	if !result.valid() {
		return Context{}, &Error{code: CodeConfigurationInvalid}
	}
	return result, nil
}

type digestorScope uint8

const (
	digestorScopeIdentity digestorScope = iota + 1
	digestorScopeSession
)

type redactedDigestor struct {
	delegate Digestor
	scope    digestorScope
}

func (value redactedDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	if value.delegate == nil || !value.purposeAllowed(purpose) {
		return identity.KeyedDigest{}, &Error{code: CodeResolutionFailed}
	}
	return value.delegate.Digest(purpose, raw)
}

func (value redactedDigestor) KeyMaterialFingerprint() [32]byte {
	if value.delegate == nil {
		return [32]byte{}
	}
	return value.delegate.KeyMaterialFingerprint()
}

func (redactedDigestor) String() string   { return "[REDACTED DIGESTOR]" }
func (redactedDigestor) GoString() string { return "tenantsecurity.Digestor{[REDACTED]}" }

func (value redactedDigestor) purposeAllowed(purpose string) bool {
	switch value.scope {
	case digestorScopeIdentity:
		switch purpose {
		case "state", "nonce", "pkce_verifier", "browser_binding", "subject":
			return true
		}
	case digestorScopeSession:
		return purpose == "session_token" || purpose == "csrf"
	}
	return false
}

func (value Context) OrganizationID() identity.OrganizationID { return value.organizationID }
func (value Context) ProviderID() identity.ProviderID         { return value.providerID }
func (value Context) PublicOrigin() string                    { return value.publicOrigin }
func (value Context) IdentityDigestor() Digestor              { return value.identityDigestor }
func (value Context) SessionDigestor() Digestor               { return value.sessionDigestor }

// ValidateOIDCTransportKeySelection proves that the separately resolved AEAD
// key belongs to neither digest-key rotation domain. References and material
// fingerprints are deployment-attested, never request or operator labels.
func (value Context) ValidateOIDCTransportKeySelection(reference string, materialFingerprint [32]byte) error {
	if !value.valid() || !validOpaqueID(reference) || zeroFingerprint(materialFingerprint) || reference == value.identityKeyRef || reference == value.sessionKeyRef ||
		subtle.ConstantTimeCompare(materialFingerprint[:], value.identityKeyProof[:]) == 1 || subtle.ConstantTimeCompare(materialFingerprint[:], value.sessionKeyProof[:]) == 1 {
		return &Error{code: CodeConfigurationInvalid}
	}
	return nil
}

func (value Context) valid() bool {
	return validOpaqueID(string(value.organizationID)) && validOpaqueID(string(value.providerID)) &&
		validOrigin(value.publicOrigin) && validOpaqueID(value.identityKeyRef) && validOpaqueID(value.sessionKeyRef) &&
		value.identityKeyRef != value.sessionKeyRef && !zeroFingerprint(value.identityKeyProof) && !zeroFingerprint(value.sessionKeyProof) &&
		subtle.ConstantTimeCompare(value.identityKeyProof[:], value.sessionKeyProof[:]) != 1 && value.identityDigestor != nil && value.sessionDigestor != nil
}

// Resolver is shared by future OIDC HTTP and browser-session composition.
type Resolver interface {
	Resolve(context.Context) (Context, error)
}

// StaticResolver is the accepted 1.0 deployment model: one process is bound to
// one tenant context constructed at startup from trusted configuration/KMS.
type StaticResolver struct{ security Context }

func (StaticResolver) String() string   { return "tenantsecurity.StaticResolver{[REDACTED]}" }
func (StaticResolver) GoString() string { return "tenantsecurity.StaticResolver{[REDACTED]}" }

func NewStaticResolver(security Context) (*StaticResolver, error) {
	if !security.valid() {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return &StaticResolver{security: security}, nil
}

func (resolver *StaticResolver) Resolve(ctx context.Context) (Context, error) {
	if resolver == nil || ctx == nil || !resolver.security.valid() {
		return Context{}, &Error{code: CodeResolutionFailed}
	}
	return resolver.security, nil
}

// HTTPAuthResolver projects only the browser-session key selection into the
// HTTP authentication boundary. The identity digestor is never exposed there.
type HTTPAuthResolver struct{ resolver Resolver }

func (HTTPAuthResolver) String() string   { return "tenantsecurity.HTTPAuthResolver{[REDACTED]}" }
func (HTTPAuthResolver) GoString() string { return "tenantsecurity.HTTPAuthResolver{[REDACTED]}" }

func NewHTTPAuthResolver(resolver Resolver) (*HTTPAuthResolver, error) {
	if resolver == nil {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	return &HTTPAuthResolver{resolver: resolver}, nil
}

func (resolver *HTTPAuthResolver) Resolve(ctx context.Context) (httpauth.TenantSecurityContext, error) {
	if resolver == nil || resolver.resolver == nil || ctx == nil {
		return httpauth.TenantSecurityContext{}, &Error{code: CodeResolutionFailed}
	}
	security, err := resolver.resolver.Resolve(ctx)
	if err != nil || !security.valid() {
		return httpauth.TenantSecurityContext{}, &Error{code: CodeResolutionFailed}
	}
	return httpauth.TenantSecurityContext{
		OrganizationID: security.organizationID,
		Origin:         security.publicOrigin,
		Digestor:       security.sessionDigestor,
	}, nil
}

func validOrigin(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return false
	}
	hostname := parsed.Hostname()
	return parsed.Scheme == "https" && parsed.Host != "" && hostname != "" && hostname == strings.ToLower(hostname) &&
		!strings.HasSuffix(hostname, ".") && parsed.Port() != "443" && parsed.User == nil && parsed.Opaque == "" &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func digestorAvailable(value Digestor) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

func sameDigestorInstance(left, right Digestor) bool {
	leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)
	if !leftValue.IsValid() || !rightValue.IsValid() || leftValue.Type() != rightValue.Type() {
		return false
	}
	switch leftValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return leftValue.Pointer() == rightValue.Pointer()
	default:
		return leftValue.Type().Comparable() && leftValue.Interface() == rightValue.Interface()
	}
}

func zeroFingerprint(value [32]byte) bool { return value == [32]byte{} }
