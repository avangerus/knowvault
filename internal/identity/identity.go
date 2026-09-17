// Package identity defines the pure, token-agnostic identity/session boundary.
//
// It deliberately does not parse, mint, sign, or persist tokens. An OIDC
// adapter and a repository must first produce Claims, CurrentPrincipal and
// CurrentProvider from their respective trusted inputs, then call Validate
// before an AccessContext or policy Subject can be created.
package identity

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// OrganizationID and PrincipalID are opaque internal identifiers. They are
// not external OIDC subjects, email addresses, or client-provided filters.
type OrganizationID string
type PrincipalID string
type ProviderID string

// PrincipalStatus mirrors the durable principal lifecycle. There is no
// implicit active or unknown value: an unknown current principal is represented
// by UnknownCurrentPrincipal.
type PrincipalStatus string

const (
	PrincipalActive        PrincipalStatus = "ACTIVE"
	PrincipalDisabled      PrincipalStatus = "DISABLED"
	PrincipalDeprovisioned PrincipalStatus = "DEPROVISIONED"
)

// ProviderStatus mirrors the durable provider lifecycle. A disabled provider
// invalidates every session that was issued through it.
type ProviderStatus string

const (
	ProviderActive   ProviderStatus = "ACTIVE"
	ProviderDisabled ProviderStatus = "DISABLED"
)

// ErrorCode is safe to map to a transport response or an audit outcome. It
// never includes an identifier, expiry timestamp, external subject, or cause.
type ErrorCode string

const (
	CodeClaimsInvalid          ErrorCode = "IDENTITY_CLAIMS_INVALID"
	CodeCurrentSnapshotInvalid ErrorCode = "IDENTITY_CURRENT_SNAPSHOT_INVALID"
	CodePrincipalUnknown       ErrorCode = "IDENTITY_PRINCIPAL_UNKNOWN"
	CodePrincipalInactive      ErrorCode = "IDENTITY_PRINCIPAL_INACTIVE"
	CodeProviderUnknown        ErrorCode = "IDENTITY_PROVIDER_UNKNOWN"
	CodeProviderInactive       ErrorCode = "IDENTITY_PROVIDER_INACTIVE"
	CodeDigestInvalid          ErrorCode = "IDENTITY_DIGEST_INVALID"
	CodeSessionExpired         ErrorCode = "IDENTITY_SESSION_EXPIRED"
	CodeSessionMismatch        ErrorCode = "IDENTITY_SESSION_MISMATCH"
	CodeValidationInvalid      ErrorCode = "IDENTITY_VALIDATION_INVALID"
	CodeDenied                 ErrorCode = "IDENTITY_DENIED"
)

// Error is deliberately content-free. Callers must use CodeOf instead of
// exposing an implementation error from a token provider or database.
type Error struct {
	code ErrorCode
}

func (errorValue *Error) Error() string { return string(errorValue.code) }

// CodeOf maps all unexpected errors to a safe denial code.
func CodeOf(err error) ErrorCode {
	var identityError *Error
	if errors.As(err, &identityError) {
		return identityError.code
	}
	return CodeDenied
}

// KeyedDigest is a validated HMAC-SHA-256 digest with a rotation key version.
// It is deliberately not a raw OIDC claim, browser secret, authorization code
// or session token. Returning its text is safe only for persistence/querying;
// callers must still never put it in a transport response or regular log.
type KeyedDigest struct{ value string }

func NewKeyedDigest(value string) (KeyedDigest, error) {
	digest := KeyedDigest{value: value}
	if !digest.valid() {
		return KeyedDigest{}, &Error{code: CodeDigestInvalid}
	}
	return digest, nil
}

func (digest KeyedDigest) Value() string { return digest.value }

func (digest KeyedDigest) valid() bool {
	const prefix = "hmac-sha256:k"
	if !strings.HasPrefix(digest.value, prefix) {
		return false
	}
	separator := strings.IndexByte(digest.value[len(prefix):], ':')
	if separator < 1 {
		return false
	}
	separator += len(prefix)
	keyVersion := digest.value[len(prefix):separator]
	if len(keyVersion) > 9 || keyVersion[0] == '0' {
		return false
	}
	for _, character := range keyVersion {
		if character < '0' || character > '9' {
			return false
		}
	}
	encoded := digest.value[separator+1:]
	if len(encoded) != 64 {
		return false
	}
	for _, character := range encoded {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// Claims is an already-verified session assertion. It contains no bearer
// token, raw external identity, or transport-specific metadata.
type Claims struct {
	organizationID   OrganizationID
	principalID      PrincipalID
	sessionRevision  int64
	providerID       ProviderID
	providerRevision int64
	expiresAt        time.Time
}

// NewClaims constructs a bounded session assertion. Signature verification,
// issuer/audience checks, and external-subject mapping intentionally belong to
// the future OIDC boundary, before this constructor is called.
func NewClaims(organizationID OrganizationID, principalID PrincipalID, sessionRevision int64, providerID ProviderID, providerRevision int64, expiresAt time.Time) (Claims, error) {
	claims := Claims{
		organizationID:   organizationID,
		principalID:      principalID,
		sessionRevision:  sessionRevision,
		providerID:       providerID,
		providerRevision: providerRevision,
		expiresAt:        expiresAt,
	}
	if !claims.valid() {
		return Claims{}, &Error{code: CodeClaimsInvalid}
	}
	return claims, nil
}

func (claims Claims) OrganizationID() OrganizationID { return claims.organizationID }
func (claims Claims) PrincipalID() PrincipalID       { return claims.principalID }
func (claims Claims) SessionRevision() int64         { return claims.sessionRevision }
func (claims Claims) ProviderID() ProviderID         { return claims.providerID }
func (claims Claims) ProviderRevision() int64        { return claims.providerRevision }
func (claims Claims) ExpiresAt() time.Time           { return claims.expiresAt }

func (claims Claims) valid() bool {
	return validOpaqueID(string(claims.organizationID)) &&
		validOpaqueID(string(claims.principalID)) &&
		claims.sessionRevision > 0 &&
		validOpaqueID(string(claims.providerID)) &&
		claims.providerRevision > 0 &&
		!claims.expiresAt.IsZero()
}

// CurrentPrincipal is the server-resolved, current durable principal state.
// Its fields remain private so untrusted transport state cannot be mistaken
// for an authoritative snapshot by assigning struct fields directly.
type CurrentPrincipal struct {
	known           bool
	organizationID  OrganizationID
	principalID     PrincipalID
	status          PrincipalStatus
	sessionRevision int64
}

// UnknownCurrentPrincipal represents a repository miss or unresolved external
// identity. It always denies; callers must never substitute an active default.
func UnknownCurrentPrincipal() CurrentPrincipal { return CurrentPrincipal{} }

// NewCurrentPrincipal constructs a current server-side principal snapshot.
// DISABLED and DEPROVISIONED are valid states, but cannot pass Validate.
func NewCurrentPrincipal(organizationID OrganizationID, principalID PrincipalID, status PrincipalStatus, sessionRevision int64) (CurrentPrincipal, error) {
	principal := CurrentPrincipal{
		known:           true,
		organizationID:  organizationID,
		principalID:     principalID,
		status:          status,
		sessionRevision: sessionRevision,
	}
	if !principal.valid() {
		return CurrentPrincipal{}, &Error{code: CodeCurrentSnapshotInvalid}
	}
	return principal, nil
}

func (principal CurrentPrincipal) Known() bool                    { return principal.known }
func (principal CurrentPrincipal) OrganizationID() OrganizationID { return principal.organizationID }
func (principal CurrentPrincipal) PrincipalID() PrincipalID       { return principal.principalID }
func (principal CurrentPrincipal) Status() PrincipalStatus        { return principal.status }
func (principal CurrentPrincipal) SessionRevision() int64         { return principal.sessionRevision }

func (principal CurrentPrincipal) valid() bool {
	return principal.known &&
		validOpaqueID(string(principal.organizationID)) &&
		validOpaqueID(string(principal.principalID)) &&
		validPrincipalStatus(principal.status) &&
		principal.sessionRevision > 0
}

func validPrincipalStatus(status PrincipalStatus) bool {
	switch status {
	case PrincipalActive, PrincipalDisabled, PrincipalDeprovisioned:
		return true
	default:
		return false
	}
}

// CurrentProvider is the server-resolved current OIDC provider state. An
// unknown provider is distinct from a disabled provider and both fail closed.
type CurrentProvider struct {
	known            bool
	organizationID   OrganizationID
	providerID       ProviderID
	status           ProviderStatus
	providerRevision int64
}

// UnknownCurrentProvider represents a repository miss. It always denies.
func UnknownCurrentProvider() CurrentProvider { return CurrentProvider{} }

// NewCurrentProvider constructs a current server-side provider snapshot.
func NewCurrentProvider(organizationID OrganizationID, providerID ProviderID, status ProviderStatus, providerRevision int64) (CurrentProvider, error) {
	provider := CurrentProvider{
		known:            true,
		organizationID:   organizationID,
		providerID:       providerID,
		status:           status,
		providerRevision: providerRevision,
	}
	if !provider.valid() {
		return CurrentProvider{}, &Error{code: CodeCurrentSnapshotInvalid}
	}
	return provider, nil
}

func (provider CurrentProvider) Known() bool                    { return provider.known }
func (provider CurrentProvider) OrganizationID() OrganizationID { return provider.organizationID }
func (provider CurrentProvider) ProviderID() ProviderID         { return provider.providerID }
func (provider CurrentProvider) Status() ProviderStatus         { return provider.status }
func (provider CurrentProvider) Revision() int64                { return provider.providerRevision }

func (provider CurrentProvider) valid() bool {
	return provider.known &&
		validOpaqueID(string(provider.organizationID)) &&
		validOpaqueID(string(provider.providerID)) &&
		validProviderStatus(provider.status) &&
		provider.providerRevision > 0
}

func validProviderStatus(status ProviderStatus) bool {
	switch status {
	case ProviderActive, ProviderDisabled:
		return true
	default:
		return false
	}
}

// Validate proves that a claims snapshot still exactly matches the current
// principal and provider snapshots at now. The expiry boundary is exclusive:
// a session is invalid at exactly expiresAt. Any unknown, inactive, expired,
// malformed, or changed principal/provider state fails closed.
func Validate(now time.Time, claims Claims, current CurrentPrincipal, provider CurrentProvider) error {
	if now.IsZero() {
		return &Error{code: CodeValidationInvalid}
	}
	if !claims.valid() {
		return &Error{code: CodeClaimsInvalid}
	}
	if !current.known {
		return &Error{code: CodePrincipalUnknown}
	}
	if !current.valid() {
		return &Error{code: CodeCurrentSnapshotInvalid}
	}
	if !provider.known {
		return &Error{code: CodeProviderUnknown}
	}
	if !provider.valid() {
		return &Error{code: CodeCurrentSnapshotInvalid}
	}
	if current.status != PrincipalActive {
		return &Error{code: CodePrincipalInactive}
	}
	if provider.status != ProviderActive {
		return &Error{code: CodeProviderInactive}
	}
	if !now.Before(claims.expiresAt) {
		return &Error{code: CodeSessionExpired}
	}
	if claims.organizationID != current.organizationID ||
		claims.principalID != current.principalID ||
		claims.sessionRevision != current.sessionRevision ||
		claims.organizationID != provider.organizationID ||
		claims.providerID != provider.providerID ||
		claims.providerRevision != provider.providerRevision {
		return &Error{code: CodeSessionMismatch}
	}
	return nil
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, runeValue := range value {
		if (runeValue >= 'a' && runeValue <= 'z') ||
			(runeValue >= 'A' && runeValue <= 'Z') ||
			(runeValue >= '0' && runeValue <= '9') ||
			strings.ContainsRune("_-.:", runeValue) {
			continue
		}
		return false
	}
	return true
}
