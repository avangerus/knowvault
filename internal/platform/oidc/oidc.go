// Package oidc is the sole OIDC protocol boundary. It owns cryptographic
// login material, provider discovery, Authorization Code + PKCE exchange and
// ID-token verification. It never persists or returns raw tokens, codes,
// subjects or client secrets.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"knowvault.local/verified-workspace/internal/identity"
)

const (
	rawBytes                   = 32
	maxAuthorizationCodeLength = 4096
	openidScope                = "openid"
)

// ErrorCode is safe for a transport response or structured log. Provider
// errors, raw codes/tokens/subjects and network causes remain wrapped only.
type ErrorCode string

const (
	CodeConfigurationInvalid ErrorCode = "OIDC_CONFIGURATION_INVALID"
	CodeMaterialFailed       ErrorCode = "OIDC_MATERIAL_FAILED"
	CodeDiscoveryFailed      ErrorCode = "OIDC_DISCOVERY_FAILED"
	CodeExchangeFailed       ErrorCode = "OIDC_EXCHANGE_FAILED"
	CodeTokenInvalid         ErrorCode = "OIDC_TOKEN_INVALID"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (errorValue *Error) Error() string { return string(errorValue.code) }
func (errorValue *Error) GoString() string {
	if errorValue == nil {
		return "oidc.Error{[REDACTED]}"
	}
	return "oidc.Error{code:" + string(errorValue.code) + ", cause:[REDACTED]}"
}
func (errorValue *Error) Unwrap() error { return errorValue.cause }

func CodeOf(err error) ErrorCode {
	var oidcError *Error
	if errors.As(err, &oidcError) {
		return oidcError.code
	}
	return CodeTokenInvalid
}

// ProviderConfiguration is the safe, revision-bound projection from the
// identity repository. ClientSecretReference is intentionally excluded: the
// protocol boundary accepts a secret only ephemerally at exchange time from a
// future secret provider.
type ProviderConfiguration struct {
	IssuerURL         string
	ClientID          string
	RedirectURL       string
	SigningAlgorithms []string
}

// Attempt contains only transient browser-facing values. The caller writes
// state to the authorization URL and browser binding to a secure cookie, then
// persists only the corresponding digests in the identity repository.
type Attempt struct {
	state                string
	nonce                string
	pkceVerifier         string
	browserBinding       string
	stateDigest          identity.KeyedDigest
	nonceDigest          identity.KeyedDigest
	pkceVerifierDigest   identity.KeyedDigest
	browserBindingDigest identity.KeyedDigest
	origin               attemptOrigin
}

type attemptOrigin uint8

const (
	attemptOriginFresh attemptOrigin = iota + 1
	attemptOriginRestored
)

func (Attempt) String() string   { return "oidc.Attempt{[REDACTED]}" }
func (Attempt) GoString() string { return "oidc.Attempt{[REDACTED]}" }

// TransportMaterial releases raw values only from an Attempt created by the
// reviewed CSPRNG constructor. Callers cannot construct a valid Attempt with a
// composite literal because the proof bit and all material are private.
func (value Attempt) TransportMaterial() (state, nonce, pkceVerifier, browserBinding string, ok bool) {
	if !validAttempt(value) || value.origin != attemptOriginFresh {
		return "", "", "", "", false
	}
	return value.state, value.nonce, value.pkceVerifier, value.browserBinding, true
}

func (value Attempt) StateDigest() identity.KeyedDigest          { return value.stateDigest }
func (value Attempt) NonceDigest() identity.KeyedDigest          { return value.nonceDigest }
func (value Attempt) PKCEVerifierDigest() identity.KeyedDigest   { return value.pkceVerifierDigest }
func (value Attempt) BrowserBindingDigest() identity.KeyedDigest { return value.browserBindingDigest }

// Subject is the only completed OIDC identity output. The raw OIDC subject
// remains local to ExchangeAndVerify and is immediately converted to a keyed
// digest with a dedicated domain-separation label.
type Subject struct {
	Digest    identity.KeyedDigest
	ExpiresAt time.Time
}

// Digestor is backed by an organization-scoped HMAC key obtained from a
// secret/KMS adapter. The reviewed primitive is shared with the browser-session
// transport boundary; every admitted purpose remains explicitly domain-separated.
type Digestor interface {
	Digest(purpose, raw string) (identity.KeyedDigest, error)
	// KeyMaterialFingerprint is SHA-256 of the exact HMAC key bytes and lets
	// trusted startup composition reject cross-purpose key aliasing.
	KeyMaterialFingerprint() [32]byte
}

// HMACDigestor owns one in-memory HMAC key. Copies of the handle share the
// same private lifecycle state, so closing any copy closes every copy.
type HMACDigestor struct {
	state *hmacDigestorState
}

type hmacDigestorState struct {
	mu         sync.RWMutex
	closed     bool
	keyVersion uint32
	secret     []byte
}

var _ Digestor = (*HMACDigestor)(nil)

func (HMACDigestor) String() string   { return "[REDACTED DIGESTOR]" }
func (HMACDigestor) GoString() string { return "oidc.HMACDigestor{[REDACTED]}" }

// NewHMACDigestor creates an in-memory digestor which owns a private copy of
// secret. The caller must close the returned handle when it is no longer used.
func NewHMACDigestor(keyVersion uint32, secret []byte) (*HMACDigestor, error) {
	if keyVersion == 0 || len(secret) < 32 || allZero(secret) {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	copySecret := append([]byte(nil), secret...)
	return &HMACDigestor{state: &hmacDigestorState{keyVersion: keyVersion, secret: copySecret}}, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func (digestor *HMACDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	if digestor == nil || digestor.state == nil {
		return identity.KeyedDigest{}, &Error{code: CodeMaterialFailed}
	}
	digestor.state.mu.RLock()
	defer digestor.state.mu.RUnlock()
	if digestor.state.closed {
		return identity.KeyedDigest{}, &Error{code: CodeMaterialFailed}
	}
	if !validPurpose(purpose) || raw == "" || !utf8.ValidString(raw) {
		return identity.KeyedDigest{}, &Error{code: CodeMaterialFailed}
	}
	mac := hmac.New(sha256.New, digestor.state.secret)
	_, _ = io.WriteString(mac, "knowvault:oidc:"+purpose+":")
	_, _ = io.WriteString(mac, raw)
	encoded := "hmac-sha256:k" + decimal(digestor.state.keyVersion) + ":" + encodeHex(mac.Sum(nil))
	digest, err := identity.NewKeyedDigest(encoded)
	if err != nil {
		return identity.KeyedDigest{}, &Error{code: CodeMaterialFailed, cause: err}
	}
	return digest, nil
}

func (digestor *HMACDigestor) KeyMaterialFingerprint() [32]byte {
	if digestor == nil || digestor.state == nil {
		return [32]byte{}
	}
	digestor.state.mu.RLock()
	defer digestor.state.mu.RUnlock()
	if digestor.state.closed {
		return [32]byte{}
	}
	return sha256.Sum256(digestor.state.secret)
}

// Close idempotently closes every copy of this handle and zeroizes the
// retained key bytes before releasing the backing slice.
func (digestor *HMACDigestor) Close() {
	if digestor == nil || digestor.state == nil {
		return
	}
	digestor.state.mu.Lock()
	defer digestor.state.mu.Unlock()
	if digestor.state.closed {
		return
	}
	clear(digestor.state.secret)
	digestor.state.secret = nil
	digestor.state.keyVersion = 0
	digestor.state.closed = true
}

// NewSecureAttempt obtains 256 bits for each distinct transient value from the
// operating system CSPRNG.
func NewSecureAttempt(digestor Digestor) (Attempt, error) {
	return newAttempt(rand.Reader, digestor)
}

// newAttempt is the package-private deterministic test seam. Production code
// has no API through which it can replace the operating-system CSPRNG.
func newAttempt(entropy io.Reader, digestor Digestor) (Attempt, error) {
	if entropy == nil || digestor == nil {
		return Attempt{}, &Error{code: CodeMaterialFailed}
	}
	state, err := randomURLValue(entropy)
	if err != nil {
		return Attempt{}, err
	}
	nonce, err := randomURLValue(entropy)
	if err != nil {
		return Attempt{}, err
	}
	verifier, err := randomURLValue(entropy)
	if err != nil {
		return Attempt{}, err
	}
	browserBinding, err := randomURLValue(entropy)
	if err != nil {
		return Attempt{}, err
	}
	return buildAttempt(digestor, state, nonce, verifier, browserBinding, attemptOriginFresh)
}

// RestoreTransportAttempt reconstructs one attempt from an already
// authenticated oidctransport record. Restored attempts can complete exchange
// but cannot be sealed again as a new browser login.
func RestoreTransportAttempt(digestor Digestor, state, nonce, pkceVerifier, browserBinding string) (Attempt, error) {
	return buildAttempt(digestor, state, nonce, pkceVerifier, browserBinding, attemptOriginRestored)
}

func buildAttempt(digestor Digestor, state, nonce, pkceVerifier, browserBinding string, origin attemptOrigin) (Attempt, error) {
	if digestor == nil || (origin != attemptOriginFresh && origin != attemptOriginRestored) ||
		!validRawURLValue(state) || !validRawURLValue(nonce) || !validRawURLValue(pkceVerifier) || !validRawURLValue(browserBinding) ||
		!allDistinct(state, nonce, pkceVerifier, browserBinding) {
		return Attempt{}, &Error{code: CodeMaterialFailed}
	}
	stateDigest, err := digestor.Digest("state", state)
	if err != nil {
		return Attempt{}, &Error{code: CodeMaterialFailed, cause: err}
	}
	nonceDigest, err := digestor.Digest("nonce", nonce)
	if err != nil {
		return Attempt{}, &Error{code: CodeMaterialFailed, cause: err}
	}
	verifierDigest, err := digestor.Digest("pkce_verifier", pkceVerifier)
	if err != nil {
		return Attempt{}, &Error{code: CodeMaterialFailed, cause: err}
	}
	browserDigest, err := digestor.Digest("browser_binding", browserBinding)
	if err != nil {
		return Attempt{}, &Error{code: CodeMaterialFailed, cause: err}
	}
	return Attempt{
		state: state, nonce: nonce, pkceVerifier: pkceVerifier, browserBinding: browserBinding,
		stateDigest: stateDigest, nonceDigest: nonceDigest, pkceVerifierDigest: verifierDigest, browserBindingDigest: browserDigest, origin: origin,
	}, nil
}

// Client is a discovered OIDC provider pinned to one reviewed configuration.
// It is safe to cache only within the organization/provider/revision that
// produced configuration; callers must discard it when that revision changes.
type Client struct {
	configuration ProviderConfiguration
	endpoint      oauth2.Endpoint
	verifier      *coreoidc.IDTokenVerifier
	digestor      Digestor
	httpClient    *http.Client
}

func (Client) String() string   { return "oidc.Client{[REDACTED]}" }
func (Client) GoString() string { return "oidc.Client{[REDACTED]}" }

// Discover verifies static configuration, fetches OIDC metadata through the
// supplied HTTP client and constructs an ID-token verifier that checks issuer,
// audience, expiry and exactly the accepted signing algorithms.
func Discover(ctx context.Context, httpClient *HardenedHTTPClient, configuration ProviderConfiguration, digestor Digestor) (*Client, error) {
	if ctx == nil || !httpClient.valid() || digestor == nil || !validConfiguration(configuration) {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	providerContext := coreoidc.ClientContext(ctx, httpClient.client)
	provider, err := coreoidc.NewProvider(providerContext, configuration.IssuerURL)
	if err != nil {
		return nil, &Error{code: CodeDiscoveryFailed, cause: err}
	}
	endpoint := provider.Endpoint()
	if !validHTTPSURL(endpoint.AuthURL) || !validHTTPSURL(endpoint.TokenURL) {
		return nil, &Error{code: CodeDiscoveryFailed}
	}
	verifier := provider.Verifier(&coreoidc.Config{
		ClientID:             configuration.ClientID,
		SupportedSigningAlgs: append([]string(nil), configuration.SigningAlgorithms...),
	})
	return &Client{configuration: cloneConfiguration(configuration), endpoint: endpoint, verifier: verifier, digestor: digestor, httpClient: httpClient.client}, nil
}

// AuthorizationURL builds an Authorization Code + S256 PKCE request. It adds
// only the required openid scope; callers cannot inject scopes or response
// parameters through this API.
func (client *Client) AuthorizationURL(attempt Attempt) (string, error) {
	if client == nil || client.verifier == nil || client.digestor == nil || client.httpClient == nil || !validConfiguration(client.configuration) ||
		!validAttempt(attempt) || !validHTTPSURL(client.endpoint.AuthURL) || !validHTTPSURL(client.endpoint.TokenURL) {
		return "", &Error{code: CodeConfigurationInvalid}
	}
	configuration := oauth2.Config{
		ClientID:    client.configuration.ClientID,
		RedirectURL: client.configuration.RedirectURL,
		Endpoint:    client.endpoint,
		Scopes:      []string{openidScope},
	}
	return configuration.AuthCodeURL(attempt.state,
		oauth2.S256ChallengeOption(attempt.pkceVerifier),
		oauth2.SetAuthURLParam("nonce", attempt.nonce),
	), nil
}

// ExchangeAndVerify exchanges one authorization code and verifies its ID token
// before returning a digest-only subject. The client secret and code are never
// persisted, logged or included in any returned error.
func (client *Client) ExchangeAndVerify(ctx context.Context, authorizationCode, clientSecret string, attempt Attempt) (Subject, error) {
	if client == nil || client.verifier == nil || client.digestor == nil || client.httpClient == nil || ctx == nil || !validAttempt(attempt) ||
		!validHTTPSURL(client.endpoint.TokenURL) || !validAuthorizationCode(authorizationCode) || clientSecret == "" || !utf8.ValidString(clientSecret) {
		return Subject{}, &Error{code: CodeConfigurationInvalid}
	}
	configuration := oauth2.Config{
		ClientID: client.configuration.ClientID, ClientSecret: clientSecret, RedirectURL: client.configuration.RedirectURL,
		Endpoint: client.endpoint, Scopes: []string{openidScope},
	}
	exchangeContext := context.WithValue(ctx, oauth2.HTTPClient, client.httpClient)
	token, err := configuration.Exchange(exchangeContext, authorizationCode, oauth2.VerifierOption(attempt.pkceVerifier))
	if err != nil {
		return Subject{}, &Error{code: CodeExchangeFailed, cause: err}
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Subject{}, &Error{code: CodeTokenInvalid}
	}
	idToken, err := client.verifier.Verify(ctx, rawIDToken)
	if err != nil || idToken.Subject == "" || !utf8.ValidString(idToken.Subject) ||
		subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(attempt.nonce)) != 1 {
		return Subject{}, &Error{code: CodeTokenInvalid, cause: err}
	}
	digest, err := client.digestor.Digest("subject", idToken.Subject)
	if err != nil {
		return Subject{}, &Error{code: CodeTokenInvalid, cause: err}
	}
	return Subject{Digest: digest, ExpiresAt: idToken.Expiry.UTC()}, nil
}

func randomURLValue(entropy io.Reader) (string, error) {
	bytes := make([]byte, rawBytes)
	if _, err := io.ReadFull(entropy, bytes); err != nil {
		return "", &Error{code: CodeMaterialFailed, cause: err}
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func validConfiguration(configuration ProviderConfiguration) bool {
	if !validHTTPSURL(configuration.IssuerURL) || !validHTTPSURL(configuration.RedirectURL) || !validOpaqueClientID(configuration.ClientID) ||
		len(configuration.SigningAlgorithms) == 0 || len(configuration.SigningAlgorithms) > 8 {
		return false
	}
	previous := ""
	for _, algorithm := range configuration.SigningAlgorithms {
		if !validSigningAlgorithm(algorithm) || (previous != "" && algorithm <= previous) {
			return false
		}
		previous = algorithm
	}
	return true
}

// ValidateProviderConfiguration applies the exact provider-configuration
// admission rules used by the protocol boundary. Its error is content-free so
// rejected configuration values cannot escape through logs or transports.
func ValidateProviderConfiguration(configuration ProviderConfiguration) error {
	if !validConfiguration(configuration) {
		return &Error{code: CodeConfigurationInvalid}
	}
	return nil
}

func validAttempt(attempt Attempt) bool {
	return (attempt.origin == attemptOriginFresh || attempt.origin == attemptOriginRestored) && validRawURLValue(attempt.state) && validRawURLValue(attempt.nonce) && validRawURLValue(attempt.pkceVerifier) && validRawURLValue(attempt.browserBinding) &&
		allDistinct(attempt.state, attempt.nonce, attempt.pkceVerifier, attempt.browserBinding) &&
		validDigest(attempt.stateDigest) && validDigest(attempt.nonceDigest) && validDigest(attempt.pkceVerifierDigest) && validDigest(attempt.browserBindingDigest)
}

func allDistinct(values ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validRawURLValue(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(rawBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == rawBytes
}

func validDigest(digest identity.KeyedDigest) bool {
	_, err := identity.NewKeyedDigest(digest.Value())
	return err == nil
}

func validHTTPSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validOpaqueClientID(value string) bool {
	return len(value) >= 3 && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validSigningAlgorithm(value string) bool {
	switch value {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	default:
		return false
	}
}

func validAuthorizationCode(value string) bool {
	return value != "" && len(value) <= maxAuthorizationCodeLength && utf8.ValidString(value) && !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validPurpose(value string) bool {
	switch value {
	case "state", "nonce", "pkce_verifier", "browser_binding", "subject", "session_token", "csrf":
		return true
	default:
		return false
	}
}

func cloneConfiguration(configuration ProviderConfiguration) ProviderConfiguration {
	copy := configuration
	copy.SigningAlgorithms = append([]string(nil), configuration.SigningAlgorithms...)
	return copy
}

func decimal(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func encodeHex(bytes []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(bytes)*2)
	for index, value := range bytes {
		encoded[index*2] = alphabet[value>>4]
		encoded[index*2+1] = alphabet[value&0x0f]
	}
	return string(encoded)
}
