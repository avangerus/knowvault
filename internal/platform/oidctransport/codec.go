// Package oidctransport seals the short-lived browser material needed to
// complete one OIDC Authorization Code + PKCE exchange. It owns no HTTP route,
// cookie issuance, tenant selection, persistence, or OIDC network call.
package oidctransport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

const (
	CookieName         = "__Host-knowvault_oidc"
	envelopeVersion    = "v1"
	plaintextSchema    = "oidc-transport-v1"
	aadSchema          = "oidc-cookie-aad-v1"
	keyBytes           = 32
	nonceBytes         = 12
	rawValueBytes      = 32
	maxEnvelopeBytes   = 2048
	maxPlaintextBytes  = 1024
	maxAttemptLifetime = 15 * time.Minute
	maxIJSONInteger    = int64(9007199254740991)
)

// ErrorCode is content-free and safe for a future HTTP transport mapping.
type ErrorCode string

const (
	CodeConfigurationInvalid ErrorCode = "OIDC_TRANSPORT_CONFIGURATION_INVALID"
	CodeSealFailed           ErrorCode = "OIDC_TRANSPORT_SEAL_FAILED"
	CodeOpenRejected         ErrorCode = "OIDC_TRANSPORT_OPEN_REJECTED"
)

// Error intentionally retains no wrapped cause: crypto, JSON, key and raw
// browser-material details are not safe outside this package.
type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

// CodeOf maps any unexpected error to the closed open/decode result.
func CodeOf(err error) ErrorCode {
	var value *Error
	if errors.As(err, &value) {
		return value.code
	}
	return CodeOpenRejected
}

// Record is the exact short-lived OIDC material recovered after a valid
// callback. Its sensitive fields are private and ordinary Go formatting is
// redacted; accessors exist only for the future transport adapter.
type Record struct {
	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	providerRev    int64
	attemptID      string
	state          string
	nonce          string
	pkceVerifier   string
	browserBinding string
	issuedAt       time.Time
	expiresAt      time.Time
}

func (Record) String() string   { return "oidctransport.Record{[REDACTED]}" }
func (Record) GoString() string { return "oidctransport.Record{[REDACTED]}" }

func (value Record) OrganizationID() identity.OrganizationID { return value.organizationID }
func (value Record) ProviderID() identity.ProviderID         { return value.providerID }
func (value Record) ProviderRevision() int64                 { return value.providerRev }
func (value Record) AttemptID() string                       { return value.attemptID }
func (value Record) State() string                           { return value.state }
func (value Record) Nonce() string                           { return value.nonce }
func (value Record) PKCEVerifier() string                    { return value.pkceVerifier }
func (value Record) BrowserBinding() string                  { return value.browserBinding }
func (value Record) IssuedAt() time.Time                     { return value.issuedAt }
func (value Record) ExpiresAt() time.Time                    { return value.expiresAt }

// MatchesState compares callback state without exposing comparison timing.
func (value Record) MatchesState(candidate string) bool {
	return value.valid() && validRawValue(candidate) && subtle.ConstantTimeCompare([]byte(value.state), []byte(candidate)) == 1
}

// RestoreAttempt re-derives all four identity-key digests from authenticated
// browser material. The restored attempt cannot be sealed as a fresh login.
func (value Record) RestoreAttempt(digestor oidc.Digestor) (oidc.Attempt, error) {
	if !value.valid() || digestor == nil {
		return oidc.Attempt{}, &Error{code: CodeOpenRejected}
	}
	attempt, err := oidc.RestoreTransportAttempt(digestor, value.state, value.nonce, value.pkceVerifier, value.browserBinding)
	if err != nil {
		return oidc.Attempt{}, &Error{code: CodeOpenRejected}
	}
	return attempt, nil
}

// NewRecord validates the complete plaintext shape before it can be sealed.
// OIDC opaque values must be the canonical 256-bit base64url values emitted by
// the reviewed OIDC boundary.
func NewRecord(
	organizationID identity.OrganizationID,
	providerID identity.ProviderID,
	providerRevision int64,
	attemptID string,
	attempt oidc.Attempt,
	issuedAt, expiresAt time.Time,
) (Record, error) {
	state, nonce, pkceVerifier, browserBinding, ok := attempt.TransportMaterial()
	if !ok {
		return Record{}, &Error{code: CodeConfigurationInvalid}
	}
	return newRecord(organizationID, providerID, providerRevision, attemptID, state, nonce, pkceVerifier, browserBinding, issuedAt, expiresAt)
}

func newRecord(
	organizationID identity.OrganizationID,
	providerID identity.ProviderID,
	providerRevision int64,
	attemptID, state, nonce, pkceVerifier, browserBinding string,
	issuedAt, expiresAt time.Time,
) (Record, error) {
	record := Record{
		organizationID: organizationID, providerID: providerID, providerRev: providerRevision, attemptID: attemptID,
		state: state, nonce: nonce, pkceVerifier: pkceVerifier, browserBinding: browserBinding,
		issuedAt: issuedAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if !record.valid() {
		return Record{}, &Error{code: CodeConfigurationInvalid}
	}
	return record, nil
}

// Codec is a copy-safe handle to one active AES-256-GCM key for the
// deployment-bound tenant. Copies share lifecycle state: closing any copy
// closes all copies and erases the retained raw key. The key and raw browser
// material are never exposed through formatting.
type Codec struct {
	state *codecState
}

type codecState struct {
	mu         sync.RWMutex
	callbackMu sync.Mutex
	closed     bool

	organizationID identity.OrganizationID
	providerID     identity.ProviderID
	publicOrigin   string
	keyReference   string
	keyID          string
	key            [keyBytes]byte
	entropy        io.Reader
	now            func() time.Time
}

func (Codec) String() string   { return "oidctransport.Codec{[REDACTED]}" }
func (Codec) GoString() string { return "oidctransport.Codec{[REDACTED]}" }

// NewCodec copies exactly one active AES-256 key. Context originates only
// from tenantsecurity's trusted startup construction; it is never selected by
// Host, Forwarded headers, URL, cookie, OIDC state, or request body.
func NewCodec(security tenantsecurity.Context, keyReference, keyID string, key []byte) (*Codec, error) {
	return newCodec(security, keyReference, keyID, key, rand.Reader, time.Now)
}

func newCodec(security tenantsecurity.Context, keyReference, keyID string, key []byte, entropy io.Reader, now func() time.Time) (*Codec, error) {
	keyFingerprint := sha256.Sum256(key)
	if len(key) != keyBytes || !hasNonZeroByte(key) || entropy == nil || now == nil || !validKeyID(keyID) || security.ValidateOIDCTransportKeySelection(keyReference, keyFingerprint) != nil ||
		!validOpaqueID(string(security.OrganizationID())) || !validOpaqueID(string(security.ProviderID())) || !validOrigin(security.PublicOrigin()) {
		return nil, &Error{code: CodeConfigurationInvalid}
	}
	state := &codecState{
		organizationID: security.OrganizationID(), providerID: security.ProviderID(), publicOrigin: security.PublicOrigin(),
		keyReference: keyReference, keyID: keyID, entropy: entropy, now: now,
	}
	copy(state.key[:], key)
	return &Codec{state: state}, nil
}

// Close waits for in-flight Seal and Open operations, erases the retained raw
// key, and closes every copy of this handle. It is safe to call repeatedly.
// AES implementations retain an operation-local expanded key schedule that Go
// does not expose for erasure; Codec deliberately retains no such schedule.
func (codec *Codec) Close() error {
	if codec == nil || codec.state == nil {
		return nil
	}
	state := codec.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	clear(state.key[:])
	state.entropy = nil
	state.now = nil
	state.closed = true
	return nil
}

// Seal validates tenant-bound, live material then returns exactly one bounded
// envelope: v1.<kid>.<nonce b64url>.<ciphertext b64url>.
func (codec *Codec) Seal(record Record) (string, error) {
	if codec == nil || codec.state == nil || !record.valid() {
		return "", &Error{code: CodeSealFailed}
	}
	plaintext, err := marshalRecord(record)
	if err != nil || len(plaintext) > maxPlaintextBytes {
		clear(plaintext)
		return "", &Error{code: CodeSealFailed}
	}
	defer clear(plaintext)
	return codec.sealPlaintextWithRecord(plaintext, record)
}

// Open authenticates and strictly decodes one sealed record. It fails closed
// for a wrong version/key ID, malformed encoding, replay to another tenant or
// origin, unknown/duplicate JSON field, expired material, or invalid shape.
func (codec *Codec) Open(envelope string) (Record, error) {
	if codec == nil || codec.state == nil {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	state := codec.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.validLocked() {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	aead, err := state.newAEADLocked()
	if err != nil {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	nonce, ciphertext, ok := state.parseEnvelopeLocked(envelope, aead.Overhead())
	if !ok {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	defer clear(nonce)
	defer clear(ciphertext)
	aad := state.aadLocked()
	if len(aad) == 0 {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	defer clear(aad)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > maxPlaintextBytes {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	defer clear(plaintext)
	record, err := unmarshalRecord(plaintext)
	canonical, canonicalErr := marshalRecord(record)
	defer clear(canonical)
	if err != nil || canonicalErr != nil || !bytes.Equal(plaintext, canonical) || !record.valid() || !state.matchesTenantLocked(record) || !state.liveLocked(record) {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	return record, nil
}

func (codec *Codec) sealPlaintext(plaintext []byte) (string, error) {
	if codec == nil || codec.state == nil || len(plaintext) == 0 || len(plaintext) > maxPlaintextBytes {
		return "", &Error{code: CodeSealFailed}
	}
	state := codec.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.sealPlaintextLocked(plaintext)
}

func (codec *Codec) sealPlaintextWithRecord(plaintext []byte, record Record) (string, error) {
	state := codec.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.validLocked() || !state.matchesTenantLocked(record) || !state.liveLocked(record) {
		return "", &Error{code: CodeSealFailed}
	}
	return state.sealPlaintextLocked(plaintext)
}

func (state *codecState) sealPlaintextLocked(plaintext []byte) (string, error) {
	if !state.validLocked() || len(plaintext) == 0 || len(plaintext) > maxPlaintextBytes {
		return "", &Error{code: CodeSealFailed}
	}
	aead, err := state.newAEADLocked()
	if err != nil {
		return "", &Error{code: CodeSealFailed}
	}
	nonce := make([]byte, nonceBytes)
	defer clear(nonce)
	state.callbackMu.Lock()
	_, err = io.ReadFull(state.entropy, nonce)
	state.callbackMu.Unlock()
	if err != nil {
		return "", &Error{code: CodeSealFailed}
	}
	aad := state.aadLocked()
	if len(aad) == 0 {
		return "", &Error{code: CodeSealFailed}
	}
	defer clear(aad)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	defer clear(ciphertext)
	envelope := envelopeVersion + "." + state.keyID + "." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext)
	if len(envelope) > maxEnvelopeBytes {
		return "", &Error{code: CodeSealFailed}
	}
	return envelope, nil
}

func (state *codecState) parseEnvelopeLocked(envelope string, overhead int) ([]byte, []byte, bool) {
	if len(envelope) == 0 || len(envelope) > maxEnvelopeBytes || strings.TrimSpace(envelope) != envelope {
		return nil, nil, false
	}
	parts := strings.Split(envelope, ".")
	if len(parts) != 4 || parts[0] != envelopeVersion || parts[1] != state.keyID || !validKeyID(parts[1]) {
		return nil, nil, false
	}
	nonce, nonceErr := canonicalDecode(parts[2])
	ciphertext, ciphertextErr := canonicalDecode(parts[3])
	if nonceErr || ciphertextErr || len(nonce) != nonceBytes || len(ciphertext) < overhead {
		clear(nonce)
		clear(ciphertext)
		return nil, nil, false
	}
	return nonce, ciphertext, true
}

func (codec *Codec) aad() []byte {
	if codec == nil || codec.state == nil {
		return nil
	}
	state := codec.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if !state.validLocked() {
		return nil
	}
	return state.aadLocked()
}

func (state *codecState) aadLocked() []byte {
	raw, err := jsonv2.Marshal(struct {
		Schema         string `json:"schema"`
		CookieName     string `json:"cookie_name"`
		OrganizationID string `json:"organization_id"`
		PublicOrigin   string `json:"public_origin"`
		KeyID          string `json:"kid"`
	}{
		Schema: aadSchema, CookieName: CookieName, OrganizationID: string(state.organizationID), PublicOrigin: state.publicOrigin, KeyID: state.keyID,
	})
	if err != nil {
		return nil
	}
	value := jsontext.Value(raw)
	if err := value.Canonicalize(); err != nil {
		return nil
	}
	return []byte(value)
}

func (codec *Codec) valid() bool {
	if codec == nil || codec.state == nil {
		return false
	}
	state := codec.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.validLocked()
}

func (state *codecState) validLocked() bool {
	return !state.closed && hasNonZeroByte(state.key[:]) && state.entropy != nil && state.now != nil && validOpaqueID(string(state.organizationID)) &&
		validOpaqueID(string(state.providerID)) && validOrigin(state.publicOrigin) && validOpaqueID(state.keyReference) && validKeyID(state.keyID)
}

func (state *codecState) matchesTenantLocked(record Record) bool {
	return record.organizationID == state.organizationID && record.providerID == state.providerID
}

func (state *codecState) liveLocked(record Record) bool {
	state.callbackMu.Lock()
	now := state.now().UTC()
	state.callbackMu.Unlock()
	return record.expiresAt.After(now) && !record.issuedAt.After(now) && record.expiresAt.Sub(record.issuedAt) <= maxAttemptLifetime
}

func (state *codecState) newAEADLocked() (cipher.AEAD, error) {
	block, err := aes.NewCipher(state.key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != nonceBytes {
		return nil, errors.New("invalid AEAD")
	}
	return aead, nil
}

type wireRecord struct {
	Schema           string `json:"schema"`
	OrganizationID   string `json:"organization_id"`
	ProviderID       string `json:"provider_id"`
	ProviderRevision int64  `json:"provider_revision"`
	LoginAttemptID   string `json:"login_attempt_id"`
	State            string `json:"state"`
	Nonce            string `json:"nonce"`
	PKCEVerifier     string `json:"pkce_verifier"`
	BrowserBinding   string `json:"browser_binding"`
	IssuedAt         string `json:"issued_at"`
	ExpiresAt        string `json:"expires_at"`
}

func marshalRecord(record Record) ([]byte, error) {
	raw, err := jsonv2.Marshal(wireRecord{
		Schema: plaintextSchema, OrganizationID: string(record.organizationID), ProviderID: string(record.providerID),
		ProviderRevision: record.providerRev, LoginAttemptID: record.attemptID, State: record.state, Nonce: record.nonce,
		PKCEVerifier: record.pkceVerifier, BrowserBinding: record.browserBinding,
		IssuedAt: record.issuedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: record.expiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}
	value := jsontext.Value(raw)
	if err := value.Canonicalize(); err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func unmarshalRecord(plaintext []byte) (Record, error) {
	var wire wireRecord
	if err := jsonv2.Unmarshal(plaintext, &wire,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.MatchCaseInsensitiveNames(false),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	); err != nil || wire.Schema != plaintextSchema {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, wire.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, wire.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || issuedAt.Location() != time.UTC || expiresAt.Location() != time.UTC {
		return Record{}, &Error{code: CodeOpenRejected}
	}
	return newRecord(identity.OrganizationID(wire.OrganizationID), identity.ProviderID(wire.ProviderID), wire.ProviderRevision,
		wire.LoginAttemptID, wire.State, wire.Nonce, wire.PKCEVerifier, wire.BrowserBinding, issuedAt, expiresAt)
}

func (record Record) valid() bool {
	return validOpaqueID(string(record.organizationID)) && validOpaqueID(string(record.providerID)) && record.providerRev > 0 && record.providerRev <= maxIJSONInteger &&
		validOpaqueID(record.attemptID) && validRawValue(record.state) && validRawValue(record.nonce) && validRawValue(record.pkceVerifier) && validRawValue(record.browserBinding) &&
		allDistinct(record.state, record.nonce, record.pkceVerifier, record.browserBinding) &&
		!record.issuedAt.IsZero() && !record.expiresAt.IsZero() && record.issuedAt.Location() == time.UTC && record.expiresAt.Location() == time.UTC &&
		record.expiresAt.After(record.issuedAt) && record.expiresAt.Sub(record.issuedAt) <= maxAttemptLifetime
}

func validRawValue(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(rawValueBytes) || !utf8.ValidString(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == rawValueBytes && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func canonicalDecode(value string) ([]byte, bool) {
	if value == "" || !utf8.ValidString(value) {
		return nil, true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return decoded, err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value
}

func validOpaqueID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validKeyID(value string) bool {
	if len(value) < 3 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
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

func hasNonZeroByte(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate != 0
}

func validOrigin(value string) bool {
	// tenantsecurity already validates this trusted input. Retain the exact
	// canonical constraints locally so a forged zero/context cannot weaken AAD.
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return false
	}
	hostname := parsed.Hostname()
	return parsed.Scheme == "https" && parsed.Host != "" && hostname != "" && hostname == strings.ToLower(hostname) &&
		!strings.HasSuffix(hostname, ".") && parsed.Port() != "443" && parsed.User == nil && parsed.Opaque == "" &&
		parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}
