// Package secretmount loads the exact startup secret set from one trusted,
// read-only mount. It has no environment fallback and no generic path API.
package secretmount

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

const (
	DefaultMountRoot         = "/run/knowvault/secrets"
	manifestFilename         = "manifest.json"
	maxManifestBytes         = 64 << 10
	maxDatabaseURL           = 4 << 10
	maxClientSecret          = 4 << 10
	maximumClients           = 64
	maximumSourceCredentials = 64
	manifestSchema           = "knowvault-secret-manifest-v1"
)

// RuntimeGID retains the server/connector mount identity. Workers have their
// own fixed group and must use the explicitly selected worker entry point.
const RuntimeGID = runtimeidentity.ServerGroupID
const WorkerRuntimeGID = runtimeidentity.WorkerGroupID

type ErrorCode string

const (
	CodeUnavailable     ErrorCode = "SECRETS_UNAVAILABLE"
	CodeManifestInvalid ErrorCode = "SECRETS_MANIFEST_INVALID"
	CodeMaterialInvalid ErrorCode = "SECRETS_MATERIAL_INVALID"
	CodeLookupDenied    ErrorCode = "SECRETS_LOOKUP_DENIED"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	var secretError *Error
	if errors.As(err, &secretError) {
		return secretError.code
	}
	return CodeUnavailable
}

// IdentityKey, SessionKey, SourceDigestKey and OIDCTransportKey are deliberately distinct
// capabilities. Their private shapes prevent even explicit Go conversion
// between purposes. Copies share one local lifecycle state; Clear on any copy
// zeroizes every copy without changing the Provider-owned source material.
type IdentityKey struct{ identity *identityKeyState }
type SessionKey struct{ session *sessionKeyState }
type SourceDigestKey struct{ sourceDigest *sourceDigestKeyState }
type OIDCTransportKey struct{ transport *transportKeyState }
type ArtifactWrapKey struct{ artifactWrap *artifactWrapKeyState }

type identityKeyState struct{ material *localKeyMaterial }
type sessionKeyState struct{ material *localKeyMaterial }
type sourceDigestKeyState struct{ material *localKeyMaterial }
type transportKeyState struct{ material *localKeyMaterial }
type artifactWrapKeyState struct{ material *localKeyMaterial }

type localKeyMaterial struct {
	mu        sync.RWMutex
	closed    bool
	reference string
	version   uint32
	keyID     string
	value     [32]byte
}

func (IdentityKey) String() string        { return "secretmount.IdentityKey{[REDACTED]}" }
func (IdentityKey) GoString() string      { return "secretmount.IdentityKey{[REDACTED]}" }
func (SessionKey) String() string         { return "secretmount.SessionKey{[REDACTED]}" }
func (SessionKey) GoString() string       { return "secretmount.SessionKey{[REDACTED]}" }
func (SourceDigestKey) String() string    { return "secretmount.SourceDigestKey{[REDACTED]}" }
func (SourceDigestKey) GoString() string  { return "secretmount.SourceDigestKey{[REDACTED]}" }
func (OIDCTransportKey) String() string   { return "secretmount.OIDCTransportKey{[REDACTED]}" }
func (OIDCTransportKey) GoString() string { return "secretmount.OIDCTransportKey{[REDACTED]}" }
func (ArtifactWrapKey) String() string    { return "secretmount.ArtifactWrapKey{[REDACTED]}" }
func (ArtifactWrapKey) GoString() string  { return "secretmount.ArtifactWrapKey{[REDACTED]}" }

func (value IdentityKey) Reference() string { return value.identity.materialReference() }
func (value IdentityKey) Version() uint32   { return value.identity.materialVersion() }
func (value IdentityKey) Bytes() []byte     { return value.identity.materialBytes() }
func (value IdentityKey) Clear()            { value.identity.clear() }

func (value SessionKey) Reference() string { return value.session.materialReference() }
func (value SessionKey) Version() uint32   { return value.session.materialVersion() }
func (value SessionKey) Bytes() []byte     { return value.session.materialBytes() }
func (value SessionKey) Clear()            { value.session.clear() }

func (value SourceDigestKey) Reference() string { return value.sourceDigest.materialReference() }
func (value SourceDigestKey) Version() uint32   { return value.sourceDigest.materialVersion() }
func (value SourceDigestKey) Bytes() []byte     { return value.sourceDigest.materialBytes() }
func (value SourceDigestKey) Clear()            { value.sourceDigest.clear() }

func (value OIDCTransportKey) Reference() string { return value.transport.materialReference() }
func (value OIDCTransportKey) KeyID() string     { return value.transport.materialKeyID() }
func (value OIDCTransportKey) Bytes() []byte     { return value.transport.materialBytes() }
func (value OIDCTransportKey) Clear()            { value.transport.clear() }

func (value ArtifactWrapKey) Reference() string { return value.artifactWrap.materialReference() }
func (value ArtifactWrapKey) Version() uint32   { return value.artifactWrap.materialVersion() }
func (value ArtifactWrapKey) Bytes() []byte     { return value.artifactWrap.materialBytes() }
func (value ArtifactWrapKey) Clear()            { value.artifactWrap.clear() }

func (state *identityKeyState) materialReference() string {
	if state == nil {
		return ""
	}
	return state.material.referenceValue()
}
func (state *identityKeyState) materialVersion() uint32 {
	if state == nil {
		return 0
	}
	return state.material.versionValue()
}
func (state *identityKeyState) materialBytes() []byte {
	if state == nil {
		return nil
	}
	return state.material.bytesValue()
}
func (state *identityKeyState) clear() {
	if state != nil {
		state.material.clear()
	}
}
func (state *sessionKeyState) materialReference() string {
	if state == nil {
		return ""
	}
	return state.material.referenceValue()
}
func (state *sessionKeyState) materialVersion() uint32 {
	if state == nil {
		return 0
	}
	return state.material.versionValue()
}
func (state *sessionKeyState) materialBytes() []byte {
	if state == nil {
		return nil
	}
	return state.material.bytesValue()
}
func (state *sessionKeyState) clear() {
	if state != nil {
		state.material.clear()
	}
}
func (state *sourceDigestKeyState) materialReference() string {
	if state == nil {
		return ""
	}
	return state.material.referenceValue()
}
func (state *sourceDigestKeyState) materialVersion() uint32 {
	if state == nil {
		return 0
	}
	return state.material.versionValue()
}
func (state *sourceDigestKeyState) materialBytes() []byte {
	if state == nil {
		return nil
	}
	return state.material.bytesValue()
}
func (state *sourceDigestKeyState) clear() {
	if state != nil {
		state.material.clear()
	}
}
func (state *transportKeyState) materialReference() string {
	if state == nil {
		return ""
	}
	return state.material.referenceValue()
}
func (state *transportKeyState) materialKeyID() string {
	if state == nil {
		return ""
	}
	return state.material.keyIDValue()
}
func (state *transportKeyState) materialBytes() []byte {
	if state == nil {
		return nil
	}
	return state.material.bytesValue()
}
func (state *transportKeyState) clear() {
	if state != nil {
		state.material.clear()
	}
}
func (state *artifactWrapKeyState) materialReference() string {
	if state == nil {
		return ""
	}
	return state.material.referenceValue()
}
func (state *artifactWrapKeyState) materialVersion() uint32 {
	if state == nil {
		return 0
	}
	return state.material.versionValue()
}
func (state *artifactWrapKeyState) materialBytes() []byte {
	if state == nil {
		return nil
	}
	return state.material.bytesValue()
}
func (state *artifactWrapKeyState) clear() {
	if state != nil {
		state.material.clear()
	}
}

func (material *localKeyMaterial) referenceValue() string {
	if material == nil {
		return ""
	}
	material.mu.RLock()
	defer material.mu.RUnlock()
	if material.closed {
		return ""
	}
	return material.reference
}
func (material *localKeyMaterial) versionValue() uint32 {
	if material == nil {
		return 0
	}
	material.mu.RLock()
	defer material.mu.RUnlock()
	if material.closed {
		return 0
	}
	return material.version
}
func (material *localKeyMaterial) keyIDValue() string {
	if material == nil {
		return ""
	}
	material.mu.RLock()
	defer material.mu.RUnlock()
	if material.closed {
		return ""
	}
	return material.keyID
}
func (material *localKeyMaterial) bytesValue() []byte {
	if material == nil {
		return nil
	}
	material.mu.RLock()
	defer material.mu.RUnlock()
	if material.closed {
		return nil
	}
	result := make([]byte, len(material.value))
	copy(result, material.value[:])
	return result
}
func (material *localKeyMaterial) clear() {
	if material == nil {
		return
	}
	material.mu.Lock()
	defer material.mu.Unlock()
	if material.closed {
		return
	}
	clear(material.value[:])
	material.reference = ""
	material.version = 0
	material.keyID = ""
	material.closed = true
}

type ownedIdentityKey struct {
	reference string
	version   uint32
	value     [32]byte
}
type ownedSessionKey struct {
	reference string
	version   uint32
	value     [32]byte
}
type ownedSourceDigestKey struct {
	reference string
	version   uint32
	value     [32]byte
}
type ownedTransportKey struct {
	reference string
	keyID     string
	value     [32]byte
}
type ownedArtifactWrapKey struct {
	reference string
	version   uint32
	value     [32]byte
}

type Provider struct {
	state *providerState
}

type providerState struct {
	mu                sync.RWMutex
	closed            bool
	organizationID    identity.OrganizationID
	providerID        identity.ProviderID
	databaseURL       []byte
	identity          ownedIdentityKey
	session           ownedSessionKey
	sourceDigest      ownedSourceDigestKey
	transport         ownedTransportKey
	artifactWrap      ownedArtifactWrapKey
	artifactWrapPrev  *ownedArtifactWrapKey
	clients           map[clientKey][]byte
	sourceCredentials map[string][]byte
}

func (Provider) String() string   { return "secretmount.Provider{[REDACTED]}" }
func (Provider) GoString() string { return "secretmount.Provider{[REDACTED]}" }

type clientKey struct {
	organizationID   string
	providerID       string
	providerRevision int64
	reference        string
}

type manifest struct {
	Schema              string                     `json:"schema"`
	OrganizationID      string                     `json:"organization_id"`
	ProviderID          string                     `json:"provider_id"`
	DatabaseURLFile     string                     `json:"database_url_file"`
	IdentityHMAC        versionedKeyManifest       `json:"identity_hmac"`
	SessionHMAC         versionedKeyManifest       `json:"session_hmac"`
	SourceDigestHMAC    versionedKeyManifest       `json:"source_digest_hmac"`
	OIDCTransportAEAD   transportKeyManifest       `json:"oidc_transport_aead"`
	ArtifactWrapKEK     versionedKeyManifest       `json:"artifact_kek"`
	ArtifactWrapKEKPrev *versionedKeyManifest      `json:"artifact_kek_previous,omitempty"`
	OIDCClients         []clientSecretManifest     `json:"oidc_client_secrets"`
	SourceCredentials   []sourceCredentialManifest `json:"source_credentials,omitempty"`
}

type versionedKeyManifest struct {
	Reference string `json:"reference"`
	Version   uint32 `json:"version"`
	Filename  string `json:"filename"`
}

type transportKeyManifest struct {
	Reference string `json:"reference"`
	KeyID     string `json:"key_id"`
	Filename  string `json:"filename"`
}

type clientSecretManifest struct {
	OrganizationID   string `json:"organization_id"`
	ProviderID       string `json:"provider_id"`
	ProviderRevision int64  `json:"provider_revision"`
	Reference        string `json:"reference"`
	Filename         string `json:"filename"`
}

type sourceCredentialManifest struct {
	Reference string `json:"reference"`
	Filename  string `json:"filename"`
}

// LoadMountedForTenant reads only the compile-time production mount and binds
// the complete in-memory set to the one trusted tenant/provider deployment.
func LoadMountedForTenant(organizationID identity.OrganizationID, providerID identity.ProviderID) (*Provider, error) {
	return loadMountedForTenant(DefaultMountRoot, organizationID, providerID)
}

// LoadWorkerMountedForTenant binds the fixed mount to the ingestion worker
// group. It does not accept a server-group mount as a fallback.
func LoadWorkerMountedForTenant(organizationID identity.OrganizationID, providerID identity.ProviderID) (*Provider, error) {
	return loadMountedForConsumer(DefaultMountRoot, organizationID, providerID, runtimeidentity.Worker)
}

// LoadMounted applies the same strict load to an explicit trusted mount root.
// LoadMountedForTenant remains the only production runtime entry point; this
// variant exists for the deployment operator's mount verification and never
// participates in application composition.
func LoadMounted(rootPath string, organizationID identity.OrganizationID, providerID identity.ProviderID) (*Provider, error) {
	return loadMountedForTenant(rootPath, organizationID, providerID)
}

// LoadWorkerMounted is the operator's explicit-root worker verification seam.
func LoadWorkerMounted(rootPath string, organizationID identity.OrganizationID, providerID identity.ProviderID) (*Provider, error) {
	return loadMountedForConsumer(rootPath, organizationID, providerID, runtimeidentity.Worker)
}

func loadMountedForTenant(rootPath string, organizationID identity.OrganizationID, providerID identity.ProviderID) (*Provider, error) {
	return loadMountedForConsumer(rootPath, organizationID, providerID, runtimeidentity.Server)
}

func loadMountedForConsumer(rootPath string, organizationID identity.OrganizationID, providerID identity.ProviderID, consumer runtimeidentity.MountConsumer) (*Provider, error) {
	if !validID(string(organizationID)) || !validID(string(providerID)) {
		return nil, &Error{code: CodeManifestInvalid}
	}
	root, err := openMountedRootForConsumer(rootPath, consumer)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	defer root.Close()

	rawManifest, err := root.read(manifestFilename, maxManifestBytes)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	defer clear(rawManifest)
	var configuration manifest
	if err := jsonv2.Unmarshal(rawManifest, &configuration,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || !validManifest(configuration) ||
		configuration.OrganizationID != string(organizationID) || configuration.ProviderID != string(providerID) {
		return nil, &Error{code: CodeManifestInvalid}
	}

	databaseURL, err := root.read(configuration.DatabaseURLFile, maxDatabaseURL)
	if err != nil || !validDatabaseURL(databaseURL) {
		return nil, &Error{code: CodeMaterialInvalid}
	}
	defer clear(databaseURL)
	identity, err := loadIdentityKey(root, configuration.IdentityHMAC)
	if err != nil {
		return nil, err
	}
	session, err := loadSessionKey(root, configuration.SessionHMAC)
	if err != nil {
		return nil, err
	}
	sourceDigest, err := loadSourceDigestKey(root, configuration.SourceDigestHMAC)
	if err != nil {
		return nil, err
	}
	transport, err := loadTransportKey(root, configuration.OIDCTransportAEAD)
	if err != nil {
		return nil, err
	}
	artifactWrap, err := loadArtifactWrapKey(root, configuration.ArtifactWrapKEK)
	if err != nil {
		return nil, err
	}
	var artifactWrapPrevious *ownedArtifactWrapKey
	if configuration.ArtifactWrapKEKPrev != nil {
		loaded, loadErr := loadArtifactWrapKey(root, *configuration.ArtifactWrapKEKPrev)
		if loadErr != nil {
			return nil, loadErr
		}
		artifactWrapPrevious = &loaded
	}
	if !keysAreIndependent(identity, session, sourceDigest, transport, artifactWrap, artifactWrapPrevious) {
		return nil, &Error{code: CodeMaterialInvalid}
	}

	clients := make(map[clientKey][]byte, len(configuration.OIDCClients))
	for _, candidate := range configuration.OIDCClients {
		key := clientKey{candidate.OrganizationID, candidate.ProviderID, candidate.ProviderRevision, candidate.Reference}
		if _, exists := clients[key]; exists {
			return nil, &Error{code: CodeManifestInvalid}
		}
		secret, readErr := root.read(candidate.Filename, maxClientSecret)
		if readErr != nil || !validClientSecret(secret) {
			return nil, &Error{code: CodeMaterialInvalid}
		}
		clients[key] = append([]byte(nil), secret...)
		clear(secret)
	}
	sourceCredentials := make(map[string][]byte, len(configuration.SourceCredentials))
	for _, candidate := range configuration.SourceCredentials {
		if _, exists := sourceCredentials[candidate.Reference]; exists {
			return nil, &Error{code: CodeManifestInvalid}
		}
		secret, readErr := root.read(candidate.Filename, maxClientSecret)
		if readErr != nil || !validClientSecret(secret) {
			return nil, &Error{code: CodeMaterialInvalid}
		}
		sourceCredentials[candidate.Reference] = append([]byte(nil), secret...)
		clear(secret)
	}

	return &Provider{state: &providerState{
		organizationID: organizationID, providerID: providerID, databaseURL: append([]byte(nil), databaseURL...),
		identity: identity, session: session, sourceDigest: sourceDigest, transport: transport,
		artifactWrap: artifactWrap, artifactWrapPrev: artifactWrapPrevious, clients: clients,
		sourceCredentials: sourceCredentials,
	}}, nil
}

func (provider *Provider) DatabaseURL() (string, error) {
	if provider == nil || provider.state == nil {
		return "", &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validDatabaseURL(state.databaseURL) {
		return "", &Error{code: CodeUnavailable}
	}
	return string(append([]byte(nil), state.databaseURL...)), nil
}

func (provider *Provider) IdentityKey() (IdentityKey, error) {
	if provider == nil || provider.state == nil {
		return IdentityKey{}, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validIdentityKey(state.identity) {
		return IdentityKey{}, &Error{code: CodeUnavailable}
	}
	material := &localKeyMaterial{reference: state.identity.reference, version: state.identity.version, value: state.identity.value}
	return IdentityKey{identity: &identityKeyState{material: material}}, nil
}

func (provider *Provider) SessionKey() (SessionKey, error) {
	if provider == nil || provider.state == nil {
		return SessionKey{}, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validSessionKey(state.session) {
		return SessionKey{}, &Error{code: CodeUnavailable}
	}
	material := &localKeyMaterial{reference: state.session.reference, version: state.session.version, value: state.session.value}
	return SessionKey{session: &sessionKeyState{material: material}}, nil
}

// SourceDigestKey returns the purpose-specific HMAC capability used for
// source-object and canonical-locator digests. It cannot be passed to the
// identity, session, transport or artifact-wrap constructors by type.
func (provider *Provider) SourceDigestKey() (SourceDigestKey, error) {
	if provider == nil || provider.state == nil {
		return SourceDigestKey{}, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validSourceDigestKey(state.sourceDigest) {
		return SourceDigestKey{}, &Error{code: CodeUnavailable}
	}
	material := &localKeyMaterial{reference: state.sourceDigest.reference, version: state.sourceDigest.version, value: state.sourceDigest.value}
	return SourceDigestKey{sourceDigest: &sourceDigestKeyState{material: material}}, nil
}

func (provider *Provider) OIDCTransportKey() (OIDCTransportKey, error) {
	if provider == nil || provider.state == nil {
		return OIDCTransportKey{}, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validTransportKey(state.transport) {
		return OIDCTransportKey{}, &Error{code: CodeUnavailable}
	}
	material := &localKeyMaterial{reference: state.transport.reference, keyID: state.transport.keyID, value: state.transport.value}
	return OIDCTransportKey{transport: &transportKeyState{material: material}}, nil
}

// ArtifactWrapKey returns a copy-safe capability over the mounted artifact
// key-wrapping KEK. It is deliberately non-convertible to the identity, session
// or transport capabilities. Only the artifact key-wrapping provider composes
// it; the raw KEK is never exposed to the rest of the application.
func (provider *Provider) ArtifactWrapKey() (ArtifactWrapKey, error) {
	if provider == nil || provider.state == nil {
		return ArtifactWrapKey{}, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || !validArtifactWrapKey(state.artifactWrap) {
		return ArtifactWrapKey{}, &Error{code: CodeUnavailable}
	}
	material := &localKeyMaterial{reference: state.artifactWrap.reference, version: state.artifactWrap.version, value: state.artifactWrap.value}
	return ArtifactWrapKey{artifactWrap: &artifactWrapKeyState{material: material}}, nil
}

// ArtifactWrapKeyPrevious returns the optional previous KEK pair mounted for
// an in-flight rotation (ADR-0070 §3). The bool is false when the deployment
// has no rotation window open; the wrap backend then holds exactly one pair.
func (provider *Provider) ArtifactWrapKeyPrevious() (ArtifactWrapKey, bool, error) {
	if provider == nil || provider.state == nil {
		return ArtifactWrapKey{}, false, &Error{code: CodeUnavailable}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed {
		return ArtifactWrapKey{}, false, &Error{code: CodeUnavailable}
	}
	if state.artifactWrapPrev == nil || !validArtifactWrapKey(*state.artifactWrapPrev) {
		return ArtifactWrapKey{}, false, nil
	}
	material := &localKeyMaterial{reference: state.artifactWrapPrev.reference, version: state.artifactWrapPrev.version, value: state.artifactWrapPrev.value}
	return ArtifactWrapKey{artifactWrap: &artifactWrapKeyState{material: material}}, true, nil
}

// Resolve implements the OIDC browser boundary with one exact, in-memory
// tuple lookup. A database reference never becomes a filesystem path.
func (provider *Provider) Resolve(ctx context.Context, request oidcweb.ClientSecretRequest) (string, error) {
	if provider == nil || provider.state == nil || ctx == nil || ctx.Err() != nil {
		return "", &Error{code: CodeLookupDenied}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	secret, exists := state.lookupClientSecret(request)
	if !exists || !validClientSecret(secret) {
		return "", &Error{code: CodeLookupDenied}
	}
	return string(append([]byte(nil), secret...)), nil
}

// ResolveReference returns one exact deployment-mounted opaque secret by its
// reference. It is used by connector workers for credentials whose control
// plane stores only a reference. References must be unique across the mounted
// provider revision; ambiguity fails closed rather than selecting a secret by
// order. The returned value is a caller-owned copy and must be cleared when no
// longer needed.
func (provider *Provider) ResolveReference(ctx context.Context, reference string) (string, error) {
	if provider == nil || provider.state == nil || ctx == nil || ctx.Err() != nil || !validID(reference) {
		return "", &Error{code: CodeLookupDenied}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed {
		return "", &Error{code: CodeLookupDenied}
	}
	var matched []byte
	matches := 0
	for key, secret := range state.clients {
		if key.reference != reference {
			continue
		}
		matched = secret
		matches++
	}
	if source, exists := state.sourceCredentials[reference]; exists {
		matched = source
		matches++
	}
	if matches != 1 {
		return "", &Error{code: CodeLookupDenied}
	}
	if !validClientSecret(matched) {
		return "", &Error{code: CodeLookupDenied}
	}
	return string(append([]byte(nil), matched...)), nil
}

// ValidateClientBinding performs the same exact tuple lookup as Resolve but
// never copies secret material out of the provider. It is intended for
// startup preflight before the HTTP listener becomes reachable.
func (provider *Provider) ValidateClientBinding(ctx context.Context, request oidcweb.ClientSecretRequest) error {
	if provider == nil || provider.state == nil || ctx == nil || ctx.Err() != nil {
		return &Error{code: CodeLookupDenied}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	secret, exists := state.lookupClientSecret(request)
	if !exists || !validClientSecret(secret) {
		return &Error{code: CodeLookupDenied}
	}
	return nil
}

func (state *providerState) lookupClientSecret(request oidcweb.ClientSecretRequest) ([]byte, bool) {
	if state.closed || !validID(string(request.OrganizationID)) || !validID(string(request.ProviderID)) ||
		request.OrganizationID != state.organizationID || request.ProviderID != state.providerID || request.ProviderRevision < 1 || !validID(request.Reference) {
		return nil, false
	}
	secret, exists := state.clients[clientKey{string(request.OrganizationID), string(request.ProviderID), request.ProviderRevision, request.Reference}]
	return secret, exists
}

// Close permanently makes the provider unavailable and clears all mutable
// in-memory secret material. It is safe to call concurrently and repeatedly.
func (provider *Provider) Close() error {
	if provider == nil || provider.state == nil {
		return nil
	}
	state := provider.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	state.closed = true
	clear(state.databaseURL)
	state.databaseURL = nil
	clear(state.identity.value[:])
	clear(state.session.value[:])
	clear(state.sourceDigest.value[:])
	clear(state.transport.value[:])
	clear(state.artifactWrap.value[:])
	if state.artifactWrapPrev != nil {
		clear(state.artifactWrapPrev.value[:])
		state.artifactWrapPrev = nil
	}
	for key, secret := range state.clients {
		clear(secret)
		delete(state.clients, key)
	}
	state.clients = nil
	for reference, secret := range state.sourceCredentials {
		clear(secret)
		delete(state.sourceCredentials, reference)
	}
	state.sourceCredentials = nil
	return nil
}

// SourceCredentialReferences returns the exact non-OIDC source credential
// references present in this immutable mount. It exposes references only,
// never secret material, and is used by the operator when deriving a worker
// mount from a trusted server mount.
func (provider *Provider) SourceCredentialReferences() ([]string, error) {
	if provider == nil || provider.state == nil {
		return nil, &Error{code: CodeLookupDenied}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed {
		return nil, &Error{code: CodeLookupDenied}
	}
	result := make([]string, 0, len(state.sourceCredentials))
	for reference, secret := range state.sourceCredentials {
		if !validID(reference) || !validClientSecret(secret) {
			return nil, &Error{code: CodeLookupDenied}
		}
		result = append(result, reference)
	}
	sort.Strings(result)
	return result, nil
}

func loadIdentityKey(root *mountedRoot, configuration versionedKeyManifest) (ownedIdentityKey, error) {
	material, err := loadKeyBytes(root, configuration.Filename)
	if err != nil {
		return ownedIdentityKey{}, err
	}
	return ownedIdentityKey{reference: configuration.Reference, version: configuration.Version, value: material}, nil
}

func loadSessionKey(root *mountedRoot, configuration versionedKeyManifest) (ownedSessionKey, error) {
	material, err := loadKeyBytes(root, configuration.Filename)
	if err != nil {
		return ownedSessionKey{}, err
	}
	return ownedSessionKey{reference: configuration.Reference, version: configuration.Version, value: material}, nil
}

func loadSourceDigestKey(root *mountedRoot, configuration versionedKeyManifest) (ownedSourceDigestKey, error) {
	material, err := loadKeyBytes(root, configuration.Filename)
	if err != nil {
		return ownedSourceDigestKey{}, err
	}
	return ownedSourceDigestKey{reference: configuration.Reference, version: configuration.Version, value: material}, nil
}

func loadTransportKey(root *mountedRoot, configuration transportKeyManifest) (ownedTransportKey, error) {
	material, err := loadKeyBytes(root, configuration.Filename)
	if err != nil {
		return ownedTransportKey{}, err
	}
	return ownedTransportKey{reference: configuration.Reference, keyID: configuration.KeyID, value: material}, nil
}

func loadArtifactWrapKey(root *mountedRoot, configuration versionedKeyManifest) (ownedArtifactWrapKey, error) {
	material, err := loadKeyBytes(root, configuration.Filename)
	if err != nil {
		return ownedArtifactWrapKey{}, err
	}
	return ownedArtifactWrapKey{reference: configuration.Reference, version: configuration.Version, value: material}, nil
}

func loadKeyBytes(root *mountedRoot, filename string) ([32]byte, error) {
	var result [32]byte
	raw, err := root.read(filename, 64)
	if err != nil || len(raw) != base64.RawURLEncoding.EncodedLen(len(result)) {
		return result, &Error{code: CodeMaterialInvalid}
	}
	defer clear(raw)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(decoded) != len(result) {
		return result, &Error{code: CodeMaterialInvalid}
	}
	defer clear(decoded)
	copy(result[:], decoded)
	return result, nil
}

func validManifest(value manifest) bool {
	if value.Schema != manifestSchema || !validID(value.OrganizationID) || !validID(value.ProviderID) || !validFilename(value.DatabaseURLFile) ||
		!validVersionedManifest(value.IdentityHMAC) || !validVersionedManifest(value.SessionHMAC) || !validVersionedManifest(value.SourceDigestHMAC) ||
		!validTransportManifest(value.OIDCTransportAEAD) || !validVersionedManifest(value.ArtifactWrapKEK) ||
		len(value.OIDCClients) < 1 || len(value.OIDCClients) > maximumClients || len(value.SourceCredentials) > maximumSourceCredentials {
		return false
	}
	seenFiles := map[string]struct{}{value.DatabaseURLFile: {}, value.IdentityHMAC.Filename: {}, value.SessionHMAC.Filename: {}, value.SourceDigestHMAC.Filename: {}, value.OIDCTransportAEAD.Filename: {}, value.ArtifactWrapKEK.Filename: {}}
	expectedFileCount := 6
	if value.ArtifactWrapKEKPrev != nil {
		// The previous pair of a rotation window is a distinct manifest entry:
		// distinct reference, version and file from the active pair.
		if !validVersionedManifest(*value.ArtifactWrapKEKPrev) ||
			value.ArtifactWrapKEKPrev.Reference == value.ArtifactWrapKEK.Reference ||
			value.ArtifactWrapKEKPrev.Version == value.ArtifactWrapKEK.Version ||
			value.ArtifactWrapKEKPrev.Filename == value.ArtifactWrapKEK.Filename {
			return false
		}
		seenFiles[value.ArtifactWrapKEKPrev.Filename] = struct{}{}
		expectedFileCount = 7
	}
	seenClients := make(map[clientKey]struct{}, len(value.OIDCClients))
	seenReferences := make(map[string]struct{}, len(value.OIDCClients)+len(value.SourceCredentials))
	if len(seenFiles) != expectedFileCount {
		return false
	}
	for _, client := range value.OIDCClients {
		if client.OrganizationID != value.OrganizationID || client.ProviderID != value.ProviderID || client.ProviderRevision < 1 || !validID(client.Reference) || !validFilename(client.Filename) {
			return false
		}
		if _, exists := seenFiles[client.Filename]; exists {
			return false
		}
		lookup := clientKey{client.OrganizationID, client.ProviderID, client.ProviderRevision, client.Reference}
		if _, exists := seenClients[lookup]; exists {
			return false
		}
		seenFiles[client.Filename] = struct{}{}
		seenClients[lookup] = struct{}{}
		if _, exists := seenReferences[client.Reference]; exists {
			return false
		}
		seenReferences[client.Reference] = struct{}{}
	}
	for _, credential := range value.SourceCredentials {
		if !validID(credential.Reference) || !validFilename(credential.Filename) {
			return false
		}
		if _, exists := seenFiles[credential.Filename]; exists {
			return false
		}
		if _, exists := seenReferences[credential.Reference]; exists {
			return false
		}
		seenFiles[credential.Filename] = struct{}{}
		seenReferences[credential.Reference] = struct{}{}
	}
	return true
}

func validVersionedManifest(value versionedKeyManifest) bool {
	return validID(value.Reference) && value.Version > 0 && validFilename(value.Filename)
}

func validTransportManifest(value transportKeyManifest) bool {
	return validID(value.Reference) && validTransportKeyID(value.KeyID) && validFilename(value.Filename)
}

func validTransportKeyID(value string) bool {
	if len(value) < 3 || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validFilename(value string) bool {
	return value != "." && value != ".." && len(value) <= 128 && validID(value) && !strings.ContainsAny(value, `/\`)
}

func validID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
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

// ValidID is the single deployment-visible identifier shape for organization,
// provider and mount-reference material: 1..128 characters, letters, digits
// and "_" "-" "." ":", no surrounding whitespace. The deployment operator
// consumes this exact rule for the identifiers it records and writes into
// mounts; it never maintains a second implementation of the shape.
func ValidID(value string) bool { return validID(value) }

// ValidateDatabaseURL applies the closed production database-URL contract to
// externally supplied material before it is written into a generated mount.
// It is the deployment operator's fail-before-write seam; production
// composition still validates the mounted material again at load time.
func ValidateDatabaseURL(raw []byte) error {
	if !validDatabaseURL(raw) {
		return &Error{code: CodeMaterialInvalid}
	}
	return nil
}

func validDatabaseURL(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maxDatabaseURL || !validSecretText(raw) {
		return false
	}
	parsed, err := url.Parse(string(raw))
	if err != nil || parsed.Scheme != "postgres" || parsed.Host == "" || parsed.User == nil || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.RawQuery != "sslmode=verify-full" || parsed.String() != string(raw) ||
		strings.Contains(parsed.Host, ",") || parsed.Path == "" || parsed.Path == "/" || strings.Count(parsed.Path, "/") != 1 {
		return false
	}
	username := parsed.User.Username()
	password, passwordPresent := parsed.User.Password()
	hostname, port, splitErr := net.SplitHostPort(parsed.Host)
	portNumber, portErr := strconv.Atoi(port)
	return splitErr == nil && hostname != "" && hostname == strings.ToLower(hostname) && !strings.HasSuffix(hostname, ".") &&
		portErr == nil && portNumber > 0 && portNumber <= 65535 && username != "" && passwordPresent && password != ""
}

func validClientSecret(raw []byte) bool {
	return len(raw) > 0 && len(raw) <= maxClientSecret && validSecretText(raw)
}

func validSecretText(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for _, character := range string(raw) {
		if character == 0 || character == '\r' || character == '\n' || (character < 0x20 || (character >= 0x7f && character <= 0x9f)) {
			return false
		}
	}
	return true
}

func keysAreIndependent(identity ownedIdentityKey, session ownedSessionKey, sourceDigest ownedSourceDigestKey, transport ownedTransportKey, artifactWrap ownedArtifactWrapKey, artifactWrapPrevious *ownedArtifactWrapKey) bool {
	if !validIdentityKey(identity) || !validSessionKey(session) || !validSourceDigestKey(sourceDigest) || !validTransportKey(transport) || !validArtifactWrapKey(artifactWrap) {
		return false
	}
	if artifactWrapPrevious != nil && !validArtifactWrapKey(*artifactWrapPrevious) {
		return false
	}
	references := []string{identity.reference, session.reference, sourceDigest.reference, transport.reference, artifactWrap.reference}
	fingerprints := [][32]byte{
		sha256.Sum256(identity.value[:]), sha256.Sum256(session.value[:]), sha256.Sum256(sourceDigest.value[:]),
		sha256.Sum256(transport.value[:]), sha256.Sum256(artifactWrap.value[:]),
	}
	if artifactWrapPrevious != nil {
		references = append(references, artifactWrapPrevious.reference)
		fingerprints = append(fingerprints, sha256.Sum256(artifactWrapPrevious.value[:]))
	}
	seenReference := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if _, exists := seenReference[reference]; exists {
			return false
		}
		seenReference[reference] = struct{}{}
	}
	seenFingerprint := make(map[[32]byte]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if _, exists := seenFingerprint[fingerprint]; exists {
			return false
		}
		seenFingerprint[fingerprint] = struct{}{}
	}
	return true
}

func validIdentityKey(value ownedIdentityKey) bool {
	return validID(value.reference) && value.version > 0 && nonzeroKey(value.value)
}

func validSessionKey(value ownedSessionKey) bool {
	return validID(value.reference) && value.version > 0 && nonzeroKey(value.value)
}

func validSourceDigestKey(value ownedSourceDigestKey) bool {
	return validID(value.reference) && value.version > 0 && nonzeroKey(value.value)
}

func validTransportKey(value ownedTransportKey) bool {
	return validID(value.reference) && validTransportKeyID(value.keyID) && nonzeroKey(value.value)
}

func validArtifactWrapKey(value ownedArtifactWrapKey) bool {
	return validID(value.reference) && value.version > 0 && nonzeroKey(value.value)
}

func nonzeroKey(value [32]byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return true
		}
	}
	return false
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
