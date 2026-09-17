package artifactcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
)

const (
	dekBytes           = 32
	wrapNonceBytes     = 12
	kekBytes           = 32
	wrappedFormatByte  = 0x01
	wrappedSchemeMount = 0x01
	wrappedDEKMinLen   = 2 + wrapNonceBytes + dekBytes + 16
	maxKEKReferenceLen = 1024
	maxIJSONInteger    = int64(9007199254740991)
)

// MountedProvider is the on-edge 1.0 reference key-wrapping backend. It is bound
// to exactly one organization and owns one copied KEK from the mounted-secret
// ArtifactWrapKey capability; it never exports the KEK. It is a copy-safe handle
// over private shared lifecycle state; closing any copy zeroizes the retained
// KEK and makes every copy fail closed.
type MountedProvider struct {
	state *mountedState
}

type mountedState struct {
	mu             sync.RWMutex
	closed         bool
	organizationID string
	keyReference   string
	keyVersion     int64
	key            [kekBytes]byte
	// Optional previous pair of an in-flight rotation (ADR-0070 §3): reads
	// accept both pairs, writes seal under the active pair only. Zeroed
	// keyVersion marks an absent previous pair.
	prevKeyReference string
	prevKeyVersion   int64
	prevKey          [kekBytes]byte
	entropy          io.Reader
}

func (MountedProvider) String() string   { return "artifactcrypto.MountedProvider{[REDACTED]}" }
func (MountedProvider) GoString() string { return "artifactcrypto.MountedProvider{[REDACTED]}" }

// NewMountedProvider copies exactly one active KEK and binds it to one tenant.
// The composition root reads the raw bytes from the mounted ArtifactWrapKey
// capability, passes them here and clears its own copy immediately after this
// returns. This package never imports the mounted-secret boundary.
func NewMountedProvider(organizationID, keyReference string, keyVersion int64, key []byte) (*MountedProvider, error) {
	return newMountedProvider(organizationID, keyReference, keyVersion, key, rand.Reader)
}

func newMountedProvider(organizationID, keyReference string, keyVersion int64, key []byte, entropy io.Reader) (*MountedProvider, error) {
	return newRotatingMountedProvider(organizationID, keyReference, keyVersion, key, "", 0, nil, entropy)
}

// NewRotatingMountedProvider mounts the active pair plus the optional previous
// pair of an in-flight KEK rotation (ADR-0070 §3). Reads accept both pairs, so
// wrappers still sealed under the previous key open during the re-wrap window;
// writes seal under the active pair only. Unknown versions fail closed. A nil
// or non-32-byte previous key means "no previous pair mounted".
func NewRotatingMountedProvider(organizationID, activeReference string, activeVersion int64, activeKey []byte,
	previousReference string, previousVersion int64, previousKey []byte) (*MountedProvider, error) {
	return newRotatingMountedProvider(organizationID, activeReference, activeVersion, activeKey,
		previousReference, previousVersion, previousKey, rand.Reader)
}

func newRotatingMountedProvider(organizationID, activeReference string, activeVersion int64, activeKey []byte,
	previousReference string, previousVersion int64, previousKey []byte, entropy io.Reader) (*MountedProvider, error) {
	if !validIdentifier(organizationID, 128) || !validKEKReference(activeReference) || activeVersion < 1 || activeVersion > maxIJSONInteger ||
		len(activeKey) != kekBytes || !hasNonZeroByte(activeKey) || entropy == nil {
		return nil, &Error{code: CodeProviderUnavailable}
	}
	state := &mountedState{organizationID: organizationID, keyReference: activeReference, keyVersion: activeVersion, entropy: entropy}
	copy(state.key[:], activeKey)
	if previousKey != nil {
		if len(previousKey) != kekBytes || !hasNonZeroByte(previousKey) ||
			!validKEKReference(previousReference) || previousVersion < 1 || previousVersion > maxIJSONInteger ||
			previousVersion == activeVersion {
			return nil, &Error{code: CodeProviderUnavailable}
		}
		state.prevKeyReference = previousReference
		state.prevKeyVersion = previousVersion
		copy(state.prevKey[:], previousKey)
	}
	return &MountedProvider{state: state}, nil
}

func (provider *MountedProvider) OrganizationID() string {
	if provider == nil || provider.state == nil {
		return ""
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed {
		return ""
	}
	return state.organizationID
}

// WrapDEK seals a fresh 32-byte DEK under the KEK and returns an atomic result
// carrying the wrapped bytes plus the exact key reference and version. It fails
// closed when the owner belongs to a different tenant.
func (provider *MountedProvider) WrapDEK(dek []byte, owner OwnerIdentity) (WrappedDEK, error) {
	if provider == nil || provider.state == nil || len(dek) != dekBytes || !hasNonZeroByte(dek) || !owner.valid() {
		return WrappedDEK{}, &Error{code: CodeWrapFailed}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || owner.organizationID != state.organizationID {
		return WrappedDEK{}, &Error{code: CodeWrapFailed}
	}
	aad, err := wrapAAD(owner, state.keyReference, state.keyVersion)
	if err != nil {
		return WrappedDEK{}, &Error{code: CodeWrapFailed}
	}
	defer clear(aad)
	aead, err := newAEAD(state.key[:])
	if err != nil {
		return WrappedDEK{}, &Error{code: CodeWrapFailed}
	}
	nonce := make([]byte, wrapNonceBytes)
	if _, err := io.ReadFull(state.entropy, nonce); err != nil {
		return WrappedDEK{}, &Error{code: CodeWrapFailed}
	}
	defer clear(nonce)
	sealed := aead.Seal(nil, nonce, dek, aad)
	defer clear(sealed)
	bytes := make([]byte, 0, 2+wrapNonceBytes+len(sealed))
	bytes = append(bytes, wrappedFormatByte, wrappedSchemeMount)
	bytes = append(bytes, nonce...)
	bytes = append(bytes, sealed...)
	return WrappedDEK{keyReference: state.keyReference, keyVersion: state.keyVersion, bytes: bytes}, nil
}

// UnwrapDEK recovers the clear DEK after verifying the tenant, the wrapped key
// reference/version and the mounted scheme. It fails closed on any tenant
// mismatch, unknown key, foreign scheme, corruption or owner mismatch.
func (provider *MountedProvider) UnwrapDEK(wrapped WrappedDEK, owner OwnerIdentity) ([]byte, error) {
	if provider == nil || provider.state == nil || !owner.valid() || len(wrapped.bytes) < wrappedDEKMinLen {
		return nil, &Error{code: CodeUnwrapRejected}
	}
	if wrapped.bytes[0] != wrappedFormatByte || wrapped.bytes[1] != wrappedSchemeMount {
		return nil, &Error{code: CodeUnwrapRejected}
	}
	state := provider.state
	state.mu.RLock()
	defer state.mu.RUnlock()
	if state.closed || owner.organizationID != state.organizationID {
		return nil, &Error{code: CodeUnwrapRejected}
	}
	// Fail closed on an unknown key: the stored reference and version must
	// match the active pair or, during an in-flight rotation (ADR-0070 §3),
	// the mounted previous pair. The AAD of each wrap carries the exact
	// reference/version it was sealed under, so the key and the AAD always
	// come from the same pair.
	reference := state.keyReference
	version := state.keyVersion
	key := state.key[:]
	if subtle.ConstantTimeCompare([]byte(wrapped.keyReference), []byte(reference)) != 1 || wrapped.keyVersion != version {
		if state.prevKeyVersion == 0 ||
			subtle.ConstantTimeCompare([]byte(wrapped.keyReference), []byte(state.prevKeyReference)) != 1 ||
			wrapped.keyVersion != state.prevKeyVersion {
			return nil, &Error{code: CodeUnwrapRejected}
		}
		reference = state.prevKeyReference
		version = state.prevKeyVersion
		key = state.prevKey[:]
	}
	aad, err := wrapAAD(owner, reference, version)
	if err != nil {
		return nil, &Error{code: CodeUnwrapRejected}
	}
	defer clear(aad)
	aead, err := newAEAD(key)
	if err != nil {
		return nil, &Error{code: CodeUnwrapRejected}
	}
	nonce := wrapped.bytes[2 : 2+wrapNonceBytes]
	ciphertext := wrapped.bytes[2+wrapNonceBytes:]
	dek, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(dek) != dekBytes {
		clear(dek)
		return nil, &Error{code: CodeUnwrapRejected}
	}
	return dek, nil
}

// Close zeroizes the retained KEK and makes every copy of this handle fail
// closed. It is safe to call concurrently and repeatedly.
func (provider *MountedProvider) Close() error {
	if provider == nil || provider.state == nil {
		return nil
	}
	state := provider.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	clear(state.key[:])
	clear(state.prevKey[:])
	state.entropy = nil
	state.organizationID = ""
	state.keyReference = ""
	state.keyVersion = 0
	state.prevKeyReference = ""
	state.prevKeyVersion = 0
	state.closed = true
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != wrapNonceBytes {
		return nil, errors.New("invalid AEAD")
	}
	return aead, nil
}

func validKEKReference(value string) bool {
	return value != "" && len(value) <= maxKEKReferenceLen && validIdentifier(value, maxKEKReferenceLen)
}

func hasNonZeroByte(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate != 0
}
