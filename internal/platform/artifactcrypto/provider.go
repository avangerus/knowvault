package artifactcrypto

// WrappedDEK is the atomic result of one wrap operation. It carries the wrapped
// bytes together with the exact key reference and version they were sealed
// under, so a caller can persist all three from one value and never re-read
// mutable current-key metadata. The wrap scheme is embedded in the bytes.
type WrappedDEK struct {
	keyReference string
	keyVersion   int64
	bytes        []byte
}

// NewWrappedDEK constructs a wrapped-DEK result. Providers (the mounted backend
// and any future KMS adapter) build it; the codec persists it atomically.
func NewWrappedDEK(keyReference string, keyVersion int64, bytes []byte) WrappedDEK {
	return WrappedDEK{keyReference: keyReference, keyVersion: keyVersion, bytes: append([]byte(nil), bytes...)}
}

func (wrapped WrappedDEK) KeyReference() string { return wrapped.keyReference }
func (wrapped WrappedDEK) KeyVersion() int64    { return wrapped.keyVersion }
func (wrapped WrappedDEK) Bytes() []byte        { return append([]byte(nil), wrapped.bytes...) }

func (WrappedDEK) String() string   { return "artifactcrypto.WrappedDEK{[REDACTED]}" }
func (WrappedDEK) GoString() string { return "artifactcrypto.WrappedDEK{[REDACTED]}" }

// KeyWrappingProvider is the replaceable, tenant-bound boundary that seals and
// recovers a per-artifact data-encryption key without ever exporting the
// key-encryption key to the rest of the application. It is bound at construction
// to exactly one organization from trusted composition; it refuses to wrap or
// unwrap for any other tenant, even when the caller supplies a formally valid
// owner identity.
//
// The on-edge 1.0 reference implementation is the mounted-secret backend in this
// package; a future external-KMS adapter implements the same interface without
// changing the artifact crypto owner or the repository contract. WrapDEK stamps
// the provider's own key reference and version into the atomic result; callers
// never choose the key. UnwrapDEK fails closed when the wrapped key
// reference/version does not match the provider or when the scheme is foreign,
// so an unknown or historical key can never silently decrypt an envelope.
type KeyWrappingProvider interface {
	// OrganizationID is the single tenant this provider is bound to.
	OrganizationID() string
	// WrapDEK returns an atomic, versioned, authenticated wrapped DEK bound to
	// the exact owner identity. It never returns the clear DEK or the KEK, and
	// fails closed on a tenant mismatch.
	WrapDEK(dek []byte, owner OwnerIdentity) (WrappedDEK, error)
	// UnwrapDEK recovers the clear DEK after verifying the tenant, the wrapped
	// key reference/version and the owner binding. The caller must clear the
	// returned slice after use.
	UnwrapDEK(wrapped WrappedDEK, owner OwnerIdentity) ([]byte, error)
	// Close zeroizes any retained key material and makes the provider fail
	// closed. It is safe to call concurrently and repeatedly.
	Close() error
}
