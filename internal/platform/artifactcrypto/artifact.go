package artifactcrypto

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
)

const (
	// CipherAES256GCM is the only accepted artifact cipher; it matches the
	// accepted artifact cipher CHECK enforced by the persistence boundary.
	CipherAES256GCM = "AES_256_GCM"

	minPlaintextBytes = 1
	maxPlaintextBytes = 8 << 20 // 8 MiB
	artifactNonceLen  = 12
	gcmTagLen         = 16
)

// Codec is the sole owner of artifact seal and open. It generates a fresh DEK
// and nonce per artifact, encrypts with AES-256-GCM, wraps the DEK through the
// replaceable provider, and recomputes the AAD from the trusted owner tuple on
// open. It never returns plaintext or ciphertext through logging or formatting.
type Codec struct {
	provider KeyWrappingProvider
	entropy  io.Reader
}

func (Codec) String() string   { return "artifactcrypto.Codec{[REDACTED]}" }
func (Codec) GoString() string { return "artifactcrypto.Codec{[REDACTED]}" }

// NewCodec binds the codec to one key-wrapping provider.
func NewCodec(provider KeyWrappingProvider) (*Codec, error) {
	return newCodec(provider, rand.Reader)
}

func newCodec(provider KeyWrappingProvider, entropy io.Reader) (*Codec, error) {
	if provider == nil || entropy == nil {
		return nil, &Error{code: CodeProviderUnavailable}
	}
	return &Codec{provider: provider, entropy: entropy}, nil
}

// Envelope is the persisted artifact ciphertext bundle plus its trusted owner
// tuple. Its ciphertext, nonce and wrapped DEK are private; formatting is
// redacted so a log statement can never disclose them. The repository assigns
// the artifact id and persists the envelope in the owning row's transaction.
type Envelope struct {
	organizationID   string
	ownerTable       string
	ownerColumn      string
	resourceType     string
	resourceID       string
	field            string
	aadSchemaVersion string
	cipher           string
	ciphertext       []byte
	sizeBytes        int
	nonce            []byte
	wrappedDEK       []byte
	wrappedDEKHash   string
	kekReference     string
	kekVersion       int64
	aadHash          string
	plaintextHash    string
}

func (Envelope) String() string   { return "artifactcrypto.Envelope{[REDACTED]}" }
func (Envelope) GoString() string { return "artifactcrypto.Envelope{[REDACTED]}" }

func (envelope Envelope) OrganizationID() string   { return envelope.organizationID }
func (envelope Envelope) OwnerTable() string       { return envelope.ownerTable }
func (envelope Envelope) OwnerColumn() string      { return envelope.ownerColumn }
func (envelope Envelope) ResourceType() string     { return envelope.resourceType }
func (envelope Envelope) ResourceID() string       { return envelope.resourceID }
func (envelope Envelope) Field() string            { return envelope.field }
func (envelope Envelope) AADSchemaVersion() string { return envelope.aadSchemaVersion }
func (envelope Envelope) Cipher() string           { return envelope.cipher }
func (envelope Envelope) SizeBytes() int           { return envelope.sizeBytes }
func (envelope Envelope) WrappedDEKHash() string   { return envelope.wrappedDEKHash }
func (envelope Envelope) KEKReference() string     { return envelope.kekReference }
func (envelope Envelope) KEKVersion() int64        { return envelope.kekVersion }
func (envelope Envelope) AADHash() string          { return envelope.aadHash }
func (envelope Envelope) PlaintextHash() string    { return envelope.plaintextHash }

// Ciphertext, Nonce and WrappedDEK return fresh copies so a caller cannot
// mutate the envelope's retained buffers.
func (envelope Envelope) Ciphertext() []byte { return append([]byte(nil), envelope.ciphertext...) }
func (envelope Envelope) Nonce() []byte      { return append([]byte(nil), envelope.nonce...) }
func (envelope Envelope) WrappedDEK() []byte { return append([]byte(nil), envelope.wrappedDEK...) }

// NewEnvelopeFromStorage rebuilds an envelope from trusted stored columns. The
// repository is the only caller; it passes the exact row values read under RLS.
func NewEnvelopeFromStorage(
	owner OwnerIdentity, cipher string, ciphertext []byte, sizeBytes int, nonce, wrappedDEK []byte,
	wrappedDEKHash, kekReference string, kekVersion int64, aadHash, plaintextHash string,
) Envelope {
	return Envelope{
		organizationID: owner.organizationID, ownerTable: owner.ownerTable, ownerColumn: owner.ownerColumn,
		resourceType: owner.resourceType, resourceID: owner.resourceID, field: owner.field,
		aadSchemaVersion: AADSchemaVersion, cipher: cipher,
		ciphertext: append([]byte(nil), ciphertext...), sizeBytes: sizeBytes,
		nonce: append([]byte(nil), nonce...), wrappedDEK: append([]byte(nil), wrappedDEK...),
		wrappedDEKHash: wrappedDEKHash, kekReference: kekReference, kekVersion: kekVersion,
		aadHash: aadHash, plaintextHash: plaintextHash,
	}
}

func (envelope Envelope) ownerIdentity() OwnerIdentity {
	return OwnerIdentity{
		organizationID: envelope.organizationID, ownerTable: envelope.ownerTable, ownerColumn: envelope.ownerColumn,
		resourceType: envelope.resourceType, resourceID: envelope.resourceID, field: envelope.field,
	}
}

// Valid reports whether the envelope is a well-formed, persistable artifact.
// The repository uses it to fail closed before an INSERT.
func (envelope Envelope) Valid() bool { return envelope.validShape() }

func (envelope Envelope) validShape() bool {
	return envelope.ownerIdentity().valid() && envelope.aadSchemaVersion == AADSchemaVersion &&
		envelope.cipher == CipherAES256GCM && envelope.sizeBytes >= minPlaintextBytes && envelope.sizeBytes <= maxPlaintextBytes &&
		len(envelope.ciphertext) == envelope.sizeBytes+gcmTagLen && len(envelope.nonce) == artifactNonceLen &&
		len(envelope.wrappedDEK) >= wrappedDEKMinLen && envelope.kekReference != "" && envelope.kekVersion >= 1
}

// Seal encrypts one payload for the exact owner. It fails closed on an invalid
// owner, an out-of-range plaintext size, a weak DEK/nonce source, or a provider
// wrap failure.
func (codec *Codec) Seal(owner OwnerIdentity, plaintext []byte) (Envelope, error) {
	if codec == nil || codec.provider == nil || codec.entropy == nil || !owner.valid() {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	if codec.provider.OrganizationID() != owner.organizationID {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	if len(plaintext) < minPlaintextBytes || len(plaintext) > maxPlaintextBytes {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	aad, err := artifactAAD(owner)
	if err != nil {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	defer clear(aad)

	dek := make([]byte, dekBytes)
	defer clear(dek)
	nonce := make([]byte, artifactNonceLen)
	defer clear(nonce)
	if _, err := io.ReadFull(codec.entropy, dek); err != nil || !hasNonZeroByte(dek) {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	if _, err := io.ReadFull(codec.entropy, nonce); err != nil {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	aead, err := newAEAD(dek)
	if err != nil {
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	if len(ciphertext) != len(plaintext)+gcmTagLen {
		clear(ciphertext)
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	wrapped, err := codec.provider.WrapDEK(dek, owner)
	wrappedBytes := wrapped.Bytes()
	kekReference := wrapped.KeyReference()
	kekVersion := wrapped.KeyVersion()
	if err != nil || len(wrappedBytes) < wrappedDEKMinLen || kekReference == "" || kekVersion < 1 {
		clear(ciphertext)
		clear(wrappedBytes)
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	envelope := Envelope{
		organizationID: owner.organizationID, ownerTable: owner.ownerTable, ownerColumn: owner.ownerColumn,
		resourceType: owner.resourceType, resourceID: owner.resourceID, field: owner.field,
		aadSchemaVersion: AADSchemaVersion, cipher: CipherAES256GCM,
		ciphertext: ciphertext, sizeBytes: len(plaintext), nonce: append([]byte(nil), nonce...), wrappedDEK: wrappedBytes,
		wrappedDEKHash: hashDigest(wrappedBytes), kekReference: kekReference, kekVersion: kekVersion,
		aadHash: hashDigest(aad), plaintextHash: hashDigest(plaintext),
	}
	if !envelope.validShape() {
		clear(ciphertext)
		clear(wrappedBytes)
		return Envelope{}, &Error{code: CodeSealFailed}
	}
	return envelope, nil
}

// Open decrypts one envelope for the exact owner. The owner tuple is recomputed
// from the trusted repository mapping by the caller and must equal the stored
// owner columns; the AAD is rebuilt from it, never from the envelope or an API
// argument. It fails closed on any owner mismatch, unknown key, tampered
// ciphertext/nonce/tag/wrapped DEK, or integrity-hash mismatch. The caller must
// clear the returned plaintext after use.
func (codec *Codec) Open(owner OwnerIdentity, envelope Envelope) ([]byte, error) {
	if codec == nil || codec.provider == nil || !owner.valid() || !envelope.validShape() {
		return nil, &Error{code: CodeOpenRejected}
	}
	if codec.provider.OrganizationID() != owner.organizationID || !sameOwner(owner, envelope.ownerIdentity()) {
		return nil, &Error{code: CodeOpenRejected}
	}
	aad, err := artifactAAD(owner)
	if err != nil {
		return nil, &Error{code: CodeOpenRejected}
	}
	defer clear(aad)
	if subtle.ConstantTimeCompare([]byte(hashDigest(aad)), []byte(envelope.aadHash)) != 1 {
		return nil, &Error{code: CodeOpenRejected}
	}
	dek, err := codec.provider.UnwrapDEK(NewWrappedDEK(envelope.kekReference, envelope.kekVersion, envelope.wrappedDEK), owner)
	if err != nil || len(dek) != dekBytes {
		clear(dek)
		return nil, &Error{code: CodeOpenRejected}
	}
	defer clear(dek)
	aead, err := newAEAD(dek)
	if err != nil {
		return nil, &Error{code: CodeOpenRejected}
	}
	plaintext, err := aead.Open(nil, envelope.nonce, envelope.ciphertext, aad)
	if err != nil {
		clear(plaintext)
		return nil, &Error{code: CodeOpenRejected}
	}
	if len(plaintext) != envelope.sizeBytes || subtle.ConstantTimeCompare([]byte(hashDigest(plaintext)), []byte(envelope.plaintextHash)) != 1 {
		clear(plaintext)
		return nil, &Error{code: CodeOpenRejected}
	}
	return plaintext, nil
}

func sameOwner(left, right OwnerIdentity) bool {
	return left.organizationID == right.organizationID && left.ownerTable == right.ownerTable &&
		left.ownerColumn == right.ownerColumn && left.resourceType == right.resourceType &&
		left.resourceID == right.resourceID && left.field == right.field
}
