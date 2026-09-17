// Package recovery implements the ADR-0070 §1.5 recovery bundle: the operator
// backup command seals entries into one encrypted bundle whose key material (a
// fresh DEK) is wrapped by a separate recovery key stored outside the bundle.
// The bundle therefore never contains source binaries, clear DEK, recovery-key
// material or signing private keys in readable form (ENCRYPTION.md §4,
// CRY-003). Restore fails closed with a typed error on a missing, wrong or
// cross-tenant recovery key and on a tampered bundle, and never returns a
// partial result under another organization key (ADR-0069, ADR-0070 §1.5).
//
// The package holds no ambient authority: key material lives only in the
// caller's process memory, is zeroized by RecoveryKey.Clear, and never leaves
// the package boundary except as the wrapped DEK inside the bundle.
package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrorCode is content-free and safe for logs and metrics.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "RECOVERY_INVALID"
	CodeDenied      ErrorCode = "RECOVERY_DENIED"
	CodeFailed      ErrorCode = "RECOVERY_FAILED"
	CodePersistence ErrorCode = "RECOVERY_PERSISTENCE_FAILED"
)

// Error preserves a safe code and hides the underlying crypto error.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps any error to a safe code.
func CodeOf(err error) ErrorCode {
	var recoveryError *Error
	if errors.As(err, &recoveryError) {
		return recoveryError.code
	}
	return CodePersistence
}

// formatVersion is the only accepted bundle format.
const formatVersion = 1

// maxEntryNameLength mirrors the mounted-secret flat-name bound.
const maxEntryNameLength = 128

// Entry is one backup item: a flat, validated name and its opaque bytes.
// Entries are created with NewEntry; the name never contains a path
// separator, an absolute path, "." or ".." (validEntryName), so a restore can
// only ever write inside the operator-chosen clean directory.
type Entry struct {
	name string
	data []byte
}

// NewEntry validates the flat name and copies the data.
func NewEntry(name string, data []byte) (*Entry, error) {
	if !validEntryName(name) {
		return nil, &Error{code: CodeInvalid}
	}
	entry := &Entry{name: name, data: make([]byte, len(data))}
	copy(entry.data, data)
	return entry, nil
}

// Name returns the flat entry name.
func (e *Entry) Name() string { return e.name }

// Data returns a copy of the entry bytes.
func (e *Entry) Data() []byte {
	data := make([]byte, len(e.data))
	copy(data, e.data)
	return data
}

// validEntryName admits exactly flat names: non-empty UTF-8, at most 128
// bytes, no path separators, no "." or ".." segments, no NUL or control
// characters, no leading/trailing whitespace. Restore applies the same
// predicate before any entry is returned, so a crafted bundle can never name
// a file outside the restore directory.
func validEntryName(name string) bool {
	if name == "" || len(name) > maxEntryNameLength || !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsAny(name, "/\\") || strings.ContainsAny(name, "\x00\x7f") {
		return false
	}
	if name == "." || name == ".." || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	return true
}

// RecoveryKey is the operator-held key material that unwraps a bundle's DEK.
// It is bound to one organization: a bundle sealed under organization X can
// never be opened by an organization-Y key, and a restore under a different
// organization key is refused before any decryption attempt (ADR-0070 §1.5:
// no partial restore under another organization key).
type RecoveryKey struct {
	org      string
	material [32]byte
}

// NewRecoveryKey binds 32 bytes of key material to an organization. The
// material is copied; call Clear on the finished key to zeroize it.
func NewRecoveryKey(org string, material []byte) (*RecoveryKey, error) {
	if !validOrganizationID(org) || len(material) != 32 {
		return nil, &Error{code: CodeInvalid}
	}
	key := &RecoveryKey{org: org}
	copy(key.material[:], material)
	return key, nil
}

// OrganizationID returns the organization this key is bound to.
func (k *RecoveryKey) OrganizationID() string { return k.org }

// Clear zeroizes the key material.
func (k *RecoveryKey) Clear() { clear(k.material[:]) }

// validOrganizationID admits a non-empty, trimmed, printable organization id.
func validOrganizationID(org string) bool {
	if org == "" || len(org) > 128 || !utf8.ValidString(org) || strings.TrimSpace(org) != org {
		return false
	}
	for _, r := range org {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// bundleBase is the open, authenticated part of the bundle. Its canonical
// serialization is bound as AAD into both cipher layers, so tampering with
// the organization, the creation time or the format version fails every open.
type bundleBase struct {
	FormatVersion  int    `json:"format_version"`
	OrganizationID string `json:"organization_id"`
	CreatedAt      string `json:"created_at"`
}

// bundle is the persisted container: the base plus the two sealed layers.
type bundle struct {
	bundleBase
	WrappedDEK string `json:"wrapped_dek"` // base64(nonce || GCM(DEK))
	Payload    string `json:"payload"`     // base64(nonce || GCM(entry records))
}

// entryRecord is one serialized entry inside the encrypted payload.
type entryRecord struct {
	Name string `json:"name"`
	Data string `json:"data"` // base64
}

// Backup seals entries into one bundle under a fresh DEK. The DEK is wrapped
// by the recovery key; the bundle bytes never contain the recovery key
// material, the DEK, or any entry in readable form. now stamps the header and
// must be supplied by the caller for a deterministic test surface.
func Backup(org string, entries []Entry, key *RecoveryKey, now time.Time) ([]byte, error) {
	if !validOrganizationID(org) || key == nil || org != key.org || now.IsZero() {
		return nil, &Error{code: CodeInvalid}
	}
	if len(entries) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	for _, entry := range entries {
		if !validEntryName(entry.name) {
			return nil, &Error{code: CodeInvalid}
		}
	}

	var dek [32]byte
	if _, err := rand.Read(dek[:]); err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	defer clear(dek[:])

	records := make([]entryRecord, 0, len(entries))
	for _, entry := range entries {
		records = append(records, entryRecord{Name: entry.name, Data: base64.StdEncoding.EncodeToString(entry.data)})
	}
	payloadJSON, err := json.Marshal(records)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}

	header := bundleBase{
		FormatVersion:  formatVersion,
		OrganizationID: org,
		CreatedAt:      now.UTC().Format(time.RFC3339),
	}
	aad, err := baseAAD(header)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	wrapped, err := sealLayer(dek[:], key.material[:], aad)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	sealedPayload, err := sealLayer(payloadJSON, dek[:], aad)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	container := bundle{
		bundleBase: header,
		WrappedDEK: base64.StdEncoding.EncodeToString(wrapped),
		Payload:    base64.StdEncoding.EncodeToString(sealedPayload),
	}
	return json.Marshal(container)
}

// Restore opens a bundle and returns its entries. It fails closed with a
// typed error: a missing or invalid key is CodeInvalid, a bundle sealed for
// another organization is CodeDenied (refused before any decryption attempt),
// and a wrong key, a tampered bundle or an invalid entry name is CodeFailed.
// Entries are returned only after every name validated, so no partial result
// is ever observable.
func Restore(bundleBytes []byte, key *RecoveryKey) ([]Entry, error) {
	if len(bundleBytes) == 0 || key == nil {
		return nil, &Error{code: CodeInvalid}
	}
	var container bundle
	if err := json.Unmarshal(bundleBytes, &container); err != nil {
		return nil, &Error{code: CodeFailed}
	}
	if container.FormatVersion != formatVersion || !validOrganizationID(container.OrganizationID) ||
		container.CreatedAt == "" || container.WrappedDEK == "" || container.Payload == "" {
		return nil, &Error{code: CodeFailed}
	}
	if container.OrganizationID != key.org {
		// A bundle sealed for another organization is refused before any
		// decryption attempt (ENCRYPTION.md §4).
		return nil, &Error{code: CodeDenied}
	}
	aad, err := baseAAD(container.bundleBase)
	if err != nil {
		return nil, &Error{code: CodeFailed}
	}
	wrappedDEK, err := base64.StdEncoding.DecodeString(container.WrappedDEK)
	if err != nil {
		return nil, &Error{code: CodeFailed}
	}
	dek, err := openLayer(wrappedDEK, key.material[:], aad)
	if err != nil {
		return nil, &Error{code: CodeFailed}
	}
	defer clear(dek)
	sealedPayload, err := base64.StdEncoding.DecodeString(container.Payload)
	if err != nil {
		return nil, &Error{code: CodeFailed}
	}
	payloadJSON, err := openLayer(sealedPayload, dek, aad)
	if err != nil {
		return nil, &Error{code: CodeFailed}
	}
	var records []entryRecord
	if err := json.Unmarshal(payloadJSON, &records); err != nil {
		return nil, &Error{code: CodeFailed}
	}
	entries := make([]Entry, 0, len(records))
	for _, record := range records {
		if !validEntryName(record.Name) {
			return nil, &Error{code: CodeFailed}
		}
		data, err := base64.StdEncoding.DecodeString(record.Data)
		if err != nil {
			return nil, &Error{code: CodeFailed}
		}
		entries = append(entries, Entry{name: record.Name, data: data})
	}
	return entries, nil
}

// baseAAD derives the authenticated binding of the open part of the bundle:
// the canonical serialization of the base header. Both cipher layers bind it,
// so any tampering with the open part fails every open.
func baseAAD(header bundleBase) ([]byte, error) {
	canonical, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	return digest[:], nil
}

// sealLayer encrypts plaintext under key with a fresh 96-bit nonce and the
// given AAD; the returned bytes are nonce || ciphertext || tag.
func sealLayer(plaintext, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// openLayer authenticates and decrypts one sealed layer (nonce || ciphertext
// || tag) under key with the given AAD.
func openLayer(sealed, key, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("layer is too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}
