// Package repository is the activated-branch boundary for encrypted artifacts.
//
// It never exposes a generic persist/load capability to application code. An
// artifact can be stored or read only through an activated owner Binding, and a
// Binding routes every write and read through a per-branch SECURITY DEFINER
// database function that atomically proves the owning row, the tenant, the
// single permitted operation and the transactional binding of owning row and
// artifact. Bindings are constructed only at composition time (or by tests
// acting as composition); an owner branch that has no Binding stays inert. The
// runtime role has no raw SELECT/INSERT on the envelope table, so a sibling
// package cannot bypass this boundary with direct or dynamic SQL. This package
// never names that table: the database functions do.
package repository

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// ErrorCode is content-free and safe for structured logs and API mapping.
type ErrorCode string

const (
	CodeInvalid        ErrorCode = "ARTIFACT_REPOSITORY_INVALID"
	CodeInert          ErrorCode = "ARTIFACT_REPOSITORY_BRANCH_INERT"
	CodeDenied         ErrorCode = "ARTIFACT_REPOSITORY_DENIED"
	CodeNotFound       ErrorCode = "ARTIFACT_REPOSITORY_NOT_FOUND"
	CodeUnavailableKey ErrorCode = "ARTIFACT_REPOSITORY_UNAVAILABLE_KEY"
	CodePersistence    ErrorCode = "ARTIFACT_REPOSITORY_PERSISTENCE_FAILED"
)

// Error preserves a safe code and never returns ciphertext, plaintext, a DEK or
// a key reference to an untrusted caller.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps every unexpected dependency error to a safe repository code.
func CodeOf(err error) ErrorCode {
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return repositoryError.code
	}
	return CodePersistence
}

// AuthorizeFunc authorizes a read of one owning row before its artifact is
// disclosed. It runs inside the caller's transaction. A binding cannot be
// activated without one.
type AuthorizeFunc func(ctx context.Context, transaction database.Transaction, access database.AccessContext, owningRowID string) error

// Binding is an activated owner branch. It names the per-branch SECURITY DEFINER
// bind and read functions and carries the domain authorization resolver. It is
// constructed only by composition or by tests acting as composition.
type Binding struct {
	field        artifactcrypto.OwnerField
	bindFunction string
	readFunction string
	authorize    AuthorizeFunc
}

// NewBinding activates one owner branch. The function names must be schema
// `app` identifiers; they are trusted composition constants, never runtime
// input.
func NewBinding(field artifactcrypto.OwnerField, bindFunction, readFunction string, authorize AuthorizeFunc) (Binding, error) {
	if !artifactcrypto.IsOwnerField(field) || !validFunctionName(bindFunction) || !validFunctionName(readFunction) ||
		bindFunction == readFunction || authorize == nil {
		return Binding{}, &Error{code: CodeInvalid}
	}
	return Binding{field: field, bindFunction: bindFunction, readFunction: readFunction, authorize: authorize}, nil
}

// Repository holds the activated bindings. Constructed with none, it is fully
// inert: no artifact can be stored or read.
type Repository struct {
	bindings map[artifactcrypto.OwnerField]Binding
}

// New builds the repository from the activated bindings.
func New(bindings ...Binding) (*Repository, error) {
	registry := make(map[artifactcrypto.OwnerField]Binding, len(bindings))
	for _, binding := range bindings {
		if !artifactcrypto.IsOwnerField(binding.field) || !validFunctionName(binding.bindFunction) ||
			!validFunctionName(binding.readFunction) || binding.authorize == nil {
			return nil, &Error{code: CodeInvalid}
		}
		if _, exists := registry[binding.field]; exists {
			return nil, &Error{code: CodeInvalid}
		}
		registry[binding.field] = binding
	}
	return &Repository{bindings: registry}, nil
}

// Store persists an artifact for an activated branch. It calls the branch's
// SECURITY DEFINER bind function, which verifies the owning row and the tenant
// and, in one transaction, inserts the artifact and links the owning row. A
// branch with no binding is inert. The database makes a committed orphan
// impossible: the runtime cannot insert the artifact any other way.
func (repository *Repository) Store(ctx context.Context, transaction database.Transaction, access database.AccessContext, field artifactcrypto.OwnerField, owningRowID, artifactID string, envelope artifactcrypto.Envelope) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaqueID(owningRowID) || !validOpaqueID(artifactID) || !envelope.Valid() {
		return &Error{code: CodeInvalid}
	}
	// Evidence anchors and normalized text have a second, keyed equality
	// projection.  Keeping the generic 13-argument path unavailable prevents a
	// caller from accidentally persisting one with only the artifact's internal
	// plaintext SHA-256.
	if field == artifactcrypto.EvidenceAnchor || field == artifactcrypto.EvidenceNormalizedText {
		return &Error{code: CodeInvalid}
	}
	binding, ok := repository.bindings[field]
	if !ok {
		return &Error{code: CodeInert}
	}
	// The envelope's tenant and resource must match the trusted access context
	// and owning row; the caller cannot store for another tenant.
	if envelope.OrganizationID() != access.OrganizationID {
		return &Error{code: CodeInvalid}
	}
	if _, err := transaction.Exec(ctx, "SELECT "+binding.bindFunction+"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
		access.OrganizationID, owningRowID, artifactID, envelope.ResourceID(), envelope.Ciphertext(), envelope.SizeBytes(),
		envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(),
		envelope.AADHash(), envelope.PlaintextHash(),
	); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// StoreKeyedProjection persists an artifact whose owner branch also needs a
// tenant-scoped keyed equality projection.  This is intentionally a distinct
// operation from Store: the database bind function has a distinct arity and
// cannot be reached through the generic artifact path.  The activated owners
// requiring it are EvidenceAnchor and EvidenceNormalizedText (ADR-0077).
func (repository *Repository) StoreKeyedProjection(ctx context.Context, transaction database.Transaction, access database.AccessContext,
	field artifactcrypto.OwnerField, owningRowID, artifactID string, envelope artifactcrypto.Envelope,
	projectionDigest string, projectionKeyVersion int) error {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil ||
		!validOpaqueID(owningRowID) || !validOpaqueID(artifactID) || !envelope.Valid() ||
		(field != artifactcrypto.EvidenceAnchor && field != artifactcrypto.EvidenceNormalizedText) ||
		envelope.OrganizationID() != access.OrganizationID ||
		!validKeyedDigest(projectionDigest, projectionKeyVersion) {
		return &Error{code: CodeInvalid}
	}
	binding, ok := repository.bindings[field]
	if !ok {
		return &Error{code: CodeInert}
	}
	if _, err := transaction.Exec(ctx, "SELECT "+binding.bindFunction+"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
		access.OrganizationID, owningRowID, artifactID, envelope.ResourceID(), envelope.Ciphertext(), envelope.SizeBytes(),
		envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(),
		envelope.AADHash(), envelope.PlaintextHash(), projectionDigest, projectionKeyVersion,
	); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

// Fetch loads an artifact for an activated branch. It authorizes the read, then
// calls the branch's SECURITY DEFINER read function, which derives the artifact
// from the trusted owning row for the tenant. The owner identity is rebuilt from
// the branch's typed selector and the resource id returned by the database — the
// caller never supplies an owner identity. The caller then decrypts with the
// codec.
func (repository *Repository) Fetch(ctx context.Context, transaction database.Transaction, access database.AccessContext, field artifactcrypto.OwnerField, owningRowID string) (artifactcrypto.OwnerIdentity, artifactcrypto.Envelope, error) {
	if repository == nil || ctx == nil || !transaction.Valid() || access.Validate() != nil || !validOpaqueID(owningRowID) {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodeInvalid}
	}
	binding, ok := repository.bindings[field]
	if !ok {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodeInert}
	}
	if err := binding.authorize(ctx, transaction, access, owningRowID); err != nil {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodeDenied, cause: err}
	}
	var (
		resourceID, wrappedDEKHash, kekReference, aadHash, plaintextHash string
		ciphertext, nonce, wrappedDEK                                    []byte
		sizeBytes                                                        int
		kekVersion                                                       int64
	)
	err := transaction.QueryRow(ctx, "SELECT resource_id, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash FROM "+binding.readFunction+"($1)", owningRowID).Scan(
		&resourceID, &ciphertext, &sizeBytes, &nonce, &wrappedDEK, &wrappedDEKHash, &kekReference, &kekVersion, &aadHash, &plaintextHash,
	)
	if database.IsNotFound(err) {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodeNotFound}
	}
	if err != nil {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodePersistence, cause: err}
	}
	owner, err := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, resourceID)
	if err != nil {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodePersistence}
	}
	envelope := artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM, ciphertext, sizeBytes, nonce, wrappedDEK,
		wrappedDEKHash, kekReference, kekVersion, aadHash, plaintextHash)
	if !envelope.Valid() {
		return artifactcrypto.OwnerIdentity{}, artifactcrypto.Envelope{}, &Error{code: CodePersistence}
	}
	return owner, envelope, nil
}

// CheckReadiness fails closed when the current tenant still holds active
// artifacts sealed under a key reference/version the provided backend cannot
// supply. It must pass before the artifact runtime is served. It runs inside a
// tenant-scoped transaction and calls a content-free SECURITY DEFINER count.
func (repository *Repository) CheckReadiness(ctx context.Context, transaction database.Transaction, keyReference string, keyVersion int64) error {
	if repository == nil || ctx == nil || !transaction.Valid() || keyReference == "" || keyVersion < 1 {
		return &Error{code: CodeInvalid}
	}
	var unavailable int64
	if err := transaction.QueryRow(ctx, "SELECT app.artifact_unavailable_key_count($1, $2)", keyReference, keyVersion).Scan(&unavailable); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if unavailable != 0 {
		return &Error{code: CodeUnavailableKey}
	}
	return nil
}

func validFunctionName(value string) bool {
	if len(value) < len("app.x") || len(value) > 128 || !strings.HasPrefix(value, "app.") {
		return false
	}
	name := strings.TrimPrefix(value, "app.")
	if name == "" {
		return false
	}
	for index, character := range name {
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if isLower || character == '_' || (index > 0 && isDigit) {
			continue
		}
		return false
	}
	return true
}

// validOpaqueID mirrors app.stage2_opaque_id_is_valid: bounded, trimmed and
// free of control characters.
func validOpaqueID(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validKeyedDigest(value string, keyVersion int) bool {
	if keyVersion < 1 || keyVersion > 999999999 {
		return false
	}
	prefix := "hmac-sha256:k" + strconv.Itoa(keyVersion) + ":"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
