package artifactcrypto

import "errors"

// ErrorCode is a stable, content-free code safe for structured logs and API
// mapping. No error in this package wraps plaintext, ciphertext, a DEK, a KEK
// or an owner tuple.
type ErrorCode string

const (
	CodeUnknownOwner        ErrorCode = "ARTIFACT_CRYPTO_UNKNOWN_OWNER"
	CodeInvalidOwner        ErrorCode = "ARTIFACT_CRYPTO_INVALID_OWNER"
	CodeSealFailed          ErrorCode = "ARTIFACT_CRYPTO_SEAL_FAILED"
	CodeOpenRejected        ErrorCode = "ARTIFACT_CRYPTO_OPEN_REJECTED"
	CodeProviderUnavailable ErrorCode = "ARTIFACT_CRYPTO_PROVIDER_UNAVAILABLE"
	CodeWrapFailed          ErrorCode = "ARTIFACT_CRYPTO_WRAP_FAILED"
	CodeUnwrapRejected      ErrorCode = "ARTIFACT_CRYPTO_UNWRAP_REJECTED"
)

// Error carries only a code. It intentionally retains no wrapped cause because
// crypto, key and payload details are not safe outside this package.
type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

// CodeOf maps any unexpected error to the closed rejection code.
func CodeOf(err error) ErrorCode {
	var value *Error
	if errors.As(err, &value) {
		return value.code
	}
	return CodeOpenRejected
}

var (
	ErrUnknownOwner         = &Error{code: CodeUnknownOwner}
	ErrInvalidOwnerIdentity = &Error{code: CodeInvalidOwner}
)
