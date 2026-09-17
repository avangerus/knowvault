package registration

import "errors"

// ErrorCode is content-free and safe for structured logs, metrics and API
// mapping. It never carries a path, a title or any source content.
type ErrorCode string

const (
	CodeRequestInvalid ErrorCode = "SOURCE_REQUEST_INVALID"
	CodeDenied         ErrorCode = "SOURCE_DENIED"
	CodeNotFound       ErrorCode = "SOURCE_NOT_FOUND"
	CodeConflict       ErrorCode = "SOURCE_CONFLICT"
	CodeUnavailable    ErrorCode = "SOURCE_UNAVAILABLE"
	CodePersistence    ErrorCode = "SOURCE_PERSISTENCE_FAILED"
	// CodeUploadRejected is UPL-1's single content-free reason a browser
	// upload did not become a stored document: an invalid name, an unknown
	// extension, an oversized file or a payload whose signature bytes do not
	// match its declared extension. internal/source/upload.ErrorCode carries
	// the precise reason as this error's cause for trusted diagnostics only.
	CodeUploadRejected ErrorCode = "SOURCE_UPLOAD_REJECTED"
)

// Error preserves a safe code while retaining its cause only for trusted
// in-process diagnostics.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps every unexpected dependency error to a safe repository code.
func CodeOf(err error) ErrorCode {
	var registrationError *Error
	if errors.As(err, &registrationError) {
		return registrationError.code
	}
	return CodePersistence
}
