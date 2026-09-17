// Package upload is the pure, capability-free validation boundary for a
// browser-uploaded document (UPL-1). It has no database, network or
// filesystem authority: given a caller-supplied file name and the file's
// bytes, it decides the sanitized object key, the declared format and the
// coarse media family from the leading signature bytes -- never from the
// name's extension alone, matching the same "content over extension" rule
// internal/connector/folder already enforces for a mounted directory.
//
// Both the write side (registration.Service.UploadDocuments, which stores an
// accepted upload) and the read side (the ingestion worker's upload-backed
// observation adapter) import this package so the accepted-format contract
// cannot drift between the two.
package upload

import (
	"strings"
	"unicode/utf8"
)

// MaxFileBytes bounds one uploaded file. It matches the FOLDER connector's
// existing per-object ceiling class (source-scope.schema.json maxFileBytes)
// so an upload cannot smuggle in an object no mounted-folder scope could ever
// admit.
const MaxFileBytes = 100 << 20 // 100 MiB

// MaxTotalBytes bounds one HTTP upload request (one or many files).
const MaxTotalBytes = 500 << 20 // 500 MiB

// MaxFilesPerRequest bounds the number of files one HTTP upload request may
// carry, independent of their size.
const MaxFilesPerRequest = 200

// MaxObjectKeyLength mirrors the source_uploaded_document.object_key CHECK.
const MaxObjectKeyLength = 300

// Family is the coarse signature-detected media family, shared with the
// folder connector's own family vocabulary (MediaFamily) so the ingestion
// pipeline's expectedMediaFamily gate accepts an uploaded object exactly like
// a mounted one.
type Family string

const (
	FamilyText  Family = "TEXT"
	FamilyPDF   Family = "PDF"
	FamilyOOXML Family = "OOXML"
)

// ErrorCode is a content-free reason an upload was refused.
type ErrorCode string

const (
	CodeNameInvalid       ErrorCode = "UPLOAD_NAME_INVALID"
	CodeExtensionUnknown  ErrorCode = "UPLOAD_EXTENSION_UNSUPPORTED"
	CodeEmpty             ErrorCode = "UPLOAD_EMPTY"
	CodeTooLarge          ErrorCode = "UPLOAD_TOO_LARGE"
	CodeTooManyFiles      ErrorCode = "UPLOAD_TOO_MANY_FILES"
	CodeTotalTooLarge     ErrorCode = "UPLOAD_TOTAL_TOO_LARGE"
	CodeSignatureMismatch ErrorCode = "UPLOAD_SIGNATURE_MISMATCH"
	CodeInvalidUTF8       ErrorCode = "UPLOAD_INVALID_UTF8"
)

// Error preserves a content-free code; it never carries the file name or bytes.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string { return string(e.Code) }

func fail(code ErrorCode) error { return &Error{Code: code} }

// CodeOf maps any error to a safe, loggable code.
func CodeOf(err error) ErrorCode {
	if typed, ok := err.(*Error); ok && typed != nil {
		return typed.Code
	}
	return CodeSignatureMismatch
}

// extensionFormat is the closed set this MVP accepts, matching UPL-1's
// contract: pdf/docx/xlsx/pptx/txt/md/html/csv. It is deliberately a strict
// subset of the FOLDER connector's full format allowlist (PRODUCT_CONSTITUTION
// §5 lists more); widening it is a product decision, not a parsing accident.
var extensionFormat = map[string]struct {
	format    string
	family    Family
	mediaType string
}{
	"pdf":      {"PDF", FamilyPDF, "application/pdf"},
	"docx":     {"DOCX", FamilyOOXML, "application/zip"},
	"pptx":     {"PPTX", FamilyOOXML, "application/zip"},
	"xlsx":     {"XLSX", FamilyOOXML, "application/zip"},
	"txt":      {"TXT", FamilyText, "text/plain"},
	"md":       {"MARKDOWN", FamilyText, "text/plain"},
	"markdown": {"MARKDOWN", FamilyText, "text/plain"},
	"html":     {"HTML", FamilyText, "text/plain"},
	"htm":      {"HTML", FamilyText, "text/plain"},
	"csv":      {"CSV", FamilyText, "text/plain"},
}

// Accepted is the sorted, human-facing list of accepted extensions, used only
// to render the UI's upload-area hint text.
var Accepted = []string{"pdf", "docx", "pptx", "xlsx", "txt", "md", "html", "csv"}

// Result is one accepted upload's validated, canonical shape.
type Result struct {
	ObjectKey       string
	DeclaredFormat  string
	MediaType       string
	MediaFamily     Family
	ContentByteSize int64
}

// SanitizeObjectKey reduces a caller-supplied file name (which may carry a
// webkitdirectory relative path, "..", drive letters or control characters)
// to the flat, safe object key this table's CHECK constraint accepts: the
// final path segment only, NFC-normalized, control-character free, bounded in
// length, and never "." or "..". A folder upload's subdirectory structure is
// intentionally not preserved as a nested key -- this is the browser-upload
// surface's whole point: no path or containment concept for the owner to get
// wrong. A colliding name is not an error here: the caller resolves it as a
// new version of the same object, exactly like a changed file on a mounted
// folder.
func SanitizeObjectKey(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fail(CodeNameInvalid)
	}
	normalized := strings.NewReplacer("\\", "/").Replace(name)
	segments := strings.Split(normalized, "/")
	base := segments[len(segments)-1]
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == ".." {
		return "", fail(CodeNameInvalid)
	}
	var builder strings.Builder
	for _, r := range base {
		switch {
		case r < 0x20 || r == 0x7f:
			return "", fail(CodeNameInvalid)
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|':
			builder.WriteRune('_')
		default:
			builder.WriteRune(r)
		}
	}
	sanitized := builder.String()
	if len(sanitized) > MaxObjectKeyLength {
		ext := extensionOf(sanitized)
		keep := MaxObjectKeyLength - len(ext)
		if keep < 1 {
			return "", fail(CodeNameInvalid)
		}
		stem := sanitized[:len(sanitized)-len(ext)]
		if len(stem) > keep {
			stem = stem[:keep]
		}
		sanitized = stem + ext
	}
	if sanitized == "" || sanitized == "." || sanitized == ".." {
		return "", fail(CodeNameInvalid)
	}
	return sanitized, nil
}

func extensionOf(name string) string {
	dot := strings.LastIndexByte(name, '.')
	if dot < 0 {
		return ""
	}
	return name[dot:]
}

// Validate sanitizes the file name, classifies the content's leading
// signature bytes and requires that family to match the extension's declared
// format -- the "check the type from content, not the extension" rule. It
// never trusts the caller-declared media type; mediaType/mediaFamily in the
// Result are always the ones this package derived from content.
func Validate(name string, content []byte) (Result, error) {
	objectKey, err := SanitizeObjectKey(name)
	if err != nil {
		return Result{}, err
	}
	if len(content) == 0 {
		return Result{}, fail(CodeEmpty)
	}
	if len(content) > MaxFileBytes {
		return Result{}, fail(CodeTooLarge)
	}
	dot := strings.LastIndexByte(objectKey, '.')
	if dot < 0 || dot == len(objectKey)-1 {
		return Result{}, fail(CodeExtensionUnknown)
	}
	ext := strings.ToLower(objectKey[dot+1:])
	spec, known := extensionFormat[ext]
	if !known {
		return Result{}, fail(CodeExtensionUnknown)
	}
	family := classify(content)
	if family != spec.family {
		return Result{}, fail(CodeSignatureMismatch)
	}
	if family == FamilyText && (!utf8.Valid(content) || containsNUL(content)) {
		return Result{}, fail(CodeInvalidUTF8)
	}
	return Result{
		ObjectKey: objectKey, DeclaredFormat: spec.format,
		MediaType: spec.mediaType, MediaFamily: family,
		ContentByteSize: int64(len(content)),
	}, nil
}

// classify performs the same bounded, content-only family detection the
// folder connector performs (internal/connector/folder classify): it never
// trusts an extension and never parses beyond the leading signature.
func classify(content []byte) Family {
	switch {
	case hasPrefix(content, "%PDF-"):
		return FamilyPDF
	case hasPrefix(content, "PK\x03\x04") || hasPrefix(content, "PK\x05\x06") || hasPrefix(content, "PK\x07\x08"):
		return FamilyOOXML
	default:
		return FamilyText
	}
}

func hasPrefix(content []byte, prefix string) bool {
	return len(content) >= len(prefix) && string(content[:len(prefix)]) == prefix
}

func containsNUL(content []byte) bool {
	for _, b := range content {
		if b == 0 {
			return true
		}
	}
	return false
}
