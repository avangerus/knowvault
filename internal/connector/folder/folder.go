// Package folder is the typed semantic owner of the safe local/SMB folder
// connector. It can do exactly three things and nothing else: discover objects
// inside an exact trusted scope, read a bounded stable snapshot of one object,
// and report a diagnosable quarantine or failure. It never creates a
// SourceObject, SourceVersion, Extraction or Evidence, never persists source
// bytes, and holds no capability to reach PostgreSQL, the catalog, evidence,
// search or any source write API.
//
// Three properties are load-bearing and each is enforced by construction, not by
// review:
//
//  1. Filesystem containment. Every open is resolved against a pinned root
//     handle (os.Root). Traversal, absolute-path substitution, POSIX symlinks
//     and Windows reparse points/junctions fail closed; follow_symlinks is not a
//     field because the connector never follows a link. The root itself is
//     re-checked for a TOCTOU swap before use.
//
//  2. Bounded stable read. Size and media signature are checked before bytes are
//     handed forward; the read is bounded by the scope byte cap; the same open
//     descriptor is re-stat'd after the read, so a file that is replaced,
//     truncated or grown mid-read produces a torn-read quarantine instead of a
//     trusted result.
//
//  3. Transient-content boundary. The connector returns bounded bytes to the
//     next in-process extraction boundary but never writes them anywhere. It has
//     no database, outbox, job, audit or artifact dependency to write them to.
//
// Error and quarantine codes are content-free and safe for structured logs and
// metrics. Source-native paths are carried only inside the typed in-process
// result (they are sensitive and must not reach open telemetry or audit); the
// codes never carry a path, byte or title.
package folder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/pathcanon"
	"knowvault.local/verified-workspace/internal/source/scopeglob"
)

// maximumScopeByteCap is the hard ceiling on a single object read, mirroring the
// folderConfig.max_file_bytes contract maximum (1 GiB). A scope may set a lower
// cap; it can never set a higher one.
const maximumScopeByteCap int64 = 1 << 30

// signatureWindow is how many leading bytes the media-signature classifier is
// allowed to inspect. It is intentionally tiny: the connector performs coarse
// family gating, not parsing.
const signatureWindow = 512

// Platform is the trusted, signed filesystem semantics of the connection root.
// It is selected by trusted configuration and is part of the connection trust
// profile; an unknown value fails closed. S3_COMPATIBLE is a distinct object
// transport with its own conditional-read connector and is deliberately not a
// value here.
type Platform uint8

const (
	PlatformPOSIX Platform = iota + 1
	PlatformWindows
)

func (p Platform) valid() bool { return p == PlatformPOSIX || p == PlatformWindows }

// AccessMode is the trusted access mode of the scope revision. The local folder
// connector build implements no item-level ACL, so it supports only
// WORKSPACE_MANAGED (an explicit data grant). SOURCE_ENFORCED is rejected at
// scope construction because this build cannot prove per-item native access;
// the database capability gate already blocks such a scope upstream, and this is
// the matching fail-closed at the connector boundary.
type AccessMode uint8

const (
	AccessWorkspaceManaged AccessMode = iota + 1
	AccessSourceEnforced
)

// Format is the closed folder format allowlist from the Product Constitution.
type Format string

const (
	FormatPDF        Format = "PDF"
	FormatDOCX       Format = "DOCX"
	FormatPPTX       Format = "PPTX"
	FormatXLSX       Format = "XLSX"
	FormatCSV        Format = "CSV"
	FormatTXT        Format = "TXT"
	FormatMarkdown   Format = "MARKDOWN"
	FormatHTML       Format = "HTML"
	FormatJSON       Format = "JSON"
	FormatXML        Format = "XML"
	FormatEML        Format = "EML"
	FormatSourceCode Format = "SOURCE_CODE"
	FormatPNG        Format = "PNG"
	FormatJPEG       Format = "JPEG"
)

// family is the coarse media family a signature resolves to. The connector gates
// on family; the trusted parser assigns the final canonical_format later.
type family uint8

const (
	familyUnknown family = iota
	familyText
	familyPDF
	familyPNG
	familyJPEG
	familyOOXML
	familyExecutable
)

func (f Format) family() (family, bool) {
	switch f {
	case FormatPDF:
		return familyPDF, true
	case FormatPNG:
		return familyPNG, true
	case FormatJPEG:
		return familyJPEG, true
	case FormatDOCX, FormatPPTX, FormatXLSX:
		return familyOOXML, true
	case FormatCSV, FormatTXT, FormatMarkdown, FormatHTML, FormatJSON, FormatXML, FormatEML, FormatSourceCode:
		return familyText, true
	default:
		return familyUnknown, false
	}
}

func (f family) mediaType() string {
	switch f {
	case familyPDF:
		return "application/pdf"
	case familyPNG:
		return "image/png"
	case familyJPEG:
		return "image/jpeg"
	case familyOOXML:
		return "application/zip"
	case familyText:
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

// ErrorCode is a content-free code for a hard connector failure (a failure that
// is not a per-object quarantine). It is safe for logs, metrics and API mapping.
type ErrorCode string

const (
	CodeScopeInvalid          ErrorCode = "FOLDER_SCOPE_INVALID"
	CodeAccessModeUnsupported ErrorCode = "FOLDER_ACCESS_MODE_UNSUPPORTED"
	CodePlatformUnsupported   ErrorCode = "FOLDER_PLATFORM_UNSUPPORTED"
	CodeRootUnavailable       ErrorCode = "FOLDER_ROOT_UNAVAILABLE"
	CodePathInvalid           ErrorCode = "FOLDER_PATH_INVALID"
	CodeContainment           ErrorCode = "FOLDER_CONTAINMENT_VIOLATION"
	CodeReadFailed            ErrorCode = "FOLDER_READ_FAILED"
	CodeQuarantined           ErrorCode = "FOLDER_OBJECT_QUARANTINED"
)

// QuarantineCode is a content-free reason a single object could not become a
// trusted discovery/read result. A quarantine is diagnosable and observable but
// never a success.
type QuarantineCode string

const (
	QuarantineSymlinkRejected QuarantineCode = "FOLDER_SYMLINK_REJECTED"
	QuarantineNonRegular      QuarantineCode = "FOLDER_NON_REGULAR"
	QuarantineOversized       QuarantineCode = "FOLDER_OBJECT_OVERSIZED"
	QuarantineUnsupportedType QuarantineCode = "FOLDER_UNSUPPORTED_TYPE"
	QuarantineMediaSignature  QuarantineCode = "FOLDER_MEDIA_SIGNATURE_MISMATCH"
	QuarantineInvalidUTF8     QuarantineCode = "FOLDER_INVALID_UTF8"
	QuarantineTornRead        QuarantineCode = "TORN_READ_VERSION_MISMATCH"
	QuarantineACLUnknown      QuarantineCode = "FOLDER_ACL_UNKNOWN"
	QuarantineContainment     QuarantineCode = "FOLDER_CONTAINMENT_VIOLATION"
)

// Error preserves a content-free code and hides the underlying cause.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string {
	if e == nil || e.code == "" {
		return string(CodeScopeInvalid)
	}
	return string(e.code)
}
func (e *Error) Unwrap() error { return e.cause }

// String/GoString are redacted so a formatted Error can never leak a path or
// cause into a log line.
func (*Error) String() string   { return "folder.Error{[REDACTED]}" }
func (*Error) GoString() string { return "folder.Error{[REDACTED]}" }

// CodeOf maps any error to a safe code.
func CodeOf(err error) ErrorCode {
	var folderError *Error
	if errors.As(err, &folderError) && folderError != nil {
		return folderError.code
	}
	return CodeReadFailed
}

func newError(code ErrorCode, cause error) error { return &Error{code: code, cause: cause} }

// ScopeParams is the trusted, already-authorized input a caller assembles from
// an activated SourceScopeRevision: the pre-mounted connection root, the signed
// platform semantics, the decrypted folder scope_config and the scope access
// mode. It never comes from a connector event or an end-user request, and the
// connector cannot widen any of it.
type ScopeParams struct {
	// RootPath is the trusted absolute host path of the pre-mounted connection
	// root (resolved from root_alias/root_identity by trusted configuration).
	RootPath string
	Platform Platform
	Access   AccessMode
	// RelativeRoot is folderConfig.relative_root: a path relative to RootPath, or
	// empty for the whole root.
	RelativeRoot string
	Recursive    bool
	IncludeGlobs []string
	ExcludeGlobs []string
	MaxFileBytes int64
	Formats      []Format
}

// Scope is the compiled, immutable scope the connector operates within. Its
// unexported fields prevent a caller from widening a validated scope or
// substituting another matcher.
type Scope struct {
	rootPath      string
	platform      Platform
	relativeRoot  string // slash form, no leading/trailing slash, may be empty
	recursive     bool
	matcher       *scopeglob.Matcher
	maxFileBytes  int64
	allowedFamily map[family]bool
}

func (Scope) String() string   { return "folder.Scope{[REDACTED]}" }
func (Scope) GoString() string { return "folder.Scope{[REDACTED]}" }

// NewScope validates trusted configuration and compiles the shared scope-glob
// matcher with the platform case mode, guaranteeing the connector evaluates
// include/exclude with the exact same engine and rules as server-side scope
// validation (SRC-013). It fails closed on any invalid field.
func NewScope(params ScopeParams) (*Scope, error) {
	if !params.Platform.valid() {
		return nil, newError(CodePlatformUnsupported, nil)
	}
	if params.Access != AccessWorkspaceManaged {
		// SOURCE_ENFORCED requires an item-ACL capability this build does not
		// implement; refusing it here is the connector-side fail-closed.
		return nil, newError(CodeAccessModeUnsupported, nil)
	}
	if !isAbsolutePath(params.RootPath) {
		return nil, newError(CodeScopeInvalid, nil)
	}
	if params.MaxFileBytes < 1 || params.MaxFileBytes > maximumScopeByteCap {
		return nil, newError(CodeScopeInvalid, nil)
	}
	relativeRoot, err := canonicalRelativeRoot(params.RelativeRoot, params.Platform)
	if err != nil {
		return nil, err
	}
	if len(params.Formats) == 0 {
		return nil, newError(CodeScopeInvalid, nil)
	}
	allowed := make(map[family]bool, len(params.Formats))
	for _, format := range params.Formats {
		fam, ok := format.family()
		if !ok {
			return nil, newError(CodeScopeInvalid, nil)
		}
		allowed[fam] = true
	}
	caseMode := scopeglob.CaseSensitive
	if params.Platform == PlatformWindows {
		caseMode = scopeglob.CaseWindows
	}
	matcher, err := scopeglob.Compile(params.IncludeGlobs, params.ExcludeGlobs, caseMode)
	if err != nil {
		return nil, newError(CodeScopeInvalid, err)
	}
	return &Scope{
		rootPath:      params.RootPath,
		platform:      params.Platform,
		relativeRoot:  relativeRoot,
		recursive:     params.Recursive,
		matcher:       matcher,
		maxFileBytes:  params.MaxFileBytes,
		allowedFamily: allowed,
	}, nil
}

// DiscoveredObject is one file the connector found inside the exact scope. Its
// RelativePath is canonical (slash, NFC) and relative to the connection root, so
// it is the exact `relative_path` input to the canonical FILE locator; it is
// sensitive source-native identity and must not reach open telemetry.
type DiscoveredObject struct {
	RelativePath    string
	SizeBytes       int64
	ModTimeUnixNano int64
}

// QuarantineNotice reports one object that could not become a trusted result.
// RelativePath is sensitive; Code is content-free.
type QuarantineNotice struct {
	RelativePath string
	Code         QuarantineCode
}

// DiscoveryResult is the typed, in-memory, side-effect-free outcome of a
// discovery pass. Objects is deterministically ordered by RelativePath so a
// repeat discovery of an unchanged tree is byte-for-byte identical.
type DiscoveryResult struct {
	Objects     []DiscoveredObject
	Quarantined []QuarantineNotice
	// Complete is true only when the whole allowed root was enumerated with no
	// directory-level enumeration/permission/I/O gap. When it is false the scan is
	// PARTIAL: an unseen object MUST NOT be treated as removed or deleted, because
	// it may live under a subtree this pass could not list. A file-level quarantine
	// (a symlink, an oversized or unsupported object, a torn read, or a single
	// entry whose identity was observed) does not clear Complete — only a directory
	// this pass could not open, list or stat does, because that hides an unknown
	// set of children. Complete defaults false and is set true only after a walk
	// that reached every allowed subtree; every early or error return leaves it
	// false (fail-closed).
	Complete bool
	// coverageGap records that at least one directory-level enumeration gap was
	// observed, so a partial scan can never be reported Complete.
	coverageGap bool
}

// noteCoverageGap records a directory-level enumeration gap: the quarantine is
// still surfaced for diagnostics, and the scan can no longer be Complete.
func (r *DiscoveryResult) noteCoverageGap(relativePath string, code QuarantineCode) {
	r.Quarantined = append(r.Quarantined, QuarantineNotice{RelativePath: relativePath, Code: code})
	r.coverageGap = true
}

// MediaFamily is the coarse, non-authoritative media family the connector
// detected from the leading signature bytes. It is deliberately NOT a Format:
// the trusted parser assigns the exact canonical_format later, and typing this
// as Format would invite a downstream consumer to mistake a coarse hint (every
// OOXML container reports one family; every text subtype reports TEXT) for the
// canonical format.
type MediaFamily string

const (
	MediaFamilyText  MediaFamily = "TEXT"
	MediaFamilyPDF   MediaFamily = "PDF"
	MediaFamilyPNG   MediaFamily = "PNG"
	MediaFamilyJPEG  MediaFamily = "JPEG"
	MediaFamilyOOXML MediaFamily = "OOXML"
)

// ReadResult is the bounded stable snapshot of one object. Content is the
// transient byte slice handed to the next in-process extraction boundary; the
// connector never persists it. NativeVersionToken is a content-hash surrogate
// because a folder object has no native version id, using the same typed
// `hash:sha256:<hex>` form accepted by source_version.
type ReadResult struct {
	RelativePath       string
	MediaFamily        MediaFamily // coarse detected family; not the canonical_format
	MediaType          string
	SizeBytes          int64
	ContentSHA256      string // "sha256:<hex>"
	NativeVersionToken string // "hash:sha256:<hex>"
	Content            []byte
}

// Connector is the stateless typed owner of the folder connector operations.
type Connector struct{}

// New returns the connector owner.
func New() *Connector { return &Connector{} }

// Discover lists every allowed object inside the exact scope and quarantines
// everything it cannot safely admit. It creates no durable state and follows no
// symlink. A repeat call over an unchanged tree is deterministic.
func (*Connector) Discover(ctx context.Context, scope *Scope) (DiscoveryResult, error) {
	if scope == nil || scope.matcher == nil {
		return DiscoveryResult{}, newError(CodeScopeInvalid, nil)
	}
	root, err := openPinnedRoot(scope.rootPath)
	if err != nil {
		return DiscoveryResult{}, err
	}
	defer func() { _ = root.Close() }()

	var result DiscoveryResult
	// The scope root prefix itself must not be reached through an in-root symlink.
	if scope.relativeRoot != "" {
		notice, symlinkErr := rejectSymlinkComponents(root, scope.relativeRoot)
		if symlinkErr != nil {
			return DiscoveryResult{}, symlinkErr
		}
		if notice != nil {
			result.Quarantined = append(result.Quarantined, *notice)
			return result, nil
		}
	}
	if walkErr := walk(ctx, root, scope, scope.relativeRoot, &result); walkErr != nil {
		return DiscoveryResult{}, walkErr
	}
	// The walk reached every allowed subtree without aborting; the scan is
	// authoritative only if no directory-level gap was observed along the way.
	result.Complete = !result.coverageGap
	sort.Slice(result.Objects, func(i, j int) bool {
		return result.Objects[i].RelativePath < result.Objects[j].RelativePath
	})
	sort.Slice(result.Quarantined, func(i, j int) bool {
		if result.Quarantined[i].RelativePath == result.Quarantined[j].RelativePath {
			return result.Quarantined[i].Code < result.Quarantined[j].Code
		}
		return result.Quarantined[i].RelativePath < result.Quarantined[j].RelativePath
	})
	return result, nil
}

// Read returns a bounded, stable, torn-read-free snapshot of one root-relative
// object, or a typed quarantine. The path must be one produced by Discover; it
// is re-validated and re-resolved against the pinned root, so a caller cannot
// smuggle a traversal or absolute path.
func (*Connector) Read(ctx context.Context, scope *Scope, relativePath string) (ReadResult, *QuarantineNotice, error) {
	if scope == nil || scope.matcher == nil {
		return ReadResult{}, nil, newError(CodeScopeInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return ReadResult{}, nil, newError(CodeReadFailed, err)
	}
	canonical, err := canonicalRootRelative(relativePath, scope.platform)
	if err != nil {
		return ReadResult{}, nil, err
	}
	if !withinRelativeRoot(canonical, scope.relativeRoot) {
		return ReadResult{}, nil, newError(CodeContainment, nil)
	}
	// The object must still satisfy the exact include/exclude boundary; a read of
	// a path outside the compiled scope is a containment violation, not a read.
	scopeRelative := scopeRelative(canonical, scope.relativeRoot)
	included, matchErr := scope.matcher.Match(scopeRelative)
	if matchErr != nil {
		return ReadResult{}, nil, newError(CodePathInvalid, matchErr)
	}
	if !included {
		return ReadResult{}, nil, newError(CodeContainment, nil)
	}

	root, err := openPinnedRoot(scope.rootPath)
	if err != nil {
		return ReadResult{}, nil, err
	}
	defer func() { _ = root.Close() }()

	quarantine, readResult, readErr := readObject(root, canonical, scope)
	if readErr != nil {
		return ReadResult{}, nil, readErr
	}
	if quarantine != nil {
		return ReadResult{}, quarantine, nil
	}
	return readResult, nil, nil
}

// openPinnedRoot pins the root directory by descriptor and rejects a symlinked
// root and a TOCTOU swap between Lstat and open (the webui asset idiom).
func openPinnedRoot(rootPath string) (*os.Root, error) {
	if strings.TrimSpace(rootPath) == "" {
		return nil, newError(CodeRootUnavailable, nil)
	}
	info, err := os.Lstat(rootPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, newError(CodeRootUnavailable, err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, newError(CodeRootUnavailable, err)
	}
	openedInfo, err := root.Stat(".")
	currentInfo, currentErr := os.Lstat(rootPath)
	if err != nil || currentErr != nil || currentInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
		_ = root.Close()
		return nil, newError(CodeRootUnavailable, nil)
	}
	return root, nil
}

func walk(ctx context.Context, root *os.Root, scope *Scope, dirRelative string, result *DiscoveryResult) error {
	if err := ctx.Err(); err != nil {
		return newError(CodeReadFailed, err)
	}
	openName := dirRelative
	if openName == "" {
		openName = "."
	}
	dir, err := root.Open(openName)
	if err != nil {
		if os.IsPermission(err) {
			// A directory we cannot open hides an unknown set of children.
			result.noteCoverageGap(dirRelative, QuarantineACLUnknown)
			return nil
		}
		if dirRelative == scope.relativeRoot {
			// The scope root itself must resolve; otherwise the scope is unusable.
			return newError(CodeRootUnavailable, err)
		}
		result.noteCoverageGap(dirRelative, QuarantineContainment)
		return nil
	}
	entries, readErr := dir.ReadDir(-1)
	_ = dir.Close()
	if readErr != nil {
		// A directory we cannot list leaves its children unknown.
		result.noteCoverageGap(dirRelative, QuarantineContainment)
		return nil
	}
	for _, entry := range entries {
		childRelative := entry.Name()
		if dirRelative != "" {
			childRelative = dirRelative + "/" + entry.Name()
		}
		info, lstatErr := root.Lstat(childRelative)
		if lstatErr != nil {
			// The entry name is known but its type is not: it may be a directory
			// hiding a subtree, so this is a coverage gap, not a file-level decision.
			if os.IsPermission(lstatErr) {
				result.noteCoverageGap(childRelative, QuarantineACLUnknown)
				continue
			}
			result.noteCoverageGap(childRelative, QuarantineContainment)
			continue
		}
		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			// A POSIX symlink or a Windows reparse point/junction is never followed.
			result.Quarantined = append(result.Quarantined, QuarantineNotice{RelativePath: childRelative, Code: QuarantineSymlinkRejected})
		case mode.IsDir():
			if scope.recursive {
				if err := walk(ctx, root, scope, childRelative, result); err != nil {
					return err
				}
			}
		case mode.IsRegular():
			admitRegular(scope, childRelative, info, result)
		default:
			// Device, socket, named pipe or any irregular entry (including a
			// Windows reparse point that did not surface as a symlink).
			result.Quarantined = append(result.Quarantined, QuarantineNotice{RelativePath: childRelative, Code: QuarantineNonRegular})
		}
	}
	return nil
}

func admitRegular(scope *Scope, childRelative string, info os.FileInfo, result *DiscoveryResult) {
	scopeRel := scopeRelative(childRelative, scope.relativeRoot)
	included, matchErr := scope.matcher.Match(scopeRel)
	if matchErr != nil {
		// A path the shared matcher cannot evaluate is not silently included, and an
		// unresolved matcher error means this pass cannot claim an authoritative
		// membership decision, so it is a coverage gap.
		result.noteCoverageGap(childRelative, QuarantineContainment)
		return
	}
	if !included {
		return
	}
	if info.Size() > scope.maxFileBytes {
		result.Quarantined = append(result.Quarantined, QuarantineNotice{RelativePath: childRelative, Code: QuarantineOversized})
		return
	}
	result.Objects = append(result.Objects, DiscoveredObject{
		RelativePath:    childRelative,
		SizeBytes:       info.Size(),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	})
}

// rejectSymlinkComponents refuses any ancestor path component that is a symlink.
// os.Root blocks symlinks that escape the root but follows in-root ones, so an
// in-root link could otherwise redirect a read out of the scope's relative_root
// and return content under a mislabelled identity. Prefixes are checked in
// increasing order, so the first link component is caught before any prefix that
// would traverse it is ever constructed.
func rejectSymlinkComponents(root *os.Root, canonical string) (*QuarantineNotice, error) {
	prefix := ""
	for _, segment := range strings.Split(canonical, "/") {
		if prefix == "" {
			prefix = segment
		} else {
			prefix += "/" + segment
		}
		info, err := root.Lstat(prefix)
		if err != nil {
			if os.IsPermission(err) {
				return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, nil
			}
			if os.IsNotExist(err) {
				return &QuarantineNotice{RelativePath: canonical, Code: QuarantineContainment}, nil
			}
			return nil, newError(CodeReadFailed, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineSymlinkRejected}, nil
		}
	}
	return nil, nil
}

// readObject performs the bounded stable read: per-component symlink refusal,
// Lstat gate, open, before/after fstat torn-read detection, a second independent
// verification read that catches a same-size in-place rewrite mtime resolution
// could hide, and signature/UTF-8 gating.
func readObject(root *os.Root, canonical string, scope *Scope) (*QuarantineNotice, ReadResult, error) {
	if notice, err := rejectSymlinkComponents(root, canonical); err != nil || notice != nil {
		return notice, ReadResult{}, err
	}

	info, err := root.Lstat(canonical)
	if err != nil {
		if os.IsPermission(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, ReadResult{}, nil
		}
		if os.IsNotExist(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineContainment}, ReadResult{}, nil
		}
		return nil, ReadResult{}, newError(CodeReadFailed, err)
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineSymlinkRejected}, ReadResult{}, nil
	}
	if !mode.IsRegular() {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineNonRegular}, ReadResult{}, nil
	}
	if info.Size() > scope.maxFileBytes {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineOversized}, ReadResult{}, nil
	}

	file, err := root.Open(canonical)
	if err != nil {
		if os.IsPermission(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, ReadResult{}, nil
		}
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineContainment}, ReadResult{}, nil
	}
	defer func() { _ = file.Close() }()

	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(info, before) {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineTornRead}, ReadResult{}, nil
	}
	if before.Size() > scope.maxFileBytes {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineOversized}, ReadResult{}, nil
	}

	// Read at most one byte beyond the cap so an object that grew past the cap
	// during the read is caught rather than silently truncated.
	limited := io.LimitReader(file, scope.maxFileBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		if os.IsPermission(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, ReadResult{}, nil
		}
		return nil, ReadResult{}, newError(CodeReadFailed, err)
	}
	if int64(len(content)) > scope.maxFileBytes {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineOversized}, ReadResult{}, nil
	}

	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
		int64(len(content)) != before.Size() {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineTornRead}, ReadResult{}, nil
	}

	fam := classify(content)
	if fam == familyExecutable || fam == familyUnknown {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineUnsupportedType}, ReadResult{}, nil
	}
	if !scope.allowedFamily[fam] {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineMediaSignature}, ReadResult{}, nil
	}
	if fam == familyText && !utf8.Valid(content) {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineInvalidUTF8}, ReadResult{}, nil
	}

	digest := sha256.Sum256(content)
	// Second independent read: a same-size in-place rewrite that leaves size and
	// mtime unchanged (coarse SMB/FAT mtime granularity, or a deliberate mtime
	// reset) would pass the fstat gate above; two full reads that disagree prove
	// the object was not stable, so the snapshot is not trusted.
	if notice, verifyErr := verifyStableSecondRead(root, canonical, before, digest, scope.maxFileBytes); verifyErr != nil || notice != nil {
		return notice, ReadResult{}, verifyErr
	}

	hexDigest := hex.EncodeToString(digest[:])
	return nil, ReadResult{
		RelativePath:       canonical,
		MediaFamily:        familyHint(fam),
		MediaType:          fam.mediaType(),
		SizeBytes:          int64(len(content)),
		ContentSHA256:      "sha256:" + hexDigest,
		NativeVersionToken: "hash:sha256:" + hexDigest,
		Content:            content,
	}, nil
}

// verifyStableSecondRead re-opens and re-reads the object from a fresh
// descriptor and requires the same identity, size and content hash as the first
// read. It closes the same-size/same-mtime in-place-rewrite window the single
// fstat compare cannot see on coarse-granularity filesystems.
func verifyStableSecondRead(root *os.Root, canonical string, first os.FileInfo, firstDigest [32]byte, maxBytes int64) (*QuarantineNotice, error) {
	file, err := root.Open(canonical)
	if err != nil {
		if os.IsPermission(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, nil
		}
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineTornRead}, nil
	}
	defer func() { _ = file.Close() }()

	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || !os.SameFile(first, stat) {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineTornRead}, nil
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		if os.IsPermission(err) {
			return &QuarantineNotice{RelativePath: canonical, Code: QuarantineACLUnknown}, nil
		}
		return nil, newError(CodeReadFailed, err)
	}
	if int64(len(content)) != first.Size() || sha256.Sum256(content) != firstDigest {
		return &QuarantineNotice{RelativePath: canonical, Code: QuarantineTornRead}, nil
	}
	return nil, nil
}

// classify performs a bounded coarse media-family classification from the
// leading signature bytes. It never trusts an extension and never parses.
func classify(content []byte) family {
	head := content
	if len(head) > signatureWindow {
		head = head[:signatureWindow]
	}
	switch {
	case len(content) == 0:
		return familyUnknown
	case hasPrefix(content, "%PDF-"):
		return familyPDF
	case hasPrefix(content, "\x89PNG\r\n\x1a\n"):
		return familyPNG
	case hasPrefix(content, "\xff\xd8\xff"):
		return familyJPEG
	case hasPrefix(content, "PK\x03\x04") || hasPrefix(content, "PK\x05\x06") || hasPrefix(content, "PK\x07\x08"):
		return familyOOXML
	case isExecutable(content):
		return familyExecutable
	case isTextHead(head):
		return familyText
	default:
		return familyUnknown
	}
}

func isExecutable(content []byte) bool {
	return hasPrefix(content, "\x7fELF") || // ELF
		hasPrefix(content, "MZ") || // PE / DOS
		hasPrefix(content, "\xca\xfe\xba\xbe") || // Mach-O fat / Java class
		hasPrefix(content, "\xfe\xed\xfa\xce") || hasPrefix(content, "\xfe\xed\xfa\xcf") || // Mach-O
		hasPrefix(content, "\xcf\xfa\xed\xfe") || hasPrefix(content, "\xce\xfa\xed\xfe") || // Mach-O LE
		hasPrefix(content, "#!") // shebang script
}

// isTextHead accepts a byte window that contains no NUL and no C0/C1 control
// other than tab/CR/LF/form feed, and is valid UTF-8 up to the window boundary.
// Form feed is a page separator in text exports, not a binary signature. Full
// UTF-8 validity of the whole object is re-checked after the family is admitted.
func isTextHead(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	for _, b := range head {
		if b == 0 {
			return false
		}
	}
	for i := 0; i < len(head); {
		r, size := utf8.DecodeRune(head[i:])
		if r == utf8.RuneError && size == 1 {
			// Possibly a multi-byte rune truncated by the window; only tolerate at
			// the very end of the window.
			if i+utf8.UTFMax > len(head) {
				return true
			}
			return false
		}
		if r != '\t' && r != '\n' && r != '\r' && r != '\f' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			return false
		}
		i += size
	}
	return true
}

func familyHint(f family) MediaFamily {
	switch f {
	case familyPDF:
		return MediaFamilyPDF
	case familyPNG:
		return MediaFamilyPNG
	case familyJPEG:
		return MediaFamilyJPEG
	case familyOOXML:
		// The connector cannot disambiguate DOCX/PPTX/XLSX; the trusted parser
		// assigns the exact canonical_format. The hint reports the container only.
		return MediaFamilyOOXML
	case familyText:
		return MediaFamilyText
	default:
		return ""
	}
}

func hasPrefix(content []byte, prefix string) bool {
	return len(content) >= len(prefix) && string(content[:len(prefix)]) == prefix
}

// canonicalRelativeRoot applies the same NFC/traversal/control/backslash rules
// the scope-glob grammar applies, plus the Windows special-namespace rules, to
// the scope relative_root. Empty is allowed and means the whole root.
func canonicalRelativeRoot(raw string, platform Platform) (string, error) {
	if raw == "" {
		return "", nil
	}
	canonical, err := canonicalRootRelative(raw, platform)
	if err != nil {
		return "", newError(CodeScopeInvalid, err)
	}
	return canonical, nil
}

// canonicalRootRelative validates a relative path through the single normative
// pathcanon implementation shared with the scope-glob matcher and the catalog
// identity, and returns the canonical slash form. There is no second copy of the
// separator / NFC / dot-segment / Windows-special rules here.
func canonicalRootRelative(raw string, platform Platform) (string, error) {
	if _, err := pathcanon.Path(raw, pathcanonCase(platform)); err != nil {
		return "", newError(CodePathInvalid, nil)
	}
	return raw, nil
}

func pathcanonCase(platform Platform) pathcanon.Case {
	if platform == PlatformWindows {
		return pathcanon.CaseWindows
	}
	return pathcanon.CaseSensitive
}

// scopeRelative strips the relative_root prefix so the shared matcher sees the
// path relative to the scope, matching server-side evaluation.
func scopeRelative(rootRelative, relativeRoot string) string {
	if relativeRoot == "" {
		return rootRelative
	}
	if rootRelative == relativeRoot {
		return ""
	}
	return strings.TrimPrefix(rootRelative, relativeRoot+"/")
}

// withinRelativeRoot verifies a root-relative path is inside the scope prefix on
// a path-segment boundary (not a raw string prefix).
func withinRelativeRoot(rootRelative, relativeRoot string) bool {
	if relativeRoot == "" {
		return true
	}
	return rootRelative == relativeRoot || strings.HasPrefix(rootRelative, relativeRoot+"/")
}

func isAbsolutePath(p string) bool {
	if p == "" {
		return false
	}
	// Accept POSIX absolute and Windows drive/UNC absolute; trusted config
	// supplies the host root, so this is a shape guard, not authorization.
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return false
}
