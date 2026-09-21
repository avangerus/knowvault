// Package analyticcatalog loads the administrator-mounted analytic catalog.
// The mount is an optional capability, and its absence is distinct from a
// malformed or unsafe mount.
package analyticcatalog

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"knowvault.local/verified-workspace/internal/analytic"
)

const (
	// DefaultMountRoot is the only production mount used by LoadMounted.
	DefaultMountRoot = "/run/knowvault/analytics"

	datasetProfileCatalogFilename = "dataset-profile-catalog.json"
	maximumCatalogBytes           = 1 << 20
)

// ErrorCode is the closed, content-free outcome vocabulary for this mount.
type ErrorCode string

const (
	// CodeMountUnavailable means the fixed root or exact catalog file is
	// absent. A present but unsafe or malformed mount is never unavailable.
	CodeMountUnavailable ErrorCode = "ANALYTIC_CATALOG_MOUNT_UNAVAILABLE"
	// CodeMountInvalid means the root/file shape or catalog content is invalid.
	CodeMountInvalid ErrorCode = "ANALYTIC_CATALOG_MOUNT_INVALID"
)

// Error deliberately carries no filesystem or decoder details. Mount errors
// can therefore be returned to callers and recorded without exposing paths,
// content, or host-specific diagnostics.
type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var mountError *Error
	if errors.As(err, &mountError) {
		return mountError.code
	}
	return CodeMountInvalid
}

// LoadMounted reads the catalog from the fixed production mount root.
func LoadMounted() (analytic.DatasetProfileCatalog, error) {
	return LoadMountedAt(DefaultMountRoot)
}

// LoadMountedAt is the explicit-root seam used by deployment and tests. It
// applies exactly the same root and file checks as LoadMounted.
func LoadMountedAt(rootPath string) (analytic.DatasetProfileCatalog, error) {
	rootInfo, err := os.Lstat(rootPath)
	if err != nil {
		if os.IsNotExist(err) {
			return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountUnavailable}
		}
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}

	filename := filepath.Join(rootPath, datasetProfileCatalogFilename)
	fileInfo, err := os.Lstat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountUnavailable}
		}
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	if fileInfo.Size() < 0 || fileInfo.Size() > maximumCatalogBytes {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}

	file, err := os.Open(filename)
	if err != nil {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	// Read one byte beyond the bound so a file that grows after Lstat is still
	// rejected without ever passing oversized bytes to the decoder.
	raw, err := io.ReadAll(io.LimitReader(file, maximumCatalogBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumCatalogBytes {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}

	catalog, err := analytic.DecodeDatasetProfileCatalogJSON(raw)
	if err != nil {
		return analytic.DatasetProfileCatalog{}, &Error{code: CodeMountInvalid}
	}
	return catalog, nil
}
