// Package tzrules loads IANA zone data from a verified, embedded copy of the
// pinned Go distribution time zone archive. It never consults the host zone
// database (TZ, ZONEINFO), the network, or alias canonicalization.
package tzrules

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// BundleSHA256 pins the embedded archive to the frozen Go 1.26.5 asset.
const BundleSHA256 = "sha256:8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8"

// errUnavailable is the single sentinel returned for every rejected name and
// every integrity, index, read, or TZif failure; it echoes no names or paths.
var errUnavailable = errors.New("tzrules: zone unavailable")

const (
	bundleSize   = 408125
	maxNameBytes = 64
	maxEntrySize = 1 << 16
)

//go:embed zoneinfo.zip
var bundle []byte

var (
	indexOnce sync.Once
	index     map[string]*zip.File
)

// archive returns the verified bundle index, or nil when the embedded archive
// fails its size, digest, or index check.
func archive() map[string]*zip.File {
	indexOnce.Do(func() {
		if len(bundle) != bundleSize {
			return
		}
		sum := sha256.Sum256(bundle)
		if "sha256:"+hex.EncodeToString(sum[:]) != BundleSHA256 {
			return
		}
		reader, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
		if err != nil {
			return
		}
		entries := make(map[string]*zip.File, len(reader.File))
		for _, entry := range reader.File {
			entries[entry.Name] = entry
		}
		index = entries
	})
	return index
}

// Load returns the location of an exact regular-file member of the embedded
// archive; "UTC" yields time.UTC once the bundle integrity check succeeded.
// Every other name must be a bounded ASCII path under a permitted area root.
func Load(name string) (*time.Location, error) {
	entries := archive()
	if entries == nil {
		return nil, errUnavailable
	}
	if name == "UTC" {
		return time.UTC, nil
	}
	entry, found := entries[name]
	if !validName(name) || !found || !entry.Mode().IsRegular() {
		return nil, errUnavailable
	}
	if entry.UncompressedSize64 > maxEntrySize {
		return nil, errUnavailable
	}
	contents, err := entry.Open()
	if err != nil {
		return nil, errUnavailable
	}
	defer contents.Close()
	data, err := io.ReadAll(io.LimitReader(contents, maxEntrySize+1))
	if err != nil || len(data) > maxEntrySize {
		return nil, errUnavailable
	}
	location, err := time.LoadLocationFromTZData(name, data)
	if err != nil {
		return nil, errUnavailable
	}
	return location, nil
}

// validName reports whether name is at most maxNameBytes bytes and a slash path
// under a permitted IANA area root whose components hold only the ASCII letters,
// digits, "_", "-", and "+", so no other byte can match. Out-of-area shorthands,
// fixed offsets, and the reserved names Local, posix, right, and Etc fail here.
func validName(name string) bool {
	if len(name) == 0 || len(name) > maxNameBytes {
		return false
	}
	root, rest, found := strings.Cut(name, "/")
	if !found || rest == "" {
		return false
	}
	switch root {
	case "Africa", "America", "Antarctica", "Arctic", "Asia", "Atlantic", "Australia", "Europe", "Indian", "Pacific":
	default:
		return false
	}
	for _, part := range strings.Split(rest, "/") {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			character := part[i]
			permitted := character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' || character == '_' || character == '-' || character == '+'
			if !permitted {
				return false
			}
		}
	}
	return true
}
