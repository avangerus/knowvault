package workercomposition

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"
)

const (
	defaultSourceMountRoot = "/run/knowvault/sources"
	sourceManifestFilename = "manifest.json"
	maxSourceManifestBytes = 64 << 10
	maxMountedRoots        = 256
	mountManifestSchema    = "knowvault-source-mount-manifest-v1"
)

type sourceMountManifest struct {
	Schema string             `json:"schema"`
	Roots  []sourceMountEntry `json:"roots"`
}

type sourceMountEntry struct {
	Alias     string `json:"alias"`
	Identity  string `json:"identity"`
	Directory string `json:"directory"`
}

type mountTuple struct {
	alias    string
	identity string
}

// mountRegistry is immutable after construction. The manifest is deployment
// configuration, not tenant data: it binds the trusted database tuple to a
// directory below the one fixed source mount root. No absolute path can enter
// from a job payload or a user request.
type mountRegistry struct {
	roots map[mountTuple]string
}

func (registry *mountRegistry) Resolve(alias, identity string) (string, bool) {
	if registry == nil || registry.roots == nil || !validMountID(alias) || !validMountID(identity) {
		return "", false
	}
	path, ok := registry.roots[mountTuple{alias: alias, identity: identity}]
	if !ok {
		return "", false
	}
	return path, true
}

func loadMountedMounts() (*mountRegistry, error) {
	return loadMountRegistry(defaultSourceMountRoot)
}

// loadMountRegistry is package-private so tests can use a temporary isolated
// mount without expanding the production path API.
func loadMountRegistry(rootPath string) (*mountRegistry, error) {
	if rootPath == "" || !filepath.IsAbs(rootPath) {
		return nil, workerError(CodeMountsUnavailable)
	}
	rootInfo, rootInfoErr := os.Lstat(rootPath)
	if rootInfoErr != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, workerError(CodeMountsUnavailable)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, workerError(CodeMountsUnavailable)
	}
	defer root.Close()
	openedRootInfo, err := root.Stat(".")
	currentRootInfo, currentRootErr := os.Lstat(rootPath)
	if err != nil || currentRootErr != nil || currentRootInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(rootInfo, openedRootInfo) || !os.SameFile(openedRootInfo, currentRootInfo) {
		return nil, workerError(CodeMountsUnavailable)
	}

	manifestPath := filepath.Join(rootPath, sourceManifestFilename)
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() {
		return nil, workerError(CodeMountsUnavailable)
	}
	manifestFile, err := root.Open(sourceManifestFilename)
	if err != nil {
		return nil, workerError(CodeMountsUnavailable)
	}
	defer manifestFile.Close()
	info, err := manifestFile.Stat()
	if err != nil || !os.SameFile(manifestInfo, info) || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS == "linux" && info.Mode().Perm()&0o022 != 0) || info.Size() < 1 || info.Size() > maxSourceManifestBytes {
		return nil, workerError(CodeMountsUnavailable)
	}
	raw, err := io.ReadAll(io.LimitReader(manifestFile, maxSourceManifestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxSourceManifestBytes {
		return nil, workerError(CodeMountsUnavailable)
	}
	defer clear(raw)

	var configuration sourceMountManifest
	if err := jsonv2.Unmarshal(raw, &configuration,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || !validMountManifest(configuration) {
		return nil, workerError(CodeMountsUnavailable)
	}

	registry := &mountRegistry{roots: make(map[mountTuple]string, len(configuration.Roots))}
	for _, entry := range configuration.Roots {
		path := filepath.Join(rootPath, entry.Directory)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || (runtime.GOOS == "linux" && info.Mode().Perm()&0o022 != 0) {
			return nil, workerError(CodeMountsUnavailable)
		}
		registry.roots[mountTuple{alias: entry.Alias, identity: entry.Identity}] = path
	}
	return registry, nil
}

func validMountManifest(value sourceMountManifest) bool {
	if value.Schema != mountManifestSchema || len(value.Roots) < 1 || len(value.Roots) > maxMountedRoots {
		return false
	}
	seen := make(map[mountTuple]struct{}, len(value.Roots))
	seenDirectories := make(map[string]struct{}, len(value.Roots))
	for _, entry := range value.Roots {
		if !validMountID(entry.Alias) || !validMountID(entry.Identity) || !validMountDirectory(entry.Directory) {
			return false
		}
		tuple := mountTuple{alias: entry.Alias, identity: entry.Identity}
		if _, exists := seen[tuple]; exists {
			return false
		}
		if _, exists := seenDirectories[entry.Directory]; exists {
			return false
		}
		seen[tuple] = struct{}{}
		seenDirectories[entry.Directory] = struct{}{}
	}
	return true
}

func validMountDirectory(value string) bool {
	return value != "." && value != ".." && validMountID(value) && !strings.ContainsAny(value, `/\\`)
}

func validMountID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
