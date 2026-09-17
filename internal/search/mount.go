package search

// This file owns the production search capability mount.  The transport itself
// is usable from contract tests without a filesystem, while production
// composition obtains endpoint, alias, generation and TLS material only from
// this fixed, administrator-owned mount.  There is no environment, system-
// trust, or database-only fallback.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"net/url"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

const (
	DefaultMountRoot          = "/run/knowvault/search"
	searchManifestFilename    = "manifest.json"
	searchRootCAFilename      = "root-ca.pem"
	searchClientCertFile      = "client-cert.pem"
	searchClientKeyFile       = "client-key.pem"
	maximumManifestBytes      = 64 << 10
	maximumRootBytes          = 1 << 20
	maximumClientCertBytes    = 256 << 10
	searchManifestSchema      = "knowvault-search-manifest-v1"
	maximumSearchCertificates = 256
)

const (
	// CodeMountUnavailable means that the required capability is not mounted.
	// Production composition treats this as a startup failure. A present but
	// malformed mount returns CodeMountInvalid and must never silently fall back.
	CodeMountUnavailable ErrorCode = "SEARCH_MOUNT_UNAVAILABLE"
	CodeMountInvalid     ErrorCode = "SEARCH_MOUNT_INVALID"
)

type mountedManifest struct {
	Schema                string `json:"schema"`
	OrganizationID        string `json:"organization_id"`
	Endpoint              string `json:"endpoint"`
	IndexAlias            string `json:"index_alias"`
	Generation            int64  `json:"generation"`
	GenerationFence       int64  `json:"generation_fence"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	ClientKeyFile         string `json:"client_key_file,omitempty"`
}

// LoadMountedForTenant loads an administrator-provisioned search capability
// for one immutable organization. A missing root is distinguishable from a
// malformed present root so the caller can report the exact startup gate;
// neither condition permits a weaker retrieval mode.
func LoadMountedForTenant(organizationID string) (Config, error) {
	return loadMountedForTenant(DefaultMountRoot, organizationID)
}

// LoadWorkerMountedForTenant reads the fixed capability under the worker's
// ownership contract, without accepting the server group as a fallback.
func LoadWorkerMountedForTenant(organizationID string) (Config, error) {
	return loadMountedForConsumer(DefaultMountRoot, organizationID, runtimeidentity.Worker)
}

// LoadMountedAt is the operator/test seam.  Production composition uses the
// fixed DefaultMountRoot and never accepts a path from a request or payload.
func LoadMountedAt(rootPath, organizationID string) (Config, error) {
	return loadMountedForTenant(rootPath, organizationID)
}

// LoadWorkerMountedAt is the explicit-root worker verification seam.
func LoadWorkerMountedAt(rootPath, organizationID string) (Config, error) {
	return loadMountedForConsumer(rootPath, organizationID, runtimeidentity.Worker)
}

func loadMountedForTenant(rootPath, organizationID string) (Config, error) {
	return loadMountedForConsumer(rootPath, organizationID, runtimeidentity.Server)
}

func loadMountedForConsumer(rootPath, organizationID string, consumer runtimeidentity.MountConsumer) (Config, error) {
	if !validOpaque(organizationID) {
		return Config{}, &Error{code: CodeMountInvalid}
	}
	root, err := openSearchMountedRootForConsumer(rootPath, consumer)
	if err != nil {
		return Config{}, &Error{code: CodeMountUnavailable}
	}
	defer root.Close()
	manifestBytes, err := root.read(searchManifestFilename, maximumManifestBytes)
	if err != nil {
		if CodeOf(err) == CodeMountInvalid {
			return Config{}, &Error{code: CodeMountInvalid}
		}
		return Config{}, &Error{code: CodeMountUnavailable}
	}
	defer clearBytes(manifestBytes)
	manifest, err := parseMountedManifest(manifestBytes, organizationID)
	if err != nil {
		return Config{}, err
	}
	rootBytes, err := root.read(manifest.RootCAFile, maximumRootBytes)
	if err != nil {
		return Config{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(rootBytes)
	roots, err := parseSearchRoots(rootBytes)
	if err != nil {
		return Config{}, &Error{code: CodeMountInvalid}
	}

	var certificate *tls.Certificate
	if manifest.ClientCertificateFile != "" || manifest.ClientKeyFile != "" {
		certificateBytes, certErr := root.read(manifest.ClientCertificateFile, maximumClientCertBytes)
		if certErr != nil {
			return Config{}, &Error{code: CodeMountInvalid}
		}
		defer clearBytes(certificateBytes)
		keyBytes, keyErr := root.read(manifest.ClientKeyFile, maximumClientCertBytes)
		if keyErr != nil {
			return Config{}, &Error{code: CodeMountInvalid}
		}
		defer clearBytes(keyBytes)
		loaded, keyErr := tls.X509KeyPair(certificateBytes, keyBytes)
		if keyErr != nil || len(loaded.Certificate) == 0 {
			return Config{}, &Error{code: CodeMountInvalid}
		}
		certificate = &loaded
	}

	return Config{
		Endpoint: manifest.Endpoint, IndexAlias: manifest.IndexAlias,
		OrganizationID: manifest.OrganizationID, Generation: manifest.Generation,
		GenerationFence: manifest.GenerationFence, TrustRoots: roots,
		ClientCertificate: certificate,
	}, nil
}

func parseMountedManifest(raw []byte, organizationID string) (mountedManifest, error) {
	var manifest mountedManifest
	if len(raw) == 0 || len(raw) > maximumManifestBytes || !validOpaque(organizationID) {
		return mountedManifest{}, &Error{code: CodeMountInvalid}
	}
	if err := jsonv2.Unmarshal(raw, &manifest,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return mountedManifest{}, &Error{code: CodeMountInvalid}
	}
	if manifest.Schema != searchManifestSchema || manifest.OrganizationID != organizationID ||
		!validSearchEndpoint(manifest.Endpoint) || !validAlias(manifest.IndexAlias) ||
		!validGeneration(manifest.Generation) || !validGeneration(manifest.GenerationFence) ||
		manifest.RootCAFile != searchRootCAFilename ||
		(manifest.ClientCertificateFile == "") != (manifest.ClientKeyFile == "") ||
		(manifest.ClientCertificateFile != "" && (manifest.ClientCertificateFile != searchClientCertFile || manifest.ClientKeyFile != searchClientKeyFile)) {
		return mountedManifest{}, &Error{code: CodeMountInvalid}
	}
	return manifest, nil
}

func parseSearchRoots(raw []byte) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > maximumRootBytes {
		return nil, errors.New("search roots unavailable")
	}
	pool := x509.NewCertPool()
	seen := make(map[[32]byte]struct{})
	count := 0
	rest := raw
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n\v\f")
		if len(rest) == 0 {
			break
		}
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return nil, errors.New("invalid search root")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !validSearchCertificate(certificate) {
			return nil, errors.New("invalid search root")
		}
		digest := sha256Bytes(block.Bytes)
		if _, duplicate := seen[digest]; duplicate {
			return nil, errors.New("duplicate search root")
		}
		seen[digest] = struct{}{}
		pool.AddCert(certificate)
		count++
		if count > maximumSearchCertificates {
			return nil, errors.New("too many search roots")
		}
		rest = remainder
	}
	if count == 0 || len(pool.Subjects()) == 0 {
		return nil, errors.New("empty search roots")
	}
	return pool, nil
}

func validSearchCertificate(value *x509.Certificate) bool {
	return value != nil && value.BasicConstraintsValid && value.IsCA &&
		(value.KeyUsage == 0 || value.KeyUsage&x509.KeyUsageCertSign != 0) && len(value.UnhandledCriticalExtensions) == 0
}

func validSearchEndpoint(value string) bool {
	if value == "" || len(value) > 2048 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && validEndpoint(parsed)
}

func sha256Bytes(value []byte) [32]byte {
	return sha256.Sum256(value)
}
