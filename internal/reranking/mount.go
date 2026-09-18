package reranking

// This file owns the administrator-provisioned reranking capability mount.
// A model endpoint, profile and TLS material are deployment inputs, not
// request data. Production composition loads them from this fixed mount only;
// there is no environment, proxy, system-trust or lexical fallback here.

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

const (
	DefaultMountRoot          = "/run/knowvault/reranking"
	rerankingManifestFilename = "manifest.json"
	rerankingProfileFilename  = "profile.json"
	rerankingRootCAFilename   = "root-ca.pem"
	rerankingClientCertFile   = "client-cert.pem"
	rerankingClientKeyFile    = "client-key.pem"
	maximumManifestBytes      = 64 << 10
	maximumProfileBytes       = 64 << 10
	maximumRootBytes          = 1 << 20
	maximumClientCertBytes    = 256 << 10
	rerankingManifestSchema   = "knowvault-reranking-manifest-v1"
	maximumCertificates       = 256
)

const (
	// CodeMountUnavailable means the optional reranking capability is absent.
	// An existing but incomplete or permission-drifted mount fails closed.
	CodeMountUnavailable ErrorCode = "RERANKING_MOUNT_UNAVAILABLE"
	// CodeMountInvalid means a mount exists but is malformed, cross-tenant or
	// permission-drifted. It never permits a weaker provider.
	CodeMountInvalid ErrorCode = "RERANKING_MOUNT_INVALID"
)

type mountedManifest struct {
	Schema                string `json:"schema"`
	OrganizationID        string `json:"organization_id"`
	ProfileFile           string `json:"profile_file"`
	ProfileHash           string `json:"profile_hash"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientKeyFile         string `json:"client_key_file"`
}

// MountedConfig is a complete, tenant-bound reranking capability. It is
// intentionally not exposed through HTTP or request payloads.
type MountedConfig struct {
	OrganizationID    string
	Profile           Profile
	TrustRoots        *x509.CertPool
	ClientCertificate *tls.Certificate
}

// LoadMountedForTenant loads the administrator-owned capability for one
// immutable organization. Both the profile and its hash are checked before
// any network client can be constructed.
func LoadMountedForTenant(organizationID string) (MountedConfig, error) {
	return loadMountedForTenant(DefaultMountRoot, organizationID)
}

// LoadMountedAt is the operator/test seam. Production composition uses the
// fixed DefaultMountRoot and never accepts a path from a request or model.
func LoadMountedAt(rootPath, organizationID string) (MountedConfig, error) {
	return loadMountedForTenant(rootPath, organizationID)
}

func loadMountedForTenant(rootPath, organizationID string) (MountedConfig, error) {
	return loadMountedForConsumer(rootPath, organizationID, runtimeidentity.Server)
}

func loadMountedForConsumer(rootPath, organizationID string, consumer runtimeidentity.MountConsumer) (MountedConfig, error) {
	if !validOpaque(organizationID) {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	root, err := openRerankingMountedRootForConsumer(rootPath, consumer)
	if err != nil {
		if CodeOf(err) == CodeMountInvalid {
			return MountedConfig{}, &Error{code: CodeMountInvalid}
		}
		return MountedConfig{}, &Error{code: CodeMountUnavailable}
	}
	defer root.Close()
	manifestBytes, err := root.read(rerankingManifestFilename, maximumManifestBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(manifestBytes)
	manifest, err := parseMountedManifest(manifestBytes, organizationID)
	if err != nil {
		return MountedConfig{}, err
	}
	profileBytes, err := root.read(manifest.ProfileFile, maximumProfileBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(profileBytes)
	var profile Profile
	if err := jsonv2.Unmarshal(profileBytes, &profile,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		profile.Validate() != nil || profile.ProfileHash != manifest.ProfileHash {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	rootBytes, err := root.read(manifest.RootCAFile, maximumRootBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(rootBytes)
	roots, err := parseRerankingRoots(rootBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	certificateBytes, err := root.read(manifest.ClientCertificateFile, maximumClientCertBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(certificateBytes)
	keyBytes, err := root.read(manifest.ClientKeyFile, maximumClientCertBytes)
	if err != nil {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	defer clearBytes(keyBytes)
	certificate, err := tls.X509KeyPair(certificateBytes, keyBytes)
	if err != nil || len(certificate.Certificate) == 0 {
		return MountedConfig{}, &Error{code: CodeMountInvalid}
	}
	return MountedConfig{OrganizationID: organizationID, Profile: profile,
		TrustRoots: roots, ClientCertificate: &certificate}, nil
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
	if manifest.Schema != rerankingManifestSchema || manifest.OrganizationID != organizationID ||
		manifest.ProfileFile != rerankingProfileFilename || !validSHA256(manifest.ProfileHash) ||
		manifest.RootCAFile != rerankingRootCAFilename ||
		manifest.ClientCertificateFile != rerankingClientCertFile || manifest.ClientKeyFile != rerankingClientKeyFile {
		return mountedManifest{}, &Error{code: CodeMountInvalid}
	}
	return manifest, nil
}

func parseRerankingRoots(raw []byte) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > maximumRootBytes {
		return nil, errors.New("reranking roots unavailable")
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
			return nil, errors.New("invalid reranking root")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !validRerankingCertificate(certificate) {
			return nil, errors.New("invalid reranking root")
		}
		digest := sha256.Sum256(block.Bytes)
		if _, duplicate := seen[digest]; duplicate {
			return nil, errors.New("duplicate reranking root")
		}
		seen[digest] = struct{}{}
		pool.AddCert(certificate)
		count++
		if count > maximumCertificates {
			return nil, errors.New("too many reranking roots")
		}
		rest = remainder
	}
	if count == 0 || len(pool.Subjects()) == 0 {
		return nil, errors.New("empty reranking roots")
	}
	return pool, nil
}

func validRerankingCertificate(value *x509.Certificate) bool {
	return value != nil && value.BasicConstraintsValid && value.IsCA &&
		(value.KeyUsage == 0 || value.KeyUsage&x509.KeyUsageCertSign != 0) && len(value.UnhandledCriticalExtensions) == 0
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
