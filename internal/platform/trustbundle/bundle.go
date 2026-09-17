// Package trustbundle loads purpose-separated administrator-mounted CA bundles
// accepted by production composition. It has no environment or system-pool
// fallback.
package trustbundle

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

const (
	DefaultMountRoot             = "/run/knowvault/trust"
	DefaultSourceMountRoot       = "/run/knowvault/source-trust"
	databaseBundleFilename       = "database-ca.pem"
	oidcBundleFilename           = "oidc-ca.pem"
	gitBundleFilename            = "git-ca.pem"
	mailBundleFilename           = "mail-ca.pem"
	sourceDatabaseBundleFilename = "database-ca.pem"
	maximumBundleBytes           = 1 << 20
	maximumCertificates          = 256
)

// ErrorCode is intentionally coarse so filesystem and parser details cannot
// leak through logs or HTTP errors.
type ErrorCode string

const (
	CodeUnavailable ErrorCode = "TRUST_BUNDLE_UNAVAILABLE"
	CodeInvalid     ErrorCode = "TRUST_BUNDLE_INVALID"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	var bundleError *Error
	if errors.As(err, &bundleError) {
		return bundleError.code
	}
	return CodeUnavailable
}

// Bundle is a copy-safe immutable handle. It retains only private DER; callers
// can obtain purpose-typed handles that reparse a fresh pool per consumer.
type Bundle struct{ state *bundleState }

type bundleState struct {
	databaseRoots       DatabaseRoots
	databaseFingerprint [sha256.Size]byte
	oidcRoots           OIDCRoots
	oidcFingerprint     [sha256.Size]byte
}

// DatabaseRoots and OIDCRoots are deliberately different compile-time types.
// Each handle owns immutable, private DER and can only produce a newly parsed
// pool; no mutable certificate, DER slice or CertPool is retained from callers.
type DatabaseRoots struct{ database *databaseRootsState }
type OIDCRoots struct{ oidc *oidcRootsState }
type GitRoots struct{ git *gitRootsState }
type MailRoots struct{ mail *mailRootsState }

// SourceBundle keeps Git, IMAP and external-database trust purpose-separated
// from the platform's own control-plane database/OIDC roots. A worker may use
// these roots only for the corresponding connector; the external-database
// roots authenticate an operator-registered POSTGRESQL_QUERY / governed-query
// source connection and must never be conflated with the platform's own
// control-plane database trust (trustbundle.Bundle.DatabaseRoots), which
// authenticates only the worker's own connection to the KnowVault database.
type SourceBundle struct {
	gitRoots            GitRoots
	gitFingerprint      [sha256.Size]byte
	mailRoots           MailRoots
	mailFingerprint     [sha256.Size]byte
	databaseRoots       DatabaseRoots
	databaseFingerprint [sha256.Size]byte
}

type databaseRootsState struct{ roots *rootSetState }
type oidcRootsState struct{ roots *rootSetState }
type gitRootsState struct{ roots *rootSetState }
type mailRootsState struct{ roots *rootSetState }

type rootSetState struct{ certificates [][]byte }

func (DatabaseRoots) String() string   { return "trustbundle.DatabaseRoots{[REDACTED]}" }
func (DatabaseRoots) GoString() string { return "trustbundle.DatabaseRoots{[REDACTED]}" }
func (OIDCRoots) String() string       { return "trustbundle.OIDCRoots{[REDACTED]}" }
func (OIDCRoots) GoString() string     { return "trustbundle.OIDCRoots{[REDACTED]}" }
func (GitRoots) String() string        { return "trustbundle.GitRoots{[REDACTED]}" }
func (GitRoots) GoString() string      { return "trustbundle.GitRoots{[REDACTED]}" }
func (MailRoots) String() string       { return "trustbundle.MailRoots{[REDACTED]}" }
func (MailRoots) GoString() string     { return "trustbundle.MailRoots{[REDACTED]}" }

func (Bundle) String() string         { return "trustbundle.Bundle{[REDACTED]}" }
func (Bundle) GoString() string       { return "trustbundle.Bundle{[REDACTED]}" }
func (SourceBundle) String() string   { return "trustbundle.SourceBundle{[REDACTED]}" }
func (SourceBundle) GoString() string { return "trustbundle.SourceBundle{[REDACTED]}" }

// LoadMounted reads only the fixed production mount.
func LoadMounted() (Bundle, error) { return loadMounted(DefaultMountRoot) }

// LoadWorkerMounted selects the ingestion worker's fixed ownership contract.
func LoadWorkerMounted() (Bundle, error) {
	return loadMountedForConsumer(DefaultMountRoot, runtimeidentity.Worker)
}

// LoadMountedAt reads the same fixed-shape, ownership-checked bundle from an
// explicitly supplied mount root. It is intended for deployment tooling that
// receives the administrator-selected root as input; it never falls back to
// DefaultMountRoot when rootPath is empty or invalid.
func LoadMountedAt(rootPath string) (Bundle, error) { return loadMounted(rootPath) }

// LoadWorkerMountedAt is the operator seam for the same worker-only contract.
func LoadWorkerMountedAt(rootPath string) (Bundle, error) {
	return loadMountedForConsumer(rootPath, runtimeidentity.Worker)
}

// LoadSourceMounted reads the fixed worker-only source trust mount. Git and
// IMAP roots are intentionally separate from database/OIDC roots so a source
// connector cannot accidentally inherit platform trust.
func LoadSourceMounted() (SourceBundle, error) { return loadSourceMounted(DefaultSourceMountRoot) }

// LoadSourceMountedAt is the explicit-root seam used by deployment tooling and
// boundary tests. Production composition uses LoadSourceMounted.
func LoadSourceMountedAt(rootPath string) (SourceBundle, error) { return loadSourceMounted(rootPath) }

// LoadWorkerSourceMounted keeps source trust separate from platform trust and
// requires the worker group on the directory and every opened file.
func LoadWorkerSourceMounted() (SourceBundle, error) {
	return loadSourceMountedForConsumer(DefaultSourceMountRoot, runtimeidentity.Worker)
}

func LoadWorkerSourceMountedAt(rootPath string) (SourceBundle, error) {
	return loadSourceMountedForConsumer(rootPath, runtimeidentity.Worker)
}

// loadMounted contains the shared FD-pinned implementation for the fixed
// production root and the operator's explicit-root entry point.
func loadMounted(rootPath string) (Bundle, error) {
	return loadMountedForConsumer(rootPath, runtimeidentity.Server)
}

func loadMountedForConsumer(rootPath string, consumer runtimeidentity.MountConsumer) (Bundle, error) {
	root, err := openMountedRootForConsumer(rootPath, consumer)
	if err != nil {
		return Bundle{}, &Error{code: CodeUnavailable}
	}
	defer root.Close()
	databaseRaw, err := root.read(databaseBundleFilename, maximumBundleBytes)
	if err != nil {
		return Bundle{}, &Error{code: CodeUnavailable}
	}
	databaseRoots, err := NewDatabaseRootsPEM(databaseRaw)
	if err != nil {
		return Bundle{}, &Error{code: CodeInvalid}
	}
	oidcRaw, err := root.read(oidcBundleFilename, maximumBundleBytes)
	if err != nil {
		return Bundle{}, &Error{code: CodeUnavailable}
	}
	oidcRoots, err := NewOIDCRootsPEM(oidcRaw)
	if err != nil {
		return Bundle{}, &Error{code: CodeInvalid}
	}
	return Bundle{state: &bundleState{
		databaseRoots: databaseRoots, databaseFingerprint: sha256.Sum256(databaseRaw),
		oidcRoots: oidcRoots, oidcFingerprint: sha256.Sum256(oidcRaw),
	}}, nil
}

func loadSourceMounted(rootPath string) (SourceBundle, error) {
	return loadSourceMountedForConsumer(rootPath, runtimeidentity.Server)
}

func loadSourceMountedForConsumer(rootPath string, consumer runtimeidentity.MountConsumer) (SourceBundle, error) {
	root, err := openMountedRootForConsumer(rootPath, consumer)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeUnavailable}
	}
	defer root.Close()
	gitRaw, err := root.read(gitBundleFilename, maximumBundleBytes)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeUnavailable}
	}
	gitRoots, err := NewGitRootsPEM(gitRaw)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeInvalid}
	}
	mailRaw, err := root.read(mailBundleFilename, maximumBundleBytes)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeUnavailable}
	}
	mailRoots, err := NewMailRootsPEM(mailRaw)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeInvalid}
	}
	databaseRaw, err := root.read(sourceDatabaseBundleFilename, maximumBundleBytes)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeUnavailable}
	}
	databaseRoots, err := NewDatabaseRootsPEM(databaseRaw)
	if err != nil {
		return SourceBundle{}, &Error{code: CodeInvalid}
	}
	return SourceBundle{
		gitRoots: gitRoots, gitFingerprint: sha256.Sum256(gitRaw),
		mailRoots: mailRoots, mailFingerprint: sha256.Sum256(mailRaw),
		databaseRoots: databaseRoots, databaseFingerprint: sha256.Sum256(databaseRaw),
	}, nil
}

// NewDatabaseRootsPEM validates and snapshots a database-purpose PEM bundle.
// Production composition uses LoadMounted; this constructor is also the
// deterministic seam used by network-boundary tests.
func NewDatabaseRootsPEM(raw []byte) (DatabaseRoots, error) {
	certificates, err := parseStrictPEM(raw)
	if err != nil {
		return DatabaseRoots{}, err
	}
	return DatabaseRoots{database: &databaseRootsState{roots: newRootSetState(certificates)}}, nil
}

// NewOIDCRootsPEM validates and snapshots an OIDC-purpose PEM bundle.
func NewOIDCRootsPEM(raw []byte) (OIDCRoots, error) {
	certificates, err := parseStrictPEM(raw)
	if err != nil {
		return OIDCRoots{}, err
	}
	return OIDCRoots{oidc: &oidcRootsState{roots: newRootSetState(certificates)}}, nil
}

// NewGitRootsPEM validates and snapshots a Git-purpose PEM bundle.
func NewGitRootsPEM(raw []byte) (GitRoots, error) {
	certificates, err := parseStrictPEM(raw)
	if err != nil {
		return GitRoots{}, err
	}
	return GitRoots{git: &gitRootsState{roots: newRootSetState(certificates)}}, nil
}

// NewMailRootsPEM validates and snapshots an IMAP-purpose PEM bundle.
func NewMailRootsPEM(raw []byte) (MailRoots, error) {
	certificates, err := parseStrictPEM(raw)
	if err != nil {
		return MailRoots{}, err
	}
	return MailRoots{mail: &mailRootsState{roots: newRootSetState(certificates)}}, nil
}

func newRootSetState(certificates [][]byte) *rootSetState {
	owned := make([][]byte, len(certificates))
	for index, certificate := range certificates {
		owned[index] = append([]byte(nil), certificate...)
	}
	return &rootSetState{certificates: owned}
}

// DatabaseRoots returns the immutable database-purpose handle.
func (value Bundle) DatabaseRoots() (DatabaseRoots, error) {
	if value.state == nil || !value.state.databaseRoots.valid() {
		return DatabaseRoots{}, &Error{code: CodeUnavailable}
	}
	return value.state.databaseRoots, nil
}

// OIDCRoots returns the immutable OIDC-purpose handle.
func (value Bundle) OIDCRoots() (OIDCRoots, error) {
	if value.state == nil || !value.state.oidcRoots.valid() {
		return OIDCRoots{}, &Error{code: CodeUnavailable}
	}
	return value.state.oidcRoots, nil
}

// NewCertPool reparses privately owned DER into a fresh database pool.
func (value DatabaseRoots) NewCertPool() (*x509.CertPool, error) {
	if !value.valid() {
		return nil, &Error{code: CodeUnavailable}
	}
	return value.database.roots.newCertPool()
}

// NewCertPool reparses privately owned DER into a fresh OIDC pool.
func (value OIDCRoots) NewCertPool() (*x509.CertPool, error) {
	if !value.valid() {
		return nil, &Error{code: CodeUnavailable}
	}
	return value.oidc.roots.newCertPool()
}

// GitRoots returns the immutable Git-purpose handle.
func (value SourceBundle) GitRoots() (GitRoots, error) {
	if !value.gitRoots.valid() {
		return GitRoots{}, &Error{code: CodeUnavailable}
	}
	return value.gitRoots, nil
}

// MailRoots returns the immutable IMAP-purpose handle.
func (value SourceBundle) MailRoots() (MailRoots, error) {
	if !value.mailRoots.valid() {
		return MailRoots{}, &Error{code: CodeUnavailable}
	}
	return value.mailRoots, nil
}

// DatabaseRoots returns the immutable external-source-database-purpose
// handle. This authenticates an operator-registered POSTGRESQL_QUERY /
// governed-query connection's own server certificate; it is loaded from the
// worker-only source-trust mount and is never the platform's own
// control-plane database trust (trustbundle.Bundle.DatabaseRoots).
func (value SourceBundle) DatabaseRoots() (DatabaseRoots, error) {
	if !value.databaseRoots.valid() {
		return DatabaseRoots{}, &Error{code: CodeUnavailable}
	}
	return value.databaseRoots, nil
}

func (value GitRoots) NewCertPool() (*x509.CertPool, error) {
	if !value.valid() {
		return nil, &Error{code: CodeUnavailable}
	}
	return value.git.roots.newCertPool()
}

func (value MailRoots) NewCertPool() (*x509.CertPool, error) {
	if !value.valid() {
		return nil, &Error{code: CodeUnavailable}
	}
	return value.mail.roots.newCertPool()
}

func (value DatabaseRoots) valid() bool {
	return value.database != nil && value.database.roots != nil && value.database.roots.valid()
}

func (value OIDCRoots) valid() bool {
	return value.oidc != nil && value.oidc.roots != nil && value.oidc.roots.valid()
}

func (value GitRoots) valid() bool {
	return value.git != nil && value.git.roots != nil && value.git.roots.valid()
}

func (value MailRoots) valid() bool {
	return value.mail != nil && value.mail.roots != nil && value.mail.roots.valid()
}

func (state *rootSetState) valid() bool {
	return state != nil && len(state.certificates) > 0 && len(state.certificates) <= maximumCertificates
}

func (state *rootSetState) newCertPool() (*x509.CertPool, error) {
	if !state.valid() {
		return nil, &Error{code: CodeUnavailable}
	}
	pool := x509.NewCertPool()
	for _, retained := range state.certificates {
		owned := append([]byte(nil), retained...)
		certificate, err := x509.ParseCertificate(owned)
		if err != nil || !validCertificate(certificate) {
			return nil, &Error{code: CodeInvalid}
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}

// DatabaseFingerprint is SHA-256 of the exact accepted database-ca.pem bytes,
// including PEM layout and whitespace.
func (value Bundle) DatabaseFingerprint() ([sha256.Size]byte, error) {
	if value.state == nil || !value.state.databaseRoots.valid() {
		return [sha256.Size]byte{}, &Error{code: CodeUnavailable}
	}
	return value.state.databaseFingerprint, nil
}

// OIDCFingerprint is SHA-256 of the exact accepted oidc-ca.pem bytes,
// including PEM layout and whitespace.
func (value Bundle) OIDCFingerprint() ([sha256.Size]byte, error) {
	if value.state == nil || !value.state.oidcRoots.valid() {
		return [sha256.Size]byte{}, &Error{code: CodeUnavailable}
	}
	return value.state.oidcFingerprint, nil
}

// GitFingerprint is SHA-256 of the exact accepted git-ca.pem bytes.
func (value SourceBundle) GitFingerprint() ([sha256.Size]byte, error) {
	if !value.gitRoots.valid() {
		return [sha256.Size]byte{}, &Error{code: CodeUnavailable}
	}
	return value.gitFingerprint, nil
}

// MailFingerprint is SHA-256 of the exact accepted mail-ca.pem bytes.
func (value SourceBundle) MailFingerprint() ([sha256.Size]byte, error) {
	if !value.mailRoots.valid() {
		return [sha256.Size]byte{}, &Error{code: CodeUnavailable}
	}
	return value.mailFingerprint, nil
}

// DatabaseFingerprint is SHA-256 of the exact accepted source-trust
// database-ca.pem bytes.
func (value SourceBundle) DatabaseFingerprint() ([sha256.Size]byte, error) {
	if !value.databaseRoots.valid() {
		return [sha256.Size]byte{}, &Error{code: CodeUnavailable}
	}
	return value.databaseFingerprint, nil
}

func parseStrictPEM(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > maximumBundleBytes {
		return nil, &Error{code: CodeInvalid}
	}
	var certificates [][]byte
	seen := make(map[[sha256.Size]byte]struct{})
	rest := raw
	count := 0
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n\v\f")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, &Error{code: CodeInvalid}
		}
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return nil, &Error{code: CodeInvalid}
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !validCertificate(certificate) {
			return nil, &Error{code: CodeInvalid}
		}
		fingerprint := sha256.Sum256(block.Bytes)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, &Error{code: CodeInvalid}
		}
		seen[fingerprint] = struct{}{}
		certificates = append(certificates, append([]byte(nil), block.Bytes...))
		count++
		if count > maximumCertificates || len(remainder) >= len(rest) {
			return nil, &Error{code: CodeInvalid}
		}
		rest = remainder
	}
	if count == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	return certificates, nil
}

func validCertificate(certificate *x509.Certificate) bool {
	return certificate != nil && certificate.BasicConstraintsValid && certificate.IsCA &&
		(certificate.KeyUsage == 0 || certificate.KeyUsage&x509.KeyUsageCertSign != 0) && len(certificate.UnhandledCriticalExtensions) == 0
}
