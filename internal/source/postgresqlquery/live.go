package postgresqlquery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// CredentialResolver is the deployment boundary for external database
// credentials. The control plane passes only the opaque reference stored on a
// source connection revision; implementations must resolve from protected
// mounted material, never from a request or job payload.
type CredentialResolver interface {
	ResolveReference(context.Context, string) (string, error)
}

// TrustRoots is the small capability boundary for the administrator-mounted
// database CA bundle. The connector deliberately accepts the interface rather
// than a raw *x509.CertPool so callers cannot share or mutate a pool between
// connections.
type TrustRoots interface {
	NewCertPool() (*x509.CertPool, error)
}

// LiveConnector opens a real PostgreSQL connection for each bounded snapshot.
// It has no catalog or workspace authority; the resulting Snapshot is handed
// to the ingestion publisher for local lease-fenced persistence.
type LiveConnector struct {
	Resolver CredentialResolver
	Roots    TrustRoots
}

const (
	queryApplicationName     = "knowvault-postgresql-query"
	discoveryApplicationName = "knowvault-postgresql-query-discovery"
)

func NewLiveConnector(resolver CredentialResolver) (*LiveConnector, error) {
	if resolver == nil {
		return nil, errors.New("postgresql query credential resolver is required")
	}
	return &LiveConnector{Resolver: resolver}, nil
}

// NewLiveConnectorWithTrust is the production constructor. A connector that
// lacks the purpose-separated administrator CA capability cannot open an
// external database connection.
func NewLiveConnectorWithTrust(resolver CredentialResolver, roots TrustRoots) (*LiveConnector, error) {
	if resolver == nil || roots == nil {
		return nil, errors.New("postgresql query credential resolver and trust roots are required")
	}
	return &LiveConnector{Resolver: resolver, Roots: roots}, nil
}

func (connector *LiveConnector) ReadProjection(ctx context.Context, connectionID, credentialReference string, projection Projection, limits Limits) (Snapshot, error) {
	if connector == nil || connector.Resolver == nil || connector.Roots == nil || ctx == nil || connectionID != projection.ConnectionID || credentialReference == "" {
		return Snapshot{}, &Error{code: CodeExternalFailure}
	}
	connection, err := connector.openConnection(ctx, credentialReference, queryApplicationName)
	if err != nil {
		return Snapshot{}, err
	}
	defer connection.Close(ctx)
	return ReadProjection(ctx, connection, projection, limits)
}

// ReadFilteredProjection opens one credential-backed connection and executes a
// closed, server-owned parameterized projection read. Like ReadProjection it
// reuses the single transport opener and requires the caller's connection ID to
// equal the Projection's; no credential, schema, SQL or identifier crosses this
// boundary from the request.
func (connector *LiveConnector) ReadFilteredProjection(ctx context.Context, connectionID, credentialReference string, request FilteredProjectionRequest, limits Limits) (Snapshot, error) {
	if connector == nil || connector.Resolver == nil || connector.Roots == nil || ctx == nil || connectionID != request.Projection.ConnectionID || credentialReference == "" {
		return Snapshot{}, &Error{code: CodeExternalFailure}
	}
	connection, err := connector.openConnection(ctx, credentialReference, queryApplicationName)
	if err != nil {
		return Snapshot{}, err
	}
	defer connection.Close(ctx)
	return ReadFilteredProjection(ctx, connection, request, limits)
}

// openConnection resolves one protected credential reference and applies the
// connector's single PostgreSQL transport policy. Callers choose only one of
// the package-owned application names; no caller-provided session settings or
// connection string can reach pgx.
func (connector *LiveConnector) openConnection(ctx context.Context, credentialReference, applicationName string) (*pgx.Conn, error) {
	if connector == nil || connector.Resolver == nil || connector.Roots == nil || ctx == nil || credentialReference == "" {
		return nil, &Error{code: CodeExternalFailure}
	}
	dsn, err := connector.Resolver.ResolveReference(ctx, credentialReference)
	if err != nil {
		return nil, &Error{code: CodeExternalFailure}
	}
	secret := []byte(dsn)
	if err := validateExternalURL(secret); err != nil {
		clearBytes(secret)
		return nil, &Error{code: CodeExternalFailure}
	}
	rawURL := string(secret)
	parsed, parseErr := url.Parse(rawURL)
	config, err := pgx.ParseConfig(rawURL)
	clearBytes(secret)
	if err != nil || config == nil || config.TLSConfig == nil {
		return nil, &Error{code: CodeExternalFailure}
	}
	// pgx accepts a number of connection-string forms and may leave the TLS
	// server name unset or derive it from a value that is not the exact DNS
	// authority we validated above. Pin SNI explicitly to the validated host;
	// a certificate for another name must never be accepted merely because the
	// CA is trusted. This also makes the production connection invariant
	// inspectable in tests without opening a socket.
	if parseErr != nil || !validateExternalTLSConfig(parsed, config) {
		return nil, &Error{code: CodeExternalFailure}
	}
	trustedRoots, err := connector.Roots.NewCertPool()
	if err != nil || trustedRoots == nil || len(trustedRoots.Subjects()) == 0 {
		return nil, &Error{code: CodeExternalFailure}
	}
	config.TLSConfig.RootCAs = trustedRoots
	config.TLSConfig.InsecureSkipVerify = false
	if config.TLSConfig.MinVersion < tls.VersionTLS12 {
		config.TLSConfig.MinVersion = tls.VersionTLS12
	}
	if config.RuntimeParams == nil {
		config.RuntimeParams = map[string]string{}
	}
	for key := range config.RuntimeParams {
		delete(config.RuntimeParams, key)
	}
	config.RuntimeParams["application_name"] = applicationName
	connection, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, &Error{code: CodeExternalFailure}
	}
	return connection, nil
}

// validateExternalTLSConfig binds the parsed, policy-validated URL to the
// driver TLS configuration. It is deliberately separate from socket dialing
// so the SNI/verification invariant has a deterministic negative test.
func validateExternalTLSConfig(parsed *url.URL, config *pgx.ConnConfig) bool {
	if parsed == nil || config == nil || config.TLSConfig == nil {
		return false
	}
	expectedHost, _, err := net.SplitHostPort(parsed.Host)
	return err == nil && validDNSHost(expectedHost) && config.TLSConfig.ServerName == expectedHost && !config.TLSConfig.InsecureSkipVerify
}

func validateExternalURL(raw []byte) error {
	if len(raw) == 0 || len(raw) > 4096 || !utf8.Valid(raw) || strings.ContainsAny(string(raw), "\x00\r\n") {
		return errors.New("invalid external database URL")
	}
	parsed, err := url.Parse(string(raw))
	if err != nil || parsed.Scheme != "postgres" || parsed.Host == "" || parsed.User == nil || parsed.Opaque != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawQuery != "sslmode=verify-full" || parsed.String() != string(raw) || parsed.Path == "" || parsed.Path == "/" || strings.Count(parsed.Path, "/") != 1 {
		return errors.New("external database URL policy rejected")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	portNumber, portErr := strconv.Atoi(port)
	password, hasPassword := parsed.User.Password()
	if err != nil || !validDNSHost(host) || portErr != nil || portNumber < 1 || portNumber > 65535 || parsed.User.Username() == "" || !hasPassword || password == "" {
		return errors.New("external database URL target rejected")
	}
	return nil
}

func validDNSHost(host string) bool {
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
