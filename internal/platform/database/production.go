package database

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

// startupLibpqEnvironmentPresent is captured before application composition.
// A second live check immediately before parsing detects additions after init;
// this bit prevents a later removal from making a contaminated startup clean.
// The process does not retain environment values in this package.
var startupLibpqEnvironmentPresent = hasLibpqEnvironment(os.Environ())

type productionDatabaseTarget struct {
	host     string
	port     uint16
	database string
	user     string
	password string
}

// OpenProduction is the only production runtime database constructor. It
// rejects libpq environment input and proves that pgx preserved the exact
// single-host verify-full target before any network operation is attempted.
func OpenProduction(ctx context.Context, config Config, roots trustbundle.DatabaseRoots) (*Store, error) {
	if ctx == nil || startupLibpqEnvironmentPresent {
		return nil, &Error{code: CodeConfigInvalid}
	}
	environment := os.Environ()
	poolConfig, err := productionPoolConfig(config, environment, roots)
	if err != nil {
		return nil, err
	}
	return openPool(ctx, poolConfig)
}

func productionPoolConfig(config Config, environment []string, roots trustbundle.DatabaseRoots) (*pgxpool.Config, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	target, err := parseProductionDatabaseTarget(config.URL)
	if err != nil {
		return nil, &Error{code: CodeConfigInvalid, cause: err}
	}
	// OpenProduction snapshots the live environment directly before this
	// libpq-compatible parser. Production startup is single-threaded and does
	// not mutate env; tests inject an exact snapshot through this private seam.
	if hasLibpqEnvironment(environment) {
		return nil, &Error{code: CodeConfigInvalid}
	}
	poolConfig, err := pgxpool.ParseConfig(config.URL)
	if err != nil || !productionConfigMatches(poolConfig, target) {
		return nil, &Error{code: CodeConfigInvalid, cause: err}
	}
	trustedRoots, err := roots.NewCertPool()
	if err != nil || len(trustedRoots.Subjects()) == 0 {
		return nil, &Error{code: CodeConfigInvalid}
	}
	poolConfig.ConnConfig.TLSConfig.RootCAs = trustedRoots

	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "knowvault-runtime"
	poolConfig.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
		return verifyRuntimeRole(connectContext, connection, config.ApplicationRole)
	}
	return poolConfig, nil
}

func hasLibpqEnvironment(environment []string) bool {
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(strings.ToUpper(name), "PG") {
			return true
		}
	}
	return false
}

func parseProductionDatabaseTarget(raw string) (productionDatabaseTarget, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "postgres" || parsed.Opaque != "" || parsed.RawPath != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.User == nil || parsed.RawQuery != "sslmode=verify-full" || parsed.String() != raw || strings.Contains(parsed.Host, ",") ||
		parsed.Path == "" || parsed.Path == "/" || strings.Count(parsed.Path, "/") != 1 {
		return productionDatabaseTarget{}, &Error{code: CodeConfigInvalid}
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil || !validProductionDNSName(host) {
		return productionDatabaseTarget{}, &Error{code: CodeConfigInvalid}
	}
	portNumber, err := strconv.ParseUint(portText, 10, 16)
	password, hasPassword := parsed.User.Password()
	user := parsed.User.Username()
	databaseName := strings.TrimPrefix(parsed.Path, "/")
	if err != nil || portNumber == 0 || strconv.FormatUint(portNumber, 10) != portText || user == "" || !hasPassword || password == "" || databaseName == "" {
		return productionDatabaseTarget{}, &Error{code: CodeConfigInvalid}
	}
	return productionDatabaseTarget{host: host, port: uint16(portNumber), database: databaseName, user: user, password: password}, nil
}

func validProductionDNSName(host string) bool {
	if host == "" || len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
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

func productionConfigMatches(poolConfig *pgxpool.Config, target productionDatabaseTarget) bool {
	if poolConfig == nil || poolConfig.ConnConfig == nil {
		return false
	}
	config := poolConfig.ConnConfig.Config
	if config.Host != target.host || config.Port != target.port || config.Database != target.database || config.User != target.user || config.Password != target.password ||
		len(config.Fallbacks) != 0 || config.RuntimeParams == nil || len(config.RuntimeParams) != 0 || config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify ||
		config.TLSConfig.ServerName != target.host || config.TLSConfig.RootCAs != nil || config.TLSConfig.VerifyPeerCertificate != nil || config.TLSConfig.VerifyConnection != nil {
		return false
	}
	// Keep the Go default floor or an explicitly stronger floor. A parser result
	// that explicitly permits pre-TLS-1.2 is not a production configuration.
	minimumIsSafe := config.TLSConfig.MinVersion == 0 || config.TLSConfig.MinVersion >= tls.VersionTLS12
	maximumIsSafe := config.TLSConfig.MaxVersion == 0 || config.TLSConfig.MaxVersion >= tls.VersionTLS12
	return minimumIsSafe && maximumIsSafe
}
