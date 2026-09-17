package database

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
)

const validProductionURL = "postgres://knowvault_app:secret@postgres.internal:5432/knowvault?sslmode=verify-full"

var _ func(context.Context, Config, trustbundle.DatabaseRoots) (*Store, error) = OpenProduction

func TestProductionPoolConfigPinsExactVerifyFullTarget(t *testing.T) {
	config := DefaultConfig()
	config.URL = validProductionURL
	roots := testTrustRoots(t)
	poolConfig, err := productionPoolConfig(config, nil, roots)
	if err != nil {
		t.Fatalf("productionPoolConfig() error = %v", err)
	}
	connection := poolConfig.ConnConfig.Config
	if connection.Host != "postgres.internal" || connection.Port != 5432 || connection.Database != "knowvault" ||
		connection.User != "knowvault_app" || connection.Password != "secret" {
		t.Fatalf("unexpected parsed production target: host=%q port=%d database=%q user=%q", connection.Host, connection.Port, connection.Database, connection.User)
	}
	if connection.TLSConfig == nil || connection.TLSConfig.InsecureSkipVerify || connection.TLSConfig.ServerName != "postgres.internal" ||
		connection.TLSConfig.RootCAs == nil || connection.TLSConfig.VerifyPeerCertificate != nil ||
		connection.TLSConfig.VerifyConnection != nil || len(connection.Fallbacks) != 0 {
		t.Fatal("production TLS/fallback invariant was not preserved")
	}
	configuredSubjectCount := len(connection.TLSConfig.RootCAs.Subjects())
	callerPool, err := roots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	addTestRoot(t, callerPool, 2)
	if configuredSubjectCount != 1 || len(callerPool.Subjects()) != 2 || len(connection.TLSConfig.RootCAs.Subjects()) != configuredSubjectCount {
		t.Fatal("caller pool mutation changed production trust roots")
	}
	if len(connection.RuntimeParams) != 1 || connection.RuntimeParams["application_name"] != "knowvault-runtime" {
		t.Fatalf("unexpected runtime parameters: %#v", connection.RuntimeParams)
	}
	if poolConfig.MaxConns != config.MaxConnections || poolConfig.MinConns != config.MinConnections || poolConfig.AfterConnect == nil {
		t.Fatal("bounded pool/runtime-role gate was not installed")
	}
}

func TestProductionEnvironmentRejectsEveryDefinedPGPrefix(t *testing.T) {
	for _, environment := range [][]string{
		{"PGHOST=postgres.internal"},
		{"PGHOST="},
		{"PGSERVICEFILE=/tmp/evil"},
		{"PGAPPNAME=override"},
		{"PGSSLROOTCERT=/tmp/ca"},
		{"pgpassword=secret"},
		{"PGX_TEST_DATABASE=postgres://other"},
	} {
		if !hasLibpqEnvironment(environment) {
			t.Fatalf("PG-prefixed environment accepted: %#v", environment)
		}
	}
	if hasLibpqEnvironment([]string{"PATH=/usr/bin", "XPGHOST=value", "MALFORMED"}) {
		t.Fatal("unrelated environment was rejected")
	}

	config := DefaultConfig()
	config.URL = validProductionURL
	if _, err := productionPoolConfig(config, []string{"PGHOST="}, testTrustRoots(t)); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("defined empty PG variable error = %v", err)
	}
}

func TestProductionPoolConfigRequiresExplicitNonEmptyTrustRoots(t *testing.T) {
	config := DefaultConfig()
	config.URL = validProductionURL
	if _, err := productionPoolConfig(config, nil, trustbundle.DatabaseRoots{}); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("zero typed trust roots error = %v", err)
	}
}

func TestProductionTargetRejectsNonCanonicalOrAmbiguousURLs(t *testing.T) {
	invalidURLs := map[string]string{
		"plaintext":               "postgres://user:secret@db.internal:5432/knowvault?sslmode=disable",
		"verify ca":               "postgres://user:secret@db.internal:5432/knowvault?sslmode=verify-ca",
		"missing mode":            "postgres://user:secret@db.internal:5432/knowvault",
		"extra parameter":         "postgres://user:secret@db.internal:5432/knowvault?sslmode=verify-full&application_name=evil",
		"service keyword":         "service=production",
		"multi host":              "postgres://user:secret@db.internal:5432,other.internal:5432/knowvault?sslmode=verify-full",
		"IPv4":                    "postgres://user:secret@127.0.0.1:5432/knowvault?sslmode=verify-full",
		"IPv6":                    "postgres://user:secret@[::1]:5432/knowvault?sslmode=verify-full",
		"socket":                  "postgres://user:secret@%2Fvar%2Frun%2Fpostgresql:5432/knowvault?sslmode=verify-full",
		"uppercase host":          "postgres://user:secret@DB.internal:5432/knowvault?sslmode=verify-full",
		"trailing dot":            "postgres://user:secret@db.internal.:5432/knowvault?sslmode=verify-full",
		"underscore host":         "postgres://user:secret@db_primary.internal:5432/knowvault?sslmode=verify-full",
		"missing port":            "postgres://user:secret@db.internal/knowvault?sslmode=verify-full",
		"zero port":               "postgres://user:secret@db.internal:0/knowvault?sslmode=verify-full",
		"noncanonical port":       "postgres://user:secret@db.internal:05432/knowvault?sslmode=verify-full",
		"missing user":            "postgres://:secret@db.internal:5432/knowvault?sslmode=verify-full",
		"missing password":        "postgres://user@db.internal:5432/knowvault?sslmode=verify-full",
		"empty password":          "postgres://user:@db.internal:5432/knowvault?sslmode=verify-full",
		"missing database":        "postgres://user:secret@db.internal:5432/?sslmode=verify-full",
		"nested database path":    "postgres://user:secret@db.internal:5432/a/b?sslmode=verify-full",
		"encoded database path":   "postgres://user:secret@db.internal:5432/a%2Fb?sslmode=verify-full",
		"fragment":                "postgres://user:secret@db.internal:5432/knowvault?sslmode=verify-full#fragment",
		"noncanonical query case": "postgres://user:secret@db.internal:5432/knowvault?sslmode=VERIFY-FULL",
	}
	for name, raw := range invalidURLs {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			if _, err := parseProductionDatabaseTarget(raw); CodeOf(err) != CodeConfigInvalid {
				t.Fatalf("unsafe URL accepted: %q (err=%v)", raw, err)
			}
		})
	}
}

func TestProductionPostParseGateRejectsDilution(t *testing.T) {
	target, err := parseProductionDatabaseTarget(validProductionURL)
	if err != nil {
		t.Fatalf("parseProductionDatabaseTarget() error = %v", err)
	}
	newConfig := func(t *testing.T) *pgxpool.Config {
		t.Helper()
		poolConfig, err := pgxpool.ParseConfig(validProductionURL)
		if err != nil {
			t.Fatalf("pgxpool.ParseConfig() error = %v", err)
		}
		return poolConfig
	}
	if !productionConfigMatches(newConfig(t), target) {
		t.Fatal("exact pgx verify-full configuration rejected")
	}

	tests := map[string]func(*pgxpool.Config){
		"nil runtime params": func(c *pgxpool.Config) { c.ConnConfig.RuntimeParams = nil },
		"host":               func(c *pgxpool.Config) { c.ConnConfig.Host = "other.internal" },
		"port":               func(c *pgxpool.Config) { c.ConnConfig.Port = 5433 },
		"database":           func(c *pgxpool.Config) { c.ConnConfig.Database = "other" },
		"user":               func(c *pgxpool.Config) { c.ConnConfig.User = "other" },
		"password":           func(c *pgxpool.Config) { c.ConnConfig.Password = "other" },
		"TLS missing":        func(c *pgxpool.Config) { c.ConnConfig.TLSConfig = nil },
		"TLS insecure":       func(c *pgxpool.Config) { c.ConnConfig.TLSConfig.InsecureSkipVerify = true },
		"TLS server name":    func(c *pgxpool.Config) { c.ConnConfig.TLSConfig.ServerName = "other.internal" },
		"TLS implicit roots": func(c *pgxpool.Config) {
			roots, err := testTrustRoots(t).NewCertPool()
			if err != nil {
				t.Fatal(err)
			}
			c.ConnConfig.TLSConfig.RootCAs = roots
		},
		"TLS custom verifier": func(c *pgxpool.Config) {
			c.ConnConfig.TLSConfig.VerifyConnection = func(tls.ConnectionState) error { return nil }
		},
		"TLS custom peer verifier": func(c *pgxpool.Config) {
			c.ConnConfig.TLSConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		},
		"TLS obsolete floor":   func(c *pgxpool.Config) { c.ConnConfig.TLSConfig.MinVersion = tls.VersionTLS11 },
		"TLS obsolete ceiling": func(c *pgxpool.Config) { c.ConnConfig.TLSConfig.MaxVersion = tls.VersionTLS11 },
		"runtime parameter":    func(c *pgxpool.Config) { c.ConnConfig.RuntimeParams["search_path"] = "public" },
		"fallback": func(c *pgxpool.Config) {
			c.ConnConfig.Fallbacks = append(c.ConnConfig.Fallbacks, &pgconn.FallbackConfig{Host: "other.internal"})
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			poolConfig := newConfig(t)
			mutate(poolConfig)
			if productionConfigMatches(poolConfig, target) {
				t.Fatal("diluted pgx configuration accepted")
			}
		})
	}
}

func testTrustRoots(t *testing.T) trustbundle.DatabaseRoots {
	t.Helper()
	certificate := newTestRootCertificate(t, 1)
	raw := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	roots, err := trustbundle.NewDatabaseRootsPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		raw[index] ^= 0xff
	}
	for index := range certificate.Raw {
		certificate.Raw[index] ^= 0xff
	}
	return roots
}

func addTestRoot(t *testing.T, pool *x509.CertPool, serial int64) {
	t.Helper()
	pool.AddCert(newTestRootCertificate(t, serial))
}

func newTestRootCertificate(t *testing.T, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "KnowVault test root " + big.NewInt(serial).String()},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4_102_444_800, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	return certificate
}
