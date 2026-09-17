package postgresqlquery

import (
	"context"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
)

type testCredentialResolver struct{}

func (testCredentialResolver) ResolveReference(context.Context, string) (string, error) {
	return "", nil
}

func TestLiveConnectorPinsValidatedHostToTLSVerification(t *testing.T) {
	const raw = "postgres://user:password@db.example:5432/knowvault?sslmode=verify-full"
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !validateExternalTLSConfig(parsed, config) {
		t.Fatalf("pgx verify-full config was not accepted: server_name=%q insecure=%v", config.TLSConfig.ServerName, config.TLSConfig.InsecureSkipVerify)
	}
	config.TLSConfig.ServerName = "other.example"
	if validateExternalTLSConfig(parsed, config) {
		t.Fatal("mismatched SNI host accepted")
	}
	config.TLSConfig.ServerName = "db.example"
	config.TLSConfig.InsecureSkipVerify = true
	if validateExternalTLSConfig(parsed, config) {
		t.Fatal("certificate verification bypass accepted")
	}
}

type testTrustRoots struct{}

func (testTrustRoots) NewCertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte("not-a-certificate"))
	return pool, nil
}

func TestLiveConnectorProductionConstructorRequiresExplicitTrust(t *testing.T) {
	resolver := testCredentialResolver{}
	if _, err := NewLiveConnectorWithTrust(resolver, nil); err == nil {
		t.Fatal("nil trust roots accepted")
	}
	connector, err := NewLiveConnector(resolver)
	if err != nil || connector == nil {
		t.Fatalf("legacy constructor: connector=%v err=%v", connector, err)
	}
	if _, err := connector.ReadProjection(context.Background(), "connection_001", "cred_001", Projection{ConnectionID: "connection_001"}, Limits{}); CodeOf(err) != CodeExternalFailure {
		t.Fatalf("connector without trust roots returned %v", err)
	}
	if _, err := NewLiveConnectorWithTrust(resolver, testTrustRoots{}); err != nil {
		t.Fatalf("valid trust roots rejected: %v", err)
	}
}

func TestValidateExternalURLRejectsNonDNSTargets(t *testing.T) {
	valid := "postgres://user:password@db.example:5432/knowvault?sslmode=verify-full"
	if err := validateExternalURL([]byte(valid)); err != nil {
		t.Fatalf("valid DNS URL rejected: %v", err)
	}
	for _, value := range []string{
		"postgres://user:password@127.0.0.1:5432/knowvault?sslmode=verify-full",
		"postgres://user:password@[::1]:5432/knowvault?sslmode=verify-full",
		"postgres://user:password@db_example:5432/knowvault?sslmode=verify-full",
		"postgres://user:password@-db.example:5432/knowvault?sslmode=verify-full",
		"postgres://user:password@db.example.:5432/knowvault?sslmode=verify-full",
	} {
		if err := validateExternalURL([]byte(value)); err == nil {
			t.Fatalf("invalid DNS URL accepted: %s", value)
		}
	}
}
