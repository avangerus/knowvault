package governedquery

import (
	"crypto/x509"
	"testing"
	"time"
)

func testTrustRoots(t *testing.T) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(testCACertPEM)) {
		t.Fatalf("failed to parse test CA certificate")
	}
	return pool
}

func validLimits() Limits {
	return Limits{StatementTimeout: 5 * time.Second, MaxRows: 1000, MaxResultBytes: 1 << 20, MaxCostEstimate: 1000}
}

func TestConfigValidate(t *testing.T) {
	base := Config{
		ConnectionID: "demo-ops-govquery", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN: "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(Config) Config
	}{
		{"empty connection id", func(c Config) Config { c.ConnectionID = ""; return c }},
		{"missing trust roots", func(c Config) Config { c.TrustRoots = nil; return c }},
		{"sslmode disable rejected", func(c Config) Config {
			c.DSN = "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=disable"
			return c
		}},
		{"literal ip host rejected", func(c Config) Config {
			c.DSN = "postgres://demo_ops_govquery:secret@127.0.0.1:5432/demo_ops?sslmode=verify-full"
			return c
		}},
		{"missing password rejected", func(c Config) Config {
			c.DSN = "postgres://demo_ops_govquery@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full"
			return c
		}},
		{"invalid limits rejected", func(c Config) Config { c.Limits.MaxRows = 0; return c }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := testCase.mutate(base)
			if err := mutated.Validate(); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestValidateDSNShape(t *testing.T) {
	valid := []byte("postgres://user:pass@example-host:5432/demo_ops?sslmode=verify-full")
	if err := validateDSN(valid); err != nil {
		t.Fatalf("expected valid DSN, got %v", err)
	}
	invalid := [][]byte{
		[]byte(""),
		[]byte("postgres://user:pass@example-host:5432/demo_ops?sslmode=require"),
		[]byte("postgres://user@example-host:5432/demo_ops?sslmode=verify-full"),
		[]byte("postgres://user:pass@example-host:5432/demo_ops/extra?sslmode=verify-full"),
		[]byte("mysql://user:pass@example-host:5432/demo_ops?sslmode=verify-full"),
	}
	for _, value := range invalid {
		if err := validateDSN(value); err == nil {
			t.Fatalf("expected rejection for %q", value)
		}
	}
}

// testCACertPEM is a real, freshly generated self-signed certificate used
// only to exercise CertPool parsing; it never anchors a real connection in
// tests.
const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUb41jVBoe+OjZsddWZ1NoxiZgZ0IwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZ292ZXJuZWRxdWVyeS10ZXN0LWNhMB4XDTI2MDkwNjIx
NDMyOFoXDTM2MDkwMzIxNDMyOFowIDEeMBwGA1UEAwwVZ292ZXJuZWRxdWVyeS10
ZXN0LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpf24FGZxuxW
oK8/TbvPUJmsSH1RMz8G+H5kNzd0XqHt0ewuMgro8VT68LmttzR2eeGnoRUZk7dk
HwQd7e6rOZVanZeqvALQM+2HcR+6vppovXUg9yeKgoDFBqVZ3x+A9c4XpibxA/vs
31CzujqYyGRsFjOpqGRwI9FTwYu6Y4XOpnWShjcZYNt8XJlsUHO0G6Za1yPkp4of
EK2VkWBPkshT102JGen/pYBQAYijRg4Tz+maQy7/QWQNvZm19CHaB0IsuljyFYwE
KuE4U12EHMZ96HB3JDAtK9sfQ40fFVKNcRgQnyAIkZH5I6Le/RTMlhtU2p6UdRGi
4rfnk6nWNQIDAQABo1MwUTAdBgNVHQ4EFgQUP5wBuw9dRO7+x0In5V0rNUIftyMw
HwYDVR0jBBgwFoAUP5wBuw9dRO7+x0In5V0rNUIftyMwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAHu1lQHH4UuZV6dgUN1xIT3widrOyWYSjKQzR
rsD/wWUKtcqjYiB6qQkeYmZtaBu2dbeirTVfZ8z1WBufEhXfO4gxlOiYOZ8Q4iiL
KyC1sp55eWgVLl5znAJwkQbAdZqO+wV9myYtK/FGuuIMHHi/snmt6X179cy03NQH
qBL6WcmhQl+ABLE8W8r/FETEbbMQKC0TZqgHS4/Y4ioRNaxKT9LDHno82uzXfzm+
QgJkyp1PECjjtl+a7Rhoc6+f6Rr1YL+svVzVsF8stxlEdmHh5eEfjhV3FrsBywnH
l5A+3plBUzevft2AAKF2l4xduolay/70n1L3L2SP43puFoMz0w==
-----END CERTIFICATE-----`
