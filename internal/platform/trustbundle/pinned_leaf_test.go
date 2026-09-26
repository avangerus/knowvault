package trustbundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSignedServerPEM returns a self-signed, non-CA server certificate like
// the one a PostgreSQL server generates for itself.
func selfSignedServerPEM(t *testing.T, name string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestDatabaseRootsAcceptPinnedSelfSignedServerCertificate(t *testing.T) {
	leaf, raw := selfSignedServerPEM(t, "db.example.test")
	roots, err := NewDatabaseRootsPEM(raw)
	if err != nil {
		t.Fatalf("pinned self-signed database certificate rejected: %v", err)
	}
	pool, err := roots.NewCertPool()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "db.example.test"}); err != nil {
		t.Fatalf("pinned server certificate does not verify: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.example.test"}); err == nil {
		t.Fatal("pinned certificate verified for another host name")
	}
}

func TestNonDatabaseRootsStillRequireCA(t *testing.T) {
	_, raw := selfSignedServerPEM(t, "idp.example.test")
	if _, err := NewOIDCRootsPEM(raw); err == nil {
		t.Fatal("OIDC roots accepted a non-CA certificate")
	}
	if _, err := NewGitRootsPEM(raw); err == nil {
		t.Fatal("Git roots accepted a non-CA certificate")
	}
	if _, err := NewMailRootsPEM(raw); err == nil {
		t.Fatal("mail roots accepted a non-CA certificate")
	}
}
