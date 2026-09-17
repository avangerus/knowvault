package trustbundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSourceRootsRemainPurposeSeparatedAndImmutable(t *testing.T) {
	gitPEM := sourceCertificatePEM(t, 11)
	mailPEM := sourceCertificatePEM(t, 12)
	gitRoots, err := NewGitRootsPEM(gitPEM)
	if err != nil {
		t.Fatal(err)
	}
	mailRoots, err := NewMailRootsPEM(mailPEM)
	if err != nil {
		t.Fatal(err)
	}
	gitPool, err := gitRoots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	mailPool, err := mailRoots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if len(gitPool.Subjects()) != 1 || len(mailPool.Subjects()) != 1 || bytes.Equal(gitPool.Subjects()[0], mailPool.Subjects()[0]) {
		t.Fatal("source-purpose roots were not separated")
	}
	gitFingerprint := sha256.Sum256(gitPEM)
	mailFingerprint := sha256.Sum256(mailPEM)
	source := SourceBundle{gitRoots: gitRoots, gitFingerprint: gitFingerprint, mailRoots: mailRoots, mailFingerprint: mailFingerprint}
	if got, err := source.GitFingerprint(); err != nil || got != gitFingerprint {
		t.Fatalf("git fingerprint=%x err=%v", got, err)
	}
	if got, err := source.MailFingerprint(); err != nil || got != mailFingerprint {
		t.Fatalf("mail fingerprint=%x err=%v", got, err)
	}
	for _, formatted := range []string{source.String(), source.GoString(), gitRoots.String(), mailRoots.String()} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, "CERTIFICATE") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
	gitPEM[0] ^= 0xff
	if pool, err := gitRoots.NewCertPool(); err != nil || len(pool.Subjects()) != 1 {
		t.Fatalf("source roots were not copied: pool=%v err=%v", pool, err)
	}
}

func TestZeroSourceBundleFailsClosed(t *testing.T) {
	var source SourceBundle
	if roots, err := source.GitRoots(); roots.git != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("git roots=%v err=%v", roots, err)
	}
	if roots, err := source.MailRoots(); roots.mail != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("mail roots=%v err=%v", roots, err)
	}
	if pool, err := (GitRoots{}).NewCertPool(); pool != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("git pool=%v err=%v", pool, err)
	}
	if pool, err := (MailRoots{}).NewCertPool(); pool != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("mail pool=%v err=%v", pool, err)
	}
}

func sourceCertificatePEM(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "knowvault-source-test-" + big.NewInt(serial).String()},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_100_000_000, 0),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
