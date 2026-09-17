//go:build linux

package embedding

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMountedAtReadsOwnedQualifiedEmbeddingCapability(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 65532); err != nil {
		t.Fatal(err)
	}
	caPEM := mountCertificatePEM(t, "KnowVault embedding test CA", true)
	clientCertPEM, clientKeyPEM := mountClientCertificatePEM(t)
	profile := testProfile()
	manifestBytes, err := json.Marshal(mountedManifest{
		Schema: embeddingManifestSchema, OrganizationID: "org_alpha",
		ProfileFile: embeddingProfileFilename, ProfileHash: profile.ProfileHash,
		RootCAFile: embeddingRootCAFilename, ClientCertificateFile: embeddingClientCertFile,
		ClientKeyFile: embeddingClientKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnedEmbeddingFile(t, root, embeddingManifestFilename, manifestBytes)
	writeOwnedEmbeddingFile(t, root, embeddingProfileFilename, profileBytes)
	writeOwnedEmbeddingFile(t, root, embeddingRootCAFilename, caPEM)
	writeOwnedEmbeddingFile(t, root, embeddingClientCertFile, clientCertPEM)
	writeOwnedEmbeddingFile(t, root, embeddingClientKeyFile, clientKeyPEM)

	config, err := LoadMountedAt(root, "org_alpha")
	if err != nil {
		t.Fatalf("LoadMountedAt: %v", err)
	}
	if config.OrganizationID != "org_alpha" || config.Profile.ProfileHash != profile.ProfileHash ||
		config.TrustRoots == nil || len(config.TrustRoots.Subjects()) != 1 || config.ClientCertificate == nil {
		t.Fatalf("unexpected mounted config: %#v", config)
	}

	if err := os.Remove(filepath.Join(root, embeddingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(embeddingProfileFilename, filepath.Join(root, embeddingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatalf("symlink manifest code=%q, want %q", CodeOf(err), CodeMountInvalid)
	}
	if err := os.Remove(filepath.Join(root, embeddingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, embeddingManifestFilename), manifestBytes, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatalf("permission-drifted root code=%q, want %q", CodeOf(err), CodeMountInvalid)
	}
}

func writeOwnedEmbeddingFile(t *testing.T, root, name string, contents []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, contents, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 65532); err != nil {
		t.Fatal(err)
	}
}

func mountCertificatePEM(t *testing.T, name string, isCA bool) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mountClientCertificatePEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "knowvault-embedding-client"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return cert, privateKey
}
