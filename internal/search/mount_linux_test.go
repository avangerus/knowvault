//go:build linux

package search

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

func TestLoadMountedAtReadsOnlyOwnedSearchCapability(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 65532); err != nil {
		t.Fatal(err)
	}
	caPEM := testSearchCAPEM(t)
	manifest := mountedManifest{
		Schema: searchManifestSchema, OrganizationID: "org_alpha",
		Endpoint: "https://search.example:9443", IndexAlias: "org-alpha-v3",
		Generation: 3, GenerationFence: 9, RootCAFile: searchRootCAFilename,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnedSearchFile(t, root, searchManifestFilename, manifestBytes)
	writeOwnedSearchFile(t, root, searchRootCAFilename, caPEM)

	config, err := LoadMountedAt(root, "org_alpha")
	if err != nil {
		t.Fatalf("LoadMountedAt: %v", err)
	}
	if config.Endpoint != manifest.Endpoint || config.IndexAlias != manifest.IndexAlias ||
		config.OrganizationID != manifest.OrganizationID || config.Generation != manifest.Generation ||
		config.GenerationFence != manifest.GenerationFence || config.TrustRoots == nil || len(config.TrustRoots.Subjects()) != 1 || config.ClientCertificate != nil {
		t.Fatalf("unexpected mounted config: %#v", config)
	}

	if err := os.Remove(filepath.Join(root, searchManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(searchRootCAFilename, filepath.Join(root, searchManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatalf("symlink manifest code=%q, want %q", CodeOf(err), CodeMountInvalid)
	}
}

func TestLoadMountedAtDistinguishesMissingRoot(t *testing.T) {
	if _, err := LoadMountedAt(filepath.Join(t.TempDir(), "missing"), "org_alpha"); CodeOf(err) != CodeMountUnavailable {
		t.Fatalf("missing root code=%q, want %q", CodeOf(err), CodeMountUnavailable)
	}
}

func writeOwnedSearchFile(t *testing.T, root, name string, contents []byte) {
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

func testSearchCAPEM(t *testing.T) []byte {
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
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "KnowVault search test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
