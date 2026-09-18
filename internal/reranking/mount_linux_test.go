//go:build linux

package reranking

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
	"syscall"
	"testing"
	"time"
)

func TestLoadMountedAtReadsOwnedQualifiedRerankingCapability(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 65532); err != nil {
		t.Fatal(err)
	}
	caPEM := mountCertificatePEM(t, "KnowVault reranking test CA", true)
	if _, err := parseRerankingRoots(append(append([]byte(nil), caPEM...), caPEM...)); err == nil {
		t.Fatal("duplicate roots accepted")
	}
	clientCertPEM, clientKeyPEM := mountClientCertificatePEM(t)
	profile := testProfile()
	manifestBytes, err := json.Marshal(mountedManifest{
		Schema: rerankingManifestSchema, OrganizationID: "org_alpha",
		ProfileFile: rerankingProfileFilename, ProfileHash: profile.ProfileHash,
		RootCAFile: rerankingRootCAFilename, ClientCertificateFile: rerankingClientCertFile,
		ClientKeyFile: rerankingClientKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	writeOwnedRerankingFile(t, root, rerankingManifestFilename, manifestBytes)
	writeOwnedRerankingFile(t, root, rerankingProfileFilename, profileBytes)
	writeOwnedRerankingFile(t, root, rerankingRootCAFilename, caPEM)
	writeOwnedRerankingFile(t, root, rerankingClientCertFile, clientCertPEM)
	writeOwnedRerankingFile(t, root, rerankingClientKeyFile, clientKeyPEM)

	config, err := LoadMountedAt(root, "org_alpha")
	if err != nil {
		t.Fatalf("LoadMountedAt: %v", err)
	}
	if config.OrganizationID != "org_alpha" || config.Profile.ProfileHash != profile.ProfileHash ||
		config.TrustRoots == nil || len(config.TrustRoots.Subjects()) != 1 || config.ClientCertificate == nil {
		t.Fatalf("unexpected mounted config: %#v", config)
	}
	if _, err := LoadMountedAt(root, "other_org"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("cross-tenant mount accepted")
	}
	if err := os.Link(filepath.Join(root, rerankingProfileFilename), filepath.Join(root, "profile-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("hardlink profile accepted")
	}
	if err := os.Remove(filepath.Join(root, "profile-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, rerankingProfileFilename), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("writable profile accepted")
	}
	if err := os.Chmod(filepath.Join(root, rerankingProfileFilename), 0o440); err != nil {
		t.Fatal(err)
	}
	profile.ModelID = "drifted"
	drifted, _ := json.Marshal(profile)
	writeOwnedRerankingFile(t, root, rerankingProfileFilename, drifted)
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("profile drift accepted")
	}
	writeOwnedRerankingFile(t, root, rerankingProfileFilename, profileBytes)
	link := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(link, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("symlink root accepted")
	}

	if err := os.Remove(filepath.Join(root, rerankingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rerankingProfileFilename, filepath.Join(root, rerankingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatalf("symlink manifest code=%q, want %q", CodeOf(err), CodeMountInvalid)
	}
	if err := os.Remove(filepath.Join(root, rerankingManifestFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, rerankingManifestFilename), manifestBytes, 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatalf("permission-drifted root code=%q, want %q", CodeOf(err), CodeMountInvalid)
	}
}

func TestAbsentMountIsOptionalButIncompleteMountFailsClosed(t *testing.T) {
	root := t.TempDir()
	if _, err := LoadMountedAt(filepath.Join(root, "absent"), "org_alpha"); CodeOf(err) != CodeMountUnavailable {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 65532); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMountedAt(root, "org_alpha"); CodeOf(err) != CodeMountInvalid {
		t.Fatal("missing manifest treated as optional")
	}
}

func TestStableDescriptorReadRejectsFileAndOwnershipDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "profile.json")
	if err := os.WriteFile(path, []byte("initial"), 0o440); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	var initial syscall.Stat_t
	if err := syscall.Fstat(fd, &initial); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed and longer"), 0o440); err != nil {
		t.Fatal(err)
	}
	if raw, err := stableRerankingRead(fd, maximumProfileBytes, initial); raw != nil || CodeOf(err) != CodeMountInvalid {
		t.Fatal("descriptor drift admitted")
	}
	final := initial
	final.Gid++
	if sameRerankingSnapshot(initial, final) {
		t.Fatal("ownership drift ignored")
	}
	final = initial
	final.Ctim.Nsec++
	if sameRerankingSnapshot(initial, final) {
		t.Fatal("metadata drift ignored")
	}
}

func writeOwnedRerankingFile(t *testing.T, root, name string, contents []byte) {
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
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "knowvault-reranking-client"},
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
