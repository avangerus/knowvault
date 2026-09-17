//go:build linux

package trustbundle

import (
	"crypto/sha256"
	"testing"
)

func TestLoadSourceMountedAtUsesOnlyPurposeSpecificFiles(t *testing.T) {
	root := newRootFixture(t)
	gitPEM := newCertificatePEM(t, 41, true, nil)
	mailPEM := newCertificatePEM(t, 42, true, nil)
	databasePEM := newCertificatePEM(t, 43, true, nil)
	writeTrustFile(t, root, gitBundleFilename, gitPEM, 0o440)
	writeTrustFile(t, root, mailBundleFilename, mailPEM, 0o440)
	writeTrustFile(t, root, sourceDatabaseBundleFilename, databasePEM, 0o440)
	source, err := LoadSourceMountedAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := source.GitFingerprint(); err != nil || got != sha256.Sum256(gitPEM) {
		t.Fatalf("git fingerprint=%x err=%v", got, err)
	}
	if got, err := source.MailFingerprint(); err != nil || got != sha256.Sum256(mailPEM) {
		t.Fatalf("mail fingerprint=%x err=%v", got, err)
	}
	if got, err := source.DatabaseFingerprint(); err != nil || got != sha256.Sum256(databasePEM) {
		t.Fatalf("database fingerprint=%x err=%v", got, err)
	}
	if _, err := source.GitRoots(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.MailRoots(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.DatabaseRoots(); err != nil {
		t.Fatal(err)
	}
}
