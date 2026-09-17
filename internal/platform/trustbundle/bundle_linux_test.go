//go:build linux

package trustbundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const trustGroupID = 65532

func TestLoadMountedReturnsPurposeSeparatedImmutableBundle(t *testing.T) {
	root := newRootFixture(t)
	databasePEM := newCertificatePEM(t, 1, true, nil)
	oidcPEM := newCertificatePEM(t, 2, true, nil)
	writeTrustBundles(t, root, databasePEM, oidcPEM)
	bundle, err := loadMounted(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := bundle.DatabaseFingerprint(); err != nil || got != sha256.Sum256(databasePEM) {
		t.Fatalf("database fingerprint=%x err=%v", got, err)
	}
	if got, err := bundle.OIDCFingerprint(); err != nil || got != sha256.Sum256(oidcPEM) {
		t.Fatalf("OIDC fingerprint=%x err=%v", got, err)
	}

	copyOfBundle := bundle
	databaseRoots, err := copyOfBundle.DatabaseRoots()
	if err != nil {
		t.Fatal(err)
	}
	oidcRoots, err := copyOfBundle.OIDCRoots()
	if err != nil {
		t.Fatal(err)
	}
	databasePool, err := databaseRoots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	oidcPool, err := oidcRoots.NewCertPool()
	if err != nil {
		t.Fatal(err)
	}
	if len(databasePool.Subjects()) != 1 || len(oidcPool.Subjects()) != 1 || bytes.Equal(databasePool.Subjects()[0], oidcPool.Subjects()[0]) {
		t.Fatal("purpose roots were not loaded independently")
	}
	extra, err := x509.ParseCertificate(decodeOneCertificate(t, newCertificatePEM(t, 3, true, nil)))
	if err != nil {
		t.Fatal(err)
	}
	databasePool.AddCert(extra)
	databaseAgain, _ := databaseRoots.NewCertPool()
	oidcAgain, _ := oidcRoots.NewCertPool()
	if len(databasePool.Subjects()) != 2 || len(databaseAgain.Subjects()) != 1 || len(oidcAgain.Subjects()) != 1 {
		t.Fatal("pool clone isolation failed")
	}
	for _, formatted := range []string{fmt.Sprintf("%v", bundle), fmt.Sprintf("%+v", bundle), fmt.Sprintf("%#v", bundle), fmt.Sprintf("%v", &bundle), fmt.Sprintf("%+v", &bundle), fmt.Sprintf("%#v", &bundle)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, "CERTIFICATE") {
			t.Fatalf("unsafe formatting %q", formatted)
		}
	}
}

func TestLoadMountedAtUsesOnlyExplicitRoot(t *testing.T) {
	root := newRootFixture(t)
	valid := newCertificatePEM(t, 12, true, nil)
	writeTrustBundles(t, root, valid, valid)
	if bundle, err := LoadMountedAt(root); err != nil || bundle.state == nil {
		t.Fatalf("explicit bundle=%#v err=%v", bundle, err)
	}
	if bundle, err := LoadMountedAt(filepath.Join(root, "missing")); bundle.state != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("missing explicit root bundle=%#v err=%v", bundle, err)
	}
}

func TestPurposeRootsDeepCopyDERAndNeverExposeRetainedMaterial(t *testing.T) {
	raw := newCertificatePEM(t, 30, true, nil)
	databaseRoots, err := NewDatabaseRootsPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	oidcRoots, err := NewOIDCRootsPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		raw[index] ^= 0xff
	}
	databasePool, err := databaseRoots.NewCertPool()
	if err != nil || len(databasePool.Subjects()) != 1 {
		t.Fatalf("database pool subjects=%d err=%v", len(databasePool.Subjects()), err)
	}
	oidcPool, err := oidcRoots.NewCertPool()
	if err != nil || len(oidcPool.Subjects()) != 1 {
		t.Fatalf("OIDC pool subjects=%d err=%v", len(oidcPool.Subjects()), err)
	}

	parsed, err := parseStrictPEM(newCertificatePEM(t, 31, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	retained := DatabaseRoots{database: &databaseRootsState{roots: newRootSetState(parsed)}}
	for index := range parsed[0] {
		parsed[0][index] ^= 0xff
	}
	if pool, err := retained.NewCertPool(); err != nil || len(pool.Subjects()) != 1 {
		t.Fatalf("retained DER mutation affected roots: pool=%v err=%v", pool, err)
	}
}

func TestLoadMountedAcceptsSameEnterpriseIntermediateForBothPurposes(t *testing.T) {
	root := newRootFixture(t)
	intermediate := newCertificatePEM(t, 4, true, nil)
	writeTrustBundles(t, root, intermediate, intermediate)
	if _, err := loadMounted(root); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMountedRequiresBothPurposeBundles(t *testing.T) {
	valid := newCertificatePEM(t, 5, true, nil)
	for _, present := range []string{databaseBundleFilename, oidcBundleFilename} {
		t.Run(present, func(t *testing.T) {
			root := newRootFixture(t)
			writeTrustFile(t, root, present, valid, 0o440)
			if bundle, err := loadMounted(root); bundle.state != nil || CodeOf(err) != CodeUnavailable {
				t.Fatalf("bundle=%#v err=%v", bundle, err)
			}
		})
	}
}

func TestLoadMountedRejectsUnsafeFilesystemObjects(t *testing.T) {
	valid := newCertificatePEM(t, 6, true, nil)
	tests := map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, root string) {
			target := filepath.Join(root, "target.pem")
			writeRawFile(t, target, valid, 0o440)
			if err := os.Symlink(target, filepath.Join(root, databaseBundleFilename)); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, root string) {
			if err := syscall.Mkfifo(filepath.Join(root, databaseBundleFilename), 0o440); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(filepath.Join(root, databaseBundleFilename), 0, trustGroupID); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, root string) {
			target := filepath.Join(root, "target.pem")
			writeRawFile(t, target, valid, 0o440)
			if err := os.Link(target, filepath.Join(root, databaseBundleFilename)); err != nil {
				t.Fatal(err)
			}
		},
		"wrong mode": func(t *testing.T, root string) { writeTrustFile(t, root, databaseBundleFilename, valid, 0o444) },
		"oversize": func(t *testing.T, root string) {
			writeTrustFile(t, root, databaseBundleFilename, bytes.Repeat([]byte{'x'}, maximumBundleBytes+1), 0o440)
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			root := newRootFixture(t)
			writeTrustFile(t, root, oidcBundleFilename, valid, 0o440)
			setup(t, root)
			if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
				t.Fatalf("bundle=%#v err=%v", bundle, err)
			}
		})
	}
	t.Run("symlink root", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		link := filepath.Join(t.TempDir(), "trust-link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(link); bundle.state != nil || CodeOf(err) != CodeUnavailable {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
}

func TestLoadMountedRejectsWrongOwnershipAndRootMode(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership boundary requires root")
	}
	valid := newCertificatePEM(t, 7, true, nil)
	t.Run("root owner", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		if err := os.Chown(root, 1, trustGroupID); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
	t.Run("root group", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		if err := os.Chown(root, 0, 1); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
	t.Run("root mode", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
	t.Run("file owner", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		if err := os.Chown(filepath.Join(root, databaseBundleFilename), 1, trustGroupID); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
	t.Run("file group", func(t *testing.T) {
		root := newRootFixture(t)
		writeTrustBundles(t, root, valid, valid)
		if err := os.Chown(filepath.Join(root, databaseBundleFilename), 0, 1); err != nil {
			t.Fatal(err)
		}
		if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
			t.Fatalf("bundle=%#v err=%v", bundle, err)
		}
	})
}

func TestLoadMountedRejectsMalformedOrUnsafeCertificates(t *testing.T) {
	valid := newCertificatePEM(t, 8, true, nil)
	leaf := newCertificatePEM(t, 9, false, nil)
	noCertSign := newCertificatePEMWithUsage(t, 10, true, x509.KeyUsageDigitalSignature, nil)
	unknownCritical := newCertificatePEM(t, 11, true, []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}})
	nonCertificate := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: decodeOneCertificate(t, valid)})
	tests := map[string][]byte{
		"empty": {}, "malformed": []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), "non certificate": nonCertificate,
		"leaf": leaf, "missing cert sign usage": noCertSign, "unknown critical extension": unknownCritical,
		"duplicate": append(append([]byte(nil), valid...), valid...), "leading garbage": append([]byte("garbage\n"), valid...),
		"trailing garbage": append(append([]byte(nil), valid...), []byte("garbage")...), "headers": withHeaders,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			root := newRootFixture(t)
			writeTrustBundles(t, root, raw, valid)
			if bundle, err := loadMounted(root); bundle.state != nil || err == nil {
				t.Fatalf("bundle=%#v err=%v", bundle, err)
			}
		})
	}
}

func TestStrictPEMRejectsMoreThanMaximumCertificates(t *testing.T) {
	var raw []byte
	for serial := int64(1); serial <= maximumCertificates+1; serial++ {
		raw = append(raw, newCertificatePEM(t, 20_000+serial, true, nil)...)
	}
	if pool, err := parseStrictPEM(raw); pool != nil || CodeOf(err) != CodeInvalid {
		t.Fatalf("pool=%v err=%v", pool, err)
	}
}

func TestZeroBundleFailsClosed(t *testing.T) {
	var bundle Bundle
	if roots, err := bundle.DatabaseRoots(); roots.database != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	if roots, err := bundle.OIDCRoots(); roots.oidc != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	if pool, err := (DatabaseRoots{}).NewCertPool(); pool != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("database pool=%v err=%v", pool, err)
	}
	if pool, err := (OIDCRoots{}).NewCertPool(); pool != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("OIDC pool=%v err=%v", pool, err)
	}
	if fingerprint, err := bundle.DatabaseFingerprint(); fingerprint != ([sha256.Size]byte{}) || CodeOf(err) != CodeUnavailable {
		t.Fatalf("fingerprint=%x err=%v", fingerprint, err)
	}
	if fingerprint, err := bundle.OIDCFingerprint(); fingerprint != ([sha256.Size]byte{}) || CodeOf(err) != CodeUnavailable {
		t.Fatalf("fingerprint=%x err=%v", fingerprint, err)
	}
}

func newRootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact production ownership requires root")
	}
	root := t.TempDir()
	if err := os.Chown(root, 0, trustGroupID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeTrustBundles(t *testing.T, root string, database, oidc []byte) {
	t.Helper()
	writeTrustFile(t, root, databaseBundleFilename, database, 0o440)
	writeTrustFile(t, root, oidcBundleFilename, oidc, 0o440)
}

func writeTrustFile(t *testing.T, root, filename string, raw []byte, mode os.FileMode) {
	t.Helper()
	writeRawFile(t, filepath.Join(root, filename), raw, mode)
}

func writeRawFile(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, trustGroupID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func newCertificatePEM(t *testing.T, serial int64, isCA bool, extensions []pkix.Extension) []byte {
	t.Helper()
	usage := x509.KeyUsageDigitalSignature
	if isCA {
		usage |= x509.KeyUsageCertSign
	}
	return newCertificatePEMWithUsage(t, serial, isCA, usage, extensions)
}

func newCertificatePEMWithUsage(t *testing.T, serial int64, isCA bool, usage x509.KeyUsage, extensions []pkix.Extension) []byte {
	t.Helper()
	parentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parent := &x509.Certificate{SerialNumber: big.NewInt(100000 + serial), Subject: pkix.Name{CommonName: "offline-enterprise-parent"}, NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_100_000_000, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: fmt.Sprintf("enterprise-anchor-%d", serial)}, NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0), BasicConstraintsValid: true, IsCA: isCA, KeyUsage: usage, ExtraExtensions: extensions}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func decodeOneCertificate(t *testing.T, raw []byte) []byte {
	t.Helper()
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("invalid fixture")
	}
	return block.Bytes
}
