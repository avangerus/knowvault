package operator

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountedClientSecretRejectsMalformedProductContractValues(t *testing.T) {
	for name, encoded := range map[string]string{
		"empty":        "",
		"control":      "bad\nsecret",
		"invalid utf8": string([]byte{0xff, 0xfe}),
		"oversize":     strings.Repeat("x", 4<<10+1),
	} {
		t.Run(name, func(t *testing.T) {
			if validMountedClientSecret([]byte(encoded)) {
				t.Fatalf("malformed client secret accepted: length=%d", len(encoded))
			}
		})
	}
}

func TestMountedClientSecretAcceptsBoundedOpaquePrintableUTF8(t *testing.T) {
	for name, value := range map[string]string{
		"short":    "short",
		"unicode":  "\u0441\u0435\u043a\u0440\u0435\u0442",
		"max-size": strings.Repeat("x", 4<<10),
	} {
		t.Run(name, func(t *testing.T) {
			if !validMountedClientSecret([]byte(value)) {
				t.Fatalf("valid opaque client secret rejected: length=%d", len(value))
			}
		})
	}
}

func TestWriteManifestFilesClientSecretPreservesOpaqueRepresentation(t *testing.T) {
	material := &generatedMaterial{
		identity:        bytes.Repeat([]byte{0x01}, keyMaterialBytes),
		identityRef:     "identity_hmac_v1",
		identityVer:     1,
		session:         bytes.Repeat([]byte{0x02}, keyMaterialBytes),
		sessionRef:      "session_hmac_v1",
		sessionVer:      1,
		sourceDigest:    bytes.Repeat([]byte{0x03}, keyMaterialBytes),
		sourceDigestRef: "source_digest_hmac_v1",
		sourceDigestVer: 1,
		transport:       bytes.Repeat([]byte{0x04}, keyMaterialBytes),
		transportRef:    "transport_aead_v1",
		transportKeyID:  "transport_key_v1",
		artifactWrap:    bytes.Repeat([]byte{0x05}, keyMaterialBytes),
		artifactWrapRef: "artifact_kek_v1",
		artifactWrapVer: 1,
		clientSecret:    []byte("opaque-secret-not-base64"),
	}
	root := t.TempDir()
	config := SecretManifestConfig{
		MountRoot: root, OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL:     []byte("postgres://user:password@db.example:5432/knowvault?sslmode=verify-full"),
		ClientReference: "client_ref",
	}
	if err := writeManifestFiles(root, config, material); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(root, clientSecretFile))
	if err != nil {
		t.Fatal(err)
	}
	want := string(material.clientSecret)
	if string(encoded) != want {
		t.Fatalf("client secret representation changed: got length %d want length %d", len(encoded), len(want))
	}
	if !bytes.Equal(encoded, material.clientSecret) {
		t.Fatalf("client secret does not round-trip byte-for-byte")
	}
}
