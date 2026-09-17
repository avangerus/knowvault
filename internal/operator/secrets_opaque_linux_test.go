//go:build linux

package operator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

func TestGenerateSecretsKeysFromPreservesOpaqueProductSecret(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	primary := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: primary, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	}); err != nil {
		t.Fatal(err)
	}
	// Product client secrets are opaque bounded printable mount text; they are
	// not required to be base64. Replace the imported value with a valid
	// non-base64 value before exercising the trusted-source reuse path.
	opaque := []byte("short")
	if err := os.WriteFile(filepath.Join(primary, clientSecretFile), opaque, 0); err != nil {
		t.Fatal(err)
	}
	worker := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: worker, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref", ClientSecret: opaque,
		KeysFromRoot: primary,
	}); err != nil {
		t.Fatal(err)
	}
	source, err := secretmount.LoadMounted(primary, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := secretmount.LoadMounted(worker, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	sourceSecret, err := source.Resolve(ctx, clientSecretRequest("client_ref"))
	if err != nil {
		t.Fatal(err)
	}
	destinationSecret, err := destination.Resolve(ctx, clientSecretRequest("client_ref"))
	if err != nil {
		t.Fatal(err)
	}
	if sourceSecret != string(opaque) || destinationSecret != sourceSecret || !bytes.Equal([]byte(destinationSecret), opaque) {
		t.Fatalf("opaque client secret changed during reuse")
	}
}

func TestGenerateSecretsKeysFromRejectsInvalidProductSecret(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	primary := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: primary, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(primary, clientSecretFile), []byte("invalid\nsecret"), 0); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: destination, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		KeysFromRoot: primary,
	}); err == nil {
		t.Fatal("invalid product-contract client secret accepted")
	}
	if _, err := os.Stat(filepath.Join(destination, manifestFilename)); !os.IsNotExist(err) {
		t.Fatalf("destination was written after invalid source: %v", err)
	}
}
