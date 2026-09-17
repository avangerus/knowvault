//go:build linux

package operator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

const (
	testOrganizationID = identity.OrganizationID("org_001")
	testProviderID     = identity.ProviderID("provider_001")
)

func clientSecretRequest(reference string) oidcweb.ClientSecretRequest {
	return oidcweb.ClientSecretRequest{
		OrganizationID: testOrganizationID, ProviderID: testProviderID,
		ProviderRevision: clientRevision, Reference: reference,
	}
}

// capabilityBytes loads one mount capability and returns its material as
// copied bytes. The five purpose-specific capability types share a Bytes()
// method but are deliberately non-convertible to each other.
func capabilityBytes[K interface{ Bytes() []byte }](t *testing.T, load func() (K, error)) []byte {
	t.Helper()
	key, err := load()
	if err != nil {
		t.Fatal(err)
	}
	return key.Bytes()
}

func TestGenerateSecretsLoadsThroughProductPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	root := t.TempDir()
	result, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: root, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 8 {
		t.Fatalf("generated files=%d", len(result.Files))
	}
	provider, err := secretmount.LoadMounted(root, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	databaseURL, err := provider.DatabaseURL()
	if err != nil || databaseURL != string(validTestDatabaseURL("knowvault_app")) {
		t.Fatalf("database URL=%q err=%v", databaseURL, err)
	}
	secret, err := provider.Resolve(ctx, clientSecretRequest("client_ref"))
	if err != nil || secret != string(validTestClientSecret()) {
		t.Fatalf("client secret changed: got length=%d err=%v", len(secret), err)
	}
}

func TestGenerateSecretsMountsAndCopiesSourceCredentials(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	primary := t.TempDir()
	source := []byte("postgres://reader:password@db.example:5432/knowvault?sslmode=verify-full")
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: primary, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		SourceCredentials: []SourceCredential{{Reference: "cred_pg_001", Secret: source}},
	}); err != nil {
		t.Fatal(err)
	}
	primaryMount, err := secretmount.LoadMounted(primary, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer primaryMount.Close()
	resolved, err := primaryMount.ResolveReference(ctx, "cred_pg_001")
	if err != nil || resolved != string(source) {
		t.Fatalf("source credential=%q err=%v", resolved, err)
	}
	worker := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: worker, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		KeysFromRoot: primary,
	}); err != nil {
		t.Fatal(err)
	}
	workerMount, err := secretmount.LoadMounted(worker, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer workerMount.Close()
	workerResolved, err := workerMount.ResolveReference(ctx, "cred_pg_001")
	if err != nil || workerResolved != string(source) {
		t.Fatalf("worker source credential=%q err=%v", workerResolved, err)
	}
}

func TestGenerateSecretsKeysFromReusesExactKeySet(t *testing.T) {
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
	worker := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: worker, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		KeysFromRoot: primary,
	}); err != nil {
		t.Fatal(err)
	}
	serverMount, err := secretmount.LoadMounted(primary, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer serverMount.Close()
	workerMount, err := secretmount.LoadMounted(worker, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer workerMount.Close()
	serverURL, err := serverMount.DatabaseURL()
	if err != nil || serverURL != string(validTestDatabaseURL("knowvault_app")) {
		t.Fatalf("server URL=%q err=%v", serverURL, err)
	}
	workerURL, err := workerMount.DatabaseURL()
	if err != nil || workerURL != string(validTestDatabaseURL("knowvault_worker")) {
		t.Fatalf("worker URL=%q err=%v", workerURL, err)
	}
	pairs := []struct {
		name string
		a, b []byte
	}{
		{"identity", capabilityBytes(t, serverMount.IdentityKey), capabilityBytes(t, workerMount.IdentityKey)},
		{"session", capabilityBytes(t, serverMount.SessionKey), capabilityBytes(t, workerMount.SessionKey)},
		{"source digest", capabilityBytes(t, serverMount.SourceDigestKey), capabilityBytes(t, workerMount.SourceDigestKey)},
		{"transport", capabilityBytes(t, serverMount.OIDCTransportKey), capabilityBytes(t, workerMount.OIDCTransportKey)},
		{"artifact wrap", capabilityBytes(t, serverMount.ArtifactWrapKey), capabilityBytes(t, workerMount.ArtifactWrapKey)},
	}
	for _, pair := range pairs {
		if !bytes.Equal(pair.a, pair.b) {
			t.Fatalf("%s key material diverged between mounts", pair.name)
		}
	}
	serverIdentity, err := serverMount.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	workerIdentity, err := workerMount.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	if serverIdentity.Reference() != workerIdentity.Reference() || serverIdentity.Version() != workerIdentity.Version() {
		t.Fatal("references/versions diverged between mounts")
	}
	serverSecret, err := serverMount.Resolve(ctx, clientSecretRequest("client_ref"))
	if err != nil {
		t.Fatal(err)
	}
	workerSecret, err := workerMount.Resolve(ctx, clientSecretRequest("client_ref"))
	if err != nil || serverSecret != workerSecret {
		t.Fatal("client secret diverged between mounts")
	}
}

func TestGenerateSecretsKeysFromRejectsImportedClientSecretMismatch(t *testing.T) {
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
	_, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref",
		ClientSecret: []byte("different-imported-secret"), KeysFromRoot: primary,
	})
	failure, ok := IsFailure(err)
	if !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("mismatched imported client secret error=%v, want MOUNT_INVALID", err)
	}
}

func TestVerifyMountRedsOnMissingKeyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	root := t.TempDir()
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: root, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyMount(ctx, root, testOrganizationID, testProviderID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, identityKeyFile)); err != nil {
		t.Fatal(err)
	}
	err := VerifyMount(ctx, root, testOrganizationID, testProviderID)
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("missing key file: err=%v", err)
	}
}

func TestGenerateSecretsWithKeysFromRequiresVerifiedSource(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	_, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_worker"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		KeysFromRoot: t.TempDir(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("unverifiable source mount: err=%v", err)
	}
}

func TestGenerateSecretsRefusesSymlinkBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounted-root ownership boundary requires root test container")
	}
	ctx := context.Background()
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// A symlinked mount root is refused before any write.
	_, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: link, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("symlink mount root: err=%v", err)
	}
	// A symlinked parent cannot be redirected either.
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: filepath.Join(link, "child"), OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("symlink mount parent: err=%v", err)
	}
	// A not-yet-existing root inside the verified parent is created by the
	// operator itself and passes the boundary.
	fresh := filepath.Join(parent, "fresh")
	if _, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: fresh, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	}); err != nil {
		t.Fatalf("fresh mount root: %v", err)
	}
}
