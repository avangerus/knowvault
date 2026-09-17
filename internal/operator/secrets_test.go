package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
)

func validTestDatabaseURL(user string) []byte {
	return []byte("postgres://" + user + ":test-password@db.example:5432/knowvault?sslmode=verify-full")
}

func validTestClientSecret() []byte {
	return []byte("pre-issued-oidc-client-secret")
}

func TestGenerateSecretsRefusesOverwriteAndRejectsNonProductionURL(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	_, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: root, OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	// The full product-path verification (secretmount.LoadMounted) is
	// linux/root-only by design; this host may fail closed there. The failure
	// paths under test fire before any mount verification.
	if err != nil {
		if failure, ok := IsFailure(err); ok && failure.Code == FailureMountInvalid {
			// Generation refused before writing is only acceptable when the
			// verification platform cannot mount; the pre-verification paths
			// below still run against an empty root.
			os.RemoveAll(root)
			_ = os.MkdirAll(root, 0o700)
		} else {
			t.Fatalf("unexpected failure: %v", err)
		}
	}

	// An existing manifest is never overwritten.
	if err := os.WriteFile(filepath.Join(root, manifestFilename), []byte(`{}`), 0o400); err != nil {
		t.Fatal(err)
	}
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: root, OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("existing manifest: err=%v", err)
	}

	// A database URL outside the production contract is rejected before any
	// write: no sslmode, plain host, unsupported scheme, non-production path.
	for _, url := range [][]byte{
		[]byte("postgres://knowvault_app:test-password@db.example:5432/knowvault"),
		[]byte("postgresql://knowvault_app:test-password@db.example:5432/knowvault?sslmode=verify-full"),
		[]byte("postgres://knowvault_app:test-password@db.example/knowvault?sslmode=verify-full"),
		[]byte("postgres://knowvault_app:test-password@db.example:5432/knowvault_test?sslmode=verify-full"),
	} {
		clean := t.TempDir()
		_, err := GenerateSecrets(ctx, SecretManifestConfig{
			MountRoot: clean, OrganizationID: "org_001", ProviderID: "provider_001",
			DatabaseURL: url, ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
		})
		if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
			t.Fatalf("non-production URL %q: err=%v", url, err)
		}
	}
}

func TestGeneratedManifestWireShape(t *testing.T) {
	material := &generatedMaterial{}
	if err := material.generate(); err != nil {
		t.Fatal(err)
	}
	material.clientSecret = validTestClientSecret()
	root := t.TempDir()
	config := SecretManifestConfig{
		MountRoot: root, OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref",
	}
	if err := writeManifestFiles(root, config, material); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, manifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema", "organization_id", "provider_id", "database_url_file",
		"identity_hmac", "session_hmac", "source_digest_hmac", "oidc_transport_aead", "artifact_kek", "oidc_client_secrets"} {
		if _, exists := wire[field]; !exists {
			t.Fatalf("manifest is missing field %q", field)
		}
	}
	if wire["schema"] != manifestSchemaName {
		t.Fatalf("schema=%v", wire["schema"])
	}
	if wire["database_url_file"] != databaseURLFile {
		t.Fatalf("database_url_file=%v", wire["database_url_file"])
	}
	// Generated key material is independent across the five capabilities and
	// every key file carries exactly the raw-url-encoded 32-byte form.
	seen := map[string]bool{}
	for _, filename := range []string{identityKeyFile, sessionKeyFile, sourceDigestFile, transportKeyFile, artifactWrapFile} {
		contents, err := os.ReadFile(filepath.Join(root, filename))
		if err != nil {
			t.Fatal(err)
		}
		if len(contents) != 43 { // base64.RawURLEncoding of 32 bytes
			t.Fatalf("%s carries %d bytes", filename, len(contents))
		}
		if seen[string(contents)] {
			t.Fatalf("key material duplicated in %s", filename)
		}
		seen[string(contents)] = true
	}
	clients := wire["oidc_client_secrets"].([]any)
	if len(clients) != 1 {
		t.Fatalf("client entries=%d", len(clients))
	}
	client := clients[0].(map[string]any)
	if client["reference"] != "client_ref" || client["provider_revision"] != float64(1) {
		t.Fatalf("client entry=%v", client)
	}
	// The atomic publish leaves no temporary files behind after success: the
	// mount contains exactly the fixed file set, nothing inert or partial.
	leftovers, err := filepath.Glob(filepath.Join(root, ".*.tmp*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestGenerateSecretsRequiresImportedClientSecret(t *testing.T) {
	_, err := GenerateSecrets(context.Background(), SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref",
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMountInvalid {
		t.Fatalf("missing imported client secret: err=%v", err)
	}
}

func TestSecretManifestConfigFormattingRedactsImportedSecret(t *testing.T) {
	canary := "oidc-config-format-canary"
	config := SecretManifestConfig{ClientSecret: []byte(canary), DatabaseURL: []byte(canary)}
	for _, formatted := range []string{
		fmt.Sprintf("%v", config), fmt.Sprintf("%#v", config), fmt.Sprintf("%+v", config),
		fmt.Sprintf("%v", &config), fmt.Sprintf("%#v", &config), fmt.Sprintf("%+v", &config),
	} {
		if strings.Contains(formatted, canary) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("secret manifest formatting leaked material: %q", formatted)
		}
	}
	material := generatedMaterial{clientSecret: []byte(canary)}
	for _, formatted := range []string{fmt.Sprintf("%#v", material), fmt.Sprintf("%#v", &material)} {
		if strings.Contains(formatted, canary) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("generated material formatting leaked material: %q", formatted)
		}
	}
}

func TestFailureMarshalConformsToClosedContract(t *testing.T) {
	for _, failure := range []*Failure{
		DependencyUnavailable("db down"),
		MountInvalid("manifest unreadable"),
		MigrationIncompatible("checksum mismatch"),
	} {
		raw := failure.Marshal()
		var wire map[string]any
		if err := json.Unmarshal(raw, &wire); err != nil {
			t.Fatal(err)
		}
		if len(wire) != 6 {
			t.Fatalf("wire record has %d fields: %s", len(wire), raw)
		}
		if wire["schema_version"] != "operator-failure-v1" || wire["fallback_allowed"] != false {
			t.Fatalf("wire record=%s", raw)
		}
		if _, hasDetail := wire["detail"]; hasDetail {
			t.Fatalf("wire record leaks detail: %s", raw)
		}
	}
	// The code-to-action and code-to-metric bindings are fixed.
	down := DependencyUnavailable("x")
	if down.Action != "RETRY_AFTER_DEPENDENCY_RECOVERY" || down.MetricName != "operator_dependency_failures_total" || !down.Retryable {
		t.Fatalf("dependency mapping: %+v", down)
	}
	mount := MountInvalid("x")
	if mount.Action != "FIX_MOUNT_AND_RESTART" || mount.MetricName != "operator_mount_failures_total" || mount.Retryable {
		t.Fatalf("mount mapping: %+v", mount)
	}
	migration := MigrationIncompatible("x")
	if migration.Action != "ROLL_BACK_OR_RUN_COMPATIBLE_MIGRATION" || migration.MetricName != "operator_migration_failures_total" || migration.Retryable {
		t.Fatalf("migration mapping: %+v", migration)
	}
}

func TestGenerateSecretsRejectsOpenRotationWindowInputs(t *testing.T) {
	// The portable surface pins the config validation independent of the
	// linux-only mount loader: empty mount root and bad client references are
	// rejected before any file is touched.
	ctx := context.Background()
	_, err := GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: "", OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("empty root: err=%v", err)
	}
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: "org_001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: " badref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("untrimmed reference: err=%v", err)
	}
	// Organization and provider identifiers follow the same opaque-id shape as
	// the client reference and are validated before any write.
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: "org\tbad", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("non-opaque organization: err=%v", err)
	}
	// The shared manifest-id shape is strict in both directions: '+' would be
	// a valid database path segment but is rejected as mount material (it
	// could not be mapped to a product file path), and an identifier that
	// only the audit shape accepts (up to 256 characters) is refused long
	// before any file is touched.
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: "org+001", ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("path-hostile organization: err=%v", err)
	}
	_, err = GenerateSecrets(ctx, SecretManifestConfig{
		MountRoot: t.TempDir(), OrganizationID: identity.OrganizationID(strings.Repeat("o", 200)), ProviderID: "provider_001",
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	})
	if failure, ok := IsFailure(err); !ok || failure.Code != FailureMigrationIncompatible {
		t.Fatalf("audit-shaped-only organization: err=%v", err)
	}
}
