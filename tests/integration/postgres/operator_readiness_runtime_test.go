//go:build linux

package postgres_test

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/operator"
)

// TestOperatorReadinessGreenWithGeneratedRuntimeMounts is enabled only by a
// TLS-enabled PostgreSQL acceptance environment. The environment supplies the
// same real database endpoint and purpose-separated trust mount used by the
// test service; the two secret mounts themselves are generated through the
// operator, then readiness must open both DatabaseURL capabilities as their
// exact runtime roles.
//
// The default pinned integration PostgreSQL service intentionally has SSL off,
// so this test skips there rather than weakening the production verify-full
// contract or substituting a mock connection.
func TestOperatorReadinessGreenWithGeneratedRuntimeMounts(t *testing.T) {
	tlsURL := os.Getenv("KNOWVAULT_TEST_POSTGRES_TLS_URL")
	trustRoot := os.Getenv("KNOWVAULT_TEST_TRUST_MOUNT")
	if tlsURL == "" || trustRoot == "" {
		t.Skip("TLS acceptance endpoint and trust mount are not configured")
	}
	parsed, err := url.Parse(tlsURL)
	if err != nil || parsed.User == nil {
		t.Fatalf("invalid TLS acceptance URL")
	}

	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_rdy_tls", "usr_rdy_tls", "ws_rdy_tls")
	if _, err := operator.RegisterProvider(ctx, admin, operator.ProviderRegistration{
		OrganizationID: "org_rdy_tls", ProviderID: "provider_rdy_tls",
		IssuerURL: "https://idp.example/auth", ClientID: "client_rdy_tls",
		ClientSecretReference: "secret_rdy_tls", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_rdy_tls",
	}); err != nil {
		t.Fatalf("RegisterProvider: %v", err)
	}

	serverURL := *parsed
	serverURL.User = url.UserPassword(operator.RoleApplication, appPassword)
	workerURL := *parsed
	workerURL.User = url.UserPassword(operator.RoleWorker, workerPassword)
	serverRoot := filepath.Join(t.TempDir(), "server")
	workerRoot := filepath.Join(t.TempDir(), "worker")
	clientSecret := []byte("runtime-readiness-client-secret")
	if _, err := operator.GenerateSecrets(ctx, operator.SecretManifestConfig{
		MountRoot: serverRoot, OrganizationID: identity.OrganizationID("org_rdy_tls"),
		ProviderID: identity.ProviderID("provider_rdy_tls"), DatabaseURL: []byte(serverURL.String()),
		ClientReference: "secret_rdy_tls", ClientSecret: clientSecret,
	}); err != nil {
		t.Fatalf("generate server mount: %v", err)
	}
	if _, err := operator.GenerateSecrets(ctx, operator.SecretManifestConfig{
		MountRoot: workerRoot, OrganizationID: identity.OrganizationID("org_rdy_tls"),
		Consumer:   "worker",
		ProviderID: identity.ProviderID("provider_rdy_tls"), DatabaseURL: []byte(workerURL.String()),
		ClientReference: "secret_rdy_tls", ClientSecret: clientSecret, KeysFromRoot: serverRoot,
	}); err != nil {
		t.Fatalf("generate worker mount: %v", err)
	}

	report, err := operator.Readiness(ctx, operator.ReadinessConfig{
		AdminURL: tlsURL, ServerMountRoot: serverRoot, WorkerMountRoot: workerRoot,
		TrustMountRoot: trustRoot, OrganizationID: identity.OrganizationID("org_rdy_tls"),
		ProviderID: identity.ProviderID("provider_rdy_tls"), MigrationsDir: operatorMigrationsDir(t),
	})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if !report.Readiness {
		failure := report.FirstFailure()
		t.Fatalf("readiness is red: %v", failure)
	}
	for _, dependency := range report.Dependencies {
		if dependency.Status != operator.StatusReady {
			t.Fatalf("dependency %s=%s, want READY", dependency.Name, dependency.Status)
		}
	}
}
