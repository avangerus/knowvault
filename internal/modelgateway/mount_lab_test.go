package modelgateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestTrustBundle writes a freshly generated, self-signed CA certificate
// in PEM form to filename inside dir, for tests that need a real, parseable
// trust bundle file (GEN-2 external-runtime TLS trust).
func writeTestTrustBundle(t *testing.T, dir, filename string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "modelgateway-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, filename), pemBytes, 0o600); err != nil {
		t.Fatalf("write test trust bundle: %v", err)
	}
}

func TestLoadLabMountedConfigAbsentIsUnavailable(t *testing.T) {
	_, err := LoadLabMountedConfigAt(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil || CodeOf(err) != CodeLabMountUnavailable {
		t.Fatalf("expected CodeLabMountUnavailable, got %v", err)
	}
}

func TestLoadLabMountedConfigRequiresAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":5,"max_output_tokens":128,"insecure_lab_mode":false}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid without insecure_lab_mode, got %v", err)
	}
}

func TestLoadLabMountedConfigRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":5,"max_output_tokens":128,"insecure_lab_mode":true,"unexpected":1}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid for an unknown field, got %v", err)
	}
}

func TestLoadLabMountedConfigValid(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":5,"max_output_tokens":128,"thinking_mode":"disabled","insecure_lab_mode":true}`)
	config, err := LoadLabMountedConfigAt(dir)
	if err != nil {
		t.Fatalf("LoadLabMountedConfigAt: %v", err)
	}
	if config.ModelID != "m" || !config.InsecureLabMode || config.Timeout.Seconds() != 5 || config.ThinkingMode != ThinkingModeDisabled {
		t.Fatalf("unexpected config: %+v", config)
	}
	if _, err := NewLabAdapter(config); err != nil {
		t.Fatalf("mounted config should build a valid adapter: %v", err)
	}
}

func TestLoadLabMountedConfigBoundsLongToolAttempt(t *testing.T) {
	for _, test := range []struct {
		seconds int64
		allowed bool
	}{{240, true}, {241, false}, {-1, false}, {9223372036854775807, false}} {
		t.Run(fmt.Sprint(test.seconds), func(t *testing.T) {
			dir := t.TempDir()
			writeLabConfig(t, dir, fmt.Sprintf(`{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":%d,"max_output_tokens":128,"thinking_mode":"disabled","insecure_lab_mode":true}`, test.seconds))
			config, err := LoadLabMountedConfigAt(dir)
			if !test.allowed {
				if err == nil || CodeOf(err) != CodeLabMountInvalid {
					t.Fatalf("out-of-range timeout accepted: %v", err)
				}
				return
			}
			if err != nil || config.Timeout != 240*time.Second {
				t.Fatalf("bounded tool attempt unavailable: timeout=%s err=%v", config.Timeout, err)
			}
			adapter, err := NewLabAdapter(config)
			if err != nil {
				t.Fatalf("bounded adapter unavailable: %v", err)
			}
			defer adapter.Close()
		})
	}
}

func TestLoadLabMountedConfigReadsAPIKeyFromSeparateFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api-key"), []byte("sk-test-secret\n"), 0o600); err != nil {
		t.Fatalf("write api key file: %v", err)
	}
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","api_key_file":"api-key","timeout_seconds":5,"max_output_tokens":128,"thinking_mode":"disabled","insecure_lab_mode":true}`)
	config, err := LoadLabMountedConfigAt(dir)
	if err != nil {
		t.Fatalf("LoadLabMountedConfigAt: %v", err)
	}
	if config.APIKey != "sk-test-secret" {
		t.Fatalf("expected api key trimmed from separate file, got %q", config.APIKey)
	}
}

func TestLoadLabMountedConfigRejectsAPIKeyFileTraversal(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","api_key_file":"../escape","timeout_seconds":5,"max_output_tokens":128,"thinking_mode":"disabled","insecure_lab_mode":true}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid for path traversal in api_key_file, got %v", err)
	}
}

func TestLoadLabMountedConfigExternalWorkspaceScoped(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api-key"), []byte("sk-live"), 0o600); err != nil {
		t.Fatalf("write api key file: %v", err)
	}
	writeTestTrustBundle(t, dir, "trust-bundle.pem")
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"https://api.deepseek.com/v1","model_id":"deepseek-v4-flash","api_key_file":"api-key","trust_bundle_file":"trust-bundle.pem","timeout_seconds":30,"max_output_tokens":1024,"thinking_mode":"disabled","insecure_lab_mode":true,"external_runtime_workspace_ids":["tko-operations"]}`)
	config, err := LoadLabMountedConfigAt(dir)
	if err != nil {
		t.Fatalf("LoadLabMountedConfigAt: %v", err)
	}
	if config.RuntimeScope() != RuntimeScopeExternalWorkspaceScoped {
		t.Fatalf("expected external workspace-scoped runtime, got %v", config.RuntimeScope())
	}
	if !config.AllowsWorkspace("tko-operations") {
		t.Fatalf("expected the explicitly listed workspace to be allowed")
	}
	if config.AllowsWorkspace("some-other-workspace") {
		t.Fatalf("expected an unlisted workspace to be denied external runtime access")
	}
	if config.TrustRoots == nil {
		t.Fatalf("expected the mounted trust bundle to populate TrustRoots")
	}
}

func TestLoadLabMountedConfigRejectsExternalEndpointWithoutTrustBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api-key"), []byte("sk-live"), 0o600); err != nil {
		t.Fatalf("write api key file: %v", err)
	}
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"https://api.deepseek.com/v1","model_id":"deepseek-v4-flash","api_key_file":"api-key","timeout_seconds":30,"max_output_tokens":1024,"thinking_mode":"disabled","insecure_lab_mode":true,"external_runtime_workspace_ids":["tko-operations"]}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid for an external endpoint with no trust_bundle_file, got %v", err)
	}
}

func TestLoadLabMountedConfigRejectsPublicEndpointWithoutExternalAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"https://api.deepseek.com/v1","model_id":"deepseek-v4-flash","timeout_seconds":30,"max_output_tokens":1024,"thinking_mode":"disabled","insecure_lab_mode":true}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid for a public endpoint with no workspace allow-list, got %v", err)
	}
}

func TestLoadLabMountedConfigRejectsMissingThinkingMode(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":5,"max_output_tokens":128,"insecure_lab_mode":true}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid when thinking_mode is omitted, got %v", err)
	}
}

func TestLoadLabMountedConfigRejectsUnknownThinkingMode(t *testing.T) {
	dir := t.TempDir()
	writeLabConfig(t, dir, `{"schema_version":"model-gateway-lab-adapter-v1","endpoint":"http://127.0.0.1:8080","model_id":"m","timeout_seconds":5,"max_output_tokens":128,"thinking_mode":"auto","insecure_lab_mode":true}`)
	_, err := LoadLabMountedConfigAt(dir)
	if err == nil || CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("expected CodeLabMountInvalid for unknown thinking_mode, got %v", err)
	}
}

func writeLabConfig(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
