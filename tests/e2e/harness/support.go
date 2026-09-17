//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// clientSecretReference names the OIDC client secret inside the generated
// secret mount; provider-register records the same reference in the provider
// revision, and the server resolves it at preflight and login time.
const clientSecretReference = "e2e-client-secret"

const runtimeGID = 65532

// installTrust writes the host-generated CA into the pinned trust mount so
// the same root serves both the PostgreSQL verify-full chain and the static
// IdP chain, exactly as the deployment document prescribes.
func installTrust(ctx context.Context, cfg config) error {
	caPEM, err := os.ReadFile(filepath.Join(cfg.caDir, "ca.pem"))
	if err != nil {
		return fmt.Errorf("read ca: %w", err)
	}
	// Empty build-context directories are not a portable ownership boundary:
	// different BuildKit/storage-driver combinations may materialize the
	// destination as root:root even when Dockerfile COPY carries --chown. The
	// harness is the one-shot root publisher for this e2e mount, so establish
	// the same root:runtime-group/0750 directory contract the production
	// operator enforces before publishing either purpose-separated file.
	const trustRoot = "/run/knowvault/trust"
	if err := syscall.Chown(trustRoot, 0, runtimeGID); err != nil {
		return fmt.Errorf("chown trust root: %w", err)
	}
	if err := os.Chmod(trustRoot, 0o750); err != nil {
		return fmt.Errorf("chmod trust root: %w", err)
	}
	for _, name := range []string{"database-ca.pem", "oidc-ca.pem"} {
		path := filepath.Join(trustRoot, name)
		if err := os.WriteFile(path, caPEM, 0o440); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := syscall.Chown(path, 0, runtimeGID); err != nil {
			return fmt.Errorf("chown %s: %w", name, err)
		}
		if err := os.Chmod(path, 0o440); err != nil {
			return fmt.Errorf("chmod %s: %w", name, err)
		}
	}
	return nil
}

// waitPG blocks until the PostgreSQL container accepts a TLS session with the
// server certificate validated against the pinned CA.
func waitPG(ctx context.Context, cfg config) error {
	caPEM, err := os.ReadFile(filepath.Join(cfg.caDir, "ca.pem"))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("ca pool: no certificates")
	}
	deadline := time.Now().Add(120 * time.Second)
	var lastErr error
	// The net dialer timeout bounds every attempt even when the host is
	// silently dropping SYNs; the outer deadline still caps the whole
	// readiness wait.
	dialer := &tls.Dialer{
		Config:    &tls.Config{RootCAs: pool, ServerName: cfg.pgHost, MinVersion: tls.VersionTLS12},
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
	}
	for time.Now().Before(deadline) {
		connection, err := dialer.DialContext(ctx, "tcp", cfg.pgHost+":5432")
		if err == nil {
			_ = connection.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("postgres did not become ready: %w", lastErr)
}

// generatePasswords writes the three runtime role password files, the
// pre-issued IdP client secret and runtime database URL files into the private
// run directory. The URL targets
// the knowvault_app role over sslmode=verify-full, which the product mount
// loader enforces. The values stay in 0400 files; they never become process
// arguments.
func generatePasswords(ctx context.Context, cfg config) error {
	runDir := "/e2e/run"
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	makePassword := func() (string, error) {
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		return hex.EncodeToString(raw), nil
	}
	writeSecret := func(path, value string) error {
		if err := os.WriteFile(path, []byte(value), 0o400); err != nil {
			return err
		}
		return os.Chmod(path, 0o400)
	}
	var app, worker, purger, clientSecret string
	var err error
	if app, err = makePassword(); err != nil {
		return err
	}
	if worker, err = makePassword(); err != nil {
		return err
	}
	if purger, err = makePassword(); err != nil {
		return err
	}
	if clientSecret, err = makePassword(); err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(runDir, "app.pw"), app); err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(runDir, "worker.pw"), worker); err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(runDir, "purger.pw"), purger); err != nil {
		return err
	}
	if err := writeSecret(filepath.Join(runDir, "oidc-client.secret"), clientSecret); err != nil {
		return err
	}
	dbURL := "postgres://knowvault_app:" + app + "@" + cfg.pgHost + ":5432/knowvault?sslmode=verify-full"
	if err := writeSecret(filepath.Join(runDir, "db.url"), dbURL); err != nil {
		return err
	}
	// The worker connects as its own database role (DEPLOYMENT.md §4), so the
	// worker mount carries its own sealed URL file.
	workerDBURL := "postgres://knowvault_worker:" + worker + "@" + cfg.pgHost + ":5432/knowvault?sslmode=verify-full"
	return writeSecret(filepath.Join(runDir, "db_worker.url"), workerDBURL)
}

// runOperator executes one built operator subcommand. The operator resolves
// the verify-full PostgreSQL chain through the process-wide certificate file,
// because the scratch runtime has no system trust store.
func runOperator(ctx context.Context, cfg config, arguments ...string) error {
	command := exec.CommandContext(ctx, "/knowvault-operator", arguments...)
	command.Env = append(os.Environ(),
		"SSL_CERT_FILE="+filepath.Join(cfg.caDir, "ca.pem"),
		// The admin URL carries the throwaway postgres password; the operator
		// environment channel keeps it out of argv, which every root process
		// in the container could read from /proc.
		"KNOWVAULT_OPERATOR_ADMIN_URL="+cfg.adminURL)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		// Operator diagnostics may embed admin-level context; redact before the
		// error surfaces in any harness report.
		return fmt.Errorf("operator %s: %v: %s", strings.Join(arguments, " "), err, redactRunSecrets(strings.TrimSpace(output.String())))
	}
	return nil
}

// redactRunSecrets replaces the runtime secrets the harness generated (role
// passwords and sealed database URLs) with a placeholder, so failure
// diagnostics that embed process output or driver errors — a pgx parse error
// carries the raw DSN, a SIGQUIT dump may carry in-flight string arguments —
// never leak secret material into the report.
func redactRunSecrets(text string) string {
	for _, path := range []string{
		"/e2e/run/app.pw", "/e2e/run/worker.pw", "/e2e/run/purger.pw", "/e2e/run/oidc-client.secret",
		"/e2e/run/db.url", "/e2e/run/db_worker.url",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text = strings.ReplaceAll(text, strings.TrimSpace(string(raw)), "[redacted]")
	}
	return text
}
