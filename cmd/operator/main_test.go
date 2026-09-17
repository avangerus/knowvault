package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeProtectedClientSecretFile(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oidc-client.secret")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadProtectedClientSecretFilePreservesExactBytes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("protected ownership and mode semantics are Linux-only")
	}
	want := []byte("opaque/client+secret_%2F-canary")
	path := writeProtectedClientSecretFile(t, want, 0o600)
	got, err := readProtectedClientSecretFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("client secret changed: got %q want %q", got, want)
	}
	clear(got)
}

func TestReadProtectedClientSecretFileRejectsUnsafeFiles(t *testing.T) {
	tests := []struct {
		name string
		make func(*testing.T) string
	}{
		{name: "missing", make: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }},
		{name: "empty", make: func(t *testing.T) string { return writeProtectedClientSecretFile(t, nil, 0o600) }},
		{name: "oversize", make: func(t *testing.T) string {
			return writeProtectedClientSecretFile(t, []byte(strings.Repeat("x", maxImportedClientSecretBytes+1)), 0o600)
		}},
		{name: "world-readable", make: func(t *testing.T) string {
			return writeProtectedClientSecretFile(t, []byte("secret"), 0o644)
		}},
		{name: "directory", make: func(t *testing.T) string { return t.TempDir() }},
		{name: "symlink", make: func(t *testing.T) string {
			parent := t.TempDir()
			target := filepath.Join(parent, "target")
			if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(parent, "link")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink unsupported: %v", err)
			}
			return link
		}},
		{name: "hardlink", make: func(t *testing.T) string {
			parent := t.TempDir()
			target := filepath.Join(parent, "target")
			if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(parent, "link")
			if err := os.Link(target, link); err != nil {
				t.Skipf("hard links unsupported: %v", err)
			}
			return link
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.make(t)
			got, err := readProtectedClientSecretFile(path)
			if err == nil {
				clear(got)
				t.Fatal("unsafe client secret file accepted")
			}
		})
	}
}

func captureCommandOutput(t *testing.T, run func() int) (string, string, int) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	code := run()
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, stdoutErr := io.ReadAll(stdoutReader)
	stderr, stderrErr := io.ReadAll(stderrReader)
	_ = stdoutReader.Close()
	_ = stderrReader.Close()
	if stdoutErr != nil || stderrErr != nil {
		t.Fatalf("capture output: stdout=%v stderr=%v", stdoutErr, stderrErr)
	}
	return string(stdout), string(stderr), code
}

func TestSecretsGenerateRejectsClientSecretInputWithoutLeak(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db-url")
	if err := os.WriteFile(databasePath, []byte("postgres://knowvault_app:test-password@db.example:5432/knowvault?sslmode=verify-full"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretCanary := "oidc-client-secret-log-canary"
	secretPath := writeProtectedClientSecretFile(t, []byte(secretCanary+"\n"), 0o600)
	out, errOut, code := captureCommandOutput(t, func() int {
		return runSecretsGenerate(context.Background(), []string{
			"-out", t.TempDir(), "-organization", "org_001", "-provider", "provider_001",
			"-database-url-file", databasePath, "-client-reference", "client_ref",
			"-client-secret-file", secretPath,
		})
	})
	if code != 1 {
		t.Fatalf("exit code=%d stdout=%q stderr=%q", code, out, errOut)
	}
	if strings.Contains(out, secretCanary) || strings.Contains(errOut, secretCanary) {
		t.Fatalf("client secret leaked by command output: stdout=%q stderr=%q", out, errOut)
	}
}

func TestSecretsGenerateRequiresClientSecretFile(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "db-url")
	if err := os.WriteFile(databasePath, []byte("postgres://knowvault_app:test-password@db.example:5432/knowvault?sslmode=verify-full"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := captureCommandOutput(t, func() int {
		return runSecretsGenerate(nil, []string{
			"-out", t.TempDir(), "-organization", "org_001", "-provider", "provider_001",
			"-database-url-file", databasePath, "-client-reference", "client_ref",
		})
	})
	if code != 1 || !strings.Contains(out, `"code":"MOUNT_INVALID"`) {
		t.Fatalf("missing client secret file: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}
