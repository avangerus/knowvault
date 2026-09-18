//go:build linux

package reranking

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRerankingProvisionKeepsTenantAndProtectedFilesOnRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected provisioning fixture requires root")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required")
	}
	base := t.TempDir()
	for _, name := range []string{"reranking-bootstrap.sh", "reranking-profile.json"} {
		data, err := os.ReadFile("../../deploy/compose/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	stub := "#!/bin/sh\nset -eu\ncase \"$1 $2\" in\n'image inspect') exit 0;;\n'volume inspect') test -f \"$KV_VOLUME_STATE\";;\n'volume create') touch \"$KV_VOLUME_STATE\";;\n'run --rm') printf 'cache-init\\n' >> \"$KV_DOCKER_CALLS\";;\n*) exit 88;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "volume-present")
	calls := filepath.Join(base, "docker-calls")
	run := func(org string, args ...string) ([]byte, error) {
		argv := append([]string{filepath.Join(base, "reranking-bootstrap.sh"), "--organization-id", org}, args...)
		command := exec.Command("bash", argv...)
		command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "KV_VOLUME_STATE="+state, "KV_DOCKER_CALLS="+calls)
		return command.CombinedOutput()
	}
	if output, err := run("test_org", "--dry-run"); err != nil {
		t.Fatalf("dry run: %v: %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(base, "pki")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote PKI")
	}
	if output, err := run("test_org"); err != nil {
		t.Fatalf("prepare: %v: %s", err, output)
	}
	mount := filepath.Join(base, "mounts/server/reranking")
	loaded, err := LoadMountedAt(mount, "test_org")
	if err != nil || loaded.Profile.ModelID != "BAAI/bge-reranker-v2-m3" {
		t.Fatalf("generated mount rejected: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(mount, "client-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if output, err := run("test_org"); err != nil {
		t.Fatalf("retry: %v: %s", err, output)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatal("retry did not restore cache initialization")
	}
	after, err := os.ReadFile(filepath.Join(mount, "client-key.pem"))
	if err != nil || string(before) != string(after) {
		t.Fatal("retry replaced key material")
	}
	if output, err := run("another_org"); err == nil {
		t.Fatalf("wrong tenant accepted: %s", output)
	}
	if err := os.Chmod(filepath.Join(mount, "client-key.pem"), 0660); err != nil {
		t.Fatal(err)
	}
	if output, err := run("test_org"); err == nil {
		t.Fatalf("permission drift accepted: %s", output)
	}
	if err := os.Chmod(filepath.Join(mount, "client-key.pem"), 0440); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(mount, "manifest.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "manifest-copy")
	if err := os.WriteFile(outside, data, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, manifest); err != nil {
		t.Fatal(err)
	}
	if output, err := run("test_org"); err == nil {
		t.Fatalf("symlink drift accepted: %s", output)
	}
	log, err := os.ReadFile(calls)
	if err != nil || strings.Count(string(log), "cache-init") != 2 {
		t.Fatal("cache preparation was skipped or ran on denied state")
	}
}
