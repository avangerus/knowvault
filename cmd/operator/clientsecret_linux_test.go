//go:build linux

package main

import (
	"os"
	"testing"

	"knowvault.local/verified-workspace/internal/operator"
)

func TestReadProtectedClientSecretFilePinsGroupReadableInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership boundary requires the pinned Linux test container")
	}
	path := writeProtectedClientSecretFile(t, []byte("group-readable-opaque-secret"), 0o440)
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if contents, err := readProtectedClientSecretFile(path); err == nil {
		clear(contents)
		t.Fatal("group-readable client secret owned by an arbitrary group was accepted")
	}
	if err := os.Chown(path, 0, operator.RuntimeGID); err != nil {
		t.Fatal(err)
	}
	contents, err := readProtectedClientSecretFile(path)
	if err != nil {
		t.Fatalf("runtime-group protected client secret rejected: %v", err)
	}
	clear(contents)
}
