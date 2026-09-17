//go:build linux

package embedding

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

func TestWorkerMountOwnershipIsDistinct(t *testing.T) {
	for name, consumer := range map[string]runtimeidentity.MountConsumer{"server": runtimeidentity.Server, "worker": runtimeidentity.Worker} {
		t.Run(name, func(t *testing.T) {
			group, _ := consumer.GroupID()
			other := runtimeidentity.Worker
			if consumer == runtimeidentity.Worker {
				other = runtimeidentity.Server
			}
			otherGroup, _ := other.GroupID()
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(directory, 0, int(group)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, embeddingManifestFilename)
			payload := []byte("synthetic owned capability")
			if err := os.WriteFile(path, payload, 0o440); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o440); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 0, int(group)); err != nil {
				t.Fatal(err)
			}
			for _, denied := range []runtimeidentity.MountConsumer{other, 255} {
				rejected, err := openEmbeddingMountedRootForConsumer(directory, denied)
				if rejected != nil {
					_ = rejected.Close()
					t.Fatal("foreign or unknown consumer opened the mount")
				}
				if err == nil {
					t.Fatal("missing consumer rejection")
				}
			}
			root, err := openEmbeddingMountedRootForConsumer(directory, consumer)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			data, err := root.read(embeddingManifestFilename, maximumManifestBytes)
			if err != nil || !bytes.Equal(data, payload) {
				t.Fatalf("own capability read failed: %v", err)
			}
			if err := os.Chown(path, 0, int(otherGroup)); err != nil {
				t.Fatal(err)
			}
			data, err = root.read(embeddingManifestFilename, maximumManifestBytes)
			if err == nil || len(data) != 0 {
				t.Fatal("an opened mount accepted a foreign-group file")
			}
		})
	}
}
