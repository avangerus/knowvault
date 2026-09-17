//go:build linux

package operator

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

func TestGenerateWorkerSecretsPreservesKeysAndSeparatesOwnership(t *testing.T) {
	ctx := context.Background()
	serverRoot, workerRoot := t.TempDir(), t.TempDir()
	serverConfig := SecretManifestConfig{
		MountRoot: serverRoot, OrganizationID: testOrganizationID, ProviderID: testProviderID,
		DatabaseURL: validTestDatabaseURL("knowvault_app"), ClientReference: "client_ref", ClientSecret: validTestClientSecret(),
	}
	if _, err := GenerateSecrets(ctx, serverConfig); err != nil {
		t.Fatal(err)
	}
	workerConfig := serverConfig
	workerConfig.MountRoot, workerConfig.KeysFromRoot, workerConfig.Consumer = workerRoot, serverRoot, "worker"
	workerConfig.DatabaseURL = validTestDatabaseURL("knowvault_worker")
	if _, err := GenerateSecrets(ctx, workerConfig); err != nil {
		t.Fatal(err)
	}
	server, err := secretmount.LoadMounted(serverRoot, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	worker, err := secretmount.LoadWorkerMounted(workerRoot, testOrganizationID, testProviderID)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	a := capabilityBytes(t, server.ArtifactWrapKey)
	b := capabilityBytes(t, worker.ArtifactWrapKey)
	defer clear(a)
	defer clear(b)
	if !bytes.Equal(a, b) {
		t.Fatal("worker lost the server's artifact key")
	}
	if url, err := worker.DatabaseURL(); err != nil || url != string(workerConfig.DatabaseURL) {
		t.Fatal("worker database identity was not preserved")
	}
	if bad, err := secretmount.LoadMounted(workerRoot, testOrganizationID, testProviderID); bad != nil || err == nil {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("server accepted worker secrets")
	}
	if bad, err := secretmount.LoadWorkerMounted(serverRoot, testOrganizationID, testProviderID); bad != nil || err == nil {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("worker accepted server secrets")
	}
	if err := VerifyMountForConsumer(ctx, workerRoot, testOrganizationID, testProviderID, "worker"); err != nil {
		t.Fatal(err)
	}
	workerConfig.Consumer = "server"
	if _, err := GenerateSecrets(ctx, workerConfig); err == nil {
		t.Fatal("existing worker mount was overwritten")
	}
	info, err := os.Lstat(workerRoot)
	if err != nil || info.Sys().(*syscall.Stat_t).Gid != secretmount.WorkerRuntimeGID {
		t.Fatal("refused generation changed existing ownership")
	}
	manifest, err := os.Lstat(filepath.Join(workerRoot, manifestFilename))
	if err != nil || manifest.Sys().(*syscall.Stat_t).Gid != secretmount.WorkerRuntimeGID {
		t.Fatal("manifest has wrong consumer")
	}
	// A later worker mount can deliberately reuse another worker's key set.
	workerConfig.MountRoot = t.TempDir()
	workerConfig.KeysFromRoot = workerRoot
	workerConfig.Consumer = "worker"
	workerConfig.KeysFromConsumer = "worker"
	if _, err := GenerateSecrets(ctx, workerConfig); err != nil {
		t.Fatal(err)
	}
}
