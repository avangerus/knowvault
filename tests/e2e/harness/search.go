//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"knowvault.local/verified-workspace/internal/search"
)

const (
	searchManifestName = "manifest.json"
	searchRootName     = "root-ca.pem"
	searchClientName   = "client-cert.pem"
	searchClientKey    = "client-key.pem"
)

type e2eSearchManifest struct {
	Schema                string `json:"schema"`
	OrganizationID        string `json:"organization_id"`
	Endpoint              string `json:"endpoint"`
	IndexAlias            string `json:"index_alias"`
	Generation            int64  `json:"generation"`
	GenerationFence       int64  `json:"generation_fence"`
	RootCAFile            string `json:"root_ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientKeyFile         string `json:"client_key_file"`
}

// prepareSearchMount lays out one administrator-owned search capability for a
// product root. The server and worker each receive a distinct copy so their
// chroots cannot accidentally share a writable path. The OpenSearch config
// directory is never exposed through this mount: only the CA and mTLS client
// pair needed by search.LoadMountedAt are copied.
func prepareSearchMount(ctx context.Context, cfg config, mountRoot string) error {
	_ = ctx
	if cfg.searchCertDir == "" || cfg.searchEndpoint == "" || cfg.searchAlias == "" || cfg.organizationID == "" || mountRoot == "" {
		return fmt.Errorf("search mount configuration is incomplete")
	}
	if err := os.MkdirAll(mountRoot, 0o750); err != nil {
		return fmt.Errorf("mkdir search mount: %w", err)
	}
	if err := os.Chmod(mountRoot, 0o750); err != nil {
		return fmt.Errorf("chmod search mount: %w", err)
	}
	if err := syscall.Chown(mountRoot, 0, runtimeGID); err != nil {
		return fmt.Errorf("chown search mount: %w", err)
	}

	manifest := e2eSearchManifest{
		Schema:                "knowvault-search-manifest-v1",
		OrganizationID:        cfg.organizationID,
		Endpoint:              cfg.searchEndpoint,
		IndexAlias:            cfg.searchAlias,
		Generation:            1,
		GenerationFence:       1,
		RootCAFile:            searchRootName,
		ClientCertificateFile: searchClientName,
		ClientKeyFile:         searchClientKey,
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("marshal search manifest: %w", err)
	}
	if err := writeSearchMountFile(filepath.Join(mountRoot, searchManifestName), rawManifest); err != nil {
		return fmt.Errorf("write search manifest: %w", err)
	}
	files := []struct {
		source string
		target string
	}{
		{source: filepath.Join(cfg.searchCertDir, "e2e-root-ca.pem"), target: searchRootName},
		{source: filepath.Join(cfg.searchCertDir, "client.pem"), target: searchClientName},
		{source: filepath.Join(cfg.searchCertDir, "client-key.pem"), target: searchClientKey},
	}
	for _, file := range files {
		contents, err := os.ReadFile(file.source)
		if err != nil {
			return fmt.Errorf("read search material: %w", err)
		}
		if len(contents) == 0 || len(contents) > 256<<10 {
			return fmt.Errorf("search material size is invalid")
		}
		if err := writeSearchMountFile(filepath.Join(mountRoot, file.target), contents); err != nil {
			return fmt.Errorf("write search material: %w", err)
		}
	}

	// Exercise the same strict loader used by production composition while the
	// harness still has a precise provisioning error. This checks ownership,
	// regular-file/no-follow semantics, manifest tenant binding, CA parsing and
	// the client key pair before either product process starts.
	_, err = search.LoadMountedAt(mountRoot, cfg.organizationID)
	if err != nil {
		return fmt.Errorf("validate search mount: %w", err)
	}
	return nil
}

func writeSearchMountFile(path string, contents []byte) error {
	if err := os.WriteFile(path, contents, 0o440); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o440); err != nil {
		return err
	}
	return syscall.Chown(path, 0, runtimeGID)
}

// waitForSearchProjection proves that the worker's ordered outbox applier
// reached the real OpenSearch node over the mounted HTTPS/mTLS capability. A
// short delay is expected after sync completion because the worker drains one
// search event per poll before claiming the next database job.
func waitForSearchProjection(ctx context.Context, cfg config, timeout time.Duration) error {
	if ctx == nil || timeout <= 0 {
		return fmt.Errorf("search projection wait configuration is invalid")
	}
	mounted, err := search.LoadMountedForTenant(cfg.organizationID)
	if err != nil {
		return fmt.Errorf("load search mount: %w", err)
	}
	client, err := search.New(mounted)
	if err != nil {
		return fmt.Errorf("construct search client: %w", err)
	}
	defer client.Close()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		result, searchErr := client.Search(ctx, search.Query{Text: "KnowVault pilot note", Size: 10})
		if searchErr == nil {
			for _, hit := range result.Hits {
				if hit.Document.OrganizationID == cfg.organizationID && hit.Document.Text != "" {
					return nil
				}
			}
			lastErr = fmt.Errorf("search returned no tenant-bound evidence (total=%d)", result.Total)
		} else {
			// Keep the content-free error code in diagnostics; the transport
			// deliberately does not expose endpoint, response body or credentials.
			lastErr = fmt.Errorf("search request: %s", search.CodeOf(searchErr))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("search projection deadline expired")
	}
	return lastErr
}
