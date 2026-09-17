package governedquery

// This file owns the administrator-provisioned mount for the ADR-0089
// governed-execution connection. It follows the exact "mounted file, never
// environment or request data" convention internal/modelgateway/mount_lab.go
// established for the GEN-1/GEN-2 interim adapter: a distinct mount root, a
// non-secret config.json, and the DSN/trust bundle each in their own file so
// neither ever appears inline in the manifest or a log.

import (
	"crypto/x509"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultMountRoot is deliberately distinct from every other mount root in
	// the system so an operator inspecting mounts can never confuse this
	// dedicated, least-privilege ad hoc query capability with the ADR-0078
	// ingestion connection, the embedding channel or the GEN-1/GEN-2 adapter.
	DefaultMountRoot       = "/run/knowvault/governedquery"
	mountConfigFilename    = "config.json"
	maxMountConfigBytes    = 16 << 10
	maxMountDSNFileBytes   = 4 << 10
	maxMountTrustBundleBytes = 1 << 20
)

type mountedConfig struct {
	SchemaVersion        string `json:"schema_version"`
	ConnectionID         string `json:"connection_id"`
	DatabaseIdentity     string `json:"database_identity"`
	WorkspaceID          string `json:"workspace_id"`
	DSNFile              string `json:"dsn_file"`
	TrustBundleFile      string `json:"trust_bundle_file"`
	StatementTimeoutSecs int    `json:"statement_timeout_seconds"`
	MaxRows              int    `json:"max_rows"`
	MaxResultBytes        int   `json:"max_result_bytes"`
	MaxCostEstimate       float64 `json:"max_cost_estimate"`
}

// LoadMountedConfig loads the ADR-0089 governed-execution capability from the
// fixed mount root. A missing directory/file is CodeMountUnavailable
// (capability absent, fail-closed per ADR-0089 §6); a present-but-malformed
// mount is CodeMountInvalid and must never be treated as absent, so drift
// cannot look like a safe no-op (mirrors modelgateway.LoadLabMountedConfig).
func LoadMountedConfig() (Config, error) {
	return loadMountedConfig(DefaultMountRoot)
}

// LoadMountedConfigAt is the operator/test seam; production composition
// always uses DefaultMountRoot.
func LoadMountedConfigAt(rootPath string) (Config, error) {
	return loadMountedConfig(rootPath)
}

func loadMountedConfig(rootPath string) (Config, error) {
	if rootPath == "" {
		return Config{}, &Error{code: CodeMountUnavailable}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, mountConfigFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, &Error{code: CodeMountUnavailable, cause: err}
		}
		return Config{}, &Error{code: CodeMountInvalid, cause: err}
	}
	if len(raw) == 0 || len(raw) > maxMountConfigBytes {
		return Config{}, &Error{code: CodeMountInvalid}
	}
	var mounted mountedConfig
	if err := jsonv2.Unmarshal(raw, &mounted, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return Config{}, &Error{code: CodeMountInvalid, cause: err}
	}
	if mounted.SchemaVersion != "governed-query-mount-v1" || mounted.StatementTimeoutSecs < 1 || mounted.StatementTimeoutSecs > 300 {
		return Config{}, &Error{code: CodeMountInvalid}
	}
	dsn, err := loadMountFile(rootPath, mounted.DSNFile, maxMountDSNFileBytes)
	if err != nil {
		return Config{}, err
	}
	trustRoots, err := loadTrustBundleFile(rootPath, mounted.TrustBundleFile)
	if err != nil {
		return Config{}, err
	}
	config := Config{
		ConnectionID: mounted.ConnectionID, DatabaseIdentity: mounted.DatabaseIdentity, WorkspaceID: mounted.WorkspaceID,
		DSN: dsn, TrustRoots: trustRoots,
		Limits: Limits{
			StatementTimeout: time.Duration(mounted.StatementTimeoutSecs) * time.Second,
			MaxRows:          mounted.MaxRows, MaxResultBytes: mounted.MaxResultBytes, MaxCostEstimate: mounted.MaxCostEstimate,
		},
	}
	if err := config.Validate(); err != nil {
		return Config{}, &Error{code: CodeMountInvalid, cause: err}
	}
	return config, nil
}

func loadMountFile(rootPath, filename string, maxBytes int) (string, error) {
	if filename == "" || filename != filepath.Base(filename) || filename == "." || filename == ".." || strings.ContainsAny(filename, `/\`) {
		return "", &Error{code: CodeMountInvalid}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, filename))
	if err != nil {
		return "", &Error{code: CodeMountInvalid, cause: err}
	}
	value := strings.TrimRight(string(raw), "\r\n")
	if value == "" || len(raw) > maxBytes {
		return "", &Error{code: CodeMountInvalid}
	}
	return value, nil
}

func loadTrustBundleFile(rootPath, filename string) (*x509.CertPool, error) {
	if filename == "" || filename != filepath.Base(filename) || filename == "." || filename == ".." || strings.ContainsAny(filename, `/\`) {
		return nil, &Error{code: CodeMountInvalid}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, filename))
	if err != nil {
		return nil, &Error{code: CodeMountInvalid, cause: err}
	}
	if len(raw) == 0 || len(raw) > maxMountTrustBundleBytes {
		return nil, &Error{code: CodeMountInvalid}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, &Error{code: CodeMountInvalid}
	}
	return pool, nil
}
