package modelgateway

// This file owns the administrator-provisioned mount for the GEN-1 (ADR-0088)
// interim adapter. It deliberately mirrors internal/embedding's
// "mounted-file, not environment or request data" convention, with one
// difference the mount's own schema, insecure_lab_mode and thinking_mode
// fields must make loud:
// this is NOT the ADR-0080 mTLS production boundary. Composition loads it only
// from this fixed root; there is no environment, proxy or discovery fallback.

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
	// DefaultLabMountRoot is intentionally a distinct directory from
	// embedding.DefaultMountRoot so the two capabilities can never be
	// confused by an operator inspecting mounts.
	DefaultLabMountRoot   = "/run/knowvault/generation"
	labConfigFilename     = "config.json"
	maximumLabConfigBytes = 16 << 10
	// maximumLabAPIKeyFileBytes bounds the separate secret file the API key
	// is read from. The key never appears inside config.json (GEN-2: "the key
	// comes from a secret file, never the manifest and never a log").
	maximumLabAPIKeyFileBytes = 4 << 10
	// maximumLabTrustBundleBytes bounds the optional mounted CA bundle for an
	// external (public) endpoint's TLS verification (GEN-2).
	maximumLabTrustBundleBytes = 1 << 20
)

const (
	// CodeLabMountUnavailable means the optional GEN-1 adapter is not
	// mounted. Composition must keep GENERATIVE absent, exactly like the
	// embedding channel's own CodeMountUnavailable, and never invent a
	// weaker default transport.
	CodeLabMountUnavailable ErrorCode = "MODEL_GATEWAY_LAB_MOUNT_UNAVAILABLE"
	// CodeLabMountInvalid means a mount exists but is malformed or missing
	// the explicit insecure_lab_mode acknowledgement.
	CodeLabMountInvalid ErrorCode = "MODEL_GATEWAY_LAB_MOUNT_INVALID"
)

type mountedLabConfig struct {
	SchemaVersion string `json:"schema_version"`
	Endpoint      string `json:"endpoint"`
	ModelID       string `json:"model_id"`
	// APIKeyFile names a file inside the same mount root that holds the raw
	// API key. It is never inlined in this JSON manifest: a manifest is
	// deployment configuration an operator may reasonably dump or diff, while
	// the key is a secret with its own file, permissions and mount (GEN-2).
	APIKeyFile string `json:"api_key_file,omitempty"`
	// TrustBundleFile names a PEM CA-bundle file inside the same mount root,
	// required whenever ExternalRuntimeWorkspaceIDs is non-empty (GEN-2): the
	// adapter never trusts the runtime image's ambient/system pool for a
	// public-PKI endpoint (the image has none, by design; see lab_adapter.go).
	TrustBundleFile string `json:"trust_bundle_file,omitempty"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
	MaxOutputTokens int    `json:"max_output_tokens"`
	// ThinkingMode is required in a mounted config so the provider request is
	// explicit and reproducible; an omitted value is allowed only for direct
	// local generic-lab LabAdapterConfig callers.
	ThinkingMode ThinkingMode `json:"thinking_mode"`
	// StructuredOutputMode is optional (D1/A1). Omission is valid and stays the
	// zero value, whose effective behavior is json_object.
	StructuredOutputMode        StructuredOutputMode `json:"structured_output_mode,omitempty"`
	InsecureLabMode             bool                 `json:"insecure_lab_mode"`
	ExternalRuntimeWorkspaceIDs []string             `json:"external_runtime_workspace_ids,omitempty"`
	ToolLoop                    *ToolLoopProfile     `json:"tool_loop,omitempty"`
}

// LoadLabMountedConfig loads the GEN-1 adapter's non-secret configuration from
// the fixed mount root. A missing directory/file is CodeLabMountUnavailable
// (capability absent); a present-but-malformed mount is CodeLabMountInvalid
// and must never be treated as absent, so drift cannot look like a safe
// no-op.
func LoadLabMountedConfig() (LabAdapterConfig, error) {
	return loadLabMountedConfig(DefaultLabMountRoot)
}

// LoadLabMountedConfigAt is the operator/test seam; production composition
// always uses DefaultLabMountRoot.
func LoadLabMountedConfigAt(rootPath string) (LabAdapterConfig, error) {
	return loadLabMountedConfig(rootPath)
}

func loadLabMountedConfig(rootPath string) (LabAdapterConfig, error) {
	if rootPath == "" {
		return LabAdapterConfig{}, &Error{code: CodeLabMountUnavailable}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, labConfigFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return LabAdapterConfig{}, &Error{code: CodeLabMountUnavailable, cause: err}
		}
		return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid, cause: err}
	}
	if len(raw) == 0 || len(raw) > maximumLabConfigBytes {
		return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid}
	}
	return parseLabMountedConfig(rootPath, raw, false)
}

func parseLabMountedConfig(rootPath string, raw []byte, strictFiles bool) (LabAdapterConfig, error) {
	var mounted mountedLabConfig
	if err := jsonv2.Unmarshal(raw, &mounted, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid, cause: err}
	}
	if !mounted.InsecureLabMode || !mounted.ThinkingMode.valid() || mounted.TimeoutSeconds < 0 || mounted.TimeoutSeconds > int(labMaxTimeout/time.Second) {
		return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid}
	}
	if strictFiles {
		for _, filename := range []string{mounted.APIKeyFile, mounted.TrustBundleFile} {
			if filename != "" && (!validProfileMountFilename(filename) || !regularProfileMountFile(filepath.Join(rootPath, filename))) {
				return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid}
			}
		}
	}
	apiKey, err := loadLabAPIKeyFile(rootPath, mounted.APIKeyFile)
	if err != nil {
		return LabAdapterConfig{}, err
	}
	trustRoots, err := loadLabTrustBundleFile(rootPath, mounted.TrustBundleFile)
	if err != nil {
		return LabAdapterConfig{}, err
	}
	config := LabAdapterConfig{
		SchemaVersion: mounted.SchemaVersion, Endpoint: mounted.Endpoint, ModelID: mounted.ModelID,
		APIKey: apiKey, Timeout: time.Duration(mounted.TimeoutSeconds) * time.Second,
		MaxOutputTokens: mounted.MaxOutputTokens, ThinkingMode: mounted.ThinkingMode, InsecureLabMode: mounted.InsecureLabMode,
		StructuredOutputMode:        mounted.StructuredOutputMode,
		ExternalRuntimeWorkspaceIDs: mounted.ExternalRuntimeWorkspaceIDs, TrustRoots: trustRoots,
		ToolLoop: mounted.ToolLoop,
	}
	if err := config.Validate(); err != nil {
		return LabAdapterConfig{}, &Error{code: CodeLabMountInvalid, cause: err}
	}
	return config, nil
}

// loadLabAPIKeyFile reads the API key from its own file inside the mount
// root. An empty APIKeyFile means the endpoint needs no key (e.g. an
// unauthenticated local lab server); a non-empty name must be a bare filename
// inside rootPath, never a path or traversal, matching the mount's own
// "fixed root only" contract. The key is never logged and never appears in
// config.json.
func loadLabAPIKeyFile(rootPath, apiKeyFile string) (string, error) {
	if apiKeyFile == "" {
		return "", nil
	}
	if apiKeyFile != filepath.Base(apiKeyFile) || apiKeyFile == "." || apiKeyFile == ".." ||
		strings.ContainsAny(apiKeyFile, `/\`) {
		return "", &Error{code: CodeLabMountInvalid}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, apiKeyFile))
	if err != nil {
		return "", &Error{code: CodeLabMountInvalid, cause: err}
	}
	key := strings.TrimRight(string(raw), "\r\n")
	if key == "" || len(raw) > maximumLabAPIKeyFileBytes {
		return "", &Error{code: CodeLabMountInvalid}
	}
	return key, nil
}

// loadLabTrustBundleFile reads an optional PEM CA bundle from its own file
// inside the mount root, following the exact same bare-filename,
// no-traversal contract as loadLabAPIKeyFile. An empty TrustBundleFile
// returns a nil pool (fine for a local lab endpoint; LabAdapterConfig.Validate
// rejects a nil pool for an external endpoint).
func loadLabTrustBundleFile(rootPath, trustBundleFile string) (*x509.CertPool, error) {
	if trustBundleFile == "" {
		return nil, nil
	}
	if trustBundleFile != filepath.Base(trustBundleFile) || trustBundleFile == "." || trustBundleFile == ".." ||
		strings.ContainsAny(trustBundleFile, `/\`) {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	raw, err := os.ReadFile(filepath.Join(rootPath, trustBundleFile))
	if err != nil {
		return nil, &Error{code: CodeLabMountInvalid, cause: err}
	}
	if len(raw) == 0 || len(raw) > maximumLabTrustBundleBytes {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, &Error{code: CodeLabMountInvalid}
	}
	return pool, nil
}
