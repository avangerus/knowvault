package ingestion

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/connector/git"
	"knowvault.local/verified-workspace/internal/connector/mail"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/observation"
)

// RemoteCredentialSource is the narrow secret capability needed by a resolver.
// The ingestion package never imports the mounted-secret implementation; the
// production composition injects it through this interface.
type RemoteCredentialSource interface {
	ResolveReference(context.Context, string) (string, error)
}

// SourceTrustPools is a deployment-owned source CA snapshot. The composition
// root builds these pools from purpose-specific mounts; nil pools fail closed.
// DatabaseRoots authenticates an operator-registered external
// POSTGRESQL_QUERY source connection's own server certificate; it is
// deliberately distinct from the platform's own control-plane database trust
// so a source connector can never accidentally inherit platform trust.
type SourceTrustPools struct {
	GitRoots      *x509.CertPool
	MailRoots     *x509.CertPool
	DatabaseRoots *x509.CertPool
}

// SourceTrustLoader is a deployment-owned source CA loader. It must return
// purpose-specific Git/IMAP roots and must never fall back to a system pool.
type SourceTrustLoader func() (SourceTrustPools, error)

// RemoteObservationAdapterResolver decrypts the exact activated source scope
// artifacts through the worker owner bindings, resolves one opaque mounted
// credential, and constructs a read-only native connector. It is deliberately
// in the ingestion package so the handler cannot receive a connector that was
// not bound to the same organization/scope revision.
type RemoteObservationAdapterResolver struct {
	database   *database.Store
	repository *repository.Repository
	codec      *artifactcrypto.Codec
	secrets    RemoteCredentialSource
	loadTrust  SourceTrustLoader
}

// NewRemoteObservationAdapterResolver binds the production-only dependencies.
// A nil dependency leaves the resolver inert rather than creating a test or
// fallback connector.
func NewRemoteObservationAdapterResolver(databaseStore *database.Store, artifactRepository *repository.Repository,
	codec *artifactcrypto.Codec, secrets RemoteCredentialSource, loadTrust SourceTrustLoader) (*RemoteObservationAdapterResolver, error) {
	if databaseStore == nil || artifactRepository == nil || codec == nil || secrets == nil || loadTrust == nil {
		return nil, failure("INGEST_RESOLVER_INVALID", nil)
	}
	return &RemoteObservationAdapterResolver{database: databaseStore, repository: artifactRepository,
		codec: codec, secrets: secrets, loadTrust: loadTrust}, nil
}

// Resolve implements ObservationAdapterResolver. It never accepts connector
// configuration or credentials from the job payload; all values come from
// encrypted owner artifacts and the fixed administrator mounts.
func (resolver *RemoteObservationAdapterResolver) Resolve(ctx context.Context, access database.AccessContext,
	target ObservationAdapterTarget) (ObservationAdapterBinding, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || access.Validate() != nil ||
		target.OrganizationID != access.OrganizationID || target.SourceType != "GIT" && target.SourceType != "MAIL" ||
		!validRemoteOpaque(target.ConnectionID) || !validRemoteOpaque(target.SourceScopeID) || target.ConnectionRevision < 1 ||
		target.SourceScopeRevision < 1 || target.AccessMode != "WORKSPACE_MANAGED" ||
		!validSHA256(target.ScopeConfigHash) || !validSHA256(target.TrustProfileHash) ||
		!validRemoteOpaque(target.ScopeConfigResource) || !validRemoteOpaque(target.TrustConfigResource) {
		return ObservationAdapterBinding{}, failure("INGEST_RESOLVER_INVALID", nil)
	}
	credentialReference, err := resolver.credentialReference(ctx, access, target.SourceScopeID, target.SourceScopeRevision)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CREDENTIAL_UNAVAILABLE", err)
	}
	trustBytes, err := resolver.readArtifact(ctx, access, artifactcrypto.SourceConnectionTrustConfig,
		target.TrustConfigResource, target.TrustProfileHash)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_UNAVAILABLE", err)
	}
	defer clearRemoteBytes(trustBytes)
	configBytes, err := resolver.readArtifact(ctx, access, artifactcrypto.SourceScopeConfig,
		target.ScopeConfigResource, target.ScopeConfigHash)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_UNAVAILABLE", err)
	}
	defer clearRemoteBytes(configBytes)
	trust, err := resolver.loadTrust()
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_UNAVAILABLE", err)
	}
	switch target.SourceType {
	case "GIT":
		return resolver.resolveGit(ctx, access, target, credentialReference, trustBytes, configBytes, trust)
	case "MAIL":
		return resolver.resolveMail(ctx, access, target, credentialReference, trustBytes, configBytes, trust)
	default:
		return ObservationAdapterBinding{}, failure("INGEST_RESOLVER_INVALID", nil)
	}
}

type remoteGitTrust struct {
	SchemaVersion string `json:"schema_version"`
	SourceType    string `json:"source_type"`
	ConnectionID  string `json:"connection_id"`
	Provider      string `json:"provider"`
	Endpoint      string `json:"endpoint"`
	WebBaseURL    string `json:"web_base_url"`
}

type remoteGitConfig struct {
	SchemaVersion  string   `json:"schema_version"`
	SourceType     string   `json:"source_type"`
	Provider       string   `json:"provider"`
	RepositoryID   string   `json:"repository_id"`
	BranchName     string   `json:"branch_name"`
	PathMatcher    string   `json:"path_matcher_version"`
	IncludePaths   []string `json:"include_paths"`
	ExcludePaths   []string `json:"exclude_paths"`
	MaxBlobBytes   int64    `json:"max_blob_bytes"`
	TextMediaTypes []string `json:"text_media_types"`
	Submodules     bool     `json:"submodules"`
	LFSContent     bool     `json:"lfs_content"`
}

type remoteMailTrust struct {
	SchemaVersion string `json:"schema_version"`
	SourceType    string `json:"source_type"`
	ConnectionID  string `json:"connection_id"`
	Endpoint      string `json:"endpoint"`
	Username      string `json:"username"`
}

type remoteMailConfig struct {
	SchemaVersion        string   `json:"schema_version"`
	SourceType           string   `json:"source_type"`
	Endpoint             string   `json:"endpoint"`
	Mailbox              string   `json:"mailbox"`
	Folder               string   `json:"folder"`
	Since                *string  `json:"since,omitempty"`
	IncludeAttachments   bool     `json:"include_attachments"`
	MaxMessageBytes      int64    `json:"max_message_bytes"`
	MaxAttachmentBytes   int64    `json:"max_attachment_bytes"`
	AttachmentMediaTypes []string `json:"attachment_media_types"`
}

func (resolver *RemoteObservationAdapterResolver) resolveGit(ctx context.Context, access database.AccessContext,
	target ObservationAdapterTarget, credentialReference string, trustBytes, configBytes []byte,
	sourceTrust SourceTrustPools) (ObservationAdapterBinding, error) {
	var trust remoteGitTrust
	var config remoteGitConfig
	if decodeRemote(trustBytes, &trust) != nil || decodeRemote(configBytes, &config) != nil ||
		trust.SourceType != "GIT" || config.SourceType != "GIT" || trust.ConnectionID != target.ConnectionID ||
		config.Provider != trust.Provider || config.SchemaVersion != "source-git-config-v1" ||
		trust.SchemaVersion != "source-git-trust-v1" || config.PathMatcher != "scope-glob-v1" || config.Submodules || config.LFSContent {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_INVALID", nil)
	}
	canonicalTrust, err := canon.GitTrustBytes(trust.ConnectionID, trust.Provider, trust.Endpoint, trust.WebBaseURL)
	if err != nil || !bytes.Equal(canonicalTrust, trustBytes) {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_INVALID", err)
	}
	canonicalConfig, err := canon.GitScopeConfigBytes(config.Provider, config.RepositoryID, config.BranchName,
		config.IncludePaths, config.ExcludePaths, config.TextMediaTypes, config.MaxBlobBytes)
	if err != nil || !bytes.Equal(canonicalConfig, configBytes) {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_INVALID", err)
	}
	if sourceTrust.GitRoots == nil || len(sourceTrust.GitRoots.Subjects()) == 0 {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_UNAVAILABLE", nil)
	}
	pool := sourceTrust.GitRoots
	credential, err := resolver.secrets.ResolveReference(ctx, credentialReference)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CREDENTIAL_UNAVAILABLE", err)
	}
	connector, err := git.New(git.Config{Provider: git.Provider(trust.Provider), Endpoint: trust.Endpoint,
		WebBaseURL: trust.WebBaseURL, RepositoryID: config.RepositoryID, BranchName: config.BranchName,
		IncludeGlobs: config.IncludePaths, ExcludeGlobs: config.ExcludePaths, MaxBlobBytes: config.MaxBlobBytes,
		TextMediaTypes: config.TextMediaTypes, AccessToken: credential, TrustRoots: pool})
	credential = ""
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONNECTOR_INVALID", err)
	}
	adapter, err := observation.NewGitAdapter(connector, access.OrganizationID, target.SourceScopeID, target.SourceScopeRevision)
	if err != nil {
		_ = connector.Close()
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONNECTOR_INVALID", err)
	}
	return ObservationAdapterBinding{Adapter: adapter, Formats: gitFormats(config.TextMediaTypes), Close: adapter.Close}, nil
}

func (resolver *RemoteObservationAdapterResolver) resolveMail(ctx context.Context, access database.AccessContext,
	target ObservationAdapterTarget, credentialReference string, trustBytes, configBytes []byte,
	sourceTrust SourceTrustPools) (ObservationAdapterBinding, error) {
	var trust remoteMailTrust
	var config remoteMailConfig
	if decodeRemote(trustBytes, &trust) != nil || decodeRemote(configBytes, &config) != nil ||
		trust.SourceType != "MAIL" || config.SourceType != "MAIL" || trust.ConnectionID != target.ConnectionID ||
		trust.SchemaVersion != "source-imap-trust-v1" || config.SchemaVersion != "source-imap-config-v1" || config.Endpoint != trust.Endpoint {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_INVALID", nil)
	}
	since, err := parseCanonicalSince(config.Since)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_INVALID", err)
	}
	canonicalTrust, err := canon.MailTrustBytes(trust.ConnectionID, trust.Endpoint, trust.Username)
	if err != nil || !bytes.Equal(canonicalTrust, trustBytes) {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_INVALID", err)
	}
	canonicalConfig, err := canon.MailScopeConfigBytes(config.Endpoint, config.Mailbox, config.Folder, since,
		config.IncludeAttachments, config.MaxMessageBytes, config.MaxAttachmentBytes, config.AttachmentMediaTypes)
	if err != nil || !bytes.Equal(canonicalConfig, configBytes) {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONFIG_INVALID", err)
	}
	if sourceTrust.MailRoots == nil || len(sourceTrust.MailRoots.Subjects()) == 0 {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_TRUST_UNAVAILABLE", nil)
	}
	pool := sourceTrust.MailRoots
	credential, err := resolver.secrets.ResolveReference(ctx, credentialReference)
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CREDENTIAL_UNAVAILABLE", err)
	}
	connector, err := mail.New(mail.Config{Endpoint: trust.Endpoint, Mailbox: config.Mailbox, Folder: config.Folder,
		Username: trust.Username, Password: credential, Since: since, IncludeAttachments: config.IncludeAttachments,
		MaxMessageBytes: config.MaxMessageBytes, MaxAttachmentBytes: config.MaxAttachmentBytes,
		AttachmentMediaTypes: config.AttachmentMediaTypes, TrustRoots: pool})
	credential = ""
	if err != nil {
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONNECTOR_INVALID", err)
	}
	adapter, err := observation.NewMailAdapter(connector, access.OrganizationID, target.SourceScopeID, target.SourceScopeRevision)
	if err != nil {
		_ = connector.Close()
		return ObservationAdapterBinding{}, failure("INGEST_REMOTE_CONNECTOR_INVALID", err)
	}
	return ObservationAdapterBinding{Adapter: adapter, Formats: mailFormats(config.IncludeAttachments, config.AttachmentMediaTypes), Close: adapter.Close}, nil
}

func (resolver *RemoteObservationAdapterResolver) credentialReference(ctx context.Context, access database.AccessContext,
	scopeID string, revision int64) (string, error) {
	var reference string
	err := resolver.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.source_scope_credential_reference($1,$2)`, scopeID, revision).Scan(&reference)
	})
	if err != nil || reference == "" {
		return "", err
	}
	return reference, nil
}

func (resolver *RemoteObservationAdapterResolver) readArtifact(ctx context.Context, access database.AccessContext,
	field artifactcrypto.OwnerField, resourceID, expectedHash string) ([]byte, error) {
	var plaintext []byte
	err := resolver.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		owner, envelope, err := resolver.repository.Fetch(ctx, tx, access, field, resourceID)
		if err != nil {
			return err
		}
		plaintext, err = resolver.codec.Open(owner, envelope)
		return err
	})
	if err != nil {
		clearRemoteBytes(plaintext)
		return nil, err
	}
	if canon.Hash(plaintext) != expectedHash {
		clearRemoteBytes(plaintext)
		return nil, failure("INGEST_REMOTE_ARTIFACT_HASH_MISMATCH", nil)
	}
	return plaintext, nil
}

func decodeRemote(raw []byte, out any) error {
	if len(raw) == 0 || out == nil {
		return failure("INGEST_REMOTE_CONFIG_INVALID", nil)
	}
	return jsonv2.Unmarshal(jsontext.Value(raw), out, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
}

func parseCanonicalSince(value *string) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, *value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != *value {
		return nil, failure("INGEST_REMOTE_CONFIG_INVALID", nil)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func gitFormats(mediaTypes []string) map[string]bool {
	formats := make(map[string]bool)
	for _, mediaType := range mediaTypes {
		switch strings.ToLower(strings.TrimSpace(mediaType)) {
		case "text/plain":
			formats["TXT"], formats["CSV"], formats["EML"] = true, true, true
		case "text/markdown":
			formats["MARKDOWN"] = true
		case "text/html":
			formats["HTML"] = true
		case "application/json":
			formats["JSON"] = true
		case "application/xml":
			formats["XML"] = true
		case "application/javascript", "text/x-go", "text/x-rust", "text/x-java-source":
			formats["SOURCE_CODE"] = true
		}
	}
	return formats
}

func mailFormats(includeAttachments bool, mediaTypes []string) map[string]bool {
	formats := map[string]bool{"EML": true}
	if !includeAttachments {
		return formats
	}
	for _, mediaType := range mediaTypes {
		switch strings.ToLower(strings.TrimSpace(mediaType)) {
		case "text/plain":
			formats["TXT"] = true
		case "text/markdown":
			formats["MARKDOWN"] = true
		case "text/html":
			formats["HTML"] = true
		case "application/json":
			formats["JSON"] = true
		case "application/xml":
			formats["XML"] = true
		case "application/pdf":
			formats["PDF"] = true
		case "image/png":
			formats["PNG"] = true
		case "image/jpeg":
			formats["JPEG"] = true
		case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
			formats["DOCX"] = true
		case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
			formats["XLSX"] = true
		case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
			formats["PPTX"] = true
		}
	}
	return formats
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 {
		return false
	}
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validRemoteOpaque(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func clearRemoteBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ ObservationAdapterResolver = (*RemoteObservationAdapterResolver)(nil)
