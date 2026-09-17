package operator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
)

// Secret file layout is fixed by the knowvault-secret-manifest-v1 wire
// contract (docs/WORKER_OPERATIONS.md). Filenames are operator constants;
// references, versions and key material travel through the manifest.
const (
	manifestFilename         = "manifest.json"
	databaseURLFile          = "db_url"
	identityKeyFile          = "identity_key"
	sessionKeyFile           = "session_key"
	sourceDigestFile         = "source_digest_key"
	transportKeyFile         = "transport_key"
	artifactWrapFile         = "artifact_kek"
	clientSecretFile         = "client_secret"
	clientRevision           = int64(1)
	keyMaterialBytes         = 32
	maximumSourceCredentials = 64
	maxSourceCredentialBytes = 4 << 10
	// The published shape matches the image contract exactly
	// (deploy/images/README.md): files mode 0440, the mount root mode 0750,
	// owned by root and the selected consumer's fixed group. Files become
	// group-readable only after the write is complete.
	secretFileMode     = 0o440
	writePrivateMode   = 0o400
	mountDirMode       = 0o750
	manifestSchemaName = "knowvault-secret-manifest-v1"
)

// RuntimeGID is the server group used for pre-issued operator input files.
// The operator exposes the value so its CLI input boundary can validate a
// group-readable pre-issued secret without importing the mounted capability
// package into the executable layer.
const RuntimeGID = secretmount.RuntimeGID

// SecretManifestConfig is the closed input of one secrets generation run.
type SecretManifestConfig struct {
	// Consumer is server (also the default) or worker. Ownership is chosen
	// before publication and is verified using that one consumer's loader.
	Consumer string
	// KeysFromConsumer independently selects the trusted source mount owner.
	KeysFromConsumer string
	MountRoot        string
	OrganizationID   identity.OrganizationID
	ProviderID       identity.ProviderID
	DatabaseURL      []byte
	ClientReference  string
	// ClientSecret is the exact opaque OIDC client secret read from the
	// required protected input file by the operator command. It is copied
	// byte-for-byte into the mount; the operator never generates this value.
	ClientSecret []byte
	// SourceCredentials are opaque connector credentials keyed by the exact
	// reference persisted in a source connection revision. They are mounted
	// separately from the OIDC client credential and are never emitted in
	// diagnostics. A worker generated with KeysFromRoot copies the complete
	// source-credential set from the trusted source mount.
	SourceCredentials []SourceCredential
	// KeysFromRoot, when set, reuses the exact key material, references and
	// keys of an existing trusted mount. The imported ClientSecret remains the
	// source of truth for the destination mount. Only the database identity
	// differs; used for the worker mount, which shares the server's key set by
	// contract.
	KeysFromRoot string
}

// SourceCredential is one operator-supplied, protected connector credential.
// The value is copied byte-for-byte into the mount and must be cleared by the
// caller after GenerateSecrets returns.
type SourceCredential struct {
	Reference string
	Secret    []byte
}

// String and GoString deliberately redact the closed generation input. The
// configuration carries database and OIDC secret bytes and must be safe when
// included in diagnostics or %#v output.
func (SecretManifestConfig) String() string   { return "operator.SecretManifestConfig{[REDACTED]}" }
func (SecretManifestConfig) GoString() string { return "operator.SecretManifestConfig{[REDACTED]}" }

// GeneratedSecret is one written file of a generated mount.
type GeneratedSecret struct {
	Path      string `json:"path"`
	Purpose   string `json:"purpose"`
	Reference string `json:"reference"`
}

// GenerateSecretsResult reports a completed generation run. Every written
// file was verified through the product mount loader before returning.
type GenerateSecretsResult struct {
	MountRoot string            `json:"mount_root"`
	Files     []GeneratedSecret `json:"files"`
}

// GenerateSecrets writes one complete knowvault-secret-manifest-v1 mount. It
// refuses to overwrite an existing manifest (mount regeneration is a
// separate, reviewed rotation path), validates the database URL and imported
// OIDC client secret through the product contracts before writing, and
// re-verifies the written mount through secretmount.LoadMounted before
// reporting success. With KeysFromRoot the same verification loads the source
// mount first and the generated mount reuses its key set verbatim while still
// requiring the caller's imported client secret.
func GenerateSecrets(ctx context.Context, config SecretManifestConfig) (*GenerateSecretsResult, error) {
	if ctx == nil {
		return nil, DependencyUnavailable("nil context")
	}
	if config.MountRoot == "" {
		return nil, MigrationIncompatible("mount root is required")
	}
	consumer, valid := secretMountConsumer(config.Consumer)
	if !valid {
		return nil, MigrationIncompatible("secret consumer must be server or worker")
	}
	if sourceConsumer, valid := secretMountConsumer(config.KeysFromConsumer); !valid || (config.KeysFromRoot == "" && sourceConsumer != runtimeidentity.Server) {
		return nil, MigrationIncompatible("invalid key-source consumer")
	}
	// Organization, provider and client reference become mount material and are
	// resolved by the product loader, so they must satisfy the same shared ID
	// shape the loader enforces (secretmount.ValidID). Accepting a wider shape
	// here would register deployment state the product can never load.
	if !secretmount.ValidID(string(config.OrganizationID)) || !secretmount.ValidID(string(config.ProviderID)) {
		return nil, MigrationIncompatible("organization and provider fail the shared manifest-id shape")
	}
	if !secretmount.ValidID(config.ClientReference) {
		return nil, MigrationIncompatible("client reference fails the shared manifest-id shape")
	}
	// The IdP client secret is deployment input, never generated material. The
	// command reads it from the mandatory protected file and this second check
	// keeps direct package callers on the same fail-closed contract.
	if !validMountedClientSecret(config.ClientSecret) {
		return nil, MountInvalid("client secret is missing or malformed")
	}
	if err := validateSourceCredentials(config.SourceCredentials, config.ClientReference); err != nil {
		return nil, err
	}
	if err := secretmount.ValidateDatabaseURL(config.DatabaseURL); err != nil {
		return nil, MountInvalid("database URL fails the production contract")
	}
	// The operator-side database identity must target exactly the production
	// database; a same-shape path like /knowvault_test is a deployment error
	// caught before any write.
	if parsed, err := url.Parse(string(config.DatabaseURL)); err != nil || parsed.Path != "/knowvault" {
		return nil, MountInvalid("database URL path must be exactly /knowvault")
	}
	// The mount boundary is proven before the first write: on this host the
	// target must not be redirectable between validation and generation. The
	// written mount is re-verified through the product loader afterwards.
	if err := verifyMountBoundary(config.MountRoot); err != nil {
		return nil, MountInvalid("mount boundary check failed: " + err.Error())
	}
	// Check before chmod/chown: a wrong consumer must not change an existing
	// consumable mount and then merely report that generation was refused.
	if _, err := os.Lstat(filepath.Join(config.MountRoot, manifestFilename)); err == nil {
		return nil, MountInvalid("mount root already carries a manifest; generation refuses to overwrite")
	} else if !os.IsNotExist(err) {
		return nil, DependencyUnavailable("mount root stat failed: " + err.Error())
	}

	if err := os.MkdirAll(config.MountRoot, mountDirMode); err != nil {
		return nil, DependencyUnavailable("mount root creation failed: " + err.Error())
	}
	if err := os.Chmod(config.MountRoot, mountDirMode); err != nil {
		return nil, DependencyUnavailable("mount root permissions failed: " + err.Error())
	}
	if err := setConsumerGroup(config.MountRoot, consumer); err != nil {
		return nil, DependencyUnavailable("mount root group assignment failed: " + err.Error())
	}

	material := &generatedMaterial{}
	defer material.clearSecrets()
	if config.KeysFromRoot != "" {
		if err := material.reuse(ctx, config); err != nil {
			return nil, err
		}
	} else {
		if err := material.generate(); err != nil {
			return nil, DependencyUnavailable("key generation failed: " + err.Error())
		}
		// Preserve the imported representation exactly. In particular, do not
		// trim, decode, encode or otherwise reinterpret an OIDC client secret.
		material.clientSecret = append([]byte(nil), config.ClientSecret...)
		material.sourceCredentials = copySourceCredentials(config.SourceCredentials)
	}

	if err := writeManifestFiles(config.MountRoot, config, material); err != nil {
		return nil, err
	}
	// The written mount must load through the product path before the operator
	// reports success. On platforms where mounted roots are unavailable by
	// design the product loader reports CodeUnavailable and generation fails
	// closed instead of claiming a verified mount.
	provider, err := loadSecretMount(config.MountRoot, config.OrganizationID, config.ProviderID, config.Consumer)
	if err != nil {
		return nil, MountInvalid("generated mount failed product verification (" + string(secretmount.CodeOf(err)) + ")")
	}
	provider.Close()
	return &GenerateSecretsResult{MountRoot: config.MountRoot, Files: material.files(config.MountRoot)}, nil
}

// VerifyMount applies the product mount loader to an existing mount and
// reports typed failure codes without modifying anything.
func VerifyMount(ctx context.Context, mountRoot string, organizationID identity.OrganizationID, providerID identity.ProviderID) error {
	return VerifyMountForConsumer(ctx, mountRoot, organizationID, providerID, "server")
}

// VerifyMountForConsumer validates exactly the selected deployment consumer;
// it never tries a second ownership profile after a failure.
func VerifyMountForConsumer(ctx context.Context, mountRoot string, organizationID identity.OrganizationID, providerID identity.ProviderID, consumer string) error {
	if ctx == nil {
		return DependencyUnavailable("nil context")
	}
	provider, err := loadSecretMount(mountRoot, organizationID, providerID, consumer)
	if err != nil {
		return MountInvalid("mount verification failed (" + string(secretmount.CodeOf(err)) + ")")
	}
	provider.Close()
	return nil
}

func secretMountConsumer(value string) (runtimeidentity.MountConsumer, bool) {
	switch value {
	case "", "server":
		return runtimeidentity.Server, true
	case "worker":
		return runtimeidentity.Worker, true
	default:
		return 0, false
	}
}

func loadSecretMount(root string, organizationID identity.OrganizationID, providerID identity.ProviderID, name string) (*secretmount.Provider, error) {
	consumer, valid := secretMountConsumer(name)
	if !valid {
		return nil, MigrationIncompatible("secret consumer must be server or worker")
	}
	if consumer == runtimeidentity.Worker {
		return secretmount.LoadWorkerMounted(root, organizationID, providerID)
	}
	return secretmount.LoadMounted(root, organizationID, providerID)
}

type generatedMaterial struct {
	identity        []byte
	identityRef     string
	identityVer     uint32
	session         []byte
	sessionRef      string
	sessionVer      uint32
	sourceDigest    []byte
	sourceDigestRef string
	sourceDigestVer uint32
	transport       []byte
	transportRef    string
	transportKeyID  string
	artifactWrap    []byte
	artifactWrapRef string
	artifactWrapVer uint32
	// clientSecret is the ready-to-mount opaque printable representation. Newly
	// generated material is canonical unpadded base64url text; a trusted source
	// mount is copied byte-for-byte without another encoding pass.
	clientSecret      []byte
	sourceCredentials []generatedSourceCredential
}

type generatedSourceCredential struct {
	reference string
	filename  string
	secret    []byte
}

func (generatedMaterial) String() string   { return "operator.generatedMaterial{[REDACTED]}" }
func (generatedMaterial) GoString() string { return "operator.generatedMaterial{[REDACTED]}" }

func (material *generatedMaterial) generate() error {
	var err error
	if material.identity, err = randomBytes(keyMaterialBytes); err != nil {
		return err
	}
	if material.session, err = randomBytes(keyMaterialBytes); err != nil {
		return err
	}
	if material.sourceDigest, err = randomBytes(keyMaterialBytes); err != nil {
		return err
	}
	if material.transport, err = randomBytes(keyMaterialBytes); err != nil {
		return err
	}
	if material.artifactWrap, err = randomBytes(keyMaterialBytes); err != nil {
		return err
	}
	material.identityRef, material.identityVer = "identity_hmac_v1", 1
	material.sessionRef, material.sessionVer = "session_hmac_v1", 1
	material.sourceDigestRef, material.sourceDigestVer = "source_digest_hmac_v1", 1
	material.transportRef, material.transportKeyID = "transport_aead_v1", "transport_key_v1"
	material.artifactWrapRef, material.artifactWrapVer = "artifact_kek_v1", 1
	return nil
}

// reuse copies the exact key set of an existing trusted mount through the
// product capability API. No raw manifest is parsed by the operator.
func (material *generatedMaterial) reuse(ctx context.Context, config SecretManifestConfig) error {
	source, err := loadSecretMount(config.KeysFromRoot, config.OrganizationID, config.ProviderID, config.KeysFromConsumer)
	if err != nil {
		return MountInvalid("keys-from mount failed product verification (" + string(secretmount.CodeOf(err)) + ")")
	}
	defer source.Close()
	identityKey, err := source.IdentityKey()
	if err != nil {
		return MountInvalid("keys-from mount carries no valid identity key")
	}
	sessionKey, err := source.SessionKey()
	if err != nil {
		return MountInvalid("keys-from mount carries no valid session key")
	}
	digestKey, err := source.SourceDigestKey()
	if err != nil {
		return MountInvalid("keys-from mount carries no valid source digest key")
	}
	transportKey, err := source.OIDCTransportKey()
	if err != nil {
		return MountInvalid("keys-from mount carries no valid transport key")
	}
	wrapKey, err := source.ArtifactWrapKey()
	if err != nil {
		return MountInvalid("keys-from mount carries no valid artifact wrap key")
	}
	// A rotation window open in the source mount is deliberately not copied:
	// the worker mount is generated only for the active pair set. An in-flight
	// rotation regenerates the dependent mount through the documented path.
	if _, open, err := source.ArtifactWrapKeyPrevious(); err != nil || open {
		if err != nil {
			return MountInvalid("keys-from mount previous-pair state unreadable")
		}
		return MigrationIncompatible("keys-from mount has an open rotation window; complete rotation first")
	}
	secret, err := source.Resolve(ctx, oidcweb.ClientSecretRequest{
		OrganizationID: config.OrganizationID, ProviderID: config.ProviderID,
		ProviderRevision: clientRevision, Reference: config.ClientReference,
	})
	if err != nil {
		return MountInvalid("keys-from mount carries no client secret for the requested reference")
	}
	// Resolve returns a product-validated opaque mount string. Preserve that
	// representation exactly: encoding it again would change the secret.
	if !validMountedClientSecret([]byte(secret)) {
		return MountInvalid("keys-from mount carries malformed client secret material")
	}
	// A worker mount must use the same pre-issued IdP credential as its source
	// mount. Compare in memory without ever placing either value in a failure
	// detail, then copy the caller's exact bytes into the destination.
	if !bytes.Equal([]byte(secret), config.ClientSecret) {
		return MountInvalid("keys-from mount client secret does not match imported client secret")
	}
	material.identity = identityKey.Bytes()
	material.identityRef, material.identityVer = identityKey.Reference(), identityKey.Version()
	material.session = sessionKey.Bytes()
	material.sessionRef, material.sessionVer = sessionKey.Reference(), sessionKey.Version()
	material.sourceDigest = digestKey.Bytes()
	material.sourceDigestRef, material.sourceDigestVer = digestKey.Reference(), digestKey.Version()
	material.transport = transportKey.Bytes()
	material.transportRef, material.transportKeyID = transportKey.Reference(), transportKey.KeyID()
	material.artifactWrap = wrapKey.Bytes()
	material.artifactWrapRef, material.artifactWrapVer = wrapKey.Reference(), wrapKey.Version()
	material.clientSecret = append([]byte(nil), config.ClientSecret...)
	references, err := source.SourceCredentialReferences()
	if err != nil {
		return MountInvalid("keys-from mount source credential inventory is unavailable")
	}
	if len(config.SourceCredentials) > 0 {
		if len(config.SourceCredentials) != len(references) {
			return MountInvalid("keys-from mount source credential set does not match requested set")
		}
		requested := make(map[string][]byte, len(config.SourceCredentials))
		for _, credential := range config.SourceCredentials {
			requested[credential.Reference] = credential.Secret
		}
		for _, reference := range references {
			secret, resolveErr := source.ResolveReference(ctx, reference)
			if resolveErr != nil || !bytes.Equal([]byte(secret), requested[reference]) {
				clear([]byte(secret))
				return MountInvalid("keys-from mount source credential does not match imported material")
			}
			clear([]byte(secret))
		}
	}
	for index, reference := range references {
		secret, resolveErr := source.ResolveReference(ctx, reference)
		if resolveErr != nil || !validMountedSourceCredential([]byte(secret)) {
			clear([]byte(secret))
			return MountInvalid("keys-from mount source credential is unavailable")
		}
		material.sourceCredentials = append(material.sourceCredentials, generatedSourceCredential{
			reference: reference, filename: sourceCredentialFilename(index), secret: append([]byte(nil), secret...),
		})
		clear([]byte(secret))
	}
	return nil
}

func (material *generatedMaterial) clearSecrets() {
	clear(material.clientSecret)
	material.clientSecret = nil
	for index := range material.sourceCredentials {
		clear(material.sourceCredentials[index].secret)
		material.sourceCredentials[index].secret = nil
	}
	material.sourceCredentials = nil
}

func randomBytes(count int) ([]byte, error) {
	raw := make([]byte, count)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

type manifestWire struct {
	Schema            string                 `json:"schema"`
	OrganizationID    string                 `json:"organization_id"`
	ProviderID        string                 `json:"provider_id"`
	DatabaseURLFile   string                 `json:"database_url_file"`
	IdentityHMAC      versionedKeyWire       `json:"identity_hmac"`
	SessionHMAC       versionedKeyWire       `json:"session_hmac"`
	SourceDigestHMAC  versionedKeyWire       `json:"source_digest_hmac"`
	OIDCTransportAEAD transportKeyWire       `json:"oidc_transport_aead"`
	ArtifactWrapKEK   versionedKeyWire       `json:"artifact_kek"`
	OIDCClients       []clientSecretWire     `json:"oidc_client_secrets"`
	SourceCredentials []sourceCredentialWire `json:"source_credentials,omitempty"`
}

type versionedKeyWire struct {
	Reference string `json:"reference"`
	Version   uint32 `json:"version"`
	Filename  string `json:"filename"`
}

type transportKeyWire struct {
	Reference string `json:"reference"`
	KeyID     string `json:"key_id"`
	Filename  string `json:"filename"`
}

type clientSecretWire struct {
	OrganizationID   string `json:"organization_id"`
	ProviderID       string `json:"provider_id"`
	ProviderRevision int64  `json:"provider_revision"`
	Reference        string `json:"reference"`
	Filename         string `json:"filename"`
}

type sourceCredentialWire struct {
	Reference string `json:"reference"`
	Filename  string `json:"filename"`
}

func writeManifestFiles(root string, config SecretManifestConfig, material *generatedMaterial) error {
	consumer, valid := secretMountConsumer(config.Consumer)
	if !valid {
		return MigrationIncompatible("secret consumer must be server or worker")
	}
	if !validGeneratedMaterial(material) {
		return MountInvalid("secret material is malformed")
	}
	for _, credential := range material.sourceCredentials {
		if credential.reference == config.ClientReference {
			return MountInvalid("source credential reference collides with OIDC reference")
		}
	}
	wire := manifestWire{
		Schema:            manifestSchemaName,
		OrganizationID:    string(config.OrganizationID),
		ProviderID:        string(config.ProviderID),
		DatabaseURLFile:   databaseURLFile,
		IdentityHMAC:      versionedKeyWire{Reference: material.identityRef, Version: material.identityVer, Filename: identityKeyFile},
		SessionHMAC:       versionedKeyWire{Reference: material.sessionRef, Version: material.sessionVer, Filename: sessionKeyFile},
		SourceDigestHMAC:  versionedKeyWire{Reference: material.sourceDigestRef, Version: material.sourceDigestVer, Filename: sourceDigestFile},
		OIDCTransportAEAD: transportKeyWire{Reference: material.transportRef, KeyID: material.transportKeyID, Filename: transportKeyFile},
		ArtifactWrapKEK:   versionedKeyWire{Reference: material.artifactWrapRef, Version: material.artifactWrapVer, Filename: artifactWrapFile},
		OIDCClients: []clientSecretWire{{
			OrganizationID: string(config.OrganizationID), ProviderID: string(config.ProviderID),
			ProviderRevision: clientRevision, Reference: config.ClientReference, Filename: clientSecretFile,
		}},
	}
	for _, credential := range material.sourceCredentials {
		wire.SourceCredentials = append(wire.SourceCredentials, sourceCredentialWire{
			Reference: credential.reference,
			Filename:  credential.filename,
		})
	}
	files := []struct {
		filename string
		contents []byte
	}{
		{databaseURLFile, config.DatabaseURL},
		{identityKeyFile, []byte(base64.RawURLEncoding.EncodeToString(material.identity))},
		{sessionKeyFile, []byte(base64.RawURLEncoding.EncodeToString(material.session))},
		{sourceDigestFile, []byte(base64.RawURLEncoding.EncodeToString(material.sourceDigest))},
		{transportKeyFile, []byte(base64.RawURLEncoding.EncodeToString(material.transport))},
		{artifactWrapFile, []byte(base64.RawURLEncoding.EncodeToString(material.artifactWrap))},
		{clientSecretFile, material.clientSecret},
	}
	for _, credential := range material.sourceCredentials {
		files = append(files, struct {
			filename string
			contents []byte
		}{credential.filename, credential.secret})
	}
	for _, file := range files {
		path := filepath.Join(root, file.filename)
		if err := writeAtomicForConsumer(path, file.contents, consumer); err != nil {
			return MountInvalid("secret file write failed for " + file.filename + ": " + err.Error())
		}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return DependencyUnavailable("manifest encoding failed: " + err.Error())
	}
	if err := writeAtomicForConsumer(filepath.Join(root, manifestFilename), raw, consumer); err != nil {
		return MountInvalid("manifest write failed: " + err.Error())
	}
	return nil
}

func validGeneratedMaterial(material *generatedMaterial) bool {
	if material == nil {
		return false
	}
	for _, key := range [][]byte{
		material.identity, material.session, material.sourceDigest, material.transport, material.artifactWrap,
	} {
		if len(key) != keyMaterialBytes {
			return false
		}
		nonzero := false
		for _, octet := range key {
			if octet != 0 {
				nonzero = true
				break
			}
		}
		if !nonzero {
			return false
		}
	}
	if !validMountedClientSecret(material.clientSecret) {
		return false
	}
	if len(material.sourceCredentials) > maximumSourceCredentials {
		return false
	}
	seenReferences := make(map[string]struct{}, len(material.sourceCredentials))
	seenFiles := map[string]struct{}{
		databaseURLFile: {}, identityKeyFile: {}, sessionKeyFile: {}, sourceDigestFile: {},
		transportKeyFile: {}, artifactWrapFile: {}, clientSecretFile: {},
	}
	for _, credential := range material.sourceCredentials {
		if !secretmount.ValidID(credential.reference) || !validGeneratedFilename(credential.filename) || !validMountedSourceCredential(credential.secret) {
			return false
		}
		if _, exists := seenReferences[credential.reference]; exists {
			return false
		}
		if _, exists := seenFiles[credential.filename]; exists {
			return false
		}
		seenReferences[credential.reference] = struct{}{}
		seenFiles[credential.filename] = struct{}{}
	}
	return secretmount.ValidID(material.identityRef) && material.identityVer > 0 &&
		secretmount.ValidID(material.sessionRef) && material.sessionVer > 0 &&
		secretmount.ValidID(material.sourceDigestRef) && material.sourceDigestVer > 0 &&
		secretmount.ValidID(material.transportRef) && secretmount.ValidID(material.transportKeyID) &&
		secretmount.ValidID(material.artifactWrapRef) && material.artifactWrapVer > 0
}

func validGeneratedFilename(value string) bool {
	return value != "" && value != "." && value != ".." && len(value) <= 128 && secretmount.ValidID(value) && !strings.ContainsAny(value, `/\\`)
}

// validMountedClientSecret mirrors secretmount's existing opaque client-secret
// contract. It deliberately does not require base64: deployed IdP secrets are
// opaque bounded printable mount text and must be copied without an encoding
// pass.
func validMountedClientSecret(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 4<<10 || !utf8.Valid(raw) {
		return false
	}
	for _, character := range string(raw) {
		if character == 0 || character == '\r' || character == '\n' ||
			(character < 0x20 || (character >= 0x7f && character <= 0x9f)) {
			return false
		}
	}
	return true
}

func validMountedSourceCredential(raw []byte) bool {
	return len(raw) > 0 && len(raw) <= maxSourceCredentialBytes && validMountedClientSecret(raw)
}

func validateSourceCredentials(credentials []SourceCredential, clientReference string) error {
	if len(credentials) > maximumSourceCredentials {
		return MigrationIncompatible("too many source credentials")
	}
	seen := make(map[string]struct{}, len(credentials)+1)
	seen[clientReference] = struct{}{}
	for _, credential := range credentials {
		if !secretmount.ValidID(credential.Reference) {
			return MigrationIncompatible("source credential reference fails the shared manifest-id shape")
		}
		if _, exists := seen[credential.Reference]; exists {
			return MigrationIncompatible("source credential reference is duplicated or collides with the OIDC reference")
		}
		if !validMountedSourceCredential(credential.Secret) {
			return MountInvalid("source credential is missing or malformed")
		}
		seen[credential.Reference] = struct{}{}
	}
	return nil
}

func copySourceCredentials(credentials []SourceCredential) []generatedSourceCredential {
	result := make([]generatedSourceCredential, 0, len(credentials))
	for index, credential := range credentials {
		result = append(result, generatedSourceCredential{
			reference: credential.Reference,
			filename:  sourceCredentialFilename(index),
			secret:    append([]byte(nil), credential.Secret...),
		})
	}
	return result
}

func sourceCredentialFilename(index int) string {
	return fmt.Sprintf("source_credential_%03d", index+1)
}

// writeAtomic publishes one secret file through a temporary name and a
// no-overwrite hard-link publish: a crash mid-write leaves at most a private
// temporary file, and a concurrent writer can never replace or follow an
// existing path (the link fails with EEXIST). Filesystems without hard-link
// support fail closed rather than degrading to an overwriting rename.
//
// Privacy ordering: the temporary file is write-private (0400) while the
// content is written and synced; the published group-readable mode (0440) and
// the pinned runtime group are applied only after the file is complete, so
// the runtime group can never observe partial key material.
func writeAtomic(path string, contents []byte) error {
	return writeAtomicForConsumer(path, contents, runtimeidentity.Server)
}

func writeAtomicForConsumer(path string, contents []byte, consumer runtimeidentity.MountConsumer) error {
	if _, valid := consumer.GroupID(); !valid {
		return MigrationIncompatible("invalid secret consumer")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(writePrivateMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := setConsumerGroup(temporaryName, consumer); err != nil {
		return err
	}
	if err := os.Chmod(temporaryName, secretFileMode); err != nil {
		return err
	}
	if err := os.Link(temporaryName, path); err != nil {
		return err
	}
	// The publish succeeded; a leftover temporary file on a failed cleanup is
	// inert (the product loader only reads the fixed file set).
	removeTemporary = false
	_ = os.Remove(temporaryName)
	return nil
}

func (material *generatedMaterial) files(root string) []GeneratedSecret {
	files := []GeneratedSecret{
		{Path: filepath.Join(root, manifestFilename), Purpose: "manifest"},
		{Path: filepath.Join(root, databaseURLFile), Purpose: "database_url"},
		{Path: filepath.Join(root, identityKeyFile), Purpose: "identity_hmac", Reference: material.identityRef},
		{Path: filepath.Join(root, sessionKeyFile), Purpose: "session_hmac", Reference: material.sessionRef},
		{Path: filepath.Join(root, sourceDigestFile), Purpose: "source_digest_hmac", Reference: material.sourceDigestRef},
		{Path: filepath.Join(root, transportKeyFile), Purpose: "oidc_transport_aead", Reference: material.transportRef},
		{Path: filepath.Join(root, artifactWrapFile), Purpose: "artifact_kek", Reference: material.artifactWrapRef},
		{Path: filepath.Join(root, clientSecretFile), Purpose: "oidc_client_secret"},
	}
	for _, credential := range material.sourceCredentials {
		files = append(files, GeneratedSecret{
			Path: filepath.Join(root, credential.filename), Purpose: "source_credential", Reference: credential.reference,
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

// RenderManifestSummary is a human-readable mount inventory for the CLI.
func RenderManifestSummary(result *GenerateSecretsResult) string {
	return fmt.Sprintf("mount written at %s (%d files)", result.MountRoot, len(result.Files))
}
