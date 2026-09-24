// Package registration is the product surface that creates a source
// connection and its WORKSPACE_MANAGED scope (ADR-0074): one Go write
// transaction drives the SECURITY DEFINER lineage insert and the four sealed
// owner-branch artifacts, and an activation request places the durable
// SOURCE_SCOPE_SYNC job through the production queue. All authority stays in
// the SQL gates the functions reuse verbatim (000006/000007/000010/000014/000016);
// this layer adds request-shape validation, the organization-OWNER policy gate
// and typed, content-free error codes.
package registration

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/netcanon"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	sourceupload "knowvault.local/verified-workspace/internal/source/upload"
)

const (
	// Server-side connection revision limits. They are constants of this
	// release, never client-supplied, and every scope bound under the
	// connection must stay within them (000007 policy guard).
	maximumScopeObjects = 10000000
	maximumScopeBytes   = 100000000000
	maximumObjectBytes  = 1000000000
	// Server-side scope revision bounds (000007 CHECK ranges).
	syncIntervalSeconds = 300
	freshnessSLA        = 600
	objectLimit         = 1000000
	byteLimit           = 10000000000
	scopeMaxObjectBytes = 1000000000
	// The registration surface serves WORKSPACE_MANAGED only (ADR-0074 s1.10).
	accessModeManaged = "WORKSPACE_MANAGED"
)

var schemaIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// Service is constructed only at the application composition root.
type Service struct {
	database         *database.Store
	audit            *audit.Store
	codec            *artifactcrypto.Codec
	queue            *jobs.Queue
	digestKey        []byte
	digestKeyVersion int
	now              func() time.Time
	newID            func(prefix string) (string, error)
}

// New binds registration to the reviewed persistence, audit, artifact codec
// and job queue. It fails closed on a nil dependency or a nil digest key.
func New(databaseStore *database.Store, auditStore *audit.Store, codec *artifactcrypto.Codec,
	queue *jobs.Queue, digestKey []byte, digestKeyVersion int) (*Service, error) {
	if databaseStore == nil || auditStore == nil || codec == nil || queue == nil || len(digestKey) != 32 || digestKeyVersion < 1 {
		return nil, &Error{code: CodePersistence}
	}
	return &Service{
		database: databaseStore, audit: auditStore, codec: codec, queue: queue,
		digestKey: append([]byte(nil), digestKey...), digestKeyVersion: digestKeyVersion,
		now: time.Now, newID: ids.New,
	}, nil
}

// RegisterRequest contains the caller-supplied source registration fields.
// Every id, revision, digest, hash, limit and access mode is server-derived or
// server-constant; nothing here becomes an identifier.
type RegisterRequest struct {
	// SourceType is empty or FOLDER for the original mounted-folder surface.
	// POSTGRESQL_QUERY selects the immutable DBA-managed projection path below.
	SourceType   string
	Name         string
	RootAlias    string
	RootIdentity string
	RelativeRoot string
	Kind         string
	Recursive    bool
	IncludeGlobs []string
	ExcludeGlobs []string
	MaxFileBytes int64
	OCRMode      string
	Formats      []string
	// PostgreSQL query projection fields. They are ignored for FOLDER requests.
	DatabaseIdentity string
	// CredentialReference names an opaque worker-mounted source credential.
	// The secret itself never enters the request or catalog. Empty retains the
	// deterministic reference used by older callers.
	CredentialReference string
	LineageID           string
	ProjectionRevision  int64
	ContractHash        string
	SchemaName          string
	RelationName        string
	RelationKind        string
	Columns             []postgresqlquery.Column
	EmptySnapshotPolicy string
	MaxRows             int64
	MaxColumns          int
	MaxFieldBytes       int64
	MaxRowBytes         int64
	MaxTotalBytes       int64
	StatementTimeoutMS  int
	// SyncIntervalSeconds is the operator-chosen schedule for this scope's
	// autonomous worker sync (V1-A). Zero keeps the previous fixed default.
	// It is not part of the content contract (postgreSQLProjection/config
	// hash), matching the existing sync_interval_seconds column, which a
	// same-lineage revision may change without a new projection lineage.
	SyncIntervalSeconds int
	// Git HTTPS source fields.  The access token is never accepted here; only
	// its opaque mounted credential reference may be supplied.
	Provider       string
	Endpoint       string
	WebBaseURL     string
	RepositoryID   string
	BranchName     string
	TextMediaTypes []string
	MaxBlobBytes   int64
	// IMAP source fields.  Password material is resolved only by the worker's
	// deployment-owned secret provider.
	Mailbox              string
	Folder               string
	Username             string
	Since                *time.Time
	IncludeAttachments   bool
	MaxMessageBytes      int64
	MaxAttachmentBytes   int64
	AttachmentMediaTypes []string
}

// RegisterResult is the content-derived identity of the registration. A replay
// returns the same ids with Created=false.
type RegisterResult struct {
	ConnectionID string
	// CredentialReference is safe opaque metadata, never credential bytes.
	// It is the exact source-mount reference bound to this connection revision
	// so operators can provision the worker mount without guessing an id.
	CredentialReference string
	SourceScopeID       string
	DiscoveredScopeID   string
	Revision            int64
	ScopeConfigHash     string
	AccessMode          string
	Created             bool
}

// Register creates the full Stage 2 DRAFT lineage in one write transaction:
// connection, revision 1, trust record and DRAFT projection, discovered scope,
// scope, revision 1, DRAFT activation, then the four sealed artifacts the
// owning rows already reference. It is idempotent by content derivation: a
// replay converges on created=false, a lineage collision with a different
// configuration is a typed conflict, and a concurrent first registration
// retries once and converges on the winner's rows.
func (s *Service) Register(ctx context.Context, access database.AccessContext, request RegisterRequest) (RegisterResult, error) {
	if s == nil || s.database == nil || s.audit == nil || s.codec == nil || access.Validate() != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	if request.isPostgreSQLQuery() {
		if err := request.validatePostgreSQLQuery(); err != nil {
			return RegisterResult{}, err
		}
		return s.registerPostgreSQLQuery(ctx, access, request)
	}
	if request.SourceType == "GIT" || request.SourceType == "MAIL" {
		if err := request.validateRemote(); err != nil {
			return RegisterResult{}, err
		}
		return s.registerRemote(ctx, access, request)
	}
	if err := request.validate(); err != nil {
		return RegisterResult{}, err
	}
	result, err := s.registerOnce(ctx, access, request)
	if err == nil {
		return result, nil
	}
	// Typed gate outcomes (denied, unavailable) survive registerOnce unchanged;
	// only raw database failures fall through to the persistence mapping.
	var registrationError *Error
	if errors.As(err, &registrationError) {
		return RegisterResult{}, err
	}
	if !isSQLState(err, "23505") {
		return RegisterResult{}, &Error{code: CodePersistence, cause: err}
	}
	// A concurrent first registration of the same lineage can commit between
	// this pass's check and its insert. One replay converges on created=false;
	// a second conflict is a real configuration collision, never a retry loop.
	result, err = s.registerOnce(ctx, access, request)
	if err != nil {
		if isSQLState(err, "23505") {
			return RegisterResult{}, &Error{code: CodeConflict}
		}
		return RegisterResult{}, &Error{code: CodePersistence, cause: err}
	}
	return result, nil
}

// UploadDocumentsRequest carries the files an owner drops onto an already
// registered FOLDER source. SourceScopeID is resolved to its connection
// exactly like Activate/Sync; every other field of the stored object --
// object key, declared format, media type/family -- is re-derived from
// content by internal/source/upload, never trusted from the caller.
type UploadDocumentsRequest struct {
	SourceScopeID string
	Files         []UploadFile
}

// UploadFile is one caller-supplied file: a display name (used only to derive
// the sanitized object key and to echo back in the result) and its bytes.
type UploadFile struct {
	Name    string
	Content []byte
}

// UploadedDocument is one accepted file's stored, canonical identity.
type UploadedDocument struct {
	Name      string
	ObjectKey string
	Version   int64
	Format    string
	ByteSize  int64
}

type UploadDocumentsResult struct {
	ConnectionID string
	Uploaded     []UploadedDocument
}

// UploadDocuments stores one or more browser-uploaded files as new or
// updated versions of a FOLDER connection's uploaded documents (UPL-1). It is
// deliberately not gated by the organization-OWNER policy Register/Activate
// use: uploading is the individual source owner's right, never a workspace
// participant's, so the only authorization here is
// source_connection.created_by == the calling principal (fail-closed
// otherwise, same content-free SOURCE_DENIED as every other refusal). Audit
// append happens in the same transaction as the writes: a failed append rolls
// every file back, matching the FIX-1 "audit is a condition of the write, not
// a side effect" rule.
func (s *Service) UploadDocuments(ctx context.Context, access database.AccessContext, request UploadDocumentsRequest) (UploadDocumentsResult, error) {
	if s == nil || s.database == nil || s.audit == nil || access.Validate() != nil {
		return UploadDocumentsResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validScopeID(request.SourceScopeID) || len(request.Files) == 0 || len(request.Files) > sourceupload.MaxFilesPerRequest {
		return UploadDocumentsResult{}, &Error{code: CodeRequestInvalid}
	}
	validated := make([]sourceupload.Result, len(request.Files))
	var totalBytes int64
	for i, file := range request.Files {
		result, err := sourceupload.Validate(file.Name, file.Content)
		if err != nil {
			return UploadDocumentsResult{}, &Error{code: CodeUploadRejected, cause: err}
		}
		validated[i] = result
		totalBytes += result.ContentByteSize
	}
	if totalBytes > sourceupload.MaxTotalBytes {
		return UploadDocumentsResult{}, &Error{code: CodeUploadRejected}
	}

	var result UploadDocumentsResult
	err := s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var connectionID, sourceType, ownerPrincipalID string
		if err := tx.QueryRow(ctx, `
			SELECT connection_id, source_type, created_by FROM app.source_scope_upload_target($1)`,
			request.SourceScopeID).Scan(&connectionID, &sourceType, &ownerPrincipalID); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeNotFound}
			}
			return err
		}
		if sourceType != "FOLDER" || ownerPrincipalID != access.PrincipalID {
			return &Error{code: CodeDenied}
		}
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		if _, err := s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceScopeChanged, ResourceType: audit.ResourceSourceScope,
			ResourceID: request.SourceScopeID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(),
			Metadata: audit.Metadata{SourceConnectionID: &connectionID, SourceScopeID: &request.SourceScopeID},
		}); err != nil {
			return err
		}
		uploaded := make([]UploadedDocument, len(request.Files))
		for i, file := range request.Files {
			validatedFile := validated[i]
			var version int64
			if err := tx.QueryRow(ctx, `
				INSERT INTO public.source_uploaded_document
					(organization_id, connection_id, object_key, declared_format, media_type,
					 media_family, byte_size, content_sha256, content, uploaded_by)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (organization_id, connection_id, object_key) DO UPDATE SET
					version = source_uploaded_document.version + 1,
					declared_format = EXCLUDED.declared_format, media_type = EXCLUDED.media_type,
					media_family = EXCLUDED.media_family, byte_size = EXCLUDED.byte_size,
					content_sha256 = EXCLUDED.content_sha256, content = EXCLUDED.content,
					uploaded_by = EXCLUDED.uploaded_by, uploaded_at = transaction_timestamp()
				RETURNING version`,
				access.OrganizationID, connectionID, validatedFile.ObjectKey, validatedFile.DeclaredFormat,
				validatedFile.MediaType, string(validatedFile.MediaFamily), validatedFile.ContentByteSize,
				canon.Hash(file.Content), file.Content, access.PrincipalID).Scan(&version); err != nil {
				return err
			}
			uploaded[i] = UploadedDocument{
				Name: file.Name, ObjectKey: validatedFile.ObjectKey, Version: version,
				Format: validatedFile.DeclaredFormat, ByteSize: validatedFile.ContentByteSize,
			}
		}
		result = UploadDocumentsResult{ConnectionID: connectionID, Uploaded: uploaded}
		return nil
	})
	if err != nil {
		var registrationError *Error
		if errors.As(err, &registrationError) {
			return UploadDocumentsResult{}, err
		}
		return UploadDocumentsResult{}, &Error{code: CodePersistence, cause: err}
	}
	return result, nil
}

// registerPostgreSQLQuery creates the same DRAFT source lineage as the folder
// path and then records the immutable projection contract. The two inserts are
// one transaction: a visible source can never exist without its exact
// projection metadata and sealed owner artifacts.
func (s *Service) registerPostgreSQLQuery(ctx context.Context, access database.AccessContext, request RegisterRequest) (RegisterResult, error) {
	projection := request.postgreSQLProjection()
	columnsJSON, err := postgresqlColumnsJSON(request.Columns)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid, cause: err}
	}
	connID := postgresqlConnectionID(access.OrganizationID, request.DatabaseIdentity, request.LineageID)
	discoveredID := postgresqlDiscoveredScopeID(access.OrganizationID, connID, request.DatabaseIdentity, request.LineageID, request.ProjectionRevision)
	scopeID := scopeID(access.OrganizationID, discoveredID)
	trustID := trustRecordID(access.OrganizationID, connID)
	credRef := request.CredentialReference
	if credRef == "" {
		credRef = credentialReference(access.OrganizationID, connID)
	}
	identityBytes, err := canon.PostgreSQLQueryScopeIdentityBytes(connID, request.DatabaseIdentity, request.LineageID, request.ProjectionRevision)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	displayBytes, err := canon.ScopeDisplayBytes(request.Name, request.Kind)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	trustBytes, err := canon.PostgreSQLQueryTrustBytes(connID, request.DatabaseIdentity, request.LineageID)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	limits := request.postgreSQLLimits()
	configBytes, err := canon.PostgreSQLQueryScopeConfigBytes(request.DatabaseIdentity, request.LineageID,
		request.ProjectionRevision, request.SchemaName, request.RelationName, request.RelationKind,
		request.ContractHash, string(columnsJSON), request.EmptySnapshotPolicy,
		limits.maxRows, limits.maxColumns, limits.maxFieldBytes, limits.maxRowBytes, limits.maxTotalBytes, limits.statementTimeoutMS)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	identityDigest := canon.HMACDigest(s.digestKey, s.digestKeyVersion, identityBytes)

	var result RegisterResult
	result.CredentialReference = credRef
	denied, unavailable := false, false
	err = s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		profile, profileErr := readPostgreSQLProfile(ctx, tx)
		if profileErr != nil {
			if database.IsNotFound(profileErr) {
				unavailable = true
				return nil
			}
			return profileErr
		}
		var connectionResourceID, scopeResourceID string
		if err := tx.QueryRow(ctx, `SELECT app.registration_connection_resource_id($1,$2,1)`, access.OrganizationID, connID).Scan(&connectionResourceID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT app.registration_scope_resource_id($1,$2,1)`, access.OrganizationID, scopeID).Scan(&scopeResourceID); err != nil {
			return err
		}
		makeArtifact := func() (string, error) { return s.newID("artifact") }
		trustArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		identityArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		displayArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		configArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		seal := func(field artifactcrypto.OwnerField, resourceID string, plaintext []byte) (artifactcrypto.Envelope, error) {
			owner, ownerErr := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, resourceID)
			if ownerErr != nil {
				return artifactcrypto.Envelope{}, ownerErr
			}
			return s.codec.Seal(owner, plaintext)
		}
		trustEnvelope, err := seal(artifactcrypto.SourceConnectionTrustConfig, connectionResourceID, trustBytes)
		if err != nil {
			return err
		}
		identityEnvelope, err := seal(artifactcrypto.SourceScopeIdentity, discoveredID, identityBytes)
		if err != nil {
			return err
		}
		displayEnvelope, err := seal(artifactcrypto.SourceScopeDisplayMetadata, discoveredID, displayBytes)
		if err != nil {
			return err
		}
		configEnvelope, err := seal(artifactcrypto.SourceScopeConfig, scopeResourceID, configBytes)
		if err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT connection_id, source_scope_id, discovered_scope_id, revision, created FROM app.source_postgresql_query_registration_begin($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)`,
			connID, request.Name, trustID, credRef, trustArtifactID, trustEnvelope.PlaintextHash(), discoveredID,
			identityDigest, int64(s.digestKeyVersion), identityArtifactID, identityEnvelope.PlaintextHash(), displayArtifactID,
			displayEnvelope.PlaintextHash(), scopeID, configArtifactID, configEnvelope.PlaintextHash(), profile.ID,
			profile.ProfileHash, profile.ConnectorBuildID, profile.ConnectorVersion, profile.ConnectorArtifactHash,
			profile.ContractSuiteHash, profile.VerifiedAt, int64(maximumScopeObjects), int64(maximumScopeBytes), int64(maximumObjectBytes),
			request.postgreSQLSyncIntervalSeconds(), freshnessSLA, int64(limits.maxRows), limits.maxTotalBytes, limits.maxRowBytes, accessModeManaged,
		).Scan(&result.ConnectionID, &result.SourceScopeID, &result.DiscoveredScopeID, &revision, &result.Created); err != nil {
			return err
		}
		result.Revision = revision
		result.ScopeConfigHash = configEnvelope.PlaintextHash()
		result.AccessMode = accessModeManaged
		if !result.Created {
			// Exact-match replay: the committed lineage already exists and the
			// application.postgresql_query_registration_begin function reported
			// created=false (idempotent convergence). The connection, discovered
			// scope and source scope are content derivations of this exact
			// request, so pin the precomputed ids to guarantee the replay returns
			// the SAME registration ids the first call created — never a second
			// registration and never a spurious SOURCE_CONFLICT — and write no
			// second audit event.
			result.ConnectionID = connID
			result.DiscoveredScopeID = discoveredID
			result.SourceScopeID = scopeID
			return nil
		}
		envelopeArgs := func(envelope artifactcrypto.Envelope) []any {
			return []any{envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(), envelope.AADHash(), envelope.PlaintextHash()}
		}
		bind := func(statement string, args ...any) error { _, err := tx.Exec(ctx, statement, args...); return err }
		if err := bind(`SELECT app.source_trust_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append([]any{access.OrganizationID, connID, int64(1), trustArtifactID, connectionResourceID}, envelopeArgs(trustEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_scope_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append([]any{access.OrganizationID, scopeID, int64(1), configArtifactID, scopeResourceID}, envelopeArgs(configEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_identity_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, append([]any{access.OrganizationID, discoveredID, identityArtifactID, discoveredID}, envelopeArgs(identityEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_display_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, append([]any{access.OrganizationID, discoveredID, displayArtifactID, discoveredID}, envelopeArgs(displayEnvelope)...)...); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_register($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14,$15,$16,$17,$18)`, scopeID, int64(1), connID, request.DatabaseIdentity, request.LineageID, request.ProjectionRevision, request.ContractHash, request.SchemaName, request.RelationName, request.RelationKind, string(columnsJSON), request.EmptySnapshotPolicy, limits.maxRows, limits.maxColumns, limits.maxFieldBytes, limits.maxRowBytes, limits.maxTotalBytes, limits.statementTimeoutMS); err != nil {
			return err
		}
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID, Action: audit.ActionSourceRegistrationCreated, ResourceType: audit.ResourceSourceScope, ResourceID: scopeID, RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(), Metadata: audit.Metadata{SourceConnectionID: &connID, SourceScopeID: &scopeID, SourceScopeRevision: &revision}})
		return err
	})
	if err != nil {
		if isSQLState(err, "23505") {
			return RegisterResult{}, &Error{code: CodeConflict}
		}
		return RegisterResult{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return RegisterResult{}, &Error{code: CodeDenied}
	}
	if unavailable {
		return RegisterResult{}, &Error{code: CodeUnavailable}
	}
	_ = projection // validation is intentionally performed before any write
	return result, nil
}

// registerRemote creates the common DRAFT lineage for a Git or IMAP source.
// The function intentionally stores no endpoint credential bytes: the
// encrypted trust/config owner branches contain only canonical non-secret
// metadata, while the worker resolves the opaque credential reference from
// its administrator-owned mount.  Both providers therefore use the same
// control-plane transaction and activation gates as Folder/PostgreSQL.
func (s *Service) registerRemote(ctx context.Context, access database.AccessContext, request RegisterRequest) (RegisterResult, error) {
	sourceType := request.SourceType
	contractVersion := "git-v1"
	connID := remoteConnectionID(access.OrganizationID, sourceType, request.Endpoint, request.Provider, request.RepositoryID, request.Mailbox)
	var identityBytes, trustBytes, configBytes []byte
	var err, trustErr, configErr error
	// The canonical functions include the connection id.  Derive the
	// connection first from the source-native immutable endpoint identity, then
	// render the final identity/trust/config bytes with that id.
	if sourceType == "MAIL" {
		contractVersion = "imap-v1"
		identityBytes, err = canon.MailScopeIdentityBytes(connID, request.Endpoint, request.Mailbox, request.Folder)
		trustBytes, trustErr = canon.MailTrustBytes(connID, request.Endpoint, request.Username)
		maxMessage, maxAttachment := request.MaxMessageBytes, request.MaxAttachmentBytes
		if maxMessage == 0 {
			maxMessage = 8 << 20
		}
		if maxAttachment == 0 {
			maxAttachment = 4 << 20
		}
		configBytes, configErr = canon.MailScopeConfigBytes(request.Endpoint, request.Mailbox, request.Folder, request.Since,
			request.IncludeAttachments, maxMessage, maxAttachment, request.AttachmentMediaTypes)
	} else {
		identityBytes, err = canon.GitScopeIdentityBytes(connID, request.Provider, request.RepositoryID, request.BranchName)
		trustBytes, trustErr = canon.GitTrustBytes(connID, request.Provider, request.Endpoint, request.WebBaseURL)
		configBytes, configErr = canon.GitScopeConfigBytes(request.Provider, request.RepositoryID, request.BranchName,
			request.IncludeGlobs, request.ExcludeGlobs, request.TextMediaTypes, request.MaxBlobBytes)
	}
	if err != nil || trustErr != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	identityHash := canon.Hash(identityBytes)
	discoveredID := remoteDiscoveredScopeID(access.OrganizationID, connID, sourceType, identityHash)
	scopeID := scopeID(access.OrganizationID, discoveredID)
	trustID := trustRecordID(access.OrganizationID, connID)
	credRef := request.CredentialReference
	if credRef == "" {
		credRef = credentialReference(access.OrganizationID, connID)
	}
	if configErr != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	identityDigest := canon.HMACDigest(s.digestKey, s.digestKeyVersion, identityBytes)
	displayBytes, err := canon.ScopeDisplayBytes(request.Name, request.Kind)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	var result RegisterResult
	result.CredentialReference = credRef
	denied, unavailable := false, false
	err = s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		profile, profileErr := readCapabilityProfile(ctx, tx, sourceType)
		if profileErr != nil {
			if database.IsNotFound(profileErr) {
				unavailable = true
				return nil
			}
			return profileErr
		}
		var connectionResourceID, scopeResourceID string
		if err := tx.QueryRow(ctx, `SELECT app.registration_connection_resource_id($1,$2,1)`, access.OrganizationID, connID).Scan(&connectionResourceID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT app.registration_scope_resource_id($1,$2,1)`, access.OrganizationID, scopeID).Scan(&scopeResourceID); err != nil {
			return err
		}
		makeArtifact := func() (string, error) { return s.newID("artifact") }
		trustArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		identityArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		displayArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		configArtifactID, err := makeArtifact()
		if err != nil {
			return err
		}
		seal := func(field artifactcrypto.OwnerField, resourceID string, plaintext []byte) (artifactcrypto.Envelope, error) {
			owner, ownerErr := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, resourceID)
			if ownerErr != nil {
				return artifactcrypto.Envelope{}, ownerErr
			}
			return s.codec.Seal(owner, plaintext)
		}
		trustEnvelope, err := seal(artifactcrypto.SourceConnectionTrustConfig, connectionResourceID, trustBytes)
		if err != nil {
			return err
		}
		identityEnvelope, err := seal(artifactcrypto.SourceScopeIdentity, discoveredID, identityBytes)
		if err != nil {
			return err
		}
		displayEnvelope, err := seal(artifactcrypto.SourceScopeDisplayMetadata, discoveredID, displayBytes)
		if err != nil {
			return err
		}
		configEnvelope, err := seal(artifactcrypto.SourceScopeConfig, scopeResourceID, configBytes)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT connection_id, source_scope_id, discovered_scope_id, revision, created FROM app.source_remote_registration_begin($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)`,
			sourceType, connID, request.Name, trustID, credRef, trustArtifactID, trustEnvelope.PlaintextHash(),
			discoveredID, identityDigest, int64(s.digestKeyVersion), identityArtifactID, identityEnvelope.PlaintextHash(),
			displayArtifactID, displayEnvelope.PlaintextHash(), scopeID, configArtifactID, configEnvelope.PlaintextHash(),
			profile.ID, profile.ProfileHash, profile.ConnectorBuildID, profile.ConnectorVersion, profile.ConnectorArtifactHash,
			profile.ContractSuiteHash, profile.VerifiedAt, int64(maximumScopeObjects), int64(maximumScopeBytes), int64(maximumObjectBytes),
			syncIntervalSeconds, freshnessSLA, int64(objectLimit), int64(byteLimit), int64(scopeMaxObjectBytes), accessModeManaged,
			contractVersion).Scan(&result.ConnectionID, &result.SourceScopeID, &result.DiscoveredScopeID, &result.Revision, &result.Created); err != nil {
			return err
		}
		result.ScopeConfigHash = configEnvelope.PlaintextHash()
		result.AccessMode = accessModeManaged
		if !result.Created {
			// Exact-match replay: the committed lineage already exists and
			// app.source_remote_registration_begin reported created=false. The
			// connection, discovered scope and source scope are content
			// derivations of this exact request, so pin the precomputed ids to
			// guarantee the replay returns the SAME registration ids the first
			// call created (idempotent re-registration) rather than ever minting
			// a second connection/source_scope or surfacing a spurious
			// SOURCE_CONFLICT, and write no second audit event.
			result.ConnectionID = connID
			result.DiscoveredScopeID = discoveredID
			result.SourceScopeID = scopeID
			return nil
		}
		envelopeArgs := func(envelope artifactcrypto.Envelope) []any {
			return []any{envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(), envelope.AADHash(), envelope.PlaintextHash()}
		}
		bind := func(statement string, args ...any) error { _, err := tx.Exec(ctx, statement, args...); return err }
		if err := bind(`SELECT app.source_trust_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append([]any{access.OrganizationID, connID, int64(1), trustArtifactID, connectionResourceID}, envelopeArgs(trustEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_scope_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, append([]any{access.OrganizationID, scopeID, int64(1), configArtifactID, scopeResourceID}, envelopeArgs(configEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_identity_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, append([]any{access.OrganizationID, discoveredID, identityArtifactID, discoveredID}, envelopeArgs(identityEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_display_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, append([]any{access.OrganizationID, discoveredID, displayArtifactID, discoveredID}, envelopeArgs(displayEnvelope)...)...); err != nil {
			return err
		}
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceRegistrationCreated, ResourceType: audit.ResourceSourceScope, ResourceID: scopeID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(), Metadata: audit.Metadata{SourceConnectionID: &connID, SourceScopeID: &scopeID, SourceScopeRevision: &result.Revision}})
		return err
	})
	if err != nil {
		if isSQLState(err, "23505") {
			return RegisterResult{}, &Error{code: CodeConflict}
		}
		return RegisterResult{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return RegisterResult{}, &Error{code: CodeDenied}
	}
	if unavailable {
		return RegisterResult{}, &Error{code: CodeUnavailable}
	}
	return result, nil
}

func (request RegisterRequest) isPostgreSQLQuery() bool {
	return request.SourceType == "POSTGRESQL_QUERY"
}

func (s *Service) registerOnce(ctx context.Context, access database.AccessContext, request RegisterRequest) (RegisterResult, error) {
	connID := connectionID(access.OrganizationID, request.RootIdentity)
	trustID := trustRecordID(access.OrganizationID, connID)
	credRef := credentialReference(access.OrganizationID, connID)
	discoveredID := discoveredScopeID(access.OrganizationID, connID, request.RelativeRoot)
	scopeID := scopeID(access.OrganizationID, discoveredID)

	identityBytes, err := canon.ScopeIdentityBytes(connID, request.RelativeRoot)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	displayBytes, err := canon.ScopeDisplayBytes(request.Name, request.Kind)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	trustBytes, err := canon.FolderTrustBytes(request.RootAlias, request.RootIdentity)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	configBytes, err := canon.ScopeConfigBytes(request.RootAlias, request.RelativeRoot, request.Recursive,
		request.IncludeGlobs, request.ExcludeGlobs, request.MaxFileBytes, request.OCRMode, request.Formats)
	if err != nil {
		return RegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	identityDigest := canon.HMACDigest(s.digestKey, s.digestKeyVersion, identityBytes)

	var result RegisterResult
	denied := false
	unavailable := false
	err = s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		profile, profileErr := readFolderProfile(ctx, tx)
		if profileErr != nil {
			if database.IsNotFound(profileErr) {
				unavailable = true
				return nil
			}
			return profileErr
		}

		// The 000007 fail-closed gate forbids EXECUTE on the resource-id
		// derivations for the app role; the registration surface reaches them
		// through the SECURITY DEFINER wrappers of 000018.
		var connectionResourceID, scopeResourceID string
		if err := tx.QueryRow(ctx, `SELECT app.registration_connection_resource_id($1, $2, 1)`,
			access.OrganizationID, connID).Scan(&connectionResourceID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT app.registration_scope_resource_id($1, $2, 1)`,
			access.OrganizationID, scopeID).Scan(&scopeResourceID); err != nil {
			return err
		}

		// Artifact ids are minted per pass; a rolled-back transaction discards
		// them and the sealed envelopes with it.
		trustArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		identityArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		displayArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}
		configArtifactID, err := s.newID("artifact")
		if err != nil {
			return err
		}

		seal := func(field artifactcrypto.OwnerField, resourceID string, plaintext []byte) (artifactcrypto.Envelope, error) {
			owner, ownerErr := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, resourceID)
			if ownerErr != nil {
				return artifactcrypto.Envelope{}, ownerErr
			}
			return s.codec.Seal(owner, plaintext)
		}
		trustEnvelope, err := seal(artifactcrypto.SourceConnectionTrustConfig, connectionResourceID, trustBytes)
		if err != nil {
			return err
		}
		identityEnvelope, err := seal(artifactcrypto.SourceScopeIdentity, discoveredID, identityBytes)
		if err != nil {
			return err
		}
		displayEnvelope, err := seal(artifactcrypto.SourceScopeDisplayMetadata, discoveredID, displayBytes)
		if err != nil {
			return err
		}
		configEnvelope, err := seal(artifactcrypto.SourceScopeConfig, scopeResourceID, configBytes)
		if err != nil {
			return err
		}

		var created bool
		var revision int64
		if err := tx.QueryRow(ctx, `
			SELECT connection_id, source_scope_id, discovered_scope_id, revision, created
			FROM app.source_folder_registration_begin(
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)`,
			connID, request.Name, trustID, credRef,
			trustArtifactID, trustEnvelope.PlaintextHash(),
			discoveredID, identityDigest, int64(s.digestKeyVersion), identityArtifactID, identityEnvelope.PlaintextHash(),
			displayArtifactID, displayEnvelope.PlaintextHash(),
			scopeID, configArtifactID, configEnvelope.PlaintextHash(),
			profile.ID, profile.ProfileHash, profile.ConnectorBuildID, profile.ConnectorVersion,
			profile.ConnectorArtifactHash, profile.ContractSuiteHash, profile.VerifiedAt,
			int64(maximumScopeObjects), int64(maximumScopeBytes), int64(maximumObjectBytes),
			syncIntervalSeconds, freshnessSLA, int64(objectLimit), int64(byteLimit), int64(scopeMaxObjectBytes),
			accessModeManaged,
		).Scan(&result.ConnectionID, &result.SourceScopeID, &result.DiscoveredScopeID, &revision, &created); err != nil {
			return err
		}
		result.Revision = revision
		result.ScopeConfigHash = configEnvelope.PlaintextHash()
		result.AccessMode = accessModeManaged
		result.Created = created
		if !created {
			// Exact-match replay: the committed lineage already exists and the
			// nonce uniqueness keeps any re-insert out. Nothing to seal or bind.
			//
			// The connection, discovered-scope and source-scope ids are content
			// derivations of the tenant plus this exact request, so on a replay
			// they are the SAME registration ids the first call created. Pin them
			// from the precomputed lineage so a replay deterministically returns
			// the existing registration (idempotent re-registration while the
			// operator works in KnowVault) rather than ever minting a second
			// connection/source_scope or surfacing a spurious SOURCE_CONFLICT.
			result.ConnectionID = connID
			result.DiscoveredScopeID = discoveredID
			result.SourceScopeID = scopeID
			return nil
		}

		bind := func(statement string, args ...any) error {
			_, err := tx.Exec(ctx, statement, args...)
			return err
		}
		envelopeArgs := func(envelope artifactcrypto.Envelope) []any {
			return []any{
				envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(), envelope.WrappedDEK(),
				envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(),
				envelope.AADHash(), envelope.PlaintextHash(),
			}
		}
		if err := bind(`SELECT app.source_trust_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			append([]any{access.OrganizationID, connID, int64(1), trustArtifactID, connectionResourceID},
				envelopeArgs(trustEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_scope_config_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			append([]any{access.OrganizationID, scopeID, int64(1), configArtifactID, scopeResourceID},
				envelopeArgs(configEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_identity_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			append([]any{access.OrganizationID, discoveredID, identityArtifactID, discoveredID},
				envelopeArgs(identityEnvelope)...)...); err != nil {
			return err
		}
		if err := bind(`SELECT app.source_discovered_scope_display_bind($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			append([]any{access.OrganizationID, discoveredID, displayArtifactID, discoveredID},
				envelopeArgs(displayEnvelope)...)...); err != nil {
			return err
		}

		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceRegistrationCreated, ResourceType: audit.ResourceSourceScope, ResourceID: scopeID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(),
			Metadata: audit.Metadata{
				SourceConnectionID:  &connID,
				SourceScopeID:       &scopeID,
				SourceScopeRevision: &revision,
			},
		})
		return err
	})
	if err != nil {
		return RegisterResult{}, err
	}
	if denied {
		return RegisterResult{}, &Error{code: CodeDenied}
	}
	if unavailable {
		return RegisterResult{}, &Error{code: CodeUnavailable}
	}
	return result, nil
}

// ActivateRequest names the scope to activate and carries the client
// idempotency key that becomes the durable queue key.
type ActivateRequest struct {
	IdempotencyKey string
	SourceScopeID  string
}

// ActivateResult carries the durable job id of the placed sync work.
type ActivateResult struct {
	JobID string
}

// SyncRequest asks the control plane to run a fresh full sync for an already
// READY source revision.  It is intentionally separate from Activate:
// activation creates the first authoritative publication, while sync refreshes
// the same immutable revision and therefore keeps the lineage/provenance tuple
// stable.  The idempotency key is still mandatory so retries cannot create
// duplicate work.
type SyncRequest struct {
	IdempotencyKey string
	SourceScopeID  string
}

// SyncResult carries the durable refresh job id.
type SyncResult struct {
	JobID string
}

// Activate gates on the sync-target projection of the pending revision
// (DRAFT/READY/FAILED, verified trust, and the derived-live confirmation for
// WORKSPACE_MANAGED) and then places the durable SOURCE_SCOPE_SYNC job through
// the production queue. Job placement and the mandatory activation audit
// record commit in one transaction (AUD-005); the client key is the job's
// idempotency key, so a replay converges on the original job and writes no
// second audit record, and a key reuse with a different scope is a conflict.
func (s *Service) Activate(ctx context.Context, access database.AccessContext, request ActivateRequest) (ActivateResult, error) {
	if s == nil || s.database == nil || s.queue == nil || s.audit == nil || access.Validate() != nil {
		return ActivateResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validScopeID(request.SourceScopeID) || len(request.IdempotencyKey) == 0 || len(request.IdempotencyKey) > 256 ||
		strings.TrimSpace(request.IdempotencyKey) != request.IdempotencyKey {
		return ActivateResult{}, &Error{code: CodeRequestInvalid}
	}

	var pendingRevision int64
	var jobID string
	denied := false
	notFound := false
	conflict := false
	err := s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceActivate)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		// The pending-revision function is a scalar SQL helper: an absent scope
		// yields NULL rather than no rows, so zero is the not-found sentinel (the
		// ingestion handler relies on the same revision==0 convention).
		if err := tx.QueryRow(ctx, `SELECT COALESCE(app.source_scope_pending_revision($1), 0)`, request.SourceScopeID).
			Scan(&pendingRevision); err != nil {
			return err
		}
		if pendingRevision == 0 {
			notFound = true
			return nil
		}
		target, targetErr := readSyncTarget(ctx, tx, request.SourceScopeID, pendingRevision)
		if targetErr != nil {
			if database.IsNotFound(targetErr) {
				notFound = true
				return nil
			}
			return targetErr
		}
		jobType := jobs.TypeSourceScopeSync
		if target.SourceType == "POSTGRESQL_QUERY" {
			jobType = jobs.TypePostgreSQLQuerySync
		}
		// The client key is the durable job's idempotency key. The check comes
		// before the state gates so a replay converges on the original job
		// regardless of what happened to the scope afterwards, and a key reused
		// with a different scope is a typed conflict (WSP-014) without ever
		// asking the state gates about that scope.
		var existingID, existingType, existingScope sql.NullString
		reuseErr := tx.QueryRow(ctx, `
			SELECT id, type, payload_json->>'source_scope_id' FROM public.job
			WHERE organization_id = $1 AND idempotency_key = $2`, access.OrganizationID, request.IdempotencyKey).
			Scan(&existingID, &existingType, &existingScope)
		if reuseErr != nil && !database.IsNotFound(reuseErr) {
			return reuseErr
		}
		if reuseErr == nil {
			if existingType.String != string(jobType) || existingScope.String != request.SourceScopeID {
				conflict = true
				return nil
			}
			jobID = existingID.String
			return nil
		}
		switch target.ActivationStatus {
		case "DRAFT", "READY", "FAILED":
		default:
			conflict = true
			return nil
		}
		if !target.TrustVerified {
			denied = true
			return nil
		}
		if target.AccessMode == accessModeManaged {
			var confirmed bool
			if err := tx.QueryRow(ctx, `SELECT app.source_scope_activation_confirmed($1, $2, $3)`,
				request.SourceScopeID, pendingRevision, target.ScopeConfigHash).Scan(&confirmed); err != nil {
				return err
			}
			if !confirmed {
				denied = true
				return nil
			}
		}

		// One activation job in flight per scope, exactly as before -- but the
		// invariant now lives in this live-job predicate instead of in a
		// content-derived job id. A derived id is the job table's PRIMARY KEY
		// and a finished job is immutable by design (000013's job_state_guard:
		// "a terminal job never moves again"), so re-deriving it made the
		// SECOND activation of a scope collide with its own history: it first
		// raised an unhandled unique violation (503 SERVICE_UNAVAILABLE), then
		// -- after 000070 taught app.enqueue_job to answer with the colliding
		// row's id -- silently returned the id of a job that had already
		// SUCCEEDED or gone DEAD hours earlier while enqueuing no work at all.
		// A caller cannot tell that apart from a real activation: the acceptance
		// stand's GIT and POSTGRESQL_QUERY sources answered 200 with a job id on
		// every :activate and never synced again. Mint the id per attempt, the
		// way Sync already does, and converge a genuine concurrent repeat on the
		// live job.
		var liveJobID string
		liveErr := tx.QueryRow(ctx, `
			SELECT id FROM public.job
			WHERE organization_id = $1 AND type = $2 AND status IN ('PENDING','RUNNING')
			  AND payload_json->>'source_scope_id' = $3
			ORDER BY created_at DESC LIMIT 1`, access.OrganizationID, string(jobType), request.SourceScopeID).Scan(&liveJobID)
		if liveErr == nil {
			jobID = liveJobID
			return nil
		}
		if !database.IsNotFound(liveErr) {
			return liveErr
		}
		mintedJobID, mintErr := s.newID("syncscope")
		if mintErr != nil {
			return mintErr
		}
		placed, enqueueErr := s.queue.EnqueueInTransaction(ctx, access, tx, jobs.Spec{
			JobID:          mintedJobID,
			Type:           jobType,
			Payload:        jobs.Payload{"source_scope_id": request.SourceScopeID, "operation": activationJobMarker},
			IdempotencyKey: request.IdempotencyKey,
			Priority:       100,
			MaxAttempts:    3,
			AvailableAfter: 0,
		})
		if enqueueErr != nil {
			return enqueueErr
		}
		jobID = placed

		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceActivationRequested, ResourceType: audit.ResourceSourceScope, ResourceID: request.SourceScopeID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(),
			Metadata: audit.Metadata{
				SourceScopeID:       &request.SourceScopeID,
				SourceScopeRevision: &pendingRevision,
				ConnectorJobID:      &jobID,
			},
		})
		return err
	})
	if err != nil {
		// Review remark Z5: 000075 pins "one live scope-sync job per scope" as
		// a partial unique index, so the read-then-enqueue fast path above no
		// longer has to win a race it cannot win under READ COMMITTED. The
		// loser of a genuinely concurrent :activate now sees that unique
		// violation instead of silently creating a second job. Converging on
		// the job that actually exists is the same answer the fast path would
		// have given a moment earlier — a repeat returns the live job, never a
		// second unit of work — so this reads it back once rather than
		// surfacing a persistence failure for a request that succeeded.
		if database.SQLStateCode(err) == uniqueViolationSQLState {
			if liveJobID, lookupErr := s.liveScopeSyncJob(ctx, access, request.SourceScopeID); lookupErr == nil && liveJobID != "" {
				return ActivateResult{JobID: liveJobID}, nil
			}
			return ActivateResult{}, &Error{code: CodeConflict, cause: err}
		}
		return ActivateResult{}, &Error{code: CodePersistence, cause: err}
	}
	if notFound {
		return ActivateResult{}, &Error{code: CodeNotFound}
	}
	if denied {
		return ActivateResult{}, &Error{code: CodeDenied}
	}
	if conflict {
		return ActivateResult{}, &Error{code: CodeConflict}
	}
	return ActivateResult{JobID: jobID}, nil
}

// uniqueViolationSQLState is PostgreSQL's unique_violation.
const uniqueViolationSQLState = "23505"

// liveScopeSyncConstraint is the partial unique index from 000075. Only a
// collision on that index means another activation is already in flight; an
// unrelated unique violation (for example an id or idempotency collision) is a
// real persistence failure and must not be hidden as a scheduler skip.
const liveScopeSyncConstraint = "job_one_live_activation_per_scope"

func isLiveScopeSyncConflict(sqlState, constraintName string) bool {
	return sqlState == uniqueViolationSQLState && constraintName == liveScopeSyncConstraint
}

// liveScopeSyncJob reads the single PENDING/RUNNING scope-sync job 000075
// allows per scope, in its own transaction (the caller's has been aborted by
// the unique violation).
func (s *Service) liveScopeSyncJob(ctx context.Context, access database.AccessContext, scopeID string) (string, error) {
	var jobID string
	err := s.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `
			SELECT id FROM public.job
			WHERE organization_id = $1 AND status IN ('PENDING','RUNNING')
			  AND type IN ('SOURCE_SCOPE_SYNC','POSTGRESQL_QUERY_SYNC')
			  AND payload_json->>'source_scope_id' = $2
			ORDER BY created_at DESC LIMIT 1`, access.OrganizationID, scopeID).Scan(&jobID)
	})
	if err != nil {
		return "", err
	}
	return jobID, nil
}

// Sync queues a full refresh for the latest READY revision of one source.
// Unlike Activate, it derives a new job identity for each idempotency key so a
// completed historical job never prevents a later refresh.  A second refresh
// while one is pending/running is rejected to keep the source publication
// single-writer and avoid concurrent duplicate snapshots.
func (s *Service) Sync(ctx context.Context, access database.AccessContext, request SyncRequest) (SyncResult, error) {
	if s == nil || s.database == nil || s.queue == nil || s.audit == nil || access.Validate() != nil {
		return SyncResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validScopeID(request.SourceScopeID) || len(request.IdempotencyKey) == 0 || len(request.IdempotencyKey) > 256 ||
		strings.TrimSpace(request.IdempotencyKey) != request.IdempotencyKey {
		return SyncResult{}, &Error{code: CodeRequestInvalid}
	}

	jobID, idErr := s.newID("syncscope")
	if idErr != nil {
		return SyncResult{}, &Error{code: CodePersistence, cause: idErr}
	}
	denied, notFound, conflict := false, false, false
	var resultID string
	err := s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceActivate)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(app.source_scope_pending_revision($1), 0)`, request.SourceScopeID).Scan(&revision); err != nil {
			return err
		}
		if revision == 0 {
			notFound = true
			return nil
		}
		target, targetErr := readSyncTarget(ctx, tx, request.SourceScopeID, revision)
		if targetErr != nil {
			if database.IsNotFound(targetErr) {
				notFound = true
				return nil
			}
			return targetErr
		}
		var existingID, existingType, existingScope sql.NullString
		reuseErr := tx.QueryRow(ctx, `
			SELECT id, type, payload_json->>'source_scope_id' FROM public.job
			WHERE organization_id = $1 AND idempotency_key = $2`, access.OrganizationID, request.IdempotencyKey).
			Scan(&existingID, &existingType, &existingScope)
		if reuseErr != nil && !database.IsNotFound(reuseErr) {
			return reuseErr
		}
		jobType := jobs.TypeSourceScopeSync
		if target.SourceType == "POSTGRESQL_QUERY" {
			jobType = jobs.TypePostgreSQLQuerySync
		}
		if reuseErr == nil {
			if existingType.String != string(jobType) || existingScope.String != request.SourceScopeID {
				conflict = true
				return nil
			}
			resultID = existingID.String
			return nil
		}
		if target.ActivationStatus != "READY" || !target.TrustVerified {
			conflict = true
			return nil
		}
		if target.AccessMode == accessModeManaged {
			var confirmed bool
			if err := tx.QueryRow(ctx, `SELECT app.source_scope_activation_confirmed($1, $2, $3)`,
				request.SourceScopeID, revision, target.ScopeConfigHash).Scan(&confirmed); err != nil {
				return err
			}
			if !confirmed {
				denied = true
				return nil
			}
		}
		// There can be only one refresh in flight for a scope.  This check is
		// serialized by the source row's activation transition in the worker;
		// it also makes the API fail closed before placing a duplicate job.
		var pendingID string
		pendingErr := tx.QueryRow(ctx, `
			SELECT id FROM public.job
			WHERE organization_id = $1 AND type = $2 AND status IN ('PENDING','RUNNING')
			  AND payload_json->>'source_scope_id' = $3
			ORDER BY created_at DESC LIMIT 1`, access.OrganizationID, string(jobType), request.SourceScopeID).Scan(&pendingID)
		if pendingErr == nil {
			conflict = true
			return nil
		}
		if !database.IsNotFound(pendingErr) {
			return pendingErr
		}
		placed, enqueueErr := s.queue.EnqueueInTransaction(ctx, access, tx, jobs.Spec{
			JobID: jobID, Type: jobType, Payload: jobs.Payload{"source_scope_id": request.SourceScopeID, "operation": activationJobMarker},
			IdempotencyKey: request.IdempotencyKey, Priority: 100, MaxAttempts: 3,
			AvailableAfter: 0,
		})
		if enqueueErr != nil {
			return enqueueErr
		}
		resultID = placed
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		actorID := access.PrincipalID
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSourceActivationRequested, ResourceType: audit.ResourceSourceScope, ResourceID: request.SourceScopeID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(),
			Metadata: audit.Metadata{SourceScopeID: &request.SourceScopeID, SourceScopeRevision: &revision, ConnectorJobID: &resultID},
		})
		return err
	})
	if err != nil {
		// Sync's own contract is "a refresh while one is pending/running is
		// rejected" (single-writer). 000075 makes that true even when two
		// callers pass its predicate check simultaneously: the loser now gets
		// the same typed conflict the predicate would have given it.
		if database.SQLStateCode(err) == uniqueViolationSQLState {
			return SyncResult{}, &Error{code: CodeConflict, cause: err}
		}
		return SyncResult{}, &Error{code: CodePersistence, cause: err}
	}
	if notFound {
		return SyncResult{}, &Error{code: CodeNotFound}
	}
	if denied {
		return SyncResult{}, &Error{code: CodeDenied}
	}
	if conflict {
		return SyncResult{}, &Error{code: CodeConflict}
	}
	return SyncResult{JobID: resultID}, nil
}

// AutoSyncLimit bounds one scheduler tick's enqueue batch. It matches the
// range app.postgresql_query_scope_due itself enforces.
const AutoSyncLimit = 20

// AutoSync is the scheduled counterpart of Sync: the worker calls it once per
// poll tick with its own service access context, never a human actor. It
// enqueues a SOURCE_SCOPE_SYNC job for a FOLDER scope or a
// POSTGRESQL_QUERY_SYNC job for a PostgreSQL projection when that source's
// sync_interval_seconds has elapsed (app.postgresql_query_scope_due, migration
// 000089). The lookup supplies bounded candidates; the worker-only schedule
// lock then serializes ticks and rechecks due, live-job, and DEAD-cooldown
// state before this method checks the current revision, trust, and
// confirmation gates. The existing database uniqueness guard also covers an
// API request racing the scheduler.
func (s *Service) AutoSync(ctx context.Context, access database.AccessContext) (int, error) {
	if s == nil || s.database == nil || s.queue == nil || s.audit == nil || access.Validate() != nil {
		return 0, &Error{code: CodeRequestInvalid}
	}
	type dueScope struct {
		scopeID  string
		revision int64
	}
	var due []dueScope
	readErr := s.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		rows, queryErr := tx.Query(ctx, `SELECT source_scope_id, source_scope_revision FROM app.postgresql_query_scope_due($1)`, AutoSyncLimit)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var item dueScope
			if scanErr := rows.Scan(&item.scopeID, &item.revision); scanErr != nil {
				return scanErr
			}
			due = append(due, item)
		}
		return rows.Err()
	})
	if readErr != nil {
		return 0, &Error{code: CodePersistence, cause: readErr}
	}
	enqueued := 0
	for _, item := range due {
		ok, syncErr := s.autoSyncOne(ctx, access, item.scopeID, item.revision)
		if syncErr != nil {
			return enqueued, syncErr
		}
		if ok {
			enqueued++
		}
	}
	return enqueued, nil
}

// scheduledSyncJobType returns the existing worker handler for a source type.
// Only FOLDER and POSTGRESQL_QUERY have a safe autonomous refresh contract in
// this worker; unsupported source types remain manual/explicit only.
func scheduledSyncJobType(sourceType string) (jobs.Type, bool) {
	switch sourceType {
	case "FOLDER":
		return jobs.TypeSourceScopeSync, true
	case "POSTGRESQL_QUERY":
		return jobs.TypePostgreSQLQuerySync, true
	default:
		return "", false
	}
}

// autoSyncOne enqueues one scheduled sync exactly as Sync would for an
// operator, except it never calls actorGate (there is no human actor to
// authorize: the schedule itself, chosen at registration under that gate, is
// the authorization) and its idempotency key is server-generated rather than
// client-supplied. The schedule lock owns the current-revision, READY, due,
// live-job, and DEAD-cooldown checks; this method retains the source-type,
// trust, and live workspace-managed confirmation checks. A scope whose
// confirmation or trust was revoked since its last sync is silently skipped
// rather than force-run.
func (s *Service) autoSyncOne(ctx context.Context, access database.AccessContext, scopeID string, revision int64) (bool, error) {
	jobID, idErr := s.newID("syncscope")
	if idErr != nil {
		return false, &Error{code: CodePersistence, cause: idErr}
	}
	enqueuedID := ""
	skip := false
	err := s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var activeRevision sql.NullInt64
		var activationStatus sql.NullString
		var stillDue bool
		if lockErr := tx.QueryRow(ctx, `
			SELECT active_revision, activation_status, still_due
			FROM app.source_scope_schedule_lock($1::text, $2::bigint)`, scopeID, revision).
			Scan(&activeRevision, &activationStatus, &stillDue); lockErr != nil {
			if database.IsNotFound(lockErr) {
				skip = true
				return nil
			}
			return lockErr
		}
		if !activeRevision.Valid || activeRevision.Int64 != revision {
			skip = true
			return nil
		}
		if activationStatus.String != "READY" {
			skip = true
			return nil
		}
		if !stillDue {
			skip = true
			return nil
		}
		target, targetErr := readSyncTarget(ctx, tx, scopeID, revision)
		if targetErr != nil {
			if database.IsNotFound(targetErr) {
				skip = true
				return nil
			}
			return targetErr
		}
		jobType, supported := scheduledSyncJobType(target.SourceType)
		if !supported {
			skip = true
			return nil
		}
		if target.ActivationStatus != "READY" || !target.TrustVerified {
			skip = true
			return nil
		}
		if target.AccessMode == accessModeManaged {
			var confirmed bool
			if err := tx.QueryRow(ctx, `SELECT app.source_scope_activation_confirmed($1, $2, $3)`,
				scopeID, revision, target.ScopeConfigHash).Scan(&confirmed); err != nil {
				return err
			}
			if !confirmed {
				skip = true
				return nil
			}
		}
		placed, enqueueErr := s.queue.EnqueueInTransaction(ctx, access, tx, jobs.Spec{
			JobID: jobID, Type: jobType, Payload: jobs.Payload{"source_scope_id": scopeID, "operation": activationJobMarker},
			IdempotencyKey: "autosync:" + jobID, Priority: 100, MaxAttempts: 3, AvailableAfter: 0,
		})
		if enqueueErr != nil {
			return enqueueErr
		}
		enqueuedID = placed
		eventID, err := s.newID("aud")
		if err != nil {
			return err
		}
		_, err = s.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorSystem,
			Action: audit.ActionSourceActivationRequested, ResourceType: audit.ResourceSourceScope, ResourceID: scopeID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: s.now().UTC(),
			Metadata: audit.Metadata{SourceScopeID: &scopeID, SourceScopeRevision: &revision, ConnectorJobID: &enqueuedID},
		})
		return err
	})
	if err != nil {
		// The scheduler already skips a scope with a live job; 000075 closes
		// the race against a concurrent operator :activate or :sync of the
		// same scope. Losing that race is precisely "someone else is already
		// refreshing this scope", which is this tick's skip, not a failure.
		if isLiveScopeSyncConflict(database.SQLStateCode(err), database.SQLConstraintName(err)) {
			return false, nil
		}
		return false, &Error{code: CodePersistence, cause: err}
	}
	if skip {
		return false, nil
	}
	return true, nil
}

// actorGate resolves the current actor the way the workspace repository does
// (the currentActor pattern) and asks the pure organization policy for the
// named operation. A false result never distinguishes "no such actor" from
// "insufficient role".
func (s *Service) actorGate(ctx context.Context, tx database.Transaction, access database.AccessContext, operation policy.Operation) (bool, error) {
	var organizationStatus, principalStatus string
	var sessionRevision int64
	err := tx.QueryRow(ctx, `
		SELECT organization.status, principal.status, principal.session_revision
		FROM public.organization AS organization
		JOIN public.principal AS principal
		  ON principal.organization_id = organization.id
		WHERE organization.id = $1 AND principal.id = $2`, access.OrganizationID, access.PrincipalID).
		Scan(&organizationStatus, &principalStatus, &sessionRevision)
	if err != nil {
		if database.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	rows, err := tx.Query(ctx, `
		SELECT role FROM public.organization_role_assignment
		WHERE organization_id = $1 AND principal_id = $2 AND revoked_at IS NULL
		ORDER BY role`, access.OrganizationID, access.PrincipalID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	roles := []policy.OrganizationRole{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return false, err
		}
		roles = append(roles, policy.OrganizationRole(role))
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	decision := policy.EvaluateOrganization(policy.OrganizationRequest{
		Operation: operation,
		Subject: policy.Subject{
			OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
			Status: policy.PrincipalStatus(principalStatus), SessionRevision: sessionRevision,
			OrganizationRoles: roles,
		},
		Organization: policy.Organization{ID: access.OrganizationID, Status: policy.OrganizationStatus(organizationStatus)},
	})
	return decision.Allowed, nil
}

type folderProfile struct {
	ID                    string
	ProfileHash           string
	ConnectorBuildID      string
	ConnectorVersion      string
	ConnectorArtifactHash string
	ContractSuiteHash     string
	VerifiedAt            time.Time
}

// readFolderProfile reads the newest verified FOLDER capability profile. The
// non-deferred capability FK of source_connection_revision re-validates the
// exact tuple at insert, so a profile that disappears between read and write
// fails the transaction instead of falling back.
func readFolderProfile(ctx context.Context, tx database.Transaction) (folderProfile, error) {
	return readCapabilityProfile(ctx, tx, "FOLDER")
}

func readPostgreSQLProfile(ctx context.Context, tx database.Transaction) (folderProfile, error) {
	return readCapabilityProfile(ctx, tx, "POSTGRESQL_QUERY")
}

func readCapabilityProfile(ctx context.Context, tx database.Transaction, connectorType string) (folderProfile, error) {
	var profile folderProfile
	err := tx.QueryRow(ctx, `
		SELECT id, profile_hash, connector_build_id, connector_version, connector_artifact_hash, contract_suite_hash, verified_at
		FROM public.connector_capability_profile
		WHERE connector_type = $1
		ORDER BY verified_at DESC, id DESC
		LIMIT 1`, connectorType).Scan(&profile.ID, &profile.ProfileHash, &profile.ConnectorBuildID, &profile.ConnectorVersion,
		&profile.ConnectorArtifactHash, &profile.ContractSuiteHash, &profile.VerifiedAt)
	return profile, err
}

type syncTarget struct {
	ConnectionID          string
	ConnectionRevision    int64
	AccessMode            string
	SourceType            string
	ScopeConfigHash       string
	TrustProfileHash      string
	ScopeConfigResourceID string
	TrustConfigResourceID string
	ActivationStatus      string
	TrustVerified         bool
}

func readSyncTarget(ctx context.Context, tx database.Transaction, scopeID string, revision int64) (syncTarget, error) {
	var target syncTarget
	err := tx.QueryRow(ctx, `
		SELECT connection_id, connection_revision, access_mode, source_type, scope_config_hash,
		       trust_profile_hash, scope_config_resource_id, trust_config_resource_id,
		       activation_status, trust_verified
		FROM app.source_scope_sync_target($1, $2)`, scopeID, revision).
		Scan(&target.ConnectionID, &target.ConnectionRevision, &target.AccessMode, &target.SourceType,
			&target.ScopeConfigHash, &target.TrustProfileHash, &target.ScopeConfigResourceID,
			&target.TrustConfigResourceID, &target.ActivationStatus, &target.TrustVerified)
	return target, err
}

// validScopeID enforces the exact app.source_generated_id_is_valid shape for
// scope ids so an invalid input never reaches SQL.
func validScopeID(value string) bool {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	const prefix = "scope_"
	if len(value) != len(prefix)+26 || !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := value[len(prefix):]
	if encoded[0] < '0' || encoded[0] > '7' {
		return false
	}
	for index := 1; index < len(encoded); index++ {
		if !strings.ContainsRune(alphabet, rune(encoded[index])) {
			return false
		}
	}
	return true
}

func (request RegisterRequest) validate() error {
	if !validName(request.Name) || !validSchemaID(request.RootAlias) || !validSchemaID(request.RootIdentity) ||
		!validKind(request.Kind) || !validRelativeRoot(request.RelativeRoot) {
		return &Error{code: CodeRequestInvalid}
	}
	if request.MaxFileBytes < 1 || request.MaxFileBytes > 1073741824 {
		return &Error{code: CodeRequestInvalid}
	}
	if request.OCRMode != "OFF" && request.OCRMode != "AUTO" {
		return &Error{code: CodeRequestInvalid}
	}
	if !validGlobs(request.IncludeGlobs) || !validGlobs(request.ExcludeGlobs) {
		return &Error{code: CodeRequestInvalid}
	}
	if len(request.Formats) == 0 || len(request.Formats) > 14 {
		return &Error{code: CodeRequestInvalid}
	}
	seen := map[string]bool{}
	for _, format := range request.Formats {
		if !validFormat(format) || seen[format] {
			return &Error{code: CodeRequestInvalid}
		}
		seen[format] = true
	}
	return nil
}

type postgresqlLimits struct {
	maxRows, maxColumns, maxFieldBytes, maxRowBytes, maxTotalBytes, statementTimeoutMS int64
}

// postgreSQLSyncIntervalSeconds resolves the operator-chosen schedule, or the
// existing fixed default when the caller omitted it. The bound matches the
// source_scope_revision CHECK (000007) so an out-of-range value fails closed
// in Go before it ever reaches SQL.
func (request RegisterRequest) postgreSQLSyncIntervalSeconds() int {
	if request.SyncIntervalSeconds == 0 {
		return syncIntervalSeconds
	}
	return request.SyncIntervalSeconds
}

func (request RegisterRequest) postgreSQLLimits() postgresqlLimits {
	limits := postgresqlLimits{maxRows: request.MaxRows, maxColumns: int64(request.MaxColumns), maxFieldBytes: request.MaxFieldBytes, maxRowBytes: request.MaxRowBytes, maxTotalBytes: request.MaxTotalBytes, statementTimeoutMS: int64(request.StatementTimeoutMS)}
	if limits.maxRows == 0 {
		limits.maxRows = 1_000_000
	}
	if limits.maxColumns == 0 {
		limits.maxColumns = 128
	}
	if limits.maxFieldBytes == 0 {
		limits.maxFieldBytes = 1 << 20
	}
	if limits.maxRowBytes == 0 {
		limits.maxRowBytes = 16 << 20
	}
	if limits.maxTotalBytes == 0 {
		limits.maxTotalBytes = 1 << 30
	}
	if limits.statementTimeoutMS == 0 {
		limits.statementTimeoutMS = 120_000
	}
	return limits
}

func (request RegisterRequest) postgreSQLProjection() postgresqlquery.Projection {
	return postgresqlquery.Projection{ConnectionID: postgresqlConnectionID("org-placeholder", request.DatabaseIdentity, request.LineageID), DatabaseIdentity: request.DatabaseIdentity, LineageID: request.LineageID, Revision: request.ProjectionRevision, ContractHash: request.ContractHash, SchemaName: request.SchemaName, RelationName: request.RelationName, RelationKind: request.RelationKind, Columns: request.Columns, EmptySnapshotPolicy: request.EmptySnapshotPolicy}
}

func (request RegisterRequest) validatePostgreSQLQuery() error {
	if request.SourceType != "POSTGRESQL_QUERY" || !validName(request.Name) || !validKind(request.Kind) ||
		!validSchemaID(request.DatabaseIdentity) || !validSchemaID(request.LineageID) || request.ProjectionRevision < 1 ||
		!validSchemaID(request.SchemaName) || !validSchemaID(request.RelationName) || request.ContractHash == "" ||
		!validPostgreSQLRelationKind(request.RelationKind) ||
		(request.EmptySnapshotPolicy != "HELD" && request.EmptySnapshotPolicy != "AUTHORITATIVE") {
		return &Error{code: CodeRequestInvalid}
	}
	if request.CredentialReference != "" && !validGeneratedID(request.CredentialReference, "cred_") {
		return &Error{code: CodeRequestInvalid}
	}
	limits := request.postgreSQLLimits()
	if limits.maxRows < 1 || limits.maxRows > 10_000_000 || limits.maxColumns < 1 || limits.maxColumns > 128 ||
		limits.maxFieldBytes < 1 || limits.maxFieldBytes > 1<<20 || limits.maxRowBytes < limits.maxFieldBytes || limits.maxRowBytes > 16<<20 ||
		limits.maxTotalBytes < limits.maxRowBytes || limits.maxTotalBytes > 1<<30 || limits.statementTimeoutMS < 100 || limits.statementTimeoutMS > 300_000 {
		return &Error{code: CodeRequestInvalid}
	}
	if request.SyncIntervalSeconds != 0 && (request.SyncIntervalSeconds < 60 || request.SyncIntervalSeconds > 86400) {
		return &Error{code: CodeRequestInvalid}
	}
	projection := request.postgreSQLProjection()
	// Replace the placeholder connection id with the deterministic tenant-free
	// identity only for contract validation; the real id is validated by the SQL
	// lineage function and is never accepted from the request.
	if err := projection.Validate(); err != nil {
		return &Error{code: CodeRequestInvalid, cause: err}
	}
	return nil
}

// validPostgreSQLRelationKind is the ADR-0097 closed set this surface
// accepts: the original DBA-reviewed VIEW/MATERIALIZED_VIEW contract, plus an
// ordinary or partitioned base table. postgresqlquery.Projection.Validate
// enforces the same set again once the full projection is assembled; this
// check exists so an unrecognized kind fails before that assembly.
func validPostgreSQLRelationKind(value string) bool {
	switch value {
	case "VIEW", "MATERIALIZED_VIEW", "TABLE", "PARTITIONED_TABLE":
		return true
	default:
		return false
	}
}

func (request RegisterRequest) validateRemote() error {
	if request.SourceType != "GIT" && request.SourceType != "MAIL" {
		return &Error{code: CodeRequestInvalid}
	}
	if !validName(request.Name) || !validKind(request.Kind) || !validGeneratedOrEmpty(request.CredentialReference, "cred_") {
		return &Error{code: CodeRequestInvalid}
	}
	if request.SourceType == "GIT" {
		if request.Provider == "MOUNT" {
			// MOUNT reads a pre-populated, read-only working-tree checkout
			// from the fixed worker mount root instead of an HTTPS hosting
			// API (V1-B). Endpoint is a safe mount-relative directory
			// identifier, never a host filesystem path, and WebBaseURL has
			// no meaning because the mount has no source-native deep link.
			if !validMountRelativePath(request.Endpoint) || request.WebBaseURL != "" || !validGitRepository(request.RepositoryID) ||
				!validGitBranch(request.BranchName) || !validGlobs(request.IncludeGlobs) || !validGlobs(request.ExcludeGlobs) ||
				request.MaxBlobBytes < 1 || request.MaxBlobBytes > 1<<30 || !validMediaTypes(request.TextMediaTypes, true, false) {
				return &Error{code: CodeRequestInvalid}
			}
			return nil
		}
		if (request.Provider != "GITHUB" && request.Provider != "GITLAB") || !validHTTPSBase(request.Endpoint) ||
			(request.WebBaseURL != "" && !validHTTPSBase(request.WebBaseURL)) || !validGitRepository(request.RepositoryID) ||
			!validGitBranch(request.BranchName) || !validGlobs(request.IncludeGlobs) || !validGlobs(request.ExcludeGlobs) ||
			request.MaxBlobBytes < 1 || request.MaxBlobBytes > 1<<30 || !validMediaTypes(request.TextMediaTypes, true, false) {
			return &Error{code: CodeRequestInvalid}
		}
		return nil
	}
	if request.Provider != "" && request.Provider != "IMAP" || !validIMAPEndpoint(request.Endpoint) ||
		!validKindText(request.Mailbox, 96) || !validKindText(request.Folder, 96) || !validKindText(request.Username, 256) {
		return &Error{code: CodeRequestInvalid}
	}
	if request.Since != nil && request.Since.IsZero() {
		return &Error{code: CodeRequestInvalid}
	}
	maxMessage := request.MaxMessageBytes
	if maxMessage == 0 {
		maxMessage = 8 << 20
	}
	maxAttachment := request.MaxAttachmentBytes
	if maxAttachment == 0 {
		maxAttachment = 4 << 20
	}
	if maxMessage < 1 || maxMessage > 64<<20 || maxAttachment < 1 || maxAttachment > 32<<20 || maxAttachment > maxMessage ||
		!validMediaTypes(request.AttachmentMediaTypes, request.IncludeAttachments, true) {
		return &Error{code: CodeRequestInvalid}
	}
	return nil
}

func validGeneratedOrEmpty(value, prefix string) bool {
	return value == "" || validGeneratedID(value, prefix)
}

func validHTTPSBase(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		netcanon.ValidCanonicalHost(parsed.Hostname()) && !strings.HasSuffix(parsed.Hostname(), ".")
}

// validMountRelativePath validates a MOUNT provider's Endpoint: a safe
// relative directory identifier under the worker's fixed source mount root,
// never an absolute host path, drive letter or traversal component. The
// connector re-validates the identical shape before opening the pinned root.
func validMountRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validIMAPEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || !netcanon.ValidCanonicalHost(host) || strings.HasSuffix(host, ".") || port == "" {
		return false
	}
	for _, character := range port {
		if character < '0' || character > '9' {
			return false
		}
	}
	parsed, err := strconv.Atoi(port)
	return err == nil && parsed >= 1 && parsed <= 65535
}

func validGitRepository(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\?#") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\r\n") {
			return false
		}
	}
	return true
}

func validGitBranch(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || value == "HEAD" ||
		strings.HasPrefix(value, "refs/") || strings.HasPrefix(value, "-") || strings.Contains(value, "..") ||
		strings.ContainsAny(value, "~^:?*[\\\r\n") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validKindText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && strings.TrimSpace(value) == value && !containsControl(value)
}

func validMediaTypes(values []string, required, attachments bool) bool {
	if required && len(values) == 0 || len(values) > 128 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 128 || strings.Count(value, "/") != 1 || strings.HasSuffix(value, "/") ||
			!strings.HasPrefix(value, "text/") && value != "application/json" && value != "application/xml" && value != "application/javascript" &&
				(!attachments || value != "application/pdf" && value != "image/png" && value != "image/jpeg" &&
					value != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" &&
					value != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" &&
					value != "application/vnd.openxmlformats-officedocument.presentationml.presentation") {
			return false
		}
		for _, character := range value {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || strings.ContainsRune("/+.-", character)) {
				return false
			}
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validGeneratedID(value, prefix string) bool {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if len(value) != len(prefix)+26 || !strings.HasPrefix(value, prefix) {
		return false
	}
	encoded := value[len(prefix):]
	if encoded[0] < '0' || encoded[0] > '7' {
		return false
	}
	for _, symbol := range encoded[1:] {
		if !strings.ContainsRune(alphabet, symbol) {
			return false
		}
	}
	return true
}

func postgresqlColumnsJSON(columns []postgresqlquery.Column) ([]byte, error) {
	items := make([]map[string]any, len(columns))
	for index, column := range columns {
		items[index] = map[string]any{"ordinal": column.Ordinal, "name": column.Name, "type_fingerprint": column.TypeFingerprint, "logical_type": column.LogicalType, "roles": column.Roles, "nullable": column.Nullable, "precision": column.Precision, "scale": column.Scale, "max_bytes": column.MaxBytes}
	}
	return canon.CanonicalJSON(items)
}

// validName mirrors the source_connection.name CHECK: trimmed, non-empty,
// bounded, no control characters.
func validName(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !containsControl(value)
}

// validSchemaID mirrors the source-scope.schema.json id pattern.
func validSchemaID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && schemaIDPattern.MatchString(value)
}

// validKind bounds the display kind, a short caller-chosen label.
func validKind(value string) bool {
	return len(value) >= 1 && len(value) <= 64 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !containsControl(value)
}

// validRelativeRoot mirrors the relativePath pattern of source-scope.schema.json:
// bounded, no leading or trailing separator, no control characters and no
// "." or ".." segment.
func validRelativeRoot(value string) bool {
	if len(value) == 0 || len(value) > 4096 || !utf8.ValidString(value) || containsControl(value) {
		return false
	}
	if value[0] == '/' || value[0] == '\\' || value[len(value)-1] == '/' || value[len(value)-1] == '\\' {
		return false
	}
	return validSegments(value)
}

// validGlobs mirrors the pathPatterns/pathPattern shapes: each pattern is
// bounded, free of control characters, relative and without "." or ".."
// segments.
func validGlobs(globs []string) bool {
	if len(globs) > 128 {
		return false
	}
	for _, glob := range globs {
		if len(glob) == 0 || len(glob) > 4096 || !utf8.ValidString(glob) || containsControl(glob) {
			return false
		}
		if glob[0] == '/' || glob[0] == '\\' || !validSegments(glob) {
			return false
		}
	}
	return true
}

func validSegments(value string) bool {
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7F {
			return true
		}
	}
	return false
}

var validFormats = map[string]bool{
	"PDF": true, "DOCX": true, "PPTX": true, "XLSX": true, "CSV": true, "TXT": true,
	"MARKDOWN": true, "HTML": true, "JSON": true, "XML": true, "EML": true,
	"SOURCE_CODE": true, "PNG": true, "JPEG": true,
}

func validFormat(value string) bool { return validFormats[value] }

func isSQLState(err error, state string) bool {
	// The PostgreSQL driver stays inside internal/platform/database; pgconn
	// errors are matched through the same narrow interface jobs.go uses.
	var sqlState interface{ SQLState() string }
	return errors.As(err, &sqlState) && sqlState.SQLState() == state
}

// activationJobMarker stamps every scope-sync job this service queues. It uses
// the existing closed `operation` payload vocabulary (jobs.Payload.Validate and
// db/migrations/000013's app.job_payload_is_safe already admit exactly this
// value), so no payload key is invented for it.
//
// Migration 000075 keys its "one live activation job per scope" partial unique
// index on this marker: the operator-facing activation authority may have at
// most one live unit of work per source scope, which is the database-level form
// of the read-then-enqueue promise this service makes above. Worker-internal
// recovery enqueues (crash resume, stale-lease fencing) carry no marker and are
// deliberately outside that constraint.
const activationJobMarker = "ACTIVATE"
