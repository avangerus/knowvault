package discovery

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// JobType is the durable queue type owned by this handler. The jobs package's
// existing queue claim surface remains closed over the database taxonomy; this
// package binds the new 000090 value without widening generic enqueue payloads.
const JobType jobs.Type = "SOURCE_DISCOVERY"

// ErrorCode is content-free and safe for worker logs. Connector errors are
// reduced to one of these codes; source SQL, credentials and catalog text never
// cross this package's error surface.
type ErrorCode string

const (
	CodeInvalid               ErrorCode = "DISCOVERY_HANDLER_INVALID"
	CodeNotFound              ErrorCode = "DISCOVERY_NOT_FOUND"
	CodePayloadInvalid        ErrorCode = "DISCOVERY_PAYLOAD_INVALID"
	CodeStartRejected         ErrorCode = "DISCOVERY_START_REJECTED"
	CodeTrustStale            ErrorCode = "DISCOVERY_TRUST_STALE"
	CodeCredentialUnavailable ErrorCode = "DISCOVERY_CREDENTIAL_UNAVAILABLE"
	CodeDatabaseChanged       ErrorCode = "DISCOVERY_DATABASE_CHANGED"
	CodePrivilegeChanged      ErrorCode = "DISCOVERY_PRIVILEGE_CHANGED"
	CodeLimitExceeded         ErrorCode = "DISCOVERY_LIMIT_EXCEEDED"
	CodeMetadataInvalid       ErrorCode = "DISCOVERY_METADATA_INVALID"
	CodeExternalUnavailable   ErrorCode = "DISCOVERY_EXTERNAL_UNAVAILABLE"
	CodeExpired               ErrorCode = "DISCOVERY_EXPIRED"
	CodeLeaseLost             ErrorCode = "DISCOVERY_LEASE_LOST"
	CodeInternalFailure       ErrorCode = "DISCOVERY_INTERNAL_FAILURE"
)

// Error preserves a stable code and keeps the dependency cause for trusted
// in-process diagnostics only.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps an unexpected handler error to a safe internal code.
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeInternalFailure
}

// CatalogConnector is the source-owned, trusted PostgreSQL catalog capability.
// Implementations resolve credentials and trust outside the job payload and
// return only one bounded catalog snapshot.
type CatalogConnector interface {
	DiscoverCatalog(context.Context, postgresqlquery.DiscoveryRequest) (postgresqlquery.CatalogSnapshot, error)
}

// Handler advances one claimed SOURCE_DISCOVERY job. It has no registration,
// scope or HTTP authority; successful work produces only an encrypted result
// artifact through the 000090 lifecycle functions.
type Handler struct {
	database   *database.Store
	queue      *jobs.Queue
	repository *repository.Repository
	codec      *artifactcrypto.Codec
	connector  CatalogConnector
	workerID   string
	leaseSecs  int
	newID      func(string) (string, error)
}

// NewHandler binds the worker's control-plane store, trusted trust-artifact
// repository, encryption codec and real source connector. Nil dependencies
// fail closed and cannot create an in-process fallback.
func NewHandler(databaseStore *database.Store, queue *jobs.Queue, artifactRepository *repository.Repository,
	codec *artifactcrypto.Codec, connector CatalogConnector, workerID string, leaseSeconds int,
	newID func(string) (string, error)) (*Handler, error) {
	if databaseStore == nil || queue == nil || artifactRepository == nil || codec == nil || connector == nil ||
		!validOpaque(workerID) || leaseSeconds < 1 || leaseSeconds > 3600 {
		return nil, &Error{code: CodeInvalid}
	}
	if newID == nil {
		newID = ids.New
	}
	return &Handler{database: databaseStore, queue: queue, repository: artifactRepository, codec: codec,
		connector: connector, workerID: workerID, leaseSecs: leaseSeconds, newID: newID}, nil
}

// Handle starts the exact request bound to the claimed lease, resolves the
// source-owned trust artifact, probes the real PostgreSQL catalogs twice, and
// commits the encrypted result and queue acknowledgement atomically.
func (h *Handler) Handle(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if h == nil || h.database == nil || h.queue == nil || h.repository == nil || h.codec == nil || h.connector == nil ||
		ctx == nil || access.Validate() != nil || access.RequestID != claimed.ID || claimed.Type != JobType ||
		!validGeneratedID(claimed.ID, "sdrq_") || claimed.LeaseEpoch < 1 || !validDiscoveryPayload(claimed.Payload, claimed.ID) {
		return &Error{code: CodePayloadInvalid}
	}

	if err := h.start(ctx, access, claimed); err != nil {
		// The start command leaves a still-PENDING request when its fifteen-minute
		// window has elapsed. Expire owns that terminal transition if the exact
		// lease is still live; a trust/security rejection remains unacknowledged so
		// queue reclamation can retry it after the control-plane state is repaired.
		if h.expire(ctx, access, claimed) == nil {
			return nil
		}
		return &Error{code: CodeStartRejected, cause: err}
	}

	runCtx, stopHeartbeat := h.startHeartbeat(ctx, access, claimed)
	defer func() { _ = stopHeartbeat() }()
	if err := h.heartbeat(runCtx, access, claimed); err != nil {
		return h.fail(ctx, access, claimed, CodeLeaseLost, err)
	}

	target, err := h.readTargetAndTrust(runCtx, access, claimed)
	if err != nil {
		return h.fail(ctx, access, claimed, CodeOf(err), err)
	}
	limits := target.limits()
	if err := limits.ValidateDurable(); err != nil {
		return h.fail(ctx, access, claimed, CodeLimitExceeded, err)
	}
	probeRequest := postgresqlquery.DiscoveryRequest{
		ConnectionID: target.connectionID, CredentialReference: target.credentialReference, Limits: limits,
	}
	first, err := h.connector.DiscoverCatalog(runCtx, probeRequest)
	if err != nil {
		return h.fail(ctx, access, claimed, mapConnectorCode(err), err)
	}
	second, err := h.connector.DiscoverCatalog(runCtx, probeRequest)
	if err != nil {
		return h.fail(ctx, access, claimed, mapConnectorCode(err), err)
	}
	if first.DatabaseOID != second.DatabaseOID || first.DatabaseName != second.DatabaseName {
		return h.fail(ctx, access, claimed, CodeDatabaseChanged, nil)
	}
	if first.PrivilegeDigest != second.PrivilegeDigest {
		return h.fail(ctx, access, claimed, CodePrivilegeChanged, nil)
	}

	resultID, err := h.newID("sdr")
	if err != nil {
		return h.fail(ctx, access, claimed, CodeInternalFailure, err)
	}
	artifactID, err := h.newID("artifact")
	if err != nil {
		return h.fail(ctx, access, claimed, CodeInternalFailure, err)
	}
	metadata, counts, err := buildMetadata(target, first)
	if err != nil {
		return h.fail(ctx, access, claimed, CodeOf(err), err)
	}
	secondMetadata, _, err := buildMetadata(target, second)
	if err != nil {
		return h.fail(ctx, access, claimed, CodeOf(err), err)
	}
	if !bytes.Equal(metadata, secondMetadata) {
		return h.fail(ctx, access, claimed, CodeDatabaseChanged, nil)
	}
	if err := h.stopAndCheckHeartbeat(stopHeartbeat, ctx); err != nil {
		return h.fail(ctx, access, claimed, CodeLeaseLost, err)
	}
	if ctx.Err() != nil {
		return h.fail(ctx, access, claimed, CodeExternalUnavailable, ctx.Err())
	}

	metadataHash := canon.Hash(metadata)
	databaseHash, err := databaseIdentityHash(first.DatabaseOID, first.DatabaseName)
	if err != nil {
		return h.fail(ctx, access, claimed, CodeMetadataInvalid, err)
	}
	resultHash, err := resultHash(resultHashInput{
		SchemaVersion: ResultSchemaVersion, OrganizationID: access.OrganizationID,
		ActorPrincipalID: target.actorPrincipalID, RequestID: claimed.ID, ResultID: resultID,
		ConnectionID: target.connectionID, ConnectionRevision: target.connectionRevision,
		TrustProfileHash: target.trustProfileHash, SecurityEpoch: target.securityEpoch,
		DatabaseIdentityHash: databaseHash, PrivilegeDigest: first.PrivilegeDigest,
		Status: counts.status, ViewCount: counts.viewCount, PreparedViewCount: counts.preparedCount,
		NeedsViewCount: counts.needsCount, MetadataPlaintextHash: metadataHash,
	})
	if err != nil {
		return h.fail(ctx, access, claimed, CodeMetadataInvalid, err)
	}
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceDiscoveryResultMetadata, access.OrganizationID, resultID)
	if err != nil {
		return h.fail(ctx, access, claimed, CodeInternalFailure, err)
	}
	envelope, err := h.codec.Seal(owner, metadata)
	if err != nil || envelope.PlaintextHash() != metadataHash {
		return h.fail(ctx, access, claimed, CodeMetadataInvalid, err)
	}
	if err := h.complete(ctx, access, claimed, resultID, artifactID, envelope, databaseHash, first.PrivilegeDigest, resultHash, counts); err != nil {
		return h.fail(ctx, access, claimed, CodeOf(err), err)
	}
	return nil
}

type target struct {
	actorPrincipalID     string
	connectionID         string
	connectionRevision   int64
	credentialReference  string
	trustProfileHash     string
	trustArtifactID      string
	maxViews             int
	maxColumns           int
	maxCommentBytes      int
	statementTimeoutMS   int
	transactionTimeoutMS int
	securityEpoch        int64
}

func (target target) limits() postgresqlquery.DiscoveryLimits {
	return postgresqlquery.DiscoveryLimits{
		MaxViews: target.maxViews, MaxColumns: target.maxColumns, MaxCommentBytes: target.maxCommentBytes,
		StatementTimeout:   time.Duration(target.statementTimeoutMS) * time.Millisecond,
		TransactionTimeout: time.Duration(target.transactionTimeoutMS) * time.Millisecond,
	}
}

func (h *Handler) start(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	return h.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.source_discovery_request_start($1, $2, $3, $4)`,
			claimed.ID, claimed.ID, h.workerID, claimed.LeaseEpoch)
		return err
	})
}

func (h *Handler) readTargetAndTrust(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) (target, error) {
	var result target
	var trustBytes []byte
	err := h.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		err := tx.QueryRow(ctx, `
			SELECT actor_principal_id, connection_id, connection_revision,
			       credential_reference, trust_profile_hash,
			       trust_profile_artifact_id, max_views, max_columns,
			       max_comment_bytes, statement_timeout_ms,
			       transaction_timeout_ms, security_epoch
			FROM app.source_discovery_worker_target($1, $2, $3, $4)`,
			claimed.ID, claimed.ID, h.workerID, claimed.LeaseEpoch).Scan(
			&result.actorPrincipalID, &result.connectionID, &result.connectionRevision,
			&result.credentialReference, &result.trustProfileHash, &result.trustArtifactID,
			&result.maxViews, &result.maxColumns, &result.maxCommentBytes,
			&result.statementTimeoutMS, &result.transactionTimeoutMS, &result.securityEpoch)
		if err != nil {
			return err
		}
		if !validGeneratedCredential(result.credentialReference) || !validGeneratedID(result.connectionID, "conn_") ||
			!validSHA256(result.trustProfileHash) || result.connectionRevision < 1 || result.securityEpoch < 1 ||
			!validOpaque(result.trustArtifactID) {
			return errMetadataInvalid
		}
		resourceID, err := sourceRevisionResourceID(access.OrganizationID, result.connectionID, result.connectionRevision)
		if err != nil {
			return err
		}
		owner, envelope, err := h.repository.Fetch(ctx, tx, access, artifactcrypto.SourceConnectionTrustConfig, resourceID)
		if err != nil {
			return err
		}
		trustBytes, err = h.codec.Open(owner, envelope)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		clearBytes(trustBytes)
		return target{}, &Error{code: CodeTrustStale, cause: err}
	}
	defer clearBytes(trustBytes)
	if err := validateTrustBytes(result, trustBytes); err != nil {
		return target{}, &Error{code: CodeTrustStale, cause: err}
	}
	return result, nil
}

type postgresTrust struct {
	SchemaVersion    string `json:"schema_version"`
	SourceType       string `json:"source_type"`
	ConnectionID     string `json:"connection_id"`
	DatabaseIdentity string `json:"database_identity"`
	LineageID        string `json:"lineage_id"`
}

func validateTrustBytes(target target, raw []byte) error {
	if len(raw) == 0 || canon.Hash(raw) != target.trustProfileHash {
		return errMetadataInvalid
	}
	var trust postgresTrust
	if err := jsonv2.Unmarshal(jsontext.Value(raw), &trust, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return errMetadataInvalid
	}
	if trust.SchemaVersion != "source-postgresql-query-trust-v1" || trust.SourceType != "POSTGRESQL_QUERY" ||
		trust.ConnectionID != target.connectionID || !validOpaque(trust.DatabaseIdentity) || !validOpaque(trust.LineageID) {
		return errMetadataInvalid
	}
	canonical, err := canon.PostgreSQLQueryTrustBytes(trust.ConnectionID, trust.DatabaseIdentity, trust.LineageID)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errMetadataInvalid
	}
	return nil
}

type resultCounts struct {
	status        string
	viewCount     int
	preparedCount int
	needsCount    int
}

func buildMetadata(target target, snapshot postgresqlquery.CatalogSnapshot) ([]byte, resultCounts, error) {
	if target.maxViews < 1 || target.maxViews > 64 || target.maxColumns < 1 || target.maxColumns > 256 ||
		target.maxCommentBytes < 1 || target.maxCommentBytes > 65536 ||
		snapshot.DatabaseOID < 1 || !validCatalogText(snapshot.DatabaseName, 128) || !validSHA256(snapshot.PrivilegeDigest) ||
		snapshot.Views == nil || len(snapshot.Views) > target.maxViews {
		return nil, resultCounts{}, &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
	}
	counts := resultCounts{viewCount: len(snapshot.Views)}
	for _, view := range snapshot.Views {
		if view.ConnectionID != target.connectionID || view.DatabaseOID != snapshot.DatabaseOID || view.DatabaseName != snapshot.DatabaseName ||
			view.RelationOID < 1 || !validCatalogText(view.SchemaName, 128) || !validCatalogText(view.RelationName, 128) ||
			!validRelationKind(view.RelationKind) || view.ApproxRowCount < -1 ||
			!validCatalogComment(view.Comment, target.maxCommentBytes) || len(view.Columns) == 0 || len(view.Columns) > target.maxColumns ||
			(view.Status != postgresqlquery.DiscoveryPrepared && view.Status != postgresqlquery.DiscoveryNeedsInterpretation) {
			return nil, resultCounts{}, &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
		}
		for index, column := range view.Columns {
			if column.Ordinal != index+1 || !validCatalogText(column.Name, 128) || column.TypeOID < 1 ||
				!validCatalogText(column.TypeName, 128) || !validOpaque(column.TypeFingerprint) ||
				!validCatalogComment(column.Comment, target.maxCommentBytes) {
				return nil, resultCounts{}, &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
			}
		}
		switch view.Status {
		case postgresqlquery.DiscoveryPrepared:
			if view.Interpretation != "" || view.Projection == nil || view.Projection.Validate() != nil ||
				view.Projection.ConnectionID != view.ConnectionID || view.Projection.SchemaName != view.SchemaName ||
				view.Projection.RelationName != view.RelationName || view.Projection.RelationKind != view.RelationKind {
				return nil, resultCounts{}, &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
			}
			counts.preparedCount++
		case postgresqlquery.DiscoveryNeedsInterpretation:
			if view.Projection != nil || !validInterpretation(view.Interpretation) {
				return nil, resultCounts{}, &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
			}
			counts.needsCount++
		}
	}
	if counts.needsCount == 0 {
		counts.status = resultSucceeded
	} else {
		counts.status = resultNeedsReview
	}
	metadata := Metadata{
		SchemaVersion: MetadataSchemaVersion, ConnectionID: target.connectionID,
		ConnectionRevision: target.connectionRevision, DatabaseOID: snapshot.DatabaseOID,
		DatabaseName: snapshot.DatabaseName, PrivilegeDigest: snapshot.PrivilegeDigest,
		Views: snapshot.Views,
	}
	encoded, err := marshalMetadata(metadata, target.maxViews)
	if err != nil || len(encoded) > 8<<20 {
		return nil, counts, &Error{code: CodeMetadataInvalid, cause: err}
	}
	return encoded, counts, nil
}

func validInterpretation(reason postgresqlquery.InterpretationReason) bool {
	switch reason {
	case postgresqlquery.InterpretationUnrecognizedFormat,
		postgresqlquery.InterpretationIncompleteContract,
		postgresqlquery.InterpretationMalformedContract,
		postgresqlquery.InterpretationUnsupportedType,
		postgresqlquery.InterpretationInvalidIdentifier,
		postgresqlquery.InterpretationNoPrimaryKey:
		return true
	default:
		return false
	}
}

// validRelationKind is the same ADR-0097 closed set the connector package
// enforces on Projection.RelationKind; the worker repeats it because the
// encrypted metadata payload is untrusted input until this check passes.
func validRelationKind(value string) bool {
	switch value {
	case "VIEW", "MATERIALIZED_VIEW", "TABLE", "PARTITIONED_TABLE":
		return true
	default:
		return false
	}
}

func validCatalogComment(value string, maxBytes int) bool {
	return value == "" || validCatalogText(value, maxBytes)
}

func (h *Handler) complete(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob,
	resultID, artifactID string, envelope artifactcrypto.Envelope, databaseHash, privilegeDigest, resultDigest string,
	counts resultCounts) error {
	return h.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_discovery_result_begin($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			claimed.ID, resultID, claimed.ID, h.workerID, claimed.LeaseEpoch, counts.status, counts.viewCount,
			counts.preparedCount, counts.needsCount, databaseHash, privilegeDigest, envelope.PlaintextHash(), resultDigest); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.source_discovery_result_bind_metadata($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
			claimed.ID, resultID, claimed.ID, h.workerID, claimed.LeaseEpoch, artifactID, envelope.SizeBytes(), envelope.Nonce(),
			envelope.Ciphertext(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(),
			envelope.AADHash(), envelope.PlaintextHash()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `SELECT app.source_discovery_request_complete($1, $2, $3, $4, $5, $6, $7, $8)`,
			claimed.ID, resultID, claimed.ID, h.workerID, claimed.LeaseEpoch, databaseHash, privilegeDigest, resultDigest)
		return err
	})
}

func (h *Handler) fail(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob, code ErrorCode, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cleanupErr error
	if code == CodeExpired {
		cleanupErr = h.expire(cleanupCtx, access, claimed)
	} else {
		cleanupErr = h.database.Write(cleanupCtx, access, func(ctx context.Context, tx database.Transaction) error {
			_, err := tx.Exec(ctx, `SELECT app.source_discovery_request_fail($1, $2, $3, $4, $5, $6)`,
				claimed.ID, claimed.ID, h.workerID, claimed.LeaseEpoch, string(code), 60)
			return err
		})
		if cleanupErr != nil && database.SQLStateCode(cleanupErr) == "55000" {
			cleanupErr = h.expire(cleanupCtx, access, claimed)
		}
	}
	if cleanupErr != nil {
		return &Error{code: CodeInternalFailure, cause: errors.Join(cause, cleanupErr)}
	}
	return &Error{code: code, cause: cause}
}

func (h *Handler) expire(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	return h.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.source_discovery_request_expire($1, $2, $3, $4)`, claimed.ID, claimed.ID, h.workerID, claimed.LeaseEpoch)
		return err
	})
}

func (h *Handler) heartbeat(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if err := h.queue.Heartbeat(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch, h.leaseSecs); err != nil {
		return &Error{code: CodeLeaseLost, cause: err}
	}
	return nil
}

type heartbeatState struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	err    error
}

func (h *Handler) startHeartbeat(parent context.Context, access database.AccessContext, claimed jobs.ClaimedJob) (context.Context, func() error) {
	ctx, cancel := context.WithCancel(parent)
	state := &heartbeatState{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(state.done)
		ticker := time.NewTicker(heartbeatInterval(h.leaseSecs))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := h.heartbeat(ctx, access, claimed); err != nil {
					state.mu.Lock()
					if ctx.Err() == nil {
						state.err = err
					}
					state.mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	return ctx, func() error {
		state.cancel()
		<-state.done
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.err
	}
}

func (h *Handler) stopAndCheckHeartbeat(stop func() error, ctx context.Context) error {
	if stop == nil {
		return &Error{code: CodeLeaseLost}
	}
	if err := stop(); err != nil {
		return err
	}
	if ctx == nil {
		return &Error{code: CodeExternalUnavailable}
	}
	if ctx.Err() != nil {
		return &Error{code: CodeExternalUnavailable, cause: ctx.Err()}
	}
	return nil
}

func heartbeatInterval(leaseSeconds int) time.Duration {
	interval := time.Duration(leaseSeconds) * time.Second / 3
	if interval > 30*time.Second {
		return 30 * time.Second
	}
	if interval < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	return interval
}

func validDiscoveryPayload(payload jobs.Payload, requestID string) bool {
	if len(payload) != 1 {
		return false
	}
	value, ok := payload["source_discovery_request_id"].(string)
	return ok && value == requestID && validGeneratedID(value, "sdrq_")
}

func mapConnectorCode(err error) ErrorCode {
	switch postgresqlquery.CodeOf(err) {
	case postgresqlquery.CodeDiscoveryInvalid:
		return CodeMetadataInvalid
	case postgresqlquery.CodeLimitExceeded:
		return CodeLimitExceeded
	case postgresqlquery.CodeDiscoveryUnavailable:
		return CodeExternalUnavailable
	default:
		return CodeCredentialUnavailable
	}
}

func sourceRevisionResourceID(organizationID, connectionID string, revision int64) (string, error) {
	if !validOpaque(organizationID) || !validGeneratedID(connectionID, "conn_") || revision < 1 {
		return "", errMetadataInvalid
	}
	raw, err := canon.CanonicalJSON(struct {
		ConnectionID   string `json:"connection_id"`
		OrganizationID string `json:"organization_id"`
		Revision       int64  `json:"revision"`
	}{ConnectionID: connectionID, OrganizationID: organizationID, Revision: revision})
	if err != nil {
		return "", errMetadataInvalid
	}
	return canon.Hash(raw), nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
