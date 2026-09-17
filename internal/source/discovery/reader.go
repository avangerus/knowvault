package discovery

import (
	"context"
	"database/sql"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// ReadResult is the bounded OWNER projection of one discovery request. Views
// are present only after a live encrypted terminal result has been authorized,
// loaded and decrypted by this service.
type ReadResult struct {
	RequestID                    string
	RequestStatus                string
	ResultID                     string
	ResultStatus                 string
	ViewCount                    int
	PreparedViewCount            int
	NeedsInterpretationViewCount int
	FailureCode                  string
	ExpiresAt                    time.Time
	Views                        []View
	connectionID                 string
	connectionRevision           int64
}

// View is a browser-safe catalog item. Selector is server-derived and is the
// only view coordinate a later registration request may return to the server.
type View struct {
	Selector       string
	SchemaName     string
	RelationName   string
	RelationKind   string
	Comment        string
	Status         postgresqlquery.DiscoveryStatus
	Interpretation postgresqlquery.InterpretationReason
	Columns        []Column
	projection     *postgresqlquery.Projection
}

// SelectedView is the trusted registration input recovered from one live
// encrypted discovery result. The browser supplies only RequestID and
// Selector; every projection field remains server-owned.
type SelectedView struct {
	RequestID          string
	ResultID           string
	Selector           string
	ConnectionID       string
	ConnectionRevision int64
	Projection         postgresqlquery.Projection
}

// Column is read-only catalog metadata. Roles are present only when the
// external view carries a valid explicit BusinessObjectContract.
type Column struct {
	Ordinal     int
	Name        string
	TypeName    string
	LogicalType postgresqlquery.LogicalType
	Nullable    bool
	Precision   int
	Scale       int
	MaxBytes    int
	Comment     string
	Roles       []postgresqlquery.Role
}

// Reader authorizes and decrypts discovery results for the source-management
// HTTP surface. It has no job, registration or activation authority.
type Reader struct {
	database         *database.Store
	codec            *artifactcrypto.Codec
	digestKey        []byte
	digestKeyVersion int
}

// NewReader binds the application database role, artifact codec, and keyed
// digest material used to issue opaque per-view selectors.
func NewReader(databaseStore *database.Store, codec *artifactcrypto.Codec, digestKey []byte, digestKeyVersion int) (*Reader, error) {
	if databaseStore == nil || codec == nil || len(digestKey) != 32 || digestKeyVersion < 1 {
		return nil, &Error{code: CodeInvalid}
	}
	return &Reader{database: databaseStore, codec: codec,
		digestKey: append([]byte(nil), digestKey...), digestKeyVersion: digestKeyVersion}, nil
}

// Get returns current request state and, for a successful still-live result,
// the bounded decrypted view inventory. Missing and unauthorized requests have
// the same content-free error.
func (reader *Reader) Get(ctx context.Context, access database.AccessContext, requestID string) (ReadResult, error) {
	if reader == nil || reader.database == nil || reader.codec == nil || ctx == nil ||
		access.Validate() != nil || !validGeneratedID(requestID, "sdrq_") {
		return ReadResult{}, &Error{code: CodeInvalid}
	}
	var result ReadResult
	err := reader.database.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var resultID, resultStatus, failureCode sql.NullString
		var viewCount, preparedCount, needsCount sql.NullInt64
		if err := tx.QueryRow(ctx, `SELECT request_id, request_status, result_id,
			result_status, view_count, prepared_view_count,
			needs_interpretation_view_count, failure_code, expires_at
			FROM app.source_discovery_request_status($1)`, requestID).Scan(
			&result.RequestID, &result.RequestStatus, &resultID, &resultStatus,
			&viewCount, &preparedCount, &needsCount, &failureCode, &result.ExpiresAt); err != nil {
			return err
		}
		result.ResultID = resultID.String
		result.ResultStatus = resultStatus.String
		result.ViewCount = int(viewCount.Int64)
		result.PreparedViewCount = int(preparedCount.Int64)
		result.NeedsInterpretationViewCount = int(needsCount.Int64)
		result.FailureCode = failureCode.String
		if result.RequestStatus != "SUCCEEDED" {
			return nil
		}
		return reader.readViews(ctx, tx, access, &result)
	})
	if err != nil {
		var discoveryError *Error
		if errors.As(err, &discoveryError) {
			return ReadResult{}, discoveryError
		}
		if database.IsNotFound(err) || database.SQLStateCode(err) == "42501" {
			return ReadResult{}, &Error{code: CodeNotFound, cause: err}
		}
		return ReadResult{}, &Error{code: CodeInternalFailure, cause: err}
	}
	return result, nil
}

// Select resolves an opaque view selector to the exact server-generated
// projection in a live OWNER-authorized result. Views needing interpretation
// cannot cross this registration boundary.
func (reader *Reader) Select(ctx context.Context, access database.AccessContext, requestID, selector string) (SelectedView, error) {
	if !validViewSelector(selector) {
		return SelectedView{}, &Error{code: CodeInvalid}
	}
	result, err := reader.Get(ctx, access, requestID)
	if err != nil {
		return SelectedView{}, err
	}
	for _, view := range result.Views {
		if view.Selector != selector {
			continue
		}
		if view.Status != postgresqlquery.DiscoveryPrepared || view.projection == nil {
			return SelectedView{}, &Error{code: CodeInvalid}
		}
		projection := cloneProjection(*view.projection)
		return SelectedView{
			RequestID: requestID, ResultID: result.ResultID, Selector: selector,
			ConnectionID:       projection.ConnectionID,
			ConnectionRevision: result.connectionRevision, Projection: projection,
		}, nil
	}
	return SelectedView{}, &Error{code: CodeNotFound}
}

func (reader *Reader) readViews(ctx context.Context, tx database.Transaction, access database.AccessContext, result *ReadResult) error {
	var requestID, resultID, resultStatus, connectionID, databaseIdentityDigest, privilegeDigest, artifactID string
	var connectionRevision int64
	var viewCount, preparedCount, needsCount, sizeBytes int
	var ciphertext, nonce, wrappedDEK []byte
	var wrappedDEKHash, kekReference, aadHash, plaintextHash string
	var kekVersion int64
	if err := tx.QueryRow(ctx, `SELECT request_id, result_id, result_status,
		connection_id, connection_revision, database_identity_hash,
		privilege_digest, view_count, prepared_view_count,
		needs_interpretation_view_count, artifact_id, ciphertext, size_bytes,
		nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
		aad_hash, plaintext_hash
		FROM app.source_discovery_result_read_for_owner_v2($1)`, result.RequestID).Scan(
		&requestID, &resultID, &resultStatus, &connectionID, &connectionRevision,
		&databaseIdentityDigest, &privilegeDigest, &viewCount, &preparedCount,
		&needsCount, &artifactID, &ciphertext,
		&sizeBytes, &nonce, &wrappedDEK, &wrappedDEKHash, &kekReference,
		&kekVersion, &aadHash, &plaintextHash); err != nil {
		if database.IsNotFound(err) {
			return &Error{code: CodeExpired, cause: err}
		}
		return err
	}
	if requestID != result.RequestID || resultID != result.ResultID || resultStatus != result.ResultStatus ||
		viewCount != result.ViewCount || preparedCount != result.PreparedViewCount || needsCount != result.NeedsInterpretationViewCount ||
		artifactID == "" || connectionRevision < 1 {
		return &Error{code: CodeMetadataInvalid, cause: errMetadataInvalid}
	}
	result.connectionID = connectionID
	result.connectionRevision = connectionRevision
	owner, err := artifactcrypto.NewOwnerIdentity(
		artifactcrypto.SourceDiscoveryResultMetadata, access.OrganizationID, resultID)
	if err != nil {
		return &Error{code: CodeMetadataInvalid, cause: err}
	}
	envelope := artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM,
		ciphertext, sizeBytes, nonce, wrappedDEK, wrappedDEKHash, kekReference,
		kekVersion, aadHash, plaintextHash)
	plaintext, err := reader.codec.Open(owner, envelope)
	if err != nil {
		return &Error{code: CodeMetadataInvalid, cause: err}
	}
	defer clearBytes(plaintext)
	var metadata Metadata
	if err := jsonv2.Unmarshal(jsontext.Value(plaintext), &metadata,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return &Error{code: CodeMetadataInvalid, cause: errors.Join(err, errMetadataInvalid)}
	}
	identityDigest, digestErr := databaseIdentityHash(metadata.DatabaseOID, metadata.DatabaseName)
	if !metadata.Validate(64) || metadata.ConnectionID != connectionID ||
		metadata.ConnectionRevision != connectionRevision || len(metadata.Views) != viewCount ||
		digestErr != nil || identityDigest != databaseIdentityDigest || metadata.PrivilegeDigest != privilegeDigest {
		return &Error{code: CodeMetadataInvalid, cause: errors.Join(digestErr, errMetadataInvalid)}
	}
	views := make([]View, len(metadata.Views))
	for index, discovered := range metadata.Views {
		selector, err := reader.viewSelector(resultID, discovered)
		if err != nil {
			return &Error{code: CodeMetadataInvalid, cause: err}
		}
		roles := make(map[int][]postgresqlquery.Role)
		if discovered.Projection != nil {
			for _, column := range discovered.Projection.Columns {
				roles[column.Ordinal] = append([]postgresqlquery.Role(nil), column.Roles...)
			}
		}
		columns := make([]Column, len(discovered.Columns))
		for columnIndex, column := range discovered.Columns {
			columns[columnIndex] = Column{
				Ordinal: column.Ordinal, Name: column.Name, TypeName: column.TypeName,
				LogicalType: column.LogicalType, Nullable: column.Nullable,
				Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes,
				Comment: column.Comment, Roles: roles[column.Ordinal],
			}
		}
		views[index] = View{
			Selector: selector, SchemaName: discovered.SchemaName,
			RelationName: discovered.RelationName, RelationKind: discovered.RelationKind,
			Comment: discovered.Comment, Status: discovered.Status,
			Interpretation: discovered.Interpretation, Columns: columns,
			projection: discovered.Projection,
		}
	}
	result.Views = views
	return nil
}

func validViewSelector(value string) bool {
	if len(value) != len("sdv_")+64 || !strings.HasPrefix(value, "sdv_") {
		return false
	}
	for _, character := range value[len("sdv_"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func cloneProjection(projection postgresqlquery.Projection) postgresqlquery.Projection {
	columns := make([]postgresqlquery.Column, len(projection.Columns))
	for index, column := range projection.Columns {
		column.Roles = append([]postgresqlquery.Role(nil), column.Roles...)
		columns[index] = column
	}
	projection.Columns = columns
	return projection
}

func (reader *Reader) viewSelector(resultID string, view postgresqlquery.ViewDiscovery) (string, error) {
	raw, err := canon.CanonicalJSON(struct {
		ResultID     string `json:"result_id"`
		RelationOID  uint32 `json:"relation_oid"`
		SchemaName   string `json:"schema_name"`
		RelationName string `json:"relation_name"`
	}{ResultID: resultID, RelationOID: view.RelationOID, SchemaName: view.SchemaName, RelationName: view.RelationName})
	if err != nil {
		return "", err
	}
	digest := canon.HMACDigest(reader.digestKey, reader.digestKeyVersion, raw)
	separator := strings.LastIndexByte(digest, ':')
	if separator < 0 || len(digest[separator+1:]) != 64 {
		return "", errMetadataInvalid
	}
	return "sdv_" + digest[separator+1:], nil
}
