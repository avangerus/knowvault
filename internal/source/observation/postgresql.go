package observation

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// PostgreSQLReader is the already-qualified external read capability exposed
// by the live connector. The adapter receives a trusted credential reference at
// composition time; it is never present in Request, Object or Page.
type PostgreSQLReader interface {
	ReadProjection(context.Context, string, string, postgresqlquery.Projection, postgresqlquery.Limits) (postgresqlquery.Snapshot, error)
}

// PostgreSQLAdapter turns one immutable projection into the same observation
// page used by document/mail/Git adapters. SQL remains an instrument boundary:
// this type accepts no SQL string and derives identity only from declared
// projection identity columns.
type PostgreSQLAdapter struct {
	reader              PostgreSQLReader
	organizationID      string
	sourceScopeID       string
	sourceScopeRevision int64
	connectionID        string
	credentialReference string
	projection          postgresqlquery.Projection
	limits              postgresqlquery.Limits
	identityKey         []byte
	identityKeyVersion  int
}

func NewPostgreSQLAdapter(reader PostgreSQLReader, organizationID, sourceScopeID string, sourceScopeRevision int64,
	connectionID, credentialReference string, projection postgresqlquery.Projection, limits postgresqlquery.Limits,
	identityKey []byte, identityKeyVersion int) (*PostgreSQLAdapter, error) {
	if reader == nil || !validOpaque(organizationID) || !validOpaque(sourceScopeID) || sourceScopeRevision < 1 || sourceScopeRevision > 9007199254740991 ||
		!validOpaque(connectionID) || !validOpaque(credentialReference) || projection.Validate() != nil || limits.Validate() != nil || len(identityKey) == 0 || identityKeyVersion < 1 {
		return nil, &Error{code: CodeInvalidRequest}
	}
	keyCopy := append([]byte(nil), identityKey...)
	return &PostgreSQLAdapter{reader: reader, organizationID: organizationID, sourceScopeID: sourceScopeID,
		sourceScopeRevision: sourceScopeRevision, connectionID: connectionID,
		credentialReference: credentialReference, projection: projection, limits: limits,
		identityKey: keyCopy, identityKeyVersion: identityKeyVersion}, nil
}

func (adapter *PostgreSQLAdapter) Kind() Kind {
	if adapter == nil {
		return ""
	}
	return KindSQLBusinessData
}

func (adapter *PostgreSQLAdapter) Observe(ctx context.Context, request Request) (Page, error) {
	if adapter == nil || ctx == nil || !validRequest(request) || request.OrganizationID != adapter.organizationID ||
		request.SourceScopeID != adapter.sourceScopeID || request.SourceScopeRevision != adapter.sourceScopeRevision {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	snapshot, err := adapter.reader.ReadProjection(ctx, adapter.connectionID, adapter.credentialReference, adapter.projection, adapter.limits)
	if err != nil {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	return adapter.pageFromSnapshot(snapshot, request.MaxObjects, request.MaxBytes)
}

// ValidateSnapshot verifies a snapshot that was read by the same trusted
// connector path.  The ingestion handler uses this seam after its existing
// read, so the source-agnostic contract is exercised without issuing a second
// external query or allowing a caller to inject SQL.
func (adapter *PostgreSQLAdapter) ValidateSnapshot(snapshot postgresqlquery.Snapshot) error {
	_, err := adapter.SnapshotPage(snapshot)
	return err
}

// SnapshotPage materializes the already-read SQL snapshot at the
// source-agnostic observation boundary. The returned page carries the minimum
// business-object envelope and is safe for the ingestion owner to retain only
// transiently; it never contains SQL text or credentials.
func (adapter *PostgreSQLAdapter) SnapshotPage(snapshot postgresqlquery.Snapshot) (Page, error) {
	if adapter == nil {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	return adapter.pageFromSnapshot(snapshot, adapter.limits.MaxRows, int64(adapter.limits.MaxTotalBytes))
}

func (adapter *PostgreSQLAdapter) pageFromSnapshot(snapshot postgresqlquery.Snapshot, maxObjects int, maxBytes int64) (Page, error) {
	if adapter == nil || maxObjects < 1 || maxBytes < 1 || !snapshot.CoverageComplete || snapshot.RowCount != len(snapshot.Rows) {
		return Page{}, &Error{code: CodeAdapterRejected}
	}
	snapshotHash, err := postgresqlquery.SnapshotSetHash(snapshot.Rows)
	if err != nil || snapshotHash != snapshot.SnapshotHash {
		return Page{}, &Error{code: CodeAdapterRejected, cause: err}
	}
	page := Page{OrganizationID: adapter.organizationID, Kind: KindSQLBusinessData,
		CoverageComplete: true, SnapshotHash: snapshot.SnapshotHash}
	if len(snapshot.Rows) > maxObjects {
		return Page{}, &Error{code: CodeInvalidRequest}
	}
	for _, row := range snapshot.Rows {
		if len(row.Canonical) == 0 || canon.Hash(row.Canonical) != row.Hash {
			return Page{}, &Error{code: CodeAdapterRejected}
		}
		identity, identityErr := postgresqlquery.IdentityDigest(adapter.identityKey, adapter.identityKeyVersion, adapter.projection, row)
		if identityErr != nil {
			return Page{}, &Error{code: CodeAdapterRejected, cause: identityErr}
		}
		observedAt := time.Now().UTC()
		lastUpdatedAt, hasSourceUpdate := postgresqlLastUpdatedAt(adapter.projection, row)
		if !hasSourceUpdate {
			// A view without a declared VERSION_HINT still has a trustworthy
			// observation time. Keep the minimum envelope complete while making
			// freshness semantics explicit: the value is observation-based, not a
			// fabricated source timestamp.
			lastUpdatedAt = observedAt
		}
		entityVersion := "native:" + row.Hash
		contract := BusinessObjectContract{
			EntityID: identity, EntityVersion: entityVersion, LastUpdatedAt: lastUpdatedAt,
			Payload: append([]byte(nil), row.Canonical...), PayloadFormat: PayloadFormatJSON,
			Provenance: BusinessObjectProvenance{
				SourceKind: string(KindSQLBusinessData), OrganizationID: adapter.organizationID,
				SourceScopeID: adapter.sourceScopeID, SourceScopeRevision: adapter.sourceScopeRevision,
				ConnectionID: adapter.projection.ConnectionID, DatabaseIdentity: adapter.projection.DatabaseIdentity,
				ProjectionLineageID: adapter.projection.LineageID, ProjectionRevision: adapter.projection.Revision,
				ProjectionContractHash: adapter.projection.ContractHash, RowVersionHash: row.Hash,
			},
		}
		var sourceUpdatedAt *time.Time
		if hasSourceUpdate {
			value := lastUpdatedAt
			sourceUpdatedAt = &value
		}
		page.Objects = append(page.Objects, Object{
			Kind: KindSQLBusinessData, ExternalID: identity,
			VersionKey: entityVersion, ObjectType: "SQL_BUSINESS_OBJECT",
			ContentHash: row.Hash, ObservedAt: observedAt, SourceUpdatedAt: sourceUpdatedAt,
			PayloadKind: PayloadTypedRow,
			BusinessRow: &BusinessRowPayload{Projection: adapter.projection, Row: row, Contract: contract},
		})
	}
	request := Request{OrganizationID: adapter.organizationID, SourceScopeID: adapter.sourceScopeID,
		SourceScopeRevision: adapter.sourceScopeRevision, MaxObjects: maxObjects, MaxBytes: maxBytes}
	if err := page.Validate(request); err != nil {
		return Page{}, err
	}
	return page, nil
}

func postgresqlLastUpdatedAt(projection postgresqlquery.Projection, row postgresqlquery.Row) (time.Time, bool) {
	for _, column := range projection.Columns {
		if !postgresqlHasRole(column.Roles, postgresqlquery.RoleVersionHint) {
			continue
		}
		value, ok := postgresqlValueAt(row.Values, column.Ordinal)
		if !ok || value.ValueTag == "NULL" {
			continue
		}
		text, ok := value.Value.(string)
		if !ok || text == "" {
			continue
		}
		var parsed time.Time
		var err error
		switch column.LogicalType {
		case postgresqlquery.TypeTimestamptz:
			parsed, err = time.Parse(time.RFC3339Nano, text)
		case postgresqlquery.TypeTimestamp:
			parsed, err = time.ParseInLocation("2006-01-02T15:04:05.999999999", text, time.UTC)
			if err != nil {
				parsed, err = time.ParseInLocation("2006-01-02 15:04:05.999999999", text, time.UTC)
			}
		case postgresqlquery.TypeDate:
			parsed, err = time.ParseInLocation("2006-01-02", text, time.UTC)
		default:
			continue
		}
		if err == nil && !parsed.IsZero() {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

func postgresqlHasRole(roles []postgresqlquery.Role, wanted postgresqlquery.Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

func postgresqlValueAt(values []postgresqlquery.ValueEntry, ordinal int) (postgresqlquery.ValueEntry, bool) {
	for _, value := range values {
		if value.Ordinal == ordinal {
			return value, true
		}
	}
	return postgresqlquery.ValueEntry{}, false
}
