package ingestion

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/observation"
)

// uploadRootAlias and uploadRootIdentity are the one reserved (root_alias,
// root_identity) tuple that means "this FOLDER connection's content lives in
// public.source_uploaded_document, not a pre-mounted host directory"
// (UPL-1). No RegisterRequest from a real operator-configured mount can ever
// collide with it: the pair is fixed by the browser-upload source-creation
// path (registration.RegisterRequest is otherwise free-form per operator
// deployment, but the web client that creates a "documents" source always
// sends exactly this pair and never exposes it for editing).
const (
	uploadRootAlias    = "browser-uploads"
	uploadRootIdentity = "managed"
)

// uploadAdapter is the observation.Adapter for a browser-upload-backed
// FOLDER connection. Unlike observation.FolderAdapter it needs no pre-mounted
// root: it reads the exact same immutable, per-object bytes the owner's
// upload REST call wrote (registration.Service.UploadDocuments), scoped to
// one connection and re-checked against the trusted format allowlist exactly
// like a discovered file would be.
type uploadAdapter struct {
	db             *database.Store
	access         database.AccessContext
	connectionID   string
	scopeID        string
	revision       int64
	maxObjectBytes int64
}

func newUploadAdapter(db *database.Store, access database.AccessContext, connectionID, scopeID string, revision, maxObjectBytes int64) *uploadAdapter {
	return &uploadAdapter{db: db, access: access, connectionID: connectionID, scopeID: scopeID, revision: revision, maxObjectBytes: maxObjectBytes}
}

func (adapter *uploadAdapter) Kind() observation.Kind { return observation.KindDocument }

type uploadedRow struct {
	objectKey   string
	version     int64
	mediaType   string
	mediaFamily string
	contentHash string
	content     []byte
	uploadedAt  time.Time
}

func (adapter *uploadAdapter) Observe(ctx context.Context, request observation.Request) (observation.Page, error) {
	if adapter == nil || adapter.db == nil || ctx == nil || request.MaxObjects < 1 ||
		request.OrganizationID != adapter.access.OrganizationID || request.SourceScopeID != adapter.scopeID ||
		request.SourceScopeRevision != adapter.revision {
		return observation.Page{}, failure("INGEST_ADAPTER_INVALID", nil)
	}
	var rows []uploadedRow
	if err := adapter.db.Read(ctx, adapter.access, func(ctx context.Context, tx database.Transaction) error {
		result, queryErr := tx.Query(ctx, `
			SELECT object_key, version, media_type, media_family, content_sha256, content, uploaded_at
			FROM public.source_uploaded_document
			WHERE organization_id = $1 AND connection_id = $2
			ORDER BY object_key`, adapter.access.OrganizationID, adapter.connectionID)
		if queryErr != nil {
			return queryErr
		}
		defer result.Close()
		for result.Next() {
			var row uploadedRow
			if scanErr := result.Scan(&row.objectKey, &row.version, &row.mediaType, &row.mediaFamily,
				&row.contentHash, &row.content, &row.uploadedAt); scanErr != nil {
				return scanErr
			}
			rows = append(rows, row)
		}
		return result.Err()
	}); err != nil {
		return observation.Page{}, failure("INGEST_ADAPTER", err)
	}
	if len(rows) > request.MaxObjects {
		return observation.Page{}, failure("INGEST_ADAPTER_INVALID", nil)
	}
	page := observation.Page{OrganizationID: adapter.access.OrganizationID, Kind: observation.KindDocument, CoverageComplete: true}
	for _, row := range rows {
		if adapter.maxObjectBytes > 0 && int64(len(row.content)) > adapter.maxObjectBytes {
			page.Quarantined = append(page.Quarantined, observation.Quarantine{ExternalID: row.objectKey, Code: "UPLOAD_OBJECT_OVERSIZED"})
			continue
		}
		page.Objects = append(page.Objects, observation.Object{
			Kind: observation.KindDocument, ExternalID: row.objectKey,
			VersionKey: "hash:" + row.contentHash, ObjectType: "DOCUMENT",
			ContentHash: row.contentHash, ObservedAt: row.uploadedAt.UTC(),
			PayloadKind: observation.PayloadBytes,
			Document:    &observation.DocumentPayload{MediaType: row.mediaType, MediaFamily: row.mediaFamily, Bytes: row.content},
		})
	}
	return page, nil
}
