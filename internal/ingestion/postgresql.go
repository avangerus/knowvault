package ingestion

// This file owns the worker-side PostgreSQL business-object publication slice.
// It deliberately shares only the *artifact publication primitives* with the
// folder pipeline; the external relational snapshot itself is atomic and is
// never fed through per-file discovery/reconciliation code.

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"sort"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/observation"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

const (
	postgresqlQueryExtractorName = "knowvault-postgresql-query-reader"
	// A publication transaction owns the job row lock, so the outer lease
	// heartbeat cannot update it while rows are being written. Renew inside the
	// transaction at bounded row boundaries instead. The new lease function
	// uses one fresh clock instant and therefore cannot revive an expired lease.
	postgresqlPublicationHeartbeatBatch = 32
	// The typed AGG-1 projection (db/migrations/000073) is derived from cells
	// this extractor ALREADY published, so it does not change the extraction:
	// reconcileStructuredSnapshotCells backfills an existing snapshot in place.
	// Moving the version instead would demand a re-extraction, and
	// question_context_active_extraction_fk pins the active extraction of every
	// version an earlier answer cited — a parser-identity bump would abort the
	// whole scope sync on the first such version (observed live on the acc
	// stand: SQLSTATE 23503).
	postgresqlQueryExtractorVersion = "1.0"
)

// PostgreSQLSnapshotRequest is the immutable hand-off between the external
// connector and the local catalog owner. Snapshot rows are typed canonical
// descriptors; no DSN, SQL or external driver handle can cross this boundary.
type PostgreSQLSnapshotRequest struct {
	ScopeID         string
	ScopeRevision   int64
	SyncRunID       string
	Projection      postgresqlquery.Projection
	Snapshot        postgresqlquery.Snapshot
	ObservationPage *observation.Page
	Claimed         jobs.ClaimedJob
}

type PostgreSQLPublishResult struct {
	ObjectsSeen       int
	ObjectsIngested   int
	VersionsCreated   int
	EvidencePublished int
	RowsReconciled    int
}

// PublishPostgreSQLSnapshot publishes one complete, already-attested external
// snapshot through the worker catalog. All object/version/extraction/evidence
// writes and absence reconciliation are one local lease-fenced transaction.
// A partial, empty-held, tampered or duplicate-identity snapshot writes nothing.
func (h *Handler) PublishPostgreSQLSnapshot(ctx context.Context, access database.AccessContext, request PostgreSQLSnapshotRequest) (PostgreSQLPublishResult, error) {
	if h == nil || h.db == nil || h.repo == nil || h.codec == nil || h.audit == nil || h.newID == nil ||
		access.Validate() != nil || request.Claimed.Type != jobs.TypePostgreSQLQuerySync ||
		!validPostgreSQLScopeID(request.ScopeID) || request.ScopeRevision < 1 || !validPostgreSQLRunID(request.SyncRunID) {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_REQUEST_INVALID", nil)
	}
	if err := request.Projection.Validate(); err != nil {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_PROJECTION_INVALID", err)
	}
	if !request.Snapshot.CoverageComplete || request.Snapshot.RowCount != len(request.Snapshot.Rows) {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_INCOMPLETE_SNAPSHOT", nil)
	}
	if len(request.Snapshot.Rows) == 0 && request.Projection.EmptySnapshotPolicy != "AUTHORITATIVE" {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_EMPTY_SNAPSHOT_HELD", nil)
	}
	if request.ObservationPage != nil {
		maxObjects := len(request.Snapshot.Rows)
		if maxObjects < 1 {
			maxObjects = 1
		}
		pageRequest := observation.Request{OrganizationID: access.OrganizationID, SourceScopeID: request.ScopeID,
			SourceScopeRevision: request.ScopeRevision, MaxObjects: maxObjects, MaxBytes: 1 << 40}
		if request.ObservationPage.Validate(pageRequest) != nil || request.ObservationPage.Kind != observation.KindSQLBusinessData || len(request.ObservationPage.Objects) != len(request.Snapshot.Rows) {
			return PostgreSQLPublishResult{}, failure("PG_QUERY_OBSERVATION_INVALID", nil)
		}
	}
	if snapshotHash, err := postgresqlquery.SnapshotSetHash(request.Snapshot.Rows); err != nil || snapshotHash != request.Snapshot.SnapshotHash {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_SNAPSHOT_TAMPERED", err)
	}
	// Validate every row and reject duplicate identity before opening the write
	// transaction. This makes a malformed result all-or-nothing even when the
	// external connector had staged it in memory for a long time.
	identityDigests := make([]string, 0, len(request.Snapshot.Rows))
	rowsByIdentity := make(map[string]postgresqlquery.Row, len(request.Snapshot.Rows))
	for _, row := range request.Snapshot.Rows {
		if len(row.Canonical) == 0 || row.Hash == "" || !bytes.Equal(row.Canonical, mustCanonicalValues(row.Values)) || canon.Hash(row.Canonical) != row.Hash {
			return PostgreSQLPublishResult{}, failure("PG_QUERY_ROW_INVALID", nil)
		}
		canonical, err := postgresqlquery.CanonicalizeRow(request.Projection.Columns, valuesFromEntries(row.Values))
		if err != nil || !bytes.Equal(canonical.Canonical, row.Canonical) {
			return PostgreSQLPublishResult{}, failure("PG_QUERY_ROW_INVALID", err)
		}
		identity, err := postgresqlquery.IdentityDigest(h.digester.Key, h.digester.KeyVersion, request.Projection, row)
		if err != nil {
			return PostgreSQLPublishResult{}, failure("PG_QUERY_IDENTITY_INVALID", err)
		}
		if _, exists := rowsByIdentity[identity]; exists {
			return PostgreSQLPublishResult{}, failure("PG_QUERY_DUPLICATE_IDENTITY", nil)
		}
		rowsByIdentity[identity] = row
		identityDigests = append(identityDigests, identity)
	}
	if request.ObservationPage != nil {
		for index, row := range request.Snapshot.Rows {
			object := request.ObservationPage.Objects[index]
			identity, err := postgresqlquery.IdentityDigest(h.digester.Key, h.digester.KeyVersion, request.Projection, row)
			if err != nil || object.ExternalID != identity || object.BusinessRow == nil || object.BusinessRow.Row.Hash != row.Hash || object.BusinessRow.Contract.EntityID != identity || object.BusinessRow.Contract.EntityVersion != object.VersionKey {
				return PostgreSQLPublishResult{}, failure("PG_QUERY_OBSERVATION_INVALID", err)
			}
		}
	}
	sort.Strings(identityDigests)

	var result PostgreSQLPublishResult
	result.ObjectsSeen = len(request.Snapshot.Rows)
	err := h.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `SELECT app.lock_job_lease($1, $2, $3)`, request.Claimed.ID, h.workerID, request.Claimed.LeaseEpoch); err != nil {
			return err
		}
		if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `SELECT app.assert_scope_revision_syncing($1, $2)`, request.ScopeID, request.ScopeRevision); err != nil {
			return err
		}
		if err := h.verifyPostgreSQLProjection(txCtx, tx, access.OrganizationID, request); err != nil {
			return err
		}
		profileBytes, profileHash, err := postgresqlExtractionProfile(request.Projection)
		if err != nil {
			return err
		}
		for index, row := range request.Snapshot.Rows {
			if index > 0 && index%postgresqlPublicationHeartbeatBatch == 0 {
				if err := h.injectFault("postgresql_publication_batch"); err != nil {
					return err
				}
				if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
					return err
				}
			}
			identity, err := postgresqlquery.IdentityDigest(h.digester.Key, h.digester.KeyVersion, request.Projection, row)
			if err != nil {
				return err
			}
			objectID, created, err := h.ensurePostgreSQLObject(txCtx, tx, access, request, identity, row)
			if err != nil {
				return err
			}
			if created {
				result.ObjectsIngested++
				if err := h.auditEntity(txCtx, access, tx, audit.ActionSourceObjectIngested, audit.ResourceSourceObject, objectID, request.SyncRunID, request.Claimed.ID); err != nil {
					return err
				}
			}
			versionID, versionCreated, err := h.ensureVersion(txCtx, tx, access, objectID, "hash:"+row.Hash, row.Hash)
			if err != nil {
				return err
			}
			if versionCreated {
				result.VersionsCreated++
				if err := h.auditEntity(txCtx, access, tx, audit.ActionSourceVersionCreated, audit.ResourceSourceObject, versionID, request.SyncRunID, request.Claimed.ID); err != nil {
					return err
				}
			}
			var already bool
			if err := tx.QueryRow(txCtx, `SELECT EXISTS (SELECT 1 FROM public.source_extraction WHERE organization_id=$1 AND source_version_id=$2 AND profile_hash=$3 AND status='SUCCEEDED')`, access.OrganizationID, versionID, profileHash).Scan(&already); err != nil {
				return err
			}
			if already {
				if err := h.publishObjectPresence(txCtx, tx, access, request.Claimed, request.ScopeID, request.ScopeRevision, request.SyncRunID, objectID, versionID, true); err != nil {
					return err
				}
				if err := h.reconcileStructuredSnapshotCells(txCtx, tx, access, request, objectID, versionID, identity, row, profileHash); err != nil {
					return err
				}
				if h.graph != nil {
					if err := h.projectGraphForPostgreSQLRow(txCtx, tx, access, request, objectID, versionID, row, profileHash); err != nil {
						return err
					}
				}
				if h.searchRepository != nil {
					if err := h.reconcilePostgreSQLSearchChunks(txCtx, tx, access, request, versionID, identity, row, profileHash); err != nil {
						return err
					}
				}
				continue
			}
			published, err := h.publishPostgreSQLRow(txCtx, tx, access, request, objectID, versionID, versionCreated, row, identity, profileBytes, profileHash)
			if err != nil {
				return err
			}
			result.EvidencePublished += published
			if err := h.publishObjectPresence(txCtx, tx, access, request.Claimed, request.ScopeID, request.ScopeRevision, request.SyncRunID, objectID, versionID, false); err != nil {
				return err
			}
			if h.graph != nil && published > 0 {
				if err := h.projectGraphForPostgreSQLRow(txCtx, tx, access, request, objectID, versionID, row, profileHash); err != nil {
					return err
				}
			}
		}
		if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
			return err
		}
		removed, err := h.reconcilePostgreSQL(txCtx, tx, access, request, identityDigests)
		if err != nil {
			return err
		}
		result.RowsReconciled = removed
		if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
			return err
		}
		updated, err := tx.Exec(txCtx, `UPDATE public.sync_run SET objects_seen=$2, objects_ingested=$3, versions_created=$4, evidence_published=$5, quarantined=0, status='SUCCEEDED', completed_at=now(), coverage_complete=true, error_code=NULL WHERE organization_id=$1 AND id=$6 AND status='RUNNING'`, access.OrganizationID, result.ObjectsSeen, result.ObjectsIngested, result.VersionsCreated, result.EvidencePublished, request.SyncRunID)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return failure("PG_QUERY_SYNC_RUN_NOT_RUNNING", nil)
		}
		rows, err := tx.Query(txCtx, `SELECT outcome, closed_object_id FROM app.source_scope_activate_revision($1,$2,$3,$4,$5,$6)`, request.ScopeID, request.ScopeRevision, request.SyncRunID, request.Claimed.ID, h.workerID, request.Claimed.LeaseEpoch)
		if err != nil {
			return err
		}
		var outcome string
		var closed []string
		for rows.Next() {
			var rowOutcome string
			var objectID *string
			if err := rows.Scan(&rowOutcome, &objectID); err != nil {
				rows.Close()
				return err
			}
			outcome = rowOutcome
			if objectID != nil {
				closed = append(closed, *objectID)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if outcome == "CUTOVER" {
			if err := h.auditScopeActivated(txCtx, access, tx, request.ScopeID, request.ScopeRevision, request.SyncRunID); err != nil {
				return err
			}
		} else if err := h.auditSync(txCtx, access, tx, request.ScopeID, request.SyncRunID); err != nil {
			return err
		}
		if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
			return err
		}
		// Test-only delay at the tail boundary proves that the final renewal is
		// inside the same transaction and still fences the commit.
		if err := h.injectFault("postgresql_publication_tail"); err != nil {
			return err
		}
		for index, objectID := range closed {
			if index > 0 && index%postgresqlPublicationHeartbeatBatch == 0 {
				if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
					return err
				}
			}
			if err := h.auditObjectClosure(txCtx, tx, access, objectID, request.SyncRunID, request.Claimed.ID); err != nil {
				return err
			}
		}
		if err := h.renewPostgreSQLPublicationLease(txCtx, tx, request.Claimed); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return PostgreSQLPublishResult{}, failure("PG_QUERY_PUBLICATION_FAILED", err)
	}
	return result, nil
}

// renewPostgreSQLPublicationLease renews a live lease from the same
// transaction that holds the publication's job-row lock. A separate queue
// heartbeat would block behind that lock until this transaction commits, which
// is too late for a large snapshot. The SQL function is the sole lease guard:
// it checks the exact organization, worker, epoch, RUNNING state and a live
// deadline before changing only lease_deadline.
func (h *Handler) renewPostgreSQLPublicationLease(ctx context.Context, tx database.Transaction, claimed jobs.ClaimedJob) error {
	seconds := h.leaseExtensionSeconds
	if seconds < 1 || seconds > 3600 {
		seconds = 60
	}
	_, err := tx.Exec(ctx, `SELECT app.heartbeat_job($1, $2, $3, $4)`,
		claimed.ID, h.workerID, claimed.LeaseEpoch, seconds)
	return err
}

func (h *Handler) verifyPostgreSQLProjection(ctx context.Context, tx database.Transaction, organization string, request PostgreSQLSnapshotRequest) error {
	columns, err := postgresqlColumnsJSON(request.Projection.Columns)
	if err != nil {
		return err
	}
	var (
		status, connectionID, databaseIdentity, lineageID, contractVersion, contractHash string
		schemaName, relationName, relationKind                                           string
		projectionRevision, scopeRevision                                                int64
		columnsJSON                                                                      []byte
	)
	err = tx.QueryRow(ctx, `SELECT status, connection_id, database_identity, lineage_id, projection_revision, contract_version, contract_hash, schema_name, relation_name, relation_kind, columns_json, source_scope_revision FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=$3`, organization, request.ScopeID, request.ScopeRevision).Scan(&status, &connectionID, &databaseIdentity, &lineageID, &projectionRevision, &contractVersion, &contractHash, &schemaName, &relationName, &relationKind, &columnsJSON, &scopeRevision)
	if err != nil {
		return err
	}
	if status != "ACTIVE" || connectionID != request.Projection.ConnectionID || databaseIdentity != request.Projection.DatabaseIdentity || lineageID != request.Projection.LineageID || projectionRevision != request.Projection.Revision || scopeRevision != request.ScopeRevision || contractVersion != postgresqlquery.ValueContractVersion || contractHash != request.Projection.ContractHash || schemaName != request.Projection.SchemaName || relationName != request.Projection.RelationName || relationKind != request.Projection.RelationKind {
		return failure("PG_QUERY_PROJECTION_DRIFT", nil)
	}
	canonicalStored := jsontext.Value(columnsJSON)
	if err := canonicalStored.Canonicalize(); err != nil {
		return failure("PG_QUERY_PROJECTION_DRIFT", err)
	}
	if !bytes.Equal([]byte(canonicalStored), columns) {
		return failure("PG_QUERY_PROJECTION_DRIFT", nil)
	}
	return nil
}

func (h *Handler) ensurePostgreSQLObject(ctx context.Context, tx database.Transaction, access database.AccessContext, request PostgreSQLSnapshotRequest, identity string, row postgresqlquery.Row) (string, bool, error) {
	locatorBytes, err := canon.CanonicalJSON(struct {
		ConnectionID         string `json:"connection_id"`
		Kind                 string `json:"kind"`
		LineageID            string `json:"projection_lineage_id"`
		Revision             int64  `json:"projection_revision"`
		EntityIdentityDigest string `json:"entity_identity_digest"`
	}{request.Projection.ConnectionID, "POSTGRESQL_QUERY_ROW", request.Projection.LineageID, request.Projection.Revision, identity})
	if err != nil {
		return "", false, err
	}
	externalIDBytes, err := canon.CanonicalJSON(struct {
		Kind      string                       `json:"kind"`
		LineageID string                       `json:"projection_lineage_id"`
		Identity  []postgresqlquery.ValueEntry `json:"identity_values"`
	}{"POSTGRESQL_QUERY_IDENTITY", request.Projection.LineageID, identityEntries(request.Projection, row)})
	if err != nil {
		return "", false, err
	}
	locatorDigest := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, locatorBytes)
	var objectID string
	err = tx.QueryRow(ctx, `SELECT id FROM public.source_object WHERE organization_id=$1 AND connection_id=$2 AND digest_key_version=$3 AND external_object_id_digest=$4`, access.OrganizationID, request.Projection.ConnectionID, h.digester.KeyVersion, identity).Scan(&objectID)
	created := false
	if database.IsNotFound(err) {
		created = true
		objectID, err = h.newID("object")
		if err != nil {
			return "", false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.source_object (organization_id,id,connection_id,object_type,digest_key_version,external_object_id_digest,canonical_locator_digest,lifecycle_state,queryable) VALUES ($1,$2,$3,'POSTGRESQL_QUERY_ROW',$4,$5,$6,'ACTIVE',false)`, access.OrganizationID, objectID, request.Projection.ConnectionID, h.digester.KeyVersion, identity, locatorDigest); err != nil {
			return "", false, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectCanonicalLocator, objectID, locatorBytes); err != nil {
			return "", false, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectExternalID, objectID, externalIDBytes); err != nil {
			return "", false, err
		}
		title := []byte(request.Projection.LineageID + "#" + identity)
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectTitle, objectID, title); err != nil {
			return "", false, err
		}
	} else if err != nil {
		return "", false, err
	} else if _, err := tx.Exec(ctx, `UPDATE public.source_object SET last_seen_at=now() WHERE organization_id=$1 AND id=$2 AND lifecycle_state='ACTIVE'`, access.OrganizationID, objectID); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_object_scope (organization_id,source_object_id,source_scope_id,source_scope_revision,membership_state) VALUES ($1,$2,$3,$4,'ACTIVE') ON CONFLICT (organization_id,source_object_id,source_scope_id,source_scope_revision) DO UPDATE SET last_seen_at=now()`, access.OrganizationID, objectID, request.ScopeID, request.ScopeRevision); err != nil {
		return "", false, err
	}
	return objectID, created, nil
}

func (h *Handler) publishPostgreSQLRow(ctx context.Context, tx database.Transaction, access database.AccessContext, request PostgreSQLSnapshotRequest, objectID, versionID string, versionCreated bool, row postgresqlquery.Row, identity string, profileBytes []byte, profileHash string) (int, error) {
	retentionFence, err := versionRetentionFence(ctx, tx, access.OrganizationID, versionID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT app.assert_version_writable($1,$2)`, versionID, retentionFence); err != nil {
		return 0, err
	}
	extractionID, err := h.newID("extraction")
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_extraction (organization_id,id,source_version_id,retention_fence_at_start,canonical_format,profile_json,profile_hash,extractor_name,extractor_version,extractor_artifact_hash,normalization_version,parser_profile_revision,ocr_used,status,started_at) VALUES ($1,$2,$3,$4,'POSTGRESQL_QUERY',$5,$6,$7,$8,$9,'text-v1',$10,false,'RUNNING',now())`, access.OrganizationID, extractionID, versionID, retentionFence, jsontext.Value(profileBytes), profileHash, postgresqlQueryExtractorName, postgresqlQueryExtractorVersion, canon.Hash([]byte(postgresqlQueryExtractorName+"@"+postgresqlQueryExtractorVersion)), postgresqlquery.ValueContractVersion); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_extraction_retention (organization_id,extraction_id,state,queryable) VALUES ($1,$2,'ACTIVE',true)`, access.OrganizationID, extractionID); err != nil {
		return 0, err
	}
	descriptors := make([]canon.EvidenceDescriptor, 0)
	ordinal := 0
	searchPlans := make([]searchChunkPlan, 0, 1)
	cardFragmentIDs := make([]string, 0)
	cardCells := make([][]byte, 0)
	renderedCells, err := postgresqlRenderedEvidenceCells(request, identity, row)
	if err != nil {
		return 0, err
	}
	cellPlans, err := structuredCellPlans(request, identity, row)
	if err != nil {
		return 0, err
	}
	admitted := 0
	for _, rendered := range renderedCells {
		column, cell := rendered.column, rendered.cell
		text, anchor, valueHash := cell.Text, cell.Anchor, cell.ValueHash
		if len(text) == 0 || !utf8.Valid(text) {
			continue
		}
		ordinal++
		fragmentID, err := h.newID("fragment")
		if err != nil {
			return 0, err
		}
		textHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, text)
		anchorHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, anchor)
		metadata, err := jsonv2.Marshal(struct {
			ParserProfileRevision string `json:"parser_profile_revision"`
			ConnectionID          string `json:"connection_id"`
			ProjectionLineageID   string `json:"projection_lineage_id"`
			ProjectionRevision    int64  `json:"projection_revision"`
			ColumnOrdinal         int    `json:"column_ordinal"`
			ColumnName            string `json:"column_name"`
			JSONPath              string `json:"json_path,omitempty"`
			CanonicalValueHash    string `json:"canonical_value_hash"`
		}{postgresqlquery.ValueContractVersion, request.Projection.ConnectionID, request.Projection.LineageID, request.Projection.Revision, column.Ordinal, column.Name, rendered.cell.Path, valueHash})
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.evidence_fragment (organization_id,id,source_version_id,extraction_id,ordinal,text_hash,text_digest_key_version,token_count,byte_count,anchor_hash,anchor_digest_key_version,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())`, access.OrganizationID, fragmentID, versionID, extractionID, ordinal, textHash, h.digester.KeyVersion, len(strings.Fields(string(text))), len(text), anchorHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeKeyedArtifact(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID, text, textHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeKeyedArtifact(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID, anchor, anchorHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.EvidenceMetadata, fragmentID, metadata); err != nil {
			return 0, err
		}
		descriptors = append(descriptors, canon.EvidenceDescriptor{FragmentID: fragmentID, Ordinal: ordinal, TextHash: textHash, AnchorHash: anchorHash})
		if admitted >= len(cellPlans) {
			return 0, failure("PG_QUERY_STRUCTURED_CELL_LINEAGE", nil)
		}
		if err := h.storeStructuredCell(ctx, tx, access, objectID, versionID, fragmentID, cellPlans[admitted]); err != nil {
			return 0, err
		}
		admitted++
		if h.searchRepository != nil {
			cardFragmentIDs = append(cardFragmentIDs, fragmentID)
			cardCells = append(cardCells, append([]byte(nil), text...))
		}
	}
	if len(descriptors) == 0 {
		return 0, failure("PG_QUERY_ROW_WITHOUT_EVIDENCE", nil)
	}
	evidenceHash, err := canon.EvidenceSetHash(descriptors)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE public.source_extraction SET status='SUCCEEDED', evidence_set_hash=$3, completed_at=now() WHERE organization_id=$1 AND id=$2`, access.OrganizationID, extractionID, evidenceHash); err != nil {
		return 0, err
	}
	if h.searchRepository != nil && len(cardFragmentIDs) > 0 {
		card, cardErr := postgresqlRowCard(request.Projection, cardCells)
		if cardErr != nil {
			return 0, cardErr
		}
		searchPlans = append(searchPlans, searchChunkPlan{text: card, fragmentIDs: cardFragmentIDs, ordinal: 1})
	}
	if err := h.publishSearchChunks(ctx, tx, access, versionID, extractionID, searchPlans); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT app.source_version_publish_extraction($1,$2,$3,$4,$5,$6,$7)`, versionID, extractionID, evidenceHash, versionCreated, request.Claimed.ID, h.workerID, request.Claimed.LeaseEpoch); err != nil {
		return 0, err
	}
	if err := h.auditEntity(ctx, access, tx, audit.ActionSourceExtractionActive, audit.ResourceSourceObject, extractionID, request.SyncRunID, request.Claimed.ID); err != nil {
		return 0, err
	}
	return len(descriptors), nil
}

// reconcilePostgreSQLSearchChunks reconstructs the same bounded text units
// from the already-attested row when a lexical projection was introduced
// after the catalog extraction. It is idempotent through publishSearchChunks:
// a complete existing set is accepted, while a partial set fails closed.
func (h *Handler) reconcilePostgreSQLSearchChunks(ctx context.Context, tx database.Transaction,
	access database.AccessContext, request PostgreSQLSnapshotRequest, versionID,
	identity string, row postgresqlquery.Row, profileHash string) error {
	if h == nil || h.searchRepository == nil {
		return nil
	}
	extractionID, fragmentIDs, err := h.graphPublication(ctx, tx, access, versionID, profileHash)
	if err != nil {
		return err
	}
	plans, err := postgresqlSearchPlans(request, identity, row, fragmentIDs)
	if err != nil {
		return err
	}
	return h.publishSearchChunks(ctx, tx, access, versionID, extractionID, plans)
}

func postgresqlSearchPlans(request PostgreSQLSnapshotRequest, identity string, row postgresqlquery.Row, fragmentIDs []string) ([]searchChunkPlan, error) {
	rendered, err := postgresqlRenderedEvidenceCells(request, identity, row)
	if err != nil {
		return nil, err
	}
	cells := make([][]byte, 0, len(rendered))
	for _, item := range rendered {
		if len(item.cell.Text) == 0 || !utf8.Valid(item.cell.Text) {
			continue
		}
		cells = append(cells, append([]byte(nil), item.cell.Text...))
	}
	if len(cells) != len(fragmentIDs) {
		return nil, failure("PG_QUERY_SEARCH_LINEAGE", nil)
	}
	if len(cells) == 0 {
		return nil, nil
	}
	card, err := postgresqlRowCard(request.Projection, cells)
	if err != nil {
		return nil, err
	}
	return []searchChunkPlan{{text: card, fragmentIDs: append([]string(nil), fragmentIDs...), ordinal: 1}}, nil
}

// postgresqlRowCard renders one row of a structured projection as a single
// retrieval unit (knowvault-DECISIONS.md 11, "smart chunks").
//
// A cell on its own — "status = IN_TRANSIT" — is not something a reader or a
// model can answer from: it names no relation, no row and no other column, so
// "how many vehicles are on the road today" retrieved a pile of unrelated
// values. The card keeps every cell verbatim (each is still its own Evidence
// fragment and its own citation) and adds only what the projection already
// knows: the qualified relation this row came from, and the row's columns
// together in projection order. Numbers, dates and identifiers stay exactly as
// the value contract rendered them.
func postgresqlRowCard(projection postgresqlquery.Projection, cells [][]byte) ([]byte, error) {
	if len(cells) == 0 {
		return nil, failure("PG_QUERY_EVIDENCE_RENDER_INVALID", nil)
	}
	var builder strings.Builder
	builder.WriteString(projection.SchemaName)
	builder.WriteString(".")
	builder.WriteString(projection.RelationName)
	for _, cell := range cells {
		builder.WriteString("\n")
		builder.Write(cell)
	}
	card, err := canon.Canonicalize([]byte(builder.String()))
	if err != nil || len(card) == 0 || !utf8.Valid(card) {
		return nil, failure("PG_QUERY_EVIDENCE_RENDER_INVALID", err)
	}
	return card, nil
}

type postgresqlRenderedCell struct {
	column postgresqlquery.Column
	cell   postgresqlquery.RenderedCell
}

// structuredCellPlan is the typed projection of ONE already-published Evidence
// cell (AGG-1, db/migrations/000073). It carries no new information across the
// boundary: the same value is already an Evidence fragment of the same
// snapshot. What it adds is the value's TYPE — a number as a number, an
// instant as an instant — so an exact aggregate is computed by comparing typed
// values over the whole snapshot rather than by parsing display strings out of
// whatever lexical retrieval happened to return.
type structuredCellPlan struct {
	ordinal     int
	columnName  string
	logicalType string
	titleRole   bool
	periodRole  bool
	statusRole  bool
	text        *string
	numeric     *string
	instant     *string
	naive       *string
	date        *string
	boolean     *bool
}

// structuredCellPlans mirrors postgresqlRenderedEvidenceCells one-for-one (same
// order, same admission filter), so the caller can zip it with the Evidence
// fragment ids it just created — or with the fragment ids an earlier run
// created — without a second, divergent notion of "which cell is this".
// A JSON leaf has no single typed scalar of the declared column type and is
// deliberately skipped: it keeps its Evidence fragment and its citation, it
// just never becomes an aggregate input.
func structuredCellPlans(request PostgreSQLSnapshotRequest, identity string, row postgresqlquery.Row) ([]structuredCellPlan, error) {
	rendered, err := postgresqlRenderedEvidenceCells(request, identity, row)
	if err != nil {
		return nil, err
	}
	plans := make([]structuredCellPlan, 0, len(rendered))
	for _, item := range rendered {
		if len(item.cell.Text) == 0 || !utf8.Valid(item.cell.Text) {
			continue
		}
		plan := structuredCellPlan{
			ordinal: item.column.Ordinal, columnName: item.column.Name,
			logicalType: string(item.column.LogicalType), titleRole: hasRole(item.column.Roles, postgresqlquery.RoleTitle),
			periodRole: hasRole(item.column.Roles, postgresqlquery.RolePeriod),
			statusRole: hasRole(item.column.Roles, postgresqlquery.RoleStatus),
		}
		if item.cell.Path != "" {
			// A JSON leaf: admitted as Evidence, not as a typed aggregate input.
			plans = append(plans, structuredCellPlan{})
			continue
		}
		value, ok := valueAt(row.Values, item.column.Ordinal)
		if !ok || value.ValueTag == "NULL" {
			plans = append(plans, structuredCellPlan{})
			continue
		}
		scalar, isString := value.Value.(string)
		switch postgresqlquery.LogicalType(plan.logicalType) {
		case postgresqlquery.TypeText, postgresqlquery.TypeUUID:
			if !isString {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.text = &scalar
		case postgresqlquery.TypeInt, postgresqlquery.TypeNumeric:
			if !isString {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.numeric = &scalar
		case postgresqlquery.TypeTimestamptz:
			if !isString {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.instant = &scalar
		case postgresqlquery.TypeTimestamp:
			if !isString {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.naive = &scalar
		case postgresqlquery.TypeDate:
			if !isString {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.date = &scalar
		case postgresqlquery.TypeBool:
			flag, isBool := value.Value.(bool)
			if !isBool {
				plans = append(plans, structuredCellPlan{})
				continue
			}
			plan.boolean = &flag
		default:
			plans = append(plans, structuredCellPlan{})
			continue
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// storeStructuredCell writes one typed cell. It is idempotent per Evidence
// fragment: re-publishing the same immutable row (a repeat sync of an
// unchanged snapshot) must converge, never duplicate or fail.
func (h *Handler) storeStructuredCell(ctx context.Context, tx database.Transaction, access database.AccessContext,
	objectID, versionID, fragmentID string, plan structuredCellPlan) error {
	if plan.columnName == "" || plan.logicalType == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO public.structured_snapshot_cell
		(organization_id, evidence_fragment_id, source_version_id, source_object_id,
		 column_ordinal, column_name, logical_type, title_role, period_role, status_role,
		 text_value, numeric_value, instant_value, naive_value, date_value, bool_value)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::numeric,$13::timestamptz,$14::timestamp,$15::date,$16)
		ON CONFLICT (organization_id, evidence_fragment_id) DO NOTHING`,
		access.OrganizationID, fragmentID, versionID, objectID, plan.ordinal, plan.columnName,
		plan.logicalType, plan.titleRole, plan.periodRole, plan.statusRole, plan.text, plan.numeric, plan.instant, plan.naive, plan.date, plan.boolean)
	return err
}

// reconcileStructuredSnapshotCells backfills the typed projection for a row
// whose Evidence was published by an earlier run (the "already extracted"
// short-circuit). Without it a snapshot ingested before AGG-1 — or a repeat
// sync that skips extraction — would leave the reducer reading a partial
// snapshot, and a partial snapshot must never become an exact number.
func (h *Handler) reconcileStructuredSnapshotCells(ctx context.Context, tx database.Transaction,
	access database.AccessContext, request PostgreSQLSnapshotRequest, objectID, versionID,
	identity string, row postgresqlquery.Row, profileHash string) error {
	if h == nil {
		return nil
	}
	_, fragmentIDs, err := h.graphPublication(ctx, tx, access, versionID, profileHash)
	if err != nil {
		return err
	}
	plans, err := structuredCellPlans(request, identity, row)
	if err != nil {
		return err
	}
	if len(plans) != len(fragmentIDs) {
		return failure("PG_QUERY_STRUCTURED_CELL_LINEAGE", nil)
	}
	for index, plan := range plans {
		if err := h.storeStructuredCell(ctx, tx, access, objectID, versionID, fragmentIDs[index], plan); err != nil {
			return err
		}
	}
	return nil
}

func postgresqlRenderedEvidenceCells(request PostgreSQLSnapshotRequest, identity string, row postgresqlquery.Row) ([]postgresqlRenderedCell, error) {
	if request.Projection.Validate() != nil || identity == "" {
		return nil, failure("PG_QUERY_EVIDENCE_RENDER_INVALID", nil)
	}
	result := make([]postgresqlRenderedCell, 0, len(request.Projection.Columns))
	for _, column := range request.Projection.Columns {
		if !hasRole(column.Roles, postgresqlquery.RoleEvidence) {
			continue
		}
		value, ok := valueAt(row.Values, column.Ordinal)
		if !ok || value.ValueTag == "NULL" || (column.LogicalType == postgresqlquery.TypeText && value.Value == "") {
			continue
		}
		cells, err := postgresqlquery.RenderedEvidenceCells(request.Projection, identity, row, column, value)
		if err != nil {
			return nil, err
		}
		for _, cell := range cells {
			if len(cell.Text) == 0 || !utf8.Valid(cell.Text) {
				continue
			}
			result = append(result, postgresqlRenderedCell{column: column, cell: cell})
		}
	}
	return result, nil
}

func (h *Handler) reconcilePostgreSQL(ctx context.Context, tx database.Transaction, access database.AccessContext, request PostgreSQLSnapshotRequest, seen []string) (int, error) {
	if len(seen) == 0 && request.Projection.EmptySnapshotPolicy != "AUTHORITATIVE" {
		return 0, failure("PG_QUERY_EMPTY_SNAPSHOT_HELD", nil)
	}
	if _, err := tx.Exec(ctx, `SELECT app.assert_scope_revision_syncing($1,$2)`, request.ScopeID, request.ScopeRevision); err != nil {
		return 0, err
	}
	var removed int
	if err := tx.QueryRow(ctx, `WITH changed AS (UPDATE public.source_object_scope os SET membership_state='MISSING', missing_at=now(), missing_sync_run_id=$7 FROM public.source_object o WHERE os.organization_id=$1 AND o.organization_id=$1 AND os.source_object_id=o.id AND os.source_scope_id=$2 AND os.source_scope_revision=$3 AND os.membership_state='ACTIVE' AND o.connection_id=$4 AND o.digest_key_version=$5 AND (cardinality($6::text[]) = 0 OR o.external_object_id_digest <> ALL($6::text[])) RETURNING 1) SELECT count(*) FROM changed`, access.OrganizationID, request.ScopeID, request.ScopeRevision, request.Projection.ConnectionID, h.digester.KeyVersion, seen, request.SyncRunID).Scan(&removed); err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, `UPDATE public.source_object o SET lifecycle_state='MISSING', queryable=false, last_seen_at=now() WHERE o.organization_id=$1 AND o.lifecycle_state='ACTIVE' AND EXISTS (SELECT 1 FROM public.source_object_scope r WHERE r.organization_id=o.organization_id AND r.source_object_id=o.id AND r.source_scope_id=$2 AND r.source_scope_revision=$3 AND r.membership_state='MISSING') AND NOT EXISTS (SELECT 1 FROM public.source_object_scope m WHERE m.organization_id=o.organization_id AND m.source_object_id=o.id AND m.membership_state='ACTIVE') RETURNING o.id`, access.OrganizationID, request.ScopeID, request.ScopeRevision)
	if err != nil {
		return 0, err
	}
	// Collect the closed ids BEFORE auditing them. A pgx connection serves one
	// result set at a time, so appending an audit event inside this rows.Next()
	// loop issues a second statement on a connection that is still streaming
	// the first: the driver refuses it with a lock error and the whole sync
	// dies as PG_QUERY_PUBLICATION_FAILED. It only ever fired once a row had
	// actually disappeared from the snapshot — i.e. from the SECOND sync of a
	// changing table onward — which is why the first sync of a fresh
	// POSTGRESQL_QUERY source always looked healthy. Every other RETURNING
	// loop in this package (the activation cutover below, handler.go's
	// close-out) already drains first for exactly this reason.
	closed := make([]string, 0)
	for rows.Next() {
		var objectID string
		if err := rows.Scan(&objectID); err != nil {
			rows.Close()
			return 0, err
		}
		closed = append(closed, objectID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	for _, objectID := range closed {
		if err := h.auditEntity(ctx, access, tx, audit.ActionSourceObjectMissing, audit.ResourceSourceObject, objectID, request.SyncRunID, request.Claimed.ID); err != nil {
			return 0, err
		}
	}
	return removed, nil
}

func postgresqlExtractionProfile(projection postgresqlquery.Projection) ([]byte, string, error) {
	columns, err := postgresqlColumnsJSON(projection.Columns)
	if err != nil {
		return nil, "", err
	}
	raw, err := jsonv2.Marshal(struct {
		CanonicalFormat        string         `json:"canonical_format"`
		ContractVersion        string         `json:"contract_version"`
		ProjectionLineageID    string         `json:"projection_lineage_id"`
		ProjectionRevision     int64          `json:"projection_revision"`
		ProjectionContractHash string         `json:"projection_contract_hash"`
		Columns                jsontext.Value `json:"columns"`
		Extractor              string         `json:"extractor"`
	}{"POSTGRESQL_QUERY", postgresqlquery.ValueContractVersion, projection.LineageID, projection.Revision, projection.ContractHash, jsontext.Value(columns), postgresqlQueryExtractorName + "@" + postgresqlQueryExtractorVersion})
	if err != nil {
		return nil, "", err
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, "", err
	}
	return []byte(canonical), canon.Hash([]byte(canonical)), nil
}

func postgresqlColumnsJSON(columns []postgresqlquery.Column) ([]byte, error) {
	items := make([]map[string]any, len(columns))
	for index, column := range columns {
		items[index] = map[string]any{"ordinal": column.Ordinal, "name": column.Name, "type_fingerprint": column.TypeFingerprint, "logical_type": column.LogicalType, "roles": column.Roles, "nullable": column.Nullable, "precision": column.Precision, "scale": column.Scale, "max_bytes": column.MaxBytes}
	}
	return canon.CanonicalJSON(items)
}

func identityEntries(projection postgresqlquery.Projection, row postgresqlquery.Row) []postgresqlquery.ValueEntry {
	result := make([]postgresqlquery.ValueEntry, 0)
	for _, column := range projection.Columns {
		if hasRole(column.Roles, postgresqlquery.RoleIdentity) {
			if value, ok := valueAt(row.Values, column.Ordinal); ok {
				result = append(result, value)
			}
		}
	}
	return result
}

func valueAt(values []postgresqlquery.ValueEntry, ordinal int) (postgresqlquery.ValueEntry, bool) {
	for _, value := range values {
		if value.Ordinal == ordinal {
			return value, true
		}
	}
	return postgresqlquery.ValueEntry{}, false
}

func valuesFromEntries(values []postgresqlquery.ValueEntry) []any {
	result := make([]any, len(values))
	for index, value := range values {
		if value.ValueTag == "NULL" {
			result[index] = nil
		} else {
			result[index] = value.Value
		}
	}
	return result
}

func mustCanonicalValues(values []postgresqlquery.ValueEntry) []byte {
	raw, err := canon.CanonicalJSON(values)
	if err != nil {
		return nil
	}
	return raw
}

func hasRole(roles []postgresqlquery.Role, wanted postgresqlquery.Role) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

func versionRetentionFence(ctx context.Context, tx database.Transaction, organizationID, versionID string) (int64, error) {
	var fence int64
	if err := tx.QueryRow(ctx, `SELECT retention_fence FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, organizationID, versionID).Scan(&fence); err != nil {
		return 0, err
	}
	return fence, nil
}

func validPostgreSQLScopeID(value string) bool {
	return validGeneratedID(value, "scope_")
}
func validPostgreSQLRunID(value string) bool {
	return validGeneratedID(value, "syncrun_")
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
