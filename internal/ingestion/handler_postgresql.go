package ingestion

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/observation"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// HandlePostgreSQLQuery drives one live external projection job. The external
// read is completed before any local catalog write; publication then runs in a
// single lease-fenced transaction and atomically advances scope authority.
func (h *Handler) HandlePostgreSQLQuery(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if h == nil {
		return failure("PG_QUERY_CONNECTOR_UNAVAILABLE", errors.New("live connector is not composed"))
	}
	if h.db == nil || h.queue == nil || h.postgresqlQuery == nil || claimed.Type != jobs.TypePostgreSQLQuerySync {
		return h.fail(ctx, access, claimed, "PG_QUERY_CONNECTOR_UNAVAILABLE", errors.New("live connector is not composed"))
	}
	scopeID, _ := claimed.Payload["source_scope_id"].(string)
	if !validPostgreSQLScopeID(scopeID) {
		return h.fail(ctx, access, claimed, "PG_QUERY_PAYLOAD_INVALID", nil)
	}
	runCtx, stopHeartbeat := h.startObjectHeartbeat(ctx, access, claimed)
	defer func() { _ = stopHeartbeat() }()
	if err := h.heartbeat(runCtx, access, claimed); err != nil {
		return h.fail(ctx, access, claimed, "PG_QUERY_HEARTBEAT", err)
	}
	var revision int64
	if err := h.db.Read(runCtx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.source_scope_pending_revision($1)`, scopeID).Scan(&revision)
	}); err != nil || revision < 1 {
		return h.fail(ctx, access, claimed, "PG_QUERY_SCOPE_NOT_FOUND", err)
	}
	syncRunID, err := h.newID("syncrun")
	if err != nil {
		return h.fail(ctx, access, claimed, "PG_QUERY_ID", err)
	}
	var projection postgresqlquery.Projection
	var limits postgresqlquery.Limits
	var credentialReference string
	if err := h.db.Write(runCtx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, scopeID, revision, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		var err error
		projection, limits, credentialReference, err = readPostgreSQLTarget(ctx, tx, access.OrganizationID, scopeID, revision)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, scopeID, revision, projection.ContractHash); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,$4,$5,'FULL','RUNNING')`, access.OrganizationID, syncRunID, scopeID, revision, claimed.ID)
		return err
	}); err != nil {
		return h.fail(ctx, access, claimed, "PG_QUERY_BEGIN_SYNC", err)
	}
	if err := h.heartbeat(runCtx, access, claimed); err != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, "PG_QUERY_HEARTBEAT", err)
	}
	if projection.QueryOnly {
		// S3 card 4: a query-only relation is registered for
		// knowvault_source_sql only. The worker never copies its rows: it
		// completes the activation with an empty, coverage-complete sync and
		// leaves the search index and evidence catalog untouched for this
		// scope. The completion transaction takes the same job-row lock an
		// indexed publication does, so the outer heartbeat is drained first.
		if err := stopHeartbeat(); err != nil {
			return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, "PG_QUERY_HEARTBEAT", err)
		}
		if err := h.completeQueryOnlySync(ctx, access, claimed, scopeID, revision, syncRunID, projection); err != nil {
			return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, postgresqlFailureCode(err), err)
		}
		if err := h.queue.Complete(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return failure("PG_QUERY_COMPLETE", err)
		}
		return nil
	}
	snapshot, err := h.postgresqlQuery.ReadProjection(runCtx, projection.ConnectionID, credentialReference, projection, limits)
	if err != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, postgresqlFailureCode(err), err)
	}
	// Validate the already-read snapshot through the source-agnostic
	// observation boundary before handing it to the catalog publisher.  This
	// does not issue another query; it proves that SQL is only a typed business
	// object adapter and that every retained row has a canonical hash and a
	// deterministic identity.
	observationAdapter, adapterErr := observation.NewPostgreSQLAdapter(
		h.postgresqlQuery, access.OrganizationID, scopeID, revision,
		projection.ConnectionID, credentialReference, projection, limits,
		h.digester.Key, h.digester.KeyVersion,
	)
	if adapterErr != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, "PG_QUERY_OBSERVATION_BOUNDARY", adapterErr)
	}
	observationPage, err := observationAdapter.SnapshotPage(snapshot)
	if err != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, "PG_QUERY_OBSERVATION_BOUNDARY", err)
	}
	// Publication holds the job row lock for its whole atomic transaction, so
	// the outer heartbeat is deliberately drained before entering it. The
	// publication path renews the same live lease inside that transaction at
	// bounded row boundaries; a separate heartbeat would block on the row lock.
	if err := stopHeartbeat(); err != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, "PG_QUERY_HEARTBEAT", err)
	}
	request := PostgreSQLSnapshotRequest{ScopeID: scopeID, ScopeRevision: revision, SyncRunID: syncRunID, Projection: projection, Snapshot: snapshot, ObservationPage: &observationPage, Claimed: claimed}
	if _, err := h.PublishPostgreSQLSnapshot(ctx, access, request); err != nil {
		return h.failPostgreSQLSync(ctx, access, claimed, scopeID, revision, syncRunID, postgresqlFailureCode(err), err)
	}
	if err := h.queue.Complete(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
		return failure("PG_QUERY_COMPLETE", err)
	}
	return nil
}

func postgresqlFailureCode(err error) string {
	if err == nil {
		return "PG_QUERY_FAILED"
	}
	if code := string(postgresqlquery.CodeOf(err)); code != "" && len(code) <= 63 {
		return code
	}
	return "PG_QUERY_FAILED"
}

// completeQueryOnlySync finishes one query-only scope activation without
// reading the external relation: the sync run is recorded as an empty,
// coverage-complete FULL scan and the scope advances exactly like an indexed
// one, so the relation is a normal enabled source that knowvault_source_sql
// can address while producing no Evidence fragment and no search document.
func (h *Handler) completeQueryOnlySync(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob, scopeID string, revision int64, syncRunID string, projection postgresqlquery.Projection) error {
	if !projection.QueryOnly {
		return errors.New("query-only completion requires a query-only projection")
	}
	return h.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `SELECT app.lock_job_lease($1,$2,$3)`, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `SELECT app.assert_scope_revision_syncing($1,$2)`, scopeID, revision); err != nil {
			return err
		}
		if err := h.verifyPostgreSQLProjection(txCtx, tx, access.OrganizationID, PostgreSQLSnapshotRequest{
			ScopeID: scopeID, ScopeRevision: revision, SyncRunID: syncRunID, Projection: projection, Claimed: claimed,
		}); err != nil {
			return err
		}
		updated, err := tx.Exec(txCtx, `UPDATE public.sync_run SET objects_seen=0, objects_ingested=0, versions_created=0, evidence_published=0, quarantined=0, status='SUCCEEDED', completed_at=now(), coverage_complete=true, error_code=NULL WHERE organization_id=$1 AND id=$2 AND status='RUNNING'`, access.OrganizationID, syncRunID)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return failure("PG_QUERY_SYNC_RUN_NOT_RUNNING", nil)
		}
		rows, err := tx.Query(txCtx, `SELECT outcome, closed_object_id FROM app.source_scope_activate_revision($1,$2,$3,$4,$5,$6)`, scopeID, revision, syncRunID, claimed.ID, h.workerID, claimed.LeaseEpoch)
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
			if err := h.auditScopeActivated(txCtx, access, tx, scopeID, revision, syncRunID); err != nil {
				return err
			}
		} else if err := h.auditSync(txCtx, access, tx, scopeID, syncRunID); err != nil {
			return err
		}
		for _, objectID := range closed {
			if err := h.auditObjectClosure(txCtx, tx, access, objectID, syncRunID, claimed.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

func (h *Handler) failPostgreSQLSync(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob, scopeID string, revision int64, syncRunID, code string, cause error) error {
	if h != nil && h.db != nil {
		_ = h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
			_, _ = tx.Exec(ctx, `SELECT app.source_scope_mark_failed($1,$2,$3,$4,$5)`, scopeID, revision, claimed.ID, h.workerID, claimed.LeaseEpoch)
			_, err := tx.Exec(ctx, `UPDATE public.sync_run SET status='FAILED',completed_at=now(),error_code=$3 WHERE organization_id=$1 AND id=$2 AND status='RUNNING'`, access.OrganizationID, syncRunID, code)
			return err
		})
	}
	return h.fail(ctx, access, claimed, code, cause)
}

type postgresqlProjectionColumn struct {
	Ordinal         int                         `json:"ordinal"`
	Name            string                      `json:"name"`
	TypeFingerprint string                      `json:"type_fingerprint"`
	LogicalType     postgresqlquery.LogicalType `json:"logical_type"`
	Roles           []postgresqlquery.Role      `json:"roles"`
	Nullable        bool                        `json:"nullable"`
	Precision       int                         `json:"precision"`
	Scale           int                         `json:"scale"`
	MaxBytes        int                         `json:"max_bytes"`
}

func readPostgreSQLTarget(ctx context.Context, tx database.Transaction, organizationID, scopeID string, revision int64) (postgresqlquery.Projection, postgresqlquery.Limits, string, error) {
	var (
		connectionID, databaseIdentity, lineageID, contractVersion, contractHash string
		schemaName, relationName, relationKind, emptyPolicy                      string
		projectionRevision                                                       int64
		columnsRaw                                                               []byte
		maxRows, maxFieldBytes, maxRowBytes, maxTotalBytes                       int64
		maxColumns, timeoutMS                                                    int
		credentialReference                                                      string
		connectionRevision                                                       int64
		queryOnly                                                                bool
	)
	if err := tx.QueryRow(ctx, `SELECT connection_id,connection_revision,credential_reference FROM app.postgresql_query_connection_target($1,$2)`, scopeID, revision).Scan(&connectionID, &connectionRevision, &credentialReference); err != nil {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", err
	}
	if connectionRevision < 1 || credentialReference == "" {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", errors.New("postgresql query connection target is invalid")
	}
	if err := tx.QueryRow(ctx, `SELECT database_identity,lineage_id,projection_revision,contract_version,contract_hash,schema_name,relation_name,relation_kind,columns_json,empty_snapshot_policy,query_only,max_rows,max_columns,max_field_bytes,max_row_bytes,max_total_bytes,statement_timeout_ms FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=$3`, organizationID, scopeID, revision).Scan(&databaseIdentity, &lineageID, &projectionRevision, &contractVersion, &contractHash, &schemaName, &relationName, &relationKind, &columnsRaw, &emptyPolicy, &queryOnly, &maxRows, &maxColumns, &maxFieldBytes, &maxRowBytes, &maxTotalBytes, &timeoutMS); err != nil {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", err
	}
	if contractVersion != postgresqlquery.ValueContractVersion {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", errors.New("postgresql projection contract version mismatch")
	}
	var columns []postgresqlProjectionColumn
	if err := jsonv2.Unmarshal(columnsRaw, &columns, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", err
	}
	projectionColumns := make([]postgresqlquery.Column, len(columns))
	for i, column := range columns {
		projectionColumns[i] = postgresqlquery.Column{Ordinal: column.Ordinal, Name: column.Name, TypeFingerprint: column.TypeFingerprint, LogicalType: column.LogicalType, Roles: column.Roles, Nullable: column.Nullable, Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes}
	}
	projection := postgresqlquery.Projection{ConnectionID: connectionID, DatabaseIdentity: databaseIdentity, LineageID: lineageID, Revision: projectionRevision, ContractHash: contractHash, SchemaName: schemaName, RelationName: relationName, RelationKind: relationKind, Columns: projectionColumns, EmptySnapshotPolicy: emptyPolicy, QueryOnly: queryOnly}
	if err := projection.Validate(); err != nil {
		return postgresqlquery.Projection{}, postgresqlquery.Limits{}, "", err
	}
	limits := postgresqlquery.Limits{MaxRows: int(maxRows), MaxColumns: maxColumns, MaxFieldBytes: int(maxFieldBytes), MaxRowBytes: int(maxRowBytes), MaxTotalBytes: int(maxTotalBytes), StatementTimeout: time.Duration(timeoutMS) * time.Millisecond, TransactionTimeout: time.Duration(timeoutMS+120000) * time.Millisecond}
	return projection, limits, credentialReference, nil
}
