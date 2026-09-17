package ingestion

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/connector/folder"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/observation"
	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/internal/source/pathcanon"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// Digester carries the organization-scoped HMAC key used to derive the
// object-identity and canonical-locator digests. The key is supplied from the
// trusted deployment secret provider, exactly like the envelope KEK.
type Digester struct {
	Key        []byte
	KeyVersion int
}

// MountRegistry resolves a connection's trusted (root_alias, root_identity) to
// the absolute host path of the pre-mounted root. It is deployment
// configuration, never a request field or a database column.
type MountRegistry interface {
	Resolve(rootAlias, rootIdentity string) (string, bool)
}

// ObservationAdapterTarget is the server-owned, content-free target passed to
// a source adapter resolver.  It contains only the exact activated lineage and
// artifact references; credentials and decrypted source configuration stay in
// the resolver/deployment boundary and can never enter a job payload or an
// observation request.
type ObservationAdapterTarget struct {
	OrganizationID      string
	ConnectionID        string
	ConnectionRevision  int64
	SourceScopeID       string
	SourceScopeRevision int64
	SourceType          string
	AccessMode          string
	ScopeConfigResource string
	ScopeConfigHash     string
	TrustConfigResource string
	TrustProfileHash    string
}

// ObservationAdapterBinding is the immutable result of resolving one
// activated remote source.  Formats are the trusted scope allowlist used by
// the common extraction pipeline; a resolver that cannot prove it returns an
// error and the sync fails closed.
type ObservationAdapterBinding struct {
	Adapter observation.Adapter
	Formats map[string]bool
	// Close retires connector transport and clears private credential state.
	// It is optional for adapters that own no external resources.
	Close func() error
}

// ObservationAdapterResolver is the deployment-owned factory for source
// connectors other than the pre-mounted folder adapter.  Implementations may
// decrypt the target artifacts and resolve purpose-specific trust roots and
// credentials, but return only a read-only observation adapter and its
// validated format allowlist.
type ObservationAdapterResolver interface {
	Resolve(context.Context, database.AccessContext, ObservationAdapterTarget) (ObservationAdapterBinding, error)
}

// Handler processes SOURCE_SCOPE_SYNC jobs for one organization. The codec and
// digester are organization-bound, matching the single-tenant worker deployment.
type Handler struct {
	db        *database.Store
	queue     *jobs.Queue
	connector *folder.Connector
	repo      *repository.Repository
	codec     *artifactcrypto.Codec
	audit     *audit.Store
	digester  Digester
	mounts    MountRegistry
	workerID  string
	// parserRevision distinguishes extraction profiles; a new revision forces a
	// new immutable Extraction and an atomic active-set switch.
	parserRevision string
	// office is the isolated office parser sandbox (ADR-0062). It is nil unless the
	// deployment pins one, and a nil sandbox means Office objects quarantine — there
	// is deliberately no in-process fallback parser to fall back to.
	office OfficeExtractor
	// pdf is the production text-PDF observation boundary. Production composition
	// supplies a dispatcher-backed implementation; nil quarantines PDF objects.
	pdf PDFExtractor
	// ocr is the production PNG/JPEG observation boundary. A nil OCR worker keeps
	// image objects quarantined until its exact profile is qualified.
	ocr OCRExtractor
	// pdfRender is the deterministic PDF page-render boundary used only after the
	// text observer explicitly classifies a PDF as scanned/mixed. It is separate
	// from the text-PDF observer so a text document can never silently fall back
	// to OCR.
	pdfRender PDFRenderExtractor
	// postgresqlQuery is the live external connector. A nil connector is a
	// deployment failure for POSTGRESQL_QUERY jobs; there is no in-process or
	// synthetic fallback.
	postgresqlQuery PostgreSQLQueryConnector
	// graph is an optional worker-side projection boundary. When configured by
	// production composition, every newly published source version also gets a
	// canonical entity/semantic-term projection in the same lease-fenced
	// transaction. The graph never receives plaintext or connector credentials.
	graph *knowledgegraph.Repository
	// adapterResolver is the deployment-owned factory for Git/IMAP (and future
	// source kinds). A nil resolver is intentional: remote activation fails
	// closed rather than silently falling back to the folder connector.
	adapterResolver ObservationAdapterResolver
	// searchRepository is the durable lexical projection boundary. It is
	// independent of the external OpenSearch transport: ingestion always emits
	// an encrypted SearchChunk/outbox event when this repository is configured,
	// while an absent vector profile remains an explicit lexical-only state.
	searchRepository *search.Repository
	// fault is a test-only failure-injection hook. It is nil in production and is
	// invoked at each crash boundary so a test can prove that a failure inside a
	// per-object transaction rolls the whole object back, and a failure after
	// publication leaves a fully-active set that a re-run resumes idempotently.
	fault func(stage string) error
	now   func() time.Time
	newID func(prefix string) (string, error)
	// leaseExtensionSeconds is the bounded extension used at the object
	// boundary. The worker sets it to the same value it uses for the initial
	// claim, while tests and direct composition retain the safe default.
	leaseExtensionSeconds int
}

// PostgreSQLQueryConnector is the only external capability accepted by the
// PostgreSQL business-object worker. Credential resolution is owned by the
// deployment connector; the handler receives only the immutable projection and
// bounded limits.
type PostgreSQLQueryConnector interface {
	ReadProjection(context.Context, string, string, postgresqlquery.Projection, postgresqlquery.Limits) (postgresqlquery.Snapshot, error)
}

// injectFault invokes the test failure hook for a named boundary, if set.
func (h *Handler) injectFault(stage string) error {
	if h.fault == nil {
		return nil
	}
	return h.fault(stage)
}

// NewHandler wires a handler. now and newID default to the wall clock and the
// ids generator; tests may override them.
func NewHandler(db *database.Store, queue *jobs.Queue, repo *repository.Repository,
	codec *artifactcrypto.Codec, digester Digester, mounts MountRegistry, workerID string,
	now func() time.Time, newID func(string) (string, error)) *Handler {
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = ids.New
	}
	auditStore, _ := audit.NewStore(db)
	return &Handler{
		db: db, queue: queue, connector: folder.New(), repo: repo, codec: codec, audit: auditStore,
		digester: digester, mounts: mounts, workerID: workerID,
		parserRevision: defaultParserRevision, now: now, newID: newID,
		leaseExtensionSeconds: 60,
	}
}

// OfficeExtractor is the isolated office parser sandbox boundary as the ingestion
// runtime sees it (ADR-0062). The interface is deliberately this narrow: a canonical
// format and one transient document in, a canonicalized and re-validated result out.
// There is no way to hand the sandbox a tenant, workspace, scope, version id,
// credential, database handle or audit/job authority, because no such parameter
// exists — the capability restriction is a property of the type, not of a policy the
// caller is trusted to follow.
type OfficeExtractor interface {
	Extract(ctx context.Context, canonicalFormat string, document []byte) (*docparser.Result, error)
}

// PDFExtractor is the narrow ingestion-side capability for text PDF. It carries
// no tenant, workspace, persistence or container-runtime authority; production
// implementations must submit the closed dispatcher v2 request.
type PDFExtractor interface {
	Extract(ctx context.Context, canonicalFormat string, document []byte) (*pdfparser.Result, error)
}

// OCRExtractor is the narrow ingestion-side capability for an isolated OCR
// worker. Scanned PDF rendering is a separate boundary; only rendered PNG/JPEG
// page bytes reach this interface.
type OCRExtractor interface {
	Extract(ctx context.Context, mediaFamily string, document []byte) (*ocrparser.Result, error)
}

// PDFRenderExtractor is the narrow capability for deterministic scanned-PDF
// page rasterization. The renderer result contains only transient PNG pages and
// a pinned renderer identity; it carries no source or persistence authority.
type PDFRenderExtractor interface {
	Extract(ctx context.Context, format string, document []byte) (*pdfrenderparser.Result, error)
}

// WithOfficeExtractor returns a copy bound to an isolated office parser sandbox.
// Without it, Office objects quarantine.
func (h *Handler) WithOfficeExtractor(office OfficeExtractor) *Handler {
	clone := *h
	clone.office = office
	return &clone
}

// WithPDFExtractor returns a copy bound to a dispatcher-backed text-PDF
// observer. Without it PDF objects quarantine and cannot fall back to text/OCR.
func (h *Handler) WithPDFExtractor(pdf PDFExtractor) *Handler {
	clone := *h
	clone.pdf = pdf
	return &clone
}

// WithOCRExtractor returns a copy bound to a qualified OCR observation worker.
// Without it image objects are quarantined with no text-parser fallback.
func (h *Handler) WithOCRExtractor(ocr OCRExtractor) *Handler {
	clone := *h
	clone.ocr = ocr
	return &clone
}

// WithPDFRenderExtractor binds the renderer used by the explicit scanned-PDF
// classification path. Without both this renderer and an OCR extractor, a
// scanned PDF remains quarantined; there is no partial fallback.
func (h *Handler) WithPDFRenderExtractor(renderer PDFRenderExtractor) *Handler {
	clone := *h
	clone.pdfRender = renderer
	return &clone
}

// WithPostgreSQLQueryConnector binds the live external PostgreSQL reader. It
// is intentionally copy-style like the parser boundaries so a running handler
// cannot have its connector replaced.
func (h *Handler) WithPostgreSQLQueryConnector(connector PostgreSQLQueryConnector) *Handler {
	clone := *h
	clone.postgresqlQuery = connector
	return &clone
}

// WithKnowledgeGraph binds the worker graph projection. It is copy-style like
// the parser capabilities, so a running handler cannot be mutated underneath
// an in-flight source sync. A nil graph is retained only for staged legacy
// qualification paths; enterprise composition supplies the real repository.
func (h *Handler) WithKnowledgeGraph(graph *knowledgegraph.Repository) *Handler {
	clone := *h
	clone.graph = graph
	return &clone
}

// WithSearchRepository binds the worker's durable lexical projection. The
// repository owns only the typed SearchChunk SQL/artifact boundary; it has no
// OpenSearch or caller-controlled query authority. Copy-style binding keeps a
// running handler's projection capability immutable.
func (h *Handler) WithSearchRepository(repository *search.Repository) *Handler {
	clone := *h
	clone.searchRepository = repository
	return &clone
}

// WithObservationAdapterResolver binds the deployment-owned remote connector
// factory. Copy-style binding prevents a running worker from changing source
// capabilities underneath an in-flight sync.
func (h *Handler) WithObservationAdapterResolver(resolver ObservationAdapterResolver) *Handler {
	clone := *h
	clone.adapterResolver = resolver
	return &clone
}

// WithParserRevision returns a copy pinned to a different parser profile
// revision, used to prove re-extraction of an unchanged version produces a new
// immutable Extraction and switches the active set atomically.
func (h *Handler) WithParserRevision(revision string) *Handler {
	clone := *h
	clone.parserRevision = revision
	return &clone
}

// WithFault returns a copy with a failure-injection hook installed (test-only).
func (h *Handler) WithFault(fault func(stage string) error) *Handler {
	clone := *h
	clone.fault = fault
	return &clone
}

// WithLeaseExtensionSeconds pins the heartbeat extension to the worker's
// claim lease. It is copy-style so a handler cannot be mutated while another
// job is using it.
func (h *Handler) WithLeaseExtensionSeconds(seconds int) *Handler {
	clone := *h
	if seconds >= 1 && seconds <= 3600 {
		clone.leaseExtensionSeconds = seconds
	}
	return &clone
}

type resolvedScope struct {
	scope        *folder.Scope
	adapter      observation.Adapter
	sourceType   string
	sourceKind   observation.Kind
	connectionID string
	scopeID      string
	revision     int64
	// pathCase is the platform's canonicalization case, so the catalog can
	// re-validate every object's identity path through the same normative
	// pathcanon semantics the connector and matcher use.
	pathCase pathcanon.Case
	// formats is the scope revision's format allowlist, so the extractor admits an
	// object only for a format the scope permits (S2a).
	formats      map[string]bool
	close        func() error
	pendingSkips map[string][]pendingObjectSkip
}

// Handle drives one claimed SOURCE_SCOPE_SYNC job to a terminal outcome: it
// begins the scope activation, records a sync run, resolves the Scope, discovers
// and ingests each object in its own fenced transaction, publishes READY on
// success, and acknowledges the job. Any failure marks the activation FAILED and
// fails the job with a safe code.
func (h *Handler) Handle(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if claimed.Type != jobs.TypeSourceScopeSync {
		return failure("INGEST_WRONG_JOB_TYPE", nil)
	}
	scopeID, _ := claimed.Payload["source_scope_id"].(string)
	if scopeID == "" {
		return h.fail(ctx, access, claimed, "INGEST_PAYLOAD_INVALID", nil)
	}

	// The claim lease covers the complete sync lifecycle, not only parser I/O.
	// Discovery, scope resolution and reconciliation can each outlive a short
	// lease on a large or slow connector. Keep one heartbeat owner for the whole
	// run and pass its child context to every bounded operation; a lost lease then
	// cancels connector/parser work instead of allowing a stale worker to publish.
	runCtx, stopRunHeartbeat := h.startObjectHeartbeat(ctx, access, claimed)
	defer func() { _ = stopRunHeartbeat() }()
	if err := h.heartbeat(runCtx, access, claimed); err != nil {
		return h.fail(ctx, access, claimed, CodeOf(err), err)
	}

	var revision int64
	if err := h.db.Read(runCtx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.source_scope_pending_revision($1)`, scopeID).Scan(&revision)
	}); err != nil || revision == 0 {
		return h.fail(ctx, access, claimed, "INGEST_SCOPE_NOT_FOUND", err)
	}

	syncRunID, err := h.newID("syncrun")
	if err != nil {
		return h.fail(ctx, access, claimed, "INGEST_ID", err)
	}
	if err := h.db.Write(runCtx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1, $2, $3, $4, $5)`,
			scopeID, revision, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run
			(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status)
			VALUES ($1, $2, $3, $4, $5, 'FULL', 'RUNNING')`,
			access.OrganizationID, syncRunID, scopeID, revision, claimed.ID)
		return err
	}); err != nil {
		return h.fail(ctx, access, claimed, "INGEST_BEGIN_SYNC", err)
	}

	resolved, err := h.resolve(runCtx, access, scopeID, revision)
	if err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(err), err)
	}
	if resolved.close != nil {
		defer func() { _ = resolved.close() }()
	}
	resolved.pendingSkips, err = h.unresolvedObjectSkips(runCtx, access, scopeID, revision)
	if err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_SKIP_RESOLUTION", err)
	}

	if err := h.injectFault("before_discovery"); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_FAULT", err)
	}
	if resolved.adapter == nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_ADAPTER_UNAVAILABLE", nil)
	}
	page, err := resolved.adapter.Observe(runCtx, observation.Request{
		OrganizationID: access.OrganizationID, SourceScopeID: scopeID,
		SourceScopeRevision: revision, MaxObjects: 10_000_000, MaxBytes: 1 << 40,
	})
	if err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_DISCOVER", err)
	}
	if page.Kind != resolved.sourceKind || page.OrganizationID != access.OrganizationID {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_OBSERVATION_INVALID", nil)
	}
	discovery := folder.DiscoveryResult{Complete: page.CoverageComplete}
	observedByPath := make(map[string]*observation.Object, len(page.Objects))
	for index := range page.Objects {
		item := &page.Objects[index]
		if item.Document == nil || item.PayloadKind != observation.PayloadBytes {
			return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_OBSERVATION_INVALID", nil)
		}
		discovery.Objects = append(discovery.Objects, folder.DiscoveredObject{
			RelativePath: item.ExternalID, SizeBytes: int64(len(item.Document.Bytes)), ModTimeUnixNano: item.ObservedAt.UnixNano(),
		})
		observedByPath[item.ExternalID] = item
	}
	for _, quarantine := range page.Quarantined {
		discovery.Quarantined = append(discovery.Quarantined, folder.QuarantineNotice{
			RelativePath: quarantine.ExternalID, Code: folder.QuarantineCode(quarantine.Code),
		})
	}
	// The typed skip ledger (R3a-1 KV-A02): the observation layer already
	// computed one content-free code per quarantined object, so carry it
	// verbatim instead of collapsing everything into the numeric
	// sync_run.quarantined count. The extraction-phase skips discovered below
	// carry their own code from the pipeline, so each cause keeps a distinct
	// typed reason instead of a single generic one.
	skips := make([]sourceObjectSkip, 0, len(discovery.Quarantined))
	for _, quarantine := range discovery.Quarantined {
		skips = append(skips, sourceObjectSkip{
			ExternalID: quarantine.RelativePath,
			ReasonCode: sourceObjectSkipReason(string(quarantine.Code)),
		})
	}
	if err := h.injectFault("after_discovery"); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_FAULT", err)
	}

	counters := syncCounters{seen: len(discovery.Objects), quarantined: len(discovery.Quarantined)}
	for _, object := range discovery.Objects {
		// A scope may contain enough objects for one pass to outlive the claim
		// lease. Heartbeat before every object, so the next iteration also
		// extends the lease between objects before another bounded read starts.
		if err := h.heartbeat(ctx, access, claimed); err != nil {
			return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(err), err)
		}
		// A single extraction may legitimately run longer than the claim lease
		// (notably a bounded parser deadline). Keep the lease alive while that
		// object is being processed. The heartbeat owns a child context: a lost
		// lease cancels parser I/O, and stopObjectHeartbeat always drains the
		// goroutine before this object can be published or the next one starts.
		result, ingestErr := h.ingestObject(runCtx, access, claimed, resolved, syncRunID, object.RelativePath, observedByPath[object.RelativePath])
		if ingestErr != nil {
			return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(ingestErr), ingestErr)
		}
		// A crash here (object committed, job not yet acknowledged) must leave a
		// fully-active set that a reclaimed re-run resumes idempotently.
		if err := h.injectFault("after_publication"); err != nil {
			return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_FAULT", err)
		}
		// The pipeline carries the typed reason of every extraction-phase
		// quarantine site (KV-A02), so no bare boolean reaches the ledger; the
		// code is normalized through the closed set here, exactly once. A code
		// outside the set becomes the closed unknown fallback rather than failing
		// the whole sync run.
		if result.quarantineReason != "" {
			counters.quarantined++
			skips = append(skips, skipForResult(object.RelativePath, result))
			continue
		}
		counters.ingested++
		if result.versionCreated {
			counters.versions++
		}
		counters.evidence += result.evidence
	}
	if err := h.heartbeat(runCtx, access, claimed); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(err), err)
	}

	// Reconciliation (SRC-006, ING-008) closes the memberships of objects a full
	// scan no longer observes — but only when the scan is an authoritative,
	// complete FULL run. If the connector could not enumerate the whole allowed
	// root (an unreadable subtree, a permission loss, an I/O error), an unseen
	// object may simply live under a subtree this pass never listed, so absence is
	// NOT deletion: memberships are preserved, no object is closed, and the run
	// records partial coverage honestly. Lease fencing and the exact scope-revision
	// key already bound reconciliation to this one authoritative run; a stale or
	// superseded lease cannot write.
	var partialCoverage *string
	observed := len(discovery.Objects) + len(discovery.Quarantined)
	switch {
	case !discovery.Complete:
		code := "INGEST_PARTIAL_COVERAGE"
		partialCoverage = &code
	case observed == 0:
		// An authoritative scan that observed nothing at all is indistinguishable
		// from a vanished or substituted mount (an unmounted volume presents an empty
		// but readable mountpoint), so it is never treated as mass deletion. Removing
		// every membership on an empty scan is irreversible, so absence with zero
		// corroboration is held rather than acted on. A genuinely emptied scope keeps
		// its memberships until a scan again observes objects or an explicit deletion
		// arrives.
		code := "INGEST_EMPTY_SCAN_UNCORROBORATED"
		partialCoverage = &code
	default:
		if err := h.reconcile(runCtx, access, claimed, resolved, syncRunID, discovery, observedByPath); err != nil {
			return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(err), err)
		}
	}

	// A crash here (scan done, authority not yet transitioned) must leave the prior
	// revision authoritative and the candidate still SYNCING — a reclaimed re-run
	// re-scans and re-attempts the transition (ADR-0061 §5).
	if err := h.injectFault("before_publish"); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_FAULT", err)
	}
	// Stop and drain the lifecycle heartbeat before the final authority
	// transition. This creates a clean lease-fenced publication barrier: any
	// in-flight heartbeat error is observed before the transaction can commit,
	// and the short final write/ack runs on the caller context after the guard is
	// closed. The deferred stop remains idempotent for every earlier return.
	if err := stopRunHeartbeat(); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, CodeOf(err), err)
	}

	coverageComplete := partialCoverage == nil

	if err := h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		// Record the run outcome first: coverage_complete is the DB containment that
		// source_scope_activate_revision reads to reject a cutover driven by a wrong,
		// foreign, stale or partial run id (ADR-0061 §4). A partial-coverage code is
		// the durable, operator-facing health signal that this pass was not
		// authoritative for deletion.
		if _, err := tx.Exec(ctx, `UPDATE public.sync_run SET status='SUCCEEDED', completed_at=now(),
			objects_seen=$2, objects_ingested=$3, versions_created=$4, evidence_published=$5, quarantined=$6,
			error_code=$8, coverage_complete=$9
			WHERE organization_id=$1 AND id=$7`,
			access.OrganizationID, counters.seen, counters.ingested, counters.versions,
			counters.evidence, counters.quarantined, syncRunID, partialCoverage, coverageComplete); err != nil {
			return err
		}
		// Persist the typed per-object skip ledger of this run in the same
		// fenced transaction as the run outcome, so the row set and the numeric
		// quarantined counter can never disagree.
		if err := h.recordObjectSkips(ctx, tx, access, syncRunID, scopeID, revision, skips); err != nil {
			return err
		}
		if coverageComplete {
			// Atomic authority transition: advance active_revision and, on a genuine
			// forward cutover, supersede every older revision — REVOKED activation,
			// ACTIVE->REMOVED memberships, and a proven SOURCE_OBJECT_DELETED for every
			// object that loses its last authority (ADR-0061 §1-§2, VER-005). The
			// function returns a typed outcome (the transaction's own truth, so the audit
			// classification cannot disagree with what it did) plus the closed object ids.
			rows, err := tx.Query(ctx, `SELECT outcome, closed_object_id
				FROM app.source_scope_activate_revision($1, $2, $3, $4, $5, $6)`,
				scopeID, revision, syncRunID, claimed.ID, h.workerID, claimed.LeaseEpoch)
			if err != nil {
				return err
			}
			var outcome string
			var closed []string
			for rows.Next() {
				var rowOutcome string
				var id *string
				if err := rows.Scan(&rowOutcome, &id); err != nil {
					rows.Close()
					return err
				}
				outcome = rowOutcome
				if id != nil {
					closed = append(closed, *id)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			// The authority transition and each object closure leave one content-free
			// audit event in this same transaction (AUD-005). Only a genuine cutover
			// (a superseded prior revision) is audited with source.scope_activated;
			// first activation, a re-sync and a refused stale candidate keep the S1e
			// source.scope_changed event.
			if outcome == "HELD" {
				// A stale candidate (a newer revision is already authoritative) was
				// refused; record it as a distinct, operator-facing health code.
				if _, err := tx.Exec(ctx, `UPDATE public.sync_run SET error_code='INGEST_STALE_CANDIDATE'
					WHERE organization_id=$1 AND id=$2`, access.OrganizationID, syncRunID); err != nil {
					return err
				}
			}
			if outcome == "CUTOVER" {
				if err := h.auditScopeActivated(ctx, access, tx, scopeID, revision, syncRunID); err != nil {
					return err
				}
			} else if err := h.auditSync(ctx, access, tx, scopeID, syncRunID); err != nil {
				return err
			}
			for _, id := range closed {
				if err := h.auditObjectClosure(ctx, tx, access, id, syncRunID, claimed.ID); err != nil {
					return err
				}
			}
			return nil
		}
		// Partial coverage never cuts over: a distinct prior revision stays
		// authoritative and the candidate is held FAILED (ADR-0061 §4); a first
		// activation or a re-sync of the current active revision publishes as before.
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_publish_partial($1, $2, $3, $4, $5)`,
			scopeID, revision, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		return h.auditSync(ctx, access, tx, scopeID, syncRunID)
	}); err != nil {
		return h.failSync(ctx, access, claimed, scopeID, revision, syncRunID, "INGEST_PUBLISH", err)
	}

	if err := h.queue.Complete(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
		return failure("INGEST_COMPLETE", err)
	}
	return nil
}

type syncCounters struct {
	seen, ingested, versions, evidence, quarantined int
}

// sourceObjectSkip is one typed, content-free per-object skip of one sync run:
// the object's stable external id and the closed reason code. It carries no
// source content.
type sourceObjectSkip struct {
	ExternalID string
	ReasonCode string
}

// sourceObjectSkipReasonExtraction and sourceObjectSkipReasonUnknown are the
// two codes the ingestion phase itself contributes. The migration's closed
// CHECK set mirrors both.
const (
	sourceObjectSkipReasonExtraction = "INGEST_EXTRACTION_SKIPPED"
	sourceObjectSkipReasonUnknown    = "INGEST_SKIP_REASON_UNKNOWN"
)

// sourceObjectSkipReasonCodes is the closed reason set, mirrored one-for-one by
// the CHECK constraint of db/migrations/000095_stage3_source_object_skip.sql.
// The connector codes, the extraction-phase code and the fallback all live
// here, so a carried code outside the set can never reach the ledger raw.
var sourceObjectSkipReasonCodes = []string{
	"FOLDER_SYMLINK_REJECTED", "FOLDER_NON_REGULAR", "FOLDER_OBJECT_OVERSIZED",
	"FOLDER_UNSUPPORTED_TYPE", "FOLDER_MEDIA_SIGNATURE_MISMATCH", "FOLDER_INVALID_UTF8",
	"TORN_READ_VERSION_MISMATCH", "FOLDER_ACL_UNKNOWN", "FOLDER_CONTAINMENT_VIOLATION",
	"GIT_UNSUPPORTED_MEDIA_TYPE", "GIT_BLOB_OVERSIZED", "GIT_INVALID_UTF8",
	"GIT_BLOB_ID_MISMATCH", "GIT_BLOB_READ_FAILED",
	"MAIL_MESSAGE_MALFORMED", "MAIL_MESSAGE_OVERSIZED", "MAIL_ATTACHMENT_OVERSIZED",
	"MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE", "MAIL_ATTACHMENT_MALFORMED",
	"MAIL_MESSAGE_READ_FAILED", "UPLOAD_OBJECT_OVERSIZED",
	sourceObjectSkipReasonExtraction, sourceObjectSkipReasonUnknown,
}

// sourceObjectSkipReason validates a connector/ingestion reason code against
// the closed set the migration CHECK enforces. A code outside the set is
// normalized to the closed unknown fallback rather than failing the whole sync
// run, and the connector codes computed today surface verbatim.
func sourceObjectSkipReason(code string) string {
	if slices.Contains(sourceObjectSkipReasonCodes, code) {
		return code
	}
	return sourceObjectSkipReasonUnknown
}

// skipForResult builds the typed ledger row for one object the extraction phase
// quarantined. The reason is the pipeline's carried code normalized through the
// closed set, so every row records a real cause and none is empty (KV-A02).
func skipForResult(relativePath string, result ingestResult) sourceObjectSkip {
	return sourceObjectSkip{
		ExternalID: relativePath,
		ReasonCode: sourceObjectSkipReason(result.quarantineReason),
	}
}

// skipIdentityArtifact is the sealed plaintext of one skip identity. The native
// external id is never stored in plaintext: the row keeps only the org-keyed
// HMAC digest, and the identity is sealed inside the artifact under the closed
// external-object-id owner branch (KV-A02b). The digest travels inside the
// authenticated artifact as well, so the authorized read path can refuse a row
// whose ledger digest was tampered with without holding the HMAC key.
type skipIdentityArtifact struct {
	ExternalID string `json:"external_id"`
	Digest     string `json:"digest"`
}

// recordObjectSkips inserts one typed skip row per skipped object of this run
// with the native identity sealed as an encrypted artifact (KV-A02b). It is
// called inside the run's publication transaction, after the sync_run counters
// are written. The ledger row is inserted first with its digest and a deferred
// artifact foreign key; only a genuinely new row is followed by the identity
// artifact bind, so a reclaimed re-run writes no orphan artifact and exactly
// one row per skipped object survives.
func (h *Handler) recordObjectSkips(ctx context.Context, tx database.Transaction, access database.AccessContext,
	syncRunID, scopeID string, revision int64, skips []sourceObjectSkip) error {
	for _, skip := range skips {
		digest := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, []byte(skip.ExternalID))
		artifactID, err := h.newID("art")
		if err != nil {
			return err
		}
		plaintext, err := jsonv2.Marshal(skipIdentityArtifact{ExternalID: skip.ExternalID, Digest: digest})
		if err != nil {
			return err
		}
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceObjectExternalID, access.OrganizationID, artifactID)
		if err != nil {
			return err
		}
		envelope, err := h.codec.Seal(owner, plaintext)
		if err != nil {
			return err
		}
		var inserted bool
		err = tx.QueryRow(ctx, `INSERT INTO public.source_object_skip
			(organization_id, sync_run_id, source_scope_id, source_scope_revision, external_id_digest,
			 digest_key_version, external_id_artifact_id, reason_code, observed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (organization_id, sync_run_id, source_scope_id, source_scope_revision, external_id_digest)
			DO NOTHING
			RETURNING true`,
			access.OrganizationID, syncRunID, scopeID, revision, digest, h.digester.KeyVersion,
			artifactID, skip.ReasonCode, h.now().UTC()).Scan(&inserted)
		if database.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.source_object_skip_bind_external_id(
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			access.OrganizationID, artifactID, artifactID, artifactID,
			envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(), envelope.WrappedDEK(),
			envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(),
			envelope.AADHash(), envelope.PlaintextHash()); err != nil {
			return err
		}
	}
	return nil
}

// activationGate is the resolution-time trust gate (SRC-014): only a SYNCING
// revision of a WORKSPACE_MANAGED source scope whose trust profile is verified
// may resolve.  The connector factory remains a second gate: a supported
// source kind without a real deployment adapter is unavailable, never a folder
// fallback.  The gate is pure so its refusal semantics carry a direct GO_UNIT
// mutation proof; resolve keeps no other activation check.
func activationGate(sourceType, accessMode, activationStatus string, trustVerified bool) error {
	switch sourceType {
	case "FOLDER", "GIT", "MAIL":
	default:
		return failure("INGEST_SCOPE_UNSUPPORTED", nil)
	}
	if accessMode != "WORKSPACE_MANAGED" {
		return failure("INGEST_SCOPE_UNSUPPORTED", nil)
	}
	if activationStatus != "SYNCING" || !trustVerified {
		return failure("INGEST_ACTIVATION_NOT_READY", nil)
	}
	return nil
}

// resolve turns an activated FOLDER SourceScopeRevision into an in-process
// folder.Scope by decrypting the scope-config and trust-profile artifacts and
// binding the pre-mounted root, all through SECURITY DEFINER reads.
func (h *Handler) resolve(ctx context.Context, access database.AccessContext, scopeID string, revision int64) (resolvedScope, error) {
	var (
		connectionID, accessMode, sourceType, scopeConfigHash, trustProfileHash string
		scopeConfigResourceID, trustConfigResourceID, activationStatus          string
		connectionRevision                                                      int64
		trustVerified                                                           bool
	)
	if err := h.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT connection_id, connection_revision, access_mode, source_type,
			scope_config_hash, trust_profile_hash, scope_config_resource_id, trust_config_resource_id,
			activation_status, trust_verified FROM app.source_scope_sync_target($1, $2)`, scopeID, revision).
			Scan(&connectionID, &connectionRevision, &accessMode, &sourceType, &scopeConfigHash,
				&trustProfileHash, &scopeConfigResourceID, &trustConfigResourceID, &activationStatus, &trustVerified)
	}); err != nil {
		return resolvedScope{}, failure("INGEST_SCOPE_NOT_FOUND", err)
	}
	if err := activationGate(sourceType, accessMode, activationStatus, trustVerified); err != nil {
		return resolvedScope{}, err
	}
	if sourceType != "FOLDER" {
		if h.adapterResolver == nil {
			return resolvedScope{}, failure("INGEST_ADAPTER_UNAVAILABLE", nil)
		}
		binding, err := h.adapterResolver.Resolve(ctx, access, ObservationAdapterTarget{
			OrganizationID: access.OrganizationID, ConnectionID: connectionID,
			ConnectionRevision: connectionRevision, SourceScopeID: scopeID,
			SourceScopeRevision: revision, SourceType: sourceType,
			AccessMode: accessMode, ScopeConfigResource: scopeConfigResourceID,
			ScopeConfigHash: scopeConfigHash, TrustConfigResource: trustConfigResourceID,
			TrustProfileHash: trustProfileHash,
		})
		if err != nil || binding.Adapter == nil {
			return resolvedScope{}, failure("INGEST_ADAPTER_UNAVAILABLE", err)
		}
		kind, formats, bindingErr := validateObservationBindingForResolution(sourceType, binding)
		if bindingErr != nil {
			return resolvedScope{}, bindingErr
		}
		return resolvedScope{adapter: binding.Adapter, sourceType: sourceType,
			sourceKind: kind, connectionID: connectionID, scopeID: scopeID,
			revision: revision, pathCase: pathcanon.CaseSensitive, formats: formats, close: binding.Close}, nil
	}

	var scopeConfig folderConfig
	if err := h.decryptJSON(ctx, access, artifactcrypto.SourceScopeConfig, scopeConfigResourceID, scopeConfigHash, &scopeConfig); err != nil {
		return resolvedScope{}, err
	}
	var trust folderTrust
	if err := h.decryptJSON(ctx, access, artifactcrypto.SourceConnectionTrustConfig, trustConfigResourceID, trustProfileHash, &trust); err != nil {
		return resolvedScope{}, err
	}

	if trust.RootAlias == uploadRootAlias && trust.RootIdentity == uploadRootIdentity {
		// UPL-1: this FOLDER connection's content is browser-uploaded, not a
		// pre-mounted host directory (mounts.go never resolves this reserved
		// alias). scopeConfig.RootAlias must still agree with the trust
		// profile like every other FOLDER scope (SRC-013 parity).
		if scopeConfig.RootAlias != trust.RootAlias {
			return resolvedScope{}, failure("INGEST_ROOT_UNRESOLVED", nil)
		}
		allowedFormats := make(map[string]bool, len(scopeConfig.Formats))
		for _, f := range scopeConfig.Formats {
			allowedFormats[f] = true
		}
		adapter := newUploadAdapter(h.db, access, connectionID, scopeID, revision, scopeConfig.MaxFileBytes)
		return resolvedScope{adapter: adapter, sourceType: sourceType, sourceKind: observation.KindDocument,
			connectionID: connectionID, scopeID: scopeID, revision: revision,
			pathCase: pathcanon.CaseSensitive, formats: allowedFormats}, nil
	}

	rootPath, ok := h.mounts.Resolve(trust.RootAlias, trust.RootIdentity)
	if !ok || scopeConfig.RootAlias != trust.RootAlias {
		return resolvedScope{}, failure("INGEST_ROOT_UNRESOLVED", nil)
	}
	platform := folder.PlatformPOSIX
	pathCase := pathcanon.CaseSensitive
	if trust.Platform == "WINDOWS" {
		platform = folder.PlatformWindows
		pathCase = pathcanon.CaseWindows
	}
	formats := make([]folder.Format, 0, len(scopeConfig.Formats))
	allowedFormats := make(map[string]bool, len(scopeConfig.Formats))
	for _, f := range scopeConfig.Formats {
		formats = append(formats, folder.Format(f))
		allowedFormats[f] = true
	}
	scope, err := folder.NewScope(folder.ScopeParams{
		RootPath: rootPath, Platform: platform, Access: folder.AccessWorkspaceManaged,
		RelativeRoot: scopeConfig.RelativeRoot, Recursive: scopeConfig.Recursive,
		IncludeGlobs: scopeConfig.IncludeGlobs, ExcludeGlobs: scopeConfig.ExcludeGlobs,
		MaxFileBytes: scopeConfig.MaxFileBytes, Formats: formats,
	})
	if err != nil {
		return resolvedScope{}, failure("INGEST_SCOPE_BUILD", err)
	}
	adapter, err := observation.NewFolderAdapter(h.connector, scope, access.OrganizationID,
		scopeID, revision, observation.KindDocument)
	if err != nil {
		return resolvedScope{}, failure("INGEST_ADAPTER", err)
	}
	return resolvedScope{scope: scope, adapter: adapter, sourceType: sourceType,
		sourceKind: observation.KindDocument, connectionID: connectionID, scopeID: scopeID,
		revision: revision, pathCase: pathCase, formats: allowedFormats}, nil
}

func observationKindForSourceType(sourceType string) (observation.Kind, bool) {
	switch sourceType {
	case "FOLDER":
		return observation.KindDocument, true
	case "GIT":
		return observation.KindGit, true
	case "MAIL":
		return observation.KindMail, true
	default:
		return "", false
	}
}

func validateObservationBinding(sourceType string, binding ObservationAdapterBinding) (observation.Kind, map[string]bool, error) {
	kind, ok := observationKindForSourceType(sourceType)
	if !ok || binding.Adapter == nil || binding.Adapter.Kind() != kind || len(binding.Formats) == 0 {
		return "", nil, failure("INGEST_ADAPTER_INVALID", nil)
	}
	formats := make(map[string]bool, len(binding.Formats))
	for name, allowed := range binding.Formats {
		if !validObservationFormat(name) || !allowed {
			return "", nil, failure("INGEST_ADAPTER_INVALID", nil)
		}
		formats[name] = true
	}
	return kind, formats, nil
}

// validateObservationBindingForResolution applies the source/type/format
// contract and retires any connector returned by a resolver when that
// contract fails.  Remote connectors own sockets and TLS state; returning an
// invalid binding must therefore never leak an acquired transport, even on a
// fail-closed path before resolvedScope can install its deferred cleanup.
func validateObservationBindingForResolution(sourceType string, binding ObservationAdapterBinding) (observation.Kind, map[string]bool, error) {
	kind, formats, err := validateObservationBinding(sourceType, binding)
	if err != nil {
		if binding.Close != nil {
			_ = binding.Close()
		}
		return "", nil, err
	}
	return kind, formats, nil
}

func validObservationFormat(value string) bool {
	switch value {
	case "PDF", "DOCX", "PPTX", "XLSX", "CSV", "TXT", "MARKDOWN", "HTML", "JSON", "XML", "EML", "SOURCE_CODE", "PNG", "JPEG":
		return true
	default:
		return false
	}
}

// decryptJSON reads an encrypted artifact by its resource id, opens it and
// unmarshals the plaintext, verifying the plaintext hash equals the trusted
// stored hash.
func (h *Handler) decryptJSON(ctx context.Context, access database.AccessContext,
	field artifactcrypto.OwnerField, resourceID, expectedHash string, out any) error {
	var plaintext []byte
	if err := h.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		owner, envelope, err := h.repo.Fetch(ctx, tx, access, field, resourceID)
		if err != nil {
			return err
		}
		plaintext, err = h.codec.Open(owner, envelope)
		return err
	}); err != nil {
		return failure("INGEST_DECRYPT", err)
	}
	if canon.Hash(plaintext) != expectedHash {
		return failure("INGEST_CONFIG_HASH_MISMATCH", nil)
	}
	if err := jsonv2.Unmarshal(jsontext.Value(plaintext), out); err != nil {
		return failure("INGEST_CONFIG_DECODE", err)
	}
	return nil
}

// folderConfig mirrors source-scope.schema.json folderConfig. Every schema field
// is present so decoding the trusted plaintext neither drops nor rejects a field.
type folderConfig struct {
	RootAlias          string   `json:"root_alias"`
	RelativeRoot       string   `json:"relative_root"`
	PathMatcherVersion string   `json:"path_matcher_version"`
	Recursive          bool     `json:"recursive"`
	IncludeGlobs       []string `json:"include_globs"`
	ExcludeGlobs       []string `json:"exclude_globs"`
	MaxFileBytes       int64    `json:"max_file_bytes"`
	OCRMode            string   `json:"ocr_mode"`
	FollowSymlinks     bool     `json:"follow_symlinks"`
	Formats            []string `json:"formats"`
}

// folderTrust is the connection trust profile (source-folder-trust-v1): the
// signed platform and the trusted root alias/identity of the pre-mounted root.
type folderTrust struct {
	SchemaVersion string `json:"schema_version"`
	Platform      string `json:"platform"`
	RootAlias     string `json:"root_alias"`
	RootIdentity  string `json:"root_identity"`
}

// reconcile marks objects not observed by a full scan MISSING in this scope.
// Absence is reversible only by successful fenced publication. An object stays
// ACTIVE while any other scope still holds an ACTIVE membership.
func (h *Handler) reconcile(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob,
	resolved resolvedScope, syncRunID string, discovery folder.DiscoveryResult,
	observedByID map[string]*observation.Object) error {
	seen := make([]string, 0, len(discovery.Objects)+len(discovery.Quarantined))
	add := func(externalID string) error {
		var identity []byte
		var err error
		if observed := observedByID[externalID]; observed != nil && observed.Kind != observation.KindDocument {
			identity, err = canon.ObservationExternalIDBytes(resolved.connectionID, string(observed.Kind), observed.ExternalID)
		} else if resolved.sourceKind != observation.KindDocument {
			// A quarantined remote object still has a stable external identity. Its
			// parent/part locator may be unavailable, but reconciliation compares
			// the external-id digest, so never substitute the locator projection.
			identity, err = canon.ObservationExternalIDBytes(resolved.connectionID, string(resolved.sourceKind), externalID)
		} else {
			identity, err = canon.FileLocatorBytes(resolved.connectionID, externalID)
		}
		if err != nil {
			return failure("INGEST_LOCATOR", err)
		}
		seen = append(seen, canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, identity))
		return nil
	}
	for _, object := range discovery.Objects {
		if err := add(object.RelativePath); err != nil {
			return err
		}
	}
	for _, quarantined := range discovery.Quarantined {
		if err := add(quarantined.RelativePath); err != nil {
			return err
		}
	}
	return h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.lock_job_lease($1, $2, $3)`, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		// Reconciliation is a derived write too: fence it to this revision's live
		// SYNCING authority (ADR-0061 §3) so a superseded revision's worker cannot
		// close memberships or objects after a cutover has revoked it.
		if _, err := tx.Exec(ctx, `SELECT app.assert_scope_revision_syncing($1, $2)`, resolved.scopeID, resolved.revision); err != nil {
			return err
		}
		// First close the memberships this scan no longer observes. A data-modifying
		// CTE would run the object-closure read against the pre-update snapshot, so
		// this is a separate statement: the object closure below must see these rows
		// as already MISSING.
		// The absence predicate is scoped to the exact connection and digest key
		// version the scan's `seen` digests were computed under, mirroring
		// ensureObject's identity lookup. An object ingested under a rotated key
		// version has a digest the current scan cannot reproduce, so scoping here
		// prevents a key rotation from manufacturing false removals.
		if _, err := tx.Exec(ctx, `UPDATE public.source_object_scope AS os
			SET membership_state='MISSING', missing_at=now(), missing_sync_run_id=$7
			FROM public.source_object AS o
			WHERE os.organization_id=$1 AND o.organization_id=$1 AND os.source_object_id=o.id
			  AND os.source_scope_id=$2 AND os.source_scope_revision=$3 AND os.membership_state='ACTIVE'
			  AND o.connection_id=$5 AND o.digest_key_version=$6
			  AND o.external_object_id_digest <> ALL($4::text[])`,
			access.OrganizationID, resolved.scopeID, resolved.revision, seen,
			resolved.connectionID, h.digester.KeyVersion, syncRunID); err != nil {
			return err
		}
		// A crash between the membership closure and its commit must roll the whole
		// reconciliation back — no membership or object is left MISSING.
		if err := h.injectFault("in_reconcile"); err != nil {
			return err
		}
		// No ACTIVE membership means the object is currently absent everywhere.
		// MISSING adds a second disclosure gate while preserving its identity and
		// immutable versions for an observed return. An overlapping ACTIVE scope
		// keeps the object available and prevents a false object-missing event.
		rows, err := tx.Query(ctx, `UPDATE public.source_object AS o
			SET lifecycle_state='MISSING', queryable=false, last_seen_at=now()
			WHERE o.organization_id=$1 AND o.lifecycle_state='ACTIVE'
			  AND EXISTS (SELECT 1 FROM public.source_object_scope AS r
			              WHERE r.organization_id=o.organization_id AND r.source_object_id=o.id
			                AND r.source_scope_id=$2 AND r.source_scope_revision=$3
			                AND r.membership_state='MISSING')
			  AND NOT EXISTS (SELECT 1 FROM public.source_object_scope AS m
			                  WHERE m.organization_id=o.organization_id AND m.source_object_id=o.id
			                    AND m.membership_state='ACTIVE')
			RETURNING o.id`,
			access.OrganizationID, resolved.scopeID, resolved.revision)
		if err != nil {
			return err
		}
		var missing []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			missing = append(missing, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// Each object closure is a significant lifecycle transition and leaves one
		// content-free audit event in the same transaction (AUD-005): a SYSTEM actor,
		// the exact object id, the sync run and job that caused it — no path, title or
		// content.
		for _, id := range missing {
			if err := h.auditEntity(ctx, access, tx, audit.ActionSourceObjectMissing, audit.ResourceSourceObject, id, syncRunID, claimed.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// auditEntity appends one content-free per-transition audit event inside the
// caller's transaction (AUD-005 completeness): a SYSTEM actor, the exact entity
// as the resource, and only safe ids in metadata (the sync run and job that
// caused it) — never a path, title, locator or Evidence text.
func (h *Handler) auditEntity(ctx context.Context, access database.AccessContext, tx database.Transaction,
	action audit.Action, resource audit.ResourceType, resourceID, syncRunID, jobID string) error {
	if h.audit == nil {
		return failure("INGEST_AUDIT_UNAVAILABLE", nil)
	}
	eventID, err := h.newID("audit")
	if err != nil {
		return err
	}
	sync := syncRunID
	job := jobID
	_, err = h.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID:      eventID,
		ActorType:    audit.ActorSystem,
		Action:       action,
		ResourceType: resource,
		ResourceID:   resourceID,
		RequestID:    access.RequestID,
		Outcome:      audit.OutcomeSuccess,
		OccurredAt:   h.now(),
		Metadata:     audit.Metadata{SyncRunID: &sync, ConnectorJobID: &job},
	})
	return err
}

// auditSync appends the scope-sync audit event inside the publication
// transaction (AUD-005). The worker is a SYSTEM actor, so no principal is bound;
// the metadata carries only safe ids (scope, sync run), never source content.
func (h *Handler) auditSync(ctx context.Context, access database.AccessContext, tx database.Transaction, scopeID, syncRunID string) error {
	if h.audit == nil {
		return failure("INGEST_AUDIT_UNAVAILABLE", nil)
	}
	eventID, err := h.newID("audit")
	if err != nil {
		return err
	}
	scope := scopeID
	run := syncRunID
	_, err = h.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID:      eventID,
		ActorType:    audit.ActorSystem,
		Action:       audit.ActionSourceScopeChanged,
		ResourceType: audit.ResourceSourceScope,
		ResourceID:   scopeID,
		RequestID:    access.RequestID,
		Outcome:      audit.OutcomeSuccess,
		OccurredAt:   h.now(),
		Metadata:     audit.Metadata{SourceScopeID: &scope, SyncRunID: &run},
	})
	return err
}

// auditScopeActivated appends the scope-revision cutover audit event inside the
// activation transaction (AUD-005, ADR-0061 §1). It marks the authority
// transition to a new revision; the metadata carries only the scope, the newly
// authoritative revision and the sync run — never source content.
func (h *Handler) auditScopeActivated(ctx context.Context, access database.AccessContext, tx database.Transaction, scopeID string, revision int64, syncRunID string) error {
	if h.audit == nil {
		return failure("INGEST_AUDIT_UNAVAILABLE", nil)
	}
	eventID, err := h.newID("audit")
	if err != nil {
		return err
	}
	scope := scopeID
	run := syncRunID
	rev := revision
	_, err = h.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID:      eventID,
		ActorType:    audit.ActorSystem,
		Action:       audit.ActionSourceScopeActivated,
		ResourceType: audit.ResourceSourceScope,
		ResourceID:   scopeID,
		RequestID:    access.RequestID,
		Outcome:      audit.OutcomeSuccess,
		OccurredAt:   h.now(),
		Metadata:     audit.Metadata{SourceScopeID: &scope, SourceScopeRevision: &rev, SyncRunID: &run},
	})
	return err
}

func (h *Handler) fail(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob, code string, cause error) error {
	_ = h.queue.Fail(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch, jobs.ErrorCode(code), 60)
	return failure(code, cause)
}

func (h *Handler) heartbeat(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob) error {
	if h.queue == nil || h.leaseExtensionSeconds < 1 || h.leaseExtensionSeconds > 3600 {
		return failure("INGEST_HEARTBEAT", nil)
	}
	if err := h.queue.Heartbeat(ctx, access, claimed.ID, h.workerID, claimed.LeaseEpoch, h.leaseExtensionSeconds); err != nil {
		return failure("INGEST_HEARTBEAT", err)
	}
	return nil
}

// leaseHeartbeatInterval deliberately stays well below the lease extension.
// Capping it at 30 seconds bounds loss detection for unusually long leases;
// using one third of the normal 60-second lease avoids a per-job DB write every
// second while retaining two thirds of the lease as scheduling/DB headroom.
// The lower bound keeps very short deployment leases from busy-looping.
func leaseHeartbeatInterval(extensionSeconds int) time.Duration {
	if extensionSeconds < 1 || extensionSeconds > 3600 {
		extensionSeconds = 60
	}
	interval := time.Duration(extensionSeconds) * time.Second / 3
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	return interval
}

// continuousHeartbeat runs the lease extension for one bounded claim
// lifecycle. It is kept independent of Handler so its cancellation/drain
// semantics can be tested without a database substitute. The production
// callback is always Handler.heartbeat; tests only exercise this concurrency
// boundary.
type continuousHeartbeat struct {
	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	err     error
	stopErr error
	once    sync.Once
}

func startContinuousHeartbeat(parent context.Context, interval time.Duration,
	beat func(context.Context) error) (context.Context, func() error) {
	if parent == nil {
		parent = context.Background()
	}
	if interval <= 0 {
		interval = time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	runner := &continuousHeartbeat{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(runner.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := beat(ctx); err != nil {
					runner.mu.Lock()
					// A normal object completion cancels the child context to
					// stop the ticker. Do not turn the resulting context
					// cancellation into a failed heartbeat. A real queue/DB
					// error is retained even when stop raced an in-flight beat.
					expectedCancellation := ctx.Err() != nil &&
						(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
					if !expectedCancellation {
						runner.err = err
					}
					runner.mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	stop := func() error {
		runner.once.Do(func() {
			cancel()
			<-runner.done
			runner.mu.Lock()
			runner.stopErr = runner.err
			runner.mu.Unlock()
		})
		runner.mu.Lock()
		defer runner.mu.Unlock()
		return runner.stopErr
	}
	return ctx, stop
}

func (h *Handler) startObjectHeartbeat(parent context.Context, access database.AccessContext,
	claimed jobs.ClaimedJob) (context.Context, func() error) {
	return startContinuousHeartbeat(parent, leaseHeartbeatInterval(h.leaseExtensionSeconds),
		func(ctx context.Context) error {
			return h.heartbeat(ctx, access, claimed)
		})
}

func (h *Handler) failSync(ctx context.Context, access database.AccessContext, claimed jobs.ClaimedJob,
	scopeID string, revision int64, syncRunID, code string, cause error) error {
	_ = h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, _ = tx.Exec(ctx, `SELECT app.source_scope_mark_failed($1, $2, $3, $4, $5)`,
			scopeID, revision, claimed.ID, h.workerID, claimed.LeaseEpoch)
		_, err := tx.Exec(ctx, `UPDATE public.sync_run SET status='FAILED', completed_at=now(), error_code=$3
			WHERE organization_id=$1 AND id=$2 AND status='RUNNING'`, access.OrganizationID, syncRunID, code)
		return err
	})
	return h.fail(ctx, access, claimed, code, cause)
}
