package workercomposition

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
	"knowvault.local/verified-workspace/internal/rotation"
	"knowvault.local/verified-workspace/internal/search"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

const (
	workerPrincipalID = "knowvault_worker"
	workerPollID      = "worker.poll"
	reclaimLimit      = 100
	unsupportedRetry  = 300
	searchDrainLimit  = 256
	// searchReindexSlice bounds one heartbeat window of a profile-revision
	// re-index. The pass is resumable, so a slice is a lease budget, not a
	// completeness limit.
	searchReindexSlice = 256
)

// Startup stage tags for DiagnosticClass. Each names the fixed capability
// NewProduction was acquiring when it stopped -- never a path, secret or
// identity -- so an operator can tell a mount problem from a database
// problem from a trust problem without the log carrying anything sensitive.
const (
	stageTrustBundle              = "TRUST_BUNDLE"
	stageTrustBundleDatabaseRoots = "TRUST_BUNDLE_DATABASE_ROOTS"
	stageSecrets                  = "SECRETS"
	stageSecretsDatabaseURL       = "SECRETS_DATABASE_URL"
	stageSourceMounts             = "SOURCE_MOUNTS"
	stageDatabaseOpen             = "DATABASE_OPEN"
	stageArtifactCodec            = "ARTIFACT_CODEC"
	stageSourceDigest             = "SOURCE_DIGEST"
	stageIngestionRepository      = "INGESTION_REPOSITORY"
	stageSearchRepository         = "SEARCH_REPOSITORY"
	stageJobsQueue                = "JOBS_QUEUE"
	stageObservationAdapter       = "OBSERVATION_ADAPTER_RESOLVER"
	stagePostgreSQLConnector      = "POSTGRESQL_CONNECTOR"
	stageSourceDiscoveryHandler   = "SOURCE_DISCOVERY_HANDLER"
	stageRotationHandler          = "ROTATION_HANDLER"
	stageSearchMount              = "SEARCH_MOUNT"
	stageEmbeddingMount           = "EMBEDDING_MOUNT"
	stageEmbeddingClient          = "EMBEDDING_CLIENT"
	stageSearchClient             = "SEARCH_CLIENT"
	stageSearchIndex              = "SEARCH_INDEX"
	stageClaimAccess              = "CLAIM_ACCESS"
	stageAuditStore               = "AUDIT_STORE"
	stageSourceScheduler          = "SOURCE_SCHEDULER"
	stageSearchProfileBootstrap   = "SEARCH_PROFILE_BOOTSTRAP"
	stageSearchApplier            = "SEARCH_APPLIER"
	stageNativeParser             = "NATIVE_PARSER"
)

type workerRunner interface {
	Execute(context.Context) error
}

type cleanupFunc func() error

// Runtime is an opaque, copy-safe one-shot worker handle. It owns no public
// resource accessors; only Run/Close can consume its lifecycle.
type Runtime struct{ state *runtimeState }

type runtimePhase uint8

const (
	runtimeReady runtimePhase = iota + 1
	runtimeRunning
	runtimeClosing
	runtimeClosed
)

type runtimeState struct {
	mu          sync.Mutex
	phase       runtimePhase
	runner      workerRunner
	cleanup     []cleanupFunc
	runCancel   context.CancelFunc
	done        chan struct{}
	closeResult error
}

func (Runtime) String() string   { return "workercomposition.Runtime{[REDACTED]}" }
func (Runtime) GoString() string { return "workercomposition.Runtime{[REDACTED]}" }

// NewProduction acquires all worker capabilities before the job loop can run.
// The worker role and fixed source/secret/trust mounts are selected here, not
// inside ingestion or a job payload.
func NewProduction(ctx context.Context, config Config, info buildinfo.Info) (*Runtime, error) {
	_ = info
	if ctx == nil || ctx.Err() != nil || !validConfig(config) {
		return nil, workerError(CodeConfigInvalid)
	}

	var acquired cleanupStack
	fail := func(stage string, cause error) (*Runtime, error) {
		_ = acquired.rollback()
		return nil, startupError(stage, cause)
	}
	if config.NativeEnabled() {
		if err := CheckNativeReadiness(ctx, config); err != nil {
			return fail(stageNativeParser, err)
		}
	}
	office, pdf, err := nativeExtractors(config)
	if err != nil {
		return fail(stageNativeParser, err)
	}

	bundle, err := trustbundle.LoadWorkerMounted()
	if err != nil {
		return fail(stageTrustBundle, err)
	}
	secrets, err := secretmount.LoadWorkerMountedForTenant(config.OrganizationID(), config.ProviderID())
	if err != nil {
		return fail(stageSecrets, err)
	}
	acquired.push(secrets.Close)

	mounts, err := loadMountedMounts()
	if err != nil {
		return fail(stageSourceMounts, err)
	}

	databaseURL, err := secrets.DatabaseURL()
	if err != nil {
		return fail(stageSecretsDatabaseURL, err)
	}
	databaseRoots, err := bundle.DatabaseRoots()
	if err != nil {
		databaseURL = ""
		return fail(stageTrustBundleDatabaseRoots, err)
	}
	databaseConfig := database.DefaultConfig()
	databaseConfig.ApplicationRole = workerPrincipalID
	databaseConfig.URL = databaseURL
	databaseStore, err := database.OpenProduction(ctx, databaseConfig, databaseRoots)
	databaseURL = ""
	databaseConfig.URL = ""
	if err != nil {
		return fail(stageDatabaseOpen, err)
	}
	acquired.push(func() error { databaseStore.Close(); return nil })

	artifactProvider, codec, err := newArtifactCodec(secrets, config)
	if err != nil {
		return fail(stageArtifactCodec, err)
	}
	acquired.push(artifactProvider.Close)

	digester, clearDigest, err := newSourceDigester(secrets)
	if err != nil {
		return fail(stageSourceDigest, err)
	}
	acquired.push(func() error { clearDigest(); return nil })

	repository, err := ingestion.BuildRepository()
	if err != nil {
		return fail(stageIngestionRepository, err)
	}
	searchRepository, err := search.NewRepository()
	if err != nil {
		return fail(stageSearchRepository, err)
	}
	queue, err := jobs.New(databaseStore)
	if err != nil {
		return fail(stageJobsQueue, err)
	}
	handler := ingestion.NewHandler(databaseStore, queue, repository, codec, digester, mounts, config.WorkerID(), time.Now, ids.New).
		WithLeaseExtensionSeconds(config.LeaseSeconds()).
		WithKnowledgeGraph(knowledgegraph.NewRepository()).
		WithSearchRepository(searchRepository)
	if config.NativeEnabled() {
		handler = handler.WithOfficeExtractor(office).WithPDFExtractor(pdf)
	}
	remoteResolver, err := ingestion.NewRemoteObservationAdapterResolver(databaseStore, repository, codec, secrets, loadSourceTrustPools)
	if err != nil {
		return fail(stageObservationAdapter, err)
	}
	handler = handler.WithObservationAdapterResolver(remoteResolver)
	// The SQL-source connector must authenticate an operator-registered
	// external database against that source's own registered CA, never
	// against databaseRoots (KnowVault's own control-plane database trust,
	// used only for databaseStore above) — see sourcePostgreSQLTrustRoots.
	pgConnector, err := postgresqlquery.NewLiveConnectorWithTrust(secrets, sourcePostgreSQLTrustRoots{})
	if err != nil {
		return fail(stagePostgreSQLConnector, err)
	}
	handler = handler.WithPostgreSQLQueryConnector(pgConnector)
	discoveryHandler, err := sourcediscovery.NewHandler(databaseStore, queue, repository, codec, pgConnector,
		config.WorkerID(), config.LeaseSeconds(), ids.New)
	if err != nil {
		return fail(stageSourceDiscoveryHandler, err)
	}
	// Rotation jobs (ADR-0070) run on the same worker substrate with the same
	// mounted key material: the provider already carries the active pair plus
	// the optional previous pair of an in-flight rotation, and the digester is
	// the active source digest key the recompute pass re-projects with.
	rotationHandler, err := rotation.NewHandler(databaseStore, queue, artifactProvider, codec,
		rotation.Digester{Key: digester.Key, KeyVersion: digester.KeyVersion}, config.WorkerID(), time.Now, ids.New)
	if err != nil {
		return fail(stageRotationHandler, err)
	}
	var searchApplier *search.Applier
	searchConfig, searchMountErr := search.LoadWorkerMountedForTenant(string(config.OrganizationID()))
	if searchMountErr != nil {
		return fail(stageSearchMount, searchMountErr)
	}
	// Worker and server must use one administrator-owned embedding profile. A
	// missing optional mount keeps lexical indexing available; a malformed
	// present mount fails startup and can never downgrade silently.
	embeddingConfig, embeddingMountErr := embedding.LoadWorkerMountedForTenant(string(config.OrganizationID()))
	var embeddingClient *embedding.Client
	if embeddingMountErr != nil {
		if embedding.CodeOf(embeddingMountErr) != embedding.CodeMountUnavailable {
			return fail(stageEmbeddingMount, embeddingMountErr)
		}
	} else {
		embeddingClient, err = embedding.New(embeddingConfig.Profile, embeddingConfig.TrustRoots, embeddingConfig.ClientCertificate, nil)
		if err != nil {
			return fail(stageEmbeddingClient, err)
		}
		acquired.push(embeddingClient.Close)
		searchConfig.VectorProfileHash = embeddingConfig.Profile.ProfileHash
		searchConfig.VectorDimension = embeddingConfig.Profile.Dimension
	}
	searchClient, clientErr := search.New(searchConfig)
	if clientErr != nil {
		return fail(stageSearchClient, clientErr)
	}
	acquired.push(searchClient.Close)
	// The indexer owns the shape of the index it writes to. A deployment
	// with a mounted embedding profile must have a vector-capable index
	// before its first write, or every document lands in an implicitly
	// created lexical index and no semantic query can ever match.
	if err := searchClient.EnsureIndex(ctx); err != nil {
		return fail(stageSearchIndex, err)
	}

	claimAccess := database.AccessContext{
		OrganizationID: string(config.OrganizationID()),
		PrincipalID:    workerPrincipalID,
		RequestID:      workerPollID,
	}
	if err := claimAccess.Validate(); err != nil {
		return fail(stageClaimAccess, err)
	}
	// The worker autonomously enqueues due FOLDER and POSTGRESQL_QUERY source
	// syncs once per poll tick, reusing the exact registration/job/audit path an
	// operator-requested :sync already uses (registration.Service.AutoSync,
	// migration 000089's app.postgresql_query_scope_due). No new audit store,
	// codec or digest key is introduced; these are the same values
	// ingestion.NewHandler already derives for this worker process.
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		return fail(stageAuditStore, err)
	}
	sourceScheduler, err := registration.New(databaseStore, auditStore, codec, queue, digester.Key, digester.KeyVersion)
	if err != nil {
		return fail(stageSourceScheduler, err)
	}
	// Provision the active lexical projection profile before the job loop. The
	// row is tenant-bound and generation-fenced; a pre-existing drift or staged
	// profile stops startup instead of allowing the applier to write stale data.
	if err := databaseStore.Write(ctx, claimAccess, func(txCtx context.Context, transaction database.Transaction) error {
		if embeddingClient != nil {
			profile := embeddingClient.Profile()
			return searchRepository.EnsureMountedProfile(txCtx, transaction, claimAccess,
				profile.ID, profile.ProfileHash, searchConfig.Generation, searchConfig.GenerationFence)
		}
		return searchRepository.EnsureMountedLexicalProfile(txCtx, transaction, claimAccess,
			searchConfig.Generation, searchConfig.GenerationFence)
	}); err != nil {
		slog.Warn("worker search profile bootstrap failed", "component", "knowvault-worker", "error_code", search.CodeOf(err))
		return fail(stageSearchProfileBootstrap, err)
	}
	if embeddingClient != nil {
		searchApplier, err = search.NewApplierWithEmbedding(databaseStore, searchRepository, codec, searchClient, embeddingClient)
	} else {
		searchApplier, err = search.NewApplier(databaseStore, searchRepository, codec, searchClient)
	}
	if err != nil {
		return fail(stageSearchApplier, err)
	}

	profileID, profileHash := search.LexicalProfileID, ""
	if embeddingClient != nil {
		profile := embeddingClient.Profile()
		profileID, profileHash = profile.ID, profile.ProfileHash
	}
	runner := &jobRunner{
		config:           config,
		queue:            queue,
		handler:          handler,
		discoveryHandler: discoveryHandler,
		rotationHandler:  rotationHandler,
		searchApplier:    searchApplier,
		claimAccess:      claimAccess,
		sourceScheduler:  sourceScheduler,
		store:            databaseStore,
		searchRepository: searchRepository,
		profileID:        profileID,
		profileHash:      profileHash,
		generation:       searchConfig.Generation,
		generationFence:  searchConfig.GenerationFence,
	}
	return &Runtime{state: &runtimeState{
		phase: runtimeReady, runner: runner, cleanup: acquired.release(), done: make(chan struct{}),
	}}, nil
}

func validConfig(config Config) bool {
	return validOpaqueID(string(config.OrganizationID())) && validOpaqueID(string(config.ProviderID())) &&
		validOpaqueID(config.WorkerID()) && config.LeaseSeconds() >= minimumLeaseSeconds &&
		config.LeaseSeconds() <= maximumLeaseSeconds && config.PollSeconds() >= minimumPollSeconds &&
		config.PollSeconds() <= maximumPollSeconds && config.PollSeconds() < config.LeaseSeconds()
}

func newArtifactCodec(provider *secretmount.Provider, config Config) (*artifactcrypto.MountedProvider, *artifactcrypto.Codec, error) {
	key, err := provider.ArtifactWrapKey()
	if err != nil {
		return nil, nil, err
	}
	defer key.Clear()
	reference, version := key.Reference(), key.Version()
	material := key.Bytes()
	defer clear(material)
	// Optional previous pair of an in-flight KEK rotation (ADR-0070 §3): reads
	// under the previous key stay available until the re-wrap window closes,
	// writes seal under the active pair only.
	previousReference, previousVersion, previousMaterial := "", int64(0), []byte(nil)
	if previous, found, previousErr := provider.ArtifactWrapKeyPrevious(); previousErr != nil {
		return nil, nil, previousErr
	} else if found {
		defer previous.Clear()
		previousReference, previousVersion = previous.Reference(), int64(previous.Version())
		previousMaterial = previous.Bytes()
		defer clear(previousMaterial)
	}
	artifactProvider, err := artifactcrypto.NewRotatingMountedProvider(string(config.OrganizationID()), reference, int64(version), material,
		previousReference, previousVersion, previousMaterial)
	if err != nil {
		return nil, nil, err
	}
	codec, err := artifactcrypto.NewCodec(artifactProvider)
	if err != nil {
		_ = artifactProvider.Close()
		return nil, nil, err
	}
	return artifactProvider, codec, nil
}

func newSourceDigester(provider *secretmount.Provider) (ingestion.Digester, func(), error) {
	key, err := provider.SourceDigestKey()
	if err != nil {
		return ingestion.Digester{}, nil, err
	}
	defer key.Clear()
	material := key.Bytes()
	if len(material) != 32 {
		clear(material)
		return ingestion.Digester{}, nil, workerError(CodeStartupFailed)
	}
	return ingestion.Digester{Key: material, KeyVersion: int(key.Version())}, func() { clear(material) }, nil
}

type jobRunner struct {
	config           Config
	queue            *jobs.Queue
	handler          *ingestion.Handler
	discoveryHandler *sourcediscovery.Handler
	rotationHandler  *rotation.Handler
	searchApplier    *search.Applier
	claimAccess      database.AccessContext
	sourceScheduler  *registration.Service
	// Search profile revision (EMB-1). The identity below is the mounted
	// capability this worker indexes under; the durable revision sequence in
	// public.organization_search_profile decides which of them a tenant reads.
	store            *database.Store
	searchRepository *search.Repository
	profileID        string
	profileHash      string
	// reindexCursor is where the next re-index slice resumes. It is in-memory
	// progress only: losing it re-reads already-rebuilt chunks, which is safe
	// because every write is an idempotent PUT keyed by the chunk id.
	reindexCursor   string
	generation      int64
	generationFence int64
}

func (runner *jobRunner) Execute(ctx context.Context) error {
	if ctx == nil || runner == nil || runner.queue == nil || runner.handler == nil {
		return workerError(CodeRuntimeState)
	}
	if err := runner.poll(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Duration(runner.config.PollSeconds()) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := runner.poll(ctx); err != nil {
				return err
			}
		}
	}
}

func (runner *jobRunner) poll(ctx context.Context) error {
	if err := runner.applySearch(ctx); err != nil {
		return err
	}
	runner.autoSyncSources(ctx)
	runner.applySearchProfileRevision(ctx)
	if _, err := runner.queue.Reclaim(ctx, runner.claimAccess, reclaimLimit); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return workerError(CodeJobLoopFailed)
	}
	claimed, found, err := runner.queue.Claim(ctx, runner.claimAccess, runner.config.WorkerID(), runner.config.LeaseSeconds())
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return workerError(CodeJobLoopFailed)
	}
	if !found {
		return nil
	}
	jobAccess := runner.claimAccess
	jobAccess.RequestID = claimed.ID
	switch claimed.Type {
	case jobs.TypeSourceScopeSync:
		if err := runner.handler.Handle(ctx, jobAccess, claimed); err != nil && ctx.Err() == nil {
			slog.Warn("worker job failed", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", ingestion.CodeOf(err), "error_class", ingestion.DiagnosticClass(err))
		}
		return nil
	case jobs.TypePostgreSQLQuerySync:
		if err := runner.handler.HandlePostgreSQLQuery(ctx, jobAccess, claimed); err != nil && ctx.Err() == nil {
			slog.Warn("worker PostgreSQL query job failed", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", ingestion.CodeOf(err), "error_class", ingestion.DiagnosticClass(err))
		}
		return nil
	case sourcediscovery.JobType:
		if err := runner.discoveryHandler.Handle(ctx, jobAccess, claimed); err != nil && ctx.Err() == nil {
			slog.Warn("worker source discovery job failed", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", sourcediscovery.CodeOf(err))
		}
		return nil
	case jobs.TypeKEKRewrap:
		if err := runner.rotationHandler.HandleKEKRewrap(ctx, jobAccess, claimed); err != nil && ctx.Err() == nil {
			slog.Warn("worker rotation job failed", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", rotation.CodeOf(err))
		}
		return nil
	case jobs.TypeDigestRecompute:
		if err := runner.rotationHandler.HandleDigestRecompute(ctx, jobAccess, claimed); err != nil && ctx.Err() == nil {
			slog.Warn("worker rotation job failed", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", rotation.CodeOf(err))
		}
		return nil
	}
	if err := runner.queue.Fail(ctx, jobAccess, claimed.ID, runner.config.WorkerID(), claimed.LeaseEpoch,
		jobs.ErrorCode(CodeJobUnsupported), unsupportedRetry); err != nil && ctx.Err() == nil {
		slog.Warn("worker job rejected", "component", "knowvault-worker", "job_type", string(claimed.Type), "error_code", jobs.CodeOf(err))
		if jobs.CodeOf(err) != jobs.CodeLeaseLost {
			return workerError(CodeJobLoopFailed)
		}
	}
	return nil
}

// autoSyncSources enqueues due scheduled source sync jobs for this worker's
// organization. A tick failure is logged and never fails the job loop itself:
// the next poll tick retries the same due lookup.
func (runner *jobRunner) autoSyncSources(ctx context.Context) {
	if runner == nil || runner.sourceScheduler == nil {
		return
	}
	if _, err := runner.sourceScheduler.AutoSync(ctx, runner.claimAccess); err != nil && ctx.Err() == nil {
		slog.Warn("worker source autosync failed", "component", "knowvault-worker", "error_code", registration.CodeOf(err))
	}
}

// applySearchProfileRevision carries out an operator's profile-revision
// command (EMB-1, migration 000072). The command itself only appends a STAGING
// revision through app.stage_search_profile_revision; the whole re-index and
// the cutover are this worker's work, on the same poll tick that drains the
// search outbox and enqueues due scheduled syncs (V1-A's AutoSync precedent).
//
// The pass is idempotent and resumable: it re-embeds every currently indexable
// chunk into a separate physical index with the staged vector space, then flips the
// revision. A crash, a restart or a repeated command converges on the same
// durable state. Until the flip the tenant keeps answering from the revision
// its corpus was actually indexed under, and a tick failure is logged rather
// than retiring the job loop: the next tick retries the same staged revision.
func (runner *jobRunner) applySearchProfileRevision(ctx context.Context) {
	if runner == nil || runner.store == nil || runner.searchRepository == nil || runner.searchApplier == nil {
		return
	}
	if runner.profileHash == "" {
		// This worker mounts no embedding channel, so it owns no vector space
		// and must never activate one. A revision staged for another indexer is
		// left exactly as it is.
		return
	}
	var staged search.Revision
	var found bool
	if err := runner.store.Read(ctx, runner.claimAccess, func(txCtx context.Context, transaction database.Transaction) error {
		var readErr error
		staged, found, readErr = runner.searchRepository.ReadRevision(txCtx, transaction, runner.claimAccess, search.RevisionStaging)
		return readErr
	}); err != nil {
		if ctx.Err() == nil {
			slog.Warn("search profile revision lookup failed", "component", "knowvault-worker", "error_code", search.CodeOf(err))
		}
		return
	}
	if !found {
		return
	}
	// Fail closed on drift: only the indexer that actually mounts the staged
	// vector space may rebuild the corpus under it or cut over to it.
	if staged.ProfileID != runner.profileID || staged.ProfileHash != runner.profileHash ||
		staged.Generation != runner.generation || staged.GenerationFence != runner.generationFence {
		slog.Warn("search profile revision does not match the mounted profile", "component", "knowvault-worker",
			"error_code", string(CodeSearchProfileRevisionDrift))
		return
	}
	cursor := runner.reindexCursor
	if err := runner.searchApplier.EnsureRevisionIndex(ctx, staged.ActivationRevision); err != nil {
		slog.Warn("search revision index preparation failed", "component", "knowvault-worker", "error_code", search.CodeOf(err))
		return
	}
	for {
		_, next, err := runner.searchApplier.Reindex(ctx, runner.claimAccess, cursor, searchReindexSlice)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("search profile reindex failed", "component", "knowvault-worker",
					"error_code", search.CodeOf(err), "error_class", search.DiagnosticClass(err))
			}
			return
		}
		if next == "" {
			break
		}
		cursor = next
		runner.reindexCursor = cursor
		if ctx.Err() != nil {
			return
		}
	}
	runner.reindexCursor = ""
	if err := runner.searchApplier.RefreshRevision(ctx, staged.ActivationRevision); err != nil {
		slog.Warn("search revision refresh failed", "component", "knowvault-worker", "error_code", search.CodeOf(err))
		return
	}
	if err := runner.store.Write(ctx, runner.claimAccess, func(txCtx context.Context, transaction database.Transaction) error {
		return runner.searchRepository.ActivateRevision(txCtx, transaction, runner.claimAccess,
			staged.ActivationRevision, time.Now().UTC())
	}); err != nil {
		if ctx.Err() == nil {
			slog.Warn("search profile activation failed", "component", "knowvault-worker", "error_code", search.CodeOf(err))
		}
		return
	}
	slog.Info("search profile revision activated", "component", "knowvault-worker",
		"activation_revision", staged.ActivationRevision)
}
func (runner *jobRunner) applySearch(ctx context.Context) error {
	if runner == nil || runner.searchApplier == nil {
		return nil
	}
	if _, err := runner.searchApplier.Drain(ctx, runner.claimAccess, searchDrainLimit); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		// An out-of-order event, stale generation, or dependency outage is
		// never skipped. Retiring the loop lets the supervisor restart with
		// the same durable event instead of processing a partially indexed
		// corpus.
		slog.Warn("search projection job failed", "component", "knowvault-worker",
			"error_code", search.CodeOf(err), "error_class", search.DiagnosticClass(err))
		return workerError(CodeJobLoopFailed)
	}
	return nil
}

// Run executes the one-shot worker loop and retires every acquired capability
// after the loop returns. A context cancellation is a clean stop.
func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || runtime.state == nil || ctx == nil || ctx.Err() != nil {
		return workerError(CodeRuntimeState)
	}
	state := runtime.state
	state.mu.Lock()
	if state.phase != runtimeReady || state.runner == nil {
		state.mu.Unlock()
		return workerError(CodeRuntimeState)
	}
	runContext, cancel := context.WithCancel(ctx)
	state.phase = runtimeRunning
	state.runCancel = cancel
	runner := state.runner
	state.mu.Unlock()

	runErr := runner.Execute(runContext)
	cancel()
	state.mu.Lock()
	if state.phase == runtimeRunning {
		state.phase = runtimeClosing
	}
	cleanup := state.cleanup
	state.cleanup = nil
	state.mu.Unlock()

	cleanupErr := closeReverse(cleanup)
	state.mu.Lock()
	state.closeResult = cleanupErr
	state.phase = runtimeClosed
	state.runCancel = nil
	close(state.done)
	state.mu.Unlock()

	if runErr != nil {
		return workerError(CodeRuntimeFailed)
	}
	return cleanupErr
}

// Close cancels a running loop, waits for its cleanup, and is safe to call on
// a copied Runtime handle.
func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.state == nil {
		return workerError(CodeRuntimeState)
	}
	state := runtime.state
	state.mu.Lock()
	switch state.phase {
	case runtimeReady:
		state.phase = runtimeClosing
		cleanup := state.cleanup
		state.cleanup = nil
		state.mu.Unlock()
		cleanupErr := closeReverse(cleanup)
		state.mu.Lock()
		state.closeResult = cleanupErr
		state.phase = runtimeClosed
		close(state.done)
		state.mu.Unlock()
		return cleanupErr
	case runtimeRunning:
		state.phase = runtimeClosing
		cancel := state.runCancel
		done := state.done
		state.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		<-done
		return runtime.closeResult()
	case runtimeClosing:
		done := state.done
		state.mu.Unlock()
		<-done
		return runtime.closeResult()
	case runtimeClosed:
		result := state.closeResult
		state.mu.Unlock()
		return result
	default:
		state.mu.Unlock()
		return workerError(CodeRuntimeState)
	}
}

func (runtime *Runtime) closeResult() error {
	state := runtime.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.closeResult
}

type cleanupStack struct{ steps []cleanupFunc }

func (stack *cleanupStack) push(step cleanupFunc) {
	if step != nil {
		stack.steps = append(stack.steps, step)
	}
}

func (stack *cleanupStack) release() []cleanupFunc {
	if stack == nil {
		return nil
	}
	steps := stack.steps
	stack.steps = nil
	return steps
}

func (stack *cleanupStack) rollback() error { return closeReverse(stack.release()) }

func closeReverse(steps []cleanupFunc) error {
	failed := false
	for index := len(steps) - 1; index >= 0; index-- {
		if steps[index] != nil && steps[index]() != nil {
			failed = true
		}
	}
	if failed {
		return workerError(CodeCleanupFailed)
	}
	return nil
}
