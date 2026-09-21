package composition

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/governedask"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/analyticcatalog"
	"knowvault.local/verified-workspace/internal/platform/apphttp"
	"knowvault.local/verified-workspace/internal/platform/browserauth"
	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/httpserver"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/oidctransport"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/systemapi"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
	"knowvault.local/verified-workspace/internal/platform/webui"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/reranking"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/searchprofile"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	CodeRuntimeStartupFailed ErrorCode = "COMPOSITION_RUNTIME_STARTUP_FAILED"
	CodeRuntimeStateInvalid  ErrorCode = "COMPOSITION_RUNTIME_STATE_INVALID"
	CodeRuntimeRunFailed     ErrorCode = "COMPOSITION_RUNTIME_RUN_FAILED"
	CodeRuntimeCleanupFailed ErrorCode = "COMPOSITION_RUNTIME_CLEANUP_FAILED"
)

type runtimePhase uint8

const (
	runtimeReady runtimePhase = iota + 1
	runtimeRunning
	runtimeClosing
	runtimeClosed
)

type runtimeRunner interface {
	ListenAndServe(context.Context) error
}

type cleanupFunc func() error

// Runtime is an opaque, copy-safe handle. Copies share one lifecycle state,
// so a listener and the retained capabilities can be consumed exactly once.
type Runtime struct{ state *runtimeState }

type runtimeState struct {
	mu          sync.Mutex
	phase       runtimePhase
	runner      runtimeRunner
	cleanup     []cleanupFunc
	runCancel   context.CancelFunc
	done        chan struct{}
	closeResult error
}

func (Runtime) String() string   { return "composition.Runtime{[REDACTED]}" }
func (Runtime) GoString() string { return "composition.Runtime{[REDACTED]}" }
func (*runtimeState) String() string {
	return "composition.runtimeState{[REDACTED]}"
}
func (*runtimeState) GoString() string {
	return "composition.runtimeState{[REDACTED]}"
}

// NewProduction acquires and validates every production capability before a
// listener can exist. It performs no discovery and never reads configuration
// from the environment; Config is the already-validated startup snapshot.
func NewProduction(ctx context.Context, config Config, info buildinfo.Info) (*Runtime, error) {
	if ctx == nil || ctx.Err() != nil || !validPreflightConfig(config) {
		return nil, runtimeError(CodeConfigInvalid)
	}

	var acquired cleanupStack
	fail := func(stage StartupStage) (*Runtime, error) {
		_ = acquired.rollback()
		return nil, runtimeStartupError(stage)
	}

	bundle, err := trustbundle.LoadMounted()
	if err != nil {
		return fail(StartupStageTrustBundle)
	}
	secrets, err := secretmount.LoadMountedForTenant(config.OrganizationID(), config.ProviderID())
	if err != nil {
		return fail(StartupStageSecrets)
	}
	acquired.push(secrets.Close)

	databaseURL, err := secrets.DatabaseURL()
	if err != nil {
		return fail(StartupStageDatabaseURL)
	}
	databaseRoots, err := bundle.DatabaseRoots()
	if err != nil {
		databaseURL = ""
		return fail(StartupStageDatabaseRoots)
	}
	databaseConfig := database.DefaultConfig()
	databaseConfig.URL = databaseURL
	databaseStore, err := database.OpenProduction(ctx, databaseConfig, databaseRoots)
	databaseURL = ""
	databaseConfig.URL = ""
	if err != nil {
		return fail(StartupStageDatabase)
	}
	acquired.push(func() error { databaseStore.Close(); return nil })

	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		return fail(StartupStageAuditStore)
	}
	identityStore, err := identityrepository.New(databaseStore, auditStore)
	if err != nil {
		return fail(StartupStageIdentityStore)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		return fail(StartupStageWorkspaceStore)
	}
	queue, err := jobs.New(databaseStore)
	if err != nil {
		return fail(StartupStageJobQueue)
	}
	artifactProvider, sourceCodec, err := newAppArtifactCodec(secrets, config)
	if err != nil {
		return fail(StartupStageArtifactCodec)
	}
	acquired.push(func() error { artifactProvider.Close(); return nil })
	digestKey, digestKeyVersion, err := newSourceRegistrationDigestKey(secrets)
	if err != nil {
		return fail(StartupStageSourceDigestKey)
	}
	defer clear(digestKey)
	sourceRegistration, err := registration.New(databaseStore, auditStore, sourceCodec, queue, digestKey, digestKeyVersion)
	if err != nil {
		return fail(StartupStageSourceRegistration)
	}
	sourceDiscovery, err := sourcediscovery.NewReader(databaseStore, sourceCodec, digestKey, digestKeyVersion)
	if err != nil {
		return fail(StartupStageSourceRegistration)
	}
	if err := preflightOIDCProvider(ctx, config, identityStore, secrets); err != nil {
		return fail(StartupStageOIDCPreflight)
	}

	identityDigestor, identityReference, err := newIdentityDigestor(secrets)
	if err != nil {
		return fail(StartupStageIdentityDigestor)
	}
	acquired.push(func() error { identityDigestor.Close(); return nil })
	sessionDigestor, sessionReference, err := newSessionDigestor(secrets)
	if err != nil {
		return fail(StartupStageSessionDigestor)
	}
	acquired.push(func() error { sessionDigestor.Close(); return nil })

	security, err := tenantsecurity.NewContext(
		config.OrganizationID(), config.ProviderID(), config.PublicOrigin(),
		identityReference, identityDigestor, sessionReference, sessionDigestor,
	)
	if err != nil {
		return fail(StartupStageTenantSecurity)
	}
	tenantResolver, err := tenantsecurity.NewStaticResolver(security)
	if err != nil {
		return fail(StartupStageTenantResolver)
	}
	httpSecurityResolver, err := tenantsecurity.NewHTTPAuthResolver(tenantResolver)
	if err != nil {
		return fail(StartupStageHTTPAuthResolver)
	}

	codec, err := newTransportCodec(secrets, security)
	if err != nil {
		return fail(StartupStageTransportCodec)
	}
	acquired.push(codec.Close)
	browser, err := oidctransport.NewBrowserTransport(codec)
	if err != nil {
		return fail(StartupStageBrowserTransport)
	}
	oidcRoots, err := bundle.OIDCRoots()
	if err != nil {
		return fail(StartupStageOIDCRoots)
	}
	oidcHTTPClient, err := oidc.NewProductionHTTPClient(oidcRoots)
	if err != nil {
		return fail(StartupStageOIDCHTTPClient)
	}
	acquired.push(func() error { oidcHTTPClient.CloseIdleConnections(); return nil })

	// FIX-7 #3: the SAME cookie issuer both mints the cookie at login
	// (oidcweb.Dependencies.Sessions) and reissues its Max-Age on this
	// package's sliding renewal (httpauth.NewWithRenewer) -- one reviewed
	// cookie-writing profile, never two.
	sessionCookies := browserauth.NewCookieIssuer()
	authenticator, err := httpauth.NewWithRenewer(httpSecurityResolver, identityStore, sessionCookies)
	if err != nil {
		return fail(StartupStageHTTPAuth)
	}
	oidcHandler, err := oidcweb.New(oidcweb.Dependencies{
		TenantResolver: tenantResolver,
		Store:          identityStore,
		Secrets:        secrets,
		Browser:        browser,
		Sessions:       sessionCookies,
		Authenticator:  authenticator,
		HTTPClient:     oidcHTTPClient,
	})
	if err != nil {
		return fail(StartupStageOIDCHandler)
	}
	sources := sourceServiceFacade{registration: sourceRegistration, discovery: sourceDiscovery, workspaces: workspaceStore}
	viewer, err := evidence.NewViewer(databaseStore, sourceCodec)
	if err != nil {
		return fail(StartupStageEvidenceViewer)
	}
	// KV-A03: the workspace MCP boundary must serve knowvault_related, so it is
	// mounted with the production relation source rather than the bare viewer.
	// relationEvidence embeds the viewer (keeping Read/ReadObject/ListObjects/
	// SearchFragments on the one implementation) and adds the cross-source
	// relation read, so the relation tool is advertised and served instead of
	// failing closed as an unwired capability.
	relationViewer, err := newRelationEvidence(viewer, databaseStore, auditStore)
	if err != nil {
		return fail(StartupStageEvidenceViewer)
	}
	// Search is a required enterprise capability.  A missing mount is a startup
	// failure rather than an invitation to silently downgrade to database-only
	// retrieval: the production Question authority must expose the same
	// post-authorized hybrid boundary through HTTP, UI and MCP on every start.
	searchConfig, searchMountErr := search.LoadMountedForTenant(string(config.OrganizationID()))
	if searchMountErr != nil {
		return fail(StartupStageSearchMount)
	}
	// One mounted embedding channel, two independent capabilities (EMB-1).
	// The mount is the transport; it is NOT the switch for either consumer:
	//
	//   * vector retrieval is enabled per tenant by the ACTIVE profile revision
	//     (migration 000072). retrieval.Executor compares that revision's
	//     profile hash with the provider's before it admits a vector channel,
	//     so a deployment can mount embedding while a tenant still answers from
	//     the lexical revision it was indexed under, and a STAGING revision is
	//     never read from before its re-index pass is activated.
	//   * the GENERATIVE claim verifier (ADR-0088 addendum) uses the same
	//     channel as soon as it is mounted, with no dependency on any tenant's
	//     retrieval revision — the interim local hashing verifier stays the
	//     fallback only for deployments that mount no embedding at all.
	//
	// A missing administrator mount is an explicit, observable capability gap
	// rather than a downgrade; a present-but-invalid mount remains a startup
	// failure so drift cannot be mistaken for a safe partial deployment.
	embeddingConfig, embeddingMountErr := embedding.LoadMountedForTenant(string(config.OrganizationID()))
	var embeddingClient *embedding.Client
	if embeddingMountErr != nil {
		if embedding.CodeOf(embeddingMountErr) != embedding.CodeMountUnavailable {
			return fail(StartupStageEmbeddingMount)
		}
	} else {
		embeddingClient, err = embedding.New(embeddingConfig.Profile, embeddingConfig.TrustRoots, embeddingConfig.ClientCertificate, nil)
		if err != nil {
			return fail(StartupStageEmbeddingClient)
		}
		acquired.push(embeddingClient.Close)
		// Bind the search index to the exact immutable embedding profile before
		// either retrieval or indexing can issue a vector request.
		searchConfig.VectorProfileHash = embeddingConfig.Profile.ProfileHash
		searchConfig.VectorDimension = embeddingConfig.Profile.Dimension
	}
	searchClient, clientErr := search.New(searchConfig)
	if clientErr != nil {
		return fail(StartupStageSearchClient)
	}
	acquired.push(searchClient.Close)
	// Reranking changes candidate order after live authorization. Its mounted
	// transport and identity are independent of the corpus embedding revision.
	rerankingConfig, rerankingMountErr := reranking.LoadMountedForTenant(string(config.OrganizationID()))
	var rerankingClient *reranking.Client
	if rerankingMountErr != nil {
		if reranking.CodeOf(rerankingMountErr) != reranking.CodeMountUnavailable {
			return fail(StartupStageRerankingMount)
		}
	} else {
		rerankingClient, err = reranking.New(rerankingConfig.Profile, rerankingConfig.TrustRoots, rerankingConfig.ClientCertificate, nil)
		if err != nil {
			return fail(StartupStageRerankingClient)
		}
		acquired.push(rerankingClient.Close)
	}
	var vectorProvider retrieval.VectorProvider
	if embeddingClient != nil {
		vectorProvider, err = retrieval.NewOpenSearchVectorProvider(embeddingClient, searchClient)
		if err != nil {
			return fail(StartupStageRetrievalExecutor)
		}
	}
	var rerankProvider retrieval.RerankProvider
	if rerankingClient != nil {
		rerankProvider = rerankingClient
	}
	retrievalExecutor, err := retrieval.NewExecutorWithProviders(searchClient, viewer, databaseStore, knowledgegraph.NewRepository(), vectorProvider, rerankProvider)
	if err != nil {
		return fail(StartupStageRetrievalExecutor)
	}
	questions, err := question.NewWithRetrieval(databaseStore, auditStore, sourceCodec, viewer, retrievalExecutor)
	if err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	// R1.1 (micro-card C): the trusted analytic DatasetProfile catalog is
	// wired only behind its own explicit administrator mount
	// (analyticcatalog.LoadMounted), exactly like the generation mount
	// below. A wholly absent mount keeps the document-only capability; a
	// present-but-invalid mount is a startup failure so drift can never look
	// like a safe partial deployment.
	datasetProfileCatalog, datasetProfileMountErr := analyticcatalog.LoadMounted()
	if datasetProfileMountErr != nil {
		if analyticcatalog.CodeOf(datasetProfileMountErr) != analyticcatalog.CodeMountUnavailable {
			return fail(StartupStageDatasetProfileMount)
		}
	} else if err := questions.EnableDatasetProfileCatalog(datasetProfileCatalog); err != nil {
		return fail(StartupStageDatasetProfileMount)
	}
	// GEN-2 (ADR-0088): the interim GENERATIVE adapter/verifier are wired only
	// behind their own explicit administrator mount, exactly like the
	// embedding mount above. A wholly absent mount keeps GENERATIVE an
	// explicit, addressable-but-unsupported capability (question.Service
	// returns CodeUnsupportedMode); a present-but-invalid mount is a startup
	// failure so drift can never look like a safe partial deployment. The
	// interim verifier prefers the real embedding channel when one is mounted
	// (e.g. a future deployment with embedding qualified) and otherwise falls
	// back to the network-free local hashing verifier (local_embed.go) rather
	// than making GENERATIVE unavailable on every deployment that has not
	// separately qualified an embedding profile (the acc stand today has
	// none) — both are the same disclosed interim check, never the ADR-0080
	// §2.3 independently-qualified verifier.
	generationProfiles, labMountErr := modelgateway.LoadMountedProfiles()
	var generationAdapter *modelgateway.LabAdapter
	if labMountErr != nil {
		if modelgateway.CodeOf(labMountErr) != modelgateway.CodeLabMountUnavailable {
			return fail(StartupStageGenerationMount)
		}
	} else {
		generationAdapter = generationProfiles.Default()
		acquired.push(generationProfiles.Close)
		var embedFunc modelgateway.EmbedFunc
		verifierThreshold := modelgateway.LocalHashVerifierThreshold
		if embeddingClient != nil {
			organizationID := string(config.OrganizationID())
			profileHash := embeddingConfig.Profile.ProfileHash
			maximumInputBytes := embeddingConfig.Profile.MaxInputBytes
			embedFunc = func(embedCtx context.Context, workspaceID, operationID, text string) ([]float32, error) {
				// A claim is verified against evidence taken verbatim from a real
				// corpus, so it carries whatever control characters that corpus
				// has. Project it exactly as the indexer projects a passage,
				// otherwise the verifier fails closed on the very documents the
				// answer is grounded in.
				projected, ok := search.EmbeddableText(text, maximumInputBytes)
				if !ok {
					return nil, errors.New("evidence has no embeddable projection")
				}
				binding := embedding.Binding{OrganizationID: organizationID, WorkspaceID: workspaceID, OperationID: operationID, ProfileHash: profileHash}
				result, embedErr := embeddingClient.Embed(embedCtx, binding, projected)
				if embedErr != nil {
					return nil, embedErr
				}
				return result.Vector, nil
			}
			verifierThreshold = modelgateway.DefaultVerifierThreshold
		} else {
			embedFunc = modelgateway.LocalHashEmbedFunc()
		}
		generationVerifier, verifierErr := modelgateway.NewVerifier(embedFunc, verifierThreshold)
		if verifierErr != nil {
			return fail(StartupStageGenerationMount)
		}
		questions.EnableGeneration(generationAdapter, generationVerifier)
		questions.EnableGenerationProfiles(generationProfiles)
	}
	// ADR-0089: the governed-query ask service is wired only behind its own
	// explicit administrator mount (governedquery.LoadMountedConfig), exactly
	// like the generation mount above, and only when a Model Gateway adapter
	// is also present -- the ADR-0089 ad hoc path composes SQL through the
	// same Model Gateway the GENERATIVE mode uses. A wholly absent
	// governedquery mount keeps every governed-query-connections route an
	// explicit SERVICE_UNAVAILABLE; a present-but-invalid mount is a startup
	// failure so drift cannot look like a safe partial deployment.
	governedAskService, governedAskErr := governedask.New(databaseStore, auditStore)
	if governedAskErr != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	governedQueryConfig, governedQueryMountErr := governedquery.LoadMountedConfig()
	if governedQueryMountErr != nil {
		if governedquery.CodeOf(governedQueryMountErr) != governedquery.CodeMountUnavailable {
			return fail(StartupStageGovernedQueryMount)
		}
	} else {
		governedAskService.EnableGovernedQueryConfig(governedQueryConfig)
		if generationAdapter != nil {
			governedAskService.EnableGovernedQuery(governedQueryConfig, generationAdapter)
		}
	}
	conversations, err := conversation.New(databaseStore, auditStore)
	if err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	// V1-C: agent access codes (ADR-0079 §3). workspaceStore already
	// implements serviceprincipal.WorkspaceAuthority (Get/AddMember/
	// RemoveMember), so a SERVICE principal's workspace grant/revoke reuses
	// the exact same command path a human OWNER's REST "add/remove member"
	// action does.
	accessCodes, err := serviceprincipal.New(databaseStore, auditStore, workspaceStore)
	if err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	workspaceHandler, err := workspaceapi.NewWithServiceAccess(authenticator, workspaceStore, sources, relationViewer, questions, conversations, accessCodes, string(config.OrganizationID()))
	if err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	// R3a-1: every address the workspace knowledge tools emit (MCP and the
	// REST parity routes) must carry the organization-scoped ADR-0077 span
	// digest, the same keyed HMAC family evidence_fragment.text_hash already
	// uses, never the package's non-secret anonymous digest. NewSpanDigestKey
	// copies the material, so the deferred clear of digestKey above cannot
	// strip the key the handler holds.
	workspaceHandler.EnableSpanDigest(address.NewSpanDigestKey(digestKey, digestKeyVersion))
	if err := workspaceHandler.EnableEvidencePageOrigin(config.PublicOrigin()); err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	questions.EnableToolLoop(workspaceHandler)
	workspaceHandler.EnableGovernedQuery(governedAskService)
	// EMB-1: the operator command that moves this tenant onto the mounted
	// embedding profile. It is composed on every start — a deployment with no
	// embedding mount still answers the status route, reporting an unavailable
	// vector capability instead of a missing endpoint — while the command
	// itself fails closed unless a real profile is mounted.
	searchProfileRepository, err := search.NewRepository()
	if err != nil {
		return fail(StartupStageSearchClient)
	}
	mountedSearchProfile := searchprofile.MountedProfile{}
	if embeddingClient != nil {
		profile := embeddingClient.Profile()
		mountedSearchProfile = searchprofile.MountedProfile{
			ProfileID: profile.ID, ProfileHash: profile.ProfileHash, Dimension: profile.Dimension,
			Generation: searchConfig.Generation, GenerationFence: searchConfig.GenerationFence,
		}
	}
	searchProfiles, err := searchprofile.New(databaseStore, auditStore, workspaceStore,
		searchProfileRepository, mountedSearchProfile)
	if err != nil {
		return fail(StartupStageWorkspaceHandler)
	}
	workspaceHandler.EnableSearchProfile(searchProfiles)
	// S3: knowvault_search becomes hybrid. The same retrieval executor the
	// question path already uses serves the tool, so the two never drift on
	// authorization, fusion or post-authorization, and the owner-only ablation
	// channel is the profile authority composed just above. A deployment with
	// no embedding mount composes exactly the same way and simply reports a
	// lexical, degraded profile: the tool stays available and stops claiming a
	// vector channel it does not have.
	workspaceHandler.EnableHybridSearch(retrievalExecutor, searchProfiles)
	// R2 Outcome 1: mount the versioned MetricDefinition catalog and the
	// owner-only authoring capability. metricdef.Store re-checks the caller's
	// workspace access through the same workspaceStore snapshot authority every
	// other protected read/write uses, and its approval commits the R1 audit
	// event inside the store's own write transaction. Both capabilities are
	// enabled only when the database, the workspace snapshot authority and the
	// audit recorder are all present; otherwise the definition routes keep the
	// existing fail-closed SERVICE_UNAVAILABLE instead of serving unaudited or
	// unchecked data.
	if databaseStore != nil && workspaceStore != nil && auditStore != nil {
		definitions, definitionsErr := metricdef.New(databaseStore, workspaceStore,
			metricDefinitionApprovalAudit{journal: auditStore})
		if definitionsErr != nil {
			return fail(StartupStageWorkspaceHandler)
		}
		workspaceHandler.EnableMetricDefinitions(definitions)
		workspaceHandler.EnableMetricDefinitionAuthoring(definitions)
		// R2 Outcome 2: mount the QueryIntent validation gate against the same
		// access-re-checked catalog, wired to the production proposer and
		// sealed-intent executor. Both are built from in-tree services only:
		// the proposer uses the workspace's own definition catalog and the
		// authority's deterministic planner/calendar, and the executor drives
		// the authority's existing persisted-run and structured-snapshot
		// reduction machinery. No model provider, DB, runtime or dependency is
		// added. A question over a workspace that holds an APPROVED definition
		// therefore yields either a server-validated intent that is executed
		// or a typed clarification -- never free-text planning; a workspace
		// with no APPROVED definition keeps today's path verbatim
		// (validateStructuredIntent returns hasIntent=false, nil).
		questions.EnableQueryIntents(definitions,
			question.NewPlannerIntentProposer(questions, definitions),
			question.NewServiceIntentExecutor(questions))
	}
	systemHandler := systemapi.New(info, systemapi.RuntimeCapabilities(embeddingClient != nil))

	// The dispatcher owns API routing. The production UI receives a fail-closed
	// API placeholder and is then installed only as the dispatcher's UI branch.
	ui, err := webui.NewProduction(http.NotFoundHandler())
	if err != nil {
		return fail(StartupStageWebUI)
	}
	acquired.push(ui.Close)
	dispatcher, err := apphttp.New(oidcHandler, systemHandler, workspaceHandler, ui)
	if err != nil {
		return fail(StartupStageHTTPDispatcher)
	}
	// D7-8: the mandatory security header set wraps the whole application
	// boundary, including the dispatcher's own 404 responses.
	handler := apphttp.WithSecurityHeaders(dispatcher)
	serverConfig := httpserver.DefaultConfig()
	serverConfig.Address = config.HTTPAddress()
	// GEN-2 (ADR-0088): the default 60s http.Server.WriteTimeout covers the
	// whole request-to-response-write window, not just writing bytes. A real
	// GENERATIVE attempt against the interim adapter's real endpoint can
	// legitimately run close to the adapter's own bounded ceiling
	// (internal/modelgateway/lab_adapter.go labMaxTimeout), well past 60s for
	// a reasoning model with real multi-fragment Evidence; the default was
	// silently killing the connection mid-handler ("upstream prematurely
	// closed connection" at the reverse proxy) before this request ever
	// reached its own deterministic terminal state. Every other route
	// finishes far under a minute, so this raises the shared ceiling rather
	// than adding a second per-route HTTP server.
	serverConfig.WriteTimeout = 280 * time.Second
	server, err := httpserver.New(serverConfig, handler)
	if err != nil {
		return fail(StartupStageHTTPServer)
	}
	runner := httpserver.Runner{Server: server, ShutdownTimeout: serverConfig.ShutdownTimeout}
	return newRuntime(runner, acquired.release()), nil
}

func newIdentityDigestor(provider *secretmount.Provider) (*oidc.HMACDigestor, string, error) {
	key, err := provider.IdentityKey()
	if err != nil {
		return nil, "", err
	}
	defer key.Clear()
	reference, version := key.Reference(), key.Version()
	material := key.Bytes()
	defer clear(material)
	digestor, err := oidc.NewHMACDigestor(version, material)
	if err != nil {
		return nil, "", err
	}
	return digestor, reference, nil
}

func newSessionDigestor(provider *secretmount.Provider) (*oidc.HMACDigestor, string, error) {
	key, err := provider.SessionKey()
	if err != nil {
		return nil, "", err
	}
	defer key.Clear()
	reference, version := key.Reference(), key.Version()
	material := key.Bytes()
	defer clear(material)
	digestor, err := oidc.NewHMACDigestor(version, material)
	if err != nil {
		return nil, "", err
	}
	return digestor, reference, nil
}

func newTransportCodec(provider *secretmount.Provider, security tenantsecurity.Context) (*oidctransport.Codec, error) {
	key, err := provider.OIDCTransportKey()
	if err != nil {
		return nil, err
	}
	defer key.Clear()
	reference, keyID := key.Reference(), key.KeyID()
	material := key.Bytes()
	defer clear(material)
	return oidctransport.NewCodec(security, reference, keyID, material)
}

func newRuntime(runner runtimeRunner, cleanup []cleanupFunc) *Runtime {
	return &Runtime{state: &runtimeState{
		phase: runtimeReady, runner: runner, cleanup: append([]cleanupFunc(nil), cleanup...), done: make(chan struct{}),
	}}
}

// Run is the sole production path to Runner.ListenAndServe. It is one-shot;
// normal listener termination and listener failures both retire all acquired
// capabilities before Run returns.
func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || runtime.state == nil || ctx == nil || ctx.Err() != nil {
		return runtimeError(CodeRuntimeStateInvalid)
	}
	state := runtime.state
	state.mu.Lock()
	if state.phase != runtimeReady || state.runner == nil {
		state.mu.Unlock()
		return runtimeError(CodeRuntimeStateInvalid)
	}
	runContext, cancel := context.WithCancel(ctx)
	state.phase = runtimeRunning
	state.runCancel = cancel
	runner := state.runner
	state.mu.Unlock()

	runErr := runner.ListenAndServe(runContext)
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
		return runtimeError(CodeRuntimeRunFailed)
	}
	return cleanupErr
}

// Close cancels a running server, waits for its bounded shutdown and then
// returns the shared cleanup result. Before Run it performs the same cleanup
// without ever entering the listener path.
func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.state == nil {
		return runtimeError(CodeRuntimeStateInvalid)
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
		return runtimeError(CodeRuntimeStateInvalid)
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

func (stack *cleanupStack) rollback() error {
	return closeReverse(stack.release())
}

func closeReverse(steps []cleanupFunc) error {
	failed := false
	for index := len(steps) - 1; index >= 0; index-- {
		if steps[index] != nil && steps[index]() != nil {
			failed = true
		}
	}
	if failed {
		return runtimeError(CodeRuntimeCleanupFailed)
	}
	return nil
}

func runtimeError(code ErrorCode) error { return &Error{code: code} }
