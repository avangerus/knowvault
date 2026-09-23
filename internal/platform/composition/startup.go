package composition

import "errors"

// StartupStage is a closed, non-secret description of the production
// capability that could not be assembled.  It is deliberately separate from
// ErrorCode: callers may only observe a stage for
// COMPOSITION_RUNTIME_STARTUP_FAILED, and only when the value is in this
// allowlist.
type StartupStage string

const (
	StartupStageUnknown            StartupStage = "UNKNOWN"
	StartupStageTrustBundle        StartupStage = "TRUST_BUNDLE"
	StartupStageSecrets            StartupStage = "SECRETS"
	StartupStageDatabaseURL        StartupStage = "DATABASE_URL"
	StartupStageDatabaseRoots      StartupStage = "DATABASE_ROOTS"
	StartupStageDatabase           StartupStage = "DATABASE"
	StartupStageAuditStore         StartupStage = "AUDIT_STORE"
	StartupStageIdentityStore      StartupStage = "IDENTITY_STORE"
	StartupStageWorkspaceStore     StartupStage = "WORKSPACE_STORE"
	StartupStageJobQueue           StartupStage = "JOB_QUEUE"
	StartupStageArtifactCodec      StartupStage = "ARTIFACT_CODEC"
	StartupStageSourceDigestKey    StartupStage = "SOURCE_DIGEST_KEY"
	StartupStageSourceRegistration StartupStage = "SOURCE_REGISTRATION"
	StartupStageOIDCPreflight      StartupStage = "OIDC_PREFLIGHT"
	StartupStageIdentityDigestor   StartupStage = "IDENTITY_DIGESTOR"
	StartupStageSessionDigestor    StartupStage = "SESSION_DIGESTOR"
	StartupStageTenantSecurity     StartupStage = "TENANT_SECURITY"
	StartupStageTenantResolver     StartupStage = "TENANT_RESOLVER"
	StartupStageHTTPAuthResolver   StartupStage = "HTTP_AUTH_RESOLVER"
	StartupStageTransportCodec     StartupStage = "TRANSPORT_CODEC"
	StartupStageBrowserTransport   StartupStage = "BROWSER_TRANSPORT"
	StartupStageOIDCRoots          StartupStage = "OIDC_ROOTS"
	StartupStageOIDCHTTPClient     StartupStage = "OIDC_HTTP_CLIENT"
	StartupStageHTTPAuth           StartupStage = "HTTP_AUTH"
	StartupStageOIDCHandler        StartupStage = "OIDC_HANDLER"
	StartupStageEvidenceViewer     StartupStage = "EVIDENCE_VIEWER"
	StartupStageSearchMount        StartupStage = "SEARCH_MOUNT"
	StartupStageSearchClient       StartupStage = "SEARCH_CLIENT"
	StartupStageEmbeddingMount     StartupStage = "EMBEDDING_MOUNT"
	StartupStageEmbeddingClient    StartupStage = "EMBEDDING_CLIENT"
	StartupStageRerankingMount     StartupStage = "RERANKING_MOUNT"
	StartupStageRerankingClient    StartupStage = "RERANKING_CLIENT"
	StartupStageRetrievalExecutor  StartupStage = "RETRIEVAL_EXECUTOR"
	// StartupStageGenerationMount is GEN-2 (ADR-0088): a present-but-invalid
	// modelgateway lab mount, or a present mount with no embedding channel to
	// back its interim verifier, is a startup failure, exactly like the
	// embedding mount above. A wholly absent mount is not a failure: it keeps
	// GENERATIVE unsupported (see internal/question EnableGeneration).
	StartupStageGenerationMount StartupStage = "GENERATION_MOUNT"
	// StartupStageGovernedQueryMount is ADR-0089: a present-but-invalid
	// governedquery mount is a startup failure, exactly like the generation
	// mount above. A wholly absent mount is not a failure: it keeps the
	// governed-query-connections routes an explicit, addressable
	// SERVICE_UNAVAILABLE (see internal/governedask.Service, capability
	// absent by default).
	StartupStageGovernedQueryMount StartupStage = "GOVERNED_QUERY_MOUNT"
	// StartupStageMetricCompareMount identifies an invalid or mismatched
	// optional comparison profile without disclosing its configuration.
	StartupStageMetricCompareMount StartupStage = "METRIC_COMPARE_MOUNT"
	// StartupStageDatasetProfileMount is R1.1 (micro-card C): a present but
	// invalid analyticcatalog mount, or a mounted catalog the Question
	// authority refuses to install, is a startup failure, exactly like the
	// generation mount above. A wholly absent mount is not a failure: it
	// keeps the document-only capability (no dataset profile catalog).
	StartupStageDatasetProfileMount StartupStage = "DATASET_PROFILE_MOUNT"
	StartupStageWorkspaceHandler    StartupStage = "WORKSPACE_HANDLER"
	StartupStageWebUI               StartupStage = "WEB_UI"
	StartupStageHTTPDispatcher      StartupStage = "HTTP_DISPATCHER"
	StartupStageHTTPServer          StartupStage = "HTTP_SERVER"
)

// StartupStageOf returns a stage only for a composition startup failure and
// only when the stage is one of the fixed values above.  Unknown errors,
// other composition error codes, and malformed values all fail closed.
func StartupStageOf(err error) StartupStage {
	var compositionError *Error
	if !errors.As(err, &compositionError) || compositionError == nil ||
		compositionError.code != CodeRuntimeStartupFailed || !knownStartupStage(compositionError.stage) {
		return StartupStageUnknown
	}
	return compositionError.stage
}

func knownStartupStage(stage StartupStage) bool {
	switch stage {
	case StartupStageTrustBundle,
		StartupStageSecrets,
		StartupStageDatabaseURL,
		StartupStageDatabaseRoots,
		StartupStageDatabase,
		StartupStageAuditStore,
		StartupStageIdentityStore,
		StartupStageWorkspaceStore,
		StartupStageJobQueue,
		StartupStageArtifactCodec,
		StartupStageSourceDigestKey,
		StartupStageSourceRegistration,
		StartupStageOIDCPreflight,
		StartupStageIdentityDigestor,
		StartupStageSessionDigestor,
		StartupStageTenantSecurity,
		StartupStageTenantResolver,
		StartupStageHTTPAuthResolver,
		StartupStageTransportCodec,
		StartupStageBrowserTransport,
		StartupStageOIDCRoots,
		StartupStageOIDCHTTPClient,
		StartupStageHTTPAuth,
		StartupStageOIDCHandler,
		StartupStageEvidenceViewer,
		StartupStageSearchMount,
		StartupStageSearchClient,
		StartupStageEmbeddingMount,
		StartupStageEmbeddingClient,
		StartupStageRerankingMount,
		StartupStageRerankingClient,
		StartupStageRetrievalExecutor,
		StartupStageGenerationMount,
		StartupStageGovernedQueryMount,
		StartupStageMetricCompareMount,
		StartupStageDatasetProfileMount,
		StartupStageWorkspaceHandler,
		StartupStageWebUI,
		StartupStageHTTPDispatcher,
		StartupStageHTTPServer:
		return true
	default:
		return false
	}
}

func runtimeStartupError(stage StartupStage) error {
	if !knownStartupStage(stage) {
		return runtimeError(CodeRuntimeStartupFailed)
	}
	return &Error{code: CodeRuntimeStartupFailed, stage: stage}
}
