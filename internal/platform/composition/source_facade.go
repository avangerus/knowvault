package composition

import (
	"context"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// metricDefinitionApprovalAudit is the R1 audit-backed boundary metricdef's
// owner-only approval commits inside its own write transaction. It invents no
// new audit vocabulary: approving a version is the workspace owner's
// governance decision over protected data, so it is recorded through the
// existing policy.decision action on a POLICY resource whose resource_id is
// the definition id. The event is appended to the caller's transaction, so an
// APPROVED version always has its audit event and a failed append rolls the
// approval back. Composition only constructs metricdef.Store with a non-nil
// journal here; a nil journal still fails every approval closed rather than
// approving unaudited.
type metricDefinitionApprovalAudit struct{ journal *audit.Store }

// Compile-time proof that the production approval boundary satisfies the exact
// capability metricdef.Store requires, so a signature drift breaks the build
// instead of the running approve route.
var _ metricdef.ApprovalAudit = metricDefinitionApprovalAudit{}

// RecordApproval is called exactly once per successful approval while the
// store's write transaction is open. Every value is server-owned: the actor is
// the approved event's own principal (which the audit store re-checks against
// the access context), the workspace is the definition's workspace and the
// resource id is the definition id. No definition, version or filter content
// beyond those identifiers reaches the journal.
func (adapter metricDefinitionApprovalAudit) RecordApproval(ctx context.Context, access database.AccessContext,
	transaction database.Transaction, event metricdef.ApprovalEvent) error {
	if adapter.journal == nil {
		return errors.New("METRICDEFINITION_APPROVAL_AUDIT_UNAVAILABLE")
	}
	eventID, err := ids.New("aev")
	if err != nil {
		return err
	}
	actorID := event.ActorPrincipalID
	workspaceID := event.WorkspaceID
	occurredAt := event.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	_, err = adapter.journal.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorHuman,
		ActorPrincipalID: &actorID, Action: audit.ActionPolicyDecision,
		ResourceType: audit.ResourcePolicy, ResourceID: event.DefinitionID,
		RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: occurredAt,
	})
	return err
}

// Compile-time proof that the configured production source service facade
// carries the read-only connector catalog capability that the onboarding route
// discovers on the injected source service. It is a pure delegation to the
// registration-owned surface below, so the route is served by the same facade
// composition wires for every other source operation, never by a bespoke fake.
var _ workspaceapi.SourceConnectorCatalog = sourceServiceFacade{}
var _ workspaceapi.SourceConnectionBootstrap = sourceServiceFacade{}
var _ workspaceapi.SourceDiscovery = sourceServiceFacade{}
var _ workspaceapi.SourceDiscoveryRegistration = sourceServiceFacade{}
var _ workspaceapi.SourceConnectionDrafts = sourceServiceFacade{}
var _ workspaceapi.SourceSchemaProvider = sourceServiceFacade{}

// sourceServiceFacadeWithSQL is the production facade plus ADR-0097's
// agent-authored SQL capability. It is a distinct concrete type on purpose:
// the handler discovers SourceSQLProvider by a type assertion, so a deployment
// that mounted no source trust bundle leaves the tool failing closed as
// SERVICE_UNAVAILABLE instead of advertising a capability it cannot serve.
// Embedding the base facade promotes every other SourceService method
// unchanged.
type sourceServiceFacadeWithSQL struct {
	sourceServiceFacade
	sourceSQL sourceSQLExecutor
}

var _ workspaceapi.SourceSQLProvider = sourceServiceFacadeWithSQL{}
var _ workspaceapi.SourceQueryCredential = sourceServiceFacadeWithSQL{}
var _ workspaceapi.SourceSQLAttemptReauthority = sourceServiceFacadeWithSQL{}

// ReauthorizeSourceSQLAttempt is the read-time reauthorization of one stored
// agent-authored SQL receipt. It is a pure delegation to the executor, which
// owns the current source-access check.
func (facade sourceServiceFacadeWithSQL) ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error {
	return facade.sourceSQL.ReauthorizeSourceSQLAttempt(ctx, access, workspaceID, disclosure)
}

// SetSourceQueryCredential is S3 card 2b's owner-only control over the source
// connection's SQL query credential. The executor owns the owner gate (through
// the repository target read), the mounted-credential resolution, the
// read-only/identity/column-privilege checks and the audited write.
func (facade sourceServiceFacadeWithSQL) SetSourceQueryCredential(ctx context.Context, access database.AccessContext, workspaceID, connectionID, credentialReference string) error {
	return facade.sourceSQL.SetSourceQueryCredential(ctx, access, workspaceID, connectionID, credentialReference)
}

// SourceSQL is a pure delegation to the executor, which owns the authorization,
// credential resolution, the single governedquery execution path and the
// mandatory attempt audit.
func (facade sourceServiceFacadeWithSQL) SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {
	return facade.sourceSQL.SourceSQL(ctx, access, workspaceID, request)
}

// newAppArtifactCodec mounts the application-side artifact codec on the same
// wrap key the worker uses, so source artifacts sealed by the web process open
// in the worker and vice versa.
func newAppArtifactCodec(provider *secretmount.Provider, config Config) (*artifactcrypto.MountedProvider, *artifactcrypto.Codec, error) {
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

// newSourceRegistrationDigestKey returns a caller-owned copy of the 32-byte
// source identity digest key with its version.
func newSourceRegistrationDigestKey(provider *secretmount.Provider) ([]byte, int, error) {
	key, err := provider.SourceDigestKey()
	if err != nil {
		return nil, 0, err
	}
	defer key.Clear()
	material := key.Bytes()
	if len(material) != 32 {
		clear(material)
		return nil, 0, runtimeStartupError(StartupStageSourceDigestKey)
	}
	return append([]byte(nil), material...), int(key.Version()), nil
}

// sourceServiceFacade adapts the registration service and the workspace
// repository to the single SourceService boundary of workspaceapi. It adds no
// logic of its own: gating, idempotency and persistence stay in the two
// components (ADR-0074).
type sourceServiceFacade struct {
	registration *registration.Service
	discovery    *sourcediscovery.Reader
	workspaces   *workspacerepository.Store
}

func (facade sourceServiceFacade) RequestDiscovery(ctx context.Context, access database.AccessContext, request registration.DiscoveryRequest) (registration.DiscoveryResult, error) {
	return facade.registration.RequestDiscovery(ctx, access, request)
}

func (facade sourceServiceFacade) GetDiscovery(ctx context.Context, access database.AccessContext, requestID string) (sourcediscovery.ReadResult, error) {
	return facade.discovery.Get(ctx, access, requestID)
}

func (facade sourceServiceFacade) RegisterDiscoveredView(ctx context.Context, access database.AccessContext, requestID, viewID string, excludedColumnOrdinals []int, mode string) (registration.RegisterResult, error) {
	selected, err := facade.discovery.Select(ctx, access, requestID, viewID)
	if err != nil {
		return registration.RegisterResult{}, err
	}
	return facade.registration.RegisterDiscoveredView(ctx, access, selected, excludedColumnOrdinals, mode)
}

func (facade sourceServiceFacade) Register(ctx context.Context, access database.AccessContext, request registration.RegisterRequest) (registration.RegisterResult, error) {
	return facade.registration.Register(ctx, access, request)
}

func (facade sourceServiceFacade) BootstrapPostgreSQLConnection(ctx context.Context, access database.AccessContext, request registration.PostgreSQLConnectionBootstrapRequest) (registration.PostgreSQLConnectionBootstrapResult, error) {
	return facade.registration.BootstrapPostgreSQLConnection(ctx, access, request)
}

func (facade sourceServiceFacade) Activate(ctx context.Context, access database.AccessContext, request registration.ActivateRequest) (registration.ActivateResult, error) {
	return facade.registration.Activate(ctx, access, request)
}

func (facade sourceServiceFacade) Sync(ctx context.Context, access database.AccessContext, request registration.SyncRequest) (registration.SyncResult, error) {
	return facade.registration.Sync(ctx, access, request)
}

func (facade sourceServiceFacade) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	return facade.workspaces.ListSources(ctx, access, workspaceID)
}

func (facade sourceServiceFacade) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (workspacerepository.ConfirmationContext, error) {
	return facade.workspaces.ConfirmationContext(ctx, access, workspaceID)
}

// ListSourceConnectionDrafts and DiscardSourceConnectionDraft expose card
// D-1's workspace-scoped draft registry on the production facade. Both are
// pure delegations: the workspace-membership policy gate, the content-free
// denial and the audit receipt stay in the workspace repository, exactly like
// ListSources and ConfirmationContext above.
func (facade sourceServiceFacade) ListSourceConnectionDrafts(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceConnectionDraft, error) {
	return facade.workspaces.ListSourceConnectionDrafts(ctx, access, workspaceID)
}

func (facade sourceServiceFacade) DiscardSourceConnectionDraft(ctx context.Context, access database.AccessContext, workspaceID, connectionID string) error {
	return facade.workspaces.DiscardSourceConnectionDraft(ctx, access, workspaceID, connectionID)
}

// UploadDocuments is UPL-1: a pure delegation like every other method here,
// added only because it widens the shared SourceService boundary.
func (facade sourceServiceFacade) UploadDocuments(ctx context.Context, access database.AccessContext, request registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return facade.registration.UploadDocuments(ctx, access, request)
}

// ListSourceSchemas and SourceSchema expose ADR-0097's read-only source schema
// capability on the production facade. Both are pure delegations to the
// workspace repository's sourceMetadataRead boundary, which owns the
// authorization, the cross-tenant denial and the source.metadata.read.* audit
// journal; this method adds no logic of its own, exactly like the other
// delegations on this facade, and touches no external source database.
func (facade sourceServiceFacade) ListSourceSchemas(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceSchemaSource, error) {
	return facade.workspaces.ListSourceSchemas(ctx, access, workspaceID)
}

func (facade sourceServiceFacade) SourceSchema(ctx context.Context, access database.AccessContext, workspaceID, sourceID, table string, offset, limit int) (workspacerepository.SourceSchema, error) {
	return facade.workspaces.SourceSchema(ctx, access, workspaceID, sourceID, table, offset, limit)
}

// ConnectorCatalog exposes the registration-owned source-connector catalog on
// the production facade. Authorization (the same source-management OWNER gate
// every source action uses) lives entirely inside registration.Service
// ConnectorCatalog; this method adds no logic of its own, exactly like the
// other delegations on this facade.
func (facade sourceServiceFacade) ConnectorCatalog(ctx context.Context, access database.AccessContext) (registration.ConnectorCatalog, error) {
	return facade.registration.ConnectorCatalog(ctx, access)
}
