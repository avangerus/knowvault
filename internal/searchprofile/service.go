// Package searchprofile is the operator authority for a tenant's retrieval
// profile revision (EMB-1, migration 000072).
//
// A workspace is indexed under exactly one retrieval profile revision. When a
// deployment mounts a new embedding channel — the first one, or a replacement
// model — the tenant does not silently change vector space: an OWNER issues one
// typed command, the worker stages the new revision, re-embeds the corpus and
// only then cuts over. Until that cutover every question is still answered from
// the revision the corpus was actually indexed under, and a tenant with no
// active revision still fails closed exactly as before.
//
// This package owns no SQL beyond reading the durable revision it reports and
// enqueuing the worker job; the revision rows themselves are written only by
// the worker role, enforced by the trigger in migration 000027/000072. The
// command is deliberately singular: there is no wizard, no per-source toggle
// and no operator-visible generation/alias arithmetic (KnowVault is
// anti-SAP by decision — see knowvault-DECISIONS.md 9).
package searchprofile

import (
	"context"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
)

// ErrorCode is content-free and safe for HTTP/MCP mapping and logs.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "SEARCH_PROFILE_REQUEST_INVALID"
	CodeDenied      ErrorCode = "SEARCH_PROFILE_DENIED"
	CodeUnavailable ErrorCode = "SEARCH_PROFILE_UNAVAILABLE"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string { return string(err.code) }
func (err *Error) Unwrap() error { return err.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// WorkspaceAuthority is the subset of the workspace store this package needs.
// Authorization reuses the existing snapshot/membership authority; this
// package invents no second access-control path.
type WorkspaceAuthority interface {
	Get(context.Context, database.AccessContext, string) (workspace.Snapshot, error)
}

// MountedProfile is the deployment's embedding capability identity, taken from
// the administrator-owned mount at composition time. An empty MountedProfile
// means no embedding channel is mounted, which makes the revision command a
// content-free SERVICE_UNAVAILABLE rather than a silent no-op.
type MountedProfile struct {
	ProfileID   string
	ProfileHash string
	Dimension   int
	// Generation and GenerationFence come from the search capability mount,
	// not the embedding one: a revision never moves the tenant to another
	// alias generation, it only re-embeds the same corpus into it.
	Generation      int64
	GenerationFence int64
}

// Available reports whether this deployment can offer a vector revision at all.
func (profile MountedProfile) Available() bool {
	return profile.ProfileID != "" && profile.ProfileHash != "" && profile.Dimension > 0 &&
		profile.Generation > 0 && profile.GenerationFence > 0
}

// Service is safe for concurrent use once constructed.
type Service struct {
	db         *database.Store
	audit      *audit.Store
	workspaces WorkspaceAuthority
	repository *search.Repository
	mounted    MountedProfile
	now        func() time.Time
	newID      func(string) (string, error)
}

func New(db *database.Store, auditStore *audit.Store, workspaces WorkspaceAuthority,
	repository *search.Repository, mounted MountedProfile) (*Service, error) {
	if db == nil || auditStore == nil || workspaces == nil || repository == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return &Service{db: db, audit: auditStore, workspaces: workspaces,
		repository: repository, mounted: mounted, now: time.Now, newID: ids.New}, nil
}

// View is the operator-visible state of the tenant's retrieval profile. It
// carries identities and statuses only: no endpoint, no credential, no
// alias/index name and no corpus content.
type View struct {
	ActiveProfileID    string
	ActiveRevision     int64
	ActiveVector       bool
	StagingProfileID   string
	StagingRevision    int64
	MountedProfileID   string
	MountedAvailable   bool
	RevisionAvailable  bool
	ReindexInProgress  bool
	RequestedProfileID string
}

// Status reports the tenant's retrieval profile to an OWNER of workspaceID.
func (service *Service) Status(ctx context.Context, access database.AccessContext, workspaceID string) (View, error) {
	if err := service.authorize(ctx, access, workspaceID); err != nil {
		return View{}, err
	}
	return service.view(ctx, access)
}

// Revise requests the one operator command: move this tenant onto the
// deployment's mounted embedding profile. It is idempotent — a request whose
// target is already the active revision changes nothing, and a repeat while a
// revision is in flight returns the same job — so an operator (or an installer
// script) can issue it unconditionally.
func (service *Service) Revise(ctx context.Context, access database.AccessContext, workspaceID string) (View, error) {
	if err := service.authorize(ctx, access, workspaceID); err != nil {
		return View{}, err
	}
	if !service.mounted.Available() {
		// No embedding channel is mounted for this deployment: there is no
		// vector space to move onto. Fail closed and observably rather than
		// enqueuing work that can never succeed.
		return View{}, &Error{code: CodeUnavailable}
	}
	current, err := service.view(ctx, access)
	if err != nil {
		return View{}, err
	}
	if current.ActiveProfileID == service.mounted.ProfileID && current.ActiveVector {
		return current, nil
	}
	eventID, err := service.newID("aev")
	if err != nil {
		return View{}, &Error{code: CodeUnavailable, cause: err}
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	var stagedRevision int64
	if err := service.db.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		// One transaction: the staged revision and the operator decision that
		// asked for it are appended together, or neither is.
		revision, stageErr := service.repository.RequestRevision(txCtx, transaction, access,
			service.mounted.ProfileID, service.mounted.ProfileHash,
			service.mounted.Generation, service.mounted.GenerationFence)
		if stageErr != nil {
			return stageErr
		}
		stagedRevision = revision
		_, appendErr := service.audit.AppendInTransaction(txCtx, access, transaction, audit.EventInput{
			EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionSearchProfileRevisionRequested, ResourceType: audit.ResourceSearchProfile,
			ResourceID: service.mounted.ProfileHash, RequestID: access.RequestID,
			WorkspaceID: &workspaceValue, Outcome: audit.OutcomeSuccess,
			OccurredAt: service.now().UTC(),
		})
		return appendErr
	}); err != nil {
		return View{}, &Error{code: CodeUnavailable, cause: err}
	}
	current.StagingProfileID = service.mounted.ProfileID
	current.StagingRevision = stagedRevision
	current.RequestedProfileID = service.mounted.ProfileID
	return current, nil
}

func (service *Service) authorize(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if service == nil || service.db == nil || service.audit == nil || service.workspaces == nil ||
		service.repository == nil || ctx == nil ||
		access.Validate() != nil || workspaceID == "" {
		return &Error{code: CodeInvalid}
	}
	snapshot, err := service.workspaces.Get(ctx, access, workspaceID)
	if err != nil {
		return &Error{code: CodeDenied, cause: err}
	}
	// The retrieval profile is tenant-wide, so the command is reserved to an
	// OWNER of the workspace it is issued from — the same authority that may
	// add sources to it and issue agent access codes over it.
	if snapshot.Status != workspace.StatusActive {
		return &Error{code: CodeDenied}
	}
	for _, member := range snapshot.Members {
		if member.PrincipalID == access.PrincipalID && member.Role == workspace.RoleOwner {
			return nil
		}
	}
	return &Error{code: CodeDenied}
}

func (service *Service) view(ctx context.Context, access database.AccessContext) (View, error) {
	view := View{
		MountedProfileID: service.mounted.ProfileID,
		MountedAvailable: service.mounted.Available(),
	}
	if err := service.db.Read(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		active, found, readErr := service.repository.ReadRevision(txCtx, transaction, access, search.RevisionActive)
		if readErr != nil {
			return readErr
		}
		if found {
			view.ActiveProfileID = active.ProfileID
			view.ActiveRevision = active.ActivationRevision
			view.ActiveVector = active.Vector()
		}
		staged, stagedFound, readErr := service.repository.ReadRevision(txCtx, transaction, access, search.RevisionStaging)
		if readErr != nil {
			return readErr
		}
		if stagedFound {
			view.StagingProfileID = staged.ProfileID
			view.StagingRevision = staged.ActivationRevision
		}
		return nil
	}); err != nil {
		return View{}, &Error{code: CodeUnavailable, cause: err}
	}
	// A staged revision that has not been cut over yet IS the progress signal:
	// the worker holds it until every indexable chunk has been rebuilt.
	view.ReindexInProgress = view.StagingRevision > 0
	view.RevisionAvailable = view.MountedAvailable &&
		(view.ActiveProfileID == "" || view.ActiveProfileID != service.mounted.ProfileID)
	return view, nil
}
