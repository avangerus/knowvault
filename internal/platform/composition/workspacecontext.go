package composition

// This file is the lead's S2 integration wiring (S2-MODEL-CONTEXT-DESIGN.md
// "Cards": "F. The lead's integration: composition/runtime.go, protected
// hashes, the live check") for ADR-0098's workspace model context: it mounts
// card A's PostgreSQL-backed workspacecontext.Store as the one Reader every
// consumer (card B's chat tool loop, card C's MCP tool/REST tool-parity/chat
// tool runtime) shares, mounts card E's proposer.Store as the
// workspacecontext.ProposalService the REST proposal routes call, and closes
// the two seams proposer/seams.go left for "the lead": VersionMinter (atomic
// accept) and RunExcerptReader (viewer-authorized example excerpts, over
// question.Service.GetBatch). It also wires the audit events neither card's
// own package boundary let it write itself: workspace.model_context_read
// (question.SetWorkspaceContextReadAuditHook, called from card C's shared
// workspaceContextToolResult core) and the two proposal-lifecycle events,
// workspace.context_proposal_created (actor SYSTEM, appended inside
// proposer.Store's own ObserveRun transaction via EnableAudit) and
// workspace.context_proposal_decided (Reject: also inside proposer.Store's
// own transaction via EnableAudit; Accept: inside proposalVersionMinter's
// own version-minting transaction below, since Accept's decision and version
// mint must commit or roll back together).
//
// A deployment with no database mount never reaches this file (NewProduction
// already failed earlier at StartupStageDatabase); every capability here is
// therefore mandatory once composed, exactly like the workspace/source/
// question capabilities above it, not another optional mount gated by its
// own LoadMounted probe.

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	"knowvault.local/verified-workspace/internal/workspacecontext/proposer"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// workspaceContextAuditEventIDPrefix mirrors internal/workspacecontext/store.go's
// own convention (ids.New("aev")) for every audit_event id this file mints.
const workspaceContextAuditEventIDPrefix = "aev"

// installWorkspaceContext mounts ADR-0098's document store, its deterministic
// proposer and every seam between them and the rest of the running system.
// It is called once from NewProduction, after workspaceHandler and questions
// both exist (it wires both) and after auditStore/workspaceStore/databaseStore
// are already mounted. A failure here is a startup failure exactly like every
// other mandatory capability above it: this product ships S2 wired or not at
// all, never silently degraded to "no workspace context this deployment".
func installWorkspaceContext(databaseStore *database.Store, workspaceStore *workspacerepository.Store,
	auditStore *audit.Store, questions *question.Service, workspaceHandler *workspaceapi.Handler) error {
	contextStore, err := workspacecontext.NewStore(databaseStore, workspaceStore, auditStore)
	if err != nil {
		return err
	}
	workspaceHandler.EnableModelContext(contextStore)
	workspaceHandler.EnableWorkspaceContext(contextStore)
	if err := questions.EnableWorkspaceContext(contextStore); err != nil {
		return err
	}

	proposals := proposer.NewStore(databaseStore, contextStore,
		&proposalVersionMinter{database: databaseStore, context: contextStore, audit: auditStore},
		&questionRunExcerptReader{questions: questions})
	proposals.EnableAudit(auditStore)
	workspaceHandler.EnableModelContextProposals(proposals)
	workspaceHandler.EnableModelContextProposalExamples(&proposalExampleResolver{proposals: proposals})
	if err := questions.EnableWorkspaceContextObserver(proposals); err != nil {
		return err
	}

	question.SetWorkspaceContextReadAuditHook(func(ctx context.Context, access database.AccessContext, trace question.WorkspaceContextReadTrace) {
		appendWorkspaceContextReadEvent(ctx, auditStore, access, trace.WorkspaceID)
	})
	return nil
}

// appendWorkspaceContextReadEvent appends exactly one
// audit.workspace.model_context_read event for one knowvault_workspace_context
// / tools/workspace-context read, reached through MCP, REST tool parity or
// (transitively, through workspaceapi.Handler.Invoke) the chat tool runtime
// -- card C's shared workspaceContextToolResult core calls
// question.ObserveWorkspaceContextRead after every successful read
// regardless of which of the three surfaces served it, so this one hook
// covers all three identically and a read is never audited twice. It is a
// best-effort side channel exactly like every other audit hook installed
// this way in this product: it never blocks or fails the read that reports
// it (the hook itself runs synchronously but its own failure is swallowed,
// never propagated back into the read).
func appendWorkspaceContextReadEvent(ctx context.Context, auditStore *audit.Store, access database.AccessContext, workspaceID string) {
	eventID, err := ids.New(workspaceContextAuditEventIDPrefix)
	if err != nil {
		return
	}
	actorType := audit.ActorHuman
	if access.EffectiveActorKind() == database.ActorKindService {
		actorType = audit.ActorService
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	_, _ = auditStore.Append(ctx, access, audit.EventInput{
		EventID: eventID, ActorType: actorType, ActorPrincipalID: &actorID,
		Action: audit.ActionWorkspaceModelContextRead, ResourceType: audit.ResourceWorkspaceModelContext,
		ResourceID: workspaceID, RequestID: access.RequestID, WorkspaceID: &workspaceValue,
		Outcome: audit.OutcomeSuccess, OccurredAt: time.Now().UTC(),
	})
}

// proposalVersionMinter adapts card A's workspacecontext.Store.AcceptProposalVersion
// into card E's proposer.VersionMinter seam (proposer/seams.go): it is the
// lead's wiring for POST .../proposals/{id}:accept's atomicity (ADR-0098
// decision 4, "Accept ... creates a new version atomically"). It opens
// exactly one database.Store.Write transaction, validates and mints the new
// version inside it, calls the caller-supplied decideProposal with that same
// transaction, and -- only once decideProposal itself has succeeded --
// appends the one workspace.context_proposal_decided audit event this
// acceptance produces, still inside the same transaction: a version is never
// minted for a decision that did not commit, and a decision is never
// recorded as decided without its audit trail, because both are the same
// database round trip.
type proposalVersionMinter struct {
	database *database.Store
	context  *workspacecontext.Store
	audit    *audit.Store
}

func (minter *proposalVersionMinter) MintAcceptedVersion(
	ctx context.Context, access workspacecontext.Access, workspaceID, ifMatchHash string,
	document workspacecontext.Document, proposalID string,
	decideProposal func(ctx context.Context, tx database.Transaction, mintedVersion int64) error,
) (workspacecontext.Version, error) {
	dbAccess := toDatabaseAccess(access)
	knownProjections, err := minter.context.KnownProjections(ctx, dbAccess, workspaceID)
	if err != nil {
		return workspacecontext.Version{}, err
	}
	var minted workspacecontext.Version
	err = minter.database.Write(ctx, dbAccess, func(ctx context.Context, tx database.Transaction) error {
		version, acceptErr := minter.context.AcceptProposalVersion(ctx, tx, dbAccess, workspaceID, document, knownProjections, ifMatchHash, proposalID)
		if acceptErr != nil {
			return acceptErr
		}
		if decideErr := decideProposal(ctx, tx, version.Number); decideErr != nil {
			return decideErr
		}
		if minter.audit != nil {
			if auditErr := minter.appendDecided(ctx, tx, dbAccess, workspaceID, proposalID); auditErr != nil {
				return auditErr
			}
		}
		minted = version
		return nil
	})
	if err != nil {
		return workspacecontext.Version{}, err
	}
	return minted, nil
}

func (minter *proposalVersionMinter) appendDecided(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID, proposalID string) error {
	eventID, err := ids.New(workspaceContextAuditEventIDPrefix)
	if err != nil {
		return err
	}
	actorID := access.PrincipalID
	workspaceValue := workspaceID
	_, appendErr := minter.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: audit.ActionWorkspaceContextProposalDecided, ResourceType: audit.ResourceWorkspaceContextProposal,
		ResourceID: proposalID, RequestID: access.RequestID, WorkspaceID: &workspaceValue,
		Outcome: audit.OutcomeSuccess, OccurredAt: time.Now().UTC(),
	})
	return appendErr
}

func toDatabaseAccess(access workspacecontext.Access) database.AccessContext {
	return database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID}
}

// questionRunExcerptReader adapts question.Service.GetBatch into card E's
// proposer.RunExcerptReader seam (proposer/seams.go): the viewer-authorized,
// at-most-300-character question excerpt a listed proposal's examples[]
// carries (S2-CONTRACT.md "examples lists only runs the viewer can read
// now"). GetBatch already resolves exactly that authorization -- a run
// absent from runIDs, not belonging to workspaceID, or not currently
// readable is simply absent from its result map -- so this adapter only
// reshapes the result, in the caller's own runIDs order, into
// proposer.RunExcerpt; the 300-character clip is proposer.Store's own
// (resolveExamples), not duplicated here.
type questionRunExcerptReader struct {
	questions *question.Service
}

func (reader *questionRunExcerptReader) GetBatch(ctx context.Context, access workspacecontext.Access, workspaceID string, runIDs []string) ([]proposer.RunExcerpt, error) {
	runs, err := reader.questions.GetBatch(ctx, toDatabaseAccess(access), workspaceID, runIDs)
	if err != nil {
		return nil, err
	}
	excerpts := make([]proposer.RunExcerpt, 0, len(runs))
	for _, runID := range runIDs {
		run, ok := runs[runID]
		if !ok {
			continue
		}
		excerpts = append(excerpts, proposer.RunExcerpt{
			QuestionRunID: run.ID, ConversationID: run.ConversationID, QuestionExcerpt: run.Question,
		})
	}
	return excerpts, nil
}

// proposalExampleResolver adapts card E's proposer.Store.GetWithExamples
// into card A's workspaceapi.ProposalExampleResolver seam
// (model_context.go's file-level deviation note 3): it resolves one listed
// proposal's example dialogue and hidden count through the identical
// evidence-row lookup and questionRunExcerptReader above that
// GetWithExamples already composes, so a proposal's examples never drift
// between whatever internal listing card E's own package might someday grow
// and what the REST proposals list actually returns. limit is
// workspaceapi's own modelContextExampleLimit (20); it is not forwarded
// because GetWithExamples applies migration 000113's identical 20-evidence-
// row cap itself (S2-MODEL-CONTEXT-DESIGN.md "Limits": "at most 20 evidence
// rows per proposal").
type proposalExampleResolver struct {
	proposals *proposer.Store
}

func (resolver *proposalExampleResolver) Examples(ctx context.Context, access database.AccessContext, workspaceID, proposalID string, limit int) ([]workspaceapi.ModelContextProposalExample, int, error) {
	listed, err := resolver.proposals.GetWithExamples(ctx, workspacecontext.Access{
		OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: access.RequestID,
	}, workspaceID, proposalID)
	if err != nil {
		return nil, 0, err
	}
	examples := make([]workspaceapi.ModelContextProposalExample, 0, len(listed.Examples))
	for _, example := range listed.Examples {
		examples = append(examples, workspaceapi.ModelContextProposalExample{
			ConversationID: example.ConversationID, QuestionExcerpt: example.QuestionExcerpt,
		})
	}
	return examples, listed.HiddenExamples, nil
}
