package question

import (
	"context"
	"errors"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// governedAttemptReauthorizer is the private governed-ask capability needed by
// Question: it combines the existing workspace ask operation with current
// attempt reauthorization. The concrete *governedask.Service already installed
// as liveDataAsk satisfies it; this adds no install path or public Question
// capability.
type governedAttemptReauthorizer interface {
	GovernedAsk
	ReauthorizeAttempt(
		ctx context.Context,
		currentAccess database.AccessContext,
		workspaceID string,
		disclosure governedask.AttemptDisclosure,
	) error
}

// authorizeGovernedQueryDisclosure reauthorizes one saved live-query result
// against the current caller. A nil dependency is the legacy absence and
// performs no validation or authority call. A present dependency must be bound
// to this Question Run before its opaque disclosure reference is passed to the
// installed authority exactly once. This gate never executes SQL, retains no
// decision, and turns every refusal into a content-free Question error.
func authorizeGovernedQueryDisclosure(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency *governedQueryDependency,
	reauthorizer governedAttemptReauthorizer,
) error {
	if dependency == nil {
		return nil
	}
	return authorizeGovernedQueryDisclosures(ctx, access, workspaceID, questionRunID, []governedQueryDependency{*dependency}, reauthorizer)
}

func authorizeGovernedQueryDisclosures(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependencies []governedQueryDependency,
	reauthorizer governedAttemptReauthorizer,
) error {
	if len(dependencies) == 0 {
		return nil
	}
	denied := false
	for _, dependency := range dependencies {
		dependency := dependency
		if err := authorizeGovernedQueryDisclosureOne(ctx, access, workspaceID, questionRunID, &dependency, reauthorizer); err != nil {
			if CodeOf(err) == CodeNotFound {
				denied = true
				continue
			}
			return err
		}
	}
	if denied {
		return &Error{code: CodeNotFound}
	}
	return nil
}

func authorizeGovernedQueryDisclosureOne(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency *governedQueryDependency,
	reauthorizer governedAttemptReauthorizer,
) error {
	if scalarInterfaceIsNil(ctx) || access.Validate() != nil ||
		!validOpaque(workspaceID) || !validOpaque(questionRunID) ||
		!dependency.validForRun(questionRunID) || scalarInterfaceIsNil(reauthorizer) {
		return &Error{code: CodeUnavailable}
	}
	if ctx.Err() != nil {
		return &Error{code: CodeUnavailable}
	}

	callErr := reauthorizer.ReauthorizeAttempt(ctx, access, workspaceID, governedask.AttemptDisclosure{
		AttemptID: dependency.attemptID, ConnectionID: dependency.connectionID,
		SQLHash: dependency.sqlHash, ExposedSchemaRevision: dependency.exposedSchemaRevision,
		ResultDigest: dependency.resultDigest,
	})
	if ctx.Err() != nil || errors.Is(callErr, context.Canceled) || errors.Is(callErr, context.DeadlineExceeded) {
		return &Error{code: CodeUnavailable}
	}
	if callErr == nil {
		return nil
	}
	var governedErr *governedask.Error
	if errors.As(callErr, &governedErr) {
		switch governedask.CodeOf(callErr) {
		case governedask.CodeUnavailable, governedask.CodeRequestInvalid, governedask.CodePersistence:
			return &Error{code: CodeUnavailable}
		}
	}
	// ReauthorizeAttempt exposes denials and missing/binding-mismatched attempts
	// as CodeDenied. Treat any other refusal as content-free not-found too; its
	// public contract never returns raw storage or content errors.
	return &Error{code: CodeNotFound}
}

// authorizeGovernedQueryDisclosureForService reads only the governed ask that
// composition already installed. A nil dependency remains a legacy success;
// a present dependency without the concrete reauthorization capability fails
// closed and does not change that one-shot installation.
func (service *Service) authorizeGovernedQueryDisclosure(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency *governedQueryDependency,
) error {
	if dependency == nil {
		return nil
	}
	var reauthorizer governedAttemptReauthorizer
	if service != nil {
		reauthorizer, _ = service.liveDataAsk.(governedAttemptReauthorizer)
	}
	return authorizeGovernedQueryDisclosure(ctx, access, workspaceID, questionRunID, dependency, reauthorizer)
}

func (service *Service) authorizeGovernedQueryDisclosures(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependencies []governedQueryDependency,
) error {
	if len(dependencies) == 0 {
		return nil
	}
	var reauthorizer governedAttemptReauthorizer
	if service != nil {
		reauthorizer, _ = service.liveDataAsk.(governedAttemptReauthorizer)
	}
	return authorizeGovernedQueryDisclosures(ctx, access, workspaceID, questionRunID, dependencies, reauthorizer)
}
