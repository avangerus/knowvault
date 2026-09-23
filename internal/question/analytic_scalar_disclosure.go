package question

import (
	"context"
	"reflect"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// scalarInterfaceIsNil reports whether one interface value is absent at either
// level: the interface itself is nil, or it holds a typed-nil pointer, map,
// func, slice, chan or interface. It is used only to keep the disclosure gate
// from dereferencing a typed-nil context or reauthorizer before the local
// refusal check; a non-nilable concrete implementation is accepted without a
// panic.
func scalarInterfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// scalarDependencyReauthorizer is the one private authority operation the scalar
// disclosure gate depends on: a fresh, current-access reauthorization of one
// already-saved opaque dependency. It is satisfied by the concrete
// *analyticsource.Resolver the Service holds after the one-shot
// EnableDatasetProfileCatalog install, and by a package test double. The
// interface adds no behavior, no default and no second install path: it only
// lets the gate be exercised against a counter or a fault without a live
// repository.
type scalarDependencyReauthorizer interface {
	ReauthorizeScalarDependency(
		ctx context.Context,
		currentAccess database.AccessContext,
		workspaceID string,
		questionRunID string,
		dependency analyticsource.ScalarDependency,
	) error
}

// authorizeScalarDisclosure is the interface-taking authorization gate for one
// decoded scalar pair. It is pure up to the single reauthorizer call: it reads
// no repository, performs no source execution, serializes nothing, persists
// nothing and caches no decision.
//
// A nil pair is the sole accepted absence and returns nil before any local check
// and before any installed capability is consulted, so decoding "no scalar" is
// never an authorization decision.
//
// A present pair is first validated locally: an absent or typed-nil context, an
// access context that fails Validate, an invalid workspace or Question Run id,
// an absent or typed-nil reauthorizer, an invalid observation and a failing
// analyticsource.VerifyScalarDependencyBinding all return the exact content-free
// CodeUnavailable refusal with no wrapped cause. No reauthorizer is called on
// any refusal, so invalid local inputs never become an I/O or existence oracle.
//
// Only then is a failed context checked and, on a still-live context, the
// reauthorizer is called exactly once with the current access unchanged, the
// workspace, the trusted Question Run id and the opaque dependency. The context
// is re-checked after the call, so a cancellation or deadline observed during
// the call is CodeUnavailable rather than a decision. Any concrete
// reauthorization refusal maps to the exact content-free CodeNotFound refusal
// with an empty unwrap chain: no resolver cause, dependency fact, identity,
// metric, receipt, value or database fact is retained, returned or exposed. On
// success it returns nil and no value, token, grant or cached decision.
func authorizeScalarDisclosure(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	pair *analyticScalarPair,
	reauthorizer scalarDependencyReauthorizer,
) error {
	if pair == nil {
		return nil
	}
	if scalarInterfaceIsNil(ctx) || access.Validate() != nil ||
		!validOpaque(workspaceID) || !validOpaque(questionRunID) ||
		scalarInterfaceIsNil(reauthorizer) || !pair.observation.valid() {
		return &Error{code: CodeUnavailable}
	}
	if err := analyticsource.VerifyScalarDependencyBinding(
		questionRunID,
		pair.observation.ReceiptSchema,
		pair.observation.ReceiptDigest,
		pair.dependency,
	); err != nil {
		return &Error{code: CodeUnavailable}
	}
	if ctx.Err() != nil {
		return &Error{code: CodeUnavailable}
	}

	callErr := reauthorizer.ReauthorizeScalarDependency(
		ctx,
		access,
		workspaceID,
		questionRunID,
		pair.dependency,
	)
	if ctx.Err() != nil {
		return &Error{code: CodeUnavailable}
	}
	if callErr != nil {
		return &Error{code: CodeNotFound}
	}
	return nil
}

// authorizeAnalyticScalarDisclosure is the Service wrapper of the scalar
// disclosure gate. It reads the two slots the one-shot
// EnableDatasetProfileCatalog install owns and delegates to the interface-taking
// helper with the installed concrete service.analyticSourceResolver; it adds no
// second install path, no setter, no runtime, SQL or model exposure and no
// Run/REST/MCP surface.
//
// A nil pair is accepted exactly as by the helper and returns nil without
// reading, requiring or changing either installed slot. A present pair requires
// a valid retained catalog and a non-nil resolver; an absent, zero or invalid
// catalog or a nil resolver is the missing analytic capability and returns the
// content-free CodeUnavailable refusal without calling the resolver. The
// wrapper never mutates, replaces or heals either slot.
func (service *Service) authorizeAnalyticScalarDisclosure(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	pair *analyticScalarPair,
) error {
	if pair == nil {
		return nil
	}
	if service == nil || !service.datasetProfileCatalog.Valid() || service.analyticSourceResolver == nil {
		return &Error{code: CodeUnavailable}
	}
	return authorizeScalarDisclosure(ctx, access, workspaceID, questionRunID, pair, service.analyticSourceResolver)
}
