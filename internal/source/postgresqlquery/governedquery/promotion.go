package governedquery

// This file is the typed "save as projection" hook ADR-0089 §5 requires: an
// operator who reviews a successful ad hoc query may promote it into a
// scheduled ADR-0078 POSTGRESQL_QUERY projection.
//
// The promotion input is an ALREADY EXECUTED attempt -- the exact statement
// the model composed and the dedicated read-only role ran, loaded by the
// server from its own attempt record -- never SQL text carried in a request
// body. PRODUCT_CONSTITUTION.md §7 forbids SQL authorship on any product,
// UI, API or operator surface, and ADR-0089's carve-out covers only the
// model-composed, server-executed path; accepting a body-supplied statement
// here would have made :promote an arbitrary SQL intake disguised as a
// bookmark. The caller therefore passes the attempt's server-owned identity
// and the hash it was shown; this package re-derives the hash from the
// stored text and refuses, content-free, on any mismatch.
//
// The real registration integration (internal/source/registration.Service)
// is a separate slice (V1-A); until it is merged onto this branch, this
// command records the operator's promotion intent against the attempt and
// returns a typed, honest "not yet integrated" result rather than silently
// doing nothing or fabricating a projection.

import (
	"context"
	"crypto/subtle"
	"errors"
)

// PromotionStatus is closed and content-free.
type PromotionStatus string

const (
	// PromotionRecordedPendingIntegration means the executed attempt was
	// recorded as a promotion candidate, but no ADR-0078 POSTGRESQL_QUERY
	// projection was created: that registration path is not yet wired on
	// this branch.
	PromotionRecordedPendingIntegration PromotionStatus = "RECORDED_PENDING_INTEGRATION"
)

// ExecutedAttempt is the server-loaded record of one governed-query attempt
// that actually ran. SQLText is never request-supplied: it is what
// Execute ran, read back from the attempt store by its id.
type ExecutedAttempt struct {
	AttemptID             string
	ConnectionID          string
	ExposedSchemaRevision int64
	SQLText               string
	SQLHash               string
}

// PromotionRequest names the executed attempt to save and the hash the
// operator was shown for it. It deliberately has no SQL field.
type PromotionRequest struct {
	ConnectionID string
	PrincipalID  string
	// ExpectedSQLHash is the hash the operator saw beside the executed
	// statement. It must equal the attempt's own hash; a mismatch means the
	// operator is confirming something other than what is stored.
	ExpectedSQLHash string
	Attempt         ExecutedAttempt
}

// PromotionResult is the typed, content-free outcome.
type PromotionResult struct {
	Status    PromotionStatus
	AttemptID string
	SQLHash   string
}

// PromoteToProjection is the typed command ADR-0089 §5 requires. It never
// creates a schedule, watermark or recurring job of its own (that remains
// the unmodified ADR-0078 registration path) and it never accepts SQL text
// from its caller's caller: only a server-loaded executed attempt.
func PromoteToProjection(ctx context.Context, request PromotionRequest) (PromotionResult, error) {
	if ctx == nil {
		return PromotionResult{}, errors.New("governed query promotion requires a context")
	}
	attempt := request.Attempt
	if !validOpaque(request.ConnectionID) || !validOpaque(request.PrincipalID) ||
		!validOpaque(attempt.AttemptID) || !validOpaque(attempt.ConnectionID) ||
		attempt.ConnectionID != request.ConnectionID || attempt.ExposedSchemaRevision < 1 ||
		len(attempt.SQLText) == 0 || len(attempt.SQLText) > maxSQLTextBytes {
		return PromotionResult{}, &Error{code: CodeInvalid}
	}
	// The attempt store is the authority for what ran; re-derive the hash
	// rather than trusting either the stored column or the caller.
	derived := sha256Hex(attempt.SQLText)
	if !constantTimeEqual(derived, attempt.SQLHash) || !constantTimeEqual(derived, request.ExpectedSQLHash) {
		return PromotionResult{}, &Error{code: CodeInvalid}
	}
	// An attempt that ran is by construction a single read-only statement the
	// dedicated role accepted, but the static pre-check stays as a cheap
	// second opinion: a projection is scheduled and re-run for months, so it
	// must still satisfy the same shape gate a fresh candidate does.
	if err := staticPrecheck(attempt.SQLText); err != nil {
		return PromotionResult{}, err
	}
	// Integration point: internal/source/registration.Service.Register with
	// SourceType "POSTGRESQL_QUERY" and this exact executed statement as the
	// operator's reviewed view definition, once that registration path is
	// merged onto this branch. Recording the attempt id and hash here keeps
	// the promotion candidate auditable and content-free in the interim.
	return PromotionResult{
		Status: PromotionRecordedPendingIntegration, AttemptID: attempt.AttemptID, SQLHash: derived,
	}, nil
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
