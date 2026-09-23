package governedask

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// AttemptDisclosure is the content-free reference to a successful governed
// query attempt whose result a caller wants to use again. It deliberately
// contains no SQL text or result data.
type AttemptDisclosure struct {
	AttemptID             string `json:"attempt_id"`
	ConnectionID          string `json:"connection_id"`
	SQLHash               string `json:"sql_hash"`
	ExposedSchemaRevision int64  `json:"exposed_schema_revision"`
	ResultDigest          string `json:"result_digest"`
}

// ReauthorizeAttempt confirms that an earlier successful governed attempt is
// still usable by this caller. It performs no SQL execution.
//
// governed_query_attempt intentionally has no result_digest column. The
// supplied ResultDigest is therefore shape-validated here but cannot be
// independently authenticated until the later Question artifact binds it.
func (service *Service) ReauthorizeAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure AttemptDisclosure) error {
	if service == nil || !service.enabled {
		return &Error{code: CodeUnavailable}
	}
	if ctx == nil {
		return &Error{code: CodeRequestInvalid}
	}
	if ctx.Err() != nil {
		return &Error{code: CodeUnavailable}
	}
	if access.Validate() != nil || !validOpaque(workspaceID) ||
		!validOpaque(disclosure.AttemptID) || !validOpaque(disclosure.ConnectionID) ||
		!validSQLHash(disclosure.SQLHash) || disclosure.ExposedSchemaRevision < 1 ||
		!validSQLHash(disclosure.ResultDigest) {
		return &Error{code: CodeRequestInvalid}
	}
	// The connection is server-owned. A request can only confirm the mounted
	// connection, never select another one.
	if disclosure.ConnectionID != service.config.ConnectionID {
		return &Error{code: CodeDenied}
	}
	if err := service.reauthorizeDisclosure(ctx, access, workspaceID); err != nil {
		return reauthorizationPublicError(ctx, err)
	}

	attempt, err := service.reauthorizeAttemptLoad(ctx, access, workspaceID, disclosure.AttemptID)
	if err != nil {
		return reauthorizationPublicError(ctx, err)
	}
	if ctx.Err() != nil {
		return &Error{code: CodeUnavailable}
	}
	if !constantTimeAttemptDisclosureMatch(attempt, disclosure) {
		return &Error{code: CodeDenied}
	}
	return nil
}

func (service *Service) reauthorizeAttemptLoad(ctx context.Context, access database.AccessContext, workspaceID, attemptID string) (governedquery.ExecutedAttempt, error) {
	if service.attemptLoader != nil {
		return service.attemptLoader(ctx, access, workspaceID, attemptID)
	}
	return service.loadExecutedAttempt(ctx, access, workspaceID, attemptID)
}

// reauthorizationPublicError deliberately collapses access denials, missing
// rows and binding mismatches to one error. Cancellation and persistence
// failures are unavailable, and neither branch wraps an underlying cause.
func reauthorizationPublicError(ctx context.Context, err error) error {
	if (ctx != nil && ctx.Err() != nil) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &Error{code: CodeUnavailable}
	}
	var governedErr *Error
	if errors.As(err, &governedErr) && governedErr.code == CodePersistence {
		return &Error{code: CodeUnavailable}
	}
	return &Error{code: CodeDenied}
}

func constantTimeAttemptDisclosureMatch(attempt governedquery.ExecutedAttempt, disclosure AttemptDisclosure) bool {
	return constantTimeStringEqual(attempt.ConnectionID, disclosure.ConnectionID) &&
		constantTimeStringEqual(attempt.SQLHash, disclosure.SQLHash) &&
		constantTimeInt64Equal(attempt.ExposedSchemaRevision, disclosure.ExposedSchemaRevision)
}

func constantTimeStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func constantTimeInt64Equal(left, right int64) bool {
	var leftBytes, rightBytes [8]byte
	binary.BigEndian.PutUint64(leftBytes[:], uint64(left))
	binary.BigEndian.PutUint64(rightBytes[:], uint64(right))
	return subtle.ConstantTimeCompare(leftBytes[:], rightBytes[:]) == 1
}
