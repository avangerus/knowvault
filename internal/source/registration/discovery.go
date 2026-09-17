package registration

import (
	"context"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// DiscoveryRequest contains the opaque control-plane coordinates for a
// pre-registration PostgreSQL catalog probe. The connection revision and
// trust hash are checked again by 000090; no scope, column selection, DSN or
// credential value is accepted here.
type DiscoveryRequest struct {
	ConnectionID   string
	IdempotencyKey string
	Limits         postgresqlquery.DiscoveryLimits
}

// DiscoveryResult identifies the durable request and its existing queue job.
// It contains no source metadata, credential reference or database identity.
type DiscoveryResult struct {
	RequestID string
	JobID     string
	Created   bool
}

// RequestDiscovery creates one connection-revision-bound discovery request.
// The database command derives the tenant, current OWNER actor, security
// epoch, fifteen-minute expiry, request hash and one SOURCE_DISCOVERY job in
// the same transaction. A replay derives the same request ID from the scoped
// idempotency key and returns the existing tuple.
func (s *Service) RequestDiscovery(ctx context.Context, access database.AccessContext, request DiscoveryRequest) (DiscoveryResult, error) {
	if s == nil || s.database == nil || access.Validate() != nil {
		return DiscoveryResult{}, &Error{code: CodeRequestInvalid}
	}
	limits, err := normalizeDiscoveryLimits(request.Limits)
	if err != nil || !validGeneratedID(request.ConnectionID, "conn_") || !validIdempotencyKey(request.IdempotencyKey) {
		return DiscoveryResult{}, &Error{code: CodeRequestInvalid}
	}
	idempotencyHash := canon.Hash([]byte(request.IdempotencyKey))
	requestID := discoveryRequestID(access.OrganizationID, access.PrincipalID, idempotencyHash)
	var result DiscoveryResult
	var denied, unavailable bool
	writeErr := s.database.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		allowed, gateErr := s.actorGate(ctx, tx, access, policy.OperationSourceRegister)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			denied = true
			return nil
		}
		var connectionRevision int64
		var trustProfileHash string
		if err := tx.QueryRow(ctx, `SELECT connection_revision, trust_profile_hash
			FROM app.source_discovery_connection_target($1)`, request.ConnectionID).Scan(
			&connectionRevision, &trustProfileHash); err != nil {
			if database.IsNotFound(err) {
				unavailable = true
				return nil
			}
			return err
		}
		return tx.QueryRow(ctx, `
			SELECT request_id, job_id, created
			FROM app.source_discovery_request_enqueue($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			requestID, request.ConnectionID, connectionRevision, trustProfileHash,
			limits.MaxViews, limits.MaxColumns, limits.MaxCommentBytes,
			limits.StatementTimeout.Milliseconds(), limits.TransactionTimeout.Milliseconds(), idempotencyHash,
		).Scan(&result.RequestID, &result.JobID, &result.Created)
	})
	if writeErr != nil {
		switch database.SQLStateCode(writeErr) {
		case "42501":
			return DiscoveryResult{}, &Error{code: CodeDenied, cause: writeErr}
		case "23505":
			return DiscoveryResult{}, &Error{code: CodeConflict, cause: writeErr}
		case "55000":
			return DiscoveryResult{}, &Error{code: CodeUnavailable, cause: writeErr}
		default:
			return DiscoveryResult{}, &Error{code: CodePersistence, cause: writeErr}
		}
	}
	if denied {
		return DiscoveryResult{}, &Error{code: CodeDenied}
	}
	if unavailable {
		return DiscoveryResult{}, &Error{code: CodeUnavailable}
	}
	if !validGeneratedID(result.RequestID, "sdrq_") || !validGeneratedID(result.JobID, "sdrq_") {
		return DiscoveryResult{}, &Error{code: CodePersistence}
	}
	return result, nil
}

func normalizeDiscoveryLimits(limits postgresqlquery.DiscoveryLimits) (postgresqlquery.DiscoveryLimits, error) {
	if limits == (postgresqlquery.DiscoveryLimits{}) {
		limits = postgresqlquery.DefaultDiscoveryLimits()
	}
	if limits.ValidateDurable() != nil {
		return postgresqlquery.DiscoveryLimits{}, &Error{code: CodeRequestInvalid}
	}
	return limits, nil
}

func validIdempotencyKey(value string) bool {
	return len(value) >= 1 && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !containsControl(value)
}

// discoveryRequestID makes the application replay key agree with the
// database command's actor-scoped idempotency namespace without storing the
// raw key.
func discoveryRequestID(organizationID, actorPrincipalID, idempotencyHash string) string {
	return deriveID("sdrq", "source-discovery-request-v1\x00"+organizationID+"\x00"+actorPrincipalID+"\x00"+idempotencyHash)
}
