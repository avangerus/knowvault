package audit

// The ADR-0089 governed model-authored SQL audit contract. Every attempt --
// success and every rejection kind -- appends exactly one
// source.governed_query_attempted event carrying the exposed-schema
// revision, a content-free hash of the exact SQL text, the EXPLAIN cost
// estimate, row count, a content-free result digest and a closed outcome
// code. Row values, the SQL text itself and any raw database error never
// appear here (ADR-0089 §4, mirroring MOD-007/MOD-008's content-free
// discipline for model-gateway attempts).

import (
	"context"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// ActionGovernedQueryAttempted is the one action this vocabulary reserves.
const ActionGovernedQueryAttempted Action = "source.governed_query_attempted"

// ResourceGovernedQueryAttempt is the one resource type this vocabulary
// reserves. resource_id is the content-free SQL hash of the attempted
// statement, so repeated identical attempts share one provenance anchor
// without ever naming a database row.
const ResourceGovernedQueryAttempt ResourceType = "GOVERNED_QUERY_ATTEMPT"

// The closed governed-query outcome vocabulary (ADR-0089 §4/§6). It mirrors
// internal/source/postgresqlquery/governedquery.Outcome exactly; the two
// must be kept in sync.
const (
	GovernedQueryOutcomeSucceeded         = "SUCCEEDED"
	GovernedQueryOutcomeRejectedStatic    = "REJECTED_STATIC"
	GovernedQueryOutcomeRejectedDatabase  = "REJECTED_DATABASE"
	GovernedQueryOutcomeTimeout           = "TIMEOUT"
	GovernedQueryOutcomeRowLimitExceeded  = "ROW_LIMIT_EXCEEDED"
	GovernedQueryOutcomeCostLimitExceeded = "COST_LIMIT_EXCEEDED"
)

func validGovernedQueryOutcome(value string) bool {
	switch value {
	case GovernedQueryOutcomeSucceeded, GovernedQueryOutcomeRejectedStatic, GovernedQueryOutcomeRejectedDatabase,
		GovernedQueryOutcomeTimeout, GovernedQueryOutcomeRowLimitExceeded, GovernedQueryOutcomeCostLimitExceeded:
		return true
	default:
		return false
	}
}

// isGovernedQueryAction reports whether the action belongs to this contract.
// The action/resource pair is one-to-one, mirroring the authority/rotation
// rule: neither may ever appear without the other.
func isGovernedQueryAction(action Action) bool {
	return action == ActionGovernedQueryAttempted
}

// hasGovernedQueryMetadata reports whether any governed-query-only field is
// set. The vocabulary is reserved: a non-governed-query event may never
// carry it.
func hasGovernedQueryMetadata(metadata Metadata) bool {
	return metadata.GovernedQueryConnectionID != nil || metadata.GovernedQueryExposedSchemaRevision != nil ||
		metadata.GovernedQuerySQLHash != nil || metadata.GovernedQueryCostEstimate != nil ||
		metadata.GovernedQueryRowCount != nil || metadata.GovernedQueryResultDigest != nil ||
		metadata.GovernedQueryOutcome != nil || metadata.GovernedQueryPurpose != nil
}

// validGovernedQueryMetadataFields checks field-level shape only. Which
// fields may be present at all is decided by validGovernedQueryProjection.
func validGovernedQueryMetadataFields(metadata Metadata) bool {
	if metadata.GovernedQueryConnectionID != nil && !validID(*metadata.GovernedQueryConnectionID) {
		return false
	}
	if metadata.GovernedQueryExposedSchemaRevision != nil &&
		(*metadata.GovernedQueryExposedSchemaRevision < 1 || *metadata.GovernedQueryExposedSchemaRevision > maxSafeInt64) {
		return false
	}
	if metadata.GovernedQuerySQLHash != nil && !validHash(*metadata.GovernedQuerySQLHash) {
		return false
	}
	if metadata.GovernedQueryCostEstimate != nil && (*metadata.GovernedQueryCostEstimate < 0 || *metadata.GovernedQueryCostEstimate > maxSafeInt64) {
		return false
	}
	if metadata.GovernedQueryRowCount != nil && (*metadata.GovernedQueryRowCount < 0 || *metadata.GovernedQueryRowCount > maxSafeInt64) {
		return false
	}
	if metadata.GovernedQueryResultDigest != nil && !validHash(*metadata.GovernedQueryResultDigest) {
		return false
	}
	if metadata.GovernedQueryOutcome != nil && !validGovernedQueryOutcome(*metadata.GovernedQueryOutcome) {
		return false
	}
	if metadata.GovernedQueryPurpose != nil && !validGovernedQueryPurpose(*metadata.GovernedQueryPurpose) {
		return false
	}
	return true
}

// validGovernedQueryPurpose bounds the one free-form governed-query field. It
// is at most 200 bytes of valid UTF-8 with no control character other than tab
// and newline, exactly the envelope the transport already accepts; it can never
// carry SQL text because SQL is rejected by the static pre-check and hashed
// separately.
func validGovernedQueryPurpose(value string) bool {
	if len(value) > 200 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 && character != '\n' && character != '\t' {
			return false
		}
	}
	return true
}

// validGovernedQueryProjection is the Go half of the governed-query audit
// contract: the action/resource pairing is closed, every attempt names its
// workspace, connection, exposed-schema revision, SQL hash and outcome, and
// the resource_id is exactly the SQL hash -- content-free provenance, never
// a database row identifier.
func validGovernedQueryProjection(input EventInput) bool {
	known := isGovernedQueryAction(input.Action)
	if known != (input.ResourceType == ResourceGovernedQueryAttempt) {
		return false
	}
	if !known {
		return true
	}
	if input.WorkspaceID == nil || (input.ActorType != ActorHuman && input.ActorType != ActorService) {
		return false
	}
	metadata := input.Metadata
	if metadata.GovernedQueryConnectionID == nil || metadata.GovernedQueryExposedSchemaRevision == nil ||
		metadata.GovernedQuerySQLHash == nil || metadata.GovernedQueryOutcome == nil ||
		input.ResourceID != *metadata.GovernedQuerySQLHash {
		return false
	}
	// A successful attempt has proven a cost, row count and result digest;
	// every rejection kind may carry whichever of those three it reached
	// before failing (e.g. a cost-limit rejection still names its cost
	// estimate, a static rejection names none of them) but never more than
	// these three plus the four always-required fields.
	if *metadata.GovernedQueryOutcome == GovernedQueryOutcomeSucceeded &&
		(metadata.GovernedQueryCostEstimate == nil || metadata.GovernedQueryRowCount == nil || metadata.GovernedQueryResultDigest == nil) {
		return false
	}
	return true
}

// GovernedQueryAttemptMatches reports whether one persisted successful
// source.governed_query_attempted event is exactly the content-free identity a
// stored source-SQL receipt names (card S3.2d R6): the same organization (RLS),
// workspace, connection, SQL hash and result digest. It reads no row and
// returns no content; a missing or mismatched event is simply false, which the
// caller turns into its content-free not-found.
func (store *Store) GovernedQueryAttemptMatches(ctx context.Context, access database.AccessContext, workspaceID, eventID, connectionID, sqlHash, resultDigest string) (bool, error) {
	if store == nil || store.database == nil || access.Validate() != nil || ctx == nil ||
		!validID(workspaceID) || !validID(eventID) || !validID(connectionID) ||
		!validHash(sqlHash) || !validHash(resultDigest) {
		return false, &Error{code: CodeInvalidEvent}
	}
	matched := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		return transaction.QueryRow(transactionContext, `
			SELECT EXISTS (
			    SELECT 1
			    FROM public.audit_event AS event
			    WHERE event.id = $1
			      AND event.workspace_id = $2
			      AND event.action = 'source.governed_query_attempted'
			      AND event.outcome = 'SUCCESS'
			      AND event.metadata_json->>'governed_query_connection_id' = $3
			      AND event.metadata_json->>'governed_query_sql_hash' = $4
			      AND event.metadata_json->>'governed_query_result_digest' = $5
			)`, eventID, workspaceID, connectionID, sqlHash, resultDigest).Scan(&matched)
	})
	if err != nil {
		return false, &Error{code: CodeAppendFailed, cause: err}
	}
	return matched, nil
}
