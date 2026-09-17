package audit

// The ADR-0089 governed model-authored SQL audit contract. Every attempt --
// success and every rejection kind -- appends exactly one
// source.governed_query_attempted event carrying the exposed-schema
// revision, a content-free hash of the exact SQL text, the EXPLAIN cost
// estimate, row count, a content-free result digest and a closed outcome
// code. Row values, the SQL text itself and any raw database error never
// appear here (ADR-0089 §4, mirroring MOD-007/MOD-008's content-free
// discipline for model-gateway attempts).

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
		metadata.GovernedQueryOutcome != nil
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
