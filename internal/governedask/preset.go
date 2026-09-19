package governedask

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// PresetCatalog is the safe, SQL-free discovery response used by MCP clients.
type PresetCatalog struct {
	ConnectionID     string                        `json:"connection_id"`
	DatabaseIdentity string                        `json:"database_identity"`
	Presets          []governedquery.PresetSummary `json:"presets"`
}

// PresetRunResult is a live database observation with a durable governed-query
// attempt id and content-free hashes. It is intentionally not represented as
// retained document evidence: the result can change on the next execution.
type PresetRunResult struct {
	AttemptID             string                      `json:"attempt_id"`
	Preset                governedquery.PresetSummary `json:"preset"`
	SQLHash               string                      `json:"sql_hash"`
	Columns               []string                    `json:"columns"`
	Rows                  [][]*string                 `json:"rows"`
	RowCount              int                         `json:"row_count"`
	CostEstimate          float64                     `json:"cost_estimate"`
	ConnectionID          string                      `json:"connection_id"`
	DatabaseIdentity      string                      `json:"database_identity"`
	ExposedSchemaRevision int64                       `json:"exposed_schema_revision"`
	ResultFormat          string                      `json:"result_format"`
	ResultDigest          string                      `json:"result_digest"`
	ExecutionStartedAt    time.Time                   `json:"execution_started_at"`
	ExecutionCompletedAt  time.Time                   `json:"execution_completed_at"`
	DataState             string                      `json:"data_state"`
}

func (service *Service) HasPresets() bool {
	return service != nil && service.enabled && service.config.HasPresets()
}

// ListPresets rechecks current workspace access and the workspace's explicit
// live-query opt-in before disclosing the mounted catalogue. SQL text is never
// part of the response.
func (service *Service) ListPresets(ctx context.Context, access database.AccessContext, workspaceID, connectionID string) (PresetCatalog, error) {
	if service == nil || !service.enabled || !service.config.HasPresets() {
		return PresetCatalog{}, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || connectionID != service.config.ConnectionID {
		return PresetCatalog{}, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return PresetCatalog{}, err
	}
	enabled, err := service.liveQueriesEnabled(ctx, access, workspaceID)
	if err != nil {
		return PresetCatalog{}, err
	}
	if !enabled {
		return PresetCatalog{}, &Error{code: CodeLiveQueriesOff}
	}
	return PresetCatalog{ConnectionID: service.config.ConnectionID, DatabaseIdentity: service.config.DatabaseIdentity, Presets: service.config.PresetSummaries(workspaceID)}, nil
}

// ResolvePresetPhrase performs exact, case-insensitive phrase matching after
// whitespace normalization. It is discovery only; execution still requires a
// separate RunPreset call and repeats all authorization and opt-in checks.
func (service *Service) ResolvePresetPhrase(ctx context.Context, access database.AccessContext, workspaceID, phrase string) (governedquery.PresetSummary, bool, error) {
	if service == nil || !service.enabled || !service.config.HasPresets() {
		return governedquery.PresetSummary{}, false, nil
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return governedquery.PresetSummary{}, false, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return governedquery.PresetSummary{}, false, err
	}
	enabled, err := service.liveQueriesEnabled(ctx, access, workspaceID)
	if err != nil || !enabled {
		if err != nil {
			return governedquery.PresetSummary{}, false, err
		}
		return governedquery.PresetSummary{}, false, &Error{code: CodeLiveQueriesOff}
	}
	preset, ok := service.config.PresetByPhrase(workspaceID, phrase)
	if !ok {
		return governedquery.PresetSummary{}, false, nil
	}
	return preset.Summary(), true, nil
}

// RunPreset executes only the statement of the reviewed attempt referenced by
// the administrator mount. The mount and request contain no SQL, so a caller
// cannot widen the query.
func (service *Service) RunPreset(ctx context.Context, access database.AccessContext, workspaceID, connectionID, presetID string) (PresetRunResult, error) {
	if service == nil || !service.enabled || !service.config.HasPresets() {
		return PresetRunResult{}, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(presetID) {
		return PresetRunResult{}, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return PresetRunResult{}, err
	}
	var disclosed PresetRunResult
	_, admissionErr := service.withAdmission(ctx, access, workspaceID, func() (AskResult, error) {
		if connectionID != service.config.ConnectionID {
			_ = service.auditAttempt(ctx, access, workspaceID, 1, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			return AskResult{}, &Error{code: CodeConnectionUnavailable}
		}
		preset, ok := service.config.PresetByID(workspaceID, presetID)
		if !ok {
			_ = service.auditAttempt(ctx, access, workspaceID, 1, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			return AskResult{}, &Error{code: CodeRequestInvalid}
		}
		enabled, err := service.liveQueriesEnabled(ctx, access, workspaceID)
		if err != nil {
			return AskResult{}, err
		}
		if !enabled {
			return AskResult{}, &Error{code: CodeLiveQueriesOff}
		}
		schema, revision, err := service.loadExposedSchema(ctx, access, workspaceID)
		if err != nil {
			return AskResult{}, err
		}
		if schema == nil {
			_ = service.auditAttempt(ctx, access, workspaceID, 1, preset.SQLHash, audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			return AskResult{}, &Error{code: CodeSchemaUnavailable}
		}
		// The preset mount carries no SQL. Resolve only the already executed
		// source attempt of this workspace/connection, then pin all three review
		// anchors before re-executing: attempt id, SQL hash and schema revision.
		sourceAttempt, loadErr := service.loadExecutedAttempt(ctx, access, workspaceID, preset.SourceAttemptID)
		if loadErr != nil || !preset.Binds(sourceAttempt) || revision != preset.ExposedSchemaRevision {
			_ = service.auditAttempt(ctx, access, workspaceID, revision, preset.SQLHash, audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
			return AskResult{}, &Error{code: CodeRequestInvalid, cause: loadErr}
		}
		result, attempt, execErr := governedquery.Execute(ctx, service.config, governedquery.ExecuteParams{SQLText: sourceAttempt.SQLText, ExposedSchemaRevision: revision})
		auditErr := service.auditAttempt(ctx, access, workspaceID, revision, attempt.SQLHash, string(attempt.Outcome), costPointer(attempt), rowCountPointer(attempt), digestPointer(attempt))
		if execErr != nil {
			return AskResult{}, &Error{code: CodeExecutionFailed, cause: execErr}
		}
		if auditErr != nil {
			return AskResult{}, &Error{code: CodeUnavailable, cause: auditErr}
		}
		attemptID, recordErr := service.recordExecutedAttempt(ctx, access, workspaceID, revision, sourceAttempt.SQLText, attempt.SQLHash, result.RowCount)
		if recordErr != nil {
			return AskResult{}, recordErr
		}
		disclosed = PresetRunResult{
			AttemptID: attemptID, Preset: preset.Summary(), SQLHash: attempt.SQLHash,
			Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount, CostEstimate: result.CostEstimate,
			ConnectionID: service.config.ConnectionID, DatabaseIdentity: service.config.DatabaseIdentity,
			ExposedSchemaRevision: revision, ResultFormat: "postgres-text-table-v1", ResultDigest: attempt.ResultDigest,
			ExecutionStartedAt: result.ExecutionStartedAt, ExecutionCompletedAt: result.ExecutionCompletedAt, DataState: "LIVE_OBSERVATION",
		}
		return AskResult{}, nil
	})
	if admissionErr != nil {
		// An execution failure already carries the governed outcome audit. The
		// admission event remains the required pre-read receipt.
		if CodeOf(admissionErr) == CodeLiveQueriesOff {
			_ = service.auditAttempt(ctx, access, workspaceID, 1, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil)
		}
		return PresetRunResult{}, admissionErr
	}
	return disclosed, nil
}
