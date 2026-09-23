package governedask

import (
	"context"
	"reflect"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// MetricComparisonResult joins the verified business projection to the live
// observation and its governed-query receipt. No result is retained as a
// document or treated as evidence from a previous execution.
type MetricComparisonResult struct {
	Ask        AskResult                `json:"ask"`
	Comparison metriccompare.Comparison `json:"comparison"`
}

type comparisonBinding struct {
	profile          metriccompare.Profile
	connectionID     string
	databaseIdentity string
}

// EnableMetricComparison mounts one operator-sealed profile. It does not read
// a schema or execute SQL; CompareWorkspace checks the current exposed schema
// and its exact revision for every request. Configuration belongs to startup,
// while CompareWorkspace may run concurrently.
func (service *Service) EnableMetricComparison(workspaceID string, profile metriccompare.Profile) error {
	if service == nil || !service.enabled || !validOpaque(service.config.ConnectionID) ||
		!validOpaque(service.config.DatabaseIdentity) || !validOpaque(workspaceID) || profile.Hash() == "" ||
		profile.MetricID() == "" {
		return &Error{code: CodeRequestInvalid}
	}
	service.comparisonMu.Lock()
	defer service.comparisonMu.Unlock()
	if service.comparisonProfiles == nil {
		service.comparisonProfiles = make(map[string]map[string]comparisonBinding)
	}
	if service.comparisonProfiles[workspaceID] == nil {
		service.comparisonProfiles[workspaceID] = make(map[string]comparisonBinding)
	}
	if existing, present := service.comparisonProfiles[workspaceID][profile.MetricID()]; present &&
		(existing.profile.Hash() != profile.Hash() || existing.connectionID != service.config.ConnectionID ||
			existing.databaseIdentity != service.config.DatabaseIdentity) {
		return &Error{code: CodeRequestInvalid}
	}
	service.comparisonProfiles[workspaceID][profile.MetricID()] = comparisonBinding{
		profile: profile, connectionID: service.config.ConnectionID, databaseIdentity: service.config.DatabaseIdentity,
	}
	return nil
}

func (service *Service) comparisonProfile(workspaceID, metricID string) (metriccompare.Profile, bool) {
	service.comparisonMu.RLock()
	defer service.comparisonMu.RUnlock()
	binding, ok := service.comparisonProfiles[workspaceID][metricID]
	if !ok || binding.connectionID != service.config.ConnectionID ||
		binding.databaseIdentity != service.config.DatabaseIdentity {
		return metriccompare.Profile{}, false
	}
	return binding.profile, true
}

// CompareWorkspace accepts only a registered metric identifier and two dates.
// The statement comes solely from the sealed operator profile. It passes
// through the same workspace, opt-in, read-only executor, audit, and disclosure
// gates as Ask; malformed or incomplete aggregates cannot reach the caller.
func (service *Service) CompareWorkspace(ctx context.Context, access database.AccessContext, workspaceID, metricID, firstDate, secondDate string) (MetricComparisonResult, error) {
	if service == nil || !service.enabled {
		return MetricComparisonResult{}, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || metricID == "" || len(metricID) > 128 {
		return MetricComparisonResult{}, &Error{code: CodeRequestInvalid}
	}
	if err := service.authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return MetricComparisonResult{}, err
	}
	var compared MetricComparisonResult
	var admittedProfile metriccompare.Profile
	var admittedProfileFound bool
	_, err := service.withAdmission(ctx, access, workspaceID, func() (AskResult, error) {
		admittedProfile, admittedProfileFound = service.comparisonProfile(workspaceID, metricID)
		if !admittedProfileFound {
			return AskResult{}, service.rejectComparison(ctx, access, workspaceID, 0, "", CodeRequestInvalid, nil)
		}
		// Compile validates both dates before any governed schema or data read.
		compiled, compileErr := metriccompare.Compile(admittedProfile, firstDate, secondDate)
		if compileErr != nil {
			return AskResult{}, service.rejectComparison(ctx, access, workspaceID, 0, "", CodeRequestInvalid, compileErr)
		}
		enabled, enabledErr := service.liveQueriesEnabled(ctx, access, workspaceID)
		if enabledErr != nil {
			return AskResult{}, enabledErr
		}
		if !enabled {
			return AskResult{}, service.rejectComparison(ctx, access, workspaceID, 0, "", CodeLiveQueriesOff, nil)
		}
		schema, revision, schemaErr := service.loadExposedSchema(ctx, access, workspaceID)
		if schemaErr != nil {
			return AskResult{}, schemaErr
		}
		if schema == nil {
			return AskResult{}, service.rejectComparison(ctx, access, workspaceID, 0, "", CodeSchemaUnavailable, nil)
		}
		if validationErr := metriccompare.ValidateAgainstExposedSchema(admittedProfile, comparisonSchema(*schema)); validationErr != nil {
			return AskResult{}, service.rejectComparison(ctx, access, workspaceID, revision, "", CodeSchemaUnavailable, validationErr)
		}
		result, attempt, executeErr := governedquery.Execute(ctx, service.config, governedquery.ExecuteParams{
			SQLText: compiled.SQL, ExposedSchemaRevision: revision,
		})
		auditErr := service.auditAttempt(ctx, access, workspaceID, revision, attempt.SQLHash,
			string(attempt.Outcome), costPointer(attempt), rowCountPointer(attempt), digestPointer(attempt))
		if executeErr != nil {
			if auditErr != nil {
				return AskResult{}, &Error{code: CodeUnavailable, cause: auditErr}
			}
			return AskResult{}, &Error{code: CodeExecutionFailed, cause: executeErr}
		}
		if auditErr != nil {
			return AskResult{}, &Error{code: CodeUnavailable, cause: auditErr}
		}
		// The operator may replace the exposed schema while the external read
		// runs. Re-read the control plane before any result or saved-attempt
		// disclosure, and refuse both revision and in-place schema drift.
		currentSchema, currentRevision, currentErr := service.loadExposedSchema(ctx, access, workspaceID)
		if currentErr != nil {
			return AskResult{}, currentErr
		}
		currentProfile, profileFound := service.comparisonProfile(workspaceID, metricID)
		if currentSchema == nil || currentRevision != revision || !reflect.DeepEqual(*schema, *currentSchema) ||
			!profileFound || currentProfile.Hash() != admittedProfile.Hash() ||
			metriccompare.ValidateAgainstExposedSchema(admittedProfile, comparisonSchema(*currentSchema)) != nil {
			return AskResult{}, &Error{code: CodeSchemaUnavailable}
		}
		var disclosureErr error
		compared, disclosureErr = service.discloseComparison(ctx, access, workspaceID, revision, compiled.SQL,
			attempt, result, auditErr, admittedProfile, firstDate, secondDate)
		return compared.Ask, disclosureErr
	})
	if err != nil {
		return MetricComparisonResult{}, err
	}
	return compared, nil
}

// discloseComparison enforces the outcome-audit and exact result-shape gates
// before the existing reauthorization and saved-attempt disclosure gate.
func (service *Service) discloseComparison(ctx context.Context, access database.AccessContext,
	workspaceID string, revision int64, sqlText string, attempt governedquery.Attempt,
	result governedquery.QueryResult, auditErr error, profile metriccompare.Profile,
	firstDate, secondDate string,
) (MetricComparisonResult, error) {
	if auditErr != nil {
		return MetricComparisonResult{}, &Error{code: CodeUnavailable, cause: auditErr}
	}
	comparison, err := metriccompare.ParseResult(metriccompare.TableResult{
		Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount,
	}, firstDate, secondDate, profile)
	if err != nil {
		return MetricComparisonResult{}, &Error{code: CodeExecutionFailed, cause: err}
	}
	ask, err := service.discloseExecutedAttempt(ctx, access, workspaceID, revision, sqlText, attempt, result, nil)
	if err != nil {
		return MetricComparisonResult{}, err
	}
	return MetricComparisonResult{Ask: ask, Comparison: comparison}, nil
}

func comparisonSchema(schema governedquery.ExposedSchema) metriccompare.Schema {
	projection := metriccompare.Schema{Revision: schema.Revision, Objects: make([]metriccompare.SchemaObject, 0, len(schema.Objects))}
	for _, object := range schema.Objects {
		item := metriccompare.SchemaObject{
			SchemaName: object.SchemaName, TableName: object.TableName,
			Columns: make([]metriccompare.SchemaColumn, 0, len(object.Columns)),
		}
		for _, column := range object.Columns {
			item.Columns = append(item.Columns, metriccompare.SchemaColumn{Name: column.Name, DataType: column.DataType})
		}
		projection.Objects = append(projection.Objects, item)
	}
	return projection
}

func (service *Service) rejectComparison(ctx context.Context, access database.AccessContext, workspaceID string, revision int64, sqlHash string, code ErrorCode, cause error) error {
	if err := service.auditAttempt(ctx, access, workspaceID, revision, sqlHash, audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil); err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	return &Error{code: code, cause: cause}
}
