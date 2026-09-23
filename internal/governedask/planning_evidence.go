package governedask

import (
	"sort"
	"strconv"

	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// Called after admission and exposed-schema loading. Every calendar remains
// bound to its metric/relation/filters and the current connection and schema.
func (service *Service) planningEvidence(workspaceID string, schema governedquery.ExposedSchema) ([]modelgateway.Evidence, error) {
	evidence, err := schemaEvidence(schema)
	if err != nil {
		return nil, err
	}
	service.comparisonMu.RLock()
	defer service.comparisonMu.RUnlock()
	profiles := make([]metriccompare.Profile, 0)
	for _, binding := range service.comparisonProfiles[workspaceID] {
		if binding.connectionID == service.config.ConnectionID && binding.databaseIdentity == service.config.DatabaseIdentity &&
			metriccompare.ValidateAgainstExposedSchema(binding.profile, comparisonSchema(schema)) == nil {
			profiles = append(profiles, binding.profile)
		}
	}
	if len(profiles) > 32 {
		return nil, &Error{code: CodeRequestInvalid}
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].MetricID() < profiles[j].MetricID() })
	for index, profile := range profiles {
		text := "Operator-confirmed metric semantics; applies only to the exact relation and filters below:\n" + profile.PlanningEvidence()
		id := "gqmetric-" + strconv.Itoa(index+1)
		hash := canon.Hash([]byte(text))
		evidence = append(evidence, modelgateway.Evidence{
			ID: id, SourceObjectID: id, SourceVersionID: id, ExtractionID: id,
			TextHash: hash, AnchorHash: hash, Text: text,
		})
	}
	return evidence, nil
}
