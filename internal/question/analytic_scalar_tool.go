package question

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const analyticScalarToolName = "knowvault_analyze"

// analyticScalarToolDefinition exposes only the safe, business-semantic
// dataset projections retained by the capability. The schema is the closed
// ProposalV2 aggregate arm; the capability remains the authority for exact
// profile, measure and period validation at invocation time.
func analyticScalarToolDefinition(cap analyticScalarCapability) (modelgateway.ToolDefinition, error) {
	profiles := cap.modelProfiles()
	if len(profiles) == 0 {
		return modelgateway.ToolDefinition{}, &Error{code: CodeInvalid}
	}

	var description strings.Builder
	description.WriteString("v1: answer one exact numeric question with one approved read-only scalar aggregate. This scalar can be one step in a mixed document-and-data question; use document tools and citations for document claims. Use only the approved dataset/profile/hash, measures and filter fields below; provide an explicit half-open period [start,end) and exactly one EQ predicate for every filter listed by the selected profile. Do not omit or duplicate a listed filter. Use empty dimensions/sort, limit 1, and VALUE output. Dates use YYYY-MM-DD. For one day, for example 2026-09-10, use start=2026-09-10 and end=2026-09-11.\n\nApproved profiles:\n")
	for _, profile := range profiles {
		fmt.Fprintf(&description, "- %s (dataset_id=%s, profile_version=%d, profile_hash=%s): %s\n", profile.DatasetLabel, profile.DatasetID, profile.ProfileVersion, profile.ProfileHash, profile.DatasetDescription)
		for _, measure := range profile.Measures {
			fmt.Fprintf(&description, "  measure %s: %s (%s; unit=%s)\n", measure.ID, measure.Description, measure.Reducer, measure.Unit)
		}
		for _, field := range profile.Fields {
			if field.Token != profile.Time.FieldToken && field.Filterable && slices.Contains(field.AllowedOperators, "EQ") {
				fmt.Fprintf(&description, "  filter %s: %s (%s; type=%s; operator=EQ", field.Token, field.Description, field.Label, field.LogicalType)
				if len(field.AllowedValues) > 0 {
					fmt.Fprintf(&description, "; allowed_values=%s", strings.Join(field.AllowedValues, ","))
				}
				description.WriteString(")\n")
			}
		}
		fmt.Fprintf(&description, "  period: %s, reporting timezone %s, calendar %s\n", profile.Time.Kind, profile.Time.ReportingTimezone, profile.Time.Calendar)
	}

	schema := json.RawMessage(`{
  "type":"object",
  "additionalProperties":false,
  "required":["schema_version","operation","dataset","period","filters","sort","limit","measure","dimensions","output"],
  "properties":{
    "schema_version":{"const":"queryintent-proposal-v2"},
    "operation":{"const":"AGGREGATE"},
    "dataset":{
      "type":"object",
      "additionalProperties":false,
      "required":["dataset_id","profile_version","expected_profile_hash"],
      "properties":{
        "dataset_id":{"type":"string","minLength":1},
        "profile_version":{"type":"integer","minimum":1},
        "expected_profile_hash":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"}
      }
    },
    "period":{
      "type":"object",
      "additionalProperties":false,
      "required":["mode","start","end"],
      "properties":{
        "mode":{"const":"EXPLICIT"},
		"start":{"type":"string","format":"date","description":"Inclusive start in YYYY-MM-DD."},
		"end":{"type":"string","format":"date","description":"Exclusive end in YYYY-MM-DD. For one day, use the following date."}
      }
    },
	"filters":{},
    "sort":{"const":[]},
    "limit":{"const":1},
    "measure":{"type":"string","minLength":1},
    "dimensions":{"const":[]},
    "output":{"const":"VALUE"}
  }
}`)
	var schemaDocument map[string]any
	if err := json.Unmarshal(schema, &schemaDocument); err != nil {
		return modelgateway.ToolDefinition{}, &Error{code: CodeInvalid}
	}
	properties, ok := schemaDocument["properties"].(map[string]any)
	if !ok {
		return modelgateway.ToolDefinition{}, &Error{code: CodeInvalid}
	}
	properties["filters"] = analyticScalarFilterSchema(profiles)
	encodedSchema, err := json.Marshal(schemaDocument)
	if err != nil {
		return modelgateway.ToolDefinition{}, &Error{code: CodeInvalid}
	}
	schema = json.RawMessage(encodedSchema)
	return modelgateway.ToolDefinition{
		Type: "function",
		Function: modelgateway.ToolFunction{
			Name:        analyticScalarToolName,
			Description: description.String(),
			Parameters:  schema,
		},
	}, nil
}

// analyticScalarFilterSchema advertises only the model-facing fields that an
// approved profile marks filterable with EQ. The frozen proposal validator is
// still authoritative, including the binding between a selected dataset and
// its own fields; this schema prevents the model from inventing a field,
// operator, scalar kind or value shape before that boundary.
func analyticScalarFilterSchema(profiles []modelDatasetProfile) map[string]any {
	type mergedField struct {
		field        modelDatasetProfileField
		unrestricted bool
		allowed      map[string]struct{}
	}
	merged := make(map[string]*mergedField)
	orderedKeys := make([]string, 0)
	minRequired := -1
	maxRequired := 0
	for _, profile := range profiles {
		required := 0
		for _, field := range profile.Fields {
			if field.Token == profile.Time.FieldToken || !field.Filterable || !slices.Contains(field.AllowedOperators, "EQ") {
				continue
			}
			required++
			switch field.LogicalType {
			case "BOOL", "INT", "NUMERIC", "TEXT", "DATE", "TIMESTAMP", "TIMESTAMPTZ":
			default:
				continue
			}
			key := field.Token + "\x00" + field.LogicalType
			entry, duplicate := merged[key]
			if duplicate {
				if len(field.AllowedValues) == 0 {
					entry.unrestricted = true
					entry.allowed = nil
				} else if !entry.unrestricted {
					for _, allowed := range field.AllowedValues {
						entry.allowed[allowed] = struct{}{}
					}
				}
				continue
			}
			entry = &mergedField{field: field, unrestricted: len(field.AllowedValues) == 0}
			if !entry.unrestricted {
				entry.allowed = make(map[string]struct{}, len(field.AllowedValues))
				for _, allowed := range field.AllowedValues {
					entry.allowed[allowed] = struct{}{}
				}
			}
			merged[key] = entry
			orderedKeys = append(orderedKeys, key)
		}
		if minRequired < 0 || required < minRequired {
			minRequired = required
		}
		if required > maxRequired {
			maxRequired = required
		}
	}

	branches := make([]any, 0, len(orderedKeys))
	for _, key := range orderedKeys {
		entry := merged[key]
		field := entry.field
		valueType := "string"
		switch field.LogicalType {
		case "BOOL":
			valueType = "boolean"
		case "INT":
			valueType = "integer"
		}
		valueSchema := map[string]any{"type": valueType}
		if !entry.unrestricted {
			allowedValues := make([]string, 0, len(entry.allowed))
			for allowed := range entry.allowed {
				allowedValues = append(allowedValues, allowed)
			}
			slices.Sort(allowedValues)
			valueSchema["enum"] = allowedValues
		}
		branches = append(branches, map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []string{"field", "op", "values"},
			"properties": map[string]any{
				"field": map[string]any{"const": field.Token},
				"op":    map[string]any{"const": "EQ"},
				"values": map[string]any{
					"type": "array", "minItems": 1, "maxItems": 1,
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"kind", "value"},
						"properties": map[string]any{
							"kind":  map[string]any{"const": field.LogicalType},
							"value": valueSchema,
						},
					},
				},
			},
		})
	}
	items := any(map[string]any{"type": "object", "additionalProperties": false})
	if len(branches) > 0 {
		items = map[string]any{"oneOf": branches}
	}
	if minRequired < 0 {
		minRequired = 0
	}
	return map[string]any{
		"type":        "array",
		"minItems":    minRequired,
		"maxItems":    maxRequired,
		"uniqueItems": true,
		"items":       items,
	}
}

// invokeAnalyticScalarTool is the sole Question-side invocation boundary. It
// never returns model text, SQL, source details or an executor error. Success
// is a safe JSON projection of the sealed observation; every refusal is the
// same content-free JSON error and has no pair.
func (service *Service) invokeAnalyticScalarTool(
	ctx context.Context,
	access database.AccessContext,
	workspaceID, runID string,
	cap analyticScalarCapability,
	raw json.RawMessage,
) (workspacetools.Result, *analyticScalarPair) {
	failure := func() (workspacetools.Result, *analyticScalarPair) {
		payload := json.RawMessage(`{"error":"ANALYTIC_SCALAR_UNAVAILABLE"}`)
		return workspacetools.Result{Text: string(payload), Structured: payload, IsError: true}, nil
	}
	if service == nil || service.analyticScalarExecutor == nil || ctx == nil ||
		!validOpaque(workspaceID) || !validOpaque(runID) {
		return failure()
	}
	intent, _, err := cap.validateProposal(raw)
	if err != nil {
		return failure()
	}
	read, err := service.analyticScalarExecutor.Execute(ctx, access, workspaceID, intent)
	if err != nil {
		return failure()
	}
	observation, err := analyticsource.CompleteScalarRead(read)
	if err != nil {
		return failure()
	}
	pair, err := newAnalyticScalarPairFrom(runID, observation)
	if err != nil {
		return failure()
	}
	values, ok := observation.Values()
	if !ok {
		return failure()
	}
	payload, err := json.Marshal(values)
	if err != nil || len(payload) == 0 || !json.Valid(payload) {
		return failure()
	}
	owned := json.RawMessage(append([]byte(nil), payload...))
	return workspacetools.Result{Text: string(owned), Structured: owned}, &pair
}

// analyticScalarPresentation renders the same server-owned answer shape in
// Russian for Cyrillic questions and in English otherwise. It copies only the
// validated observation into AnswerResult; observation timing and receipt
// digest are provenance fields and never become claims about source freshness.
func analyticScalarPresentation(questionText string, observation analyticScalarObservation) (string, *AnswerResult, error) {
	if !observation.valid() {
		return "", nil, &Error{code: CodeInvalid}
	}
	ru := containsCyrillic(questionText)
	start, err := time.Parse("2006-01-02", observation.PeriodStart)
	if err != nil {
		return "", nil, &Error{code: CodeInvalid}
	}
	end, err := time.Parse("2006-01-02", observation.PeriodEndExclusive)
	if err != nil || !end.After(start) {
		return "", nil, &Error{code: CodeInvalid}
	}
	endInclusive := end.AddDate(0, 0, -1)
	label := analyticScalarDateLabel(start, endInclusive, ru)
	result := &AnswerResult{
		Kind:      "CALCULATION",
		Value:     observation.Value,
		Unit:      observation.MetricUnit,
		Operation: observation.MetricReducer,
		Rule:      analyticScalarRule(observation.MetricID, ru),
		Period: &AnswerPeriod{
			From:  observation.PeriodStart,
			To:    endInclusive.Format("2006-01-02"),
			Label: label,
		},
		Timezone:     observation.PeriodReportingTimezone,
		Snapshot:     AnswerSnapshot{RowCount: int(observation.ContributingRows)},
		Completeness: "COMPLETE",
		ObservationWindow: &AnswerObservationWindow{
			Basis:       observation.WindowBasis,
			StartedAt:   observation.ObservedStartedAt,
			CompletedAt: observation.ObservedCompletedAt,
		},
		ReceiptDigest: observation.ReceiptDigest,
	}
	result.ResultDigest = canonicalResultDigest(result)
	if ru {
		return "\u0418\u0442\u043e\u0433\u043e: " + observation.Value + " " + observation.MetricUnit + " \u0437\u0430 " + label + ".", result, nil
	}
	return "Total: " + observation.Value + " " + observation.MetricUnit + " for " + label + ".", result, nil
}

func containsCyrillic(value string) bool {
	for _, character := range value {
		if unicode.Is(unicode.Cyrillic, character) {
			return true
		}
	}
	return false
}

func analyticScalarRule(metricID string, russian bool) string {
	if russian {
		return "\u0441\u0443\u043c\u043c\u0430 \u0443\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u043e\u0439 \u043c\u0435\u0442\u0440\u0438\u043a\u0438 \u00ab" + metricID + "\u00bb"
	}
	return "sum of approved measure «" + metricID + "»"
}

func analyticScalarDateLabel(start, end time.Time, russian bool) string {
	if start.Equal(end) {
		if russian {
			return fmt.Sprintf("%d %s %d \u0433\u043e\u0434\u0430", start.Day(), russianMonth(start.Month()), start.Year())
		}
		return fmt.Sprintf("%s %d, %d", englishMonth(start.Month()), start.Day(), start.Year())
	}
	if russian {
		return fmt.Sprintf("%d %s %d \u0433\u043e\u0434\u0430 \u2014 %d %s %d \u0433\u043e\u0434\u0430", start.Day(), russianMonth(start.Month()), start.Year(), end.Day(), russianMonth(end.Month()), end.Year())
	}
	return fmt.Sprintf("%s %d, %d through %s %d, %d", englishMonth(start.Month()), start.Day(), start.Year(), englishMonth(end.Month()), end.Day(), end.Year())
}

func russianMonth(month time.Month) string {
	return [...]string{"", "\u044f\u043d\u0432\u0430\u0440\u044f", "\u0444\u0435\u0432\u0440\u0430\u043b\u044f", "\u043c\u0430\u0440\u0442\u0430", "\u0430\u043f\u0440\u0435\u043b\u044f", "\u043c\u0430\u044f", "\u0438\u044e\u043d\u044f", "\u0438\u044e\u043b\u044f", "\u0430\u0432\u0433\u0443\u0441\u0442\u0430", "\u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f", "\u043e\u043a\u0442\u044f\u0431\u0440\u044f", "\u043d\u043e\u044f\u0431\u0440\u044f", "\u0434\u0435\u043a\u0430\u0431\u0440\u044f"}[month]
}

func englishMonth(month time.Month) string {
	return [...]string{"", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}[month]
}
