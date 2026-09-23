package question

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const trustedMetricToolName = "knowvault_compare_metric"

// TrustedMetricComparison is kept separate from ad hoc GovernedAsk. The model
// chooses only a catalogued metric and dates; it never supplies SQL or a table.
type TrustedMetricComparison interface {
	ComparisonCatalog(context.Context, database.AccessContext, string) ([]governedask.ComparisonSummary, error)
	CompareWorkspace(context.Context, database.AccessContext, string, string, string, string) (governedask.MetricComparisonResult, error)
}

type metricToolArguments struct {
	MetricID string `json:"metric_id"`
	DateA    string `json:"date_a"`
	DateB    string `json:"date_b"`
}

type metricToolDay struct {
	Date             string `json:"date"`
	SnapshotAt       string `json:"snapshot_at"`
	Value            string `json:"value"`
	ContributingRows int64  `json:"contributing_rows"`
	DistinctSubjects int64  `json:"distinct_subjects"`
}

type metricToolResult struct {
	MetricID      string        `json:"metric_id"`
	Unit          string        `json:"unit"`
	Coverage      string        `json:"coverage"`
	First         metricToolDay `json:"first"`
	Second        metricToolDay `json:"second"`
	Delta         string        `json:"delta"`
	PercentChange string        `json:"percent_change"`
	AttemptID     string        `json:"attempt_id"`
	ReceiptDigest string        `json:"receipt_digest"`
}

func trustedMetricToolDefinition(catalog []governedask.ComparisonSummary) (modelgateway.ToolDefinition, bool) {
	if len(catalog) == 0 {
		return modelgateway.ToolDefinition{}, false
	}
	ids := make([]string, 0, len(catalog))
	labels := make([]string, 0, len(catalog))
	for _, item := range catalog {
		if !validGovernedID(item.MetricID) || !utf8.ValidString(item.Unit) || !utf8.ValidString(item.Description) ||
			len(item.Unit) > 128 || len(item.Description) > 512 {
			return modelgateway.ToolDefinition{}, false
		}
		ids = append(ids, item.MetricID)
		labels = append(labels, item.MetricID+" (unit: "+item.Unit+"): "+item.Description)
	}
	schema, err := json.Marshal(map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"metric_id", "date_a", "date_b"},
		"properties": map[string]any{
			"metric_id": map[string]any{"type": "string", "enum": ids},
			"date_a":    map[string]any{"type": "string", "description": "First date, YYYY-MM-DD"},
			"date_b":    map[string]any{"type": "string", "description": "Second date, YYYY-MM-DD"},
		},
	})
	if err != nil {
		return modelgateway.ToolDefinition{}, false
	}
	return modelgateway.ToolDefinition{Type: "function", Function: modelgateway.ToolFunction{
		Name: trustedMetricToolName,
		Description: "Compare two dates using an administrator-approved metric. Available metrics: " + strings.Join(labels, "; ") +
			". Values describe observed snapshots; do not infer complete population coverage. Cite attempt_id and receipt_digest as a live read.",
		Parameters: schema,
	}}, true
}

func parseTrustedMetricArguments(raw json.RawMessage) (metricToolArguments, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > 1024 || !json.Valid(trimmed) {
		return metricToolArguments{}, false
	}
	var args metricToolArguments
	if err := jsonv2.Unmarshal(trimmed, &args, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		!validGovernedID(args.MetricID) || len(args.DateA) != 10 || len(args.DateB) != 10 || args.DateA == args.DateB {
		return metricToolArguments{}, false
	}
	for _, date := range []string{args.DateA, args.DateB} {
		for index, character := range date {
			if index == 4 || index == 7 {
				if character != '-' {
					return metricToolArguments{}, false
				}
			} else if character < '0' || character > '9' {
				return metricToolArguments{}, false
			}
		}
	}
	return args, true
}

func metricDay(value metriccompare.DailyValue) metricToolDay {
	return metricToolDay{Date: value.Date, SnapshotAt: value.SnapshotAt, Value: value.Value,
		ContributingRows: value.ContributingRows, DistinctSubjects: value.DistinctSubjects}
}

func invokeTrustedMetricToolRetained(ctx context.Context, access database.AccessContext, workspaceID, questionRunID string,
	compare TrustedMetricComparison, catalog []governedask.ComparisonSummary, raw json.RawMessage, maxResultBytes int,
) (workspacetools.Result, *liveDataExecution, error) {
	if ctx == nil || compare == nil || ctx.Err() != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	args, ok := parseTrustedMetricArguments(raw)
	if !ok {
		return liveDataRefusal("LIVE_DATA_INVALID_ARGUMENTS"), nil, nil
	}
	approved := false
	approvedUnit := ""
	for _, item := range catalog {
		if item.MetricID == args.MetricID {
			approved = true
			approvedUnit = item.Unit
			break
		}
	}
	if !approved {
		return liveDataRefusal("LIVE_DATA_INVALID_ARGUMENTS"), nil, nil
	}
	result, err := compare.CompareWorkspace(ctx, access, workspaceID, args.MetricID, args.DateA, args.DateB)
	if err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, err
	}
	if ctx.Err() != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, ctx.Err()
	}
	projection, _, ok, _ := projectLiveDataResultDetailed(result.Ask, maxResultBytes)
	if !ok || !validOpaque(questionRunID) || result.Comparison.MetricID != args.MetricID ||
		result.Comparison.Unit != approvedUnit || !validGovernedSHA256(result.Comparison.ProfileHash) ||
		result.Comparison.First.Date != args.DateA || result.Comparison.Second.Date != args.DateB ||
		result.Comparison.Coverage != metriccompare.ObservedSnapshot || !comparisonMatchesRows(result.Comparison, projection) {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	dependency := governedQueryDependency{questionRunID: questionRunID, attemptID: projection.AttemptID,
		connectionID: result.Ask.ConnectionID, sqlHash: projection.SQLHash,
		exposedSchemaRevision: projection.ExposedSchemaRevision, resultDigest: projection.ResultDigest}
	if !dependency.validForRun(questionRunID) {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	projection.ReceiptDigest, err = liveDataReceiptDigest(questionRunID, projection)
	if err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	output := metricToolResult{MetricID: result.Comparison.MetricID, Unit: result.Comparison.Unit,
		Coverage: result.Comparison.Coverage, First: metricDay(result.Comparison.First), Second: metricDay(result.Comparison.Second),
		Delta: result.Comparison.Delta, PercentChange: result.Comparison.PercentChange,
		AttemptID: projection.AttemptID, ReceiptDigest: projection.ReceiptDigest}
	payload, err := json.Marshal(output)
	if err != nil || len(payload) > maxResultBytes {
		return liveDataRefusal("LIVE_DATA_RESULT_TOO_LARGE"), nil, nil
	}
	payload = append(json.RawMessage(nil), payload...)
	return workspacetools.Result{Text: string(payload), Structured: payload},
		&liveDataExecution{projection: projection, dependency: dependency}, nil
}

func comparisonMatchesRows(value metriccompare.Comparison, projection liveDataProjection) bool {
	if projection.RowCount != 2 || len(projection.Columns) != 6 ||
		strings.Join(projection.Columns, ",") != "local_date,snapshot_at,contributing_rows,distinct_subjects,nonnull_count,value" {
		return false
	}
	for _, day := range []metriccompare.DailyValue{value.First, value.Second} {
		matched := false
		for _, row := range projection.Rows {
			if len(row) != 6 || row[0] == nil || *row[0] != day.Date {
				continue
			}
			if row[1] == nil || row[2] == nil || row[3] == nil || row[4] == nil || row[5] == nil ||
				!sameMetricSnapshot(*row[1], day.SnapshotAt) || !sameMetricValue(*row[5], day.Value) ||
				!sameMetricCount(*row[2], day.ContributingRows) || !sameMetricCount(*row[3], day.DistinctSubjects) ||
				!sameMetricCount(*row[4], day.ContributingRows) {
				return false
			}
			matched = true
		}
		if !matched {
			return false
		}
	}
	return true
}

func sameMetricSnapshot(raw, normalized string) bool {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999-07", "2006-01-02 15:04:05.999999999-0700"} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.Format(time.RFC3339Nano) == normalized
		}
	}
	return false
}

func sameMetricValue(raw, normalized string) bool {
	left, leftOK := new(big.Rat).SetString(raw)
	right, rightOK := new(big.Rat).SetString(normalized)
	return leftOK && rightOK && left.Cmp(right) == 0
}

func sameMetricCount(raw string, expected int64) bool {
	parsed, err := strconv.ParseInt(raw, 10, 64)
	return err == nil && parsed == expected
}
