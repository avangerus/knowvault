package question

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// ActionTextMaxRunes bounds every Request/Detail string the live action
// stream discloses. It mirrors the post-answer tool summary's 180-rune bound
// (web/src/tool-call-summary.ts's `bounded`) so the live and post-answer
// projections read consistently, and it is re-checked at the transport
// boundary (workspaceapi.questionEventStream.action) as defense in depth.
const ActionTextMaxRunes = 180

// actionExcerptMaxRunes bounds one search-hit title folded into a Detail
// string; several may be joined, so it is deliberately smaller than the
// overall Request/Detail bound.
const actionExcerptMaxRunes = 60

// boundedActionText is the single place that enforces the R2 length bound
// and collapses whitespace/control bytes for every Request/Detail string.
func boundedActionText(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if !utf8.ValidString(value) {
		value = strings.ToValidUTF8(value, "�")
	}
	runes := []rune(value)
	if len(runes) > ActionTextMaxRunes {
		return string(runes[:ActionTextMaxRunes]) + "…"
	}
	return value
}

func shortExcerpt(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > actionExcerptMaxRunes {
		return string(runes[:actionExcerptMaxRunes]) + "…"
	}
	return value
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return singular
	}
	return plural
}

// asObject decodes a JSON object into a generic, read-only projection. It
// never fails loudly: any non-object payload (including an array, a scalar
// or invalid JSON) yields a nil map, so every caller below falls back to its
// safe default rather than guessing at an unexpected shape.
func asObject(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	return value
}

func stringField(fields map[string]any, key string) (string, bool) {
	value, ok := fields[key].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func nestedObject(fields map[string]any, key string) map[string]any {
	nested, _ := fields[key].(map[string]any)
	return nested
}

func arrayField(fields map[string]any, key string) ([]any, bool) {
	value, ok := fields[key].([]any)
	return value, ok
}

// actionRequestText projects a short, safe description of a tool call's
// request from a fixed set of already-reviewed argument fields, for a fixed
// set of known tool names. An unrecognized name (a future or external
// catalog tool) always yields "": its argument shape has not been reviewed,
// so nothing from it is ever surfaced here.
func actionRequestText(name string, args json.RawMessage) string {
	fields := asObject(args)
	switch name {
	case "knowvault_search":
		if query, ok := stringField(fields, "query"); ok {
			return boundedActionText(query)
		}
	case "knowvault_read", "knowvault_evidence_read":
		if id, ok := stringField(fields, "fragment_id"); ok {
			return boundedActionText(id)
		}
		if address, ok := stringField(fields, "address"); ok {
			return boundedActionText(address)
		}
	case liveDataToolName:
		if question, ok := stringField(fields, "question"); ok {
			return boundedActionText(question)
		}
	case analyticScalarToolName:
		if summary := analyticScalarRequestSummary(fields); summary != "" {
			return boundedActionText(summary)
		}
	case trustedMetricToolName:
		if summary := trustedMetricRequestSummary(fields); summary != "" {
			return boundedActionText(summary)
		}
	case "knowvault_grep":
		if pattern, ok := stringField(fields, "pattern"); ok {
			return boundedActionText(pattern)
		}
	case "knowvault_related":
		if id, ok := stringField(fields, "fragment_id"); ok {
			return boundedActionText(id)
		}
		if address, ok := stringField(fields, "address"); ok {
			return boundedActionText(address)
		}
	case "knowvault_sources", "knowvault_sources_list":
		return "Workspace sources"
	case "knowvault_list_objects", "knowvault_workspace_list":
		return "Workspace object inventory"
	}
	return ""
}

func analyticScalarRequestSummary(fields map[string]any) string {
	if fields == nil {
		return ""
	}
	measure, hasMeasure := stringField(fields, "measure")
	datasetID, _ := stringField(nestedObject(fields, "dataset"), "dataset_id")
	period := nestedObject(fields, "period")
	start, hasStart := stringField(period, "start")
	end, hasEnd := stringField(period, "end")
	var builder strings.Builder
	if datasetID != "" {
		builder.WriteString(datasetID)
	}
	if hasMeasure {
		if builder.Len() > 0 {
			builder.WriteString(": ")
		}
		builder.WriteString(measure)
	}
	if hasStart && hasEnd {
		if builder.Len() > 0 {
			builder.WriteString(" ")
		}
		fmt.Fprintf(&builder, "[%s..%s)", start, end)
	}
	return builder.String()
}

func trustedMetricRequestSummary(fields map[string]any) string {
	metricID, hasMetric := stringField(fields, "metric_id")
	dateA, hasA := stringField(fields, "date_a")
	dateB, hasB := stringField(fields, "date_b")
	if !hasMetric || !hasA || !hasB {
		return ""
	}
	return metricID + ": " + dateA + " vs " + dateB
}

// actionResultText projects a short, safe outcome summary from a fixed set
// of already-reviewed result fields, for the same fixed set of known tool
// names as actionRequestText. A failed call never inspects the tool result
// at all: it maps a small closed set of the product's own error codes to a
// generic phrase and otherwise says "Failed", so a raw error/advice string
// (which could echo back untrusted content) is never disclosed.
//
// F1: liveDataToolName, analyticScalarToolName and trustedMetricToolName are
// deliberately absent from this switch and fall through to the default
// "Completed", even on success. Their result carries the value/delta/
// row-count/unit itself -- the live action stream (beginToolAction in
// action_observer.go) emits this text immediately after the tool call, from
// inside the tool loop, before the per-run disclosure reauthorization that
// the final answer must still pass (service.go's
// authorizeAnalyticScalarDisclosure / authorizeGovernedQueryDisclosures,
// checked when the run is later read). If that later check denies the run,
// the answer is withheld, but a value already streamed live cannot be
// un-shown. Only the step's own succeeded/failed outcome may be disclosed
// this early for these three tools; the full result (including any number)
// still reaches the client through the post-answer trace, which is gated by
// that same reauthorization because it is part of the same Run.
func actionResultText(name string, succeeded bool, result workspacetools.Result) string {
	if !succeeded {
		return boundedActionText(actionFailureText(result))
	}
	fields := asObject(result.Structured)
	switch name {
	case "knowvault_search":
		return boundedActionText(searchResultSummary(fields))
	case "knowvault_read", "knowvault_evidence_read":
		return boundedActionText(readResultSummary(fields))
	case "knowvault_grep":
		return boundedActionText(countSummary(fields, "matches", "match", "matches"))
	case "knowvault_related":
		return boundedActionText(countSummary(fields, "relations", "relation", "relations"))
	case "knowvault_list_objects", "knowvault_workspace_list":
		return boundedActionText(countSummary(fields, "objects", "object", "objects"))
	case "knowvault_sources", "knowvault_sources_list":
		return boundedActionText(countSummary(fields, "sources", "source", "sources"))
	default:
		return "Completed"
	}
}

func countSummary(fields map[string]any, key, singular, plural string) string {
	items, ok := arrayField(fields, key)
	if !ok {
		return "Completed"
	}
	if len(items) == 0 {
		return "No results"
	}
	if len(items) == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", len(items), plural)
}

func searchResultSummary(fields map[string]any) string {
	results, ok := arrayField(fields, "results")
	if !ok {
		return "Completed"
	}
	if len(results) == 0 {
		return "No results"
	}
	titles := make([]string, 0, 2)
	for _, item := range results {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if excerpt, ok := stringField(entry, "excerpt"); ok {
			titles = append(titles, shortExcerpt(excerpt))
		}
		if len(titles) == 2 {
			break
		}
	}
	label := fmt.Sprintf("%d %s", len(results), pluralize(len(results), "hit", "hits"))
	if len(titles) == 0 {
		return label
	}
	return label + ": " + strings.Join(titles, "; ")
}

func readResultSummary(fields map[string]any) string {
	text, ok := fields["text"].(string)
	if !ok {
		return "Completed"
	}
	count := utf8.RuneCountInString(text)
	if hasMore, _ := fields["has_more"].(bool); hasMore {
		return fmt.Sprintf("Read %d characters (more available)", count)
	}
	return fmt.Sprintf("Read %d characters", count)
}

// actionFailureCodes maps a small, closed set of the product's own tool
// error codes (see tool_loop.go, live_data_tool.go, trusted_metric_tool.go
// and analytic_scalar_tool.go) to a short user phrase. Every other code,
// including one this package has never emitted, falls back to "Failed" in
// actionFailureText: the map is deliberately not exhaustive so a new or
// unrecognized code can never be mistaken for a safe, reviewed one.
var actionFailureCodes = map[string]string{
	"NOT_FOUND":                             "Not found",
	"TOOL_UNAVAILABLE":                      "Unavailable",
	"INVALID_TOOL_ARGUMENTS":                "Invalid request",
	"TOOL_SCOPE_CHANGED":                    "Workspace changed",
	"FINALIZATION_REQUIRED":                 "Unavailable",
	"LIVE_DATA_UNAVAILABLE":                 "Unavailable",
	"REQUESTED_DATE_MISMATCH":               "Unavailable",
	"TRUSTED_COMPARISON_REQUIRED":           "Unavailable",
	"ANALYTIC_SCALAR_UNAVAILABLE":           "Unavailable",
	"ANALYTIC_OBSERVATION_ALREADY_RECORDED": "Unavailable",
	"ANALYTIC_TOOL_UNAVAILABLE":             "Unavailable",
	"TRACE_LIMIT":                           "Limit reached",
	"LIVE_DATA_RESULT_TOO_LARGE":            "Result too large",
	"ACCESS_DENIED":                         "Access denied",
	"NOT_READABLE":                          "Access denied",
	"SERVICE_UNAVAILABLE":                   "Unavailable",
}

func actionFailureText(result workspacetools.Result) string {
	var payload struct {
		Error string `json:"error"`
	}
	text := result.Text
	if len(result.Structured) > 0 {
		text = string(result.Structured)
	}
	if json.Unmarshal([]byte(text), &payload) == nil && payload.Error != "" {
		if message, ok := actionFailureCodes[payload.Error]; ok {
			return message
		}
	}
	return "Failed"
}
