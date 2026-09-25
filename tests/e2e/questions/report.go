package questions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report is the machine-readable run report.
type Report struct {
	SchemaVersion string            `json:"schema_version"`
	Title         string            `json:"title"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Model         string            `json:"model"`
	Endpoint      string            `json:"endpoint"`
	Mode          string            `json:"mode"`
	Command       string            `json:"command"`
	TotalSeconds  float64           `json:"total_seconds"`
	InputTokens   int               `json:"input_tokens"`
	OutputTokens  int               `json:"output_tokens"`
	Cost          CostReport        `json:"cost"`
	Runs          []RunReport       `json:"runs"`
	Questions     []QuestionVerdict `json:"questions"`
	Failed        bool              `json:"failed"`
}

// CostReport is the DeepSeek token cost of the full run.
type CostReport struct {
	Currency           string  `json:"currency"`
	Tier               string  `json:"tier"`
	InputCacheMissRate float64 `json:"input_cache_miss_rate_per_million"`
	OutputRate         float64 `json:"output_rate_per_million"`
	InputCost          float64 `json:"input_cost"`
	OutputCost         float64 `json:"output_cost"`
	Total              float64 `json:"total"`
	PricingSource      string  `json:"pricing_source"`
	Note               string  `json:"note,omitempty"`
}

// PeakAt reports whether at is inside DeepSeek's peak window.
func PeakAt(at time.Time, pricing Pricing) (bool, string) {
	utc := at.UTC()
	weekday := int(utc.Weekday())
	allowedDay := false
	for _, day := range pricing.PeakWeekdaysUTC {
		if day == weekday {
			allowedDay = true
			break
		}
	}
	if allowedDay {
		for _, window := range pricing.PeakHoursUTC {
			if len(window) == 2 && utc.Hour() >= window[0] && utc.Hour() < window[1] {
				return true, "peak"
			}
		}
	}
	return false, "off-peak"
}

// ComputeCost bills every input token at the cache-miss rate because the
// adapter usage projection carries only prompt/completion totals.
func ComputeCost(pricing Pricing, at time.Time, inputTokens, outputTokens int) CostReport {
	peak, tier := PeakAt(at, pricing)
	inputRate := pricing.InputCacheMissOffPeak
	outputRate := pricing.OutputOffPeak
	if peak {
		inputRate = pricing.InputCacheMissPeak
		outputRate = pricing.OutputPeak
	}
	inputCost := float64(inputTokens) / 1_000_000 * inputRate
	outputCost := float64(outputTokens) / 1_000_000 * outputRate
	return CostReport{
		Currency:           pricing.Currency,
		Tier:               tier,
		InputCacheMissRate: inputRate,
		OutputRate:         outputRate,
		InputCost:          inputCost,
		OutputCost:         outputCost,
		Total:              inputCost + outputCost,
		PricingSource:      pricing.Source,
		Note:               pricing.Note,
	}
}

// NewReport assembles the report from judged runs.
func NewReport(set *Set, mode, command string, runs []RunReport, started time.Time) Report {
	verdicts := Judge(set, runs)
	totalSeconds := 0.0
	inputTokens, outputTokens := 0, 0
	failed := false
	for _, run := range runs {
		totalSeconds += run.Seconds
		inputTokens += run.InputTokens
		outputTokens += run.OutputTokens
	}
	for _, verdict := range verdicts {
		if !verdict.Passed {
			failed = true
		}
	}
	return Report{
		SchemaVersion: "question-set-report-v1",
		Title:         set.Title,
		GeneratedAt:   time.Now().UTC(),
		Model:         set.Model.ModelID,
		Endpoint:      set.Model.Endpoint,
		Mode:          mode,
		Command:       command,
		TotalSeconds:  totalSeconds,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		Cost:          ComputeCost(set.Model.Pricing, started, inputTokens, outputTokens),
		Runs:          runs,
		Questions:     verdicts,
		Failed:        failed,
	}
}

// WriteReport writes report.md and report.json into dir.
func WriteReport(dir string, report Report) (string, string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	markdownPath := filepath.Join(dir, "report.md")
	jsonPath := filepath.Join(dir, "report.json")
	if err := os.WriteFile(markdownPath, []byte(RenderMarkdown(report)), 0o644); err != nil {
		return "", "", err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jsonPath, append(raw, '\n'), 0o644); err != nil {
		return "", "", err
	}
	return markdownPath, jsonPath, nil
}

// RenderMarkdown renders the report as Markdown: a per-question summary, the
// per-run table (one row per question and run), and the totals.
func RenderMarkdown(report Report) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# %s\n\n", report.Title)
	fmt.Fprintf(&builder, "- Generated: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&builder, "- Model channel: `%s` at `%s`\n", report.Model, report.Endpoint)
	fmt.Fprintf(&builder, "- Mode: %s\n", report.Mode)
	fmt.Fprintf(&builder, "- Command: `%s`\n", report.Command)
	fmt.Fprintf(&builder, "- Total time: %.2f s\n", report.TotalSeconds)
	fmt.Fprintf(&builder, "- DeepSeek tokens: %d input + %d output = %d\n", report.InputTokens, report.OutputTokens, report.InputTokens+report.OutputTokens)
	fmt.Fprintf(&builder, "- DeepSeek cost: %.6f %s (%s tier; input at the cache-miss rate %.2f/1M, output %.2f/1M; %s)\n",
		report.Cost.Total, report.Cost.Currency, report.Cost.Tier, report.Cost.InputCacheMissRate, report.Cost.OutputRate, report.Cost.PricingSource)
	if report.Failed {
		fmt.Fprintf(&builder, "- Result: **FAIL** (at least one question did not pass)\n\n")
	} else {
		fmt.Fprintf(&builder, "- Result: **PASS**\n\n")
	}
	builder.WriteString("Verification status field: the API response's `status` together with `tool_loop.stop_reason`; the only tolerated failure is `CITATIONS_UNVERIFIED` (a citation really failed). Steps count model-requested tool calls: the final `submit_answer` and the product's automatic citation reads are not steps.\n\n")

	builder.WriteString("## Question summary\n\n")
	builder.WriteString("| # | Passed | Failed rules |\n|---|---|---|\n")
	for _, question := range report.Questions {
		failed := []string{}
		for _, rule := range question.Rules {
			if !rule.Passed {
				failed = append(failed, fmt.Sprintf("`%s` (%d/%d)", rule.ID, rule.Passes, rule.Required))
			}
		}
		state := "yes"
		if !question.Passed {
			state = "NO"
		}
		fmt.Fprintf(&builder, "| %s | %s | %s |\n", question.QuestionID, state, strings.Join(failed, ", "))
	}
	builder.WriteString("\n")

	builder.WriteString("## Runs\n\n")
	builder.WriteString("| # | Run | Steps | Seconds | Tool calls (name: main argument) | Rules | Answer |\n")
	builder.WriteString("|---|---|---|---|---|---|---|\n")
	for _, run := range report.Runs {
		calls := make([]string, 0, len(run.ToolCalls))
		for _, call := range run.ToolCalls {
			calls = append(calls, fmt.Sprintf("%s: %s", call.Name, truncate(call.MainArgument, 60)))
		}
		rules := make([]string, 0, len(run.Verdicts))
		for _, verdict := range run.Verdicts {
			mark := "pass"
			if !verdict.Passed {
				mark = "FAIL"
			}
			rules = append(rules, verdict.ID+"="+mark)
		}
		fmt.Fprintf(&builder, "| %s | %d | %d | %.2f | %s | %s | %s |\n",
			run.QuestionID, run.Run, run.Steps, run.Seconds,
			escapeCell(strings.Join(calls, "; ")), escapeCell(strings.Join(rules, ", ")), escapeCell(run.Answer))
	}
	builder.WriteString("\n")

	builder.WriteString("## Per-run status and verdicts\n\n")
	for _, run := range report.Runs {
		fmt.Fprintf(&builder, "### %s run %d\n\n", run.QuestionID, run.Run)
		fmt.Fprintf(&builder, "- Question: %s\n", run.QuestionText)
		fmt.Fprintf(&builder, "- Status: `%s` / stop_reason `%s` / grounding `%s`\n", run.Status, run.StopReason, run.GroundingStatus)
		fmt.Fprintf(&builder, "- Steps: %d; seconds: %.2f; tokens: %d in / %d out\n", run.Steps, run.Seconds, run.InputTokens, run.OutputTokens)
		if len(run.SQLTexts) > 0 {
			fmt.Fprintf(&builder, "- Executed SQL: %s\n", escapeCell(strings.Join(run.SQLTexts, " | ")))
		}
		fmt.Fprintf(&builder, "\nVerdicts: %s\n\n", verdictsInline(run.Verdicts))
		fmt.Fprintf(&builder, "Answer:\n\n```text\n%s\n```\n\n", run.Answer)
	}
	return builder.String()
}

func verdictsInline(verdicts []RuleVerdict) string {
	parts := make([]string, 0, len(verdicts))
	for _, verdict := range verdicts {
		mark := "PASS"
		if !verdict.Passed {
			mark = "FAIL"
		}
		detail := ""
		if verdict.Detail != "" {
			detail = " (" + verdict.Detail + ")"
		}
		parts = append(parts, fmt.Sprintf("`%s`=%s%s", verdict.ID, mark, detail))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func escapeCell(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\n", "<br>")
	value = strings.ReplaceAll(value, "|", "\\|")
	return value
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}
