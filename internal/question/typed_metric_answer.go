package question

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"regexp"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/metriccompare"
)

// renderTypedMetricAnswer builds prose solely from authenticated comparison
// results and already-verified citation numbers. It is intentionally not wired
// into Question run creation or persistence yet.
func renderTypedMetricAnswer(questionRunID string, record *ToolLoopRecord,
	dependencies []governedQueryDependency, citations []Citation, language string) (string, error) {
	invalid := func() (string, error) { return "", &Error{code: CodeInvalid} }
	if language != "en" && language != "ru" {
		return invalid()
	}
	executions, successful, valid := governedQueryToolExecutions(questionRunID, dependencies, record)
	if !valid || !successful || len(executions) == 0 || len(executions) > liveDataMaxSuccessfulCalls || record == nil {
		return invalid()
	}
	parts := make([]string, 0, len(executions)+1)
	index := 0
	for _, call := range record.Calls {
		if call.Outcome != "SUCCEEDED" || (call.Name != trustedMetricToolName && call.Name != liveDataToolName) {
			continue
		}
		if call.Name != trustedMetricToolName || index >= len(executions) {
			return invalid()
		}
		projection, ok := decodeTrustedMetricProjection(questionRunID, call.Result.Structured, call.Evidence)
		if !ok || projection.AttemptID != executions[index].projection.AttemptID ||
			projection.ReceiptDigest != executions[index].projection.ReceiptDigest {
			return invalid()
		}
		var result metricToolResult
		if err := jsonv2.Unmarshal(call.Result.Structured, &result, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
			return invalid()
		}
		comparison := metriccompare.Comparison{
			MetricID: result.MetricID, ProfileHash: result.ProfileHash, Unit: result.Unit, Coverage: result.Coverage,
			First: metriccompare.DailyValue{Date: result.First.Date, SnapshotAt: result.First.SnapshotAt,
				Value: result.First.Value, ContributingRows: result.First.ContributingRows,
				DistinctSubjects: result.First.DistinctSubjects, NonNullCount: result.First.ContributingRows},
			Second: metriccompare.DailyValue{Date: result.Second.Date, SnapshotAt: result.Second.SnapshotAt,
				Value: result.Second.Value, ContributingRows: result.Second.ContributingRows,
				DistinctSubjects: result.Second.DistinctSubjects, NonNullCount: result.Second.ContributingRows},
			Delta: result.Delta, PercentChange: result.PercentChange,
		}
		prose, err := metriccompare.PresentInLanguage(comparison, language)
		if err != nil {
			return invalid()
		}
		parts = append(parts, fmt.Sprintf("%s [Live result %d]", prose, index+1))
		index++
	}
	if index != len(executions) {
		return invalid()
	}
	seen := make(map[int64]struct{}, len(citations))
	var documentSources strings.Builder
	for _, citation := range citations {
		if citation.Number < 1 {
			return invalid()
		}
		if _, duplicate := seen[citation.Number]; duplicate {
			continue
		}
		seen[citation.Number] = struct{}{}
		fmt.Fprintf(&documentSources, " [%d]", citation.Number)
	}
	if documentSources.Len() > 0 {
		if language == "ru" {
			parts = append(parts, "\u0418\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0438 \u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u043E\u0432:"+documentSources.String())
		} else {
			parts = append(parts, "Document sources:"+documentSources.String())
		}
	}
	question := ""
	if len(record.Messages) >= 2 && record.Messages[0].Role == "system" && record.Messages[1].Role == "user" {
		question = record.Messages[1].Content
	}
	quoted := 0
	quotedNumbers := make(map[int64]struct{}, 2)
	for _, citation := range citations {
		if quoted == 2 {
			break
		}
		if _, duplicate := quotedNumbers[citation.Number]; duplicate {
			continue
		}
		if excerpt := relevantMetricSourceExcerpt(question, citation.Excerpt); excerpt != "" {
			label := "Source excerpt"
			if language == "ru" {
				label = "\u0424\u0440\u0430\u0433\u043C\u0435\u043D\u0442 \u0438\u0441\u0442\u043E\u0447\u043D\u0438\u043A\u0430"
			}
			parts = append(parts, fmt.Sprintf("%s [%d]: “%s”", label, citation.Number, escapeMetricSourceExcerpt(excerpt)))
			quotedNumbers[citation.Number] = struct{}{}
			quoted++
		}
	}
	return strings.Join(parts, "\n\n"), nil
}

var metricExcerptWords = regexp.MustCompile(`[\pL\pN_.-]+`)

// The excerpt is source data, never an instruction. Only a line associated
// with the current question is displayed; the citation still opens the full
// current-access-checked fragment.
func relevantMetricSourceExcerpt(question, excerpt string) string {
	if question == "" || excerpt == "" {
		return ""
	}
	questionWords := metricExcerptWords.FindAllString(strings.ToLower(question), -1)
	identifiers := make([]string, 0, 2)
	terms := make(map[string]struct{}, len(questionWords))
	for _, word := range questionWords {
		if strings.Contains(word, ".") && utf8.RuneCountInString(word) >= 8 {
			identifiers = append(identifiers, word)
		} else if utf8.RuneCountInString(word) >= 5 {
			terms[word] = struct{}{}
		}
	}
	bestScore, bestAnchor, bestLine := 0, "", ""
	for _, line := range strings.Split(strings.ReplaceAll(excerpt, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		score, anchor := 0, ""
		for _, identifier := range identifiers {
			if strings.Contains(lower, identifier) {
				score, anchor = 100, identifier
				break
			}
		}
		if score == 0 {
			matched := make(map[string]struct{})
			for _, word := range metricExcerptWords.FindAllString(lower, -1) {
				if _, wanted := terms[word]; wanted {
					matched[word] = struct{}{}
					if anchor == "" {
						anchor = word
					}
				}
			}
			if len(matched) >= 2 {
				score = len(matched)
			}
		}
		if score > bestScore {
			bestScore, bestAnchor, bestLine = score, anchor, line
		}
	}
	if bestScore == 0 {
		return ""
	}
	// Keep the matching term visible even when the source line is long.
	line := []rune(bestLine)
	if len(line) <= 320 {
		return string(line)
	}
	anchorAt := strings.Index(strings.ToLower(string(line)), bestAnchor)
	if anchorAt < 0 {
		anchorAt = 0
	}
	anchorRune := utf8.RuneCountInString(strings.ToLower(string(line))[:anchorAt])
	start := max(0, anchorRune-80)
	if start+320 > len(line) {
		start = len(line) - 320
	}
	result := string(line[start : start+320])
	if start > 0 {
		result = "…" + result
	}
	if start+320 < len(line) {
		result += "…"
	}
	return result
}

func escapeMetricSourceExcerpt(excerpt string) string {
	// HTML and Markdown syntax from a document must remain visible text, not
	// links, formatting, or injected page elements in the rendered answer.
	return strings.NewReplacer(`\`, `\\`, "`", "\\`", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]",
		"(", "\\(", ")", "\\)", "#", "\\#", "!", "\\!", "|", "\\|").Replace(html.EscapeString(excerpt))
}
