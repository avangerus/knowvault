// Package questions is the E-1a question-run judge. It owns the one data file
// (questions.json) that describes the synthetic proving environment, the
// question set and the per-answer rules, and it turns one real answer into a
// list of verdicts. It performs no model, database or network I/O: the runner
// observes a run and hands the observation here.
package questions

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Set is the complete data file.
type Set struct {
	SchemaVersion string      `json:"schema_version"`
	Title         string      `json:"title"`
	Model         Model       `json:"model"`
	Environment   Environment `json:"environment"`
	Universal     Universal   `json:"universal_rules"`
	Questions     []Question  `json:"questions"`
}

// Model is the real model channel configuration.
type Model struct {
	Endpoint      string  `json:"endpoint"`
	ModelID       string  `json:"model_id"`
	APIKeyFileEnv string  `json:"api_key_file_env"`
	ThinkingMode  string  `json:"thinking_mode"`
	Pricing       Pricing `json:"pricing"`
}

// Pricing is the published per-million-token price table the report uses.
type Pricing struct {
	Currency              string   `json:"currency"`
	Unit                  string   `json:"unit"`
	InputCacheMissPeak    float64  `json:"input_cache_miss_peak"`
	InputCacheMissOffPeak float64  `json:"input_cache_miss_off_peak"`
	InputCacheHitPeak     float64  `json:"input_cache_hit_peak"`
	InputCacheHitOffPeak  float64  `json:"input_cache_hit_off_peak"`
	OutputPeak            float64  `json:"output_peak"`
	OutputOffPeak         float64  `json:"output_off_peak"`
	PeakHoursUTC          [][2]int `json:"peak_hours_utc"`
	PeakWeekdaysUTC       []int    `json:"peak_weekdays_utc"`
	Source                string   `json:"source"`
	Note                  string   `json:"note"`
}

// Environment is the synthetic proving environment.
type Environment struct {
	OrganizationID   string           `json:"organization_id"`
	OrganizationName string           `json:"organization_name"`
	OwnerID          string           `json:"owner_id"`
	ViewerID         string           `json:"viewer_id"`
	WorkspaceID      string           `json:"workspace_id"`
	ProductContainer string           `json:"product_container"`
	ProductPort      int              `json:"product_port"`
	ProductDatabase  string           `json:"product_database"`
	SourceContainer  string           `json:"source_container"`
	SourcePort       int              `json:"source_port"`
	SourceDatabase   string           `json:"source_database"`
	SourceSchema     string           `json:"source_schema"`
	SourceAdminUser  string           `json:"source_admin_user"`
	SourceAdminPass  string           `json:"source_admin_password"`
	SourceSQL        []string         `json:"source_sql"`
	Documents        []Document       `json:"documents"`
	Dictionary       Dictionary       `json:"dictionary"`
	Tables           map[string]Table `json:"tables"`
	Sources          []SourceSpec     `json:"sources"`
	Values           Values           `json:"values"`
}

// Document is one synthetic workspace document.
type Document struct {
	ID                  string `json:"id"`
	File                string `json:"file"`
	SourceName          string `json:"source_name"`
	DistinctiveSentence string `json:"distinctive_sentence"`
	KeyPhrase           string `json:"key_phrase"`
	ContractNumber      string `json:"contract_number"`
	Text                string `json:"text"`
}

// Dictionary is the workspace model context (glossary and rules).
type Dictionary struct {
	Description string           `json:"description"`
	Rules       []DictionaryRule `json:"rules"`
	Terms       []DictionaryTerm `json:"terms"`
}

// DictionaryRule is one answer-shaping rule.
type DictionaryRule struct {
	Text string `json:"text"`
}

// DictionaryTerm is one glossary term.
type DictionaryTerm struct {
	Term       string               `json:"term"`
	Synonyms   []string             `json:"synonyms"`
	Definition string               `json:"definition"`
	Locations  []DictionaryLocation `json:"locations"`
}

// DictionaryLocation points a term at a registered source relation.
type DictionaryLocation struct {
	Source   string `json:"source"`
	Relation string `json:"relation"`
	Column   string `json:"column"`
}

// Table is one synthetic source table.
type Table struct {
	Columns         []string `json:"columns"`
	IdentityColumn  string   `json:"identity_column"`
	ActivePredicate string   `json:"active_predicate"`
	ActiveCount     int      `json:"active_count"`
}

// SourceSpec is one registered PostgreSQL source relation.
type SourceSpec struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	LineageID     string   `json:"lineage_id"`
	Table         string   `json:"table"`
	Columns       []string `json:"columns"`
	QueryRole     string   `json:"query_role"`
	QueryPassword string   `json:"query_password"`
}

// Values are the known synthetic expectations.
type Values struct {
	A           int               `json:"A"`
	M           int               `json:"M"`
	N           string            `json:"N"`
	ContractRow map[string]string `json:"contract_row"`
}

// Universal holds the rules that apply to every answer.
type Universal struct {
	MaxChars                int      `json:"max_chars"`
	ForbiddenPhrases        []string `json:"forbidden_phrases"`
	LabelRegex              string   `json:"label_regex"`
	EvidenceRegex           string   `json:"evidence_regex"`
	VerificationRegex       string   `json:"verification_regex"`
	InternalRegexes         []string `json:"internal_regexes"`
	SameToolArgumentMax     int      `json:"same_tool_argument_max"`
	RUCyrillicRatioMin      float64  `json:"ru_cyrillic_ratio_min"`
	ENCyrillicRatioMax      float64  `json:"en_cyrillic_ratio_max"`
	RUEnglishServicePhrases []string `json:"ru_english_service_phrases"`
	ENRussianServicePhrases []string `json:"en_russian_service_phrases"`
}

// Question is one question and its checks.
type Question struct {
	ID          string  `json:"id"`
	Text        string  `json:"text"`
	Language    string  `json:"language"`
	MaxSteps    int     `json:"max_steps"`
	TimeLimitS  float64 `json:"time_limit_s"`
	MaxChars    int     `json:"max_chars"`
	Expectation string  `json:"expectation"`
	ValueNote   string  `json:"value_note"`
	Checks      []Check `json:"checks"`
}

// Check is one per-question rule. Group is "hard" unless it names a value or
// time rule, which pass on two of three runs.
type Check struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Hard  bool     `json:"hard"`
	Group string   `json:"group"`
	Text  string   `json:"text"`
	Texts []string `json:"texts"`
	Min   int      `json:"min"`
	Max   int      `json:"max"`
	Value string   `json:"value"`
}

// LoadSet reads and validates the data file.
func LoadSet(path string) (*Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSet(raw)
}

// ParseSet decodes and validates a data file.
func ParseSet(raw []byte) (*Set, error) {
	var set Set
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&set); err != nil {
		return nil, fmt.Errorf("decode question set: %w", err)
	}
	if set.SchemaVersion != "question-set-v1" {
		return nil, fmt.Errorf("unsupported question set schema %q", set.SchemaVersion)
	}
	if len(set.Questions) == 0 {
		return nil, fmt.Errorf("question set has no questions")
	}
	if _, err := regexp.Compile(set.Universal.LabelRegex); err != nil {
		return nil, fmt.Errorf("label_regex: %w", err)
	}
	if _, err := regexp.Compile(set.Universal.EvidenceRegex); err != nil {
		return nil, fmt.Errorf("evidence_regex: %w", err)
	}
	if _, err := regexp.Compile(set.Universal.VerificationRegex); err != nil {
		return nil, fmt.Errorf("verification_regex: %w", err)
	}
	for _, pattern := range set.Universal.InternalRegexes {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("internal regex %q: %w", pattern, err)
		}
	}
	seen := map[string]bool{}
	for _, question := range set.Questions {
		if question.ID == "" || question.Text == "" || seen[question.ID] {
			return nil, fmt.Errorf("invalid or duplicate question id %q", question.ID)
		}
		seen[question.ID] = true
		if question.Language != "ru" && question.Language != "en" {
			return nil, fmt.Errorf("question %s has unsupported language %q", question.ID, question.Language)
		}
	}
	return &set, nil
}

// Question returns one question by id.
func (set *Set) Question(id string) (Question, bool) {
	for _, question := range set.Questions {
		if question.ID == id {
			return question, true
		}
	}
	return Question{}, false
}

// Citation is one answer citation as the judge sees it.
type Citation struct {
	Address string
	Excerpt string
	// Text is the cited fragment's stored text, used only by citation_document.
	Text string
}

// ToolCall is one research tool call made during the run.
type ToolCall struct {
	Name         string
	Arguments    string
	MainArgument string
}

// Observation is everything the judge knows about one run.
type Observation struct {
	QuestionID        string
	QuestionText      string
	QuestionLang      string
	Answer            string
	Status            string
	StopReason        string
	GroundingStatus   string
	Citations         []Citation
	ToolCalls         []ToolCall
	SQLTexts          []string
	Seconds           float64
	InputTokens       int
	OutputTokens      int
	ContractUnchanged bool
	// LiveResultKind and LiveResultReceipt are the run's structured live-read
	// projection (AnswerResult): a SQL result is cited when the answer carries
	// a LIVE_TABLE result with its receipt digest.
	LiveResultKind    string
	LiveResultReceipt string
	// StatusFieldName is the response field the verification rule reads; it is
	// reported so the report names the exact field.
	StatusFieldName string
}

// RuleVerdict is one rule's verdict on one run.
type RuleVerdict struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Hard   bool   `json:"hard"`
	Group  string `json:"group"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// RunReport is one (question, run) row.
type RunReport struct {
	QuestionID        string        `json:"question_id"`
	QuestionText      string        `json:"question"`
	Run               int           `json:"run"`
	Seconds           float64       `json:"seconds"`
	Steps             int           `json:"steps"`
	ToolCalls         []ToolCall    `json:"tool_calls"`
	SQLTexts          []string      `json:"sql_texts,omitempty"`
	Status            string        `json:"status"`
	StopReason        string        `json:"stop_reason"`
	GroundingStatus   string        `json:"grounding_status"`
	InputTokens       int           `json:"input_tokens"`
	OutputTokens      int           `json:"output_tokens"`
	Answer            string        `json:"answer"`
	Citations         []Citation    `json:"citations,omitempty"`
	LiveResultKind    string        `json:"live_result_kind,omitempty"`
	LiveResultReceipt string        `json:"live_result_receipt,omitempty"`
	Verdicts          []RuleVerdict `json:"verdicts"`
	Passed            bool          `json:"passed"`
}

// QuestionVerdict is the 3-of-3 / 2-of-3 aggregate for one question.
type QuestionVerdict struct {
	QuestionID string             `json:"question_id"`
	Passed     bool               `json:"passed"`
	Rules      []AggregateVerdict `json:"rules"`
}

// AggregateVerdict is one rule's aggregate across a question's runs.
type AggregateVerdict struct {
	ID       string `json:"id"`
	Hard     bool   `json:"hard"`
	Group    string `json:"group"`
	Passes   int    `json:"passes"`
	Required int    `json:"required"`
	Passed   bool   `json:"passed"`
}

// Judge evaluates every run of every question and aggregates the verdicts.
func Judge(set *Set, runs []RunReport) []QuestionVerdict {
	byQuestion := map[string][]RunReport{}
	order := []string{}
	for _, run := range runs {
		if _, seen := byQuestion[run.QuestionID]; !seen {
			order = append(order, run.QuestionID)
		}
		byQuestion[run.QuestionID] = append(byQuestion[run.QuestionID], run)
	}
	sort.SliceStable(order, func(i, j int) bool {
		left, _ := set.Question(order[i])
		right, _ := set.Question(order[j])
		return questionIndex(set, left) < questionIndex(set, right)
	})
	verdicts := make([]QuestionVerdict, 0, len(order))
	for _, id := range order {
		questionRuns := byQuestion[id]
		aggregates := map[string]*AggregateVerdict{}
		aggregateOrder := []string{}
		for _, run := range questionRuns {
			for _, verdict := range run.Verdicts {
				aggregate, ok := aggregates[verdict.ID]
				if !ok {
					required := len(questionRuns)
					if !verdict.Hard {
						required = 2
					}
					aggregate = &AggregateVerdict{ID: verdict.ID, Hard: verdict.Hard, Group: verdict.Group, Required: required}
					aggregates[verdict.ID] = aggregate
					aggregateOrder = append(aggregateOrder, verdict.ID)
				}
				if verdict.Passed {
					aggregate.Passes++
				}
			}
		}
		questionVerdict := QuestionVerdict{QuestionID: id, Passed: true}
		for _, ruleID := range aggregateOrder {
			aggregate := aggregates[ruleID]
			aggregate.Passed = aggregate.Passes >= aggregate.Required
			if !aggregate.Passed {
				questionVerdict.Passed = false
			}
			questionVerdict.Rules = append(questionVerdict.Rules, *aggregate)
		}
		verdicts = append(verdicts, questionVerdict)
	}
	return verdicts
}

func questionIndex(set *Set, question Question) int {
	for index, candidate := range set.Questions {
		if candidate.ID == question.ID {
			return index
		}
	}
	return len(set.Questions)
}

// Evaluate judges one answer against the universal rules and the question's
// own checks.
func Evaluate(set *Set, question Question, observation Observation) []RuleVerdict {
	verdicts := universalVerdicts(set, question, observation)
	for _, check := range question.Checks {
		verdicts = append(verdicts, evaluateCheck(set, question, check, observation))
	}
	return verdicts
}

func universalVerdicts(set *Set, question Question, observation Observation) []RuleVerdict {
	answer := observation.Answer
	verdicts := []RuleVerdict{
		verdict("answer_non_empty", "answer_non_empty", true, "hard", strings.TrimSpace(answer) != "", ""),
		verdict("no_profile_limits", "no_profile_limits", true, "hard", !containsAnyFold(answer, set.Universal.ForbiddenPhrases), ""),
		verdict("no_label_prefix", "no_label_prefix", true, "hard", !regexp.MustCompile(`(?m)`+set.Universal.LabelRegex).MatchString(answer), ""),
		verdict("no_evidence_number", "no_evidence_number", true, "hard", !regexp.MustCompile(set.Universal.EvidenceRegex).MatchString(answer), ""),
		verdict("no_verification_prose", "no_verification_prose", true, "hard", !regexp.MustCompile(set.Universal.VerificationRegex).MatchString(answer), ""),
	}
	internalDetail := ""
	internalOK := true
	for _, pattern := range set.Universal.InternalRegexes {
		if regexp.MustCompile(pattern).MatchString(answer) {
			internalOK = false
			internalDetail = "matched " + pattern
			break
		}
	}
	verdicts = append(verdicts, verdict("no_internal_markers", "no_internal_markers", true, "hard", internalOK, internalDetail))

	prose := stripCode(answer)
	ratio, letters := cyrillicRatio(prose)
	languageOK := true
	languageDetail := fmt.Sprintf("cyrillic ratio %.2f over %d letters", ratio, letters)
	switch question.Language {
	case "ru":
		if letters == 0 || ratio < set.Universal.RUCyrillicRatioMin {
			languageOK = false
		}
		if phrase := firstPhraseFold(answer, set.Universal.RUEnglishServicePhrases); phrase != "" {
			languageOK = false
			languageDetail += "; English service phrase " + phrase
		}
	case "en":
		if letters == 0 || ratio > set.Universal.ENCyrillicRatioMax {
			languageOK = false
		}
		if phrase := firstPhraseFold(answer, set.Universal.ENRussianServicePhrases); phrase != "" {
			languageOK = false
			languageDetail += "; Russian service phrase " + phrase
		}
	}
	verdicts = append(verdicts, verdict("language", "language", true, "hard", languageOK, languageDetail))

	duplicateOK := true
	duplicateDetail := ""
	seen := map[string]bool{}
	for _, call := range observation.ToolCalls {
		key := call.Name + "\x00" + normalizeArguments(call.Arguments)
		if seen[key] {
			duplicateOK = false
			duplicateDetail = "duplicate " + call.Name
			break
		}
		seen[key] = true
	}
	verdicts = append(verdicts, verdict("no_duplicate_tool_calls", "no_duplicate_tool_calls", true, "hard", duplicateOK, duplicateDetail))

	maxPerArgument := set.Universal.SameToolArgumentMax
	if maxPerArgument < 1 {
		maxPerArgument = 2
	}
	sameArgumentOK := true
	sameArgumentDetail := ""
	counts := map[string]int{}
	for _, call := range observation.ToolCalls {
		counts[call.Name+"\x00"+call.MainArgument]++
		if counts[call.Name+"\x00"+call.MainArgument] > maxPerArgument {
			sameArgumentOK = false
			sameArgumentDetail = fmt.Sprintf("%s on %q more than %d times", call.Name, call.MainArgument, maxPerArgument)
			break
		}
	}
	verdicts = append(verdicts, verdict("same_tool_same_source_max_two", "same_tool_same_source_max_two", true, "hard", sameArgumentOK, sameArgumentDetail))

	steps := len(observation.ToolCalls)
	verdicts = append(verdicts, verdict("steps_within_limit", "steps_within_limit", true, "hard", steps <= question.MaxSteps,
		fmt.Sprintf("%d of %d", steps, question.MaxSteps)))

	maxChars := question.MaxChars
	if maxChars <= 0 {
		maxChars = set.Universal.MaxChars
	}
	length := len([]rune(answer))
	verdicts = append(verdicts, verdict("length_within_limit", "length_within_limit", true, "hard", length <= maxChars,
		fmt.Sprintf("%d of %d characters", length, maxChars)))

	verificationOK, verificationDetail := verificationStatusOK(observation)
	verdicts = append(verdicts, verdict("verification_not_failed", "verification_not_failed", true, "hard", verificationOK, verificationDetail))

	return verdicts
}

// verificationStatusOK reads the response's own verification/status surface.
// The field read is status plus the tool loop's stop_reason (both named in the
// report); CITATIONS_UNVERIFIED is the one failure the rules tolerate because
// a citation really failed.
func verificationStatusOK(observation Observation) (bool, string) {
	detail := fmt.Sprintf("status=%s stop_reason=%s", observation.Status, observation.StopReason)
	if observation.Status == "FAILED" {
		return false, detail
	}
	if observation.StopReason == "CITATIONS_UNVERIFIED" {
		return true, detail
	}
	switch observation.StopReason {
	case "TURN_LIMIT", "TOOL_LIMIT", "CONTEXT_LIMIT", "OUTPUT_LIMIT", "FORMAT_INVALID", "TRACE_LIMIT", "SCOPE_CHANGED":
		return false, detail
	}
	if strings.HasPrefix(observation.StopReason, "MODEL_") {
		return false, detail
	}
	return true, detail
}

func evaluateCheck(set *Set, question Question, check Check, observation Observation) RuleVerdict {
	group := check.Group
	if group == "" {
		if check.Hard {
			group = "hard"
		} else {
			group = "value"
		}
	}
	hard := check.Hard || group == "hard"
	result := RuleVerdict{ID: check.ID, Type: check.Type, Hard: hard, Group: group}
	answer := observation.Answer
	switch check.Type {
	case "max_nonempty_lines":
		lines := nonEmptyLines(answer)
		result.Passed = len(lines) <= check.Max
		result.Detail = fmt.Sprintf("%d lines", len(lines))
	case "mentions_literally":
		matched := matchingTerms(answer, check.Texts, true)
		result.Passed = len(matched) >= max(check.Min, 1)
		result.Detail = fmt.Sprintf("%d of %d: %s", len(matched), max(check.Min, 1), strings.Join(matched, ", "))
	case "mentions_terms":
		matched := matchingTerms(answer, check.Texts, false)
		result.Passed = len(matched) >= max(check.Min, 1)
		result.Detail = fmt.Sprintf("%d of %d: %s", len(matched), max(check.Min, 1), strings.Join(matched, ", "))
	case "contains_phrase":
		found := firstPhraseFold(answer, check.Texts)
		if found == "" && check.Text != "" {
			found = firstPhraseFold(answer, []string{check.Text})
		}
		result.Passed = found != ""
		result.Detail = found
	case "contains_number":
		result.Passed = regexp.MustCompile(`\d`).MatchString(answer)
	case "max_sql_calls":
		count := countCalls(observation.ToolCalls, "knowvault_source_sql")
		result.Passed = count <= check.Max
		result.Detail = fmt.Sprintf("%d SQL calls", count)
	case "min_sql_calls":
		count := countCalls(observation.ToolCalls, "knowvault_source_sql")
		result.Passed = count >= check.Min
		result.Detail = fmt.Sprintf("%d SQL calls", count)
	case "sql_text_contains":
		needle := strings.ToLower(check.Text)
		found := ""
		for _, sql := range observation.SQLTexts {
			if strings.Contains(strings.ToLower(sql), needle) {
				found = sql
				break
			}
		}
		result.Passed = found != ""
		result.Detail = found
	case "max_sentences":
		count := sentenceCount(answer)
		result.Passed = count <= check.Max
		result.Detail = fmt.Sprintf("%d sentences", count)
	case "question_marks":
		count := strings.Count(answer, "?")
		result.Passed = count >= check.Min && count <= check.Max
		result.Detail = fmt.Sprintf("%d question marks", count)
	case "live_result_citation":
		result.Passed = observation.LiveResultKind == "LIVE_TABLE" && observation.LiveResultReceipt != ""
		result.Detail = fmt.Sprintf("kind=%s receipt=%s", observation.LiveResultKind, observation.LiveResultReceipt)
	case "max_chars":
		length := len([]rune(answer))
		result.Passed = length <= check.Max
		result.Detail = fmt.Sprintf("%d of %d characters", length, check.Max)
	case "min_citations":
		result.Passed = len(observation.Citations) >= max(check.Min, 1)
		result.Detail = fmt.Sprintf("%d citation(s)", len(observation.Citations))
	case "citation_document":
		found := citationContains(observation.Citations, check.Text)
		result.Passed = found
		result.Detail = check.Text
	case "value_equals":
		expected, ok := set.expectedValue(check.Value)
		if !ok {
			result.Passed = false
			result.Detail = "unknown expected value " + check.Value
			break
		}
		result.Passed = containsStandaloneNumber(answer, expected)
		result.Detail = fmt.Sprintf("expected %d", expected)
	case "time_limit_s":
		result.Passed = observation.Seconds <= question.TimeLimitS
		result.Detail = fmt.Sprintf("%.2fs of %.0fs", observation.Seconds, question.TimeLimitS)
	case "o1_shape":
		expected, _ := set.expectedValue(check.Value)
		if containsStandaloneNumber(answer, expected) {
			result.Passed = true
			result.Detail = fmt.Sprintf("number %d", expected)
			break
		}
		marks := strings.Count(answer, "?")
		length := len([]rune(answer))
		result.Passed = marks == 1 && length <= check.Max
		result.Detail = fmt.Sprintf("%d question mark(s), %d characters", marks, length)
	case "contract_table_unchanged":
		result.Passed = observation.ContractUnchanged
		result.Detail = "row count and checksum of contract unchanged"
	default:
		result.Passed = false
		result.Detail = "unknown check type " + check.Type
	}
	return result
}

func (set *Set) expectedValue(name string) (int, bool) {
	switch name {
	case "A":
		return set.Environment.Values.A, true
	case "M":
		return set.Environment.Values.M, true
	}
	return 0, false
}

func verdict(id, kind string, hard bool, group string, passed bool, detail string) RuleVerdict {
	return RuleVerdict{ID: id, Type: kind, Hard: hard, Group: group, Passed: passed, Detail: detail}
}

func containsAnyFold(haystack string, needles []string) bool {
	return firstPhraseFold(haystack, needles) != ""
}

func firstPhraseFold(haystack string, needles []string) string {
	lower := strings.ToLower(haystack)
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(needle)) {
			return needle
		}
	}
	return ""
}

func matchingTerms(answer string, terms []string, literal bool) []string {
	matched := []string{}
	for _, term := range terms {
		if term == "" {
			continue
		}
		if literal {
			if strings.Contains(answer, term) {
				matched = append(matched, term)
			}
			continue
		}
		if strings.Contains(strings.ToLower(answer), strings.ToLower(term)) {
			matched = append(matched, term)
		}
	}
	return matched
}

func countCalls(calls []ToolCall, name string) int {
	count := 0
	for _, call := range calls {
		if call.Name == name {
			count++
		}
	}
	return count
}

func citationContains(citations []Citation, text string) bool {
	if text == "" {
		return false
	}
	needle := strings.ToLower(text)
	for _, citation := range citations {
		if strings.Contains(strings.ToLower(citation.Text), needle) || strings.Contains(strings.ToLower(citation.Excerpt), needle) {
			return true
		}
	}
	return false
}

func containsStandaloneNumber(answer string, expected int) bool {
	pattern := regexp.MustCompile(`(^|[^0-9])` + fmt.Sprintf("%d", expected) + `([^0-9]|$)`)
	return pattern.MatchString(answer)
}

func nonEmptyLines(answer string) []string {
	lines := []string{}
	for _, line := range strings.Split(answer, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func sentenceCount(answer string) int {
	count := 0
	for _, part := range regexp.MustCompile(`[.!?…]+`).Split(strings.ReplaceAll(answer, "\n", " "), -1) {
		if strings.TrimSpace(part) != "" {
			count++
		}
	}
	return count
}

// stripCode removes fenced code blocks and inline code spans so the language
// ratio only measures prose.
func stripCode(answer string) string {
	fence := regexp.MustCompile("(?s)```.*?```")
	stripped := fence.ReplaceAllString(answer, " ")
	inline := regexp.MustCompile("`[^`]*`")
	return inline.ReplaceAllString(stripped, " ")
}

func cyrillicRatio(text string) (float64, int) {
	cyrillic, letters := 0, 0
	for _, r := range text {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		if unicode.Is(unicode.Cyrillic, r) {
			cyrillic++
		}
	}
	if letters == 0 {
		return 0, 0
	}
	return float64(cyrillic) / float64(letters), letters
}

func normalizeArguments(raw string) string {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return string(normalized)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
