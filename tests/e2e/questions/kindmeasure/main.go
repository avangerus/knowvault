// Command kindmeasure measures ADR-0099 amendment 1's separate recognition
// step on the real model (card D-15, result 3).
//
// Given a file of phrasings with their expected kinds, it runs each phrasing
// the configured number of times through exactly the recognition step the
// product uses (internal/question's model-backed KindRecogniser) and prints:
//
//   - per expected kind, how many phrasings were recognised correctly;
//   - separately, every case where a `full` question was recognised as any
//     other kind.
//
// It exits non-zero when the overall accuracy is below -min-accuracy or when a
// single `full` question was recognised as another kind, so the command itself
// can gate the card's acceptance criterion.
//
// Run it with the wrapper: tests/e2e/questions/run-kind-measure.sh -file PATH
//
// The phrasings file is JSON: either a bare array or an object under
// "phrasings", each entry {"question": "...", "kind": "full"} where kind is one
// of full, change, hypothetical, plain_overview, workspace_overview,
// sources_overview, greeting, off_topic, vague.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/question"
)

// phrasing is one line of the input file.
type phrasing struct {
	Question string `json:"question"`
	Kind     string `json:"kind"`
}

// phrasingDocument is the object form of the input file. A bare JSON array of
// phrasing is accepted too.
type phrasingDocument struct {
	Phrasings []phrasing `json:"phrasings"`
}

// attempt is one recognition of one phrasing.
type attempt struct {
	Question string
	Run      int
	Expected question.AnswerKind
	Got      question.AnswerKind
	Usage    modelgateway.TokenUsage
}

func (item attempt) Correct() bool { return item.Expected == item.Got }

// tally is one expected kind's per-kind count.
type tally struct {
	Expected question.AnswerKind
	Correct  int
	Total    int
}

func main() {
	file := flag.String("file", "", "JSON file of phrasings with expected kinds (required)")
	runs := flag.Int("runs", 3, "recognition runs per phrasing")
	keyFile := flag.String("key-file", "", "file holding the model API key (default $KNOWVAULT_KIND_MEASURE_API_KEY_FILE or $HOME/.deepseek/api_key)")
	endpoint := flag.String("endpoint", "https://api.deepseek.com/v1", "OpenAI-compatible chat-completions base URL")
	model := flag.String("model", "deepseek-flash", "model id")
	workspace := flag.String("workspace", "ws_kind_measure", "workspace identity the model call is scoped to")
	minAccuracy := flag.Float64("min-accuracy", 0.95, "minimum fraction of recognition runs that must be correct")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout of one recognition call")
	flag.Parse()

	if err := run(*file, *runs, resolveKeyFile(*keyFile), *endpoint, *model, *workspace, *minAccuracy, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "kind measure:", err)
		os.Exit(1)
	}
}

func run(file string, runs int, keyFile, endpoint, model, workspace string, minAccuracy float64, timeout time.Duration) error {
	if strings.TrimSpace(file) == "" {
		return fmt.Errorf("-file is required")
	}
	if runs < 1 {
		return fmt.Errorf("-runs must be at least 1")
	}
	if minAccuracy < 0 || minAccuracy > 1 {
		return fmt.Errorf("-min-accuracy must be between 0 and 1")
	}
	phrasings, err := loadPhrasings(file)
	if err != nil {
		return err
	}
	apiKey, err := readKeyFile(keyFile)
	if err != nil {
		return err
	}
	adapter, err := newAdapter(endpoint, model, apiKey, workspace, timeout)
	if err != nil {
		return err
	}
	defer adapter.Close()

	recogniser := question.NewModelKindRecogniser(adapter, workspace)
	if recogniser == nil {
		return fmt.Errorf("recognition step could not be built for workspace %q", workspace)
	}

	attempts := measure(context.Background(), recogniser, phrasings, runs)
	render(os.Stdout, attempts, runs, model, minAccuracy)

	correct, total := 0, 0
	for _, item := range attempts {
		total++
		if item.Correct() {
			correct++
		}
	}
	accuracy := 0.0
	if total > 0 {
		accuracy = float64(correct) / float64(total)
	}
	if misses := fullMisrecognitions(attempts); len(misses) > 0 {
		return fmt.Errorf("%d full question(s) were recognised as another kind", len(misses))
	}
	if accuracy < minAccuracy {
		return fmt.Errorf("accuracy %.4f is below the required %.4f", accuracy, minAccuracy)
	}
	return nil
}

func resolveKeyFile(explicit string) string {
	if value := strings.TrimSpace(explicit); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("KNOWVAULT_KIND_MEASURE_API_KEY_FILE")); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + string(os.PathSeparator) + ".deepseek" + string(os.PathSeparator) + "api_key"
}

// readKeyFile reads the key only at run time. The path is never echoed with the
// key, and the key is never written anywhere but into the adapter.
func readKeyFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("no API key file: pass -key-file or set KNOWVAULT_KIND_MEASURE_API_KEY_FILE")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read API key file: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if key == "" {
		return "", fmt.Errorf("API key file is empty")
	}
	return key, nil
}

// loadPhrasings accepts a bare JSON array or an object under "phrasings".
func loadPhrasings(path string) ([]phrasing, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read phrasings: %w", err)
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("phrasings file is empty")
	}
	var list []phrasing
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("decode phrasings array: %w", err)
		}
	} else {
		var document phrasingDocument
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, fmt.Errorf("decode phrasings document: %w", err)
		}
		list = document.Phrasings
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("phrasings file has no phrasings")
	}
	for index, item := range list {
		if strings.TrimSpace(item.Question) == "" {
			return nil, fmt.Errorf("phrasing %d has no question", index+1)
		}
		if _, ok := question.ParseAnswerKind(item.Kind); !ok {
			return nil, fmt.Errorf("phrasing %d has unknown expected kind %q", index+1, item.Kind)
		}
	}
	return list, nil
}

// newAdapter builds the real model channel. The endpoint is treated as an
// external workspace-scoped runtime, exactly like the production mount: it
// carries its own trust roots and is reachable only by the named workspace.
func newAdapter(endpoint, model, apiKey, workspace string, timeout time.Duration) (*modelgateway.LabAdapter, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return nil, fmt.Errorf("system certificate pool: %w", err)
	}
	seconds := int(timeout.Seconds())
	if seconds < 10 {
		seconds = 10
	}
	if seconds > modelgateway.MaxToolLoopTimeoutSeconds {
		seconds = modelgateway.MaxToolLoopTimeoutSeconds
	}
	return modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion,
		Endpoint:      endpoint, ModelID: model, APIKey: apiKey,
		MaxOutputTokens: 4096, InsecureLabMode: true,
		ThinkingMode:                modelgateway.ThinkingModeDisabled,
		TrustRoots:                  pool,
		ExternalRuntimeWorkspaceIDs: []string{workspace},
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "kind-measure", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 65536,
			MaxToolResultBytes: 8192, MaxOutputTokens: 2048, TimeoutSeconds: seconds,
		},
	})
}

// measure runs every phrasing through the recognition step and records each
// attempt, in input order, with its expected kind. The step never returns an
// error: a failed or unlisted answer is recorded as the resolved kind (full).
func measure(ctx context.Context, recogniser question.KindRecogniser, phrasings []phrasing, runs int) []attempt {
	attempts := make([]attempt, 0, len(phrasings)*runs)
	for _, item := range phrasings {
		expected, _ := question.ParseAnswerKind(item.Kind)
		for run := 1; run <= runs; run++ {
			recognition := recogniser.Recognise(ctx, item.Question)
			attempts = append(attempts, attempt{
				Question: item.Question, Run: run, Expected: expected,
				Got: recognition.Resolved(), Usage: recognition.Usage,
			})
		}
	}
	return attempts
}

// fullMisrecognitions lists every attempt whose expected kind is full and whose
// recognised kind is not.
func fullMisrecognitions(attempts []attempt) []attempt {
	misses := []attempt{}
	for _, item := range attempts {
		if item.Expected == question.AnswerKindFull && item.Got != question.AnswerKindFull {
			misses = append(misses, item)
		}
	}
	return misses
}

// tallies returns the per-expected-kind counts in the closed list's order.
func tallies(attempts []attempt) []tally {
	byKind := map[question.AnswerKind]*tally{}
	for _, item := range attempts {
		entry, ok := byKind[item.Expected]
		if !ok {
			entry = &tally{Expected: item.Expected}
			byKind[item.Expected] = entry
		}
		entry.Total++
		if item.Correct() {
			entry.Correct++
		}
	}
	list := make([]tally, 0, len(byKind))
	for _, kind := range question.AnswerKinds() {
		if entry, ok := byKind[kind]; ok {
			list = append(list, *entry)
		}
	}
	return list
}

// render prints the per-kind counts, the full-to-other list and the cost.
func render(out io.Writer, attempts []attempt, runs int, model string, minAccuracy float64) {
	fmt.Fprintf(out, "kind recognition: %d phrasing(s), %d run(s) each on model %q\n", len(attempts)/max(runs, 1), runs, model)
	total, correct := 0, 0
	inputTokens, outputTokens := 0, 0
	for _, item := range attempts {
		total++
		if item.Correct() {
			correct++
		}
		inputTokens += item.Usage.Input
		outputTokens += item.Usage.Output
	}
	accuracy := 0.0
	if total > 0 {
		accuracy = float64(correct) / float64(total)
	}
	fmt.Fprintf(out, "recognised correctly: %d/%d (%.1f%%); required %.1f%% -> %s\n\n",
		correct, total, accuracy*100, minAccuracy*100, passFail(accuracy >= minAccuracy))

	fmt.Fprintln(out, "per expected kind:")
	for _, entry := range tallies(attempts) {
		fmt.Fprintf(out, "  %-18s %d/%d\n", entry.Expected, entry.Correct, entry.Total)
	}
	fmt.Fprintln(out)

	misses := fullMisrecognitions(attempts)
	fmt.Fprintf(out, "full questions recognised as another kind: %d\n", len(misses))
	for _, miss := range misses {
		fmt.Fprintf(out, "  got %-18s run %d  %q\n", miss.Got, miss.Run, miss.Question)
	}
	fmt.Fprintln(out)

	fmt.Fprintf(out, "recognition cost: %d input + %d output = %d tokens", inputTokens, outputTokens, inputTokens+outputTokens)
	if total > 0 {
		fmt.Fprintf(out, " (%.0f input + %.0f output per recognition)",
			float64(inputTokens)/float64(total), float64(outputTokens)/float64(total))
	}
	fmt.Fprintln(out)

	// Misrecognitions other than full-to-other are not a hard failure by
	// themselves, but naming them makes the per-kind numbers auditable.
	others := []attempt{}
	for _, item := range attempts {
		if !item.Correct() && !(item.Expected == question.AnswerKindFull) {
			others = append(others, item)
		}
	}
	if len(others) > 0 {
		sort.SliceStable(others, func(i, j int) bool { return others[i].Expected < others[j].Expected })
		fmt.Fprintln(out, "\nother misrecognitions:")
		for _, item := range others {
			fmt.Fprintf(out, "  expected %-16s got %-18s run %d  %q\n", item.Expected, item.Got, item.Run, item.Question)
		}
	}
}

func passFail(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
