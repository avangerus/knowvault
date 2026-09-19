// Command mutation-registry executes the R1 product-semantic mutation corpus.
// Every case starts from a clean source copy and a green baseline is required
// before either a weakening or a semantic-preserving mutation is evaluated.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type mutationTestRegistry struct {
	RegistryVersion string                      `json:"registry_version"`
	Entries         []mutationTestRegistryEntry `json:"entries"`
}

type mutationTestRegistryEntry struct {
	InvariantID          string             `json:"invariant_id"`
	CriticalInvariantIDs []string           `json:"critical_invariant_ids"`
	Harness              string             `json:"harness"`
	TestName             string             `json:"test_name"`
	TestPackage          string             `json:"test_package"`
	Mutations            []mutationTestCase `json:"mutations"`
}

type mutationTestCase struct {
	ID           string `json:"id"`
	Target       string `json:"target"`
	Kind         string `json:"kind"`
	Expected     string `json:"expected"`
	Old          string `json:"old"`
	New          string `json:"new"`
	SchemaCaseID string `json:"schema_case_id"`
}

func main() {
	rootFlag := flag.String("root", ".", "repository root")
	flag.Parse()

	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		fatal(err)
	}
	if os.Getenv("KNOWVAULT_TEST_POSTGRES_URL") == "" {
		fatal(errors.New("KNOWVAULT_TEST_POSTGRES_URL is required; mutation evidence cannot skip PostgreSQL"))
	}
	if os.Getenv("KNOWVAULT_TEST_OFFICE_WORKER_IMAGE") == "" {
		fatal(errors.New("KNOWVAULT_TEST_OFFICE_WORKER_IMAGE is required; mutation evidence cannot skip the isolated parser"))
	}

	registry, err := readRegistry(filepath.Join(root, "tests", "contracts", "mutation-registry.json"))
	if err != nil {
		fatal(err)
	}
	if registry.RegistryVersion != "1.0" {
		fatal(fmt.Errorf("unsupported mutation registry version %q", registry.RegistryVersion))
	}

	env := overrideEnvironment(os.Environ(), "REPO_ROOT", root)
	baseline := make(map[string]bool)
	for _, entry := range registry.Entries {
		if entry.TestName == "" {
			fatal(fmt.Errorf("mutation entry %q has no executable test", entry.InvariantID))
		}
		baselineKey := entry.Harness + "/" + entry.TestName
		if !baseline[baselineKey] {
			fmt.Printf("BASELINE %s/%s ...\n", entry.Harness, entry.TestName)
			ok, output, runErr := runHarness(root, root, entry.Harness, entry.TestPackage, entry.TestName, env)
			if runErr != nil {
				fatal(fmt.Errorf("baseline %s/%s could not start: %w\n%s", entry.Harness, entry.TestName, runErr, output))
			}
			if !ok {
				fatal(fmt.Errorf("baseline %s/%s is not green; external prerequisites are not satisfied\n%s", entry.Harness, entry.TestName, output))
			}
			baseline[baselineKey] = true
			fmt.Printf("BASELINE %s/%s GREEN\n", entry.Harness, entry.TestName)
		}
		for _, mutation := range entry.Mutations {
			fmt.Printf("MUTATION %s/%s expected=%s ...\n", entry.InvariantID, mutation.ID, mutation.Expected)
			mutatedRoot, cleanup, applyErr := materializeMutation(root, mutation)
			if applyErr != nil {
				fatal(fmt.Errorf("materialize %s/%s: %w", entry.InvariantID, mutation.ID, applyErr))
			}
			mutationEnvironment := overrideEnvironment(env, "REPO_ROOT", mutatedRoot)
			if entry.Harness == "SCHEMA_SUITE" {
				mutationEnvironment = overrideEnvironment(mutationEnvironment, "SCHEMA_CASE_ID", mutation.SchemaCaseID)
			}
			ok, output, runErr := runHarness(root, mutatedRoot, entry.Harness, entry.TestPackage, entry.TestName, mutationEnvironment)
			cleanupErr := cleanup()
			if cleanupErr != nil {
				fatal(fmt.Errorf("cleanup %s/%s: %w", entry.InvariantID, mutation.ID, cleanupErr))
			}
			if runErr != nil {
				fatal(fmt.Errorf("mutation %s/%s could not start: %w\n%s", entry.InvariantID, mutation.ID, runErr, output))
			}
			expectedGreen := mutation.Expected == "GREEN"
			if ok != expectedGreen {
				fatal(fmt.Errorf("mutation %s/%s produced %s, expected %s\n%s", entry.InvariantID, mutation.ID, outcome(ok), mutation.Expected, output))
			}
			fmt.Printf("MUTATION %s/%s %s\n", entry.InvariantID, mutation.ID, outcome(ok))
		}
	}
	runDualLayerProbes(root, env)

	fmt.Printf("Mutation registry passed: %d invariant entries, %d mutation cases.\n", len(registry.Entries), mutationCount(registry))
}

// recognizedUncoveredEntry is the ADR-0071 registration shape the runner needs
// for probe execution; the checker owns the full structural validation.
type recognizedUncoveredEntry struct {
	CriticalID  string `json:"critical_id"`
	Disposition string `json:"disposition"`
	Probe       string `json:"probe"`
}

type recognizedUncoveredFile struct {
	Version int                        `json:"version"`
	Entries []recognizedUncoveredEntry `json:"entries"`
}

// runDualLayerProbes executes every committed dual-layer probe from the
// recognized-uncovered registry and requires exit 0 (ADR-0071 §1.2). A dual
// layer whose probe is missing, unpinned or failing is a red CI state — the
// probe's liveness is executed here, never assumed.
func runDualLayerProbes(root string, environment []string) {
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "recognized-uncovered-critical.json"))
	if err != nil {
		fatal(fmt.Errorf("read recognized-uncovered registry: %w", err))
	}
	var recognized recognizedUncoveredFile
	if err := json.Unmarshal(raw, &recognized); err != nil {
		fatal(fmt.Errorf("parse recognized-uncovered registry: %w", err))
	}
	if recognized.Version != 1 {
		fatal(fmt.Errorf("unsupported recognized-uncovered registry version %d", recognized.Version))
	}
	for _, entry := range recognized.Entries {
		if entry.Disposition != "DUAL_LAYER" {
			continue
		}
		if entry.Probe == "" {
			fatal(fmt.Errorf("dual-layer entry %q has no probe", entry.CriticalID))
		}
		probePath := filepath.Join(root, filepath.FromSlash(entry.Probe))
		if info, err := os.Stat(probePath); err != nil || info.IsDir() {
			fatal(fmt.Errorf("dual-layer probe for %q is missing: %q", entry.CriticalID, entry.Probe))
		}
		fmt.Printf("PROBE %s ...\n", entry.CriticalID)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		command := exec.CommandContext(ctx, "pwsh", "-NoProfile", "-File", probePath, "-Root", root)
		command.Dir = root
		command.Env = environment
		var output bytes.Buffer
		command.Stdout = &output
		command.Stderr = &output
		err := command.Run()
		if ctx.Err() != nil {
			cancel()
			fatal(fmt.Errorf("dual-layer probe %s timed out: %w", entry.CriticalID, ctx.Err()))
		}
		cancel()
		if err != nil {
			fatal(fmt.Errorf("dual-layer probe %s failed (exit 0 required): %w\n%s", entry.CriticalID, err, output.String()))
		}
		fmt.Printf("PROBE %s PASSED\n", entry.CriticalID)
	}
}

func readRegistry(path string) (mutationTestRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return mutationTestRegistry{}, err
	}
	var registry mutationTestRegistry
	if err := json.Unmarshal(raw, &registry); err != nil {
		return mutationTestRegistry{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return registry, nil
}

func mutationCount(registry mutationTestRegistry) int {
	count := 0
	for _, entry := range registry.Entries {
		count += len(entry.Mutations)
	}
	return count
}

func materializeMutation(root string, mutation mutationTestCase) (string, func() error, error) {
	temporaryRoot, err := os.MkdirTemp("", "knowvault-mutation-")
	if err != nil {
		return "", func() error { return nil }, err
	}
	cleanup := func() error { return os.RemoveAll(temporaryRoot) }
	if err := copyMutationTree(root, temporaryRoot); err != nil {
		_ = cleanup()
		return "", func() error { return nil }, err
	}
	target := filepath.Join(temporaryRoot, filepath.FromSlash(mutation.Target))
	source, err := os.ReadFile(target)
	if err != nil {
		_ = cleanup()
		return "", func() error { return nil }, err
	}
	old := []byte(mutation.Old)
	if bytes.Count(source, old) != 1 {
		_ = cleanup()
		return "", func() error { return nil }, fmt.Errorf("mutation anchor occurs %d times in %s", bytes.Count(source, old), mutation.Target)
	}
	mutated := bytes.Replace(source, old, []byte(mutation.New), 1)
	if bytes.Equal(source, mutated) {
		_ = cleanup()
		return "", func() error { return nil }, errors.New("mutation did not change its target")
	}
	if err := os.WriteFile(target, mutated, 0o644); err != nil {
		_ = cleanup()
		return "", func() error { return nil }, err
	}
	return temporaryRoot, cleanup, nil
}

func copyMutationTree(root, destination string) error {
	// scripts/ and the governance documents are copied because the
	// checker-native corpus entries execute checker self-tests that read the
	// real .github workflow, delivery state, the protected tests/e2e tree and
	// license policy from the mutated tree. The checker also reads architecture/guardrails.yaml,
	// architecture/protected-hashes.json and
	// architecture/recognized-uncovered-critical.json from its working
	// directory, and POSTGRES_INTEGRATION entries mutate SQL/Go targets whose
	// baselines must run against the full tree — so the three architecture
	// files join the copied set, making the copied tree's read-set match the
	// checker's. Every harness only ever reads from this copied tree, so the
	// extra files cannot affect non-checker entries.
	for _, relative := range []string{
		"go.mod", "go.sum", "internal", "cmd", "db", "deploy", "architecture/contracts",
		"architecture/guardrails.yaml", "architecture/protected-hashes.json",
		"architecture/recognized-uncovered-critical.json",
		"architecture/licenses.yaml", "architecture/versions.json",
		"tests/contracts", "tests/e2e", "tests/integration/postgres", "tests/integration/parserv2harness", "tests/integration/sandboxdispatch",
		"scripts", "docs", "CONTRIBUTING.md", ".github",
	} {
		source := filepath.Join(root, filepath.FromSlash(relative))
		target := filepath.Join(destination, filepath.FromSlash(relative))
		if info, err := os.Stat(source); err != nil {
			return fmt.Errorf("stat %s: %w", relative, err)
		} else if info.IsDir() {
			if err := copyDirectory(source, target); err != nil {
				return fmt.Errorf("copy %s: %w", relative, err)
			}
		} else if err := copyFile(source, target); err != nil {
			return fmt.Errorf("copy %s: %w", relative, err)
		}
	}
	return nil
}

func copyDirectory(source, destination string) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "node_modules" {
			continue
		}
		from := filepath.Join(source, entry.Name())
		to := filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			if err := copyDirectory(from, to); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(from, to); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

// postgresIntegrationTimeout bounds each independent PostgreSQL integration
// invocation (baseline and every mutant) with its own finite deadline.
const postgresIntegrationTimeout = 15 * time.Minute

func runIntegrationTest(root, testName string, environment []string) (bool, string, error) {
	// The real Office parser proof repeatedly crosses Docker, PID namespace and
	// cgroup boundaries. A successful cold baseline was measured at 7m49.693s on
	// the hosted CI runner, which left the previous eight-minute deadline too
	// tight: the following mutant could be killed at the same hard deadline
	// without ever producing a verdict. Each independent invocation now receives
	// its own finite fifteen-minute deadline, which still fails closed when the
	// proof genuinely hangs or stalls.
	ctx, cancel := context.WithTimeout(context.Background(), postgresIntegrationTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-count=1", "./tests/integration/postgres", "-run", "^"+testName+"$")
	command.Dir = root
	command.Env = environment
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil {
		return false, output.String(), ctx.Err()
	}
	if err == nil {
		return true, output.String(), nil
	}
	return false, output.String(), nil
}

func runUnitTest(root, packagePath, testName string, environment []string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "test", "-mod=readonly", "-count=1", packagePath, "-run", "^"+testName+"$")
	command.Dir = root
	command.Env = environment
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil {
		return false, output.String(), ctx.Err()
	}
	if err == nil {
		return true, output.String(), nil
	}
	return false, output.String(), nil
}

func runHarness(originalRoot, executionRoot, harness, testPackage, testName string, environment []string) (bool, string, error) {
	switch harness {
	case "POSTGRES_INTEGRATION":
		return runIntegrationTest(executionRoot, testName, environment)
	case "SCHEMA_SUITE":
		return runSchemaSuite(originalRoot, executionRoot, environment)
	case "GO_UNIT":
		return runUnitTest(executionRoot, testPackage, testName, environment)
	default:
		return false, "", fmt.Errorf("unsupported mutation harness %q", harness)
	}
}

func runSchemaSuite(originalRoot, executionRoot string, environment []string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	script := filepath.Join(originalRoot, "tests", "contracts", "schema-tests.mjs")
	command := exec.CommandContext(ctx, "node", script)
	command.Dir = originalRoot
	command.Env = overrideEnvironment(environment, "REPO_ROOT", executionRoot)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil {
		return false, output.String(), ctx.Err()
	}
	if err == nil {
		return true, output.String(), nil
	}
	return false, output.String(), nil
}

func overrideEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	overridden := make([]string, 0, len(environment)+1)
	found := false
	for _, item := range environment {
		if strings.HasPrefix(item, prefix) {
			if !found {
				overridden = append(overridden, prefix+value)
				found = true
			}
			continue
		}
		overridden = append(overridden, item)
	}
	if !found {
		overridden = append(overridden, prefix+value)
	}
	return overridden
}

func outcome(green bool) string {
	if green {
		return "GREEN"
	}
	return "RED"
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "mutation registry failed: %v\n", err)
	os.Exit(1)
}
