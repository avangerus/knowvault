// Command check-architecture enforces repository-level anti-drift rules.
// It intentionally uses only the Go standard library so the guardrail itself
// cannot introduce an unreviewed dependency.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type protectedManifest struct {
	Version   int               `json:"version"`
	Algorithm string            `json:"algorithm"`
	Files     map[string]string `json:"files"`
}

type invariantTestRegistry struct {
	Rules []struct {
		ID             string   `json:"id"`
		Phase          string   `json:"phase"`
		Status         string   `json:"status"`
		PhaseState     string   `json:"phase_state"`
		Harness        string   `json:"harness"`
		MutationCorpus string   `json:"mutation_corpus"`
		CaseIDs        []string `json:"case_ids"`
		TestNames      []string `json:"test_names"`
	} `json:"rules"`
}

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

// recognizedUncoveredCriticalFile is the ADR-0071 registration of critical
// invariants whose product stage has not arrived yet (STAGE_GATED) or whose
// enforcement is proven dual-layer by a pinned probe (DUAL_LAYER). Recognition
// is the explicit, machine-validated "current debt, not future work" registration, never
// a silent exemption: suppression is conditional and self-policing.
type recognizedUncoveredCriticalFile struct {
	Version int                  `json:"version"`
	Entries []recognizedCritical `json:"entries"`
}

type recognizedCritical struct {
	CriticalID   string `json:"critical_id"`
	Disposition  string `json:"disposition"`
	ProductStage string `json:"product_stage"`
	Probe        string `json:"probe"`
	Evidence     string `json:"evidence"`
}

type invariantRegistryRegistration struct {
	Status         string
	CaseIDs        []string
	Harness        string
	MutationCorpus string
	TestNames      []string
}

type fixtureCaseIndex struct {
	Cases []struct {
		ID                  string `json:"id"`
		Kind                string `json:"kind"`
		ExpectedSchemaValid *bool  `json:"expected_schema_valid"`
	} `json:"cases"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	rebaseline := flag.Bool("rebaseline", false, "recompute architecture/protected-hashes.json from the protected inventory and exit")
	verifyE2EJSON := flag.String("verify-e2e-json", "", "verify the machine-readable JSON output of the exact R3 e2e test")
	verifyE2EPackage := flag.String("verify-e2e-package", "", "expected package in the R3 e2e JSON output")
	verifyE2ETest := flag.String("verify-e2e-test", "", "expected test name in the R3 e2e JSON output")
	verifyParserSyftJSON := flag.String("verify-parser-syft-json", "", "verify a Syft JSON scan against the locked parser release identity")
	verifyParserGrypeJSON := flag.String("verify-parser-grype-json", "", "verify a Grype JSON scan against the locked parser release identity and database")
	verifyParserNativeGrypeJSON := flag.String("verify-parser-native-grype-json", "", "verify the exact native libc6 PURL scan against the same locked database")
	flag.Parse()
	if *verifyE2EJSON != "" {
		if err := verifyR3E2EJSON(*verifyE2EJSON, *verifyE2EPackage, *verifyE2ETest); err != nil {
			fatal([]string{"R3 e2e JSON proof failed: " + err.Error()})
		}
		fmt.Println("R3 e2e JSON proof passed.")
		return
	}
	if *verifyParserSyftJSON != "" || *verifyParserGrypeJSON != "" || *verifyParserNativeGrypeJSON != "" {
		if *verifyParserSyftJSON == "" || *verifyParserGrypeJSON == "" || *verifyParserNativeGrypeJSON == "" {
			fatal([]string{"parser release scan proof requires Syft, image Grype and native Grype JSON inputs"})
		}
		absRoot, err := filepath.Abs(*root)
		if err != nil {
			fatal([]string{err.Error()})
		}
		if err := verifyParserReleaseScans(absRoot, *verifyParserSyftJSON, *verifyParserGrypeJSON, *verifyParserNativeGrypeJSON); err != nil {
			fatal([]string{"parser release scan proof failed: " + err.Error()})
		}
		fmt.Println("parser release scan proof passed.")
		return
	}

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fatal([]string{err.Error()})
	}
	if *rebaseline {
		if err := rebuildProtectedManifest(absRoot); err != nil {
			fatal([]string{err.Error()})
		}
		fmt.Println("protected-hashes baseline rebuilt.")
		return
	}

	var problems []string
	stage1DatabaseProblems := checkStage1DatabaseGate(absRoot)
	stage1DatabaseReady := len(stage1DatabaseProblems) == 0
	problems = append(problems, stage1DatabaseProblems...)
	problems = append(problems, checkProtectedFiles(absRoot)...)
	problems = append(problems, checkAcceptedADRImmutability(absRoot)...)
	problems = append(problems, checkContractJSON(absRoot)...)
	problems = append(problems, checkFixtureJSON(absRoot)...)
	problems = append(problems, checkInvariantTestRegistry(absRoot)...)
	problems = append(problems, checkVersionLock(absRoot)...)
	problems = append(problems, checkActualDependencyInventory(absRoot)...)
	problems = append(problems, checkGoDependencyChecksumCoverage(absRoot)...)
	problems = append(problems, checkOIDCImportBoundary(absRoot)...)
	problems = append(problems, checkSecretMountImportBoundary(absRoot)...)
	problems = append(problems, checkRuntimeGIDConsistency(absRoot)...)
	problems = append(problems, checkTrustBundleBoundary(absRoot)...)
	problems = append(problems, checkProductionConstructorBoundary(absRoot)...)
	problems = append(problems, checkCompositionImportBoundary(absRoot)...)
	problems = append(problems, checkProductionRuntimeBoundary(absRoot)...)
	problems = append(problems, checkScopeGlobBoundary(absRoot)...)
	problems = append(problems, checkFolderConnectorBoundary(absRoot)...)
	problems = append(problems, checkHTMLParserBoundary(absRoot)...)
	problems = append(problems, checkNetHTMLModuleScope(absRoot)...)
	problems = append(problems, checkCatalogEvidenceBoundary(absRoot)...)
	problems = append(problems, checkScopeRevisionCutoverBoundary(absRoot)...)
	problems = append(problems, checkWorkspaceSourceRepository(absRoot)...)
	problems = append(problems, checkWorkspaceManagedAuthorityCommandBoundary(absRoot)...)
	problems = append(problems, checkWorkspaceManagedAuthorityCommandRuntime(absRoot)...)
	problems = append(problems, checkArtifactCompositionForbidden(absRoot)...)
	problems = append(problems, checkParserSandboxBoundary(absRoot)...)
	problems = append(problems, checkIngestionSpawnBoundary(absRoot)...)
	problems = append(problems, checkSandboxDispatcherBoundary(absRoot)...)
	problems = append(problems, checkV2TestOnlyBoundary(absRoot)...)
	problems = append(problems, checkDocumentParserEntrypointBoundary(absRoot)...)
	problems = append(problems, checkExtractionIdentityBinding(absRoot)...)
	problems = append(problems, checkSupplyChainLifecycleBoundary(absRoot)...)
	problems = append(problems, checkParserRuntimeCompliance(absRoot)...)
	problems = append(problems, checkDeferredStageLeaks(absRoot, stage1DatabaseReady)...)
	problems = append(problems, checkLicensePolicy(absRoot)...)
	problems = append(problems, checkRequiredCI(absRoot)...)
	problems = append(problems, checkForbiddenDirectories(absRoot)...)
	problems = append(problems, checkCommandSurface(absRoot)...)
	problems = append(problems, checkApplicationLanguages(absRoot)...)
	problems = append(problems, checkAPI(absRoot)...)
	problems = append(problems, checkUISurface(absRoot)...)
	problems = append(problems, checkDeploymentManifests(absRoot)...)
	problems = append(problems, checkOperatorArtifact(absRoot)...)
	problems = append(problems, checkGoBoundaries(absRoot)...)
	problems = append(problems, checkAuthorizeNoOpGate(absRoot)...)

	if len(problems) > 0 {
		sort.Strings(problems)
		fatal(problems)
	}

	fmt.Println("Architecture guardrails passed.")
}

// verifyR3E2EJSON is the runtime half of the R3 execution proof. A successful
// package event is not evidence that the named test ran: go test emits a
// package-level pass even when -run selects no tests. We therefore require one
// and only one exact test event with Action=pass and reject the no-test marker
// and every malformed/non-JSON line. The caller owns the process exit status;
// this verifier only proves the structured event stream.
func verifyR3E2EJSON(path, expectedPackage, expectedTest string) error {
	if path == "" || expectedPackage == "" || expectedTest == "" {
		return fmt.Errorf("JSON path, package and test are required")
	}
	if expectedPackage != r3E2EPackage {
		return fmt.Errorf("R3 verifier is bound to the exact package %s", r3E2EPackage)
	}
	if expectedTest != r3E2ETest || !regexp.MustCompile(`^Test[A-Za-z0-9]+$`).MatchString(expectedTest) {
		return fmt.Errorf("R3 verifier is bound to the exact TestE2ER3FullLoop name")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	type event struct {
		Action  string `json:"Action"`
		Package string `json:"Package"`
		Test    string `json:"Test"`
		Output  string `json:"Output"`
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	lineNumber := 0
	exactPasses := 0
	exactRuns := 0
	exactFailures := 0
	hadEvent := false
	for scanner.Scan() {
		lineNumber++
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return fmt.Errorf("blank line %d is not a go test JSON event", lineNumber)
		}
		var decoded event
		if err := json.Unmarshal(line, &decoded); err != nil {
			return fmt.Errorf("line %d is not valid JSON: %w", lineNumber, err)
		}
		hadEvent = true
		if strings.Contains(strings.ToLower(decoded.Output), "no tests to run") {
			return fmt.Errorf("line %d reports no tests to run", lineNumber)
		}
		if decoded.Package != expectedPackage || decoded.Test != expectedTest {
			continue
		}
		switch decoded.Action {
		case "run":
			exactRuns++
		case "pass":
			exactPasses++
		case "fail":
			exactFailures++
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read JSON events: %w", err)
	}
	if !hadEvent {
		return fmt.Errorf("JSON event stream is empty")
	}
	if exactRuns != 1 {
		return fmt.Errorf("expected exactly one run event for %s/%s, got %d", expectedPackage, expectedTest, exactRuns)
	}
	if exactPasses != 1 {
		return fmt.Errorf("expected exactly one pass event for %s/%s, got %d", expectedPackage, expectedTest, exactPasses)
	}
	if exactFailures != 0 {
		return fmt.Errorf("exact test emitted %d fail event(s)", exactFailures)
	}
	return nil
}

// verifyParserReleaseScans binds live scanner output to the protected parser
// release lock. CI generates both JSON documents from the just-built image with
// exact scanner images and an exact Grype database; this verifier rejects a
// clean scan of a different image, tool, database or package closure.
func verifyParserReleaseScans(root, syftPath, grypePath, nativeGrypePath string) error {
	readObject := func(path string) (map[string]any, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := rejectDuplicateJSON(raw); err != nil {
			return nil, err
		}
		var object map[string]any
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, err
		}
		return object, nil
	}
	lock, err := readObject(filepath.Join(root, "workers", "document-parser", "release", "image-lock.json"))
	if err != nil {
		return fmt.Errorf("read parser image lock: %w", err)
	}
	attestation, err := readObject(filepath.Join(root, "workers", "document-parser", "release", "vulnerability-attestation.json"))
	if err != nil {
		return fmt.Errorf("read vulnerability attestation: %w", err)
	}
	manifestDigest, _ := lock["oci_manifest_digest"].(string)
	configDigest, _ := lock["config_digest"].(string)
	if manifestDigest == "" || configDigest == "" {
		return fmt.Errorf("parser image lock has no exact OCI/config identity")
	}
	identity, _ := attestation["identity"].(map[string]any)
	dockerManifest, _ := identity["docker_distribution_manifest_digest"].(string)
	database, _ := attestation["database"].(map[string]any)
	if database == nil {
		return fmt.Errorf("vulnerability attestation lacks image/database identity")
	}

	syft, err := readObject(syftPath)
	if err != nil {
		return fmt.Errorf("read Syft JSON: %w", err)
	}
	descriptor, _ := syft["descriptor"].(map[string]any)
	if descriptor["name"] != "syft" || descriptor["version"] != "1.48.0" {
		return fmt.Errorf("Syft tool identity mismatch")
	}
	source, _ := syft["source"].(map[string]any)
	metadata, _ := source["metadata"].(map[string]any)
	if source["type"] != "image" || !parserScanImageIdentityMatches(metadata, configDigest, manifestDigest, dockerManifest) {
		return fmt.Errorf("Syft scan is not bound to the locked parser image")
	}
	expectedArtifacts := map[string]bool{
		"SparseBitSet@1.3[java-archive]": true, "commons-codec@1.20.0[java-archive]": true,
		"commons-collections4@4.5.0[java-archive]": true, "commons-compress@1.28.0[java-archive]": true,
		"commons-io@2.21.0[java-archive]": true, "commons-lang3@3.18.0[java-archive]": true,
		"commons-logging@1.4.0[java-archive]": true, "commons-math3@3.6.1[java-archive]": true,
		"curvesapi@1.08[java-archive]": true, "document-parser-worker@2.1.0[java-archive]": true,
		"fontbox@3.0.8[java-archive]": true, "jrt-fs@21.0.12[java-archive]": true,
		"log4j-api@2.25.5[java-archive]": true, "openjdk@21.0.12[binary]": true,
		"pdfbox@3.0.8[java-archive]": true, "pdfbox-io@3.0.8[java-archive]": true,
		"poi@5.5.1[java-archive]": true, "poi-ooxml@5.5.1[java-archive]": true,
		"poi-ooxml-lite@5.5.1[java-archive]": true, "xmlbeans@5.3.0[java-archive]": true,
	}
	artifacts, ok := syft["artifacts"].([]any)
	if !ok || len(artifacts) != len(expectedArtifacts) {
		return fmt.Errorf("Syft artifact count mismatch: got %d, want %d", len(artifacts), len(expectedArtifacts))
	}
	seenArtifacts := make(map[string]bool, len(artifacts))
	for _, raw := range artifacts {
		artifact, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("Syft artifact is not an object")
		}
		key := fmt.Sprintf("%s@%s[%s]", artifact["name"], artifact["version"], artifact["type"])
		if !expectedArtifacts[key] || seenArtifacts[key] {
			return fmt.Errorf("unexpected or duplicate Syft artifact %s", key)
		}
		seenArtifacts[key] = true
	}

	grype, err := readObject(grypePath)
	if err != nil {
		return fmt.Errorf("read Grype JSON: %w", err)
	}
	matches, matchesOK := grype["matches"].([]any)
	if !matchesOK || len(matches) != 0 {
		return fmt.Errorf("Grype reported %d vulnerability match(es)", len(matches))
	}
	if ignored, exists := grype["ignoredMatches"]; exists {
		ignoredMatches, ok := ignored.([]any)
		if !ok || len(ignoredMatches) != 0 {
			return fmt.Errorf("Grype reported suppressed matches")
		}
	}
	grypeSource, _ := grype["source"].(map[string]any)
	grypeTarget, _ := grypeSource["target"].(map[string]any)
	if grypeSource["type"] != "image" || !parserScanImageIdentityMatches(grypeTarget, configDigest, manifestDigest, dockerManifest) {
		return fmt.Errorf("Grype scan is not bound to the locked parser image")
	}
	grypeDescriptor, _ := grype["descriptor"].(map[string]any)
	if grypeDescriptor["name"] != "grype" || grypeDescriptor["version"] != "0.116.0" {
		return fmt.Errorf("Grype tool identity mismatch")
	}
	dbEnvelope, _ := grypeDescriptor["db"].(map[string]any)
	dbStatus, _ := dbEnvelope["status"].(map[string]any)
	if dbStatus["schemaVersion"] != database["schema_version"] || dbStatus["built"] != database["built_at"] || dbStatus["valid"] != true || !strings.Contains(fmt.Sprint(dbStatus["from"]), fmt.Sprint(database["archive_sha256"])) {
		return fmt.Errorf("Grype database identity mismatch")
	}
	native, err := readObject(nativeGrypePath)
	if err != nil {
		return fmt.Errorf("read native Grype JSON: %w", err)
	}
	return verifyParserNativeScan(native, database)
}

// A scratch image has no distro package inventory. Scan the exact libc6 PURL
// derived from its pinned native layer as a separate mandatory proof.
func verifyParserNativeScan(scan, database map[string]any) error {
	source, _ := scan["source"].(map[string]any)
	distro, _ := scan["distro"].(map[string]any)
	if source["type"] != "purl" || source["target"] != "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.8?arch=amd64&distro=ubuntu-24.04" || distro["name"] != "ubuntu" || distro["version"] != "24.04" {
		return fmt.Errorf("native Grype package/distro identity mismatch")
	}
	matches, ok := scan["matches"].([]any)
	if !ok || len(matches) != 0 {
		return fmt.Errorf("native Grype finding or missing matches")
	}
	if raw, exists := scan["ignoredMatches"]; exists {
		ignored, ok := raw.([]any)
		if !ok || len(ignored) != 0 {
			return fmt.Errorf("native Grype suppressed findings")
		}
	}
	descriptor, _ := scan["descriptor"].(map[string]any)
	envelope, _ := descriptor["db"].(map[string]any)
	status, _ := envelope["status"].(map[string]any)
	checksum, _ := database["archive_sha256"].(string)
	if descriptor["name"] != "grype" || descriptor["version"] != "0.116.0" || checksum == "" || status["schemaVersion"] != database["schema_version"] || status["built"] != database["built_at"] || status["valid"] != true || !strings.Contains(fmt.Sprint(status["from"]), checksum) {
		return fmt.Errorf("native Grype tool/database identity mismatch")
	}
	return nil
}

// OCI archive scans have no registry RepoDigests. Bind their embedded manifest
// and config bytes to the exact release digests instead of inventing a Docker
// distribution identity. The historical Docker scan path remains unchanged.
func parserScanImageIdentityMatches(metadata map[string]any, configDigest, manifestDigest, dockerManifest string) bool {
	if metadata["imageID"] != configDigest {
		return false
	}
	if dockerManifest != "" {
		return metadata["manifestDigest"] == dockerManifest && anyStringHasSuffix(metadata["repoDigests"], "@"+manifestDigest)
	}
	if metadata["mediaType"] != "application/vnd.oci.image.manifest.v1+json" || metadata["manifestDigest"] != manifestDigest {
		return false
	}
	for field, expected := range map[string]string{"manifest": manifestDigest, "config": configDigest} {
		encoded, ok := metadata[field].(string)
		if !ok || len(encoded) == 0 || len(encoded) > 2*1024*1024 {
			return false
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != expected {
			return false
		}
	}
	return true
}

func anyStringHasSuffix(value any, suffix string) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if text, ok := item.(string); ok && strings.HasSuffix(text, suffix) {
			return true
		}
	}
	return false
}

// checkWorkspaceSourceRepository keeps the first public source-binding
// commands on the accepted inert configuration boundary. The database gate is
// necessary but not sufficient: the caller must bind an exact v2 request,
// authorize from a fresh row-locked snapshot, and never compose later source
// authority from this repository checkpoint.
func checkWorkspaceSourceRepository(root string) []string {
	paths := []string{
		"internal/workspace/repository/repository.go",
		"internal/workspace/repository/source_commands.go",
		"internal/workspace/repository/source_commands_test.go",
		"internal/workspace/repository/idempotency.go",
		"internal/policy/decision.go",
		"internal/policy/decision_test.go",
		"tests/integration/postgres/workspace_source_repository_test.go",
		"docs/adr/0051-public-workspace-source-repository-commands-accepted.md",
	}
	contents := make(map[string]string, len(paths))
	var problems []string
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, "workspace source repository missing required file: "+relative)
			continue
		}
		contents[relative] = string(raw)
	}
	if len(problems) != 0 {
		return problems
	}
	return checkWorkspaceSourceRepositoryContents(contents)
}

func checkWorkspaceSourceRepositoryContents(contents map[string]string) []string {
	required := map[string][]string{
		"internal/workspace/repository/repository.go": {
			"func loadCurrentSnapshot(", "SELECT current_revision", "FOR UPDATE", "var lockedRevision int64",
			"AND workspace.current_revision = $3", "arguments = append(arguments, lockedRevision)",
			"principal_id = app.current_principal_id()", "AND removed_at IS NULL", "if !currentlyVisible {",
			"Do not turn the serialization barrier into an existence oracle",
			"return workspace.Snapshot{}, \"\", nil, false, nil",
			"The locked workspace cannot disappear or change its pointer inside",
			"return workspace.Snapshot{}, \"\", nil, false, &Error{code: CodePersistence}",
			"Operation: policy.OperationWorkspaceViewMetadata", "if !decision.Allowed {", "return &Error{code: CodeNotFound}",
		},
		"internal/workspace/repository/source_commands.go": {
			"func (store *Store) AddSource(", "func (store *Store) RemoveSource(",
			"stableWorkspaceSourceID(access.OrganizationID, request.WorkspaceID, request.SourceScopeID)",
			`"workspace-source-lineage-v1\x00" + organizationID + "\x00" + workspaceID + "\x00" + sourceScopeID`,
			`return "binding_" + crockford128(digest[:16])`, "bits := uint(2)",
			"reserveCommand(", "authorizeSourceMutation(",
			"loadCurrentSnapshot(ctx, transaction, access.OrganizationID, workspaceID, true)",
			"currentMembership(current, access.PrincipalID)", "policy.OperationWorkspaceManageSources",
			"scope.status = 'DRAFT'", "scope.active_revision IS NULL", "revision.scope_config_hash = $4",
			"workspace.NextSourceBindingEnabled", "workspace.NextSourceBindingDisabled", "persistRevisionSnapshot(",
			"authorizeReplaySnapshot(", "receiptPreconditionFailed", "receiptNotFound", "receiptDenied",
		},
		"internal/workspace/repository/source_commands_test.go": {
			"TestSourceCommandHashesUseV2AndBindRemoveLineage", "TestAddingSourceV2DoesNotChangeWorkspaceV1Hash",
			"TestSourceGateV2IntentRequiresEveryExactField", "TestStableWorkspaceSourceIDIsScopeStableAndClosed",
			"TestSourceProjectionAddDisableAndReenableReusesLineage", "TestSourceProjectionRejectsAlreadyStateAndTupleSubstitution",
			"TestSourceAuthorizationTerminalHidesMissingWorkspace",
		},
		"internal/workspace/repository/idempotency.go": {
			`sourceCommandSchemaVersion = "workspace-command-v2"`, "operationSourceAdd", "operationSourceRemove",
			"ExpectedWorkspaceRevision", "ExpectedConfigurationHash", "WorkspaceSourceID", "SourceScopeID",
			"SourceScopeRevision", "ScopeConfigHash", "AccessMode", "storedGateVersion == 2",
		},
		"internal/policy/decision.go": {
			`OperationWorkspaceManageSources Operation = "workspace.manage_sources"`,
			"case OperationWorkspaceManage, OperationWorkspaceManageSources:", "WorkspaceOwner || request.Membership.Role == WorkspaceManager",
		},
		"internal/policy/decision_test.go": {
			"TestWorkspaceSourceManagementIsAnExplicitOwnerManagerOperation", "OperationWorkspaceManageSources",
		},
		"tests/integration/postgres/workspace_source_repository_test.go": {
			"TestWorkspaceSourceRepositoryAddRemoveAndReenableStableLineage",
			"TestWorkspaceSourceRepositoryFailsClosedForStaleDeniedAndForeignScopeTuple",
			"TestWorkspaceSourceRepositorySerializesSameAndDifferentIdempotencyKeys",
			"assertRepositorySourceConfigurationRemainsDraft", "source-hidden-workspace", "source-cross-tenant-hidden",
		},
		"docs/adr/0051-public-workspace-source-repository-commands-accepted.md": {
			"workspace-command-v2", "organization_id + workspace_id + source_scope_id", "Crockford Base32",
			"row-lock barrier", "post-lock membership", "workspace.manage_sources", "existence oracles",
			"same ID", "simultaneous", "one success and one terminal stale result", "configuration provenance only",
			"does not confirm", "create a grant", "ingest content", "authorize retrieval", "No dependency", "license",
		},
	}
	var problems []string
	for relative, fragments := range required {
		content, ok := contents[relative]
		if !ok {
			problems = append(problems, "workspace source repository missing required content: "+relative)
			continue
		}
		for _, fragment := range fragments {
			if !strings.Contains(content, fragment) {
				problems = append(problems, "workspace source repository missing control in "+relative+": "+fragment)
			}
		}
	}
	production := contents["internal/workspace/repository/source_commands.go"]
	for _, forbidden := range []string{
		"INSERT INTO public.source_scope_activation", "UPDATE public.source_scope_activation",
		"INSERT INTO public.source_connection_activation", "UPDATE public.source_connection_activation",
		"INSERT INTO public.workspace_managed_grant", "INSERT INTO public.connector_job",
		"INSERT INTO public.source_object", "INSERT INTO public.evidence", "INSERT INTO public.question_run",
	} {
		if strings.Contains(production, forbidden) {
			problems = append(problems, "workspace source repository composes forbidden authority: "+forbidden)
		}
	}
	repository := contents["internal/workspace/repository/repository.go"]
	currentRevisionLockFence := "SELECT current_revision\n\t\t\tFROM public.workspace\n\t\t\tWHERE organization_id = $1 AND id = $2\n\t\t\tFOR UPDATE"
	if !strings.Contains(repository, currentRevisionLockFence) {
		problems = append(problems, "workspace source repository lost the dedicated current-revision row-lock barrier")
	}
	lockedVisibilityFence := "if !currentlyVisible {\n\t\t\t// The tenant row is deliberately broader than content visibility.\n\t\t\t// Do not turn the serialization barrier into an existence oracle.\n\t\t\treturn workspace.Snapshot{}, \"\", nil, false, nil\n\t\t}"
	if !strings.Contains(repository, lockedVisibilityFence) {
		problems = append(problems, "workspace source repository lost the exact post-lock hidden-workspace NOT_FOUND fence")
	}
	lockedPersistenceFence := "if database.IsNotFound(err) {\n\t\tif lock {\n\t\t\t// The locked workspace cannot disappear or change its pointer inside\n\t\t\t// this transaction; a missing exact revision is integrity failure.\n\t\t\treturn workspace.Snapshot{}, \"\", nil, false, &Error{code: CodePersistence}"
	if !strings.Contains(repository, lockedPersistenceFence) {
		problems = append(problems, "workspace source repository treats a missing post-lock exact snapshot as ordinary absence")
	}
	return problems
}

// checkWorkspaceManagedAuthorityCommandBoundary keeps the ADR-0053 authority
// command contract frozen. The four confirmation-authority operations exist
// only as a reviewed canonical envelope, schema and golden vectors: weakening
// the policy matrix wording, reusing the workspace command receipt family,
// adding client-owned server fields, requiring a WorkspaceRevision for
// revocation or persisting the raw Idempotency-Key must fail here rather than
// surface during the later migration/repository checkpoint.
func checkWorkspaceManagedAuthorityCommandBoundary(root string) []string {
	paths := []string{
		"docs/adr/0053-workspace-managed-authority-command-boundary-accepted.md",
		"architecture/contracts/workspace-managed-authority-command.schema.json",
		"architecture/contracts/embedding-profile-v1.schema.json",
		"architecture/contracts/embedding-mount-manifest-v1.schema.json",
		"tests/contracts/runner/workspace_managed_authority_command.go",
		"tests/contracts/runner/workspace_managed_authority_command_test.go",
		"tests/contracts/runner/contract_test.go",
		"tests/contracts/schema-tests.mjs",
		"tests/contracts/fixture-cases.json",
		"docs/CANONICALIZATION.md",
		"docs/DATA_MODEL.md",
	}
	contents := make(map[string]string, len(paths))
	var problems []string
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, "workspace-managed authority command boundary missing required file: "+relative)
			continue
		}
		contents[relative] = string(raw)
	}
	if len(problems) != 0 {
		return problems
	}
	return checkWorkspaceManagedAuthorityCommandBoundaryContents(contents)
}

func checkWorkspaceManagedAuthorityCommandBoundaryContents(contents map[string]string) []string {
	required := map[string][]string{
		"docs/adr/0053-workspace-managed-authority-command-boundary-accepted.md": {
			"WORKSPACE_CONFIRMATION_GRANT_ISSUE", "WORKSPACE_CONFIRMATION_GRANT_REVOKE",
			"WORKSPACE_MANAGED_CONFIRM", "WORKSPACE_MANAGED_CONFIRM_REVOKE",
			"workspace-managed-authority-command-v1",
			"WORKSPACE_AUTHORITY_REQUEST_INVALID", "WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT",
			"WORKSPACE_AUTHORITY_DENIED", "WORKSPACE_AUTHORITY_NOT_FOUND",
			"WORKSPACE_AUTHORITY_PRECONDITION_FAILED", "WORKSPACE_AUTHORITY_PERSISTENCE_FAILED",
			"Organization role alone never authorizes a confirmation",
			"ownership or management without that exact unrevoked actor grant is",
			"`CONNECTOR_ADMIN`, `SECURITY_AUDITOR` and ordinary members cannot",
			"Grant revocation does not require a current",
			"The raw Idempotency-Key never enters the",
			"(organization_id, actor_principal_id, idempotency_key_hash)",
			"workspace_managed_authority_command_receipt",
			"must not extend `workspace_command_receipt`",
			"with `ttl_seconds` an integer between 60 and",
			"`SUCCESS`, `DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED`",
			"must fail closed if it finds authority rows created",
			"workspace.source_confirmation_grant_issued", "workspace.source_confirmation_grant_revoked",
			"workspace.source_confirmed", "workspace.source_confirmation_revoked",
			// command_id (defect #2): server-generated audit resource ID that
			// exists on every business terminal outcome, including failures
			// with no created or parent authority row.
			"reserves a `command_id` at receipt",
			"server-generated at reservation time, immutable, unique within the tenant",
			"never enters the request canonical bytes or request hash",
			"has a `command_id`,",
			"`command_id` is",
			"the audit resource ID for all four operations",
			"WORKSPACE_AUTHORITY_COMMAND",
			"`audit.resource_id = receipt.command_id`",
			"Grant, confirmation and revocation IDs never serve as the audit resource ID",
			// trusted tenant binding (hardening P1 #1): request organization_id
			// is canonical/hashed but never tenant authority; only the trusted
			// AccessContext.OrganizationID ever selects a tenant.
			"the server exact-matches request `organization_id`",
			"against the trusted `AccessContext.OrganizationID`",
			"`SET LOCAL app.organization_id`",
			"`receipt.organization_id`, `audit.organization_id`, and the",
			"actor-scoped idempotency namespace all come exclusively from the trusted",
			"never from the request body, on either",
			"A mismatch between request `organization_id` and",
			"before any workspace, target principal, grant, confirmation, binding, policy",
			"or warning lookup runs",
			"is null, matching the existing `NOT_FOUND` rule rather than a special case",
			"Replay resolves the receipt only inside the trusted `AccessContext.OrganizationID`",
			"never select it, so a cross-tenant replay is exactly as indistinguishable",
			// decision phase / branch split after all business preconditions
			// (hardening P1 #2): the terminal decision is settled before any
			// branch is entered, and no branch may straddle that decision.
			"runs one common decision phase before any",
			"no branch may be entered until that phase",
			"the trusted tenant fence defined above; opening",
			"the workspace serialization row lock, taken only",
			"loading, locking and exact-matching every business projection the specific",
			"does the transaction settle on exactly one terminal",
			"the branch choice follows the decision, the",
			"decision never follows the branch",
			"each resolve",
			"strictly before any later check that could",
			"The business-failure branch is entered only once the decision phase has",
			"creates no result or revocation ID, no authority timestamp, no result JCS or",
			"performs no authority-table INSERT",
			"The success branch is entered only once the decision phase has settled on",
			"it can never be the branch that first discovers an ordinary",
			"Once entered, the success branch performs only:",
			"it never switches an already-chosen",
			"Replay never re-enters the decision",
			// exact receipt -> audit outcome/error_code mapping (defect #2).
			"Receipt status maps to audit outcome and error code exhaustively and without",
			"`SUCCESS` maps to audit outcome `SUCCESS` with a null error code",
			"`DENIED` maps to audit outcome `DENIED` with error code",
			"`NOT_FOUND` maps to audit outcome `DENIED`",
			"`PRECONDITION_FAILED` maps to audit outcome `FAILED` with error code",
			"`PENDING` is never terminal and",
			// exact per-operation audit metadata (defect #2).
			"Audit metadata for `DENIED`, `NOT_FOUND` and `PRECONDITION_FAILED` contains",
			"exactly one key, `authority_operation`, and nothing else",
			"`SUCCESS` metadata is closed per operation to trusted, persisted result and",
			"`authority_result_id` (the created `grant_id`)",
			"`authority_parent_id` (the revoked `grant_id`)",
			"`authority_result_id` (the created `confirmation_id`)",
			"`authority_parent_id` (the revoked `confirmation_id`)",
			"`authority_reason_code` fixed to `AUTHORITY_REVOKED`",
			"`authority_reason_code` fixed to `ACCESS_REVOKED`",
			// AuditEvent.workspace_id nullability rule (defect #2).
			"The main `AuditEvent.workspace_id` follows its own exhaustive rule",
			"On `NOT_FOUND`",
			"it is always null",
			"only if same-tenant workspace visibility was already",
			// operation-specific initial/replay visibility (defect #4).
			"Initial execution and replay use different visibility rules",
			"the bare",
			`term "workspace visibility" is never used without one of the following four`,
			"For `WORKSPACE_CONFIRMATION_GRANT_ISSUE`, both",
			"the issuer needs no",
			"For `WORKSPACE_MANAGED_CONFIRM`, initial execution requires a current",
			"it does not re-require that",
			"the historical actor grant remain live or that policy or warning still match",
			"For `WORKSPACE_CONFIRMATION_GRANT_REVOKE`, both initial execution and replay",
			"self-revoke visibility never requires current",
			"For `WORKSPACE_MANAGED_CONFIRM_REVOKE`, both initial execution and replay are",
			"A cross-tenant reference is",
			"always `WORKSPACE_AUTHORITY_NOT_FOUND`, never `WORKSPACE_AUTHORITY_DENIED`",
			"replay never repeats the",
			"execution-time preconditions",
			"Authority-metadata visibility",
			"never grants source content or evidence access",
			// anti-drift closing paragraph (defect #7 cross-reference).
			"the schema is registered in the official contract fixture suite",
			"collapsing initial",
			"and replay visibility into one undefined \"visibility\" concept",
			"using a",
			"created grant or confirmation ID as the audit resource on a failure path",
			"dropping `command_id`",
			"weakening the exact receipt-status-to-audit-outcome",
			"the exact property set of each of the four request definitions",
			"exact one-to-one `operation`-to-request-definition mapping",
			// closing anchors for the two hardening P1 invariant classes.
			"letting request `organization_id` govern",
			"dropping the",
			"`AuditEvent.workspace_id` null rule on tenant mismatch",
			"before the tenant fence",
			"before the decision phase's business-precondition",
			"reload policy, warning,",
			"parent or binding projections it should already hold from the decision",
		},
		"architecture/contracts/workspace-managed-authority-command.schema.json": {
			`"workspace-managed-authority-command-v1"`,
			"WORKSPACE_CONFIRMATION_GRANT_ISSUE", "WORKSPACE_CONFIRMATION_GRANT_REVOKE",
			"WORKSPACE_MANAGED_CONFIRM", "WORKSPACE_MANAGED_CONFIRM_REVOKE",
			`"additionalProperties": false`, `"ttl_seconds"`,
		},
		"tests/contracts/runner/workspace_managed_authority_command.go": {
			`workspaceManagedAuthorityCommandSchemaVersion = "workspace-managed-authority-command-v1"`,
			`operationConfirmationGrantIssue  = "WORKSPACE_CONFIRMATION_GRANT_ISSUE"`,
			`operationConfirmationGrantRevoke = "WORKSPACE_CONFIRMATION_GRANT_REVOKE"`,
			`operationManagedConfirm          = "WORKSPACE_MANAGED_CONFIRM"`,
			`operationManagedConfirmRevoke    = "WORKSPACE_MANAGED_CONFIRM_REVOKE"`,
			`"WORKSPACE_AUTHORITY_REQUEST_INVALID"`,
			`"expected_policy_revision"`, "unknown request field", "missing request field", "null request field",
		},
		"tests/contracts/runner/workspace_managed_authority_command_test.go": {
			"workspaceManagedAuthorityValidFixturesFromRegistry",
			"the registry is the only source of truth for the fixture inventory",
			"TestWorkspaceManagedAuthorityCommandGoldenVectors",
			"TestWorkspaceManagedAuthorityCommandRequestHashBindsEveryField",
			"TestWorkspaceManagedAuthorityCommandCanonicalizationDeterminism",
		},
		"tests/contracts/runner/contract_test.go": {
			`case "workspace-managed-authority-command":`,
			"TestWorkspaceManagedAuthorityCommandFixtureInventoryMatchesRegistry",
			"no fixture is registered more than once, no registered fixture is",
			"registered %d times, expected exactly once",
			"expected exactly 26 registered workspace-managed authority command fixtures",
		},
		"tests/contracts/schema-tests.mjs": {
			`"workspace-managed-authority-command": "architecture/contracts/workspace-managed-authority-command.schema.json"`,
		},
		"tests/contracts/fixture-cases.json": {
			`"workspace.authority.grant-issue.valid"`,
			`"workspace.authority.grant-revoke.valid"`,
			`"workspace.authority.confirm.valid"`,
			`"workspace.authority.confirm-revoke.valid"`,
			`"workspace.authority.unsafe-integer"`,
			`"contract": "workspace-managed-authority-command"`,
			`"validator": "workspace-managed-authority-command"`,
			`"expected_error_code": "WORKSPACE_AUTHORITY_REQUEST_INVALID"`,
			`"expected_error_code": "JSON_NUMBER_NOT_IJSON"`,
		},
		"docs/CANONICALIZATION.md": {
			"### 6.1. Workspace-managed authority command envelope",
			"workspace-managed-authority-command-v1",
			"(organization_id, actor_principal_id, idempotency_key_hash)",
			"WORKSPACE_AUTHORITY_REQUEST_INVALID",
			"is always trusted `AccessContext.OrganizationID`, and not",
			"but never selects",
			"it is exact-matched against",
			"are taken exclusively from",
		},
		"docs/DATA_MODEL.md": {
			"workspace_managed_authority_command_receipt",
			"`PENDING`, `SUCCESS`, `DENIED`, `NOT_FOUND`, `PRECONDITION_FAILED`",
			"must fail closed",
			"`command_id` is reserved upon receipt creation",
			"server-generated, immutable, unique within the tenant",
			"only audit resource ID for all four operations",
			"always trusted `AccessContext.OrganizationID`, never `request.organization_id`",
			"does not control tenant context for `database.Write`",
		},
	}
	var problems []string
	for relative, fragments := range required {
		content, ok := contents[relative]
		if !ok {
			problems = append(problems, "workspace-managed authority command boundary missing required content: "+relative)
			continue
		}
		for _, fragment := range fragments {
			if !strings.Contains(content, fragment) {
				problems = append(problems, "workspace-managed authority command boundary missing control in "+relative+": "+fragment)
			}
		}
	}
	// The removed valid/invalid fixture-inventory tests must stay removed:
	// the registry (fixture-cases.json) is the only source of truth for
	// which fixtures exist, not a second hardcoded Go slice.
	authorityTest := contents["tests/contracts/runner/workspace_managed_authority_command_test.go"]
	for _, forbidden := range []string{
		"TestWorkspaceManagedAuthorityCommandValidFixtures", "TestWorkspaceManagedAuthorityCommandInvalidFixtures",
		"var workspaceManagedAuthorityValidFixtures = map[string]string{",
	} {
		if strings.Contains(authorityTest, forbidden) {
			problems = append(problems, "workspace-managed authority command test reintroduces a second fixture-inventory source of truth: "+forbidden)
		}
	}
	adr := contents["docs/adr/0053-workspace-managed-authority-command-boundary-accepted.md"]
	// The success branch must never be the place that first reloads current
	// policy, warning, parent or binding projections: that regression was
	// exactly what let it discover an ordinary PRECONDITION_FAILED after the
	// branch was already chosen. This phrase belongs only to a superseded
	// draft of this ADR and must never come back.
	for _, forbidden := range []string{
		"reloads the current policy", "It reloads the current policy",
	} {
		if strings.Contains(adr, forbidden) {
			problems = append(problems, "workspace-managed authority command boundary reintroduces a success-branch precondition reload: "+forbidden)
		}
	}
	problems = append(problems, authorityDecisionPhaseOrderingIsSafe(adr)...)
	schema := contents["architecture/contracts/workspace-managed-authority-command.schema.json"]
	// Server-owned result fields, warning bodies and the raw Idempotency-Key
	// must never become request schema surface.
	for _, forbidden := range []string{
		"idempotency_key", "granted_at", "granted_by", "valid_from", "valid_until",
		"confirmed_at", "confirmed_by", "revoked_at", "revoked_by", "revocation_id",
		"reason_code", "risk_codes", "warning_text", `"permission"`,
	} {
		if strings.Contains(schema, forbidden) {
			problems = append(problems, "workspace-managed authority command schema exposes a server-owned or forbidden field: "+forbidden)
		}
	}
	problems = append(problems, checkWorkspaceManagedAuthorityCommandSchemaShape(schema, contents["tests/contracts/runner/workspace_managed_authority_command.go"])...)
	return problems
}

// authorityDecisionPhaseOrderingIsSafe proves, by textual position rather
// than by presence alone, that the ADR keeps the trusted tenant fence and
// the terminal-decision settlement strictly before the checks and branches
// that could otherwise leak a hidden workspace's existence or straddle a
// business precondition across branches. A mutation that reorders these
// sentences without deleting any of them would defeat a presence-only check;
// it cannot defeat an index comparison.
func authorityDecisionPhaseOrderingIsSafe(adr string) []string {
	anchors := map[string]string{
		"trusted tenant fence":             "the trusted tenant fence defined above; opening",
		"workspace serialization row lock": "the workspace serialization row lock, taken only",
		"business projection loading":      "loading, locking and exact-matching every business projection the specific",
		"terminal decision settlement":     "does the transaction settle on exactly one terminal",
		"business-failure branch entry":    "The business-failure branch is entered only once the decision phase has",
		"success branch entry":             "The success branch is entered only once the decision phase has settled on",
	}
	index := make(map[string]int, len(anchors))
	var problems []string
	for name, anchor := range anchors {
		position := strings.Index(adr, anchor)
		if position < 0 {
			problems = append(problems, "workspace-managed authority command boundary is missing decision-phase ordering anchor: "+name)
			continue
		}
		index[name] = position
	}
	if len(problems) != 0 {
		return problems
	}
	if !(index["trusted tenant fence"] < index["workspace serialization row lock"] &&
		index["workspace serialization row lock"] < index["business projection loading"] &&
		index["business projection loading"] < index["terminal decision settlement"]) {
		problems = append(problems, "workspace-managed authority command boundary decision-phase steps are not in trusted-tenant-first order")
	}
	if !(index["terminal decision settlement"] < index["business-failure branch entry"] &&
		index["terminal decision settlement"] < index["success branch entry"]) {
		problems = append(problems, "workspace-managed authority command boundary chooses a branch before the decision phase settles")
	}
	return problems
}

// authorityOperationConstants extracts `operationXxx = "OP_STRING"` pairs
// from the authority-command runner source, mapping the Go identifier to the
// operation string it is bound to.
func authorityOperationConstants(source string) map[string]string {
	result := map[string]string{}
	pattern := regexp.MustCompile(`(operation[A-Za-z]+)\s*=\s*"([A-Z_]+)"`)
	for _, match := range pattern.FindAllStringSubmatch(source, -1) {
		result[match[1]] = match[2]
	}
	return result
}

// authorityGoRequestFieldSets extracts, per operation string, the exact set
// of request field names the Go validator accepts from
// workspaceManagedAuthorityRequestFields. This is parsed from source text
// (not imported as a package) so the architecture checker stays a single
// dependency-free binary; the same idiom is used throughout this file for
// SQL migrations.
func authorityGoRequestFieldSets(source string) (map[string]map[string]bool, []string) {
	const marker = "var workspaceManagedAuthorityRequestFields = map[string]map[string]authorityFieldKind{"
	start := strings.Index(source, marker)
	if start < 0 {
		return nil, []string{"workspace-managed authority command Go source lost workspaceManagedAuthorityRequestFields"}
	}
	constants := authorityOperationConstants(source)
	blockPattern := regexp.MustCompile(`(operation[A-Za-z]+):\s*\{([^{}]*)\}`)
	fieldPattern := regexp.MustCompile(`"([a-z_]+)":`)
	var problems []string
	result := map[string]map[string]bool{}
	for _, match := range blockPattern.FindAllStringSubmatch(source[start:], -1) {
		operation, ok := constants[match[1]]
		if !ok {
			problems = append(problems, "workspace-managed authority command Go source references an undeclared operation constant: "+match[1])
			continue
		}
		fields := map[string]bool{}
		for _, fieldMatch := range fieldPattern.FindAllStringSubmatch(match[2], -1) {
			fields[fieldMatch[1]] = true
		}
		result[operation] = fields
	}
	return result, problems
}

func checkWorkspaceManagedAuthorityCommandSchemaShape(schemaRaw, goSource string) []string {
	const prefix = "workspace-managed authority command schema "
	var schema map[string]any
	if err := json.Unmarshal([]byte(schemaRaw), &schema); err != nil {
		return []string{prefix + "is not valid JSON: " + err.Error()}
	}
	object := func(value any) map[string]any {
		result, _ := value.(map[string]any)
		return result
	}
	var problems []string
	if closed, ok := schema["additionalProperties"].(bool); !ok || closed {
		problems = append(problems, prefix+"envelope is not a closed object")
	}

	// operationToRequestDef is the exact, closed one-to-one mapping this
	// contract owns. It is the independent expectation the schema's oneOf
	// and Go's operation inventory are both checked against.
	operationToRequestDef := map[string]string{
		"WORKSPACE_CONFIRMATION_GRANT_ISSUE":  "grantIssueRequest",
		"WORKSPACE_CONFIRMATION_GRANT_REVOKE": "grantRevokeRequest",
		"WORKSPACE_MANAGED_CONFIRM":           "managedConfirmRequest",
		"WORKSPACE_MANAGED_CONFIRM_REVOKE":    "managedConfirmRevokeRequest",
	}
	// requestDefExpectedFieldCount is a cheap, independent redundant fence:
	// a coordinated drift that breaks the schema, the Go map and this count
	// identically at once is what the exact field-set comparison below still
	// catches, but this makes an accidental single-field slip fail loudly
	// even before that comparison runs.
	requestDefExpectedFieldCount := map[string]int{
		"grantIssueRequest":           7,
		"grantRevokeRequest":          6,
		"managedConfirmRequest":       16,
		"managedConfirmRevokeRequest": 5,
	}

	operations := make([]string, 0, len(operationToRequestDef))
	for operation := range operationToRequestDef {
		operations = append(operations, operation)
	}
	sort.Strings(operations)

	enumValues, _ := object(object(schema["properties"])["operation"])["enum"].([]any)
	if len(enumValues) != len(operations) {
		problems = append(problems, prefix+"operation enum is not exactly the four accepted operations")
	} else {
		for index, operation := range operations {
			if enumValues[index] != operation {
				problems = append(problems, prefix+"operation enum drifted: "+operation)
			}
		}
	}

	// Exact one-to-one operation -> request-definition mapping in the closed
	// oneOf: every operation appears in exactly one branch, every branch
	// names exactly the expected $ref, and no $ref is reused across branches.
	oneOf, _ := schema["oneOf"].([]any)
	branchOperations := map[string]int{}
	defUsage := map[string]int{}
	for _, rawBranch := range oneOf {
		branch := object(rawBranch)
		branchProperties := object(branch["properties"])
		operation, _ := object(branchProperties["operation"])["const"].(string)
		ref, _ := object(branchProperties["request"])["$ref"].(string)
		branchOperations[operation]++
		defName := strings.TrimPrefix(ref, "#/$defs/")
		defUsage[defName]++
		expectedDef, known := operationToRequestDef[operation]
		if !known {
			problems = append(problems, prefix+"oneOf branch names an unknown operation: "+operation)
			continue
		}
		if defName != expectedDef {
			problems = append(problems, prefix+"oneOf maps "+operation+" to "+defName+", expected "+expectedDef)
		}
	}
	if len(oneOf) != len(operationToRequestDef) {
		problems = append(problems, prefix+"oneOf does not have exactly four branches")
	}
	for operation := range operationToRequestDef {
		if branchOperations[operation] != 1 {
			problems = append(problems, prefix+"operation "+operation+" does not appear in exactly one oneOf branch")
		}
	}
	for _, defName := range operationToRequestDef {
		if defUsage[defName] != 1 {
			problems = append(problems, prefix+"request definition "+defName+" is not used by exactly one oneOf branch")
		}
	}

	definitions := object(schema["$defs"])
	goFieldSets, goProblems := authorityGoRequestFieldSets(goSource)
	problems = append(problems, goProblems...)

	requests := map[string]map[string]any{
		"grantIssueRequest":           object(definitions["grantIssueRequest"]),
		"grantRevokeRequest":          object(definitions["grantRevokeRequest"]),
		"managedConfirmRequest":       object(definitions["managedConfirmRequest"]),
		"managedConfirmRevokeRequest": object(definitions["managedConfirmRevokeRequest"]),
	}
	defToOperation := map[string]string{}
	for operation, defName := range operationToRequestDef {
		defToOperation[defName] = operation
	}
	for name, request := range requests {
		if request == nil {
			problems = append(problems, prefix+"is missing request definition "+name)
			continue
		}
		if closed, ok := request["additionalProperties"].(bool); !ok || closed {
			problems = append(problems, prefix+name+" is not a closed object")
		}
		properties := object(request["properties"])
		if _, ok := properties["expected_policy_revision"]; !ok {
			problems = append(problems, prefix+name+" lost the current-policy precondition")
		}
		requiredNames, _ := request["required"].([]any)
		requiredSet := make(map[string]bool, len(requiredNames))
		for _, item := range requiredNames {
			key, _ := item.(string)
			requiredSet[key] = true
		}
		for key := range properties {
			if !requiredSet[key] {
				problems = append(problems, prefix+name+" declares an optional request field: "+key)
			}
		}
		for _, item := range requiredNames {
			key, _ := item.(string)
			if _, ok := properties[key]; !ok {
				problems = append(problems, prefix+name+" requires an undeclared field: "+key)
			}
		}

		// Exact property-set proof: schema properties for this request
		// definition must equal, field for field, the Go validator's field
		// set for the operation that maps to this definition — and both
		// must equal the independently pinned expected field count.
		expectedCount, hasExpectedCount := requestDefExpectedFieldCount[name]
		if hasExpectedCount && len(properties) != expectedCount {
			problems = append(problems, fmt.Sprintf("%s%s has %d properties, expected exactly %d", prefix, name, len(properties), expectedCount))
		}
		operation, known := defToOperation[name]
		if !known {
			continue
		}
		goFields, hasGoFields := goFieldSets[operation]
		if !hasGoFields {
			problems = append(problems, prefix+"Go validator has no field set for operation "+operation)
			continue
		}
		if hasExpectedCount && len(goFields) != expectedCount {
			problems = append(problems, fmt.Sprintf("%sGo validator field set for %s has %d fields, expected exactly %d", prefix, operation, len(goFields), expectedCount))
		}
		for key := range properties {
			if !goFields[key] {
				problems = append(problems, prefix+name+" declares "+key+" but the Go validator for "+operation+" does not accept it")
			}
		}
		for key := range goFields {
			if _, ok := properties[key]; !ok {
				problems = append(problems, prefix+"Go validator for "+operation+" accepts "+key+" but "+name+" does not declare it")
			}
		}
	}
	for _, name := range []string{"grantRevokeRequest", "managedConfirmRevokeRequest"} {
		properties := object(requests[name]["properties"])
		for key := range properties {
			if strings.HasPrefix(key, "expected_workspace") {
				problems = append(problems, prefix+name+" gained a current-WorkspaceRevision precondition: "+key)
			}
		}
	}
	confirmProperties := object(requests["managedConfirmRequest"]["properties"])
	for _, key := range []string{"warning_version", "warning_contract_hash", "acknowledgement_code", "access_mode"} {
		if _, ok := confirmProperties[key]; !ok {
			problems = append(problems, prefix+"managedConfirmRequest lost the warning/access binding: "+key)
		}
	}
	ttl := object(definitions["ttlSeconds"])
	minimum, minimumOK := ttl["minimum"].(float64)
	maximum, maximumOK := ttl["maximum"].(float64)
	if !minimumOK || !maximumOK || minimum != 60 || maximum != 86400 {
		problems = append(problems, prefix+"ttl bounds drifted from the accepted 60..86400 window")
	}

	// schema enum vs Go operation inventory: same set, independent of the
	// oneOf checks above (which only prove internal schema consistency).
	goOperationSet := map[string]bool{}
	for operation := range goFieldSets {
		goOperationSet[operation] = true
	}
	if len(goOperationSet) != len(operationToRequestDef) {
		problems = append(problems, fmt.Sprintf("%sGo validator declares %d operations, expected exactly %d", prefix, len(goOperationSet), len(operationToRequestDef)))
	}
	for operation := range operationToRequestDef {
		if !goOperationSet[operation] {
			problems = append(problems, prefix+"Go validator is missing operation "+operation)
		}
	}
	for operation := range goOperationSet {
		if _, ok := operationToRequestDef[operation]; !ok {
			problems = append(problems, prefix+"Go validator declares an operation outside the closed set: "+operation)
		}
	}
	return problems
}

// checkWorkspaceManagedAuthorityCommandRuntime replaces the ADR-0053 runtime
// deferral gate with the positive implementation gate its own checkpoint owes.
//
// ADR-0053 froze the authority command boundary as contract-only and forbade
// migration 000011 from existing. Migration 000011 is that reviewed checkpoint,
// so the negative assertion is retired here — but only the negative one. Each
// invariant the deferral protected by absence is now protected by presence:
// the receipt family is separate, the four operations are the closed set, the
// INSERT path exists only behind the receipt gate, and the tokens still may not
// appear in the surfaces that remain deferred.
func checkWorkspaceManagedAuthorityCommandRuntime(root string) []string {
	var problems []string

	// Exactly one migration 000011, and no 000012: this checkpoint owns one
	// migration, and the next one is not part of it.
	implementation, _ := filepath.Glob(filepath.Join(root, "db", "migrations", "000011*"))
	if len(implementation) != 1 {
		problems = append(problems, fmt.Sprintf(
			"workspace-managed authority runtime needs exactly one migration 000011, found %d", len(implementation)))
	}
	// Migration 000012 is the encrypted-artifact containment checkpoint, not part
	// of this runtime. Any other 000012 file would mean this checkpoint grew a
	// migration it does not own.
	premature, _ := filepath.Glob(filepath.Join(root, "db", "migrations", "000012*"))
	for _, path := range premature {
		if filepath.ToSlash(relative(root, path)) != "db/migrations/000012_stage2_encrypted_artifact_containment.sql" {
			problems = append(problems, "workspace-managed authority runtime does not own migration 000012: "+relative(root, path))
		}
	}
	problems = append(problems, checkWorkspaceManagedAuthorityCommandMigration(root)...)
	problems = append(problems, checkWorkspaceManagedAuthorityCommandRepository(root)...)

	// The migration must be in the integration bootstrap, or every gate below
	// is proved against a schema no test ever builds.
	bootstrap, err := os.ReadFile(filepath.Join(root, "tests", "integration", "postgres", "rls_test.go"))
	if err != nil {
		problems = append(problems, err.Error())
	} else if !strings.Contains(string(bootstrap), "000011_stage2_workspace_managed_authority_command.sql") {
		problems = append(problems, "migration 000011 is missing from the integration migration bootstrap")
	}

	problems = append(problems, checkWorkspaceManagedAuthorityCommandTokenSurface(root)...)
	return problems
}

// checkWorkspaceManagedAuthorityCommandTokenSurface is the walk half of the
// ADR-0053 runtime gate: the workspace-managed authority command tokens may not
// appear in any production surface except the ones ADR-0053 and its ADR-0087 §1
// amendment name. internal/audit is exempt: the audit contract is part of this
// checkpoint. The internal/workspace/repository authority_*.go files are the
// checkpoint-0055 runtime's positive-gated home. ADR-0087 §1 additionally names
// internal/platform/workspaceapi (the REST/MCP composition surface) as a place
// where these tokens are permitted, so the whole package is exempt here. db and
// tests/integration are exempt in the caller because they are where the
// implementation and its proof live.
func checkWorkspaceManagedAuthorityCommandTokenSurface(root string) []string {
	var problems []string
	tokens := []string{
		"WORKSPACE_CONFIRMATION_GRANT_ISSUE", "WORKSPACE_CONFIRMATION_GRANT_REVOKE",
		"WORKSPACE_MANAGED_CONFIRM", "WORKSPACE_AUTHORITY_",
		"workspace_managed_authority_command_receipt",
	}
	auditPackage := filepath.Join(root, "internal", "audit")
	// ADR-0087 §1: internal/platform/workspaceapi is the REST/MCP composition
	// surface that will call the ADR-0053 authority runtime, so the authority
	// command tokens are permitted across that package.
	workspaceAPIPackage := filepath.Join(root, "internal", "platform", "workspaceapi")
	for _, directory := range []string{
		"internal", "cmd", "api", "web", "deploy",
	} {
		_ = walkDir(filepath.Join(root, directory), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				problems = append(problems, walkErr.Error())
				return nil
			}
			if entry.IsDir() {
				if path == auditPackage || path == workspaceAPIPackage {
					return filepath.SkipDir
				}
				switch entry.Name() {
				case "node_modules", ".pnpm-store", "dist", "coverage":
					return filepath.SkipDir
				}
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".sql", ".ts", ".tsx", ".js", ".mjs", ".json", ".yaml", ".yml", ".toml", ".sh", ".ps1":
			default:
				return nil
			}
			// The checkpoint-0055 authority runtime is the positive-gated home of
			// these tokens: they must appear there (proved by
			// checkWorkspaceManagedAuthorityCommandRepository) rather than being
			// forbidden. The exemption is exactly the authority_*.go files under
			// the workspace repository package, and nothing else; the same tokens
			// leaking into any other file of that package still reds this scan.
			if strings.HasPrefix(entry.Name(), "authority_") &&
				filepath.Dir(path) == filepath.Join(root, "internal", "workspace", "repository") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				problems = append(problems, err.Error())
				return nil
			}
			content := string(raw)
			for _, token := range tokens {
				if strings.Contains(content, token) {
					problems = append(problems, "workspace-managed authority command surface is deferred: "+token+" appears in "+relative(root, path))
				}
			}
			return nil
		})
	}
	return problems
}

// checkWorkspaceManagedAuthorityCommandMigration proves migration 000011 still
// carries every gate ADR-0053 owes it. Each control below is the anchor of one
// normative invariant; deleting the SQL that implements it deletes the anchor
// and reds this checker, so weakening the boundary is a build failure rather
// than a review debate.
func checkWorkspaceManagedAuthorityCommandMigration(root string) []string {
	path := filepath.Join(root, "db", "migrations", "000011_stage2_workspace_managed_authority_command.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{"workspace-managed authority migration is unreadable: " + err.Error()}
	}
	return checkWorkspaceManagedAuthorityCommandMigrationContent(string(raw))
}

// checkWorkspaceManagedAuthorityCommandRepository proves the checkpoint-0055 Go
// runtime is present and uncomposed. The token scan above exempts the
// authority_*.go files from the "these tokens must not appear" rule; this gate
// is the positive half that replaces it — the four operations, the closed
// WORKSPACE_AUTHORITY_ error surface, the single reused JCS engine, the four
// canonical result contracts and the separate receipt family must all be
// present, and the runtime must never write the workspace command receipt
// family. Deleting or weakening any of these reds the checker.
func checkWorkspaceManagedAuthorityCommandRepository(root string) []string {
	base := filepath.Join(root, "internal", "workspace", "repository")
	files := map[string]string{}
	for _, name := range []string{
		"authority_command.go", "authority_commands.go", "authority_result.go",
		"authority_receipt.go", "authority_policy.go", "authority_facts.go",
	} {
		raw, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			return []string{"workspace-managed authority runtime file is unreadable: " + name + ": " + err.Error()}
		}
		files[name] = string(raw)
	}
	return checkWorkspaceManagedAuthorityCommandRepositoryContent(files)
}

// checkWorkspaceManagedAuthorityCommandRepositoryContent takes the runtime file
// contents rather than paths so each anchor can be mutation-tested directly:
// removing any control below must red this checker.
func checkWorkspaceManagedAuthorityCommandRepositoryContent(files map[string]string) []string {
	var problems []string
	required := map[string][]string{
		"authority_command.go": {
			"WORKSPACE_CONFIRMATION_GRANT_ISSUE",
			"WORKSPACE_CONFIRMATION_GRANT_REVOKE",
			"WORKSPACE_MANAGED_CONFIRM_REVOKE",
			"workspace-managed-authority-command-v1",
			"WORKSPACE_AUTHORITY_REQUEST_INVALID",
			"WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT",
			"WORKSPACE_AUTHORITY_DENIED",
			"WORKSPACE_AUTHORITY_NOT_FOUND",
			"WORKSPACE_AUTHORITY_PRECONDITION_FAILED",
			"WORKSPACE_AUTHORITY_PERSISTENCE_FAILED",
			"jsontext.Value",
		},
		"authority_commands.go": {
			"func (store *Store) IssueConfirmationGrant",
			"func (store *Store) RevokeConfirmationGrant",
			"func (store *Store) ConfirmManagedSource",
			"func (store *Store) RevokeManagedConfirmation",
			// The workspace lock and the actor reload are one ordered helper; the
			// trusted tenant fence and the reused-key non-oracle live in the
			// tenant-mismatch terminator.
			"func (store *Store) lockThenReload",
			"func (store *Store) terminateTenantMismatch",
			"isAuthorityConflict(reserveErr)",
		},
		"authority_result.go": {
			"workspace-source-confirmation-grant-v1",
			"workspace-source-confirmation-grant-revocation-v1",
			"workspace-managed-confirmation-v1",
			"workspace-managed-confirmation-revocation-v1",
		},
		"authority_receipt.go": {
			"workspace_managed_authority_command_receipt",
			"ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING",
		},
		// The decision phase reads protected projections only through lazy
		// loaders, so visibility and authorization always resolve first; the
		// duplicate-confirm precheck and the operation-specific replay terminals
		// are part of that same ordering contract.
		"authority_policy.go": {
			"business confirmBusiness",
			"liveConfirmationExists",
			"issueReplayTerminal",
			"confirmReplayTerminal",
			"grantRevokeReplayTerminal",
			"confirmRevokeReplayTerminal",
			// Replay is permitted only for a revocable lifecycle status: weakening
			// this lets a DELETING/DELETED workspace leak its stored result.
			"!revocableWorkspaceStatus(ws.status)",
		},
		"authority_facts.go": {
			"func confirmLiveConfirmationExists",
			// The minimal visibility facts are split from the protected
			// revision/configuration projection: an eager read would drop the
			// separate loader or widen the visibility query. The visibility
			// loader must still take the workspace serialization FOR UPDATE lock.
			"func lockWorkspaceVisibility",
			"func loadWorkspaceRevisionConfig",
			"SELECT status FROM public.workspace WHERE organization_id = $1 AND id = $2",
			`query += " FOR UPDATE"`,
			"func loadParentGrantIdentity",
			"func loadParentGrantBusiness",
		},
	}
	for name, anchors := range required {
		content, ok := files[name]
		if !ok {
			problems = append(problems, "workspace-managed authority runtime is missing file: "+name)
			continue
		}
		for _, anchor := range anchors {
			if !strings.Contains(content, anchor) {
				problems = append(problems, "workspace-managed authority runtime lost control in "+name+": "+anchor)
			}
		}
	}
	// The runtime never writes the workspace command receipt family: an authority
	// command creates no WorkspaceRevision, so reusing that receipt would bind
	// two unrelated result contracts into one namespace.
	for _, name := range []string{"authority_receipt.go", "authority_commands.go"} {
		if content, ok := files[name]; ok && strings.Contains(content, "INTO public.workspace_command_receipt") {
			problems = append(problems, "workspace-managed authority runtime reused the workspace command receipt family in "+name)
		}
	}

	// ADR-0053 lock ordering: the workspace serialization lock is taken before
	// the current actor is reloaded. The locking calls are the FOR-UPDATE
	// (true) variants, which appear only in lockThenReload, so their relative
	// position proves the order; reversing the two reds this gate. This guards
	// the real behaviour — the lock precedes the reload — rather than any test
	// observability string.
	if commands, ok := files["authority_commands.go"]; ok {
		lockIndex := strings.Index(commands, "lockWorkspaceVisibility(ctx, transaction, access.OrganizationID, workspaceID, access.PrincipalID, true)")
		actorIndex := strings.Index(commands, "store.authorityCurrentActor(ctx, transaction, access, true)")
		if lockIndex < 0 || actorIndex < 0 || lockIndex > actorIndex {
			problems = append(problems, "workspace-managed authority runtime must take the workspace lock before reloading the actor")
		}
	}
	return problems
}

// checkWorkspaceManagedAuthorityCommandMigrationContent takes the migration
// text rather than a path so each control can be mutation-tested directly:
// deleting any anchor below must red this checker.
func checkWorkspaceManagedAuthorityCommandMigrationContent(migration string) []string {
	var problems []string

	required := map[string]string{
		// Fail-closed upgrade: pre-receipt rows are never declared trusted.
		"fail-closed upgrade gate": "refusing to declare them trusted or backfill receipts",
		// A separate receipt family, closed to the four operations.
		"authority receipt relation":    "CREATE TABLE public.workspace_managed_authority_command_receipt",
		"closed operation set":          "'WORKSPACE_MANAGED_CONFIRM_REVOKE'",
		"closed receipt status set":     "CHECK (status IN ('PENDING', 'SUCCESS', 'DENIED', 'NOT_FOUND', 'PRECONDITION_FAILED'))",
		"exhaustive request projection": "workspace_managed_authority_command_receipt_projection_exact",
		// Receipt lifecycle.
		"pending cannot commit":      "workspace_managed_authority_command_receipt_requires_terminal",
		"terminal receipt immutable": "terminal workspace managed authority receipt is immutable",
		"receipt is append-only":     "workspace_managed_authority_command_receipt_no_delete",
		// Receipt/actor/operation gate on every authority relation.
		"grant receipt gate":                   "workspace_source_confirmation_actor_grant_receipt_gate",
		"grant revocation receipt gate":        "actor_grant_revocation_receipt_gate",
		"confirmation receipt gate":            "workspace_managed_grant_confirmation_receipt_gate",
		"confirmation revocation receipt gate": "workspace_managed_grant_revocation_receipt_gate",
		// Receipt <-> authority row <-> audit event atomic binding.
		"result binding":       "workspace_managed_authority_command_receipt_result_binding",
		"audit binding":        "workspace_managed_authority_receipt_audit_binding",
		"audit is claimed":     "audit_event_authority_is_claimed",
		"authority audit type": "'WORKSPACE_AUTHORITY_COMMAND'",
		// A SUCCESS audit event must name the row that was actually persisted.
		// Proving only the metadata key set lets a command persist grant A and
		// audit a well-formed projection of grant B, so the value comparison
		// against the trusted persisted row is the load-bearing control here.
		"audit metadata matches the persisted row": "PERFORM app.authority_audit_metadata_matches_row(",
		"audit metadata operation binding":         "authority audit metadata operation does not match its receipt",
		"grant issue audit value comparison":       "grant issue audit metadata does not match the created grant",
		"grant revoke audit value comparison":      "grant revoke audit metadata does not match the created revocation",
		"confirm audit value comparison":           "confirm audit metadata does not match the created confirmation",
		"confirm revoke audit value comparison":    "confirm revoke audit metadata does not match the created revocation",
		// The grant-issue request is optimistic and must actually be applied.
		"grant issue optimistic precondition": "actor grant expected workspace revision or configuration hash is not current",
		// The canonical request is inert as a tenant selector, but only
		// NOT_FOUND (and the PENDING it is reserved as) may carry a request
		// naming a foreign organization: ADR-0053 makes every cross-tenant
		// reference NOT_FOUND and never DENIED. Any other status asserts a
		// tenant-bound fact its own request must not disclaim.
		// The receipt's own canonical request bytes are hash-bound too. The
		// counted anchor above is scoped to the four authority relations, so
		// without this the receipt CHECK would have no anchor at all.
		"receipt request hash binding": "CHECK (app.authority_canonical_hash_matches(canonical_request_bytes, ",
		"request tenant binding":       "status IN ('PENDING', 'NOT_FOUND')\n        OR request_organization_id = organization_id",
		// The SECURITY DEFINER gates read past FORCE ROW LEVEL SECURITY only
		// while the migration owner bypasses it. An owner without that property
		// would under-count rows and weaken every gate silently, so the
		// migration refuses to install rather than install a weaker contract.
		"migration owner gate": "is neither SUPERUSER nor BYPASSRLS",
		// Commit-time TOCTOU protection. The share lock is the control: a plain
		// SELECT degrades the deferred gate into a no-op under REPEATABLE READ
		// and leaves a race window under READ COMMITTED.
		"commit-time policy lock":            "WHERE id = NEW.organization_id\n    FOR SHARE",
		"commit-time warning gate":           "EXECUTE FUNCTION app.workspace_managed_confirmation_warning_at_commit()",
		"commit-time warning lock":           "LOCK TABLE public.workspace_managed_warning_contract IN SHARE MODE;",
		"commit-time warning isolation gate": "current_setting('transaction_isolation') <> 'read committed'",
		// The authority audit vocabulary is reserved to the four actions, so the
		// database refuses the same shapes the Go validator refuses.
		"reserved audit vocabulary": "workspace-managed authority audit vocabulary is reserved",
		// SECURITY DEFINER must survive the CREATE OR REPLACE of 000009's guard.
		"replaced guard keeps security definer": "CREATE OR REPLACE FUNCTION app.workspace_source_audit_projection_guard()\nRETURNS trigger\nLANGUAGE plpgsql\nSECURITY DEFINER",
		// Row-level security.
		"receipt force rls": "ALTER TABLE public.workspace_managed_authority_command_receipt FORCE ROW LEVEL SECURITY",
	}
	for control, anchor := range required {
		if !strings.Contains(migration, anchor) {
			problems = append(problems, "migration 000011 is missing its "+control+" control: "+anchor)
		}
	}

	// Controls that must appear once per authority relation or per operation.
	// Presence alone is not enough for these: the migration applies each of them
	// four times, so a drift that drops exactly one site — the realistic drift —
	// would leave a presence anchor satisfied by the other three. Pinning the
	// count is what makes a single missing site a build failure.
	counted := map[string]struct {
		anchor string
		count  int
	}{
		"receipt gate on each of the four authority relations": {
			"receipt := app.workspace_managed_authority_fresh_receipt(", 4},
		"canonical hash bound to stored bytes on each authority relation": {
			"CHECK (app.authority_canonical_hash_matches(canonical_bytes, ", 4},
		"server-owned timestamp bound to the transaction second in each operation": {
			"<> app.authority_transaction_epoch()", 4},
		"commit-time policy gate on each authority relation": {
			"EXECUTE FUNCTION app.authority_current_policy_deferred_guard()", 4},
		// The runtime role gets INSERT on the four authority relations and
		// nothing else. Pinning the verbatim line is what makes the realistic
		// drift — widening an existing grant to "GRANT INSERT, UPDATE ON TABLE
		// ..." rather than adding a new line — a build failure. A forbidden
		// substring cannot express this: the receipt legitimately needs UPDATE,
		// so "UPDATE ON TABLE public.workspace_" cannot simply be banned.
		"exact INSERT-only grant on each authority relation": {
			"GRANT INSERT ON TABLE public.workspace_", 4},
	}
	for control, want := range counted {
		if got := strings.Count(migration, want.anchor); got != want.count {
			problems = append(problems, fmt.Sprintf(
				"migration 000011 applies its %s %d times, want %d: %s",
				control, got, want.count, want.anchor))
		}
	}

	forbidden := map[string]string{
		// ADR-0053: the authority sidecar never creates a WorkspaceRevision, so
		// the workspace receipt family must not be reused or extended.
		"extends the workspace command receipt family": "ALTER TABLE public.workspace_command_receipt",
		// The runtime role may insert only; authority rows are append-only.
		"grants UPDATE on an authority relation":                                "GRANT UPDATE ON TABLE public.workspace_",
		"grants DELETE on an authority relation":                                "GRANT DELETE ON TABLE public.workspace_",
		"grants a write privilege on an authority relation in a compound grant": "UPDATE, DELETE ON TABLE public.workspace_",
		"grants an authority privilege to PUBLIC":                               "TO PUBLIC",
	}
	for problem, anchor := range forbidden {
		if strings.Contains(migration, anchor) {
			problems = append(problems, "migration 000011 "+problem+": "+anchor)
		}
	}
	return problems
}

// checkScopeGlobBoundary keeps source scope selection on one exact, bounded
// grammar. Standard-library glob matchers have different grammar and platform
// semantics, so even a well-intentioned local fallback is an authorization bug.
func checkScopeGlobBoundary(root string) []string {
	required := map[string][]string{
		"internal/source/scopeglob/scopeglob.go": {
			`"scope-glob-v1"`, "maximumPatterns", "maximumBytes", "maximumSegments",
			"maximumMatchSteps", "compiled bool", "!matcher.compiled", "CodeMatchLimit",
			"strings.EqualFold", "pathcanon.Path", "pathcanon.Pattern", "matchPattern", "matchSegment",
		},
		"internal/source/pathcanon/pathcanon.go": {
			"raw != norm.NFC.String(raw)", "strings.EqualFold", "MaxBytes", "MaxSegments",
			"CaseWindows", "validWindowsSegment", `"CON", "PRN", "AUX", "NUL"`,
		},
		"internal/source/scopeglob/scopeglob_test.go": {
			"TestAcceptedContractGoldenVectors", "source-scope-glob-v1.json",
			"TestZeroValueAndNilMatcherFailClosed", "TestTotalMatchBudgetFailsClosed",
			"TestWindowsModeRejectsUnsafeNames", `"value": *matcher`,
		},
		"tests/contracts/runner/source_scope.go": {
			`"knowvault.local/verified-workspace/internal/source/scopeglob"`,
			"scopeglob.Compile", "scopeglob.CaseWindows", "matchScopeGlobs", `profile["platform"]`,
			`case "POSIX", "S3_COMPATIBLE":`, "CONNECTION_PLATFORM_UNKNOWN_SIGNED",
		},
		"docs/adr/0045-bounded-shared-source-scope-matcher-accepted.md": {
			"scope-glob-v1", "zero value", "fail closed", "exclude", "strings.EqualFold",
			"4,194,304", "path.Match", "filepath.Match", "root Go module", "No new dependency",
		},
	}
	var problems []string
	for relative, fragments := range required {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, "scope glob boundary missing required file: "+relative)
			continue
		}
		for _, fragment := range fragments {
			if !bytes.Contains(raw, []byte(fragment)) {
				problems = append(problems, "scope glob boundary missing control in "+relative+": "+fragment)
			}
		}
	}
	runner, err := os.ReadFile(filepath.Join(root, "tests", "contracts", "runner", "source_scope.go"))
	if err == nil && (bytes.Contains(runner, []byte("func validateScopeGlob(")) || bytes.Contains(runner, []byte("func scopeGlobMatches(")) || bytes.Contains(runner, []byte("func matchScopeGlobSegment("))) {
		problems = append(problems, "scope glob boundary permits a second contract-runner grammar")
	}

	for _, directory := range []string{"internal/source", "internal/connector"} {
		base := filepath.Join(root, filepath.FromSlash(directory))
		_ = walkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			relative = filepath.ToSlash(relative)
			if strings.HasPrefix(relative, "internal/source/scopeglob/") {
				return nil
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				problems = append(problems, "scope glob boundary cannot parse "+relative)
				return nil
			}
			globAliases := map[string]bool{}
			for _, imported := range parsed.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil || (importPath != "path" && importPath != "path/filepath") {
					continue
				}
				alias := filepath.Base(importPath)
				if imported.Name != nil {
					alias = imported.Name.Name
				}
				globAliases[alias] = true
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "Match" {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if ok && globAliases[identifier.Name] {
					problems = append(problems, "scope glob boundary forbids "+identifier.Name+".Match in "+relative)
				}
				return true
			})
			return nil
		})
	}
	return problems
}

// checkCatalogEvidenceBoundary asserts the S1d catalog/extraction/Evidence
// migration keeps its load-bearing controls in the schema: per-branch bind/read
// functions (so no runtime role touches encrypted_artifact directly), the lease
// and version-retention fencing primitives, the atomic publication function, the
// fail-closed viewer authorization, and forced row-level security on every new
// tenant table. It also confirms the worker-side pipeline packages never name the
// encrypted-artifact table (they reach it only through the bind/read functions).
func checkCatalogEvidenceBoundary(root string) []string {
	var problems []string
	migration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000014_stage2_catalog_extraction_evidence.sql"))
	if err != nil {
		return []string{"catalog/evidence boundary missing migration 000014"}
	}
	content := string(migration)
	// The owner-branch bind/read pairs are generated from a format template over
	// the branch suffixes; the fencing, publication, authorization and activation
	// functions are literal.
	requiredMarkers := []string{
		"app.source_object_bind_%1$s", "app.source_object_read_%1$s",
		"app.evidence_fragment_bind_%1$s", "app.evidence_fragment_read_%1$s",
		"'canonical_locator'", "'external_object_id'", "'title'",
		"'normalized_text'", "'anchor'", "'metadata'",
		"app.lock_job_lease", "app.assert_version_writable",
		"app.source_version_publish_extraction", "app.evidence_fragment_readable",
		"app.source_scope_begin_sync", "app.source_scope_publish_ready",
	}
	for _, marker := range requiredMarkers {
		if !strings.Contains(content, marker) {
			problems = append(problems, "catalog/evidence migration 000014 is missing "+marker)
		}
	}
	// Row-level security is forced on every new tenant table through a loop over
	// the table inventory that must include the Evidence relations.
	if !strings.Contains(content, "FORCE ROW LEVEL SECURITY") ||
		!strings.Contains(content, "'evidence_fragment'") || !strings.Contains(content, "'source_object'") {
		problems = append(problems, "catalog/evidence migration 000014 does not force RLS on every new tenant table")
	}
	// The current-version cutover is fenced inside the publication function (a
	// stale worker cannot make a version current out of band): the function takes
	// a make-current flag, and the worker holds only SELECT/INSERT on source_version.
	if !strings.Contains(content, "p_make_current") {
		problems = append(problems, "catalog/evidence publication is missing the fenced current-version cutover")
	}
	if !strings.Contains(content, "GRANT SELECT, INSERT ON TABLE public.source_version TO knowvault_worker") {
		problems = append(problems, "catalog/evidence does not restrict the worker to SELECT/INSERT on source_version")
	}
	// Connection-trust verification is never a worker capability: no SECURITY
	// DEFINER setter for the trust projection may exist.
	if strings.Contains(content, "source_connection_trust_set_status") {
		problems = append(problems, "catalog/evidence exposes a worker-callable connection-trust setter")
	}
	// One normative path canonicalization: the scope-glob matcher, the folder
	// connector and the catalog identity all route through internal/source/pathcanon
	// and none keeps its own copy of the segment rules.
	pathcanonImport := `"knowvault.local/verified-workspace/internal/source/pathcanon"`
	for _, path := range []string{"internal/source/scopeglob/scopeglob.go", "internal/connector/folder/folder.go"} {
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			problems = append(problems, "cannot read "+path+" for path-canonicalization parity")
			continue
		}
		text := string(raw)
		if !strings.Contains(text, pathcanonImport) {
			problems = append(problems, path+" does not route path canonicalization through pathcanon")
		}
		if strings.Contains(text, "func validWindowsSegment(") {
			problems = append(problems, path+" keeps a second copy of the Windows path-segment rules")
		}
	}
	// The scope-sync state change is audited in-transaction (AUD-005).
	if !strings.Contains(content, "audit_event") || !strings.Contains(content, "knowvault_worker") {
		problems = append(problems, "catalog/evidence does not grant the worker in-transaction audit append")
	}
	// The atomic publication pointer and encrypted_artifact are never written by a
	// runtime role directly: no GRANT INSERT/UPDATE on the pointer table.
	if strings.Contains(content, "INSERT ON TABLE\n    public.source_version_active_extraction") ||
		regexp.MustCompile(`GRANT[^;]*INSERT[^;]*source_version_active_extraction`).MatchString(content) {
		problems = append(problems, "catalog/evidence migration 000014 grants direct writes on the active-extraction pointer")
	}
	// Worker-side pipeline packages reach ciphertext only through app.* functions,
	// and the test-only failure-injection hook must never be driven from
	// production code (it is inert without a caller, but the class is closed here).
	for _, pkg := range []string{"internal/ingestion", "internal/source/evidence"} {
		problems = append(problems, scanPaths(filepath.Join(root, filepath.FromSlash(pkg)), func(path string) []string {
			if filepath.Ext(path) != ".go" {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return []string{readErr.Error()}
			}
			if strings.Contains(strings.ToLower(string(raw)), "encrypted_artifact") {
				return []string{"catalog/evidence pipeline names the encrypted_artifact table directly: " + relative(root, path)}
			}
			if !strings.HasSuffix(path, "_test.go") && strings.Contains(string(raw), ".WithFault(") {
				return []string{"catalog/evidence pipeline drives the test-only fault hook from production code: " + relative(root, path)}
			}
			return nil
		})...)
	}
	return problems
}

// checkScopeRevisionCutoverBoundary asserts the ADR-0061 scope-revision cutover
// keeps its load-bearing controls: migration 000016 must own the atomic authority
// transition (activate_revision), the worker fence (assert_scope_revision_syncing),
// the partial-coverage hold (publish_partial) and the independent coverage
// containment (coverage_complete), and it must supersede the prior revision
// (REVOKED activation, REMOVED memberships, DELETED object closure). The cutover
// primitives are worker-only, never granted to the web/API role, and the ingestion
// orchestrator must fence its derived writes to the candidate revision's live
// SYNCING authority (so a superseded worker cannot write).
func checkScopeRevisionCutoverBoundary(root string) []string {
	var problems []string
	migration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000016_stage2_source_scope_revision_cutover.sql"))
	if err != nil {
		return []string{"scope-revision cutover boundary missing migration 000016"}
	}
	content := string(migration)
	for _, marker := range []string{
		"app.source_scope_activate_revision", "app.assert_scope_revision_syncing",
		"app.source_scope_publish_partial",
		"coverage_complete", "'REVOKED'", "membership_state = 'REMOVED'",
		"lifecycle_state = 'DELETED'", "older than the active revision",
	} {
		if !strings.Contains(content, marker) {
			problems = append(problems, "scope-revision cutover migration 000016 is missing "+marker)
		}
	}
	// The scan-safety containment: activate_revision gates on a complete coverage
	// run, so a partial scan can never drive supersession.
	if !strings.Contains(content, "requires a complete coverage run") {
		problems = append(problems, "scope-revision cutover migration 000016 is missing the coverage-run containment")
	}
	// The cutover primitives are a worker capability only: the fence, the cutover
	// and the partial-hold are granted to knowvault_worker and never to the web/API
	// role knowvault_app.
	if !strings.Contains(content, "TO knowvault_worker") {
		problems = append(problems, "scope-revision cutover migration 000016 does not grant its primitives to the worker")
	}
	if regexp.MustCompile(`GRANT[^;]*source_scope_activate_revision[^;]*knowvault_app`).MatchString(content) ||
		regexp.MustCompile(`GRANT[^;]*assert_scope_revision_syncing[^;]*knowvault_app`).MatchString(content) {
		problems = append(problems, "scope-revision cutover exposes a cutover primitive to the web/API role")
	}
	// CREATE FUNCTION grants EXECUTE to PUBLIC by default, so the default grant must
	// be revoked (like every peer SECURITY DEFINER function) or knowvault_app could
	// invoke the mass-delete cutover primitive. Each primitive must appear inside a
	// REVOKE ... FROM PUBLIC block.
	for _, fn := range []string{
		"source_scope_activate_revision", "assert_scope_revision_syncing",
		"source_scope_publish_partial",
	} {
		if !regexp.MustCompile(`REVOKE ALL ON FUNCTION[\s\S]*?` + fn + `[\s\S]*?FROM PUBLIC`).MatchString(content) {
			problems = append(problems, "scope-revision cutover does not REVOKE "+fn+" from PUBLIC")
		}
	}
	// The ingestion orchestrator fences every derived write to the candidate
	// revision's live SYNCING authority (ADR-0061 §3): both the per-object pipeline
	// and reconciliation call assert_scope_revision_syncing.
	for _, path := range []string{"internal/ingestion/pipeline.go", "internal/ingestion/handler.go"} {
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			problems = append(problems, "cannot read "+path+" for scope-revision fencing")
			continue
		}
		if !strings.Contains(string(raw), "app.assert_scope_revision_syncing") {
			problems = append(problems, path+" does not fence derived writes to the candidate revision's SYNCING authority")
		}
	}
	return problems
}

// checkHTMLParserBoundary keeps the safe folder-HTML extractor a pure, bounded,
// capability-free parser over transient bytes: it may reach only a fixed stdlib
// subset, the pinned golang.org/x/net/html tree builder and the shared text
// canonicalizer — never a network (net/http), filesystem (os), process (os/exec),
// database, catalog, evidence, jobs or logging capability. It must keep its
// load-bearing controls in source: the pure tree parse (no fetch), the
// active/embedded/hidden content drop, the bounded node/depth/output limits, the
// UTF-8 gate, the single canonicalization authority and the text-free quarantine
// with no fallback. This is the static mutation-proof of the dependency,
// network/active-content and profile boundaries (PARSER_CONTRACTS.md §5).
func checkHTMLParserBoundary(root string) []string {
	paths := []string{
		"internal/source/html/html.go",
		"internal/source/html/html_test.go",
		"tests/integration/postgres/catalog_evidence_html_test.go",
		"docs/adr/0060-text-structured-format-extraction-accepted.md",
	}
	contents := make(map[string]string, len(paths))
	var problems []string
	for _, relativePath := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relativePath)))
		if err != nil {
			problems = append(problems, "html parser boundary missing required file: "+relativePath)
			continue
		}
		contents[relativePath] = string(raw)
	}
	if len(problems) != 0 {
		return problems
	}
	problems = append(problems, checkHTMLParserBoundaryContents(contents)...)

	// Independent AST import walk over the actual package: the extractor holds no
	// network/filesystem/durable-sink/authority capability.
	base := filepath.Join(root, filepath.FromSlash("internal/source/html"))
	_ = walkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		relativePath := filepath.ToSlash(relative(root, path))
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			problems = append(problems, "html parser boundary cannot parse "+relativePath)
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			if !allowedHTMLParserImport(importPath) {
				problems = append(problems, "html parser boundary forbids non-allowlisted import in "+relativePath+": "+importPath)
			}
		}
		return nil
	})
	return problems
}

// allowedHTMLParserImport is a fully closed positive allowlist, not a denylist.
// The extractor may reach only the exact stdlib packages it needs to walk bytes,
// the pinned x/net/html tree builder and its atom table, the shared canonicalizer,
// and the Go test package. Anything else — os (filesystem), net/http (network),
// os/exec (process), any database/catalog/evidence/jobs capability, or logging
// that could exfiltrate source markup — is refused, so the parser cannot gain a
// network, filesystem or durable-sink capability.
func allowedHTMLParserImport(importPath string) bool {
	switch importPath {
	case "bytes", "errors", "strings", "unicode/utf8", "testing",
		"golang.org/x/net/html", "golang.org/x/net/html/atom",
		"knowvault.local/verified-workspace/internal/source/canon":
		return true
	default:
		return false
	}
}

// checkHTMLParserBoundaryContents asserts the extractor keeps its load-bearing
// safety controls. It is factored out so the checker self-tests can drive it with
// mutated source.
func checkHTMLParserBoundaryContents(contents map[string]string) []string {
	var problems []string
	source := contents["internal/source/html/html.go"]

	// Pure parse over transient bytes: the only entry point is the x/net/html tree
	// builder reading the in-memory bytes — it never fetches a URL or opens a file.
	pure := []string{"xhtml.Parse(bytes.NewReader(raw)", "utf8.Valid(raw)"}
	for _, marker := range pure {
		if !strings.Contains(source, marker) {
			problems = append(problems, "html parser pure/UTF-8 control removed: "+marker)
		}
	}

	// Active/embedded/hidden content is dropped before any text is collected.
	activeDrop := []string{"isDropped(", "hasHiddenAttr(", "atom.Script", "atom.Iframe", "atom.Form", "atom.Object", "atom.Style"}
	for _, marker := range activeDrop {
		if !strings.Contains(source, marker) {
			problems = append(problems, "html parser active-content drop control removed: "+marker)
		}
	}

	// Bounded parse: node, depth and output limits fail closed to a quarantine.
	bounds := []string{"MaxNodes", "MaxDepth", "MaxOutputBytes", "MaxInputBytes", "ErrQuarantine",
		"e.nodes > e.limits.MaxNodes", "depth > e.limits.MaxDepth", "e.outBytes > e.limits.MaxOutputBytes"}
	for _, marker := range bounds {
		if !strings.Contains(source, marker) {
			problems = append(problems, "html parser resource-bound control removed: "+marker)
		}
	}

	// Single canonicalization authority and text-free quarantine with no fallback.
	general := []string{"canon.Canonicalize(", "len(e.lines) == 0"}
	for _, marker := range general {
		if !strings.Contains(source, marker) {
			problems = append(problems, "html parser canonicalization/quarantine control removed: "+marker)
		}
	}

	// Every import in the extractor's import block is on the closed allowlist. A
	// forbidden capability — network, filesystem, process, database or logging —
	// fails here.
	inImport := false
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "import (" {
			inImport = true
			continue
		}
		if inImport && trimmed == ")" {
			inImport = false
			continue
		}
		if !inImport || trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		// Strip an optional import alias (e.g. `xhtml "golang.org/x/net/html"`).
		unquoted := trimmed
		if idx := strings.IndexByte(unquoted, '"'); idx >= 0 {
			unquoted = unquoted[idx:]
		}
		unquoted = strings.Trim(unquoted, "\t \"")
		if !allowedHTMLParserImport(unquoted) {
			problems = append(problems, "html parser gained a non-allowlisted import: "+unquoted)
		}
	}
	return problems
}

// netHTMLImportPermitted decides whether a `golang.org/x/net…` import in the file
// at repo-relative path rel is allowed. The activation justification is a minimal
// surface: `golang.org/x/net` may be imported ONLY by the safe HTML extractor
// package `internal/source/html`, and ONLY its stdlib-only `html` / `html/atom`
// subpackages — never `html/charset` (which would pull x/text and sniff), and
// never a network subpackage (`http2`, `proxy`, `websocket`, …). Any other x/net
// import anywhere in the repo is refused, so activating x/net for HTML text
// extraction cannot silently grow into a network/SSRF/crawler capability.
func netHTMLImportPermitted(rel, importPath string) bool {
	if !strings.HasPrefix(importPath, "golang.org/x/net") {
		return true // not an x/net import; out of scope for this gate
	}
	if importPath != "golang.org/x/net/html" && importPath != "golang.org/x/net/html/atom" {
		return false
	}
	dir := "internal/source/html/"
	rel = filepath.ToSlash(rel)
	return rel == strings.TrimSuffix(dir, "/") || strings.HasPrefix(rel, dir)
}

// checkNetHTMLModuleScope enforces netHTMLImportPermitted across the whole repo:
// the only enforceable guarantee behind the x/net activation is that no package
// other than the safe HTML extractor can reach the module, and even it can reach
// only the html/atom subpackages. Without this, the STAGE_2 leak-scan removal of
// "golang.org/x/net" would leave the module importable repo-wide.
func checkNetHTMLModuleScope(root string) []string {
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if entry.IsDir() {
			first := strings.Split(rel, "/")[0]
			switch first {
			case ".git", "node_modules", "web", "docs", "architecture", "scripts":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			if !netHTMLImportPermitted(rel, importPath) {
				problems = append(problems, "golang.org/x/net is scoped to internal/source/html (html/atom only); forbidden import in "+rel+": "+importPath)
			}
		}
		return nil
	})
	return problems
}

// checkFolderConnectorBoundary keeps the safe folder connector a pure,
// capability-free component: it may only reach the standard library, the shared
// scope-glob grammar and text normalization, and it must keep the three
// load-bearing containment/stable-read/transient-content controls in source. A
// connector that could import PostgreSQL, the catalog, evidence, search, jobs,
// audit or the model gateway would hold a durable-sink or authority capability
// the connector boundary forbids.
func checkFolderConnectorBoundary(root string) []string {
	paths := []string{
		"internal/connector/folder/folder.go",
		"internal/connector/folder/folder_test.go",
		"tests/integration/postgres/folder_connector_test.go",
		"docs/adr/0057-safe-folder-connector-accepted.md",
	}
	contents := make(map[string]string, len(paths))
	var problems []string
	for _, relativePath := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relativePath)))
		if err != nil {
			problems = append(problems, "folder connector boundary missing required file: "+relativePath)
			continue
		}
		contents[relativePath] = string(raw)
	}
	if len(problems) != 0 {
		return problems
	}
	problems = append(problems, checkFolderConnectorBoundaryContents(contents)...)

	// Independent AST import walk over the actual package: the connector holds no
	// catalog/evidence/database/search/jobs/model capability.
	base := filepath.Join(root, filepath.FromSlash("internal/connector/folder"))
	_ = walkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		relativePath := filepath.ToSlash(relative(root, path))
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			problems = append(problems, "folder connector boundary cannot parse "+relativePath)
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			if !allowedConnectorImport(importPath) {
				problems = append(problems, "folder connector boundary forbids non-allowlisted import in "+relativePath+": "+importPath)
			}
		}
		return nil
	})
	return problems
}

// allowedConnectorImport is a closed allowlist, not a denylist: the folder
// connector may reach only the standard library, the shared scope-glob grammar
// and text normalization. Anything else — a database/catalog/evidence/search/
// jobs/model capability, or even stdlib logging that could exfiltrate source
// bytes or a source path to open telemetry — is refused.
func allowedConnectorImport(importPath string) bool {
	if importPath == "" {
		return false
	}
	// Logging/formatting-to-stream stdlib packages are the realistic path for
	// source bytes or a source-native path to reach open telemetry, so they are
	// denied even though they are standard library. The connector reports through
	// content-free typed codes, never a formatted stream.
	switch importPath {
	case "log", "log/slog", "fmt":
		return false
	}
	// Any other standard library import path has no dot in its first segment.
	first, _, _ := strings.Cut(importPath, "/")
	if !strings.Contains(first, ".") {
		return true
	}
	allowed := []string{
		"knowvault.local/verified-workspace/internal/source/pathcanon",
		"knowvault.local/verified-workspace/internal/source/scopeglob",
		"golang.org/x/text/",
	}
	for _, prefix := range allowed {
		if importPath == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(importPath, prefix) {
			return true
		}
	}
	return false
}

// checkFolderConnectorBoundaryContents asserts the connector source keeps its
// three load-bearing controls and never gains a durable-sink capability. It is
// factored out so the checker self-tests can drive it with mutated source.
func checkFolderConnectorBoundaryContents(contents map[string]string) []string {
	var problems []string
	folderSource := contents["internal/connector/folder/folder.go"]

	// Containment: pinned root handle with a TOCTOU re-check and symlink refusal.
	containment := []string{"os.OpenRoot(", "os.SameFile(info, openedInfo)", "root.Lstat(", "os.ModeSymlink"}
	for _, marker := range containment {
		if !strings.Contains(folderSource, marker) {
			problems = append(problems, "folder connector containment control removed: "+marker)
		}
	}

	// Stable read: before/after descriptor stat comparison that catches a torn read.
	stableRead := []string{"before, err := file.Stat()", "after, err := file.Stat()", "os.SameFile(before, after)", `"TORN_READ_VERSION_MISMATCH"`, "utf8.Valid(content)"}
	for _, marker := range stableRead {
		if !strings.Contains(folderSource, marker) {
			problems = append(problems, "folder connector stable-read control removed: "+marker)
		}
	}

	// Shared grammar and content-free, redacted diagnostics.
	general := []string{"scopeglob.Compile(", "[REDACTED]", "FOLDER_CONTAINMENT_VIOLATION", "FOLDER_ACL_UNKNOWN"}
	for _, marker := range general {
		if !strings.Contains(folderSource, marker) {
			problems = append(problems, "folder connector control removed: "+marker)
		}
	}

	// Transient-content / capability boundary: every import in the connector's
	// import block is on the closed allowlist (stdlib, scopeglob, x/text). A
	// forbidden capability — or stdlib logging that could exfiltrate bytes — fails.
	inImport := false
	for _, line := range strings.Split(folderSource, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "import (" {
			inImport = true
			continue
		}
		if inImport && trimmed == ")" {
			inImport = false
			continue
		}
		if !inImport || trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		unquoted := strings.Trim(strings.TrimPrefix(trimmed, "_ "), "\t \"")
		if !allowedConnectorImport(unquoted) {
			problems = append(problems, "folder connector gained a non-allowlisted import: "+unquoted)
		}
	}
	return problems
}

func checkProtectedFiles(root string) []string {
	manifestPath := filepath.Join(root, "architecture", "protected-hashes.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return []string{"missing or unreadable architecture/protected-hashes.json"}
	}

	var manifest protectedManifest
	if err := rejectDuplicateJSON(raw); err != nil {
		return []string{"invalid architecture/protected-hashes.json: " + err.Error()}
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return []string{"invalid architecture/protected-hashes.json: " + err.Error()}
	}

	required, problems := collectProtectedPaths(root)
	problems = append(problems, validateProtectedGovernanceInventory(root, required)...)
	accepted, _ := filepath.Glob(filepath.Join(root, "docs", "adr", "*-accepted.md"))
	for _, path := range accepted {
		required = append(required, filepath.ToSlash(relative(root, path)))
	}
	_ = walkDir(filepath.Join(root, "tests", "contracts"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", ".pnpm-store", "coverage", ".cache", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			required = append(required, filepath.ToSlash(relative(root, path)))
		}
		return nil
	})
	for _, directory := range []string{
		filepath.Join(root, "db"),
		filepath.Join(root, "internal", "audit"),
		filepath.Join(root, "internal", "identity"),
		filepath.Join(root, "internal", "policy"),
		filepath.Join(root, "internal", "platform", "httpauth"),
		filepath.Join(root, "internal", "platform", "httpserver"),
		filepath.Join(root, "internal", "platform", "webui"),
		filepath.Join(root, "internal", "platform", "tenantsecurity"),
		filepath.Join(root, "internal", "platform", "browserauth"),
		filepath.Join(root, "internal", "platform", "apphttp"),
		filepath.Join(root, "internal", "platform", "oidctransport"),
		filepath.Join(root, "internal", "platform", "oidcweb"),
		filepath.Join(root, "internal", "platform", "secretmount"),
		filepath.Join(root, "internal", "platform", "netcanon"),
		filepath.Join(root, "internal", "platform", "artifactcrypto"),
		filepath.Join(root, "internal", "artifact", "repository"),
		filepath.Join(root, "internal", "platform", "trustbundle"),
		filepath.Join(root, "internal", "platform", "composition"),
		filepath.Join(root, "internal", "embedding"),
		filepath.Join(root, "internal", "platform", "workspaceapi"),
		filepath.Join(root, "internal", "platform", "database"),
		filepath.Join(root, "internal", "platform", "oidc"),
		filepath.Join(root, "internal", "workspace"),
		filepath.Join(root, "internal", "source", "pathcanon"),
		filepath.Join(root, "internal", "source", "scopeglob"),
		filepath.Join(root, "internal", "connector"),
		filepath.Join(root, "internal", "jobs"),
		filepath.Join(root, "tests", "integration", "postgres"),
	} {
		_ = walkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				problems = append(problems, walkErr.Error())
				return nil
			}
			if !entry.IsDir() {
				required = append(required, filepath.ToSlash(relative(root, path)))
			}
			return nil
		})
	}
	sort.Strings(required)
	unique := required[:0]
	for _, path := range required {
		if len(unique) == 0 || unique[len(unique)-1] != path {
			unique = append(unique, path)
		}
	}
	required = unique
	for _, relative := range required {
		if _, ok := manifest.Files[relative]; !ok {
			problems = append(problems, "protected hash manifest is incomplete: "+relative)
		}
	}
	if manifest.Version != 1 || manifest.Algorithm != "SHA256" {
		problems = append(problems, "protected hash manifest version/algorithm is not the accepted baseline")
	}
	for relative, expected := range manifest.Files {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(relative)))
		if clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(relative) {
			problems = append(problems, "protected manifest path escapes repository: "+relative)
			continue
		}
		if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{64}$`, expected); !matched {
			problems = append(problems, "invalid protected SHA-256: "+relative)
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		content, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, "missing protected file: "+relative)
			continue
		}
		sum := sha256.Sum256(content)
		actual := hex.EncodeToString(sum[:])
		if !strings.EqualFold(actual, expected) {
			problems = append(problems, "protected file changed without architecture baseline update: "+relative)
		}
	}
	return problems
}

// validateProtectedGovernanceInventory keeps the normative guardrail list and
// the derived hash inventory joined at one boundary. A collector change alone
// is insufficient: removing either protected_files entry from guardrails.yaml
// must fail, and every regular file currently under tests/e2e must be present
// in the derived protected set.
func validateProtectedGovernanceInventory(root string, protectedPaths []string) []string {
	guardrails, err := os.ReadFile(filepath.Join(root, "architecture", "guardrails.yaml"))
	if err != nil {
		return []string{"missing architecture/guardrails.yaml for protected governance inventory: " + err.Error()}
	}
	patterns, problems := parseProtectedFilePatterns(string(guardrails))
	for _, required := range []string{
		"tests/e2e/**",
		"internal/ingestion/**",
		"internal/sandboxdispatch/**",
		"internal/source/canon/**",
		"internal/source/dispatchparser/**",
		"internal/source/docparser/**",
		"internal/source/pdfparser/**",
		"internal/source/ocrparser/**",
		"internal/source/ocrworker/**",
		"internal/source/pdfrenderparser/**",
		"internal/source/pdfrenderworker/**",
		"tests/integration/parserv2harness/**",
		"tests/integration/sandboxdispatch/**",
		"workers/document-parser/**",
		"workers/tesseract-ocr/**",
	} {
		count := 0
		for _, pattern := range patterns {
			if pattern == required {
				count++
			}
		}
		if count != 1 {
			problems = append(problems, fmt.Sprintf("protected_files must contain exactly one %s entry, got %d", required, count))
		}
	}
	protected := make(map[string]bool, len(protectedPaths))
	for _, path := range protectedPaths {
		protected[path] = true
	}
	e2eRoot := filepath.Join(root, "tests", "e2e")
	info, statErr := os.Stat(e2eRoot)
	if statErr != nil {
		problems = append(problems, "tests/e2e is missing from the protected-hash inventory: "+statErr.Error())
		return problems
	}
	if !info.IsDir() {
		return append(problems, "tests/e2e protected path is not a directory")
	}
	_ = walkDir(e2eRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		relativePath := filepath.ToSlash(relative(root, path))
		if !protected[relativePath] {
			problems = append(problems, "tests/e2e file is outside the protected-hash inventory: "+relativePath)
		}
		return nil
	})
	return problems
}

func parseProtectedFilePatterns(guardrails string) ([]string, []string) {
	lines := strings.Split(strings.ReplaceAll(guardrails, "\r\n", "\n"), "\n")
	var entries []string
	var problems []string
	inSection := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "protected_files:" && len(line)-len(strings.TrimLeft(line, " \t")) == 0 {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			break
		}
		if indent != 2 || !strings.HasPrefix(trimmed, "-") {
			problems = append(problems, "protected_files contains a non-list entry: "+trimmed)
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if value == "" {
			problems = append(problems, "protected_files contains an empty entry")
			continue
		}
		entries = append(entries, value)
	}
	if !inSection {
		problems = append(problems, "guardrails.yaml is missing the protected_files section")
	}
	return entries, problems
}

// collectProtectedPaths assembles the complete protected-file inventory: the
// fixed normative files, accepted ADRs, contract fixtures and every file of
// the protected package directories. It is the single source for both the
// check and the -rebaseline rebuild.
func collectProtectedPaths(root string) ([]string, []string) {
	var problems []string
	required := []string{
		".gitattributes",
		".dockerignore",
		".gitignore",
		"go.mod",
		"go.sum",
		"web/package.json",
		"web/pnpm-lock.yaml",
		"deploy/images/Dockerfile.connector",
		"deploy/images/Dockerfile.dispatcher",
		"deploy/images/Dockerfile.operator",
		"deploy/images/Dockerfile.server",
		"deploy/images/Dockerfile.worker",
		"deploy/images/Dockerfile.purger",
		"deploy/images/README.md",
		"deploy/compose/compose.yaml",
		"deploy/manifests/sandbox-dispatcher.yaml",
		".github/CODEOWNERS",
		".github/workflows/architecture.yml",
		".github/workflows/codeql.yml",
		".github/workflows/dependency-review.yml",
		"PRODUCT_CONSTITUTION.md",
		"ARCHITECTURE.md",
		"POKA_YOKE.md",
		"architecture/guardrails.yaml",
		"architecture/licenses.yaml",
		"architecture/versions.json",
		"architecture/accepted-adr-immutable.json",
		"api/openapi.yaml",
		"docs/CANONICALIZATION.md",
		"docs/CONTRACT_VALIDATION.md",
		"docs/DEPLOYMENT.md",
		"docs/ENCRYPTION.md",
		"docs/NUMERIC_VALIDATION.md",
		"docs/PARSER_CONTRACTS.md",
		"docs/SOURCE_CONTRACTS.md",
		"docs/HLD.md",
		"docs/DATA_MODEL.md",
		"docs/OPERATOR_ARTIFACT.md",
		"docs/qualification-s2b-document-parser.md",
		"docs/TRUST_BOUNDARY.md",
		"docs/adr/README.md",
		"scripts/check-architecture.go",
		"scripts/check_architecture_test.go",
		"scripts/check-architecture.ps1",
		"scripts/run-install-smoke.ps1",
	}
	// Keep public pilot controls and replacement product guides required so
	// regeneration cannot silently discard their protection.
	required = append(required,
		"cmd/worker/main_test.go",
		"deploy/compose/native-ingest.yaml",
		"docs/MODEL-PROFILES.md",
		"docs/NATIVE-INGEST.md",
		"docs/PILOT-ACCEPTANCE.md",
		"docs/release/PLAN.md",
		"internal/modelgateway/converse.go",
		"internal/modelgateway/converse_diagnostics_test.go",
		"internal/modelgateway/lab_adapter.go",
		"internal/modelgateway/mount_lab.go",
		"internal/modelgateway/mount_profiles.go",
		"internal/modelgateway/mount_profiles_test.go",
		"internal/modelgateway/profiles.go",
		"internal/modelgateway/profiles_test.go",
		"internal/platform/runtimeidentity/mounts.go",
		"internal/platform/workercomposition/native.go",
		"internal/platform/workercomposition/native_test.go",
		"internal/question/model_profiles.go",
		"internal/question/model_profiles_test.go",
		"internal/question/model_response_diagnostics_test.go",
		"internal/question/service.go",
		"internal/question/tool_finalization_test.go",
		"internal/question/tool_loop.go",
		"internal/retrieval/workspace_copy_units_test.go",
		"internal/retrieval/workspace_groups.go",
		"internal/retrieval/workspacesearch.go",
		"internal/search/applier.go",
		"internal/search/applier_test.go",
		"internal/search/consumer_mount_linux_test.go",
		"internal/source/evidence/hybrid.go",
		"internal/source/evidence/search_exact.go",
		"internal/source/evidence/search_query.go",
		"internal/source/evidence/viewer.go",
		"internal/source/evidence/viewer_exact.go",
		"internal/source/evidence/viewer_exact_test.go",
		"internal/source/evidence/viewer_layout.go",
		"internal/source/evidence/viewer_layout_test.go",
		"internal/source/evidence/viewer_structural_layout.go",
		"internal/source/evidence/viewer_structural_layout_test.go",
		"scripts/parser_scan_identity_test.go",
		"scripts/runtime_identity_test.go",
		"web/src/main.tsx",
		"web/src/styles.css",
	)
	accepted, _ := filepath.Glob(filepath.Join(root, "docs", "adr", "*-accepted.md"))
	for _, path := range accepted {
		required = append(required, filepath.ToSlash(relative(root, path)))
	}
	// architecture/contracts/*.schema.json is pinned by the guardrails.yaml
	// glob entry itself (review-opus-s2-6-7.md remark: this collector used
	// to hold a literal per-schema list instead, so a newly added schema --
	// as source-connection-trust-verify*.schema.json (ADR-0087 §2) was on
	// 59fb336..7792f01 -- silently shipped unprotected until someone
	// remembered to add its name here by hand). Every *.schema.json file
	// present on disk is required, exactly like the accepted-ADR glob above:
	// the file set on disk, not a maintained enumeration, is the source of
	// truth.
	schemas, _ := filepath.Glob(filepath.Join(root, "architecture", "contracts", "*.schema.json"))
	for _, path := range schemas {
		required = append(required, filepath.ToSlash(relative(root, path)))
	}
	_ = walkDir(filepath.Join(root, "tests", "contracts"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", ".pnpm-store", "coverage", ".cache", "tmp":
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			required = append(required, filepath.ToSlash(relative(root, path)))
		}
		return nil
	})
	_ = walkDir(filepath.Join(root, "tests", "e2e"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		required = append(required, filepath.ToSlash(relative(root, path)))
		return nil
	})
	for _, directory := range []string{
		filepath.Join(root, "db"),
		filepath.Join(root, "internal", "audit"),
		filepath.Join(root, "internal", "identity"),
		filepath.Join(root, "internal", "policy"),
		filepath.Join(root, "internal", "platform", "httpauth"),
		filepath.Join(root, "internal", "platform", "httpserver"),
		filepath.Join(root, "internal", "platform", "webui"),
		filepath.Join(root, "internal", "platform", "tenantsecurity"),
		filepath.Join(root, "internal", "platform", "browserauth"),
		filepath.Join(root, "internal", "platform", "apphttp"),
		filepath.Join(root, "internal", "platform", "oidctransport"),
		filepath.Join(root, "internal", "platform", "oidcweb"),
		filepath.Join(root, "internal", "platform", "secretmount"),
		filepath.Join(root, "internal", "platform", "netcanon"),
		filepath.Join(root, "internal", "platform", "artifactcrypto"),
		filepath.Join(root, "internal", "artifact", "repository"),
		filepath.Join(root, "internal", "platform", "trustbundle"),
		filepath.Join(root, "internal", "platform", "composition"),
		filepath.Join(root, "internal", "platform", "purgercomposition"),
		filepath.Join(root, "internal", "embedding"),
		filepath.Join(root, "internal", "platform", "workspaceapi"),
		filepath.Join(root, "internal", "platform", "database"),
		filepath.Join(root, "internal", "platform", "oidc"),
		filepath.Join(root, "internal", "operator"),
		filepath.Join(root, "internal", "workspace"),
		filepath.Join(root, "internal", "source", "pathcanon"),
		filepath.Join(root, "internal", "source", "scopeglob"),
		filepath.Join(root, "internal", "connector"),
		filepath.Join(root, "internal", "jobs"),
		filepath.Join(root, "internal", "ingestion"),
		filepath.Join(root, "internal", "sandboxdispatch"),
		filepath.Join(root, "internal", "source", "canon"),
		filepath.Join(root, "internal", "source", "dispatchparser"),
		filepath.Join(root, "internal", "source", "docparser"),
		filepath.Join(root, "internal", "source", "pdfparser"),
		filepath.Join(root, "internal", "source", "ocrparser"),
		filepath.Join(root, "internal", "source", "ocrworker"),
		filepath.Join(root, "internal", "source", "pdfrenderparser"),
		filepath.Join(root, "internal", "source", "pdfrenderworker"),
		filepath.Join(root, "tests", "integration", "parserv2harness"),
		filepath.Join(root, "tests", "integration", "postgres"),
		filepath.Join(root, "tests", "integration", "sandboxdispatch"),
		filepath.Join(root, "workers", "document-parser"),
		filepath.Join(root, "workers", "tesseract-ocr"),
	} {
		_ = walkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				if os.IsNotExist(walkErr) {
					return nil
				}
				problems = append(problems, walkErr.Error())
				return nil
			}
			// Maven target/ is a reproducible, gitignored build output. Protect
			// the Dockerfile, dependency locks, sources, tests and release
			// evidence, never workstation-specific compiled classes/JAR copies.
			if entry.IsDir() && filepath.ToSlash(relative(root, path)) == "workers/document-parser/target" {
				return filepath.SkipDir
			}
			if !entry.IsDir() {
				required = append(required, filepath.ToSlash(relative(root, path)))
			}
			return nil
		})
	}
	sort.Strings(required)
	return required, problems
}

// rebuildProtectedManifest recomputes the protected-hash baseline from the
// exact inventory collectProtectedPaths assembles. It exists so the baseline
// is never hand-edited: -rebaseline is the only supported way to accept
// reviewed protected-file changes.
func rebuildProtectedManifest(root string) error {
	required, problems := collectProtectedPaths(root)
	if len(problems) > 0 {
		return fmt.Errorf("collect protected paths: %s", strings.Join(problems, "; "))
	}
	files := make(map[string]string, len(required))
	for _, relative := range required {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("read protected file %s: %w", relative, err)
		}
		sum := sha256.Sum256(content)
		files[relative] = hex.EncodeToString(sum[:])
	}
	raw, err := json.MarshalIndent(protectedManifest{Version: 1, Algorithm: "SHA256", Files: files}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode protected manifest: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(root, "architecture", "protected-hashes.json"), raw, 0o644); err != nil {
		return fmt.Errorf("write protected manifest: %w", err)
	}
	return nil
}

// checkAcceptedADRImmutability freezes accepted ADRs as immutable history. It
// is a distinct, loudly named gate: editing an already-accepted ADR fails here
// and cannot pass as a routine protected-hash bump, because it also requires
// changing an entry in a manifest whose sole purpose is immutability. A new ADR
// appends one entry; an existing entry must never change.
func checkAcceptedADRImmutability(root string) []string {
	manifestPath := filepath.Join(root, "architecture", "accepted-adr-immutable.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return []string{"missing or unreadable architecture/accepted-adr-immutable.json"}
	}
	if err := rejectDuplicateJSON(raw); err != nil {
		return []string{"invalid architecture/accepted-adr-immutable.json: " + err.Error()}
	}
	var manifest struct {
		Algorithm string            `json:"algorithm"`
		Accepted  map[string]string `json:"accepted"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return []string{"invalid architecture/accepted-adr-immutable.json: " + err.Error()}
	}
	fileHashes := make(map[string]string)
	accepted, _ := filepath.Glob(filepath.Join(root, "docs", "adr", "*-accepted.md"))
	for _, path := range accepted {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return []string{"unreadable accepted ADR: " + relative(root, path)}
		}
		sum := sha256.Sum256(content)
		fileHashes[filepath.ToSlash(relative(root, path))] = hex.EncodeToString(sum[:])
	}
	return verifyAcceptedADRImmutability(manifest.Algorithm, manifest.Accepted, fileHashes)
}

func verifyAcceptedADRImmutability(algorithm string, frozen, onDisk map[string]string) []string {
	var problems []string
	if algorithm != "SHA256" {
		problems = append(problems, "accepted-ADR immutability manifest algorithm is not the accepted baseline")
	}
	for path, actual := range onDisk {
		expected, ok := frozen[path]
		if !ok {
			problems = append(problems, "accepted ADR is not frozen in the immutability manifest: "+path)
			continue
		}
		if !strings.EqualFold(actual, expected) {
			problems = append(problems, "accepted ADR content changed — accepted ADRs are immutable history: "+path)
		}
	}
	for path, expected := range frozen {
		if _, ok := onDisk[path]; !ok {
			problems = append(problems, "immutability manifest references a missing or renamed accepted ADR: "+path)
		}
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
		if clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(path) ||
			!strings.HasPrefix(path, "docs/adr/") || !strings.HasSuffix(path, "-accepted.md") {
			problems = append(problems, "immutability manifest has an invalid ADR path: "+path)
		}
		if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{64}$`, expected); !matched {
			problems = append(problems, "immutability manifest has an invalid SHA-256: "+path)
		}
	}
	return problems
}

func checkContractJSON(root string) []string {
	paths, _ := filepath.Glob(filepath.Join(root, "architecture", "contracts", "*.schema.json"))
	var problems []string
	expected := map[string]bool{
		"answer-manifest.schema.json": true, "audit-checkpoint.schema.json": true, "audit-event.schema.json": true,
		"connector-event.schema.json": true, "encrypted-artifact-aad.schema.json": true, "model-answer.schema.json": true,
		"numeric-validator-output.schema.json": true, "source-anchor.schema.json": true, "source-scope.schema.json": true,
		"verifier-output.schema.json": true, "workspace-managed-authority-command.schema.json": true,
		"document-parser-result-v1.schema.json": true,
		"pdf-parser-result-v1.schema.json":      true,
		"pdf-render-result-v1.schema.json":      true,
		"ocr-result-v1.schema.json":             true,
		"sandbox-job.schema.json":               true, "sandbox-lease.schema.json": true,
		"sandbox-job-v2.schema.json": true, "sandbox-lease-v2.schema.json": true,
		"sandbox-outcome.schema.json": true, "sandbox-limit-confirmation.schema.json": true,
		"sandbox-outcome-v2.schema.json": true, "sandbox-limit-confirmation-v2.schema.json": true,
		"sandbox-parser-request-v1.schema.json":     true,
		"sandbox-registration-v2.schema.json":       true,
		"sandbox-supervisor-handoff-v1.schema.json": true,
		"operator-failure.schema.json":              true, "operator-readiness.schema.json": true,
		"extractive-answer-plan.schema.json":                 true,
		"answer-document-version.schema.json":                true,
		"postgresql-query-value-v1.schema.json":              true,
		"knowledge-plan-v1.schema.json":                      true,
		"embedding-profile-v1.schema.json":                   true,
		"embedding-mount-manifest-v1.schema.json":            true,
		"source-connection-trust-verify-request.schema.json": true,
		"source-connection-trust-verify-result.schema.json":  true,
		"source-connection-trust-verify.schema.json":         true,
		"source-discovery-request.schema.json":               true,
		"source-discovery-result.schema.json":                true,
		"source-discovery-job-payload.schema.json":           true,
	}
	if len(paths) != len(expected) {
		problems = append(problems, fmt.Sprintf("expected exactly %d reviewed contract schemas, found %d", len(expected), len(paths)))
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		name := filepath.Base(path)
		seen[name] = true
		if !expected[name] {
			problems = append(problems, "unreviewed contract schema: "+name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if err := rejectDuplicateJSON(raw); err != nil {
			problems = append(problems, "invalid contract JSON "+relative(root, path)+": "+err.Error())
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			problems = append(problems, "invalid contract JSON "+relative(root, path)+": "+err.Error())
			continue
		}
		for _, key := range []string{"$schema", "$id", "title"} {
			if _, ok := schema[key]; !ok {
				problems = append(problems, "contract missing "+key+": "+relative(root, path))
			}
		}
		if _, typed := schema["type"]; !typed {
			if _, composed := schema["oneOf"]; !composed {
				problems = append(problems, "contract requires type or oneOf: "+relative(root, path))
			}
		}
		problems = append(problems, checkSchemaNumericBounds(schema, relative(root, path)+"#")...)
	}
	for name := range expected {
		if !seen[name] {
			problems = append(problems, "missing reviewed contract schema: "+name)
		}
	}
	return problems
}

func checkSchemaNumericBounds(value any, path string) []string {
	const safe = float64(9007199254740991)
	var problems []string
	switch typed := value.(type) {
	case map[string]any:
		numeric := false
		switch declared := typed["type"].(type) {
		case string:
			numeric = declared == "integer" || declared == "number"
		case []any:
			for _, item := range declared {
				if item == "integer" || item == "number" {
					numeric = true
				}
			}
		}
		if numeric {
			maximum, ok := typed["maximum"].(float64)
			if !ok || maximum > safe {
				problems = append(problems, "numeric schema has no I-JSON safe maximum: "+path)
			}
			if minimum, ok := typed["minimum"].(float64); ok && minimum < -safe {
				problems = append(problems, "numeric schema has unsafe minimum: "+path)
			}
			if minimum, ok := typed["exclusiveMinimum"].(float64); ok && minimum < -safe {
				problems = append(problems, "numeric schema has unsafe exclusiveMinimum: "+path)
			}
		}
		for key, child := range typed {
			problems = append(problems, checkSchemaNumericBounds(child, path+"/"+key)...)
		}
	case []any:
		for index, child := range typed {
			problems = append(problems, checkSchemaNumericBounds(child, fmt.Sprintf("%s/%d", path, index))...)
		}
	}
	return problems
}

func checkFixtureJSON(root string) []string {
	return scanPaths(filepath.Join(root, "tests", "contracts"), func(path string) []string {
		if filepath.Ext(path) != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return []string{err.Error()}
		}
		if err := rejectDuplicateJSON(raw); err != nil {
			return []string{"invalid fixture JSON " + relative(root, path) + ": " + err.Error()}
		}
		return nil
	})
}

func checkInvariantTestRegistry(root string) []string {
	guardrailRaw, err := os.ReadFile(filepath.Join(root, "architecture", "guardrails.yaml"))
	if err != nil {
		return []string{"missing architecture/guardrails.yaml"}
	}
	registryRaw, err := os.ReadFile(filepath.Join(root, "tests", "contracts", "invariant-test-registry.json"))
	if err != nil {
		return []string{"missing tests/contracts/invariant-test-registry.json"}
	}
	mutationRegistryRaw, err := os.ReadFile(filepath.Join(root, "tests", "contracts", "mutation-registry.json"))
	if err != nil {
		return []string{"missing tests/contracts/mutation-registry.json"}
	}
	fixtureRaw, err := os.ReadFile(filepath.Join(root, "tests", "contracts", "fixture-cases.json"))
	if err != nil {
		return []string{"missing tests/contracts/fixture-cases.json"}
	}
	recognizedRaw, err := os.ReadFile(filepath.Join(root, "architecture", "recognized-uncovered-critical.json"))
	if err != nil {
		return []string{"missing architecture/recognized-uncovered-critical.json for invariant phase validation"}
	}

	var registry invariantTestRegistry
	var mutationRegistry mutationTestRegistry
	var fixtures fixtureCaseIndex
	var recognizedFile recognizedUncoveredCriticalFile
	if err := json.Unmarshal(registryRaw, &registry); err != nil {
		return []string{"invalid invariant test registry: " + err.Error()}
	}
	if err := json.Unmarshal(mutationRegistryRaw, &mutationRegistry); err != nil {
		return []string{"invalid mutation registry: " + err.Error()}
	}
	if err := json.Unmarshal(fixtureRaw, &fixtures); err != nil {
		return []string{"invalid fixture case index: " + err.Error()}
	}
	if err := json.Unmarshal(recognizedRaw, &recognizedFile); err != nil {
		return []string{"invalid recognized-uncovered registry: " + err.Error()}
	}
	// Preserve the reviewed product proof floor independently of private work plans.
	const activeStage = 2

	fixtureIDs := make(map[string]bool)
	var problems []string
	for _, fixture := range fixtures.Cases {
		if fixture.ID == "" || fixtureIDs[fixture.ID] {
			problems = append(problems, "empty or duplicate fixture case id: "+fixture.ID)
		}
		fixtureIDs[fixture.ID] = true
	}
	registryByID := make(map[string]invariantRegistryRegistration)
	checkerSelfTests := map[string]bool{
		"architecture.runtime.listener-before-preflight":             true,
		"architecture.runtime.second-run":                            true,
		"architecture.runtime.partial-startup-leak":                  true,
		"architecture.runtime.cleanup-before-drain":                  true,
		"architecture.runtime.double-cleanup":                        true,
		"architecture.runtime.early-cleanup-return":                  true,
		"architecture.runtime.handler-close-capability":              true,
		"architecture.runtime.entrypoint-bypass":                     true,
		"architecture.outbox.runtime-write-grant":                    true,
		"architecture.outbox.trigger-depth-capability":               true,
		"architecture.connector.folder-database-capability":          true,
		"architecture.connector.folder-root-handle":                  true,
		"architecture.connector.folder-stable-read":                  true,
		"architecture.sandbox.dispatcher-capability-boundary":        true,
		"architecture.parser.html-active-content-drop":               true,
		"architecture.parser.html-resource-bound":                    true,
		"architecture.parser.html-capability-import":                 true,
		"architecture.parser.html-module-scope":                      true,
		"architecture.supply.unknown-component":                      true,
		"architecture.supply.missing-integrity":                      true,
		"architecture.supply.extra-license-component":                true,
		"architecture.supply.unknown-deferred-component":             true,
		"architecture.supply.unknown-deferred-gate":                  true,
		"architecture.supply.unknown-go-module":                      true,
		"architecture.supply.unknown-node-package":                   true,
		"architecture.supply.pnpm-integrity-mismatch":                true,
		"architecture.supply.unknown-oci-image":                      true,
		"architecture.supply.unknown-ci-action":                      true,
		"architecture.supply.go-replace-or-workspace":                true,
		"architecture.supply.short-integrity":                        true,
		"architecture.supply.non-exact-version":                      true,
		"architecture.supply.node-unbound-manifest":                  true,
		"architecture.supply.docker-remote-dependency":               true,
		"architecture.supply.local-action-dependency":                true,
		"architecture.supply.license-missing-source":                 true,
		"architecture.supply.duplicate-license-section":              true,
		"architecture.supply.parser-runtime-compliance":              true,
		"architecture.license.unknown-or-forbidden":                  true,
		"architecture.ci.required-command-comment-only":              true,
		"architecture.ci.required-command-echo-only":                 true,
		"architecture.ci.required-command-disabled-step":             true,
		"architecture.ci.required-command-unreachable":               true,
		"architecture.ci.required-command-heredoc":                   true,
		"architecture.ci.r3-exact-execution":                         true,
		"architecture.protection.governance-inventory":               true,
		"architecture.parser.observer-identity-outside-profile-hash": true,
		"architecture.parser.sandbox-core-hardening":                 true,
		"architecture.command.closed-inventory":                      true,
	}
	foundCheckerSelfTests := make(map[string]bool)
	postgresTestPaths, postgresTestsErr := filepath.Glob(filepath.Join(root, "tests", "integration", "postgres", "*_test.go"))
	var postgresTestsRaw []byte
	if postgresTestsErr == nil && len(postgresTestPaths) == 0 {
		postgresTestsErr = fmt.Errorf("no PostgreSQL integration tests found")
	}
	for _, testPath := range postgresTestPaths {
		if postgresTestsErr != nil {
			break
		}
		contents, readErr := os.ReadFile(testPath)
		if readErr != nil {
			postgresTestsErr = readErr
			break
		}
		postgresTestsRaw = append(postgresTestsRaw, contents...)
		postgresTestsRaw = append(postgresTestsRaw, '\n')
	}
	for _, rule := range registry.Rules {
		if rule.ID == "" || registryByID[rule.ID].Status != "" {
			problems = append(problems, "empty or duplicate invariant test registry id: "+rule.ID)
			continue
		}
		registryByID[rule.ID] = invariantRegistryRegistration{
			Status:         rule.Status,
			CaseIDs:        rule.CaseIDs,
			Harness:        rule.Harness,
			MutationCorpus: rule.MutationCorpus,
			TestNames:      rule.TestNames,
		}
		phaseNumber, phaseOK := invariantRoadmapStage(rule.Phase)
		if !phaseOK {
			problems = append(problems, "invariant test has unknown or missing phase: "+rule.ID+" -> "+rule.Phase)
			continue
		}
		if rule.Status == "PLANNED" {
			if rule.PhaseState != "NOT_STARTED" {
				problems = append(problems, "planned invariant lacks explicit not-started phase registration: "+rule.ID)
			}
			if phaseNumber <= activeStage {
				problems = append(problems, "planned invariant is overdue for the product proof floor: "+rule.ID+" -> "+rule.Phase)
			}
			if rule.Harness != "" || rule.MutationCorpus != "" || len(rule.CaseIDs) != 0 || len(rule.TestNames) != 0 {
				problems = append(problems, "planned invariant carries executable proof fields: "+rule.ID)
			}
			continue
		}
		if rule.Status != "EXECUTABLE" {
			problems = append(problems, "invariant test has unsupported status: "+rule.ID+" -> "+rule.Status)
			continue
		}
		if rule.PhaseState != "" {
			problems = append(problems, "executable invariant carries phase deferral state: "+rule.ID+" -> "+rule.PhaseState)
		}
		if rule.Status == "EXECUTABLE" && rule.Harness == "CHECK_ARCHITECTURE_SELF_TEST" {
			if !checkerSelfTests[rule.ID] || len(rule.CaseIDs) != 0 || len(rule.TestNames) != 0 {
				problems = append(problems, "invalid checker-native invariant test registration: "+rule.ID)
			} else {
				foundCheckerSelfTests[rule.ID] = true
			}
		} else if rule.Status == "EXECUTABLE" && rule.Harness == "POSTGRES_INTEGRATION" {
			if postgresTestsErr != nil || len(rule.CaseIDs) != 0 || len(rule.TestNames) == 0 {
				problems = append(problems, "invalid PostgreSQL integration invariant registration: "+rule.ID)
				continue
			}
			seenNames := make(map[string]bool)
			for _, testName := range rule.TestNames {
				if seenNames[testName] || !regexp.MustCompile(`^Test[A-Za-z0-9]+$`).MatchString(testName) ||
					!regexp.MustCompile(`(?m)^func\s+`+regexp.QuoteMeta(testName)+`\s*\(`).Match(postgresTestsRaw) {
					problems = append(problems, "PostgreSQL integration invariant references missing or duplicate test: "+rule.ID+" -> "+testName)
				}
				seenNames[testName] = true
			}
		} else if rule.Status == "EXECUTABLE" && rule.Harness == "GO_UNIT" {
			// A product unit mutation corpus is executed by the mutation runner
			// against the real repository; the rule names the tests, and the
			// corpus entry pins the test package and the mutation anchors.
			if rule.MutationCorpus != "tests/contracts/mutation-registry.json" || len(rule.CaseIDs) != 0 || len(rule.TestNames) == 0 {
				problems = append(problems, "invalid Go unit invariant registration: "+rule.ID)
				continue
			}
			seenNames := make(map[string]bool)
			for _, testName := range rule.TestNames {
				if seenNames[testName] || !regexp.MustCompile(`^Test[A-Za-z0-9]+$`).MatchString(testName) {
					problems = append(problems, "Go unit invariant references missing or duplicate test: "+rule.ID+" -> "+testName)
				}
				seenNames[testName] = true
			}
		} else if rule.Status == "EXECUTABLE" {
			if rule.Harness != "" && rule.Harness != "CONTRACT_FIXTURE" {
				problems = append(problems, "unknown executable invariant harness: "+rule.ID+" -> "+rule.Harness)
			}
			if len(rule.CaseIDs) == 0 {
				problems = append(problems, "executable invariant test has no fixture case: "+rule.ID)
			}
			for _, caseID := range rule.CaseIDs {
				if !fixtureIDs[caseID] {
					problems = append(problems, "invariant test references missing fixture case: "+rule.ID+" -> "+caseID)
				}
			}
		} else if rule.Harness == "CHECK_ARCHITECTURE_SELF_TEST" {
			problems = append(problems, "checker-native invariant must be executable: "+rule.ID)
		}
	}
	for id := range checkerSelfTests {
		if !foundCheckerSelfTests[id] {
			problems = append(problems, "missing executable checker-native mutation registration: "+id)
		}
	}
	fixtureByID := make(map[string]struct {
		Kind                string
		ExpectedSchemaValid *bool
	})
	for _, fixture := range fixtures.Cases {
		fixtureByID[fixture.ID] = struct {
			Kind                string
			ExpectedSchemaValid *bool
		}{Kind: fixture.Kind, ExpectedSchemaValid: fixture.ExpectedSchemaValid}
	}
	problems = append(problems, checkMutationRegistry(root, mutationRegistry, registryByID, postgresTestsRaw, fixtureByID)...)

	inCritical := false
	currentInvariant := ""
	foundNegative := make(map[string]bool)
	criticalNegativeTests := make(map[string][]string)
	seenCritical := make(map[string]bool)
	for _, line := range strings.Split(string(guardrailRaw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "critical_invariants:" {
			inCritical = true
			continue
		}
		if trimmed == "release_requirements:" {
			inCritical = false
			currentInvariant = ""
		}
		if !inCritical {
			continue
		}
		if strings.HasPrefix(trimmed, "- id: ") {
			currentInvariant = strings.TrimSpace(strings.TrimPrefix(trimmed, "- id: "))
			if seenCritical[currentInvariant] {
				problems = append(problems, "duplicate critical invariant id: "+currentInvariant)
			}
			seenCritical[currentInvariant] = true
			continue
		}
		if currentInvariant != "" && strings.HasPrefix(trimmed, "negative_tests: [") && strings.HasSuffix(trimmed, "]") {
			inside := strings.TrimSuffix(strings.TrimPrefix(trimmed, "negative_tests: ["), "]")
			for _, rawID := range strings.Split(inside, ",") {
				id := strings.TrimSpace(rawID)
				if _, ok := registryByID[id]; !ok {
					problems = append(problems, "critical invariant references unknown negative test: "+currentInvariant+" -> "+id)
				}
				criticalNegativeTests[currentInvariant] = append(criticalNegativeTests[currentInvariant], id)
			}
			foundNegative[currentInvariant] = true
		}
	}
	for _, line := range strings.Split(string(guardrailRaw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- id: ") {
			id := strings.TrimSpace(strings.TrimPrefix(trimmed, "- id: "))
			if regexp.MustCompile(`^[A-Z]+-[0-9]+$`).MatchString(id) && !foundNegative[id] {
				problems = append(problems, "critical invariant has no negative test mapping: "+id)
			}
		}
	}
	recognizedByID, recognizedProblems := validateRecognizedUncoveredCritical(recognizedFile, criticalNegativeTests, registryByID, mutationRegistry, root)
	problems = append(problems, recognizedProblems...)
	problems = append(problems, checkCriticalMutationCoverage(criticalNegativeTests, registryByID, mutationRegistry, recognizedByID, activeStage)...)
	return problems
}

// checkCriticalMutationCoverage makes the critical denominator explicit. The
// guardrail document owns the mapping from a critical invariant to its
// executable negative proofs; the mutation registry owns the claim that the
// product semantics behind that invariant has been tested by mutation. A
// checker-native test is not a mutation corpus, and a fixture-only proof is
// not silently promoted to product mutation evidence.
// coveredCriticalByMutationCorpus returns the critical invariants that own a
// real mutation corpus: an entry binding the critical id whose test owns the
// critical and that carries at least one mutation case. A binding without
// mutations is not coverage.
func coveredCriticalByMutationCorpus(mutationRegistry mutationTestRegistry, criticalNegativeTests map[string][]string) map[string]bool {
	criticalOwners := make(map[string]map[string]bool)
	for criticalID, testIDs := range criticalNegativeTests {
		for _, testID := range testIDs {
			if criticalOwners[testID] == nil {
				criticalOwners[testID] = make(map[string]bool)
			}
			criticalOwners[testID][criticalID] = true
		}
	}

	knownCritical := make(map[string]bool)
	for criticalID := range criticalNegativeTests {
		knownCritical[criticalID] = true
	}
	coveredCritical := make(map[string]bool)
	for _, entry := range mutationRegistry.Entries {
		if len(entry.CriticalInvariantIDs) == 0 || len(entry.Mutations) == 0 {
			continue
		}
		for _, criticalID := range entry.CriticalInvariantIDs {
			if knownCritical[criticalID] && criticalOwners[entry.InvariantID][criticalID] {
				coveredCritical[criticalID] = true
			}
		}
	}
	return coveredCritical
}

// suppressedByRecognition applies the ADR-0071 dispositions. A STAGE_GATED
// critical is suppressed only while its product stage has not arrived
// (rank(product_stage) > rank(activeStage)); the reviewed proof floor decides when the
// debt returns. A DUAL_LAYER critical is suppressed while its probe is
// committed and pinned — the probe's liveness is executed by the mutation
// runner in mandatory CI, and an unpinned or missing probe re-opens debt
// through the recognition validation, never silently.
func suppressedByRecognition(criticalID string, recognized map[string]recognizedCritical, activeStage int) bool {
	entry, ok := recognized[criticalID]
	if !ok {
		return false
	}
	switch entry.Disposition {
	case "STAGE_GATED":
		stage, stageOK := invariantRoadmapStage(entry.ProductStage)
		return stageOK && stage > activeStage
	case "DUAL_LAYER":
		return true
	}
	return false
}

// validateRecognizedUncoveredCritical enforces the ADR-0071 honesty
// constraints on the recognized-uncovered registry. Only structurally valid
// entries may suppress corpus debt: a broken entry keeps its debt visible and
// adds its own error, so recognition can never hide a failing invariant.
// STAGE_GATED demands a canonical product stage and the absence of seated
// product-harness enforcement; DUAL_LAYER demands a committed, pinned probe;
// recognition alongside a covering corpus entry is a redundancy error.
func validateRecognizedUncoveredCritical(file recognizedUncoveredCriticalFile, criticalNegativeTests map[string][]string, registrations map[string]invariantRegistryRegistration, mutationRegistry mutationTestRegistry, root string) (map[string]recognizedCritical, []string) {
	var problems []string
	valid := make(map[string]recognizedCritical)
	if file.Version != 1 {
		problems = append(problems, "recognized-uncovered registry has unsupported version: "+strconv.Itoa(file.Version))
	}
	coveredCritical := coveredCriticalByMutationCorpus(mutationRegistry, criticalNegativeTests)
	seen := make(map[string]bool)
	for _, entry := range file.Entries {
		if entry.CriticalID == "" || seen[entry.CriticalID] {
			problems = append(problems, "recognized entry has empty or duplicate critical id: "+entry.CriticalID)
			continue
		}
		seen[entry.CriticalID] = true
		testIDs, known := criticalNegativeTests[entry.CriticalID]
		if !known {
			problems = append(problems, "recognized critical is unknown to guardrails: "+entry.CriticalID)
			continue
		}
		hasExecutable := false
		for _, testID := range testIDs {
			if registrations[testID].Status == "EXECUTABLE" {
				hasExecutable = true
			}
		}
		if !hasExecutable {
			problems = append(problems, "recognized critical owns no executable negative test: "+entry.CriticalID)
			continue
		}
		if entry.Evidence == "" {
			problems = append(problems, "recognized critical lacks an evidence anchor: "+entry.CriticalID)
			continue
		}
		switch entry.Disposition {
		case "STAGE_GATED":
			_, stageOK := invariantRoadmapStage(entry.ProductStage)
			if !stageOK {
				problems = append(problems, "stage-gated recognized entry has invalid product stage: "+entry.CriticalID+" -> "+entry.ProductStage)
				continue
			}
			seated := false
			for _, testID := range testIDs {
				registration := registrations[testID]
				if registration.Harness == "GO_UNIT" || registration.Harness == "POSTGRES_INTEGRATION" {
					problems = append(problems, "stage-gated recognized critical has seated product enforcement: "+entry.CriticalID+" -> "+testID)
					seated = true
					break
				}
			}
			if seated {
				continue
			}
			valid[entry.CriticalID] = entry
		case "DUAL_LAYER":
			if entry.Probe == "" {
				problems = append(problems, "dual-layer recognized entry has no probe: "+entry.CriticalID)
				continue
			}
			if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry.Probe))); err != nil || info.IsDir() {
				problems = append(problems, "dual-layer probe is missing: "+entry.CriticalID+" -> "+entry.Probe)
				continue
			}
			if !probePinnedInManifest(root, entry.Probe) {
				problems = append(problems, "dual-layer probe is not pinned: "+entry.CriticalID+" -> "+entry.Probe)
				continue
			}
			valid[entry.CriticalID] = entry
		default:
			problems = append(problems, "recognized entry has unsupported disposition: "+entry.CriticalID+" -> "+entry.Disposition)
		}
	}
	var redundant []string
	for criticalID := range valid {
		if coveredCritical[criticalID] {
			problems = append(problems, "recognized critical is also covered by the mutation corpus: "+criticalID)
			redundant = append(redundant, criticalID)
		}
	}
	for _, criticalID := range redundant {
		delete(valid, criticalID)
	}
	sort.Strings(problems)
	return valid, problems
}

// probePinnedInManifest verifies that a dual-layer probe is registered in the
// protected-hashes manifest. A missing or unpinned probe re-opens debt
// (ADR-0071 §1.2), and the manifest itself is enforced by checkProtectedFiles.
func probePinnedInManifest(root, relative string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "protected-hashes.json"))
	if err != nil {
		return false
	}
	var manifest protectedManifest
	if rejectDuplicateJSON(raw) != nil || json.Unmarshal(raw, &manifest) != nil {
		return false
	}
	_, pinned := manifest.Files[relative]
	return pinned
}

func checkCriticalMutationCoverage(criticalNegativeTests map[string][]string, registrations map[string]invariantRegistryRegistration, mutationRegistry mutationTestRegistry, recognized map[string]recognizedCritical, activeStage int) []string {
	coveredCritical := coveredCriticalByMutationCorpus(mutationRegistry, criticalNegativeTests)

	criticalOwners := make(map[string]map[string]bool)
	for criticalID, testIDs := range criticalNegativeTests {
		for _, testID := range testIDs {
			if criticalOwners[testID] == nil {
				criticalOwners[testID] = make(map[string]bool)
			}
			criticalOwners[testID][criticalID] = true
		}
	}
	knownCritical := make(map[string]bool)
	for criticalID := range criticalNegativeTests {
		knownCritical[criticalID] = true
	}

	var problems []string
	for _, entry := range mutationRegistry.Entries {
		if _, ok := redOnlyGuardMutationInvariants[entry.InvariantID]; ok {
			continue
		}
		if len(entry.CriticalInvariantIDs) == 0 {
			problems = append(problems, "mutation registry entry has no critical invariant binding: "+entry.InvariantID)
			continue
		}
		seenCritical := make(map[string]bool)
		for _, criticalID := range entry.CriticalInvariantIDs {
			if seenCritical[criticalID] {
				problems = append(problems, "duplicate critical invariant binding: "+entry.InvariantID+" -> "+criticalID)
			}
			seenCritical[criticalID] = true
			if !knownCritical[criticalID] {
				problems = append(problems, "mutation registry references unknown critical invariant: "+entry.InvariantID+" -> "+criticalID)
				continue
			}
			if !criticalOwners[entry.InvariantID][criticalID] {
				problems = append(problems, "mutation registry critical binding does not own its test: "+entry.InvariantID+" -> "+criticalID)
			}
		}
	}
	for criticalID, testIDs := range criticalNegativeTests {
		hasExecutableSemantics := false
		for _, testID := range testIDs {
			registration, ok := registrations[testID]
			if !ok || registration.Status != "EXECUTABLE" {
				continue
			}
			hasExecutableSemantics = true
		}
		if hasExecutableSemantics && !coveredCritical[criticalID] && !suppressedByRecognition(criticalID, recognized, activeStage) {
			problems = append(problems, "critical invariant has no product mutation corpus: "+criticalID)
		}
	}
	sort.Strings(problems)
	return problems
}

// redOnlyGuardMutationInvariants is the closed inventory of guard invariants
// whose only failure mode is the guard being dropped or inverted, so their
// corpus is necessarily RED-only and is bound to the protected-independent Go
// unit probe in the mapped package that asserts it. The R1 entries are the
// honest-grounding and audit-before-data guards; the R2 entries are the six
// Outcome-3 QueryIntent/AnswerResult negative controls; the R3a-1 entry is the
// address span-hash tamper refusal in ./internal/address. These entries are
// validated by checkRedOnlyGuardMutationEntry instead of the generic RED/GREEN
// rule because a semantic-preserving direction does not exist for a guard: the
// closed id set never relaxes the requirement for any other mutation entry.
var redOnlyGuardMutationInvariants = map[string]string{
	"acceptance.grounding.span-hash-checked":        "./internal/question",
	"acceptance.grounding.similarity-not-proof":     "./internal/question",
	"acceptance.audit.admission-before-data":        "./internal/question",
	"acceptance.audit.revoke-recheck":               "./internal/question",
	"acceptance.audit.rowset-admission-before-data": "./internal/question",
	"acceptance.audit.rowset-read-failure-outcome":  "./internal/question",
	// R2 Outcome 3 negative controls.
	"acceptance.queryintent.retired-version-refused":   "./internal/question",
	"acceptance.queryintent.disallowed-filter-refused": "./internal/question",
	"acceptance.queryintent.unknown-metric-refused":    "./internal/question",
	"acceptance.queryintent.malformed-period-refused":  "./internal/question",
	"acceptance.answer.result-digest-deterministic":    "./internal/question",
	"acceptance.answer.partial-completeness-preserved": "./internal/question",
	// R3a-1 Outcome 1: the address span-hash tamper refusal is a pure guard,
	// so its corpus is RED-only and bound to ./internal/address.
	"acceptance.r3a1.address.span-hash-verification": "./internal/address",
	// R3a-1 Outcome 1 whole-object read guards: next-cursor and whole-original
	// hash integrity are pure guards, RED-only, in ./internal/address.
	"acceptance.r3a1.address.whole-object-no-silent-truncation": "./internal/address",
	"acceptance.r3a1.address.whole-object-hash-integrity":       "./internal/address",
	// R3a-1 Outcome 4 code sources: a ref-scoped grep must resolve the ref from
	// object-inventory metadata so a hit at ref A is never reported for ref B
	// once the file differs there. The scoping check is a pure guard, so its
	// corpus is RED-only and bound to the workspaceapi probe.
	"acceptance.r3a1.grep.ref-scoped-no-cross-ref-leak": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 authorization negative control: a principal without the
	// workspace right must get the existing content-free denial and every MCP/REST
	// tool call must journal admission before data and its outcome (denials with a
	// class). The denial mapping is a pure guard, so its corpus is RED-only.
	"acceptance.r3a1.authorization.denial-content-free-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 list negative control: the code-source inventory rows must carry the mirror age, so dropping that guard is a pure RED weakening bound to the workspaceapi list probe.
	"acceptance.r3a1.inventory.code-source-mirror-age": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 3 external-agent authorization negative control: an expired
	// or foreign-tenant token must never reach tools/list. httpauth's session /
	// tenant cross-check is a pure guard, so its corpus is RED-only and bound to
	// the workspaceapi probe.
	"acceptance.r3a1.authorization.expired-and-foreign-token-refused": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 list negative control: the typed, content-free skip ledger
	// of knowvault_list_objects must keep each skipped object's external_id,
	// closed reason_code and moment and must report skipped_count as the row
	// count. Dropping the typed reason is a pure RED weakening, so its corpus is
	// RED-only and bound to the workspaceapi list probe.
	"acceptance.r3a1.inventory.typed-skip-ledger": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 1 negative control: read(address) must refuse an address
	// from another workspace with the existing content-free denial. The
	// foreign-workspace denial mapping is a pure guard, so its corpus is
	// RED-only and bound to the workspaceapi address-read probe.
	"acceptance.r3a1.authorization.read-address-foreign-workspace-denial-content-free": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 refresh negative control: knowvault_refresh and its REST tools/refresh parity route must answer a principal without the workspace right with the existing content-free denial and journal the denial class, so weakening the MCP refresh denial mapping is a pure RED guard bound to the workspaceapi refresh probe.
	"acceptance.r3a1.authorization.refresh-denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 sources negative control: knowvault_sources and its REST
	// tools/sources parity route must answer a principal without the workspace
	// right with the existing content-free denial and record admission before
	// data plus the closed denial class, so weakening the sources denial
	// mapping is a pure RED guard bound to the workspaceapi sources probe.
	"acceptance.r3a1.sources.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 search negative control: knowvault_search must answer a
	// principal without the workspace right with the existing content-free
	// denial and record admission before data plus the closed denial class, so
	// weakening the search denial mapping is a pure RED guard bound to the
	// workspaceapi search probe.
	"acceptance.r3a1.search.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 1 whole-object read against the real evidence store: the
	// production viewer must serve every fragment of the active extraction
	// reassembled as the whole object, so weakening internal/source/evidence/
	// viewer.go is a pure RED guard bound to the real-viewer assembly probe in
	// the PostgreSQL integration package that kills it.
	"acceptance.r3a1.read.whole-object-real-viewer-assembly": "./tests/integration/postgres",
	// R3a-1 Outcome 2 relation tool: knowvault_related must serve both
	// directions of a cross-source relation (what the addressed object
	// references and the documents that reference it), each hit carrying its
	// address and version. The closed direction vocabulary is a pure guard, so
	// its corpus is RED-only and bound to the workspaceapi relation probe.
	"acceptance.r3a1.related.cross-source-both-directions": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 related negative control: knowvault_related must answer a
	// principal without the workspace right with the existing content-free
	// denial and record admission before data plus the closed denial outcome, so
	// weakening the related denial mapping is a pure RED guard bound to the
	// workspaceapi related probe.
	"acceptance.r3a1.related.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 grep negative control: knowvault_grep must answer a
	// principal without the workspace right with the existing content-free
	// denial and record admission before data plus the closed denial class, so
	// weakening the grep denial mapping is a pure RED guard bound to the
	// workspaceapi grep probe.
	"acceptance.r3a1.grep.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 list negative control: knowvault_list_objects must answer
	// a principal without the workspace right with the existing content-free
	// denial (workspace objects not found) and record admission before data plus
	// the closed denial class, so weakening the list denial mapping is a pure RED
	// guard bound to the workspaceapi list probe.
	"acceptance.r3a1.list-objects.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 Outcome 2 read negative control: knowvault_read and its REST
	// tools/read parity route must answer a principal without the workspace
	// right with the existing content-free denial and record admission before
	// data plus the closed denial class, so weakening the read denial mapping
	// in the paged read core is a pure RED guard bound to the workspaceapi read
	// probe.
	"acceptance.r3a1.read.denial-admitted-and-audited": "./internal/platform/workspaceapi",
	// R3a-1 carried-over acc2 guard: a member's read of a workspace whose
	// persisted revision configuration hash is stale must stay readable with the
	// closed degraded marker WORKSPACE_CONFIGURATION_HASH_STALE, and a member
	// mutation must repair the hash through the audited policy.decision path
	// instead of failing WORKSPACE_PERSISTENCE_FAILED. The shared
	// stored-versus-live hash predicate is a pure guard, so its corpus is
	// RED-only and bound to ./internal/workspace/repository.
	"acceptance.r3a1.workspace.degraded-configuration-hash-read-and-repair": "./internal/workspace/repository",
	// R3a-1 Outcome 2 canonical tool-name contract: the workspace knowledge
	// dispatch table must never resolve a wiki-rag name, so a wiki-rag token
	// registered as a REST subpath would make the removed name dispatchable
	// through /workspaces/{id}/tools/... . The unregistered-segment refusal is a
	// pure guard, so its corpus is RED-only and bound to the workspaceapi probe.
	"acceptance.r3a1.tools.canonical-names-no-wiki-rag-alias": "./internal/platform/workspaceapi",
	// R3a-1 carried-over acc2 guard: every knowledge tool's MCP content[].text
	// channel must carry the same addresses the structured channel carries, so
	// dropping that text projection is a pure RED weakening bound to the
	// workspaceapi text-channel probe.
	"acceptance.r3a1.mcp.text-channel-carries-addresses": "./internal/platform/workspaceapi",
}

// checkRedOnlyGuardMutationEntry validates the structure of one RED-only guard
// entry: the Go unit harness, the registered probe package, an existing probe
// test, at least one case, and every case a RED weakening whose anchor is
// unique in an internal/ product target. The runtime RED outcome is proved by
// the mutation runner, never here.
func checkRedOnlyGuardMutationEntry(root string, entry mutationTestRegistryEntry) []string {
	var problems []string
	if entry.Harness != "GO_UNIT" {
		problems = append(problems, "RED-only guard mutation must use the Go unit harness: "+entry.InvariantID)
	}
	if entry.TestPackage != redOnlyGuardMutationInvariants[entry.InvariantID] {
		problems = append(problems, "RED-only guard mutation test package is not the registered probe package: "+entry.InvariantID)
	}
	if entry.TestName == "" || !goUnitTestExists(root, entry.TestPackage, entry.TestName) {
		problems = append(problems, "RED-only guard mutation references a missing probe: "+entry.InvariantID+" -> "+entry.TestName)
	}
	if len(entry.Mutations) == 0 {
		problems = append(problems, "RED-only guard mutation entry has no case: "+entry.InvariantID)
	}
	seenMutationIDs := make(map[string]bool)
	for _, mutation := range entry.Mutations {
		if mutation.ID == "" || seenMutationIDs[mutation.ID] {
			problems = append(problems, "empty or duplicate R1 guard mutation id: "+entry.InvariantID+" -> "+mutation.ID)
		}
		seenMutationIDs[mutation.ID] = true
		if mutation.Expected != "RED" {
			problems = append(problems, "RED-only guard mutation must be RED: "+entry.InvariantID+" -> "+mutation.ID)
		}
		if !strings.Contains(mutation.Kind, "WEAKENING") {
			problems = append(problems, "RED-only guard mutation is not declared as a weakening: "+entry.InvariantID+" -> "+mutation.ID)
		}
		if mutation.Old == "" || mutation.Old == mutation.New {
			problems = append(problems, "RED-only guard mutation is incomplete: "+entry.InvariantID+" -> "+mutation.ID)
		}
		target := filepath.ToSlash(filepath.Clean(mutation.Target))
		if mutation.Target == "" || target != mutation.Target || filepath.IsAbs(mutation.Target) ||
			strings.HasPrefix(target, "../") || !strings.HasPrefix(target, "internal/") {
			problems = append(problems, "RED-only guard mutation target is not an internal product path: "+entry.InvariantID+" -> "+mutation.ID)
			continue
		}
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(target)))
		if err != nil {
			problems = append(problems, "RED-only guard mutation target is unreadable: "+entry.InvariantID+" -> "+mutation.Target+": "+err.Error())
			continue
		}
		if bytes.Count(source, []byte(mutation.Old)) != 1 {
			problems = append(problems, "RED-only guard mutation anchor is not unique in its target: "+entry.InvariantID+" -> "+mutation.ID)
		}
	}
	return problems
}

// checkMutationRegistry validates the declarative half of the R1 corpus. It
// deliberately checks only registration and mutation setup here; the actual
// RED/GREEN outcomes are proved by the mutation runner in mandatory CI. This
// keeps a source-text anchor from becoming a self-confirming proof.
func checkMutationRegistry(root string, mutationRegistry mutationTestRegistry, registrations map[string]invariantRegistryRegistration, postgresTestsRaw []byte, fixtureByID map[string]struct {
	Kind                string
	ExpectedSchemaValid *bool
}) []string {
	var problems []string
	if mutationRegistry.RegistryVersion != "1.0" {
		problems = append(problems, "mutation registry has unsupported version: "+mutationRegistry.RegistryVersion)
	}

	entriesByInvariant := make(map[string]mutationTestRegistryEntry)
	for _, entry := range mutationRegistry.Entries {
		if entry.InvariantID == "" || entriesByInvariant[entry.InvariantID].InvariantID != "" {
			problems = append(problems, "empty or duplicate mutation registry invariant id: "+entry.InvariantID)
			continue
		}
		entriesByInvariant[entry.InvariantID] = entry
		if _, ok := redOnlyGuardMutationInvariants[entry.InvariantID]; ok {
			problems = append(problems, checkRedOnlyGuardMutationEntry(root, entry)...)
			continue
		}
		registration, registered := registrations[entry.InvariantID]
		if !registered || registration.Status != "EXECUTABLE" {
			problems = append(problems, "mutation registry references non-executable invariant: "+entry.InvariantID)
			continue
		}
		switch entry.Harness {
		case "POSTGRES_INTEGRATION":
			// A contract invariant may also have an independent PostgreSQL
			// product corpus. Keep the contract registration as its primary
			// executable proof; the mutation registry must still name a real
			// integration test discovered from the copied source tree below.
			if registration.Harness != "POSTGRES_INTEGRATION" &&
				registration.Harness != "" && registration.Harness != "CONTRACT_FIXTURE" {
				problems = append(problems, "mutation registry uses PostgreSQL harness for non-PostgreSQL invariant: "+entry.InvariantID)
			}
		case "SCHEMA_SUITE":
			if registration.Harness != "" && registration.Harness != "CONTRACT_FIXTURE" {
				problems = append(problems, "mutation registry uses schema harness for non-contract invariant: "+entry.InvariantID)
			}
		case "GO_UNIT":
			// A checker-native negative test may have an independent product
			// mutation corpus, but the checker itself is never that corpus.
			if registration.Harness != "" && registration.Harness != "CHECK_ARCHITECTURE_SELF_TEST" && registration.Harness != "GO_UNIT" {
				problems = append(problems, "mutation registry uses Go unit harness for an invariant without a product unit registration: "+entry.InvariantID)
			}
		default:
			problems = append(problems, "mutation registry uses unsupported harness: "+entry.InvariantID)
		}
		if registration.MutationCorpus != "tests/contracts/mutation-registry.json" {
			problems = append(problems, "mutation registry is not linked from invariant registration: "+entry.InvariantID)
		}
		postgresMutationTestMissing := false
		if entry.Harness == "POSTGRES_INTEGRATION" {
			if registration.Harness == "POSTGRES_INTEGRATION" && !containsString(registration.TestNames, entry.TestName) {
				postgresMutationTestMissing = true
			}
			if !regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(entry.TestName) + `\s*\(`).Match(postgresTestsRaw) {
				postgresMutationTestMissing = true
			}
		}
		if entry.TestName == "" ||
			(entry.Harness == "POSTGRES_INTEGRATION" && postgresMutationTestMissing) ||
			(entry.Harness == "SCHEMA_SUITE" && entry.TestName != "SchemaContractSuite") ||
			(entry.Harness == "GO_UNIT" && !goUnitTestExists(root, entry.TestPackage, entry.TestName)) {
			problems = append(problems, "mutation registry references missing or unregistered mutation test: "+entry.InvariantID+" -> "+entry.TestName)
		}
		if entry.Harness == "GO_UNIT" && entry.TestPackage == "" {
			problems = append(problems, "Go unit mutation has no test package: "+entry.InvariantID)
		}
		if len(entry.Mutations) < 2 {
			problems = append(problems, "mutation registry entry needs RED and GREEN cases: "+entry.InvariantID)
		}
		seenMutationIDs := make(map[string]bool)
		foundRed, foundGreen := false, false
		for _, mutation := range entry.Mutations {
			if mutation.ID == "" || seenMutationIDs[mutation.ID] {
				problems = append(problems, "empty or duplicate mutation id: "+entry.InvariantID+" -> "+mutation.ID)
			}
			seenMutationIDs[mutation.ID] = true
			if mutation.Expected != "RED" && mutation.Expected != "GREEN" {
				problems = append(problems, "mutation has unsupported expected outcome: "+entry.InvariantID+" -> "+mutation.ID)
			} else if mutation.Expected == "RED" {
				foundRed = true
			} else {
				foundGreen = true
			}
			if mutation.Kind == "" || mutation.Old == "" || mutation.Old == mutation.New {
				problems = append(problems, "mutation is incomplete or does not change semantics: "+entry.InvariantID+" -> "+mutation.ID)
			}
			if mutation.Expected == "RED" && !strings.Contains(mutation.Kind, "WEAKENING") {
				problems = append(problems, "RED mutation is not declared as a weakening: "+entry.InvariantID+" -> "+mutation.ID)
			}
			if mutation.Expected == "GREEN" && !strings.Contains(mutation.Kind, "PRESERVING") {
				problems = append(problems, "GREEN mutation is not declared semantic-preserving: "+entry.InvariantID+" -> "+mutation.ID)
			}
			if mutation.Expected == "GREEN" && mutationExecutableText(mutation.Old) == mutationExecutableText(mutation.New) {
				problems = append(problems, "GREEN mutation changes only comments or formatting: "+entry.InvariantID+" -> "+mutation.ID)
			}
			if entry.Harness == "SCHEMA_SUITE" {
				fixture, ok := fixtureByID[mutation.SchemaCaseID]
				if mutation.SchemaCaseID == "" || !ok {
					problems = append(problems, "schema mutation has no registered schema fixture case: "+entry.InvariantID+" -> "+mutation.ID)
				} else if fixture.Kind != "SCHEMA_INSTANCE" || fixture.ExpectedSchemaValid == nil {
					problems = append(problems, "schema mutation fixture is not an executable schema case: "+entry.InvariantID+" -> "+mutation.ID+" -> "+mutation.SchemaCaseID)
				}
			}

			target := filepath.ToSlash(filepath.Clean(mutation.Target))
			allowedSchemaTarget := entry.Harness == "SCHEMA_SUITE" && strings.HasPrefix(target, "architecture/contracts/")
			// The checker-native license and protection guards are load-bearing on
			// their own contract documents, and their GO_UNIT corpus mutations
			// weaken those exact documents while the checker self-tests execute
			// against the mutated tree. The exemption is limited to these exact
			// paths and never opens docs/ or architecture/ wholesale.
			allowedGovernanceTarget := entry.Harness == "GO_UNIT" &&
				(target == "architecture/licenses.yaml" || target == "architecture/guardrails.yaml")
			if mutation.Target == "" || target != mutation.Target || strings.HasPrefix(target, "../") || target == ".." || filepath.IsAbs(mutation.Target) ||
				strings.HasPrefix(target, "tests/") || (strings.HasPrefix(target, "docs/") && !allowedGovernanceTarget) ||
				(strings.HasPrefix(target, "architecture/") && !allowedSchemaTarget && !allowedGovernanceTarget) {
				problems = append(problems, "mutation target is not a relative product path: "+entry.InvariantID+" -> "+mutation.ID)
				continue
			}
			targetPath := filepath.Join(root, filepath.FromSlash(target))
			source, err := os.ReadFile(targetPath)
			if err != nil {
				problems = append(problems, "mutation target is unreadable: "+entry.InvariantID+" -> "+mutation.Target+": "+err.Error())
				continue
			}
			if bytes.Count(source, []byte(mutation.Old)) != 1 {
				problems = append(problems, "mutation anchor is not unique in its target: "+entry.InvariantID+" -> "+mutation.ID)
			}
		}
		if !foundRed || !foundGreen {
			problems = append(problems, "mutation registry entry lacks one RED and one GREEN direction: "+entry.InvariantID)
		}
	}

	for invariantID, registration := range registrations {
		if registration.MutationCorpus == "" {
			continue
		}
		if registration.MutationCorpus == "CHECK_ARCHITECTURE_SELF_TEST" {
			continue
		}
		if registration.MutationCorpus != "tests/contracts/mutation-registry.json" {
			problems = append(problems, "invariant references unknown mutation corpus: "+invariantID+" -> "+registration.MutationCorpus)
			continue
		}
		if _, registered := entriesByInvariant[invariantID]; !registered {
			problems = append(problems, "executable invariant has no mutation registry entry: "+invariantID)
		}
	}
	return problems
}

// mutationExecutableText removes comments and normalizes whitespace so a
// preserving mutation cannot satisfy the second direction with documentation
// or formatting churn. It intentionally does not attempt to prove equivalence:
// that is the mutation runner's job. It only rejects the empty/decorative class
// before a case reaches the runtime corpus.
func mutationExecutableText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	var out strings.Builder
	state := byte(0) // 0 normal, '/', '-', '*', '\'', '"', or '`' for a literal/comment state
	for i := 0; i < len(value); i++ {
		current := value[i]
		next := byte(0)
		if i+1 < len(value) {
			next = value[i+1]
		}
		switch state {
		case '/':
			if current == '\n' {
				state = 0
				out.WriteByte(current)
			}
		case '-':
			if current == '\n' {
				state = 0
				out.WriteByte(current)
			}
		case '*':
			if current == '*' && next == '/' {
				i++
				state = 0
			}
		case '\'', '"', '`':
			out.WriteByte(current)
			if current == '\\' && state != '`' && i+1 < len(value) {
				i++
				out.WriteByte(value[i])
				continue
			}
			if current == state {
				// SQL escapes a single quote by doubling it. Keep both bytes
				// inside the literal instead of ending it at the first one.
				if state == '\'' && next == state {
					i++
					out.WriteByte(value[i])
					continue
				}
				state = 0
			}
		default:
			switch {
			case current == '/' && next == '/':
				i++
				state = '/'
			case current == '-' && next == '-':
				i++
				state = '-'
			case current == '/' && next == '*':
				i++
				state = '*'
			case current == '\'' || current == '"' || current == '`':
				state = current
				out.WriteByte(current)
			default:
				out.WriteByte(current)
			}
		}
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func goUnitTestExists(root, packagePath, testName string) bool {
	if root == "" || packagePath == "" || testName == "" || filepath.IsAbs(packagePath) {
		return false
	}
	relative := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(packagePath, "./")))
	if relative == "." || relative == "" || strings.HasPrefix(relative, "../") {
		return false
	}
	paths, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(relative), "*_test.go"))
	if err != nil || len(paths) == 0 {
		return false
	}
	pattern := regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(testName) + `\s*\(`)
	for _, path := range paths {
		raw, readErr := os.ReadFile(path)
		if readErr == nil && pattern.Match(raw) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func invariantRoadmapStage(phase string) (int, bool) {
	if phase == "STAGE_0A" {
		return 0, true
	}
	match := regexp.MustCompile(`^STAGE_([0-6])$`).FindStringSubmatch(phase)
	if len(match) != 2 {
		return 0, false
	}
	stage, err := strconv.Atoi(match[1])
	return stage, err == nil
}

func sortedKeys(documents map[string]string) []string {
	keys := make([]string, 0, len(documents))
	for key := range documents {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func checkVersionLock(root string) []string {
	path := filepath.Join(root, "architecture", "versions.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{"missing architecture/versions.json"}
	}
	var lock any
	if err := rejectDuplicateJSON(raw); err != nil {
		return []string{"invalid architecture/versions.json: " + err.Error()}
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return []string{"invalid architecture/versions.json: " + err.Error()}
	}
	problems := validateVersionInventory(lock)
	expectedStrings := map[string]string{
		"status":                                          "accepted-baseline",
		"toolchains.go.version":                           "1.26.5",
		"toolchains.go.go_directive":                      "1.26.0",
		"toolchains.go.toolchain_directive":               "go1.26.5",
		"toolchains.go.ci_environment.GOTOOLCHAIN":        "local",
		"toolchains.go.ci_environment.GOEXPERIMENT":       "jsonv2",
		"toolchains.node.version":                         "24.18.0",
		"toolchains.node.scope":                           "build-only",
		"toolchains.pnpm.version":                         "11.4.0",
		"toolchains.corepack_bundled.version":             "0.35.0",
		"toolchains.npm_bundled.version":                  "11.16.0",
		"toolchains.yarn_bundled.version":                 "1.22.22",
		"frontend.react.version":                          "19.2.6",
		"frontend.react_dom.version":                      "19.2.6",
		"frontend.react_types.version":                    "19.2.7",
		"frontend.react_dom_types.version":                "19.2.3",
		"frontend.typescript.version":                     "6.0.3",
		"frontend.esbuild.version":                        "0.28.1",
		"frontend.ajv.version":                            "8.20.0",
		"frontend.ajv_formats.version":                    "3.0.1",
		"go_dependencies.pgx.version":                     "v5.10.0",
		"go_dependencies.google_compute_metadata.version": "v0.3.0",
		"go_dependencies.oidc.version":                    "v3.20.0",
		"go_dependencies.go_jose.version":                 "v4.1.4",
		"go_dependencies.pgpassfile.version":              "v1.0.0",
		"go_dependencies.pgservicefile.version":           "v0.0.0-20240606120523-5a60cdf6a761",
		"go_dependencies.puddle.version":                  "v2.2.2",
		"go_dependencies.x_oauth2.version":                "v0.36.0",
		"go_dependencies.x_sync.version":                  "v0.22.0",
		"go_dependencies.x_sys.version":                   "v0.47.0",
		"go_dependencies.x_text.version":                  "v0.40.0",
		"go_dependencies.x_net.version":                   "v0.57.0",
		"go_build_tools.oapi_codegen.version":             "v2.7.2",
		"go_build_tools.sqlc.version":                     "v1.31.1",
		"go_build_tools.syft.version":                     "v1.48.0",
		"go_build_tools.syft.image":                       "anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c",
		"go_build_tools.syft.image_digest":                "sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c",
		"go_build_tools.grype.version":                    "v0.116.0",
		"go_build_tools.grype.image":                      "anchore/grype:v0.116.0@sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821",
		"go_build_tools.grype.image_digest":               "sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821",
		"ci_actions.checkout.version":                     "v7.0.0",
		"ci_actions.checkout.source_commit":               "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
		"ci_actions.codeql_init.repository":               "github/codeql-action/init",
		"ci_actions.codeql_init.version":                  "v4.38.1",
		"ci_actions.codeql_init.source_commit":            "1c5b675653bb5c22dbe9b12b556ec555138e09fd",
		"ci_actions.codeql_analyze.repository":            "github/codeql-action/analyze",
		"ci_actions.codeql_analyze.version":               "v4.38.1",
		"ci_actions.codeql_analyze.source_commit":         "1c5b675653bb5c22dbe9b12b556ec555138e09fd",
		"ci_actions.dependency_review.repository":         "actions/dependency-review-action",
		"ci_actions.dependency_review.version":            "v5.0.0",
		"ci_actions.dependency_review.source_commit":      "a1d282b36b6f3519aa1f3fc636f609c47dddb294",
		"data_services.postgresql.version":                "18.4",
		"data_services.opensearch.version":                "3.7.0",
		"application_images.server_runtime_base":          "scratch",
		"application_images.worker_runtime_base":          "scratch",
		"application_images.connector_runtime_base":       "scratch",
		"operator_artifact.version":                       "0.1.0",
		"operator_artifact.image":                         "knowvault-operator:0.1.0",
		"operator_artifact.image_digest":                  "sha256:a96e84878ec9c6bce6953cf8ee375a6a0926bd1a8002f3ae53aec6d53d19ce31",
		"operator_artifact.binary":                        "knowvault-operator",
		"operator_artifact.source":                        "cmd/operator",
		"operator_artifact.platform":                      "linux/amd64",
		"operator_artifact.migrations":                    "db/migrations",
		"operator_artifact.dockerfile":                    "deploy/images/Dockerfile.operator",
		"operator_artifact.builder_image":                 "golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669",
		"operator_artifact.runtime_base":                  "scratch",
		"operator_artifact.runtime_user":                  "0:0",
		"operator_artifact.runtime_filesystem":            "read-only-compatible",
		"operator_artifact.runtime_network":               "no-runtime-downloads",
		"operator_artifact.build_network":                 "module-cache-warm-then-none",
		"operator_artifact.source_date_epoch":             "1704067200",
		"operator_artifact.binary_digest":                 "sha256:86638dd298ea3b4e77a65b2a5d88fc86c6462ece90889fee970f55ed29bb953a",
		"operator_artifact.migration_digest":              "sha256:a237b8542b291553e632f12db1708d656380a464b13a76a67c3642e5a8836e93",
		"operator_artifact.artifact_identity":             "sha256:85adcfc39d9b7a04afc2189eed4e58889686b493243036d94eda1e842b8d3a3b",
		"operator_artifact.license":                       "BSD-3-Clause",
		"operator_artifact.license_source":                "https://go.dev/LICENSE",
		"operator_artifact.sbom.status":                   "RELEASE_ATTESTATION_REQUIRED",
		"operator_artifact.sbom.format":                   "SPDX-2.3",
		"operator_artifact.sbom.generator":                "Syft",
		"operator_artifact.sbom.generator_version":        "1.48.0",
		"operator_artifact.sbom.output":                   "knowvault-operator.sbom.spdx.json",
		"operator_artifact.sbom.identity_binding":         "artifact_identity",
		"deferred_runtime_locks.status":                   "stage-blocking-before-first-use",
		"deferred_dependency_locks.status":                "deny-before-import-or-runtime-start",
	}
	for jsonPath, expected := range expectedStrings {
		actual, ok := jsonValueAt(lock, jsonPath)
		if !ok || actual != expected {
			problems = append(problems, fmt.Sprintf("version lock mismatch %s: expected %q, got %v", jsonPath, expected, actual))
		}
	}
	for _, jsonPath := range []string{
		"policy.runtime_latest_tags",
		"policy.runtime_downloads",
		"policy.node_in_production",
		"policy.go_toolchain_auto_download",
	} {
		actual, ok := jsonValueAt(lock, jsonPath)
		if !ok || actual != false {
			problems = append(problems, "version policy must be false: "+jsonPath)
		}
	}
	if actual, ok := jsonValueAt(lock, "lock_version"); !ok || actual != float64(1) {
		problems = append(problems, "architecture/versions.json lock_version must equal 1")
	}
	for _, stage := range []string{"STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "STAGE_6"} {
		value, ok := jsonValueAt(lock, "deferred_dependency_locks.stage_gates."+stage)
		items, isArray := value.([]any)
		if !ok || !isArray || len(items) == 0 {
			problems = append(problems, "missing non-empty deferred dependency gate: "+stage)
		}
	}
	for _, forbidden := range []string{`"version": "latest"`, `:latest`, `@main`} {
		if strings.Contains(string(raw), forbidden) {
			problems = append(problems, "floating version in architecture/versions.json: "+forbidden)
		}
	}
	problems = append(problems, checkVersionInventoryMutationTests(lock)...)
	return problems
}

type reviewedNodePackage struct {
	Key          string
	Package      string
	SelectedName string
}

var reviewedEsbuildPlatformPackages = []reviewedNodePackage{
	{Key: "esbuild_aix_ppc64", Package: "@esbuild/aix-ppc64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_android_arm", Package: "@esbuild/android-arm", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_android_arm64", Package: "@esbuild/android-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_android_x64", Package: "@esbuild/android-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_darwin_arm64", Package: "@esbuild/darwin-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_darwin_x64", Package: "@esbuild/darwin-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_freebsd_arm64", Package: "@esbuild/freebsd-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_freebsd_x64", Package: "@esbuild/freebsd-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_arm", Package: "@esbuild/linux-arm", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_arm64", Package: "@esbuild/linux-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_ia32", Package: "@esbuild/linux-ia32", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_loong64", Package: "@esbuild/linux-loong64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_mips64el", Package: "@esbuild/linux-mips64el", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_ppc64", Package: "@esbuild/linux-ppc64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_riscv64", Package: "@esbuild/linux-riscv64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_s390x", Package: "@esbuild/linux-s390x", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_linux_x64", Package: "@esbuild/linux-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_netbsd_arm64", Package: "@esbuild/netbsd-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_netbsd_x64", Package: "@esbuild/netbsd-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_openbsd_arm64", Package: "@esbuild/openbsd-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_openbsd_x64", Package: "@esbuild/openbsd-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_openharmony_arm64", Package: "@esbuild/openharmony-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_sunos_x64", Package: "@esbuild/sunos-x64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_win32_arm64", Package: "@esbuild/win32-arm64", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_win32_ia32", Package: "@esbuild/win32-ia32", SelectedName: "esbuild platform packages"},
	{Key: "esbuild_win32_x64", Package: "@esbuild/win32-x64", SelectedName: "esbuild platform packages"},
}

var reviewedVersionComponentFields = map[string][]string{
	"toolchains.go":                                     {"version", "go_directive", "toolchain_directive", "ci_environment", "build_image", "license"},
	"toolchains.node":                                   {"version", "scope", "build_image", "license"},
	"toolchains.pnpm":                                   {"version", "activation", "dist_integrity", "license"},
	"toolchains.corepack_bundled":                       {"version", "scope", "license", "rule"},
	"toolchains.npm_bundled":                            {"version", "scope", "license", "rule"},
	"toolchains.yarn_bundled":                           {"version", "scope", "license", "rule"},
	"frontend.react":                                    {"version", "dist_integrity", "license"},
	"frontend.react_dom":                                {"version", "dist_integrity", "license"},
	"frontend.react_types":                              {"package", "version", "scope", "dist_integrity", "license"},
	"frontend.react_dom_types":                          {"package", "version", "scope", "dist_integrity", "license"},
	"frontend.typescript":                               {"version", "dist_integrity", "license"},
	"frontend.esbuild":                                  {"version", "scope", "dist_integrity", "license"},
	"frontend.ajv":                                      {"version", "scope", "dist_integrity", "license"},
	"frontend.ajv_formats":                              {"version", "scope", "dist_integrity", "license"},
	"node_transitive_dependencies.fast_deep_equal":      {"package", "version", "dist_integrity", "license"},
	"node_transitive_dependencies.fast_uri":             {"package", "version", "dist_integrity", "license"},
	"node_transitive_dependencies.json_schema_traverse": {"package", "version", "dist_integrity", "license"},
	"node_transitive_dependencies.require_from_string":  {"package", "version", "dist_integrity", "license"},
	"node_transitive_dependencies.scheduler":            {"package", "version", "dist_integrity", "license"},
	"node_transitive_dependencies.csstype":              {"package", "version", "dist_integrity", "license"},
	"go_dependencies.pgx":                               {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.google_compute_metadata":           {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.oidc":                              {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.go_jose":                           {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.pgpassfile":                        {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.pgservicefile":                     {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.puddle":                            {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.x_oauth2":                          {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.x_sync":                            {"module", "version", "module_sum", "go_mod_sum", "source_commit", "license"},
	"go_dependencies.x_sys":                             {"module", "version", "module_sum", "go_mod_sum", "source_commit", "role", "license"},
	"go_dependencies.x_text":                            {"module", "version", "module_sum", "go_mod_sum", "source_commit", "role", "license"},
	"go_dependencies.x_net":                             {"module", "version", "module_sum", "go_mod_sum", "source_commit", "role", "license"},
	"go_build_tools.oapi_codegen":                       {"module", "version", "module_sum", "go_mod_sum", "source_commit", "scope", "license", "rule"},
	"go_build_tools.sqlc":                               {"module", "version", "module_sum", "go_mod_sum", "source_commit", "scope", "license", "rule"},
	"go_build_tools.syft":                               {"module", "version", "source_commit", "release_checksum_manifest_sha256", "image", "image_digest", "scope", "license", "rule"},
	"go_build_tools.grype":                              {"module", "version", "source_commit", "release_checksum_manifest_sha256", "image", "image_digest", "scope", "license", "rule"},
	"ci_actions.checkout":                               {"repository", "version", "source_commit", "license", "scope"},
	"ci_actions.codeql_init":                            {"repository", "version", "source_commit", "license", "scope"},
	"ci_actions.codeql_analyze":                         {"repository", "version", "source_commit", "license", "scope"},
	"ci_actions.dependency_review":                      {"repository", "version", "source_commit", "license", "scope"},
	"ci_actions.powershell_probe_runner":                {"repository", "version", "source_commit", "release_artifact", "release_checksum_sha256", "license", "scope", "rule"},
	"data_services.postgresql":                          {"version", "image", "license"},
	"data_services.opensearch":                          {"version", "image", "license"},
	// ARC-005: a runtime component of the install needs an ADR as well as a
	// license record. These two are the install's own infrastructure
	// (ADR-0090), so "adr" is a required field of their inventory entry, not an
	// optional annotation: dropping it fails this closed-key check.
	"data_services.reverse_proxy":     {"version", "image", "license", "scope", "adr"},
	"data_services.built_in_idp":      {"version", "image", "license", "scope", "adr"},
	"data_services.embedding_runtime": {"version", "image", "license", "scope"},
}

var reviewedVersionGroups = map[string][]string{
	"toolchains":                   {"go", "node", "pnpm", "corepack_bundled", "npm_bundled", "yarn_bundled"},
	"frontend":                     {"react", "react_dom", "react_types", "react_dom_types", "typescript", "esbuild", "ajv", "ajv_formats"},
	"node_transitive_dependencies": {"fast_deep_equal", "fast_uri", "json_schema_traverse", "require_from_string", "scheduler", "csstype"},
	"go_dependencies":              {"google_compute_metadata", "oidc", "go_jose", "pgx", "pgpassfile", "pgservicefile", "puddle", "x_oauth2", "x_sync", "x_sys", "x_text", "x_net"},
	"go_build_tools":               {"oapi_codegen", "sqlc", "syft", "grype"},
	"ci_actions":                   {"checkout", "powershell_probe_runner", "codeql_init", "codeql_analyze", "dependency_review"},
	"data_services":                {"postgresql", "opensearch", "reverse_proxy", "built_in_idp", "embedding_runtime"},
}

func init() {
	for _, component := range reviewedEsbuildPlatformPackages {
		path := "node_transitive_dependencies." + component.Key
		reviewedVersionComponentFields[path] = []string{"package", "version", "dist_integrity", "license"}
		reviewedVersionGroups["node_transitive_dependencies"] = append(
			reviewedVersionGroups["node_transitive_dependencies"], component.Key,
		)
	}
}

// Supply-chain lifecycle states. Every deferred entry declares one explicitly;
// there is no implicit state, so a component cannot drift into use unnoticed.
//
//   - lifecycleDeferred: denied repository-wide (the default).
//   - lifecycleQualifiedNotActive: exact-version qualified, usable ONLY inside its
//     declared isolated worker build/test subtree, still unreachable from
//     production composition, deploy, runtime and every production image build
//     context. This is a narrowing of the leak scan's scope for named tokens, not
//     a suspension of it, and it is declared per component so POI, PDFBox and
//     Tesseract each get the same boundary without a copied exception.
//   - lifecycleEvidenceOnly: real build/test evidence is present in a declared
//     isolated subtree, but release qualification is incomplete. It receives the
//     same default-deny boundary and can never be reached from production.
//   - ACTIVE is not a value here: activation removes the entry from the deferred
//     locks AND from the closed registry below, so it cannot be a silent step.
const (
	lifecycleDeferred           = "DEFERRED"
	lifecycleQualifiedNotActive = "QUALIFIED_NOT_ACTIVE"
	lifecycleEvidenceOnly       = "EVIDENCE_ONLY"
)

// qualifiedIsolation is the machine-checked contract a QUALIFIED_NOT_ACTIVE
// component must satisfy. It is mirrored here so editing architecture/versions.json
// alone cannot widen a component's reach: both files must change in lockstep.
type qualifiedIsolation struct {
	ExactVersion      string
	IsolatedSubtree   string
	LeakTokens        []string
	Evidence          string
	BuilderImage      string
	RuntimeBase       string
	RuntimeStrategy   string
	RuntimeModules    []string
	OCIManifestDigest string
	ConfigDigest      string
	ArtifactDigest    string
	LayerDigests      []string
	Compliance        string
}

type deferredInventoryItem struct {
	ID            string
	Kind          string
	Stage         string
	Lifecycle     string
	Qualification *qualifiedIsolation
}

var documentParserWorkerIsolation = &qualifiedIsolation{
	ExactVersion:      "2.1.0",
	IsolatedSubtree:   "workers/document-parser/",
	LeakTokens:        []string{"document-parser-worker"},
	Evidence:          "docs/qualification-s2b-document-parser.md",
	BuilderImage:      "maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8",
	RuntimeBase:       "scratch",
	RuntimeStrategy:   "jlink",
	RuntimeModules:    []string{"java.base", "java.desktop", "java.logging", "java.security.jgss", "java.xml.crypto"},
	OCIManifestDigest: "sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855",
	ConfigDigest:      "sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467",
	ArtifactDigest:    "sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414",
	LayerDigests: []string{
		"sha256:88a11acca421df58865f88d823431f52bda8175d5e6fd1692f2a487cc08f4c70",
		"sha256:17c02ca28da47e5a67ba1947fd042307e2285f94bf2d25bc0409f58337b05faf",
		"sha256:63c13e8ea6c10b81562d53428ece2363c7bb062d5d9747c2f87bbaeea22963a0",
		"sha256:36940d4560923835ac9eeccc0143ca747fe22821bc818faef116a68b7d522889",
		"sha256:6497328e1d8bf7f489b5284b656625833be2bea7f0709bb4447810c65845465a",
		"sha256:77ab5ba073fde3c4a0b3a17426a495c37713063bb59a0816dd90b3dc86a01cd2",
		"sha256:bdc0761c2529d7d054fc5c57ac1571244b5ec959f764161d846600211af80818",
		"sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1",
	},
	Compliance: "workers/document-parser/release/source-compliance/openjdk-temurin-21.0.12+8/SOURCE-OFFER.json",
}

var apachePOIIsolation = &qualifiedIsolation{
	ExactVersion:    "5.5.1",
	IsolatedSubtree: "workers/document-parser/",
	LeakTokens:      []string{"org.apache.poi", "apache-poi"},
	Evidence:        "docs/qualification-s2b-document-parser.md",
}

var apachePDFBoxIsolation = &qualifiedIsolation{
	ExactVersion:    "3.0.8",
	IsolatedSubtree: "workers/document-parser/",
	LeakTokens:      []string{"org.apache.pdfbox", "apache-pdfbox", "pdfbox"},
	Evidence:        "docs/qualification-s2b-document-parser.md",
}

var tesseractEvidenceIsolation = &qualifiedIsolation{
	ExactVersion:    "1.0.0",
	IsolatedSubtree: "workers/tesseract-ocr/",
	LeakTokens:      []string{"tesseract", "leptonica", "tessdata"},
	Evidence:        "workers/tesseract-ocr/release/image-lock.json",
}

var expectedDeferredRuntime = []deferredInventoryItem{
	{ID: "oci.document-parser-worker", Kind: "OCI_IMAGE", Stage: "STAGE_2", Lifecycle: lifecycleQualifiedNotActive},
	{ID: "oci.sandbox-dispatcher", Kind: "OCI_IMAGE", Stage: "STAGE_2", Lifecycle: lifecycleDeferred},
	{ID: "maven.apache-poi", Kind: "MAVEN_ARTIFACT", Stage: "STAGE_2", Lifecycle: lifecycleQualifiedNotActive},
	{ID: "maven.apache-pdfbox", Kind: "MAVEN_ARTIFACT", Stage: "STAGE_2", Lifecycle: lifecycleQualifiedNotActive},
	{ID: "oci.tesseract-ocr-worker", Kind: "OCI_IMAGE", Stage: "STAGE_2", Lifecycle: lifecycleEvidenceOnly},
	{ID: "model.tessdata", Kind: "MODEL_ARTIFACT", Stage: "STAGE_2", Lifecycle: lifecycleEvidenceOnly},
	{ID: "oci.vllm", Kind: "OCI_IMAGE", Stage: "STAGE_3", Lifecycle: lifecycleDeferred},
	{ID: "model.embedding", Kind: "MODEL_ARTIFACT", Stage: "STAGE_3", Lifecycle: lifecycleDeferred},
	{ID: "model.reranker", Kind: "MODEL_ARTIFACT", Stage: "STAGE_3", Lifecycle: lifecycleDeferred},
	{ID: "model.generator", Kind: "MODEL_ARTIFACT", Stage: "STAGE_4", Lifecycle: lifecycleDeferred},
	{ID: "model.verifier", Kind: "MODEL_ARTIFACT", Stage: "STAGE_4", Lifecycle: lifecycleDeferred},
	{ID: "oci.opentelemetry-collector", Kind: "OCI_IMAGE", Stage: "STAGE_6", Lifecycle: lifecycleDeferred},
}

var expectedDeferredGates = map[string][]deferredInventoryItem{
	"STAGE_1": {
		{ID: "scim.server-auth", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
	},
	"STAGE_2": {
		{ID: "oci.document-parser-worker", Kind: "OCI_IMAGE", Lifecycle: lifecycleQualifiedNotActive, Qualification: documentParserWorkerIsolation},
		{ID: "oci.sandbox-dispatcher", Kind: "OCI_IMAGE", Lifecycle: lifecycleDeferred},
		{ID: "maven.apache-poi", Kind: "MAVEN_ARTIFACT", Lifecycle: lifecycleQualifiedNotActive, Qualification: apachePOIIsolation},
		{ID: "maven.apache-pdfbox", Kind: "MAVEN_ARTIFACT", Lifecycle: lifecycleQualifiedNotActive, Qualification: apachePDFBoxIsolation},
		{ID: "oci.tesseract-ocr-worker", Kind: "OCI_IMAGE", Lifecycle: lifecycleEvidenceOnly, Qualification: tesseractEvidenceIsolation},
		{ID: "model.tessdata", Kind: "MODEL_ARTIFACT", Lifecycle: lifecycleEvidenceOnly, Qualification: tesseractEvidenceIsolation},
	},
	"STAGE_3": {
		{ID: "go.opensearch-client", Kind: "GO_MODULE_OR_ADR", Lifecycle: lifecycleDeferred},
		{ID: "oci.vllm", Kind: "OCI_IMAGE", Lifecycle: lifecycleDeferred},
		{ID: "model.embedding", Kind: "MODEL_ARTIFACT", Lifecycle: lifecycleDeferred},
		{ID: "model.reranker", Kind: "MODEL_ARTIFACT", Lifecycle: lifecycleDeferred},
	},
	"STAGE_4": {
		{ID: "model.generator", Kind: "MODEL_ARTIFACT", Lifecycle: lifecycleDeferred},
		{ID: "model.verifier", Kind: "MODEL_ARTIFACT", Lifecycle: lifecycleDeferred},
	},
	"STAGE_5": {
		{ID: "git.https-transport", Kind: "IMPLEMENTATION_OR_ADR", Lifecycle: lifecycleDeferred},
		{ID: "mail.microsoft-graph", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
		{ID: "mail.gmail-api", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
		{ID: "mail.imap", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
		{ID: "s3.compatible-client", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
	},
	"STAGE_6": {
		{ID: "go.opentelemetry", Kind: "GO_MODULE", Lifecycle: lifecycleDeferred},
		{ID: "oci.opentelemetry-collector", Kind: "OCI_IMAGE", Lifecycle: lifecycleDeferred},
		{ID: "kms.provider-adapters", Kind: "PROVIDER_SDK", Lifecycle: lifecycleDeferred},
		{ID: "secret.provider-adapters", Kind: "PROVIDER_SDK", Lifecycle: lifecycleDeferred},
	},
}

func validateVersionInventory(lock any) []string {
	root, ok := lock.(map[string]any)
	if !ok {
		return []string{"architecture/versions.json must be an object"}
	}
	var problems []string
	problems = append(problems, exactObjectKeys(root, "versions", []string{
		"$schema", "lock_version", "status", "observed_at", "policy", "toolchains", "frontend", "node_transitive_dependencies", "go_dependencies", "go_build_tools", "ci_actions", "data_services", "application_images", "operator_artifact", "supply_chain_lifecycle", "deferred_runtime_locks", "deferred_dependency_locks",
	})...)
	problems = append(problems, exactNestedKeys(lock, "supply_chain_lifecycle", []string{
		"states", "DEFERRED", "QUALIFIED_NOT_ACTIVE", "EVIDENCE_ONLY", "ACTIVE", "rule",
	})...)
	problems = append(problems, exactNestedKeys(lock, "policy", []string{
		"container_references", "runtime_latest_tags", "runtime_downloads", "node_in_production", "go_toolchain_auto_download", "release_requires_transitive_sbom_and_license_gate", "offline_bundle_requires_platform_manifest_and_blob_digests",
	})...)
	for groupPath, componentNames := range reviewedVersionGroups {
		value, exists := jsonValueAt(lock, groupPath)
		group, isObject := value.(map[string]any)
		if !exists || !isObject {
			problems = append(problems, "version inventory group missing or not object: "+groupPath)
			continue
		}
		problems = append(problems, exactObjectKeys(group, groupPath, componentNames)...)
		for _, componentName := range componentNames {
			componentPath := groupPath + "." + componentName
			componentValue, exists := jsonValueAt(lock, componentPath)
			component, isObject := componentValue.(map[string]any)
			if !exists || !isObject {
				problems = append(problems, "reviewed component missing or not object: "+componentPath)
				continue
			}
			problems = append(problems, exactObjectKeys(component, componentPath, reviewedVersionComponentFields[componentPath])...)
			if version, ok := component["version"].(string); !ok || strings.TrimSpace(version) == "" {
				problems = append(problems, "reviewed component has no exact version: "+componentPath)
			} else if !isExactComponentVersion(componentPath, version) {
				problems = append(problems, "reviewed component uses non-exact version syntax: "+componentPath+" -> "+version)
			}
			if license, ok := component["license"].(string); !ok || strings.TrimSpace(license) == "" {
				problems = append(problems, "reviewed component has no concluded license: "+componentPath)
			}
			problems = append(problems, validateComponentIntegrity(componentPath, component, lock)...)
		}
	}
	problems = append(problems, exactNestedKeys(lock, "toolchains.go.ci_environment", []string{"GOTOOLCHAIN", "GOEXPERIMENT"})...)
	problems = append(problems, exactNestedKeys(lock, "application_images", []string{"server_runtime_base", "worker_runtime_base", "connector_runtime_base", "ca_bundle"})...)
	problems = append(problems, validateOperatorArtifact(lock)...)
	problems = append(problems, exactNestedKeys(lock, "deferred_runtime_locks", []string{"status", "components", "rule"})...)
	problems = append(problems, exactNestedKeys(lock, "deferred_dependency_locks", []string{"status", "stage_gates", "rule"})...)
	problems = append(problems, exactNestedKeys(lock, "deferred_dependency_locks.stage_gates", []string{"STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "STAGE_6"})...)
	problems = append(problems, validateDeferredInventory(lock)...)
	return problems
}

// validateOperatorArtifact keeps the one-shot deployment artifact in the same
// closed, exact inventory as the application toolchains. The operator binary
// is not a new runtime capability: this record binds the existing command and
// migration stream to its reproducible image construction and release
// attestation hook.
func validateOperatorArtifact(lock any) []string {
	value, ok := jsonValueAt(lock, "operator_artifact")
	artifact, isObject := value.(map[string]any)
	if !ok || !isObject {
		return []string{"operator_artifact is missing or not an object"}
	}

	expectedKeys := []string{
		"version", "image", "image_digest", "binary", "source", "platform", "migrations", "dockerfile", "builder_image",
		"runtime_base", "runtime_user", "runtime_filesystem", "runtime_network",
		"build_network", "source_date_epoch", "binary_digest", "migration_digest", "artifact_identity",
		"license", "license_source", "sbom",
	}
	problems := exactObjectKeys(artifact, "operator_artifact", expectedKeys)
	expectedStrings := map[string]string{
		"version":            "0.1.0",
		"image":              "knowvault-operator:0.1.0",
		"binary":             "knowvault-operator",
		"source":             "cmd/operator",
		"platform":           "linux/amd64",
		"migrations":         "db/migrations",
		"dockerfile":         "deploy/images/Dockerfile.operator",
		"builder_image":      "golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669",
		"runtime_base":       "scratch",
		"runtime_user":       "0:0",
		"runtime_filesystem": "read-only-compatible",
		"runtime_network":    "no-runtime-downloads",
		"build_network":      "module-cache-warm-then-none",
		"source_date_epoch":  "1704067200",
		"license":            "BSD-3-Clause",
		"license_source":     "https://go.dev/LICENSE",
	}
	for key, expected := range expectedStrings {
		if artifact[key] != expected {
			problems = append(problems, fmt.Sprintf("operator artifact lock mismatch operator_artifact.%s: expected %q, got %v", key, expected, artifact[key]))
		}
	}
	if version, ok := artifact["version"].(string); !ok || !isExactComponentVersion("operator_artifact", version) {
		problems = append(problems, "operator artifact version is not exact semver")
	}

	sha256Pattern := regexp.MustCompile("^sha256:[0-9a-f]{64}$")
	for _, key := range []string{"image_digest", "binary_digest", "migration_digest", "artifact_identity"} {
		digest, ok := artifact[key].(string)
		hexDigest := strings.TrimPrefix(digest, "sha256:")
		if !ok || !sha256Pattern.MatchString(digest) || strings.Trim(hexDigest, "0") == "" {
			problems = append(problems, "operator artifact digest is missing, malformed, or zero: operator_artifact."+key)
		}
	}
	builderImage, _ := artifact["builder_image"].(string)
	if !regexp.MustCompile("^[^\\s:@]+(?:/[^\\s:@]+)*:[^\\s@]+@sha256:[0-9a-f]{64}$").MatchString(builderImage) {
		problems = append(problems, "operator artifact builder image is not tag-and-digest pinned")
	}

	rawSBOM, ok := artifact["sbom"]
	sbom, isObject := rawSBOM.(map[string]any)
	if !ok || !isObject {
		return append(problems, "operator artifact sbom hook is missing or not an object")
	}
	sbomKeys := []string{"status", "format", "generator", "generator_version", "output", "identity_binding"}
	problems = append(problems, exactObjectKeys(sbom, "operator_artifact.sbom", sbomKeys)...)
	for key, expected := range map[string]string{
		"status":            "RELEASE_ATTESTATION_REQUIRED",
		"format":            "SPDX-2.3",
		"generator":         "Syft",
		"generator_version": "1.48.0",
		"output":            "knowvault-operator.sbom.spdx.json",
		"identity_binding":  "artifact_identity",
	} {
		if sbom[key] != expected {
			problems = append(problems, fmt.Sprintf("operator artifact SBOM hook mismatch operator_artifact.sbom.%s: expected %q, got %v", key, expected, sbom[key]))
		}
	}
	return problems
}

func isExactComponentVersion(path, version string) bool {
	plainSemver := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	goSemver := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	if path == "data_services.postgresql" {
		return regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version)
	}
	if strings.HasPrefix(path, "go_dependencies.") || strings.HasPrefix(path, "go_build_tools.") || strings.HasPrefix(path, "ci_actions.") {
		return goSemver.MatchString(version)
	}
	return plainSemver.MatchString(version)
}

func validateDeferredInventory(lock any) []string {
	var problems []string
	problems = append(problems, validateDeferredItems(lock, "deferred_runtime_locks.components", expectedDeferredRuntime, true)...)
	stages := []string{"STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "STAGE_6"}
	for _, stage := range stages {
		problems = append(problems, validateDeferredItems(lock, "deferred_dependency_locks.stage_gates."+stage, expectedDeferredGates[stage], false)...)
	}
	return problems
}

func validateDeferredItems(root any, path string, expected []deferredInventoryItem, includeStage bool) []string {
	value, ok := jsonValueAt(root, path)
	items, isArray := value.([]any)
	if !ok || !isArray {
		return []string{"deferred inventory is not a typed array: " + path}
	}
	var problems []string
	if len(items) != len(expected) {
		problems = append(problems, fmt.Sprintf("deferred inventory membership mismatch %s: expected %d, got %d", path, len(expected), len(items)))
	}
	for index, raw := range items {
		item, isObject := raw.(map[string]any)
		if !isObject {
			problems = append(problems, fmt.Sprintf("deferred inventory item is not object: %s[%d]", path, index))
			continue
		}
		if index >= len(expected) {
			problems = append(problems, fmt.Sprintf("unknown deferred component: %s[%d]", path, index))
			continue
		}
		want := expected[index]
		expectedKeys := []string{"id", "kind"}
		if includeStage {
			expectedKeys = append(expectedKeys, "stage")
		}
		expectedKeys = append(expectedKeys, "lifecycle")
		if want.Qualification != nil {
			expectedKeys = append(expectedKeys, "qualification")
		}
		problems = append(problems, exactObjectKeys(item, fmt.Sprintf("%s[%d]", path, index), expectedKeys)...)
		if item["id"] != want.ID || item["kind"] != want.Kind || (includeStage && item["stage"] != want.Stage) {
			problems = append(problems, fmt.Sprintf("deferred inventory item mismatch %s[%d]: expected %s/%s/%s", path, index, want.ID, want.Kind, want.Stage))
		}
		if item["lifecycle"] != want.Lifecycle {
			problems = append(problems, fmt.Sprintf("deferred component lifecycle mismatch %s[%d] (%s): expected %s, got %v", path, index, want.ID, want.Lifecycle, item["lifecycle"]))
		}
		problems = append(problems, validateQualification(fmt.Sprintf("%s[%d]", path, index), want, item)...)
	}
	return problems
}

// validateQualification binds a QUALIFIED_NOT_ACTIVE entry's declared isolation to
// the closed registry. Widening a component's reach therefore requires editing both
// architecture/versions.json and this protected checker, never one alone.
func validateQualification(path string, want deferredInventoryItem, item map[string]any) []string {
	raw, declared := item["qualification"]
	if want.Qualification == nil {
		if declared {
			return []string{"non-qualified deferred component declares a qualification: " + path}
		}
		return nil
	}
	if !declared {
		return []string{"QUALIFIED_NOT_ACTIVE component declares no qualification: " + path}
	}
	qualification, isObject := raw.(map[string]any)
	if !isObject {
		return []string{"qualification is not an object: " + path}
	}
	expectedKeys := []string{"exact_version", "isolated_subtree", "leak_tokens", "evidence"}
	if want.Qualification != nil && want.Qualification.BuilderImage != "" {
		expectedKeys = append(expectedKeys, "builder_image", "runtime_base", "runtime_strategy", "runtime_modules", "oci_manifest_digest", "config_digest", "artifact_digest", "layer_digests", "compliance")
	}
	problems := exactObjectKeys(qualification, path+".qualification", expectedKeys)
	if qualification["exact_version"] != want.Qualification.ExactVersion {
		problems = append(problems, fmt.Sprintf("qualification exact_version mismatch %s: expected %s", path, want.Qualification.ExactVersion))
	}
	if qualification["isolated_subtree"] != want.Qualification.IsolatedSubtree {
		problems = append(problems, fmt.Sprintf("qualification isolated_subtree mismatch %s: expected %s", path, want.Qualification.IsolatedSubtree))
	}
	if qualification["evidence"] != want.Qualification.Evidence {
		problems = append(problems, fmt.Sprintf("qualification evidence mismatch %s: expected %s", path, want.Qualification.Evidence))
	}
	if want.Qualification != nil && want.Qualification.BuilderImage != "" {
		if qualification["builder_image"] != want.Qualification.BuilderImage {
			problems = append(problems, fmt.Sprintf("qualification builder_image mismatch %s: expected %s", path, want.Qualification.BuilderImage))
		}
		if qualification["runtime_base"] != want.Qualification.RuntimeBase {
			problems = append(problems, fmt.Sprintf("qualification runtime_base mismatch %s: expected %s", path, want.Qualification.RuntimeBase))
		}
		if qualification["runtime_strategy"] != want.Qualification.RuntimeStrategy {
			problems = append(problems, fmt.Sprintf("qualification runtime_strategy mismatch %s: expected %s", path, want.Qualification.RuntimeStrategy))
		}
		if qualification["compliance"] != want.Qualification.Compliance {
			problems = append(problems, fmt.Sprintf("qualification compliance mismatch %s: expected %s", path, want.Qualification.Compliance))
		}
		for key, expected := range map[string]string{
			"oci_manifest_digest": want.Qualification.OCIManifestDigest,
			"config_digest":       want.Qualification.ConfigDigest,
			"artifact_digest":     want.Qualification.ArtifactDigest,
		} {
			if qualification[key] != expected {
				problems = append(problems, fmt.Sprintf("qualification %s mismatch %s: expected %s", key, path, expected))
			}
		}
		layerDigests := want.Qualification.LayerDigests
		if got, ok := qualification["layer_digests"].([]any); !ok || len(got) != len(layerDigests) {
			problems = append(problems, fmt.Sprintf("qualification layer_digests mismatch %s: expected exactly %d digests", path, len(layerDigests)))
		} else {
			for index, digest := range got {
				if digest != layerDigests[index] {
					problems = append(problems, fmt.Sprintf("qualification layer_digests mismatch %s[%d]: expected %s", path, index, layerDigests[index]))
				}
			}
		}
		modules, isArray := qualification["runtime_modules"].([]any)
		if !isArray || len(modules) != len(want.Qualification.RuntimeModules) {
			problems = append(problems, fmt.Sprintf("qualification runtime_modules mismatch %s: expected exactly %d modules", path, len(want.Qualification.RuntimeModules)))
		} else {
			for index, module := range modules {
				if module != want.Qualification.RuntimeModules[index] {
					problems = append(problems, fmt.Sprintf("qualification runtime_modules mismatch %s[%d]: expected %s", path, index, want.Qualification.RuntimeModules[index]))
				}
			}
		}
	}
	tokens, isArray := qualification["leak_tokens"].([]any)
	if !isArray || len(tokens) != len(want.Qualification.LeakTokens) {
		problems = append(problems, fmt.Sprintf("qualification leak_tokens mismatch %s: expected exactly %d declared tokens", path, len(want.Qualification.LeakTokens)))
		return problems
	}
	for i, token := range tokens {
		if token != want.Qualification.LeakTokens[i] {
			problems = append(problems, fmt.Sprintf("qualification leak_tokens mismatch %s[%d]: expected %s", path, i, want.Qualification.LeakTokens[i]))
		}
	}
	return problems
}

// qualifiedIsolationsFromLock reads the declared QUALIFIED_NOT_ACTIVE isolations
// from architecture/versions.json. It is the single source both the isolation gate
// and the leak scan's narrow allowance read, so the two cannot disagree about which
// tokens are tolerated in which subtree.
func qualifiedIsolationsFromLock(root string) (map[string]qualifiedIsolation, []string) {
	isolations := make(map[string]qualifiedIsolation)
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "versions.json"))
	if err != nil {
		return nil, []string{"missing or unreadable architecture/versions.json"}
	}
	var lock any
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, []string{"invalid architecture/versions.json: " + err.Error()}
	}
	var problems []string
	for _, stage := range []string{"STAGE_1", "STAGE_2", "STAGE_3", "STAGE_4", "STAGE_5", "STAGE_6"} {
		value, ok := jsonValueAt(lock, "deferred_dependency_locks.stage_gates."+stage)
		items, isArray := value.([]any)
		if !ok || !isArray {
			continue
		}
		for _, entry := range items {
			item, isObject := entry.(map[string]any)
			if !isObject || (item["lifecycle"] != lifecycleQualifiedNotActive && item["lifecycle"] != lifecycleEvidenceOnly) {
				continue
			}
			id, _ := item["id"].(string)
			qualification, isObject := item["qualification"].(map[string]any)
			if !isObject {
				problems = append(problems, "scoped lifecycle component has no qualification object: "+id)
				continue
			}
			isolation := qualifiedIsolation{}
			isolation.ExactVersion, _ = qualification["exact_version"].(string)
			isolation.IsolatedSubtree, _ = qualification["isolated_subtree"].(string)
			isolation.Evidence, _ = qualification["evidence"].(string)
			isolation.BuilderImage, _ = qualification["builder_image"].(string)
			isolation.RuntimeBase, _ = qualification["runtime_base"].(string)
			isolation.RuntimeStrategy, _ = qualification["runtime_strategy"].(string)
			isolation.OCIManifestDigest, _ = qualification["oci_manifest_digest"].(string)
			isolation.ConfigDigest, _ = qualification["config_digest"].(string)
			isolation.ArtifactDigest, _ = qualification["artifact_digest"].(string)
			isolation.Compliance, _ = qualification["compliance"].(string)
			if modules, ok := qualification["runtime_modules"].([]any); ok {
				for _, module := range modules {
					if text, ok := module.(string); ok && strings.TrimSpace(text) != "" {
						isolation.RuntimeModules = append(isolation.RuntimeModules, text)
					}
				}
			}
			if digests, ok := qualification["layer_digests"].([]any); ok {
				for _, digest := range digests {
					if text, ok := digest.(string); ok && strings.TrimSpace(text) != "" {
						isolation.LayerDigests = append(isolation.LayerDigests, text)
					}
				}
			}
			tokens, _ := qualification["leak_tokens"].([]any)
			for _, token := range tokens {
				if text, ok := token.(string); ok && strings.TrimSpace(text) != "" {
					isolation.LeakTokens = append(isolation.LeakTokens, text)
				}
			}
			if len(isolation.LeakTokens) == 0 {
				problems = append(problems, "scoped lifecycle component declares no leak tokens: "+id)
			}
			isolations[id] = isolation
		}
	}
	return isolations, problems
}

func validateComponentIntegrity(path string, component map[string]any, lock any) []string {
	var required map[string]*regexp.Regexp
	sha512Pattern := regexp.MustCompile(`^sha512-[A-Za-z0-9+/]+={0,2}$`)
	h1Pattern := regexp.MustCompile(`^h1:[A-Za-z0-9+/]+={0,2}$`)
	hex40Pattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Pattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	imagePattern := regexp.MustCompile(`^[^\s:@]+(?:/[^\s:@]+)*:[^\s@]+@sha256:[0-9a-f]{64}$`)
	switch {
	case path == "toolchains.go" || path == "toolchains.node":
		required = map[string]*regexp.Regexp{"build_image": imagePattern}
	case path == "toolchains.pnpm" || strings.HasPrefix(path, "frontend.") || strings.HasPrefix(path, "node_transitive_dependencies."):
		required = map[string]*regexp.Regexp{"dist_integrity": sha512Pattern}
	case strings.HasPrefix(path, "go_dependencies.") || path == "go_build_tools.oapi_codegen" || path == "go_build_tools.sqlc":
		required = map[string]*regexp.Regexp{"module_sum": h1Pattern, "go_mod_sum": h1Pattern, "source_commit": hex40Pattern}
	case path == "go_build_tools.syft" || path == "go_build_tools.grype":
		required = map[string]*regexp.Regexp{"source_commit": hex40Pattern, "release_checksum_manifest_sha256": hex64Pattern, "image": regexp.MustCompile(`^[^\s:@]+(?:/[^\s:@]+)*:[^\s@]+@sha256:[0-9a-f]{64}$`), "image_digest": regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)}
	case path == "ci_actions.checkout" || path == "ci_actions.codeql_init" || path == "ci_actions.codeql_analyze" || path == "ci_actions.dependency_review":
		required = map[string]*regexp.Regexp{"source_commit": hex40Pattern}
	case path == "ci_actions.powershell_probe_runner":
		required = map[string]*regexp.Regexp{"source_commit": hex40Pattern, "release_checksum_sha256": hex64Pattern}
	case strings.HasPrefix(path, "data_services."):
		required = map[string]*regexp.Regexp{"image": imagePattern}
	case path == "toolchains.corepack_bundled" || path == "toolchains.npm_bundled" || path == "toolchains.yarn_bundled":
		builder, ok := jsonValueAt(lock, "toolchains.node.build_image")
		if !ok || !imagePattern.MatchString(fmt.Sprint(builder)) {
			return []string{"bundled component lacks exact builder provenance: " + path}
		}
		return nil
	default:
		return []string{"reviewed component has no integrity policy: " + path}
	}
	var problems []string
	for field, pattern := range required {
		value, ok := component[field].(string)
		valid := ok && pattern.MatchString(value)
		if valid && strings.HasPrefix(value, "sha512-") {
			valid = hasExactBase64Digest(value, "sha512-", 64)
		}
		if valid && strings.HasPrefix(value, "h1:") {
			valid = hasExactBase64Digest(value, "h1:", 32)
		}
		if !valid {
			problems = append(problems, "missing or invalid integrity evidence: "+path+"."+field)
		}
	}
	return problems
}

func hasExactBase64Digest(value, prefix string, size int) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == size
}

func exactNestedKeys(root any, path string, expected []string) []string {
	value, ok := jsonValueAt(root, path)
	object, isObject := value.(map[string]any)
	if !ok || !isObject {
		return []string{"required version inventory object missing: " + path}
	}
	return exactObjectKeys(object, path, expected)
}

func exactObjectKeys(object map[string]any, path string, expected []string) []string {
	wanted := make(map[string]bool, len(expected))
	for _, key := range expected {
		wanted[key] = true
	}
	var problems []string
	for key := range object {
		if !wanted[key] {
			problems = append(problems, "unknown field or component in closed version inventory: "+path+"."+key)
		}
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			problems = append(problems, "missing field or component in closed version inventory: "+path+"."+key)
		}
	}
	return problems
}

func checkVersionInventoryMutationTests(lock any) []string {
	mutate := func(change func(map[string]any)) any {
		raw, _ := json.Marshal(lock)
		var cloned map[string]any
		_ = json.Unmarshal(raw, &cloned)
		change(cloned)
		return cloned
	}
	unknown := mutate(func(cloned map[string]any) {
		cloned["frontend"].(map[string]any)["unreviewed_mit_component"] = map[string]any{
			"version": "1.0.0", "dist_integrity": "sha512-YQ==", "license": "MIT",
		}
	})
	missingIntegrity := mutate(func(cloned map[string]any) {
		delete(cloned["frontend"].(map[string]any)["react"].(map[string]any), "dist_integrity")
	})
	unknownDeferredRuntime := mutate(func(cloned map[string]any) {
		items := cloned["deferred_runtime_locks"].(map[string]any)["components"].([]any)
		items[0].(map[string]any)["id"] = "oci.unreviewed-runtime"
	})
	unknownDeferredGate := mutate(func(cloned map[string]any) {
		stages := cloned["deferred_dependency_locks"].(map[string]any)["stage_gates"].(map[string]any)
		items := stages["STAGE_1"].([]any)
		items[0].(map[string]any)["id"] = "go.unreviewed-module"
	})
	shortSHA512 := mutate(func(cloned map[string]any) {
		cloned["frontend"].(map[string]any)["react"].(map[string]any)["dist_integrity"] = "sha512-YQ=="
	})
	shortH1 := mutate(func(cloned map[string]any) {
		cloned["go_dependencies"].(map[string]any)["pgx"].(map[string]any)["module_sum"] = "h1:YQ=="
	})
	nonExactVersion := mutate(func(cloned map[string]any) {
		cloned["node_transitive_dependencies"].(map[string]any)["fast_deep_equal"].(map[string]any)["version"] = "^3.1.3"
	})
	var problems []string
	unknownProblems := validateVersionInventory(unknown)
	if !containsProblem(unknownProblems, "unknown field or component in closed version inventory: frontend.unreviewed_mit_component") {
		problems = append(problems, "architecture.supply.unknown-component mutation was accepted")
	}
	missingProblems := validateVersionInventory(missingIntegrity)
	if !containsProblem(missingProblems, "missing field or component in closed version inventory: frontend.react.dist_integrity") ||
		!containsProblem(missingProblems, "missing or invalid integrity evidence: frontend.react.dist_integrity") {
		problems = append(problems, "architecture.supply.missing-integrity mutation was accepted")
	}
	if len(validateDeferredInventory(unknownDeferredRuntime)) == 0 {
		problems = append(problems, "architecture.supply.unknown-deferred-component mutation was accepted")
	}
	if len(validateDeferredInventory(unknownDeferredGate)) == 0 {
		problems = append(problems, "architecture.supply.unknown-deferred-gate mutation was accepted")
	}
	if !containsProblem(validateVersionInventory(shortSHA512), "missing or invalid integrity evidence: frontend.react.dist_integrity") ||
		!containsProblem(validateVersionInventory(shortH1), "missing or invalid integrity evidence: go_dependencies.pgx.module_sum") {
		problems = append(problems, "architecture.supply.short-integrity mutation was accepted")
	}
	if !containsProblem(validateVersionInventory(nonExactVersion), "reviewed component uses non-exact version syntax: node_transitive_dependencies.fast_deep_equal -> ^3.1.3") {
		problems = append(problems, "architecture.supply.non-exact-version mutation was accepted")
	}
	return problems
}

func containsProblem(problems []string, expected string) bool {
	for _, problem := range problems {
		if problem == expected {
			return true
		}
	}
	return false
}

func containsProblemPrefix(problems []string, prefix string) bool {
	for _, problem := range problems {
		if strings.HasPrefix(problem, prefix) {
			return true
		}
	}
	return false
}

func jsonValueAt(root any, dotted string) (any, bool) {
	current := root
	for _, segment := range strings.Split(dotted, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

type lockedGoModule struct {
	Version  string
	Sum      string
	GoModSum string
}

type lockedNodePackage struct {
	Version   string
	Integrity string
}

type actualNodePackage struct {
	Name      string
	Version   string
	Integrity string
}

func checkActualDependencyInventory(root string) []string {
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "versions.json"))
	if err != nil {
		return []string{"missing architecture/versions.json for actual dependency reconciliation"}
	}
	var lock any
	if err := json.Unmarshal(raw, &lock); err != nil {
		return []string{"invalid architecture/versions.json for actual dependency reconciliation: " + err.Error()}
	}
	goModules := lockedGoModulesFromVersionLock(lock)
	nodePackages := lockedNodePackagesFromVersionLock(lock)
	pnpmPackageManager := lockedPNPMPackageManagerFromVersionLock(lock)
	allowedImages := lockedImagesFromVersionLock(lock)
	allowedActions := lockedActionsFromVersionLock(lock)
	isolations, isolationProblems := qualifiedIsolationsFromLock(root)
	problems := isolationProblems
	// A declared isolated worker subtree is governed by checkSupplyChainLifecycleBoundary
	// instead: its base images must be digest-pinned there, but they are deliberately
	// NOT in the ACTIVE inventory, because the component has not been activated. Routing
	// the subtree to its own gate keeps that distinction honest — dropping it into the
	// ACTIVE inventory to silence this walk would assert an activation that has not
	// happened.
	inIsolatedSubtree := func(rel string) bool {
		for _, isolation := range isolations {
			if isolation.IsolatedSubtree != "" && strings.HasPrefix(rel, isolation.IsolatedSubtree) {
				return true
			}
		}
		return false
	}
	err = walkFiles(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, "cannot inspect dependency manifest: "+path+": "+walkErr.Error())
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor":
				if path != root {
					problems = append(problems, "vendored Go source is forbidden by the module checksum baseline: "+filepath.ToSlash(relative(root, path)))
					return filepath.SkipDir
				}
			case ".git", "node_modules", ".pnpm-store", "dist", "coverage", ".cache", "tmp":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if inIsolatedSubtree(rel) {
			return nil
		}
		if strings.HasPrefix(rel, ".github/actions/") {
			problems = append(problems, "local GitHub Action code is forbidden until separately locked and reviewed: "+rel)
		}
		switch info.Name() {
		case "go.mod":
			problems = append(problems, validateGoModuleManifest(path, rel, goModules)...)
		case "go.work", "go.work.sum":
			problems = append(problems, "Go workspace files are forbidden by the closed module inventory: "+rel)
		case "package.json":
			problems = append(problems, validateNodeManifest(path, rel, nodePackages, pnpmPackageManager)...)
		case "pnpm-lock.yaml":
			problems = append(problems, validatePNPMLock(path, rel, nodePackages)...)
		case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock", "bun.lockb", "pnpm-workspace.yaml", ".npmrc", ".pnpmfile.cjs", ".yarnrc", ".yarnrc.yml":
			problems = append(problems, "unreviewed or ambiguous Node lock/workspace file is forbidden: "+rel)
		}
		if strings.HasSuffix(info.Name(), ".go") {
			problems = append(problems, validateGoImports(path, rel, goModules)...)
		}
		if dependencyRuntimeFile(rel, info.Name()) {
			contents, readErr := os.ReadFile(path)
			if readErr != nil {
				problems = append(problems, "cannot read runtime dependency file: "+rel)
			} else {
				problems = append(problems, validateRuntimeReferences(rel, string(contents), allowedImages, allowedActions)...)
				if strings.HasPrefix(info.Name(), "Dockerfile") {
					problems = append(problems, validateDockerfileDependencies(rel, string(contents), allowedImages)...)
				}
			}
		}
		return nil
	})
	if err != nil {
		problems = append(problems, "actual dependency inventory walk failed: "+err.Error())
	}
	problems = append(problems, checkActualDependencyMutationTests(goModules, nodePackages, allowedImages, allowedActions)...)
	return problems
}

func lockedGoModulesFromVersionLock(lock any) map[string]lockedGoModule {
	result := make(map[string]lockedGoModule)
	for _, groupPath := range []string{"go_dependencies", "go_build_tools"} {
		value, ok := jsonValueAt(lock, groupPath)
		group, isObject := value.(map[string]any)
		if !ok || !isObject {
			continue
		}
		for _, raw := range group {
			component, isObject := raw.(map[string]any)
			if !isObject {
				continue
			}
			module, hasModule := component["module"].(string)
			version, hasVersion := component["version"].(string)
			if !hasModule || !hasVersion {
				continue
			}
			result[module] = lockedGoModule{
				Version: version, Sum: fmt.Sprint(component["module_sum"]), GoModSum: fmt.Sprint(component["go_mod_sum"]),
			}
		}
	}
	return result
}

func checkGoDependencyChecksumCoverage(root string) []string {
	versionRaw, err := os.ReadFile(filepath.Join(root, "architecture", "versions.json"))
	if err != nil {
		return []string{"missing architecture/versions.json for Go dependency checksum coverage"}
	}
	var lock any
	if err := json.Unmarshal(versionRaw, &lock); err != nil {
		return []string{"invalid architecture/versions.json for Go dependency checksum coverage: " + err.Error()}
	}
	goSumRaw, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return []string{"missing go.sum for Go dependency checksum coverage"}
	}
	goSum := string(goSumRaw)
	dependencies, ok := jsonValueAt(lock, "go_dependencies")
	if !ok {
		return []string{"version lock is missing go_dependencies for checksum coverage"}
	}
	components, ok := dependencies.(map[string]any)
	if !ok {
		return []string{"version lock go_dependencies is not an object for checksum coverage"}
	}
	var problems []string
	for componentName, rawComponent := range components {
		component, ok := rawComponent.(map[string]any)
		if !ok {
			problems = append(problems, "Go dependency lock component is not an object: "+componentName)
			continue
		}
		module, moduleOK := component["module"].(string)
		version, versionOK := component["version"].(string)
		sum, sumOK := component["module_sum"].(string)
		goModSum, goModSumOK := component["go_mod_sum"].(string)
		if !moduleOK || !versionOK || !sumOK || !goModSumOK {
			problems = append(problems, "Go dependency lock lacks checksum fields: "+componentName)
			continue
		}
		if !strings.Contains(goSum, module+" "+version+" "+sum) ||
			!strings.Contains(goSum, module+" "+version+"/go.mod "+goModSum) {
			problems = append(problems, "Go dependency exact checksum is absent from root go.sum: "+module+"@"+version)
		}
	}
	return problems
}

func lockedNodePackagesFromVersionLock(lock any) map[string]lockedNodePackage {
	paths := map[string]string{
		"react": "frontend.react", "react-dom": "frontend.react_dom", "@types/react": "frontend.react_types", "@types/react-dom": "frontend.react_dom_types", "typescript": "frontend.typescript",
		"esbuild": "frontend.esbuild", "ajv": "frontend.ajv", "ajv-formats": "frontend.ajv_formats",
		"fast-deep-equal":      "node_transitive_dependencies.fast_deep_equal",
		"fast-uri":             "node_transitive_dependencies.fast_uri",
		"json-schema-traverse": "node_transitive_dependencies.json_schema_traverse",
		"require-from-string":  "node_transitive_dependencies.require_from_string",
		"scheduler":            "node_transitive_dependencies.scheduler",
		"csstype":              "node_transitive_dependencies.csstype",
	}
	for _, component := range reviewedEsbuildPlatformPackages {
		paths[component.Package] = "node_transitive_dependencies." + component.Key
	}
	result := make(map[string]lockedNodePackage, len(paths))
	for packageName, path := range paths {
		version, versionOK := jsonValueAt(lock, path+".version")
		integrity, integrityOK := jsonValueAt(lock, path+".dist_integrity")
		if versionOK && integrityOK {
			result[packageName] = lockedNodePackage{Version: fmt.Sprint(version), Integrity: fmt.Sprint(integrity)}
		}
	}
	return result
}

func lockedPNPMPackageManagerFromVersionLock(lock any) string {
	version, versionOK := jsonValueAt(lock, "toolchains.pnpm.version")
	integrity, integrityOK := jsonValueAt(lock, "toolchains.pnpm.dist_integrity")
	if !versionOK || !integrityOK {
		return ""
	}
	encoded := strings.TrimPrefix(fmt.Sprint(integrity), "sha512-")
	digest, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(digest) != sha512DigestSize {
		return ""
	}
	return "pnpm@" + fmt.Sprint(version) + "+sha512." + hex.EncodeToString(digest)
}

const sha512DigestSize = 64

func lockedImagesFromVersionLock(lock any) map[string]bool {
	result := map[string]bool{"scratch": true}
	for _, path := range []string{
		"toolchains.go.build_image", "toolchains.node.build_image", "data_services.postgresql.image", "data_services.opensearch.image",
		"data_services.reverse_proxy.image", "data_services.built_in_idp.image", "data_services.embedding_runtime.image",
		"go_build_tools.syft.image", "go_build_tools.grype.image",
	} {
		if value, ok := jsonValueAt(lock, path); ok {
			result[fmt.Sprint(value)] = true
		}
	}
	return result
}

func lockedActionsFromVersionLock(lock any) map[string]bool {
	result := make(map[string]bool)
	for _, name := range []string{"checkout", "codeql_init", "codeql_analyze", "dependency_review"} {
		repository, repoOK := jsonValueAt(lock, "ci_actions."+name+".repository")
		commit, commitOK := jsonValueAt(lock, "ci_actions."+name+".source_commit")
		if repoOK && commitOK {
			result[fmt.Sprint(repository)+"@"+fmt.Sprint(commit)] = true
		}
	}
	return result
}

func parseGoModRequirements(contents string) map[string]string {
	result := make(map[string]string)
	inRequireBlock := false
	for _, line := range strings.Split(contents, "\n") {
		if index := strings.Index(line, "//"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if inRequireBlock {
			if fields[0] == ")" {
				inRequireBlock = false
				continue
			}
			if len(fields) >= 2 {
				result[fields[0]] = fields[1]
			}
			continue
		}
		if fields[0] != "require" {
			continue
		}
		if len(fields) == 2 && fields[1] == "(" {
			inRequireBlock = true
		} else if len(fields) >= 3 {
			result[fields[1]] = fields[2]
		}
	}
	return result
}

func validateGoModuleManifest(path, rel string, allowed map[string]lockedGoModule) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{"cannot read Go module manifest: " + rel}
	}
	contents := string(raw)
	var problems []string
	if goModuleHasForbiddenReplacement(contents) {
		problems = append(problems, "Go replace directive is forbidden by the closed module inventory: "+rel)
	}
	if !regexp.MustCompile(`(?m)^go 1\.26\.0\s*$`).MatchString(contents) || !regexp.MustCompile(`(?m)^toolchain go1\.26\.5\s*$`).MatchString(contents) {
		problems = append(problems, "Go module toolchain is not exact locked baseline: "+rel)
	}
	requirements := parseGoModRequirements(contents)
	sumContents := ""
	if len(requirements) > 0 {
		sumRaw, sumErr := os.ReadFile(filepath.Join(filepath.Dir(path), "go.sum"))
		if sumErr != nil {
			problems = append(problems, "Go module with dependencies has no go.sum: "+rel)
		} else {
			sumContents = string(sumRaw)
		}
	}
	for module, version := range requirements {
		locked, exists := allowed[module]
		if !exists {
			problems = append(problems, "actual Go module is absent from ACTIVE version inventory: "+rel+" -> "+module)
			continue
		}
		if version != locked.Version {
			problems = append(problems, fmt.Sprintf("actual Go module version mismatch %s -> %s: expected %s, got %s", rel, module, locked.Version, version))
		}
		if locked.Sum == "" || locked.GoModSum == "" ||
			!strings.Contains(sumContents, module+" "+version+" "+locked.Sum) ||
			!strings.Contains(sumContents, module+" "+version+"/go.mod "+locked.GoModSum) {
			problems = append(problems, "actual Go module checksum mismatch: "+rel+" -> "+module)
		}
	}
	return problems
}

func goModuleHasForbiddenReplacement(contents string) bool {
	return regexp.MustCompile(`(?m)^\s*replace(?:\s|\()`).MatchString(contents)
}

func goWorkspaceFileForbidden(name string) bool {
	return name == "go.work" || name == "go.work.sum"
}

func goVendoredSourceForbidden(name string) bool {
	return name == "vendor"
}

func validateGoImports(path, rel string, allowed map[string]lockedGoModule) []string {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return []string{"cannot parse Go imports for dependency inventory: " + rel}
	}
	var problems []string
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil || importPath == "" {
			continue
		}
		first := strings.Split(importPath, "/")[0]
		if !strings.Contains(first, ".") || strings.HasPrefix(importPath, "knowvault.local/") {
			continue
		}
		matched := false
		for module := range allowed {
			if importPath == module || strings.HasPrefix(importPath, module+"/") {
				matched = true
				break
			}
		}
		if !matched {
			problems = append(problems, "actual Go import is absent from ACTIVE version inventory: "+rel+" -> "+importPath)
		}
	}
	return problems
}

func validateNodeManifest(path, rel string, allowed map[string]lockedNodePackage, expectedPackageManager string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{"cannot read Node manifest: " + rel}
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return []string{"invalid Node manifest: " + rel + ": " + err.Error()}
	}
	var problems []string
	if nodeManifestHasForbiddenDependencyOverride(manifest) {
		problems = append(problems, "Node dependency overrides or patch hooks are forbidden by the exact lock baseline: "+rel)
	}
	if !nodeManifestPackageManagerExact(manifest, expectedPackageManager) {
		problems = append(problems, "Node packageManager does not exact-match locked pnpm version/integrity: "+rel)
	}
	manifestDependencies := make(map[string]string)
	for _, section := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		rawDependencies, exists := manifest[section]
		if !exists {
			continue
		}
		dependencies, isObject := rawDependencies.(map[string]any)
		if !isObject {
			problems = append(problems, "Node dependency section is not object: "+rel+" -> "+section)
			continue
		}
		for packageName, rawVersion := range dependencies {
			version := fmt.Sprint(rawVersion)
			if nodeWorkspaceDependencyForbidden(version) {
				problems = append(problems, "workspace Node dependencies are forbidden in the single-importer baseline: "+rel+" -> "+packageName)
				continue
			}
			if previous, duplicate := manifestDependencies[packageName]; duplicate && previous != version {
				problems = append(problems, "Node package has conflicting direct versions: "+rel+" -> "+packageName)
			}
			manifestDependencies[packageName] = version
			locked, allowedPackage := allowed[packageName]
			if !allowedPackage {
				problems = append(problems, "actual Node package is absent from ACTIVE version inventory: "+rel+" -> "+packageName)
			} else if version != locked.Version {
				problems = append(problems, fmt.Sprintf("actual Node package version mismatch %s -> %s: expected %s, got %s", rel, packageName, locked.Version, version))
			}
		}
	}
	lockPath := filepath.Join(filepath.Dir(path), "pnpm-lock.yaml")
	lockRaw, lockErr := os.ReadFile(lockPath)
	if lockErr != nil {
		problems = append(problems, "Node manifest has no sibling reviewed pnpm lock: "+rel)
	} else {
		importer, importerCount, importerProblems := parsePNPMRootImporter(string(lockRaw))
		problems = append(problems, importerProblems...)
		problems = append(problems, validatePNPMImporterBinding(manifestDependencies, importer, importerCount, rel)...)
		problems = append(problems, validatePNPMImporterResolution(importer, parsePNPMPackages(string(lockRaw)), allowed, rel)...)
	}
	return problems
}

func nodeManifestPackageManagerExact(manifest map[string]any, expected string) bool {
	packageManager, exists := manifest["packageManager"]
	return exists && expected != "" && packageManager == expected
}

func nodeWorkspaceDependencyForbidden(version string) bool {
	return strings.HasPrefix(version, "workspace:")
}

func nodeManifestHasForbiddenDependencyOverride(manifest map[string]any) bool {
	for _, key := range []string{"pnpm", "resolutions", "overrides"} {
		if _, exists := manifest[key]; exists {
			return true
		}
	}
	return false
}

type pnpmImporterEntry struct {
	Specifier string
	Version   string
}

func parsePNPMRootImporter(contents string) (map[string]pnpmImporterEntry, int, []string) {
	result := make(map[string]pnpmImporterEntry)
	lines := strings.Split(strings.ReplaceAll(contents, "\r\n", "\n"), "\n")
	inImporters := false
	inRoot := false
	inDependencySection := false
	currentPackage := ""
	importerCount := 0
	var problems []string
	for _, line := range lines {
		if line == "importers:" {
			inImporters = true
			continue
		}
		if inImporters && line == "packages:" {
			break
		}
		if !inImporters || strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trimmed := strings.TrimSpace(line)
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			importerCount++
			name := strings.Trim(strings.TrimSuffix(trimmed, ":"), "'\"")
			inRoot = name == "."
			inDependencySection = false
			currentPackage = ""
			continue
		}
		if !inRoot {
			continue
		}
		if indent == 4 && strings.HasSuffix(trimmed, ":") {
			section := strings.TrimSuffix(trimmed, ":")
			inDependencySection = section == "dependencies" || section == "devDependencies" || section == "peerDependencies" || section == "optionalDependencies"
			currentPackage = ""
			continue
		}
		if inDependencySection && indent == 6 && strings.HasSuffix(trimmed, ":") {
			currentPackage = strings.Trim(strings.TrimSuffix(trimmed, ":"), "'\"")
			if _, duplicate := result[currentPackage]; duplicate {
				problems = append(problems, "duplicate package in pnpm root importer: "+currentPackage)
			}
			result[currentPackage] = pnpmImporterEntry{}
			continue
		}
		if currentPackage != "" && indent == 8 {
			entry := result[currentPackage]
			if strings.HasPrefix(trimmed, "specifier: ") {
				entry.Specifier = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "specifier: ")), "'\"")
			} else if strings.HasPrefix(trimmed, "version: ") {
				entry.Version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "version: ")), "'\"")
			}
			result[currentPackage] = entry
		}
	}
	return result, importerCount, problems
}

func validatePNPMImporterBinding(manifest map[string]string, importer map[string]pnpmImporterEntry, importerCount int, rel string) []string {
	var problems []string
	if importerCount != 1 {
		problems = append(problems, fmt.Sprintf("pnpm lock must contain exactly one sibling root importer for %s: got %d", rel, importerCount))
	}
	for packageName, manifestVersion := range manifest {
		entry, exists := importer[packageName]
		if !exists || entry.Specifier != manifestVersion || (entry.Version != manifestVersion && !strings.HasPrefix(entry.Version, manifestVersion+"(")) {
			problems = append(problems, "Node manifest is not exact-bound to pnpm root importer: "+rel+" -> "+packageName)
		}
	}
	for packageName := range importer {
		if _, exists := manifest[packageName]; !exists {
			problems = append(problems, "pnpm root importer contains dependency absent from Node manifest: "+rel+" -> "+packageName)
		}
	}
	return problems
}

func validatePNPMImporterResolution(importer map[string]pnpmImporterEntry, packages []actualNodePackage, allowed map[string]lockedNodePackage, rel string) []string {
	var problems []string
	for packageName, entry := range importer {
		locked, exists := allowed[packageName]
		resolvedVersion := strings.SplitN(entry.Version, "(", 2)[0]
		if !exists || resolvedVersion != locked.Version {
			problems = append(problems, "pnpm importer resolves outside ACTIVE inventory: "+rel+" -> "+packageName)
			continue
		}
		matches := 0
		for _, packageEntry := range packages {
			if packageEntry.Name == packageName && packageEntry.Version == resolvedVersion && packageEntry.Integrity == locked.Integrity {
				matches++
			}
		}
		if matches != 1 {
			problems = append(problems, fmt.Sprintf("pnpm importer dependency must resolve to exactly one integrity-bound package %s -> %s: got %d", rel, packageName, matches))
		}
	}
	return problems
}

func parsePNPMPackages(contents string) []actualNodePackage {
	var result []actualNodePackage
	inPackages := false
	currentIndex := -1
	flush := func() {
		currentIndex = -1
	}
	for _, line := range strings.Split(contents, "\n") {
		if line == "packages:" {
			inPackages = true
			continue
		}
		if inPackages && line == "snapshots:" {
			break
		}
		if !inPackages {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			flush()
			key := strings.Trim(strings.TrimSuffix(strings.TrimSpace(line), ":"), "'\"")
			separator := strings.LastIndex(key, "@")
			if separator > 0 && separator < len(key)-1 {
				result = append(result, actualNodePackage{Name: key[:separator], Version: key[separator+1:]})
				currentIndex = len(result) - 1
			}
			continue
		}
		if currentIndex >= 0 && strings.Contains(line, "resolution:") && strings.Contains(line, "integrity:") {
			match := regexp.MustCompile(`integrity:\s*([^,}\s]+)`).FindStringSubmatch(line)
			if len(match) == 2 {
				result[currentIndex].Integrity = match[1]
			}
		}
	}
	return result
}

func validatePNPMLock(path, rel string, allowed map[string]lockedNodePackage) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{"cannot read pnpm lock: " + rel}
	}
	var problems []string
	if pnpmLockHasForbiddenOverride(string(raw)) {
		problems = append(problems, "pnpm lock contains forbidden override patch or catalog: "+rel)
	}
	problems = append(problems, validatePNPMPackages(parsePNPMPackages(string(raw)), rel, allowed)...)
	return problems
}

func pnpmLockHasForbiddenOverride(contents string) bool {
	return regexp.MustCompile(`(?m)^(?:patchedDependencies|overrides|packageExtensions|catalogs):\s*$`).MatchString(contents)
}

func validatePNPMPackages(actual []actualNodePackage, rel string, allowed map[string]lockedNodePackage) []string {
	var problems []string
	seen := make(map[string]bool)
	for _, packageLock := range actual {
		key := packageLock.Name + "@" + packageLock.Version
		if seen[key] {
			problems = append(problems, "duplicate actual pnpm package entry: "+rel+" -> "+key)
		}
		seen[key] = true
		locked, exists := allowed[packageLock.Name]
		if !exists {
			problems = append(problems, "actual pnpm package is absent from ACTIVE version inventory: "+rel+" -> "+packageLock.Name)
		} else if packageLock.Version != locked.Version || packageLock.Integrity != locked.Integrity {
			problems = append(problems, "actual pnpm package version/integrity mismatch: "+rel+" -> "+packageLock.Name)
		}
	}
	return problems
}

func dependencyRuntimeFile(rel, name string) bool {
	normalized := filepath.ToSlash(rel)
	return strings.HasPrefix(normalized, ".github/workflows/") || strings.HasPrefix(normalized, ".github/actions/") || strings.HasPrefix(normalized, "deploy/") ||
		strings.HasPrefix(normalized, "infra/") || strings.HasPrefix(name, "Dockerfile") ||
		name == "compose.yaml" || name == "compose.yml" || name == "docker-compose.yaml" || name == "docker-compose.yml"
}

func validateRuntimeReferences(rel, contents string, allowedImages, allowedActions map[string]bool) []string {
	var problems []string
	imageCandidates := make(map[string]bool)
	exactImagePattern := regexp.MustCompile(`[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}`)
	for _, image := range exactImagePattern.FindAllString(contents, -1) {
		imageCandidates[image] = true
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*FROM(?:\s+--platform=[^\s]+)?\s+([^\s]+)`),
		regexp.MustCompile(`(?m)^\s*image:\s*["']?([^"'\s#]+)`),
		regexp.MustCompile(`(?m)^\s*[A-Z][A-Z0-9_]*_IMAGE:\s*["']?([^"'\s#]+)`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(contents, -1) {
			if len(match) == 2 {
				imageCandidates[match[1]] = true
			}
		}
	}
	for image := range imageCandidates {
		if !allowedImages[image] {
			problems = append(problems, "actual OCI image is absent from ACTIVE version inventory: "+rel+" -> "+image)
		}
	}
	actionPattern := regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)`)
	for _, match := range actionPattern.FindAllStringSubmatch(contents, -1) {
		action := strings.Trim(match[1], "'\"")
		if strings.HasPrefix(action, "./") {
			problems = append(problems, "local GitHub Action dependency is forbidden until separately locked: "+rel+" -> "+action)
			continue
		}
		if strings.HasPrefix(action, "docker://") {
			image := strings.TrimPrefix(action, "docker://")
			if !allowedImages[image] {
				problems = append(problems, "actual action OCI image is absent from ACTIVE version inventory: "+rel+" -> "+image)
			}
			continue
		}
		if !allowedActions[action] {
			problems = append(problems, "actual CI action is absent from ACTIVE version inventory: "+rel+" -> "+action)
		}
	}
	return problems
}

func validateDockerfileDependencies(rel, contents string, allowedImages map[string]bool) []string {
	var problems []string
	aliases := make(map[string]bool)
	fromPattern := regexp.MustCompile(`(?mi)^\s*FROM(?:\s+--platform=[^\s]+)?\s+([^\s]+)(?:\s+AS\s+([^\s]+))?`)
	for _, match := range fromPattern.FindAllStringSubmatch(contents, -1) {
		if len(match) > 2 && match[2] != "" {
			aliases[strings.ToLower(match[2])] = true
		}
	}
	remoteFromPattern := regexp.MustCompile(`(?mi)(?:^\s*COPY\s+--from=|--mount=[^\r\n]*\bfrom=)([^,\s]+)`)
	for _, match := range remoteFromPattern.FindAllStringSubmatch(contents, -1) {
		from := strings.Trim(match[1], "'\"")
		if _, numericErr := strconv.Atoi(from); numericErr == nil || aliases[strings.ToLower(from)] {
			continue
		}
		if !allowedImages[from] {
			problems = append(problems, "Docker remote stage is absent from ACTIVE image inventory: "+rel+" -> "+from)
		}
	}
	if regexp.MustCompile(`(?mi)^\s*ADD\s+(?:--[^\s]+\s+)*["']?https?://`).MatchString(contents) {
		problems = append(problems, "Docker remote ADD is forbidden: "+rel)
	}
	forbiddenInstaller := regexp.MustCompile(`(?i)\b(curl|wget|git\s+clone|go\s+install|pip[0-9]*\s+install|npm\s+(?:install|ci)|pnpm\s+install|yarn\s+install|apt-get|apt\s+install|apk\s+add|dnf\s+install|yum\s+install)\b`)
	inRun := false
	for _, line := range strings.Split(strings.ReplaceAll(contents, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "RUN ") || strings.HasPrefix(upper, "RUN\t") {
			inRun = true
		}
		if inRun && forbiddenInstaller.MatchString(trimmed) {
			problems = append(problems, "Docker network installer is forbidden; use reviewed offline inputs: "+rel)
			inRun = false
		}
		if inRun && !strings.HasSuffix(trimmed, "\\") {
			inRun = false
		}
	}
	return problems
}

func checkActualDependencyMutationTests(goModules map[string]lockedGoModule, nodePackages map[string]lockedNodePackage, allowedImages, allowedActions map[string]bool) []string {
	var problems []string
	unknownGo := parseGoModRequirements("module example.local/m\n\ngo 1.26.0\n\ntoolchain go1.26.5\n\nrequire github.com/example/unreviewed v1.2.3\n")
	if _, allowed := goModules["github.com/example/unreviewed"]; allowed || unknownGo["github.com/example/unreviewed"] == "" {
		problems = append(problems, "architecture.supply.unknown-go-module mutation setup failed")
	} else {
		problems = append(problems, assertUnknownGoDependencyRejected(unknownGo, goModules)...)
	}
	if !goModuleHasForbiddenReplacement("module example.local/m\nreplace golang.org/x/text => ../unreviewed\n") || !goWorkspaceFileForbidden("go.work") || !goVendoredSourceForbidden("vendor") {
		problems = append(problems, "architecture.supply.go-replace-or-workspace mutation was accepted")
	}
	unknownPackage := `{"dependencies":{"unreviewed-mit-helper":"1.2.3"}}`
	var manifest map[string]any
	_ = json.Unmarshal([]byte(unknownPackage), &manifest)
	if !nodeManifestMapRejectsUnknown(manifest, nodePackages) {
		problems = append(problems, "architecture.supply.unknown-node-package mutation was accepted")
	}
	if nodeManifestPackageManagerExact(manifest, lockedPNPMReferenceForMutation()) || !nodeWorkspaceDependencyForbidden("workspace:*") ||
		!nodeManifestHasForbiddenDependencyOverride(map[string]any{"overrides": map[string]any{"ajv": "file:../evil"}}) ||
		!pnpmLockHasForbiddenOverride("patchedDependencies:\n  ajv@8.20.0: patches/evil.patch\n") {
		problems = append(problems, "architecture.supply.node-unbound-manifest mutation was accepted")
	}
	if len(validatePNPMImporterBinding(map[string]string{"ajv": "8.20.0"}, map[string]pnpmImporterEntry{}, 1, "mutated/package.json")) == 0 {
		problems = append(problems, "architecture.supply.node-unbound-manifest mutation was accepted")
	}
	if len(validatePNPMImporterResolution(map[string]pnpmImporterEntry{"ajv": {Specifier: "8.20.0", Version: "8.20.0"}}, nil, nodePackages, "mutated/package.json")) == 0 {
		problems = append(problems, "architecture.supply.node-unbound-manifest mutation was accepted")
	}
	wrongPNPM := "packages:\n\n  ajv@8.20.0:\n    resolution: {integrity: sha512-WRONG==}\n\nsnapshots:\n"
	actual := parsePNPMPackages(wrongPNPM)
	if len(actual) != 1 || actual[0].Name != "ajv" || actual[0].Integrity == nodePackages["ajv"].Integrity {
		problems = append(problems, "architecture.supply.pnpm-integrity-mismatch mutation setup failed")
	} else if len(validatePNPMPackages(actual, "mutated/pnpm-lock.yaml", nodePackages)) == 0 {
		problems = append(problems, "architecture.supply.pnpm-integrity-mismatch mutation was accepted")
	}
	if len(validateRuntimeReferences("deploy/mutated.yaml", "image: evil.example/unreviewed:1.0@sha256:"+strings.Repeat("a", 64), allowedImages, allowedActions)) == 0 {
		problems = append(problems, "architecture.supply.unknown-oci-image mutation was accepted")
	}
	if len(validateRuntimeReferences(".github/workflows/mutated.yml", "steps:\n  - uses: evil/example@"+strings.Repeat("b", 40), allowedImages, allowedActions)) == 0 {
		problems = append(problems, "architecture.supply.unknown-ci-action mutation was accepted")
	}
	if len(validateDockerfileDependencies("Dockerfile.mutated", "FROM scratch\nCOPY --from=evil.example/tool:1 /tool /tool\nADD https://evil.example/install.sh /tmp/install.sh\n", allowedImages)) == 0 {
		problems = append(problems, "architecture.supply.docker-remote-dependency mutation was accepted")
	}
	if len(validateRuntimeReferences(".github/workflows/mutated.yml", "steps:\n  - uses: ./tools/unreviewed-action\n", allowedImages, allowedActions)) == 0 {
		problems = append(problems, "architecture.supply.local-action-dependency mutation was accepted")
	}
	return problems
}

func lockedPNPMReferenceForMutation() string {
	return "pnpm@11.4.0+sha512." + strings.Repeat("0", 128)
}

func assertUnknownGoDependencyRejected(requirements map[string]string, allowed map[string]lockedGoModule) []string {
	for module := range requirements {
		if _, exists := allowed[module]; !exists {
			return nil
		}
	}
	return []string{"architecture.supply.unknown-go-module mutation was accepted"}
}

func nodeManifestMapRejectsUnknown(manifest map[string]any, allowed map[string]lockedNodePackage) bool {
	for _, section := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"} {
		dependencies, _ := manifest[section].(map[string]any)
		for packageName := range dependencies {
			if _, exists := allowed[packageName]; !exists {
				return true
			}
		}
	}
	return false
}

// parserSandboxCore is the one package that owns the hardened process boundary every
// isolated parser runs behind. Its import list is an allowlist, not a denylist: a
// package that cannot import a database, audit, job, secret, filesystem or network
// package cannot hand any of those capabilities to a hostile data-plane component,
// whatever a future caller intends. os/exec is the one capability it holds, and only
// to spawn the pinned sandbox command.
const parserSandboxCore = "internal/source/sandbox"

var parserSandboxCoreImports = map[string]bool{
	"bytes": true, "context": true, "errors": true, "io": true,
	"os/exec": true, "time": true,
}

// parserSandboxFacades are the per-parser typed boundaries over that core. Each is
// checked only if it exists, so the PDF and OCR invokers inherit this boundary the
// moment they land rather than needing a remembered follow-up. A façade's allowlist
// is the shared base plus its own re-validator: it may not reach another parser's,
// and it may not hold os/exec — spawning belongs to the core alone, which is what
// keeps the hardening single-sourced.
var parserSandboxFacades = []struct{ dir, revalidator string }{
	{"internal/source/docworker", "internal/source/docparser"},
	{"internal/source/pdfworker", "internal/source/pdfparser"},
	{"internal/source/ocrworker", "internal/source/ocrparser"},
}

var parserSandboxFacadeBaseImports = map[string]bool{
	"context": true, "errors": true, "strconv": true, "time": true,
	"knowvault.local/verified-workspace/" + parserSandboxCore: true,
}

// parserSandboxCoreMarkers are asserted in the core and nowhere else. One
// implementation cannot hold for Office and quietly lapse for OCR.
var parserSandboxCoreMarkers = map[string]string{
	"command.Env = []string{}": "the sandbox must not inherit the runtime environment",
	"context.WithTimeout":      "the sandbox must be bounded by a wall clock",
	"&boundedWriter{limit:":    "both sandbox streams must be bounded",
	"command.WaitDelay":        "a sandbox that ignores its kill must not hold the worker",
	"kind != r.config.Kind":    "a sandbox pinned for one parser must refuse another parser's work",
}

// checkParserSandboxBoundary enforces ADR-0062 §2a/§2d and ADR-0063 §2 on the Go side
// of every isolated parser: the core holds no authority to give away, empties the
// environment, bounds both streams and enforces its wall clock; each façade adds only
// its protocol and re-checks the pinned artifact identity; and the ingestion runtime
// reaches all of it only through that boundary, never by spawning a process itself.
func checkParserSandboxBoundary(root string) []string {
	dirs := []string{parserSandboxCore}
	for _, facade := range parserSandboxFacades {
		dirs = append(dirs, facade.dir)
	}
	contents, problems := loadGoPackageSources(root, dirs)
	return append(problems, checkParserSandboxBoundaryContents(contents)...)
}

func checkParserSandboxBoundaryContents(contents map[string]string) []string {
	var problems []string

	core, ok := contents[parserSandboxCore+"/sandbox.go"]
	if !ok {
		return []string{"missing the shared parser sandbox core: " + parserSandboxCore + "/sandbox.go"}
	}
	for marker, requirement := range parserSandboxCoreMarkers {
		if !strings.Contains(core, marker) {
			problems = append(problems, "parser sandbox core weakened ("+requirement+"): missing "+marker)
		}
	}
	problems = append(problems, assertGoImportAllowlist(contents, parserSandboxCore, parserSandboxCoreImports,
		"parser sandbox core imports outside its closed allowlist")...)

	for _, facade := range parserSandboxFacades {
		if !goPackagePresent(contents, facade.dir) {
			continue
		}
		allowed := make(map[string]bool, len(parserSandboxFacadeBaseImports)+1)
		for importPath := range parserSandboxFacadeBaseImports {
			allowed[importPath] = true
		}
		allowed["knowvault.local/verified-workspace/"+facade.revalidator] = true
		problems = append(problems, assertGoImportAllowlist(contents, facade.dir, allowed,
			"parser sandbox façade imports outside its closed allowlist")...)

		var facadeSource strings.Builder
		for path, source := range contents {
			if strings.HasPrefix(path, facade.dir+"/") && !strings.HasSuffix(path, "_test.go") {
				facadeSource.WriteString(source)
			}
		}
		source := facadeSource.String()
		for marker, requirement := range map[string]string{
			"sandbox.New(":   "a parser façade must run behind the shared sandbox core",
			"ArtifactHash()": "the sandbox result must match the pinned artifact identity",
		} {
			if !strings.Contains(source, marker) {
				problems = append(problems, "parser sandbox façade weakened ("+requirement+"): "+facade.dir+" is missing "+marker)
			}
		}
	}
	return problems
}

// sandboxDispatcherTrees are the dispatcher boundary: the broker core, its
// production composition and the fourth binary. The gate keeps the closed
// capability of ADR-0068 — the dispatcher leases documents to registered sockets
// and never creates a container or invokes a container runtime.
var sandboxDispatcherTrees = []string{
	"internal/sandboxdispatch",
	"internal/platform/dispatchercomposition",
	"cmd/sandbox-dispatcher",
}

// sandboxDispatcherCoreImports is the closed import allowlist of the broker core.
// Database, audit, jobs, network-server and process-spawn packages are absent on
// purpose: the core cannot reach any application authority.
var sandboxDispatcherCoreImports = map[string]bool{
	"bytes": true, "context": true, "crypto/sha256": true,
	"encoding/binary": true, "encoding/hex": true, "encoding/json": true,
	"encoding/json/jsontext": true, "encoding/json/v2": true,
	"errors": true, "fmt": true, "io": true, "net": true, "os": true,
	"path/filepath": true, "regexp": true, "strconv": true, "strings": true,
	"sync": true, "time": true,
}

// sandboxDispatcherLinuxObserverImports extends the core allowlist with the two
// kernel-surface imports permitted only in the exact Linux peer-observation,
// SCM_RIGHTS handoff and socket-ownership files. The capability scan below
// denies the syscall/unsafe token surface anywhere else.
var sandboxDispatcherLinuxObserverImports = map[string]bool{
	"bufio": true, "context": true, "crypto/sha256": true,
	"encoding/binary": true, "encoding/hex": true, "encoding/json": true,
	"encoding/json/jsontext": true, "encoding/json/v2": true,
	"errors": true, "fmt": true, "io": true, "net": true, "os": true,
	"path/filepath": true, "regexp": true, "strconv": true, "strings": true,
	"sync": true, "syscall": true, "time": true, "unsafe": true,
	"golang.org/x/sys/unix": true,
}

// Status publication has its own file-scoped surface. Random epochs and atomic
// status-file operations must not widen the broker's general import authority.
var sandboxDispatcherStatusImports = map[string]bool{
	"crypto/rand": true, "encoding/hex": true, "encoding/json": true,
	"errors": true, "path": true, "regexp": true, "time": true,
}

var sandboxDispatcherLinuxStatusImports = map[string]bool{
	"crypto/rand": true, "encoding/hex": true, "errors": true, "os": true,
	"path": true, "strings": true, "sync": true, "golang.org/x/sys/unix": true,
}

// sandboxDispatcherCompositionImports is the closed allowlist of the production
// composition; the only application capability it may acquire is the broker.
var sandboxDispatcherCompositionImports = map[string]bool{
	"context": true, "errors": true, "os": true, "strconv": true,
	"strings": true, "sync": true, "time": true,
	"knowvault.local/verified-workspace/internal/sandboxdispatch": true,
}

// sandboxDispatcherMainImports is the closed allowlist of the fourth binary.
var sandboxDispatcherMainImports = map[string]bool{
	"context": true, "log/slog": true, "os": true,
	"knowvault.local/verified-workspace/internal/platform/buildinfo":             true,
	"knowvault.local/verified-workspace/internal/platform/dispatchercomposition": true,
	"knowvault.local/verified-workspace/internal/platform/lifecycle":             true,
}

// sandboxDispatcherCoreMarkers prove the closed protocol and the supervisor
// semantics in the core and nowhere else. A drifted or removed marker is a
// weakened boundary, not a style note.
var sandboxDispatcherCoreMarkers = map[string]string{
	"internal/sandboxdispatch/wire.go":                   `j.ContainerCreationCap != "FORBIDDEN"`,
	"internal/sandboxdispatch/wire.go#contract":          `j.OutputContract != OutputContractV1`,
	"internal/sandboxdispatch/dispatch.go#observe":       `d.cfg.Observer.Observe(conn)`,
	"internal/sandboxdispatch/dispatch.go#digest":        `"sha256:"+hex.EncodeToString(digest[:]) != job.InputArtifact.ContentDigest`,
	"internal/sandboxdispatch/dispatch.go#deadline":      `time.AfterFunc(time.Until(deadlineAt), func() { d.expire(active, true) })`,
	"internal/sandboxdispatch/dispatch.go#kill":          `active.obs.PID > 0 && (deadlineFired || active.transferSent)`,
	"internal/sandboxdispatch/dispatch.go#killcall":      `d.cfg.Killer.Kill(active.obs)`,
	"internal/sandboxdispatch/dispatch.go#inversion":     `reportedAt.After(active.deadlineAt()) || reportedAt.Before(active.issuedAt())`,
	"internal/sandboxdispatch/dispatch.go#selfidentity":  `*outcome.ExtractionIdentity != d.extractionIdentityLocked(active)`,
	"internal/sandboxdispatch/dispatch.go#rebind":        `if taken {`,
	"internal/sandboxdispatch/dispatch.go#method":        `ObservationMethod:  "KERNEL_CGROUP_NAMESPACE"`,
	"internal/sandboxdispatch/dispatch.go#registry":      `!taken || existing == nil`,
	"internal/sandboxdispatch/observer_linux.go#recheck": `current != obs.CgroupPath`,
	"internal/sandboxdispatch/lease.go#handoff":          `if l.transferSent {`,
	"internal/sandboxdispatch/limits.go#identity":        `func CanonicalLimitsIdentity(`,
}

// sandboxDispatcherCompositionMarkers prove the production composition is the
// role-separated DispatcherV2. V2 acquires the fixed kernel observer and
// supervisor internally; composition must not silently fall back to the legacy
// single-socket broker.
var sandboxDispatcherCompositionMarkers = map[string]string{
	"internal/platform/dispatchercomposition/runtime.go":       `sandboxdispatch.NewV2(config.v2Config())`,
	"internal/platform/dispatchercomposition/runtime.go#close": `runtime.state.broker.Close()`,
}

// sandboxDispatcherMainMarkers prove the binary goes through the composition root.
var sandboxDispatcherMainMarkers = map[string]string{
	"cmd/sandbox-dispatcher/main.go": `dispatchercomposition.LoadProduction()`,
}

// checkSandboxDispatcherBoundary keeps the dispatcher on its closed capability:
// strict wire decoding, kernel-observed limits, the supervisor-owned deadline and
// no container-runtime reachability (SAN-001..SAN-004, ADR-0068 R-7..R-11).
func checkSandboxDispatcherBoundary(root string) []string {
	contents, problems := loadGoPackageSources(root, sandboxDispatcherTrees)
	return append(problems, checkSandboxDispatcherBoundaryContents(contents)...)
}

func checkSandboxDispatcherBoundaryContents(contents map[string]string) []string {
	var problems []string
	coreDir := sandboxDispatcherTrees[0]

	if _, ok := contents[coreDir+"/dispatch.go"]; !ok {
		problems = append(problems, "missing the sandbox dispatcher core: "+coreDir+"/dispatch.go")
	}
	// The linux peer-credential file carries the kernel syscall surface; the rest
	// of the core must stay on the plain allowlist (fail-closed: syscall imported
	// but unused elsewhere would otherwise slip past the token scan).
	coreContents := make(map[string]string, len(contents))
	linuxKernelContents := make(map[string]string, 6)
	statusContents := make(map[string]string, 1)
	linuxStatusContents := make(map[string]string, 1)
	linuxKernelFiles := map[string]bool{
		coreDir + "/observer_linux.go":       true,
		coreDir + "/v2_handoff_linux.go":     true,
		coreDir + "/v2_paths_linux.go":       true,
		coreDir + "/v2_peer_linux.go":        true,
		coreDir + "/v2_peer_linux_test.go":   true,
		coreDir + "/v2_supervisor_linux.go":  true,
		coreDir + "/v2_status_linux_test.go": true,
	}
	for rel, source := range contents {
		if strings.HasPrefix(rel, coreDir+"/") {
			if rel == coreDir+"/v2_status.go" {
				statusContents[rel] = source
			} else if rel == coreDir+"/v2_status_linux.go" {
				linuxStatusContents[rel] = source
			} else if linuxKernelFiles[rel] {
				linuxKernelContents[rel] = source
			} else {
				coreContents[rel] = source
			}
		}
	}
	problems = append(problems, assertGoImportAllowlist(coreContents, coreDir, sandboxDispatcherCoreImports,
		"sandbox dispatcher core imports outside its closed allowlist")...)
	problems = append(problems, assertGoImportAllowlist(linuxKernelContents, coreDir, sandboxDispatcherLinuxObserverImports,
		"sandbox dispatcher linux observer imports outside its closed allowlist")...)
	problems = append(problems, assertGoImportAllowlist(statusContents, coreDir, sandboxDispatcherStatusImports,
		"sandbox dispatcher status imports outside its closed allowlist")...)
	problems = append(problems, assertGoImportAllowlist(linuxStatusContents, coreDir, sandboxDispatcherLinuxStatusImports,
		"sandbox dispatcher linux status imports outside its closed allowlist")...)
	problems = append(problems, assertGoImportAllowlist(contents, "internal/platform/dispatchercomposition", sandboxDispatcherCompositionImports,
		"sandbox dispatcher composition imports outside its closed allowlist")...)
	problems = append(problems, assertGoImportAllowlist(contents, "cmd/sandbox-dispatcher", sandboxDispatcherMainImports,
		"sandbox dispatcher binary imports outside its closed allowlist")...)

	for key, marker := range sandboxDispatcherCoreMarkers {
		path := strings.SplitN(key, "#", 2)[0]
		source, ok := contents[path]
		if !ok || !strings.Contains(source, marker) {
			problems = append(problems, "sandbox dispatcher core weakened: missing "+marker+" in "+path)
		}
	}
	for key, marker := range sandboxDispatcherCompositionMarkers {
		path := strings.SplitN(key, "#", 2)[0]
		source, ok := contents[path]
		if !ok || !strings.Contains(source, marker) {
			problems = append(problems, "sandbox dispatcher composition weakened: missing "+marker+" in "+path)
		}
	}
	if source := contents["internal/platform/dispatchercomposition/runtime.go"]; strings.Contains(source, "sandboxdispatch.New(") {
		problems = append(problems, "sandbox dispatcher composition weakened: legacy v1 broker is still constructed")
	}
	for key, marker := range sandboxDispatcherMainMarkers {
		path := strings.SplitN(key, "#", 2)[0]
		source, ok := contents[path]
		if !ok || !strings.Contains(source, marker) {
			problems = append(problems, "sandbox dispatcher binary weakened: missing "+marker+" in "+path)
		}
	}

	// Capability-deny: no container-runtime token and no process spawn may appear
	// anywhere in the boundary, including tests — the gate is not optional there.
	// syscall/unsafe are permitted only in the linux peer-credential file.
	for _, rel := range sortedKeys(contents) {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		source := contents[rel]
		for _, token := range []string{"docker", "podman", "runc", "containerd", "nspawn", "crictl", "os/exec", "exec.Command"} {
			if strings.Contains(source, token) {
				problems = append(problems, "sandbox dispatcher capability token forbidden: "+rel+" contains "+token)
			}
		}
		if strings.Contains(source, "syscall.") || strings.Contains(source, "unsafe.") {
			if !linuxKernelFiles[rel] {
				problems = append(problems, "sandbox dispatcher kernel syscall surface outside the linux observer: "+rel)
			}
		}
	}
	return problems
}

// checkV2TestOnlyBoundary forbids a production-compiled TestOnly escape. Test
// helpers may still use that word in _test.go files, but the dispatcher core and
// every composition root must have one fail-closed Linux identity path.
func checkV2TestOnlyBoundary(root string) []string {
	var problems []string
	for _, subtree := range []string{"internal", "cmd"} {
		_ = walkDir(filepath.Join(root, subtree), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			rel := filepath.ToSlash(relative(root, path))
			raw, err := os.ReadFile(path)
			if err == nil && strings.Contains(string(raw), "TestOnly") {
				problems = append(problems, "sandbox dispatcher TestOnly escape used by production code: "+rel)
			}
			return nil
		})
	}
	return problems
}

const documentParserMain = "workers/document-parser/src/main/java/local/knowvault/docparser/Main.java"

// checkDocumentParserEntrypointBoundary keeps the released JAR on the same
// one-shot authority boundary as dispatcher v2. A legacy stdin/format CLI would
// remain callable from the production image even if Go composition never used
// it, so source shape and behavior tests both make that bypass load-bearing.
func checkDocumentParserEntrypointBoundary(root string) []string {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(documentParserMain)))
	if err != nil {
		return []string{"document parser production entrypoint is missing or unreadable"}
	}
	return checkDocumentParserEntrypointContents(string(raw))
}

func checkDocumentParserEntrypointContents(source string) []string {
	var problems []string
	for _, marker := range []string{"DispatcherArguments.parse(args)", "OneShotParserWorker.run("} {
		if !strings.Contains(source, marker) {
			problems = append(problems, "document parser entrypoint is not dispatcher-once: missing "+marker)
		}
	}
	for _, forbidden := range []string{"System.in", "case \"format\"", "isDispatcherMode", "--observation-profile-revision"} {
		if strings.Contains(source, forbidden) {
			problems = append(problems, "document parser direct CLI bypass is forbidden: "+forbidden)
		}
	}
	return problems
}

// checkIngestionSpawnBoundary keeps the ingestion runtime on the far side of the
// sandbox: it may reach a parser only through a façade, never by spawning a process.
func checkIngestionSpawnBoundary(root string) []string {
	var problems []string
	_ = walkDir(filepath.Join(root, "internal", "ingestion"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, spec := range parsed.Imports {
			importPath, _ := strconv.Unquote(spec.Path.Value)
			if importPath == "os/exec" {
				problems = append(problems, "the ingestion runtime may not spawn a process directly: "+filepath.ToSlash(relative(root, path)))
			}
		}
		return nil
	})
	return problems
}

// extractionIdentityMarkers prove the isolated worker's identity reaches the
// immutable extraction identity (ADR-0062 §2f, PARSER_CONTRACTS.md §6). Without this
// binding a new worker image under an unchanged parser_profile_revision leaves
// profile_hash equal, the "already extracted" short-circuit fires, and the platform
// keeps serving Evidence attributed to a build that no longer exists.
var extractionIdentityMarkers = map[string]struct {
	pattern     *regexp.Regexp
	requirement string
}{
	"internal/source/canon/hash.go": {
		regexp.MustCompile(`Observer\s+\*ObserverIdentity`),
		"the extraction profile must be able to carry the observing sandbox",
	},
	"internal/source/canon/hash.go#compose": {
		regexp.MustCompile(`CompositeArtifactHash\(p\.ArtifactHash,\s*\*p\.Observer\)`),
		"the observer must compose into the extractor artifact hash",
	},
	"internal/ingestion/pipeline.go": {
		regexp.MustCompile(`ParserRevision:\s*parserRevision,\s*Observer:\s*observer`),
		"the extraction profile must be built with the observer the parser returned",
	},
	"internal/ingestion/pipeline.go#require": {
		regexp.MustCompile(`observerRequired\(formatRevision\)\s*!=\s*\(observer\s*!=\s*nil\)`),
		"a worker-backed format must fail closed if it lost its observer identity",
	},
}

func checkExtractionIdentityBinding(root string) []string {
	contents, problems := loadNamedSources(root, []string{
		"internal/source/canon/hash.go",
		"internal/ingestion/pipeline.go",
	})
	return append(problems, checkExtractionIdentityBindingContents(contents)...)
}

func checkExtractionIdentityBindingContents(contents map[string]string) []string {
	var problems []string
	for key, marker := range extractionIdentityMarkers {
		path := strings.SplitN(key, "#", 2)[0]
		source, ok := contents[path]
		if !ok {
			problems = append(problems, "missing extraction identity source: "+path)
			continue
		}
		if !marker.pattern.MatchString(source) {
			problems = append(problems, "extraction identity binding weakened ("+marker.requirement+"): "+path)
		}
	}
	return problems
}

// loadGoPackageSources reads every Go file of the named package directories, keyed by
// slash-relative path. A directory that does not exist contributes nothing, which is
// how a boundary can be declared for a parser that has not landed yet.
func loadGoPackageSources(root string, dirs []string) (map[string]string, []string) {
	contents := make(map[string]string)
	var problems []string
	for _, dir := range dirs {
		_ = walkDir(filepath.Join(root, filepath.FromSlash(dir)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
				return nil
			}
			rel := filepath.ToSlash(relative(root, path))
			raw, err := os.ReadFile(path)
			if err != nil {
				problems = append(problems, "unreadable parser sandbox source: "+rel)
				return nil
			}
			contents[rel] = string(raw)
			return nil
		})
	}
	return contents, problems
}

func loadNamedSources(root string, paths []string) (map[string]string, []string) {
	contents := make(map[string]string)
	var problems []string
	for _, rel := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			problems = append(problems, "unreadable source: "+rel)
			continue
		}
		contents[rel] = string(raw)
	}
	return contents, problems
}

func goPackagePresent(contents map[string]string, dir string) bool {
	for path := range contents {
		if strings.HasPrefix(path, dir+"/") && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			return true
		}
	}
	return false
}

func assertGoImportAllowlist(contents map[string]string, dir string, allowed map[string]bool, message string) []string {
	var problems []string
	for _, rel := range sortedKeys(contents) {
		if !strings.HasPrefix(rel, dir+"/") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), rel, contents[rel], parser.ImportsOnly)
		if err != nil {
			problems = append(problems, "cannot parse imports in "+rel+": "+err.Error())
			continue
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if !allowed[importPath] {
				problems = append(problems, message+": "+rel+" -> "+importPath)
			}
		}
	}
	return problems
}

// productionTreePrefixes are the trees a QUALIFIED_NOT_ACTIVE component must stay
// out of: application source, deployment manifests and the API/DB surface.
var productionTreePrefixes = []string{"cmd/", "internal/", "web/", "api/", "db/", "deploy/", ".github/"}

// isolatedWorkerFileTypes is the default-deny allowlist for an isolated worker
// subtree. Application source languages are absent on purpose: a subtree that
// carries no Go/TypeScript/SQL cannot be imported by the application at all, which
// is what makes "unreachable from production" a structural property rather than a
// promise. Build/dependency descriptors, worker source, test corpora, pinned digest
// files and documentation are what remains.
var isolatedWorkerFileTypes = map[string]bool{
	".java": true, ".py": true, ".xml": true, ".properties": true, ".json": true, ".md": true,
	".txt": true, ".sha256": true, ".docx": true, ".pptx": true, ".xlsx": true,
	".yaml": true, ".yml": true, ".sh": true,
}

// checkSupplyChainLifecycleBoundary proves the QUALIFIED_NOT_ACTIVE contract for
// every component that declares it. One reusable boundary serves POI now and PDFBox
// and Tesseract later: each declares its own isolated subtree and tokens in
// architecture/versions.json and gets exactly these checks, so no per-component
// exception is ever written into the leak scan and none has to be remembered and
// removed later.
func checkSupplyChainLifecycleBoundary(root string) []string {
	isolations, problems := qualifiedIsolationsFromLock(root)
	declaredSubtrees := make(map[string]bool)

	for id, isolation := range isolations {
		subtree := isolation.IsolatedSubtree
		switch {
		case subtree == "" || !strings.HasSuffix(subtree, "/"):
			problems = append(problems, "isolated subtree must be a directory path ending in '/': "+id)
			continue
		case strings.HasPrefix(subtree, "/") || strings.Contains(subtree, "..") || strings.Contains(subtree, "\\"):
			problems = append(problems, "isolated subtree must be a clean repository-relative path: "+id+" -> "+subtree)
			continue
		}
		for _, production := range productionTreePrefixes {
			if strings.HasPrefix(subtree, production) {
				problems = append(problems, "isolated subtree may not live inside a production tree: "+id+" -> "+subtree)
			}
		}
		declaredSubtrees[subtree] = true

		if !isExactComponentVersion("", isolation.ExactVersion) {
			problems = append(problems, "QUALIFIED_NOT_ACTIVE component has no exact version: "+id+" -> "+isolation.ExactVersion)
		}
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(isolation.Evidence))); err != nil || info.IsDir() {
			problems = append(problems, "qualification evidence document is missing: "+id+" -> "+isolation.Evidence)
		}
		// A qualified id must appear exactly twice in the lock — once in the runtime
		// components list, once in its stage gate — and nowhere else. An id that also
		// appeared in an ACTIVE inventory group would be activated-in-fact.
		problems = append(problems, checkQualifiedIDNotActive(root, id)...)

		subtreeRoot := filepath.Join(root, filepath.FromSlash(subtree))
		info, err := os.Stat(subtreeRoot)
		if err != nil || !info.IsDir() {
			problems = append(problems, "declared isolated subtree does not exist: "+id+" -> "+subtree)
			continue
		}
		problems = append(problems, checkIsolatedSubtreeContents(root, subtreeRoot, subtree)...)
		problems = append(problems, checkIsolatedSubtreeUnreferenced(root, subtree)...)
	}

	// Every worker subtree must be declared. An undeclared one would get neither the
	// contents gate nor the unreachability gate.
	workersRoot := filepath.Join(root, "workers")
	if entries, err := os.ReadDir(workersRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				problems = append(problems, "workers/ may contain only declared isolated subtrees: workers/"+entry.Name())
				continue
			}
			if !declaredSubtrees["workers/"+entry.Name()+"/"] {
				problems = append(problems, "undeclared isolated worker subtree: workers/"+entry.Name()+"/")
			}
		}
	}
	return problems
}

// checkParserRuntimeCompliance closes R-16 mechanically for the qualified
// document-parser image. The shipped stage must contain only a jlink runtime on
// scratch; the builder remains pinned and the source offer, notices and SPDX
// inventory must describe the exact runtime and jar closure. This is deliberately
// a content check over independent artifacts, not a check that merely looks for
// a sentence in an ADR.
func checkParserRuntimeCompliance(root string) []string {
	isolations, problems := qualifiedIsolationsFromLock(root)
	isolation, ok := isolations["oci.document-parser-worker"]
	if !ok {
		return append(problems, "R-16 parser runtime qualification is missing")
	}
	paths := map[string]string{
		"dockerfile":                "workers/document-parser/Dockerfile",
		"image lock":                "workers/document-parser/release/image-lock.json",
		"SBOM":                      "workers/document-parser/release/sbom.spdx.json",
		"vulnerability attestation": "workers/document-parser/release/vulnerability-attestation.json",
		"notices":                   "workers/document-parser/release/THIRD_PARTY_NOTICES.md",
		"source offer":              isolation.Compliance,
		"closure":                   "workers/document-parser/dependencies.lock.json",
	}
	contents := make(map[string][]byte, len(paths))
	for label, relative := range paths {
		if strings.TrimSpace(relative) == "" {
			problems = append(problems, "R-16 parser runtime qualification has no "+label+" path")
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, "R-16 parser runtime "+label+" is missing: "+relative)
			continue
		}
		contents[label] = raw
	}
	if len(contents) != len(paths) {
		return problems
	}
	problems = append(problems, validateParserRuntimeComplianceContents(
		isolation,
		string(contents["dockerfile"]),
		contents["image lock"],
		contents["SBOM"],
		string(contents["notices"]),
		contents["source offer"],
		contents["closure"],
		contents["vulnerability attestation"],
	)...)
	workflowRaw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "architecture.yml"))
	if err != nil {
		problems = append(problems, "R-16 parser live supply-chain CI workflow is missing")
	} else {
		workflow := string(workflowRaw)
		for _, required := range []string{
			"anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c",
			"anchore/grype:v0.116.0@sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821",
			"a52051769db44825dcab6e6d4c32ffee53cdea0d456d98630b55b15ad52b16f3",
			"GRYPE_DB_AUTO_UPDATE=false",
			"GRYPE_CHECK_FOR_APP_UPDATE=false",
			"-verify-parser-syft-json /scan/syft.json",
			"-verify-parser-grype-json /scan/grype.json",
			"-verify-parser-native-grype-json /scan/grype-native.json",
		} {
			if !strings.Contains(workflow, required) {
				problems = append(problems, "R-16 parser live supply-chain CI is missing exact marker: "+required)
			}
		}
	}
	prepareRaw, err := os.ReadFile(filepath.Join(root, "tests", "integration", "postgres", "prepare-office-worker.sh"))
	if err != nil {
		problems = append(problems, "R-16 parser canonical OCI build verifier is missing")
	} else {
		prepare := string(prepareRaw)
		for _, required := range append([]string{
			"docker buildx build",
			"--no-cache",
			"--provenance=false",
			"--build-arg SOURCE_DATE_EPOCH=1704067200",
			"--platform linux/amd64",
			"rewrite-timestamp=true",
			"sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855",
			"sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467",
			"sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414",
			"hashlib.sha256(data).hexdigest()",
			"docker load --input",
		}, isolation.LayerDigests...) {
			if !strings.Contains(prepare, required) {
				problems = append(problems, "R-16 parser canonical OCI build verifier is missing exact marker: "+required)
			}
		}
	}

	// Adversarial mutations are part of the checker itself. A runtime-base swap,
	// a compliance-strategy swap and a source-offer drift must all turn the gate
	// red; this prevents the release artifact check from becoming a presence test.
	mutatedDockerfile := strings.Replace(string(contents["dockerfile"]),
		"FROM scratch AS runtime", "FROM eclipse-temurin:21-jre@sha256:"+strings.Repeat("a", 64)+" AS runtime", 1)
	if len(validateParserRuntimeComplianceContents(isolation, mutatedDockerfile, contents["image lock"], contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance runtime-base mutation was accepted")
	}
	mutatedLock := strings.Replace(string(contents["image lock"]), `"runtime_strategy": "jlink"`, `"runtime_strategy": "full-jre"`, 1)
	if len(validateParserRuntimeComplianceContents(isolation, string(contents["dockerfile"]), []byte(mutatedLock), contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance image-lock mutation was accepted")
	}
	mutatedArtifactLock := strings.Replace(string(contents["image lock"]), isolation.ArtifactDigest, "sha256:"+strings.Repeat("0", 64), 1)
	if len(validateParserRuntimeComplianceContents(isolation, string(contents["dockerfile"]), []byte(mutatedArtifactLock), contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance artifact-binding mutation was accepted")
	}
	mutatedSBOM := strings.Replace(string(contents["SBOM"]), isolation.ArtifactDigest, "sha256:"+strings.Repeat("0", 64), 1)
	if len(validateParserRuntimeComplianceContents(isolation, string(contents["dockerfile"]), contents["image lock"], []byte(mutatedSBOM), string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance SBOM-identity mutation was accepted")
	}
	mutatedVulnerability := strings.Replace(string(contents["vulnerability attestation"]), `"matches": 0`, `"matches": 1`, 1)
	if len(validateParserRuntimeComplianceContents(isolation, string(contents["dockerfile"]), contents["image lock"], contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], []byte(mutatedVulnerability))) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance vulnerability-result mutation was accepted")
	}
	mutatedOffer := strings.Replace(string(contents["source offer"]), isolation.Compliance, "workers/document-parser/release/source-compliance/other.json", 1)
	if mutatedOffer == string(contents["source offer"]) {
		mutatedOffer = strings.Replace(string(contents["source offer"]), `"source_commit": "9de4f68c88a0a1510373f291d1a95b1f6b0db8c8"`, `"source_commit": "0000000000000000000000000000000000000000"`, 1)
	}
	if len(validateParserRuntimeComplianceContents(isolation, string(contents["dockerfile"]), contents["image lock"], contents["SBOM"], string(contents["notices"]), []byte(mutatedOffer), contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance source-offer mutation was accepted")
	}
	expectedModules := strings.Join(isolation.RuntimeModules, ",")
	mutatedModules := strings.Replace(string(contents["dockerfile"]), "--add-modules "+expectedModules, "--add-modules "+expectedModules+",java.sql", 1)
	if len(validateParserRuntimeComplianceContents(isolation, mutatedModules, contents["image lock"], contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance extra-jlink-module mutation was accepted")
	}
	mutatedNative := strings.Replace(string(contents["dockerfile"]), "    && cp -L /lib64/ld-linux-x86-64.so.2 /build/native/lib64/ld-linux-x86-64.so.2", "    && cp -L /lib64/ld-linux-x86-64.so.2 /build/native/lib64/ld-linux-x86-64.so.2\n    && cp -L /lib/x86_64-linux-gnu/libc.so.6 /build/native/lib/x86_64-linux-gnu/extra-libc.so.6", 1)
	if len(validateParserRuntimeComplianceContents(isolation, mutatedNative, contents["image lock"], contents["SBOM"], string(contents["notices"]), contents["source offer"], contents["closure"], contents["vulnerability attestation"])) == 0 {
		problems = append(problems, "architecture.supply.parser-runtime-compliance extra-native-loader mutation was accepted")
	}
	return problems
}

func validateParserRuntimeComplianceContents(isolation qualifiedIsolation, dockerfile string, imageLockRaw, sbomRaw []byte, notices string, sourceOfferRaw, closureRaw, vulnerabilityAttestationRaw []byte) []string {
	var problems []string
	if isolation.BuilderImage == "" || isolation.RuntimeBase != "scratch" || isolation.RuntimeStrategy != "jlink" || len(isolation.RuntimeModules) == 0 || isolation.OCIManifestDigest == "" || isolation.ConfigDigest == "" || isolation.ArtifactDigest == "" || len(isolation.LayerDigests) == 0 || isolation.Compliance == "" {
		return []string{"R-16 parser runtime qualification is incomplete in architecture/versions.json"}
	}

	fromLine := regexp.MustCompile(`(?mi)^\s*FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?`)
	matches := fromLine.FindAllStringSubmatch(strings.ReplaceAll(dockerfile, "\r\n", "\n"), -1)
	if len(matches) < 2 {
		problems = append(problems, "R-16 parser Dockerfile must have a pinned builder and a final runtime stage")
	} else {
		if matches[0][1] != isolation.BuilderImage {
			problems = append(problems, "R-16 parser Dockerfile builder does not match the version lock")
		}
		last := matches[len(matches)-1]
		if last[1] != isolation.RuntimeBase || last[2] != "runtime" {
			problems = append(problems, "R-16 parser Dockerfile final stage is not scratch/runtime")
		}
	}
	requiredDockerfile := []string{
		"jlink --module-path \"$JAVA_HOME/jmods\"",
		"--add-modules " + strings.Join(isolation.RuntimeModules, ","),
		"--output /build/jre",
		"COPY --from=build /build/jre /opt/jre",
		"ENTRYPOINT [\"/opt/jre/bin/java\"",
		"USER 65532:65532",
	}
	for _, required := range requiredDockerfile {
		if !strings.Contains(dockerfile, required) {
			problems = append(problems, "R-16 parser Dockerfile is missing required runtime construction: "+required)
		}
	}
	moduleMatches := regexp.MustCompile(`--add-modules\s+([^\s\\]+)`).FindAllStringSubmatch(dockerfile, -1)
	expectedModules := strings.Join(isolation.RuntimeModules, ",")
	if len(moduleMatches) != 1 || moduleMatches[0][1] != expectedModules {
		problems = append(problems, "R-16 parser Dockerfile jlink module set is not exact")
	}
	nativeCopies := []string{
		"cp -L /lib/x86_64-linux-gnu/libc.so.6 /build/native/lib/x86_64-linux-gnu/libc.so.6",
		"cp -L /lib/x86_64-linux-gnu/libpthread.so.0 /build/native/lib/x86_64-linux-gnu/libpthread.so.0",
		"cp -L /lib/x86_64-linux-gnu/libdl.so.2 /build/native/lib/x86_64-linux-gnu/libdl.so.2",
		"cp -L /lib/x86_64-linux-gnu/librt.so.1 /build/native/lib/x86_64-linux-gnu/librt.so.1",
		"cp -L /lib/x86_64-linux-gnu/libm.so.6 /build/native/lib/x86_64-linux-gnu/libm.so.6",
		"cp -L /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /build/native/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"cp -L /lib64/ld-linux-x86-64.so.2 /build/native/lib64/ld-linux-x86-64.so.2",
	}
	if strings.Count(dockerfile, "cp -L ") != len(nativeCopies) {
		problems = append(problems, "R-16 parser Dockerfile native loader closure is not exact")
	}
	for _, required := range nativeCopies {
		if !strings.Contains(dockerfile, required) {
			problems = append(problems, "R-16 parser Dockerfile is missing native loader closure entry: "+required)
		}
	}
	if strings.Count(dockerfile, "COPY --from=build /build/native") != 2 {
		problems = append(problems, "R-16 parser Dockerfile native COPY closure is not exact")
	}
	if strings.Contains(dockerfile, "eclipse-temurin:21-jre@") {
		problems = append(problems, "R-16 parser Dockerfile still ships the Debian JRE base")
	}

	var imageLock map[string]any
	if err := rejectDuplicateJSON(imageLockRaw); err != nil || json.Unmarshal(imageLockRaw, &imageLock) != nil {
		return append(problems, "R-16 parser image-lock is invalid JSON")
	}
	problems = append(problems, exactObjectKeys(imageLock, "workers/document-parser/release/image-lock.json", []string{
		"schema", "component", "dockerfile", "platform", "oci_manifest_digest", "config_digest", "layer_digests", "builder_image", "runtime_base", "runtime_strategy", "jvm_modules", "native_runtime", "artifact_identity", "sbom", "vulnerability_scan", "notices", "source_compliance",
	})...)
	expectedImageValues := map[string]string{
		"schema":              "knowvault-parser-runtime-lock-v3",
		"component":           "oci.document-parser-worker",
		"dockerfile":          "workers/document-parser/Dockerfile",
		"platform":            "linux/amd64",
		"oci_manifest_digest": isolation.OCIManifestDigest,
		"config_digest":       isolation.ConfigDigest,
		"builder_image":       isolation.BuilderImage,
		"runtime_base":        isolation.RuntimeBase,
		"runtime_strategy":    isolation.RuntimeStrategy,
		"notices":             "workers/document-parser/release/THIRD_PARTY_NOTICES.md",
		"source_compliance":   isolation.Compliance,
	}
	for key, expected := range expectedImageValues {
		if imageLock[key] != expected {
			problems = append(problems, fmt.Sprintf("R-16 parser image-lock %s mismatch: expected %q", key, expected))
		}
	}
	problems = append(problems, validateExactStringArray(imageLock["jvm_modules"], isolation.RuntimeModules, "R-16 parser image-lock jvm_modules")...)
	digestPattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	for _, key := range []string{"oci_manifest_digest", "config_digest"} {
		digest, _ := imageLock[key].(string)
		if !digestPattern.MatchString(digest) {
			problems = append(problems, "R-16 parser image-lock "+key+" is not an immutable SHA-256 digest")
		}
	}
	artifactIdentity, artifactIdentityOK := imageLock["artifact_identity"].(map[string]any)
	if !artifactIdentityOK {
		problems = append(problems, "R-16 parser image-lock artifact_identity is not an object")
	} else {
		problems = append(problems, exactObjectKeys(artifactIdentity, "R-16 parser image-lock artifact_identity", []string{"path", "digest"})...)
		if artifactIdentity["path"] != "/app/artifact.sha256" || artifactIdentity["digest"] != isolation.ArtifactDigest {
			problems = append(problems, "R-16 parser image-lock artifact identity is not bound to the qualified runtime artifact")
		}
	}
	sbomSum := sha256.Sum256(sbomRaw)
	expectedSBOMDigest := "sha256:" + hex.EncodeToString(sbomSum[:])
	sbomLock, sbomLockOK := imageLock["sbom"].(map[string]any)
	if !sbomLockOK {
		problems = append(problems, "R-16 parser image-lock sbom is not an object")
	} else {
		problems = append(problems, exactObjectKeys(sbomLock, "R-16 parser image-lock sbom", []string{"path", "digest", "format", "bound_oci_manifest_digest", "bound_artifact_digest", "generator"})...)
		for key, expected := range map[string]any{
			"path":                      "workers/document-parser/release/sbom.spdx.json",
			"digest":                    expectedSBOMDigest,
			"format":                    "SPDX-2.3",
			"bound_oci_manifest_digest": isolation.OCIManifestDigest,
			"bound_artifact_digest":     isolation.ArtifactDigest,
		} {
			if sbomLock[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser image-lock sbom.%s mismatch", key))
			}
		}
		generator, ok := sbomLock["generator"].(map[string]any)
		if !ok {
			problems = append(problems, "R-16 parser image-lock sbom.generator is not an object")
		} else {
			problems = append(problems, exactObjectKeys(generator, "R-16 parser image-lock sbom.generator", []string{"name", "version", "source_commit", "image_digest", "release_checksum_manifest_sha256", "observed_artifact_count"})...)
			for key, expected := range map[string]any{
				"name":                             "Syft",
				"version":                          "1.48.0",
				"source_commit":                    "3e2bc6ed095f7ec1a415fb38cfe1c319e95dfed6",
				"image_digest":                     "sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c",
				"release_checksum_manifest_sha256": "0dd856e828c76a9c5a736a0d568a136b64acf0d9720b868547e2217e7bed5d61",
				"observed_artifact_count":          float64(20),
			} {
				if generator[key] != expected {
					problems = append(problems, fmt.Sprintf("R-16 parser image-lock sbom.generator.%s mismatch", key))
				}
			}
		}
	}
	vulnerabilitySum := sha256.Sum256(vulnerabilityAttestationRaw)
	expectedVulnerabilityDigest := "sha256:" + hex.EncodeToString(vulnerabilitySum[:])
	vulnerabilityLock, vulnerabilityLockOK := imageLock["vulnerability_scan"].(map[string]any)
	if !vulnerabilityLockOK {
		problems = append(problems, "R-16 parser image-lock vulnerability_scan is not an object")
	} else {
		problems = append(problems, exactObjectKeys(vulnerabilityLock, "R-16 parser image-lock vulnerability_scan", []string{"attestation", "attestation_digest", "bound_oci_manifest_digest", "bound_artifact_digest", "scanner"})...)
		for key, expected := range map[string]any{
			"attestation":               "workers/document-parser/release/vulnerability-attestation.json",
			"attestation_digest":        expectedVulnerabilityDigest,
			"bound_oci_manifest_digest": isolation.OCIManifestDigest,
			"bound_artifact_digest":     isolation.ArtifactDigest,
		} {
			if vulnerabilityLock[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser image-lock vulnerability_scan.%s mismatch", key))
			}
		}
		scanner, ok := vulnerabilityLock["scanner"].(map[string]any)
		if !ok {
			problems = append(problems, "R-16 parser image-lock vulnerability_scan.scanner is not an object")
		} else {
			problems = append(problems, exactObjectKeys(scanner, "R-16 parser image-lock vulnerability_scan.scanner", []string{"name", "version", "source_commit", "image_digest", "release_checksum_manifest_sha256"})...)
			for key, expected := range map[string]any{
				"name":                             "Grype",
				"version":                          "0.116.0",
				"source_commit":                    "3b014b00097d43933e5cce485e744db8289a406f",
				"image_digest":                     "sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821",
				"release_checksum_manifest_sha256": "c9cc93489491e6a2c9cd0e3382ddc1bf6b16f1ff8fc897cc0d00b270943517b6",
			} {
				if scanner[key] != expected {
					problems = append(problems, fmt.Sprintf("R-16 parser image-lock vulnerability_scan.scanner.%s mismatch", key))
				}
			}
		}
	}
	layers, layersOK := imageLock["layer_digests"].([]any)
	if !layersOK || len(layers) != len(isolation.LayerDigests) {
		problems = append(problems, fmt.Sprintf("R-16 parser image-lock layer_digests must contain exactly %d digests", len(isolation.LayerDigests)))
	} else {
		for index, layer := range layers {
			if layer != isolation.LayerDigests[index] {
				problems = append(problems, fmt.Sprintf("R-16 parser image-lock layer_digests[%d] mismatch", index))
			}
			digest, _ := layer.(string)
			if !digestPattern.MatchString(digest) {
				problems = append(problems, fmt.Sprintf("R-16 parser image-lock layer_digests[%d] is not an immutable SHA-256 digest", index))
			}
		}
	}
	nativeRuntime, nativeOK := imageLock["native_runtime"].([]any)
	if !nativeOK || len(nativeRuntime) != 1 {
		problems = append(problems, "R-16 parser image-lock must carry exactly one native runtime package")
	} else if native, ok := nativeRuntime[0].(map[string]any); !ok {
		problems = append(problems, "R-16 parser image-lock native runtime entry is not an object")
	} else {
		problems = append(problems, exactObjectKeys(native, "R-16 parser image-lock native_runtime[0]", []string{"package", "version", "architecture", "license"})...)
		for key, expected := range map[string]string{"package": "libc6", "version": "2.39-0ubuntu8.8", "architecture": "amd64", "license": "LGPL-2.1-or-later"} {
			if native[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser image-lock native runtime %s mismatch: expected %q", key, expected))
			}
		}
	}

	var closure struct {
		RuntimeClosure []struct {
			Coordinate string `json:"coordinate"`
			Version    string `json:"version"`
			License    string `json:"license"`
		} `json:"runtime_closure"`
		Forbidden []string `json:"forbidden_in_closure"`
	}
	if err := rejectDuplicateJSON(closureRaw); err != nil || json.Unmarshal(closureRaw, &closure) != nil || len(closure.RuntimeClosure) == 0 {
		return append(problems, "R-16 parser dependency closure is invalid JSON")
	}
	if !containsString(closure.Forbidden, "org.apache.logging.log4j:log4j-core") {
		problems = append(problems, "R-16 parser closure lost the log4j-core exclusion")
	}

	var sbom map[string]any
	if err := rejectDuplicateJSON(sbomRaw); err != nil || json.Unmarshal(sbomRaw, &sbom) != nil {
		return append(problems, "R-16 parser SPDX SBOM is invalid JSON")
	}
	problems = append(problems, exactObjectKeys(sbom, "workers/document-parser/release/sbom.spdx.json", []string{
		"SPDXID", "spdxVersion", "name", "dataLicense", "documentNamespace", "documentComment", "creationInfo", "packages",
	})...)
	if sbom["spdxVersion"] != "SPDX-2.3" || sbom["dataLicense"] != "CC0-1.0" {
		problems = append(problems, "R-16 parser SPDX SBOM has an unexpected document identity")
	}
	expectedSBOMBinding := fmt.Sprintf("Release identity binding: oci_manifest_digest=%s; config_digest=%s; artifact_digest=%s; independent runtime scan: Syft v1.48.0 image sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c observed_artifacts=20; raw Syft JSON sha256:e7a0baf793057f1839753e6d892425d9898d8aef763aaf20cdc68d1df95f4452; reviewed transformation retains worker 2.1.0 and all 17 exact Maven JAR identities, folds jrt-fs into the pinned Temurin runtime/source offer and identifies libc6 from the verified native layer; the exact OCI archive and native PURL scans have zero findings and suppressions on the same pinned database. Production activation remains open.", isolation.OCIManifestDigest, isolation.ConfigDigest, isolation.ArtifactDigest)
	if sbom["documentComment"] != expectedSBOMBinding {
		problems = append(problems, "R-16 parser SPDX SBOM is not bound to the qualified OCI and artifact identities")
	}
	packages, ok := sbom["packages"].([]any)
	if !ok || len(packages) < len(closure.RuntimeClosure)+3 {
		problems = append(problems, "R-16 parser SPDX SBOM does not cover the worker, JDK and full jar closure")
	}
	packageByName := make(map[string]map[string]any)
	for _, raw := range packages {
		pkg, ok := raw.(map[string]any)
		if !ok {
			problems = append(problems, "R-16 parser SPDX SBOM contains a non-object package")
			continue
		}
		name, _ := pkg["name"].(string)
		packageByName[name] = pkg
		license, _ := pkg["licenseConcluded"].(string)
		if license == "GPL-2.0-only" || license == "GPL-2.0-or-later" || license == "GPL-3.0-only" || license == "LGPL-2.1-only" || strings.Contains(strings.ToLower(name), "debian") || strings.Contains(strings.ToLower(name), "ubuntu") {
			problems = append(problems, "R-16 parser SPDX SBOM contains a shipped OS/copyleft package: "+name)
		}
	}
	for _, dependency := range closure.RuntimeClosure {
		pkg, exists := packageByName[dependency.Coordinate]
		if !exists {
			problems = append(problems, "R-16 parser SPDX SBOM misses closure artifact: "+dependency.Coordinate)
			continue
		}
		if pkg["versionInfo"] != dependency.Version || pkg["licenseConcluded"] != dependency.License {
			problems = append(problems, "R-16 parser SPDX SBOM disagrees with closure: "+dependency.Coordinate)
		}
	}
	if jdk, exists := packageByName["Eclipse Temurin OpenJDK runtime"]; !exists || jdk["versionInfo"] != "21.0.12+8" || jdk["licenseConcluded"] != "GPL-2.0-only WITH Classpath-exception-2.0" {
		problems = append(problems, "R-16 parser SPDX SBOM misses the exact OpenJDK Classpath-exception runtime record")
	}
	if libc, exists := packageByName["libc6"]; !exists || libc["versionInfo"] != "2.39-0ubuntu8.8" || libc["licenseConcluded"] != "LGPL-2.1-or-later" {
		problems = append(problems, "R-16 parser SPDX SBOM misses the exact native libc6 runtime record")
	}
	if worker, exists := packageByName["KnowVault document-parser-worker"]; !exists || worker["versionInfo"] != "2.1.0" {
		problems = append(problems, "R-16 parser SPDX SBOM misses the worker artifact record")
	}

	var vulnerabilityAttestation map[string]any
	if err := rejectDuplicateJSON(vulnerabilityAttestationRaw); err != nil || json.Unmarshal(vulnerabilityAttestationRaw, &vulnerabilityAttestation) != nil {
		return append(problems, "R-16 parser vulnerability attestation is invalid JSON")
	}
	problems = append(problems, exactObjectKeys(vulnerabilityAttestation, "workers/document-parser/release/vulnerability-attestation.json", []string{
		"schema", "component", "scanned_at", "identity", "scanner", "database", "result",
	})...)
	if vulnerabilityAttestation["schema"] != "knowvault-vulnerability-attestation-v2" || vulnerabilityAttestation["component"] != "oci.document-parser-worker" {
		problems = append(problems, "R-16 parser vulnerability attestation has an unexpected identity")
	}
	scannedAt, _ := vulnerabilityAttestation["scanned_at"].(string)
	if !regexp.MustCompile(`^2026-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$`).MatchString(scannedAt) {
		problems = append(problems, "R-16 parser vulnerability attestation scanned_at is not a UTC release timestamp")
	}
	identity, identityOK := vulnerabilityAttestation["identity"].(map[string]any)
	if !identityOK {
		problems = append(problems, "R-16 parser vulnerability attestation identity is not an object")
	} else {
		problems = append(problems, exactObjectKeys(identity, "R-16 parser vulnerability attestation identity", []string{"oci_manifest_digest", "config_digest", "artifact_digest"})...)
		for key, expected := range map[string]any{
			"oci_manifest_digest": isolation.OCIManifestDigest,
			"config_digest":       isolation.ConfigDigest,
			"artifact_digest":     isolation.ArtifactDigest,
		} {
			if identity[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser vulnerability attestation identity.%s mismatch", key))
			}
		}
	}
	scanner, scannerOK := vulnerabilityAttestation["scanner"].(map[string]any)
	if !scannerOK {
		problems = append(problems, "R-16 parser vulnerability attestation scanner is not an object")
	} else {
		problems = append(problems, exactObjectKeys(scanner, "R-16 parser vulnerability attestation scanner", []string{"name", "version", "source_commit", "image_digest", "release_checksum_manifest_sha256"})...)
		for key, expected := range map[string]any{
			"name":                             "Grype",
			"version":                          "0.116.0",
			"source_commit":                    "3b014b00097d43933e5cce485e744db8289a406f",
			"image_digest":                     "sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821",
			"release_checksum_manifest_sha256": "c9cc93489491e6a2c9cd0e3382ddc1bf6b16f1ff8fc897cc0d00b270943517b6",
		} {
			if scanner[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser vulnerability attestation scanner.%s mismatch", key))
			}
		}
	}
	database, databaseOK := vulnerabilityAttestation["database"].(map[string]any)
	if !databaseOK {
		problems = append(problems, "R-16 parser vulnerability attestation database is not an object")
	} else {
		problems = append(problems, exactObjectKeys(database, "R-16 parser vulnerability attestation database", []string{"schema_version", "built_at", "archive_sha256"})...)
		for key, expected := range map[string]any{
			"schema_version": "v6.1.9",
			"built_at":       "2026-09-20T06:27:54Z",
			"archive_sha256": "a52051769db44825dcab6e6d4c32ffee53cdea0d456d98630b55b15ad52b16f3",
		} {
			if database[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser vulnerability attestation database.%s mismatch", key))
			}
		}
	}
	result, resultOK := vulnerabilityAttestation["result"].(map[string]any)
	if !resultOK {
		problems = append(problems, "R-16 parser vulnerability attestation result is not an object")
	} else {
		problems = append(problems, exactObjectKeys(result, "R-16 parser vulnerability attestation result", []string{"status", "matches", "suppressed_matches"})...)
		if result["status"] != "PASS" || result["matches"] != float64(0) || result["suppressed_matches"] != float64(0) {
			problems = append(problems, "R-16 parser vulnerability attestation is not a zero-finding unsuppressed PASS")
		}
	}

	var sourceOffer map[string]any
	if err := rejectDuplicateJSON(sourceOfferRaw); err != nil || json.Unmarshal(sourceOfferRaw, &sourceOffer) != nil {
		return append(problems, "R-16 parser OpenJDK source offer is invalid JSON")
	}
	problems = append(problems, exactObjectKeys(sourceOffer, "workers/document-parser/release/source-compliance", []string{
		"schema", "component", "version", "license", "source_commit", "source_repository", "source_archive", "notice", "runtime_modules", "native_packages",
	})...)
	expectedOfferValues := map[string]string{
		"schema":            "knowvault-source-compliance-v1",
		"component":         "Eclipse Temurin OpenJDK runtime",
		"version":           "21.0.12+8",
		"license":           "GPL-2.0-only WITH Classpath-exception-2.0",
		"source_commit":     "9de4f68c88a0a1510373f291d1a95b1f6b0db8c8",
		"source_repository": "https://github.com/openjdk/jdk21u/tree/9de4f68c88a0a1510373f291d1a95b1f6b0db8c8",
		"source_archive":    "https://github.com/openjdk/jdk21u/archive/9de4f68c88a0a1510373f291d1a95b1f6b0db8c8.tar.gz",
		"notice":            "workers/document-parser/release/THIRD_PARTY_NOTICES.md",
	}
	for key, expected := range expectedOfferValues {
		if sourceOffer[key] != expected {
			problems = append(problems, fmt.Sprintf("R-16 parser source offer %s mismatch: expected %q", key, expected))
		}
	}
	problems = append(problems, validateExactStringArray(sourceOffer["runtime_modules"], isolation.RuntimeModules, "R-16 parser source offer runtime_modules")...)
	nativeOffers, nativeOffersOK := sourceOffer["native_packages"].([]any)
	if !nativeOffersOK || len(nativeOffers) != 1 {
		problems = append(problems, "R-16 parser source offer must carry exactly one native package offer")
	} else if native, ok := nativeOffers[0].(map[string]any); !ok {
		problems = append(problems, "R-16 parser source offer native package is not an object")
	} else {
		problems = append(problems, exactObjectKeys(native, "R-16 parser source offer native_packages[0]", []string{"package", "version", "architecture", "license", "source_offer"})...)
		for key, expected := range map[string]string{"package": "libc6", "version": "2.39-0ubuntu8.8", "architecture": "amd64", "license": "LGPL-2.1-or-later", "source_offer": "https://launchpad.net/ubuntu/+source/glibc/2.39-0ubuntu8.8"} {
			if native[key] != expected {
				problems = append(problems, fmt.Sprintf("R-16 parser source offer native package %s mismatch: expected %q", key, expected))
			}
		}
	}
	for _, required := range []string{
		"Eclipse Temurin OpenJDK runtime 21.0.12+8",
		"GPL-2.0-only WITH Classpath-exception-2.0",
		"https://github.com/openjdk/jdk21u/tree/9de4f68c88a0a1510373f291d1a95b1f6b0db8c8",
		"Apache POI 5.5.1",
		"Apache PDFBox 3.0.8",
		"org.apache.logging.log4j:log4j-api",
	} {
		if !strings.Contains(notices, required) {
			problems = append(problems, "R-16 parser notices missing required disclosure: "+required)
		}
	}
	return problems
}

func validateExactStringArray(value any, expected []string, label string) []string {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return []string{fmt.Sprintf("%s must contain exactly %d entries", label, len(expected))}
	}
	var problems []string
	for index, item := range items {
		if item != expected[index] {
			problems = append(problems, fmt.Sprintf("%s[%d] mismatch: expected %q", label, index, expected[index]))
		}
	}
	return problems
}

// checkQualifiedIDNotActive keeps QUALIFIED_NOT_ACTIVE strictly short of ACTIVE: the
// component id may appear only in the two deferred inventories.
func checkQualifiedIDNotActive(root string, id string) []string {
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "versions.json"))
	if err != nil {
		return []string{"missing or unreadable architecture/versions.json"}
	}
	if count := strings.Count(string(raw), `"`+id+`"`); count != 2 {
		return []string{fmt.Sprintf("QUALIFIED_NOT_ACTIVE component %s must appear exactly twice in the version lock (deferred runtime lock + stage gate), found %d", id, count)}
	}
	return nil
}

// checkIsolatedSubtreeContents enforces default-deny inside the subtree: no
// application source language (so nothing there can be imported into the product)
// and no unpinned base image in its build files.
func checkIsolatedSubtreeContents(root, subtreeRoot, subtree string) []string {
	fromLine := regexp.MustCompile(`(?mi)^\s*FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?`)
	digest := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	var problems []string
	_ = walkDir(subtreeRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() {
			// Maven output is a generated build product, not an input reachable
			// from the isolated source subtree. Its .class/JAR files are checked
			// by the worker build and must not turn a clean source tree red.
			if entry.Name() == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		name := strings.ToLower(entry.Name())
		if strings.HasPrefix(name, "dockerfile") {
			content, err := os.ReadFile(path)
			if err != nil {
				problems = append(problems, "unreadable isolated worker build file: "+rel)
				return nil
			}
			// Stage names declared by an earlier FROM ... AS <name> are internal
			// references, not images to pin; only external bases must carry a digest.
			stages := map[string]bool{}
			for _, match := range fromLine.FindAllStringSubmatch(string(content), -1) {
				image := strings.Trim(match[1], `"'`)
				if match[2] != "" {
					stages[strings.ToLower(strings.Trim(match[2], `"'`))] = true
				}
				if image == "scratch" || strings.HasPrefix(image, "$") || stages[strings.ToLower(image)] {
					continue
				}
				if strings.Contains(image, ":latest") || !digest.MatchString(image) {
					problems = append(problems, "isolated worker image requires exact tag and digest in "+rel+": "+image)
				}
			}
			return nil
		}
		extension := strings.ToLower(filepath.Ext(name))
		switch extension {
		case ".go", ".ts", ".tsx", ".mjs", ".cjs", ".js", ".sql":
			problems = append(problems, "application source language inside an isolated worker subtree makes it reachable from production: "+rel)
			return nil
		}
		if !isolatedWorkerFileTypes[extension] {
			problems = append(problems, "forbidden or unknown file type in isolated worker subtree "+subtree+": "+rel)
		}
		return nil
	})
	return problems
}

// checkIsolatedSubtreeUnreferenced proves the subtree is unreachable from production
// composition, deployment and the production image build context: no production tree
// names it, and .dockerignore (a default-deny allowlist) never re-admits it.
func checkIsolatedSubtreeUnreferenced(root, subtree string) []string {
	var problems []string
	trimmed := strings.TrimSuffix(subtree, "/")
	for _, tree := range productionTreePrefixes {
		treeRoot := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(tree, "/")))
		_ = walkDir(treeRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if strings.Contains(string(content), trimmed) {
				problems = append(problems,
					"production tree references the isolated worker subtree (it must stay unreachable from composition, deploy and runtime): "+
						filepath.ToSlash(relative(root, path)))
			}
			return nil
		})
	}
	ignore, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		return append(problems, "missing or unreadable .dockerignore")
	}
	for _, line := range strings.Split(string(ignore), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "!") && strings.Contains(line, strings.Split(trimmed, "/")[0]) {
			problems = append(problems,
				"the production image build context re-admits the isolated worker subtree: .dockerignore line "+line)
		}
	}
	return problems
}

func checkDeferredStageLeaks(root string, stage1DatabaseReady bool) []string {
	patterns := map[string][]string{
		"STAGE_1 identity dependency": {
			"github.com/elimity-com/scim", "github.com/cybozu-go/scim",
		},
		"STAGE_2 parser runtime/dependency": {
			"org.apache.poi", "apache-poi", "org.apache.pdfbox", "pdfbox",
			"tesseract", "gosseract", "leptonica", "tessdata",
			"apache/tika", "paddleocr",
		},
		"STAGE_3 search/model runtime": {
			"opensearch-go", "vllm", "qwen3-embedding", "qwen3-reranker",
		},
		"STAGE_4 generation model": {
			"qwen3-14b",
		},
		"STAGE_5 connector dependency": {
			"go-git", "git2go", "go-imap", "msgraph-sdk-go", "google.golang.org/api/gmail", "aws-sdk-go-v2", "minio-go",
		},
		"STAGE_6 observability/KMS dependency": {
			"go.opentelemetry.io/", "aws-sdk-go-v2/service/kms", "cloud.google.com/go/kms", "azkeys",
		},
	}
	if !stage1DatabaseReady {
		patterns["STAGE_1 PostgreSQL runtime"] = []string{"github.com/jackc/pgx/v5"}
	}
	skippedDirs := map[string]bool{
		".git": true, ".github": true, "architecture": true, "docs": true, "scripts": true, "tests": true, "out": true,
	}
	// The single narrow allowance: a QUALIFIED_NOT_ACTIVE component's declared tokens
	// inside its declared isolated subtree. Everything else — every other token, every
	// other path, every DEFERRED component including PDFBox and Tesseract — stays
	// denied exactly as before. The allowance is data-driven from the version lock, so
	// no per-component exception is written into this scan.
	isolations, problems := qualifiedIsolationsFromLock(root)
	allowedInSubtree := make(map[string][]string)
	for _, isolation := range isolations {
		if isolation.IsolatedSubtree == "" {
			continue
		}
		for _, token := range isolation.LeakTokens {
			allowedInSubtree[isolation.IsolatedSubtree] = append(allowedInSubtree[isolation.IsolatedSubtree], strings.ToLower(token))
		}
	}
	tokenIsQualifiedHere := func(rel, token string) bool {
		for subtree, tokens := range allowedInSubtree {
			if !strings.HasPrefix(rel, subtree) {
				continue
			}
			for _, allowed := range tokens {
				if allowed == token {
					return true
				}
			}
		}
		return false
	}
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return nil
		}
		first := strings.Split(filepath.ToSlash(rel), "/")[0]
		if entry.IsDir() {
			if skippedDirs[first] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "internal/platform/database/generated/") {
			problems = append(problems, "sqlc generated output is forbidden before the reviewed sqlc artifact and explicit repository-query gate: "+filepath.ToSlash(rel))
			return nil
		}
		name := strings.ToLower(entry.Name())
		ext := strings.ToLower(filepath.Ext(name))
		// Scanned file types include the descriptors a JVM/Maven worker uses
		// (.java/.xml/.properties/.sh): a gated token must not be able to hide in a
		// file type the scan never opened.
		scanned := ext == ".go" || ext == ".mod" || ext == ".sum" || ext == ".json" ||
			ext == ".yaml" || ext == ".yml" || ext == ".toml" || ext == ".java" ||
			ext == ".xml" || ext == ".properties" || ext == ".gradle" || ext == ".kts" ||
			ext == ".sh" || strings.HasPrefix(name, "dockerfile") || strings.Contains(name, "compose")
		if !scanned {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		slashed := filepath.ToSlash(rel)
		content := strings.ToLower(string(raw))
		for gate, tokens := range patterns {
			for _, token := range tokens {
				lowered := strings.ToLower(token)
				if !strings.Contains(content, lowered) {
					continue
				}
				if tokenIsQualifiedHere(slashed, lowered) {
					continue
				}
				problems = append(problems, fmt.Sprintf("%s used before exact lock (%s): %s", gate, token, slashed))
			}
		}
		return nil
	})
	return problems
}

func checkOIDCImportBoundary(root string) []string {
	const allowedDirectory = "internal/platform/oidc/"
	allowedImports := []string{
		"github.com/coreos/go-oidc/",
		"github.com/go-jose/go-jose/",
		"golang.org/x/oauth2",
	}
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, "tests/") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			for _, allowedImport := range allowedImports {
				if (importPath == strings.TrimSuffix(allowedImport, "/") || strings.HasPrefix(importPath, allowedImport)) && !strings.HasPrefix(rel, allowedDirectory) {
					problems = append(problems, "OIDC dependency imported outside internal/platform/oidc: "+rel+" -> "+importPath)
				}
			}
		}
		return nil
	})
	return problems
}

func checkSecretMountImportBoundary(root string) []string {
	const secretImport = "knowvault.local/verified-workspace/internal/platform/secretmount"
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, "internal/platform/secretmount/") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			// The e2e harness computes the external-subject digest through the
			// production loader on purpose: the digest must never drift from
			// what the server verifies at login. It reads the identity key of
			// the operator-generated test mount, not a product secret.
			allowedConsumer := strings.HasPrefix(rel, "internal/platform/composition/") ||
				strings.HasPrefix(rel, "internal/platform/workercomposition/") ||
				strings.HasPrefix(rel, "internal/platform/purgercomposition/") ||
				strings.HasPrefix(rel, "internal/operator/") ||
				strings.HasPrefix(rel, "tests/e2e/harness/")
			if err == nil && importPath == secretImport && !allowedConsumer {
				problems = append(problems, "mounted key capability imported outside production composition: "+rel)
			}
		}
		return nil
	})
	return problems
}

// checkRuntimeGIDConsistency binds each image to its one mount consumer.
// Workers cannot inherit the server/parser identity, and adding a second
// accepted ownership value to a reader is not an alternative to that binding.
func checkRuntimeGIDConsistency(root string) []string {
	var problems []string
	identityPath := filepath.Join(root, "internal", "platform", "runtimeidentity", "mounts.go")
	source, err := os.ReadFile(identityPath)
	if err != nil {
		problems = append(problems, "runtime gid source unreadable: "+relative(root, identityPath))
		return problems
	}
	for name, expected := range map[string]string{"ServerGroupID": "65532", "WorkerGroupID": "65530"} {
		declarations := regexp.MustCompile(`\b`+name+`\s*=\s*([0-9]+)`).FindAllSubmatch(source, -1)
		if len(declarations) != 1 || string(declarations[0][1]) != expected {
			problems = append(problems, "runtime identity must pin "+name+"="+expected+" exactly once")
		}
	}
	provider, err := os.ReadFile(filepath.Join(root, "internal/platform/secretmount/provider.go"))
	if err != nil || !strings.Contains(string(provider), "const RuntimeGID = runtimeidentity.ServerGroupID") ||
		!strings.Contains(string(provider), "const WorkerRuntimeGID = runtimeidentity.WorkerGroupID") {
		problems = append(problems, "secret mount groups must alias the closed runtime identity contract")
	}
	groupAssignment := regexp.MustCompile(`(?:-g\s+|chown[^\r\n]*:|--chown=[0-9]*:|USER\s+[0-9]*:|root:)([0-9]+)`)
	imageDir := filepath.Join(root, "deploy", "images")
	_ = walkDir(imageDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if (name != "Dockerfile" && !strings.HasPrefix(name, "Dockerfile.") && name != "README.md") ||
			strings.HasSuffix(name, ".dockerignore") {
			return nil
		}
		// The one-shot operator is the trusted producer of root:RuntimeGID
		// mounts, not a consumer running under RuntimeGID. Its separate artifact
		// gate requires USER 0:0 and the exact operator source that performs the
		// group assignment; applying the application USER rule here would make
		// the published mount impossible to create.
		if name == "Dockerfile.operator" || name == "Dockerfile.dispatcher" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, "image contract file unreadable: "+relative(root, path))
			return nil
		}
		captures := groupAssignment.FindAllSubmatch(raw, -1)
		if len(captures) == 0 {
			problems = append(problems, "image contract file pins no runtime group assignment: "+relative(root, path))
			return nil
		}
		runtimeGID := "65532"
		if name == "Dockerfile.worker" {
			runtimeGID = "65530"
		}
		seen := map[string]bool{}
		for _, capture := range captures {
			seen[string(capture[1])] = true
			if name == "README.md" && (string(capture[1]) == "65530" || string(capture[1]) == "65532") {
				continue
			}
			if string(capture[1]) != runtimeGID {
				problems = append(problems, fmt.Sprintf("image contract group %s in %s diverges from its consumer group %s",
					string(capture[1]), relative(root, path), runtimeGID))
			}
		}
		if name == "README.md" && (!seen["65530"] || !seen["65532"]) {
			problems = append(problems, "image README must document both server and worker mount groups")
		}
		return nil
	})
	return problems
}

func checkTrustBundleBoundary(root string) []string {
	const trustImport = "knowvault.local/verified-workspace/internal/platform/trustbundle"
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if rel == ".git" || strings.HasPrefix(rel, ".git/") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			lowerName := strings.ToLower(entry.Name())
			if strings.HasSuffix(lowerName, ".pem") || strings.HasSuffix(lowerName, ".crt") || strings.HasSuffix(lowerName, ".cer") {
				problems = append(problems, "static trust material is forbidden in repository: "+rel)
			}
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasPrefix(rel, "internal/platform/trustbundle/") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			allowedConsumer := strings.HasPrefix(rel, "internal/platform/composition/") ||
				strings.HasPrefix(rel, "internal/platform/workercomposition/") ||
				strings.HasPrefix(rel, "internal/platform/purgercomposition/") ||
				rel == "internal/operator/readiness.go" ||
				rel == "internal/platform/database/production.go" || rel == "internal/platform/oidc/httpclient.go"
			if err == nil && importPath == trustImport && !allowedConsumer {
				problems = append(problems, "mounted trust capability imported outside approved production consumers: "+rel)
			}
		}
		return nil
	})
	for _, relative := range []string{"deploy/images/Dockerfile.server", "deploy/images/Dockerfile.worker", "deploy/images/Dockerfile.connector", "deploy/images/Dockerfile.purger"} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			continue
		}
		problems = append(problems, validateNoShippedTrustMaterial(relative, string(raw))...)
	}
	mutated := "FROM scratch\nCOPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\nENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\nRUN update-ca-certificates\n"
	if len(validateNoShippedTrustMaterial("Dockerfile.mutated", mutated)) < 3 {
		problems = append(problems, "architecture.runtime.shipped-ca-bundle mutation was accepted")
	}
	return problems
}

func validateNoShippedTrustMaterial(relative, content string) []string {
	lower := strings.ToLower(content)
	var problems []string
	for _, forbidden := range []string{"database-ca.pem", "oidc-ca.pem", "/etc/ssl/certs", "ca-certificates.crt", "update-ca-certificates", "ssl_cert_file", "ssl_cert_dir"} {
		if strings.Contains(lower, forbidden) {
			problems = append(problems, "application image contains a forbidden CA trust surface in "+relative+": "+forbidden)
		}
	}
	return problems
}

func checkProductionConstructorBoundary(root string) []string {
	forbidden := map[string]map[string]bool{
		"knowvault.local/verified-workspace/internal/platform/database": {"Open": true},
		"knowvault.local/verified-workspace/internal/platform/oidc":     {"NewHardenedHTTPClient": true},
		"knowvault.local/verified-workspace/internal/platform/trustbundle": {
			"NewDatabaseRootsPEM": true, "NewOIDCRootsPEM": true,
		},
	}
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, "scripts/") || strings.HasPrefix(rel, "tests/") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		aliases := make(map[string]string)
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || forbidden[importPath] == nil {
				continue
			}
			alias := filepath.Base(importPath)
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			if alias == "." {
				problems = append(problems, "dot import can bypass production constructor boundary: "+rel+" -> "+importPath)
			} else if alias != "_" {
				aliases[alias] = importPath
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			importPath := aliases[identifier.Name]
			if forbidden[importPath][selector.Sel.Name] {
				problems = append(problems, "non-production constructor referenced by runtime code: "+rel+" -> "+identifier.Name+"."+selector.Sel.Name)
			}
			return true
		})
		return nil
	})
	return problems
}

func checkCompositionImportBoundary(root string) []string {
	const compositionImport = "knowvault.local/verified-workspace/internal/platform/composition"
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, "internal/platform/composition/") {
			return nil
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err == nil && importPath == compositionImport && !strings.HasPrefix(rel, "cmd/server/") {
				problems = append(problems, "production composition imported outside cmd/server: "+rel)
			}
		}
		return nil
	})
	configuration, err := os.ReadFile(filepath.Join(root, "internal", "platform", "composition", "config.go"))
	if err != nil {
		problems = append(problems, "production composition config is missing")
	} else {
		for _, forbidden := range []string{"KNOWVAULT_WEB_", "WebAssetDirectory", "os.Getenv(", "os.LookupEnv("} {
			if strings.Contains(string(configuration), forbidden) {
				problems = append(problems, "production composition config contains forbidden environment/path surface: "+forbidden)
			}
		}
	}
	return problems
}

const (
	runtimeGuardPrefix         = "architecture.runtime"
	runtimeProductionSource    = "internal/platform/composition/runtime.go"
	purgerRuntimeSource        = "internal/platform/purgercomposition/runtime.go"
	httpServerProductionSource = "internal/platform/httpserver/server.go"
	// The sandbox dispatcher is the second production listener (ADR-0068): it
	// owns the unix socket at the orchestration boundary and nothing else.
	dispatcherRuntimeSource         = "internal/platform/dispatchercomposition/runtime.go"
	sandboxDispatcherDispatchSource = "internal/sandboxdispatch/dispatch.go"
	sandboxDispatcherV2Source       = "internal/sandboxdispatch/v2.go"
)

type runtimeGuardCall struct {
	rel        string
	function   string
	importPath string
	selector   string
}

// checkProductionRuntimeBoundary keeps process assembly as a single, reviewable
// capability graph. These checks deliberately inspect the AST: comments and
// similarly named local functions cannot satisfy the production contract.
func checkProductionRuntimeBoundary(root string) []string {
	runtimePath := filepath.Join(root, filepath.FromSlash(runtimeProductionSource))
	runtimeRaw, err := os.ReadFile(runtimePath)
	if err != nil {
		return []string{runtimeGuardPrefix + ".missing: production Runtime source is missing"}
	}

	var problems []string
	problems = append(problems, validateProductionRuntimeSource(runtimeProductionSource, runtimeRaw)...)
	problems = append(problems, checkProductionRuntimeGuardMutations(runtimeRaw)...)
	purgerPath := filepath.Join(root, filepath.FromSlash(purgerRuntimeSource))
	purgerRaw, purgerErr := os.ReadFile(purgerPath)
	if purgerErr != nil {
		problems = append(problems, runtimeGuardPrefix+".purger-missing: privileged purger Runtime source is missing")
	} else {
		problems = append(problems, validateProductionPurgerRuntimeSource(purgerRuntimeSource, purgerRaw)...)
	}
	entrypointSource := "cmd/server/main.go"
	entrypointRaw, entrypointErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(entrypointSource)))
	if entrypointErr != nil {
		problems = append(problems, runtimeGuardPrefix+".entrypoint-missing: production server entrypoint is missing")
	} else {
		problems = append(problems, validateProductionServerEntrypoint(entrypointSource, entrypointRaw)...)
	}
	workerEntrypointSource := "cmd/worker/main.go"
	workerEntrypointRaw, workerEntrypointErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(workerEntrypointSource)))
	if workerEntrypointErr != nil {
		problems = append(problems, runtimeGuardPrefix+".worker-entrypoint-missing: production worker entrypoint is missing")
	} else {
		problems = append(problems, validateProductionWorkerEntrypoint(workerEntrypointSource, workerEntrypointRaw)...)
	}
	purgerEntrypointSource := "cmd/purger/main.go"
	purgerEntrypointRaw, purgerEntrypointErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(purgerEntrypointSource)))
	if purgerEntrypointErr != nil {
		problems = append(problems, runtimeGuardPrefix+".purger-entrypoint-missing: privileged purger entrypoint is missing")
	} else {
		problems = append(problems, validateProductionPurgerEntrypoint(purgerEntrypointSource, purgerEntrypointRaw)...)
	}

	targets := map[string]map[string]string{
		"knowvault.local/verified-workspace/internal/platform/trustbundle": {"LoadMounted": "trust-load"},
		"knowvault.local/verified-workspace/internal/platform/secretmount": {"LoadMountedForTenant": "secret-load"},
		"knowvault.local/verified-workspace/internal/platform/database":    {"OpenProduction": "database-open"},
		"knowvault.local/verified-workspace/internal/platform/oidc":        {"NewProductionHTTPClient": "oidc-http"},
	}
	targetCounts := map[string]int{}
	purgerTargetCounts := map[string]int{}
	listenAndServeCount := 0
	dispatcherListenCount := 0
	databaseURLCount := 0
	purgerDatabaseURLCount := 0
	preflightCount := 0

	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || filepath.Ext(entry.Name()) != ".go" || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		// Files under tests/ are executable qualification harnesses, never
		// production composition roots. They may call the real public listener
		// APIs directly; reflection or token-splitting to evade this AST gate is
		// forbidden by review and unnecessary once the ownership scan is scoped
		// to production source.
		if strings.HasPrefix(rel, ".git/") || strings.HasPrefix(rel, "scripts/") || strings.HasPrefix(rel, "tests/") {
			return nil
		}
		parsed, aliases, parseErr := parseGoFileWithAliases(path, nil)
		if parseErr != nil {
			problems = append(problems, runtimeGuardPrefix+".parse: cannot inspect "+rel+": "+parseErr.Error())
			return nil
		}
		for _, imported := range parsed.Imports {
			if imported.Name == nil || imported.Name.Name != "." {
				continue
			}
			importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
			if unquoteErr == nil && runtimeSensitiveImport(importPath) {
				problems = append(problems, runtimeGuardPrefix+".dot-import: reviewed production capabilities and listener packages cannot be dot-imported: "+rel+" -> "+importPath)
			}
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					if identifier, direct := call.Fun.(*ast.Ident); direct && identifier.Name == "preflightOIDCProvider" {
						preflightCount++
						if rel != runtimeProductionSource || function.Name.Name != "NewProduction" {
							problems = append(problems, runtimeGuardPrefix+".oidc-preflight-owner: provider preflight is owned only by composition.NewProduction: "+rel+"#"+function.Name.Name)
						}
					}
					return true
				}
				approvedOperatorProbe := rel == "internal/operator/readiness.go" && function.Name.Name == "probeRuntimeMount"
				if selector.Sel.Name == "DatabaseURL" {
					if rel == runtimeProductionSource && function.Name.Name == "NewProduction" {
						databaseURLCount++
					} else if rel == purgerRuntimeSource && function.Name.Name == "NewProduction" {
						purgerDatabaseURLCount++
					} else if !strings.HasPrefix(rel, "internal/platform/workercomposition/") && !approvedOperatorProbe {
						problems = append(problems, runtimeGuardPrefix+".database-url-owner: mounted database capability is owned only by production composition roots: "+rel+"#"+function.Name.Name)
					}
				}
				if selector.Sel.Name == "ListenAndServe" {
					if rel == dispatcherRuntimeSource && function.Name.Name == "Run" && methodReceiverNamed(function, "Runtime") {
						dispatcherListenCount++
					} else {
						listenAndServeCount++
						if rel != runtimeProductionSource || function.Name.Name != "Run" || !methodReceiverNamed(function, "Runtime") {
							problems = append(problems, runtimeGuardPrefix+".listener-owner: ListenAndServe is allowed only in (*Runtime).Run: "+rel+"#"+function.Name.Name)
						}
					}
				}
				identifier, ok := selector.X.(*ast.Ident)
				if !ok {
					return true
				}
				importPath := aliases[identifier.Name]
				if code := targets[importPath][selector.Sel.Name]; code != "" {
					if rel == runtimeProductionSource && function.Name.Name == "NewProduction" {
						targetCounts[code]++
					} else if rel == purgerRuntimeSource && function.Name.Name == "NewProduction" {
						purgerTargetCounts[code]++
					} else if !strings.HasPrefix(rel, "internal/platform/workercomposition/") && !approvedOperatorProbe {
						problems = append(problems, runtimeGuardPrefix+"."+code+"-owner: production capability may be acquired only by approved composition roots: "+rel+"#"+function.Name.Name)
					}
				}
				return true
			})
		}
		problems = append(problems, validateListenerPackageOwnership(rel, parsed, aliases)...)
		return nil
	})

	for _, code := range []string{"trust-load", "secret-load", "database-open", "oidc-http"} {
		if targetCounts[code] != 1 {
			problems = append(problems, fmt.Sprintf("%s.%s-count: expected exactly one production call, found %d", runtimeGuardPrefix, code, targetCounts[code]))
		}
	}
	for _, code := range []string{"trust-load", "secret-load", "database-open"} {
		if purgerTargetCounts[code] != 1 {
			problems = append(problems, fmt.Sprintf("%s.purger-%s-count: expected exactly one privileged purger call, found %d", runtimeGuardPrefix, code, purgerTargetCounts[code]))
		}
	}
	if purgerTargetCounts["oidc-http"] != 0 {
		problems = append(problems, fmt.Sprintf("%s.purger-oidc-http-forbidden: privileged purger must not acquire OIDC HTTP capability, found %d", runtimeGuardPrefix, purgerTargetCounts["oidc-http"]))
	}
	if listenAndServeCount != 1 {
		problems = append(problems, fmt.Sprintf("%s.listener-count: expected exactly one production ListenAndServe call, found %d", runtimeGuardPrefix, listenAndServeCount))
	}
	if dispatcherListenCount != 1 {
		problems = append(problems, fmt.Sprintf("%s.listener-count: expected exactly one sandbox dispatcher ListenAndServe call, found %d", runtimeGuardPrefix, dispatcherListenCount))
	}
	if databaseURLCount != 1 {
		problems = append(problems, fmt.Sprintf("%s.database-url-count: expected exactly one production DatabaseURL call, found %d", runtimeGuardPrefix, databaseURLCount))
	}
	if purgerDatabaseURLCount != 1 {
		problems = append(problems, fmt.Sprintf("%s.purger-database-url-count: expected exactly one privileged purger DatabaseURL call, found %d", runtimeGuardPrefix, purgerDatabaseURLCount))
	}
	if preflightCount != 1 {
		problems = append(problems, fmt.Sprintf("%s.oidc-preflight-count: expected exactly one production preflight call, found %d", runtimeGuardPrefix, preflightCount))
	}
	return problems
}

func validateProductionServerEntrypoint(rel string, raw []byte) []string {
	parsed, aliases, err := parseGoFileWithAliases(rel, raw)
	if err != nil {
		return []string{runtimeGuardPrefix + ".entrypoint-parse: cannot parse " + rel}
	}
	allowedImports := map[string]bool{
		"context": true, "log/slog": true, "os": true, "time": true,
		"knowvault.local/verified-workspace/internal/platform/buildinfo":   true,
		"knowvault.local/verified-workspace/internal/platform/composition": true,
		"knowvault.local/verified-workspace/internal/platform/lifecycle":   true,
	}
	var problems []string
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil || !allowedImports[importPath] {
			problems = append(problems, runtimeGuardPrefix+".entrypoint-import: server entrypoint may depend only on composition and process lifecycle packages")
		}
	}
	mainFunction := findFunction(parsed, "main", "")
	if mainFunction == nil || mainFunction.Body == nil || len(mainFunction.Body.List) != 1 || !isExitRunStatement(mainFunction.Body.List[0], aliases) {
		problems = append(problems, runtimeGuardPrefix+".entrypoint-main: main must contain exactly os.Exit(run())")
	}
	runFunction := findFunction(parsed, "run", "")
	if runFunction == nil || runFunction.Body == nil {
		return append(problems, runtimeGuardPrefix+".entrypoint-run: run function is missing")
	}
	counts := map[string]int{"config": 0, "constructor": 0, "run": 0, "close": 0}
	ast.Inspect(runFunction.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.DeferStmt:
			if selector, ok := value.Call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Close" {
				counts["close"]++
			}
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
				if identifier, direct := selector.X.(*ast.Ident); direct {
					qualified := aliases[identifier.Name] + "." + selector.Sel.Name
					switch qualified {
					case "knowvault.local/verified-workspace/internal/platform/composition.LoadProduction":
						counts["config"]++
					case "knowvault.local/verified-workspace/internal/platform/composition.NewProduction":
						counts["constructor"]++
					case "os.Exit", "log.Fatal", "log.Fatalf", "log.Panic", "log.Panicf":
						problems = append(problems, runtimeGuardPrefix+".entrypoint-termination: run must return so deferred cleanup executes")
					}
				}
				if selector.Sel.Name == "Run" {
					counts["run"]++
				}
			}
		}
		return true
	})
	for operation, count := range counts {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s.entrypoint-%s-count: expected exactly one call, found %d", runtimeGuardPrefix, operation, count))
		}
	}
	return problems
}

func validateProductionWorkerEntrypoint(rel string, raw []byte) []string {
	parsed, aliases, err := parseGoFileWithAliases(rel, raw)
	if err != nil {
		return []string{runtimeGuardPrefix + ".worker-entrypoint-parse: cannot parse " + rel}
	}
	allowedImports := map[string]bool{
		"context": true, "log/slog": true, "os": true, "time": true,
		"knowvault.local/verified-workspace/internal/platform/buildinfo":         true,
		"knowvault.local/verified-workspace/internal/platform/lifecycle":         true,
		"knowvault.local/verified-workspace/internal/platform/workercomposition": true,
	}
	var problems []string
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil || !allowedImports[importPath] {
			problems = append(problems, runtimeGuardPrefix+".worker-entrypoint-import: worker entrypoint may depend only on worker composition and process lifecycle packages")
		}
	}
	mainFunction := findFunction(parsed, "main", "")
	if mainFunction == nil || mainFunction.Body == nil || len(mainFunction.Body.List) != 1 || !isExitRunStatement(mainFunction.Body.List[0], aliases) {
		problems = append(problems, runtimeGuardPrefix+".worker-entrypoint-main: main must contain exactly os.Exit(run())")
	}
	runFunction := findFunction(parsed, "run", "")
	if runFunction == nil || runFunction.Body == nil {
		return append(problems, runtimeGuardPrefix+".worker-entrypoint-run: run function is missing")
	}
	counts := map[string]int{"config": 0, "constructor": 0, "run": 0, "close": 0}
	ast.Inspect(runFunction.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.DeferStmt:
			if selector, ok := value.Call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Close" {
				counts["close"]++
			}
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
				if identifier, direct := selector.X.(*ast.Ident); direct {
					qualified := aliases[identifier.Name] + "." + selector.Sel.Name
					switch qualified {
					case "knowvault.local/verified-workspace/internal/platform/workercomposition.LoadProduction":
						counts["config"]++
					case "knowvault.local/verified-workspace/internal/platform/workercomposition.NewProduction":
						counts["constructor"]++
					case "os.Exit", "log.Fatal", "log.Fatalf", "log.Panic", "log.Panicf":
						problems = append(problems, runtimeGuardPrefix+".worker-entrypoint-termination: run must return so deferred cleanup executes")
					}
				}
				if selector.Sel.Name == "Run" {
					counts["run"]++
				}
			}
		}
		return true
	})
	for operation, count := range counts {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s.worker-entrypoint-%s-count: expected exactly one call, found %d", runtimeGuardPrefix, operation, count))
		}
	}
	return problems
}

func validateProductionPurgerEntrypoint(rel string, raw []byte) []string {
	parsed, aliases, err := parseGoFileWithAliases(rel, raw)
	if err != nil {
		return []string{runtimeGuardPrefix + ".purger-entrypoint-parse: cannot parse " + rel}
	}
	allowedImports := map[string]bool{
		"context": true, "log/slog": true, "os": true, "time": true,
		"knowvault.local/verified-workspace/internal/platform/buildinfo":         true,
		"knowvault.local/verified-workspace/internal/platform/lifecycle":         true,
		"knowvault.local/verified-workspace/internal/platform/purgercomposition": true,
	}
	var problems []string
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil || !allowedImports[importPath] {
			problems = append(problems, runtimeGuardPrefix+".purger-entrypoint-import: purger entrypoint may depend only on purger composition and process lifecycle packages")
		}
	}
	mainFunction := findFunction(parsed, "main", "")
	if mainFunction == nil || mainFunction.Body == nil || len(mainFunction.Body.List) != 1 || !isExitRunStatement(mainFunction.Body.List[0], aliases) {
		problems = append(problems, runtimeGuardPrefix+".purger-entrypoint-main: main must contain exactly os.Exit(run())")
	}
	runFunction := findFunction(parsed, "run", "")
	if runFunction == nil || runFunction.Body == nil {
		return append(problems, runtimeGuardPrefix+".purger-entrypoint-run: run function is missing")
	}
	counts := map[string]int{"config": 0, "constructor": 0, "run": 0, "close": 0}
	ast.Inspect(runFunction.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.DeferStmt:
			if selector, ok := value.Call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Close" {
				counts["close"]++
			}
		case *ast.CallExpr:
			if selector, ok := value.Fun.(*ast.SelectorExpr); ok {
				if identifier, direct := selector.X.(*ast.Ident); direct {
					qualified := aliases[identifier.Name] + "." + selector.Sel.Name
					switch qualified {
					case "knowvault.local/verified-workspace/internal/platform/purgercomposition.LoadProduction":
						counts["config"]++
					case "knowvault.local/verified-workspace/internal/platform/purgercomposition.NewProduction":
						counts["constructor"]++
					case "os.Exit", "log.Fatal", "log.Fatalf", "log.Panic", "log.Panicf":
						problems = append(problems, runtimeGuardPrefix+".purger-entrypoint-termination: run must return so deferred cleanup executes")
					}
				}
				if selector.Sel.Name == "Run" {
					counts["run"]++
				}
			}
		}
		return true
	})
	for operation, count := range counts {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s.purger-entrypoint-%s-count: expected exactly one call, found %d", runtimeGuardPrefix, operation, count))
		}
	}
	return problems
}

func isExitRunStatement(statement ast.Stmt, aliases map[string]string) bool {
	expression, ok := statement.(*ast.ExprStmt)
	if !ok {
		return false
	}
	exitCall, ok := expression.X.(*ast.CallExpr)
	if !ok || len(exitCall.Args) != 1 {
		return false
	}
	exitSelector, ok := exitCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	exitPackage, packageOK := exitSelector.X.(*ast.Ident)
	if !packageOK || aliases[exitPackage.Name] != "os" || exitSelector.Sel.Name != "Exit" {
		return false
	}
	runCall, ok := exitCall.Args[0].(*ast.CallExpr)
	if !ok || len(runCall.Args) != 0 {
		return false
	}
	runIdentifier, ok := runCall.Fun.(*ast.Ident)
	return ok && runIdentifier.Name == "run"
}

func validateProductionRuntimeSource(rel string, raw []byte) []string {
	parsed, aliases, err := parseGoFileWithAliases(rel, raw)
	if err != nil {
		return []string{runtimeGuardPrefix + ".parse: cannot parse " + rel}
	}
	var problems []string
	newProduction := findFunction(parsed, "NewProduction", "")
	if newProduction == nil || newProduction.Body == nil {
		return []string{runtimeGuardPrefix + ".constructor: NewProduction is missing"}
	}

	required := map[string]int{
		"trust-load": 0, "secret-load": 0, "database-open": 0, "oidc-http": 0,
		"webui-production": 0, "database-url": 0, "oidc-preflight": 0,
	}
	ordered := map[string]token.Pos{}
	listenCalls := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.GoStmt:
			if value.Pos() >= newProduction.Body.Pos() && value.End() <= newProduction.Body.End() {
				problems = append(problems, runtimeGuardPrefix+".constructor-goroutine: NewProduction must not start goroutines")
			}
		case *ast.CallExpr:
			function := enclosingFunction(parsed, value.Pos())
			selector, selectorOK := value.Fun.(*ast.SelectorExpr)
			if selectorOK && selector.Sel.Name == "ListenAndServe" {
				listenCalls++
				if function == newProduction {
					problems = append(problems, runtimeGuardPrefix+".constructor-listener: NewProduction must not bind or serve a listener")
				}
			}
			if selectorOK && function == newProduction {
				if identifier, ok := selector.X.(*ast.Ident); ok {
					importPath := aliases[identifier.Name]
					key := ""
					switch importPath + "." + selector.Sel.Name {
					case "knowvault.local/verified-workspace/internal/platform/trustbundle.LoadMounted":
						key = "trust-load"
					case "knowvault.local/verified-workspace/internal/platform/secretmount.LoadMountedForTenant":
						key = "secret-load"
					case "knowvault.local/verified-workspace/internal/platform/database.OpenProduction":
						key = "database-open"
					case "knowvault.local/verified-workspace/internal/platform/oidc.NewProductionHTTPClient":
						key = "oidc-http"
					case "knowvault.local/verified-workspace/internal/platform/webui.NewProduction":
						key = "webui-production"
					case "knowvault.local/verified-workspace/internal/platform/webui.New":
						problems = append(problems, runtimeGuardPrefix+".webui-fail-open: production composition must use webui.NewProduction")
					case "os.Getenv", "os.LookupEnv", "os.Environ", "knowvault.local/verified-workspace/internal/platform/httpserver.ConfigFromEnvironment":
						problems = append(problems, runtimeGuardPrefix+".constructor-env: NewProduction must consume only the validated Config snapshot")
					}
					if key != "" {
						required[key]++
						if _, exists := ordered[key]; !exists {
							ordered[key] = value.Pos()
						}
					}
				}
				if selector.Sel.Name == "DatabaseURL" {
					required["database-url"]++
					if _, exists := ordered["database-url"]; !exists {
						ordered["database-url"] = value.Pos()
					}
				}
			}
			if identifier, ok := value.Fun.(*ast.Ident); ok && function == newProduction && identifier.Name == "preflightOIDCProvider" {
				required["oidc-preflight"]++
				if _, exists := ordered["oidc-preflight"]; !exists {
					ordered["oidc-preflight"] = value.Pos()
				}
			}
		}
		return true
	})

	for name, count := range required {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s.%s-count: NewProduction requires exactly one AST call, found %d", runtimeGuardPrefix, name, count))
		}
	}
	if listenCalls != 1 {
		problems = append(problems, fmt.Sprintf("%s.listener-count: runtime.go requires exactly one ListenAndServe call, found %d", runtimeGuardPrefix, listenCalls))
	}
	order := []string{"trust-load", "secret-load", "database-url", "database-open", "oidc-preflight", "oidc-http", "webui-production"}
	for index := 1; index < len(order); index++ {
		if ordered[order[index-1]] != token.NoPos && ordered[order[index]] != token.NoPos && ordered[order[index-1]] >= ordered[order[index]] {
			problems = append(problems, runtimeGuardPrefix+".graph-order: production capability order drifted at "+order[index-1]+" -> "+order[index])
		}
	}
	problems = append(problems, validateOpaqueRuntime(parsed)...)
	return problems
}

// validateProductionPurgerRuntimeSource protects the privileged, non-listening
// purge composition root. It deliberately has a smaller capability inventory
// than the HTTP runtime: mounted trust, tenant secrets and the purger database
// role are the only production capabilities it may acquire.
func validateProductionPurgerRuntimeSource(rel string, raw []byte) []string {
	parsed, aliases, err := parseGoFileWithAliases(rel, raw)
	if err != nil {
		return []string{runtimeGuardPrefix + ".purger-parse: cannot parse " + rel}
	}
	var problems []string
	newProduction := findFunction(parsed, "NewProduction", "")
	if newProduction == nil || newProduction.Body == nil {
		return []string{runtimeGuardPrefix + ".purger-constructor: NewProduction is missing"}
	}
	required := map[string]int{"trust-load": 0, "secret-load": 0, "database-url": 0, "database-open": 0}
	ordered := map[string]token.Pos{}
	listenCalls := 0
	ast.Inspect(parsed, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.GoStmt:
			if value.Pos() >= newProduction.Body.Pos() && value.End() <= newProduction.Body.End() {
				problems = append(problems, runtimeGuardPrefix+".purger-constructor-goroutine: NewProduction must not start goroutines")
			}
		case *ast.CallExpr:
			function := enclosingFunction(parsed, value.Pos())
			selector, selectorOK := value.Fun.(*ast.SelectorExpr)
			if selectorOK && selector.Sel.Name == "ListenAndServe" {
				listenCalls++
				problems = append(problems, runtimeGuardPrefix+".purger-listener: privileged purger must never bind or serve a listener")
			}
			if !selectorOK || function != newProduction {
				return true
			}
			if identifier, ok := selector.X.(*ast.Ident); ok {
				importPath := aliases[identifier.Name]
				key := ""
				switch importPath + "." + selector.Sel.Name {
				case "knowvault.local/verified-workspace/internal/platform/trustbundle.LoadMounted":
					key = "trust-load"
				case "knowvault.local/verified-workspace/internal/platform/secretmount.LoadMountedForTenant":
					key = "secret-load"
				case "knowvault.local/verified-workspace/internal/platform/database.OpenProduction":
					key = "database-open"
				case "os.Getenv", "os.LookupEnv", "os.Environ":
					problems = append(problems, runtimeGuardPrefix+".purger-constructor-env: NewProduction must consume only the validated Config snapshot")
				case "knowvault.local/verified-workspace/internal/platform/oidc.NewProductionHTTPClient",
					"knowvault.local/verified-workspace/internal/platform/webui.NewProduction",
					"knowvault.local/verified-workspace/internal/platform/webui.New":
					problems = append(problems, runtimeGuardPrefix+".purger-capability: privileged purger acquired a non-purge production capability")
				}
				if key != "" {
					required[key]++
					if _, exists := ordered[key]; !exists {
						ordered[key] = value.Pos()
					}
				}
			}
			if selector.Sel.Name == "DatabaseURL" {
				required["database-url"]++
				if _, exists := ordered["database-url"]; !exists {
					ordered["database-url"] = value.Pos()
				}
			}
		}
		return true
	})
	for name, count := range required {
		if count != 1 {
			problems = append(problems, fmt.Sprintf("%s.purger-%s-count: NewProduction requires exactly one AST call, found %d", runtimeGuardPrefix, name, count))
		}
	}
	if listenCalls != 0 {
		problems = append(problems, fmt.Sprintf("%s.purger-listener-count: expected no ListenAndServe calls, found %d", runtimeGuardPrefix, listenCalls))
	}
	order := []string{"trust-load", "secret-load", "database-url", "database-open"}
	for index := 1; index < len(order); index++ {
		if ordered[order[index-1]] != token.NoPos && ordered[order[index]] != token.NoPos && ordered[order[index-1]] >= ordered[order[index]] {
			problems = append(problems, runtimeGuardPrefix+".purger-graph-order: privileged purge capability order drifted at "+order[index-1]+" -> "+order[index])
		}
	}
	problems = append(problems, validateOpaqueRuntime(parsed)...)
	return problems
}

func validateListenerPackageOwnership(rel string, parsed *ast.File, aliases map[string]string) []string {
	var problems []string
	// The e2e harness runs the product binaries against in-process test
	// fixtures (static IdP, TLS proxy) that must own listeners by nature; the
	// ownership invariant covers product HTTP surfaces, so test fixtures are
	// out of scope, mirroring the tests/ skip in checkOIDCImportBoundary.
	if strings.HasPrefix(rel, "tests/") {
		return nil
	}
	ast.Inspect(parsed, func(node ast.Node) bool {
		selectorValue, selectorExpression := node.(*ast.SelectorExpr)
		if selectorExpression {
			if identifier, ok := selectorValue.X.(*ast.Ident); ok && rel != httpServerProductionSource {
				importPath := aliases[identifier.Name]
				forbiddenReference := (importPath == "net" && selectorValue.Sel.Name == "ListenConfig") ||
					(importPath == "net/http" && (selectorValue.Sel.Name == "DefaultServeMux" || selectorValue.Sel.Name == "Server"))
				if forbiddenReference {
					problems = append(problems, runtimeGuardPrefix+".listener-api-owner: listener/global HTTP capability is owned only by "+httpServerProductionSource+": "+rel)
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, directPackageCall := selector.X.(*ast.Ident)
		importPath := ""
		if directPackageCall {
			importPath = aliases[identifier.Name]
		}
		forbidden := (importPath == "net" && strings.HasPrefix(selector.Sel.Name, "Listen") &&
			!(selector.Sel.Name == "ListenUnix" && (rel == sandboxDispatcherDispatchSource || rel == sandboxDispatcherV2Source))) ||
			(importPath == "net/http" && (selector.Sel.Name == "ListenAndServe" || selector.Sel.Name == "ListenAndServeTLS" || selector.Sel.Name == "Serve" || selector.Sel.Name == "ServeTLS" || selector.Sel.Name == "Handle" || selector.Sel.Name == "HandleFunc")) ||
			(importPath == "net/http" && selector.Sel.Name == "DefaultServeMux")
		if selector.Sel.Name == "Serve" {
			if parent, ok := selector.X.(*ast.SelectorExpr); ok && parent.Sel.Name == "Server" {
				forbidden = true
			}
		}
		if forbidden && rel != httpServerProductionSource {
			problems = append(problems, runtimeGuardPrefix+".listener-api-owner: listener/global HTTP API is owned only by "+httpServerProductionSource+": "+rel)
		}
		return true
	})
	return problems
}

func runtimeSensitiveImport(importPath string) bool {
	switch importPath {
	case "net", "net/http", "os",
		"knowvault.local/verified-workspace/internal/platform/database",
		"knowvault.local/verified-workspace/internal/platform/httpserver",
		"knowvault.local/verified-workspace/internal/platform/oidc",
		"knowvault.local/verified-workspace/internal/platform/secretmount",
		"knowvault.local/verified-workspace/internal/platform/trustbundle",
		"knowvault.local/verified-workspace/internal/platform/webui":
		return true
	default:
		return false
	}
}

func validateOpaqueRuntime(parsed *ast.File) []string {
	var problems []string
	for _, declaration := range parsed.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range generic.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || (typeSpec.Name.Name != "Runtime" && typeSpec.Name.Name != "runtimeState") {
				continue
			}
			structure, ok := typeSpec.Type.(*ast.StructType)
			if !ok {
				continue
			}
			for _, field := range structure.Fields.List {
				if typeSpec.Name.Name == "Runtime" {
					for _, name := range field.Names {
						if ast.IsExported(name.Name) {
							problems = append(problems, runtimeGuardPrefix+".opaque-runtime: Runtime must not expose fields")
						}
					}
				}
				if typeMentionsProductionHandler(field.Type) {
					problems = append(problems, runtimeGuardPrefix+".handler-exposure: Runtime lifecycle state must not expose HTTP/UI handlers")
				}
			}
		}
	}
	return problems
}

func typeMentionsProductionHandler(expression ast.Expr) bool {
	found := false
	ast.Inspect(expression, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.Ident:
			if value.Name == "Handler" || value.Name == "ProductionHandler" {
				found = true
			}
		case *ast.SelectorExpr:
			if value.Sel.Name == "Handler" || value.Sel.Name == "ProductionHandler" || value.Sel.Name == "Server" {
				found = true
			}
		}
		return !found
	})
	return found
}

func parseGoFileWithAliases(filename string, raw []byte) (*ast.File, map[string]string, error) {
	var source any
	if raw != nil {
		source = raw
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		return nil, nil, err
	}
	aliases := make(map[string]string)
	for _, imported := range parsed.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			continue
		}
		alias := filepath.Base(importPath)
		if imported.Name != nil {
			alias = imported.Name.Name
		}
		if alias != "." && alias != "_" {
			aliases[alias] = importPath
		}
	}
	return parsed, aliases, nil
}

func findFunction(parsed *ast.File, name, receiver string) *ast.FuncDecl {
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == name && (receiver == "" || methodReceiverNamed(function, receiver)) {
			return function
		}
	}
	return nil
}

func enclosingFunction(parsed *ast.File, position token.Pos) *ast.FuncDecl {
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Body != nil && position >= function.Body.Pos() && position <= function.Body.End() {
			return function
		}
	}
	return nil
}

func methodReceiverNamed(function *ast.FuncDecl, expected string) bool {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return false
	}
	expression := function.Recv.List[0].Type
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = pointer.X
	}
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == expected
}

func checkProductionRuntimeGuardMutations(raw []byte) []string {
	mutations := []struct{ name, old, replacement, expected string }{
		{"fail-open-webui", "webui.NewProduction(", "webui.New(", ".webui-fail-open:"},
		{"missing-preflight", "preflightOIDCProvider(", "mutatedPreflightOIDCProvider(", ".oidc-preflight-count:"},
		{"duplicate-listener", "runErr := runner.ListenAndServe(runContext)", "_ = runner.ListenAndServe(runContext)\n\trunErr := runner.ListenAndServe(runContext)", ".listener-count:"},
		{"constructor-goroutine", "func NewProduction(ctx context.Context, config Config, info buildinfo.Info) (*Runtime, error) {", "func NewProduction(ctx context.Context, config Config, info buildinfo.Info) (*Runtime, error) {\n\tgo func() {}()", ".constructor-goroutine:"},
	}
	var problems []string
	for _, mutation := range mutations {
		if !bytes.Contains(raw, []byte(mutation.old)) {
			problems = append(problems, runtimeGuardPrefix+".mutation-fixture: missing anchor for "+mutation.name)
			continue
		}
		mutated := bytes.Replace(raw, []byte(mutation.old), []byte(mutation.replacement), 1)
		detected := false
		for _, issue := range validateProductionRuntimeSource(runtimeProductionSource, mutated) {
			if strings.Contains(issue, runtimeGuardPrefix+mutation.expected) {
				detected = true
				break
			}
		}
		if !detected {
			problems = append(problems, runtimeGuardPrefix+".mutation-accepted: "+mutation.name)
		}
	}
	return problems
}

func checkStage1DatabaseGate(root string) []string {
	requiredFiles := map[string][]string{
		"api/openapi.yaml": {
			"HANDLER_READY_NOT_COMPOSED", "/session/csrf:", "/workspaces:", "/workspaces/{workspace_id}:",
			"/workspaces/{workspace_id}:archive:", "/workspaces/{workspace_id}/members:",
			"/workspaces/{workspace_id}/members/{principal_id}:", "/workspaces/{workspace_id}:transfer-ownership:",
			"Idempotency-Key", "If-Match", "X-KnowVault-CSRF", "Origin", "X-Request-ID", "X-Content-Type-Options",
			"PreconditionRequired", "RevisionConflict", "PayloadTooLarge", "SessionCookie",
		},
		"db/migrations/000001_stage1_tenancy.sql": {
			"ALTER ROLE knowvault_app NOSUPERUSER", "NOBYPASSRLS", "SET row_security = 'on'",
			"CREATE TABLE public.organization", "CREATE TABLE public.principal", "CREATE TABLE public.workspace",
			"CREATE TABLE public.workspace_revision", "CREATE TABLE public.workspace_member",
			"current_setting('app.organization_id', true)", "FORCE ROW LEVEL SECURITY",
			"GRANT SELECT, INSERT, UPDATE", "TO knowvault_app",
		},
		"internal/platform/database/database.go": {
			"pool *pgxpool.Pool", "func Open(", "verifyRuntimeRole", "session_user::text",
			"set_config('app.organization_id', $1, true)", "set_config('app.principal_id', $2, true)",
			"set_config('app.request_id', $3, true)", "NewOIDCServiceAccess", "IsNotFound", "func (store *Store) Read(", "func (store *Store) Write(",
		},
		"internal/platform/database/database_test.go": {
			"TestAccessContextRejectsAmbiguousIdentifiers", "TestOIDCServiceAccessIsTenantScopedAndDoesNotAcceptAnActorOverride", "TestIsNotFoundAcceptsOnlyTheDatabaseNoRowsSentinel", "TestConfigIsBoundedAndContentFree",
		},
		"internal/platform/database/production.go": {
			"func OpenProduction(", "startupLibpqEnvironmentPresent", "hasLibpqEnvironment(os.Environ())", "pgxpool.ParseConfig(config.URL)",
			"roots trustbundle.DatabaseRoots", "roots.NewCertPool()", "len(trustedRoots.Subjects()) == 0", "config.TLSConfig.InsecureSkipVerify", "config.TLSConfig.ServerName != target.host", "config.TLSConfig.RootCAs != nil", "len(config.Fallbacks) != 0", "len(config.RuntimeParams) != 0", "TLSConfig.RootCAs = trustedRoots",
		},
		"internal/platform/database/production_test.go": {
			"TestProductionPoolConfigPinsExactVerifyFullTarget", "TestProductionEnvironmentRejectsEveryDefinedPGPrefix",
			"TestProductionTargetRejectsNonCanonicalOrAmbiguousURLs", "TestProductionPostParseGateRejectsDilution", "TestProductionPoolConfigRequiresExplicitNonEmptyTrustRoots", "caller pool mutation changed production trust roots",
		},
		"internal/platform/trustbundle/bundle.go": {
			"DefaultMountRoot", "/run/knowvault/trust", "database-ca.pem", "oidc-ca.pem", "func LoadMounted()", "parseStrictPEM", "maximumBundleBytes", "maximumCertificates", "BasicConstraintsValid", "x509.KeyUsageCertSign", "UnhandledCriticalExtensions", "type DatabaseRoots struct", "type OIDCRoots struct", "type databaseRootsState struct", "type oidcRootsState struct", "NewDatabaseRootsPEM", "NewOIDCRootsPEM", "func (value Bundle) DatabaseRoots()", "func (value Bundle) OIDCRoots()", "func (value DatabaseRoots) NewCertPool()", "func (value OIDCRoots) NewCertPool()", "x509.ParseCertificate(owned)", "DatabaseFingerprint", "OIDCFingerprint", "sha256.Sum256(block.Bytes)", "sha256.Sum256(databaseRaw)", "sha256.Sum256(oidcRaw)", "[REDACTED]",
		},
		"internal/platform/trustbundle/reader_linux.go": {
			"//go:build linux", "syscall.O_DIRECTORY", "syscall.O_NOFOLLOW", "syscall.O_NONBLOCK", "syscall.O_CLOEXEC", "syscall.Openat", "syscall.Fstat", "info.Uid != 0", "consumer.GroupID()", "info.Gid != group", "info.Gid != root.group", "info.Nlink != 1", "0o750", "0o440", "stableRead", "len(contents) != int(initial.Size)", "sameFileSnapshot", "initial.Mtim", "initial.Ctim",
		},
		"internal/platform/trustbundle/reader_linux_test.go": {
			"TestStableReadRequiresExactInitialSize", "TestStableReadRequiresUnchangedSameFDMetadata", "TestStableReadAcceptsExactSnapshotAndRejectsSecondFstatFailure",
		},
		"internal/platform/trustbundle/reader_other.go": {
			"//go:build !linux", "CodeUnavailable",
		},
		"internal/platform/trustbundle/bundle_linux_test.go": {
			"TestLoadMountedReturnsPurposeSeparatedImmutableBundle", "TestPurposeRootsDeepCopyDERAndNeverExposeRetainedMaterial", "TestLoadMountedAcceptsSameEnterpriseIntermediateForBothPurposes", "TestLoadMountedRequiresBothPurposeBundles", "TestLoadMountedRejectsUnsafeFilesystemObjects", "TestLoadMountedRejectsWrongOwnershipAndRootMode", "TestLoadMountedRejectsMalformedOrUnsafeCertificates", "TestStrictPEMRejectsMoreThanMaximumCertificates", "TestZeroBundleFailsClosed",
		},
		"internal/platform/composition/config.go": {
			"type Config struct", "func LoadProduction()", "environment := os.Environ()", "KNOWVAULT_ORGANIZATION_ID", "KNOWVAULT_PROVIDER_ID",
			"KNOWVAULT_PUBLIC_ORIGIN", "KNOWVAULT_HTTP_ADDR", "seenFolded", "validPublicOrigin", "validHTTPAddress", "composition.Config{[REDACTED]}",
		},
		"internal/platform/composition/config_test.go": {
			"TestLoadProductionAcceptsOnlyCompleteCanonicalNonSecretConfiguration", "TestLoadProductionRejectsMissingUnknownAndCaseFoldedDuplicateVariables",
			"TestLoadProductionRejectsEmptyWhitespaceControlAndInvalidUTF8WithoutNormalization", "TestLoadProductionRejectsNonCanonicalPublicOrigin",
			"TestLoadProductionRejectsNonCanonicalHTTPAddress", "TestLoadProductionRejectsEveryWebAssetDirectoryOverride", "TestConfigurationErrorsAreContentFree", "TestConfigurationFormattingRedactsValueAndPointer",
		},
		"docs/adr/0036-production-postgresql-constructor-accepted.md": {
			"OpenProduction", "any defined `PG*`", "single-threaded", "pre-listener", "verify-full", "RuntimeParams",
		},
		"tests/integration/postgres/rls_test.go": {
			"TestRLSFailsClosedAcrossOrganizations", "TestRuntimeRoleCannotDeleteTenantRows",
			"TestIdentitySessionsAreTenantBoundOneTimeAndRevocable", "TestOIDCLoginAttemptTransitionsAndDigestOnlyStorage",
			"TestAuditAppendInTransactionCommitsAndRollsBackWithTheBusinessMutation",
			"TestIdentityRepositoryCreatesAuditedOneTimeSessionAndFailsClosedOnProviderChange",
			"TestWorkspaceRepositoryCreatesHashVerifiedTenantScopedWorkspace", "TestWorkspaceCommandConcurrentCreateCommitsExactlyOnce",
			"TestWorkspaceCommandReceiptRLSAndImmutabilityFailClosed", "TestWorkspaceManagerCanRemoveSelfAndReplayIsCurrentAccessGated",
			"TestWorkspaceInactiveTargetDenialIsTerminalAndExactReplaySafe", "TestWorkspaceCommandDatabaseGateRejectsRawStateBypasses", "LoadProviderConfiguration",
			"LoadPendingLoginConfiguration", "completed login replay did not deny", "provider current revision change did not deny pending load", "value.NonceDigest = mustKeyedDigest", "value.PKCEVerifierDigest = mustKeyedDigest",
		},
		"docs/adr/0012-stage1-postgresql-rls-gate-accepted.md": {
			"knowvault_app", "FORCE ROW LEVEL SECURITY", "transaction-local",
		},
		"db/migrations/000002_stage1_audit.sql": {
			"CREATE TABLE public.audit_event", "CREATE TABLE public.audit_chain_head",
			"FORCE ROW LEVEL SECURITY", "audit_event_no_mutation", "audit_event_chain_append",
			"USING ERRCODE = '40001'", "GRANT SELECT, INSERT ON TABLE public.audit_event",
		},
		"db/migrations/000003_stage1_identity.sql": {
			"CREATE TABLE public.oidc_provider", "CREATE TABLE public.external_identity",
			"CREATE TABLE public.oidc_login_attempt", "CREATE TABLE public.identity_session",
			"UNIQUE (organization_id, login_attempt_id)", "identity_session_login_completion_guard",
			"principal_identity_revocation_guard", "FORCE ROW LEVEL SECURITY",
		},
		"db/migrations/000004_stage1_workspace_command_idempotency.sql": {
			"CREATE TABLE public.workspace_revision_snapshot", "CREATE TABLE public.workspace_command_receipt",
			"idempotency_key_hash", "gate_version", "command_workspace_id", "command_target_principal_id", "command_resource_id",
			"app.current_principal_id()", "app.workspace_command_hash_is_valid", "app.workspace_command_gate_fresh_success",
			"workspace_command_receipt_insert_guard", "workspace_command_receipt_terminal_guard", "workspace_command_receipt_requires_terminal",
			"workspace_command_receipt_terminal_validator", "workspace_runtime_requires_success_receipt", "workspace_revision_runtime_requires_success_receipt",
			"workspace_revision_snapshot_runtime_requires_success_receipt", "workspace_member_runtime_requires_success_receipt",
			"workspace_command_receipt_actor_isolation", "workspace_revision_snapshot_no_mutation", "SECURITY DEFINER", "session_user = 'knowvault_app'", "FORCE ROW LEVEL SECURITY",
			"GRANT SELECT, INSERT ON TABLE public.workspace_revision_snapshot", "GRANT SELECT, INSERT, UPDATE ON TABLE public.workspace_command_receipt",
		},
		"db/migrations/000005_stage2_encrypted_artifact_outbox.sql": {
			"CREATE TABLE public.encrypted_artifact", "aad_schema_version", "app.encrypted_artifact_owner_is_valid",
			"wrapped_dek_hash", "size_bytes + 16", "octet_length(nonce) = 12",
			"UNIQUE (organization_id, kek_reference, kek_version, nonce)",
			"Keep nonce and hashes as non-decryptable purge provenance", "encrypted_artifact_state_guard",
			"CREATE TABLE public.outbox_sequence_head", "CREATE TABLE public.outbox_event", "app.outbox_payload_is_safe",
			"outbox_event_sequence_head_fk", "REFERENCES public.outbox_sequence_head(organization_id)",
			"^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$", "FOR SHARE",
			"app.enqueue_outbox_event", "last_assigned_sequence = last_assigned_sequence + 1", "outbox event must be published in tenant sequence order",
			"NEW.published_at := transaction_timestamp()", "SECURITY DEFINER", "FORCE ROW LEVEL SECURITY",
			"GRANT SELECT ON TABLE public.outbox_event TO knowvault_app",
		},
		"db/migrations/000006_stage2_source_connection_draft.sql": {
			"CREATE TABLE public.connector_capability_profile", "CREATE TABLE public.source_connection",
			"CREATE TABLE public.source_connection_revision", "CREATE TABLE public.source_connection_trust_record",
			"CREATE TABLE public.source_connection_trust_projection", "active_revision bigint CHECK (active_revision IS NULL)",
			"source_connection_latest_revision_exact", "source_connection_revision_trust_exact",
			"source_connection_revision_artifact_exact", "FORCE ROW LEVEL SECURITY", "GRANT SELECT ON TABLE",
		},
		"tests/integration/postgres/artifact_outbox_test.go": {
			"TestEncryptedArtifactCryptoShapePurgeAndRuntimeImmutability",
			"TestEncryptedArtifactAndOutboxRLSTenantIsolation",
			"TestOutboxRollbackGaplessAndConcurrentSequence",
			"TestOutboxPublishStrictOrderServerTimeAndImmutability",
			"TestTenantDeletionTransitionSerializesAfterArtifactAndOutboxCreation",
		},
		"tests/integration/postgres/source_connection_draft_test.go": {
			"TestSourceConnectionDraftChainIsFailClosedAndTenantReadable",
			"TestSourceConnectionRevisionAndTrustAreImmutable",
			"TestSourceConnectionExactTuplesRejectForgery",
			"TestSourceConnectionCheckpointRejectsAuthorityAndUnsafeReferences",
			"TestSourceConnectionHardDeleteRequiresTenantDeletionState",
		},
		"tests/integration/postgres/source_scope_draft_test.go": {
			"TestSourceScopeDraftChainIsTenantIsolatedAndFailClosed",
			"TestSourceScopeSchemaContainsNoRawExternalIdentity",
			"TestSourceScopeExactTuplesRejectForgery",
			"TestSourceScopeRowsAreImmutable",
			"TestSourceScopeHardDeleteRequiresExactChildFirstOrder",
		},
		"db/migrations/000008_stage2_workspace_source_snapshot.sql": {
			"CREATE TABLE public.workspace_source", "CREATE TABLE public.workspace_revision_source",
			"source_scope_revision_exact_binding_key", "workspace_revision_source_exact_workspace_snapshot_fk",
			"workspace_revision_source_exact_binding_fk", "workspace_revision_source_exact_scope_revision_fk",
			"workspace_revision_source_exact_set", "workspace_revision_snapshot_exact_source_set",
			"workspace_source_snapshot_exact_guard", "workspace_source_immutable", "workspace_revision_source_immutable",
			"member.principal_id = app.current_principal_id()", "FORCE ROW LEVEL SECURITY", "GRANT SELECT ON TABLE",
		},
		"tests/integration/postgres/workspace_source_snapshot_test.go": {
			"TestWorkspaceSourceSnapshotIsTenantIsolatedReadOnlyAndInert",
			"TestWorkspaceSourceSnapshotRejectsTupleAndCanonicalSetForgery",
			"TestWorkspaceSourceRowsAreImmutableAndDeleteChildFirst",
			"same-tenant workspace outsider",
		},
		"db/migrations/000009_stage2_workspace_source_command_gate.sql": {
			"ALTER TABLE public.workspace_command_receipt", "WORKSPACE_SOURCE_ADD", "WORKSPACE_SOURCE_REMOVE",
			"workspace_command_source_projection_validator", "workspace_source_projection_difference_count",
			"ordinary workspace command changed source projection", "workspace source command changed undeclared bindings",
			"workspace source add is not absent-or-disabled transition", "workspace source remove is not enabled-to-disabled transition",
			"workspace source command has stale base snapshot", "workspace source command requires ACTIVE base",
			"workspace source command did not install exact mutable projection", "workspace.updated_at = NEW.terminal_at",
			"workspace_source_id_closed_check", "workspace_source_generated_id_is_valid",
			"workspace_source_controller_insert", "workspace_revision_source_controller_insert",
			"member.role IN ('OWNER', 'MANAGER')", "member.valid_to_revision = workspace_revision_source.workspace_revision",
			"(NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL)",
			"(audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id)",
			"audit_row.workspace_id IS DISTINCT FROM NEW.command_workspace_id",
			"GRANT SELECT, INSERT ON TABLE public.workspace_source, public.workspace_revision_source TO knowvault_app;",
		},
		"docs/adr/0050-workspace-source-command-gate-accepted.md": {
			"single actor-scoped", "one fresh immutable workspace revision", "stable lineage",
			"changes exactly one", "carry every row forward exactly", "OWNER", "MANAGER",
			"seven content-free target fields", "no confirmation or authority", "no activation, connector job/event",
			"must be `ACTIVE`", "exact result revision", "existence oracle", "caller-prefix ID validator",
		},
		"internal/workspace/repository/source_projection_test.go": {
			"TestSourceProjectionRequiresExactCanonicalBindingSet", "TestEveryOrdinaryWorkspaceRevisionCarriesExactSourceProjection",
			`"metadata"`, `"member add"`, `"archive"`,
		},
		"tests/contracts/runner/audit_workspace_source_test.go": {
			"TestWorkspaceSourceAuditProjectionAcceptsEveryTerminalOutcome", "denied hidden workspace", "failed missing workspace",
		},
		"tests/integration/postgres/workspace_source_command_gate_test.go": {
			"TestWorkspaceSourceClosedIDValidatorExposesOnlyBindingAndScope",
			"TestWorkspaceSourceCommandGateAllowsOneExactAddAndKeepsScopeDraft",
			"TestWorkspaceSourceRemoveAndReAddReuseStableLineage",
			"TestWorkspaceSourceCommandRejectsCanonicalMutableAndPointerSmuggling",
			"TestWorkspaceSourceCommandRejectsReadOnlyAndArchivedBase",
			"TestWorkspaceSourceCommandRejectsStaleBaseSnapshot",
			"TestWorkspaceSourceCommandRejectsUndeclaredSecondBindingChange",
			"TestOrdinaryWorkspaceCommandsCarryNonEmptySourceProjectionExactly",
			"TestWorkspaceSourceLineageRequiresFreshExactAddReceipt",
			"TestWorkspaceSourceFailureReceiptsAreTerminalWithoutMutation",
			"TestWorkspaceMemberCannotInsertSourceConfiguration",
			"TestManagerSelfRemovalCarriesSourcesOnceThenLosesInsertAuthority",
		},
		"db/migrations/000010_stage2_workspace_managed_confirmation_authority.sql": {
			"CREATE TABLE public.organization_policy_revision", "CREATE TABLE public.workspace_managed_warning_contract",
			"CREATE TABLE public.workspace_source_confirmation_actor_grant", "CREATE TABLE public.workspace_source_confirmation_actor_grant_revocation",
			"CREATE TABLE public.workspace_managed_grant_confirmation", "CREATE TABLE public.workspace_managed_grant_revocation",
			"organization_policy_revision_safe_integer", "CHECK (policy_revision BETWEEN 1 AND 9007199254740991)",
			"app.authority_current_policy_guard()", "requires the current organization policy revision",
			"app.stage2_opaque_id_is_valid(grant_id)", "app.stage2_opaque_id_is_valid(confirmation_id)",
			"workspace_revision_source_exact_confirmation_target_key", "workspace_managed_grant_confirmation_target_fk",
			"FOR UPDATE", "FORCE ROW LEVEL SECURITY", "GRANT SELECT ON TABLE",
			"sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d",
			"WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
			"app.workspace_managed_grant_confirmation_derived_live_guard",
			"app.workspace_managed_warning_contract_current_revision()",
			"warning is not the current registry revision",
		},
		"tests/integration/postgres/workspace_managed_confirmation_authority_test.go": {
			"TestConfirmationAuthorityMigrationApplies", "TestOrganizationPolicyRegistryBridge",
			"TestOrganizationPolicyRevisionSafeIntegerBound", "TestPolicyRegistryAllowsMonotonicGapsNotContiguous",
			"TestCurrentPolicyInvariantAcrossAuthorityTables", "TestGrantExpiryCannotBeBackdated",
			"TestAuthorityIDsAcceptCanonicalOpaqueForms", "TestWarningRegistryV1IsSealedAndImmutable",
			"TestWarningRevisionAdvanceMakesOldConfirmationStaleAndBlocksNewConfirmations",
			"TestAuthorityTimestampV1Validator", "TestConfirmationCompositeForeignKeysRejectForgery",
			"TestSourceEnforcedConfirmationRejected", "TestOneRevocationPerParent",
			"TestAuthorityRowsAreImmutable", "TestTenantHardDeleteRequiresChildFirstOrder",
			"TestAuthorityRLSFailsClosed", "TestAuthorityCatalogPrivilegeMatrixIsSelectOnly",
			"TestAuthorityHelperFunctionsAreNotExecutable", "TestConcurrentConfirmationsForSameTupleCommitAtMostOnce",
			"TestConfirmationVersusGrantRevocationConcurrency", "TestReplacementConfirmationVersusConfirmationRevocationConcurrency",
			"TestRevokeThenReplaceRequiresNewConfirmationID", "TestGrantRevocationKillSwitchDisablesDependentConfirmations",
			"fetchAuthorityClock", "emulateFutureWarningRevision",
		},
		"docs/adr/0046-encrypted-artifact-and-ordered-outbox-foundation-accepted.md": {
			"8 MiB", "closed 26-branch map", "purge provenance", "tenant-local ordered stream",
			"cannot update or", "delete events", "No outbox applier may be composed", "lease/CAS", "No new runtime component or dependency",
			"storage foundation, not permission to compose an", "tenant-bound composite",
		},
		"docs/adr/0047-source-control-plane-revision-and-activation-boundaries-accepted.md": {
			"immutable configuration", "latest_revision", "active_revision", "exact workspace binding",
			"only a safe control-plane draft", "no query, connector event or content-bearing", "no new dependency or license",
		},
		"docs/adr/0048-source-discovery-and-scope-draft-checkpoint-accepted.md": {
			"storage checkpoint only", "explicit keyed-digest", "Every scope and activation remains `DRAFT`",
			"active_revision` remains `NULL`", "future activation and use gate must re-check", "No new runtime component, dependency or license",
		},
		"docs/adr/0049-inert-workspace-source-snapshot-accepted.md": {
			"storage checkpoint only", "complete arrays in both directions", "contains no `workspace_managed_grant_confirmation`",
			"workspace ownership alone must not grant source data", "confers no retrieval or ingestion authority", "No dependency or license",
		},
		"db/migrations/000007_stage2_source_scope_draft.sql": {
			"CREATE TABLE public.source_discovered_scope", "CREATE TABLE public.source_scope (",
			"CREATE TABLE public.source_scope_revision", "CREATE TABLE public.source_scope_activation",
			"source_scope_revision_discovery_fk", "source_scope_revision_policy_exact",
			"source_discovered_scope_artifact_exact", "source_scope_revision_artifact_exact",
			"source_scope_latest_revision_exact", "active_revision bigint CHECK (active_revision IS NULL)",
			"scope_contract_version", "FORCE ROW LEVEL SECURITY", "GRANT SELECT ON TABLE",
		},
		"architecture/contracts/source-scope.schema.json": {
			"Immutable Source Scope Revision 1.2", "\"schema_version\": { \"const\": \"1.2\" }",
			"discovered_scope_id", "discovered_identity_digest", "hmac-sha256:k",
		},
		"tests/contracts/runner/source_scope.go": {
			"validateDiscoveredScopeTrust", "sourceDiscoveryIdentityInput", "SOURCE_SCOPE_DISCOVERY_MISMATCH", "discovered_identity_digest",
			"hmac.New(sha256.New, keyBytes)", "discovery_digest_test_keys",
		},
		"docs/TRUST_BOUNDARY.md": {"/db/**"},
		"POKA_YOKE.md":           {"JOB-005", "SRC-017"},
		"internal/audit/audit.go": {
			"func Build(", "encoding/json/jsontext", "func (store *Store) Append(",
			"func (store *Store) AppendInTransaction(", "database.IsSerializationFailure", "canonicalEvidenceIDs",
			"ResourceWorkspaceSource", "ActionWorkspaceSourceAdded", "ActionWorkspaceSourceRemoved", "validActionProjection",
			"sourceMutationMetadataOnly", "input.Outcome == OutcomeSuccess && input.WorkspaceID == nil",
		},
		"internal/audit/audit_test.go": {
			"TestBuildDerivesCanonicalEventAndHash", "TestBuildSerializesEmptyEvidenceAsArray",
			"TestBuildWorkspaceSourceMutationUsesExactContentFreeProjection", "TestBuildRejectsInexactWorkspaceSourceMutationProjection",
			"TestBuildWorkspaceSourceMutationAcceptsEveryTerminalOutcome", "denied hidden workspace",
			"failed missing workspace", `"missing workspace"`,
		},
		"architecture/contracts/audit-event.schema.json": {
			"WORKSPACE_SOURCE", "workspace_source_id", "scope_config_hash", "access_mode", "enabled",
		},
		"tests/contracts/runner/audit.go": {
			"validateWorkspaceSourceAuditProjection", "workspace_revision", "workspace_source_id", "scope_config_hash", "access_mode", "enabled",
			`stringValue(event["outcome"]) == "SUCCESS"`,
		},
		"internal/policy/decision.go": {
			"func EvaluateWorkspace(", "func EvaluateOrganization(", "ReasonOrganizationMismatch", "OperationWorkspaceCreate", "OperationWorkspaceReadContent",
		},
		"internal/policy/decision_test.go": {
			"TestOrganizationAdminDoesNotReceiveWorkspaceContentAccess", "TestEvaluateOrganizationAllowsOnlyActiveOwnerOrAdminToCreateWorkspace",
		},
		"internal/workspace/workspace.go": {
			"func Normalize(", "func CanonicalSnapshot(", "func ParseCanonicalSnapshot(", "func ConfigurationHash(", "func IsConfigurationHash(", "func NextMetadata(", "func NextWithMember(", "func NextWithoutMember(", "func NextWithMemberRole(", "func NextOwnershipTransferred(", "func NextSourceBindingEnabled(", "func NextSourceBindingDisabled(", "func NextArchived(", "workspace-configuration-v1", "norm.NFC", "source_bindings",
		},
		"internal/workspace/workspace_test.go": {
			"TestNormalizeAndConfigurationHashAreCanonical", "TestNormalizeRejectsAmbiguousOrUnsafeWorkspaceConfiguration", "TestNextRevisionMutationsPreserveImmutableConfigurationRules", "TestNextSourceBindingEnabledAddsOrReenablesOnlyExactBinding", "TestNextSourceBindingDisabledRetainsOnlyExactBinding",
		},
		"internal/workspace/repository/repository.go": {
			"func (store *Store) Create(", "func (store *Store) Get(", "func (store *Store) List(", "func (store *Store) Update(", "func (store *Store) AddMember(", "func (store *Store) ChangeMemberRole(", "func (store *Store) RemoveMember(", "func (store *Store) TransferOwnership(", "func (store *Store) Archive(", "IdempotencyKey", "ExpectedConfigurationHash", "CodeRevisionConflict", "CodeIdempotencyConflict", "appendFailed", "valid_to_revision = $4", "AppendInTransaction", "EvaluateOrganization", "ConfigurationHash",
			"revisionSourceProjection", "loadCurrentSnapshot", "sourceProjectionMatchesSnapshot",
			"sourceProjectionMatchesBindings", "carrySourceProjection", "currentSources",
		},
		"internal/workspace/repository/idempotency.go": {
			"workspace-command-v1", "type commandIntent struct", "func commandResourceID(", "func reserveCommand(", "func persistRevisionSnapshot(", "func completeCommand(", "ParseCanonicalSnapshot", "idempotencyKeyHash",
			"workspace_revision_source", "carriedSources",
		},
		"internal/workspace/repository/idempotency_test.go": {
			"TestWorkspaceCommandHashesAreTypedCanonicalAndUnicodeNormalized", "TestIdempotencyKeyRequiresCanonical256BitBase64URL",
		},
		"internal/identity/identity.go": {
			"func Validate(", "NewKeyedDigest", "UnknownCurrentPrincipal", "UnknownCurrentProvider", "ProviderRevision", "CodeSessionMismatch", "CodePrincipalInactive",
		},
		"internal/identity/identity_test.go": {
			"TestValidateAcceptsOnlyExactCurrentActiveSnapshot", "TestValidateFailsClosedForChangedOrUnavailableCurrentState", "TestKeyedDigestAcceptsOnlyVersionedLowercaseHMACSHA256",
		},
		"internal/identity/repository/repository.go": {
			"func (store *Store) BeginLogin(", "func (store *Store) LoadProviderConfiguration(", "func (store *Store) LoadPendingLoginConfiguration(", "func (store *Store) CompleteLogin(", "func (store *Store) ResolveSession(",
			"type PendingLoginRequest struct", "attempt.nonce_digest = $7", "attempt.pkce_verifier_digest = $8", "provider.current_revision = attempt.provider_revision",
			"request.ProviderRevision", "request.NonceDigest.Value()", "request.PKCEVerifierDigest.Value()", "NewOIDCServiceAccess", "AppendInTransaction", "ActorSystem", "NewKeyedDigest",
		},
		"internal/platform/oidc/oidc.go": {
			"func NewSecureAttempt(", "func newAttempt(", "func Discover(", "func (client *Client) AuthorizationURL(", "func (client *Client) ExchangeAndVerify(",
			"S256ChallengeOption", "ConstantTimeCompare", "go-oidc", "session_token", "csrf", "type HMACDigestor struct", "type hmacDigestorState struct", "func (digestor *HMACDigestor) Close()", "clear(digestor.state.secret)", "ValidateProviderConfiguration", "KeyMaterialFingerprint", "TransportMaterial", "attemptOriginFresh", "attemptOriginRestored", "RestoreTransportAttempt", "allDistinct", "[REDACTED]", "func (Client) GoString()",
		},
		"internal/platform/oidc/oidc_test.go": {
			"TestNewAttemptUsesDistinctCSPRNGValuesAndDomainSeparatedDigests", "TestDigestorAndConfigurationFailClosed", "TestSessionAndCSRFDigestsAreDomainSeparated",
			"forged.TransportMaterial", "restored.TransportMaterial", "RestoreTransportAttempt", "TestHMACDigestorFormattingDoesNotExposeSecret", "TestHMACDigestorCopiesShareCloseAndZeroizeRetainedSecret", "TestHMACDigestorConcurrentCloseIsRaceSafe", "TestValidateProviderConfigurationReturnsContentFreeError", "TestOIDCErrorAndClientFormattingDoNotExposeCausesOrDigestors", "TestAttemptDigestFailureIsMappedToContentFreeOIDCError",
		},
		"internal/platform/httpauth/auth.go": {
			"__Host-knowvault_session", "X-KnowVault-CSRF", "type TenantSecurityContext struct", "Resolve(context.Context) (TenantSecurityContext, error)",
			"Digest(\"session_token\"", "Digest(\"csrf\"", "ResolveSession(", "subtle.ConstantTimeCompare", "headerValues", "Claims.PrincipalID()",
		},
		"internal/platform/httpauth/auth_test.go": {
			"TestAuthenticateRejectsAbsentDuplicateAndMalformedSessionCookies", "TestAuthenticateRejectsInconsistentResolvedSession",
			"TestAuthenticatePropagatesServerRequestIDAndReturnsOnlyDerivedProof", "TestVerifyCSRFFailsClosedAndExemptsSafeMethods",
			"TestAuthenticateRejectsInvalidTenantSecurityContext", "TestVerifyCSRFUsesExactTenantOrigin",
		},
		"internal/platform/tenantsecurity/tenantsecurity.go": {
			"type Context struct", "identityKeyRef", "sessionKeyRef", "value.identityKeyRef != value.sessionKeyRef",
			"type StaticResolver struct", "type HTTPAuthResolver struct", "security.sessionDigestor", "Resolve(ctx context.Context)",
			"[REDACTED]", "digestorAvailable", "sameDigestorInstance", "purposeAllowed", "ValidateOIDCTransportKeySelection", "KeyMaterialFingerprint", "ConstantTimeCompare",
		},
		"internal/platform/tenantsecurity/tenantsecurity_test.go": {
			"TestContextRequiresDistinctKeySelectionsAndCanonicalDeploymentIdentity", "same key reference", "typed nil digestor",
			"TestContextRequiresIndependentOIDCTransportKeyReference", "TestStaticAndHTTPResolversNeverSelectTenantFromRequestData", "TestErrorsAreContentFreeAndHaveNoUnwrapChain",
		},
		"internal/platform/browserauth/browserauth.go": {
			"sessionBytes", "maximumSessionLife", "type SessionMaterial struct", "[REDACTED]", "Digest() identity.KeyedDigest",
			"NewSessionMaterial(security tenantsecurity.Context)", "security.SessionDigestor().Digest(\"session_token\"", "httpauth.SessionCookieName",
			"Secure: true", "HttpOnly: true", "SameSite: http.SameSiteLaxMode", "MaxAge: maxAge",
		},
		"internal/platform/browserauth/browserauth_test.go": {
			"TestSessionMaterialUsesOnlySessionSelectionAndRedactsFormatting", "TestCookieIssuerEmitsExactHostOnlyBoundedProfile",
			"TestCookieIssuerFailsClosedWithoutWritingOnInvalidMaterialOrLifetime", "TestSessionMaterialFailsClosedOnEntropyAndDigestErrors",
		},
		"internal/platform/oidctransport/codec.go": {
			"__Host-knowvault_oidc", "AES-256-GCM", "oidc-transport-v1", "oidc-cookie-aad-v1", "maxEnvelopeBytes", "maxPlaintextBytes", "maxAttemptLifetime",
			"NewRecord(", "attempt oidc.Attempt", "attempt.TransportMaterial", "MatchesState", "RestoreAttempt", "oidc.RestoreTransportAttempt", "allDistinct", "validKeyID", "ValidateOIDCTransportKeySelection", "type codecState struct", "func (codec *Codec) Close() error", "clear(state.key[:])", "newAEADLocked", "sha256.Sum256(key)", "cipher.NewGCM", "rand.Reader", "jsontext.Value", "Canonicalize", "RejectUnknownMembers(true)", "AllowDuplicateNames(false)", "[REDACTED]",
		},
		"internal/platform/oidctransport/codec_test.go": {
			"TestSealOpenRoundTripUsesCanonicalEnvelopeAndRedactsFormatting", "TestOpenFailsClosedForMalformedUnknownAndAADMismatch",
			"TestEnvelopeWorksAcrossInstancesAndRotationInvalidatesPendingLogin", "TestOpenStrictlyRejectsPlaintextSchemaTenantAndExpiry",
			"TestCanonicalPlaintextAADAndKidLimit", "delimiter kid", "reused verifier", "TestCodecCopiesShareCloseAndEraseRetainedKey", "TestCodecZeroAndNilHandlesFailClosed", "TestCodecCloseWaitsForInflightSeal", "TestCodecConcurrentCopiesAreRaceFree", "TestExportedRecordBoundaryAcceptsOnlySecureOIDCAttempt", "digest key reference reused for AEAD", "TestConfigurationRecordAndEntropyFailuresDoNotLeak",
		},
		"internal/platform/httpserver/server.go": {
			"defaultShutdownTimeout   = 75 * time.Second", "Runner", "Shutdown", "Close()",
		},
		"internal/platform/httpserver/server_test.go": {
			"defaultConfig.ShutdownTimeout != 75*time.Second", "TestRunnerServesAndShutsDownAfterCancellation",
		},
		"internal/platform/webui/handler.go": {
			"imageAssetDirectory = \"/web/dist\"", "type ProductionHandler struct", "func NewProduction(api http.Handler) (*ProductionHandler, error)", "return newProduction(api, imageAssetDirectory)", "os.OpenRoot", "root.FS()", "root.Lstat(\"index.html\")", "maximumIndexBytes", "os.Lstat", "os.SameFile", "func (handler *ProductionHandler) Close() error", "handler.mu.RLock()", "CodeAssetsUnavailable", "func New(api http.Handler) http.Handler", "func newHandler(api http.Handler, assetDirectory string)",
		},
		"internal/platform/webui/handler_test.go": {
			"package webui", "newHandler(api, directory)", "TestProductionRequiresCompleteFixedShapeBeforeServing", "TestProductionRejectsNilAndTypedNilAPI", "TestProductionRejectsMissingInvalidEmptyAndOversizedIndex", "TestProductionRejectsSymlinkRootAndIndex", "TestProductionRootConfinesRelativeAndAbsoluteAssetSymlinks", "TestProductionCloseFailsClosedAndIsConcurrentServeSafe", "TestProductionErrorsAreContentFreeAndRedacted", "TestAPIPathsNeverFallThroughToUI", "TestUnknownNonAPIPathServesIndex",
		},
		"cmd/server/main.go": {
			"os.Exit(run())", "composition.LoadProduction()", "composition.NewProduction", "runtime.Run(ctx)", "lifecycle.SignalContext",
		},
		"cmd/worker/main.go": {
			"os.Exit(run())", "workercomposition.LoadProduction()", "workercomposition.NewProduction", "runtime.Run(ctx)", "lifecycle.SignalContext", "native-readiness", "workercomposition.CheckNativeReadiness",
		},
		"cmd/purger/main.go": {
			"os.Exit(run())", "purgercomposition.LoadProduction()", "purgercomposition.NewProduction", "runtime.Run(ctx)", "lifecycle.SignalContext",
		},
		"internal/platform/workercomposition/config.go": {
			"KNOWVAULT_WORKER_ID", "KNOWVAULT_WORKER_LEASE_SECONDS", "KNOWVAULT_WORKER_POLL_SECONDS", "rejected rather than silently ignored", "validOpaqueID", "KNOWVAULT_WORKER_NATIVE_PROFILE", "NativeProfileRevision",
		},
		"internal/platform/workercomposition/mounts.go": {
			"/run/knowvault/sources", "manifest.json", "knowvault-source-mount-manifest-v1", "RejectUnknownMembers(true)", "AllowDuplicateNames(false)", "filepath.Join(rootPath, entry.Directory)", "ModeSymlink",
		},
		"internal/platform/workercomposition/runtime.go": {
			"ApplicationRole = workerPrincipalID", "database.OpenProduction", "secretmount.LoadWorkerMountedForTenant", "trustbundle.LoadWorkerMounted", "search.LoadWorkerMountedForTenant", "embedding.LoadWorkerMountedForTenant", "runner.Execute", "WithLeaseExtensionSeconds", "closeReverse", "workercomposition.Runtime{[REDACTED]}", "CheckNativeReadiness(ctx, config)", "handler.WithOfficeExtractor(office).WithPDFExtractor(pdf)",
		},
		"internal/platform/workercomposition/native.go": {
			"/run/knowvault/sandbox/submit/dispatcher.sock", "dispatchparser.NewProduction(canonicalNativeSubmitSocket)", "dispatchparser.CheckProductionReadiness(ctx, canonicalNativeSubmitSocket)", "CodeNativeDisabled", "CodeNativeNotReady",
		},
		"internal/platform/purgercomposition/config.go": {
			"func LoadProduction()", "KNOWVAULT_PURGER_ID", "KNOWVAULT_PURGER_LEASE_SECONDS", "KNOWVAULT_PURGER_POLL_SECONDS", "seenFolded", "validOpaqueID", "purgercomposition.Config{[REDACTED]}",
		},
		"internal/platform/purgercomposition/runtime.go": {
			"purgerPrincipalID", "database.OpenProduction", "secretmount.LoadMountedForTenant", "purge.NewRunner", "closeReverse", "purgercomposition.Runtime{[REDACTED]}",
		},
		"deploy/images/Dockerfile.server": {
			"FROM scratch AS runtime", "COPY internal ./internal", "COPY web/dist /out/runtime/web/dist",
			"/out/runtime/run/knowvault/secrets", "/out/runtime/run/knowvault/trust", "find /out/runtime/web -type f -exec chmod 0440",
			"COPY --from=builder /out/runtime/web /web", "USER 65532:65532", "ENTRYPOINT [\"/knowvault-server\"]",
		},
		"deploy/images/Dockerfile.worker": {
			"FROM scratch AS runtime", "COPY internal ./internal", "COPY cmd/worker ./cmd/worker",
			"/out/runtime/run/knowvault/secrets", "/out/runtime/run/knowvault/sources", "/out/runtime/run/knowvault/trust",
			"USER 65530:65530", "ENTRYPOINT [\"/knowvault-worker\"]",
		},
		"deploy/images/Dockerfile.purger": {
			"FROM scratch AS runtime", "COPY internal ./internal", "COPY cmd/purger ./cmd/purger",
			"/out/runtime/run/knowvault/secrets", "/out/runtime/run/knowvault/trust",
			"USER 65532:65532", "ENTRYPOINT [\"/knowvault-purger\"]",
		},
		"internal/platform/oidctransport/cookie.go": {
			"type BrowserTransport struct", "type PreparedCookie interface", "WriteOnce", "CompareAndSwap(false, true)", "http.ParseCookie", "cookie.Quoted", "len(headers) != 1", "count != 1", "Secure: true", "HttpOnly: true", "SameSite: http.SameSiteLaxMode", "MaxAge: -1",
		},
		"internal/platform/oidctransport/cookie_test.go": {
			"TestBrowserTransportIssuesOpensAndClearsExactCookieProfile", "TestBrowserTransportRejectsDuplicateMissingMalformedAndOversizedCookies", "malformed sibling", "trailing empty pair", "quoted target", "TestBrowserTransportPreparesBeforeCommitAndIssuesCapabilityOnlyOnce", "panic(\"Issue must not consult the clock\")",
		},
		"internal/platform/oidc/httpclient.go": {
			"type HardenedHTTPClient struct", "NewProductionHTTPClient(roots trustbundle.OIDCRoots)", "roots.NewCertPool()", "len(rootCopy.Subjects()) == 0", "Proxy: nil", "MaxResponseHeaderBytes", "DisableCompression", "NewHardenedHTTPClient(transport *http.Transport)", "transport.Clone()", "InsecureSkipVerify", "MaxVersion", "tls.VersionTLS12", "http.ErrUseLastResponse", "request.URL.Scheme != \"https\"", "maximumOIDCResponseBodyBytes", "boundedResponseRoundTripper", "response.ContentLength > maximumOIDCResponseBodyBytes", "boundedResponseBody", "var probe [1]byte", "closeOnce.Do", "CloseIdleConnections", "[REDACTED]",
		},
		"internal/platform/oidc/httpclient_test.go": {
			"TestProductionHTTPClientRejectsMissingTrustRoots", "TestProductionHTTPClientOwnsExactDirectTransportProfile", "TestProductionHTTPClientCloseIdleConnectionsClosesItsPool", "caller mutation changed production trust roots", "TestHardenedHTTPClientAllowsOnlyHTTPSAndNeverFollowsRedirects", "TestHardenedHTTPClientRejectsDeclaredOversizedBodyBeforeReadingAndClosesIt", "TestHardenedHTTPClientRejectsChunkedOverflowAtMaxPlusOneAndClosesOnce", "TestHardenedHTTPClientAcceptsExactBodyLimitAndDelegatesClose", "TestExchangeUsesTheSameHardenedHTTPClient", "TestDiscoverExchangeAndJWKSUseInjectedHardenedClientNotDefaultClient", "TestHardenedHTTPClientRejectsUnsafeProductionTransport", "TestHardenedHTTPClientClosesOnlyItsInjectedIdleTransport",
		},
		"docs/adr/0039-customer-mounted-purpose-scoped-trust-roots-accepted.md": {
			"database-ca.pem", "oidc-ca.pem", "openat(O_NOFOLLOW)", "customer-supplied", "non-convertible opaque types", "copies of validated certificate DER", "system-root fallback", "restart",
		},
		"docs/adr/0040-bounded-oidc-response-streams-accepted.md": {
			"discovery, JWKS and token", "4 MiB", "streaming response-body limiter", "probes one additional byte", "closes the underlying body exactly once", "content-free", "CloseIdleConnections",
		},
		"internal/platform/oidcweb/handler.go": {
			"loginPath", "callbackPath", "type ClientSecretRequest struct", "ProviderRevision", "handler.browser.Clear(writer)", "prepared.WriteOnce(writer)", "LoadPendingLoginConfiguration", "CompleteLogin", "maximumSessionLife", "AUTH_CALLBACK_FAILED", "Cache-Control", "no-store",
		},
		"internal/platform/oidcweb/handler_test.go": {
			"TestLoginOrdersDurableCommitBeforeCookieAndPersistsExactProofs", "TestLoginNeverIssuesCookieBeforeBeginSucceeds", "TestCallbackClearsThenCompletesExactRevisionAndOnlyThenIssuesSession", "TestCallbackRejectsMismatchedClientSecretScope", "TestCallbackRejectsMalformedStateMismatchAndProtocolDenialWithoutLeaks", "TestHandlerRejectsRedirectMismatchAndStrictRoutes",
		},
		"internal/platform/apphttp/dispatcher.go": {
			"type Dispatcher struct", "exactPath", "inNamespace", "RawPath == \"\"", "systemapi.HealthPath", "systemapi.BuildInfoPath", "writeNotFound", "[REDACTED]",
		},
		"internal/platform/apphttp/dispatcher_test.go": {
			"TestDispatcherRoutesOnlyExactSpecialisedPaths", "TestDispatcherReservesEntireAuthNamespaceFromTheSPA", "encoded auth alias", "encoded api delimiter workspace", "TestDispatcherRejectsMissingAndTypedNilDependencies",
		},
		"internal/platform/secretmount/provider.go": {
			"knowvault-secret-manifest-v1", "LoadMountedForTenant", "DefaultMountRoot", "RejectUnknownMembers(true)", "AllowDuplicateNames(false)", "RawURLEncoding.Strict()", "keysAreIndependent", "sslmode=verify-full", "type IdentityKey struct", "type SessionKey struct", "type OIDCTransportKey struct", "type identityKeyState struct", "type sessionKeyState struct", "type transportKeyState struct", "func (value IdentityKey) Clear()", "func (value SessionKey) Clear()", "func (value OIDCTransportKey) Clear()", "func (provider *Provider) IdentityKey()", "func (provider *Provider) SessionKey()", "func (provider *Provider) OIDCTransportKey()", "type providerState struct", "func (Provider) String() string", "ValidateClientBinding", "func (provider *Provider) Close() error", "clear(state.databaseURL)", "[REDACTED]",
			"source_digest_hmac", "type SourceDigestKey struct", "type sourceDigestKeyState struct", "func (value SourceDigestKey) Clear()", "func (provider *Provider) SourceDigestKey()", "validSourceDigestKey",
		},
		"internal/platform/secretmount/reader_linux.go": {
			"syscall.Openat", "syscall.O_NOFOLLOW", "syscall.O_CLOEXEC", "syscall.Fstat", "info.Uid != 0", "info.Nlink != 1", "permissions == 0o400", "permissions == 0o440",
		},
		"internal/platform/secretmount/reader_other.go": {
			"//go:build !linux", "CodeUnavailable",
		},
		"internal/platform/secretmount/provider_linux_test.go": {
			"TestLoadMountedPreloadsExactMaterialAndResolvesTypedClientSecret", "TestPurposeTypedCapabilitiesOwnClearableCopiesWithoutClosingProvider", "TestCapabilityCopiesRaceSafelyWithClear", "identitySink := func(IdentityKey)", "sessionSink := func(SessionKey)", "transportSink := func(OIDCTransportKey)", "TestLoadMountedRejectsStrictManifestFormsAndTraversal", "TestLoadMountedRejectsManifestOutsideExpectedTenantScope", "arbitrary service file", "multiple host fallback", "TestProviderCloseZeroizesMaterialAndFailsClosed", "TestZeroProviderFailsClosedAndFormatsRedacted", "TestProviderConcurrentCloseAndAccessIsRaceSafe", "TestProviderNeverRereadsMountedSourceFilesAndRedactsFormatting",
			"sourceDigestSink := func(SourceDigestKey)", "duplicate source digest reference", "duplicate source digest material", "source digest after close",
		},
		"internal/platform/composition/preflight.go": {
			"preflightOIDCProvider", "startupRequestIDBytes", "rand.Read", "LoadProviderConfiguration", "oidcCallbackPath", "oidc.ValidateProviderConfiguration", "ValidateClientBinding", "CodeOIDCPreflightFailed", "[REDACTED]",
		},
		"internal/platform/composition/preflight_test.go": {
			"TestOIDCProviderPreflightLoadsAndValidatesExactCurrentBinding", "TestOIDCProviderPreflightRejectsEveryCurrentProjectionMismatchBeforeSecretLookup", "TestOIDCProviderPreflightRejectsZeroInvalidAndTypedNilInputsWithoutCalls", "TestOIDCProviderPreflightHonorsCancellationBeforeAndDuringDependencies", "TestOIDCProviderPreflightFailsClosedOnIDLoaderAndBindingErrors", "TestStartupRequestIDUsesCanonicalFreshCSPRNGMaterial",
		},
		"docs/adr/0041-purpose-typed-mounted-key-capabilities-accepted.md": {
			"IdentityKey", "SessionKey", "OIDCTransportKey", "non-convertible", "Calling `Clear`", "Provider retains", "race-safe",
		},
		"docs/adr/0042-production-local-readiness-gates-accepted.md": {
			"webui.NewProduction", "/web/dist", "2 MiB", "os.OpenRoot", "Root.FS", "ProductionHandler", "128-bit CSPRNG", "LoadProviderConfiguration", "oidc.ValidateProviderConfiguration", "performs no OIDC discovery", "COMPOSITION_OIDC_PREFLIGHT_FAILED",
		},
		"internal/platform/secretmount/reader_linux_test.go": {
			"TestMountedRootRejectsSymlinkFIFOAndDirectory", "TestZeroMountedRootCannotReadOrCloseAProcessDescriptor", "TestMountedRootRejectsNonRootOwnedRootAndFile", "TestMountedRootAcceptsRootOwnedGroupReadableFile", "TestMountedRootRejectsHardLinkedSecretFile",
		},
		"internal/platform/workspaceapi/workspaceapi.go": {
			"apiPrefix", "workspacesPath", "csrfPath", "Idempotency-Key", "If-Match", "X-Request-ID",
			"ForceQuery", "maxBodyBytes", "http.MaxBytesReader", "jsonv2.RejectUnknownMembers(true)",
			"PRECONDITION_REQUIRED", "WORKSPACE_REVISION_CONFLICT", "serviceErrorResponse", "http.StatusPreconditionFailed",
		},
		"internal/platform/workspaceapi/workspaceapi_test.go": {
			"TestCreateAuthenticatesThenCSRFFirstAndReturnsNoStoreETag", "TestStrictJSONAndConditionalHeadersFailClosed",
			"TestMutationsRequireCanonicalIfMatchAndDispatchAllRepositoryOperations", "TestInvalidRoutesQueriesAndMethodsDoNotReachService",
			"TestServiceErrorMappingPreservesPreconditionsAndResourceNonEnumeration", "TestRequestIDFailureDoesNotAuthenticateCallServiceOrEchoClientValue",
			"TestBodylessMutationsApplyEncodingAndSizeGate",
		},
		"docs/adr/0013-stage1-audit-foundation-accepted.md": {
			"audit_event", "canonicalized", "bounded transaction retry",
		},
		"docs/adr/0014-stage1-default-deny-policy-accepted.md": {
			"default deny", "Organization Admin", "audit.read_metadata",
		},
		"docs/adr/0015-stage1-oidc-dependency-lock-accepted.md": {
			"Authorization Code", "PKCE", "go-oidc", "hand-rolled JWT",
		},
		"docs/adr/0016-stage1-identity-session-foundation-accepted.md": {
			"session_revision", "DEPROVISIONED", "server-resolved", "fail closed",
		},
		"docs/adr/0017-stage1-identity-persistence-accepted.md": {
			"digest", "PENDING", "session_revision", "no HTTP login/callback route",
		},
		"docs/adr/0018-atomic-domain-audit-accepted.md": {
			"AppendInTransaction", "same `database.Write` transaction", "identity.login",
		},
		"docs/adr/0019-identity-repository-preauth-boundary-accepted.md": {
			"svc_oidc", "digest", "identity.login", "OIDC protocol adapter",
		},
		"docs/adr/0020-oidc-protocol-boundary-accepted.md": {
			"S256 PKCE", "go-oidc", "constant time", "provider revision",
		},
		"docs/adr/0021-canonical-workspace-configuration-accepted.md": {
			"workspace-configuration-v1", "NFC", "exactly one", "source bindings",
		},
		"docs/adr/0022-workspace-control-plane-repository-accepted.md": {
			"Organization `OWNER` or `ADMIN`", "same external `NOT_FOUND`", "configuration hash", "audit event",
		},
		"docs/adr/0023-workspace-revision-mutations-accepted.md": {
			"workspace.manage", "revision `n+1`", "ACTIVE principal", "ARCHIVED",
		},
		"docs/adr/0024-workspace-membership-lifecycle-accepted.md": {
			"owner-only", "valid_to_revision", "exactly one", "database.Write",
		},
		"docs/adr/0025-workspace-optimistic-concurrency-accepted.md": {
			"configuration hash", "WORKSPACE_REVISION_CONFLICT", "FAILED audit", "idempotency ledger",
		},
		"docs/adr/0026-workspace-command-idempotency-accepted.md": {
			"Idempotency-Key", "workspace-command-v1", "PENDING", "workspace_revision_snapshot", "current active identity",
		},
		"docs/adr/0027-workspace-runtime-command-gate-accepted.md": {
			"fresh `workspace_command_receipt`", "Deferred PostgreSQL", "SECURITY DEFINER", "session_user = 'knowvault_app'", "role switching",
		},
		"docs/adr/0028-http-session-and-csrf-boundary-accepted.md": {
			"TenantSecurityContext", "__Host-knowvault_session", "session_token", "X-KnowVault-CSRF", "constant time", "invalidates existing browser sessions",
		},
		"docs/adr/0029-workspace-http-control-plane-handler-accepted.md": {
			"internal/platform/workspaceapi", "32 KiB", "Idempotency-Key", "If-Match", "428", "412", "same external `404`", "not composed into `cmd/server`",
		},
		"docs/adr/0030-single-tenant-security-and-session-cookie-accepted.md": {
			"one deployment-bound tenant per server process", "two distinct", "session_token", "SameSite=Lax",
			"AEAD-sealed `__Host-knowvault_oidc`", "browser-binding cookie alone is insufficient",
		},
		"docs/adr/0031-oidc-sealed-browser-transport-accepted.md": {
			"__Host-knowvault_oidc", "oidc-transport-v1", "oidc-cookie-aad-v1", "AES-256-GCM", "key-material fingerprint", "opaque `oidc.Attempt`", "one active key", "different instances", "not a session",
		},
		"docs/adr/0032-oidc-callback-prerequisites-accepted.md": {
			"LoadPendingLoginConfiguration", "four digests", "atomic", "Fresh and restored", "http.ParseCookie", "does not add `/auth/login`",
		},
		"docs/adr/0033-oidc-browser-http-boundary-accepted.md": {
			"GET /auth/login", "GET /auth/callback", "one-shot", "WriteOnce", "HardenedHTTPClient", "does not yet", "cmd/server",
		},
		"docs/adr/0034-exact-root-http-dispatcher-accepted.md": {
			"apphttp.Dispatcher", "`http.DefaultServeMux`", "entire remaining `/auth` namespace", "remaining `/api` namespace", "not yet composed", "cmd/server",
		},
		"docs/adr/0035-linux-mounted-secret-boundary-accepted.md": {
			"knowvault-secret-manifest-v1", "LoadMountedForTenant", "openat", "UID 0", "0400 or 0440", "sslmode=verify-full", "does not yet authorize", "cmd/server",
		},
		"docs/adr/0037-production-nonsecret-composition-config-accepted.md": {
			"opaque, validated `Config`", "snapshots `os.Environ` exactly once", "Unknown names", "There are no defaults", "does not accept a caller-supplied root", "KNOWVAULT_WEB_ASSET_DIRECTORY", "Only", "`cmd/server`",
		},
		"docs/adr/0038-closeable-runtime-crypto-owners-accepted.md": {
			"copy-safe opaque handles", "HMACDigestor.Close", "Codec.Close", "operation-local AES-GCM", "zeroizes", "75 seconds", "does not yet authorize listener composition",
		},
	}
	var problems []string
	for relative, requiredFragments := range requiredFiles {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, "Stage 1 database gate missing required file: "+relative)
			continue
		}
		content := string(raw)
		for _, fragment := range requiredFragments {
			if !strings.Contains(content, fragment) {
				problems = append(problems, "Stage 1 database gate missing required control in "+relative+": "+fragment)
			}
		}
	}

	migration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000001_stage1_tenancy.sql"))
	if err == nil && strings.Count(string(migration), "FORCE ROW LEVEL SECURITY") < 6 {
		problems = append(problems, "Stage 1 database gate does not force RLS on every initial tenant relation")
	}
	auditMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000002_stage1_audit.sql"))
	if err == nil && strings.Count(string(auditMigration), "FORCE ROW LEVEL SECURITY") < 2 {
		problems = append(problems, "Stage 1 audit gate does not force RLS on audit event and chain head")
	}
	workspaceCommandMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000004_stage1_workspace_command_idempotency.sql"))
	if err == nil {
		content := string(workspaceCommandMigration)
		if strings.Count(content, "FORCE ROW LEVEL SECURITY") < 2 {
			problems = append(problems, "Stage 1 workspace command gate does not force RLS on receipt and immutable revision snapshot")
		}
		if strings.Count(content, "SECURITY DEFINER") < 9 {
			problems = append(problems, "Stage 1 workspace command gate lost a SECURITY DEFINER deferred validator or runtime shape guard")
		}
		if regexp.MustCompile(`(?m)^\s*idempotency_key\s+text\b`).MatchString(content) {
			problems = append(problems, "Stage 1 workspace command gate persists a raw Idempotency-Key instead of its SHA-256 hash")
		}
	}
	artifactOutboxMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000005_stage2_encrypted_artifact_outbox.sql"))
	if err == nil {
		ownerTuples, ownerProblems := loadEncryptedArtifactOwnerTuples(root)
		problems = append(problems, ownerProblems...)
		problems = append(problems, checkArtifactOutboxMigration(string(artifactOutboxMigration), ownerTuples)...)
		problems = append(problems, checkEncryptedArtifactOwnerParity(root, ownerTuples)...)
	}
	artifactContainmentMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000012_stage2_encrypted_artifact_containment.sql"))
	if err == nil {
		problems = append(problems, checkArtifactContainmentMigration(string(artifactContainmentMigration))...)
	}
	sourceDiscoveryMigration, sourceDiscoveryErr := os.ReadFile(filepath.Join(root, "db", "migrations", "000090_stage4_source_discovery.sql"))
	if sourceDiscoveryErr != nil {
		problems = append(problems, "Stage 4 source discovery gate missing migration 000090_stage4_source_discovery.sql")
	} else {
		ownerTuples, ownerProblems := loadEncryptedArtifactOwnerTuples(root)
		problems = append(problems, ownerProblems...)
		problems = append(problems, checkSourceDiscoveryMigration(string(sourceDiscoveryMigration), ownerTuples)...)
	}
	sourceDraftMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000006_stage2_source_connection_draft.sql"))
	if err == nil {
		problems = append(problems, checkSourceConnectionDraftMigration(string(sourceDraftMigration))...)
	}
	sourceScopeDraftMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000007_stage2_source_scope_draft.sql"))
	if err == nil {
		problems = append(problems, checkSourceScopeDraftMigration(string(sourceScopeDraftMigration))...)
	}
	workspaceSourceSnapshotMigration, err := os.ReadFile(filepath.Join(root, "db", "migrations", "000008_stage2_workspace_source_snapshot.sql"))
	if err == nil {
		problems = append(problems, checkWorkspaceSourceSnapshotMigration(string(workspaceSourceSnapshotMigration))...)
	}
	workspaceSourceCommandAccepted := false
	workspaceSourceCommandMigration, workspaceSourceCommandErr := os.ReadFile(filepath.Join(root, "db", "migrations", "000009_stage2_workspace_source_command_gate.sql"))
	if workspaceSourceCommandErr == nil {
		commandProblems := checkWorkspaceSourceCommandMigration(string(workspaceSourceCommandMigration))
		workspaceSourceCommandAccepted = len(commandProblems) == 0
		problems = append(problems, commandProblems...)
	}
	workspaceSourceRepositoryAccepted := workspaceSourceCommandAccepted && len(checkWorkspaceSourceRepository(root)) == 0
	confirmationAuthorityMigration, confirmationAuthorityErr := os.ReadFile(filepath.Join(root, "db", "migrations", "000010_stage2_workspace_managed_confirmation_authority.sql"))
	if confirmationAuthorityErr == nil {
		problems = append(problems, checkWorkspaceManagedConfirmationAuthorityMigration(string(confirmationAuthorityMigration))...)
	}
	sourceScopeSchema, sourceScopeErr := os.ReadFile(filepath.Join(root, "architecture", "contracts", "source-scope.schema.json"))
	if sourceScopeErr == nil {
		content := string(sourceScopeSchema)
		if strings.Contains(content, "workspace_managed_confirmation_id") || strings.Contains(content, `"external_scope_id"`) {
			problems = append(problems, "source scope v1.2 reintroduces reusable workspace consent or raw external identity authority")
		}
	}
	for _, rootName := range []string{"cmd", "internal"} {
		problems = append(problems, scanPaths(filepath.Join(root, rootName), func(path string) []string {
			if filepath.Ext(path) != ".go" {
				return nil
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return []string{readErr.Error()}
			}
			content := strings.ToLower(string(raw))
			if strings.Contains(content, "encrypted_artifact") || strings.Contains(content, "outbox_event") || strings.Contains(content, "enqueue_outbox_event") {
				return []string{"encrypted artifact repository or outbox delivery composed before its accepted owner/worker gate: " + relative(root, path)}
			}
			if regexp.MustCompile(`\b(?:from|insert\s+into|update|delete\s+from)\s+(?:public\.)?source_connection(?:_revision|_trust_record|_trust_projection)?\b`).MatchString(content) {
				return []string{"source connection repository composed before its accepted command/audit gate: " + relative(root, path)}
			}
			if regexp.MustCompile(`\b(?:from|insert\s+into|update|delete\s+from)\s+(?:public\.)?source_(?:discovered_scope|scope(?:_revision|_activation)?)\b`).MatchString(content) &&
				(!workspaceSourceRepositoryAccepted || filepath.ToSlash(relative(root, path)) != "internal/workspace/repository/source_commands.go") {
				return []string{"source scope repository composed before its accepted command/audit gate: " + relative(root, path)}
			}
			questionReadProjection := filepath.ToSlash(relative(root, path)) == "internal/question/service.go" &&
				!regexp.MustCompile(`\b(?:insert\s+into|update|delete\s+from)\s+(?:public\.)?workspace_(?:source|revision_source)\b`).MatchString(content)
			if regexp.MustCompile(`\b(?:from|insert\s+into|update|delete\s+from)\s+(?:public\.)?workspace_(?:source|revision_source)\b`).MatchString(content) &&
				(!workspaceSourceCommandAccepted || (!strings.HasPrefix(filepath.ToSlash(relative(root, path)), "internal/workspace/repository/") && !questionReadProjection)) {
				return []string{"workspace source repository composed before its accepted command/audit gate: " + relative(root, path)}
			}
			return nil
		})...)
	}
	httpAuth, err := os.ReadFile(filepath.Join(root, "internal", "platform", "httpauth", "auth.go"))
	if err == nil && strings.Contains(string(httpAuth), "func (errorValue *Error) Unwrap") {
		problems = append(problems, "HTTP auth error retains an unwrap chain that may disclose raw session-dependent adapter errors")
	}
	oidcProtocol, err := os.ReadFile(filepath.Join(root, "internal", "platform", "oidc", "oidc.go"))
	if err == nil && strings.Contains(string(oidcProtocol), "func NewAttempt(") {
		problems = append(problems, "production OIDC API exposes a caller-selected entropy source instead of the operating-system CSPRNG")
	}
	serverMain, err := os.ReadFile(filepath.Join(root, "cmd", "server", "main.go"))
	if err == nil && (strings.Contains(string(serverMain), "internal/platform/workspaceapi") || strings.Contains(string(serverMain), "internal/platform/oidcweb") || strings.Contains(string(serverMain), "internal/platform/apphttp") || strings.Contains(string(serverMain), "internal/platform/secretmount")) {
		problems = append(problems, "HTTP routes were composed before the accepted production composition slice")
	}
	if err == nil && (strings.Contains(string(serverMain), "KNOWVAULT_WEB_DIR") || strings.Contains(string(serverMain), "webui.New(systemapi.New(info),")) {
		problems = append(problems, "server can select an arbitrary web asset filesystem root")
	}
	serverDockerfile, dockerErr := os.ReadFile(filepath.Join(root, "deploy", "images", "Dockerfile.server"))
	if dockerErr == nil && strings.Contains(string(serverDockerfile), "KNOWVAULT_WEB_DIR") {
		problems = append(problems, "server image retains a deprecated web asset environment selector")
	}
	return problems
}

func loadEncryptedArtifactOwnerTuples(root string) ([]string, []string) {
	raw, err := os.ReadFile(filepath.Join(root, "architecture", "contracts", "encrypted-artifact-aad.schema.json"))
	if err != nil {
		return nil, []string{"cannot read encrypted artifact AAD schema"}
	}
	var schema struct {
		AllOf []struct {
			OneOf []struct {
				Properties map[string]struct {
					Const string `json:"const"`
				} `json:"properties"`
			} `json:"oneOf"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil || len(schema.AllOf) != 1 || len(schema.AllOf[0].OneOf) == 0 {
		return nil, []string{"cannot derive encrypted artifact owner inventory from AAD schema"}
	}
	result := make([]string, 0, len(schema.AllOf[0].OneOf))
	seen := make(map[string]bool)
	for _, branch := range schema.AllOf[0].OneOf {
		values := []string{
			branch.Properties["owner_table"].Const,
			branch.Properties["owner_column"].Const,
			branch.Properties["resource_type"].Const,
			branch.Properties["field"].Const,
		}
		valid := true
		for _, value := range values {
			valid = valid && value != "" && !strings.Contains(value, "'")
		}
		tuple := "('" + strings.Join(values, "', '") + "')"
		if !valid || seen[tuple] {
			return nil, []string{"AAD schema has an invalid or duplicate encrypted artifact owner branch"}
		}
		seen[tuple] = true
		result = append(result, tuple)
	}
	return result, nil
}

// checkEncryptedArtifactOwnerParity proves the closed 26-branch owner inventory
// is set-equal across all four sources of truth: the AAD schema (already
// reduced to ownerTuples), the SQL owner-validation function (checked by
// checkArtifactOutboxMigration), the typed Go runtime registry and the
// normative documentation table. It eliminates the owner-count drift class in
// one machine-checked gate.
func checkEncryptedArtifactOwnerParity(root string, ownerTuples []string) []string {
	if len(ownerTuples) == 0 {
		return []string{"encrypted artifact owner inventory is unavailable for parity"}
	}
	schemaSet := make(map[string]bool, len(ownerTuples))
	for _, tuple := range ownerTuples {
		schemaSet[tuple] = true
	}
	var problems []string

	goRaw, err := os.ReadFile(filepath.Join(root, "internal", "platform", "artifactcrypto", "owner_registry.go"))
	if err != nil {
		problems = append(problems, "cannot read artifactcrypto owner registry for parity")
	} else {
		problems = append(problems, compareOwnerInventory("Go runtime registry", schemaSet, extractOwnerTuples(encryptedArtifactGoOwnerPattern, string(goRaw)))...)
	}

	docsRaw, err := os.ReadFile(filepath.Join(root, "docs", "ENCRYPTION.md"))
	if err != nil {
		problems = append(problems, "cannot read ENCRYPTION.md for parity")
	} else {
		problems = append(problems, compareOwnerInventory("normative documentation", schemaSet, extractOwnerTuples(encryptedArtifactDocOwnerPattern, string(docsRaw)))...)
	}
	return problems
}

// encryptedArtifactGoOwnerPattern extracts the four owner-tuple components from
// each row of the typed Go registry literal in artifactcrypto/owner_registry.go.
var encryptedArtifactGoOwnerPattern = regexp.MustCompile(`ownerTable:\s*"([^"]+)",\s*ownerColumn:\s*"([^"]+)",\s*resourceType:\s*"([^"]+)",\s*aadField:\s*"([^"]+)"`)

// encryptedArtifactDocOwnerPattern extracts the owner tuple from each row of the
// normative documentation table in docs/ENCRYPTION.md.
var encryptedArtifactDocOwnerPattern = regexp.MustCompile("\\|\\s*`([a-z_0-9]+)\\.([a-z_0-9]+)`\\s*\\|\\s*`([A-Z_]+)\\s*/\\s*([A-Z_]+)`\\s*\\|")

func extractOwnerTuples(pattern *regexp.Regexp, content string) map[string]int {
	result := make(map[string]int)
	for _, match := range pattern.FindAllStringSubmatch(content, -1) {
		tuple := "('" + match[1] + "', '" + match[2] + "', '" + match[3] + "', '" + match[4] + "')"
		result[tuple]++
	}
	return result
}

func compareOwnerInventory(source string, schemaSet map[string]bool, other map[string]int) []string {
	var problems []string
	for tuple, count := range other {
		if count != 1 {
			problems = append(problems, "encrypted artifact "+source+" duplicates owner branch: "+tuple)
		}
		if !schemaSet[tuple] {
			problems = append(problems, "encrypted artifact "+source+" has an unaccepted owner branch: "+tuple)
		}
	}
	for tuple := range schemaSet {
		if _, ok := other[tuple]; !ok {
			problems = append(problems, "encrypted artifact "+source+" is missing owner branch: "+tuple)
		}
	}
	if len(other) != len(schemaSet) {
		problems = append(problems, "encrypted artifact "+source+" owner inventory count does not equal the accepted 26-branch schema")
	}
	return problems
}

func checkArtifactOutboxMigration(content string, ownerTuples []string) []string {
	var problems []string
	legacyOwnerTuples := make([]string, 0, len(ownerTuples))
	for _, tuple := range ownerTuples {
		if tuple != "('source_discovery_result', 'metadata_artifact_id', 'SOURCE_DISCOVERY_RESULT', 'DISCOVERY_METADATA')" {
			legacyOwnerTuples = append(legacyOwnerTuples, tuple)
		}
	}
	if strings.Count(content, "FORCE ROW LEVEL SECURITY") < 3 {
		problems = append(problems, "encrypted artifact/outbox gate does not force RLS on all three tenant relations")
	}
	start := strings.Index(content, "CREATE OR REPLACE FUNCTION app.encrypted_artifact_owner_is_valid(")
	endMarker := "\n$$;\n\nCREATE TABLE public.encrypted_artifact"
	end := strings.Index(content, endMarker)
	if start < 0 || end <= start || len(ownerTuples) == 0 {
		return append(problems, "encrypted artifact SQL owner function or schema inventory is unavailable")
	}
	ownerBody := content[start:end]
	ownerBody = regexp.MustCompile(`(?m)--.*$`).ReplaceAllString(ownerBody, "")
	ownerBody = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(ownerBody, "")
	for _, tuple := range legacyOwnerTuples {
		if strings.Count(ownerBody, tuple) != 1 {
			problems = append(problems, "encrypted artifact SQL owner inventory missing or duplicates exact branch: "+tuple)
		}
	}
	if strings.Count(ownerBody, "_artifact_id'") != len(legacyOwnerTuples) {
		problems = append(problems, "encrypted artifact SQL owner inventory has an unaccepted extra or missing branch")
	}
	if strings.Count(content, "UNIQUE (organization_id, kek_reference, kek_version, nonce)") != 1 ||
		strings.Contains(content, "UNIQUE (organization_id, kek_reference, kek_version, wrapped_dek_hash, nonce)") {
		problems = append(problems, "encrypted artifact nonce fence is not the exact tenant KEK reference/version tuple")
	}
	for statement, name := range map[string]string{
		"GRANT SELECT, INSERT ON TABLE public.encrypted_artifact TO knowvault_app;": "artifact",
		"GRANT SELECT ON TABLE public.outbox_sequence_head TO knowvault_app;":       "outbox head",
		"GRANT SELECT ON TABLE public.outbox_event TO knowvault_app;":               "outbox event",
	} {
		if strings.Count(content, statement) != 1 {
			problems = append(problems, "encrypted artifact/outbox gate lost exact runtime grant for "+name)
		}
	}
	allowedRuntimeGrants := map[string]bool{
		"grant select, insert on table public.encrypted_artifact to knowvault_app;": true,
		"grant select on table public.outbox_sequence_head to knowvault_app;":       true,
		"grant select on table public.outbox_event to knowvault_app;":               true,
		"grant execute on function app.stage2_opaque_id_is_valid(text), app.stage2_sha256_is_valid(text), app.outbox_reference_id_is_valid(text), app.encrypted_artifact_owner_is_valid(text, text, text, text), app.outbox_payload_is_safe(jsonb), app.enqueue_outbox_event(text, text, text, text, jsonb) to knowvault_app;": true,
	}
	grantPattern := regexp.MustCompile(`(?is)\bGRANT\s+[^;]+?\s+TO\s+knowvault_app\s*;`)
	for _, statement := range grantPattern.FindAllString(content, -1) {
		normalized := strings.Join(strings.Fields(strings.ToLower(statement)), " ")
		if allowedRuntimeGrants[normalized] {
			continue
		}
		problems = append(problems, "encrypted artifact/outbox gate contains an unexpected runtime grant: "+normalized)
	}
	for name, pattern := range map[string]string{
		"nontransactional-sequence": `(?i)\b(?:nextval|serial|generated\s+[^\n]*identity|create\s+sequence)\b`,
		"ordered-skip-locked":       `(?i)\bskip\s+locked\b`,
		"trigger-depth-capability":  `(?i)\bpg_trigger_depth\s*\(`,
		"before-insert-allocation":  `(?is)before\s+insert\s+on\s+public\.outbox_event`,
		"runtime-artifact-mutation": `(?is)grant\s+(?:all(?:\s+privileges)?|[^;]*(?:update|delete|truncate|references|trigger))[^;]*\bon\s+(?:table\s+)?public\.encrypted_artifact\b[^;]*\bto\s+knowvault_app`,
		"runtime-head-write":        `(?is)grant\s+(?:all(?:\s+privileges)?|[^;]*(?:insert|update|delete|truncate|references|trigger))[^;]*\bon\s+(?:table\s+)?public\.outbox_sequence_head\b[^;]*\bto\s+knowvault_app`,
		"runtime-event-write":       `(?is)grant\s+(?:all(?:\s+privileges)?|[^;]*(?:insert|update|delete|truncate|references|trigger))[^;]*\bon\s+(?:table\s+)?public\.outbox_event\b[^;]*\bto\s+knowvault_app`,
	} {
		if regexp.MustCompile(pattern).MatchString(content) {
			problems = append(problems, "encrypted artifact/outbox gate permits "+name)
		}
	}
	return problems
}

// checkArtifactContainmentMigration proves migration 000012 removes the runtime
// role's raw access to encrypted_artifact and exposes only a content-free
// readiness preflight. This is the independent database containment layer: the
// name-based anti-drift scan is only a signal, while these revokes are the
// enforced boundary.
// checkArtifactCompositionForbidden keeps the artifact runtime out of the server
// composition. The encrypted-artifact runtime may not be wired into cmd until an
// accepted readiness/preflight composition slice exists, so an active artifact
// under an unavailable key can never be served.
func checkArtifactCompositionForbidden(root string) []string {
	return scanPaths(filepath.Join(root, "cmd"), func(path string) []string {
		if filepath.Ext(path) != ".go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return []string{err.Error()}
		}
		content := string(raw)
		if strings.Contains(content, "internal/artifact/repository") || strings.Contains(content, "internal/platform/artifactcrypto") {
			return []string{"artifact runtime composed before its accepted readiness/preflight gate: " + relative(root, path)}
		}
		return nil
	})
}

func checkArtifactContainmentMigration(content string) []string {
	var problems []string
	lower := strings.ToLower(content)
	if strings.Count(lower, "revoke select, insert on public.encrypted_artifact from knowvault_app") != 1 {
		problems = append(problems, "containment migration does not revoke the runtime role's raw SELECT/INSERT on encrypted_artifact")
	}
	if regexp.MustCompile(`(?is)\bGRANT\s+[^;]*\bON\s+(?:table\s+)?public\.encrypted_artifact\b[^;]*\bTO\s+knowvault_app`).MatchString(content) {
		problems = append(problems, "containment migration re-grants runtime table access on encrypted_artifact")
	}
	if !strings.Contains(content, "app.artifact_unavailable_key_count(") {
		problems = append(problems, "containment migration lacks the readiness preflight function")
	}
	if !regexp.MustCompile(`(?is)artifact_unavailable_key_count\([^)]*\)\s+RETURNS\s+bigint\b(?:.|\n)*?SECURITY\s+DEFINER`).MatchString(content) {
		problems = append(problems, "containment preflight is not a SECURITY DEFINER count function")
	}
	if !regexp.MustCompile(`(?is)REVOKE\s+ALL\s+ON\s+FUNCTION\s+app\.artifact_unavailable_key_count\(text,\s*bigint\)\s+FROM\s+PUBLIC`).MatchString(content) {
		problems = append(problems, "containment preflight is not revoked from PUBLIC")
	}
	if !regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+app\.artifact_unavailable_key_count\(text,\s*bigint\)\s+TO\s+knowvault_app`).MatchString(content) {
		problems = append(problems, "containment preflight execute is not granted to the runtime role")
	}
	if !regexp.MustCompile(`(?is)SELECT\s+count\(\*\)\s+FROM\s+public\.encrypted_artifact`).MatchString(content) {
		problems = append(problems, "containment preflight does not restrict itself to a bare count")
	}
	if regexp.MustCompile(`(?is)grant\s+[^;]*(?:insert|update|delete|truncate|references|trigger)[^;]*\bon\s+(?:table\s+)?public\.encrypted_artifact\b[^;]*\bto\s+knowvault_app`).MatchString(lower) {
		problems = append(problems, "containment migration grants a mutating privilege on encrypted_artifact to the runtime role")
	}
	return problems
}

// checkSourceDiscoveryMigration proves the Stage 4 storage seam before any
// worker, HTTP or UI composition can treat discovery as a durable capability.
// It checks the closed job/payload vocabulary, owner-only enqueue command,
// lease-fenced worker commands, immutable request/result relations, and the
// encrypted-artifact owner branch. The real PostgreSQL suite proves the same
// controls against the database engine.
func checkSourceDiscoveryMigration(content string, ownerTuples []string) []string {
	var problems []string
	for _, fragment := range []string{
		"BEGIN;",
		"COMMIT;",
		"CREATE TABLE public.source_discovery_request",
		"CREATE TABLE public.source_discovery_result",
		"CREATE OR REPLACE FUNCTION app.source_discovery_request_enqueue(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_request_start(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_result_begin(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_result_bind_metadata(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_request_complete(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_request_fail(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_request_expire(",
		"CREATE OR REPLACE FUNCTION app.source_discovery_result_read_metadata(",
		"ALTER TABLE public.source_discovery_request FORCE ROW LEVEL SECURITY;",
		"ALTER TABLE public.source_discovery_result FORCE ROW LEVEL SECURITY;",
		"status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'EXPIRED')",
		"status text NOT NULL CHECK (status IN ('SUCCEEDED', 'NEEDS_INTERPRETATION'))",
		"CHECK (expires_at = issued_at + interval '15 minutes')",
		"CHECK (expires_at = created_at + interval '15 minutes')",
		"CHECK (prepared_view_count + needs_interpretation_view_count = view_count)",
		"CHECK (status <> 'SUCCEEDED' OR needs_interpretation_view_count = 0)",
		"UNIQUE (organization_id, request_id)",
		"app.source_discovery_failure_code_is_valid",
		"CREATE OR REPLACE FUNCTION app.source_discovery_revision_is_bound(",
		"app.source_discovery_job_payload_is_valid(payload_json)",
		"AND NOT (payload_json ? 'source_discovery_request_id')",
		"jsonb_build_object('source_discovery_request_id', p_request_id)",
		"IF session_user <> 'knowvault_app' THEN",
		"IF session_user <> 'knowvault_worker' THEN",
		"app.source_discovery_job_lease_is_live",
		"job.id = p_request_id",
		"job.idempotency_key = 'source-discovery:' || p_request_id",
		"app.complete_job(p_job_id, p_worker_id, p_lease_epoch)",
		"app.fail_job(",
		"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER",
	} {
		if !strings.Contains(content, fragment) {
			problems = append(problems, "Stage 4 source discovery migration is missing control: "+fragment)
		}
	}
	if strings.Count(content, "FORCE ROW LEVEL SECURITY") < 2 {
		problems = append(problems, "Stage 4 source discovery migration does not force RLS on both relations")
	}
	if strings.Count(content, "CREATE TABLE public.source_discovery_request") != 1 ||
		strings.Count(content, "CREATE TABLE public.source_discovery_result") != 1 {
		problems = append(problems, "Stage 4 source discovery migration creates a request or result relation more than once")
	}

	const discoveryOwnerTuple = "('source_discovery_result', 'metadata_artifact_id', 'SOURCE_DISCOVERY_RESULT', 'DISCOVERY_METADATA')"
	ownerStart := strings.Index(content, "CREATE OR REPLACE FUNCTION app.encrypted_artifact_owner_is_valid(")
	ownerEnd := -1
	if ownerStart >= 0 {
		ownerEnd = strings.Index(content[ownerStart:], "\n$$;")
	}
	if ownerStart < 0 || ownerEnd < 0 {
		problems = append(problems, "Stage 4 source discovery migration lacks its SQL encrypted-artifact owner validator")
	} else {
		ownerBody := content[ownerStart : ownerStart+ownerEnd]
		if strings.Count(ownerBody, discoveryOwnerTuple) != 1 {
			problems = append(problems, "Stage 4 SQL encrypted-artifact owner validator lacks one exact discovery-result branch")
		}
	}
	ownerAccepted := false
	for _, tuple := range ownerTuples {
		if tuple == discoveryOwnerTuple {
			ownerAccepted = true
			break
		}
	}
	if !ownerAccepted {
		problems = append(problems, "Stage 4 discovery-result artifact owner is absent from the accepted AAD inventory")
	}

	requestStart := strings.Index(content, "CREATE TABLE public.source_discovery_request")
	requestEnd := -1
	if requestStart >= 0 {
		requestEnd = strings.Index(content[requestStart:], "CREATE INDEX source_discovery_request_status_order")
	}
	if requestStart < 0 || requestEnd < 0 {
		problems = append(problems, "Stage 4 request relation definition is unavailable for field-boundary checks")
	} else {
		requestDefinition := content[requestStart : requestStart+requestEnd]
		for _, forbidden := range []string{"database_identity_hash", "privilege_digest", "credential_reference", "dsn", "catalog_oid"} {
			if strings.Contains(strings.ToLower(requestDefinition), forbidden) {
				problems = append(problems, "Stage 4 request persists a worker/source-only field: "+forbidden)
			}
		}
	}
	resultStart := strings.Index(content, "CREATE TABLE public.source_discovery_result")
	resultEnd := -1
	if resultStart >= 0 {
		resultEnd = strings.Index(content[resultStart:], "ALTER TABLE public.source_discovery_request\n")
	}
	if resultStart < 0 || resultEnd < 0 {
		problems = append(problems, "Stage 4 result relation definition is unavailable for tuple checks")
	} else {
		resultDefinition := content[resultStart : resultStart+resultEnd]
		for _, required := range []string{"actor_principal_id", "connection_id", "connection_revision", "trust_profile_hash", "security_epoch", "database_identity_hash", "privilege_digest", "metadata_artifact_id"} {
			if !strings.Contains(resultDefinition, required) {
				problems = append(problems, "Stage 4 result relation is missing exact tuple field: "+required)
			}
		}
	}

	lower := strings.ToLower(content)
	grantPattern := regexp.MustCompile(`(?is)\bgrant\s+[^;]+\s+on\s+(?:table\s+)?public\.(?:source_discovery_request|source_discovery_result)\b[^;]*\bto\s+(?:knowvault_app|knowvault_worker)\s*;`)
	for _, statement := range grantPattern.FindAllString(content, -1) {
		if strings.Contains(strings.ToLower(statement), "knowvault_app") ||
			strings.Contains(strings.ToLower(statement), "insert") ||
			strings.Contains(strings.ToLower(statement), "update") ||
			strings.Contains(strings.ToLower(statement), "delete") {
			problems = append(problems, "Stage 4 discovery relation grants direct runtime mutation: "+strings.Join(strings.Fields(statement), " "))
		}
	}
	if regexp.MustCompile(`(?is)\bgrant\s+(?:all|[^;]*(?:insert|update|delete|truncate|references|trigger))[^;]*\bon\s+(?:table\s+)?public\.(?:source_discovery_request|source_discovery_result)\b[^;]*\bto\s+(?:knowvault_app|knowvault_worker)`).MatchString(lower) {
		problems = append(problems, "Stage 4 discovery relations grant a direct mutating privilege to a runtime role")
	}
	if !strings.Contains(content, "organization.role_revision = p_security_epoch") ||
		!strings.Contains(content, "security_epoch BETWEEN 1 AND 9007199254740991") {
		problems = append(problems, "Stage 4 discovery security epoch is not server-bound to a positive safe integer")
	}
	if !strings.Contains(content, "connection.status = 'DRAFT'") || !strings.Contains(content, "connection.active_revision IS NULL") {
		problems = append(problems, "Stage 4 discovery can probe a non-DRAFT or active source connection")
	}
	if strings.Count(content, "app.enqueue_job(") != 1 || strings.Contains(content, "CREATE TABLE public.source_discovery_job") {
		problems = append(problems, "Stage 4 discovery does not use exactly the existing durable job queue")
	}
	if strings.Count(content, "app.source_discovery_revision_is_bound(") < 3 {
		problems = append(problems, "Stage 4 failure/expiry cleanup does not recheck the immutable source revision and trust binding")
	}
	return problems
}

func checkSourceConnectionDraftMigration(content string) []string {
	var problems []string
	for _, tableName := range []string{
		"connector_capability_profile", "source_connection", "source_connection_revision",
		"source_connection_trust_record", "source_connection_trust_projection",
	} {
		if strings.Count(content, "CREATE TABLE public."+tableName+" (") != 1 {
			problems = append(problems, "source DRAFT checkpoint misses exact table: "+tableName)
		}
	}
	if strings.Count(content, "FORCE ROW LEVEL SECURITY") != 4 {
		problems = append(problems, "source DRAFT checkpoint must force RLS on exactly four tenant relations")
	}
	if strings.Count(content, "active_revision bigint CHECK (active_revision IS NULL)") != 1 ||
		strings.Contains(content, "active_revision bigint NOT NULL") {
		problems = append(problems, "source DRAFT checkpoint permits an active connection revision")
	}
	if strings.Count(content, "status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT')") != 2 ||
		regexp.MustCompile(`(?i)'(?:READY|SYNCING|VERIFIED)'`).MatchString(content) {
		problems = append(problems, "source DRAFT checkpoint persists a non-DRAFT authority state")
	}
	for _, exact := range []string{
		"CREATE CONSTRAINT TRIGGER source_connection_revision_artifact_exact",
		"CREATE CONSTRAINT TRIGGER source_connection_latest_revision_exact",
		"CREATE CONSTRAINT TRIGGER source_connection_revision_trust_exact",
		"DEFERRABLE INITIALLY DEFERRED",
		"artifact.owner_table <> 'source_connection_revision'",
		"artifact.owner_column <> 'trust_profile_artifact_id'",
		"artifact.resource_type <> 'SOURCE_TRUST_CONFIG'",
		"artifact.field_name <> 'TRUST_CONFIG'",
		"artifact.plaintext_hash <> NEW.trust_profile_hash",
		"app.source_generated_id_is_valid(credential_reference, 'cred')",
		"app.source_generated_id_is_valid(connector_agent_id, 'agent')",
	} {
		if !strings.Contains(content, exact) {
			problems = append(problems, "source DRAFT checkpoint lost exact fail-closed coupling: "+exact)
		}
	}
	connectionStart := strings.Index(content, "CREATE TABLE public.source_connection (")
	revisionStart := strings.Index(content, "CREATE TABLE public.source_connection_revision (")
	trustStart := strings.Index(content, "CREATE TABLE public.source_connection_trust_record (")
	connectionBody, revisionBody := "", ""
	if connectionStart >= 0 && revisionStart > connectionStart {
		connectionBody = content[connectionStart:revisionStart]
	}
	if revisionStart >= 0 && trustStart > revisionStart {
		revisionBody = content[revisionStart:trustStart]
	}
	if regexp.MustCompile(`(?is)FOREIGN\s+KEY\s*\([^)]*latest_revision`).MatchString(connectionBody) ||
		strings.Contains(revisionBody, "REFERENCES public.source_connection_trust_record") {
		problems = append(problems, "source DRAFT checkpoint reintroduces a circular hard-delete foreign key")
	}
	if regexp.MustCompile(`(?is)CREATE\s+TABLE\s+public\.(?:source_scope|source_object|source_version|evidence|query|question|job|connector_event)\b`).MatchString(content) {
		problems = append(problems, "source DRAFT checkpoint introduces scope, ingestion, evidence, query, job, or event authority")
	}
	allowedGrant := strings.Join(strings.Fields(strings.ToLower(`GRANT SELECT ON TABLE
    public.connector_capability_profile,
    public.source_connection,
    public.source_connection_revision,
    public.source_connection_trust_record,
    public.source_connection_trust_projection
TO knowvault_app;`)), " ")
	grantPattern := regexp.MustCompile(`(?is)\bGRANT\s+[^;]+?\s+TO\s+knowvault_app\s*;`)
	grants := grantPattern.FindAllString(content, -1)
	if len(grants) != 1 || strings.Join(strings.Fields(strings.ToLower(grants[0])), " ") != allowedGrant {
		problems = append(problems, "source DRAFT checkpoint runtime grant is not exact SELECT-only access")
	}
	if !strings.Contains(content, "REVOKE ALL ON FUNCTION") ||
		regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION`).MatchString(content) {
		problems = append(problems, "source DRAFT checkpoint exposes privileged helper execution")
	}
	return problems
}

func checkSourceScopeDraftMigration(content string) []string {
	var problems []string
	for _, tableName := range []string{
		"source_discovered_scope", "source_scope", "source_scope_revision", "source_scope_activation",
	} {
		if strings.Count(content, "CREATE TABLE public."+tableName+" (") != 1 {
			problems = append(problems, "source-scope DRAFT checkpoint misses exact table: "+tableName)
		}
	}
	if strings.Count(content, "FORCE ROW LEVEL SECURITY") != 4 {
		problems = append(problems, "source-scope DRAFT checkpoint must force RLS on exactly four tenant relations")
	}
	if strings.Count(content, "active_revision bigint CHECK (active_revision IS NULL)") != 1 ||
		strings.Contains(content, "active_revision bigint NOT NULL") {
		problems = append(problems, "source-scope DRAFT checkpoint permits an active scope revision")
	}
	for _, bound := range []struct {
		field, pattern string
		count          int
	}{
		{"latest revision", `(?m)^\s*latest_revision\s+bigint\s+NOT\s+NULL\s+CHECK\s*\(latest_revision\s+BETWEEN\s+1\s+AND\s+9007199254740991\)`, 1},
		{"scope revision", `(?m)^\s*revision\s+bigint\s+NOT\s+NULL\s+CHECK\s*\(revision\s+BETWEEN\s+1\s+AND\s+9007199254740991\)`, 1},
		{"connection revision", `(?m)^\s*connection_revision\s+bigint\s+NOT\s+NULL\s+CHECK\s*\(connection_revision\s+BETWEEN\s+1\s+AND\s+9007199254740991\)`, 2},
		{"activation scope revision", `(?m)^\s*source_scope_revision\s+bigint\s+NOT\s+NULL\s+CHECK\s*\(source_scope_revision\s+BETWEEN\s+1\s+AND\s+9007199254740991\)`, 1},
	} {
		if len(regexp.MustCompile(`(?is)`+bound.pattern).FindAllString(content, -1)) != bound.count {
			problems = append(problems, "source-scope DRAFT checkpoint lost I-JSON bound for "+bound.field)
		}
	}
	if strings.Count(content, "status text NOT NULL DEFAULT 'DRAFT' CHECK (status = 'DRAFT')") != 2 ||
		strings.Count(content, "status text NOT NULL DEFAULT 'ACTIVE' CHECK (status = 'ACTIVE')") != 1 ||
		regexp.MustCompile(`(?i)'(?:READY|SYNCING|VERIFIED|REVOKED|FAILED)'`).MatchString(content) {
		problems = append(problems, "source-scope DRAFT checkpoint persists an unaccepted authority state")
	}
	for _, exact := range []string{
		"app.source_generated_id_is_valid(id, 'discovered')",
		"app.source_generated_id_is_valid(id, 'scope')",
		"app.source_keyed_digest_matches_version(identity_digest, identity_digest_key_version)",
		"expected_resource_id := NEW.id",
		"identity_artifact.resource_id <> expected_resource_id",
		"display_artifact.resource_id <> expected_resource_id",
		"identity_artifact.plaintext_hash <> NEW.identity_plaintext_hash",
		"display_artifact.plaintext_hash <> NEW.display_metadata_hash",
		"artifact.plaintext_hash <> NEW.scope_config_hash",
		"identity_artifact.purged_at IS NOT NULL",
		"display_artifact.purged_at IS NOT NULL",
		"artifact.purged_at IS NOT NULL",
		"scope_contract_version text NOT NULL DEFAULT '1.2' CHECK (scope_contract_version = '1.2')",
		"active_revision bigint CHECK (active_revision IS NULL)",
		"removed_at timestamptz CHECK (removed_at IS NULL)",
		"activated_at timestamptz CHECK (activated_at IS NULL)",
		"CREATE CONSTRAINT TRIGGER source_discovered_scope_artifact_exact",
		"CREATE CONSTRAINT TRIGGER source_scope_revision_artifact_exact",
		"CREATE CONSTRAINT TRIGGER source_scope_revision_policy_exact",
		"CREATE CONSTRAINT TRIGGER source_scope_latest_revision_exact",
		"capability.stable_object_ids AND capability.item_level_acl AND capability.acl_refresh",
		"NEW.max_object_bytes > connection_revision.max_object_bytes",
	} {
		if !strings.Contains(content, exact) {
			problems = append(problems, "source-scope DRAFT checkpoint lost exact fail-closed coupling: "+exact)
		}
	}
	if !regexp.MustCompile(`(?is)UNIQUE\s*\(\s*organization_id\s*,\s*connection_id\s*,\s*connection_revision\s*,\s*identity_digest_key_version\s*,\s*identity_digest\s*\)`).MatchString(content) {
		problems = append(problems, "source-scope DRAFT checkpoint does not uniquely bind one discovered identity per connection revision and digest key")
	}
	if strings.Contains(content, "source_discovered_scope_resource_id") {
		problems = append(problems, "source discovery artifact resource ID drifted from the accepted generated discovery ID")
	}
	if strings.Contains(content, "external_scope_id") || strings.Contains(content, "raw_identity") {
		problems = append(problems, "source-scope DRAFT checkpoint persists caller-controlled raw external identity")
	}
	scopeStart := strings.Index(content, "CREATE TABLE public.source_scope (")
	revisionStart := strings.Index(content, "CREATE TABLE public.source_scope_revision (")
	scopeBody := ""
	if scopeStart >= 0 && revisionStart > scopeStart {
		scopeBody = content[scopeStart:revisionStart]
	}
	if regexp.MustCompile(`(?is)FOREIGN\s+KEY\s*\([^)]*latest_revision`).MatchString(scopeBody) {
		problems = append(problems, "source-scope DRAFT checkpoint reintroduces a circular latest-revision foreign key")
	}
	if regexp.MustCompile(`(?is)CREATE\s+(?:TABLE|FUNCTION)\s+(?:public|app)\.(?:workspace_source|workspace_managed|scan_run|connector_job|connector_event|source_object|source_version|evidence|question|query)\b`).MatchString(content) {
		problems = append(problems, "source-scope DRAFT checkpoint introduces binding, scan, event, ingestion, evidence, or query authority")
	}
	allowedGrant := strings.Join(strings.Fields(strings.ToLower(`GRANT SELECT ON TABLE
    public.source_discovered_scope,
    public.source_scope,
    public.source_scope_revision,
    public.source_scope_activation
TO knowvault_app;`)), " ")
	grantPattern := regexp.MustCompile(`(?is)\bGRANT\s+[^;]+?\s+TO\s+knowvault_app\s*;`)
	grants := grantPattern.FindAllString(content, -1)
	if len(grants) != 1 || strings.Join(strings.Fields(strings.ToLower(grants[0])), " ") != allowedGrant {
		problems = append(problems, "source-scope DRAFT checkpoint runtime grant is not exact SELECT-only access")
	}
	if !strings.Contains(content, "REVOKE ALL ON FUNCTION") ||
		regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION`).MatchString(content) {
		problems = append(problems, "source-scope DRAFT checkpoint exposes privileged helper execution")
	}
	return problems
}

func checkWorkspaceSourceSnapshotMigration(content string) []string {
	var problems []string
	for _, tableName := range []string{"workspace_source", "workspace_revision_source"} {
		if strings.Count(content, "CREATE TABLE public."+tableName+" (") != 1 {
			problems = append(problems, "workspace-source snapshot misses exact table: "+tableName)
		}
	}
	if strings.Count(content, "FORCE ROW LEVEL SECURITY") != 2 {
		problems = append(problems, "workspace-source snapshot must force RLS on exactly two tenant relations")
	}
	for _, exact := range []string{
		"source_scope_revision_exact_binding_key",
		"workspace_revision_source_exact_workspace_snapshot_fk",
		"workspace_revision_source_exact_binding_fk",
		"workspace_revision_source_exact_scope_revision_fk",
		"CREATE CONSTRAINT TRIGGER workspace_revision_source_exact_set",
		"CREATE CONSTRAINT TRIGGER workspace_revision_snapshot_exact_source_set",
		"expected_bindings <> actual_bindings",
		"canonical_document ->> 'schema_version' <> 'workspace-configuration-v1'",
		"access_mode IN ('WORKSPACE_MANAGED', 'SOURCE_ENFORCED')",
		"app.source_generated_id_is_valid(id, 'binding')",
		"CREATE TRIGGER workspace_source_immutable",
		"CREATE TRIGGER workspace_revision_source_immutable",
	} {
		if !strings.Contains(content, exact) {
			problems = append(problems, "workspace-source snapshot lost exact fail-closed coupling: "+exact)
		}
	}
	if strings.Count(content, "FROM public.workspace_member AS member") != 2 ||
		strings.Count(content, "member.workspace_id = workspace_source.workspace_id") != 1 ||
		strings.Count(content, "member.workspace_id = workspace_revision_source.workspace_id") != 1 ||
		strings.Count(content, "member.principal_id = app.current_principal_id()") != 2 ||
		strings.Count(content, "member.removed_at IS NULL") != 2 {
		problems = append(problems, "workspace-source snapshot RLS does not require current workspace membership on both relations")
	}
	if regexp.MustCompile(`(?i)workspace_managed_grant_confirmation|\b(?:ready|syncing|queryable|connector_job|connector_event|scan_run|evidence_fragment)\b`).MatchString(content) {
		problems = append(problems, "workspace-source snapshot introduces confirmation, activation, job, event, evidence, or query authority")
	}
	allowedGrant := strings.Join(strings.Fields(strings.ToLower(`GRANT SELECT ON TABLE
    public.workspace_source,
    public.workspace_revision_source
TO knowvault_app;`)), " ")
	grantPattern := regexp.MustCompile(`(?is)\bGRANT\s+[^;]+?\s+TO\s+knowvault_app\s*;`)
	grants := grantPattern.FindAllString(content, -1)
	if len(grants) != 1 || strings.Join(strings.Fields(strings.ToLower(grants[0])), " ") != allowedGrant {
		problems = append(problems, "workspace-source snapshot runtime grant is not exact SELECT-only access")
	}
	if !strings.Contains(content, "REVOKE ALL ON FUNCTION app.workspace_source_snapshot_exact_guard() FROM PUBLIC;") ||
		regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION`).MatchString(content) {
		problems = append(problems, "workspace-source snapshot exposes privileged helper execution")
	}
	return problems
}

// checkWorkspaceSourceCommandMigration accepts configuration provenance only.
// It deliberately proves that migration 000009 extends the one primary
// workspace receipt and cannot smuggle a second binding or any data authority.
func checkWorkspaceSourceCommandMigration(content string) []string {
	var problems []string

	if regexp.MustCompile(`(?is)CREATE\s+TABLE\s+(?:public\.)?[^\s(]*receipt`).MatchString(content) ||
		strings.Contains(content, "CREATE TABLE public.workspace_command_receipt") {
		problems = append(problems, "workspace-source command gate creates a second receipt instead of extending the primary workspace receipt")
	}
	if strings.Count(content, "ALTER TABLE public.workspace_command_receipt") < 2 ||
		strings.Count(content, "ADD COLUMN command_workspace_source_id") != 1 ||
		strings.Count(content, "ADD COLUMN source_expected_workspace_revision") != 1 ||
		strings.Count(content, "ADD COLUMN source_expected_configuration_hash") != 1 {
		problems = append(problems, "workspace-source command gate does not extend the one primary receipt with one exact source target")
	}
	for _, exact := range []string{
		"operation IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE') AND gate_version = 2",
		"command_resource_id = command_workspace_source_id",
		"workspace source add is not absent-or-disabled transition",
		"workspace source remove is not enabled-to-disabled transition",
		"workspace source command changed undeclared bindings",
		"ordinary workspace command changed source projection",
		"NEW.source_expected_workspace_revision, NEW.result_workspace_revision,",
		"NEW.command_workspace_source_id",
		"old_target.enabled IS DISTINCT FROM false",
		"old_target.enabled IS DISTINCT FROM true",
		"workspace source command has stale base snapshot",
		"previous_canonical ->> 'status' <> 'ACTIVE'",
		"result_canonical ->> 'status' <> 'ACTIVE'",
		"workspace source command did not install exact mutable projection",
		"workspace.current_revision = NEW.result_workspace_revision",
		"workspace.updated_at = NEW.terminal_at",
	} {
		if !strings.Contains(content, exact) {
			problems = append(problems, "workspace-source command gate lost exact one-binding/carry proof: "+exact)
		}
	}
	if strings.Count(content, "CREATE CONSTRAINT TRIGGER workspace_command_source_projection_validator") != 1 ||
		strings.Count(content, "WHEN (NEW.operation NOT IN ('WORKSPACE_SOURCE_ADD', 'WORKSPACE_SOURCE_REMOVE'))") != 1 ||
		strings.Count(content, "app.workspace_source_projection_difference_count(") < 3 {
		problems = append(problems, "workspace-source command gate does not reconcile ordinary and source commands through one terminal receipt proof")
	}

	validatorStart := strings.Index(content, "CREATE OR REPLACE FUNCTION app.workspace_source_generated_id_is_valid")
	validatorEnd := -1
	if validatorStart >= 0 {
		if relativeEnd := strings.Index(content[validatorStart:], "$$;"); relativeEnd >= 0 {
			validatorEnd = validatorStart + relativeEnd + len("$$;")
		}
	}
	validator := ""
	if validatorStart >= 0 && validatorEnd > validatorStart {
		validator = content[validatorStart:validatorEnd]
	}
	if validator == "" || strings.Contains(validator, "SECURITY DEFINER") ||
		!strings.Contains(validator, "WHEN 'binding' THEN value ~ '^binding_[0-7][0-9A-HJKMNP-TV-Z]{25}$'") ||
		!strings.Contains(validator, "WHEN 'scope' THEN value ~ '^scope_[0-7][0-9A-HJKMNP-TV-Z]{25}$'") ||
		!strings.Contains(validator, "ELSE false") ||
		strings.Contains(validator, "source_generated_id_is_valid(value, prefix_value)") ||
		!strings.Contains(content, "DROP CONSTRAINT workspace_source_id_check") ||
		!strings.Contains(content, "ADD CONSTRAINT workspace_source_id_closed_check") ||
		regexp.MustCompile(`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+app\.source_generated_id_is_valid`).MatchString(content) {
		problems = append(problems, "workspace-source runtime ID validation is not a closed binding/scope-only wrapper with the legacy arbitrary-prefix helper revoked")
	}

	lineagePolicy := sqlStatement(content, "CREATE POLICY workspace_source_controller_insert")
	projectionPolicy := sqlStatement(content, "CREATE POLICY workspace_revision_source_controller_insert")
	if lineagePolicy == "" || !strings.Contains(lineagePolicy, "FOR INSERT WITH CHECK") ||
		!strings.Contains(lineagePolicy, "member.role IN ('OWNER', 'MANAGER')") ||
		!strings.Contains(lineagePolicy, "member.removed_at IS NULL") ||
		strings.Contains(lineagePolicy, "valid_to_revision") {
		problems = append(problems, "workspace-source lineage INSERT is not limited to a current OWNER/MANAGER")
	}
	if projectionPolicy == "" || !strings.Contains(projectionPolicy, "FOR INSERT WITH CHECK") ||
		!strings.Contains(projectionPolicy, "member.role IN ('OWNER', 'MANAGER')") ||
		!strings.Contains(projectionPolicy, "member.removed_at IS NULL") ||
		!strings.Contains(projectionPolicy, "member.valid_to_revision = workspace_revision_source.workspace_revision") {
		problems = append(problems, "workspace-source revision INSERT lost its exact OWNER/MANAGER self-removal transition")
	}

	if strings.Count(content, "(NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL)") != 1 ||
		strings.Count(content, "(audit_row.workspace_id IS NOT NULL AND audit_row.workspace_id <> NEW.command_workspace_id)") != 3 ||
		strings.Count(content, "audit_row.workspace_id IS DISTINCT FROM NEW.command_workspace_id") != 1 {
		problems = append(problems, "workspace-source audit does not require workspace on SUCCESS while keeping only non-success targets nullable")
	}
	for _, exact := range []string{
		"(SELECT count(*) FROM jsonb_object_keys(NEW.metadata_json)) <> 7",
		"NEW.policy_decision_id IS NOT NULL",
		"NEW.referenced_evidence_ids_json <> '[]'::jsonb",
		"audit_row.metadata_json <> jsonb_build_object(",
		"'workspace_revision', expected_audit_revision",
		"'enabled', expected_enabled",
	} {
		if !strings.Contains(content, exact) {
			problems = append(problems, "workspace-source terminal audit lost exact content-free projection: "+exact)
		}
	}

	if strings.Count(content, "GRANT SELECT, INSERT ON TABLE public.workspace_source, public.workspace_revision_source TO knowvault_app;") != 1 ||
		regexp.MustCompile(`(?is)GRANT\s+[^;]*(?:UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER)[^;]*ON\s+(?:TABLE\s+)?public\.workspace_(?:source|revision_source)[^;]*TO\s+knowvault_app`).MatchString(content) {
		problems = append(problems, "workspace-source command gate runtime table grant is not exact SELECT/INSERT-only access")
	}
	for name, pattern := range map[string]string{
		"confirmation-or-domain-grant": `(?i)\b(?:workspace_managed_(?:confirmation|grant)|grant_confirmation|source_access_grant)\b`,
		"activation-mutation":          `(?is)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?source_scope_activation\b|\bSET\s+active_revision\s*=`,
		"authority-state":              `(?i)\b(?:READY|SYNCING|QUERYABLE|AUTHORIZED)\b`,
		"job-query-or-data-plane":      `(?is)CREATE\s+(?:TABLE|FUNCTION)\s+(?:public|app)\.(?:connector_job|connector_event|scan_run|source_object|source_version|evidence(?:_fragment)?|question(?:_run)?|query(?:_run)?)\b`,
	} {
		if regexp.MustCompile(pattern).MatchString(content) {
			problems = append(problems, "workspace-source configuration checkpoint introduces forbidden "+name)
		}
	}
	return problems
}

// checkWorkspaceManagedConfirmationAuthorityMigration enforces every hardened
// invariant of the ADR-0052 persistence-only checkpoint (000010): exactly the
// six closed tables, the safe-integer organization policy counter, the one
// shared current-policy insert guard installed on all four authority tables,
// opaque (not source-generated) authority IDs, the exact configuration-hash
// bearing confirmation target key/FK, forced RLS everywhere required, a
// SELECT-only runtime grant with zero EXECUTE surface, the workspace row
// lock used by both revocation guards and the derived-live validator, both
// revocation relations considered by the live validator, the sealed warning
// v1 hash/acknowledgement, and the absence of any mutable status/revoked_at
// column on the grant or confirmation tables or of any later-checkpoint
// authority (receipt/API/outbox/activation/job/ingestion/retrieval).
func checkWorkspaceManagedConfirmationAuthorityMigration(content string) []string {
	var problems []string

	for _, tableName := range []string{
		"organization_policy_revision", "workspace_managed_warning_contract",
		"workspace_source_confirmation_actor_grant", "workspace_source_confirmation_actor_grant_revocation",
		"workspace_managed_grant_confirmation", "workspace_managed_grant_revocation",
	} {
		if strings.Count(content, "CREATE TABLE public."+tableName+" (") != 1 {
			problems = append(problems, "workspace-managed confirmation authority misses exact table: "+tableName)
		}
	}

	if !strings.Contains(content, "ADD CONSTRAINT organization_policy_revision_safe_integer") ||
		!strings.Contains(content, "CHECK (policy_revision BETWEEN 1 AND 9007199254740991)") {
		problems = append(problems, "workspace-managed confirmation authority lost the safe-integer organization policy counter constraint")
	}

	// A bare total-occurrence count is a false-green gate: it cannot tell two
	// triggers stacked on one table (and none on another) apart from the
	// correct one-trigger-per-table layout. Confirm each of the four tables
	// individually has its own "BEFORE INSERT ON public.<table>" immediately
	// followed by "FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_
	// guard();" — this exact adjacency is how every such trigger is written in
	// this migration, and table names that share a prefix (the grant table is
	// itself a prefix of its own "_revocation" child) do not collide because
	// the literal newline right after the table name only matches the exact
	// table, never a longer name built by appending "_revocation".
	currentPolicyTables := []string{
		"workspace_source_confirmation_actor_grant",
		"workspace_source_confirmation_actor_grant_revocation",
		"workspace_managed_grant_confirmation",
		"workspace_managed_grant_revocation",
	}
	for _, tableName := range currentPolicyTables {
		marker := "BEFORE INSERT ON public." + tableName + "\nFOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();"
		if !strings.Contains(content, marker) {
			problems = append(problems, "workspace-managed confirmation authority missing current-policy guard trigger on "+tableName)
		}
	}
	if strings.Count(content, "EXECUTE FUNCTION app.authority_current_policy_guard()") != 4 {
		problems = append(problems, "workspace-managed confirmation authority does not install the one shared current-policy guard exactly once per authority table")
	}

	for _, idColumn := range []string{"grant_id", "confirmation_id"} {
		if !strings.Contains(content, "app.stage2_opaque_id_is_valid("+idColumn+")") {
			problems = append(problems, "workspace-managed confirmation authority does not validate "+idColumn+" as an opaque ID")
		}
	}
	if strings.Count(content, "app.stage2_opaque_id_is_valid(revocation_id)") != 2 {
		problems = append(problems, "workspace-managed confirmation authority does not validate both revocation_id columns as opaque IDs")
	}
	if regexp.MustCompile(`app\.source_generated_id_is_valid\((?:grant_id|confirmation_id|revocation_id)`).MatchString(content) {
		problems = append(problems, "workspace-managed confirmation authority IDs regressed to the source connection/scope/binding generated-ID validator")
	}

	targetKey := sqlStatement(content, "ADD CONSTRAINT workspace_revision_source_exact_confirmation_target_key")
	targetFK := extractBalanced(content, "CONSTRAINT workspace_managed_grant_confirmation_target_fk")
	if targetKey == "" || !strings.Contains(targetKey, "workspace_configuration_hash") {
		problems = append(problems, "workspace-managed confirmation authority target UNIQUE key lost exact workspace_configuration_hash")
	}
	if targetFK == "" || !strings.Contains(targetFK, "workspace_configuration_hash") {
		problems = append(problems, "workspace-managed confirmation authority target FK lost exact workspace_configuration_hash")
	}

	if strings.Count(content, "FORCE ROW LEVEL SECURITY") != 5 {
		problems = append(problems, "workspace-managed confirmation authority does not force RLS on exactly five tenant relations")
	}

	grantPattern := regexp.MustCompile(`(?is)GRANT\s+([^;]+?)\s+ON\s+TABLE\s+[^;]+?\s+TO\s+knowvault_app\s*;`)
	grantMatches := grantPattern.FindAllStringSubmatch(content, -1)
	if len(grantMatches) != 6 {
		problems = append(problems, "workspace-managed confirmation authority does not grant knowvault_app exactly once per table")
	}
	for _, match := range grantMatches {
		if strings.ToUpper(strings.TrimSpace(match[1])) != "SELECT" {
			problems = append(problems, "workspace-managed confirmation authority grants more than SELECT to knowvault_app: "+strings.TrimSpace(match[1]))
		}
	}
	if strings.Contains(content, "GRANT EXECUTE") {
		problems = append(problems, "workspace-managed confirmation authority grants EXECUTE on a helper function to PUBLIC or knowvault_app")
	}

	if strings.Count(content, "FOR UPDATE;") != 3 {
		problems = append(problems, "workspace-managed confirmation authority lost a required workspace row lock (a revocation guard or the derived-live validator)")
	}

	liveGuardBody := sqlFunctionBody(content, "app.workspace_managed_grant_confirmation_derived_live_guard")
	if liveGuardBody == "" ||
		!strings.Contains(liveGuardBody, "workspace_managed_grant_revocation") ||
		!strings.Contains(liveGuardBody, "workspace_source_confirmation_actor_grant_revocation") {
		problems = append(problems, "derived-live validator lost one of the two revocation relations")
	}

	// "Current" warning must be defined as the maximum registered revision,
	// not merely "any historical row the confirmation's hash happens to
	// match" (the warning FK alone proves only historical existence). Both
	// the confirmation exact_guard (rejects a new confirmation naming a stale
	// warning) and the derived-live validator (makes an old confirmation
	// stale once a newer warning revision is registered) must each re-join
	// against the live current-revision helper, not just the confirmation's
	// own stored warning fields.
	if !strings.Contains(content, "app.workspace_managed_warning_contract_current_revision()") {
		problems = append(problems, "workspace-managed confirmation authority lost the current-warning-revision helper")
	}
	exactGuardBody := sqlFunctionBody(content, "app.workspace_managed_grant_confirmation_exact_guard")
	if exactGuardBody == "" || !strings.Contains(exactGuardBody, "app.workspace_managed_warning_contract_current_revision()") {
		problems = append(problems, "confirmation exact guard does not require the current warning registry revision")
	}
	if liveGuardBody == "" ||
		!regexp.MustCompile(`warning\.revision\s*=\s*app\.workspace_managed_warning_contract_current_revision\(\)`).MatchString(liveGuardBody) {
		problems = append(problems, "derived-live validator does not require the current warning registry revision")
	}

	if !strings.Contains(content, "sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d") ||
		!strings.Contains(content, "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL") {
		problems = append(problems, "workspace-managed confirmation authority weakened the sealed warning v1 hash/acknowledgement")
	}

	for name, ddl := range map[string]string{
		"grant":        extractCreateTable(content, "workspace_source_confirmation_actor_grant"),
		"confirmation": extractCreateTable(content, "workspace_managed_grant_confirmation"),
	} {
		if ddl == "" {
			continue
		}
		if regexp.MustCompile(`(?m)^\s*(status|revoked_at)\s+\S`).MatchString(ddl) {
			problems = append(problems, "workspace-managed confirmation authority "+name+" table gained a mutable status/revoked_at column")
		}
	}

	if regexp.MustCompile(`(?i)\b(?:workspace_command_receipt|connector_job|connector_event|scan_run|source_object|evidence_fragment|question_run|outbox_event|audit_event|source_scope_activation)\b`).MatchString(content) {
		problems = append(problems, "workspace-managed confirmation authority introduces receipt/outbox/audit/activation/job/ingestion/retrieval authority")
	}

	return problems
}

// extractCreateTable returns the full "CREATE TABLE public.<name> (...)"
// statement text using balanced-paren matching, so it is robust regardless
// of ordering with other tables sharing a name prefix (e.g. a grant table
// and its own "_revocation" child table).
func extractCreateTable(content, tableName string) string {
	marker := "CREATE TABLE public." + tableName + " ("
	start := strings.Index(content, marker)
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start + len(marker) - 1; i < len(content); i++ {
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return content[start : i+1]
			}
		}
	}
	return ""
}

// extractBalanced returns the text starting at marker up to the end of its
// first balanced parenthesised group, so a specific named CONSTRAINT clause
// can be isolated from the rest of its enclosing CREATE TABLE statement.
func extractBalanced(content, marker string) string {
	start := strings.Index(content, marker)
	if start < 0 {
		return ""
	}
	openIndex := strings.Index(content[start:], "(")
	if openIndex < 0 {
		return ""
	}
	openIndex += start
	depth := 0
	for i := openIndex; i < len(content); i++ {
		switch content[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return content[start : i+1]
			}
		}
	}
	return ""
}

// sqlFunctionBody returns the full "CREATE OR REPLACE FUNCTION <prefix>...$$;"
// text for a plpgsql/sql function, used to scope a substring search to one
// function body instead of the whole migration file.
func sqlFunctionBody(content, functionSignaturePrefix string) string {
	start := strings.Index(content, "CREATE OR REPLACE FUNCTION "+functionSignaturePrefix)
	if start < 0 {
		return ""
	}
	relativeEnd := strings.Index(content[start:], "$$;")
	if relativeEnd < 0 {
		return ""
	}
	return content[start : start+relativeEnd+len("$$;")]
}

func sqlStatement(content, marker string) string {
	start := strings.Index(content, marker)
	if start < 0 {
		return ""
	}
	end := strings.Index(content[start:], ";")
	if end < 0 {
		return ""
	}
	return content[start : start+end+1]
}

// requiredCiExecutableCommands is the exact command contract a required CI check
// must prove executable. It is shared by checkRequiredCI and the mutation
// self-test so the two can never drift apart.
var requiredCiExecutableCommands = []string{
	"go run ./scripts/check-architecture.go -root /src",
	"corepack pnpm install --frozen-lockfile --ignore-scripts",
	"node schema-tests.mjs",
	"node license-tests.mjs licenses.json",
	"node web-license-tests.mjs licenses.json",
	"corepack pnpm exec tsc --noEmit",
	"corepack pnpm exec esbuild --version",
	"go test -count=1 ./...",
	`go test -mod=readonly -count=1 "${unit_packages[@]}" -timeout=10m`,
	"go test -mod=readonly -count=1 -timeout=30m ./tests/integration/postgres",
	"go test -mod=readonly -json -tags e2e ./tests/e2e -run=^TestE2ER3FullLoop$ -count=1 -timeout 30m 2>&1 | tee /tmp/knowvault-r3-go-test.json",
	"go run ./scripts/check-architecture.go -verify-e2e-json /tmp/knowvault-r3-go-test.json -verify-e2e-package knowvault.local/verified-workspace/tests/e2e -verify-e2e-test TestE2ER3FullLoop",
	"go run ./tests/contracts/mutation-runner -root /src",
}

const (
	r3E2EPackage         = "knowvault.local/verified-workspace/tests/e2e"
	r3E2ETest            = "TestE2ER3FullLoop"
	r3E2EJSONPath        = "/tmp/knowvault-r3-go-test.json"
	r3E2EGoTestCommand   = "go test -mod=readonly -json -tags e2e ./tests/e2e -run=^TestE2ER3FullLoop$ -count=1 -timeout 30m 2>&1 | tee /tmp/knowvault-r3-go-test.json"
	r3E2EVerifyCommand   = "go run ./scripts/check-architecture.go -verify-e2e-json /tmp/knowvault-r3-go-test.json -verify-e2e-package knowvault.local/verified-workspace/tests/e2e -verify-e2e-test TestE2ER3FullLoop"
	r3E2EStatusCapture   = "test_status=${PIPESTATUS[0]}"
	r3E2EStatusAssertion = `test "$test_status" -eq 0`
)

// checkR3E2EProof protects the execution boundary around the R3 end-to-end
// charter. The Go test command must be anchored to one exact test and emit
// JSON into the stdlib verifier; the shell must preserve the producer's exit
// status instead of allowing tee (or the verifier) to create a false green.
func checkR3E2EProof(workflow string) []string {
	blocks := extractYAMLRunBlocks(workflow)
	var problems []string
	r3Block := ""
	for _, block := range blocks {
		if strings.Contains(block, r3E2EGoTestCommand) {
			r3Block = block
			break
		}
	}
	if r3Block == "" || !runBlocksContainExecutable(blocks, r3E2EGoTestCommand) {
		problems = append(problems, "R3 e2e proof is missing the exact anchored go test -json command")
	}
	if r3Block == "" || !runBlocksContainExecutable(blocks, r3E2EVerifyCommand) {
		problems = append(problems, "R3 e2e proof is missing the exact machine-readable verifier command")
	}
	statusCaptureSegment := strings.Join(strings.Fields(r3E2EStatusCapture), " ")
	goTestSegment := strings.Join(strings.Fields(r3E2EGoTestCommand), " ")
	goTestSegmentAt := -1
	captureSegmentAt := -1
	statusOverwritten := false
	if r3Block != "" {
		for index, segment := range executableShellSegments(r3Block) {
			if segment == goTestSegment {
				if goTestSegmentAt >= 0 {
					problems = append(problems, "R3 e2e proof executes the exact go test pipeline more than once")
				} else {
					goTestSegmentAt = index
				}
			}
			if segment == statusCaptureSegment {
				if captureSegmentAt >= 0 {
					statusOverwritten = true
				} else {
					captureSegmentAt = index
				}
				continue
			}
			if captureSegmentAt >= 0 && regexp.MustCompile(`^(?:export\s+)?test_status\s*=`).MatchString(segment) {
				statusOverwritten = true
			}
		}
	}
	if r3Block == "" || captureSegmentAt < 0 {
		problems = append(problems, "R3 e2e proof does not preserve the go test producer exit status")
	}
	if r3Block == "" || goTestSegmentAt < 0 || captureSegmentAt != goTestSegmentAt+1 {
		problems = append(problems, "R3 e2e proof must capture PIPESTATUS immediately after the go test pipeline")
	}
	if statusOverwritten {
		problems = append(problems, "R3 e2e proof overwrites the captured go test producer exit status")
	}
	if r3Block == "" || !regexp.MustCompile(`(?m)^\s*`+regexp.QuoteMeta(r3E2EStatusAssertion)+`\s*$`).MatchString(r3Block) {
		problems = append(problems, "R3 e2e proof does not assert the preserved go test exit status")
	}
	if r3Block != "" {
		goTestAt := strings.Index(r3Block, r3E2EGoTestCommand)
		captureAt := strings.Index(r3Block, r3E2EStatusCapture)
		verifyAt := strings.Index(r3Block, r3E2EVerifyCommand)
		assertAt := strings.Index(r3Block, r3E2EStatusAssertion)
		if goTestAt < 0 || captureAt <= goTestAt || verifyAt <= captureAt || assertAt <= verifyAt {
			problems = append(problems, "R3 e2e proof does not order test, status capture, verifier and final status assertion transactionally")
		}
	}
	if strings.Contains(workflow, "-run TestE2ER3FullLoop") {
		problems = append(problems, "R3 e2e proof uses an unanchored test selector")
	}
	if !strings.Contains(workflow, "-verify-e2e-package "+r3E2EPackage) || !strings.Contains(workflow, "-verify-e2e-test "+r3E2ETest) {
		problems = append(problems, "R3 e2e verifier is not bound to the exact package and test")
	}
	return problems
}

func checkRequiredCI(root string) []string {
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "architecture.yml"))
	if err != nil {
		return []string{"missing required architecture CI workflow"}
	}
	codeowners, err := os.ReadFile(filepath.Join(root, ".github", "CODEOWNERS"))
	if err != nil {
		return []string{"missing CODEOWNERS"}
	}
	attributes, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		return []string{"missing .gitattributes"}
	}
	var problems []string
	packageRaw, packageErr := os.ReadFile(filepath.Join(root, "tests", "contracts", "package.json"))
	if packageErr != nil {
		problems = append(problems, "missing contract-test package.json")
	} else {
		var packageJSON map[string]any
		if json.Unmarshal(packageRaw, &packageJSON) != nil || packageJSON["packageManager"] != "pnpm@11.4.0+sha512.f0febc7e37552ab485494a914241b338e0b3580b93d54ce31f00933015880863129038a1b4ae4e414a0ee63ac35bf21197e990172c4a68256450b5636310968f" {
			problems = append(problems, "contract-test packageManager is not checksum-pinned pnpm 11.4.0")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "tests", "contracts", "package-lock.json")); err == nil {
		problems = append(problems, "package-lock.json is forbidden; pnpm-lock.yaml is the only JS lockfile")
	}
	if _, err := os.Stat(filepath.Join(root, "tests", "contracts", "pnpm-lock.yaml")); err != nil {
		problems = append(problems, "missing tests/contracts/pnpm-lock.yaml")
	}
	workflowText := string(workflow)
	if regexp.MustCompile(`(?m)^\s*(?:-\s*)?(?:if|continue-on-error):`).MatchString(workflowText) {
		problems = append(problems, "required architecture CI forbids conditional or continue-on-error jobs and steps")
	}
	for _, required := range []string{
		"actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
		"persist-credentials: false",
		"GOTOOLCHAIN=local",
		"GOEXPERIMENT=jsonv2",
		"golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669",
		"node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d",
		"postgres:18.4@sha256:b913fd5699b8bd23fa4b06d72ecdd939fad43b80fb8651bac06caa0e6d135cac",
		"-w /repo/tests/contracts/runner",
	} {
		if !strings.Contains(workflowText, required) {
			problems = append(problems, "required CI workflow misses: "+required)
		}
	}
	runBlocks := extractYAMLRunBlocks(workflowText)
	problems = append(problems, checkR3E2EProof(workflowText)...)
	for _, requiredCommand := range requiredCiExecutableCommands {
		if !runBlocksContainExecutable(runBlocks, requiredCommand) {
			problems = append(problems, "required CI workflow has no executable exact command: "+requiredCommand)
		}
	}
	problems = append(problems, checkCICommandMutationTests()...)
	for label, pattern := range map[string]string{
		"npm":  `(?m)(^|[ \t])npm[ \t]+(ci|install|run)([ \t]|$)`,
		"yarn": `(?m)(^|[ \t])yarn[ \t]+(install|run)([ \t]|$)`,
	} {
		if regexp.MustCompile(pattern).MatchString(workflowText) {
			problems = append(problems, "required CI workflow uses forbidden package manager command: "+label)
		}
	}
	problems = append(problems, checkRequiredCodeowners(string(codeowners))...)
	for _, required := range []string{
		"*.md text eol=lf", "*.yaml text eol=lf", "*.json text eol=lf", "*.go text eol=lf", "*.sql text eol=lf", "*.ps1 text eol=lf",
		".gitattributes text eol=lf", ".gitignore text eol=lf", "CODEOWNERS text eol=lf",
		".dockerignore text eol=lf", ".env.example text eol=lf", "Dockerfile* text eol=lf",
	} {
		if !strings.Contains(string(attributes), required) {
			problems = append(problems, ".gitattributes misses LF rule: "+required)
		}
	}
	return problems
}

var requiredCodeownerPatterns = []string{
	"/architecture/**", "/tests/contracts/**", "/tests/e2e/**",
	"/.gitattributes", "/.dockerignore", "/.gitignore",
	"/go.mod", "/go.sum", "/db/**", "/internal/platform/database/**", "/internal/platform/oidc/**", "/internal/audit/**", "/internal/identity/**", "/internal/policy/**", "/internal/source/scopeglob/**", "/tests/integration/postgres/**", "/web/package.json", "/web/pnpm-lock.yaml", "/deploy/images/Dockerfile.*",
	"/deploy/compose/compose.yaml", "/.github/workflows/architecture.yml",
}

var requiredCodeownerOwners = []string{"@avangerus"}

// checkRequiredCodeowners parses active CODEOWNERS rules instead of searching
// raw text. A commented-out path or a path with no owner must not satisfy the
// trust boundary, and the exact patterns are shared by the checker and its
// mutation tests.
func checkRequiredCodeowners(content string) []string {
	owned := make(map[string]map[string]bool)
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		if owned[fields[0]] == nil {
			owned[fields[0]] = make(map[string]bool)
		}
		for _, owner := range fields[1:] {
			owned[fields[0]][owner] = true
		}
	}
	var problems []string
	for _, required := range requiredCodeownerPatterns {
		for _, owner := range requiredCodeownerOwners {
			if !owned[required][owner] {
				problems = append(problems, "CODEOWNERS misses active protected path owner: "+required+" -> "+owner)
			}
		}
	}
	return problems
}

func extractYAMLRunBlocks(workflow string) []string {
	lines := strings.Split(strings.ReplaceAll(workflow, "\r\n", "\n"), "\n")
	var blocks []string
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "run:") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "run:"))
		if value != "" && value != ">" && value != ">-" && value != "|" && value != "|-" {
			blocks = append(blocks, value)
			continue
		}
		var blockLines []string
		for next := index + 1; next < len(lines); next++ {
			nextLine := lines[next]
			if strings.TrimSpace(nextLine) == "" {
				blockLines = append(blockLines, "")
				continue
			}
			nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " \t"))
			if nextIndent <= indent {
				break
			}
			blockLines = append(blockLines, strings.TrimSpace(nextLine))
			index = next
		}
		blocks = append(blocks, strings.Join(blockLines, "\n"))
	}
	return blocks
}

func runBlocksContainExecutable(blocks []string, required string) bool {
	required = strings.Join(strings.Fields(required), " ")
	for _, block := range blocks {
		for _, normalized := range executableShellSegments(block) {
			if regexp.MustCompile(`(^|\s)(?:exit|return)(?:\s|$)`).MatchString(normalized) || normalized == "false" {
				break
			}
			if normalized == required {
				return true
			}
		}
	}
	return false
}

// executableShellSegments returns the normalized shell segments that can
// actually run in a workflow block. Comments, heredocs and conditional bodies
// are excluded so a marker copied into prose cannot satisfy an exact-command
// contract. Keeping this parser shared lets the R3 PIPESTATUS capture use the
// same executable-boundary proof as every other required CI command.
func executableShellSegments(block string) []string {
	if strings.Contains(block, "<<") || regexp.MustCompile(`(?m)^\s*(?:if|case)\b`).MatchString(block) {
		return nil
	}
	var segments []string
	for _, segment := range splitShellSegments(block) {
		normalized := strings.Join(strings.Fields(segment), " ")
		normalized = strings.Trim(normalized, "'\"()")
		segments = append(segments, normalized)
	}
	return segments
}

func splitShellSegments(block string) []string {
	block = strings.ReplaceAll(block, "&&", "\n")
	block = strings.ReplaceAll(block, ";", "\n")
	var segments []string
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		segments = append(segments, trimmed)
	}
	return segments
}

func checkCICommandMutationTests() []string {
	command := "go run ./scripts/check-architecture.go -root /src"
	commentOnly := "jobs:\n  guard:\n    steps:\n      - run: |-\n          # " + command + "\n"
	echoOnly := "jobs:\n  guard:\n    steps:\n      - run: echo '" + command + "'\n"
	disabledStep := "jobs:\n  guard:\n    steps:\n      - if: false\n        run: " + command + "\n"
	continueOnError := "jobs:\n  guard:\n    steps:\n      - continue-on-error: true\n        run: " + command + "\n"
	unreachable := "jobs:\n  guard:\n    steps:\n      - run: exit 0; " + command + "\n"
	heredoc := "jobs:\n  guard:\n    steps:\n      - run: |-\n          cat <<'EOF'\n          " + command + "\n          EOF\n"
	var problems []string
	if runBlocksContainExecutable(extractYAMLRunBlocks(commentOnly), command) {
		problems = append(problems, "architecture.ci.required-command-comment-only mutation was accepted")
	}
	if runBlocksContainExecutable(extractYAMLRunBlocks(echoOnly), command) {
		problems = append(problems, "architecture.ci.required-command-echo-only mutation was accepted")
	}
	for _, mutation := range []string{disabledStep, continueOnError} {
		if !regexp.MustCompile(`(?m)^\s*(?:-\s*)?(?:if|continue-on-error):`).MatchString(mutation) {
			problems = append(problems, "architecture.ci.required-command-disabled-step mutation was accepted")
		}
	}
	if runBlocksContainExecutable(extractYAMLRunBlocks(unreachable), command) {
		problems = append(problems, "architecture.ci.required-command-unreachable mutation was accepted")
	}
	if runBlocksContainExecutable(extractYAMLRunBlocks(heredoc), command) {
		problems = append(problems, "architecture.ci.required-command-heredoc mutation was accepted")
	}
	return problems
}

func checkLicensePolicy(root string) []string {
	policyRaw, err := os.ReadFile(filepath.Join(root, "architecture", "licenses.yaml"))
	if err != nil {
		return []string{"missing architecture/licenses.yaml"}
	}
	versionRaw, err := os.ReadFile(filepath.Join(root, "architecture", "versions.json"))
	if err != nil {
		return []string{"missing architecture/versions.json for license check"}
	}
	var lock any
	if err := json.Unmarshal(versionRaw, &lock); err != nil {
		return []string{"cannot parse version lock for license check: " + err.Error()}
	}
	var problems []string
	policy := string(policyRaw)
	for _, required := range []string{
		"default: deny",
		"legal_review_required_for_changes: true",
		"expression: Artistic-2.0",
		"name: npm CLI",
		"name: pnpm",
		"name: Syft",
		"name: Grype",
		"name: actions/checkout",
		"name: fast-uri",
	} {
		if !strings.Contains(policy, required) {
			problems = append(problems, "license policy misses reviewed entry: "+required)
		}
	}
	// This is deliberately an allowlist. A denylist would silently accept a new,
	// misspelled or non-SPDX license and would contradict the repository's
	// default-deny supply-chain policy.
	allowed := map[string]bool{
		"Apache-2.0":   true,
		"MIT":          true,
		"BSD-2-Clause": true,
		"BSD-3-Clause": true,
		"PostgreSQL":   true,
		"PSF-2.0":      true,
		"ISC":          true,
	}
	conditionallyAllowed := map[string]map[string]bool{
		// ADR-0009 permits this exact bundled, unused build-image component.
		"Artistic-2.0": {"toolchains.npm_bundled": true},
	}
	problems = append(problems, checkVersionedComponentLicenses(lock, allowed, conditionallyAllowed)...)
	selectedComponents, parseProblems := parseSelectedComponentLicenses(policy)
	problems = append(problems, parseProblems...)
	reviewedNames := map[string]string{
		"toolchains.go": "Go", "toolchains.node": "Node.js", "toolchains.pnpm": "pnpm",
		"toolchains.corepack_bundled": "Corepack", "toolchains.npm_bundled": "npm CLI", "toolchains.yarn_bundled": "Yarn Classic",
		"frontend.react": "React", "frontend.react_dom": "React DOM", "frontend.react_types": "React TypeScript definitions", "frontend.react_dom_types": "React DOM TypeScript definitions", "frontend.typescript": "TypeScript", "frontend.esbuild": "esbuild",
		"frontend.ajv": "Ajv", "frontend.ajv_formats": "ajv-formats",
		"node_transitive_dependencies.fast_deep_equal": "fast-deep-equal", "node_transitive_dependencies.fast_uri": "fast-uri",
		"node_transitive_dependencies.json_schema_traverse": "json-schema-traverse", "node_transitive_dependencies.require_from_string": "require-from-string",
		"node_transitive_dependencies.scheduler": "scheduler", "node_transitive_dependencies.csstype": "csstype",
		"go_dependencies.google_compute_metadata": "cloud.google.com/go/compute/metadata", "go_dependencies.oidc": "go-oidc", "go_dependencies.go_jose": "go-jose",
		"go_dependencies.pgx": "pgx", "go_dependencies.pgpassfile": "pgpassfile", "go_dependencies.pgservicefile": "pgservicefile",
		"go_dependencies.puddle": "puddle", "go_dependencies.x_oauth2": "golang.org/x/oauth2", "go_dependencies.x_sync": "golang.org/x/sync", "go_dependencies.x_sys": "golang.org/x/sys", "go_dependencies.x_text": "golang.org/x/text", "go_dependencies.x_net": "golang.org/x/net",
		"go_build_tools.oapi_codegen": "oapi-codegen", "go_build_tools.sqlc": "sqlc", "go_build_tools.syft": "Syft", "go_build_tools.grype": "Grype",
		"ci_actions.checkout": "actions/checkout", "data_services.postgresql": "PostgreSQL", "data_services.opensearch": "OpenSearch",
	}
	for _, component := range reviewedEsbuildPlatformPackages {
		reviewedNames["node_transitive_dependencies."+component.Key] = component.SelectedName
	}
	for path, selectedName := range reviewedNames {
		lockedLicense, locked := jsonValueAt(lock, path+".license")
		selected, reviewed := selectedComponents[selectedName]
		if !locked || !reviewed || lockedLicense != selected.License || selected.Status != "ACTIVE" {
			problems = append(problems, fmt.Sprintf("version/license inventory mismatch %s (%s): lock=%v policy=%q status=%q", path, selectedName, lockedLicense, selected.License, selected.Status))
		}
	}
	problems = append(problems, validateSelectedComponentInventory(selectedComponents)...)
	problems = append(problems, checkLicensePolicyMutationTests(policy, selectedComponents, lock, allowed, conditionallyAllowed)...)
	return problems
}

func checkVersionedComponentLicenses(lock any, allowed map[string]bool, conditionallyAllowed map[string]map[string]bool) []string {
	var problems []string
	var walk func(any, string)
	walk = func(value any, path string) {
		switch typed := value.(type) {
		case map[string]any:
			if _, versioned := typed["version"]; versioned {
				license, exists := typed["license"].(string)
				if !exists || license == "" {
					problems = append(problems, "versioned component has no concluded license: "+path)
				} else if !allowed[license] && !conditionallyAllowed[license][path] {
					problems = append(problems, "versioned component uses unknown, forbidden, or unapproved conditional license: "+path+" -> "+license)
				}
			}
			for key, child := range typed {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				walk(child, childPath)
			}
		case []any:
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s[%d]", path, index))
			}
		}
	}
	walk(lock, "")
	return problems
}

type selectedComponentPolicy struct {
	License string
	Status  string
	Role    string
	Source  string
}

var expectedSelectedComponentStatus = map[string]string{
	"Go": "ACTIVE", "TypeScript": "ACTIVE", "React": "ACTIVE", "React DOM": "ACTIVE", "React TypeScript definitions": "ACTIVE", "React DOM TypeScript definitions": "ACTIVE", "esbuild": "ACTIVE", "esbuild platform packages": "ACTIVE",
	"Node.js": "ACTIVE", "pnpm": "ACTIVE", "Corepack": "ACTIVE", "npm CLI": "ACTIVE", "Yarn Classic": "ACTIVE",
	"Ajv": "ACTIVE", "ajv-formats": "ACTIVE", "fast-deep-equal": "ACTIVE", "fast-uri": "ACTIVE",
	"json-schema-traverse": "ACTIVE", "require-from-string": "ACTIVE", "scheduler": "ACTIVE", "csstype": "ACTIVE",
	"oapi-codegen": "ACTIVE", "cloud.google.com/go/compute/metadata": "ACTIVE", "go-oidc": "ACTIVE", "go-jose": "ACTIVE", "golang.org/x/oauth2": "ACTIVE", "pgx": "ACTIVE", "pgpassfile": "ACTIVE", "pgservicefile": "ACTIVE", "puddle": "ACTIVE", "golang.org/x/sync": "ACTIVE", "golang.org/x/sys": "ACTIVE", "golang.org/x/text": "ACTIVE", "sqlc": "ACTIVE", "Syft": "ACTIVE", "Grype": "ACTIVE",
	"actions/checkout": "ACTIVE", "PostgreSQL": "ACTIVE", "OpenSearch": "ACTIVE", "golang.org/x/net": "ACTIVE",
	"libc6 (isolated parser runtime)": "DEFERRED",
	"Apache POI":                      "DEFERRED", "Apache PDFBox": "DEFERRED", "Tesseract OCR": "DEFERRED", "tessdata (Tesseract trained data)": "DEFERRED", "Leptonica": "DEFERRED", "vLLM": "DEFERRED",
	"Qwen3-Embedding-0.6B": "DEFERRED", "Qwen3-Reranker-0.6B": "DEFERRED", "Qwen3-14B": "DEFERRED",
	"OpenTelemetry": "DEFERRED",
}

func validateSelectedComponentInventory(selectedComponents map[string]selectedComponentPolicy) []string {
	var problems []string
	for name, expectedStatus := range expectedSelectedComponentStatus {
		selected, exists := selectedComponents[name]
		if !exists {
			problems = append(problems, "license policy misses exact selected component: "+name)
		} else if selected.Status != expectedStatus {
			problems = append(problems, fmt.Sprintf("selected component status mismatch %s: expected %s, got %s", name, expectedStatus, selected.Status))
		}
	}
	for name := range selectedComponents {
		if _, expected := expectedSelectedComponentStatus[name]; !expected {
			problems = append(problems, "license policy contains unknown selected component: "+name)
		}
	}
	return problems
}

func checkLicensePolicyMutationTests(policy string, selected map[string]selectedComponentPolicy, lock any, allowed map[string]bool, conditionallyAllowed map[string]map[string]bool) []string {
	var problems []string
	mutated := make(map[string]selectedComponentPolicy, len(selected)+1)
	for name, item := range selected {
		mutated[name] = item
	}
	mutated["Unreviewed MIT helper"] = selectedComponentPolicy{License: "MIT", Status: "ACTIVE", Role: "unreviewed", Source: "https://example.invalid/license"}
	if !containsProblem(validateSelectedComponentInventory(mutated), "license policy contains unknown selected component: Unreviewed MIT helper") {
		problems = append(problems, "architecture.supply.extra-license-component mutation was accepted")
	}
	lines := strings.Split(strings.ReplaceAll(policy, "\r\n", "\n"), "\n")
	removedSource := false
	var missingSourceLines []string
	for _, line := range lines {
		if !removedSource && strings.HasPrefix(line, "    source: ") {
			removedSource = true
			continue
		}
		missingSourceLines = append(missingSourceLines, line)
	}
	_, missingSourceProblems := parseSelectedComponentLicenses(strings.Join(missingSourceLines, "\n"))
	if !containsProblemPrefix(missingSourceProblems, "selected component has no source:") {
		problems = append(problems, "architecture.supply.license-missing-source mutation was accepted")
	}
	_, duplicateSectionProblems := parseSelectedComponentLicenses(policy + "\nselected_components:\n")
	if !containsProblem(duplicateSectionProblems, "license policy must contain exactly one top-level selected_components section") {
		problems = append(problems, "architecture.supply.duplicate-license-section mutation was accepted")
	}
	mutatedLock, cloneErr := cloneJSONValue(lock)
	if cloneErr != nil {
		problems = append(problems, "architecture.license.unknown-or-forbidden mutation setup failed: "+cloneErr.Error())
	} else if !setToolchainLicense(mutatedLock, "Unknown-License") {
		problems = append(problems, "architecture.license.unknown-or-forbidden mutation setup failed")
	} else if !containsProblemPrefix(checkVersionedComponentLicenses(mutatedLock, allowed, conditionallyAllowed), "versioned component uses unknown, forbidden, or unapproved conditional license:") {
		problems = append(problems, "architecture.license.unknown-or-forbidden mutation was accepted")
	}
	preservingLock, cloneErr := cloneJSONValue(lock)
	if cloneErr != nil {
		problems = append(problems, "architecture.license.unknown-or-forbidden preserving mutation setup failed: "+cloneErr.Error())
	} else if !setToolchainLicense(preservingLock, "MIT") {
		problems = append(problems, "architecture.license.unknown-or-forbidden preserving mutation setup failed")
	} else if preservingProblems := checkVersionedComponentLicenses(preservingLock, allowed, conditionallyAllowed); len(preservingProblems) != 0 {
		problems = append(problems, "architecture.license.unknown-or-forbidden preserving mutation was rejected: "+strings.Join(preservingProblems, "; "))
	}
	return problems
}

func cloneJSONValue(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var clone any
	if err := json.Unmarshal(raw, &clone); err != nil {
		return nil, err
	}
	return clone, nil
}

func setToolchainLicense(value any, license string) bool {
	root, ok := value.(map[string]any)
	if !ok {
		return false
	}
	toolchains, ok := root["toolchains"].(map[string]any)
	if !ok {
		return false
	}
	goToolchain, ok := toolchains["go"].(map[string]any)
	if !ok {
		return false
	}
	goToolchain["license"] = license
	return true
}

func parseSelectedComponentLicenses(policy string) (map[string]selectedComponentPolicy, []string) {
	components := make(map[string]selectedComponentPolicy)
	inSelected := false
	currentName := ""
	current := selectedComponentPolicy{}
	currentKeys := make(map[string]bool)
	flush := func(problems *[]string) {
		if currentName == "" {
			return
		}
		if current.License == "" {
			*problems = append(*problems, "selected component has no license: "+currentName)
		}
		if current.Status != "ACTIVE" && current.Status != "DEFERRED" {
			*problems = append(*problems, "selected component has invalid status: "+currentName)
		}
		if strings.TrimSpace(current.Role) == "" {
			*problems = append(*problems, "selected component has no role: "+currentName)
		}
		if !strings.HasPrefix(current.Source, "https://") {
			*problems = append(*problems, "selected component has no source: "+currentName)
		}
		if _, duplicate := components[currentName]; duplicate {
			*problems = append(*problems, "duplicate selected component license entry: "+currentName)
		} else if current.License != "" && (current.Status == "ACTIVE" || current.Status == "DEFERRED") && current.Role != "" && strings.HasPrefix(current.Source, "https://") {
			components[currentName] = current
		}
		currentName, current = "", selectedComponentPolicy{}
		currentKeys = make(map[string]bool)
	}
	var problems []string
	sectionCount := 0
	policyLines := strings.Split(strings.ReplaceAll(policy, "\r\n", "\n"), "\n")
	for _, line := range policyLines {
		if strings.TrimSpace(line) == "selected_components:" && !strings.HasPrefix(line, " ") {
			sectionCount++
		}
	}
	for _, line := range policyLines {
		trimmed := strings.TrimSpace(line)
		if !inSelected {
			if trimmed == "selected_components:" && !strings.HasPrefix(line, " ") {
				inSelected = true
			}
			continue
		}
		if trimmed != "" && !strings.HasPrefix(line, " ") {
			flush(&problems)
			break
		}
		if strings.HasPrefix(trimmed, "- name: ") {
			flush(&problems)
			currentName = strings.TrimSpace(strings.TrimPrefix(trimmed, "- name: "))
			currentKeys["name"] = true
			continue
		}
		if currentName == "" || trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			problems = append(problems, "malformed selected component field: "+currentName)
			continue
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if currentKeys[key] {
			problems = append(problems, "duplicate selected component field: "+currentName+" -> "+key)
			continue
		}
		currentKeys[key] = true
		switch key {
		case "status":
			current.Status = value
		case "role":
			current.Role = value
		case "license":
			current.License = value
		case "source":
			current.Source = value
		default:
			problems = append(problems, "unknown selected component field: "+currentName+" -> "+key)
		}
	}
	flush(&problems)
	if sectionCount != 1 {
		problems = append(problems, "license policy must contain exactly one top-level selected_components section")
	}
	return components, problems
}

func rejectDuplicateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple top-level JSON values")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	tokenValue, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := tokenValue.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object member %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("unterminated JSON array")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}

// walkDir and walkFiles keep generated local evidence/build caches out of the
// source-policy scans. These paths are never application inputs: E2E runs,
// toolchain caches and controller evidence are intentionally untracked and may
// contain vendored fixtures, Dockerfiles or test certificates that would
// otherwise be misclassified as repository source. The skip is exact to the
// workspace root and only applies to conventional generated names.
func walkDir(root string, fn func(path string, entry os.DirEntry, walkErr error) error) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && path != root && entry.IsDir() && generatedWorkspaceDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		return fn(path, entry, walkErr)
	})
}

func walkFiles(root string, fn func(path string, info os.FileInfo, walkErr error) error) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr == nil && path != root && info.IsDir() && generatedWorkspaceDirectory(info.Name()) {
			return filepath.SkipDir
		}
		return fn(path, info, walkErr)
	})
}

func generatedWorkspaceDirectory(name string) bool {
	return name == "out" || name == ".codex-docker-cli" || name == ".tmp" || strings.HasPrefix(name, ".tmp-")
}

func checkForbiddenDirectories(root string) []string {
	forbidden := []string{
		"internal/chat",
		"internal/conversations",
		"internal/agents",
		"internal/mcp",
		"internal/knowledge-graph",
		"internal/graph",
		"internal/reports",
		"internal/timeline",
		"internal/commitments",
		"internal/notifications",
		"internal/write-actions",
		"internal/writeactions",
	}
	var problems []string
	for _, relative := range forbidden {
		if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err == nil && info.IsDir() {
			problems = append(problems, "forbidden product module: "+relative)
		}
	}
	return problems
}

func checkCommandSurface(root string) []string {
	cmdRoot := filepath.Join(root, "cmd")
	entries, err := os.ReadDir(cmdRoot)
	if os.IsNotExist(err) {
		if _, moduleErr := os.Stat(filepath.Join(root, "go.mod")); moduleErr == nil {
			return []string{"Go module exists but cmd/server, cmd/worker, cmd/connector and cmd/purger are missing"}
		}
		return nil
	}
	if err != nil {
		return []string{err.Error()}
	}
	guardrailRaw, err := os.ReadFile(filepath.Join(root, "architecture", "guardrails.yaml"))
	if err != nil {
		return []string{"missing architecture/guardrails.yaml for command inventory: " + err.Error()}
	}
	return checkAllowedBinaryInventory(cmdRoot, entries, string(guardrailRaw))
}

// checkAllowedBinaryInventory makes guardrails.yaml the sole source of the
// command permission inventory. The checker deliberately has no parallel map
// of allowed names: the five reviewed entries must map one-to-one to cmd/
// directories, and the operator is an inventory entry without implying that
// its production composition or activation has occurred.
func checkAllowedBinaryInventory(cmdRoot string, entries []os.DirEntry, guardrails string) []string {
	allowedBinaries, problems := parseAllowedBinaries(guardrails)
	if len(allowedBinaries) != 6 {
		problems = append(problems, fmt.Sprintf("allowed_binaries must contain exactly six entries, got %d", len(allowedBinaries)))
	}
	allowed := make(map[string]bool, len(allowedBinaries))
	for _, binary := range allowedBinaries {
		if !strings.HasPrefix(binary, "knowvault-") {
			problems = append(problems, "allowed_binaries entry has an invalid product prefix: "+binary)
			continue
		}
		directory := strings.TrimPrefix(binary, "knowvault-")
		if directory == "" || allowed[directory] {
			problems = append(problems, "allowed_binaries entry is empty or duplicated: "+binary)
			continue
		}
		allowed[directory] = true
	}
	if !allowed["operator"] {
		problems = append(problems, "allowed_binaries must include knowvault-operator")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !allowed[entry.Name()] {
			problems = append(problems, "only reviewed application commands are allowed: cmd/"+entry.Name())
			continue
		}
	}
	for directory := range allowed {
		info, err := os.Stat(filepath.Join(cmdRoot, directory))
		if err != nil || !info.IsDir() {
			problems = append(problems, "allowed binary has no matching cmd directory: "+directory)
		}
	}
	found := make(map[string]bool)
	for _, entry := range entries {
		if entry.IsDir() && allowed[entry.Name()] {
			found[entry.Name()] = true
		}
	}
	// These four are the separately reviewed product composition commands;
	// they are deliberately not another allowed-binaries inventory. Operator
	// and sandbox-dispatcher remain permission/inventory entries only here.
	for _, name := range []string{"server", "worker", "connector", "purger"} {
		if !found[name] {
			problems = append(problems, "required Go command is missing: cmd/"+name)
		}
	}
	return problems
}

func parseAllowedBinaries(guardrails string) ([]string, []string) {
	lines := strings.Split(strings.ReplaceAll(guardrails, "\r\n", "\n"), "\n")
	var entries []string
	var problems []string
	inSection := false
	for _, line := range lines {
		if strings.TrimSpace(line) == "allowed_binaries:" && len(line)-len(strings.TrimLeft(line, " \t")) == 0 {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			break
		}
		if indent != 2 || !strings.HasPrefix(trimmed, "-") {
			problems = append(problems, "allowed_binaries contains a non-list entry: "+strings.TrimSpace(line))
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		if value == "" || !regexp.MustCompile(`^knowvault-[a-z0-9]+(?:-[a-z0-9]+)*$`).MatchString(value) {
			problems = append(problems, "allowed_binaries contains an invalid entry: "+value)
			continue
		}
		entries = append(entries, value)
	}
	if !inSection {
		problems = append(problems, "guardrails.yaml is missing the allowed_binaries section")
	}
	return entries, problems
}

const (
	pinnedTimezoneArchivePath   = "internal/tzrules/zoneinfo.zip"
	pinnedTimezoneArchiveSize   = 408125
	pinnedTimezoneArchiveDigest = "8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8"
)

// pinnedTimezoneArchive admits exactly one archive into the default-deny
// application tree: the normalized pinned path holding a regular, non-symlink
// file whose size and SHA-256 match the frozen zoneinfo bundle. The archive is
// never admitted by name or extension alone.
func pinnedTimezoneArchive(root, path string, entry os.DirEntry) bool {
	if !entry.Type().IsRegular() || filepath.ToSlash(relative(root, path)) != pinnedTimezoneArchivePath {
		return false
	}
	info, err := entry.Info()
	if err != nil || info.Size() != pinnedTimezoneArchiveSize {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]) == pinnedTimezoneArchiveDigest
}

func checkApplicationLanguages(root string) []string {
	// Application directories are default-deny. The list includes the approved
	// source languages plus inert configuration/document/asset formats needed by
	// the web build. An unknown extension is rejected instead of being silently
	// treated as harmless source code.
	allowedApplicationExtensions := map[string]bool{
		".go": true, ".ts": true, ".tsx": true, ".sql": true, ".css": true, ".html": true,
		".json": true, ".yaml": true, ".yml": true, ".svg": true, ".png": true,
		".jpg": true, ".jpeg": true, ".webp": true, ".ico": true,
		".woff": true, ".woff2": true, ".txt": true, ".md": true,
	}
	skippedDirectories := map[string]bool{
		"node_modules": true, ".pnpm-store": true, "dist": true, "coverage": true, ".cache": true,
	}
	var problems []string
	for _, directory := range []string{"cmd", "internal", "web", "api", "db", "apps", "modules", "packages"} {
		applicationRoot := filepath.Join(root, directory)
		if info, err := os.Stat(applicationRoot); err != nil || !info.IsDir() {
			continue
		}
		_ = walkDir(applicationRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				problems = append(problems, walkErr.Error())
				return nil
			}
			if entry.IsDir() {
				if filepath.ToSlash(relative(root, path)) == pinnedTimezoneArchivePath {
					problems = append(problems, "forbidden or unknown application file type: "+relative(root, path))
				}
				if path != applicationRoot && skippedDirectories[entry.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			extension := strings.ToLower(filepath.Ext(path))
			if !allowedApplicationExtensions[extension] && !pinnedTimezoneArchive(root, path, entry) {
				problems = append(problems, "forbidden or unknown application file type: "+relative(root, path))
			}
			return nil
		})
	}
	for _, name := range []string{"app.js", "app.jsx", "app.mjs", "app.cjs"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			problems = append(problems, "forbidden legacy JavaScript application entrypoint: "+name)
		}
	}
	return problems
}

func checkAPI(root string) []string {
	// The enterprise surface intentionally exposes workspace-scoped
	// /conversations routes.  Legacy global chat/agent/action/search surfaces
	// remain forbidden; conversation metadata is not the retired global chat
	// API and is governed by the lifecycle authority and workspace RBAC.
	fragments := []string{
		"/chat",
		"/agents",
		"/actions",
		"/execute-sql",
		"/global-search",
	}
	return scanFiles(filepath.Join(root, "api"), func(path, content string) []string {
		var problems []string
		for _, fragment := range fragments {
			if strings.Contains(content, fragment) {
				problems = append(problems, fmt.Sprintf("forbidden API fragment %q in %s", fragment, relative(root, path)))
			}
		}
		return problems
	})
}

func checkUISurface(root string) []string {
	patterns := []string{
		`data-route="answers"`,
		`data-route="chat"`,
		"aria-label=\"\u0423\u0432\u0435\u0434\u043e\u043c\u043b\u0435\u043d\u0438\u044f\"",
		`aria-label="Notifications"`,
		`/notifications`,
	}

	inspect := func(path, content string) []string {
		var problems []string
		for _, pattern := range patterns {
			if strings.Contains(content, pattern) {
				problems = append(problems, fmt.Sprintf("forbidden 1.0 UI surface %q in %s", pattern, relative(root, path)))
			}
		}
		return problems
	}

	var problems []string
	for _, name := range []string{"index.html"} {
		path := filepath.Join(root, name)
		if raw, err := os.ReadFile(path); err == nil {
			problems = append(problems, inspect(path, string(raw))...)
		}
	}
	problems = append(problems, scanFiles(filepath.Join(root, "web"), inspect)...)
	return problems
}

func checkDeploymentManifests(root string) []string {
	imageLine := regexp.MustCompile(`(?mi)^\s*(?:image:|FROM)\s+([^\s]+)[^\r\n]*`)
	pythonImport := regexp.MustCompile(`^\s*from\s+[.A-Za-z_][.A-Za-z_0-9]*\s+import(?:\s|$)`)
	digest := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	var problems []string
	for _, dir := range []string{"deploy", ".github", ".gitlab"} {
		problems = append(problems, scanFiles(filepath.Join(root, dir), func(path, content string) []string {
			var found []string
			for _, match := range imageLine.FindAllStringSubmatch(content, -1) {
				// Python import syntax is not a Docker base reference. Keep
				// checking other lines, including embedded Dockerfile templates.
				if filepath.Ext(path) == ".py" && pythonImport.MatchString(match[0]) {
					continue
				}
				image := strings.Trim(match[1], `"'`)
				if image == "scratch" {
					continue
				}
				if strings.Contains(image, ":latest") || !digest.MatchString(image) {
					found = append(found, "image requires exact tag and digest in "+relative(root, path)+": "+image)
				}
			}
			return found
		})...)
	}
	sandboxPath := filepath.Join(root, "deploy", "manifests", "sandbox-dispatcher.yaml")
	if raw, err := os.ReadFile(sandboxPath); err == nil {
		content := string(raw)
		required := []string{
			"kind: SandboxDispatcherDeployment",
			"lifecycle: CONTRACT_ONLY",
			"activation: EXTERNAL_ACCEPTANCE_REQUIRED",
			"binary: knowvault-sandbox-dispatcher",
			"protocol: DISPATCHER_V2",
			"creates_containers: false",
			"container_runtime_access: false",
			"database_access: false",
			"secret_access: false",
			"worker_input_direction: PULL_ONLY",
			"socket_cardinality: ONE_PER_PARSER_ROLE",
			"parser_type_binding: SOCKET_PROPERTY",
			"source: SO_PEERCRED",
			"exact_uid_gid_required: true",
			"role_uids_pairwise_distinct: true",
			"supervisor: REQUIRED",
			"deadline: HARD",
			"descendant_cleanup: REQUIRED",
			"source: KERNEL_OBSERVATION",
			"startup_environment:",
			"KNOWVAULT_DISPATCHER_ROOT_DIR: /run/knowvault/sandbox",
			"KNOWVAULT_DISPATCHER_SUBMIT_SOCKET: unix:///run/knowvault/sandbox/submit/dispatcher.sock",
			"KNOWVAULT_DISPATCHER_HANDOFF_SOCKET: unix:///run/knowvault/sandbox/supervisor/handoff.sock",
			"KNOWVAULT_DISPATCHER_OFFICE_REGISTER_SOCKET: unix:///run/knowvault/sandbox/office/register.sock",
			"KNOWVAULT_DISPATCHER_PDF_REGISTER_SOCKET: unix:///run/knowvault/sandbox/pdf/register.sock",
			"KNOWVAULT_DISPATCHER_SUPERVISOR_UID: \"0\"",
			"KNOWVAULT_DISPATCHER_SUPERVISOR_GID: \"0\"",
			"KNOWVAULT_DISPATCHER_SUBMITTER_UID: \"65530\"",
			"KNOWVAULT_DISPATCHER_SUBMITTER_GID: \"65530\"",
			"KNOWVAULT_DISPATCHER_OFFICE_WORKER_UID: \"65532\"",
			"KNOWVAULT_DISPATCHER_OFFICE_WORKER_GID: \"65532\"",
			"KNOWVAULT_DISPATCHER_PDF_WORKER_UID: \"65533\"",
			"KNOWVAULT_DISPATCHER_PDF_WORKER_GID: \"65533\"",
			"KNOWVAULT_DISPATCHER_MAX_PAYLOAD_BYTES: \"67108864\"",
			"KNOWVAULT_DISPATCHER_FRAME_TIMEOUT_MS: \"5000\"",
		}
		for _, fragment := range required {
			if !strings.Contains(content, fragment) {
				problems = append(problems, "sandbox contract-only manifest missing required binding "+fragment)
			}
		}
		normalized := strings.ReplaceAll(content, "\r\n", "\n")
		for role, block := range map[string]string{
			"submit":     "    submit:\n      path: /run/knowvault/sandbox/submit/dispatcher.sock\n      owner_uid: 65530\n      owner_gid: 65530\n      mode: \"0600\"\n      mount_cardinality: EXACTLY_ONE_CONSUMER",
			"supervisor": "    supervisor_handoff:\n      path: /run/knowvault/sandbox/supervisor/handoff.sock\n      owner_uid: 0\n      owner_gid: 0\n      mode: \"0600\"\n      mount_cardinality: EXACTLY_ONE_CONSUMER",
			"office":     "    register_office:\n      path: /run/knowvault/sandbox/office/register.sock\n      owner_uid: 65532\n      owner_gid: 65532\n      mode: \"0600\"\n      mount_cardinality: EXACTLY_ONE_CONSUMER",
			"pdf":        "    register_pdf:\n      path: /run/knowvault/sandbox/pdf/register.sock\n      owner_uid: 65533\n      owner_gid: 65533\n      mode: \"0600\"\n      mount_cardinality: EXACTLY_ONE_CONSUMER",
		} {
			if strings.Count(normalized, block) != 1 {
				problems = append(problems, "sandbox contract-only manifest requires one exact UID/GID/path block for role "+role)
			}
		}
		if strings.Count(content, `mode: "0600"`) != 4 || strings.Count(content, "mount_cardinality: EXACTLY_ONE_CONSUMER") != 4 {
			problems = append(problems, "sandbox contract-only manifest must expose four owner-only, single-consumer role sockets")
		}
		for _, forbidden := range []string{
			"lifecycle: ACTIVE",
			"activation: AUTOMATIC",
			"container_runtime_access: true",
			"database_access: true",
			"secret_access: true",
			"worker_input_direction: PUSH",
			"socket_cardinality: EXACTLY_ONE",
			"image:",
			"FROM ",
		} {
			if strings.Contains(content, forbidden) {
				problems = append(problems, "sandbox contract-only manifest contains forbidden activation/runtime binding "+forbidden)
			}
		}
	} else if !os.IsNotExist(err) {
		problems = append(problems, "cannot read sandbox contract-only manifest: "+err.Error())
	}
	return problems
}

// checkOperatorArtifact is the source-level supply-chain gate for the
// knowvault-operator image. It deliberately checks the build definition and
// lock together: a Dockerfile that happens to contain the right binary name is
// not enough when migrations can be omitted, the compile can fetch, or the
// final stage can regain a shell/root filesystem.
func checkOperatorArtifact(root string) []string {
	lockPath := filepath.Join(root, "architecture", "versions.json")
	rawLock, err := os.ReadFile(lockPath)
	if err != nil {
		return []string{"missing architecture/versions.json for operator artifact check"}
	}
	if err := rejectDuplicateJSON(rawLock); err != nil {
		return []string{"invalid architecture/versions.json for operator artifact check: " + err.Error()}
	}
	var lock any
	if err := json.Unmarshal(rawLock, &lock); err != nil {
		return []string{"invalid architecture/versions.json for operator artifact check: " + err.Error()}
	}
	problems := validateOperatorArtifact(lock)

	dockerfilePath := filepath.Join(root, "deploy", "images", "Dockerfile.operator")
	rawDockerfile, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return append(problems, "missing deploy/images/Dockerfile.operator")
	}
	dockerfile := string(rawDockerfile)
	required := []string{
		"FROM golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669 AS builder",
		"ARG SOURCE_DATE_EPOCH=1704067200",
		"find /out/runtime -exec touch -h -d \"@${SOURCE_DATE_EPOCH}\" {} +",
		"ENV GOTOOLCHAIN=local",
		"ENV GOEXPERIMENT=jsonv2",
		"ARG TARGETOS=linux",
		"ARG TARGETARCH=amd64",
		"test \"${TARGETOS}\" = linux && test \"${TARGETARCH}\" = amd64",
		"COPY go.mod go.sum ./",
		"RUN go mod download",
		"COPY cmd/operator ./cmd/operator",
		"COPY internal ./internal",
		"COPY db/migrations ./db/migrations",
		"RUN --network=none",
		"-mod=readonly",
		"-trimpath",
		"-buildvcs=false",
		"-buildid=",
		"-o /out/runtime/knowvault-operator ./cmd/operator",
		"FROM scratch AS runtime",
		"USER 0:0",
		"WORKDIR /",
		"COPY --from=builder /out/runtime/ /",
		"ENTRYPOINT [\"/knowvault-operator\"]",
		"operator-artifact-v1",
		"artifact_identity",
		"RELEASE_ATTESTATION_REQUIRED",
		"SPDX-2.3",
		"generator_version",
		"1.48.0",
	}
	for _, marker := range required {
		if !strings.Contains(dockerfile, marker) {
			problems = append(problems, "operator artifact Dockerfile is missing required marker: "+marker)
		}
	}
	runtimeAt := strings.Index(dockerfile, "FROM scratch AS runtime")
	if runtimeAt < 0 {
		runtimeAt = len(dockerfile)
	}
	runtime := dockerfile[runtimeAt:]
	for _, forbidden := range []string{
		"RUN ", "ADD ", "apt-get", "apk add", "curl", "wget", "go mod download",
		"/bin/sh", "/bin/bash", "FROM golang:", "COPY --from=builder /src",
	} {
		if strings.Contains(runtime, forbidden) {
			problems = append(problems, "operator artifact runtime stage contains forbidden build/runtime surface: "+forbidden)
		}
	}

	contextPath := filepath.Join(root, "deploy", "images", "Dockerfile.operator.dockerignore")
	contextRaw, err := os.ReadFile(contextPath)
	if err != nil {
		problems = append(problems, "missing Dockerfile.operator-specific build context policy")
	} else {
		context := string(contextRaw)
		for _, marker := range []string{"!go.mod", "!go.sum", "!cmd/**", "!internal/**", "!db/migrations/**"} {
			if !strings.Contains(context, marker) {
				problems = append(problems, "operator artifact build context does not admit required input: "+marker)
			}
		}
	}
	return problems
}

// checkAuthorizeNoOpGate enforces D7-1 mechanically: no authorize function in
// the tree may be a placeholder whose body is a single unconditional
// `return nil`. A real authorize must make a decision (a database gate, a
// policy check) and surface a denial. This catches both named functions whose
// name contains "authorize" and authorize closures assigned to an
// authorize-named variable.
func checkAuthorizeNoOpGate(root string) []string {
	var problems []string
	problems = append(problems, scanFiles(filepath.Join(root, "internal"), func(path, content string) []string {
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(relative(root, path))
		parsed, err := parser.ParseFile(token.NewFileSet(), path, content, 0)
		if err != nil {
			return []string{"cannot parse Go source for authorize gate in " + rel + ": " + err.Error()}
		}
		var found []string
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.FuncDecl:
				if strings.Contains(strings.ToLower(typed.Name.Name), "authorize") && isUnconditionalNilReturn(typed.Type, typed.Body) {
					found = append(found, "no-op authorize function must not exist (D7-1): "+rel+"#"+typed.Name.Name)
				}
			case *ast.AssignStmt:
				for _, left := range typed.Lhs {
					identifier, ok := left.(*ast.Ident)
					if !ok || !strings.Contains(strings.ToLower(identifier.Name), "authorize") {
						continue
					}
					if len(typed.Rhs) != 1 {
						continue
					}
					if literal, ok := typed.Rhs[0].(*ast.FuncLit); ok && isUnconditionalNilReturn(literal.Type, literal.Body) {
						found = append(found, "no-op authorize closure must not exist (D7-1): "+rel+"#"+identifier.Name)
					}
				}
			}
			return true
		})
		return found
	})...)
	return problems
}

// isUnconditionalNilReturn reports whether the function signature returns a
// single bare error and its body is exactly one `return nil` statement.
func isUnconditionalNilReturn(signature *ast.FuncType, body *ast.BlockStmt) bool {
	if signature == nil || signature.Results == nil || len(signature.Results.List) != 1 || body == nil {
		return false
	}
	errorType, ok := signature.Results.List[0].Type.(*ast.Ident)
	if !ok || errorType.Name != "error" {
		return false
	}
	if len(body.List) != 1 {
		return false
	}
	returnStatement, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(returnStatement.Results) != 1 {
		return false
	}
	nilLiteral, ok := returnStatement.Results[0].(*ast.Ident)
	return ok && nilLiteral.Name == "nil"
}

func checkGoBoundaries(root string) []string {
	var problems []string
	problems = append(problems, scanFiles(filepath.Join(root, "internal"), func(path, content string) []string {
		if filepath.Ext(path) != ".go" {
			return nil
		}

		rel := filepath.ToSlash(relative(root, path))
		parsed, err := parser.ParseFile(token.NewFileSet(), path, content, parser.ImportsOnly)
		if err != nil {
			return []string{"cannot parse Go imports in " + rel + ": " + err.Error()}
		}
		var found []string
		if strings.Contains(content, "NewOIDCServiceAccess(") &&
			rel != "internal/platform/database/database.go" &&
			rel != "internal/platform/database/database_test.go" &&
			rel != "internal/identity/repository/repository.go" {
			found = append(found, "OIDC pre-auth database context outside the reviewed identity boundary: "+rel)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			lower := strings.ToLower(importPath)
			if strings.HasPrefix(importPath, "github.com/jackc/pgx/v5") && !strings.HasPrefix(rel, "internal/platform/database/") &&
				!strings.HasPrefix(rel, "internal/operator/") && !strings.HasPrefix(rel, "internal/source/postgresqlquery/") {
				found = append(found, "PostgreSQL driver outside internal/platform/database: "+rel)
			}
			if strings.Contains(lower, "opensearch") && !strings.HasPrefix(rel, "internal/search/") {
				found = append(found, "OpenSearch client outside internal/search: "+rel)
			}
			usesModelProvider := strings.Contains(lower, "vllm") || strings.Contains(lower, "openai") ||
				strings.Contains(lower, "anthropic") || strings.Contains(lower, "ollama")
			if usesModelProvider && !strings.HasPrefix(rel, "internal/modelgateway/") {
				found = append(found, "model provider client outside internal/modelgateway: "+rel)
			}
			usesSecretProvider := strings.Contains(lower, "secretsmanager") || strings.Contains(lower, "keyvault") ||
				strings.Contains(lower, "secretmanager") || strings.Contains(lower, "hashicorp/vault")
			if usesSecretProvider && !strings.HasPrefix(rel, "internal/platform/secrets/") &&
				!strings.HasPrefix(rel, "internal/source/") && !strings.HasPrefix(rel, "internal/connector/") {
				found = append(found, "secret provider client outside approved packages: "+rel)
			}
			usesAuditSink := strings.Contains(lower, "syslog") || strings.Contains(lower, "eventhub") || strings.Contains(lower, "splunk")
			if usesAuditSink && !strings.HasPrefix(rel, "internal/audit/") {
				found = append(found, "audit sink client outside internal/audit: "+rel)
			}
			// ADR-0089 §3: internal/source/postgresqlquery/governedquery is the
			// single owner of the dedicated governed-execution database role's
			// connection capability and the only code that may pass
			// model-authored SQL text to a database call. internal/governedask
			// is the one server-owned orchestration service permitted to call
			// it (it never accepts SQL as input; it only forwards the exact
			// model-composed candidate governedquery.Execute already refuses
			// to trust); internal/platform/workspaceapi is the thin REST/MCP
			// transport surface that calls that service; internal/platform/
			// composition wires the mounted config into it. No other package
			// may import it, so a mutation routing governed SQL execution
			// through another package fails this guard exactly as the
			// postgresqlquery owner package itself already does for the
			// ADR-0078 ingestion connector.
			if strings.HasPrefix(importPath, "knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery") &&
				!strings.HasPrefix(rel, "internal/source/postgresqlquery/governedquery/") &&
				!strings.HasPrefix(rel, "internal/governedask/") &&
				!strings.HasPrefix(rel, "internal/platform/workspaceapi/") &&
				!strings.HasPrefix(rel, "internal/platform/composition/") {
				found = append(found, "governed query execution capability outside its owner package: "+rel)
			}
		}
		return found
	})...)
	return problems
}

func scanFiles(root string, inspect func(path, content string) []string) []string {
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil
	}

	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "node_modules", ".pnpm-store", "dist", "coverage", ".cache":
				return filepath.SkipDir
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, err.Error())
			return nil
		}
		problems = append(problems, inspect(path, string(raw))...)
		return nil
	})
	return problems
}

func scanPaths(root string, inspect func(path string) []string) []string {
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil
	}
	var problems []string
	_ = walkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			problems = append(problems, walkErr.Error())
			return nil
		}
		if !entry.IsDir() {
			problems = append(problems, inspect(path)...)
		}
		return nil
	})
	return problems
}

func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}

func fatal(problems []string) {
	fmt.Fprintln(os.Stderr, "Architecture guardrails failed:")
	for _, problem := range problems {
		fmt.Fprintln(os.Stderr, " -", problem)
	}
	os.Exit(1)
}
