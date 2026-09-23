package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionRuntimeGuardMutationsAreRejected(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(runtimeProductionSource)))
	if err != nil {
		t.Fatal(err)
	}
	if problems := checkProductionRuntimeGuardMutations(raw); len(problems) != 0 {
		t.Fatalf("runtime mutation guard is incomplete: %v", problems)
	}
}

func TestListenerPackageOwnershipRejectsBypasses(t *testing.T) {
	mutations := map[string]string{
		"net listen": `package bypass
import "net"
func run() { _, _ = net.Listen("tcp", ":8080") }
`,
		"global serve mux": `package bypass
import "net/http"
var mux = http.DefaultServeMux
`,
		"package listener": `package bypass
import "net/http"
func run() { _ = http.ListenAndServe(":8080", nil) }
`,
	}
	for name, source := range mutations {
		t.Run(name, func(t *testing.T) {
			parsed, aliases, err := parseGoFileWithAliases("bypass.go", []byte(source))
			if err != nil {
				t.Fatal(err)
			}
			problems := validateListenerPackageOwnership("internal/bypass/bypass.go", parsed, aliases)
			if len(problems) == 0 || !strings.Contains(problems[0], runtimeGuardPrefix+".listener-api-owner:") {
				t.Fatalf("listener ownership bypass was accepted: %v", problems)
			}
		})
	}
}

func TestOpaqueRuntimeRejectsExportedAndHandlerFields(t *testing.T) {
	source := `package composition
import "net/http"
type Runtime struct { Handler http.Handler; state *runtimeState }
type runtimeState struct { server *http.Server }
`
	parsed, _, err := parseGoFileWithAliases("runtime_mutated.go", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	problems := validateOpaqueRuntime(parsed)
	joined := strings.Join(problems, "\n")
	for _, code := range []string{".opaque-runtime:", ".handler-exposure:"} {
		if !strings.Contains(joined, runtimeGuardPrefix+code) {
			t.Fatalf("missing %s rejection in %v", code, problems)
		}
	}
}

func TestProductionServerEntrypointRejectsDirectListenerBypass(t *testing.T) {
	source := `package main
import (
    "context"
    "net/http"
    "os"
)
func main() { os.Exit(run()) }
func run() int { _ = context.Background(); _ = http.ListenAndServe(":8080", nil); return 0 }
`
	problems := validateProductionServerEntrypoint("cmd/server/main.go", []byte(source))
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, runtimeGuardPrefix+".entrypoint-import:") {
		t.Fatalf("direct listener import was accepted: %v", problems)
	}
}

func TestProductionWorkerEntrypointRejectsCapabilityImports(t *testing.T) {
	source := `package main
import (
    "context"
    "os"
    "time"
    "knowvault.local/verified-workspace/internal/platform/buildinfo"
    "knowvault.local/verified-workspace/internal/platform/database"
    "knowvault.local/verified-workspace/internal/platform/lifecycle"
    "knowvault.local/verified-workspace/internal/platform/workercomposition"
)
func main() { os.Exit(run()) }
func run() int {
    _ = context.Background(); _ = time.Second; _ = buildinfo.Info{}; _ = database.DefaultConfig()
    _ = lifecycle.SignalContext; _ = workercomposition.LoadProduction
    return 0
}
`
	problems := validateProductionWorkerEntrypoint("cmd/worker/main.go", []byte(source))
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, runtimeGuardPrefix+".worker-entrypoint-import:") {
		t.Fatalf("worker capability import was accepted: %v", problems)
	}
}

func TestProductionPurgerEntrypointRejectsCapabilityImports(t *testing.T) {
	source := `package main
import (
    "context"
    "os"
    "time"
    "knowvault.local/verified-workspace/internal/platform/buildinfo"
    "knowvault.local/verified-workspace/internal/platform/database"
    "knowvault.local/verified-workspace/internal/platform/lifecycle"
    "knowvault.local/verified-workspace/internal/platform/purgercomposition"
)
func main() { os.Exit(run()) }
func run() int {
    _ = context.Background(); _ = time.Second; _ = buildinfo.Info{}; _ = database.DefaultConfig()
    _ = lifecycle.SignalContext; _ = purgercomposition.LoadProduction
    return 0
}
`
	problems := validateProductionPurgerEntrypoint("cmd/purger/main.go", []byte(source))
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, runtimeGuardPrefix+".purger-entrypoint-import:") {
		t.Fatalf("purger capability import was accepted: %v", problems)
	}
}

func TestArtifactOutboxGuardRejectsOwnerPrivilegeAndTriggerDepthMutations(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000005_stage2_encrypted_artifact_outbox.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ownerTuples, ownerProblems := loadEncryptedArtifactOwnerTuples("..")
	if len(ownerProblems) != 0 {
		t.Fatal(ownerProblems)
	}
	baseline := string(raw)
	if problems := checkArtifactOutboxMigration(baseline, ownerTuples); len(problems) != 0 {
		t.Fatalf("accepted migration fails its guard: %v", problems)
	}
	mutations := map[string]string{
		"duplicate owner": strings.Replace(baseline,
			"('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),",
			"('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),\n        ('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),", 1),
		"owner moved to comment": strings.Replace(baseline,
			"        ('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT'),\n", "", 1) +
			"\n-- ('external_identity', 'external_subject_artifact_id', 'EXTERNAL_IDENTITY', 'SUBJECT')\n",
		"grant all event":     baseline + "\nGRANT ALL PRIVILEGES ON TABLE public.outbox_event TO knowvault_app;\n",
		"grant truncate head": baseline + "\nGRANT TRUNCATE ON public.outbox_sequence_head TO knowvault_app;\n",
		"grant references":    baseline + "\nGRANT REFERENCES ON public.outbox_event TO knowvault_app;\n",
		"grant trigger":       baseline + "\nGRANT TRIGGER ON public.outbox_event TO knowvault_app;\n",
		"trigger depth":       baseline + "\nSELECT pg_trigger_depth();\n",
		"runtime update":      baseline + "\nGRANT UPDATE ON public.outbox_event TO knowvault_app;\n",
		"multi-table grant":   baseline + "\nGRANT UPDATE ON TABLE public.organization, public.outbox_event TO knowvault_app;\n",
		"arbitrary function":  baseline + "\nGRANT EXECUTE ON FUNCTION app.stage2_escalate() TO knowvault_app;\n",
		"caller hash nonce fence": strings.Replace(baseline,
			"UNIQUE (organization_id, kek_reference, kek_version, nonce)",
			"UNIQUE (organization_id, kek_reference, kek_version, wrapped_dek_hash, nonce)", 1),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if problems := checkArtifactOutboxMigration(mutated, ownerTuples); len(problems) == 0 {
				t.Fatal("unsafe migration mutation was accepted")
			}
		})
	}
}

func TestArtifactContainmentGuardRejectsRuntimeAccessAndLeakyPreflight(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000012_stage2_encrypted_artifact_containment.sql"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkArtifactContainmentMigration(baseline); len(problems) != 0 {
		t.Fatalf("accepted containment migration fails its guard: %v", problems)
	}
	mutations := map[string]string{
		"missing revoke":          strings.Replace(baseline, "REVOKE SELECT, INSERT ON public.encrypted_artifact FROM knowvault_app;", "", 1),
		"regrant select":          baseline + "\nGRANT SELECT ON public.encrypted_artifact TO knowvault_app;\n",
		"regrant insert":          baseline + "\nGRANT INSERT ON public.encrypted_artifact TO knowvault_app;\n",
		"regrant update":          baseline + "\nGRANT UPDATE ON public.encrypted_artifact TO knowvault_app;\n",
		"preflight not definer":   strings.Replace(baseline, "STABLE\nSECURITY DEFINER", "STABLE\nSECURITY INVOKER", 1),
		"preflight not from pub":  strings.Replace(baseline, "REVOKE ALL ON FUNCTION app.artifact_unavailable_key_count(text, bigint) FROM PUBLIC;", "", 1),
		"preflight execute lost":  strings.Replace(baseline, "GRANT EXECUTE ON FUNCTION app.artifact_unavailable_key_count(text, bigint) TO knowvault_app;", "", 1),
		"preflight leaks content": strings.Replace(baseline, "SELECT count(*)", "SELECT ciphertext", 1),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if problems := checkArtifactContainmentMigration(mutated); len(problems) == 0 {
				t.Fatal("unsafe containment migration mutation was accepted")
			}
		})
	}
}

func TestAcceptedADRImmutabilityGuardRejectsHistoryEdits(t *testing.T) {
	// Baseline: every on-disk accepted ADR matches its frozen hash.
	if problems := checkAcceptedADRImmutability(".."); len(problems) != 0 {
		t.Fatalf("accepted ADRs fail immutability baseline: %v", problems)
	}
	const adr = "docs/adr/0055-encrypted-artifact-key-wrapping-backend-accepted.md"
	frozen := map[string]string{adr: "1111111111111111111111111111111111111111111111111111111111111111"}
	for name, disk := range map[string]map[string]string{
		"edited accepted ADR": {adr: "2222222222222222222222222222222222222222222222222222222222222222"},
		"unfrozen accepted ADR": {
			adr:                             "1111111111111111111111111111111111111111111111111111111111111111",
			"docs/adr/0056-new-accepted.md": "3333333333333333333333333333333333333333333333333333333333333333",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if problems := verifyAcceptedADRImmutability("SHA256", frozen, disk); len(problems) == 0 {
				t.Fatal("accepted-ADR history drift was accepted")
			}
		})
	}
	// A frozen entry whose file disappeared (rename/delete) is rejected.
	if problems := verifyAcceptedADRimmutabilityMissing(); len(problems) == 0 {
		t.Fatal("missing accepted ADR was accepted")
	}
	// A non-SHA256 manifest algorithm is rejected.
	if problems := verifyAcceptedADRImmutability("MD5", frozen, map[string]string{adr: "1111111111111111111111111111111111111111111111111111111111111111"}); len(problems) == 0 {
		t.Fatal("wrong immutability algorithm was accepted")
	}
}

func TestProtectedNormativeInventoryIncludesHLDLiveDoDAndADRIndex(t *testing.T) {
	paths, problems := collectProtectedPaths("..")
	if len(problems) != 0 {
		t.Fatalf("collect protected paths: %v", problems)
	}
	if problems := validateProtectedGovernanceInventory("..", paths); len(problems) != 0 {
		t.Fatalf("accepted protected governance inventory fails its own guard: %v", problems)
	}
	protected := make(map[string]bool, len(paths))
	for _, path := range paths {
		protected[path] = true
	}
	requiredNormative := []string{
		"docs/HLD.md",
		"docs/adr/README.md",
		"internal/ingestion/handler.go",
		"internal/sandboxdispatch/v2.go",
		"tests/integration/parserv2harness/harness_linux.go",
		"tests/integration/sandboxdispatch/dispatcher_v2_real_linux_test.go",
		"workers/document-parser/Dockerfile",
		"workers/document-parser/release/image-lock.json",
	}
	for _, required := range requiredNormative {
		t.Run(required, func(t *testing.T) {
			if !protected[required] {
				t.Fatalf("normative file can drift outside protected-hash inventory: %s", required)
			}
		})
	}
	for path := range protected {
		if strings.HasPrefix(path, "workers/document-parser/target/") {
			t.Fatalf("reproducible Maven output entered protected source inventory: %s", path)
		}
	}

	// Mutation coverage: removing HLD from the inventory must be observable as
	// an incomplete normative protection set.
	t.Run("HLD removal is rejected", func(t *testing.T) {
		delete(protected, "docs/HLD.md")
		for _, required := range requiredNormative {
			if !protected[required] {
				if required != "docs/HLD.md" {
					t.Fatalf("unexpected missing normative file after HLD removal: %s", required)
				}
				return
			}
		}
		t.Fatal("HLD removal was accepted by normative protection inventory test")
	})
}

func TestProtectedManifestRebuildPreservesAcceptedInventory(t *testing.T) {
	const manifestPath = "architecture/protected-hashes.json"
	acceptedBytes, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(manifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	var accepted protectedManifest
	if err := json.Unmarshal(acceptedBytes, &accepted); err != nil {
		t.Fatal(err)
	}
	if len(accepted.Files) == 0 {
		t.Fatal("accepted protected inventory is empty")
	}

	// Capture the accepted inventory before regeneration, independently of the
	// collector. Short fixture bytes exercise hashing without copying product data.
	root := t.TempDir()
	expectedHashes := make(map[string]string, len(accepted.Files))
	for relative := range accepted.Files {
		if !filepath.IsLocal(filepath.FromSlash(relative)) {
			t.Fatalf("protected fixture path is not local: %s", relative)
		}
		content := []byte("protected fixture: " + relative + "\n")
		writeFixtureFile(t, root, relative, content)
		sum := sha256.Sum256(content)
		expectedHashes[relative] = hex.EncodeToString(sum[:])
	}
	writeFixtureFile(t, root, manifestPath, acceptedBytes)
	if err := rebuildProtectedManifest(root); err != nil {
		t.Fatalf("rebuild accepted protected inventory: %v", err)
	}
	rebuiltBytes, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt protectedManifest
	if err := json.Unmarshal(rebuiltBytes, &rebuilt); err != nil {
		t.Fatal(err)
	}
	if rebuilt.Version != 1 || rebuilt.Algorithm != "SHA256" {
		t.Fatalf("unexpected rebuilt manifest format: version=%d algorithm=%s", rebuilt.Version, rebuilt.Algorithm)
	}
	for relative, expected := range expectedHashes {
		actual, exists := rebuilt.Files[relative]
		if !exists {
			t.Errorf("rebuild dropped accepted protected path: %s", relative)
		} else if actual != expected {
			t.Errorf("rebuild did not hash current fixture bytes: %s", relative)
		}
	}
	if len(rebuilt.Files) != len(expectedHashes) {
		t.Errorf("rebuild changed accepted inventory size: got %d, want %d", len(rebuilt.Files), len(expectedHashes))
	}

	// A previously pinned file must fail closed when missing, without replacing
	// the last manifest with a partial inventory. One representative is sufficient.
	const missingPath = "web/src/main.tsx"
	if _, exists := accepted.Files[missingPath]; !exists {
		t.Fatalf("missing-file control is outside accepted inventory: %s", missingPath)
	}
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(missingPath))); err != nil {
		t.Fatal(err)
	}
	if err := rebuildProtectedManifest(root); err == nil || !strings.Contains(err.Error(), missingPath) {
		t.Errorf("missing accepted protected file did not stop rebuild: %v", err)
	}
	afterFailure, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(manifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFailure, rebuiltBytes) {
		t.Error("failed rebuild changed the previous manifest bytes")
	}
}

func verifyAcceptedADRimmutabilityMissing() []string {
	const adr = "docs/adr/0055-encrypted-artifact-key-wrapping-backend-accepted.md"
	frozen := map[string]string{adr: "1111111111111111111111111111111111111111111111111111111111111111"}
	return verifyAcceptedADRImmutability("SHA256", frozen, map[string]string{})
}

func TestEncryptedArtifactOwnerParityGuardRejectsRegistryAndDocDrift(t *testing.T) {
	ownerTuples, ownerProblems := loadEncryptedArtifactOwnerTuples("..")
	if len(ownerProblems) != 0 {
		t.Fatal(ownerProblems)
	}
	if len(ownerTuples) != 27 {
		t.Fatalf("accepted owner inventory is %d branches, expected 27", len(ownerTuples))
	}
	// Baseline: schema, SQL function, Go registry and documentation all agree.
	if problems := checkEncryptedArtifactOwnerParity("..", ownerTuples); len(problems) != 0 {
		t.Fatalf("accepted owner inventory fails parity: %v", problems)
	}

	schemaSet := make(map[string]bool, len(ownerTuples))
	for _, tuple := range ownerTuples {
		schemaSet[tuple] = true
	}
	sample := ownerTuples[0]
	missing := make(map[string]int, len(schemaSet))
	duplicate := make(map[string]int, len(schemaSet))
	extra := make(map[string]int, len(schemaSet)+1)
	for _, tuple := range ownerTuples {
		if tuple != sample {
			missing[tuple] = 1
		}
		duplicate[tuple] = 1
		extra[tuple] = 1
	}
	duplicate[sample] = 2
	extra["('rogue', 'rogue_artifact_id', 'ROGUE', 'ROGUE')"] = 1
	for name, other := range map[string]map[string]int{
		"missing branch":   missing,
		"duplicate branch": duplicate,
		"extra branch":     extra,
	} {
		t.Run(name, func(t *testing.T) {
			if problems := compareOwnerInventory("test", schemaSet, other); len(problems) == 0 {
				t.Fatal("owner-inventory drift was accepted")
			}
		})
	}

	goRaw, err := os.ReadFile(filepath.Join("..", "internal", "platform", "artifactcrypto", "owner_registry.go"))
	if err != nil {
		t.Fatal(err)
	}
	if problems := compareOwnerInventory("go", schemaSet, extractOwnerTuples(encryptedArtifactGoOwnerPattern, string(goRaw))); len(problems) != 0 {
		t.Fatalf("baseline Go registry drift: %v", problems)
	}
	droppedRegistry := strings.Replace(string(goRaw),
		`{field: ExternalIdentitySubject, ownerTable: "external_identity", ownerColumn: "external_subject_artifact_id", resourceType: "EXTERNAL_IDENTITY", aadField: "SUBJECT"},`, "", 1)
	if problems := compareOwnerInventory("go", schemaSet, extractOwnerTuples(encryptedArtifactGoOwnerPattern, droppedRegistry)); len(problems) == 0 {
		t.Fatal("dropped Go registry branch was accepted")
	}

	docsRaw, err := os.ReadFile(filepath.Join("..", "docs", "ENCRYPTION.md"))
	if err != nil {
		t.Fatal(err)
	}
	if problems := compareOwnerInventory("docs", schemaSet, extractOwnerTuples(encryptedArtifactDocOwnerPattern, string(docsRaw))); len(problems) != 0 {
		t.Fatalf("baseline documentation drift: %v", problems)
	}
}

func TestWorkspaceSourceCommandGuardRejectsProofAndAuthorityDrift(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000009_stage2_workspace_source_command_gate.sql"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkWorkspaceSourceCommandMigration(baseline); len(problems) != 0 {
		t.Fatalf("accepted workspace-source migration fails its guard: %v", problems)
	}
	mutations := map[string]string{
		"second receipt": baseline + "\nCREATE TABLE public.workspace_source_receipt (id text);\n",
		"source transition weakened": strings.Replace(baseline,
			"workspace source remove is not enabled-to-disabled transition",
			"workspace source remove accepted without transition", 1),
		"ordinary carry removed": strings.Replace(baseline,
			"ordinary workspace command changed source projection",
			"ordinary workspace command ignored source projection", 1),
		"controller widened": strings.Replace(baseline,
			"member.role IN ('OWNER', 'MANAGER')", "member.role IN ('OWNER', 'MANAGER', 'MEMBER')", 1),
		"self removal fence removed": strings.Replace(baseline,
			"member.valid_to_revision = workspace_revision_source.workspace_revision", "member.valid_to_revision IS NOT NULL", 1),
		"active base removed": strings.Replace(baseline,
			"previous_canonical ->> 'status' <> 'ACTIVE'", "previous_canonical ->> 'status' <> 'DELETED'", 1),
		"mutable pointer proof removed": strings.Replace(baseline,
			"workspace.current_revision = NEW.result_workspace_revision", "workspace.current_revision > 0", 1),
		"transaction clock proof removed": strings.Replace(baseline,
			"workspace.updated_at = NEW.terminal_at", "workspace.updated_at IS NOT NULL", 1),
		"closed prefix weakened": strings.Replace(baseline,
			"ELSE false", "ELSE value IS NOT NULL", 1),
		"legacy check retained": strings.Replace(baseline,
			"DROP CONSTRAINT workspace_source_id_check", "DROP CONSTRAINT workspace_source_id_closed_check", 1),
		"success workspace nullable": strings.Replace(baseline,
			"OR (NEW.outcome = 'SUCCESS' AND NEW.workspace_id IS NULL)", "OR false", 1),
		"runtime update grant":   baseline + "\nGRANT UPDATE ON public.workspace_revision_source TO knowvault_app;\n",
		"confirmation authority": baseline + "\nCREATE TABLE public.workspace_managed_confirmation (id text);\n",
		"job authority":          baseline + "\nCREATE TABLE public.connector_job (id text);\n",
		"activation mutation":    baseline + "\nUPDATE public.source_scope_activation SET status = 'ACTIVE';\n",
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if problems := checkWorkspaceSourceCommandMigration(mutated); len(problems) == 0 {
				t.Fatal("unsafe workspace-source migration mutation was accepted")
			}
		})
	}
}

func TestWorkspaceManagedConfirmationAuthorityGuardRejectsHardeningRegressions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000010_stage2_workspace_managed_confirmation_authority.sql"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkWorkspaceManagedConfirmationAuthorityMigration(baseline); len(problems) != 0 {
		t.Fatalf("accepted workspace-managed confirmation authority migration fails its own guard: %v", problems)
	}

	mutations := map[string]string{
		"missing table": strings.Replace(baseline,
			"CREATE TABLE public.workspace_managed_warning_contract (",
			"CREATE TABLE public.workspace_managed_warning_contract_v2 (", 1),
		"safe integer bound removed": strings.Replace(baseline,
			"CHECK (policy_revision BETWEEN 1 AND 9007199254740991);",
			"CHECK (policy_revision > 0);", 1),
		"current policy guard missing on grant table": strings.Replace(baseline,
			"CREATE TRIGGER workspace_source_confirmation_actor_grant_current_policy_exact\n"+
				"BEFORE INSERT ON public.workspace_source_confirmation_actor_grant\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();\n",
			"", 1),
		"current policy guard missing on grant revocation table": strings.Replace(baseline,
			"CREATE TRIGGER workspace_source_confirmation_actor_grant_revocation_current_policy_exact\n"+
				"BEFORE INSERT ON public.workspace_source_confirmation_actor_grant_revocation\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();\n",
			"", 1),
		"current policy guard missing on confirmation table": strings.Replace(baseline,
			"CREATE TRIGGER workspace_managed_grant_confirmation_current_policy_exact\n"+
				"BEFORE INSERT ON public.workspace_managed_grant_confirmation\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();\n",
			"", 1),
		"current policy guard missing on confirmation revocation table": strings.Replace(baseline,
			"CREATE TRIGGER workspace_managed_grant_revocation_current_policy_exact\n"+
				"BEFORE INSERT ON public.workspace_managed_grant_revocation\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();\n",
			"", 1),
		// This is the exact false-green scenario the per-table check exists to
		// catch: moving the confirmation-revocation table's trigger onto the
		// grant table leaves the grant table with two such triggers and the
		// confirmation-revocation table with none, while the naive total
		// count (still 4) would not have noticed anything wrong.
		"current policy guard moved from confirmation revocation to grant table": strings.Replace(baseline,
			"BEFORE INSERT ON public.workspace_managed_grant_revocation\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();",
			"BEFORE INSERT ON public.workspace_source_confirmation_actor_grant\n"+
				"FOR EACH ROW EXECUTE FUNCTION app.authority_current_policy_guard();", 1),
		"authority ID reverts to source-generated validator": strings.Replace(baseline,
			"grant_id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(grant_id)),",
			"grant_id text NOT NULL CHECK (app.source_generated_id_is_valid(grant_id, 'grant')),", 1),
		"target FK loses configuration hash": strings.Replace(baseline,
			"            organization_id, workspace_id, workspace_revision, workspace_configuration_hash,\n"+
				"            workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode\n"+
				"        )\n"+
				"        REFERENCES public.workspace_revision_source (",
			"            organization_id, workspace_id, workspace_revision,\n"+
				"            workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode\n"+
				"        )\n"+
				"        REFERENCES public.workspace_revision_source (", 1),
		"target unique key loses configuration hash": strings.Replace(baseline,
			"        organization_id, workspace_id, workspace_revision, workspace_configuration_hash,\n"+
				"        workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode\n"+
				"    );",
			"        organization_id, workspace_id, workspace_revision,\n"+
				"        workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode\n"+
				"    );", 1),
		"force RLS removed": strings.Replace(baseline,
			"ALTER TABLE public.workspace_managed_grant_revocation FORCE ROW LEVEL SECURITY;", "", 1),
		"runtime grant widened to INSERT": baseline + "\nGRANT INSERT ON TABLE public.workspace_managed_grant_confirmation TO knowvault_app;\n",
		"runtime grant widened to UPDATE": strings.Replace(baseline,
			"GRANT SELECT ON TABLE public.workspace_managed_grant_revocation TO knowvault_app;",
			"GRANT SELECT, UPDATE ON TABLE public.workspace_managed_grant_revocation TO knowvault_app;", 1),
		"helper EXECUTE granted": baseline + "\nGRANT EXECUTE ON FUNCTION app.authority_current_policy_guard() TO knowvault_app;\n",
		"workspace row lock removed": strings.Replace(baseline,
			"WHERE organization_id = NEW.organization_id AND id = parent_workspace_id\n    FOR UPDATE;",
			"WHERE organization_id = NEW.organization_id AND id = parent_workspace_id;", 1),
		"derived-live validator drops grant revocation relation": strings.Replace(baseline,
			"public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation",
			"public.workspace_source_confirmation_actor_grant AS grant_revocation", 1),
		"derived-live validator drops confirmation revocation relation": strings.Replace(baseline,
			"public.workspace_managed_grant_revocation AS revocation",
			"public.workspace_managed_grant_confirmation AS revocation", 1),
		"warning hash weakened": strings.Replace(baseline,
			"sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d",
			"sha256:0000000000000000000000000000000000000000000000000000000000000000", -1),
		"warning acknowledgement weakened": strings.Replace(baseline,
			"WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
			"WORKSPACE_MEMBERS_ACKNOWLEDGED", -1),
		"mutable status column added to grant table": strings.Replace(baseline,
			"CREATE TABLE public.workspace_source_confirmation_actor_grant (\n    organization_id text NOT NULL",
			"CREATE TABLE public.workspace_source_confirmation_actor_grant (\n    status text,\n    organization_id text NOT NULL", 1),
		"mutable revoked_at column added to confirmation table": strings.Replace(baseline,
			"CREATE TABLE public.workspace_managed_grant_confirmation (\n    organization_id text NOT NULL",
			"CREATE TABLE public.workspace_managed_grant_confirmation (\n    revoked_at text,\n    organization_id text NOT NULL", 1),
		"outbox authority introduced":        baseline + "\nINSERT INTO public.outbox_event (organization_id) VALUES ('x');\n",
		"connector job authority introduced": baseline + "\nCREATE TABLE public.connector_job (id text);\n",
		"confirmation exact guard skips current-warning check": strings.Replace(baseline,
			"    IF NOT EXISTS (\n"+
				"        SELECT 1 FROM public.workspace_managed_warning_contract\n"+
				"        WHERE revision = app.workspace_managed_warning_contract_current_revision()\n"+
				"          AND warning_version = NEW.warning_version\n"+
				"          AND warning_contract_hash = NEW.warning_contract_hash\n"+
				"    ) THEN\n"+
				"        RAISE EXCEPTION 'workspace managed confirmation warning is not the current registry revision'\n"+
				"            USING ERRCODE = '23514';\n"+
				"    END IF;\n\n",
			"", 1),
		"derived-live validator skips current-warning check": strings.Replace(baseline,
			"     AND warning.revision = app.workspace_managed_warning_contract_current_revision()\n",
			"", 1),
		"current-warning helper function removed": strings.Replace(baseline,
			"app.workspace_managed_warning_contract_current_revision()",
			"app.workspace_managed_warning_contract_current_revision_removed()", -1),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if mutated == baseline {
				t.Fatalf("mutation %q did not change the baseline (marker text drifted)", name)
			}
			if problems := checkWorkspaceManagedConfirmationAuthorityMigration(mutated); len(problems) == 0 {
				t.Fatal("unsafe workspace-managed confirmation authority mutation was accepted")
			}
		})
	}
}

func TestWorkspaceSourceRepositoryGuardRejectsPolicyIdentityAndAuthorityDrift(t *testing.T) {
	root := ".."
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
	baseline := make(map[string]string, len(paths))
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		baseline[relative] = string(raw)
	}
	if problems := checkWorkspaceSourceRepositoryContents(baseline); len(problems) != 0 {
		t.Fatalf("accepted workspace source repository fails its guard: %v", problems)
	}
	mutations := map[string]func(map[string]string){
		"v1 source envelope": func(files map[string]string) {
			files["internal/workspace/repository/idempotency.go"] = strings.Replace(files["internal/workspace/repository/idempotency.go"], "workspace-command-v2", "workspace-command-v1", 1)
		},
		"actor scoped lineage": func(files map[string]string) {
			files["internal/workspace/repository/source_commands.go"] = strings.Replace(files["internal/workspace/repository/source_commands.go"], "organizationID + \"\\x00\" + workspaceID + \"\\x00\" + sourceScopeID", "organizationID + \"\\x00\" + actorID + \"\\x00\" + sourceScopeID", 1)
		},
		"unlocked snapshot": func(files map[string]string) {
			files["internal/workspace/repository/source_commands.go"] = strings.Replace(files["internal/workspace/repository/source_commands.go"], "workspaceID, true)", "workspaceID, false)", 1)
		},
		"serialization row lock removed": func(files map[string]string) {
			files["internal/workspace/repository/repository.go"] = strings.Replace(files["internal/workspace/repository/repository.go"], "WHERE organization_id = $1 AND id = $2\n\t\t\tFOR UPDATE", "WHERE organization_id = $1 AND id = $2", 1)
		},
		"post-lock membership removed": func(files map[string]string) {
			files["internal/workspace/repository/repository.go"] = strings.Replace(files["internal/workspace/repository/repository.go"], "principal_id = app.current_principal_id()", "principal_id IS NOT NULL", 1)
		},
		"hidden workspace becomes persistence oracle": func(files map[string]string) {
			needle := "// Do not turn the serialization barrier into an existence oracle.\n\t\t\treturn workspace.Snapshot{}, \"\", nil, false, nil"
			files["internal/workspace/repository/repository.go"] = strings.Replace(files["internal/workspace/repository/repository.go"], needle, "// existence oracle regression\n\t\t\treturn workspace.Snapshot{}, \"\", nil, false, &Error{code: CodePersistence}", 1)
		},
		"generic manage policy": func(files map[string]string) {
			files["internal/workspace/repository/source_commands.go"] = strings.Replace(files["internal/workspace/repository/source_commands.go"], "policy.OperationWorkspaceManageSources", "policy.OperationWorkspaceManage", 1)
		},
		"scope activation write": func(files map[string]string) {
			files["internal/workspace/repository/source_commands.go"] += "\n// INSERT INTO public.source_scope_activation\n"
		},
		"serialization test removed": func(files map[string]string) {
			files["tests/integration/postgres/workspace_source_repository_test.go"] = strings.Replace(files["tests/integration/postgres/workspace_source_repository_test.go"], "TestWorkspaceSourceRepositorySerializesSameAndDifferentIdempotencyKeys", "TestSourceConcurrencyRemoved", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			files := make(map[string]string, len(baseline))
			for path, content := range baseline {
				files[path] = content
			}
			mutate(files)
			if problems := checkWorkspaceSourceRepositoryContents(files); len(problems) == 0 {
				t.Fatal("unsafe workspace source repository mutation was accepted")
			}
		})
	}
}

func TestV2TestOnlyBoundaryRejectsProductionUse(t *testing.T) {
	root := t.TempDir()
	productionDir := filepath.Join(root, "internal", "platform", "dispatchercomposition")
	if err := os.MkdirAll(productionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafe := []byte("package dispatchercomposition\nvar cfg = struct{ TestOnly bool }{TestOnly: true}\n")
	if err := os.WriteFile(filepath.Join(productionDir, "unsafe.go"), unsafe, 0o600); err != nil {
		t.Fatal(err)
	}
	if problems := checkV2TestOnlyBoundary(root); len(problems) == 0 {
		t.Fatal("production TestOnly escape was accepted")
	}
	if err := os.Rename(filepath.Join(productionDir, "unsafe.go"), filepath.Join(productionDir, "unsafe_test.go")); err != nil {
		t.Fatal(err)
	}
	if problems := checkV2TestOnlyBoundary(root); len(problems) != 0 {
		t.Fatalf("test-only use was rejected: %v", problems)
	}
}

func TestDocumentParserEntrypointBoundaryRejectsDirectCLI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(documentParserMain)))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkDocumentParserEntrypointContents(baseline); len(problems) != 0 {
		t.Fatalf("accepted one-shot entrypoint fails its guard: %v", problems)
	}
	mutations := map[string]string{
		"stdin reader":      strings.Replace(baseline, "DispatcherArguments.parse(args)", "System.in.read(); DispatcherArguments.parse(args)", 1),
		"format selector":   strings.Replace(baseline, "case \"mode\"", "case \"format\"", 1),
		"dispatcher bypass": strings.Replace(baseline, "DispatcherArguments.parse(args)", "legacyArguments(args)", 1),
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if mutated == baseline {
				t.Fatal("mutation marker drifted")
			}
			if problems := checkDocumentParserEntrypointContents(mutated); len(problems) == 0 {
				t.Fatal("direct parser CLI mutation was accepted")
			}
		})
	}
}

func TestWorkspaceManagedAuthorityCommandBoundaryGuardRejectsContractDrift(t *testing.T) {
	root := ".."
	adr := "docs/adr/0053-workspace-managed-authority-command-boundary-accepted.md"
	schema := "architecture/contracts/workspace-managed-authority-command.schema.json"
	runner := "tests/contracts/runner/workspace_managed_authority_command.go"
	runnerTest := "tests/contracts/runner/workspace_managed_authority_command_test.go"
	contractTest := "tests/contracts/runner/contract_test.go"
	schemaTests := "tests/contracts/schema-tests.mjs"
	fixtureCases := "tests/contracts/fixture-cases.json"
	canonicalization := "docs/CANONICALIZATION.md"
	dataModel := "docs/DATA_MODEL.md"
	paths := []string{adr, schema, runner, runnerTest, contractTest, schemaTests, fixtureCases, canonicalization, dataModel}
	baseline := make(map[string]string, len(paths))
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		baseline[relative] = string(raw)
	}
	if problems := checkWorkspaceManagedAuthorityCommandBoundaryContents(baseline); len(problems) != 0 {
		t.Fatalf("accepted authority command boundary fails its guard: %v", problems)
	}
	mutations := map[string]func(map[string]string){
		"authority receipt family replaced by workspace command receipt": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr], "workspace_managed_authority_command_receipt", "workspace_command_receipt", -1)
		},
		"data model reuses workspace command receipt": func(files map[string]string) {
			files[dataModel] = strings.Replace(files[dataModel], "workspace_managed_authority_command_receipt", "workspace_command_receipt", -1)
		},
		"org admin confirms directly": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"Organization role alone never authorizes a confirmation",
				"Organization admins confirm directly", 1)
		},
		"workspace owner confirms without actor grant": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"ownership or management without that exact unrevoked actor grant is",
				"ownership suffices and the grant is", 1)
		},
		"connector admin issues grants": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"`CONNECTOR_ADMIN`, `SECURITY_AUDITOR` and ordinary members cannot",
				"`CONNECTOR_ADMIN` may", 1)
		},
		"grant revocation demands current workspace revision in prose": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"Grant revocation does not require a current",
				"Grant revocation requires the current", 1)
		},
		"revoke request gains workspace revision precondition": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"grant_hash": { "$ref": "#/$defs/sha256Hash" },`,
				`"grant_hash": { "$ref": "#/$defs/sha256Hash" },
        "expected_workspace_revision": { "$ref": "#/$defs/revision" },`, 1)
		},
		"client owned grant timestamp in schema": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"target_principal_id": { "$ref": "#/$defs/id" },`,
				`"granted_at": { "$ref": "#/$defs/id" },`, 1)
		},
		"client owned reason code in schema": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"confirmation_hash": { "$ref": "#/$defs/sha256Hash" },`,
				`"confirmation_hash": { "$ref": "#/$defs/sha256Hash" },
        "reason_code": { "$ref": "#/$defs/id" },`, 1)
		},
		"raw idempotency key becomes envelope surface": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"request": { "type": "object" }`,
				`"request": { "type": "object" },
    "idempotency_key": { "type": "string" }`, 1)
		},
		"current policy precondition dropped from issue request": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"ttl_seconds": { "$ref": "#/$defs/ttlSeconds" },
        "expected_policy_revision": { "$ref": "#/$defs/policyRevision" }`,
				`"ttl_seconds": { "$ref": "#/$defs/ttlSeconds" }`, 1)
		},
		"current warning binding dropped from confirm request": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"warning_contract_hash": { "$ref": "#/$defs/sha256Hash" },`,
				"", 1)
		},
		"ttl window widened": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"ttlSeconds": { "type": "integer", "minimum": 60, "maximum": 86400 }`,
				`"ttlSeconds": { "type": "integer", "minimum": 1, "maximum": 86400 }`, 1)
		},
		"fifth authority operation introduced": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				`"WORKSPACE_MANAGED_CONFIRM_REVOKE"
      ]`,
				`"WORKSPACE_MANAGED_CONFIRM_REVOKE",
        "WORKSPACE_CONFIRMATION_GRANT_SUSPEND"
      ]`, 1)
		},
		"canonicalization envelope section removed": func(files map[string]string) {
			files[canonicalization] = strings.Replace(files[canonicalization],
				"### 6.1. Workspace-managed authority command envelope",
				"### 6.1. Removed", 1)
		},
		"non-success audit metadata allowlist opened": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"exactly one key, `authority_operation`, and nothing else",
				"an operation-specific metadata map", 1)
		},
		"determinism test removed": func(files map[string]string) {
			files[runnerTest] = strings.Replace(files[runnerTest],
				"TestWorkspaceManagedAuthorityCommandCanonicalizationDeterminism",
				"TestWorkspaceManagedAuthorityCommandRemoved", 1)
		},
		"request invalid code renamed in runner": func(files map[string]string) {
			files[runner] = strings.Replace(files[runner],
				`"WORKSPACE_AUTHORITY_REQUEST_INVALID"`,
				`"WORKSPACE_REQUEST_INVALID"`, 1)
		},
		"second fixture-inventory source of truth reintroduced": func(files map[string]string) {
			files[runnerTest] = strings.Replace(files[runnerTest],
				"func TestWorkspaceManagedAuthorityCommandGoldenVectors(t *testing.T) {",
				"var workspaceManagedAuthorityValidFixtures = map[string]string{}\n\nfunc TestWorkspaceManagedAuthorityCommandValidFixtures(t *testing.T) {}\n\nfunc TestWorkspaceManagedAuthorityCommandGoldenVectors(t *testing.T) {", 1)
		},
		"field consistently removed from grantIssueRequest properties and required": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema], "        \"target_principal_id\",\n", "", 1)
			files[schema] = strings.Replace(files[schema], "        \"target_principal_id\": { \"$ref\": \"#/$defs/id\" },\n", "", 1)
		},
		"field consistently added to grantIssueRequest properties and required": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				"        \"expected_policy_revision\"\n      ],\n      \"properties\": {",
				"        \"expected_policy_revision\",\n        \"extra_authority_field\"\n      ],\n      \"properties\": {", 1)
			files[schema] = strings.Replace(files[schema],
				"        \"expected_policy_revision\": { \"$ref\": \"#/$defs/policyRevision\" }\n      }\n    },",
				"        \"expected_policy_revision\": { \"$ref\": \"#/$defs/policyRevision\" },\n        \"extra_authority_field\": { \"$ref\": \"#/$defs/id\" }\n      }\n    },", 1)
		},
		"operation reassigned to a different request definition": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				"\"operation\": { \"const\": \"WORKSPACE_CONFIRMATION_GRANT_ISSUE\" },\n        \"request\": { \"$ref\": \"#/$defs/grantIssueRequest\" }",
				"\"operation\": { \"const\": \"WORKSPACE_CONFIRMATION_GRANT_ISSUE\" },\n        \"request\": { \"$ref\": \"#/$defs/grantRevokeRequest\" }", 1)
		},
		"operation branch duplicated in oneOf": func(files map[string]string) {
			files[schema] = strings.Replace(files[schema],
				"\"operation\": { \"const\": \"WORKSPACE_MANAGED_CONFIRM\" },\n        \"request\": { \"$ref\": \"#/$defs/managedConfirmRequest\" }\n      },\n      \"required\": [\"operation\", \"request\"]\n    },",
				"\"operation\": { \"const\": \"WORKSPACE_MANAGED_CONFIRM\" },\n        \"request\": { \"$ref\": \"#/$defs/managedConfirmRequest\" }\n      },\n      \"required\": [\"operation\", \"request\"]\n    },\n    {\n      \"type\": \"object\",\n      \"properties\": {\n        \"operation\": { \"const\": \"WORKSPACE_MANAGED_CONFIRM\" },\n        \"request\": { \"$ref\": \"#/$defs/managedConfirmRequest\" }\n      },\n      \"required\": [\"operation\", \"request\"]\n    },", 1)
		},
		// The marker deliberately stops at the closing quote: a later contract
		// appended to schemaPaths turns this entry's line terminator from "\n" into
		// ",\n", and a marker that spelled the terminator would silently stop
		// mutating (the failure this test itself reports as "marker text drifted").
		"authority schema removed from AJV schemaPaths": func(files map[string]string) {
			files[schemaTests] = strings.Replace(files[schemaTests],
				"  \"workspace-managed-authority-command\": \"architecture/contracts/workspace-managed-authority-command.schema.json\"",
				"", 1)
		},
		"one authority case removed from registry": func(files map[string]string) {
			files[fixtureCases] = strings.Replace(files[fixtureCases],
				"      \"id\": \"workspace.authority.confirm-revoke.valid\",\n"+
					"      \"kind\": \"SCHEMA_INSTANCE\",\n"+
					"      \"contract\": \"workspace-managed-authority-command\",\n"+
					"      \"fixture\": \"fixtures/valid/workspace-managed-authority-command-confirm-revoke.json\",\n"+
					"      \"context\": \"\",\n"+
					"      \"validator\": \"workspace-managed-authority-command\",\n"+
					"      \"mutation\": \"NONE\",\n"+
					"      \"schema_mutation\": \"\",\n"+
					"      \"expected_schema_valid\": true,\n"+
					"      \"expected_error_code\": null\n"+
					"    },\n", "", 1)
		},
		"audit status mapping weakened for NOT_FOUND": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"`NOT_FOUND` maps to audit outcome `DENIED`",
				"`NOT_FOUND` maps to audit outcome `SUCCESS`", 1)
		},
		"command_id dropped from receipt contract": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"reserves a `command_id` at receipt",
				"reserves nothing at receipt", 1)
		},
		"created grant or confirmation ID used as failure audit resource": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"Grant, confirmation and revocation IDs never serve as the audit resource ID",
				"Grant, confirmation and revocation IDs serve as the audit resource ID on failure", 1)
		},
		"self-revoke requires current membership": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"self-revoke visibility never requires current",
				"self-revoke visibility always requires current", 1)
		},
		"replay re-requires live grant and current warning": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"it does not re-require that\nthe historical actor grant remain live or that policy or warning still match",
				"it re-requires that\nthe historical actor grant remain live or that policy or warning still match", 1)
		},
		// Hardening P1 #1: trusted tenant binding.
		"tenant exact-match assertion removed": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"the server exact-matches request `organization_id`",
				"the server accepts request `organization_id`", 1)
		},
		"request organization allowed to select tenant": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"never from the request body, on either",
				"or from the request body, on either", 1)
		},
		"tenant mismatch workspace_id null rule dropped": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"is null, matching the existing `NOT_FOUND` rule rather than a special case",
				"is populated for audit completeness", 1)
		},
		"policy and warning silently dropped from the mismatch lookup fence": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"before any workspace, target principal, grant, confirmation, binding, policy\nor warning lookup runs.",
				"before any workspace, target principal, grant, confirmation, binding\nlookup runs.", 1)
		},
		// Hardening P1 #2: branch split after all business preconditions.
		"tenant fence relocated after business preconditions": func(files map[string]string) {
			// Moves the exact tenant-fence anchor text later in the file
			// without deleting it, so plain fragment presence still passes
			// and only the index-based ordering check can catch the reorder.
			marker := "the trusted tenant fence defined above; opening"
			files[adr] = strings.Replace(files[adr], marker, "an internal validation step and", 1)
			files[adr] = strings.Replace(files[adr],
				"does the transaction settle on exactly one terminal",
				marker+" does the transaction settle on exactly one terminal", 1)
		},
		"terminal decision settled only after branch entry": func(files map[string]string) {
			// Same relocation technique: the exact anchor text survives, just
			// moved past the branch-entry anchor, so only the ordering check
			// (not fragment presence) can flag it.
			marker := "does the transaction settle on exactly one terminal"
			files[adr] = strings.Replace(files[adr], marker, "reaches an intermediate step", 1)
			files[adr] = strings.Replace(files[adr],
				"The business-failure branch is entered only once the decision phase has",
				"The business-failure branch is entered only once the decision phase has, and only then "+marker+",", 1)
		},
		"success branch reload of policy and warning reintroduced": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"Once entered, the success branch performs only:",
				"Once entered, the success branch reloads the current policy, the current warning contract and the exact parents and binding, then performs only:", 1)
		},
		"success branch allowed to discover precondition failure first": func(files map[string]string) {
			files[adr] = strings.Replace(files[adr],
				"it can never be the branch that first discovers an ordinary",
				"it may be the branch that first discovers an ordinary", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			files := make(map[string]string, len(baseline))
			for path, content := range baseline {
				files[path] = content
			}
			mutate(files)
			changed := false
			for path := range files {
				if files[path] != baseline[path] {
					changed = true
				}
			}
			if !changed {
				t.Fatalf("mutation %q did not change the baseline (marker text drifted)", name)
			}
			if problems := checkWorkspaceManagedAuthorityCommandBoundaryContents(files); len(problems) == 0 {
				t.Fatal("unsafe authority command boundary mutation was accepted")
			}
		})
	}
}

// TestWorkspaceManagedAuthorityCommandRuntimeGateAcceptsRepository pins the
// positive gate that replaced the ADR-0053 runtime deferral: migration 000011
// now exists, so the boundary is proved by presence rather than by absence.
func TestWorkspaceManagedAuthorityCommandRuntimeGateAcceptsRepository(t *testing.T) {
	if problems := checkWorkspaceManagedAuthorityCommandRuntime(".."); len(problems) != 0 {
		t.Fatalf("accepted repository fails the authority runtime gate: %v", problems)
	}
}

// writeAuthorityTokenFile writes a Go file under root that carries one of the
// ADR-0053 workspace-managed authority command tokens, so a synthetic tree can
// prove the token-scan boundary without needing the migrations, repository
// runtime or bootstrap that checkWorkspaceManagedAuthorityCommandRuntime reads.
func writeAuthorityTokenFile(t *testing.T, root, relative, token string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "package surface\n\nconst v = \"" + token + "\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWorkspaceManagedAuthorityCommandTokenBoundaryPerADR0087 proves the
// ADR-0087 §1 amendment of the ADR-0053 runtime boundary: every authority
// command token is permitted inside internal/platform/workspaceapi (the REST/
// MCP composition surface named by ADR-0087), while the same token anywhere else
// under internal, cmd, api, web or deploy — for example cmd/ or internal/source/
// — still reds the scan.
func TestWorkspaceManagedAuthorityCommandTokenBoundaryPerADR0087(t *testing.T) {
	tokens := []string{
		"WORKSPACE_CONFIRMATION_GRANT_ISSUE", "WORKSPACE_CONFIRMATION_GRANT_REVOKE",
		"WORKSPACE_MANAGED_CONFIRM", "WORKSPACE_AUTHORITY_",
		"workspace_managed_authority_command_receipt",
	}
	for _, token := range tokens {
		token := token
		t.Run("workspaceapi permits "+token, func(t *testing.T) {
			root := t.TempDir()
			writeAuthorityTokenFile(t, root, "internal/platform/workspaceapi/compose.go", token)
			if problems := checkWorkspaceManagedAuthorityCommandTokenSurface(root); len(problems) != 0 {
				t.Fatalf("token %q inside internal/platform/workspaceapi was rejected: %v", token, problems)
			}
		})
		t.Run("non-workspaceapi rejects "+token, func(t *testing.T) {
			for _, relative := range []string{"cmd/cli/surface.go", "internal/source/compose.go"} {
				root := t.TempDir()
				writeAuthorityTokenFile(t, root, relative, token)
				if problems := checkWorkspaceManagedAuthorityCommandTokenSurface(root); len(problems) == 0 {
					t.Fatalf("token %q in %s was accepted", token, relative)
				}
			}
		})
	}
}

// TestWorkspaceManagedAuthorityCommandTokenSurfaceAcceptance keeps the positive
// gate load-bearing on the real tree: the repository runtime must still appear
// in internal/workspace/repository and the tree as a whole must stay green once
// the ADR-0087 §1 workspaceapi exemption is in force. Removing the workspaceapi
// exemption would red this run because the composition surface files carry no
// tokens yet, so the boundary is proved by the synthetic-tree tests above plus
// this acceptance run.
func TestWorkspaceManagedAuthorityCommandTokenSurfaceAcceptance(t *testing.T) {
	if problems := checkWorkspaceManagedAuthorityCommandTokenSurface(".."); len(problems) != 0 {
		t.Fatalf("accepted tree fails the authority command token surface: %v", problems)
	}
}

// TestWorkspaceManagedAuthorityCommandRepositoryMutationsAreRejected proves the
// positive gate is load-bearing: removing any anchor of the checkpoint-0055
// runtime, or reusing the workspace command receipt family, must red the
// checker. Without this, the token-scan exemption for the authority_*.go files
// would let the whole runtime be deleted or hollowed out unnoticed.
func TestWorkspaceManagedAuthorityCommandRepositoryMutationsAreRejected(t *testing.T) {
	base := filepath.Join("..", "internal", "workspace", "repository")
	names := []string{
		"authority_command.go", "authority_commands.go", "authority_result.go",
		"authority_receipt.go", "authority_policy.go", "authority_facts.go",
	}
	baseline := map[string]string{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			t.Fatal(err)
		}
		baseline[name] = string(raw)
	}
	if problems := checkWorkspaceManagedAuthorityCommandRepositoryContent(baseline); len(problems) != 0 {
		t.Fatalf("accepted authority runtime fails its own gate: %v", problems)
	}

	removals := map[string][]string{
		"authority_command.go": {
			"WORKSPACE_CONFIRMATION_GRANT_ISSUE",
			"WORKSPACE_MANAGED_CONFIRM_REVOKE",
			"workspace-managed-authority-command-v1",
			"WORKSPACE_AUTHORITY_PRECONDITION_FAILED",
			"jsontext.Value",
		},
		"authority_commands.go": {
			"func (store *Store) ConfirmManagedSource",
			"func (store *Store) RevokeManagedConfirmation",
			"func (store *Store) lockThenReload",
			"func (store *Store) terminateTenantMismatch",
			"isAuthorityConflict(reserveErr)",
		},
		"authority_result.go": {
			"workspace-managed-confirmation-v1",
			"workspace-source-confirmation-grant-revocation-v1",
		},
		"authority_receipt.go": {
			"workspace_managed_authority_command_receipt",
			"ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING",
		},
		"authority_policy.go": {
			"business confirmBusiness",
			"liveConfirmationExists",
			"issueReplayTerminal",
			"grantRevokeReplayTerminal",
			"!revocableWorkspaceStatus(ws.status)",
		},
		"authority_facts.go": {
			"func confirmLiveConfirmationExists",
			"func lockWorkspaceVisibility",
			"func loadWorkspaceRevisionConfig",
			`query += " FOR UPDATE"`,
			"func loadParentGrantIdentity",
		},
	}
	for name, anchors := range removals {
		for _, anchor := range anchors {
			mutated := cloneAuthorityRuntimeFiles(baseline)
			replaced := strings.ReplaceAll(mutated[name], anchor, "")
			if replaced == mutated[name] {
				t.Fatalf("anchor not present to mutate: %q in %s", anchor, name)
			}
			mutated[name] = replaced
			if problems := checkWorkspaceManagedAuthorityCommandRepositoryContent(mutated); len(problems) == 0 {
				t.Fatalf("removing %q from %s did not red the authority runtime gate", anchor, name)
			}
		}
	}

	// Reusing the workspace command receipt family must red the gate.
	mutated := cloneAuthorityRuntimeFiles(baseline)
	mutated["authority_receipt.go"] += "\nvar _ = `INSERT INTO public.workspace_command_receipt (organization_id) VALUES ($1)`\n"
	if problems := checkWorkspaceManagedAuthorityCommandRepositoryContent(mutated); len(problems) == 0 {
		t.Fatal("reusing the workspace command receipt family did not red the authority runtime gate")
	}

	// Reversing the workspace lock and the actor reload must red the gate: the
	// two FOR-UPDATE locking calls in lockThenReload are swapped, so the workspace
	// lock now follows the actor reload.
	reversed := cloneAuthorityRuntimeFiles(baseline)
	commands := reversed["authority_commands.go"]
	lockCall := "lockWorkspaceVisibility(ctx, transaction, access.OrganizationID, workspaceID, access.PrincipalID, true)"
	actorCall := "store.authorityCurrentActor(ctx, transaction, access, true)"
	commands = strings.Replace(commands, lockCall, "__authority_swap__", 1)
	commands = strings.Replace(commands, actorCall, lockCall, 1)
	commands = strings.Replace(commands, "__authority_swap__", actorCall, 1)
	if commands == reversed["authority_commands.go"] {
		t.Fatal("could not construct the reversed-lock-order mutation")
	}
	reversed["authority_commands.go"] = commands
	if problems := checkWorkspaceManagedAuthorityCommandRepositoryContent(reversed); len(problems) == 0 {
		t.Fatal("reversing the workspace lock and actor reload did not red the authority runtime gate")
	}
}

func cloneAuthorityRuntimeFiles(files map[string]string) map[string]string {
	clone := make(map[string]string, len(files))
	for name, content := range files {
		clone[name] = content
	}
	return clone
}

// TestWorkspaceManagedAuthorityCommandMigrationMutationsAreRejected proves each
// control of migration 000011 is load-bearing. Every mutation deletes exactly
// one anchor from the real migration, or introduces exactly one forbidden
// construct, and must red the checker: a weakened boundary is a build failure,
// not a review debate.
func TestWorkspaceManagedAuthorityCommandMigrationMutationsAreRejected(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "db", "migrations", "000011_stage2_workspace_managed_authority_command.sql"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkWorkspaceManagedAuthorityCommandMigrationContent(baseline); len(problems) != 0 {
		t.Fatalf("accepted migration 000011 fails its own gate: %v", problems)
	}

	// Deleting any one of these must red the checker.
	removals := []string{
		"refusing to declare them trusted or backfill receipts",
		"CREATE TABLE public.workspace_managed_authority_command_receipt",
		"'WORKSPACE_MANAGED_CONFIRM_REVOKE'",
		"workspace_managed_authority_command_receipt_projection_exact",
		"workspace_managed_authority_command_receipt_requires_terminal",
		"terminal workspace managed authority receipt is immutable",
		"workspace_managed_authority_command_receipt_no_delete",
		"workspace_source_confirmation_actor_grant_receipt_gate",
		"actor_grant_revocation_receipt_gate",
		"workspace_managed_grant_confirmation_receipt_gate",
		"workspace_managed_grant_revocation_receipt_gate",
		"workspace_managed_authority_command_receipt_result_binding",
		"workspace_managed_authority_receipt_audit_binding",
		"audit_event_authority_is_claimed",
		"EXECUTE FUNCTION app.authority_current_policy_deferred_guard()",
		"EXECUTE FUNCTION app.workspace_managed_confirmation_warning_at_commit()",
		"LOCK TABLE public.workspace_managed_warning_contract IN SHARE MODE;",
		"current_setting('transaction_isolation') <> 'read committed'",
		"ALTER TABLE public.workspace_managed_authority_command_receipt FORCE ROW LEVEL SECURITY",
		"workspace-managed authority audit vocabulary is reserved",
		"WHERE id = NEW.organization_id\n    FOR SHARE",
		// P0: a SUCCESS audit event must project the row actually persisted,
		// not merely a well-formed key set.
		"PERFORM app.authority_audit_metadata_matches_row(",
		"authority audit metadata operation does not match its receipt",
		"grant issue audit metadata does not match the created grant",
		"grant revoke audit metadata does not match the created revocation",
		"confirm audit metadata does not match the created confirmation",
		"confirm revoke audit metadata does not match the created revocation",
		// The SECURITY DEFINER gates are only sound while the owner bypasses RLS.
		"is neither SUPERUSER nor BYPASSRLS",
		// The optimistic grant-issue precondition.
		"actor grant expected workspace revision or configuration hash is not current",
		"status IN ('PENDING', 'NOT_FOUND')\n        OR request_organization_id = organization_id",
	}
	// Removing every occurrence of an anchor can only ever red a presence
	// check, so on its own that loop proves the anchor list is not stale rather
	// than that each control is load-bearing. These mutations are the ones that
	// carry the claim: each deletes exactly ONE site of a control the migration
	// applies four times — the drift a careless edit actually produces — and a
	// checker that only tested presence would stay green on every one of them.
	singleSiteDrifts := []string{
		"receipt := app.workspace_managed_authority_fresh_receipt(",
		"CHECK (app.authority_canonical_hash_matches(canonical_bytes, ",
		"<> app.authority_transaction_epoch()",
		"EXECUTE FUNCTION app.authority_current_policy_deferred_guard()",
	}
	// Drifts that rewrite a control in place rather than deleting it. Each is
	// the shape a careless edit actually takes — widening an existing GRANT
	// rather than adding a new line, or neutering a condition while leaving its
	// error message behind — and each would survive a checker that anchored the
	// message or banned only the standalone form.
	inPlaceDrifts := map[string]string{
		"grant widened in place to UPDATE": strings.Replace(baseline,
			"GRANT INSERT ON TABLE public.workspace_managed_grant_confirmation TO knowvault_app;",
			"GRANT INSERT, UPDATE ON TABLE public.workspace_managed_grant_confirmation TO knowvault_app;", 1),
		"grant widened in place to DELETE": strings.Replace(baseline,
			"GRANT INSERT ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;",
			"GRANT INSERT, DELETE ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;", 1),
		"isolation assertion neutered, message kept": strings.Replace(baseline,
			"current_setting('transaction_isolation') <> 'read committed'", "false", 1),
		"P0 metadata binding call removed": strings.Replace(baseline,
			"PERFORM app.authority_audit_metadata_matches_row(", "PERFORM app.authority_noop(", 1),
		"request tenant equality dropped": strings.Replace(baseline,
			"status IN ('PENDING', 'NOT_FOUND')\n        OR request_organization_id = organization_id",
			"status IS NOT NULL", 1),
		"receipt request hash check dropped": strings.Replace(baseline,
			"CHECK (app.authority_canonical_hash_matches(canonical_request_bytes, ",
			"CHECK (app.authority_noop(canonical_request_bytes, ", 1),
	}
	for name, mutated := range inPlaceDrifts {
		t.Run(name, func(t *testing.T) {
			if mutated == baseline {
				t.Fatal("the mutation changed nothing (marker drifted)")
			}
			if problems := checkWorkspaceManagedAuthorityCommandMigrationContent(mutated); len(problems) == 0 {
				t.Fatal("an in-place weakening left the checker green")
			}
		})
	}

	for _, anchor := range singleSiteDrifts {
		t.Run("dropped one site of "+anchor, func(t *testing.T) {
			if strings.Count(baseline, anchor) < 2 {
				t.Fatalf("anchor %q is no longer applied at several sites (marker drifted)", anchor)
			}
			mutated := strings.Replace(baseline, anchor, "", 1)
			if problems := checkWorkspaceManagedAuthorityCommandMigrationContent(mutated); len(problems) == 0 {
				t.Fatalf("dropping one site of %q left the checker green", anchor)
			}
		})
	}

	for _, anchor := range removals {
		t.Run("removed "+anchor, func(t *testing.T) {
			mutated := strings.ReplaceAll(baseline, anchor, "")
			if mutated == baseline {
				t.Fatalf("mutation anchor %q is absent from the migration (marker drifted)", anchor)
			}
			if problems := checkWorkspaceManagedAuthorityCommandMigrationContent(mutated); len(problems) == 0 {
				t.Fatal("migration 000011 with a removed control was accepted")
			}
		})
	}

	// Introducing any one of these must red the checker.
	additions := map[string]string{
		"extends the old workspace receipt family": "ALTER TABLE public.workspace_command_receipt ADD COLUMN authority_operation text;",
		"grants UPDATE on an authority relation":   "GRANT UPDATE ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;",
		"grants DELETE on an authority relation":   "GRANT DELETE ON TABLE public.workspace_source_confirmation_actor_grant TO knowvault_app;",
		"grants a privilege to PUBLIC":             "GRANT EXECUTE ON FUNCTION app.authority_canonical_object(bytea) TO PUBLIC;",
	}
	for name, statement := range additions {
		t.Run("added "+name, func(t *testing.T) {
			if problems := checkWorkspaceManagedAuthorityCommandMigrationContent(baseline + "\n" + statement + "\n"); len(problems) == 0 {
				t.Fatalf("migration 000011 that %s was accepted", name)
			}
		})
	}
}

// TestWorkspaceManagedAuthorityCommandSurfacesStayDeferred proves the four
// operations and the WORKSPACE_AUTHORITY_ error namespace still may not appear
// in the surfaces this checkpoint defers. internal/audit is exempt because the
// audit contract is part of this checkpoint.
func TestWorkspaceManagedAuthorityCommandSurfacesStayDeferred(t *testing.T) {
	scenarios := map[string]struct {
		relative string
		content  string
	}{
		// The token-scan exemption is scoped to the authority_*.go runtime files
		// only: the same token in any other file of the repository package still
		// reds the scan, so the runtime cannot be smuggled into an unexempt file.
		"authority token in a non-authority repository file": {
			relative: "internal/workspace/repository/source_commands.go",
			content:  "package repository\n\nconst leaked = \"WORKSPACE_MANAGED_CONFIRM_REVOKE\"\n",
		},
		"authority error namespace in API surface": {
			relative: "api/openapi_authority.yaml",
			content:  "code: WORKSPACE_AUTHORITY_DENIED\n",
		},
		"authority receipt in composition": {
			relative: "cmd/server/authority.go",
			content:  "package main\n\nconst receipt = \"workspace_managed_authority_command_receipt\"\n",
		},
		"authority operation in deployment surface": {
			relative: "deploy/compose/authority.yaml",
			content:  "operation: WORKSPACE_CONFIRMATION_GRANT_ISSUE\n",
		},
	}
	for name, scenario := range scenarios {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(scenario.relative))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(scenario.content), 0o644); err != nil {
				t.Fatal(err)
			}
			var leaked bool
			for _, problem := range checkWorkspaceManagedAuthorityCommandRuntime(root) {
				if strings.Contains(problem, "surface is deferred") &&
					strings.Contains(problem, filepath.Base(scenario.relative)) {
					leaked = true
				}
			}
			if !leaked {
				t.Fatal("a deferred authority surface token was accepted")
			}
		})
	}
}

// TestWorkspaceManagedAuthorityCommandGateRequiresBootstrapAndOneMigration
// proves the gate notices a migration that no integration test ever applies,
// and a migration 000012 that this checkpoint does not own.
func TestWorkspaceManagedAuthorityCommandGateRequiresBootstrapAndOneMigration(t *testing.T) {
	t.Run("migration missing from the integration bootstrap", func(t *testing.T) {
		root := t.TempDir()
		writeAuthorityGateFixture(t, root)
		if err := os.WriteFile(filepath.Join(root, "tests", "integration", "postgres", "rls_test.go"),
			[]byte("package postgres_test\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !containsProblemFragment(checkWorkspaceManagedAuthorityCommandRuntime(root),
			"missing from the integration migration bootstrap") {
			t.Fatal("a migration 000011 outside the integration bootstrap was accepted")
		}
	})

	t.Run("migration 000012 is not owned by this checkpoint", func(t *testing.T) {
		root := t.TempDir()
		writeAuthorityGateFixture(t, root)
		if err := os.WriteFile(filepath.Join(root, "db", "migrations", "000012_stage2_next.sql"),
			[]byte("BEGIN;\nCOMMIT;\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if !containsProblemFragment(checkWorkspaceManagedAuthorityCommandRuntime(root), "does not own migration 000012") {
			t.Fatal("a premature migration 000012 was accepted")
		}
	})
}

// writeAuthorityGateFixture copies the real migration and bootstrap into a
// temporary root so a single deliberate mutation is the only difference.
func writeAuthorityGateFixture(t *testing.T, root string) {
	t.Helper()
	for _, relative := range []string{
		"db/migrations/000011_stage2_workspace_managed_authority_command.sql",
		"tests/integration/postgres/rls_test.go",
	} {
		raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// containsProblemFragment is a substring match, unlike the exact-equality
// containsProblem in the checker itself.
func containsProblemFragment(problems []string, fragment string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, fragment) {
			return true
		}
	}
	return false
}

func TestFolderConnectorBoundaryGuardRejectsCapabilityAndContainmentRegressions(t *testing.T) {
	const folderRel = "internal/connector/folder/folder.go"
	load := func() map[string]string {
		contents := map[string]string{}
		for _, rel := range []string{
			folderRel,
			"internal/connector/folder/folder_test.go",
			"tests/integration/postgres/folder_connector_test.go",
			"docs/adr/0057-safe-folder-connector-accepted.md",
		} {
			raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			contents[rel] = string(raw)
		}
		return contents
	}
	if problems := checkFolderConnectorBoundaryContents(load()); len(problems) != 0 {
		t.Fatalf("accepted folder connector fails its own guard: %v", problems)
	}

	mutations := map[string]func(string) string{
		"database capability import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`+"\n\t\"knowvault.local/verified-workspace/internal/platform/database\"", 1)
		},
		"jobs capability import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`+"\n\t\"knowvault.local/verified-workspace/internal/jobs\"", 1)
		},
		"stdlib logging import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`,
				`"knowvault.local/verified-workspace/internal/source/scopeglob"`+"\n\t\"log\"", 1)
		},
		"root handle removed":  func(source string) string { return strings.ReplaceAll(source, "os.OpenRoot(", "openRootDisabled(") },
		"stable read removed":  func(source string) string { return strings.ReplaceAll(source, "os.SameFile(before, after)", "true") },
		"symlink refusal gone": func(source string) string { return strings.ReplaceAll(source, "os.ModeSymlink", "os.ModeType&0") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			contents := load()
			contents[folderRel] = mutate(contents[folderRel])
			if contents[folderRel] == load()[folderRel] {
				t.Fatalf("mutation %q did not change the source (marker drifted)", name)
			}
			if problems := checkFolderConnectorBoundaryContents(contents); len(problems) == 0 {
				t.Fatalf("unsafe folder connector mutation %q was accepted", name)
			}
		})
	}
}

// TestHTMLParserBoundaryGuardRejectsCapabilityAndActiveContentRegressions is the
// executable mutation proof behind the html-active-content-drop / html-resource-bound
// / html-capability-import checker-native invariants: a regression that would let
// the extractor keep active content, drop a resource bound, or gain a network/
// filesystem/logging capability is rejected by its own guard.
func TestHTMLParserBoundaryGuardRejectsCapabilityAndActiveContentRegressions(t *testing.T) {
	const htmlRel = "internal/source/html/html.go"
	load := func() map[string]string {
		contents := map[string]string{}
		for _, rel := range []string{
			htmlRel,
			"internal/source/html/html_test.go",
			"tests/integration/postgres/catalog_evidence_html_test.go",
			"docs/adr/0060-text-structured-format-extraction-accepted.md",
		} {
			raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			contents[rel] = string(raw)
		}
		return contents
	}
	if problems := checkHTMLParserBoundaryContents(load()); len(problems) != 0 {
		t.Fatalf("accepted html parser fails its own guard: %v", problems)
	}

	mutations := map[string]func(string) string{
		// html-capability-import: a network capability.
		"network capability import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/canon"`,
				`"knowvault.local/verified-workspace/internal/source/canon"`+"\n\t\"net/http\"", 1)
		},
		// html-capability-import: a filesystem capability.
		"filesystem capability import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/canon"`,
				`"knowvault.local/verified-workspace/internal/source/canon"`+"\n\t\"os\"", 1)
		},
		// html-capability-import: logging that could exfiltrate source markup.
		"logging capability import": func(source string) string {
			return strings.Replace(source,
				`"knowvault.local/verified-workspace/internal/source/canon"`,
				`"knowvault.local/verified-workspace/internal/source/canon"`+"\n\t\"log\"", 1)
		},
		// html-active-content-drop: active content no longer dropped.
		"active-content drop removed": func(source string) string {
			return strings.ReplaceAll(source, "isDropped(", "keepEverything(")
		},
		// html-active-content-drop: hidden-subtree policy removed.
		"hidden-attr drop removed": func(source string) string {
			return strings.ReplaceAll(source, "hasHiddenAttr(", "neverHidden(")
		},
		// html-resource-bound: node/depth limit removed.
		"node/depth bound removed": func(source string) string {
			return strings.ReplaceAll(source, "e.nodes > e.limits.MaxNodes", "false")
		},
		// html-resource-bound: output bound removed.
		"output bound removed": func(source string) string {
			return strings.ReplaceAll(source, "e.outBytes > e.limits.MaxOutputBytes", "false")
		},
		// pure/UTF-8 gate removed.
		"utf-8 gate removed": func(source string) string {
			return strings.ReplaceAll(source, "utf8.Valid(raw)", "true")
		},
		// no-fallback quarantine removed.
		"text-free quarantine removed": func(source string) string {
			return strings.ReplaceAll(source, "len(e.lines) == 0", "false")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			contents := load()
			contents[htmlRel] = mutate(contents[htmlRel])
			if contents[htmlRel] == load()[htmlRel] {
				t.Fatalf("mutation %q did not change the source (marker drifted)", name)
			}
			if problems := checkHTMLParserBoundaryContents(contents); len(problems) == 0 {
				t.Fatalf("unsafe html parser mutation %q was accepted", name)
			}
		})
	}
}

// TestParserSandboxGuardRejectsHardeningAndCapabilityRegressions is the executable
// mutation proof behind the architecture.parser.sandbox-core-hardening
// checker-native invariant. The property it defends is that the hardening lives in
// exactly one place: a regression that lets the sandbox inherit an environment, lose
// its wall clock or its stream bounds, serve a parser it was not pinned for, or a
// façade that reaches around the core to spawn a process itself, is rejected.
func TestParserSandboxGuardRejectsHardeningAndCapabilityRegressions(t *testing.T) {
	const coreRel = parserSandboxCore + "/sandbox.go"
	const facadeRel = "internal/source/docworker/docworker.go"
	load := func() map[string]string {
		contents := map[string]string{}
		for _, rel := range []string{coreRel, facadeRel} {
			raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			contents[rel] = string(raw)
		}
		return contents
	}
	if problems := checkParserSandboxBoundaryContents(load()); len(problems) != 0 {
		t.Fatalf("accepted parser sandbox fails its own guard: %v", problems)
	}

	mutations := map[string]struct {
		path   string
		mutate func(string) string
	}{
		"environment inherited": {coreRel, func(s string) string {
			return strings.Replace(s, "command.Env = []string{}", "command.Env = os.Environ()", 1)
		}},
		"wall clock dropped": {coreRel, func(s string) string {
			return strings.Replace(s, "context.WithTimeout", "context.WithCancel", 1)
		}},
		"stream bounds dropped": {coreRel, func(s string) string {
			return strings.ReplaceAll(s, "&boundedWriter{limit:", "&plainWriter{cap:")
		}},
		"kill delay dropped": {coreRel, func(s string) string {
			return strings.Replace(s, "command.WaitDelay", "command.ignoredDelay", 1)
		}},
		"kind gate dropped": {coreRel, func(s string) string {
			return strings.Replace(s, "kind != r.config.Kind", "false", 1)
		}},
		"core gains a database capability": {coreRel, func(s string) string {
			return strings.Replace(s, `"os/exec"`, `"os/exec"`+"\n\t\"knowvault.local/verified-workspace/internal/platform/database\"", 1)
		}},
		"façade spawns its own process": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, `"os/exec"`+"\n\t\"strconv\"", 1)
		}},
		"façade gains a database capability": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, "\"strconv\"\n\t\"knowvault.local/verified-workspace/internal/platform/database\"", 1)
		}},
		"façade gains an audit capability": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, "\"strconv\"\n\t\"knowvault.local/verified-workspace/internal/audit\"", 1)
		}},
		"façade gains a network capability": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, "\"strconv\"\n\t\"net/http\"", 1)
		}},
		"façade gains a filesystem capability": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, "\"strconv\"\n\t\"os\"", 1)
		}},
		"façade reaches another parser's re-validator": {facadeRel, func(s string) string {
			return strings.Replace(s, `"strconv"`, "\"strconv\"\n\t\"knowvault.local/verified-workspace/internal/source/ocrparser\"", 1)
		}},
		"façade leaves the shared core": {facadeRel, func(s string) string {
			return strings.Replace(s, "sandbox.New(", "localSandboxNew(", 1)
		}},
		"pinned identity recheck dropped": {facadeRel, func(s string) string {
			return strings.ReplaceAll(s, "ArtifactHash()", "artifactHashIgnored")
		}},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			contents := load()
			original := contents[mutation.path]
			contents[mutation.path] = mutation.mutate(original)
			if contents[mutation.path] == original {
				t.Fatalf("mutation %q did not change the source (marker drifted)", name)
			}
			if problems := checkParserSandboxBoundaryContents(contents); len(problems) == 0 {
				t.Fatalf("unsafe parser sandbox mutation %q was accepted", name)
			}
		})
	}
}

// TestSandboxDispatcherGuardRejectsCapabilityAndProtocolRegressions is the
// executable mutation proof behind the sandbox dispatcher boundary (ADR-0068
// R-7..R-11, SAN-001..SAN-004): the dispatcher never spawns a process, never
// touches a container runtime, verifies the payload digest before handoff, binds
// one socket per parser type, quarantines every failure after the transfer and
// confirms limits only from the kernel cgroup observation.
func TestSandboxDispatcherGuardRejectsCapabilityAndProtocolRegressions(t *testing.T) {
	const (
		dispatchRel      = "internal/sandboxdispatch/dispatch.go"
		wireRel          = "internal/sandboxdispatch/wire.go"
		leaseRel         = "internal/sandboxdispatch/lease.go"
		limitsRel        = "internal/sandboxdispatch/limits.go"
		observerLinuxRel = "internal/sandboxdispatch/observer_linux.go"
		runtimeRel       = "internal/platform/dispatchercomposition/runtime.go"
		dispatcherCmd    = "cmd/sandbox-dispatcher/main.go"
	)
	load := func() map[string]string {
		contents, loadProblems := loadGoPackageSources("..", sandboxDispatcherTrees)
		if len(loadProblems) != 0 {
			t.Fatalf("load sandbox dispatcher sources: %v", loadProblems)
		}
		return contents
	}
	if problems := checkSandboxDispatcherBoundaryContents(load()); len(problems) != 0 {
		t.Fatalf("accepted sandbox dispatcher fails its own guard: %v", problems)
	}

	mutations := map[string]struct {
		path   string
		mutate func(string) string
	}{
		"core gains a spawn capability": {dispatchRel, func(s string) string {
			return strings.Replace(s, `"context"`, `"context"`+"\n\t\"os/exec\"", 1)
		}},
		"core gains a container runtime token": {dispatchRel, func(s string) string {
			return strings.Replace(s, "never spawns a process", "never spawns a process with docker", 1)
		}},
		"supervisor kills without the deadline firing": {dispatchRel, func(s string) string {
			return strings.Replace(s, "active.obs.PID > 0 && (deadlineFired || active.transferSent)", "active.obs.PID > 0", 1)
		}},
		"supervisor kill loses its observation": {dispatchRel, func(s string) string {
			return strings.Replace(s, "d.cfg.Killer.Kill(active.obs)", "d.cfg.Killer.Kill(Observation{})", 1)
		}},
		"deadline inversion check removed": {dispatchRel, func(s string) string {
			return strings.Replace(s, "reportedAt.After(active.deadlineAt()) || reportedAt.Before(active.issuedAt())", "false", 1)
		}},
		"extraction identity echo check removed": {dispatchRel, func(s string) string {
			return strings.Replace(s, "*outcome.ExtractionIdentity != d.extractionIdentityLocked(active)", "false", 1)
		}},
		"second registration rejection removed": {dispatchRel, func(s string) string {
			return strings.Replace(s, "if taken {", "if false {", 1)
		}},
		"cgroup recheck before the kill dropped": {observerLinuxRel, func(s string) string {
			return strings.Replace(s, "if err != nil || current != obs.CgroupPath {", "if err != nil {", 1)
		}},
		"supervisor deadline timer dropped": {dispatchRel, func(s string) string {
			return strings.Replace(s, "time.AfterFunc(time.Until(deadlineAt), func() { d.expire(active, true) })", "time.AfterFunc(time.Minute, func() { d.expire(active, true) })", 1)
		}},
		"payload digest verification dropped": {dispatchRel, func(s string) string {
			return strings.Replace(s, `"sha256:"+hex.EncodeToString(digest[:]) != job.InputArtifact.ContentDigest`, `false != job.InputArtifact.ContentDigest`, 1)
		}},
		"kernel observation dropped": {dispatchRel, func(s string) string {
			return strings.Replace(s, "d.cfg.Observer.Observe(conn)", "fakeObserve(conn)", 1)
		}},
		"second registration socket accepted": {dispatchRel, func(s string) string {
			return strings.Replace(s, "!taken || existing == nil", "true", 1)
		}},
		"kernel syscall surface outside the linux observer": {dispatchRel, func(s string) string {
			return strings.Replace(s, "os.MkdirAll", "syscall.Mkdir", 1)
		}},
		"syscall import in the plain core": {dispatchRel, func(s string) string {
			return strings.Replace(s, `"context"`, `"context"`+"\n\t\"syscall\"", 1)
		}},
		"core gains a database capability": {dispatchRel, func(s string) string {
			return strings.Replace(s, `"context"`, `"context"`+"\n\t\"knowvault.local/verified-workspace/internal/platform/database\"", 1)
		}},
		"status random capability leaks into core": {dispatchRel, func(s string) string {
			return strings.Replace(s, `"context"`, `"context"`+"\n\t\"crypto/rand\"", 1)
		}},
		"status writer gains a network capability": {"internal/sandboxdispatch/v2_status_linux.go", func(s string) string {
			return strings.Replace(s, `"os"`, `"os"`+"\n\t\"net\"", 1)
		}},
		"status document gains a kernel capability": {"internal/sandboxdispatch/v2_status.go", func(s string) string {
			return strings.Replace(s, `"errors"`, `"errors"`+"\n\t\"golang.org/x/sys/unix\"", 1)
		}},
		"container creation capability weakened": {wireRel, func(s string) string {
			return strings.Replace(s, `j.ContainerCreationCap != "FORBIDDEN"`, `j.ContainerCreationCap != "ALLOWED"`, 1)
		}},
		"retry accepted after the transfer": {leaseRel, func(s string) string {
			return strings.Replace(s, "if l.transferSent {", "if false {", 1)
		}},
		"limit identity computation renamed": {limitsRel, func(s string) string {
			return strings.Replace(s, "func CanonicalLimitsIdentity(", "func canonicalLimitsIdentity(", 1)
		}},
		"observation method becomes a worker self-report": {dispatchRel, func(s string) string {
			return strings.Replace(s, `ObservationMethod:  "KERNEL_CGROUP_NAMESPACE"`, `ObservationMethod:  "WORKER_SELF_REPORT"`, 1)
		}},
		"production dispatcher replaced by a fake": {runtimeRel, func(s string) string {
			return strings.Replace(s, "sandboxdispatch.NewV2(config.v2Config())", "sandboxdispatch.NewV2ForTests(config.v2Config())", 1)
		}},
		"binary bypasses the composition root": {dispatcherCmd, func(s string) string {
			return strings.Replace(s, "dispatchercomposition.LoadProduction()", "dispatchercomposition.loadProductionFromEnvironment()", 1)
		}},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			contents := load()
			original := contents[mutation.path]
			contents[mutation.path] = mutation.mutate(original)
			if contents[mutation.path] == original {
				t.Fatalf("mutation %q did not change the source (marker drifted)", name)
			}
			if problems := checkSandboxDispatcherBoundaryContents(contents); len(problems) == 0 {
				t.Fatalf("unsafe sandbox dispatcher mutation %q was accepted", name)
			}
		})
	}
}

// TestExtractionIdentityGuardRejectsAnUnboundObserver is the executable mutation
// proof behind the architecture.parser.observer-identity-outside-profile-hash
// checker-native invariant. Without the binding it defends, swapping a worker image
// under an unchanged parser_profile_revision leaves profile_hash equal, the
// "already extracted" short-circuit fires, and the platform keeps serving Evidence
// attributed to a build that no longer exists.
func TestExtractionIdentityGuardRejectsAnUnboundObserver(t *testing.T) {
	const canonRel = "internal/source/canon/hash.go"
	const pipelineRel = "internal/ingestion/pipeline.go"
	load := func() map[string]string {
		contents := map[string]string{}
		for _, rel := range []string{canonRel, pipelineRel} {
			raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			contents[rel] = string(raw)
		}
		return contents
	}
	if problems := checkExtractionIdentityBindingContents(load()); len(problems) != 0 {
		t.Fatalf("accepted extraction identity fails its own guard: %v", problems)
	}

	mutations := map[string]struct {
		path   string
		mutate func(string) string
	}{
		"profile can no longer carry an observer": {canonRel, func(s string) string {
			return strings.Replace(s, "Observer        *ObserverIdentity", "observer        *ObserverIdentity", 1)
		}},
		"observer stops composing into the artifact hash": {canonRel, func(s string) string {
			return strings.Replace(s, "CompositeArtifactHash(p.ArtifactHash, *p.Observer)", "p.ArtifactHash, error(nil)", 1)
		}},
		"profile built without the observer": {pipelineRel, func(s string) string {
			return strings.Replace(s, "ParserRevision: parserRevision, Observer: observer", "ParserRevision: parserRevision", 1)
		}},
		"lost observer no longer fails closed": {pipelineRel, func(s string) string {
			return strings.Replace(s, "observerRequired(formatRevision) != (observer != nil)", "false", 1)
		}},
	}
	for name, mutation := range mutations {
		t.Run(name, func(t *testing.T) {
			contents := load()
			original := contents[mutation.path]
			contents[mutation.path] = mutation.mutate(original)
			if contents[mutation.path] == original {
				t.Fatalf("mutation %q did not change the source (marker drifted)", name)
			}
			if problems := checkExtractionIdentityBindingContents(contents); len(problems) == 0 {
				t.Fatalf("unbound extraction identity mutation %q was accepted", name)
			}
		})
	}
}

// TestR3E2EWorkflowRequiresExactExecutionProof is the checker-native proof for
// CI-002. It covers the failure modes that made a package-level go test green
// insufficient evidence: renamed/deleted tests, an unanchored selector, a
// missing JSON verifier, a wrong package binding, and a dropped producer exit
// status.
func TestR3E2EWorkflowRequiresExactExecutionProof(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "architecture.yml"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(raw)
	if problems := checkR3E2EProof(baseline); len(problems) != 0 {
		t.Fatalf("accepted R3 e2e workflow fails its own guard: %v", problems)
	}
	mutations := map[string]func(string) string{
		"test renamed": func(source string) string {
			return strings.Replace(source, "TestE2ER3FullLoop", "TestE2ER3FullLoopRenamed", 1)
		},
		"test selector unanchored": func(source string) string {
			return strings.Replace(source, "-run=^TestE2ER3FullLoop$", "-run TestE2ER3FullLoop", 1)
		},
		"json output removed": func(source string) string {
			return strings.Replace(source, " -json -tags e2e", " -tags e2e", 1)
		},
		"verifier removed": func(source string) string {
			return strings.Replace(source, "              "+r3E2EVerifyCommand+"\n", "              # verifier removed\n", 1)
		},
		"wrong package binding": func(source string) string {
			return strings.Replace(source, "-verify-e2e-package "+r3E2EPackage, "-verify-e2e-package wrong/package", 1)
		},
		"producer status dropped": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusCapture+"\n", "              test_status=0\n", 1)
		},
		"producer status capture commented": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusCapture+"\n", "              # "+r3E2EStatusCapture+"\n", 1)
		},
		"producer status capture echoed and forced": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusCapture+"\n", "              echo "+r3E2EStatusCapture+"\n              test_status=0\n", 1)
		},
		"producer status capture overwritten": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusCapture+"\n", "              "+r3E2EStatusCapture+"\n              test_status=0\n", 1)
		},
		"command inserted before producer status capture": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusCapture+"\n", "              true\n              "+r3E2EStatusCapture+"\n", 1)
		},
		"status assertion removed": func(source string) string {
			return strings.Replace(source, "              "+r3E2EStatusAssertion+"\n", "              true\n", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := mutate(baseline)
			if mutated == baseline {
				t.Fatalf("mutation %q did not change the workflow (marker drifted)", name)
			}
			if problems := checkR3E2EProof(mutated); len(problems) == 0 {
				t.Fatalf("R3 e2e weakening %q was accepted", name)
			}
		})
	}
}

func TestR3E2EJSONVerifierRejectsMissingOrAmbiguousTestEvidence(t *testing.T) {
	const packageName = r3E2EPackage
	const testName = r3E2ETest
	valid := "{\"Action\":\"run\",\"Package\":\"" + packageName + "\",\"Test\":\"" + testName + "\"}\n" +
		"{\"Action\":\"pass\",\"Package\":\"" + packageName + "\",\"Test\":\"" + testName + "\"}\n"
	path := filepath.Join(t.TempDir(), "r3.json")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyR3E2EJSON(path, packageName, testName); err != nil {
		t.Fatalf("valid exact R3 JSON was rejected: %v", err)
	}
	mutations := map[string]string{
		"no exact test event": "{\"Action\":\"pass\",\"Package\":\"" + packageName + "\",\"Test\":\"Other\"}\n",
		"duplicate pass":      valid + "{\"Action\":\"pass\",\"Package\":\"" + packageName + "\",\"Test\":\"" + testName + "\"}\n",
		"no tests marker":     valid + "{\"Action\":\"output\",\"Package\":\"" + packageName + "\",\"Output\":\"[no tests to run]\\n\"}\n",
		"malformed event":     valid + "not-json\n",
	}
	for name, mutated := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := verifyR3E2EJSON(path, packageName, testName); err == nil {
				t.Fatalf("R3 JSON weakening %q was accepted", name)
			}
		})
	}
}

// TestProtectedGovernanceFilesAreCodeownedAndHashed is the executable proof
// for ARC-006. The full repository must contribute every e2e file to the
// protected inventory; the active CODEOWNERS parser
// catches deletion, comment-out and owner removal rather than raw substrings.
func TestProtectedGovernanceFilesAreCodeownedAndHashed(t *testing.T) {
	paths, problems := collectProtectedPaths("..")
	if len(problems) != 0 {
		t.Fatalf("collect protected paths: %v", problems)
	}
	if problems := validateProtectedGovernanceInventory("..", paths); len(problems) != 0 {
		t.Fatalf("accepted protected governance inventory fails its own guard: %v", problems)
	}
	protected := make(map[string]bool, len(paths))
	for _, path := range paths {
		protected[path] = true
	}
	if _, err := os.Stat(filepath.Join("..", "tests", "e2e")); err == nil {
		foundE2E := false
		for path := range protected {
			if strings.HasPrefix(path, "tests/e2e/") {
				foundE2E = true
				break
			}
		}
		if !foundE2E {
			t.Fatalf("tests/e2e is outside the protected-hash inventory")
		}
	}
	codeowners, err := os.ReadFile(filepath.Join("..", ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	if problems := checkRequiredCodeowners(string(codeowners)); len(problems) != 0 {
		t.Fatalf("accepted CODEOWNERS fails its own guard: %v", problems)
	}
	mutations := map[string]func(string) string{
		"e2e rule removed": func(source string) string {
			return strings.Replace(source, "/tests/e2e/** @avangerus\n", "", 1)
		},
		"e2e rule commented": func(source string) string {
			return strings.Replace(source, "/tests/e2e/** @avangerus", "# /tests/e2e/** @avangerus", 1)
		},
		"owner removed": func(source string) string {
			return strings.Replace(source, "/tests/e2e/** @avangerus", "/tests/e2e/**", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := mutate(string(codeowners))
			if mutated == string(codeowners) {
				t.Fatalf("mutation %q did not change CODEOWNERS (marker drifted)", name)
			}
			if problems := checkRequiredCodeowners(mutated); len(problems) == 0 {
				t.Fatalf("CODEOWNERS weakening %q was accepted", name)
			}
		})
	}
}

// TestCommandSurfaceUsesClosedGuardrailInventory proves that the command
// checker consumes the five-entry guardrail inventory, including operator, and
// rejects both an unknown command and an inventory that silently drops it.
func TestCommandSurfaceUsesClosedGuardrailInventory(t *testing.T) {
	guardrails, err := os.ReadFile(filepath.Join("..", "architecture", "guardrails.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join("..", "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := string(guardrails)
	if problems := checkAllowedBinaryInventory(filepath.Join("..", "cmd"), entries, baseline); len(problems) != 0 {
		t.Fatalf("accepted command inventory fails its own guard: %v", problems)
	}
	mutations := map[string]func(string) string{
		"operator removed": func(source string) string {
			return strings.Replace(source, "  - knowvault-operator\n", "", 1)
		},
		"unknown command admitted": func(source string) string {
			return strings.Replace(source, "  - knowvault-operator\n", "  - knowvault-unknown\n", 1)
		},
		"duplicate command admitted": func(source string) string {
			return strings.Replace(source, "  - knowvault-operator\n", "  - knowvault-server\n", 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := mutate(baseline)
			if mutated == baseline {
				t.Fatalf("mutation %q did not change guardrails (marker drifted)", name)
			}
			if problems := checkAllowedBinaryInventory(filepath.Join("..", "cmd"), entries, mutated); len(problems) == 0 {
				t.Fatalf("command inventory weakening %q was accepted", name)
			}
		})
	}
	// Reordering the closed set does not change its meaning and remains green.
	reordered := strings.Replace(baseline, "  - knowvault-server\n  - knowvault-worker\n", "  - knowvault-worker\n  - knowvault-server\n", 1)
	if reordered == baseline {
		reordered = strings.Replace(baseline, "  - knowvault-worker\n  - knowvault-server\n", "  - knowvault-server\n  - knowvault-worker\n", 1)
	}
	if reordered == baseline {
		t.Fatal("preserving command-inventory mutation did not change guardrails")
	}
	if problems := checkAllowedBinaryInventory(filepath.Join("..", "cmd"), entries, reordered); len(problems) != 0 {
		t.Fatalf("reordered command inventory was rejected: %v", problems)
	}
}

// TestNetHTMLModuleScopeRejectsForeignImports is the executable proof behind the
// architecture.parser.html-module-scope invariant: golang.org/x/net may be imported
// only by internal/source/html and only its html/html/atom subpackages, so the
// activation cannot silently grow a network/SSRF/charset capability anywhere.
func TestNetHTMLModuleScopeRejectsForeignImports(t *testing.T) {
	// Permitted: the safe extractor package importing the two allowed subpackages.
	for _, importPath := range []string{"golang.org/x/net/html", "golang.org/x/net/html/atom"} {
		if !netHTMLImportPermitted("internal/source/html/html.go", importPath) {
			t.Fatalf("permitted import wrongly rejected: %s", importPath)
		}
	}
	// A non-x/net import is out of scope and always permitted here.
	if !netHTMLImportPermitted("internal/anything/x.go", "bytes") {
		t.Fatal("non-x/net import must be out of scope for this gate")
	}
	// Forbidden: a network/charset/other x/net subpackage even inside the html dir.
	for _, importPath := range []string{
		"golang.org/x/net/http2", "golang.org/x/net/proxy", "golang.org/x/net/websocket",
		"golang.org/x/net/html/charset", "golang.org/x/net",
	} {
		if netHTMLImportPermitted("internal/source/html/html.go", importPath) {
			t.Fatalf("forbidden x/net subpackage wrongly permitted: %s", importPath)
		}
	}
	// Forbidden: the allowed subpackages imported from ANY other package.
	for _, rel := range []string{
		"internal/ingestion/pipeline.go", "internal/source/format/format.go",
		"internal/connector/folder/folder.go", "cmd/server/main.go",
	} {
		if netHTMLImportPermitted(rel, "golang.org/x/net/html") {
			t.Fatalf("x/net import wrongly permitted outside internal/source/html: %s", rel)
		}
	}
	// The live tree passes its own scope gate.
	if problems := checkNetHTMLModuleScope(".."); len(problems) != 0 {
		t.Fatalf("live tree fails the x/net module-scope gate: %v", problems)
	}
}

// TestInvariantRegistryPhaseGateRejectsOverdueAndAmbiguousStates is the
// executable mutation proof for the R1 registry phase rule. A future proof may
// be explicitly NOT_STARTED, an overdue proof may not remain deferred, and an
// executable proof may not carry a deferral marker. A line-ending-only change
// remains accepted, proving the gate evaluates registry semantics rather than
// matching copied source text.
func TestInvariantRegistryPhaseGateRejectsOverdueAndAmbiguousStates(t *testing.T) {
	if problems := checkInvariantTestRegistryFixture(t, nil); !onlyCriticalMutationCoverageDebt(problems) {
		t.Fatalf("live invariant registry has an unexpected phase/registry failure: %v", problems)
	}

	cases := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"future proof loses explicit phase registration": {
			mutate: func(source string) string {
				return strings.Replace(source, `"phase_state":"NOT_STARTED"`, `"phase_state":""`, 1)
			},
			want: "lacks explicit not-started phase registration",
		},
		"future proof is moved below the required coverage floor": {
			mutate: func(source string) string {
				return strings.Replace(source,
					`"id":"acceptance.acl.source-intersection","phase":"STAGE_3"`,
					`"id":"acceptance.acl.source-intersection","phase":"STAGE_2"`, 1)
			},
			want: "planned invariant is overdue",
		},
		"executable proof carries a deferral marker": {
			mutate: func(source string) string {
				return strings.Replace(source,
					`"id":"architecture.runtime.listener-before-preflight","phase":"STAGE_1","kind":"ARCHITECTURE_NEGATIVE","status":"EXECUTABLE"`,
					`"id":"architecture.runtime.listener-before-preflight","phase":"STAGE_1","kind":"ARCHITECTURE_NEGATIVE","status":"EXECUTABLE","phase_state":"NOT_STARTED"`, 1)
			},
			want: "executable invariant carries phase deferral state",
		},
		"registry line ending is semantic-preserving": {
			mutate: func(source string) string { return strings.ReplaceAll(source, "\n", "\r\n") },
			want:   "",
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			problems := checkInvariantTestRegistryFixture(t, testCase.mutate)
			if testCase.want == "" {
				if !onlyCriticalMutationCoverageDebt(problems) {
					t.Fatalf("semantics-preserving registry mutation was rejected: %v", problems)
				}
				return
			}
			if !containsProblemFragment(problems, testCase.want) {
				t.Fatalf("registry mutation was accepted or reported the wrong class: %v", problems)
			}
		})
	}
}

func onlyCriticalMutationCoverageDebt(problems []string) bool {
	for _, problem := range problems {
		if !strings.HasPrefix(problem, "critical invariant has no product mutation corpus: ") {
			return false
		}
	}
	return true
}

// TestMutationRegistryCannotBecomeDecorative proves the second half of the R1
// registration rule: an executable overdue invariant cannot silently lose its
// corpus link, and a weakening cannot be relabelled as the preserving direction.
func TestMutationRegistryCannotBecomeDecorative(t *testing.T) {
	tests := map[string]struct {
		mutate func(string) string
		want   string
	}{
		"executable proof loses corpus link": {
			mutate: func(source string) string {
				return strings.Replace(source,
					`"id":"acceptance.ten.missing-organization-column","phase":"STAGE_1","kind":"MIGRATION_NEGATIVE","status":"EXECUTABLE","harness":"POSTGRES_INTEGRATION","mutation_corpus":"tests/contracts/mutation-registry.json"`,
					`"id":"acceptance.ten.missing-organization-column","phase":"STAGE_1","kind":"MIGRATION_NEGATIVE","status":"EXECUTABLE","harness":"POSTGRES_INTEGRATION"`, 1)
			},
			want: "mutation registry is not linked from invariant registration",
		},
		"weakening is relabelled preserving": {
			mutate: func(source string) string { return source },
			want:   "GREEN mutation is not declared semantic-preserving",
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			problems := checkInvariantTestRegistryFixture(t, testCase.mutate)
			if name == "weakening is relabelled preserving" {
				problems = checkMutationRegistryFixture(t, func(source string) string {
					return strings.Replace(source, `"expected": "RED"`, `"expected": "GREEN"`, 1)
				})
			}
			if !containsProblemFragment(problems, testCase.want) {
				t.Fatalf("mutation registry weakening was accepted or reported the wrong class: %v", problems)
			}
		})
	}
}

func TestMutationRegistryRejectsCommentOnlyPreservingCases(t *testing.T) {
	problems := checkMutationRegistryFixture(t, func(source string) string {
		source = strings.Replace(source,
			`"old": "    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),\n    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),\n"`,
			`"old": "-- old preserving note\n"`, 1)
		source = strings.Replace(source,
			`"new": "    id text NOT NULL PRIMARY KEY CHECK (char_length(id) BETWEEN 3 AND 128),\n    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),\n"`,
			`"new": "-- new preserving note\n"`, 1)
		return source
	})
	if !containsProblemFragment(problems, "GREEN mutation changes only comments or formatting") {
		t.Fatalf("comment-only preserving mutation was accepted: %v", problems)
	}
}

// TestRequiredCiWorkflowGuardRejectsCommandWeakenings is the executable mutation
// proof behind the architecture.ci.required-command-* checker-native invariants:
// the shared exact-command contract is evaluated against the real workflow, and
// a weakening that demotes a required command to a comment, an echo or dead
// text must leave it non-executable.
func TestRequiredCiWorkflowGuardRejectsCommandWeakenings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "architecture.yml"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := extractYAMLRunBlocks(string(raw))
	for _, requiredCommand := range requiredCiExecutableCommands {
		if !runBlocksContainExecutable(blocks, requiredCommand) {
			t.Fatalf("required CI workflow has no executable exact command: %s", requiredCommand)
		}
	}

	const command = "go run ./scripts/check-architecture.go -root /src"
	weakened := map[string]string{
		"comment only": "jobs:\n  guard:\n    steps:\n      - run: |-\n          # " + command + "\n",
		"echo only":    "jobs:\n  guard:\n    steps:\n      - run: echo '" + command + "'\n",
		"unreachable":  "jobs:\n  guard:\n    steps:\n      - run: exit 0; " + command + "\n",
		"heredoc":      "jobs:\n  guard:\n    steps:\n      - run: |-\n          cat <<'EOF'\n          " + command + "\n          EOF\n",
	}
	for name, workflow := range weakened {
		if runBlocksContainExecutable(extractYAMLRunBlocks(workflow), command) {
			t.Fatalf("weakened CI command %q remained executable", name)
		}
	}
}

// TestLicensePolicyGuardRejectsReviewedEntryRemoval is the executable mutation
// proof behind the architecture.license.unknown-or-forbidden checker-native
// invariant: the reviewed inventory in the real policy file is load-bearing, and
// removing a reviewed entry must red the policy guard.
func TestLicensePolicyGuardRejectsReviewedEntryRemoval(t *testing.T) {
	if problems := checkLicensePolicy(".."); len(problems) != 0 {
		t.Fatalf("accepted license policy fails its own guard: %v", problems)
	}
	root := t.TempDir()
	for _, relative := range []string{"architecture/licenses.yaml", "architecture/versions.json"} {
		raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, root, relative, raw)
	}
	policyPath := filepath.Join(root, "architecture", "licenses.yaml")
	baseline, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	const fastURI = "  - name: fast-uri\n    status: ACTIVE\n    role: transitive contract-test URI implementation\n    license: BSD-3-Clause\n    source: https://github.com/fastify/fast-uri/blob/main/LICENSE\n"
	if strings.Count(string(baseline), fastURI) != 1 {
		t.Fatal("fast-uri reviewed entry anchor is not unique")
	}
	if err := os.WriteFile(policyPath, []byte(strings.Replace(string(baseline), fastURI, "", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if problems := checkLicensePolicy(root); len(problems) == 0 {
		t.Fatal("removing the reviewed fast-uri entry was accepted")
	}
}

// TestTimezoneDataAssetMutationsAreRejected proves that the embedded timezone
// bundle is a closed, content-addressed supply-chain component.
func TestTimezoneDataAssetMutationsAreRejected(t *testing.T) {
	versionRaw, err := os.ReadFile(filepath.Join("..", "architecture", "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]any
	if err := json.Unmarshal(versionRaw, &baseline); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]any){
		"unknown asset": func(lock map[string]any) {
			lock["data_assets"].(map[string]any)["unexpected"] = map[string]any{}
		},
		"missing sha256": func(lock map[string]any) {
			delete(lock["data_assets"].(map[string]any)["iana_timezone_database"].(map[string]any), "sha256")
		},
		"changed sha256": func(lock map[string]any) {
			lock["data_assets"].(map[string]any)["iana_timezone_database"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		},
		"changed size": func(lock map[string]any) {
			lock["data_assets"].(map[string]any)["iana_timezone_database"].(map[string]any)["size_bytes"] = float64(1)
		},
		"floating builder": func(lock map[string]any) {
			lock["data_assets"].(map[string]any)["iana_timezone_database"].(map[string]any)["builder_image"] = "golang:1.26.5-bookworm"
		},
		"unknown license": func(lock map[string]any) {
			lock["data_assets"].(map[string]any)["iana_timezone_database"].(map[string]any)["license"] = "Unknown-License"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			lock, cloneErr := cloneJSONValue(baseline)
			if cloneErr != nil {
				t.Fatal(cloneErr)
			}
			mutate(lock.(map[string]any))
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "architecture"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeJSONFixture(t, filepath.Join(root, "architecture", "versions.json"), lock)
			if problems := checkVersionLock(root); len(problems) == 0 {
				t.Fatal("timezone data asset mutation was accepted")
			}
		})
	}

	policyRaw, err := os.ReadFile(filepath.Join("..", "architecture", "licenses.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const entry = "  - name: IANA Time Zone Database\n    status: ACTIVE\n    role: embedded deterministic timezone rules\n    license: LicenseRef-IANA-TZ-Public-Domain\n    source: https://raw.githubusercontent.com/golang/go/go1.26.5/lib/time/README\n"
	t.Run("removed selected component", func(t *testing.T) {
		root := t.TempDir()
		writeFixtureFile(t, root, "architecture/versions.json", versionRaw)
		mutated := strings.Replace(string(policyRaw), entry, "", 1)
		if mutated == string(policyRaw) {
			t.Fatal("IANA selected component anchor is not unique")
		}
		writeFixtureFile(t, root, "architecture/licenses.yaml", []byte(mutated))
		if problems := checkLicensePolicy(root); len(problems) == 0 {
			t.Fatal("removing the IANA timezone selected component was accepted")
		}
	})
	t.Run("source drift", func(t *testing.T) {
		root := t.TempDir()
		writeFixtureFile(t, root, "architecture/versions.json", versionRaw)
		mutated := strings.Replace(string(policyRaw), "source: https://raw.githubusercontent.com/golang/go/go1.26.5/lib/time/README", "source: https://example.invalid/iana", 1)
		if mutated == string(policyRaw) {
			t.Fatal("IANA provenance anchor is absent")
		}
		writeFixtureFile(t, root, "architecture/licenses.yaml", []byte(mutated))
		if problems := checkLicensePolicy(root); len(problems) == 0 {
			t.Fatal("IANA source provenance drift was accepted")
		}
	})
}

// TestGoBoundaryRejectsHostTimezoneAuthority proves the AST boundary that keeps
// standard-library host timezone database authority out of every production
// caller: normal, aliased and dot imports are rejected, including the exact
// loader file, explicit TZif parsing and unrelated time APIs are accepted, and
// unparseable Go fails closed.
func TestGoBoundaryRejectsHostTimezoneAuthority(t *testing.T) {
	bypassPath := "internal/tzperiod/bypass.go"
	for name, bypass := range map[string]struct{ path, source string }{
		"normal import": {bypassPath, `package tzperiod
import "time"
func at(name string) { _, _ = time.LoadLocation(name) }
`},
		"aliased import": {bypassPath, `package tzperiod
import clock "time"
func at(name string) { _, _ = clock.LoadLocation(name) }
`},
		"dot import": {bypassPath, `package tzperiod
import . "time"
func at(name string) { _, _ = LoadLocation(name) }
`},
		"function value": {bypassPath, `package tzperiod
import "time"
var at = time.LoadLocation
`},
		"dot function value": {bypassPath, `package tzperiod
import . "time"
var at = LoadLocation
`},
		"sibling of the approved owner": {"internal/tzrules/sibling.go", `package tzrules
import "time"
func at(name string) { _, _ = time.LoadLocation(name) }
`},
		"command caller": {"cmd/tzperiod/main.go", `package main
import "time"
func at(name string) { _, _ = time.LoadLocation(name) }
`},
		"owner direct host lookup": {timezoneAuthorityOwner, `package tzrules
import "time"
func at(name string) { _, _ = time.LoadLocation(name) }
`},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFixtureFile(t, root, bypass.path, []byte(bypass.source))
			problems := checkGoBoundaries(root)
			if len(problems) == 0 {
				t.Fatal("host timezone database authority was accepted")
			}
			if !strings.Contains(problems[0], timezoneAuthorityOwner) {
				t.Fatalf("rejection does not name the exact owner: %v", problems)
			}
		})
	}
	for name, approved := range map[string]struct{ path, source string }{
		"TZif parser owner": {timezoneAuthorityOwner, `package tzrules
import "time"
func at(data []byte, name string) { _, _ = time.LoadLocationFromTZData(name, data) }
`},
		"unrelated time APIs": {bypassPath, `package tzperiod
import "time"
func zone() *time.Location { return time.FixedZone("fixed", 3600) }
func now() time.Time { return time.Now().In(time.UTC) }
`},
		"internal tzrules Load caller": {bypassPath, `package tzperiod
import (
	"time"
	"knowvault.local/verified-workspace/internal/tzrules"
)
func at(name string) (*time.Location, error) { return tzrules.Load(name) }
`},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFixtureFile(t, root, approved.path, []byte(approved.source))
			if problems := checkGoBoundaries(root); len(problems) != 0 {
				t.Fatalf("approved timezone authority was rejected: %v", problems)
			}
		})
	}
	t.Run("unparseable source fails closed", func(t *testing.T) {
		root := t.TempDir()
		writeFixtureFile(t, root, bypassPath, []byte("package tzperiod\n\nimport \"time\"\n\nfunc at() { _ = time.Now( }\n"))
		if problems := checkGoBoundaries(root); len(problems) == 0 {
			t.Fatal("unparseable Go source was accepted")
		}
	})
}

// TestSupplyChainGuardRejectsNonExactGoModuleVersions is the executable mutation
// proof behind the architecture.supply.non-exact-version checker-native
// invariant: the real module manifest reconciles to the exact version lock, and
// a shortened version in go.mod must red the guard.
func TestSupplyChainGuardRejectsNonExactGoModuleVersions(t *testing.T) {
	versionRaw, err := os.ReadFile(filepath.Join("..", "architecture", "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock any
	if err := json.Unmarshal(versionRaw, &lock); err != nil {
		t.Fatal(err)
	}
	goModules := lockedGoModulesFromVersionLock(lock)
	modulePath := filepath.Join("..", "go.mod")
	if problems := validateGoModuleManifest(modulePath, "go.mod", goModules); len(problems) != 0 {
		t.Fatalf("accepted go.mod fails the supply guard: %v", problems)
	}
	root := t.TempDir()
	for _, relative := range []string{"go.mod", "go.sum"} {
		raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		writeFixtureFile(t, root, relative, raw)
	}
	shortened, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	shortened = []byte(strings.Replace(string(shortened), "golang.org/x/net v0.57.0", "golang.org/x/net v0.57", 1))
	if err := os.WriteFile(filepath.Join(root, "go.mod"), shortened, 0o644); err != nil {
		t.Fatal(err)
	}
	if problems := validateGoModuleManifest(filepath.Join(root, "go.mod"), "go.mod", goModules); len(problems) == 0 {
		t.Fatal("a shortened Go module version was accepted")
	}
}

func checkMutationRegistryFixture(t *testing.T, mutate func(string) string) []string {
	return checkInvariantTestRegistryFixtures(t, nil, mutate)
}

// checkInvariantTestRegistryFixture evaluates the real registry and guardrails
// in an isolated tree. The PostgreSQL test source is copied as well, so a test
// name remains a real executable registration rather than a string-only fixture.
func checkInvariantTestRegistryFixture(t *testing.T, mutate func(string) string) []string {
	return checkInvariantTestRegistryFixturesWithRecognized(t, mutate, nil, nil)
}

func checkInvariantTestRegistryFixtures(t *testing.T, registryMutate, mutationMutate func(string) string) []string {
	return checkInvariantTestRegistryFixturesWithRecognized(t, registryMutate, mutationMutate, nil)
}

func checkInvariantTestRegistryFixturesWithRecognized(t *testing.T, registryMutate, mutationMutate, recognizedMutate func(string) string) []string {
	t.Helper()
	root := t.TempDir()
	for _, relative := range []string{
		"architecture/guardrails.yaml",
		"architecture/protected-hashes.json",
		"architecture/recognized-uncovered-critical.json",
		"tests/contracts/mutation-probes/ing-006.ps1",
		"architecture/contracts/answer-manifest.schema.json",
		"architecture/contracts/extractive-answer-plan.schema.json",
		"architecture/contracts/sandbox-job.schema.json",
		"architecture/contracts/sandbox-lease.schema.json",
		"architecture/contracts/sandbox-outcome.schema.json",
		"architecture/contracts/sandbox-limit-confirmation.schema.json",
		"architecture/contracts/operator-failure.schema.json",
		"architecture/contracts/operator-readiness.schema.json",
		"architecture/contracts/source-anchor.schema.json",
		"architecture/contracts/source-scope.schema.json",
		"tests/contracts/fixture-cases.json",
		"db/migrations/000001_stage1_tenancy.sql",
		"db/migrations/000002_stage1_audit.sql",
		"db/migrations/000003_stage1_identity.sql",
		"db/migrations/000005_stage2_encrypted_artifact_outbox.sql",
		"db/migrations/000006_stage2_source_connection_draft.sql",
		"db/migrations/000007_stage2_source_scope_draft.sql",
		"db/migrations/000008_stage2_workspace_source_snapshot.sql",
		"db/migrations/000009_stage2_workspace_source_command_gate.sql",
		"db/migrations/000013_stage2_durable_ingestion_jobs.sql",
		"db/migrations/000014_stage2_catalog_extraction_evidence.sql",
		"db/migrations/000015_stage2_source_version_purge.sql",
		"db/migrations/000016_stage2_source_scope_revision_cutover.sql",
		"db/migrations/000017_stage2_keyed_evidence_anchor.sql",
		"db/migrations/000019_stage2_secret_rotation.sql",
		"db/migrations/000020_stage2_keyed_text_digest.sql",
		"db/migrations/000021_stage2_evidence_fragment_reproject_null_fence.sql",
		"db/migrations/000022_stage2_answer_document_amendment.sql",
		"db/migrations/000030_stage3_search_retention_cleanup.sql",
		"db/migrations/000070_stage2_enqueue_job_id_idempotent.sql",
		"db/migrations/000077_stage2_evidence_fragment_readable_per_scope.sql",
		"db/migrations/000100_stage2_durable_ingestion_lease_clock.sql",
		"db/migrations/000107_stage2_source_observed_presence.sql",
		"internal/connector/folder/folder.go",
		"internal/audit/audit.go",
		"internal/audit/audit_test.go",
		"internal/identity/repository/repository.go",
		"internal/answer/repository/repository.go",
		"internal/answer/repository/repository_test.go",
		"internal/operator/bootstrap.go",
		"internal/operator/readiness.go",
		"internal/operator/readiness_test.go",
		"internal/operator/secrets.go",
		"internal/operator/secrets_linux_test.go",
		"internal/operator/tenant.go",
		"internal/operator/tenant_test.go",
		"tests/integration/postgres/catalog_evidence_purge_test.go",
		"tests/integration/postgres/catalog_evidence_worker_identity_test.go",
		"tests/integration/postgres/operator_credentials_test.go",
		"tests/integration/postgres/operator_tenant_test.go",
		"internal/platform/artifactcrypto/aad.go",
		"internal/platform/artifactcrypto/artifactcrypto_test.go",
		"internal/platform/composition/runtime.go",
		"internal/platform/composition/runtime_test.go",
		"cmd/server/main.go",
		"cmd/server/main_test.go",
		"internal/platform/oidcweb/handler.go",
		"internal/platform/oidcweb/logout_test.go",
		"internal/ingestion/handler.go",
		"internal/ingestion/handler_test.go",
		"internal/ingestion/pipeline.go",
		"internal/ingestion/pipeline_retry_test.go",
		"internal/recovery/recovery.go",
		"internal/policy/decision.go",
		"internal/source/canon/hash.go",
		"internal/source/canon/profile_test.go",
		"internal/source/canon/text.go",
		"internal/source/canon/text_test.go",
		"internal/source/docparser/docparser.go",
		"internal/source/docparser/docparser_test.go",
		"internal/source/pathcanon/pathcanon.go",
		"internal/source/pathcanon/pathcanon_test.go",
		"internal/source/scopeglob/scopeglob.go",
		"internal/workspace/repository/idempotency.go",
		"internal/workspace/repository/idempotency_test.go",
		"internal/workspace/repository/source_commands.go",
		"internal/platform/workspaceapi/workspaceapi.go",
		"internal/platform/workspaceapi/workspaceapi_audit_journal_test.go",
		"internal/platform/workspaceapi/workspaceapi_evidence_test.go",
		"internal/platform/workspaceapi/workspaceapi_surface_projection_test.go",
		"internal/sandboxdispatch/dispatch.go",
		"internal/sandboxdispatch/lease.go",
		"internal/sandboxdispatch/wire.go",
		"tests/integration/sandboxdispatch/dispatcher_loopback_test.go",
		"internal/sandboxdispatch/client.go",
		"internal/sandboxdispatch/registration_test.go",
		"tests/integration/sandboxdispatch/registration_handshake_test.go",
		"go.mod",
		".github/CODEOWNERS",
		".github/workflows/architecture.yml",
		"architecture/licenses.yaml",
		"deploy/images/Dockerfile.operator",
		"scripts/operator_artifact_test.go",
		"scripts/check_architecture_test.go",
	} {
		source, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		writeFixtureFile(t, root, relative, source)
	}
	registryRelative := "tests/contracts/invariant-test-registry.json"
	registry, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(registryRelative)))
	if err != nil {
		t.Fatal(err)
	}
	if registryMutate != nil {
		registry = []byte(registryMutate(string(registry)))
	}
	writeFixtureFile(t, root, registryRelative, registry)
	mutationRelative := "tests/contracts/mutation-registry.json"
	mutationRegistry, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(mutationRelative)))
	if err != nil {
		t.Fatal(err)
	}
	if mutationMutate != nil {
		mutationRegistry = []byte(mutationMutate(string(mutationRegistry)))
	}
	writeFixtureFile(t, root, mutationRelative, mutationRegistry)
	recognizedRelative := "architecture/recognized-uncovered-critical.json"
	recognized, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(recognizedRelative)))
	if err != nil {
		t.Fatal(err)
	}
	if recognizedMutate != nil {
		recognized = []byte(recognizedMutate(string(recognized)))
	}
	writeFixtureFile(t, root, recognizedRelative, recognized)
	// The registry grows with production capabilities. Copy the actual Go
	// targets and executable probes instead of an obsolete partial allow-list;
	// otherwise missing fixture files mask both preserving and weakening cases.
	if err := filepath.Walk(filepath.Join("..", "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		relative, err := filepath.Rel("..", path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeFixtureFile(t, root, filepath.ToSlash(relative), data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	paths, err := filepath.Glob(filepath.Join("..", "tests", "integration", "postgres", "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sourcePath := range paths {
		source, readErr := os.ReadFile(sourcePath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		writeFixtureFile(t, root, filepath.ToSlash(filepath.Join("tests", "integration", "postgres", filepath.Base(sourcePath))), source)
	}
	return checkInvariantTestRegistry(root)
}

// TestRecognizedUncoveredGate proves the ADR-0071 checker half on the live
// registries: the 32 recognized criticals (31 STAGE_GATED behind the P2
// coordinate, ING-006 DUAL_LAYER with its committed and pinned probe) no
// longer fail the corpus-debt error — the debt is registered, not hidden.
func TestRecognizedUncoveredGate(t *testing.T) {
	if problems := checkInvariantTestRegistryFixture(t, nil); len(problems) != 0 {
		t.Fatalf("live recognized registry does not clear the corpus debt: %v", problems)
	}
}

// TestRecognizedStageGateReopensDebtWhenStageArrives proves the "current debt,
// not future work" rule mechanically: moving a recognized product stage to the active
// coordinate returns the id to the corpus-debt error immediately.
func TestRecognizedStageGateReopensDebtWhenStageArrives(t *testing.T) {
	mutate := func(source string) string {
		return strings.Replace(source, `"product_stage": "STAGE_3"`, `"product_stage": "STAGE_2"`, 1)
	}
	problems := checkInvariantTestRegistryFixturesWithRecognized(t, nil, nil, mutate)
	if !containsProblemFragment(problems, "critical invariant has no product mutation corpus: SRCH-009") {
		t.Fatalf("stage-gated recognition did not re-open debt at the active stage: %v", problems)
	}
}

// TestRecognizedUnknownCriticalRejected proves that recognition of an id that
// guardrails do not know fails structural validation instead of suppressing.
func TestRecognizedUnknownCriticalRejected(t *testing.T) {
	mutate := func(source string) string {
		return strings.Replace(source, `"critical_id": "SIG-001"`, `"critical_id": "ACL-999"`, 1)
	}
	problems := checkInvariantTestRegistryFixturesWithRecognized(t, nil, nil, mutate)
	if !containsProblemFragment(problems, "recognized critical is unknown to guardrails: ACL-999") {
		t.Fatalf("recognition of an unknown critical was not rejected: %v", problems)
	}
}

// TestRecognizedDualLayerProbeMissingReopensDebt proves that a missing
// dual-layer probe re-opens the debt instead of keeping the suppression.
func TestRecognizedDualLayerProbeMissingReopensDebt(t *testing.T) {
	mutate := func(source string) string {
		return strings.Replace(source, `"probe": "tests/contracts/mutation-probes/ing-006.ps1"`, `"probe": "tests/contracts/mutation-probes/other.ps1"`, 1)
	}
	problems := checkInvariantTestRegistryFixturesWithRecognized(t, nil, nil, mutate)
	if !containsProblemFragment(problems, "dual-layer probe is missing: ING-006") ||
		!containsProblemFragment(problems, "critical invariant has no product mutation corpus: ING-006") {
		t.Fatalf("a missing dual-layer probe did not fail validation and re-open debt: %v", problems)
	}
}

// TestValidateRecognizedUncoveredCritical enforces every ADR-0071 honesty
// constraint structurally: unknown invariants, non-executable owners, missing
// evidence, invalid stages, seated product enforcement, missing or unpinned
// dual-layer probes, redundancy with a covering corpus entry and unsupported
// dispositions all fail, and none of them may suppress debt.
func TestValidateRecognizedUncoveredCritical(t *testing.T) {
	root := t.TempDir()
	manifestDir := filepath.Join(root, "architecture")
	probesDir := filepath.Join(root, "tests", "contracts", "mutation-probes")
	if err := os.MkdirAll(manifestDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(probesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"version":1,"algorithm":"sha256","files":{"tests/contracts/mutation-probes/probe-a.ps1":"aa"}}`
	if err := os.WriteFile(filepath.Join(manifestDir, "protected-hashes.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(probesDir, "probe-a.ps1"), []byte("# probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(probesDir, "probe-b.ps1"), []byte("# probe"), 0o644); err != nil {
		t.Fatal(err)
	}

	negative := map[string][]string{
		"CRIT-1":  {"test.one"},
		"CRIT-2":  {"test.two"},
		"CRIT-3":  {"test.three"},
		"CRIT-4":  {"test.four"},
		"CRIT-6":  {"test.six"},
		"CRIT-7":  {"test.seven"},
		"CRIT-8":  {"test.eight"},
		"CRIT-9":  {"test.nine"},
		"CRIT-10": {"test.ten"},
		"CRIT-11": {"test.eleven"},
		"CRIT-12": {"test.twelve"},
	}
	registrations := map[string]invariantRegistryRegistration{
		"test.one":    {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.two":    {Status: "PLANNED"},
		"test.three":  {Status: "EXECUTABLE", Harness: "GO_UNIT"},
		"test.four":   {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.six":    {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.seven":  {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.eight":  {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.nine":   {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.ten":    {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.eleven": {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
		"test.twelve": {Status: "EXECUTABLE", Harness: "CONTRACT_FIXTURE"},
	}
	mutationRegistry := mutationTestRegistry{RegistryVersion: "1.0", Entries: []mutationTestRegistryEntry{{
		InvariantID:          "test.four",
		CriticalInvariantIDs: []string{"CRIT-4"},
		Mutations:            []mutationTestCase{{ID: "m1"}},
	}}}
	file := recognizedUncoveredCriticalFile{Version: 1, Entries: []recognizedCritical{
		{CriticalID: "CRIT-1", Disposition: "STAGE_GATED", ProductStage: "STAGE_4", Evidence: "docs/evidence.md#crit-1"},
		{CriticalID: "CRIT-2", Disposition: "STAGE_GATED", ProductStage: "STAGE_4", Evidence: "docs/evidence.md#crit-2"},
		{CriticalID: "CRIT-3", Disposition: "STAGE_GATED", ProductStage: "STAGE_4", Evidence: "docs/evidence.md#crit-3"},
		{CriticalID: "CRIT-4", Disposition: "STAGE_GATED", ProductStage: "STAGE_6", Evidence: "docs/evidence.md#crit-4"},
		{CriticalID: "CRIT-1", Disposition: "DUAL_LAYER", Probe: "tests/contracts/mutation-probes/probe-a.ps1", Evidence: "docs/evidence.md#dup"},
		{CriticalID: "CRIT-5", Disposition: "STAGE_GATED", ProductStage: "STAGE_4", Evidence: "docs/evidence.md#crit-5"},
		{CriticalID: "CRIT-6", Disposition: "STAGE_GATED", ProductStage: "STAGE_X", Evidence: "docs/evidence.md#crit-6"},
		{CriticalID: "CRIT-7", Disposition: "STAGE_GATED", ProductStage: "STAGE_4"},
		{CriticalID: "CRIT-8", Disposition: "STAGE_GATED", ProductStage: "STAGE_4", Evidence: "docs/evidence.md#crit-8"},
		{CriticalID: "CRIT-9", Disposition: "DUAL_LAYER", Evidence: "docs/evidence.md#crit-9"},
		{CriticalID: "CRIT-10", Disposition: "DUAL_LAYER", Probe: "tests/contracts/mutation-probes/missing.ps1", Evidence: "docs/evidence.md#crit-10"},
		{CriticalID: "CRIT-11", Disposition: "DUAL_LAYER", Probe: "tests/contracts/mutation-probes/probe-b.ps1", Evidence: "docs/evidence.md#crit-11"},
		{CriticalID: "CRIT-12", Disposition: "MYSTERY", Evidence: "docs/evidence.md#crit-12"},
	}}
	valid, problems := validateRecognizedUncoveredCritical(file, negative, registrations, mutationRegistry, root)
	wants := []string{
		"recognized entry has empty or duplicate critical id: CRIT-1",
		"recognized critical is unknown to guardrails: CRIT-5",
		"stage-gated recognized entry has invalid product stage: CRIT-6 -> STAGE_X",
		"recognized critical owns no executable negative test: CRIT-2",
		"stage-gated recognized critical has seated product enforcement: CRIT-3 -> test.three",
		"recognized critical lacks an evidence anchor: CRIT-7",
		"recognized critical is also covered by the mutation corpus: CRIT-4",
		"dual-layer recognized entry has no probe: CRIT-9",
		"dual-layer probe is missing: CRIT-10 -> tests/contracts/mutation-probes/missing.ps1",
		"dual-layer probe is not pinned: CRIT-11 -> tests/contracts/mutation-probes/probe-b.ps1",
		"recognized entry has unsupported disposition: CRIT-12 -> MYSTERY",
	}
	for _, want := range wants {
		if !containsProblemFragment(problems, want) {
			t.Fatalf("recognized validation missed %q: %v", want, problems)
		}
	}
	_, crit1 := valid["CRIT-1"]
	_, crit8 := valid["CRIT-8"]
	if len(valid) != 2 || !crit1 || !crit8 {
		t.Fatalf("only structurally valid entries may suppress debt, got: %v", valid)
	}
}

func writeFixtureFile(t *testing.T, root, relative string, contents []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyParserReleaseScansRejectsBoundIdentityAndEvidenceDrift(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{name: "valid"},
		{name: "wrong image", mutate: func(syft, _ map[string]any) {
			syft["source"].(map[string]any)["metadata"].(map[string]any)["imageID"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{name: "unexpected package", mutate: func(syft, _ map[string]any) {
			syft["artifacts"].([]any)[0].(map[string]any)["version"] = "0.0.0"
		}},
		{name: "finding", mutate: func(_, grype map[string]any) {
			grype["matches"] = []any{map[string]any{"vulnerability": "CVE-test"}}
		}},
		{name: "suppressed finding", mutate: func(_, grype map[string]any) {
			grype["ignoredMatches"] = []any{map[string]any{"vulnerability": "CVE-test"}}
		}},
		{name: "database drift", mutate: func(_, grype map[string]any) {
			grype["descriptor"].(map[string]any)["db"].(map[string]any)["status"].(map[string]any)["from"] = "https://example.invalid/db?checksum=sha256:wrong"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			syft, grype := validParserReleaseScanFixtures(t)
			if test.mutate != nil {
				test.mutate(syft, grype)
			}
			temp := t.TempDir()
			syftPath := filepath.Join(temp, "syft.json")
			grypePath := filepath.Join(temp, "grype.json")
			nativePath := filepath.Join(temp, "native.json")
			writeJSONFixture(t, syftPath, syft)
			writeJSONFixture(t, grypePath, grype)
			writeJSONFixture(t, nativePath, validNativeParserScanFixture(grype))
			err := verifyParserReleaseScans(root, syftPath, grypePath, nativePath)
			if test.mutate == nil && err != nil {
				t.Fatalf("valid live scan evidence rejected: %v", err)
			}
			if test.mutate != nil && err == nil {
				t.Fatal("mutated live scan evidence was accepted")
			}
		})
	}
}

func validParserReleaseScanFixtures(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	artifacts := []any{}
	for _, triple := range [][3]string{
		{"SparseBitSet", "1.3", "java-archive"}, {"commons-codec", "1.20.0", "java-archive"},
		{"commons-collections4", "4.5.0", "java-archive"}, {"commons-compress", "1.28.0", "java-archive"},
		{"commons-io", "2.21.0", "java-archive"}, {"commons-lang3", "3.18.0", "java-archive"},
		{"commons-logging", "1.4.0", "java-archive"}, {"commons-math3", "3.6.1", "java-archive"},
		{"curvesapi", "1.08", "java-archive"}, {"document-parser-worker", "2.1.0", "java-archive"},
		{"fontbox", "3.0.8", "java-archive"}, {"jrt-fs", "21.0.12", "java-archive"},
		{"log4j-api", "2.25.5", "java-archive"}, {"openjdk", "21.0.12", "binary"},
		{"pdfbox", "3.0.8", "java-archive"}, {"pdfbox-io", "3.0.8", "java-archive"},
		{"poi", "5.5.1", "java-archive"}, {"poi-ooxml", "5.5.1", "java-archive"},
		{"poi-ooxml-lite", "5.5.1", "java-archive"}, {"xmlbeans", "5.3.0", "java-archive"},
	} {
		artifacts = append(artifacts, map[string]any{"name": triple[0], "version": triple[1], "type": triple[2]})
	}
	const (
		ociManifest = "sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855"
		config      = "sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467"
		dbChecksum  = "972de542534d3461cc3c3849a37a3f917b823de3b9c367e289db0d163519b42b"
	)
	metadata := func() map[string]any {
		value := map[string]any{"imageID": config, "manifestDigest": ociManifest, "mediaType": "application/vnd.oci.image.manifest.v1+json"}
		for _, field := range []string{"manifest", "config"} {
			raw, err := os.ReadFile(filepath.Join("testdata", "parser-runtime-v3", field+".json"))
			if err != nil {
				t.Fatal(err)
			}
			value[field] = base64.StdEncoding.EncodeToString(raw)
		}
		return value
	}
	syft := map[string]any{
		"descriptor": map[string]any{"name": "syft", "version": "1.48.0"},
		"source":     map[string]any{"type": "image", "metadata": metadata()},
		"artifacts":  artifacts,
	}
	grype := map[string]any{
		"matches":        []any{},
		"ignoredMatches": []any{},
		"source":         map[string]any{"type": "image", "target": metadata()},
		"descriptor": map[string]any{
			"name": "grype", "version": "0.116.0",
			"db": map[string]any{"status": map[string]any{
				"schemaVersion": "v6.1.9", "built": "2026-09-22T06:30:41Z", "valid": true,
				"from": "https://grype.anchore.io/db?checksum=sha256%3A" + dbChecksum,
			}},
		},
	}
	return syft, grype
}

func validNativeParserScanFixture(grype map[string]any) map[string]any {
	return map[string]any{
		"source":  map[string]any{"type": "purl", "target": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.8?arch=amd64&distro=ubuntu-24.04"},
		"distro":  map[string]any{"name": "ubuntu", "version": "24.04"},
		"matches": []any{}, "ignoredMatches": []any{}, "descriptor": grype["descriptor"],
	}
}

func TestVerifyNativeParserScanRejectsMissingWrongAndSuppressedEvidence(t *testing.T) {
	database := map[string]any{"schema_version": "v6.1.9", "built_at": "2026-09-22T06:30:41Z", "archive_sha256": "972de542534d3461cc3c3849a37a3f917b823de3b9c367e289db0d163519b42b"}
	for name, mutate := range map[string]func(map[string]any){
		"valid":           nil,
		"wrong package":   func(s map[string]any) { s["source"].(map[string]any)["target"] = "pkg:deb/ubuntu/libc6@0" },
		"wrong distro":    func(s map[string]any) { s["distro"].(map[string]any)["version"] = "22.04" },
		"finding":         func(s map[string]any) { s["matches"] = []any{"CVE-test"} },
		"suppression":     func(s map[string]any) { s["ignoredMatches"] = []any{"CVE-test"} },
		"missing matches": func(s map[string]any) { delete(s, "matches") },
		"missing tool":    func(s map[string]any) { delete(s, "descriptor") },
		"database drift": func(s map[string]any) {
			s["descriptor"].(map[string]any)["db"].(map[string]any)["status"].(map[string]any)["from"] = "manual import"
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, grype := validParserReleaseScanFixtures(t)
			scan := validNativeParserScanFixture(grype)
			if mutate != nil {
				mutate(scan)
			}
			if err := verifyParserNativeScan(scan, database); (err != nil) != (mutate != nil) {
				t.Fatalf("unexpected verification result: %v", err)
			}
		})
	}
}

func writeJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeGovernedQueryImportFile writes a synthetic .go file that imports the
// ADR-0089 governed-query owner package from an arbitrary location, to prove
// checkGoBoundaries confines that import to its owner package plus the two
// permitted orchestration/composition surfaces.
func writeGovernedQueryImportFile(t *testing.T, root, relative string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content := "package surface\n\nimport _ \"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGovernedQueryBoundaryPerADR0089 proves the ADR-0089 §3 anchor: only the
// owner package itself, its REST/MCP orchestration surface
// (internal/platform/workspaceapi) and the composition root that wires its
// mounted config may import internal/source/postgresqlquery/governedquery;
// every other package -- in particular internal/ingestion, internal/question
// and internal/modelgateway, none of which may ever hold the dedicated
// governed-execution role's connection capability or forward model-authored
// SQL text to a database call -- fails the scan.
func TestGovernedQueryBoundaryPerADR0089(t *testing.T) {
	allowed := []string{
		"internal/source/postgresqlquery/governedquery/extra.go",
		"internal/governedask/extra.go",
		"internal/platform/workspaceapi/governedquery_ask.go",
		"internal/platform/composition/runtime_extra.go",
	}
	for _, relative := range allowed {
		relative := relative
		t.Run("permits "+relative, func(t *testing.T) {
			root := t.TempDir()
			writeGovernedQueryImportFile(t, root, relative)
			if problems := checkGoBoundaries(root); len(problems) != 0 {
				t.Fatalf("import inside %s was rejected: %v", relative, problems)
			}
		})
	}
	disallowed := []string{
		"internal/ingestion/governed.go",
		"internal/question/governed.go",
		"internal/modelgateway/governed.go",
		"internal/source/postgresqlquery/governed_caller.go",
	}
	for _, relative := range disallowed {
		relative := relative
		t.Run("rejects "+relative, func(t *testing.T) {
			root := t.TempDir()
			writeGovernedQueryImportFile(t, root, relative)
			if problems := checkGoBoundaries(root); len(problems) == 0 {
				t.Fatalf("import inside %s was accepted", relative)
			}
		})
	}
}

// TestGovernedQueryBoundaryAcceptance keeps the positive gate load-bearing on
// the real tree: the accepted checkpoint must still pass with zero
// violations, so the synthetic-tree rejections above are proof the guard is
// active, not merely permissive by construction.
func TestGovernedQueryBoundaryAcceptance(t *testing.T) {
	if problems := checkGoBoundaries(".."); len(problems) != 0 {
		t.Fatalf("accepted tree fails the governed query boundary: %v", problems)
	}
}

// TestApplicationLanguageArchiveException proves the application-language
// default-deny admits exactly the pinned IANA timezone bundle: the real bytes
// at the normalized path only, never the same bytes under another path,
// altered bytes, a directory, or a symlink.
func TestApplicationLanguageArchiveException(t *testing.T) {
	pinned, err := os.ReadFile(filepath.Join("..", "internal", "tzrules", "zoneinfo.zip"))
	if err != nil {
		t.Fatal(err)
	}
	accepted := func(t *testing.T, relativePath string, contents []byte) {
		t.Helper()
		root := t.TempDir()
		writeFixtureFile(t, root, relativePath, contents)
		if problems := checkApplicationLanguages(root); len(problems) != 0 {
			t.Fatalf("%s was rejected: %v", relativePath, problems)
		}
	}
	rejected := func(t *testing.T, relativePath string, contents []byte) {
		t.Helper()
		root := t.TempDir()
		writeFixtureFile(t, root, relativePath, contents)
		if problems := checkApplicationLanguages(root); len(problems) == 0 {
			t.Fatalf("%s was accepted", relativePath)
		}
	}
	t.Run("pinned archive at exact path", func(t *testing.T) {
		accepted(t, pinnedTimezoneArchivePath, pinned)
		for _, problem := range checkApplicationLanguages("..") {
			if strings.Contains(problem, "zoneinfo.zip") {
				t.Fatalf("real repository asset was rejected: %v", problem)
			}
		}
	})
	t.Run("pinned bytes at another path", func(t *testing.T) {
		rejected(t, "internal/tzrules/timezones.zip", pinned)
	})
	t.Run("altered bytes at exact path", func(t *testing.T) {
		altered := append([]byte(nil), pinned...)
		altered[len(altered)/2] ^= 0xff
		rejected(t, "internal/tzrules/zoneinfo.zip", altered)
	})
	t.Run("directory at exact path", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "internal", "tzrules", "zoneinfo.zip"), 0o755); err != nil {
			t.Fatal(err)
		}
		if problems := checkApplicationLanguages(root); len(problems) == 0 {
			t.Fatal("directory at the pinned archive path was accepted")
		}
	})
	t.Run("symlink at exact path", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "pinned.zip")
		if err := os.WriteFile(target, pinned, 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "internal", "tzrules", "zoneinfo.zip")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks are unavailable on this platform: %v", err)
		}
		if problems := checkApplicationLanguages(root); len(problems) == 0 {
			t.Fatal("symlink at the pinned archive path was accepted")
		}
	})
	t.Run("approved extension", func(t *testing.T) {
		accepted(t, "internal/tzrules/tzdata.json", []byte("{\"version\":1}\n"))
	})
	t.Run("unknown extension", func(t *testing.T) {
		rejected(t, "internal/tzrules/tzdata.dat", []byte("zone data"))
	})
}
