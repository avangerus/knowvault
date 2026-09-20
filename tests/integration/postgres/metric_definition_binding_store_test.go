package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// storeBindingHash returns a canonical profile hash: the "sha256:" tag plus 64
// lowercase hex characters. It is unique to this file so it cannot collide with
// the migration test's bindingHash helper.
func storeBindingHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

// storeBoundSpec builds a complete metric-definition spec carrying the supplied
// binding. It reuses the shape of metricDefinitionSpec so the only difference
// under test is the binding field.
func storeBoundSpec(name, connectionID string, projectionVersion int64, binding metricdef.DatasetBinding) metricdef.Spec {
	spec := metricDefinitionSpec(name, connectionID, projectionVersion)
	spec.Binding = binding
	return spec
}

// storeBoundBinding constructs a valid bound DatasetBinding through the public
// constructor so the test never hand-rolls the internal value.
func storeBoundBinding(t *testing.T, datasetID, measureID, hashCharacter string) metricdef.DatasetBinding {
	t.Helper()
	binding, err := metricdef.NewDatasetBinding(metricdef.DatasetBindingInput{
		DatasetID:      datasetID,
		ProfileVersion: 7,
		ProfileHash:    storeBindingHash(hashCharacter),
		MeasureID:      measureID,
		Mode:           metricdef.BindingModeLive,
	})
	if err != nil {
		t.Fatalf("build dataset binding: %v", err)
	}
	return binding
}

// seedBoundMetricDefinitionVersion inserts one metric_definition plus one
// metric_definition_version row in a single admin transaction with all five
// binding columns present in the INSERT. approved_by/approved_at follow the
// status so an APPROVED seed is never rewritten by a later UPDATE.
func seedBoundMetricDefinitionVersion(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, ownerID, definitionID string, version int64, status string,
	datasetID string, profileVersion int64, profileHash, measureID, executionMode string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
INSERT INTO public.metric_definition (
organization_id, workspace_id, id, owner_principal_id, current_version, created_by
) VALUES ($1, $2, $3, $4, $5, $4)
ON CONFLICT (organization_id, workspace_id, id) DO UPDATE
SET current_version = GREATEST(public.metric_definition.current_version, EXCLUDED.current_version)`,
		organizationID, workspaceID, definitionID, ownerID, version); err != nil {
		t.Fatalf("seed bound metric_definition: %v", err)
	}
	approvedBy, approvedAt := "NULL", "NULL"
	if status == "APPROVED" {
		approvedBy = fmt.Sprintf("'%s'", ownerID)
		approvedAt = "transaction_timestamp()"
	}
	statement := fmt.Sprintf(`
INSERT INTO public.metric_definition_version (
organization_id, workspace_id, definition_id, version, status,
name, source_connection_id, projection_version, entity_key, grain,
owner_principal_id, created_by, approved_by, approved_at,
dataset_id, profile_version, profile_hash, measure_id, execution_mode
) VALUES ($1, $2, $3, $4, '%s', 'm', 'conn_m', 1, 'k', 'MONTH', $5, $5, %s, %s,
          $6, $7, $8, $9, $10)`,
		status, approvedBy, approvedAt)
	if _, err := tx.Exec(ctx, statement, organizationID, workspaceID, definitionID, version, ownerID,
		datasetID, profileVersion, profileHash, measureID, executionMode); err != nil {
		t.Fatalf("seed bound metric_definition_version: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// storeBindingColumns reads the five persisted binding columns for one version
// directly from the admin connection, so the test can prove the stored shape
// independently of the Store's own read path.
func storeBindingColumns(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, definitionID string, version int64) (bool, string, int64, string, string, string) {
	t.Helper()
	var datasetID, profileHash, measureID, executionMode *string
	var profileVersion *int64
	if err := admin.QueryRow(ctx, `
SELECT dataset_id, profile_version, profile_hash, measure_id, execution_mode
  FROM public.metric_definition_version
 WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3 AND version = $4`,
		organizationID, workspaceID, definitionID, version).
		Scan(&datasetID, &profileVersion, &profileHash, &measureID, &executionMode); err != nil {
		t.Fatalf("read binding columns: %v", err)
	}
	// allNull is true only for the explicit five-NULL legacy shape. Any
	// partial-NULL or all-present row returns false.
	if datasetID == nil && profileVersion == nil && profileHash == nil && measureID == nil && executionMode == nil {
		return true, "", 0, "", "", ""
	}
	if datasetID == nil || profileVersion == nil || profileHash == nil || measureID == nil || executionMode == nil {
		return false, "", 0, "", "", ""
	}
	return false, *datasetID, *profileVersion, *profileHash, *measureID, *executionMode
}

// assertBinding reads a definition and requires all five accessors to equal the
// expected binding. It is content-free: it only compares the values the caller
// already supplied.
func assertBinding(t *testing.T, definition metricdef.Definition, want metricdef.DatasetBinding) {
	t.Helper()
	got := definition.Binding()
	if got.DatasetID() != want.DatasetID() || got.ProfileVersion() != want.ProfileVersion() ||
		got.ProfileHash() != want.ProfileHash() || got.MeasureID() != want.MeasureID() ||
		got.Mode() != want.Mode() {
		t.Fatalf("binding mismatch: got dataset=%q version=%d hash=%q measure=%q mode=%q",
			got.DatasetID(), got.ProfileVersion(), got.ProfileHash(), got.MeasureID(), got.Mode())
	}
}

// TestMetricDefinitionBindingStorePersistence is the focused real-PostgreSQL
// proof that the metricdef Store persists, reads and preserves the five
// DatasetBinding accessors. It exercises the accepted public API end to end on
// the canonical schema: draft+list+get round-trip, atomic five-column draft
// update, legacy all-NULL read, APPROVED bound seed supremacy, the fail-closed
// bound approval rollback, and the legacy unbound approval success path.
func TestMetricDefinitionBindingStorePersistence(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	seedOrganization(t, ctx, admin, "org_mbind", "usr_mbind_owner", "ws_mbind")

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}

	owner := database.AccessContext{OrganizationID: "org_mbind", PrincipalID: "usr_mbind_owner", RequestID: "req_mbind_owner"}

	// (1) CreateDraft with Spec.Binding; GetVersion and List return all five
	// accessors unchanged.
	bindingOne := storeBoundBinding(t, "dataset_store", "measure_store", "a")
	recorder := &recordingApprovalAudit{}
	definitions, err := metricdef.New(databaseStore, workspaceStore, recorder)
	if err != nil {
		t.Fatalf("create metric definition store: %v", err)
	}
	created, err := definitions.CreateDraft(ctx, owner, "ws_mbind", "metric_bound_one",
		storeBoundSpec("Bound one", "conn_mbind", 3, bindingOne))
	if err != nil {
		t.Fatalf("create bound draft: %v", err)
	}
	if created.Version() != 1 || created.Status() != metricdef.StatusDraft {
		t.Fatalf("created version/status=%d/%q", created.Version(), created.Status())
	}
	assertBinding(t, created, bindingOne)

	loaded, err := definitions.GetVersion(ctx, owner, "ws_mbind", "metric_bound_one", 1)
	if err != nil {
		t.Fatalf("get bound version: %v", err)
	}
	assertBinding(t, loaded, bindingOne)

	listed, err := definitions.List(ctx, owner, "ws_mbind")
	if err != nil {
		t.Fatalf("list definitions: %v", err)
	}
	var listedBound *metricdef.Definition
	for index := range listed {
		if listed[index].ID() == "metric_bound_one" {
			listedBound = &listed[index]
		}
	}
	if listedBound == nil {
		t.Fatalf("bound definition missing from list")
	}
	assertBinding(t, *listedBound, bindingOne)

	// (2) A DRAFT edit with a second complete binding keeps the same version and
	// GetVersion returns the replacement: the five-column update is atomic, not
	// dropped.
	bindingTwo := storeBoundBinding(t, "dataset_store_two", "measure_store_two", "b")
	edited, err := definitions.CreateDraft(ctx, owner, "ws_mbind", "metric_bound_one",
		storeBoundSpec("Bound one revised", "conn_mbind", 4, bindingTwo))
	if err != nil {
		t.Fatalf("edit bound draft: %v", err)
	}
	if edited.Version() != 1 || edited.Status() != metricdef.StatusDraft {
		t.Fatalf("edited version/status=%d/%q", edited.Version(), edited.Status())
	}
	assertBinding(t, edited, bindingTwo)
	reread, err := definitions.GetVersion(ctx, owner, "ws_mbind", "metric_bound_one", 1)
	if err != nil {
		t.Fatalf("get edited version: %v", err)
	}
	assertBinding(t, reread, bindingTwo)

	// (3) A legacy row seeded with all five NULLs loads via GetVersion and the
	// binding is the explicit zero value.
	seedMetricDefinitionVersion(t, ctx, admin, "org_mbind", "ws_mbind", "usr_mbind_owner", "metric_legacy_store", 1, "DRAFT")
	legacy, err := definitions.GetVersion(ctx, owner, "ws_mbind", "metric_legacy_store", 1)
	if err != nil {
		t.Fatalf("get legacy version: %v", err)
	}
	if !legacy.Binding().IsZero() {
		t.Fatalf("legacy binding not zero: %+v", legacy.Binding())
	}

	// (4) A direct APPROVED bound seed is inserted with all five binding columns
	// plus approved_by/approved_at in one INSERT. CreateDraft supersedes it to
	// version 2; version 1 stays APPROVED with its original binding and version 2
	// is DRAFT with the new binding.
	approvedSeedBinding := storeBoundBinding(t, "dataset_seed", "measure_seed", "c")
	seedBoundMetricDefinitionVersion(t, ctx, admin, "org_mbind", "ws_mbind", "usr_mbind_owner",
		"metric_bound_approved", 1, "APPROVED",
		approvedSeedBinding.DatasetID(), approvedSeedBinding.ProfileVersion(), approvedSeedBinding.ProfileHash(),
		approvedSeedBinding.MeasureID(), string(approvedSeedBinding.Mode()))
	supersedingBinding := storeBoundBinding(t, "dataset_supersede", "measure_supersede", "d")
	superseded, err := definitions.CreateDraft(ctx, owner, "ws_mbind", "metric_bound_approved",
		storeBoundSpec("Bound approved revised", "conn_mbind", 5, supersedingBinding))
	if err != nil {
		t.Fatalf("supersede approved bound definition: %v", err)
	}
	if superseded.Version() != 2 || superseded.Status() != metricdef.StatusDraft {
		t.Fatalf("superseded version/status=%d/%q", superseded.Version(), superseded.Status())
	}
	assertBinding(t, superseded, supersedingBinding)
	stillApproved, err := definitions.GetVersion(ctx, owner, "ws_mbind", "metric_bound_approved", 1)
	if err != nil {
		t.Fatalf("get approved version 1: %v", err)
	}
	if stillApproved.Status() != metricdef.StatusApproved {
		t.Fatalf("version 1 status=%q want APPROVED", stillApproved.Status())
	}
	assertBinding(t, stillApproved, approvedSeedBinding)

	// List returns both versions of the superseded definition with their exact
	// per-version statuses and bindings, so the history view is proven independently
	// of GetVersion.
	history, err := definitions.List(ctx, owner, "ws_mbind")
	if err != nil {
		t.Fatalf("list superseded history: %v", err)
	}
	var historyV1, historyV2 *metricdef.Definition
	for index := range history {
		if history[index].ID() != "metric_bound_approved" {
			continue
		}
		switch history[index].Version() {
		case 1:
			historyV1 = &history[index]
		case 2:
			historyV2 = &history[index]
		}
	}
	if historyV1 == nil || historyV2 == nil {
		t.Fatalf("history versions missing: v1=%v v2=%v", historyV1 != nil, historyV2 != nil)
	}
	if historyV1.Status() != metricdef.StatusApproved {
		t.Fatalf("history version 1 status=%q want APPROVED", historyV1.Status())
	}
	if historyV2.Status() != metricdef.StatusDraft {
		t.Fatalf("history version 2 status=%q want DRAFT", historyV2.Status())
	}
	assertBinding(t, *historyV1, approvedSeedBinding)
	assertBinding(t, *historyV2, supersedingBinding)

	// (5) For a separate bound DRAFT, Approve is fail-closed: it returns the
	// content-free CodeBindingApprovalUnavailable, records no audit event, and
	// leaves the row DRAFT with NULL approved_by/approved_at. This is the
	// rollback/fail-closed assertion.
	boundDraftBinding := storeBoundBinding(t, "dataset_failclosed", "measure_failclosed", "e")
	if _, err := definitions.CreateDraft(ctx, owner, "ws_mbind", "metric_bound_failclosed",
		storeBoundSpec("Bound fail-closed", "conn_mbind", 6, boundDraftBinding)); err != nil {
		t.Fatalf("create fail-closed bound draft: %v", err)
	}
	eventsBefore := len(recorder.events)
	if _, err := definitions.Approve(ctx, owner, "ws_mbind", "metric_bound_failclosed"); metricdef.CodeOf(err) != metricdef.CodeBindingApprovalUnavailable {
		t.Fatalf("bound approval code=%q err=%v", metricdef.CodeOf(err), err)
	}
	if len(recorder.events) != 0 {
		t.Fatalf("fail-closed approval recorded %d audit events, want 0", len(recorder.events))
	}
	if len(recorder.events) != eventsBefore {
		t.Fatalf("audit event count changed from %d to %d", eventsBefore, len(recorder.events))
	}
	var failClosedStatus string
	var failClosedApprovedBy, failClosedApprovedAt *string
	if err := admin.QueryRow(ctx, `
SELECT status, approved_by, approved_at
  FROM public.metric_definition_version
 WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3 AND version = 1`,
		"org_mbind", "ws_mbind", "metric_bound_failclosed").
		Scan(&failClosedStatus, &failClosedApprovedBy, &failClosedApprovedAt); err != nil {
		t.Fatalf("read fail-closed row: %v", err)
	}
	if failClosedStatus != "DRAFT" || failClosedApprovedBy != nil || failClosedApprovedAt != nil {
		t.Fatalf("fail-closed row mutated: status=%q approved_by=%v approved_at=%v",
			failClosedStatus, failClosedApprovedBy, failClosedApprovedAt)
	}

	// (6) A separate legacy unbound DRAFT approves successfully and records
	// exactly one event; the stored row is APPROVED. The unbound shape (all five
	// binding columns NULL) is the only approvable shape.
	if _, err := definitions.CreateDraft(ctx, owner, "ws_mbind", "metric_unbound_ok",
		metricDefinitionSpec("Unbound approve", "conn_mbind", 2)); err != nil {
		t.Fatalf("create unbound draft: %v", err)
	}
	approvedUnbound, err := definitions.Approve(ctx, owner, "ws_mbind", "metric_unbound_ok")
	if err != nil {
		t.Fatalf("approve unbound draft: %v", err)
	}
	if approvedUnbound.Status() != metricdef.StatusApproved {
		t.Fatalf("unbound approved status=%q", approvedUnbound.Status())
	}
	if approvedUnbound.Binding().IsZero() != true {
		t.Fatalf("unbound approved binding not zero: %+v", approvedUnbound.Binding())
	}
	if len(recorder.events) != 1 {
		t.Fatalf("unbound approval audit events=%d, want 1", len(recorder.events))
	}

	// (7) The stored shape of the unbound row is five NULLs, exactly the shape
	// the migration CHECK admits as the legacy state; the Store read of the
	// legacy shape stayed content-free and zero. A partial-null shape cannot be
	// persisted through the CHECK, so no impossible row is faked here.
	allNull, datasetNull, versionNull, hashNull, measureNull, modeNull := storeBindingColumns(t, ctx, admin,
		"org_mbind", "ws_mbind", "metric_unbound_ok", 1)
	if !allNull {
		t.Fatalf("unbound row is not all-NULL")
	}
	if datasetNull != "" || versionNull != 0 || hashNull != "" || measureNull != "" || modeNull != "" {
		t.Fatalf("unbound row not all-NULL: dataset=%q version=%d hash=%q measure=%q mode=%q",
			datasetNull, versionNull, hashNull, measureNull, modeNull)
	}
}
