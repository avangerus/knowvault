package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// checkerProbe is the focused fake of the DatasetBindingApprovalChecker seam.
// It records how many times Check was invoked, the exact arguments Store passed,
// the error it should surface, and appends to a shared sequence slice so the
// test can prove the relative order of the checker and the audit boundary.
type checkerProbe struct {
	calls        int
	err          error
	gotAccess    database.AccessContext
	gotWorkspace string
	got          metricdef.Definition
	sequence     *[]string
}

func (probe *checkerProbe) Check(_ context.Context, access database.AccessContext,
	workspaceID string, definition metricdef.Definition) error {
	probe.calls++
	probe.gotAccess = access
	probe.gotWorkspace = workspaceID
	probe.got = definition
	if probe.sequence != nil {
		*probe.sequence = append(*probe.sequence, "check")
	}
	return probe.err
}

// checkerAuditProbe is the recording approval boundary the store owns during
// the test. It appends every event the store hands it and, when a shared
// sequence slice is supplied, records that the audit ran after the checker.
type checkerAuditProbe struct {
	events   []metricdef.ApprovalEvent
	sequence *[]string
}

func (probe *checkerAuditProbe) RecordApproval(_ context.Context, _ database.AccessContext,
	_ database.Transaction, event metricdef.ApprovalEvent) error {
	probe.events = append(probe.events, event)
	if probe.sequence != nil {
		*probe.sequence = append(*probe.sequence, "audit")
	}
	return nil
}

// openCheckerStore opens the bounded application database/workspace repository
// against the already reset+seeded stage-1 database with fresh synthetic IDs and
// returns a metricdef.Store created only through the explicit
// NewWithDatasetBindingApprovalChecker constructor, plus the owner access
// context. No production helper is edited: the same setup pattern the binding
// store suite uses is repeated here with IDs unique to this file.
func openCheckerStore(t *testing.T, ctx context.Context,
	checker metricdef.DatasetBindingApprovalChecker,
	auditor metricdef.ApprovalAudit) (*metricdef.Store, database.AccessContext) {
	t.Helper()
	organizationID, ownerID := "org_mcheck", "usr_mcheck_owner"

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
	definitions, err := metricdef.NewWithDatasetBindingApprovalChecker(databaseStore, workspaceStore, auditor, checker)
	if err != nil {
		t.Fatalf("create metric definition store with checker: %v", err)
	}
	owner := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_mcheck_owner"}
	return definitions, owner
}

// checkerApprovalColumns reads the persisted status/approved_by/approved_at for
// one version straight from the admin connection, so the row state is proved
// independently of the Store's read path. A nil pointer means SQL NULL.
func checkerApprovalColumns(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, definitionID string, version int64) (string, *string, *bool) {
	t.Helper()
	var status string
	var approvedBy *string
	var approvedAt *bool
	if err := admin.QueryRow(ctx, `
SELECT status, approved_by, approved_at IS NOT NULL
  FROM public.metric_definition_version
 WHERE organization_id = $1 AND workspace_id = $2 AND definition_id = $3 AND version = $4`,
		organizationID, workspaceID, definitionID, version).Scan(&status, &approvedBy, &approvedAt); err != nil {
		t.Fatalf("read approval columns for %s v%d: %v", definitionID, version, err)
	}
	return status, approvedBy, approvedAt
}

// assertProbeDefinition requires the Definition handed to the checker to be the
// exact current bound DRAFT: identity, version, status and all five binding
// accessors. It is content-free — it only compares values the caller supplied.
func assertProbeDefinition(t *testing.T, got metricdef.Definition, want metricdef.Definition) {
	t.Helper()
	if got.ID() != want.ID() || got.Version() != want.Version() || got.Status() != want.Status() {
		t.Fatalf("probe definition identity mismatch: got id=%q version=%d status=%q, want id=%q version=%d status=%q",
			got.ID(), got.Version(), got.Status(), want.ID(), want.Version(), want.Status())
	}
	assertBinding(t, got, want.Binding())
}

// TestMetricDefinitionBindingApprovalCheckerOrdering is the focused
// real-PostgreSQL proof of the R1-C2.6b approval-checker seam ordering. One
// reset and four scenarios with disjoint definition IDs prove: (1) a nil
// checker fails a bound approval closed with the typed code and leaves the row
// DRAFT; (2) a failing checker is called exactly once with the exact owner
// access, workspace and current bound definition, its private error never
// escapes, the sequence is "check" only and the row stays DRAFT; (3) a
// succeeding checker runs strictly before the audit ("check","audit"), the
// audit fires exactly once and the row becomes APPROVED; (4) an unbound v1 DRAFT
// approves with zero checker calls and sequence "audit" only, proving the
// checker is never invoked for an unbound definition.
func TestMetricDefinitionBindingApprovalCheckerOrdering(t *testing.T) {
	ctx := context.Background()
	// One reset and one seed for the whole test: the four scenarios below use
	// disjoint definition IDs inside the single synthetic workspace.
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_mcheck", "usr_mcheck_owner", "ws_mcheck")

	// (1) checker=nil: a bound DRAFT approval fails closed with the typed code.
	// The checker is absent, no audit event is recorded, and the row never leaves
	// DRAFT with NULL approvals.
	{
		nilAudit := &checkerAuditProbe{}
		definitions, owner := openCheckerStore(t, ctx, nil, nilAudit)
		binding := storeBoundBinding(t, "dataset_nil", "measure_nil", "a")
		if _, err := definitions.CreateDraft(ctx, owner, "ws_mcheck", "metric_checker_nil",
			storeBoundSpec("Checker nil", "conn_mcheck", 3, binding)); err != nil {
			t.Fatalf("(nil) create bound draft: %v", err)
		}
		approved, err := definitions.Approve(ctx, owner, "ws_mcheck", "metric_checker_nil")
		if metricdef.CodeOf(err) != metricdef.CodeBindingApprovalUnavailable {
			t.Fatalf("(nil) approve code=%q err=%v", metricdef.CodeOf(err), err)
		}
		if approved.ID() != "" {
			t.Fatalf("(nil) approval returned a definition: %q", approved.ID())
		}
		if len(nilAudit.events) != 0 {
			t.Fatalf("(nil) recorded %d audit events", len(nilAudit.events))
		}
		status, approvedBy, approvedAt := checkerApprovalColumns(t, ctx, admin,
			"org_mcheck", "ws_mcheck", "metric_checker_nil", 1)
		if status != "DRAFT" || approvedBy != nil || approvedAt == nil || *approvedAt {
			t.Fatalf("(nil) row status=%q approvedBy=%v approvedAtSet=%v", status, approvedBy, approvedAt)
		}
	}

	// (2) checker returns a private error: the bound approval returns exactly
	// CodeBindingApprovalUnavailable, the private detail never reaches the
	// caller, the probe ran once with the exact owner access, workspace and
	// current bound DRAFT, the sequence is "check" alone, no audit event is
	// recorded and the row stays DRAFT with NULL approvals.
	{
		sequence := []string{}
		probe := &checkerProbe{err: errors.New("private checker detail"), sequence: &sequence}
		auditProbe := &checkerAuditProbe{sequence: &sequence}
		definitions, owner := openCheckerStore(t, ctx, probe, auditProbe)
		binding := storeBoundBinding(t, "dataset_private", "measure_private", "b")
		created, err := definitions.CreateDraft(ctx, owner, "ws_mcheck", "metric_checker_private",
			storeBoundSpec("Checker private", "conn_mcheck", 3, binding))
		if err != nil {
			t.Fatalf("(private) create bound draft: %v", err)
		}
		approved, err := definitions.Approve(ctx, owner, "ws_mcheck", "metric_checker_private")
		if metricdef.CodeOf(err) != metricdef.CodeBindingApprovalUnavailable {
			t.Fatalf("(private) approve code=%q err=%v", metricdef.CodeOf(err), err)
		}
		if strings.Contains(err.Error(), "private checker detail") {
			t.Fatalf("(private) error leaked checker detail: %v", err)
		}
		if approved.ID() != "" {
			t.Fatalf("(private) approval returned a definition: %q", approved.ID())
		}
		if probe.calls != 1 {
			t.Fatalf("(private) checker calls=%d", probe.calls)
		}
		if probe.gotAccess != owner {
			t.Fatalf("(private) checker access=%+v want %+v", probe.gotAccess, owner)
		}
		if probe.gotWorkspace != "ws_mcheck" {
			t.Fatalf("(private) checker workspace=%q", probe.gotWorkspace)
		}
		assertProbeDefinition(t, probe.got, created)
		if strings.Join(sequence, ",") != "check" {
			t.Fatalf("(private) sequence=%v", sequence)
		}
		if len(auditProbe.events) != 0 {
			t.Fatalf("(private) recorded %d audit events", len(auditProbe.events))
		}
		status, approvedBy, approvedAt := checkerApprovalColumns(t, ctx, admin,
			"org_mcheck", "ws_mcheck", "metric_checker_private", 1)
		if status != "DRAFT" || approvedBy != nil || approvedAt == nil || *approvedAt {
			t.Fatalf("(private) row status=%q approvedBy=%v approvedAtSet=%v", status, approvedBy, approvedAt)
		}
	}

	// (3) checker success on a bound DRAFT: approval succeeds, the sequence is
	// exactly "check","audit", the checker ran once with the exact current bound
	// definition, exactly one audit event was recorded and both the returned and
	// the stored row are APPROVED.
	{
		sequence := []string{}
		probe := &checkerProbe{sequence: &sequence}
		auditProbe := &checkerAuditProbe{sequence: &sequence}
		definitions, owner := openCheckerStore(t, ctx, probe, auditProbe)
		binding := storeBoundBinding(t, "dataset_ok", "measure_ok", "c")
		created, err := definitions.CreateDraft(ctx, owner, "ws_mcheck", "metric_checker_success",
			storeBoundSpec("Checker success", "conn_mcheck", 3, binding))
		if err != nil {
			t.Fatalf("(success) create bound draft: %v", err)
		}
		approved, err := definitions.Approve(ctx, owner, "ws_mcheck", "metric_checker_success")
		if err != nil {
			t.Fatalf("(success) approve: %v", err)
		}
		if approved.Status() != metricdef.StatusApproved || approved.Version() != 1 {
			t.Fatalf("(success) returned status=%q version=%d", approved.Status(), approved.Version())
		}
		assertBinding(t, approved, binding)
		if probe.calls != 1 {
			t.Fatalf("(success) checker calls=%d", probe.calls)
		}
		if probe.gotAccess != owner || probe.gotWorkspace != "ws_mcheck" {
			t.Fatalf("(success) checker access=%+v workspace=%q", probe.gotAccess, probe.gotWorkspace)
		}
		assertProbeDefinition(t, probe.got, created)
		if strings.Join(sequence, ",") != "check,audit" {
			t.Fatalf("(success) sequence=%v", sequence)
		}
		if len(auditProbe.events) != 1 {
			t.Fatalf("(success) recorded %d audit events", len(auditProbe.events))
		}
		status, approvedBy, approvedAt := checkerApprovalColumns(t, ctx, admin,
			"org_mcheck", "ws_mcheck", "metric_checker_success", 1)
		if status != "APPROVED" || approvedBy == nil || *approvedBy != owner.PrincipalID ||
			approvedAt == nil || !*approvedAt {
			t.Fatalf("(success) row status=%q approvedBy=%v approvedAtSet=%v", status, approvedBy, approvedAt)
		}
	}

	// (4) checker injected but unbound v1 DRAFT: approval succeeds with zero
	// checker calls, the sequence is "audit" alone, exactly one audit event is
	// recorded and the returned row is APPROVED. This proves an unbound v1 never
	// invokes the checker.
	{
		sequence := []string{}
		probe := &checkerProbe{err: errors.New("should never run"), sequence: &sequence}
		auditProbe := &checkerAuditProbe{sequence: &sequence}
		definitions, owner := openCheckerStore(t, ctx, probe, auditProbe)
		if _, err := definitions.CreateDraft(ctx, owner, "ws_mcheck", "metric_checker_unbound",
			metricDefinitionSpec("Checker unbound", "conn_mcheck", 3)); err != nil {
			t.Fatalf("(unbound) create draft: %v", err)
		}
		approved, err := definitions.Approve(ctx, owner, "ws_mcheck", "metric_checker_unbound")
		if err != nil {
			t.Fatalf("(unbound) approve: %v", err)
		}
		if approved.Status() != metricdef.StatusApproved || approved.Version() != 1 {
			t.Fatalf("(unbound) returned status=%q version=%d", approved.Status(), approved.Version())
		}
		if !approved.Binding().IsZero() {
			t.Fatalf("(unbound) binding not zero: %+v", approved.Binding())
		}
		if probe.calls != 0 {
			t.Fatalf("(unbound) checker calls=%d", probe.calls)
		}
		if strings.Join(sequence, ",") != "audit" {
			t.Fatalf("(unbound) sequence=%v", sequence)
		}
		if len(auditProbe.events) != 1 {
			t.Fatalf("(unbound) recorded %d audit events", len(auditProbe.events))
		}
		status, approvedBy, approvedAt := checkerApprovalColumns(t, ctx, admin,
			"org_mcheck", "ws_mcheck", "metric_checker_unbound", 1)
		if status != "APPROVED" || approvedBy == nil || *approvedBy != owner.PrincipalID ||
			approvedAt == nil || !*approvedAt {
			t.Fatalf("(unbound) row status=%q approvedBy=%v approvedAtSet=%v", status, approvedBy, approvedAt)
		}
	}
}
