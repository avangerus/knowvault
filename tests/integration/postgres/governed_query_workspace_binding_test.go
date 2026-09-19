package postgres_test

// AGG-2 defect B, real-PostgreSQL regression.
//
// Before this fix, a governed-query connection's authorization was hardcoded
// to a single workspace_id in two places: the administrator-mounted capability
// file (governedquery.Config.WorkspaceID, loaded once at process start) and
// this connection's own governed_query_connection.workspace_id column, which
// 000068's own guard trigger makes immutable after the row is first created.
// internal/governedask.Service.Ask/SetLiveQueries/RegisterExposedSchema/Promote
// each rejected any workspaceID other than that one hardcoded value with
// CodeRequestInvalid before ever consulting workspace membership or role. A
// structural source's dedicated governed-execution connection is a property
// of the SOURCE (the external database and the least-privilege role that
// reaches it), not of whichever workspace happened to register it first, so
// a second workspace that also has this same source's live corpus bound had
// no way to ever enable "live queries" for it.
//
// The fix moves the authorization surface to a new, independent table,
// public.governed_query_workspace_binding (migration 000078): any workspace
// with sufficient role (checked the ordinary way, through
// internal/policy.EvaluateWorkspace, exactly like every other workspace-scoped
// mutation) may opt itself into a connection it can reach, with its own
// live_queries_enabled toggle -- enabling live queries in one workspace never
// enables or disables them in another that shares the same connection.
//
// This test never dials the connection's external PostgreSQL server (the
// mounted DSN below is syntactically valid but unreachable and is never
// used): SetLiveQueries and the CodeLiveQueriesOff/CodeSchemaUnavailable
// branches of Ask are internal-database-only operations, so the distinction
// between "this workspace has not opted in" (CodeLiveQueriesOff) and "this
// workspace opted in but no exposed schema is registered yet"
// (CodeSchemaUnavailable) is itself the black-box proof that a workspace's
// own opt-in state -- not the connection's original mounted workspace_id --
// is what gates it, without needing a live external database or a real model
// runtime for this narrower proof.
import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/workspace"
)

const (
	govBindOrg        = "org_governed_binding"
	govBindOwner      = "usr_governed_binding_owner"
	govBindWorkspaceA = "ws_governed_binding_alpha"
	govBindWorkspaceB = "ws_governed_binding_beta"
	govBindConnection = "govbind-shared-connection"
)

// govBindTestCACertPEM is a real, freshly generated self-signed certificate
// used only to exercise x509.CertPool parsing for governedquery.Config's
// TrustRoots (its Validate requires at least one subject); it never anchors
// a real connection anywhere in this test, which never dials out.
const govBindTestCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDITCCAgmgAwIBAgIUb41jVBoe+OjZsddWZ1NoxiZgZ0IwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVZ292ZXJuZWRxdWVyeS10ZXN0LWNhMB4XDTI2MDkwNjIx
NDMyOFoXDTM2MDkwMzIxNDMyOFowIDEeMBwGA1UEAwwVZ292ZXJuZWRxdWVyeS10
ZXN0LWNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwpf24FGZxuxW
oK8/TbvPUJmsSH1RMz8G+H5kNzd0XqHt0ewuMgro8VT68LmttzR2eeGnoRUZk7dk
HwQd7e6rOZVanZeqvALQM+2HcR+6vppovXUg9yeKgoDFBqVZ3x+A9c4XpibxA/vs
31CzujqYyGRsFjOpqGRwI9FTwYu6Y4XOpnWShjcZYNt8XJlsUHO0G6Za1yPkp4of
EK2VkWBPkshT102JGen/pYBQAYijRg4Tz+maQy7/QWQNvZm19CHaB0IsuljyFYwE
KuE4U12EHMZ96HB3JDAtK9sfQ40fFVKNcRgQnyAIkZH5I6Le/RTMlhtU2p6UdRGi
4rfnk6nWNQIDAQABo1MwUTAdBgNVHQ4EFgQUP5wBuw9dRO7+x0In5V0rNUIftyMw
HwYDVR0jBBgwFoAUP5wBuw9dRO7+x0In5V0rNUIftyMwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAQEAHu1lQHH4UuZV6dgUN1xIT3widrOyWYSjKQzR
rsD/wWUKtcqjYiB6qQkeYmZtaBu2dbeirTVfZ8z1WBufEhXfO4gxlOiYOZ8Q4iiL
KyC1sp55eWgVLl5znAJwkQbAdZqO+wV9myYtK/FGuuIMHHi/snmt6X179cy03NQH
qBL6WcmhQl+ABLE8W8r/FETEbbMQKC0TZqgHS4/Y4ioRNaxKT9LDHno82uzXfzm+
QgJkyp1PECjjtl+a7Rhoc6+f6Rr1YL+svVzVsF8stxlEdmHh5eEfjhV3FrsBywnH
l5A+3plBUzevft2AAKF2l4xduolay/70n1L3L2SP43puFoMz0w==
-----END CERTIFICATE-----`

// seedGovernedBindingWorkspace adds a second, independent workspace to an
// already-seeded organization (seedOrganization creates the first), with the
// same owner as an OWNER member -- mirroring the acc stand's real demo-2
// shape, where demo-admin owns both the acceptance and the demo workspace.
func seedGovernedBindingWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, ownerID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive,
		OwnerPrincipalID: ownerID, Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("normalize %s: %v", workspaceID, err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("configuration hash %s: %v", workspaceID, err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("canonical snapshot %s: %v", workspaceID, err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql:  "INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id) VALUES ($1, $2, $1, 'ACTIVE', $3)",
			args: []any{workspaceID, organizationID, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, canonicalBytes},
		},
		{
			sql:  "INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)",
			args: []any{"wsm_" + workspaceID, organizationID, workspaceID, ownerID},
		},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed %s: %v", workspaceID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit %s: %v", workspaceID, err)
	}
}

// newGovernedBindingService builds a real internal-database-backed
// governedask.Service, mounted with a syntactically valid but never-dialled
// external connection (mountedWorkspaceID models the pre-AGG-2 single
// hardcoded workspace the connection happened to be provisioned against).
func newGovernedBindingService(t *testing.T, appStore *database.Store, auditStore *audit.Store, mountedWorkspaceID string) *governedask.Service {
	t.Helper()
	service, err := governedask.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("governedask.New: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(govBindTestCACertPEM)) {
		t.Fatalf("parse test CA certificate")
	}
	config := governedquery.Config{
		ConnectionID: govBindConnection, DatabaseIdentity: "govbind_db", WorkspaceID: mountedWorkspaceID,
		DSN:        "postgres://govbind_role:secret@govbind-external-host:5432/govbind_db?sslmode=verify-full",
		TrustRoots: pool,
		Limits: governedquery.Limits{
			StatementTimeout: 5 * time.Second, MaxRows: 1000, MaxResultBytes: 1 << 20, MaxCostEstimate: 1000,
		},
		Presets: []governedquery.Preset{{
			ID: "contract-count", Version: "v1", Name: "Contract count", Description: "Current contract count.",
			Phrases: []string{"check contracts"}, WorkspaceID: govBindWorkspaceA, SourceAttemptID: "gqat_reviewed",
			SQLHash: canon.Hash([]byte("SELECT count(*) FROM reporting.contracts")), ExposedSchemaRevision: 2,
		}},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("mounted config invalid: %v", err)
	}
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: "http://127.0.0.1:8080",
		ModelID: "govbind-test-model", MaxOutputTokens: 128, InsecureLabMode: true,
	})
	if err != nil {
		t.Fatalf("lab adapter: %v", err)
	}
	service.EnableGovernedQuery(config, adapter)
	return service
}

// TestGovernedQueryWorkspaceBindingIsPerWorkspaceNotPerConnection is the
// AGG-2 defect B proof. The connection is mounted with workspace A recorded
// as its (now vestigial) WorkspaceID/legacy governed_query_connection row --
// exactly the pre-fix shape -- yet workspace B, sharing nothing with A but
// the connection id, can independently opt in, toggle its own flag and see
// its own state change, all gated by its own membership/role, never by
// equality with the mounted WorkspaceID.
func TestGovernedQueryWorkspaceBindingIsPerWorkspaceNotPerConnection(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, govBindOrg, govBindOwner, govBindWorkspaceA)
	seedGovernedBindingWorkspace(t, ctx, admin, govBindOrg, govBindWorkspaceB, govBindOwner)

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	service := newGovernedBindingService(t, appStore, auditStore, govBindWorkspaceA)

	access := func(requestID string) database.AccessContext {
		return database.AccessContext{OrganizationID: govBindOrg, PrincipalID: govBindOwner, RequestID: requestID}
	}
	ask := func(workspaceID, requestID string) error {
		_, err := service.Ask(ctx, access(requestID), workspaceID, govBindConnection, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0442\u0440\u043e\u043a?")
		return err
	}
	// A requested connection must never silently select the mounted one.
	// These calls use a real authorized workspace but an unrelated connection;
	// none may create a binding, discover a schema, execute or promote SQL.
	const wrongConnection = "another-source"
	if _, err := service.Ask(ctx, access("req_gb_wrong_ask"), govBindWorkspaceA, wrongConnection, "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0442\u0440\u043e\u043a?"); governedask.CodeOf(err) != governedask.CodeConnectionUnavailable {
		t.Fatalf("wrong connection ask: %v", err)
	}
	if err := service.SetLiveQueries(ctx, access("req_gb_wrong_enable"), govBindWorkspaceA, wrongConnection, true); governedask.CodeOf(err) != governedask.CodeConnectionUnavailable {
		t.Fatalf("wrong connection toggle: %v", err)
	}
	if _, err := service.RegisterExposedSchema(ctx, access("req_gb_wrong_schema"), govBindWorkspaceA, wrongConnection, nil); governedask.CodeOf(err) != governedask.CodeConnectionUnavailable {
		t.Fatalf("wrong connection schema: %v", err)
	}
	if _, err := service.Promote(ctx, access("req_gb_wrong_promote"), govBindWorkspaceA, wrongConnection, "gqat_unknown", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); governedask.CodeOf(err) != governedask.CodeConnectionUnavailable {
		t.Fatalf("wrong connection promotion: %v", err)
	}

	// Neither workspace has opted in yet: both are gated off, including A --
	// proving the connection's mounted WorkspaceID grants nothing by itself
	// any more.
	if err := ask(govBindWorkspaceA, "req_gb_ask_a_before"); governedask.CodeOf(err) != governedask.CodeLiveQueriesOff {
		t.Fatalf("workspace A before opt-in: code=%s err=%v, want GOVERNED_ASK_LIVE_QUERIES_DISABLED", governedask.CodeOf(err), err)
	}
	if err := ask(govBindWorkspaceB, "req_gb_ask_b_before"); governedask.CodeOf(err) != governedask.CodeLiveQueriesOff {
		t.Fatalf("workspace B before opt-in: code=%s err=%v, want GOVERNED_ASK_LIVE_QUERIES_DISABLED", governedask.CodeOf(err), err)
	}

	// Workspace B opts itself in. Before AGG-2 this returned CodeRequestInvalid
	// unconditionally (workspaceID != service.config.WorkspaceID, which is A).
	if err := service.SetLiveQueries(ctx, access("req_gb_enable_b"), govBindWorkspaceB, govBindConnection, true); err != nil {
		t.Fatalf("enable live queries for workspace B: %v (code=%s)", err, governedask.CodeOf(err))
	}

	// A is unaffected by B's opt-in.
	if err := ask(govBindWorkspaceA, "req_gb_ask_a_after_b"); governedask.CodeOf(err) != governedask.CodeLiveQueriesOff {
		t.Fatalf("workspace A after B opts in: code=%s err=%v, want still GOVERNED_ASK_LIVE_QUERIES_DISABLED", governedask.CodeOf(err), err)
	}
	// B is past the live-queries gate now (no exposed schema registered yet,
	// so the next typed refusal is CodeSchemaUnavailable, distinct from
	// CodeLiveQueriesOff -- proving B's own flag, not A's mounted identity,
	// is what gated it).
	if err := ask(govBindWorkspaceB, "req_gb_ask_b_after_enable"); governedask.CodeOf(err) != governedask.CodeSchemaUnavailable {
		t.Fatalf("workspace B after opt-in: code=%s err=%v, want GOVERNED_ASK_SCHEMA_UNAVAILABLE", governedask.CodeOf(err), err)
	}

	// Workspace A independently opts in too -- both workspaces share the
	// connection and each has its own live binding.
	if err := service.SetLiveQueries(ctx, access("req_gb_enable_a"), govBindWorkspaceA, govBindConnection, true); err != nil {
		t.Fatalf("enable live queries for workspace A: %v (code=%s)", err, governedask.CodeOf(err))
	}
	if err := ask(govBindWorkspaceA, "req_gb_ask_a_after_enable"); governedask.CodeOf(err) != governedask.CodeSchemaUnavailable {
		t.Fatalf("workspace A after opt-in: code=%s err=%v, want GOVERNED_ASK_SCHEMA_UNAVAILABLE", governedask.CodeOf(err), err)
	}

	// Disabling B's flag turns B off again while A, opted in independently,
	// stays on: the toggle is per (connection, workspace), never global to
	// the connection.
	if err := service.SetLiveQueries(ctx, access("req_gb_disable_b"), govBindWorkspaceB, govBindConnection, false); err != nil {
		t.Fatalf("disable live queries for workspace B: %v (code=%s)", err, governedask.CodeOf(err))
	}
	if err := ask(govBindWorkspaceB, "req_gb_ask_b_after_disable"); governedask.CodeOf(err) != governedask.CodeLiveQueriesOff {
		t.Fatalf("workspace B after disable: code=%s err=%v, want GOVERNED_ASK_LIVE_QUERIES_DISABLED", governedask.CodeOf(err), err)
	}
	if err := ask(govBindWorkspaceA, "req_gb_ask_a_still_on"); governedask.CodeOf(err) != governedask.CodeSchemaUnavailable {
		t.Fatalf("workspace A after B's disable: code=%s err=%v, want still GOVERNED_ASK_SCHEMA_UNAVAILABLE (unaffected by B)", governedask.CodeOf(err), err)
	}

	// Direct database proof beside the black-box behaviour above: exactly one
	// governed_query_connection row (the connection is shared, not
	// duplicated), and two independent binding rows with the exact
	// live_queries_enabled state each workspace's own calls set.
	var connectionRows int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.governed_query_connection WHERE organization_id=$1 AND id=$2`,
		govBindOrg, govBindConnection).Scan(&connectionRows); err != nil {
		t.Fatal(err)
	}
	if connectionRows != 1 {
		t.Fatalf("governed_query_connection rows=%d, want exactly 1 shared connection", connectionRows)
	}
	var enabledA, enabledB bool
	if err := admin.QueryRow(ctx, `SELECT live_queries_enabled FROM public.governed_query_workspace_binding
		WHERE organization_id=$1 AND connection_id=$2 AND workspace_id=$3`,
		govBindOrg, govBindConnection, govBindWorkspaceA).Scan(&enabledA); err != nil {
		t.Fatalf("read workspace A binding: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT live_queries_enabled FROM public.governed_query_workspace_binding
		WHERE organization_id=$1 AND connection_id=$2 AND workspace_id=$3`,
		govBindOrg, govBindConnection, govBindWorkspaceB).Scan(&enabledB); err != nil {
		t.Fatalf("read workspace B binding: %v", err)
	}
	if !enabledA || enabledB {
		t.Fatalf("binding rows enabledA=%v enabledB=%v, want true/false", enabledA, enabledB)
	}

	// The optional preset catalogue is visible only after ordinary workspace
	// authorization and opt-in. Its reference is deliberately pinned to schema
	// revision 2 while the current exposed schema below is revision 1. The run
	// must refuse before dialling the intentionally unreachable external host.
	objects := []governedquery.ExposedObject{{
		SchemaName: "reporting", TableName: "contracts", Description: "Contracts",
		Columns: []governedquery.ExposedColumn{{Name: "id", DataType: "text", Description: "Contract identifier"}},
	}}
	objectsJSON, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.governed_query_exposed_schema
		(organization_id, connection_id, revision, objects_json, revision_hash, created_by)
		VALUES ($1,$2,1,$3::jsonb,$4,$5)`, govBindOrg, govBindConnection, string(objectsJSON), canon.Hash(objectsJSON), govBindOwner); err != nil {
		t.Fatalf("seed preset schema: %v", err)
	}
	presetSQL := "SELECT count(*) FROM reporting.contracts"
	if _, err := admin.Exec(ctx, `INSERT INTO public.governed_query_attempt
		(organization_id, id, connection_id, workspace_id, exposed_schema_revision, sql_hash, sql_text, row_count, executed_by)
		VALUES ($1,$2,$3,$4,2,$5,$6,1,$7)`, govBindOrg, "gqat_reviewed", govBindConnection,
		govBindWorkspaceA, canon.Hash([]byte(presetSQL)), presetSQL, govBindOwner); err != nil {
		t.Fatalf("seed reviewed preset attempt: %v", err)
	}
	catalog, err := service.ListPresets(ctx, access("req_gb_preset_list"), govBindWorkspaceA, govBindConnection)
	if err != nil || len(catalog.Presets) != 1 || catalog.Presets[0].ID != "contract-count" {
		t.Fatalf("list governed presets: catalog=%+v err=%v", catalog, err)
	}
	if err := service.SetLiveQueries(ctx, access("req_gb_reenable_b_for_catalog"), govBindWorkspaceB, govBindConnection, true); err != nil {
		t.Fatalf("re-enable workspace B for catalogue isolation proof: %v", err)
	}
	otherCatalog, err := service.ListPresets(ctx, access("req_gb_preset_list_b"), govBindWorkspaceB, govBindConnection)
	if err != nil || len(otherCatalog.Presets) != 0 {
		t.Fatalf("preset metadata leaked across workspaces: catalog=%+v err=%v", otherCatalog, err)
	}
	if _, err := service.RunPreset(ctx, access("req_gb_preset_stale"), govBindWorkspaceA, govBindConnection, "contract-count"); governedask.CodeOf(err) != governedask.CodeRequestInvalid {
		t.Fatalf("stale preset revision must fail before external dial: code=%s err=%v", governedask.CodeOf(err), err)
	}
}
