package postgres_test

// RED proof for R1-C2.6b-4a1a: one admitted PostgreSQL source. This mini-card
// covers only the positive path and detached proof: a fully admitted,
// workspace-managed PostgreSQL source is resolved through
// Store.ResolvePostgreSQLAuthority, and the returned value must be an immutable,
// accessor-only projection that exposes the current workspace revision and
// configuration hash, the exact requested tuple, a valid detached
// postgresqlquery.Projection, and valid server-owned postgresqlquery.Limits.
// The result must carry no connection credential/reference, DSN, SQL, rows,
// model DTO or evidence receipt. No negative mutations are exercised here.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	authorityCredentialSentinel = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	authorityDSNSentinel        = "postgres://kv-secret:password@admission.invalid:5432/knowvault"
	authoritySQLSentinel        = "SELECT route_id, collected_at, tonnes, note FROM public.admission_view"
)

func TestPostgreSQLSourceAuthorityAdmission(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	// 1. Registration tenant: org, members, app Store, audit, jobs, service.
	_, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	// 2. Register one real PostgreSQL query projection (registration-owned ids).
	req := isolationProjectionRequest("kv_pgq_admission", "admission_view", "admission-lineage",
		"Admission operations", "sha256:"+strings.Repeat("7", 64))
	req.CredentialReference = authorityCredentialSentinel
	req.MaxRows = 73
	req.MaxColumns = len(req.Columns)
	req.MaxFieldBytes = 512
	req.MaxRowBytes = 2048
	req.MaxTotalBytes = 8192
	req.StatementTimeoutMS = 2500
	registered, err := service.Register(ctx, regOwnerAccess("req_admission_register"), req)
	if err != nil {
		t.Fatalf("register admission projection: %v (dsn=%s)", err, authorityDSNSentinel)
	}
	if registered.SourceScopeID == "" || registered.ScopeConfigHash == "" {
		t.Fatalf("register returned no scope identity: %#v", registered)
	}
	if registered.CredentialReference != authorityCredentialSentinel {
		t.Fatalf("registration credential reference = %q, want the valid opaque sentinel", registered.CredentialReference)
	}

	// 3. VERIFIED trust for the connection, then the WORKSPACE_MANAGED binding.
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin,
		registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAD")

	// 4. Issue the runtime grant and confirm the managed source.
	runtime := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, runtime, binding, "admission-grant")
	if _, err := runtime.ConfirmManagedSource(ctx,
		authorityAccess(binding, regOwner, "req_admission_confirm"),
		confirmRuntimeRequest(binding, grant, "admission-confirm")); err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	// 5. Worker bootstrap: begin-sync, projection activation and scope publish.
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatalf("worker queue: %v", err)
	}
	workerAccess := workerAccess(t, regOrg)
	bootstrapScheduledScope(t, ctx, admin, workerStore, workerQueue, workerAccess,
		registered.SourceScopeID, jobs.TypePostgreSQLQuerySync, req.ContractHash)
	_ = codec

	workspaceID := binding.workspaceID
	workspaceSourceID := binding.workspaceSourceID
	wantProjection := postgresqlquery.Projection{
		ConnectionID:        registered.ConnectionID,
		DatabaseIdentity:    req.DatabaseIdentity,
		LineageID:           req.LineageID,
		Revision:            req.ProjectionRevision,
		ContractHash:        req.ContractHash,
		SchemaName:          req.SchemaName,
		RelationName:        req.RelationName,
		RelationKind:        req.RelationKind,
		Columns:             cloneAuthorityColumns(req.Columns),
		EmptySnapshotPolicy: req.EmptySnapshotPolicy,
	}
	wantLimits := postgresqlquery.Limits{
		MaxRows:            int(req.MaxRows),
		MaxColumns:         req.MaxColumns,
		MaxFieldBytes:      int(req.MaxFieldBytes),
		MaxRowBytes:        int(req.MaxRowBytes),
		MaxTotalBytes:      int(req.MaxTotalBytes),
		StatementTimeout:   time.Duration(req.StatementTimeoutMS) * time.Millisecond,
		TransactionTimeout: time.Duration(req.StatementTimeoutMS+120000) * time.Millisecond,
	}
	authorityRequest := workspacerepository.PostgreSQLAuthorityRequest{
		WorkspaceID:         workspaceID,
		WorkspaceSourceID:   workspaceSourceID,
		SourceScopeID:       registered.SourceScopeID,
		SourceScopeRevision: req.ProjectionRevision,
		ScopeConfigHash:     registered.ScopeConfigHash,
		AccessMode:          "WORKSPACE_MANAGED",
	}

	store := newAuthorityRuntime(t, ctx)
	ownerAccess := authorityAccess(binding, regOwner, "req_admission_resolve")

	got, err := store.ResolvePostgreSQLAuthority(ctx, ownerAccess, authorityRequest)
	if err != nil {
		t.Fatalf("resolve postgresql authority: %v", err)
	}
	assertNoExportedAuthorityResultFields(t, got)

	// Positive path: current workspace revision + configuration hash, and the
	// exact requested tuple.
	if got.WorkspaceRevision() != binding.workspaceRevision {
		t.Fatalf("workspace revision = %d, want %d", got.WorkspaceRevision(), binding.workspaceRevision)
	}
	if got.WorkspaceConfigurationHash() != binding.workspaceConfHash {
		t.Fatalf("workspace configuration hash = %q, want %q",
			got.WorkspaceConfigurationHash(), binding.workspaceConfHash)
	}
	if got.WorkspaceID() != workspaceID || got.WorkspaceSourceID() != workspaceSourceID ||
		got.SourceScopeID() != registered.SourceScopeID || got.SourceScopeRevision() != 1 ||
		got.ScopeConfigHash() != registered.ScopeConfigHash || got.AccessMode() != "WORKSPACE_MANAGED" {
		t.Fatalf("resolved tuple drifted: %#v", got)
	}

	// Detached, validated projection and server-owned limits.
	projection := got.Projection()
	if err := projection.Validate(); err != nil {
		t.Fatalf("projection invalid: %v", err)
	}
	limits := got.Limits()
	if err := limits.Validate(); err != nil {
		t.Fatalf("limits invalid: %v", err)
	}
	if !reflect.DeepEqual(projection, wantProjection) {
		t.Fatalf("projection = %#v, want %#v", projection, wantProjection)
	}
	if !reflect.DeepEqual(limits, wantLimits) {
		t.Fatalf("limits = %#v, want %#v", limits, wantLimits)
	}

	// Mutating nested values from the returned accessors must not change the
	// same result. Every accessor call returns a detached snapshot.
	if len(projection.Columns) == 0 || len(projection.Columns[0].Roles) == 0 {
		t.Fatal("projection has no nested column roles to detach")
	}
	projection.Columns[0].Name = "mutated"
	projection.Columns[0].Roles[0] = postgresqlquery.RoleTitle
	projection.Columns[0].Roles = append(projection.Columns[0].Roles, postgresqlquery.RoleEvidence)
	projection.Columns = append(projection.Columns, postgresqlquery.Column{Name: "forged"})
	limits.MaxRows++
	if gotAgain := got.Projection(); !reflect.DeepEqual(gotAgain, wantProjection) {
		t.Fatalf("same result projection was not detached: got %#v, want %#v", gotAgain, wantProjection)
	}
	if gotAgain := got.Limits(); !reflect.DeepEqual(gotAgain, wantLimits) {
		t.Fatalf("same result limits were not detached: got %#v, want %#v", gotAgain, wantLimits)
	}

	again, err := store.ResolvePostgreSQLAuthority(ctx, ownerAccess, authorityRequest)
	if err != nil {
		t.Fatalf("resolve postgresql authority (second): %v", err)
	}
	secondProjection := again.Projection()
	if err := secondProjection.Validate(); err != nil {
		t.Fatalf("second projection invalid: %v", err)
	}
	if !reflect.DeepEqual(secondProjection, wantProjection) {
		t.Fatalf("second resolution projection differs: got %#v, want %#v", secondProjection, wantProjection)
	}
	if !reflect.DeepEqual(again.Limits(), wantLimits) {
		t.Fatalf("second resolution limits differ: got %#v, want %#v", again.Limits(), wantLimits)
	}
	if got.WorkspaceRevision() != again.WorkspaceRevision() ||
		got.WorkspaceConfigurationHash() != again.WorkspaceConfigurationHash() ||
		got.WorkspaceID() != again.WorkspaceID() ||
		got.WorkspaceSourceID() != again.WorkspaceSourceID() ||
		got.SourceScopeID() != again.SourceScopeID() ||
		got.SourceScopeRevision() != again.SourceScopeRevision() ||
		got.ScopeConfigHash() != again.ScopeConfigHash() ||
		got.AccessMode() != again.AccessMode() {
		t.Fatalf("second resolution scalar accessors differ: first=%s second=%s", formatAuthorityResult(t, got), formatAuthorityResult(t, again))
	}

	// No secret or raw-material leakage in any accessor, formatting or JSON
	// surface. The credential sentinel is concrete; the DSN/SQL markers are
	// defensive generic markers, not values seeded in the result.
	rendered := formatAuthorityResult(t, got)
	data, err := jsonv2.Marshal(got)
	if err != nil {
		t.Fatalf("marshal authority result: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("authority result JSON = %s, want exactly {}", data)
	}
	combined := strings.ToLower(fmt.Sprintf("%+v", got) + fmt.Sprintf("%#v", got) + rendered + string(data))
	for _, marker := range []string{
		strings.ToLower(authorityCredentialSentinel),
		"postgres://",
		"postgresql://",
		"select ",
		"insert ",
		"update ",
		"delete ",
	} {
		if strings.Contains(combined, marker) {
			t.Fatalf("resolved projection leaked %q in %s", marker, combined)
		}
	}

	// Source-plane privilege loss must fail closed without returning the
	// database cause, SQL or credential metadata. Use a fresh request and
	// restore the runtime grant immediately after the resolver returns so the
	// following reauthorization race starts from the original fixture.
	privilegeRequest := workspacerepository.PostgreSQLAuthorityRequest{
		WorkspaceID:         workspaceID,
		WorkspaceSourceID:   workspaceSourceID,
		SourceScopeID:       registered.SourceScopeID,
		SourceScopeRevision: req.ProjectionRevision,
		ScopeConfigHash:     registered.ScopeConfigHash,
		AccessMode:          "WORKSPACE_MANAGED",
	}
	privilegeAccess := authorityAccess(binding, regOwner, "req_admission_projection_privilege")
	privilegeRestored := false
	restoreProjectionRead := func() {
		if privilegeRestored {
			return
		}
		if _, restoreErr := admin.Exec(context.Background(),
			`GRANT SELECT ON public.postgresql_query_projection TO knowvault_app`); restoreErr != nil {
			t.Errorf("restore postgresql projection read privilege: %v", restoreErr)
			return
		}
		privilegeRestored = true
	}
	defer restoreProjectionRead()
	if _, err := admin.Exec(ctx, `REVOKE SELECT ON public.postgresql_query_projection FROM knowvault_app`); err != nil {
		t.Fatalf("revoke postgresql projection read privilege: %v", err)
	}
	rejected, rejectedErr := store.ResolvePostgreSQLAuthority(ctx, privilegeAccess, privilegeRequest)
	restoreProjectionRead()
	if rejectedErr == nil {
		t.Fatalf("projection privilege loss resolved authority: result=%s", formatAuthorityResult(t, rejected))
	}
	if gotCode := workspacerepository.CodeOf(rejectedErr); gotCode != workspacerepository.CodePersistence {
		t.Fatalf("projection privilege loss error code = %q, want %q", gotCode, workspacerepository.CodePersistence)
	}
	if rejectedErr.Error() != string(workspacerepository.CodePersistence) {
		t.Fatalf("projection privilege loss error text = %q, want %q", rejectedErr.Error(), workspacerepository.CodePersistence)
	}
	if errors.Unwrap(rejectedErr) != nil {
		t.Fatalf("projection privilege loss exposed an underlying error: %v", errors.Unwrap(rejectedErr))
	}
	if rejected.WorkspaceID() != "" || rejected.WorkspaceRevision() != 0 ||
		rejected.WorkspaceConfigurationHash() != "" || rejected.WorkspaceSourceID() != "" ||
		rejected.SourceScopeID() != "" || rejected.SourceScopeRevision() != 0 ||
		rejected.ScopeConfigHash() != "" || rejected.AccessMode() != "" {
		t.Fatalf("projection privilege loss returned scalar authority accessors: %s", formatAuthorityResult(t, rejected))
	}
	safeError := strings.ToLower(rejectedErr.Error())
	for _, forbidden := range []string{
		"permission",
		"postgresql_query_projection",
		"select",
		strings.ToLower(authorityCredentialSentinel),
		"postgres://",
	} {
		if strings.Contains(safeError, forbidden) {
			t.Fatalf("projection privilege loss error leaked %q: %q", forbidden, rejectedErr.Error())
		}
	}

	// Reauthorization race: a resolver that has been admitted but has not yet
	// read the current workspace snapshot must re-check the principal before it
	// discloses the source authority. Hold the snapshot relation lock so the
	// resolver is observably waiting, commit the principal revocation, then
	// release the blocker and require a content-free NOT_FOUND result.
	raceCtx, cancelRace := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRace()
	blocker, err := admin.Begin(raceCtx)
	if err != nil {
		t.Fatalf("begin snapshot blocker: %v", err)
	}
	released := false
	releaseBlocker := func() {
		if released {
			return
		}
		released = true
		if rollbackErr := blocker.Rollback(context.Background()); rollbackErr != nil {
			t.Errorf("release snapshot blocker: %v", rollbackErr)
		}
	}
	defer releaseBlocker()
	if _, err := blocker.Exec(raceCtx, `LOCK TABLE public.workspace_revision_snapshot IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock workspace revision snapshot: %v", err)
	}

	type authorityResolution struct {
		result workspacerepository.PostgreSQLAuthorityResult
		err    error
	}
	done := make(chan authorityResolution, 1)
	go func() {
		result, resolveErr := store.ResolvePostgreSQLAuthority(raceCtx,
			authorityAccess(binding, regOwner, "req_admission_reauthorization_race"), authorityRequest)
		done <- authorityResolution{result: result, err: resolveErr}
	}()

	waiting := false
	pollDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(pollDeadline) {
		var observed bool
		if err := admin.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM pg_locks AS waiting_lock
				JOIN pg_class AS relation ON relation.oid = waiting_lock.relation
				JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
				JOIN pg_stat_activity AS activity ON activity.pid = waiting_lock.pid
				WHERE waiting_lock.locktype = 'relation'
				  AND waiting_lock.mode = 'AccessShareLock'
				  AND NOT waiting_lock.granted
				  AND namespace.nspname = 'public'
				  AND relation.relname = 'workspace_revision_snapshot'
				  AND activity.application_name = 'knowvault-runtime'
				  AND activity.wait_event_type = 'Lock'
			)`,
		).Scan(&observed); err != nil {
			releaseBlocker()
			t.Fatalf("poll for workspace snapshot lock wait: %v", err)
		}
		if observed {
			waiting = true
			break
		}
		select {
		case outcome := <-done:
			releaseBlocker()
			t.Fatalf("resolver completed before waiting for workspace snapshot lock: err=%v result=%s", outcome.err, formatAuthorityResult(t, outcome.result))
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !waiting {
		releaseBlocker()
		select {
		case outcome := <-done:
			t.Fatalf("resolver never waited for workspace snapshot lock: err=%v result=%s", outcome.err, formatAuthorityResult(t, outcome.result))
		case <-time.After(1 * time.Second):
			t.Fatal("resolver never waited for workspace snapshot lock within 8 seconds")
		}
	}

	disabled := false
	defer func() {
		if !disabled {
			return
		}
		if _, restoreErr := admin.Exec(context.Background(),
			`UPDATE public.principal SET status = 'ACTIVE', session_revision = session_revision + 1 WHERE organization_id = $1 AND id = $2`, regOrg, regOwner); restoreErr != nil {
			t.Errorf("restore principal status: %v", restoreErr)
		}
	}()
	if tag, err := admin.Exec(ctx, `
		UPDATE public.principal
		SET status = 'DISABLED', session_revision = session_revision + 1
		WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE'`, regOrg, regOwner); err != nil {
		releaseBlocker()
		t.Fatalf("disable principal during authority race: %v", err)
	} else if tag.RowsAffected() != 1 {
		releaseBlocker()
		t.Fatalf("disable principal during authority race affected %d rows, want 1", tag.RowsAffected())
	} else {
		disabled = true
	}

	releaseBlocker()
	var outcome authorityResolution
	select {
	case outcome = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("resolver did not finish after releasing workspace snapshot lock")
	}
	if outcome.err == nil {
		t.Fatalf("revoked principal resolved authority: result=%s", formatAuthorityResult(t, outcome.result))
	}
	if gotCode := workspacerepository.CodeOf(outcome.err); gotCode != workspacerepository.CodeNotFound {
		t.Fatalf("revoked principal error code = %q, want %q", gotCode, workspacerepository.CodeNotFound)
	}
	if outcome.err.Error() != string(workspacerepository.CodeNotFound) {
		t.Fatalf("revoked principal error text = %q, want %q", outcome.err.Error(), workspacerepository.CodeNotFound)
	}
	if outcome.result.WorkspaceID() != "" || outcome.result.WorkspaceRevision() != 0 ||
		outcome.result.WorkspaceConfigurationHash() != "" || outcome.result.WorkspaceSourceID() != "" ||
		outcome.result.SourceScopeID() != "" || outcome.result.SourceScopeRevision() != 0 ||
		outcome.result.ScopeConfigHash() != "" || outcome.result.AccessMode() != "" {
		t.Fatalf("revoked principal returned scalar authority accessors: %s", formatAuthorityResult(t, outcome.result))
	}
}

func assertNoExportedAuthorityResultFields(t *testing.T, got workspacerepository.PostgreSQLAuthorityResult) {
	t.Helper()
	typ := reflect.TypeOf(got)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("PostgreSQLAuthorityResult kind = %s, want struct", typ.Kind())
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("PostgreSQLAuthorityResult exposes exported field %q", field.Name)
		}
	}
}

// formatAuthorityResult renders every accessor of the resolved projection so the
// no-leak assertion covers the whole observable surface, not just JSON output.
func formatAuthorityResult(t *testing.T, got workspacerepository.PostgreSQLAuthorityResult) string {
	t.Helper()
	projection := got.Projection()
	limits := got.Limits()
	var out strings.Builder
	fmt.Fprintf(&out, "workspace_revision=%d workspace_configuration_hash=%q workspace_id=%q workspace_source_id=%q source_scope_id=%q source_scope_revision=%d scope_config_hash=%q access_mode=%q ",
		got.WorkspaceRevision(), got.WorkspaceConfigurationHash(), got.WorkspaceID(), got.WorkspaceSourceID(), got.SourceScopeID(), got.SourceScopeRevision(), got.ScopeConfigHash(), got.AccessMode())
	fmt.Fprintf(&out, "projection connection_id=%q database_identity=%q lineage_id=%q revision=%d contract_hash=%q schema=%q relation=%q relation_kind=%q empty_snapshot_policy=%q ",
		projection.ConnectionID, projection.DatabaseIdentity, projection.LineageID, projection.Revision, projection.ContractHash, projection.SchemaName, projection.RelationName, projection.RelationKind, projection.EmptySnapshotPolicy)
	for _, column := range projection.Columns {
		fmt.Fprintf(&out, "column ordinal=%d name=%q type_fingerprint=%q logical_type=%q roles=%v nullable=%t precision=%d scale=%d max_bytes=%d ",
			column.Ordinal, column.Name, column.TypeFingerprint, column.LogicalType, column.Roles, column.Nullable, column.Precision, column.Scale, column.MaxBytes)
	}
	fmt.Fprintf(&out, "limits max_rows=%d max_columns=%d max_field_bytes=%d max_row_bytes=%d max_total_bytes=%d statement_timeout=%s transaction_timeout=%s",
		limits.MaxRows, limits.MaxColumns, limits.MaxFieldBytes, limits.MaxRowBytes, limits.MaxTotalBytes, limits.StatementTimeout.String(), limits.TransactionTimeout.String())
	return out.String()
}

func cloneAuthorityColumns(input []postgresqlquery.Column) []postgresqlquery.Column {
	output := append([]postgresqlquery.Column(nil), input...)
	for index := range output {
		output[index].Roles = append([]postgresqlquery.Role(nil), input[index].Roles...)
	}
	return output
}
