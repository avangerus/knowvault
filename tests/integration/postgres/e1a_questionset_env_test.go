package postgres_test

// E-1a synthetic workspace builder. It seeds the real product schema through
// the production registration authority, ingests the synthetic documents
// through the real worker ingestion path, registers the synthetic PostgreSQL
// source relations, configures the query credential and composes the real
// Question Run tool runtime. No product code is stubbed except the model
// channel itself, which the caller supplies.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacecontext"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// e1aEnvOptions parameterizes the proving environment. A nil source SQL
// executor means the synthetic PostgreSQL source is registered but never
// executed (the stub-model smoke run).
type e1aEnvOptions struct {
	SourceIdentity string
	Credentials    map[string]string
	Roots          *x509.CertPool
	SourceSQL      *e1aSourceSQL
	DocumentRoot   string
	// ContractChecksum computes the synthetic contract table's row count and
	// checksum, or nil when no real source database is attached.
	ContractChecksum func(ctx context.Context) (string, error)
	// Origin overrides the tenant security origin the HTTP authenticator
	// enforces. Empty keeps kvA01Origin, so the question set is unchanged;
	// card U-1 passes the origin of its local stand.
	Origin string
	// LeaveSourcesUnconfirmed binds every PostgreSQL source scope to the
	// workspace, activates its projection, and stops before minting its
	// managed-source confirmation, so the workspace's Sources surface offers
	// the table confirmation action (card U-1). The document folder keeps its
	// normal confirmed, activated lifecycle.
	LeaveSourcesUnconfirmed bool
	// WireHTTPQuestions mounts the question service on the workspace handler so
	// the HTTP question routes the web interface uses are served (card U-1).
	// The question set calls the service directly and leaves this off.
	WireHTTPQuestions bool
	// H5Source is the synthetic PostgreSQL database source H5 asks about. It is
	// not bound by this builder: the run binds it through e1aH5Deferred when it
	// reaches H5, and leaves its table confirmation unminted, so the product
	// must answer that it cannot read the database yet. A nil source leaves
	// every other user of this builder in exactly the environment it had
	// before, and while it is nil the other questions also see exactly the
	// workspace they had before the card.
	H5Source *questions.SourceSpec
	// H5SourceIdentity is the database identity the H5 source registers with;
	// it is the identity of the H5 database container, not the shared source.
	H5SourceIdentity string
	// ConfirmH5Source mints the H5 source's table confirmation instead of
	// leaving it awaiting confirmation. The harness test uses it to prove the
	// H5 readiness check fails when the database's tables are confirmed.
	ConfirmH5Source bool
}

// e1aEnvironment is the composed proving environment.
type e1aEnvironment struct {
	Set              *questions.Set
	Admin            *pgxpool.Pool
	AppStore         *database.Store
	Codec            *artifactcrypto.Codec
	Authority        *workspacerepository.Store
	ContextStore     *workspacecontext.Store
	Questions        *question.Service
	Handler          *workspaceapi.Handler
	SourceService    e1aSourceService
	FolderConnection string
	// SourceConnectionIDs maps the question set's source id to its real
	// product connection id.
	SourceConnectionIDs map[string]string
	ContractChecksum    func(ctx context.Context) (string, error)
	// H5SourceID and H5SourceName are the product connection id and human name
	// of the database H5 asks about. They are empty until the run reaches H5
	// and binds it through e1aH5Deferred.
	H5SourceID   string
	H5SourceName string
	// h5 is what deferred H5 binding needs; nil when the environment has no H5
	// source.
	h5 *e1aH5Deferred
}

// buildE1aEnvironment seeds the synthetic product workspace.
func buildE1aEnvironment(t *testing.T, ctx context.Context, admin *pgxpool.Pool, set *questions.Set, opts e1aEnvOptions) *e1aEnvironment {
	t.Helper()
	if admin == nil {
		t.Fatal("product database admin pool is required")
	}
	appStore, codec, registrations := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	authority, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("workspace repository: %v", err)
	}
	contextStore, err := workspacecontext.NewStore(appStore, authority, auditStore)
	if err != nil {
		t.Fatalf("workspace context store: %v", err)
	}

	// 1. Register the synthetic document folder through the production
	// registration authority.
	folderRequest := registration.RegisterRequest{
		Name: "Регламенты и договоры", RootAlias: regRootAls, RootIdentity: regRootID,
		RelativeRoot: "projects/alpha", Kind: "documents", Recursive: true,
		IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
		OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN"},
	}
	folder, err := registrations.Register(ctx, regOwnerAccess("req_e1a_folder"), folderRequest)
	if err != nil {
		t.Fatalf("register document source: %v (code=%s)", err, registration.CodeOf(err))
	}

	// 2. Write the synthetic documents and ingest them through the real worker
	// handler.
	root := opts.DocumentRoot
	if root == "" {
		root = t.TempDir()
	}
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, document := range set.Environment.Documents {
		if err := os.WriteFile(filepath.Join(directory, document.File), []byte(document.Text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	folderFixture := seedRegistrationWorkspaceBinding(t, ctx, admin, folder.SourceScopeID,
		e1aScopeConfigHash(t, ctx, admin, folder.SourceScopeID), mustID(t, "binding"))
	e1aMintConfirmation(t, ctx, folderFixture)
	verifyIsolationTrust(t, ctx, admin, folder.ConnectionID)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatalf("job queue: %v", err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, regMounts{root: root}, regWorkerID, time.Now, ids.New)
	e1aActivateAndSync(t, ctx, registrations, queue, ingest, folder.SourceScopeID, "e1a-documents")

	// 3. Register the synthetic PostgreSQL source relations, verify trust,
	// activate them and bind them to the same workspace.
	connectionIDs := map[string]string{}
	for index, source := range set.Environment.Sources {
		request := registration.RegisterRequest{
			SourceType: "POSTGRESQL_QUERY", Name: source.Name, Kind: "business-objects",
			DatabaseIdentity: opts.SourceIdentity, LineageID: source.LineageID, ProjectionRevision: 1,
			ContractHash: sourceContractHash(source), SchemaName: set.Environment.SourceSchema,
			RelationName: source.Table, RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
			Columns: sourceColumns(set, source),
		}
		registered, err := registrations.Register(ctx, regOwnerAccess(fmt.Sprintf("req_e1a_source_%d", index)), request)
		if err != nil {
			t.Fatalf("register source %s: %v (code=%s)", source.Table, err, registration.CodeOf(err))
		}
		connectionIDs[source.ID] = registered.ConnectionID
		sourceFixture := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID,
			e1aScopeConfigHash(t, ctx, admin, registered.SourceScopeID), mustID(t, "binding"))
		if opts.LeaveSourcesUnconfirmed {
			// The binding stays unconfirmed, so the Sources surface offers the
			// table confirmation action. Trust verification and an ACTIVE
			// projection are still required: the question tool loop discloses a
			// run only while every enabled binding is trust-verified, and the
			// workspace model context resolves its data locations against
			// ACTIVE projections.
			verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
			e1aActivateSource(t, ctx, admin, registered.SourceScopeID)
			continue
		}
		e1aMintConfirmation(t, ctx, sourceFixture)
		verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
		e1aActivateSource(t, ctx, admin, registered.SourceScopeID)
		if opts.SourceSQL != nil {
			reference, referenceErr := ids.New("cred")
			if referenceErr != nil {
				t.Fatalf("credential reference: %v", referenceErr)
			}
			opts.SourceSQL.credentials[reference] = opts.Credentials[source.ID]
			if err := authority.SetSourceQueryCredential(ctx, regOwnerAccess("req_e1a_cred_"+source.ID), regWorkspace, registered.ConnectionID, reference); err != nil {
				t.Fatalf("configure query credential for %s: %v", source.Table, err)
			}
		}
	}

	// 3b. Card E-2: the database H5 asks about is only prepared here. Binding
	// it changes the workspace's source list, so the run binds it when it
	// reaches H5; every other question is then asked in exactly the workspace
	// it had before the card. The block is skipped for every caller that did
	// not ask for the source, so the other users of this builder keep the
	// environment they had.
	var h5 *e1aH5Deferred
	if opts.H5Source != nil {
		h5 = &e1aH5Deferred{
			registrations: registrations,
			source:        *opts.H5Source,
			identity:      opts.H5SourceIdentity,
			confirm:       opts.ConfirmH5Source,
		}
	}

	// 4. Seed the workspace model context (dictionary) with the two terms the
	// card requires.
	document := workspacecontext.Document{
		Description: set.Environment.Dictionary.Description,
		Rules:       []workspacecontext.Rule{},
		Glossary:    []workspacecontext.Term{},
		Sources:     []workspacecontext.Source{},
	}
	for _, rule := range set.Environment.Dictionary.Rules {
		document.Rules = append(document.Rules, workspacecontext.Rule{Text: rule.Text})
	}
	known := map[string]string{}
	for _, source := range set.Environment.Sources {
		known[source.ID] = connectionIDs[source.ID]
	}
	for _, term := range set.Environment.Dictionary.Terms {
		entry := workspacecontext.Term{Term: term.Term, Synonyms: append([]string(nil), term.Synonyms...), Definition: term.Definition}
		for _, location := range term.Locations {
			connectionID, ok := known[location.Source]
			if !ok {
				continue
			}
			entry.DataLocations = append(entry.DataLocations, workspacecontext.DataLocation{
				SourceConnectionID: connectionID,
				Relation:           set.Environment.SourceSchema + "." + location.Relation,
				Column:             location.Column,
			})
		}
		document.Glossary = append(document.Glossary, entry)
	}
	contextAccess := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_e1a_context"}
	if _, err := contextStore.Save(ctx, contextAccess, regWorkspace, document, "sha256:empty", e1aIdempotencyKey("context-save")); err != nil {
		t.Fatalf("save workspace dictionary: %v (code=%s)", err, workspacecontext.CodeOf(err))
	}

	// 5. Compose the real question service and tool runtime.
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("evidence viewer: %v", err)
	}
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("conversation service: %v", err)
	}
	questionsService, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatalf("question service: %v", err)
	}
	if err := questionsService.EnableWorkspaceContext(contextStore); err != nil {
		t.Fatalf("enable workspace context: %v", err)
	}
	if opts.SourceSQL != nil {
		opts.SourceSQL.workspaces = authority
		opts.SourceSQL.auditor = auditStore
	}
	sourceService := e1aSourceService{registrations: registrations, workspaces: authority, sql: opts.SourceSQL}
	authenticator, err := httpauth.New(
		kvA01TenantResolver{organizationID: regOrg, origin: opts.Origin},
		kvA01SessionResolver{organizationID: regOrg, principalID: regOwner, claims: kvA01Claims(t, regOrg, regOwner)},
	)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	var httpQuestions workspaceapi.QuestionService
	if opts.WireHTTPQuestions {
		httpQuestions = questionsService
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(authenticator, authority, sourceService, viewer, httpQuestions, conversations)
	if err != nil {
		t.Fatalf("workspace handler: %v", err)
	}
	questionsService.EnableToolLoop(handler)

	return &e1aEnvironment{
		Set: set, Admin: admin, AppStore: appStore, Codec: codec, Authority: authority,
		ContextStore: contextStore, Questions: questionsService, Handler: handler,
		SourceService: sourceService, FolderConnection: folder.ConnectionID,
		SourceConnectionIDs: connectionIDs, ContractChecksum: opts.ContractChecksum,
		h5: h5,
	}
}

// e1aScopeConfigHash reads the scope revision's committed config hash.
func e1aScopeConfigHash(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeID string) string {
	t.Helper()
	var hash string
	if err := admin.QueryRow(ctx, `SELECT scope_config_hash FROM public.source_scope_revision
		WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, scopeID).Scan(&hash); err != nil {
		t.Fatalf("read scope config hash: %v", err)
	}
	return hash
}

// e1aActivateAndSync places the production activation job and runs it through
// the real worker ingestion handler.
func e1aActivateAndSync(t *testing.T, ctx context.Context, registrations *registration.Service,
	queue *jobs.Queue, handler *ingestion.Handler, scopeID, label string) {
	t.Helper()
	activated, err := registrations.Activate(ctx, regOwnerAccess("req_"+label), registration.ActivateRequest{
		IdempotencyKey: label, SourceScopeID: scopeID,
	})
	if err != nil {
		t.Fatalf("activate %s: %v (code=%s)", label, err, registration.CodeOf(err))
	}
	claimed, ok, err := queue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if claimed.ID != activated.JobID {
		t.Fatalf("worker claimed %q, want activation job %q", claimed.ID, activated.JobID)
	}
	if err := handler.Handle(ctx, workerAccess(t, regOrg), claimed); err != nil {
		t.Fatalf("handle %s: %v (code=%s)", label, err, ingestion.CodeOf(err))
	}
}

// e1aMintConfirmation mints the production actor grant and managed-source
// confirmation the worker's claim-time liveness check requires.
func e1aMintConfirmation(t *testing.T, ctx context.Context, fixture authorityOpsFixture) {
	t.Helper()
	store := newAuthorityRuntime(t, ctx)
	label := mustID(t, "qset")
	grant := issueRuntimeGrant(t, ctx, store, fixture, label+"-grant")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_"+label+"-confirm"),
		confirmRuntimeRequest(fixture, grant, label+"-confirm")); err != nil {
		t.Fatalf("mint managed source confirmation: %v", err)
	}
}

// e1aActivateSource drives the production DRAFT -> SYNCING -> READY activation
// lifecycle the SQL execution gate requires, without running a data sync.
func e1aActivateSource(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeID string) {
	t.Helper()
	for _, status := range []string{"SYNCING", "READY"} {
		if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
			SET status=$3 WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1 AND revision=1`,
			regOrg, scopeID, status); err != nil {
			t.Fatalf("advance source activation to %s: %v", status, err)
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope SET active_revision=1 WHERE organization_id=$1 AND id=$2`, regOrg, scopeID); err != nil {
		t.Fatalf("pin source active revision: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.postgresql_query_projection SET status='ACTIVE'
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, scopeID); err != nil {
		t.Fatalf("activate registered projection: %v", err)
	}
}

func sourceContractHash(source questions.SourceSpec) string {
	raw, err := canon.CanonicalJSON(source.Columns)
	if err != nil {
		return "sha256:" + strings.Repeat("a", 64)
	}
	return canon.Hash(raw)
}

// sourceColumns builds the registered projection for one synthetic table.
func sourceColumns(set *questions.Set, source questions.SourceSpec) []postgresqlquery.Column {
	table := set.Environment.Tables[source.ID]
	columns := make([]postgresqlquery.Column, 0, len(source.Columns))
	for index, name := range source.Columns {
		column := postgresqlquery.Column{
			Ordinal: index + 1, Name: name, TypeFingerprint: "oid:25",
			LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 256,
		}
		if name == table.IdentityColumn {
			column.Roles = []postgresqlquery.Role{postgresqlquery.RoleIdentity}
			column.TypeFingerprint = "oid:23"
			column.LogicalType = postgresqlquery.TypeInt
			column.MaxBytes = 16
		}
		switch name {
		case "signed_on":
			column.TypeFingerprint = "oid:1082"
			column.LogicalType = postgresqlquery.TypeDate
			column.MaxBytes = 32
		case "amount":
			column.TypeFingerprint = "oid:1700:p:14:s:2"
			column.LogicalType = postgresqlquery.TypeNumeric
			column.Precision = 14
			column.Scale = 2
			column.MaxBytes = 64
		}
		columns = append(columns, column)
	}
	return columns
}

// e1aIdempotencyKey returns a fresh 32-byte idempotency key.
func e1aIdempotencyKey(label string) string {
	key := make([]byte, 32)
	copy(key, []byte(label))
	for index := len(label); index < len(key); index++ {
		key[index] = byte(index)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

var e1aQuestionRunCounter atomic.Int64

// e1aRunQuestionSet executes every question of the set three times and judges
// each answer. The model channel is whatever the caller enabled on the
// service.
func e1aRunQuestionSet(t *testing.T, ctx context.Context, env *e1aEnvironment, profileFor func(questions.Question) string) []questions.RunReport {
	t.Helper()
	// Card D-15: this run measures recognition, so the question set asks the
	// service to recognise every question's kind in a separate short model call
	// and the runner reports it per run. The answers themselves are unchanged.
	env.Questions.EnableAnswerKindRecognition()
	only := map[string]bool{}
	if value := strings.TrimSpace(os.Getenv("KNOWVAULT_QUESTION_SET_ONLY")); value != "" {
		for _, id := range strings.Split(value, ",") {
			only[strings.TrimSpace(id)] = true
		}
	}
	runs := []questions.RunReport{}
	// Card E-2: H5's database is bound when the run reaches H5, so every
	// question before it is asked in exactly the workspace it had before the
	// card. A question after H5 would see a workspace the earlier questions
	// never had.
	h5Bound := false
	for _, item := range env.Set.Questions {
		if len(only) > 0 && !only[item.ID] {
			continue
		}
		if h5Bound && item.ID != "H5" {
			t.Fatalf("question %s runs after H5 and would see the H5 database; keep H5 last", item.ID)
		}
		for runIndex := 1; runIndex <= 3; runIndex++ {
			contractBefore := ""
			if item.ID == "H4" && env.ContractChecksum != nil {
				value, err := env.ContractChecksum(ctx)
				if err != nil {
					t.Fatalf("checksum synthetic contract table: %v", err)
				}
				contractBefore = value
			}
			// Card E-2: bind the database H5 asks about now, and read the
			// product's own source status for it immediately before asking. H5
			// only tests the product's "cannot be read yet" answer while the
			// tables await confirmation, so a confirmed database is a harness
			// error, never an answer failure.
			h5Confirmation := e1aH5Confirmation{}
			if item.ID == "H5" && env.h5 != nil {
				env.e1aBindH5Source(t, ctx)
				h5Bound = true
				confirmation, confirmErr := e1aReadH5Confirmation(ctx, env)
				if confirmErr != nil {
					t.Fatalf("H5 database must await confirmation just before it is asked about: %v", confirmErr)
				}
				h5Confirmation = confirmation
			}
			key := e1aIdempotencyKey(fmt.Sprintf("%s-run-%d-%d", item.ID, runIndex, e1aQuestionRunCounter.Add(1)))
			access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: fmt.Sprintf("req_e1a_%s_%d", item.ID, runIndex)}
			started := time.Now()
			run, err := env.Questions.Create(ctx, access, question.CreateRequest{
				WorkspaceID: regWorkspace, Question: item.Text,
				ModelProfileID: profileFor(item), IdempotencyKey: key,
			})
			elapsed := time.Since(started).Seconds()
			report := questions.RunReport{
				QuestionID: item.ID, QuestionText: item.Text, Run: runIndex, Seconds: elapsed,
				Status: "FAILED", StopReason: "RUN_ERROR", Answer: "", ToolCalls: []questions.ToolCall{},
			}
			if err != nil {
				report.Answer = "question run failed: " + string(question.CodeOf(err))
				report.StopReason = "RUN_ERROR"
			} else {
				report = e1aObserveRun(item, runIndex, run, elapsed)
			}
			// The confirmation read belongs to this run even when the run
			// itself failed, so it is set after the observed run replaces the
			// report.
			report.DatabaseName = h5Confirmation.SourceName
			report.DatabaseAwaitingConfirmation = h5Confirmation.Awaiting
			contractUnchanged := true
			if item.ID == "H4" && env.ContractChecksum != nil {
				after, checksumErr := env.ContractChecksum(ctx)
				if checksumErr != nil {
					t.Fatalf("re-checksum synthetic contract table: %v", checksumErr)
				}
				contractUnchanged = contractBefore == after
			}
			observation := questions.Observation{
				QuestionID: item.ID, QuestionText: item.Text, QuestionLang: item.Language,
				Answer: report.Answer, Status: report.Status, StopReason: report.StopReason,
				GroundingStatus: report.GroundingStatus, Seconds: elapsed,
				InputTokens: report.InputTokens, OutputTokens: report.OutputTokens,
				Citations: report.Citations, ToolCalls: report.ToolCalls, SQLTexts: report.SQLTexts,
				LiveResultKind: report.LiveResultKind, LiveResultReceipt: report.LiveResultReceipt,
				ContractUnchanged: contractUnchanged, StatusFieldName: "status",
			}
			report.Verdicts = questions.Evaluate(env.Set, item, observation)
			report.Passed = true
			for _, verdict := range report.Verdicts {
				if !verdict.Passed && verdict.Hard {
					report.Passed = false
				}
			}
			runs = append(runs, report)
			fmt.Printf("E1A RUN %s run=%d steps=%d seconds=%.2f tokens_in=%d tokens_out=%d\n",
				item.ID, runIndex, report.Steps, report.Seconds, report.InputTokens, report.OutputTokens)
		}
	}
	return runs
}

// e1aObserveRun projects one product Question Run into a judgeable report row.
func e1aObserveRun(item questions.Question, runIndex int, run question.Run, elapsed float64) questions.RunReport {
	report := questions.RunReport{
		QuestionID: item.ID, QuestionText: item.Text, Run: runIndex, Seconds: elapsed,
		Status: run.ResultStatus, StopReason: "ANSWER", GroundingStatus: string(run.GroundingStatus),
		Answer: run.Answer, ToolCalls: []questions.ToolCall{}, SQLTexts: []string{},
	}
	if run.ToolLoop != nil {
		report.StopReason = run.ToolLoop.StopReason
		report.InputTokens = run.ToolLoop.Usage.Input
		report.OutputTokens = run.ToolLoop.Usage.Output
		// Card D-15: the kind the separate recognition step returned for this
		// run, and that step's own token cost. The recognition tokens are part
		// of the run's honest total while remaining visible on their own.
		report.Kind = run.ToolLoop.AnswerKind
		if run.ToolLoop.AnswerKindUsage != nil {
			report.KindInputTokens = run.ToolLoop.AnswerKindUsage.Input
			report.KindOutputTokens = run.ToolLoop.AnswerKindUsage.Output
			report.InputTokens += report.KindInputTokens
			report.OutputTokens += report.KindOutputTokens
		}
		for _, call := range run.ToolLoop.Calls {
			if call.System || call.Name == "submit_answer" {
				// Automatic citation reads and the final answer submission are
				// the product's own reserve, not model-requested steps.
				continue
			}
			arguments := string(call.Arguments)
			report.ToolCalls = append(report.ToolCalls, questions.ToolCall{
				Name: call.Name, Arguments: arguments, MainArgument: e1aMainArgument(call.Name, arguments),
			})
			if call.Name == "knowvault_source_sql" {
				if sqlText := e1aSQLText(arguments); sqlText != "" {
					report.SQLTexts = append(report.SQLTexts, sqlText)
				}
			}
		}
	}
	report.Steps = len(report.ToolCalls)
	if run.AnswerResult != nil {
		report.LiveResultKind = run.AnswerResult.Kind
		report.LiveResultReceipt = run.AnswerResult.ReceiptDigest
		if report.LiveResultReceipt == "" {
			report.LiveResultReceipt = run.AnswerResult.ResultDigest
		}
	}
	for _, citation := range run.Citations {
		report.Citations = append(report.Citations, questions.Citation{
			Address: citation.Address, Excerpt: citation.Excerpt,
		})
	}
	return report
}

// e1aMainArgument picks the tool call's human-relevant main argument, and for
// the same-source rule the source or document identity.
func e1aMainArgument(name, arguments string) string {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
		return ""
	}
	pick := func(keys ...string) string {
		for _, key := range keys {
			if value, ok := decoded[key]; ok {
				if text, ok := value.(string); ok {
					return text
				}
			}
		}
		return ""
	}
	switch name {
	case "knowvault_source_sql", "knowvault_source_schema":
		return pick("source_id")
	case "knowvault_read", "knowvault_evidence_read":
		return pick("address", "fragment_id")
	case "knowvault_search", "knowvault_grep":
		return pick("query", "pattern", "fragment_id")
	case "knowvault_related":
		return pick("fragment_id", "address")
	}
	return pick("query", "source_id", "fragment_id", "address", "limit")
}

func e1aSQLText(arguments string) string {
	var decoded struct {
		SQL string `json:"sql"`
	}
	if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
		return ""
	}
	return decoded.SQL
}

// e1aQuestionProfile maps a question to the mounted profile whose step budget
// is the question's own limit (the mounted profile floor is two turns).
func e1aQuestionProfile(question questions.Question) string {
	limit := question.MaxSteps
	if limit < 2 {
		limit = 2
	}
	return fmt.Sprintf("steps-%d", limit)
}
