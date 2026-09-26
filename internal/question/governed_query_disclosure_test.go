package question

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
)

type governedDisclosureRecorder struct {
	calls       int
	order       []string
	ctx         context.Context
	access      database.AccessContext
	workspaceID string
	disclosures []governedask.AttemptDisclosure
	err         error
	errs        []error
	onCall      func(int)
}

func (recorder *governedDisclosureRecorder) AskWorkspace(
	context.Context,
	database.AccessContext,
	string,
	string,
) (governedask.AskResult, error) {
	return governedask.AskResult{}, nil
}

func (recorder *governedDisclosureRecorder) ReauthorizeAttempt(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	disclosure governedask.AttemptDisclosure,
) error {
	recorder.calls++
	recorder.order = append(recorder.order, disclosure.AttemptID)
	recorder.ctx, recorder.access, recorder.workspaceID = ctx, access, workspaceID
	recorder.disclosures = append(recorder.disclosures, disclosure)
	if recorder.onCall != nil {
		recorder.onCall(recorder.calls)
	}
	if recorder.calls <= len(recorder.errs) {
		return recorder.errs[recorder.calls-1]
	}
	return recorder.err
}

func governedDisclosureDependency(runID string) *governedQueryDependency {
	return &governedQueryDependency{
		questionRunID: runID, attemptID: "gqat_" + runID,
		connectionID: "conn_live_001", sqlHash: "sha256:" + strings.Repeat("a", 64),
		exposedSchemaRevision: 7, resultDigest: "sha256:" + strings.Repeat("b", 64),
	}
}

func assertGovernedQuestionRefusal(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != want {
		t.Fatalf("refusal = %v, want content-free %s", err, want)
	}
	if typed.cause != nil || errors.Unwrap(err) != nil || err.Error() != string(want) {
		t.Fatalf("refusal = %#v, want exact bare %s without a cause", err, want)
	}
}

func TestAuthorizeGovernedQueryDisclosureForwardsCurrentAccessOnce(t *testing.T) {
	runID := "run_governed_current"
	dependency := governedDisclosureDependency(runID)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, kind := range []database.ActorKind{database.ActorKindHuman, database.ActorKindService} {
		t.Run(string(kind), func(t *testing.T) {
			access := questionAccess(kind)
			recorder := &governedDisclosureRecorder{}
			if err := authorizeGovernedQueryDisclosure(ctx, access, "workspace_live", runID, dependency, recorder); err != nil {
				t.Fatalf("accepted dependency refused: %v", err)
			}
			if recorder.calls != 1 || recorder.ctx != ctx || recorder.access != access || recorder.workspaceID != "workspace_live" {
				t.Fatalf("reauthorization = calls %d, same context %v, access %+v, workspace %q", recorder.calls, recorder.ctx == ctx, recorder.access, recorder.workspaceID)
			}
			want := governedask.AttemptDisclosure{
				AttemptID: dependency.attemptID, ConnectionID: dependency.connectionID,
				SQLHash: dependency.sqlHash, ExposedSchemaRevision: dependency.exposedSchemaRevision,
				ResultDigest: dependency.resultDigest,
			}
			if len(recorder.disclosures) != 1 || recorder.disclosures[0] != want {
				t.Fatalf("disclosure = %#v, want %#v", recorder.disclosures, want)
			}
		})
	}
}

func TestAuthorizeGovernedQueryDisclosureNilAndInvalidInputsDoNotCall(t *testing.T) {
	good := governedDisclosureDependency("run_governed_local")
	recorder := &governedDisclosureRecorder{}
	if err := authorizeGovernedQueryDisclosure(nil, database.AccessContext{}, "", "", nil, nil); err != nil {
		t.Fatalf("legacy nil dependency refused: %v", err)
	}
	if recorder.calls != 0 {
		t.Fatalf("legacy nil dependency made %d calls", recorder.calls)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	badBinding := *good
	badBinding.attemptID = "not-an-attempt"
	for _, testCase := range []struct {
		name        string
		ctx         context.Context
		access      database.AccessContext
		workspaceID string
		runID       string
		dependency  *governedQueryDependency
		missingAuth bool
	}{
		{name: "nil context", ctx: nil, access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: good.questionRunID, dependency: good},
		{name: "invalid access", ctx: context.Background(), access: database.AccessContext{}, workspaceID: "workspace_live", runID: good.questionRunID, dependency: good},
		{name: "invalid workspace", ctx: context.Background(), access: questionAccess(database.ActorKindHuman), workspaceID: "bad/workspace", runID: good.questionRunID, dependency: good},
		{name: "invalid run", ctx: context.Background(), access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: "bad/run", dependency: good},
		{name: "cross-run dependency", ctx: context.Background(), access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: "run_governed_other", dependency: good},
		{name: "invalid dependency", ctx: context.Background(), access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: good.questionRunID, dependency: &badBinding},
		{name: "missing reauthorizer", ctx: context.Background(), access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: good.questionRunID, dependency: good, missingAuth: true},
		{name: "typed nil context", ctx: (*scalarNilContext)(nil), access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: good.questionRunID, dependency: good},
		{name: "canceled context", ctx: canceled, access: questionAccess(database.ActorKindHuman), workspaceID: "workspace_live", runID: good.questionRunID, dependency: good},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var authority governedAttemptReauthorizer = recorder
			if testCase.missingAuth {
				authority = nil
			}
			before := recorder.calls
			err := authorizeGovernedQueryDisclosure(testCase.ctx, testCase.access, testCase.workspaceID,
				testCase.runID, testCase.dependency, authority)
			assertGovernedQuestionRefusal(t, err, CodeUnavailable)
			if recorder.calls != before {
				t.Fatalf("local refusal made a reauthorization call: before=%d after=%d", before, recorder.calls)
			}
		})
	}

	var typedNil governedAttemptReauthorizer = (*governedDisclosureRecorder)(nil)
	err := authorizeGovernedQueryDisclosure(context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_live", good.questionRunID, good, typedNil)
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)
	if recorder.calls != 0 {
		t.Fatalf("typed-nil reauthorizer made %d calls", recorder.calls)
	}
}

func TestAuthorizeGovernedQueryDisclosureCollapsesDenialAndCancellation(t *testing.T) {
	runID := "run_governed_refusal"
	dependency := governedDisclosureDependency(runID)
	access := questionAccess(database.ActorKindHuman)

	contentRefusal := &governedDisclosureRecorder{err: errors.New("hidden SQL binding refusal")}
	err := authorizeGovernedQueryDisclosure(context.Background(), access, "workspace_live", runID,
		dependency, contentRefusal)
	assertGovernedQuestionRefusal(t, err, CodeNotFound)
	if contentRefusal.calls != 1 {
		t.Fatalf("content refusal calls = %d, want exactly one", contentRefusal.calls)
	}

	err = authorizeGovernedQueryDisclosure(context.Background(), access, "workspace_live", runID,
		dependency, &governedask.Service{})
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)

	ctx, cancel := context.WithCancel(context.Background())
	recorder := &governedDisclosureRecorder{onCall: func(int) { cancel() }}
	err = authorizeGovernedQueryDisclosure(ctx, access, "workspace_live", runID, dependency, recorder)
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)
	if recorder.calls != 1 {
		t.Fatalf("during-call cancellation calls = %d, want exactly one", recorder.calls)
	}
}

func TestAuthorizeGovernedQueryDisclosuresRequiresEveryCurrentAttempt(t *testing.T) {
	runID := "run_governed_multi"
	first := *governedDisclosureDependency(runID)
	second := first
	second.attemptID = "gqat_run_governed_multi_2"
	second.sqlHash = "sha256:" + strings.Repeat("c", 64)
	third := first
	third.attemptID = "gqat_run_governed_multi_3"
	third.resultDigest = "sha256:" + strings.Repeat("d", 64)
	dependencies := []governedQueryDependency{first, second, third}
	access := questionAccess(database.ActorKindHuman)

	denied := &governedDisclosureRecorder{errs: []error{nil, errors.New("revoked second read"), nil}}
	err := authorizeGovernedQueryDisclosures(context.Background(), access, "workspace_live", runID, dependencies, denied)
	assertGovernedQuestionRefusal(t, err, CodeNotFound)
	wantAttempts := []string{first.attemptID, second.attemptID, third.attemptID}
	if denied.calls != len(dependencies) || !reflect.DeepEqual(denied.order, wantAttempts) {
		t.Fatalf("reauthorized only a prefix: calls=%d order=%v want=%v", denied.calls, denied.order, wantAttempts)
	}

	fatal := &governedBatchThenFatal{}
	err = authorizeGovernedQueryDisclosures(context.Background(), access, "workspace_live", runID, dependencies, fatal)
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)
	if fatal.calls != 2 {
		t.Fatalf("fatal reauthorization calls=%d, want abort at unavailable dependency", fatal.calls)
	}

	batchDenied := &governedDisclosureRecorder{errs: []error{errors.New("revoked first read"), nil}}
	deniedRuns, err := authorizeGovernedQueryDisclosureBatchMany(context.Background(), access, "workspace_live",
		[]string{runID}, map[string][]governedQueryDependency{runID: dependencies[:2]}, batchDenied, nil)
	if err != nil || !reflect.DeepEqual(deniedRuns, []string{runID}) || batchDenied.calls != 2 {
		t.Fatalf("batch multi-read reauthorization = denied %v err %v calls %d", deniedRuns, err, batchDenied.calls)
	}
}

type governedBatchThenFatal struct {
	calls int
}

func (authority *governedBatchThenFatal) AskWorkspace(
	context.Context,
	database.AccessContext,
	string,
	string,
) (governedask.AskResult, error) {
	return governedask.AskResult{}, nil
}

func (authority *governedBatchThenFatal) ReauthorizeAttempt(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	disclosure governedask.AttemptDisclosure,
) error {
	authority.calls++
	if authority.calls == 1 {
		return errors.New("revoked binding")
	}
	return (&governedask.Service{}).ReauthorizeAttempt(ctx, access, workspaceID, disclosure)
}

func TestAuthorizeGovernedQueryDisclosureBatchSortsDenialsAndAbortsFatal(t *testing.T) {
	alpha := governedDisclosureDependency("run_governed_alpha")
	beta := governedDisclosureDependency("run_governed_beta")
	legacy := "run_governed_legacy"
	dependencies := map[string]*governedQueryDependency{
		"run_governed_alpha": alpha,
		"run_governed_beta":  beta,
		"run_governed_extra": governedDisclosureDependency("run_governed_extra"),
	}
	orderedRecorder := &governedDisclosureRecorder{}
	orderedAlpha, orderedBeta := *alpha, *beta
	orderedDependencies := map[string]*governedQueryDependency{
		"run_governed_alpha": &orderedAlpha,
		"run_governed_beta":  &orderedBeta,
		"run_governed_extra": dependencies["run_governed_extra"],
	}
	orderedDependencies["run_governed_alpha"].connectionID = "conn_mounted"
	orderedDependencies["run_governed_beta"].connectionID = "conn_mounted"
	denied, err := authorizeGovernedQueryDisclosureBatch(context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_live", []string{legacy, "run_governed_beta", "run_governed_alpha", "run_governed_beta"}, orderedDependencies, orderedRecorder, nil)
	if err != nil || denied != nil || !reflect.DeepEqual(orderedRecorder.order, []string{alpha.attemptID, beta.attemptID}) {
		t.Fatalf("ordered batch = denied %v err %v calls %v", denied, err, orderedRecorder.order)
	}

	denier := &governedDisclosureRecorder{err: errors.New("denied live attempt")}
	denied, err = authorizeGovernedQueryDisclosureBatch(context.Background(), questionAccess(database.ActorKindService),
		"workspace_live", []string{legacy, "run_governed_beta", "run_governed_alpha", "run_governed_beta"}, dependencies, denier, nil)
	if err != nil || !reflect.DeepEqual(denied, []string{"run_governed_alpha", "run_governed_beta"}) {
		t.Fatalf("denials = %v, err = %v, want sorted present runs only", denied, err)
	}
	if !reflect.DeepEqual(denier.order, []string{alpha.attemptID, beta.attemptID}) {
		t.Fatalf("denial call order = %v, want sorted present dependencies", denier.order)
	}

	fatal := &governedBatchThenFatal{}
	denied, err = authorizeGovernedQueryDisclosureBatch(context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_live", []string{"run_governed_beta", "run_governed_alpha"}, dependencies, fatal, nil)
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)
	if denied != nil || fatal.calls != 2 {
		t.Fatalf("fatal batch = denied %v calls %d, want nil after two sorted attempts", denied, fatal.calls)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	denied, err = authorizeGovernedQueryDisclosureBatch(canceled, questionAccess(database.ActorKindHuman),
		"workspace_live", []string{"run_governed_alpha"}, map[string]*governedQueryDependency{"run_governed_alpha": alpha},
		&governedDisclosureRecorder{}, nil)
	assertGovernedQuestionRefusal(t, err, CodeUnavailable)
	if denied != nil {
		t.Fatalf("canceled batch denials = %v, want nil", denied)
	}
}

func TestGovernedQueryDependencyIsPrivateAndAbsentFromRunAndService(t *testing.T) {
	dependencyType := reflect.TypeOf(governedQueryDependency{})
	for index := 0; index < dependencyType.NumField(); index++ {
		if dependencyType.Field(index).IsExported() {
			t.Fatalf("governedQueryDependency exposes field %q", dependencyType.Field(index).Name)
		}
	}
	dependencyPointer := reflect.TypeOf((*governedQueryDependency)(nil))
	for _, publicType := range []reflect.Type{reflect.TypeOf(Run{}), reflect.TypeOf(Service{})} {
		for index := 0; index < publicType.NumField(); index++ {
			field := publicType.Field(index)
			if field.Type == dependencyPointer {
				t.Fatalf("%s carries governedQueryDependency through %q", publicType, field.Name)
			}
			if publicType == reflect.TypeOf(Run{}) && strings.Contains(strings.ToLower(field.Tag.Get("json")), "governed_query_dependency") {
				t.Fatalf("Run exposes governed dependency JSON field %q", field.Tag.Get("json"))
			}
		}
	}
	raw, err := jsonv2.Marshal(Run{ID: "run_public", Answer: "public answer"})
	if err != nil || strings.Contains(string(raw), "governed_query_dependency") || strings.Contains(string(raw), "gqat_") {
		t.Fatalf("Run JSON exposed governed dependency: %s err=%v", raw, err)
	}
}

func TestReadStoredRunGovernedGateIsPostTransactionPrivateAndFailClosed(t *testing.T) {
	function := readStoredRunDeclaration(t)
	body := function.Body.List
	local := false
	for _, statement := range body {
		declaration, ok := statement.(*ast.DeclStmt)
		if !ok {
			continue
		}
		generic, ok := declaration.Decl.(*ast.GenDecl)
		if !ok || generic.Tok != token.VAR {
			continue
		}
		for _, specification := range generic.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if ok && len(value.Names) == 1 && value.Names[0].Name == "retainedGovernedQueryDependencies" {
				local = value.Type != nil && batchGateTypeName(value.Type) == "[]governedQueryDependency" && len(value.Values) == 0
			}
		}
	}
	if !local {
		t.Fatal("readStoredRun does not keep the governed dependency in a private method local")
	}

	dbIndex, scalarIndex, governedIndex := -1, -1, -1
	for index, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if ok && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.db.Read" {
			dbIndex = index
		}
		if branch, ok := statement.(*ast.IfStmt); ok {
			if init, ok := branch.Init.(*ast.AssignStmt); ok && len(init.Rhs) == 1 {
				switch readGateCallName(init.Rhs[0]) {
				case "service.authorizeAnalyticScalarDisclosure":
					scalarIndex = index
				case "service.authorizeGovernedQueryDisclosures":
					governedIndex = index
				}
			}
		}
	}
	if dbIndex < 0 || scalarIndex <= dbIndex || governedIndex <= scalarIndex || governedIndex != len(body)-2 {
		t.Fatalf("read gate order db=%d scalar=%d governed=%d body=%d", dbIndex, scalarIndex, governedIndex, len(body))
	}
	governedBranch := body[governedIndex].(*ast.IfStmt)
	governedInit := governedBranch.Init.(*ast.AssignStmt)
	call := governedInit.Rhs[0].(*ast.CallExpr)
	wantArgs := []string{"ctx", "access", "workspaceID", "runID", "retainedGovernedQueryDependencies"}
	if len(call.Args) != len(wantArgs) {
		t.Fatalf("governed gate args = %d, want %d", len(call.Args), len(wantArgs))
	}
	for index, arg := range call.Args {
		if readGateCallName(arg) != wantArgs[index] {
			t.Fatalf("governed gate arg %d = %q, want %q", index, readGateCallName(arg), wantArgs[index])
		}
	}
	if len(governedBranch.Body.List) != 1 {
		t.Fatalf("governed refusal branch has %d statements, want one", len(governedBranch.Body.List))
	}
	refusal, ok := governedBranch.Body.List[0].(*ast.ReturnStmt)
	if !ok || !readGateReturnsZeroRun(refusal) || len(refusal.Results) != 2 {
		t.Fatal("governed refusal does not return exact zero Run and error")
	}
	if returned, ok := refusal.Results[1].(*ast.Ident); !ok || returned.Name != "err" {
		t.Fatal("governed refusal wraps or changes the gate error")
	}

	dbCall := body[dbIndex].(*ast.AssignStmt).Rhs[0]
	captures, statusChecks := 0, 0
	ast.Inspect(dbCall, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			if target, ok := assignment.Lhs[0].(*ast.Ident); ok && target.Name == "retainedGovernedQueryDependencies" {
				captures++
				if readGateCallName(assignment.Rhs[0]) != "structured.governedQueryDependencies" {
					t.Fatalf("governed dependency capture source = %q", readGateCallName(assignment.Rhs[0]))
				}
			}
		}
		if expression, ok := node.(*ast.CallExpr); ok && readGateCallName(expression) == "governedQueryAnswerResultsAllowedForStatus" {
			statusChecks++
			if len(expression.Args) != 4 || readGateCallName(expression.Args[0]) != "status" {
				t.Fatal("single-run status guard does not use the database result status")
			}
		}
		return true
	})
	if captures != 1 || statusChecks != 1 {
		t.Fatalf("transaction captures=%d status consistency checks=%d, want one each", captures, statusChecks)
	}
}

func TestReadStoredRunBatchGovernedGateDeniesWholeRunsAndAudits(t *testing.T) {
	function := readStoredRunBatchDeclaration(t)
	body := function.Body.List
	local := false
	for _, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || readGateCallName(assignment.Lhs[0]) != "retainedGovernedQueryDependencies" {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || readGateCallName(call) != "make" || len(call.Args) == 0 || batchGateTypeName(call.Args[0]) != "map[string][]governedQueryDependency" {
			continue
		}
		local = true
	}
	if !local {
		t.Fatal("readStoredRunBatch does not retain dependencies in a private local map")
	}
	dbCallIndex := -1
	for index, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if ok && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.db.Read" {
			dbCallIndex = index
		}
	}
	if dbCallIndex < 0 {
		t.Fatal("readStoredRunBatch no longer uses its governed artifact transaction")
	}
	captures, statusChecks := 0, 0
	ast.Inspect(body[dbCallIndex], func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && len(assignment.Rhs) == 1 {
			if index, ok := assignment.Lhs[0].(*ast.IndexExpr); ok && readGateCallName(index.X) == "retainedGovernedQueryDependencies" {
				captures++
				if readGateCallName(assignment.Rhs[0]) != "structured.governedQueryDependencies" {
					t.Fatalf("governed dependency map source = %q", readGateCallName(assignment.Rhs[0]))
				}
			}
		}
		if call, ok := node.(*ast.CallExpr); ok && readGateCallName(call) == "governedQueryAnswerResultsAllowedForStatus" {
			statusChecks++
			if len(call.Args) != 4 || readGateCallName(call.Args[0]) != "run.ResultStatus" {
				t.Fatal("batch status guard does not use the database result status")
			}
		}
		return true
	})
	if captures != 1 || statusChecks != 1 {
		t.Fatalf("batch transaction captures=%d status consistency checks=%d, want one each", captures, statusChecks)
	}

	gateIndex, candidateIndex := -1, -1
	scalarGateIndex := -1
	for index, statement := range body {
		if rangeStatement, ok := statement.(*ast.RangeStmt); ok && readGateCallName(rangeStatement.X) == "result" && rangeStatement.Tok == token.DEFINE {
			if len(rangeStatement.Body.List) == 1 {
				if assignment, ok := rangeStatement.Body.List[0].(*ast.AssignStmt); ok && len(assignment.Lhs) == 1 && readGateCallName(assignment.Lhs[0]) == "governedCandidateRunIDs" {
					candidateIndex = index
				}
			}
		}
		if assignment, ok := statement.(*ast.AssignStmt); ok && len(assignment.Lhs) == 2 && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.authorizeGovernedQueryDisclosureBatchMany" {
			gateIndex = index
			call := assignment.Rhs[0].(*ast.CallExpr)
			wantArgs := []string{"ctx", "access", "workspaceID", "governedCandidateRunIDs", "retainedGovernedQueryDependencies"}
			if len(call.Args) != len(wantArgs) {
				t.Fatalf("governed batch gate args = %d, want %d", len(call.Args), len(wantArgs))
			}
			for argIndex, argument := range call.Args {
				if readGateCallName(argument) != wantArgs[argIndex] {
					t.Fatalf("governed batch arg %d = %q, want %q", argIndex, readGateCallName(argument), wantArgs[argIndex])
				}
			}
		}
		if assignment, ok := statement.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.authorizeAnalyticScalarDisclosureBatch" {
			scalarGateIndex = index
		}
	}
	if candidateIndex <= scalarGateIndex+2 || scalarGateIndex < 0 || gateIndex <= candidateIndex || gateIndex < 1 {
		t.Fatalf("scalar/governed batch order = scalar %d candidates %d gate %d", scalarGateIndex, candidateIndex, gateIndex)
	}
	if rangeStatement, ok := body[gateIndex+2].(*ast.RangeStmt); !ok || readGateCallName(rangeStatement.X) != "governedDenied" || len(rangeStatement.Body.List) != 2 {
		t.Fatal("governed denial does not have a whole-run delete and one audit per run")
	} else {
		deleteStatement, ok := rangeStatement.Body.List[0].(*ast.ExprStmt)
		if !ok || readGateCallName(deleteStatement.X) != "delete" {
			t.Fatal("governed denial does not delete the whole run")
		}
		auditStatement, ok := rangeStatement.Body.List[1].(*ast.ExprStmt)
		if !ok || readGateCallName(auditStatement.X) != "service.recordStoredRunReadFailure" {
			t.Fatal("governed denial does not record one read failure outcome per run")
		}
		auditCall := auditStatement.X.(*ast.CallExpr)
		wantAuditArgs := []string{"ctx", "access", "workspaceID", "runID"}
		if len(auditCall.Args) != 5 {
			t.Fatalf("governed denial audit args = %d, want 5", len(auditCall.Args))
		}
		for index, argument := range auditCall.Args[:4] {
			if readGateCallName(argument) != wantAuditArgs[index] {
				t.Fatalf("governed denial audit arg %d = %q, want %q", index, readGateCallName(argument), wantAuditArgs[index])
			}
		}
		if !batchGateFreshNotFoundCause(auditCall.Args[4]) {
			t.Fatal("governed denial audit does not use a fresh bare CodeNotFound")
		}
	}
	if gateIndex+1 >= len(body) {
		t.Fatal("governed batch gate has no fatal refusal branch")
	}
	fatalBranch, ok := body[gateIndex+1].(*ast.IfStmt)
	if !ok || readGateCallName(fatalBranch.Cond) != "err != nil" || len(fatalBranch.Body.List) != 1 {
		t.Fatal("governed batch fatal branch is not immediate")
	}
	fatal, ok := fatalBranch.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(fatal.Results) != 2 {
		t.Fatal("governed batch fatal branch does not return two results")
	}
	if empty, ok := fatal.Results[0].(*ast.Ident); !ok || empty.Name != "nil" {
		t.Fatal("governed batch fatal branch returns a partial map")
	}
	if unchanged, ok := fatal.Results[1].(*ast.Ident); !ok || unchanged.Name != "err" {
		t.Fatal("governed batch fatal branch wraps its content-free error")
	}
	success, ok := body[len(body)-1].(*ast.ReturnStmt)
	if !ok || len(success.Results) != 2 || readGateCallName(success.Results[0]) != "result" || readGateCallName(success.Results[1]) != "nil" {
		t.Fatal("readStoredRunBatch does not return only the map surviving governed denial")
	}
}

func TestGovernedDependencyDeniedReadProducesOneContentFreeAuditOutcome(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := &Service{admission: journal}
	service.newID = func(prefix string) (string, error) { return prefix + "_0001", nil }
	service.now = func() time.Time { return time.Unix(0, 0).UTC() }
	access := questionAccess(database.ActorKindHuman)
	service.recordStoredRunReadFailure(context.Background(), access, "workspace_live", "run_governed_alpha", &Error{code: CodeNotFound})
	if len(journal.appended) != 1 {
		t.Fatalf("audit outcomes = %d, want one", len(journal.appended))
	}
	event := journal.appended[0]
	if event.Action != audit.ActionQuestionFailed || event.Outcome != audit.OutcomeFailed || event.ErrorCode == nil || *event.ErrorCode != "QUESTION_READ_DENIED" || event.Metadata.QuestionRunID == nil || *event.Metadata.QuestionRunID != "run_governed_alpha" {
		t.Fatalf("denied governed read outcome = %#v", event)
	}
}

func TestReadPathStatusGuardKeepsOnlyClarificationWithoutCompletedLiveReceipt(t *testing.T) {
	projection, dependency, record := livePersistenceFixture(t)
	if governedQueryAnswerResultAllowedForStatus("COMPLETED", &dependency, nil, record) {
		t.Fatal("completed live run without AnswerResult was allowed")
	}
	record.StopReason = "CLARIFICATION"
	if !governedQueryAnswerResultAllowedForStatus("COMPLETED", &dependency, nil, record) {
		t.Fatal("completed clarification without AnswerResult was refused")
	}
	answer := livePersistenceAnswer(t, projection, dependency)
	if !governedQueryAnswerResultAllowedForStatus("COMPLETED", &dependency, answer, record) {
		t.Fatal("completed live run with a bound AnswerResult was refused")
	}
}

func TestGovernedDisclosureSurfaceHasOnlyPrivateReauthorizer(t *testing.T) {
	const filename = "governed_query_disclosure.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var capability *ast.InterfaceType
	for _, declaration := range parsed.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, specification := range generic.Specs {
			named, ok := specification.(*ast.TypeSpec)
			if !ok || named.Name.Name != "governedAttemptReauthorizer" {
				continue
			}
			if named.Name.IsExported() {
				t.Fatal("governed reauthorizer interface is exported")
			}
			capability, _ = named.Type.(*ast.InterfaceType)
		}
	}
	if capability == nil || len(capability.Methods.List) != 2 {
		t.Fatalf("private governed capability = %v, want AskWorkspace plus ReauthorizeAttempt", capability)
	}
	if got := reflect.TypeOf((*governedAttemptReauthorizer)(nil)).Elem().NumMethod(); got != 2 {
		t.Fatalf("private governed capability methods = %d, want exactly two", got)
	}
	for _, sourceFile := range []string{"governed_query_disclosure.go", "governed_query_batch_disclosure.go"} {
		raw, err := os.ReadFile(sourceFile)
		if err != nil {
			t.Fatalf("read %s: %v", sourceFile, err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), sourceFile, raw, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", sourceFile, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if ok && (identifier.Name == "postgresqlquery" || identifier.Name == "analyticsource" || identifier.Name == "Execute") {
				t.Fatalf("%s introduces source execution through %q", sourceFile, identifier.Name)
			}
			return true
		})
	}
}
