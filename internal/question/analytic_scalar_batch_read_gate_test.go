package question

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// readStoredRunBatchDeclaration parses the production service.go and returns the
// one readStoredRunBatch method declaration the batch disclosure gate is wired
// into.
func readStoredRunBatchDeclaration(t *testing.T) *ast.FuncDecl {
	t.Helper()
	rawFile, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatalf("read service.go: %v", err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "service.go", rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse service.go: %v", err)
	}
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "readStoredRunBatch" {
			return function
		}
	}
	t.Fatalf("service.go does not declare readStoredRunBatch")
	return nil
}

// batchGateTypeName renders a parsed type expression so the private pair map
// type can be pinned exactly without a string search.
func batchGateTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + batchGateTypeName(typed.X)
	case *ast.SelectorExpr:
		return batchGateTypeName(typed.X) + "." + typed.Sel.Name
	case *ast.MapType:
		return "map[" + batchGateTypeName(typed.Key) + "]" + batchGateTypeName(typed.Value)
	case *ast.ArrayType:
		return "[]" + batchGateTypeName(typed.Elt)
	default:
		return ""
	}
}

// batchGateReturnedCode reads the literal code value out of the returned
// &Error{...} composite in a two-result return statement so the preserved
// transaction error mapping and the fatal gate return can be pinned exactly.
func batchGateReturnedCode(statement *ast.ReturnStmt) string {
	if len(statement.Results) != 2 {
		return ""
	}
	unary, ok := statement.Results[1].(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return ""
	}
	composite, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	for _, element := range composite.Elts {
		keyValue, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if !ok || key.Name != "code" {
			continue
		}
		if value, ok := keyValue.Value.(*ast.Ident); ok {
			return value.Name
		}
	}
	return ""
}

// batchGateFreshNotFoundCause reports whether one expression is the fresh bare
// &Error{code: CodeNotFound} composite literal the denied-audit loop must build
// per removed run, rather than a shared variable.
func batchGateFreshNotFoundCause(expression ast.Expr) bool {
	unary, ok := expression.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return false
	}
	composite, ok := unary.X.(*ast.CompositeLit)
	if !ok || len(composite.Elts) != 1 {
		return false
	}
	keyValue, ok := composite.Elts[0].(*ast.KeyValueExpr)
	if !ok {
		return false
	}
	key, ok := keyValue.Key.(*ast.Ident)
	if !ok || key.Name != "code" {
		return false
	}
	value, ok := keyValue.Value.(*ast.Ident)
	return ok && value.Name == "CodeNotFound"
}

// TestReadStoredRunBatchScalarGateOrderingAndPrivacy is the structural pin that
// the accepted private batch disclosure gate is wired into the production
// batched stored-run reader exactly once, after the read transaction has ended
// and its error mapping has run, with candidate ids derived only from the final
// surviving result map. It proves the private pair map is a method-local
// declared outside db.Read and populated only by the strict decode, that the
// gate call passes no SQL and no source executor, that a fatal gate error
// returns a nil map plus the bare error before anything is deleted, that each
// denied run is deleted whole and audited with a fresh bare CodeNotFound, and
// that only the remaining map is returned after every check. It also proves by
// reflection that neither Run nor Service carries the pair.
func TestReadStoredRunBatchScalarGateOrderingAndPrivacy(t *testing.T) {
	function := readStoredRunBatchDeclaration(t)
	body := function.Body.List

	// The private pair map is a method-local variable, declared (not package
	// level, not a Run/Service/context/transport field) with the exact private
	// map type and initialized empty before the read transaction.
	captureDeclaration := -1
	for index, statement := range body {
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
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "retainedAnalyticScalarPairs" {
				continue
			}
			if value.Type == nil || batchGateTypeName(value.Type) != "map[string]*analyticScalarPair" {
				t.Fatalf("scalar pair local is not the private map[string]*analyticScalarPair")
			}
			if len(value.Values) != 1 || readGateCallName(value.Values[0]) != "make" {
				t.Fatalf("scalar pair local is not initialized empty with make")
			}
			captureDeclaration = index
		}
	}
	if captureDeclaration < 0 {
		t.Fatalf("readStoredRunBatch does not retain the decoded pairs in a private local map")
	}

	// The read transaction assignment and its preserved error mapping.
	dbIndex := -1
	for index, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if ok && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.db.Read" {
			dbIndex = index
		}
	}
	if dbIndex < 0 {
		t.Fatalf("readStoredRunBatch no longer calls service.db.Read")
	}
	if captureDeclaration > dbIndex {
		t.Fatalf("scalar pair map is declared inside or after the read transaction")
	}

	dbStatement, ok := body[dbIndex].(*ast.AssignStmt)
	if !ok || len(dbStatement.Rhs) != 1 {
		t.Fatalf("db.Read statement has an unexpected shape")
	}
	dbCall, ok := dbStatement.Rhs[0].(*ast.CallExpr)
	if !ok {
		t.Fatalf("db.Read statement does not wrap a call")
	}

	// The decoded pair may only be installed into the map once, and only from
	// the decoded structured answer while inside the db.Read closure.
	mapAssignments := 0
	mapCaptureInsideTransaction := false
	ast.Inspect(function, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		index, ok := assignment.Lhs[0].(*ast.IndexExpr)
		if !ok || readGateCallName(index.X) != "retainedAnalyticScalarPairs" {
			return true
		}
		mapAssignments++
		if readGateCallName(assignment.Rhs[0]) != "structured.analyticScalarPair" {
			t.Fatalf("scalar pair map is assigned from %q, want the decoded private pair", readGateCallName(assignment.Rhs[0]))
		}
		return true
	})
	if mapAssignments != 1 {
		t.Fatalf("scalar pair map assignments = %d, want exactly one", mapAssignments)
	}
	ast.Inspect(dbCall, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		index, ok := assignment.Lhs[0].(*ast.IndexExpr)
		if ok && readGateCallName(index.X) == "retainedAnalyticScalarPairs" {
			mapCaptureInsideTransaction = true
		}
		return true
	})
	if !mapCaptureInsideTransaction {
		t.Fatalf("scalar pair map capture is not inside the db.Read transaction closure")
	}

	// The preserved transaction error mapping is the statement right after
	// db.Read and still returns a nil map with the existing CodeUnavailable.
	mappingIndex := dbIndex + 1
	if mappingIndex >= len(body) {
		t.Fatalf("db.Read has no following error mapping")
	}
	mapping, ok := body[mappingIndex].(*ast.IfStmt)
	if !ok || mapping.Init != nil || readGateCallName(mapping.Cond) != "err != nil" {
		t.Fatalf("db.Read error mapping is not the preserved err != nil branch")
	}
	if len(mapping.Body.List) != 1 {
		t.Fatalf("db.Read error mapping has %d statements, want one", len(mapping.Body.List))
	}
	mapped, ok := mapping.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(mapped.Results) != 2 {
		t.Fatalf("db.Read error mapping does not return two results")
	}
	if empty, ok := mapped.Results[0].(*ast.Ident); !ok || empty.Name != "nil" {
		t.Fatalf("db.Read error mapping does not return a nil map")
	}
	if code := batchGateReturnedCode(mapped); code != "CodeUnavailable" {
		t.Fatalf("db.Read error code = %q, want the preserved CodeUnavailable", code)
	}

	// Candidate ids are derived only from the final surviving result map, in a
	// loop that sits after the transaction error mapping and before the gate.
	candidateLoopIndex := -1
	for index, statement := range body {
		rangeStatement, ok := statement.(*ast.RangeStmt)
		if !ok || readGateCallName(rangeStatement.X) != "result" {
			continue
		}
		if rangeStatement.Tok != token.DEFINE {
			continue
		}
		key, ok := rangeStatement.Key.(*ast.Ident)
		if !ok || key.Name != "runID" || rangeStatement.Value != nil {
			continue
		}
		if len(rangeStatement.Body.List) != 1 {
			continue
		}
		appendStatement, ok := rangeStatement.Body.List[0].(*ast.AssignStmt)
		if !ok || len(appendStatement.Lhs) != 1 || readGateCallName(appendStatement.Lhs[0]) != "candidateRunIDs" {
			continue
		}
		if len(appendStatement.Rhs) != 1 || readGateCallName(appendStatement.Rhs[0]) != "append" {
			continue
		}
		candidateLoopIndex = index
	}
	if candidateLoopIndex < 0 {
		t.Fatalf("readStoredRunBatch does not derive candidate ids from the final surviving result map")
	}
	if candidateLoopIndex <= mappingIndex {
		t.Fatalf("candidate derivation is not after the transaction error mapping")
	}

	// The gate invocation is called exactly once and receives only the current
	// request context, current access, workspace and the private candidate ids
	// plus the private pair map: no SQL, no source executor, no model value.
	helperIndex := -1
	for index, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 || len(assignment.Lhs) != 2 {
			continue
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok || readGateCallName(call) != "service.authorizeAnalyticScalarDisclosureBatch" {
			continue
		}
		helperIndex = index
		if readGateCallName(assignment.Lhs[0]) != "denied" || readGateCallName(assignment.Lhs[1]) != "err" {
			t.Fatalf("batch gate does not start with the denied/err assignment")
		}
		if len(call.Args) != 5 {
			t.Fatalf("batch gate args = %d, want the five private inputs", len(call.Args))
		}
		wantArgs := []string{"ctx", "access", "workspaceID", "candidateRunIDs", "retainedAnalyticScalarPairs"}
		for argIndex, argument := range call.Args {
			if readGateCallName(argument) != wantArgs[argIndex] {
				t.Fatalf("batch gate arg %d = %q, want %q", argIndex, readGateCallName(argument), wantArgs[argIndex])
			}
		}
	}
	if helperIndex < 0 {
		t.Fatalf("readStoredRunBatch does not call the batch disclosure gate")
	}
	gateCalls := 0
	ast.Inspect(function, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && readGateCallName(call) == "service.authorizeAnalyticScalarDisclosureBatch" {
			gateCalls++
		}
		return true
	})
	if gateCalls != 1 {
		t.Fatalf("batch gate calls = %d, want exactly one", gateCalls)
	}
	if helperIndex <= candidateLoopIndex {
		t.Fatalf("batch gate is not after the candidate derivation")
	}

	// A fatal gate error returns a nil map plus the exact bare error, before
	// anything is deleted or audited: the err != nil branch directly follows.
	fatalBranch, ok := body[helperIndex+1].(*ast.IfStmt)
	if !ok || readGateCallName(fatalBranch.Cond) != "err != nil" || len(fatalBranch.Body.List) != 1 {
		t.Fatalf("batch gate refusal is not the one err != nil fatal return")
	}
	fatal, ok := fatalBranch.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(fatal.Results) != 2 {
		t.Fatalf("batch gate refusal does not return two results")
	}
	if empty, ok := fatal.Results[0].(*ast.Ident); !ok || empty.Name != "nil" {
		t.Fatalf("batch gate refusal does not return a nil map")
	}
	if bare, ok := fatal.Results[1].(*ast.Ident); !ok || bare.Name != "err" {
		t.Fatalf("batch gate refusal wraps the gate error instead of returning it unchanged")
	}

	// Every denied id deletes the whole Run from the final map and records one
	// content-free denied read outcome with a fresh bare CodeNotFound cause.
	if helperIndex+2 >= len(body) {
		t.Fatalf("batch gate has no denied deletion loop")
	}
	deniedLoop, ok := body[helperIndex+2].(*ast.RangeStmt)
	if !ok || readGateCallName(deniedLoop.X) != "denied" {
		t.Fatalf("the statement after the batch gate is not the denied deletion loop")
	}
	if len(deniedLoop.Body.List) != 2 {
		t.Fatalf("denied loop body has %d statements, want the delete and the audit call", len(deniedLoop.Body.List))
	}
	deletion, ok := deniedLoop.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("denied loop does not start with a deletion")
	}
	deleteCall, ok := deletion.X.(*ast.CallExpr)
	if !ok || readGateCallName(deleteCall) != "delete" || len(deleteCall.Args) != 2 ||
		readGateCallName(deleteCall.Args[0]) != "result" || readGateCallName(deleteCall.Args[1]) != "runID" {
		t.Fatalf("denied loop does not delete the whole run from the result map")
	}
	auditStatement, ok := deniedLoop.Body.List[1].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("denied loop does not end with the per-run audit call")
	}
	auditCall, ok := auditStatement.X.(*ast.CallExpr)
	if !ok || readGateCallName(auditCall) != "service.recordStoredRunReadFailure" || len(auditCall.Args) != 5 {
		t.Fatalf("denied loop does not call recordStoredRunReadFailure with five inputs")
	}
	wantAuditArgs := []string{"ctx", "access", "workspaceID", "runID", ""}
	for argIndex := 0; argIndex < 4; argIndex++ {
		if readGateCallName(auditCall.Args[argIndex]) != wantAuditArgs[argIndex] {
			t.Fatalf("audit arg %d = %q, want %q", argIndex, readGateCallName(auditCall.Args[argIndex]), wantAuditArgs[argIndex])
		}
	}
	if !batchGateFreshNotFoundCause(auditCall.Args[4]) {
		t.Fatalf("per-run audit does not use a fresh bare CodeNotFound cause")
	}

	// Only the remaining map is returned, as the last statement, after every
	// check above.
	success, ok := body[len(body)-1].(*ast.ReturnStmt)
	if !ok || len(success.Results) != 2 {
		t.Fatalf("readStoredRunBatch does not end in the success return")
	}
	if loaded, ok := success.Results[0].(*ast.Ident); !ok || loaded.Name != "result" {
		t.Fatalf("batch success return does not return the remaining result map")
	}
	if empty, ok := success.Results[1].(*ast.Ident); !ok || empty.Name != "nil" {
		t.Fatalf("batch success return does not return a nil error")
	}
	if helperIndex+2 >= len(body)-1 {
		t.Fatalf("readStoredRunBatch success return does not follow the denied deletion loop")
	}

	// No package-level source execution is introduced into the batch reader: the
	// gate path never names analyticsource, a source executor or a repository.
	ast.Inspect(function, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		for _, forbidden := range []string{"analyticsource", "postgresqlquery", "retrieval"} {
			if identifier.Name == forbidden {
				t.Fatalf("readStoredRunBatch names the source execution package %q", forbidden)
			}
		}
		return true
	})

	// The private pair type exposes no exported field or method, and neither Run
	// nor Service carries the pair, so it can never reach a public Run field,
	// context value, Service state or transport projection.
	pairType := reflect.TypeOf(analyticScalarPair{})
	for index := 0; index < pairType.NumField(); index++ {
		if pairType.Field(index).IsExported() {
			t.Fatalf("analyticScalarPair exposes the exported field %q", pairType.Field(index).Name)
		}
	}
	for index := 0; index < pairType.NumMethod(); index++ {
		if pairType.Method(index).IsExported() {
			t.Fatalf("analyticScalarPair exposes the exported method %q", pairType.Method(index).Name)
		}
	}
	pairPointer := reflect.TypeOf(&analyticScalarPair{})
	for index := 0; index < reflect.TypeOf(Run{}).NumField(); index++ {
		field := reflect.TypeOf(Run{}).Field(index)
		if field.Type == pairPointer {
			t.Fatalf("Run carries the analytic scalar pair through field %q", field.Name)
		}
		lowered := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		for _, forbidden := range []string{"analytic", "scalar", "dependency"} {
			if strings.Contains(lowered, forbidden) {
				t.Fatalf("Run carries the artifact-only %q through field %q", forbidden, field.Name)
			}
		}
	}
	for index := 0; index < reflect.TypeOf(Service{}).NumField(); index++ {
		if field := reflect.TypeOf(Service{}).Field(index); field.Type == pairPointer {
			t.Fatalf("Service carries the analytic scalar pair through field %q", field.Name)
		}
	}
}

// TestReadStoredRunBatchDeniedAuditIsOneContentFreeOutcomePerRun reuses the
// existing admission journal double to prove the per-run audit the batch
// integration performs with a fresh bare CodeNotFound yields exactly one
// content-free QUESTION_READ_DENIED failure outcome naming that run, so a denied
// scalar run always leaves its admission paired with its outcome.
func TestReadStoredRunBatchDeniedAuditIsOneContentFreeOutcomePerRun(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := &Service{admission: journal}
	service.newID = func(prefix string) (string, error) { return prefix + "_0001", nil }
	service.now = func() time.Time { return time.Unix(0, 0).UTC() }
	access := questionAccess(database.ActorKindHuman)

	deniedRunIDs := []string{"run_batch_alpha", "run_batch_beta"}
	for _, runID := range deniedRunIDs {
		// The integration builds a fresh cause for every removed run; reusing the
		// same literal here mirrors that call site exactly.
		service.recordStoredRunReadFailure(context.Background(), access, "workspace_scalar_batch",
			runID, &Error{code: CodeNotFound})
	}
	if len(journal.appended) != len(deniedRunIDs) {
		t.Fatalf("denied outcomes = %d, want one per removed run", len(journal.appended))
	}
	for index, runID := range deniedRunIDs {
		event := journal.appended[index]
		if event.Action != audit.ActionQuestionFailed || event.Outcome != audit.OutcomeFailed {
			t.Fatalf("outcome %d = %s/%s, want the failed question action", index, event.Action, event.Outcome)
		}
		if event.ErrorCode == nil || *event.ErrorCode != "QUESTION_READ_DENIED" {
			t.Fatalf("outcome %d error code = %v, want the content-free QUESTION_READ_DENIED", index, event.ErrorCode)
		}
		if event.Metadata.QuestionRunID == nil || *event.Metadata.QuestionRunID != runID {
			t.Fatalf("outcome %d does not name the removed run", index)
		}
	}
}
