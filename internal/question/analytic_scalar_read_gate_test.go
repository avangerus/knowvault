package question

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// readStoredRunDeclaration parses the production service.go and returns the one
// readStoredRun method declaration the disclosure gate is wired into.
func readStoredRunDeclaration(t *testing.T) *ast.FuncDecl {
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
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "readStoredRun" {
			return function
		}
	}
	t.Fatalf("service.go does not declare readStoredRun")
	return nil
}

// readGateCallName renders a parsed expression as its dotted call name, so a
// test can match one call by source spelling without a string search.
func readGateCallName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return readGateCallName(typed.X) + "." + typed.Sel.Name
	case *ast.CallExpr:
		return readGateCallName(typed.Fun)
	case *ast.ParenExpr:
		return readGateCallName(typed.X)
	case *ast.StarExpr:
		return "*" + readGateCallName(typed.X)
	case *ast.BinaryExpr:
		return readGateCallName(typed.X) + " " + typed.Op.String() + " " + readGateCallName(typed.Y)
	default:
		return ""
	}
}

// readGateReturnsZeroRun reports whether one return statement's first result is
// the exact zero Run composite literal, so a refusal can never hand back the
// populated local result.
func readGateReturnsZeroRun(statement *ast.ReturnStmt) bool {
	if len(statement.Results) == 0 {
		return false
	}
	composite, ok := statement.Results[0].(*ast.CompositeLit)
	if !ok || len(composite.Elts) != 0 {
		return false
	}
	name, ok := composite.Type.(*ast.Ident)
	return ok && name.Name == "Run"
}

// readGateErrorCode reads the literal code value out of a returned &Error{...}
// composite so the existing transaction error mapping can be pinned exactly.
func readGateErrorCode(statement *ast.ReturnStmt) string {
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

// TestReadStoredRunScalarGateOrderingAndPrivacy is the structural pin that the
// accepted private analytic scalar gate is wired into the production
// single stored-run reader exactly once, after the read transaction has ended
// and its error mapping has run, immediately before the Run is returned. It
// proves the private pair is captured only in a method-local variable declared
// outside the db.Read closure, that the gate invocation passes no SQL and no
// source executor, that a gate refusal returns the exact zero Run plus the
// gate's bare error, and that the existing transaction error mapping is
// preserved. It also proves by reflection that neither Run nor Service carries
// the pair.
func TestReadStoredRunScalarGateOrderingAndPrivacy(t *testing.T) {
	function := readStoredRunDeclaration(t)
	body := function.Body.List

	// The private pair is a method-local variable, declared (not package level,
	// not a Run/Service/context/transport field) with the exact private type.
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
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "retainedAnalyticScalarPair" {
				continue
			}
			if len(value.Values) != 0 || value.Type == nil ||
				readGateCallName(value.Type) != "*analyticScalarPair" {
				t.Fatalf("scalar pair local is not the private uninitialized *analyticScalarPair")
			}
			captureDeclaration = index
		}
	}
	if captureDeclaration < 0 {
		t.Fatalf("readStoredRun does not retain the decoded pair in a private local")
	}

	// The read transaction assignment and its error mapping.
	dbIndex := -1
	for index, statement := range body {
		assignment, ok := statement.(*ast.AssignStmt)
		if ok && len(assignment.Rhs) == 1 && readGateCallName(assignment.Rhs[0]) == "service.db.Read" {
			dbIndex = index
		}
	}
	if dbIndex < 0 {
		t.Fatalf("readStoredRun no longer calls service.db.Read")
	}
	if captureDeclaration > dbIndex {
		t.Fatalf("scalar pair local is declared inside or after the read transaction")
	}

	// The decoded pair may only be assigned once, and only from the decoded
	// structured answer while inside the db.Read closure.
	captureAssignments := 0
	ast.Inspect(function, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		target, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok || target.Name != "retainedAnalyticScalarPair" {
			return true
		}
		captureAssignments++
		if readGateCallName(assignment.Rhs[0]) != "structured.analyticScalarPair" {
			t.Fatalf("scalar pair local is assigned from %q, want the decoded private pair", readGateCallName(assignment.Rhs[0]))
		}
		return true
	})
	if captureAssignments != 1 {
		t.Fatalf("scalar pair local assignments = %d, want exactly one", captureAssignments)
	}

	dbStatement, ok := body[dbIndex].(*ast.AssignStmt)
	if !ok || len(dbStatement.Rhs) != 1 {
		t.Fatalf("db.Read statement has an unexpected shape")
	}
	dbCall, ok := dbStatement.Rhs[0].(*ast.CallExpr)
	if !ok {
		t.Fatalf("db.Read statement does not wrap a call")
	}
	captureInsideTransaction := false
	ast.Inspect(dbCall, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		target, ok := assignment.Lhs[0].(*ast.Ident)
		if ok && target.Name == "retainedAnalyticScalarPair" {
			captureInsideTransaction = true
		}
		return true
	})
	if !captureInsideTransaction {
		t.Fatalf("scalar pair capture is not inside the db.Read transaction closure")
	}

	// The preserved transaction error mapping is the statement right after
	// db.Read and still returns the exact zero Run with the same two codes and
	// the original cause.
	if dbIndex+1 >= len(body) {
		t.Fatalf("db.Read has no following error mapping")
	}
	mapping, ok := body[dbIndex+1].(*ast.IfStmt)
	if !ok || mapping.Init != nil || readGateCallName(mapping.Cond) != "err != nil" {
		t.Fatalf("db.Read error mapping is not the preserved err != nil branch")
	}
	mappedCodes := []string{}
	ast.Inspect(mapping, func(node ast.Node) bool {
		returned, ok := node.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if !readGateReturnsZeroRun(returned) {
			t.Fatalf("db.Read error mapping no longer returns the exact zero Run")
		}
		mappedCodes = append(mappedCodes, readGateErrorCode(returned))
		return true
	})
	if !reflect.DeepEqual(mappedCodes, []string{"CodeNotFound", "CodeUnavailable"}) {
		t.Fatalf("db.Read error codes = %v, want the preserved NOT_FOUND/UNAVAILABLE mapping", mappedCodes)
	}

	// The gate invocation is exactly the statement after the error mapping, so
	// it is lexically after db.Read and its error handling.
	if dbIndex+2 >= len(body) {
		t.Fatalf("readStoredRun has no disclosure gate after the error mapping")
	}
	gate, ok := body[dbIndex+2].(*ast.IfStmt)
	if !ok {
		t.Fatalf("the statement after db.Read error mapping is not the disclosure gate")
	}
	gateInit, ok := gate.Init.(*ast.AssignStmt)
	if !ok || len(gateInit.Rhs) != 1 {
		t.Fatalf("disclosure gate does not start with an err := call assignment")
	}
	gateCall, ok := gateInit.Rhs[0].(*ast.CallExpr)
	if !ok || readGateCallName(gateCall) != "service.authorizeAnalyticScalarDisclosure" {
		t.Fatalf("disclosure gate call = %q, want service.authorizeAnalyticScalarDisclosure", readGateCallName(gateInit.Rhs[0]))
	}
	if readGateCallName(gate.Cond) != "err != nil" {
		t.Fatalf("disclosure gate does not test err != nil")
	}

	// The gate is called exactly once in the whole method and receives only the
	// current request context, current access, workspace, trusted run id and the
	// private pair: no SQL, no source executor, no model or transport value.
	gateCalls := 0
	ast.Inspect(function, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if readGateCallName(call) == "service.authorizeAnalyticScalarDisclosure" {
			gateCalls++
			if len(call.Args) != 5 {
				t.Fatalf("disclosure gate args = %d, want the five private inputs", len(call.Args))
			}
			wantArgs := []string{"ctx", "access", "workspaceID", "runID", "retainedAnalyticScalarPair"}
			for index, argument := range call.Args {
				if readGateCallName(argument) != wantArgs[index] {
					t.Fatalf("disclosure gate arg %d = %q, want %q", index, readGateCallName(argument), wantArgs[index])
				}
			}
		}
		return true
	})
	if gateCalls != 1 {
		t.Fatalf("disclosure gate calls = %d, want exactly one", gateCalls)
	}

	// No package-level source execution is introduced into the reader: the gate
	// path never names analyticsource, a source executor or a repository.
	ast.Inspect(function, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		for _, forbidden := range []string{"analyticsource", "postgresqlquery", "retrieval"} {
			if identifier.Name == forbidden {
				t.Fatalf("readStoredRun names the source execution package %q", forbidden)
			}
		}
		return true
	})

	// A gate refusal returns the exact zero Run plus the gate's own error,
	// unchanged and unwrapped: no cause, no token, no populated result.
	if len(gate.Body.List) != 1 {
		t.Fatalf("disclosure gate refusal body has %d statements, want one", len(gate.Body.List))
	}
	refusal, ok := gate.Body.List[0].(*ast.ReturnStmt)
	if !ok || !readGateReturnsZeroRun(refusal) || len(refusal.Results) != 2 {
		t.Fatalf("disclosure gate refusal does not return the exact zero Run")
	}
	if returned, ok := refusal.Results[1].(*ast.Ident); !ok || returned.Name != "err" {
		t.Fatalf("disclosure gate refusal wraps the gate error instead of returning it unchanged")
	}

	// The gate is immediately before the one success return, so it cannot be
	// skipped and no populated Run can escape after a refusal.
	if len(body) != dbIndex+4 {
		t.Fatalf("readStoredRun tail shape changed: %d statements after db.Read", len(body)-dbIndex)
	}
	success, ok := body[len(body)-1].(*ast.ReturnStmt)
	if !ok || len(success.Results) != 2 {
		t.Fatalf("readStoredRun does not end in the success return")
	}
	if loaded, ok := success.Results[0].(*ast.Ident); !ok || loaded.Name != "result" {
		t.Fatalf("readStoredRun success return does not return the populated result")
	}
	if empty, ok := success.Results[1].(*ast.Ident); !ok || empty.Name != "nil" {
		t.Fatalf("readStoredRun success return does not return a nil error")
	}

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

// TestReadStoredRunScalarDisclosureRefusalStaysContentFree reuses the existing
// disclosure gate double to prove the error readStoredRun hands back unchanged
// on a present-pair refusal is the exact content-free CodeNotFound with no
// wrapped cause, and that a nil pair (the legacy absence) returns nil with zero
// resolver calls. Combined with the structural pin above - the refusal branch
// returns Run{} plus this bare error - a refused reauthorization cannot yield a
// populated Run.
func TestReadStoredRunScalarDisclosureRefusalStaysContentFree(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	recorder := &scalarDisclosureRecorder{err: errors.New("revoked after the run was stored")}

	err := authorizeScalarDisclosure(context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_scalar_pair", analyticScalarPairRunID, &pair, recorder)
	assertScalarDisclosureRefusal(t, err, CodeNotFound)
	assertScalarDisclosureHidesFacts(t, err)
	if recorder.calls != 1 {
		t.Fatalf("present-pair refusal calls = %d, want exactly one", recorder.calls)
	}

	// The production wrapper readStoredRun calls treats the legacy nil pair as
	// the sole accepted absence: nil, with no resolver call and no authority
	// requirement, so a stored run without a scalar stays readable.
	if err := (&Service{}).authorizeAnalyticScalarDisclosure(
		context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_scalar_pair", analyticScalarPairRunID, nil); err != nil {
		t.Fatalf("legacy nil pair refused: %v", err)
	}
}
