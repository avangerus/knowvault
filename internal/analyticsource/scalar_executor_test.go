package analyticsource

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// scalarExecutorWorkspaceID deliberately differs from every identity the sealed
// fixture profile and its catalog carry, so a value copied from the intent or
// the profile instead of the argument is visible.
const scalarExecutorWorkspaceID = "scalar_executor_workspace"

// scalarExecutorFixture builds one sealed scalar intent, the resolver whose
// catalog authorized it, and a non-nil zero authorized reader. The resolver's
// store owns no database, so an accepted selection reaches the repository
// boundary and refuses there without a database and without a mock.
func scalarExecutorFixture(t *testing.T) (queryintent.ValidatedIntentV2, *Resolver, *repository.PostgreSQLAuthorizedReader) {
	t.Helper()
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)
	intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))
	resolver, err := NewResolver(new(repository.Store), catalog)
	if err != nil {
		t.Fatalf("build fixture resolver: %v", err)
	}
	return intent, resolver, new(repository.PostgreSQLAuthorizedReader)
}

// assertScalarReadRefusal requires one Execute refusal to return the exact zero
// ScalarRead and the one content-free sentinel, with no wrapped cause.
func assertScalarReadRefusal(t *testing.T, value ScalarRead, err error) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refused execution returned %v, want errMismatch", err)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("refusal wraps %v, want the exact unwrapped errMismatch", unwrapped)
	}
	if !reflect.DeepEqual(value, ScalarRead{}) {
		t.Fatalf("refusal returned %+v, want the exact zero ScalarRead", value)
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
}

func TestNewScalarExecutorRetainsExactDependencies(t *testing.T) {
	_, resolver, reader := scalarExecutorFixture(t)
	executor, err := NewScalarExecutor(resolver, reader)
	if err != nil {
		t.Fatalf("a resolver and reader were refused: %v", err)
	}
	if executor.resolver != resolver || executor.reader != reader {
		t.Fatal("the executor did not retain the exact dependencies")
	}
	if executor.now == nil || reflect.ValueOf(executor.now).Pointer() != reflect.ValueOf(time.Now).Pointer() {
		t.Fatal("the executor did not retain the default time.Now clock")
	}
	for name, refuse := range map[string]struct {
		resolver *Resolver
		reader   *repository.PostgreSQLAuthorizedReader
	}{
		"nil resolver": {nil, reader},
		"nil reader":   {resolver, nil},
		"nil both":     {nil, nil},
		"zero and nil": {&Resolver{}, nil},
	} {
		value, refusal := NewScalarExecutor(refuse.resolver, refuse.reader)
		if value != nil {
			t.Fatalf("%s returned an executor instead of nil", name)
		}
		if refusal != errMismatch || !errors.Is(refusal, errMismatch) {
			t.Fatalf("%s returned %v, want errMismatch", name, refusal)
		}
	}
}

// TestScalarExecutorExecuteRefusesEveryClosedInput proves every input outside
// the accepted shape returns the exact zero ScalarRead and the exact unwrapped
// errMismatch, including the otherwise valid call that the nil-database store
// refuses at the repository boundary.
func TestScalarExecutorExecuteRefusesEveryClosedInput(t *testing.T) {
	intent, resolver, reader := scalarExecutorFixture(t)
	executor, err := NewScalarExecutor(resolver, reader)
	if err != nil {
		t.Fatalf("build fixture executor: %v", err)
	}
	access := database.AccessContext{
		OrganizationID: "scalar_org", PrincipalID: "scalar_principal", RequestID: "scalar_request",
	}
	if err := access.Validate(); err != nil {
		t.Fatalf("the fixture access context is not valid: %v", err)
	}

	clockless := &ScalarExecutor{resolver: resolver, reader: reader}
	cases := []struct {
		name      string
		executor  *ScalarExecutor
		ctx       context.Context
		access    database.AccessContext
		workspace string
		intent    queryintent.ValidatedIntentV2
	}{
		{"nil executor", nil, context.Background(), access, scalarExecutorWorkspaceID, intent},
		{"zero executor", &ScalarExecutor{}, context.Background(), access, scalarExecutorWorkspaceID, intent},
		{"nil clock", clockless, context.Background(), access, scalarExecutorWorkspaceID, intent},
		{"zero access", executor, context.Background(), database.AccessContext{}, scalarExecutorWorkspaceID, intent},
		{"nil context", executor, nil, access, scalarExecutorWorkspaceID, intent},
		{"empty workspace", executor, context.Background(), access, "", intent},
		{"untrimmed workspace", executor, context.Background(), access, scalarExecutorWorkspaceID + " ", intent},
		{"control bearing workspace", executor, context.Background(), access, scalarExecutorWorkspaceID + "\x00", intent},
		{"overlong workspace", executor, context.Background(), access, strings.Repeat("w", 257), intent},
		{"zero intent", executor, context.Background(), access, scalarExecutorWorkspaceID, queryintent.ValidatedIntentV2{}},
		{"repository boundary", executor, context.Background(), access, scalarExecutorWorkspaceID, intent},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value, refusal := test.executor.Execute(test.ctx, test.access, test.workspace, test.intent)
			assertScalarReadRefusal(t, value, refusal)
			for _, disclosure := range []string{scalarExecutorWorkspaceID, access.OrganizationID,
				access.PrincipalID, access.RequestID} {
				if strings.Contains(refusal.Error(), disclosure) {
					t.Fatalf("the refusal disclosed %q", disclosure)
				}
			}
		})
	}
}

// TestScalarExecutorResolveRequestDerivesOnlyFromSealedIntent proves the one
// resolver selection is named by the workspace argument and the sealed catalog
// and dataset identities alone, and that every malformed input refuses with the
// exact zero ResolveRequest and the exact unwrapped errMismatch.
func TestScalarExecutorResolveRequestDerivesOnlyFromSealedIntent(t *testing.T) {
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)
	intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))

	request, err := scalarExecutorResolveRequest(scalarExecutorWorkspaceID, intent)
	if err != nil {
		t.Fatalf("the sealed intent was refused: %v", err)
	}
	want := ResolveRequest{
		WorkspaceID:     scalarExecutorWorkspaceID,
		CatalogID:       catalog.ID(),
		CatalogRevision: catalog.Revision(),
		CatalogHash:     catalog.Hash(),
		ProfileKey:      profile.Key(),
		ProfileHash:     profile.Hash(),
	}
	if request != want {
		t.Fatalf("derived request = %+v, want %+v", request, want)
	}
	if request.WorkspaceID == catalog.ID() || request.WorkspaceID == profile.Key().DatasetID() {
		t.Fatal("the derived workspace equals a catalog or dataset identity")
	}

	for name, refuse := range map[string]struct {
		workspace string
		intent    queryintent.ValidatedIntentV2
	}{
		"zero workspace":            {"", intent},
		"untrimmed workspace":       {scalarExecutorWorkspaceID + " ", intent},
		"overlong workspace":        {strings.Repeat("w", 257), intent},
		"zero intent":               {scalarExecutorWorkspaceID, queryintent.ValidatedIntentV2{}},
		"zero workspace and intent": {"", queryintent.ValidatedIntentV2{}},
	} {
		value, refusal := scalarExecutorResolveRequest(refuse.workspace, refuse.intent)
		if refusal != errMismatch || !errors.Is(refusal, errMismatch) {
			t.Fatalf("%s returned %v, want errMismatch", name, refusal)
		}
		if value != (ResolveRequest{}) {
			t.Fatalf("%s returned %+v, want the exact zero ResolveRequest", name, value)
		}
	}
}

// TestScalarExecutorDetachesPlanOrdinals proves the Snapshot ordinals handed to
// a caller are a fresh copy of the plan's, so mutating the returned slice cannot
// reach the compiled plan, and an absent slice stays nil.
func TestScalarExecutorDetachesPlanOrdinals(t *testing.T) {
	source := []int{2, 5}
	detached := detachedScalarOrdinals(source)
	if !slices.Equal(detached, source) {
		t.Fatalf("detached ordinals = %v, want %v", detached, source)
	}
	detached[0] = 999
	if source[0] != 2 {
		t.Fatal("mutating the detached ordinals reached the source slice")
	}
	if detachedScalarOrdinals(nil) != nil {
		t.Fatal("a nil ordinal slice did not stay nil")
	}
}

// TestScalarExecutorValuesExposeNoAccessor pins the private result shape: the
// executor and the ScalarRead expose no exported field, ScalarRead exposes no
// method at all, and the only callable entry point is Execute.
func TestScalarExecutorValuesExposeNoAccessor(t *testing.T) {
	wantFields := map[reflect.Type][][2]string{
		reflect.TypeOf(ScalarExecutor{}): {
			{"resolver", "*analyticsource.Resolver"},
			{"reader", "*repository.PostgreSQLAuthorizedReader"},
			{"now", "func() time.Time"},
		},
		reflect.TypeOf(ScalarRead{}): {
			{"snapshot", "postgresqlquery.Snapshot"},
			{"measureOrdinal", "int"},
			{"identityOrdinals", "[]int"},
			{"context", "analyticsource.scalarReadContext"},
		},
	}
	for value, want := range wantFields {
		fields := make([][2]string, 0, value.NumField())
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			fields = append(fields, [2]string{field.Name, field.Type.String()})
			if field.IsExported() {
				t.Fatalf("%s exposes an exported field %q", value, field.Name)
			}
		}
		if !reflect.DeepEqual(fields, want) {
			t.Fatalf("%s fields = %v, want %v", value, fields, want)
		}
	}
	if reflect.TypeOf(ScalarExecutor{}).NumMethod() != 0 {
		t.Fatal("ScalarExecutor observes an exported method on the value")
	}
	readMethods := make([]string, 0, reflect.TypeOf(ScalarRead{}).NumMethod())
	for index := 0; index < reflect.TypeOf(ScalarRead{}).NumMethod(); index++ {
		readMethods = append(readMethods, reflect.TypeOf(ScalarRead{}).Method(index).Name)
	}
	if !slices.Equal(readMethods, []string{"MarshalJSON"}) {
		t.Fatalf("ScalarRead methods = %v, want exactly the opaque [MarshalJSON]", readMethods)
	}
	pointer := reflect.TypeOf(&ScalarExecutor{})
	exposed := make([]string, 0, pointer.NumMethod())
	for index := 0; index < pointer.NumMethod(); index++ {
		exposed = append(exposed, pointer.Method(index).Name)
	}
	if !slices.Equal(exposed, []string{"Execute"}) {
		t.Fatalf("*ScalarExecutor methods = %v, want exactly [Execute]", exposed)
	}
}

// TestScalarExecutorSourceChoreography parses the production file and pins the
// closed surface and the fixed execution order: one selection derived from the
// sealed intent, two Resolve calls around exactly one ReadFilteredBound, the
// plan compiled from the resolved profile, the authority request built only from
// the resolved binding, the resolved authority passed as the read's expected
// authority, and a post-read binding equality.
func TestScalarExecutorSourceChoreography(t *testing.T) {
	const filename = "scalar_executor.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	if parsed.Name.Name != "analyticsource" {
		t.Fatalf("package = %q, want analyticsource", parsed.Name.Name)
	}

	allowedImports := map[string]bool{
		"context":                true,
		"encoding/json/jsontext": true,
		"time":                   true,
		"knowvault.local/verified-workspace/internal/analytic":               true,
		"knowvault.local/verified-workspace/internal/platform/database":      true,
		"knowvault.local/verified-workspace/internal/queryintent":            true,
		"knowvault.local/verified-workspace/internal/source/postgresqlquery": true,
		"knowvault.local/verified-workspace/internal/workspace/repository":   true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the executor: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	functions := map[string]*ast.FuncDecl{}
	methods := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		typed, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if typed.Recv == nil {
			functions[typed.Name.Name] = typed
			continue
		}
		methods[typed.Name.Name] = typed
	}
	declaredFunctions := make([]string, 0, len(functions))
	for name := range functions {
		declaredFunctions = append(declaredFunctions, name)
	}
	slices.Sort(declaredFunctions)
	wantFunctions := []string{
		"NewScalarExecutor", "detachedScalarBytes", "detachedScalarOrdinals", "detachedScalarRows",
		"detachedScalarSnapshot", "detachedScalarValue", "detachedScalarValues", "newScalarRead",
		"scalarExecutorResolveRequest",
	}
	if !slices.Equal(declaredFunctions, wantFunctions) {
		t.Fatalf("declared functions = %v, want %v", declaredFunctions, wantFunctions)
	}
	constructor := functions["NewScalarExecutor"]
	if receiver := astFieldInventory(constructor.Recv); len(receiver) != 0 {
		t.Fatalf("NewScalarExecutor receiver = %v, want none", receiver)
	}
	wantConstructorParameters := [][2]string{
		{"resolver", "*Resolver"}, {"reader", "*repository.PostgreSQLAuthorizedReader"},
	}
	if parameters := astFieldInventory(constructor.Type.Params); !slices.Equal(parameters, wantConstructorParameters) {
		t.Fatalf("NewScalarExecutor parameters = %v, want %v", parameters, wantConstructorParameters)
	}
	wantConstructorResults := [][2]string{{"", "*ScalarExecutor"}, {"", "error"}}
	if results := astFieldInventory(constructor.Type.Results); !slices.Equal(results, wantConstructorResults) {
		t.Fatalf("NewScalarExecutor results = %v, want %v", results, wantConstructorResults)
	}

	declaredMethods := make([]string, 0, len(methods))
	for name := range methods {
		declaredMethods = append(declaredMethods, name)
	}
	slices.Sort(declaredMethods)
	if !slices.Equal(declaredMethods, []string{"Execute", "MarshalJSON"}) {
		t.Fatalf("declared methods = %v, want exactly [Execute MarshalJSON]", declaredMethods)
	}
	marshal := methods["MarshalJSON"]
	if receiver := astFieldInventory(marshal.Recv); len(receiver) != 1 || receiver[0][1] != "ScalarRead" {
		t.Fatalf("MarshalJSON receiver = %v, want one ScalarRead", receiver)
	}
	if parameters := astFieldInventory(marshal.Type.Params); len(parameters) != 0 {
		t.Fatalf("MarshalJSON parameters = %v, want none", parameters)
	}
	if results := astFieldInventory(marshal.Type.Results); len(results) != 2 || results[1][1] != "error" {
		t.Fatalf("MarshalJSON results = %v, want two results ending in error", results)
	}
	execute := methods["Execute"]
	if receiver := astFieldInventory(execute.Recv); len(receiver) != 1 || receiver[0][1] != "*ScalarExecutor" {
		t.Fatalf("Execute receiver = %v, want one *ScalarExecutor", receiver)
	}
	wantExecuteParameters := [][2]string{
		{"ctx", "context.Context"}, {"access", "database.AccessContext"},
		{"workspaceID", "string"}, {"intent", "queryintent.ValidatedIntentV2"},
	}
	if parameters := astFieldInventory(execute.Type.Params); !slices.Equal(parameters, wantExecuteParameters) {
		t.Fatalf("Execute parameters = %v, want %v", parameters, wantExecuteParameters)
	}
	wantExecuteResults := [][2]string{{"", "ScalarRead"}, {"", "error"}}
	if results := astFieldInventory(execute.Type.Results); !slices.Equal(results, wantExecuteResults) {
		t.Fatalf("Execute results = %v, want %v", results, wantExecuteResults)
	}

	assertScalarExecutorChoreography(t, execute)
	assertScalarExecutorRequestLiteral(t, functions["scalarExecutorResolveRequest"])
}

// scalarExecutorCall is one rendered call in source order.
type scalarExecutorCall struct {
	text string
	call *ast.CallExpr
}

// assertScalarExecutorChoreography pins the Execute body call order and every
// security-relevant argument the bounded read sequence uses.
func assertScalarExecutorChoreography(t *testing.T, execute *ast.FuncDecl) {
	t.Helper()
	calls := make([]scalarExecutorCall, 0, 16)
	ast.Inspect(execute.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		text, ok := astExpressionText(call.Fun)
		if !ok {
			return true
		}
		calls = append(calls, scalarExecutorCall{text: text, call: call})
		return true
	})

	indexesOf := func(want string) []int {
		indexes := []int{}
		for index, candidate := range calls {
			if candidate.text == want {
				indexes = append(indexes, index)
			}
		}
		return indexes
	}
	resolves := indexesOf("executor.resolver.Resolve")
	reads := indexesOf("executor.reader.ReadFilteredBound")
	compiles := indexesOf("compileScalarReadPlan")
	equalities := indexesOf("after.binding.equal")
	derivations := indexesOf("scalarExecutorResolveRequest")
	nows := indexesOf("executor.now")
	validates := indexesOf("access.Validate")
	constructions := indexesOf("newScalarRead")
	if len(resolves) != 2 {
		t.Fatalf("Execute calls Resolve %d times, want exactly two", len(resolves))
	}
	if len(reads) != 1 {
		t.Fatalf("Execute calls ReadFilteredBound %d times, want exactly one", len(reads))
	}
	if len(compiles) != 1 {
		t.Fatalf("Execute calls compileScalarReadPlan %d times, want exactly one", len(compiles))
	}
	if len(equalities) != 1 {
		t.Fatalf("Execute calls binding.equal %d times, want exactly one", len(equalities))
	}
	if len(derivations) != 1 {
		t.Fatalf("Execute calls scalarExecutorResolveRequest %d times, want exactly one", len(derivations))
	}
	if len(validates) != 1 {
		t.Fatalf("Execute validates the access context %d times, want exactly one", len(validates))
	}
	if len(nows) != 2 {
		t.Fatalf("Execute reads the private clock %d times, want exactly two", len(nows))
	}
	if len(constructions) != 1 {
		t.Fatalf("Execute calls newScalarRead %d times, want exactly one", len(constructions))
	}
	// The access context is validated before any resolver I/O, and the two clock
	// readings bracket exactly the one read call: the started reading is the call
	// immediately before its zero guard, that guard is immediately before the
	// read, and the completed reading is the call immediately after the read. The
	// completed guard and order check follow it and precede publication.
	if !(validates[0] < derivations[0] && validates[0] < resolves[0]) {
		t.Fatalf("Execute validates access after resolver I/O: %v", calls)
	}
	startedGuards := indexesOf("started.IsZero")
	completedGuards := indexesOf("completed.IsZero")
	completedOrders := indexesOf("completed.Before")
	if len(startedGuards) != 1 || !(nows[0]+1 == startedGuards[0] && startedGuards[0]+1 == reads[0]) {
		t.Fatalf("Execute started clock/guard at %v/%v, want immediately before the read at %v", nows, startedGuards, reads[0])
	}
	if !(nows[1] == reads[0]+1) {
		t.Fatalf("Execute completed clock at %v, want immediately after the read at %v", nows[1], reads[0])
	}
	if len(completedGuards) != 1 || len(completedOrders) != 1 ||
		!(reads[0] < completedGuards[0] && reads[0] < completedOrders[0]) {
		t.Fatalf("Execute completed-window guards at %v/%v, want both after the read", completedGuards, completedOrders)
	}
	if !(derivations[0] < resolves[0] && resolves[0] < compiles[0] && compiles[0] < reads[0] && reads[0] < resolves[1] && resolves[1] < equalities[0] && equalities[0] < constructions[0]) {
		t.Fatalf("Execute call order = %v, want derive, validate, resolve, compile, start, read, complete, resolve, equal, construct", calls)
	}

	for _, index := range resolves {
		assertScalarExecutorCallArguments(t, calls[index].call, "executor.resolver.Resolve", []string{"ctx", "access", "request"})
	}
	assertScalarExecutorCallArguments(t, calls[compiles[0]].call, "compileScalarReadPlan",
		[]string{"before.binding.profile", "intent"})
	assertScalarExecutorCallArguments(t, calls[reads[0]].call, "executor.reader.ReadFilteredBound",
		[]string{"ctx", "access", "authority", "before.authority", "plan.read"})
	assertScalarExecutorCallArguments(t, calls[equalities[0]].call, "after.binding.equal",
		[]string{"before.binding"})
	assertScalarExecutorCallArguments(t, calls[constructions[0]].call, "newScalarRead",
		[]string{"intent", "before.binding", "access", "before.authority.Limits()", "started", "completed",
			"snapshot", "plan.measureOrdinal", "plan.identityOrdinals"})

	assertScalarExecutorAuthorityLiteral(t, execute)
}

// assertScalarExecutorCallArguments pins one call's callee and its complete
// argument list as exact AST expressions, so a substituted argument is visible.
func assertScalarExecutorCallArguments(t *testing.T, call *ast.CallExpr, callee string, want []string) {
	t.Helper()
	if got, ok := astExpressionText(call.Fun); !ok || got != callee {
		t.Fatalf("call callee = %v, want %s", call.Fun, callee)
	}
	args, ok := astCallArguments(call)
	if !ok || !slices.Equal(args, want) {
		t.Fatalf("%s passes %v, want %v", callee, args, want)
	}
}

// assertScalarExecutorAuthorityLiteral pins the one PostgreSQLAuthorityRequest
// literal in the Execute body to its six declared fields, each drawn from the
// resolved binding's opaque authority facts except the fixed managed access
// mode, so no authority value can come from the intent, the profile, a caller
// argument or a literal.
func assertScalarExecutorAuthorityLiteral(t *testing.T, execute *ast.FuncDecl) {
	t.Helper()
	var literal *ast.CompositeLit
	ast.Inspect(execute.Body, func(node ast.Node) bool {
		candidate, ok := node.(*ast.CompositeLit)
		if ok && astTypeName(candidate.Type) == "repository.PostgreSQLAuthorityRequest" {
			literal = candidate
			return false
		}
		return true
	})
	if literal == nil {
		t.Fatal("Execute holds no PostgreSQLAuthorityRequest literal")
	}
	want := [][2]string{
		{"WorkspaceID", "before.binding.binding.workspaceID"},
		{"WorkspaceSourceID", "before.binding.binding.workspaceSourceID"},
		{"SourceScopeID", "before.binding.binding.sourceScopeID"},
		{"ScopeConfigHash", "before.binding.binding.sourceScopeConfigurationHash"},
		{"AccessMode", "repositoryManagedAccessMode"},
		{"SourceScopeRevision", "before.binding.binding.sourceScopeRevision"},
	}
	got := make([][2]string, 0, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("the PostgreSQLAuthorityRequest literal holds a positional element")
		}
		key, keyOK := pair.Key.(*ast.Ident)
		value, valueOK := astExpressionText(pair.Value)
		if !keyOK || !valueOK {
			t.Fatalf("the PostgreSQLAuthorityRequest literal holds one unsupported member %v", element)
		}
		got = append(got, [2]string{key.Name, value})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("PostgreSQLAuthorityRequest literal = %v, want %v", got, want)
	}
}

// assertScalarExecutorRequestLiteral pins that the resolver selection literal
// is built only from the argument workspace and the sealed intent accessors.
func assertScalarExecutorRequestLiteral(t *testing.T, request *ast.FuncDecl) {
	t.Helper()
	calls := map[string]bool{}
	ast.Inspect(request.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if text, ok := astExpressionText(call.Fun); ok {
			calls[text] = true
		}
		return true
	})
	for _, want := range []string{
		"intent.Valid", "intent.CatalogID", "intent.CatalogRevision", "intent.CatalogHash",
		"intent.Dataset", "dataset.DatasetID", "dataset.ProfileVersion",
		"dataset.ExpectedProfileHash", "analytic.NewProfileKey",
	} {
		if !calls[want] {
			t.Fatalf("scalarExecutorResolveRequest does not call %s", want)
		}
	}

	var literal *ast.CompositeLit
	ast.Inspect(request.Body, func(node ast.Node) bool {
		literal = scalarExecutorResolveRequestLiteral(node, literal)
		return true
	})
	if literal == nil {
		t.Fatal("scalarExecutorResolveRequest holds no ResolveRequest literal")
	}
	want := [][2]string{
		{"WorkspaceID", "workspaceID"},
		{"CatalogID", "catalogID"},
		{"CatalogRevision", "catalogRevision"},
		{"CatalogHash", "catalogHash"},
		{"ProfileKey", "profileKey"},
		{"ProfileHash", "profileHash"},
	}
	got := make([][2]string, 0, len(literal.Elts))
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			t.Fatal("the ResolveRequest literal holds a positional element")
		}
		key, keyOK := pair.Key.(*ast.Ident)
		value, valueOK := astExpressionText(pair.Value)
		if !keyOK || !valueOK {
			t.Fatalf("the ResolveRequest literal holds one unsupported member %v", element)
		}
		got = append(got, [2]string{key.Name, value})
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ResolveRequest literal = %v, want %v", got, want)
	}
}

// scalarExecutorResolveRequestLiteral returns the first ResolveRequest composite
// literal in the helper body, leaving the accepted value untouched.
func scalarExecutorResolveRequestLiteral(node ast.Node, accepted *ast.CompositeLit) *ast.CompositeLit {
	if accepted != nil {
		return accepted
	}
	var expression ast.Expr
	switch typed := node.(type) {
	case *ast.ReturnStmt:
		if len(typed.Results) == 0 {
			return nil
		}
		expression = typed.Results[0]
	case *ast.AssignStmt:
		if len(typed.Rhs) != 1 {
			return nil
		}
		expression = typed.Rhs[0]
	default:
		return nil
	}
	literal, ok := expression.(*ast.CompositeLit)
	if !ok || astTypeName(literal.Type) != "ResolveRequest" || len(literal.Elts) == 0 {
		return nil
	}
	return literal
}

// scalarReadConstruction is one accepted newScalarRead argument set. A refusal
// case copies it and changes exactly one semantic member, so every refusal is
// attributable to that member alone.
type scalarReadConstruction struct {
	intent      queryintent.ValidatedIntentV2
	binding     eligibilityBinding
	access      database.AccessContext
	limits      postgresqlquery.Limits
	startedAt   time.Time
	completedAt time.Time
	snapshot    postgresqlquery.Snapshot
	measure     int
	identity    []int
}

// build runs the production construction boundary for one argument set.
func (value scalarReadConstruction) build() (ScalarRead, error) {
	return newScalarRead(value.intent, value.binding, value.access, value.limits, value.startedAt,
		value.completedAt, value.snapshot, value.measure, value.identity)
}

// scalarReadConstructionFixture assembles one accepted argument set: a sealed
// scalar intent, an independently sealed eligibility binding, a valid access
// context, the default server-owned limits, one ordered UTC window, a complete
// nonempty snapshot built by the production canonicalizer, and the plan's
// measure and identity Snapshot ordinals.
func scalarReadConstructionFixture(t *testing.T) scalarReadConstruction {
	t.Helper()
	intent, _, _ := scalarExecutorFixture(t)
	binding, _, _ := sealedEligibility(t)
	access := database.AccessContext{
		OrganizationID: "scalar_org", PrincipalID: "scalar_principal", RequestID: "scalar_request",
	}
	if err := access.Validate(); err != nil {
		t.Fatalf("the fixture access context is not valid: %v", err)
	}
	columns := scalarSumNumericColumns("oid:1700:p:24:s:6", 24, 6)
	return scalarReadConstruction{
		intent:      intent,
		binding:     binding,
		access:      access,
		limits:      postgresqlquery.DefaultLimits(),
		startedAt:   time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		completedAt: time.Date(2026, 9, 10, 0, 0, 2, 0, time.UTC),
		snapshot:    scalarSumBuildSnapshot(t, columns, [][]any{{"grain-a", "1.250000"}, {"grain-b", "2.500000"}}),
		measure:     2,
		identity:    []int{1},
	}
}

// TestScalarReadConstructionRetainsExactSemanticContext proves the private
// construction boundary retains the exact sealed intent, eligibility binding,
// access context and limits, with a UTC Round(0) read window.
func TestScalarReadConstructionRetainsExactSemanticContext(t *testing.T) {
	fixture := scalarReadConstructionFixture(t)
	read, err := fixture.build()
	if err != nil {
		t.Fatalf("the exact fixture was refused: %v", err)
	}
	want := scalarReadContext{
		intent:      fixture.intent,
		binding:     fixture.binding,
		access:      fixture.access,
		limits:      fixture.limits,
		startedAt:   fixture.startedAt.UTC().Round(0),
		completedAt: fixture.completedAt.UTC().Round(0),
	}
	if !reflect.DeepEqual(read.context, want) {
		t.Fatalf("retained context = %+v, want the exact semantic context", read.context)
	}
	if read.context.startedAt != want.startedAt || read.context.completedAt != want.completedAt {
		t.Fatal("retained window is not the exact Round(0) wall times")
	}
	if read.context.startedAt.Location() != time.UTC || read.context.completedAt.Location() != time.UTC {
		t.Fatal("retained window is not normalized to UTC")
	}
	if !read.context.intent.Valid() || !read.context.binding.equal(fixture.binding) {
		t.Fatal("retained context does not reproduce the sealed intent and binding")
	}
	if read.measureOrdinal != fixture.measure || !slices.Equal(read.identityOrdinals, fixture.identity) {
		t.Fatal("retained mapping ordinals are not the plan's")
	}
}

// TestScalarReadConstructionNormalizesWindowToUTCRoundZero proves a non-UTC
// window is retained as its exact UTC Round(0) wall time.
func TestScalarReadConstructionNormalizesWindowToUTCRoundZero(t *testing.T) {
	fixture := scalarReadConstructionFixture(t)
	zone := time.FixedZone("fixture-offset", 3*3600)
	fixture.startedAt = time.Date(2026, 9, 10, 12, 30, 45, 123456789, zone)
	fixture.completedAt = fixture.startedAt.Add(1500 * time.Millisecond)
	read, err := fixture.build()
	if err != nil {
		t.Fatalf("the offset fixture was refused: %v", err)
	}
	wantStarted := fixture.startedAt.UTC().Round(0)
	wantCompleted := fixture.completedAt.UTC().Round(0)
	if read.context.startedAt != wantStarted || read.context.completedAt != wantCompleted {
		t.Fatalf("window = %v..%v, want %v..%v",
			read.context.startedAt, read.context.completedAt, wantStarted, wantCompleted)
	}
	if read.context.startedAt.Location() != time.UTC || read.context.completedAt.Location() != time.UTC {
		t.Fatal("an offset window was not normalized to UTC")
	}
}

// TestScalarReadConstructionChecksOrderBeforeNormalizingWindow pins the one
// micro-window order: newScalarRead must reject a zero or backwards instant
// while the monotonic reading is still attached, then normalize both times to
// UTC Round(0), and then reject a normalized wall window that runs backwards.
// Round(0) drops the monotonic reading, so the first check is the only place a
// monotonic ordering can be honored and the second is the only place a
// reversed persisted wall window can be caught.
func TestScalarReadConstructionChecksOrderBeforeNormalizingWindow(t *testing.T) {
	const filename = "scalar_executor.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var construction *ast.FuncDecl
	for _, declaration := range parsed.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Name.Name == "newScalarRead" {
			construction = function
		}
	}
	if construction == nil {
		t.Fatal("newScalarRead is not declared")
	}

	type windowCall struct {
		name string
		pos  token.Pos
	}
	var calls []windowCall
	ast.Inspect(construction.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		text, ok := astExpressionText(call.Fun)
		if !ok {
			return true
		}
		switch text {
		case "startedAt.IsZero", "completedAt.IsZero", "completedAt.Before", "startedAt.UTC", "completedAt.UTC":
			calls = append(calls, windowCall{text, call.Pos()})
		}
		return true
	})
	slices.SortStableFunc(calls, func(first, second windowCall) int { return int(first.pos) - int(second.pos) })
	got := make([]string, 0, len(calls))
	for _, call := range calls {
		got = append(got, call.name)
	}
	want := []string{
		"startedAt.IsZero", "completedAt.IsZero", "completedAt.Before",
		"startedAt.UTC", "completedAt.UTC", "completedAt.Before",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("newScalarRead window checks = %v, want the monotonic check before normalization and the wall check after %v", got, want)
	}
}

// TestScalarReadConstructionDetachesSnapshotBytesAndOrdinals proves the
// published ScalarRead owns a deep copy: mutating the reader's snapshot rows,
// canonical bytes, byte-backed JSON and text values, or identity ordinals after
// construction cannot alter it.
func TestScalarReadConstructionDetachesSnapshotBytesAndOrdinals(t *testing.T) {
	fixture := scalarReadConstructionFixture(t)
	fixture.snapshot = postgresqlquery.Snapshot{
		Rows: []postgresqlquery.Row{{
			Values: []postgresqlquery.ValueEntry{
				{Ordinal: 1, TypeFingerprint: "oid:3802", LogicalType: postgresqlquery.TypeJSONB,
					ValueTag: "JSONB", Value: jsontext.Value(`{"a":1}`)},
				{Ordinal: 2, TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
					ValueTag: "TEXT", Value: []byte("raw")},
			},
			Canonical: []byte(`[1,2]`),
			Hash:      "sha256:fixture",
		}},
		RowCount: 1, DecodedBytes: 5, CoverageComplete: true, SnapshotHash: "sha256:fixture",
	}
	fixture.identity = []int{1}
	read, err := fixture.build()
	if err != nil {
		t.Fatalf("the byte-backed fixture was refused: %v", err)
	}

	fixture.snapshot.Rows[0].Values[0].Value.(jsontext.Value)[1] = 'X'
	fixture.snapshot.Rows[0].Values[1].Value.([]byte)[0] = 'Y'
	fixture.snapshot.Rows[0].Canonical[0] = 'Z'
	fixture.snapshot.Rows[0] = postgresqlquery.Row{}
	fixture.identity[0] = 42

	if got := string(read.snapshot.Rows[0].Values[0].Value.(jsontext.Value)); got != `{"a":1}` {
		t.Fatalf("retained JSON value = %q, want the original bytes", got)
	}
	if got := string(read.snapshot.Rows[0].Values[1].Value.([]byte)); got != "raw" {
		t.Fatalf("retained []byte value = %q, want the original bytes", got)
	}
	if got := string(read.snapshot.Rows[0].Canonical); got != `[1,2]` {
		t.Fatalf("retained canonical bytes = %q, want the original bytes", got)
	}
	if len(read.snapshot.Rows) != 1 || read.snapshot.RowCount != 1 {
		t.Fatal("mutating the reader's rows reached the retained snapshot")
	}
	if !slices.Equal(read.identityOrdinals, []int{1}) {
		t.Fatalf("retained identity ordinals = %v, want [1]", read.identityOrdinals)
	}
}

// TestScalarReadSnapshotDetachmentPreservesNilAndEmpty proves the deep copy
// keeps nil and empty byte- and entry-backed members distinct exactly as the
// reader produced them.
func TestScalarReadSnapshotDetachmentPreservesNilAndEmpty(t *testing.T) {
	if detached := detachedScalarSnapshot(postgresqlquery.Snapshot{}); detached.Rows != nil {
		t.Fatal("a nil Rows slice did not stay nil")
	}
	if detached := detachedScalarSnapshot(postgresqlquery.Snapshot{Rows: []postgresqlquery.Row{}}); detached.Rows == nil || len(detached.Rows) != 0 {
		t.Fatal("an empty Rows slice did not stay a non-nil empty slice")
	}
	nilRow := detachedScalarSnapshot(postgresqlquery.Snapshot{Rows: []postgresqlquery.Row{{}}})
	if nilRow.Rows[0].Values != nil || nilRow.Rows[0].Canonical != nil {
		t.Fatal("nil row Values or Canonical did not stay nil")
	}
	emptyRow := detachedScalarSnapshot(postgresqlquery.Snapshot{Rows: []postgresqlquery.Row{{
		Values: []postgresqlquery.ValueEntry{}, Canonical: []byte{},
	}}})
	if emptyRow.Rows[0].Values == nil || emptyRow.Rows[0].Canonical == nil {
		t.Fatal("empty row Values or Canonical did not stay non-nil")
	}
	if detachedScalarValue(nil) != nil {
		t.Fatal("a nil Value did not stay nil")
	}
	if value, ok := detachedScalarValue([]byte(nil)).([]byte); !ok || value != nil {
		t.Fatal("a typed nil []byte Value did not stay a nil []byte")
	}
	if value, ok := detachedScalarValue([]byte{}).([]byte); !ok || value == nil {
		t.Fatal("an empty []byte Value did not stay a non-nil empty []byte")
	}
	if value, ok := detachedScalarValue(jsontext.Value(nil)).(jsontext.Value); !ok || value != nil {
		t.Fatal("a typed nil jsontext.Value did not stay a typed nil jsontext.Value")
	}
}

// TestScalarReadConstructionRefusesClosedInput proves every member outside the
// accepted shape returns the exact zero ScalarRead and the exact unwrapped
// errMismatch.
func TestScalarReadConstructionRefusesClosedInput(t *testing.T) {
	fixture := scalarReadConstructionFixture(t)
	cases := []struct {
		name   string
		mutate func(*scalarReadConstruction)
	}{
		{"zero intent", func(value *scalarReadConstruction) { value.intent = queryintent.ValidatedIntentV2{} }},
		{"zero binding", func(value *scalarReadConstruction) { value.binding = eligibilityBinding{} }},
		{"zero access", func(value *scalarReadConstruction) { value.access = database.AccessContext{} }},
		{"zero limits", func(value *scalarReadConstruction) { value.limits = postgresqlquery.Limits{} }},
		{"zero started", func(value *scalarReadConstruction) { value.startedAt = time.Time{} }},
		{"zero completed", func(value *scalarReadConstruction) { value.completedAt = time.Time{} }},
		{"reversed window", func(value *scalarReadConstruction) {
			value.completedAt = value.startedAt.Add(-time.Nanosecond)
		}},
		{"incomplete snapshot", func(value *scalarReadConstruction) { value.snapshot.CoverageComplete = false }},
		{"zero snapshot", func(value *scalarReadConstruction) { value.snapshot = postgresqlquery.Snapshot{} }},
		{"empty snapshot", func(value *scalarReadConstruction) { value.snapshot.Rows = []postgresqlquery.Row{} }},
		{"row count drift", func(value *scalarReadConstruction) { value.snapshot.RowCount++ }},
		{"zero measure ordinal", func(value *scalarReadConstruction) { value.measure = 0 }},
		{"negative measure ordinal", func(value *scalarReadConstruction) { value.measure = -1 }},
		{"empty identity ordinals", func(value *scalarReadConstruction) { value.identity = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			refuse := fixture
			test.mutate(&refuse)
			value, err := refuse.build()
			assertScalarReadRefusal(t, value, err)
		})
	}
}

// TestScalarReadMarshalsOpaqueEmptyObject proves a fully populated private
// ScalarRead still serializes as the opaque empty object.
func TestScalarReadMarshalsOpaqueEmptyObject(t *testing.T) {
	read, err := scalarReadConstructionFixture(t).build()
	if err != nil {
		t.Fatalf("the exact fixture was refused: %v", err)
	}
	for name, value := range map[string]ScalarRead{"zero": {}, "populated": read} {
		encoded, marshalErr := jsonv2.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("%s ScalarRead failed to marshal: %v", name, marshalErr)
		}
		if string(encoded) != "{}" {
			t.Fatalf("%s ScalarRead marshaled as %s, want {}", name, encoded)
		}
	}
}

// TestScalarReadSurfaceCarriesNoAuthorityCredentialOrSQLMember proves neither
// ScalarRead nor its retained context names or retains an authority result,
// credential, SQL plan, resolver or reader.
func TestScalarReadSurfaceCarriesNoAuthorityCredentialOrSQLMember(t *testing.T) {
	forbidden := []string{
		"authority", "credential", "secret", "dsn", "sql", "token", "capability",
		"envelope", "resolver", "handle", "receipt",
	}
	denied := []reflect.Type{
		reflect.TypeOf(repository.PostgreSQLAuthorityResult{}),
		reflect.TypeOf(repository.PostgreSQLAuthorityRequest{}),
		reflect.TypeOf(repository.PostgreSQLFilteredRead{}),
		reflect.TypeOf(&Resolver{}),
		reflect.TypeOf(&repository.PostgreSQLAuthorizedReader{}),
	}
	for _, surface := range []reflect.Type{reflect.TypeOf(ScalarRead{}), reflect.TypeOf(scalarReadContext{})} {
		for index := 0; index < surface.NumField(); index++ {
			field := surface.Field(index)
			for _, text := range forbidden {
				if strings.Contains(strings.ToLower(field.Name), text) {
					t.Fatalf("%s field %s carries a forbidden member: %s", surface, field.Name, text)
				}
			}
			for _, banned := range denied {
				if field.Type == banned {
					t.Fatalf("%s field %s retains %s", surface, field.Name, banned)
				}
			}
		}
	}
}
