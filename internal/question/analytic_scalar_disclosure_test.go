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

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// scalarDisclosureRecorder is the test double for scalarDependencyReauthorizer.
// It records the exact arguments of every call and returns the configured
// refusal, optionally running an onCall side effect (a cancellation) before it
// reports.
type scalarDisclosureRecorder struct {
	calls         int
	ctx           context.Context
	access        database.AccessContext
	workspaceID   string
	questionRunID string
	dependency    analyticsource.ScalarDependency
	err           error
	onCall        func()
}

func (recorder *scalarDisclosureRecorder) ReauthorizeScalarDependency(
	ctx context.Context,
	currentAccess database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency analyticsource.ScalarDependency,
) error {
	recorder.calls++
	recorder.ctx = ctx
	recorder.access = currentAccess
	recorder.workspaceID = workspaceID
	recorder.questionRunID = questionRunID
	recorder.dependency = dependency
	if recorder.onCall != nil {
		recorder.onCall()
	}
	return recorder.err
}

// TestAuthorizeScalarDisclosureNilPairSucceedsWithoutAuthority proves the nil
// pair is the sole accepted absence: it returns nil with zero reauthorizer
// calls, needs no installed catalog or resolver, and succeeds even with a nil
// context and zero access on the bare Service wrapper.
func TestAuthorizeScalarDisclosureNilPairSucceedsWithoutAuthority(t *testing.T) {
	recorder := &scalarDisclosureRecorder{}
	if err := authorizeScalarDisclosure(context.Background(), questionAccess(database.ActorKindHuman),
		"ws_operations", analyticScalarPairRunID, nil, recorder); err != nil {
		t.Fatalf("nil pair refused: %v", err)
	}
	if recorder.calls != 0 {
		t.Fatalf("nil pair calls = %d, want zero", recorder.calls)
	}

	if err := (&Service{}).authorizeAnalyticScalarDisclosure(
		nil, database.AccessContext{}, "", "", nil); err != nil {
		t.Fatalf("bare Service refused the nil pair: %v", err)
	}
}

// TestAuthorizeScalarDisclosureForwardsExactCurrentAccess proves the accepted
// pair calls the reauthorizer exactly once, forwarding the caller's current
// access unchanged for both the HUMAN and SERVICE actor kinds, the workspace,
// the trusted Question Run id and the opaque dependency.
func TestAuthorizeScalarDisclosureForwardsExactCurrentAccess(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, kind := range []database.ActorKind{database.ActorKindHuman, database.ActorKindService} {
		t.Run(string(kind), func(t *testing.T) {
			access := questionAccess(kind)
			recorder := &scalarDisclosureRecorder{}
			if err := authorizeScalarDisclosure(ctx, access, "workspace_scalar_pair",
				analyticScalarPairRunID, &pair, recorder); err != nil {
				t.Fatalf("accepted pair refused: %v", err)
			}
			if recorder.calls != 1 {
				t.Fatalf("calls = %d, want exactly one", recorder.calls)
			}
			if recorder.ctx != ctx {
				t.Fatal("reauthorizer received a different context")
			}
			if recorder.access != access {
				t.Fatalf("reauthorizer access = %+v, want the unchanged %+v", recorder.access, access)
			}
			if recorder.workspaceID != "workspace_scalar_pair" {
				t.Fatalf("reauthorizer workspace = %q, want workspace_scalar_pair", recorder.workspaceID)
			}
			if recorder.questionRunID != analyticScalarPairRunID {
				t.Fatalf("reauthorizer run = %q, want %q", recorder.questionRunID, analyticScalarPairRunID)
			}
			if recorder.dependency != pair.dependency {
				t.Fatal("reauthorizer did not receive the opaque dependency unchanged")
			}
		})
	}
}

// TestAuthorizeScalarDisclosureRefusesLocallyWithZeroCalls proves every invalid
// local input, invalid pair, broken binding and missing authority returns the
// exact content-free CodeUnavailable with zero reauthorizer calls.
func TestAuthorizeScalarDisclosureRefusesLocallyWithZeroCalls(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	invalidObservation := pair
	invalidObservation.observation.Value = "03888"
	crossReceipt := pair
	crossReceipt.observation.ReceiptDigest = "sha256:" + strings.Repeat("c", 64)

	for _, testCase := range []struct {
		name          string
		ctx           context.Context
		access        database.AccessContext
		workspaceID   string
		questionRunID string
		pair          *analyticScalarPair
		nilAuthority  bool
	}{
		{name: "nil context", ctx: nil, access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &pair},
		{name: "invalid access", ctx: context.Background(), access: database.AccessContext{},
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &pair},
		{name: "empty workspace", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "", questionRunID: analyticScalarPairRunID, pair: &pair},
		{name: "padded workspace", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: " ws_operations", questionRunID: analyticScalarPairRunID, pair: &pair},
		{name: "empty run", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: "", pair: &pair},
		{name: "punctuated run", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: "run/../x", pair: &pair},
		{name: "invalid observation", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &invalidObservation},
		{name: "cross-run binding", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: "run_scalar_other", pair: &pair},
		{name: "cross-receipt binding", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &crossReceipt},
		{name: "zero pair", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &analyticScalarPair{}},
		{name: "missing authority", ctx: context.Background(), access: questionAccess(database.ActorKindHuman),
			workspaceID: "ws_operations", questionRunID: analyticScalarPairRunID, pair: &pair, nilAuthority: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var recorder *scalarDisclosureRecorder
			var authority scalarDependencyReauthorizer
			if !testCase.nilAuthority {
				recorder = &scalarDisclosureRecorder{}
				authority = recorder
			}
			err := authorizeScalarDisclosure(testCase.ctx, testCase.access, testCase.workspaceID,
				testCase.questionRunID, testCase.pair, authority)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
			if recorder != nil && recorder.calls != 0 {
				t.Fatalf("local refusal calls = %d, want zero", recorder.calls)
			}
		})
	}
}

// scalarNilContext is a pointer-receiver context whose methods panic when
// invoked on a nil receiver. It proves the disclosure gate rejects a typed-nil
// context before ever calling ctx.Err or the reauthorizer.
type scalarNilContext struct{}

func (typed *scalarNilContext) Deadline() (time.Time, bool) {
	if typed == nil {
		panic("typed-nil context was used")
	}
	return time.Time{}, false
}

func (typed *scalarNilContext) Done() <-chan struct{} {
	if typed == nil {
		panic("typed-nil context was used")
	}
	return nil
}

func (typed *scalarNilContext) Err() error {
	if typed == nil {
		panic("typed-nil context was used")
	}
	return nil
}

func (typed *scalarNilContext) Value(key any) any {
	if typed == nil {
		panic("typed-nil context was used")
	}
	return nil
}

// TestAuthorizeScalarDisclosureRefusesTypedNilContext proves a present pair with
// a nil-interface context and with a typed-nil pointer context refuses exact
// CodeUnavailable with zero reauthorizer calls, and that the typed-nil context
// methods are never invoked.
func TestAuthorizeScalarDisclosureRefusesTypedNilContext(t *testing.T) {
	pair := analyticScalarPairFixture(t)

	for _, testCase := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "nil interface", ctx: nil},
		{name: "typed-nil pointer", ctx: (*scalarNilContext)(nil)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &scalarDisclosureRecorder{}
			err := authorizeScalarDisclosure(testCase.ctx, questionAccess(database.ActorKindHuman),
				"workspace_scalar_pair", analyticScalarPairRunID, &pair, recorder)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
			if recorder.calls != 0 {
				t.Fatalf("typed-nil context calls = %d, want zero", recorder.calls)
			}
		})
	}
}

// TestAuthorizeScalarDisclosureRefusesTypedNilReauthorizer proves a present pair
// with a typed-nil pointer reauthorizer refuses exact CodeUnavailable before the
// reauthorization call instead of panicking on the nil receiver.
func TestAuthorizeScalarDisclosureRefusesTypedNilReauthorizer(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var authority scalarDependencyReauthorizer = (*scalarDisclosureRecorder)(nil)
	err := authorizeScalarDisclosure(ctx, questionAccess(database.ActorKindHuman),
		"workspace_scalar_pair", analyticScalarPairRunID, &pair, authority)
	assertScalarDisclosureRefusal(t, err, CodeUnavailable)
}

// TestAuthorizeScalarDisclosureMissingInstallRefuses proves the Service wrapper
// refuses a present pair content-free when the one-shot installed capability is
// absent (bare Service), is a catalog without a resolver, or is a resolver
// without a valid catalog.
func TestAuthorizeScalarDisclosureMissingInstallRefuses(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	access := questionAccess(database.ActorKindHuman)

	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 400,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)})
	installed := analyticCandidateFixtureService(t, catalog)
	heldResolver := installed.analyticSourceResolver

	for _, testCase := range []struct {
		name    string
		service *Service
	}{
		{name: "bare service", service: &Service{}},
		{name: "catalog without resolver", service: &Service{datasetProfileCatalog: catalog}},
		{name: "resolver without catalog", service: &Service{analyticSourceResolver: heldResolver}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.service.authorizeAnalyticScalarDisclosure(ctx, access,
				"workspace_scalar_pair", analyticScalarPairRunID, &pair)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
		})
	}
	if installed.analyticSourceResolver != heldResolver || !installed.datasetProfileCatalog.Valid() {
		t.Fatal("missing-install refusals mutated the installed slots")
	}
}

// TestAuthorizeScalarDisclosureServiceMapsResolverRefusal proves the wrapper
// delegates to the installed concrete resolver and maps its refusal to the
// content-free CodeNotFound without mutating the installed slots.
func TestAuthorizeScalarDisclosureServiceMapsResolverRefusal(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 401,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)})
	service := analyticCandidateFixtureService(t, catalog)
	heldResolver := service.analyticSourceResolver

	err := service.authorizeAnalyticScalarDisclosure(ctx, questionAccess(database.ActorKindHuman),
		"workspace_scalar_pair", analyticScalarPairRunID, &pair)
	assertScalarDisclosureRefusal(t, err, CodeNotFound)
	if service.analyticSourceResolver != heldResolver || !service.datasetProfileCatalog.Valid() {
		t.Fatal("resolver refusal mutated the installed slots")
	}
}

// TestAuthorizeScalarDisclosureMapsRefusalToContentFreeNotFound proves any
// concrete reauthorization refusal becomes the exact content-free CodeNotFound
// with no wrapped cause and no dependency, identity, receipt or database fact.
func TestAuthorizeScalarDisclosureMapsRefusalToContentFreeNotFound(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	secret := "dependency catalog_scalar_pair connection_scalar_pair 3888 " + pair.observation.ReceiptDigest
	recorder := &scalarDisclosureRecorder{err: errors.New(secret)}

	err := authorizeScalarDisclosure(context.Background(), questionAccess(database.ActorKindService),
		"workspace_scalar_pair", analyticScalarPairRunID, &pair, recorder)
	assertScalarDisclosureRefusal(t, err, CodeNotFound)
	if recorder.calls != 1 {
		t.Fatalf("calls = %d, want exactly one", recorder.calls)
	}
	assertScalarDisclosureHidesFacts(t, err)
}

// TestAuthorizeScalarDisclosureRefusesFailedContexts proves a context canceled
// or expired before the call refuses before any reauthorizer call, and a context
// that fails during or after the call refuses CodeUnavailable rather than
// trusting the call result.
func TestAuthorizeScalarDisclosureRefusesFailedContexts(t *testing.T) {
	pair := analyticScalarPairFixture(t)
	access := questionAccess(database.ActorKindHuman)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer expire()
	if expired.Err() == nil {
		t.Fatal("expired fixture context is still live")
	}

	for _, testCase := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "canceled before", ctx: canceled},
		{name: "expired before", ctx: expired},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &scalarDisclosureRecorder{}
			err := authorizeScalarDisclosure(testCase.ctx, access, "workspace_scalar_pair",
				analyticScalarPairRunID, &pair, recorder)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
			if recorder.calls != 0 {
				t.Fatalf("pre-call context failure calls = %d, want zero", recorder.calls)
			}
		})
	}

	t.Run("canceled during call", func(t *testing.T) {
		ctx, duringCancel := context.WithCancel(context.Background())
		defer duringCancel()
		recorder := &scalarDisclosureRecorder{onCall: duringCancel}
		err := authorizeScalarDisclosure(ctx, access, "workspace_scalar_pair",
			analyticScalarPairRunID, &pair, recorder)
		assertScalarDisclosureRefusal(t, err, CodeUnavailable)
		if recorder.calls != 1 {
			t.Fatalf("during-call cancellation calls = %d, want exactly one", recorder.calls)
		}
	})

	t.Run("canceled during call beside refusal", func(t *testing.T) {
		ctx, duringCancel := context.WithCancel(context.Background())
		defer duringCancel()
		recorder := &scalarDisclosureRecorder{onCall: duringCancel, err: errors.New("late refusal")}
		err := authorizeScalarDisclosure(ctx, access, "workspace_scalar_pair",
			analyticScalarPairRunID, &pair, recorder)
		assertScalarDisclosureRefusal(t, err, CodeUnavailable)
		if recorder.calls != 1 {
			t.Fatalf("during-call cancellation calls = %d, want exactly one", recorder.calls)
		}
	})
}

// TestAuthorizeScalarDisclosureNeverDisclosesPairOrErrorFacts proves generic
// JSON of the pair either refuses to serialize the unexported-only struct or
// yields the opaque empty object, and that every refusal error, its JSON and its
// serialization error hide the GM value, contributing rows, metric, dataset, run
// id, receipt digest and retained database identities.
func TestAuthorizeScalarDisclosureNeverDisclosesPairOrErrorFacts(t *testing.T) {
	pair := analyticScalarPairFixture(t)

	assertScalarDisclosureJSONHidesFacts(t, pair)
	assertScalarDisclosureJSONHidesFacts(t, pair.dependency)

	refusal := &scalarDisclosureRecorder{err: errors.New("dependency refusal")}
	unavailableErr := authorizeScalarDisclosure(nil, questionAccess(database.ActorKindHuman),
		"ws_operations", analyticScalarPairRunID, &pair, refusal)
	notFoundErr := authorizeScalarDisclosure(context.Background(), questionAccess(database.ActorKindHuman),
		"workspace_scalar_pair", analyticScalarPairRunID, &pair, refusal)

	for _, refusalErr := range []error{unavailableErr, notFoundErr} {
		assertScalarDisclosureHidesFacts(t, refusalErr)
		assertScalarDisclosureJSONHidesFacts(t, refusalErr)
	}
}

// TestAnalyticScalarDisclosureSurfaceIsPrivate proves by AST and reflection that
// the file adds exactly one private interface, the private gate helper, the
// private nil-interface check and one private Service method, and no exported
// setter, constructor or install path.
func TestAnalyticScalarDisclosureSurfaceIsPrivate(t *testing.T) {
	const filename = "analytic_scalar_disclosure.go"
	rawFile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	functions := []string{}
	methods := []string{}
	types := []string{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Name.IsExported() {
				t.Fatalf("%s declares the exported function %s", filename, typed.Name.Name)
			}
			if typed.Recv == nil {
				functions = append(functions, typed.Name.Name)
			} else {
				methods = append(methods, typed.Name.Name)
			}
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch named := specification.(type) {
				case *ast.TypeSpec:
					if named.Name.IsExported() || named.Name.Name != "scalarDependencyReauthorizer" {
						t.Fatalf("%s declares the type %s, want only the private interface", filename, named.Name.Name)
					}
					types = append(types, named.Name.Name)
					interfaceType, ok := named.Type.(*ast.InterfaceType)
					if !ok || interfaceType.Methods == nil || len(interfaceType.Methods.List) != 1 {
						t.Fatalf("%s must declare exactly one interface method", filename)
					}
				case *ast.ValueSpec:
					for _, name := range named.Names {
						if name.IsExported() {
							t.Fatalf("%s declares the exported value %s", filename, name.Name)
						}
					}
				}
			}
		}
	}
	if !reflect.DeepEqual(functions, []string{"scalarInterfaceIsNil", "authorizeScalarDisclosure"}) {
		t.Fatalf("functions = %v, want exactly the private helpers", functions)
	}
	if !reflect.DeepEqual(methods, []string{"authorizeAnalyticScalarDisclosure"}) {
		t.Fatalf("methods = %v, want exactly the private Service wrapper", methods)
	}
	if !reflect.DeepEqual(types, []string{"scalarDependencyReauthorizer"}) {
		t.Fatalf("types = %v, want exactly the private interface", types)
	}

	authority := reflect.TypeOf((*scalarDependencyReauthorizer)(nil)).Elem()
	if authority.NumMethod() != 1 || authority.Method(0).Name != "ReauthorizeScalarDependency" {
		t.Fatalf("scalarDependencyReauthorizer surface = %v, want one ReauthorizeScalarDependency method", authority)
	}
}

// assertScalarDisclosureRefusal proves one refusal is the exact content-free
// requested code with an empty unwrap chain and an exact code message.
func assertScalarDisclosureRefusal(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != want {
		t.Fatalf("refusal = %v, want content-free %s", err, want)
	}
	if typed.cause != nil {
		t.Fatalf("refusal cause = %v, want nil", typed.cause)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
	if err.Error() != string(want) {
		t.Fatalf("refusal message = %q, want the exact code %q", err.Error(), want)
	}
}

// scalarDisclosureSecretFragments are the controlled facts a refusal must never
// carry: the GM value, contributing rows, metric, dataset, Question Run, receipt
// digest and every retained database identity.
func scalarDisclosureSecretFragments() []string {
	return []string{
		"3888", "407", "assigned_tasks", "gm_assignments", "run_scalar_pair",
		"sha256:", "catalog_scalar_pair", "connection_scalar_pair",
		"workspace_scalar_pair", "database_scalar_pair", "org_scalar_pair", "source_scope_scalar_pair",
	}
}

// assertScalarDisclosureHidesFacts proves one refusal message carries no
// controlled fact.
func assertScalarDisclosureHidesFacts(t *testing.T, err error) {
	t.Helper()
	message := err.Error()
	for _, fragment := range scalarDisclosureSecretFragments() {
		if strings.Contains(message, fragment) {
			t.Fatalf("refusal %q discloses the fact %q", message, fragment)
		}
	}
}

// assertScalarDisclosureJSONHidesFacts proves generic JSON of one value either
// serializes to the opaque empty object or refuses to serialize the
// unexported-only struct, and in neither case carries a controlled fact.
func assertScalarDisclosureJSONHidesFacts(t *testing.T, value any) {
	t.Helper()
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		for _, fragment := range scalarDisclosureSecretFragments() {
			if strings.Contains(err.Error(), fragment) {
				t.Fatalf("JSON error %q discloses the fact %q", err.Error(), fragment)
			}
		}
		return
	}
	if string(raw) != "{}" {
		t.Fatalf("JSON = %s, want the opaque empty object", raw)
	}
	for _, fragment := range scalarDisclosureSecretFragments() {
		if strings.Contains(string(raw), fragment) {
			t.Fatalf("JSON %s discloses the fact %q", raw, fragment)
		}
	}
}
