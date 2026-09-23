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
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// scalarBatchDisclosureRecorder is the test double for scalarDependencyReauthorizer
// used by the batch gate. It records every call in order, keeps the exact
// dependency per run id, and returns the configured per-run refusal.
type scalarBatchDisclosureRecorder struct {
	calls        int
	order        []string
	ctx          context.Context
	access       database.AccessContext
	workspaceID  string
	dependencies map[string]analyticsource.ScalarDependency
	errs         map[string]error
	onCall       func(runID string)
}

func (recorder *scalarBatchDisclosureRecorder) ReauthorizeScalarDependency(
	ctx context.Context,
	currentAccess database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency analyticsource.ScalarDependency,
) error {
	recorder.calls++
	recorder.order = append(recorder.order, questionRunID)
	recorder.ctx = ctx
	recorder.access = currentAccess
	recorder.workspaceID = workspaceID
	if recorder.dependencies == nil {
		recorder.dependencies = map[string]analyticsource.ScalarDependency{}
	}
	recorder.dependencies[questionRunID] = dependency
	if recorder.onCall != nil {
		recorder.onCall(questionRunID)
	}
	return recorder.errs[questionRunID]
}

// analyticScalarBatchPair builds one accepted pair bound to the supplied
// Question Run id from the approved local observation and the source-owned
// canonical dependency fixture.
func analyticScalarBatchPair(t *testing.T, runID string) *analyticScalarPair {
	t.Helper()
	observation := analyticScalarObservationFixture(t)
	dependency := analyticScalarPairDependency(t, runID, observation.ReceiptDigest)
	pair := analyticScalarPair{observation: observation, dependency: dependency}
	return &pair
}

// TestAuthorizeScalarDisclosureBatchMixedLegacyAuthorizedDenied proves a mixed
// batch calls the single gate once per present pair in sorted order, skips the
// legacy nil pair with no call, collects the CodeNotFound run id and leaves
// irrelevant pair-map entries untouched.
func TestAuthorizeScalarDisclosureBatchMixedLegacyAuthorizedDenied(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	beta := analyticScalarBatchPair(t, "run_batch_beta")
	delta := analyticScalarBatchPair(t, "run_batch_delta")
	irrelevant := analyticScalarBatchPair(t, "run_batch_irrelevant")
	pairs := map[string]*analyticScalarPair{
		"run_batch_alpha":      alpha,
		"run_batch_beta":       beta,
		"run_batch_delta":      delta,
		"run_batch_irrelevant": irrelevant,
	}
	recorder := &scalarBatchDisclosureRecorder{
		errs: map[string]error{"run_batch_beta": errors.New("opaque refusal")},
	}

	denied, err := authorizeScalarDisclosureBatch(context.Background(),
		questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
		[]string{"run_batch_gamma", "run_batch_delta", "run_batch_beta", "run_batch_alpha"},
		pairs, recorder)
	if err != nil {
		t.Fatalf("mixed batch refused: %v", err)
	}
	if !reflect.DeepEqual(denied, []string{"run_batch_beta"}) {
		t.Fatalf("denied = %v, want [run_batch_beta]", denied)
	}
	if !reflect.DeepEqual(recorder.order, []string{"run_batch_alpha", "run_batch_beta", "run_batch_delta"}) {
		t.Fatalf("call order = %v, want each present run once in sorted order", recorder.order)
	}
	for runID, pair := range map[string]*analyticScalarPair{
		"run_batch_alpha": alpha, "run_batch_beta": beta, "run_batch_delta": delta,
	} {
		if recorder.dependencies[runID] != pair.dependency {
			t.Fatalf("dependency for %s was not forwarded unchanged", runID)
		}
	}
	if _, called := recorder.dependencies["run_batch_irrelevant"]; called {
		t.Fatal("irrelevant pair-map entry was reauthorized")
	}
}

// TestAuthorizeScalarDisclosureBatchDeduplicatesAndSorts proves one id is
// processed exactly once regardless of repetition or caller order.
func TestAuthorizeScalarDisclosureBatchDeduplicatesAndSorts(t *testing.T) {
	pairs := map[string]*analyticScalarPair{
		"run_batch_alpha": analyticScalarBatchPair(t, "run_batch_alpha"),
		"run_batch_beta":  analyticScalarBatchPair(t, "run_batch_beta"),
	}
	recorder := &scalarBatchDisclosureRecorder{}

	denied, err := authorizeScalarDisclosureBatch(context.Background(),
		questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
		[]string{"run_batch_beta", "run_batch_alpha", "run_batch_beta", "run_batch_alpha"},
		pairs, recorder)
	if err != nil || denied != nil {
		t.Fatalf("dedup batch = (%v, %v), want (nil, nil)", denied, err)
	}
	if recorder.calls != 2 {
		t.Fatalf("calls = %d, want exactly two unique ids", recorder.calls)
	}
	if !reflect.DeepEqual(recorder.order, []string{"run_batch_alpha", "run_batch_beta"}) {
		t.Fatalf("call order = %v, want sorted unique ids", recorder.order)
	}
}

// TestAuthorizeScalarDisclosureBatchLaterFatalReturnsNilNotPrefix proves a fatal
// error after an earlier denial aborts with a nil denied list and the exact bare
// error rather than a partial prefix.
func TestAuthorizeScalarDisclosureBatchLaterFatalReturnsNilNotPrefix(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	beta := analyticScalarBatchPair(t, "run_batch_beta")
	beta.observation.Value = "03888"
	pairs := map[string]*analyticScalarPair{
		"run_batch_alpha": alpha,
		"run_batch_beta":  beta,
	}
	recorder := &scalarBatchDisclosureRecorder{
		errs: map[string]error{"run_batch_alpha": errors.New("first run denied")},
	}

	denied, err := authorizeScalarDisclosureBatch(context.Background(),
		questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
		[]string{"run_batch_beta", "run_batch_alpha"}, pairs, recorder)
	assertScalarDisclosureRefusal(t, err, CodeUnavailable)
	if denied != nil {
		t.Fatalf("denied = %v, want nil after a later fatal error", denied)
	}
	if recorder.calls != 1 || !reflect.DeepEqual(recorder.order, []string{"run_batch_alpha"}) {
		t.Fatalf("calls = %v, want only the earlier denied run", recorder.order)
	}
}

// TestAuthorizeScalarDisclosureBatchRefusesInvalidCandidateBeforeAuthority
// proves an empty or invalid candidate id is never accepted as legacy: the batch
// fails content-free with a nil result before any reauthorizer call, even when a
// valid present candidate sorts before the invalid one. That last ordering
// distinguishes the eager whole-batch validation from a lazy validate-and-call
// loop, which would reauthorize the earlier valid run before noticing the later
// invalid id.
func TestAuthorizeScalarDisclosureBatchRefusesInvalidCandidateBeforeAuthority(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	pairs := map[string]*analyticScalarPair{"run_batch_alpha": alpha}

	for _, testCase := range []struct {
		name       string
		candidates []string
	}{
		{name: "empty beside present", candidates: []string{"run_batch_alpha", ""}},
		{name: "padded beside present", candidates: []string{" run_batch_alpha", "run_batch_alpha"}},
		{name: "punctuated beside present", candidates: []string{"run_batch_alpha", "run/../x"}},
		{name: "valid present sorts before later invalid", candidates: []string{"run_batch_alpha", "z invalid"}},
		{name: "only invalid legacy", candidates: []string{"", "bad id"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &scalarBatchDisclosureRecorder{}
			denied, err := authorizeScalarDisclosureBatch(context.Background(),
				questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
				testCase.candidates, pairs, recorder)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
			if denied != nil {
				t.Fatalf("denied = %v, want nil for an invalid candidate", denied)
			}
			if recorder.calls != 0 {
				t.Fatalf("calls = %d, want zero before any authority work", recorder.calls)
			}
		})
	}
}

// TestAuthorizeScalarDisclosureBatchRefusesCancellation proves a failed context
// refuses CodeUnavailable without trusting a call result, while an all-legacy
// batch performs no authority work and never reads the context.
func TestAuthorizeScalarDisclosureBatchRefusesCancellation(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	pairs := map[string]*analyticScalarPair{"run_batch_alpha": alpha}
	access := questionAccess(database.ActorKindHuman)

	t.Run("canceled before present pair", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		recorder := &scalarBatchDisclosureRecorder{}
		denied, err := authorizeScalarDisclosureBatch(ctx, access, "workspace_scalar_batch",
			[]string{"run_batch_alpha"}, pairs, recorder)
		assertScalarDisclosureRefusal(t, err, CodeUnavailable)
		if denied != nil || recorder.calls != 0 {
			t.Fatalf("pre-call cancellation = (%v, %d calls), want (nil, 0)", denied, recorder.calls)
		}
	})

	t.Run("canceled during call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		recorder := &scalarBatchDisclosureRecorder{onCall: func(string) { cancel() }}
		denied, err := authorizeScalarDisclosureBatch(ctx, access, "workspace_scalar_batch",
			[]string{"run_batch_alpha"}, pairs, recorder)
		assertScalarDisclosureRefusal(t, err, CodeUnavailable)
		if denied != nil || recorder.calls != 1 {
			t.Fatalf("during-call cancellation = (%v, %d calls), want (nil, 1)", denied, recorder.calls)
		}
	})

	t.Run("all legacy ignores canceled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		recorder := &scalarBatchDisclosureRecorder{}
		denied, err := authorizeScalarDisclosureBatch(ctx, access, "workspace_scalar_batch",
			[]string{"run_batch_legacy"}, map[string]*analyticScalarPair{}, recorder)
		if err != nil || denied != nil || recorder.calls != 0 {
			t.Fatalf("all-legacy batch = (%v, %v, %d calls), want (nil, nil, 0)",
				denied, err, recorder.calls)
		}
	})
}

// TestAuthorizeScalarDisclosureBatchForwardsCurrentAccess proves the batch
// forwards the caller's current access unchanged for the HUMAN and SERVICE actor
// kinds together with the workspace, trusted run id and opaque dependency.
func TestAuthorizeScalarDisclosureBatchForwardsCurrentAccess(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	pairs := map[string]*analyticScalarPair{"run_batch_alpha": alpha}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	for _, kind := range []database.ActorKind{database.ActorKindHuman, database.ActorKindService} {
		t.Run(string(kind), func(t *testing.T) {
			access := questionAccess(kind)
			recorder := &scalarBatchDisclosureRecorder{}
			denied, err := authorizeScalarDisclosureBatch(ctx, access, "workspace_scalar_batch",
				[]string{"run_batch_alpha"}, pairs, recorder)
			if err != nil || denied != nil || recorder.calls != 1 {
				t.Fatalf("batch = (%v, %v, %d calls), want (nil, nil, 1)", denied, err, recorder.calls)
			}
			if recorder.ctx != ctx || recorder.access != access ||
				recorder.workspaceID != "workspace_scalar_batch" ||
				recorder.dependencies["run_batch_alpha"] != alpha.dependency {
				t.Fatal("batch did not forward the exact current access, workspace and dependency")
			}
		})
	}
}

// TestAuthorizeScalarDisclosureBatchIgnoresIrrelevantPairs proves a pair-map
// entry outside the candidate list never triggers a call and, through the
// wrapper, never forces an install.
func TestAuthorizeScalarDisclosureBatchIgnoresIrrelevantPairs(t *testing.T) {
	irrelevant := analyticScalarBatchPair(t, "run_batch_irrelevant")
	pairs := map[string]*analyticScalarPair{"run_batch_irrelevant": irrelevant}

	recorder := &scalarBatchDisclosureRecorder{}
	denied, err := authorizeScalarDisclosureBatch(context.Background(),
		questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
		[]string{"run_batch_legacy"}, pairs, recorder)
	if err != nil || denied != nil || recorder.calls != 0 {
		t.Fatalf("irrelevant pair = (%v, %v, %d calls), want (nil, nil, 0)",
			denied, err, recorder.calls)
	}

	denied, err = (&Service{}).authorizeAnalyticScalarDisclosureBatch(context.Background(),
		questionAccess(database.ActorKindHuman), "workspace_scalar_batch",
		[]string{"run_batch_legacy"}, pairs)
	if err != nil || denied != nil {
		t.Fatalf("bare Service with an irrelevant pair = (%v, %v), want (nil, nil)", denied, err)
	}
}

// TestAuthorizeScalarDisclosureBatchServiceWrapperInstall proves the wrapper
// requires the installed catalog and resolver only when a candidate carries a
// present pair, and never mutates the installed slots.
func TestAuthorizeScalarDisclosureBatchServiceWrapperInstall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	access := questionAccess(database.ActorKindHuman)
	const workspaceID = "workspace_scalar_batch"

	pair := analyticScalarBatchPair(t, "run_batch_alpha")
	present := map[string]*analyticScalarPair{"run_batch_alpha": pair}
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 402,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)})
	installed := analyticCandidateFixtureService(t, catalog)
	heldResolver := installed.analyticSourceResolver

	t.Run("all legacy succeeds without install", func(t *testing.T) {
		denied, err := (&Service{}).authorizeAnalyticScalarDisclosureBatch(ctx, access, workspaceID,
			[]string{"run_batch_legacy", "run_batch_missing"}, map[string]*analyticScalarPair{})
		if err != nil || denied != nil {
			t.Fatalf("all-legacy bare Service = (%v, %v), want (nil, nil)", denied, err)
		}
	})

	t.Run("missing install with present pair", func(t *testing.T) {
		for _, service := range []*Service{
			{},
			{datasetProfileCatalog: catalog},
			{analyticSourceResolver: heldResolver},
		} {
			denied, err := service.authorizeAnalyticScalarDisclosureBatch(ctx, access, workspaceID,
				[]string{"run_batch_alpha"}, present)
			assertScalarDisclosureRefusal(t, err, CodeUnavailable)
			if denied != nil {
				t.Fatalf("denied = %v, want nil for a missing install", denied)
			}
		}
	})

	t.Run("installed resolver refusal is denied", func(t *testing.T) {
		denied, err := installed.authorizeAnalyticScalarDisclosureBatch(ctx, access, workspaceID,
			[]string{"run_batch_alpha"}, present)
		if err != nil {
			t.Fatalf("installed batch refused: %v", err)
		}
		if !reflect.DeepEqual(denied, []string{"run_batch_alpha"}) {
			t.Fatalf("denied = %v, want [run_batch_alpha]", denied)
		}
	})

	if installed.analyticSourceResolver != heldResolver || !installed.datasetProfileCatalog.Valid() {
		t.Fatal("batch wrapper mutated the installed slots")
	}
}

// TestAuthorizeScalarDisclosureBatchIsDeterministicAndContentFree proves the
// same logical batch yields the same sorted denied ids regardless of input order
// or repetition, and that a fatal refusal stays content-free.
func TestAuthorizeScalarDisclosureBatchIsDeterministicAndContentFree(t *testing.T) {
	alpha := analyticScalarBatchPair(t, "run_batch_alpha")
	beta := analyticScalarBatchPair(t, "run_batch_beta")
	pairs := map[string]*analyticScalarPair{
		"run_batch_alpha": alpha,
		"run_batch_beta":  beta,
	}
	refusal := errors.New("dependency 3888 sha256: receipt")
	access := questionAccess(database.ActorKindHuman)

	first, firstErr := authorizeScalarDisclosureBatch(context.Background(), access, "workspace_scalar_batch",
		[]string{"run_batch_beta", "run_batch_alpha", "run_batch_beta"}, pairs,
		&scalarBatchDisclosureRecorder{errs: map[string]error{"run_batch_beta": refusal}})
	second, secondErr := authorizeScalarDisclosureBatch(context.Background(), access, "workspace_scalar_batch",
		[]string{"run_batch_alpha", "run_batch_beta"}, pairs,
		&scalarBatchDisclosureRecorder{errs: map[string]error{"run_batch_beta": refusal}})
	if firstErr != nil || secondErr != nil {
		t.Fatalf("deterministic batches refused: %v, %v", firstErr, secondErr)
	}
	if !reflect.DeepEqual(first, second) || !reflect.DeepEqual(first, []string{"run_batch_beta"}) {
		t.Fatalf("denied = %v and %v, want the stable [run_batch_beta]", first, second)
	}
	for _, runID := range first {
		for _, fragment := range scalarDisclosureSecretFragments() {
			if strings.Contains(runID, fragment) {
				t.Fatalf("denied id %q carries the controlled fact %q", runID, fragment)
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	denied, err := authorizeScalarDisclosureBatch(ctx, access, "workspace_scalar_batch",
		[]string{"run_batch_alpha"}, pairs, &scalarBatchDisclosureRecorder{})
	assertScalarDisclosureRefusal(t, err, CodeUnavailable)
	assertScalarDisclosureHidesFacts(t, err)
	if denied != nil {
		t.Fatalf("denied = %v, want nil on a fatal context refusal", denied)
	}
}

// TestAnalyticScalarBatchDisclosureSurfaceIsPrivate proves by AST that the batch
// file declares exactly the one private helper, the one private Service wrapper
// and no exported or extra declaration.
func TestAnalyticScalarBatchDisclosureSurfaceIsPrivate(t *testing.T) {
	const filename = "analytic_scalar_batch_disclosure.go"
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
					if named.Name.IsExported() {
						t.Fatalf("%s declares the exported type %s", filename, named.Name.Name)
					}
					types = append(types, named.Name.Name)
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
	if !reflect.DeepEqual(functions, []string{"authorizeScalarDisclosureBatch"}) {
		t.Fatalf("functions = %v, want exactly the private batch helper", functions)
	}
	if !reflect.DeepEqual(methods, []string{"authorizeAnalyticScalarDisclosureBatch"}) {
		t.Fatalf("methods = %v, want exactly the private Service wrapper", methods)
	}
	if len(types) != 0 {
		t.Fatalf("types = %v, want no new type", types)
	}
}
