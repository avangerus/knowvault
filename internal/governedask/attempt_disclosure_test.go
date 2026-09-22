package governedask

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

const (
	reauthorizationSQLHash    = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	reauthorizationResultHash = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func reauthorizationAccess() database.AccessContext {
	return database.AccessContext{OrganizationID: "org_0001", PrincipalID: "principal_0001", RequestID: "request_0001"}
}

func reauthorizationDisclosure() AttemptDisclosure {
	return AttemptDisclosure{
		AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: reauthorizationSQLHash,
		ExposedSchemaRevision: 7, ResultDigest: reauthorizationResultHash,
	}
}

func reauthorizationAttempt() governedquery.ExecutedAttempt {
	disclosure := reauthorizationDisclosure()
	return governedquery.ExecutedAttempt{
		AttemptID: disclosure.AttemptID, ConnectionID: disclosure.ConnectionID, SQLHash: disclosure.SQLHash,
		ExposedSchemaRevision: disclosure.ExposedSchemaRevision,
	}
}

func reauthorizationService(gate func(context.Context, database.AccessContext, string) error, loader func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error)) *Service {
	return &Service{
		enabled: true, config: governedquery.Config{ConnectionID: "conn_0001"},
		disclosureCheck: gate, attemptLoader: loader,
	}
}

func assertReauthorizationCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func TestReauthorizeAttemptForwardsCurrentAccessAndNeverExecutesSQL(t *testing.T) {
	ctx := context.Background()
	access := reauthorizationAccess()
	disclosure := reauthorizationDisclosure()
	var gateCtx context.Context
	var gateAccess database.AccessContext
	var gateWorkspace string
	var loadCtx context.Context
	var loadAccess database.AccessContext
	var loadWorkspace, loadAttemptID string
	service := reauthorizationService(
		func(gotCtx context.Context, gotAccess database.AccessContext, workspaceID string) error {
			gateCtx, gateAccess, gateWorkspace = gotCtx, gotAccess, workspaceID
			return nil
		},
		func(gotCtx context.Context, gotAccess database.AccessContext, workspaceID, attemptID string) (governedquery.ExecutedAttempt, error) {
			loadCtx, loadAccess, loadWorkspace, loadAttemptID = gotCtx, gotAccess, workspaceID, attemptID
			return reauthorizationAttempt(), nil
		},
	)

	if err := service.ReauthorizeAttempt(ctx, access, "ws_0001", disclosure); err != nil {
		t.Fatalf("ReauthorizeAttempt() error = %v", err)
	}
	if gateCtx != ctx || loadCtx != ctx || !reflect.DeepEqual(gateAccess, access) || !reflect.DeepEqual(loadAccess, access) {
		t.Fatal("ReauthorizeAttempt did not forward the current context and access")
	}
	if gateWorkspace != "ws_0001" || loadWorkspace != "ws_0001" || loadAttemptID != disclosure.AttemptID {
		t.Fatalf("unexpected current gate/load scope: gate=%q loader=%q/%q", gateWorkspace, loadWorkspace, loadAttemptID)
	}
	// The minimal test service has no executable config. Success proves this
	// path only gates and loads the saved attempt; it does not rerun SQL.
}

func TestReauthorizeAttemptRejectsInvalidLocalInputWithoutRepositoryCalls(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		ctx        context.Context
		access     database.AccessContext
		workspace  string
		disclosure AttemptDisclosure
	}{
		{name: "nil context", access: reauthorizationAccess(), workspace: "ws_0001", disclosure: reauthorizationDisclosure()},
		{name: "invalid access", ctx: context.Background(), workspace: "ws_0001", disclosure: reauthorizationDisclosure()},
		{name: "invalid workspace", ctx: context.Background(), access: reauthorizationAccess(), workspace: "bad workspace", disclosure: reauthorizationDisclosure()},
		{name: "invalid attempt", ctx: context.Background(), access: reauthorizationAccess(), workspace: "ws_0001", disclosure: AttemptDisclosure{ConnectionID: "conn_0001", SQLHash: reauthorizationSQLHash, ExposedSchemaRevision: 7, ResultDigest: reauthorizationResultHash}},
		{name: "invalid connection", ctx: context.Background(), access: reauthorizationAccess(), workspace: "ws_0001", disclosure: AttemptDisclosure{AttemptID: "gqat_0001", ConnectionID: "bad connection", SQLHash: reauthorizationSQLHash, ExposedSchemaRevision: 7, ResultDigest: reauthorizationResultHash}},
		{name: "invalid sql hash", ctx: context.Background(), access: reauthorizationAccess(), workspace: "ws_0001", disclosure: AttemptDisclosure{AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: "sha256:invalid", ExposedSchemaRevision: 7, ResultDigest: reauthorizationResultHash}},
		{name: "invalid revision", ctx: context.Background(), access: reauthorizationAccess(), workspace: "ws_0001", disclosure: AttemptDisclosure{AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: reauthorizationSQLHash, ResultDigest: reauthorizationResultHash}},
		{name: "invalid result digest", ctx: context.Background(), access: reauthorizationAccess(), workspace: "ws_0001", disclosure: AttemptDisclosure{AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: reauthorizationSQLHash, ExposedSchemaRevision: 7, ResultDigest: "sha256:invalid"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			service := reauthorizationService(
				func(context.Context, database.AccessContext, string) error { calls++; return nil },
				func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
					calls++
					return reauthorizationAttempt(), nil
				},
			)
			err := service.ReauthorizeAttempt(testCase.ctx, testCase.access, testCase.workspace, testCase.disclosure)
			assertReauthorizationCode(t, err, CodeRequestInvalid)
			if calls != 0 {
				t.Fatalf("invalid local input made %d repository calls, want 0", calls)
			}
		})
	}
}

func TestReauthorizeAttemptCollapsesRevocationAndAttemptAbsence(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		gateErr   error
		loadErr   error
		wantLoads int
	}{
		{name: "revoked live binding", gateErr: &Error{code: CodeLiveQueriesOff}},
		{name: "foreign workspace or attempt", loadErr: errors.New("foreign-attempt-secret"), wantLoads: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			loads := 0
			service := reauthorizationService(
				func(context.Context, database.AccessContext, string) error { return testCase.gateErr },
				func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
					loads++
					return governedquery.ExecutedAttempt{}, testCase.loadErr
				},
			)
			err := service.ReauthorizeAttempt(context.Background(), reauthorizationAccess(), "ws_0001", reauthorizationDisclosure())
			assertReauthorizationCode(t, err, CodeDenied)
			if loads != testCase.wantLoads {
				t.Fatalf("loader calls = %d, want %d", loads, testCase.wantLoads)
			}
			if strings.Contains(err.Error(), "secret") || errors.Unwrap(err) != nil {
				t.Fatalf("public error leaked a denial cause: %v", err)
			}
		})
	}
}

func TestReauthorizeAttemptRejectsStoredBindingMismatch(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		attempt governedquery.ExecutedAttempt
	}{
		{name: "sql hash", attempt: governedquery.ExecutedAttempt{AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: reauthorizationResultHash, ExposedSchemaRevision: 7}},
		{name: "schema revision", attempt: governedquery.ExecutedAttempt{AttemptID: "gqat_0001", ConnectionID: "conn_0001", SQLHash: reauthorizationSQLHash, ExposedSchemaRevision: 8}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service := reauthorizationService(
				func(context.Context, database.AccessContext, string) error { return nil },
				func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
					return testCase.attempt, nil
				},
			)
			assertReauthorizationCode(t, service.ReauthorizeAttempt(context.Background(), reauthorizationAccess(), "ws_0001", reauthorizationDisclosure()), CodeDenied)
		})
	}
}

func TestReauthorizeAttemptRejectsConfiguredConnectionMismatchWithoutCalls(t *testing.T) {
	calls := 0
	service := reauthorizationService(
		func(context.Context, database.AccessContext, string) error { calls++; return nil },
		func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
			calls++
			return reauthorizationAttempt(), nil
		},
	)
	disclosure := reauthorizationDisclosure()
	disclosure.ConnectionID = "conn_other"
	assertReauthorizationCode(t, service.ReauthorizeAttempt(context.Background(), reauthorizationAccess(), "ws_0001", disclosure), CodeDenied)
	if calls != 0 {
		t.Fatalf("configured connection mismatch made %d repository calls, want 0", calls)
	}
}

func TestReauthorizeAttemptCanceledOrExpiredContextIsUnavailableWithoutCalls(t *testing.T) {
	for _, testCase := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "canceled", ctx: canceledReauthorizationContext()},
		{name: "deadline exceeded", ctx: expiredReauthorizationContext()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			service := reauthorizationService(
				func(context.Context, database.AccessContext, string) error { calls++; return nil },
				func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
					calls++
					return reauthorizationAttempt(), nil
				},
			)
			assertReauthorizationCode(t, service.ReauthorizeAttempt(testCase.ctx, reauthorizationAccess(), "ws_0001", reauthorizationDisclosure()), CodeUnavailable)
			if calls != 0 {
				t.Fatalf("unavailable context made %d repository calls, want 0", calls)
			}
		})
	}
}

func canceledReauthorizationContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredReauthorizationContext() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	return ctx
}

func TestReauthorizeAttemptOnlyShapeValidatesResultDigestUntilQuestionArtifact(t *testing.T) {
	service := reauthorizationService(
		func(context.Context, database.AccessContext, string) error { return nil },
		func(context.Context, database.AccessContext, string, string) (governedquery.ExecutedAttempt, error) {
			return reauthorizationAttempt(), nil
		},
	)
	disclosure := reauthorizationDisclosure()
	// governed_query_attempt has no result_digest. A second valid-shaped value
	// remains unauthenticated until the Question artifact supplies that binding.
	disclosure.ResultDigest = reauthorizationSQLHash
	if err := service.ReauthorizeAttempt(context.Background(), reauthorizationAccess(), "ws_0001", disclosure); err != nil {
		t.Fatalf("valid-shaped unauthenticated result digest was rejected: %v", err)
	}
}
