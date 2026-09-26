package postgres_test

// Card E-2: H5 asks a count question about a database whose tables await
// confirmation. The harness reads the product's own source status immediately
// before asking and fails when that database's tables are confirmed instead:
// with a confirmed database H5 would no longer test the product's "cannot be
// read yet" answer, so that is a harness error, never an answer verdict.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// e1aH5Deferred is the H5 database the shared builder was asked for but has not
// bound yet. Binding it changes the workspace's source list, so the run binds
// it only when it reaches H5; every other question is then asked in exactly the
// workspace it had before the card.
type e1aH5Deferred struct {
	registrations *registration.Service
	source        questions.SourceSpec
	identity      string
	confirm       bool
	bound         bool
}

// e1aBindH5Source registers and binds the H5 database once, mints its table
// confirmation only when the caller asked for a confirmed database, and records
// the product connection it got.
func (env *e1aEnvironment) e1aBindH5Source(t *testing.T, ctx context.Context) {
	t.Helper()
	if env == nil || env.h5 == nil || env.h5.bound {
		return
	}
	h5 := env.h5
	request := registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: h5.source.Name, Kind: "business-objects",
		DatabaseIdentity: h5.identity, LineageID: h5.source.LineageID, ProjectionRevision: 1,
		ContractHash: sourceContractHash(h5.source), SchemaName: env.Set.Environment.SourceSchema,
		RelationName: h5.source.Table, RelationKind: "TABLE", EmptySnapshotPolicy: "HELD",
		Columns: sourceColumns(env.Set, h5.source),
	}
	registered, err := h5.registrations.Register(ctx, regOwnerAccess("req_e1a_h5_source"), request)
	if err != nil {
		t.Fatalf("register H5 source %s: %v (code=%s)", h5.source.Table, err, registration.CodeOf(err))
	}
	sourceFixture := seedRegistrationWorkspaceBinding(t, ctx, env.Admin, registered.SourceScopeID,
		e1aScopeConfigHash(t, ctx, env.Admin, registered.SourceScopeID), mustID(t, "binding"))
	if h5.confirm {
		e1aMintConfirmation(t, ctx, sourceFixture)
	}
	verifyIsolationTrust(t, ctx, env.Admin, registered.ConnectionID)
	e1aActivateSource(t, ctx, env.Admin, registered.SourceScopeID)
	env.H5SourceID = registered.ConnectionID
	env.H5SourceName = h5.source.Name
	env.SourceConnectionIDs[h5.source.ID] = registered.ConnectionID
	h5.bound = true
}

// e1aH5Confirmation is the harness's read of the product's own source status
// for the database H5 asks about.
type e1aH5Confirmation struct {
	ConnectionID string
	SourceName   string
	Awaiting     bool
	Detail       string
}

// e1aReadH5Confirmation reads the product's source status and reports whether
// the H5 database's tables still await confirmation.
func e1aReadH5Confirmation(ctx context.Context, env *e1aEnvironment) (e1aH5Confirmation, error) {
	if env == nil || env.Authority == nil || env.H5SourceID == "" {
		return e1aH5Confirmation{}, errors.New("the environment has no H5 database source")
	}
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_e1a_h5_confirmation"}
	statuses, err := env.Authority.ListSources(ctx, access, regWorkspace)
	if err != nil {
		return e1aH5Confirmation{}, fmt.Errorf("read workspace sources from the product: %w", err)
	}
	return h5AwaitingConfirmation(statuses, env.H5SourceID, env.H5SourceName)
}

// h5AwaitingConfirmation classifies the product's source status: the named
// connection must exist and must not be confirmed. A confirmed or missing
// connection is returned as an error so the caller fails the harness instead
// of judging an answer that was never asked the intended question.
func h5AwaitingConfirmation(statuses []workspacerepository.SourceStatus, connectionID, wantName string) (e1aH5Confirmation, error) {
	confirmation := e1aH5Confirmation{ConnectionID: connectionID, SourceName: wantName}
	for _, status := range statuses {
		if status.ConnectionID != connectionID {
			continue
		}
		confirmation.SourceName = status.ConnectionName
		confirmation.Awaiting = !status.Confirmed
		confirmation.Detail = fmt.Sprintf("connection %q confirmed=%t trust_verified=%t activation=%s",
			status.ConnectionName, status.Confirmed, status.TrustVerified, status.ActivationStatus)
		if status.Confirmed {
			return confirmation, fmt.Errorf("H5 database %q tables are confirmed, want awaiting confirmation (%s)",
				status.ConnectionName, confirmation.Detail)
		}
		return confirmation, nil
	}
	return confirmation, fmt.Errorf("H5 database connection %q is not bound to the workspace", connectionID)
}

// TestH5HarnessFailsWhenDatabaseConfirmed is the fixture proof of the harness
// contract: an unconfirmed database is accepted, a confirmed one and a missing
// one both fail the harness.
func TestH5HarnessFailsWhenDatabaseConfirmed(t *testing.T) {
	statuses := []workspacerepository.SourceStatus{
		{ConnectionID: "conn_contract", ConnectionName: "Договоры", Confirmed: true, TrustVerified: true, ActivationStatus: "READY"},
		{ConnectionID: "conn_request", ConnectionName: "Заявки", Confirmed: false, TrustVerified: true, ActivationStatus: "READY"},
	}
	confirmation, err := h5AwaitingConfirmation(statuses, "conn_request", "Заявки")
	if err != nil || !confirmation.Awaiting || confirmation.SourceName != "Заявки" {
		t.Fatalf("unconfirmed H5 database = %#v err=%v, want awaiting confirmation", confirmation, err)
	}

	confirmed := []workspacerepository.SourceStatus{
		{ConnectionID: "conn_request", ConnectionName: "Заявки", Confirmed: true, TrustVerified: true, ActivationStatus: "READY"},
	}
	if _, err := h5AwaitingConfirmation(confirmed, "conn_request", "Заявки"); err == nil {
		t.Fatal("the harness accepted a confirmed H5 database; want a harness failure")
	}

	if _, err := h5AwaitingConfirmation(statuses, "conn_missing", "Заявки"); err == nil {
		t.Fatal("the harness accepted a missing H5 database; want a harness failure")
	}
}

// TestQuestionSetH5DatabaseConfirmedFailsHarness is the product-side half: it
// reads the real product's own source status through the shared builder twice.
// With the H5 source left awaiting confirmation the harness accepts it; with
// its confirmation minted the harness fails. It proves the check reads the
// product and not only a fixture.
func TestQuestionSetH5DatabaseConfirmedFailsHarness(t *testing.T) {
	if strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL")) == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the product-side H5 confirmation proof")
	}
	ctx := context.Background()
	set := loadE1aSet(t)
	h5 := set.Environment.UnconfirmedDatabase.Source

	t.Run("awaiting confirmation is accepted", func(t *testing.T) {
		admin := resetStage1Database(t)
		env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
			SourceIdentity: "pgdb-e2-unconfirmed", H5Source: &h5, H5SourceIdentity: "pgdb-e2-unconfirmed-h5",
		})
		env.e1aBindH5Source(t, ctx)
		confirmation, err := e1aReadH5Confirmation(ctx, env)
		if err != nil || !confirmation.Awaiting {
			t.Fatalf("unconfirmed H5 environment = %#v err=%v, want accepted awaiting confirmation", confirmation, err)
		}
	})

	t.Run("confirmed fails the harness", func(t *testing.T) {
		admin := resetStage1Database(t)
		env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{
			SourceIdentity: "pgdb-e2-confirmed", H5Source: &h5, H5SourceIdentity: "pgdb-e2-confirmed-h5",
			ConfirmH5Source: true,
		})
		env.e1aBindH5Source(t, ctx)
		if _, err := e1aReadH5Confirmation(ctx, env); err == nil {
			t.Fatal("the harness accepted a confirmed H5 database; want a harness failure")
		}
	})
}
