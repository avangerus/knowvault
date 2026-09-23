package repository

import (
	"context"
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	lookupTestWorkspaceID  = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	lookupTestScopeID      = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	lookupTestConnectionID = "con_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func lookupTestAccess() database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		PrincipalID:    "prn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		RequestID:      "req_01ARZ3NDEKTSV4RRFFQ69G5FAV",
	}
}

func lookupTestValue() PostgreSQLAuthorityLookup {
	return PostgreSQLAuthorityLookup{
		WorkspaceID:   lookupTestWorkspaceID,
		SourceScopeID: lookupTestScopeID,
		ConnectionID:  lookupTestConnectionID,
	}
}

// assertLookupFailure proves one failed lookup returns the zero candidate and a
// content-free repository error: the exact safe code as its whole string form,
// no unwrap chain and no retained cause.
func assertLookupFailure(t *testing.T, store *Store, ctx context.Context, access database.AccessContext, lookup PostgreSQLAuthorityLookup, wantCode ErrorCode) {
	t.Helper()
	candidate, err := store.ResolvePostgreSQLAuthorityRequest(ctx, access, lookup)
	if candidate != (PostgreSQLAuthorityRequest{}) {
		t.Fatalf("candidate = %#v, want the zero candidate", candidate)
	}
	if err == nil {
		t.Fatal("expected a content-free repository error")
	}
	if got := err.Error(); got != string(wantCode) {
		t.Fatalf("error string = %q, want %q", got, string(wantCode))
	}
	if got := CodeOf(err); got != wantCode {
		t.Fatalf("error code = %q, want %q", got, wantCode)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("error retains an unwrap chain: %v", unwrapped)
	}
	var repositoryError *Error
	if !errors.As(err, &repositoryError) || repositoryError.cause != nil {
		t.Fatalf("error is not a content-free repository error: %#v", err)
	}
}

func TestResolvePostgreSQLAuthorityRequestRejectsInvalidAdmission(t *testing.T) {
	boundaryStore := &Store{database: &database.Store{}}
	emptyAccess := database.AccessContext{}
	unknownActorKind := lookupTestAccess()
	unknownActorKind.ActorKind = database.ActorKind("ROBOT")
	paddedPrincipal := lookupTestAccess()
	paddedPrincipal.PrincipalID = lookupTestAccess().PrincipalID + " "
	controlRequestID := lookupTestAccess()
	controlRequestID.RequestID = "req_\x00control"
	tests := []struct {
		name   string
		store  *Store
		ctx    context.Context
		access database.AccessContext
	}{
		{name: "nil store", store: nil, ctx: context.Background(), access: lookupTestAccess()},
		{name: "nil database", store: &Store{}, ctx: context.Background(), access: lookupTestAccess()},
		{name: "nil context", store: boundaryStore, ctx: nil, access: lookupTestAccess()},
		{name: "empty access", store: boundaryStore, ctx: context.Background(), access: emptyAccess},
		{name: "unknown actor kind", store: boundaryStore, ctx: context.Background(), access: unknownActorKind},
		{name: "padded principal", store: boundaryStore, ctx: context.Background(), access: paddedPrincipal},
		{name: "control request id", store: boundaryStore, ctx: context.Background(), access: controlRequestID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertLookupFailure(t, test.store, test.ctx, test.access, lookupTestValue(), CodeRequestInvalid)
		})
	}
}

func TestResolvePostgreSQLAuthorityRequestRejectsEveryMalformedLookupID(t *testing.T) {
	boundaryStore := &Store{database: &database.Store{}}
	malformed := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "too short", value: "ab"},
		{name: "too long", value: strings.Repeat("a", 129)},
		{name: "leading whitespace", value: " " + lookupTestWorkspaceID},
		{name: "trailing whitespace", value: lookupTestWorkspaceID + " "},
		{name: "embedded whitespace", value: "ws alpha"},
		{name: "tab", value: "ws\talpha"},
		{name: "null control character", value: "ws_\x00alpha"},
		{name: "newline control character", value: "ws_al\npha"},
		{name: "invalid utf8", value: "ws_\xffalpha"},
		{name: "non ascii letter", value: "ws_alph\u00e4"},
		{name: "forbidden character", value: "ws_al/pha"},
	}
	fields := []struct {
		name string
		set  func(*PostgreSQLAuthorityLookup, string)
	}{
		{name: "workspace", set: func(lookup *PostgreSQLAuthorityLookup, value string) { lookup.WorkspaceID = value }},
		{name: "source scope", set: func(lookup *PostgreSQLAuthorityLookup, value string) { lookup.SourceScopeID = value }},
		{name: "connection", set: func(lookup *PostgreSQLAuthorityLookup, value string) { lookup.ConnectionID = value }},
	}
	for _, field := range fields {
		for _, value := range malformed {
			t.Run(field.name+" id "+value.name, func(t *testing.T) {
				lookup := lookupTestValue()
				field.set(&lookup, value.value)
				assertLookupFailure(t, boundaryStore, context.Background(), lookupTestAccess(), lookup, CodeRequestInvalid)
			})
		}
	}
}

// TestResolvePostgreSQLAuthorityRequestAdmitsValidLookupToTheDatabaseBoundary
// proves admission itself never rejects a fully valid lookup: it reaches the
// database boundary. A zero-value database store has no pool, so that read can
// only fail closed with the content-free persistence error, which also proves
// no driver cause is wrapped and no candidate is fabricated. The query,
// cardinality and denial cases belong to the integration card.
func TestResolvePostgreSQLAuthorityRequestAdmitsValidLookupToTheDatabaseBoundary(t *testing.T) {
	assertLookupFailure(t, &Store{database: &database.Store{}}, context.Background(), lookupTestAccess(), lookupTestValue(), CodePersistence)
}
