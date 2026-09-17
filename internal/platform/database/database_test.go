package database

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAccessContextRejectsAmbiguousIdentifiers(t *testing.T) {
	t.Parallel()

	valid := AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_01"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid access context rejected: %v", err)
	}

	for name, access := range map[string]AccessContext{
		"empty organization": {PrincipalID: "usr_alice", RequestID: "req_01"},
		"whitespace":         {OrganizationID: "org alpha", PrincipalID: "usr_alice", RequestID: "req_01"},
		"padded":             {OrganizationID: " org_alpha", PrincipalID: "usr_alice", RequestID: "req_01"},
		"non-ASCII":          {OrganizationID: "org_\u0430\u043b\u044c\u0444\u0430", PrincipalID: "usr_alice", RequestID: "req_01"},
		"overlong":           {OrganizationID: string(make([]byte, 129)), PrincipalID: "usr_alice", RequestID: "req_01"},
	} {
		name, access := name, access
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if CodeOf(access.Validate()) != CodeContextInvalid {
				t.Fatalf("invalid context was accepted: %#v", access)
			}
		})
	}
}

func TestOIDCServiceAccessIsTenantScopedAndDoesNotAcceptAnActorOverride(t *testing.T) {
	t.Parallel()

	access, err := NewOIDCServiceAccess("org_alpha", "req_oidc_001")
	if err != nil {
		t.Fatalf("NewOIDCServiceAccess() error = %v", err)
	}
	if access.OrganizationID != "org_alpha" || access.PrincipalID != oidcServicePrincipal || access.RequestID != "req_oidc_001" {
		t.Fatalf("unexpected OIDC service access: %#v", access)
	}
	if _, err := NewOIDCServiceAccess("org alpha", "req_oidc_001"); CodeOf(err) != CodeContextInvalid {
		t.Fatalf("ambiguous OIDC organization accepted: %v", err)
	}
}

func TestIsNotFoundAcceptsOnlyTheDatabaseNoRowsSentinel(t *testing.T) {
	t.Parallel()

	if !IsNotFound(pgx.ErrNoRows) {
		t.Fatal("pgx.ErrNoRows must be recognized at the database boundary")
	}
	if IsNotFound(errors.New("no rows")) {
		t.Fatal("lookalike error must not be recognized as a database no-row result")
	}
}

func TestConfigIsBoundedAndContentFree(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()
	config.URL = "postgres://knowvault_app:secret@127.0.0.1/knowvault"
	if err := config.validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	config.MaxConnections = 65
	err := config.validate()
	if CodeOf(err) != CodeConfigInvalid || err.Error() != string(CodeConfigInvalid) {
		t.Fatalf("unsafe configuration code = %v", err)
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("local validation must not expose a cause")
	}
}

func TestCodeOfNeverLeaksUnexpectedDatabaseErrors(t *testing.T) {
	t.Parallel()

	if got := CodeOf(errors.New("postgres://secret@host/tenant")); got != CodeTransactionFailed {
		t.Fatalf("unexpected error code = %q", got)
	}
}
