package postgres_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/operator"
)

// TestOperatorBootstrapReconcilesRuntimeCredentials proves that a repeated
// bootstrap rotates real PostgreSQL credentials. A green operator run may not
// leave the server and worker mounts pointing at passwords the database no
// longer accepts (or silently ignore newly supplied password files).
func TestOperatorBootstrapReconcilesRuntimeCredentials(t *testing.T) {
	ctx := context.Background()
	admin := resetForOperatorBootstrap(t)
	oldPasswords := map[string]string{
		operator.RoleApplication: "operator-old-app-password",
		operator.RoleWorker:      "operator-old-worker-password",
		operator.RolePurger:      "operator-old-purger-password",
	}
	newPasswords := map[string]string{
		operator.RoleApplication: "operator-new-app-password",
		operator.RoleWorker:      "operator-new-worker-password",
		operator.RolePurger:      "operator-new-purger-password",
	}

	if err := operator.EnsureRoles(ctx, admin, oldPasswords); err != nil {
		t.Fatalf("initial EnsureRoles: %v", err)
	}
	for role, password := range oldPasswords {
		assertRuntimeLogin(t, ctx, role, password, true)
	}

	if err := operator.EnsureRoles(ctx, admin, newPasswords); err != nil {
		t.Fatalf("credential-reconciling EnsureRoles: %v", err)
	}
	for role, password := range newPasswords {
		assertRuntimeLogin(t, ctx, role, password, true)
	}
	for role, password := range oldPasswords {
		assertRuntimeLogin(t, ctx, role, password, false)
	}
}

func assertRuntimeLogin(t *testing.T, ctx context.Context, role, password string, wantSuccess bool) {
	t.Helper()
	parsed, err := url.Parse(testDatabaseURL(t))
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	parsed.User = url.UserPassword(role, password)
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		if wantSuccess {
			t.Fatalf("configure runtime login for %s: %v", role, err)
		}
		return
	}
	defer pool.Close()
	var currentUser string
	err = pool.QueryRow(ctx, "SELECT current_user").Scan(&currentUser)
	if wantSuccess {
		if err != nil {
			t.Fatalf("runtime login for %s failed: %v", role, err)
		}
		if currentUser != role {
			t.Fatalf("runtime login current_user=%q, want %q", currentUser, role)
		}
		return
	}
	if err == nil {
		t.Fatalf("stale credential for %s still authenticated", role)
	}
}
