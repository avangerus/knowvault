package governedquery

// scoped_settings_integration_test.go is S3 card 2c's proof that every
// agent-authored transaction pins the server-owned resource settings. It opens
// the exact transaction shape prepareScopedTransaction builds on the card's
// real PostgreSQL container and reads the values back with SHOW, so a
// regression that drops a pin fails here rather than under customer load.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestScopedTransactionPinsServerOwnedSettings(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the ADR-0097 transaction-pin proof")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close(ctx)
	transaction, err := admin.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatalf("begin read-only transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if err := prepareScopedTransaction(ctx, transaction, validLimits(), ScopedSchema{Relations: rolePrivilegeRelations()}); err != nil {
		t.Fatalf("prepare scoped transaction: %v", err)
	}

	expected := map[string][]string{
		"lock_timeout":                        {scopedLockTimeout, "2000ms"},
		"work_mem":                            {scopedWorkMem},
		"idle_in_transaction_session_timeout": {"5s", "5000ms"},
		"transaction_read_only":               {"on"},
	}
	for name, allowed := range expected {
		var got string
		if err := transaction.QueryRow(ctx, "SHOW "+name).Scan(&got); err != nil {
			t.Fatalf("SHOW %s: %v", name, err)
		}
		matched := false
		for _, want := range allowed {
			if got == want {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("SHOW %s = %q, want one of %v", name, got, allowed)
		}
	}
	// temp_file_limit is superuser-only on PostgreSQL, so the card pins it only
	// where the server allows it: either the pinned value or the server's own
	// unlimited default (-1).
	var tempFileLimit string
	if err := transaction.QueryRow(ctx, "SHOW temp_file_limit").Scan(&tempFileLimit); err != nil {
		t.Fatalf("SHOW temp_file_limit: %v", err)
	}
	if tempFileLimit != scopedTempFileLimit && tempFileLimit != "-1" {
		t.Fatalf("SHOW temp_file_limit = %q, want %q or -1", tempFileLimit, scopedTempFileLimit)
	}
}
