package postgresqlquery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The external source login cannot normally SET a DBA-only resource limit.
// Its administrator-pinned default must remain usable after the denied SET,
// while an unlimited or oversized default must never admit a source read.
func TestTempFileLimitHonorsUnprivilegedRoleDefaults(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("set KNOWVAULT_TEST_POSTGRES_URL for the real PostgreSQL spill-budget proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("admin PostgreSQL connection: %v", err)
	}
	defer func() { _ = admin.Close(context.Background()) }()

	for _, test := range []struct {
		name    string
		setting string
		wantKB  int64
		accept  bool
	}{
		{name: "no_spill", setting: "0", wantKB: 0, accept: true},
		{name: "stricter_than_connector", setting: "64MB", wantKB: 64 * 1024, accept: true},
		{name: "connector_ceiling", setting: "256MB", wantKB: 256 * 1024, accept: true},
		{name: "unlimited_is_refused", setting: "-1"},
		{name: "oversized_is_refused", setting: "512MB", wantKB: 512 * 1024},
	} {
		t.Run(test.name, func(t *testing.T) {
			var random [8]byte
			if _, err := rand.Read(random[:]); err != nil {
				t.Fatal(err)
			}
			roleName := "kv_pgq_spill_" + hex.EncodeToString(random[:])
			roleSQL := pgx.Identifier{roleName}.Sanitize()
			if _, err := admin.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'synthetic-spill-budget-only'"); err != nil {
				t.Fatalf("create source role: %v", err)
			}
			defer func() {
				if _, err := admin.Exec(ctx, "DROP ROLE "+roleSQL); err != nil {
					t.Errorf("drop synthetic source role: %v", err)
				}
			}()
			// setting is a fixed fixture above, never a caller-provided value.
			if _, err := admin.Exec(ctx, "ALTER ROLE "+roleSQL+" SET temp_file_limit = '"+test.setting+"'"); err != nil {
				t.Fatalf("pin source role spill budget: %v", err)
			}
			config, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatal("parse synthetic PostgreSQL connection")
			}
			config.User = roleName
			config.Password = "synthetic-spill-budget-only"
			reader, err := pgx.ConnectConfig(ctx, config)
			if err != nil {
				t.Fatalf("unprivileged source connection: %v", err)
			}
			defer func() { _ = reader.Close(ctx) }()
			var maySet, superuser, bypassRLS bool
			if err := reader.QueryRow(ctx, `SELECT pg_catalog.has_parameter_privilege(current_user, 'temp_file_limit', 'SET'), rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&maySet, &superuser, &bypassRLS); err != nil {
				t.Fatalf("inspect source role authority: %v", err)
			}
			if maySet || superuser || bypassRLS {
				t.Fatal("source fixture unexpectedly has privileged authority")
			}
			tx, err := reader.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly, DeferrableMode: pgx.Deferrable})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			err = enforceTempFileLimit(ctx, tx)
			if test.accept && err != nil {
				t.Fatalf("bounded unprivileged source default rejected: %v", err)
			}
			if !test.accept && (err == nil || CodeOf(err) != CodeExternalFailure) {
				t.Fatalf("unsafe source default accepted or wrong failure: %v", err)
			}
			var rawLimit, readOnly string
			if err := tx.QueryRow(ctx, "SELECT current_setting('temp_file_limit'), current_setting('transaction_read_only')").Scan(&rawLimit, &readOnly); err != nil {
				t.Fatalf("denied SET left the source transaction aborted: %v", err)
			}
			if readOnly != "on" {
				t.Fatal("spill-budget handling relaxed read-only isolation")
			}
			if test.setting == "-1" {
				if rawLimit != "-1" {
					t.Fatalf("unexpected change to administrator-pinned default: %q", rawLimit)
				}
			} else if value, ok := tempFileLimitKB(rawLimit); !ok || value != test.wantKB {
				t.Fatalf("administrator-pinned default changed: %q", rawLimit)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit after spill-budget check: %v", err)
			}
		})
	}
}
