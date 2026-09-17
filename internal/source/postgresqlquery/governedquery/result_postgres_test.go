package governedquery

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Only the dedicated integration database is used; no product schema is
// touched. Real PostgreSQL wire values expose loss that fake Go rows cannot.
func TestRunQueryPreservesPostgresValuesAndRejectsOverflow(t *testing.T) {
	dsn := os.Getenv("KNOWVAULT_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("dedicated test PostgreSQL required")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	before := time.Now().UTC()
	query := "SELECT 9007199254740993.123456789::numeric AS amount,\n NULL::text AS missing, ''::text AS empty, repeat('\u042f', 6000) AS full_text,\n DATE '2026-08-31' AS business_date"
	result, err := runQuery(ctx, tx, query, validLimits())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowCount != 1 || len(result.Rows) != 1 || len(result.Rows[0]) != 5 {
		t.Fatalf("bad shape: %+v", result)
	}
	row := result.Rows[0]
	if row[0] == nil || *row[0] != "9007199254740993.123456789" || row[1] != nil || row[2] == nil || *row[2] != "" || row[3] == nil || *row[3] != strings.Repeat("\u042f", 6000) || row[4] == nil || *row[4] != "2026-08-31" {
		t.Fatal("SQL values were truncated, reformatted or conflated")
	}
	if result.ExecutionStartedAt.Before(before) || result.ExecutionCompletedAt.Before(result.ExecutionStartedAt) || result.ExecutionCompletedAt.After(time.Now().UTC()) {
		t.Fatal("invalid execution interval")
	}
	digest := resultDigest(result)
	other, err := runQuery(ctx, tx, query, validLimits())
	if err != nil || resultDigest(other) != digest {
		t.Fatal("same ordered result has a different digest")
	}
	*other.Rows[0][0] = "9007199254740994.123456789"
	if resultDigest(other) == digest {
		t.Fatal("changed number has the same digest")
	}
	*other.Rows[0][0] = *result.Rows[0][0]
	empty := ""
	other.Rows[0][1] = &empty
	if resultDigest(other) == digest {
		t.Fatal("NULL and empty text have the same digest")
	}
	for _, tc := range []struct {
		name, query string
		limits      Limits
	}{
		{"bytes", query, Limits{MaxRows: 100, MaxResultBytes: 100}},
		{"rows", "SELECT generate_series(1, 3)", Limits{MaxRows: 2, MaxResultBytes: 1000}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runQuery(ctx, tx, tc.query, tc.limits)
			if CodeOf(err) != CodeInvalid || len(got.Rows) != 0 || got.RowCount != 0 {
				t.Fatal("overflow returned a partial table")
			}
		})
	}
}
