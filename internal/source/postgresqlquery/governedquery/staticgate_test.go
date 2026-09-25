package governedquery

// staticgate_test.go is cards S3.2d and S3.2e's proof for the deterministic
// pre-EXPLAIN refusal gate (R2 and R3). The gate runs before any dial, so every
// refusal case here also proves the statement never reached a server:
// ExecuteScoped is called with a syntactically valid but unreachable DSN and
// still returns SQL_REJECTED_STATIC.

import (
	"context"
	"strings"
	"testing"
)

// staticGateRefusalConfig is the syntactically valid but unreachable connection
// every refusal proof uses. If the gate admitted one of these statements, the
// attempt would fail with DATABASE_REJECTED instead of SQL_REJECTED_STATIC, so
// a passing case also proves nothing was dialled.
func staticGateRefusalConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ConnectionID: "source-sql-gate", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN:        "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
}

// assertStaticRefusalReachesNoServer proves each statement is refused by the
// gate and left no result, no cost estimate and no database round trip.
func assertStaticRefusalReachesNoServer(t *testing.T, sqlTexts []string) {
	t.Helper()
	config := staticGateRefusalConfig(t)
	for _, sqlText := range sqlTexts {
		result, attempt, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: sqlText, Schema: contractsScope()})
		if CodeOf(err) != CodeSQLRejectedStatic {
			t.Fatalf("%q = %v (%s), want %s", sqlText, err, CodeOf(err), CodeSQLRejectedStatic)
		}
		if attempt.Outcome != OutcomeRejectedStatic || len(result.Rows) != 0 || attempt.CostEstimate != 0 {
			t.Fatalf("%q recorded %+v / %+v", sqlText, attempt, result)
		}
	}
}

func TestStaticGateRefusesSettingChanges(t *testing.T) {
	refused := []string{
		"SELECT set_config('statement_timeout', '0', true)",
		"SELECT SET_CONFIG('work_mem', '1GB', true)",
		`SELECT "set_config"('work_mem', '1GB', true)`,
		`SELECT pg_catalog.set_config('work_mem', '1GB', true)`,
		`SELECT "pg_catalog"."set_config"('work_mem', '1GB', true)`,
		`WITH x AS (SELECT set_config('work_mem', '1GB', true)) SELECT * FROM x`,
		`SELECT pg_catalog."set_config"('work_mem', '1GB', true)`,
		`SELECT U&"set_config"('work_mem', '1GB', true)`,
		`SELECT U&"set" FROM kv_s3_2c.contracts`,
		`SET LOCAL work_mem = '1GB'`,
		`RESET ALL`,
	}
	for _, sqlText := range refused {
		if err := staticPrecheck(sqlText); err == nil {
			t.Fatalf("setting change %q passed the gate", sqlText)
		}
	}
	// A quoted string value that merely contains the word is data, not a call;
	// a column named set is ordinary SQL, not a setting change (card S3.2e R2).
	accepted := []string{
		`SELECT 'set_config' AS note FROM kv_s3_2c.contracts`,
		`SELECT set FROM kv_s3_2c.contracts`,
		`SELECT "SET" FROM kv_s3_2c.contracts`,
	}
	for _, sqlText := range accepted {
		if err := staticPrecheck(sqlText); err != nil {
			t.Fatalf("ordinary statement %q was refused: %v", sqlText, err)
		}
	}
}

// TestStaticGateAcceptsOrdinaryAnalyticSQL is card S3.2e R2: a name from a
// refused family is refused only where it names a call or an inspection
// relation. A column, an alias or a benign JSON function that merely shares a
// spelling stays ordinary analytic SQL.
func TestStaticGateAcceptsOrdinaryAnalyticSQL(t *testing.T) {
	accepted := []string{
		`SELECT set FROM kv_s3_2c.contracts`,
		`SELECT reset FROM kv_s3_2c.contracts`,
		`SELECT lo_amount, lo_bound FROM kv_s3_2c.contracts`,
		`SELECT amount AS set, status AS reset, amount AS lo_amount, id AS lo_bound FROM kv_s3_2c.contracts`,
		`SELECT row_to_json(contracts) FROM kv_s3_2c.contracts`,
		`SELECT array_to_json(array_agg(id)) FROM kv_s3_2c.contracts`,
		`SELECT json_agg(id) FROM kv_s3_2c.contracts`,
		`SELECT 'U&' AS note FROM kv_s3_2c.contracts`,
		`SELECT 'set_config' AS note FROM kv_s3_2c.contracts`,
		`SELECT "amount$" FROM kv_s3_2c.contracts`,
		`SELECT count(*) FROM kv_s3_2c.contracts WHERE status = 'active'`,
	}
	for _, sqlText := range accepted {
		if err := staticPrecheck(sqlText); err != nil {
			t.Fatalf("ordinary analytic statement %q was refused: %v", sqlText, err)
		}
	}
}

// TestStaticGateRefusesUnmodeledLexicalForms is card S3.2e R1: every lexical
// form the gate does not model is refused before anything reaches the server.
func TestStaticGateRefusesUnmodeledLexicalForms(t *testing.T) {
	assertStaticRefusalReachesNoServer(t, []string{
		// Dollar-quoted literals and any dollar sign outside a quoted identifier.
		`SELECT $$payload$$`,
		`SELECT $tag$payload$tag$`,
		`SELECT $1`,
		`SELECT id FROM kv_s3_2c.contracts WHERE amount = $1`,
		`SELECT amount FROM kv_s3_2c.contracts WHERE status = 'a$b'`,
		`SELECT lo$bound FROM kv_s3_2c.contracts`,
		// Escape-string literals.
		`SELECT E'escape'`,
		`SELECT e'escape'`,
		`SELECT id FROM kv_s3_2c.contracts WHERE status = E'a\tb'`,
		// A backslash inside a string literal.
		`SELECT 'back\slash'`,
		`SELECT id FROM kv_s3_2c.contracts WHERE status = 'a\b'`,
		// The U& Unicode escape introducer.
		`SELECT U&'unicode'`,
		`SELECT U&"identifier"`,
	})
}

func TestStaticGateRefusesCrossSessionAndServerFileFamilies(t *testing.T) {
	families := map[string]string{
		"pg_stat_get family":       `SELECT pg_stat_get_activity(1)`,
		"pg_stat view function":    `SELECT pg_stat_get_backend_pid(1)`,
		"pg_stat_activity view":    `SELECT * FROM pg_stat_activity`,
		"cancel backend":           `SELECT pg_cancel_backend(1)`,
		"terminate backend":        `SELECT pg_terminate_backend(1)`,
		"backend pid":              `SELECT pg_backend_pid()`,
		"advisory lock":            `SELECT pg_advisory_lock(1)`,
		"advisory xact lock":       `SELECT pg_advisory_xact_lock(1)`,
		"try advisory lock":        `SELECT pg_try_advisory_lock(1)`,
		"try advisory xact lock":   `SELECT pg_try_advisory_xact_lock(1)`,
		"sleep":                    `SELECT pg_sleep(1)`,
		"sleep for":                `SELECT pg_sleep_for('1s')`,
		"query to xml":             `SELECT query_to_xml('SELECT 1', true, false, '')`,
		"table to xml":             `SELECT table_to_xml('kv_s3_2c.contracts'::regclass, true, false, '')`,
		"cursor to xml":            `SELECT cursor_to_xml('c', 0, true, false, '')`,
		"schema to xml":            `SELECT schema_to_xml('kv_s3_2c', true, false, '')`,
		"query to xml and schema":  `SELECT query_to_xml_and_xmlschema('SELECT 1', true, false, '')`,
		"lo import":                `SELECT lo_import('/etc/passwd')`,
		"lo get":                   `SELECT lo_get(1)`,
		"lo unlink":                `SELECT lo_unlink(1)`,
		"pg read file":             `SELECT pg_read_file('/etc/passwd')`,
		"pg read binary file":      `SELECT pg_read_binary_file('/etc/passwd')`,
		"pg ls dir":                `SELECT pg_ls_dir('/')`,
		"pg ls logdir":             `SELECT pg_ls_logdir()`,
		"pg stat file via prefix":  `SELECT pg_stat_file('/etc/passwd')`,
		"schema qualified variant": `SELECT pg_catalog.pg_read_file('/etc/passwd')`,
		"quoted variant":           `SELECT "lo_import"('/etc/passwd')`,
		// Card S3.2e R3: session, lock and blocking-pid inspection.
		"pg_locks view":          `SELECT * FROM pg_locks`,
		"pg_lock_status function": `SELECT pg_lock_status()`,
		"blocking pids":          `SELECT pg_blocking_pids(1)`,
		"safe snapshot blocking": `SELECT pg_safe_snapshot_blocking_pids(1)`,
	}
	for name, sqlText := range families {
		t.Run(name, func(t *testing.T) {
			if err := staticPrecheck(sqlText); err == nil {
				t.Fatalf("%q was admitted by the gate", sqlText)
			}
		})
	}
	// A normal registered read must still pass.
	if err := staticPrecheck(`SELECT count(*) FROM kv_s3_2c.contracts WHERE status = 'active'`); err != nil {
		t.Fatalf("a normal read was refused: %v", err)
	}
}

func TestStaticGateRefusalReachesNoServer(t *testing.T) {
	assertStaticRefusalReachesNoServer(t, []string{
		`SELECT set_config('work_mem', '1GB', true)`,
		`SELECT pg_cancel_backend(1)`,
		`SELECT U&"pg_read_file"('/etc/passwd')`,
	})
}

// TestSQLTokensAgreeWithPostgreSQL is card S3.2e R1's tokenizer anchor: the
// gate's identifier stream is the one PostgreSQL sees, with quoted identifiers
// decoded, case folded and string literals skipped, so a forbidden name is
// refused only when it is genuinely named and a call is a call.
func TestSQLTokensAgreeWithPostgreSQL(t *testing.T) {
	tokens, err := sqlTokenize(`SELECT "pg_catalog"."set_config"('a,b') FROM "MyTable" AS t WHERE t."lo$col" = 1`)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	var names []string
	calls := 0
	for index, token := range tokens {
		if token.kind != sqlTokenIdentifier {
			continue
		}
		names = append(names, token.text)
		if index+1 < len(tokens) && tokens[index+1].kind == sqlTokenPunctuation && tokens[index+1].text == "(" {
			calls++
		}
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"pg_catalog", "set_config", "mytable", "t", "lo$col"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tokens %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "a,b") {
		t.Fatalf("a string literal leaked into the identifier stream: %q", joined)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want exactly the one real call", calls)
	}
}
