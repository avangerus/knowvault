package governedquery

// staticgate_test.go is card S3.2d's proof for the deterministic pre-EXPLAIN
// refusal gate (R2 and R3). The gate runs before any dial, so every case here
// also proves the statement never reached a server: ExecuteScoped is called
// with a syntactically valid but unreachable DSN and still returns
// SQL_REJECTED_STATIC.

import (
	"context"
	"strings"
	"testing"
)

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
		`SELECT "SET" FROM kv_s3_2c.contracts`,
		`SET LOCAL work_mem = '1GB'`,
		`RESET ALL`,
	}
	for _, sqlText := range refused {
		if err := staticPrecheck(sqlText); err == nil {
			t.Fatalf("setting change %q passed the gate", sqlText)
		}
	}
	// A quoted string value that merely contains the word is data, not a call.
	if err := staticPrecheck(`SELECT 'set_config' AS note FROM kv_s3_2c.contracts`); err != nil {
		t.Fatalf("a string literal naming set_config was refused: %v", err)
	}
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
		"query to json":            `SELECT query_to_json('SELECT 1')`,
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
	config := Config{
		ConnectionID: "source-sql-gate", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN:        "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
	for _, sqlText := range []string{
		`SELECT set_config('work_mem', '1GB', true)`,
		`SELECT pg_cancel_backend(1)`,
		`SELECT U&"pg_read_file"('/etc/passwd')`,
	} {
		result, attempt, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: sqlText, Schema: contractsScope()})
		if CodeOf(err) != CodeSQLRejectedStatic {
			t.Fatalf("%q = %v (%s), want %s", sqlText, err, CodeOf(err), CodeSQLRejectedStatic)
		}
		if attempt.Outcome != OutcomeRejectedStatic || len(result.Rows) != 0 || attempt.CostEstimate != 0 {
			t.Fatalf("%q recorded %+v / %+v", sqlText, attempt, result)
		}
	}
}

func TestSQLIdentifiersNormalizesQuotesAndSchema(t *testing.T) {
	tokens := strings.Join(sqlIdentifiers(`SELECT "pg_catalog"."set_config"('a') FROM "MyTable"`), ",")
	if !strings.Contains(tokens, "set_config") || !strings.Contains(tokens, "pg_catalog") || !strings.Contains(tokens, "mytable") {
		t.Fatalf("normalized tokens = %q", tokens)
	}
}
