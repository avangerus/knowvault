package governedquery

// scoped_test.go is the ADR-0097 plan-scope proof: the walk that the
// knowvault_source_sql tool relies on accepts every registered relation a CTE,
// JOIN, subquery or expanded view planner produces, and refuses a relation
// outside the source, a system catalog and a function scan before execution.
// The synthetic plans mirror the exact EXPLAIN (VERBOSE, FORMAT JSON) shape
// PostgreSQL 18 prints (verified against a real server by scoped_integration
// _test.go); the ExecutionScoped-level refusals are proven here without a
// database because the static pre-check runs before any connection is dialled.

import (
	"context"
	"testing"
)

func scopedSchema(relations ...ScopedRelation) ScopedSchema {
	return ScopedSchema{Relations: relations}
}

func contractsScope() ScopedSchema {
	return scopedSchema(
		ScopedRelation{Schema: "public", Table: "contracts", Columns: []string{"id", "status", "amount"}},
		ScopedRelation{Schema: "public", Table: "customers", Columns: []string{"id", "name"}},
	)
}

func TestScopedSchemaValidate(t *testing.T) {
	if err := contractsScope().Validate(); err != nil {
		t.Fatalf("valid scope was refused: %v", err)
	}
	cases := map[string]ScopedSchema{
		"empty":            {},
		"empty schema":     scopedSchema(ScopedRelation{Table: "t", Columns: []string{"c"}}),
		"empty table":      scopedSchema(ScopedRelation{Schema: "public", Columns: []string{"c"}}),
		"no columns":       scopedSchema(ScopedRelation{Schema: "public", Table: "t"}),
		"uppercase table":  scopedSchema(ScopedRelation{Schema: "public", Table: "T", Columns: []string{"c"}}),
		"duplicate table":  scopedSchema(ScopedRelation{Schema: "public", Table: "t", Columns: []string{"c"}}, ScopedRelation{Schema: "public", Table: "t", Columns: []string{"c"}}),
		"duplicate column": scopedSchema(ScopedRelation{Schema: "public", Table: "t", Columns: []string{"c", "c"}}),
	}
	for name, schema := range cases {
		if err := schema.Validate(); err == nil {
			t.Fatalf("%s scope was accepted", name)
		}
	}
}

func TestPlanScopeAcceptsRegisteredRelations(t *testing.T) {
	cases := map[string]string{
		// A plain aggregate over one registered base table.
		"base table": `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public","Output":["id","status"]}}]`,
		// An inlined CTE: the CTE body is the scan, the CTE Scan has no relation.
		"cte": `[{"Plan":{"Node Type":"CTE Scan","CTE Name":"counted","Plans":[
			{"Node Type":"Aggregate","Plans":[{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"}]}]}}]`,
		// A join of two registered tables.
		"join": `[{"Plan":{"Node Type":"Hash Join","Plans":[
			{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"},
			{"Node Type":"Hash","Plans":[{"Node Type":"Seq Scan","Relation Name":"customers","Schema":"public"}]}]}}]`,
		// A subquery plan.
		"subquery": `[{"Plan":{"Node Type":"Subquery Scan","Plans":[
			{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"}]}}]`,
		// An expanded view: the planner inlines the view into its base relation.
		"view expansion": `[{"Plan":{"Node Type":"Subquery Scan","Alias":"active_contracts","Plans":[
			{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"}]}}]`,
		// A materialized CTE: the body hangs under the CTE Scan as a subplan.
		"materialized cte": `[{"Plan":{"Node Type":"CTE Scan","CTE Name":"c","Plans":[
			{"Node Type":"Materialize","Subplan Name":"CTE c","Plans":[{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"}]}]}}]`,
	}
	for name, plan := range cases {
		if code := PlanScopeProblem([]byte(plan), contractsScope()); code != "" {
			t.Fatalf("%s plan was refused with %s", name, code)
		}
	}
}

func TestPlanScopeRefusesRelationsOutsideTheSource(t *testing.T) {
	cases := map[string]string{
		"foreign table":         `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"payroll","Schema":"public"}}]`,
		"foreign schema":        `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"billing"}}]`,
		"pg_catalog":            `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"pg_class","Schema":"pg_catalog"}}]`,
		"information_schema":    `[{"Plan":{"Node Type":"Seq Scan","Relation Name":"tables","Schema":"information_schema"}}]`,
		"function scan":         `[{"Plan":{"Node Type":"Function Scan","Function Name":"read_secrets"}}]`,
		"function scan child":   `[{"Plan":{"Node Type":"Nested Loop","Plans":[{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"},{"Node Type":"Function Scan","Function Name":"leak"}]}}]`,
		"foreign nested join":   `[{"Plan":{"Node Type":"Hash Join","Plans":[{"Node Type":"Seq Scan","Relation Name":"contracts","Schema":"public"},{"Node Type":"Seq Scan","Relation Name":"payroll","Schema":"public"}]}}]`,
		"foreign under subplan": `[{"Plan":{"Node Type":"Subquery Scan","Plans":[{"Node Type":"Seq Scan","Relation Name":"payroll","Schema":"public"}]}}]`,
	}
	for name, plan := range cases {
		if code := PlanScopeProblem([]byte(plan), contractsScope()); code != CodeRelationNotInSource {
			t.Fatalf("%s plan = %q, want %s", name, code, CodeRelationNotInSource)
		}
	}
}

func TestPlanScopeRefusesAmbiguousOrMalformedPlans(t *testing.T) {
	ambiguous := scopedSchema(
		ScopedRelation{Schema: "public", Table: "contracts", Columns: []string{"id"}},
		ScopedRelation{Schema: "archive", Table: "contracts", Columns: []string{"id"}},
	)
	// PostgreSQL omits "Schema" when the relation resolved through the search
	// path; with the same table name in two registered schemas the walk must
	// refuse rather than guess which one the planner read.
	if code := PlanScopeProblem([]byte(`[{"Plan":{"Node Type":"Seq Scan","Relation Name":"contracts"}}]`), ambiguous); code != CodeRelationNotInSource {
		t.Fatalf("ambiguous unqualified relation = %q, want %s", code, CodeRelationNotInSource)
	}
	// The same plan against a single schema resolves through the search path.
	if code := PlanScopeProblem([]byte(`[{"Plan":{"Node Type":"Seq Scan","Relation Name":"contracts"}}]`), contractsScope()); code != "" {
		t.Fatalf("unambiguous unqualified relation was refused with %q", code)
	}
	for _, plan := range []string{"", "{}", "[]", `[{"Plan":{}},{"Plan":{}}]`, "not-json"} {
		if code := PlanScopeProblem([]byte(plan), contractsScope()); code != CodeRelationNotInSource {
			t.Fatalf("malformed plan %q = %q, want %s", plan, code, CodeRelationNotInSource)
		}
	}
}

func TestExecuteScopedRefusesStaticsBeforeDialling(t *testing.T) {
	config := Config{
		ConnectionID: "source-sql-demo", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN:        "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
	writes := []string{
		"DELETE FROM contracts",
		"UPDATE contracts SET status = 'x'",
		"INSERT INTO contracts VALUES (1)",
		"DROP TABLE contracts",
		"ALTER TABLE contracts ADD COLUMN x int",
		"SELECT 1; DROP TABLE contracts",
		"SELECT 1 -- trailing comment",
		"SELECT count(*) FROM contracts /* hidden second statement */;",
		"CREATE VIEW v AS SELECT 1",
	}
	for _, sqlText := range writes {
		result, attempt, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: sqlText, Schema: contractsScope()})
		if CodeOf(err) != CodeSQLRejectedStatic {
			t.Fatalf("%q = %v, want %s", sqlText, CodeOf(err), CodeSQLRejectedStatic)
		}
		if attempt.Outcome != OutcomeRejectedStatic || attempt.SQLHash == "" || len(result.Rows) != 0 {
			t.Fatalf("%q recorded attempt %+v result %+v", sqlText, attempt, result)
		}
	}
}

func TestExecuteScopedRefusesAnInvalidScopeBeforeDialling(t *testing.T) {
	config := Config{
		ConnectionID: "source-sql-demo", DatabaseIdentity: "demo_ops", WorkspaceID: "tko-operations",
		DSN:        "postgres://demo_ops_govquery:secret@knowvault-acc-postgres:5432/demo_ops?sslmode=verify-full",
		TrustRoots: testTrustRoots(t), Limits: validLimits(),
	}
	if _, _, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: "SELECT 1", Schema: ScopedSchema{}}); CodeOf(err) != CodeInvalid {
		t.Fatalf("empty scope = %v, want %s", CodeOf(err), CodeInvalid)
	}
	if _, _, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: "SELECT 1"}); CodeOf(err) != CodeInvalid {
		t.Fatalf("zero params = %v, want %s", CodeOf(err), CodeInvalid)
	}
	long := make([]byte, maxSQLTextBytes+1)
	for index := range long {
		long[index] = 'a'
	}
	if _, _, err := ExecuteScoped(context.Background(), config, ScopedParams{SQLText: "SELECT " + string(long), Schema: contractsScope()}); CodeOf(err) != CodeInvalid {
		t.Fatalf("over-long SQL = %v, want %s", CodeOf(err), CodeInvalid)
	}
}
