package governedask

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

func TestGovernedAskRequiresSchemaQualifiedRelations(t *testing.T) {
	for _, required := range []string{"schema_name.table_name", "unqualified object names"} {
		if !strings.Contains(askSystemInstructions, required) {
			t.Fatalf("governed query instructions do not require %q", required)
		}
	}
}

func TestCandidateSQLAcceptsSingleFactClaim(t *testing.T) {
	sql := "SELECT count(*) FROM fleet_trips"
	plan := modelgateway.ClaimPlan{
		SchemaVersion: "1.4",
		Claims:        []modelgateway.Claim{{ID: "C1", Text: &sql, Kind: "FACT", EvidenceIDs: []string{"E1"}}},
		Sections:      []modelgateway.Section{{ID: "S1", OrderedClaimIDs: []string{"C1"}}},
	}
	got, ok := candidateSQL(plan)
	if !ok || got != sql {
		t.Fatalf("expected sql=%q ok=true, got sql=%q ok=%v", sql, got, ok)
	}
}

func TestCandidateSQLRejectsUnknownClaim(t *testing.T) {
	reason := "NO_RELEVANT_EVIDENCE"
	plan := modelgateway.ClaimPlan{
		SchemaVersion: "1.4",
		Claims:        []modelgateway.Claim{{ID: "C1", Kind: "UNKNOWN", UnknownReason: &reason}},
		Sections:      []modelgateway.Section{{ID: "S1", OrderedClaimIDs: []string{"C1"}}},
	}
	if _, ok := candidateSQL(plan); ok {
		t.Fatalf("expected an UNKNOWN claim to be rejected as a SQL candidate")
	}
}

func TestCandidateSQLRejectsMultipleClaims(t *testing.T) {
	sql := "SELECT 1"
	plan := modelgateway.ClaimPlan{
		SchemaVersion: "1.4",
		Claims: []modelgateway.Claim{
			{ID: "C1", Text: &sql, Kind: "FACT", EvidenceIDs: []string{"E1"}},
			{ID: "C2", Text: &sql, Kind: "FACT", EvidenceIDs: []string{"E1"}},
		},
		Sections: []modelgateway.Section{{ID: "S1", OrderedClaimIDs: []string{"C1", "C2"}}},
	}
	if _, ok := candidateSQL(plan); ok {
		t.Fatalf("expected more than one claim to be rejected as ambiguous")
	}
}

func TestSchemaEvidenceOneItemPerObject(t *testing.T) {
	schema := governedquery.ExposedSchema{
		Revision: 1,
		Objects: []governedquery.ExposedObject{
			{SchemaName: "public", TableName: "fleet_trips", Description: "Trips.", Columns: []governedquery.ExposedColumn{{Name: "driver", DataType: "text", Description: "Driver."}}},
		},
	}
	evidence, err := schemaEvidence(schema)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("expected one evidence item per exposed object, got %d", len(evidence))
	}
	if err := evidence[0].Validate(); err != nil {
		t.Fatalf("expected a well-formed synthetic evidence item, got %v", err)
	}
}

// TestDiscloseExecutedAttemptFailsClosedOnAuditError is INT-2 #4's guard for
// FIX-1 #1: Ask() must never disclose a successfully executed query's rows
// when its own mandatory audit append failed. discloseExecutedAttempt is the
// exact code Ask() calls for that decision (service.go), so this exercises
// the real production path without needing a live database, Model Gateway or
// governed-execution role -- the audit-failure branch returns before any of
// those would be touched. It is also the targeted test for the
// governedask-audit-ignored mutant: reverting the "if auditErr != nil"
// refusal here makes the mutated build fall through to
// recordExecutedAttempt, which needs a real *database.Store this test never
// constructs, so the mutant reliably goes RED.
func TestDiscloseExecutedAttemptFailsClosedOnAuditError(t *testing.T) {
	calls := 0
	service := &Service{disclosureCheck: func(context.Context, database.AccessContext, string) error {
		calls++
		return nil
	}}
	auditErr := errors.New("audit append failed")
	value := "3"
	result := governedquery.QueryResult{Columns: []string{"count"}, Rows: [][]*string{{&value}}, RowCount: 1}
	attempt := governedquery.Attempt{SQLHash: "deadbeef", Outcome: governedquery.OutcomeSucceeded}

	got, err := service.discloseExecutedAttempt(context.Background(), database.AccessContext{}, "ws_demo", 1,
		"SELECT count(*) FROM fleet_trips", attempt, result, auditErr)

	if got.AttemptID != "" || got.SQL != "" || got.RowCount != 0 || got.Columns != nil || got.Rows != nil || got.Answer != "" {
		t.Fatalf("expected a zeroed AskResult (0 rows disclosed) when the audit append failed, got %+v", got)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeUnavailable {
		t.Fatalf("expected a CodeUnavailable *Error, got %v", err)
	}
	if !errors.Is(err, auditErr) {
		t.Fatalf("expected the disclosure error to wrap the audit append error, got %v", err)
	}

	if calls != 0 {
		t.Fatalf("expected the audit-error branch to skip disclosure reauthorization, got %d call(s)", calls)
	}
}

func TestValidOpaque(t *testing.T) {
	if !validOpaque("ws_alpha-01") {
		t.Fatalf("expected a valid opaque id to pass")
	}
	for _, value := range []string{"", "has space", "semi;colon"} {
		if validOpaque(value) {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestAskOutputSchemaClosesEveryObjectLevel(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal([]byte(askOutputSchema), &schema); err != nil {
		t.Fatalf("askOutputSchema is not valid JSON: %v", err)
	}

	assertClosed := func(where string, object map[string]any) {
		t.Helper()
		if object["type"] != "object" {
			t.Fatalf("%s: expected object schema, got type=%v", where, object["type"])
		}
		closed, ok := object["additionalProperties"].(bool)
		if !ok || closed {
			t.Fatalf("%s: expected additionalProperties=false, got %v", where, object["additionalProperties"])
		}
	}

	assertClosed("top-level object", schema)
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("askOutputSchema has no properties object")
	}
	claims, ok := properties["claims"].(map[string]any)
	if !ok {
		t.Fatal("askOutputSchema has no properties.claims object")
	}
	claimItems, ok := claims["items"].(map[string]any)
	if !ok {
		t.Fatal("askOutputSchema claims has no items object schema")
	}
	assertClosed("claim object", claimItems)

	sections, ok := properties["sections"].(map[string]any)
	if !ok {
		t.Fatal("askOutputSchema has no properties.sections object")
	}
	sectionItems, ok := sections["items"].(map[string]any)
	if !ok {
		t.Fatal("askOutputSchema sections has no items object schema")
	}
	assertClosed("section object", sectionItems)
}

func TestAskInstructionsRequireExactTopLevelMembers(t *testing.T) {
	lowered := strings.ToLower(askSystemInstructions)
	for _, required := range []string{
		"schema_version",
		"claims",
		"sections",
		"additional",
		"punctuation-named",
		"top-level object contains exactly",
	} {
		if !strings.Contains(lowered, required) {
			t.Fatalf("governed query instructions do not state the top-level member rule %q", required)
		}
	}
}

func TestAskSystemInstructionsStateClaimTextBoundary(t *testing.T) {
	for _, required := range []string{
		"single line",
		"valid UTF-8",
		"2000 UTF-8 bytes",
		"newline",
		"carriage return",
		"tab",
		"control character",
		"leading/trailing whitespace",
		"U+200E",
		"U+200F",
		"U+202A-U+202E",
		"U+2066-U+2069",
	} {
		if !strings.Contains(askSystemInstructions, required) {
			t.Fatalf("governed query instructions do not state the SQL text boundary %q", required)
		}
	}
}

// TestDiscloseExecutedAttemptReauthorizesBeforeDisclosure guards the
// disclosure-time reauthorization gate: even with a successful audit append and
// a real, nonempty result, a denied caller or a workspace with live queries
// disabled must receive exactly the typed error and a completely zero
// AskResult. The injected counter proves the gate ran exactly once, and the
// nonempty QueryResult proves the gate -- not an empty result -- is what
// suppresses disclosure.
func TestDiscloseExecutedAttemptReauthorizesBeforeDisclosure(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		gateErr  error
		wantCode ErrorCode
	}{
		{name: "denied", gateErr: &Error{code: CodeDenied}, wantCode: CodeDenied},
		{name: "live queries off", gateErr: &Error{code: CodeLiveQueriesOff}, wantCode: CodeLiveQueriesOff},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			calls := 0
			gateErr := testCase.gateErr
			service := &Service{disclosureCheck: func(context.Context, database.AccessContext, string) error {
				calls++
				return gateErr
			}}
			value := "3"
			result := governedquery.QueryResult{Columns: []string{"count"}, Rows: [][]*string{{&value}}, RowCount: 1}
			attempt := governedquery.Attempt{SQLHash: "deadbeef", Outcome: governedquery.OutcomeSucceeded}

			got, err := service.discloseExecutedAttempt(context.Background(), database.AccessContext{}, "ws_demo", 1,
				"SELECT count(*) FROM fleet_trips", attempt, result, nil)

			if calls != 1 {
				t.Fatalf("expected exactly one disclosure reauthorization call, got %d", calls)
			}
			var typed *Error
			if !errors.As(err, &typed) || typed.code != testCase.wantCode {
				t.Fatalf("expected a %s *Error, got %v", testCase.wantCode, err)
			}
			if !reflect.DeepEqual(got, AskResult{}) {
				t.Fatalf("expected a completely zero AskResult when disclosure is refused, got %+v", got)
			}
		})
	}
}
