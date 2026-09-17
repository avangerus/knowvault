package ingestion

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestGraphTermInputsKeepCanonicalTitleAndContextTermsSeparate(t *testing.T) {
	terms := graphTermInputs("Operations Kafka", []plannedUnit{{text: []byte("Kafka is a message bus")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	if len(terms) == 0 {
		t.Fatal("graph term projection produced no terms")
	}
	if terms[0].Label != "operations kafka" || terms[0].TermKind != "CANONICAL" || terms[0].ContextHash != "" {
		t.Fatalf("title term=%+v, want canonical title without context hash", terms[0])
	}
	foundContext := false
	for _, term := range terms[1:] {
		if term.Label == "kafka" {
			foundContext = true
			if term.TermKind != "CONTEXT" || term.ContextHash == "" {
				t.Fatalf("kafka context term=%+v, want context hash", term)
			}
		}
	}
	if !foundContext {
		t.Fatal("content token Kafka was not projected as a context term")
	}
}

func TestGraphTermInputsProjectOnlyExplicitDefinitionAsSynonym(t *testing.T) {
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("\u0428\u0438\u043d\u0430 \u2014 \u044d\u0442\u043e Kafka")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	var synonym, context bool
	for _, term := range terms {
		if term.Label == "\u0448\u0438\u043d\u0430" && term.TermKind == "SYNONYM" {
			synonym = true
			if term.ContextHash == "" || term.EvidenceFragmentID == "" {
				t.Fatalf("synonym=%+v lacks Evidence context", term)
			}
		}
		if term.Label == "kafka" && term.TermKind == "CONTEXT" {
			context = true
		}
	}
	if !synonym || !context {
		t.Fatalf("terms=%+v, want explicit synonym and context token", terms)
	}
}

func TestGraphTermInputsAcceptsExplicitDefinitionWithInternalStopWord(t *testing.T) {
	terms := graphTermInputs("Contract", []plannedUnit{{text: []byte("Kafka means bus in operations.")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	for _, term := range terms {
		if term.Label == "kafka" && term.TermKind == "SYNONYM" {
			return
		}
	}
	t.Fatalf("explicit definition with internal stop word was not projected: terms=%+v", terms)
}

func TestGraphTermInputsRejectIncompleteOrNumericDefinitions(t *testing.T) {
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("Kafka means a. 2026 — 08")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	for _, term := range terms {
		if term.TermKind == "SYNONYM" {
			t.Fatalf("unsafe definition became synonym: %+v", term)
		}
	}
}

func TestGraphTermInputsProjectExplicitMultiTokenAndBilingualAliases(t *testing.T) {
	fragmentID := "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("Event streaming bus, also known as Kafka Bridge. \u0428\u0438\u043d\u0430 \u0442\u0430\u043a\u0436\u0435 \u0438\u0437\u0432\u0435\u0441\u0442\u043d\u0430 \u043a\u0430\u043a event streaming bus.")}}, []string{fragmentID})
	seen := map[string]graphTermInput{}
	for _, term := range terms {
		if term.TermKind == "SYNONYM" {
			seen[term.Label] = term
		}
	}
	for _, label := range []string{"event streaming bus", "\u0448\u0438\u043d\u0430"} {
		term, ok := seen[label]
		if !ok {
			t.Fatalf("explicit alias %q was not projected: terms=%+v", label, terms)
		}
		if term.EvidenceFragmentID != fragmentID || term.ContextHash == "" {
			t.Fatalf("alias %q lost Evidence/context provenance: %+v", label, term)
		}
	}
}

func TestGraphTermInputsProjectMarkedAbbreviationOnly(t *testing.T) {
	fragmentID := "fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("Message Bus (abbr: MB). Plain label (MB) is not an abbreviation assertion.")}}, []string{fragmentID})
	var abbreviation graphTermInput
	for _, term := range terms {
		if term.TermKind == "ABBREVIATION" {
			if abbreviation.Label != "" {
				t.Fatalf("multiple abbreviation assertions: previous=%+v current=%+v", abbreviation, term)
			}
			abbreviation = term
		}
	}
	if abbreviation.Label != "mb" || abbreviation.EvidenceFragmentID != fragmentID || abbreviation.ContextHash == "" {
		t.Fatalf("marked abbreviation=%+v, want mb with Evidence/context provenance", abbreviation)
	}
}

func TestGraphTermInputsProjectAbbreviationForOrientation(t *testing.T) {
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("MB is an abbreviation for Message Bus")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	for _, term := range terms {
		if term.TermKind == "ABBREVIATION" && term.Label == "mb" {
			return
		}
	}
	t.Fatalf("abbreviation-for assertion was not projected: terms=%+v", terms)
}

func TestGraphTermInputsKeepExplicitDashWithoutWhitespaceBounded(t *testing.T) {
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("EventBus—message broker")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	for _, term := range terms {
		if term.TermKind == "SYNONYM" && term.Label == "eventbus" {
			return
		}
	}
	t.Fatalf("explicit adjacent dash definition was not projected: terms=%+v", terms)
}

func TestGraphTermInputsRejectAmbiguousOrUnmarkedAliasSyntax(t *testing.T) {
	terms := graphTermInputs("Glossary", []plannedUnit{{text: []byte("Kafka also known as the platform used by teams. Plain label (MB) remains context.")}}, []string{"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	for _, term := range terms {
		if term.TermKind == "SYNONYM" || term.TermKind == "ABBREVIATION" {
			t.Fatalf("ambiguous/unmarked prose became semantic alias: %+v", term)
		}
	}
}

func TestPostgreSQLGraphTermInputsBindColumnNamesToEvidenceCells(t *testing.T) {
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "waste_daily",
		Revision: 1, ContractHash: "sha256:" + strings.Repeat("a", 64),
		SchemaName: "reporting", RelationName: "waste_daily", RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "crew", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 128},
			{Ordinal: 3, Name: "kilograms", TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 2, MaxBytes: 64},
		},
	}
	row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{
		"550e8400-e29b-41d4-a716-446655440000", "Alpha", "12.50",
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := "hmac-sha256:k1:" + strings.Repeat("b", 64)
	terms, err := postgresqlGraphTermInputs(PostgreSQLSnapshotRequest{Projection: projection}, row, []string{"frag_crew", "frag_kilograms"}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(terms) != 3 || terms[0].Label != "waste_daily" || terms[0].TermKind != "CANONICAL" {
		t.Fatalf("terms=%+v, want lineage plus two column context terms", terms)
	}
	if terms[1].Label != "crew" || terms[1].TermKind != "CONTEXT" || terms[1].EvidenceFragmentID != "frag_crew" || terms[1].ContextHash == "" {
		t.Fatalf("crew term=%+v", terms[1])
	}
	if terms[2].Label != "kilograms" || terms[2].TermKind != "CONTEXT" || terms[2].EvidenceFragmentID != "frag_kilograms" || terms[2].ContextHash == "" {
		t.Fatalf("metric term=%+v", terms[2])
	}
}

func TestPostgreSQLGraphTermInputsRejectEvidenceFragmentDrift(t *testing.T) {
	projection := postgresqlquery.Projection{
		ConnectionID: "conn_demo", DatabaseIdentity: "db_demo", LineageID: "waste_daily",
		Revision: 1, ContractHash: "sha256:" + strings.Repeat("a", 64),
		SchemaName: "reporting", RelationName: "waste_daily", RelationKind: "VIEW", EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "kilograms", TypeFingerprint: "oid:1700:p:12:s:2", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 2, MaxBytes: 64},
		},
	}
	row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{"550e8400-e29b-41d4-a716-446655440000", "12.50"})
	if err != nil {
		t.Fatal(err)
	}
	identity := "hmac-sha256:k1:" + strings.Repeat("b", 64)
	if _, err := postgresqlGraphTermInputs(PostgreSQLSnapshotRequest{Projection: projection}, row, nil, identity); CodeOf(err) != "INGEST_GRAPH_EVIDENCE_MAPPING" {
		t.Fatalf("missing fragment mapping accepted: %v (code=%s)", err, CodeOf(err))
	}
	if _, err := postgresqlGraphTermInputs(PostgreSQLSnapshotRequest{Projection: projection}, row, []string{"frag_one", "frag_extra"}, identity); CodeOf(err) != "INGEST_GRAPH_EVIDENCE_MAPPING" {
		t.Fatalf("extra fragment mapping accepted: %v (code=%s)", err, CodeOf(err))
	}
}
