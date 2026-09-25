package question

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestToolLoopGreetingQuestionRecognizesOnlyGreetings(t *testing.T) {
	for _, greeting := range []string{"привет", "Привет!", "Здравствуйте", "hello", "Hi!"} {
		if !toolLoopGreetingQuestion(greeting) {
			t.Fatalf("greeting %q was not recognized", greeting)
		}
	}
	for _, question := range []string{"что ты знаешь?", "сколько договоров действует?", "какая погода в Москве?"} {
		if toolLoopGreetingQuestion(question) {
			t.Fatalf("non-greeting %q was treated as a greeting", question)
		}
	}
}

func TestToolLoopOverviewSourcesCarryNameAndConnectionID(t *testing.T) {
	seen, ingested := int64(3), int64(3)
	raw := json.RawMessage(`{"sources":[
		{"connection_id":"conn_contract","connection_name":"\u0414\u043e\u0433\u043e\u0432\u043e\u0440\u044b","source_type":"POSTGRESQL_QUERY","postgresql_schema_name":"public","postgresql_relation_name":"contract","enabled":true,"activation_status":"READY","sync_status":"SUCCEEDED","freshness_state":"FRESH","objects_seen":0,"objects_ingested":0},
		{"connection_id":"conn_folder","connection_name":"\u0420\u0435\u0433\u043b\u0430\u043c\u0435\u043d\u0442\u044b \u0438 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u044b","source_type":"FOLDER","enabled":true,"activation_status":"READY","objects_seen":3,"objects_ingested":3}
	]}`)
	sources := toolLoopOverviewSourcesFromResult(raw)
	if len(sources) != 2 {
		t.Fatalf("decoded %d sources, want 2", len(sources))
	}
	contract := toolLoopOverviewSourceLine(questionLanguageRussian, sources[0])
	for _, want := range []string{"Договоры", "source_id=conn_contract", "POSTGRESQL_QUERY", "public.contract", "READY"} {
		if !strings.Contains(contract, want) {
			t.Fatalf("contract source line %q omitted %q", contract, want)
		}
	}
	folder := toolLoopOverviewSourceLine(questionLanguageRussian, sources[1])
	for _, want := range []string{"Регламенты и договоры", "source_id=conn_folder", "FOLDER", "объектов 3/3"} {
		if !strings.Contains(folder, want) {
			t.Fatalf("folder source line %q omitted %q", folder, want)
		}
	}
	if got := toolLoopOverviewSourceLine(questionLanguageEnglish, toolLoopOverviewSource{Name: "Clients", ConnectionID: "conn_client", SourceType: "POSTGRESQL_QUERY", ObjectsIngested: &ingested, ObjectsSeen: &seen}); !strings.Contains(got, "objects 3/3") {
		t.Fatalf("english source line lost its counts: %q", got)
	}
}

func TestToolLoopModelToolCallsIgnoreSystemReads(t *testing.T) {
	record := &ToolLoopRecord{Calls: []ToolCallRecord{
		{Name: "knowvault_sources", System: true},
		{Name: "knowvault_list_objects", System: true},
		{Name: "knowvault_read", System: true},
		{Name: "knowvault_search"},
		{Name: "knowvault_source_sql"},
	}}
	if got := toolLoopModelToolCalls(record); got != 2 {
		t.Fatalf("model tool calls = %d, want the 2 non-system calls", got)
	}
	if got := toolLoopModelToolCalls(nil); got != 0 {
		t.Fatalf("nil record counted %d calls", got)
	}
}

func TestInsertToolLoopMessageKeepsListsIndependent(t *testing.T) {
	base := []modelgateway.Message{{Role: "system"}, {Role: "user", Content: "question"}}
	inserted := insertToolLoopMessage(base, len(base)-1, modelgateway.Message{Role: "user", Content: "overview"})
	if len(inserted) != 3 || inserted[1].Content != "overview" || inserted[2].Content != "question" {
		t.Fatalf("insert produced %+v", inserted)
	}
	if len(base) != 2 || base[1].Content != "question" {
		t.Fatalf("insert mutated its input: %+v", base)
	}
}

func TestToolLoopClaimKeptKeepsLiveContentWhenDocumentCitationsFail(t *testing.T) {
	if kept, liveOnly := toolLoopClaimKept(true, 1, true, 0, true); !kept || liveOnly {
		t.Fatalf("verified document claim: kept=%v liveOnly=%v", kept, liveOnly)
	}
	if kept, liveOnly := toolLoopClaimKept(false, 0, true, 1, true); !kept || liveOnly {
		t.Fatalf("live-only claim: kept=%v liveOnly=%v", kept, liveOnly)
	}
	kept, liveOnly := toolLoopClaimKept(true, 0, true, 1, true)
	if !kept || !liveOnly {
		t.Fatalf("failed document citations beside a bound live read must keep the live content: kept=%v liveOnly=%v", kept, liveOnly)
	}
	if kept, _ := toolLoopClaimKept(true, 0, true, 0, true); kept {
		t.Fatal("a claim with only failed document citations and no live read was kept")
	}
	if kept, _ := toolLoopClaimKept(false, 0, true, 1, false); kept {
		t.Fatal("a claim whose live read did not bind was kept")
	}
	if kept, _ := toolLoopClaimKept(false, 0, true, 0, true); kept {
		t.Fatal("a claim with no evidence at all was kept")
	}
}

func TestNormalizeToolCitationSelectorAcceptsEitherSpelling(t *testing.T) {
	address := normalizeToolCitationSelector(toolCitation{FragmentID: "kv1:object_a~fragment_b"})
	if address.Address != "kv1:object_a~fragment_b" || address.FragmentID != "" {
		t.Fatalf("canonical address in fragment_id was not normalized: %+v", address)
	}
	fragment := normalizeToolCitationSelector(toolCitation{Address: "fragment_b"})
	if fragment.FragmentID != "fragment_b" || fragment.Address != "" {
		t.Fatalf("bare fragment id in address was not normalized: %+v", fragment)
	}
	unchanged := normalizeToolCitationSelector(toolCitation{Address: "kv1:object_a~fragment_b"})
	if unchanged.Address != "kv1:object_a~fragment_b" || unchanged.FragmentID != "" {
		t.Fatalf("canonical address was changed: %+v", unchanged)
	}
}

func TestToolLoopUnverifiedLiveAnswerClearsPersistedProof(t *testing.T) {
	record := &ToolLoopRecord{
		ClaimEvidenceVersion: "v1",
		ClaimEvidence:        []ToolClaimEvidence{{TextHash: "sha256:x"}},
		VerifiedClaims:       []int{0},
		AllClaimsBound:       true,
	}
	answer, result, status, returned := toolLoopUnverifiedLiveAnswer(record, questionLanguageRussian)
	if returned != record || result != nil || status != "INSUFFICIENT_EVIDENCE" || answer == "" {
		t.Fatalf("unexpected fallback: answer=%q status=%q", answer, status)
	}
	if record.StopReason != "CITATIONS_UNVERIFIED" || record.ClaimEvidenceVersion != "" ||
		record.ClaimEvidence != nil || record.VerifiedClaims != nil || record.AllClaimsBound {
		t.Fatalf("fallback left a persisted proof beside the failure text: %+v", record)
	}
}
