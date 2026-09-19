package modelgateway

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func testHash(prefix byte) string {
	return "sha256:" + strings.Repeat(string(prefix), 64)
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	profile := Profile{
		SchemaVersion:     ProfileSchemaVersion,
		ID:                "profile_generation_v1",
		Purpose:           PurposeGeneration,
		ModelID:           "model-exact-v1",
		ArtifactHash:      testHash('a'),
		TokenizerHash:     testHash('b'),
		RuntimeHash:       testHash('c'),
		ConfigurationHash: testHash('d'),
		Endpoint:          "https://model.example:8443",
		ServerName:        "model.example",
		ContextTokens:     32768,
		MaxOutputTokens:   1024,
		Revision:          1,
	}
	raw, err := profileCanonical(profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.ProfileHash = canonHash(raw)
	return profile
}

func canonHash(raw []byte) string {
	return canon.Hash(raw)
}

func testEvidence(id string) Evidence {
	return Evidence{ID: id, SourceObjectID: "object_1", SourceVersionID: "version_1", ExtractionID: "extraction_1", TextHash: testHash('e'), AnchorHash: testHash('f'), Text: "Kafka \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f \u0432 \u0448\u0438\u043d\u0435."}
}

func testSchema(t *testing.T) ([]byte, string) {
	t.Helper()
	raw, err := canon.CanonicalJSON(map[string]any{"type": "object", "properties": map[string]any{"claims": map[string]any{"type": "array"}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw, canonHash(raw)
}

func TestProfileValidationBindsCanonicalIdentity(t *testing.T) {
	profile := testProfile(t)
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	profile.ModelID = "different-model"
	if CodeOf(profile.Validate()) != CodeProfile {
		t.Fatal("profile mutation was accepted")
	}
}

func TestGenerateRequestRejectsNonCanonicalOrMismatchedContext(t *testing.T) {
	profile := testProfile(t)
	schema, schemaHash := testSchema(t)
	request := GenerateRequest{
		SchemaVersion:      SchemaVersion,
		Binding:            Binding{OrganizationID: "org_1", WorkspaceID: "workspace_1", QuestionRunID: "qrun_1", Purpose: PurposeGeneration, ProfileHash: profile.ProfileHash, RetrievalSnapshotHash: testHash('1'), ContextPackHash: testHash('2')},
		Question:           "\u0427\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 \u0448\u0438\u043d\u0430?",
		SystemInstructions: "\u0412\u0435\u0440\u043d\u0438 \u0442\u043e\u043b\u044c\u043a\u043e JSON claim plan.",
		OutputSchema:       schema,
		OutputSchemaHash:   schemaHash,
		ContextTokenCount:  64,
		MaxOutputTokens:    128,
		Evidence:           []Evidence{testEvidence("ev_a")},
	}
	if err := request.Validate(profile); err != nil {
		t.Fatal(err)
	}
	request.SystemInstructions = "\u0421\u0442\u0440\u043e\u0433\u0430\u044f \u0441\u0445\u0435\u043c\u0430:\n- \u0442\u043e\u043b\u044c\u043a\u043e JSON\n- \u0431\u0435\u0437 \u0438\u043d\u0441\u0442\u0440\u0443\u043c\u0435\u043d\u0442\u043e\u0432"
	if err := request.Validate(profile); err != nil {
		t.Fatalf("multiline server-owned instructions rejected: %v", err)
	}
	request.Binding.ProfileHash = testHash('9')
	if CodeOf(request.Validate(profile)) != CodeBinding {
		t.Fatal("binding mutation was accepted")
	}
	request.Binding.ProfileHash = profile.ProfileHash
	request.OutputSchema = []byte(`{ "type": "object", "properties": {"claims": {"type":"array"}} }`)
	if CodeOf(request.Validate(profile)) != CodeInvalid {
		t.Fatal("non-canonical output schema was accepted")
	}
}

// TestEvidenceValidateAcceptsRealFragmentIDScheme guards a regression found
// live on the acc acceptance stand (GEN-2): validEvidenceID used to require an
// "ev_" prefix that no real Evidence ID in this deployment actually has —
// evidence_fragment.id values are minted as "fragment_<ULID>" — so every real
// GENERATIVE attempt failed MODEL_REQUEST_INVALID before a single byte
// reached the model. Evidence IDs validate on shape alone now, exactly like
// the other opaque identifiers on the same struct.
func TestEvidenceValidateAcceptsRealFragmentIDScheme(t *testing.T) {
	if err := testEvidence("fragment_01M1SHVWVE8GEH04R30GAXP92K").Validate(); err != nil {
		t.Fatalf("expected a real fragment_<ULID> Evidence ID to validate, got %v", err)
	}
	if err := testEvidence("").Validate(); CodeOf(err) != CodeInvalid {
		t.Fatal("expected an empty Evidence ID to still be rejected")
	}
}

func TestClaimPlanRequiresEvidenceAndAcyclicSupport(t *testing.T) {
	evidence := []Evidence{testEvidence("ev_a")}
	factText := "\u0424\u0430\u043a\u0442"
	plan := ClaimPlan{SchemaVersion: ModelAnswerVersion,
		Claims:   []Claim{{ID: "C1", Text: &factText, Kind: "FACT", EvidenceIDs: []string{"ev_a"}, SupportingClaimIDs: []string{}}},
		Sections: []Section{{ID: "S1", Title: nil, OrderedClaimIDs: []string{"C1"}}}}
	if err := plan.Validate(evidence); err != nil {
		t.Fatal(err)
	}
	if diagnostic, err := plan.validate(evidence); err != nil || diagnostic != "" {
		t.Fatalf("valid plan produced diagnostic=%q err=%v, want empty/nil", diagnostic, err)
	}
	plan.Claims[0].EvidenceIDs = []string{"ev_missing"}
	if diagnostic, err := plan.validate(evidence); err == nil || diagnostic != ResponseClaimEvidenceInvalid || CodeOf(err) != CodeResponse {
		t.Fatalf("unknown evidence reference diagnostic=%q err=%v, want %s/CodeResponse", diagnostic, err, ResponseClaimEvidenceInvalid)
	}
	if CodeOf(plan.Validate(evidence)) != CodeResponse {
		t.Fatal("unknown evidence reference was accepted")
	}
	plan.Claims[0].EvidenceIDs = []string{"ev_a"}
	inferenceText := "\u0412\u044b\u0432\u043e\u0434"
	plan.Claims = []Claim{
		{ID: "C1", Text: &factText, Kind: "FACT", EvidenceIDs: []string{"ev_a"}, SupportingClaimIDs: []string{}},
		{ID: "C2", Text: &inferenceText, Kind: "INFERENCE", EvidenceIDs: []string{}, SupportingClaimIDs: []string{"C1"}},
	}
	plan.Sections[0].OrderedClaimIDs = []string{"C1", "C2"}
	if err := plan.Validate(evidence); err != nil {
		t.Fatal(err)
	}
	plan.Claims[0].Kind = "INFERENCE"
	plan.Claims[0].EvidenceIDs = []string{}
	plan.Claims[0].SupportingClaimIDs = []string{"C2"}
	if diagnostic, err := plan.validate(evidence); err == nil || diagnostic != ResponseClaimSupportInvalid || CodeOf(err) != CodeResponse {
		t.Fatalf("cyclic unsupported claims diagnostic=%q err=%v, want %s/CodeResponse", diagnostic, err, ResponseClaimSupportInvalid)
	}
	if CodeOf(plan.Validate(evidence)) != CodeResponse {
		t.Fatal("cyclic unsupported claims were accepted")
	}
}

func TestClaimPlanStrictJSONRequiresNullableMembers(t *testing.T) {
	var plan ClaimPlan
	raw := []byte(`{"schema_version":"1.4","claims":[{"claim_id":"C1","text":"fact","kind":"FACT","unknown_reason":null,"evidence_ids":["ev_a"],"supporting_claim_ids":[]}],"sections":[{"section_id":"S1","title":null,"ordered_claim_ids":["C1"]}]}`)
	if err := strictJSON(raw, &plan); err != nil {
		t.Fatal(err)
	}
	missing := []byte(`{"schema_version":"1.4","claims":[{"claim_id":"C1","text":"fact","kind":"FACT","unknown_reason":null,"evidence_ids":["ev_a"],"supporting_claim_ids":[]}],"sections":[{"section_id":"S1","ordered_claim_ids":["C1"]}]}`)
	if err := strictJSON(missing, &plan); err == nil {
		t.Fatal("missing required nullable section title was accepted")
	}
	unknown := []byte(`{"schema_version":"1.4","claims":[],"sections":[],"extra":true}`)
	if err := strictJSON(unknown, &plan); err == nil {
		t.Fatal("unknown model-answer field was accepted")
	}
	duplicate := []byte(`{"schema_version":"1.4","schema_version":"1.4","claims":[],"sections":[]}`)
	if err := strictJSON(duplicate, &plan); err == nil {
		t.Fatal("duplicate model-answer member was accepted")
	}
}

func TestModelEndpointRequiresHTTPSNamedHost(t *testing.T) {
	for _, value := range []struct{ endpoint, server string }{
		{"http://model.example:8443", "model.example"},
		{"https://192.168.1.51:8443", "192.168.1.51"},
		{"https://model.example:08443", "model.example"},
	} {
		if validModelEndpoint(value.endpoint, value.server) {
			t.Fatalf("unsafe model endpoint accepted: %#v", value)
		}
	}
	if !validModelEndpoint("https://model.example:8443", "model.example") {
		t.Fatal("valid model endpoint rejected")
	}
}
