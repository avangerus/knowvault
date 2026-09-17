package question

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

type noModelProfileTools struct{ t *testing.T }

func (runtime noModelProfileTools) Catalog(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
	runtime.t.Fatal("rejected or replayed request reached the tool catalogue")
	return nil, workspacetools.ErrUnavailable
}
func (runtime noModelProfileTools) Invoke(context.Context, workspacetools.Scope, string, json.RawMessage) (workspacetools.Result, error) {
	runtime.t.Fatal("rejected or replayed request invoked a tool")
	return workspacetools.Result{}, workspacetools.ErrUnavailable
}

func testModelProfileService(t *testing.T, journal admissionJournal) *Service {
	t.Helper()
	local := modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: "http://127.0.0.1:1/v1", ModelID: "local-fixture",
		MaxOutputTokens: 256, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{ID: "test-loop", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 32768,
			MaxToolResultBytes: 4096, MaxOutputTokens: 256, TimeoutSeconds: 10},
	}
	cloud := local
	cloud.Endpoint, cloud.ModelID = "https://model.example.invalid/v1", "cloud-fixture"
	cloud.ExternalRuntimeWorkspaceIDs = []string{"ws_0001"}
	cloud.TrustRoots = x509.NewCertPool()
	registry, err := modelgateway.NewProfileRegistry("local", []modelgateway.ProfileConfig{
		{ID: "local", Label: "Local current label", Config: local},
		{ID: "cloud", Label: "Cloud current label", Config: cloud},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	service := testCreateService(journal)
	service.EnableGeneration(registry.Default(), nil)
	service.EnableGenerationProfiles(registry)
	service.EnableToolLoop(noModelProfileTools{t})
	return service
}

func TestModelProfilesKeepPrivateScopeAndCapturedChoice(t *testing.T) {
	service := testModelProfileService(t, &recordingAdmissionJournal{})
	if got := service.ModelProfiles("ws_private"); len(got) != 1 || got[0].ID != "local" || !got[0].IsDefault {
		t.Fatalf("private workspace received an unavailable choice: %+v", got)
	}
	options := service.ModelProfiles("ws_0001")
	if len(options) != 2 || options[1].Location != ProcessingModeExternal {
		t.Fatalf("allowed catalogue=%+v", options)
	}
	selected, err := service.selectGeneration("ws_0001", "cloud")
	if err != nil {
		t.Fatal(err)
	}
	options[1].Label = "caller changed label"
	local, err := service.selectGeneration("ws_private", "local")
	if err != nil || selected.adapter == local.adapter || selected.adapter.ProviderName() != "cloud-fixture" ||
		local.adapter != service.generation || selected.profile.Label != "Cloud current label" {
		t.Fatal("per-request selection changed shared default or captured metadata")
	}
	mode, provider := service.ProcessingMode("ws_0001")
	if mode != ProcessingModeInternal || provider != "local-fixture" {
		t.Fatalf("cloud selection changed default processing mode: %s/%s", mode, provider)
	}
}

func TestNamedModelCreateDeniesBeforeInspectingProfileAvailability(t *testing.T) {
	for _, profileID := range []string{"local", "cloud", "unknown"} {
		t.Run(profileID, func(t *testing.T) {
			journal := &recordingAdmissionJournal{}
			service := testModelProfileService(t, journal)
			service.authorizeModelSelectionFn = func(context.Context, database.AccessContext, string) error {
				journal.order = append(journal.order, "authorize")
				return &Error{code: CodeDenied}
			}
			service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
				t.Fatal("unauthorized model request reached replay/data")
				return Run{}, false, nil
			}
			request := questionCreateRequest()
			request.ModelProfileID = profileID
			if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); CodeOf(err) != CodeDenied {
				t.Fatalf("profile availability changed denial: %v", err)
			}
			if !reflect.DeepEqual(journal.order, []string{"admission", "authorize", "admission"}) || len(journal.appended) != 2 {
				t.Fatalf("authorization was not preceded by one durable admission: %v", journal.order)
			}
			for _, event := range journal.appended {
				if event.WorkspaceID != nil {
					t.Fatal("unknown or denied workspace acquired a disclosure FK")
				}
				if _, err := audit.Build("org_0001", event, 0, ""); err != nil {
					t.Fatal(err)
				}
			}
			if journal.appended[1].Outcome != audit.OutcomeDenied {
				t.Fatal("profile access denial was not journalled")
			}
		})
	}
}

func TestNamedModelCreateRefusesUnavailableProfileInAuthorizedWorkspace(t *testing.T) {
	for _, profileID := range []string{"cloud", "unknown"} {
		journal := &recordingAdmissionJournal{}
		service := testModelProfileService(t, journal)
		service.authorizeModelSelectionFn = func(context.Context, database.AccessContext, string) error { return nil }
		request := questionCreateRequest()
		request.WorkspaceID, request.ModelProfileID = "ws_private", profileID
		if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); CodeOf(err) != CodeUnsupportedMode {
			t.Fatalf("unavailable profile silently fell back: %v", err)
		}
		if len(journal.appended) != 2 || journal.appended[1].WorkspaceID == nil || *journal.appended[1].WorkspaceID != request.WorkspaceID ||
			journal.appended[1].Outcome != audit.OutcomeDenied || *journal.appended[1].ErrorCode != "QUESTION_MODEL_PROFILE_UNAVAILABLE" {
			t.Fatal("authorized workspace cannot see its profile refusal")
		}
	}
}

func TestNamedModelAdmissionFailureDoesNotInspectAuthorityOrReplay(t *testing.T) {
	service := testModelProfileService(t, failingAdmissionJournal{})
	service.authorizeModelSelectionFn = func(context.Context, database.AccessContext, string) error {
		t.Fatal("failed audit allowed authorization read")
		return nil
	}
	request := questionCreateRequest()
	request.ModelProfileID = "cloud"
	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); CodeOf(err) != CodeUnavailable {
		t.Fatalf("audit failure did not fail closed: %v", err)
	}
}

func TestNamedModelAuthorityFailureIsNotReportedAsAccessDenial(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testModelProfileService(t, journal)
	service.authorizeModelSelectionFn = func(context.Context, database.AccessContext, string) error {
		return &Error{code: CodeUnavailable}
	}
	request := questionCreateRequest()
	request.ModelProfileID = "cloud"
	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); CodeOf(err) != CodeUnavailable {
		t.Fatalf("authority failure did not fail closed: %v", err)
	}
	if len(journal.appended) != 2 || journal.appended[1].Outcome != audit.OutcomeFailed ||
		journal.appended[1].ErrorCode == nil || *journal.appended[1].ErrorCode != "QUESTION_MODEL_ACCESS_FAILED" || journal.appended[1].WorkspaceID != nil {
		t.Fatal("authority failure was reported as a permission denial or disclosed a workspace")
	}
}

func TestNamedModelReplayPreservesHistoricalProfileAndConflictsOnDifferentChoice(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testModelProfileService(t, journal)
	service.authorizeModelSelectionFn = func(context.Context, database.AccessContext, string) error {
		journal.order = append(journal.order, "authorize")
		return nil
	}
	request := questionCreateRequest()
	request.ModelProfileID = "cloud"
	text, _ := canonicalQuestion(request.Question)
	storedHash := toolLoopRequestHash(text, "", "cloud")
	stored := Run{ID: "qrun_historical", ModelProfile: &ModelProfile{ID: "cloud", Label: "Historical label", Location: ProcessingModeExternal}}
	service.lookupIdempotencyFn = func(_ context.Context, _ database.AccessContext, _ string, digest, _ string) (Run, bool, error) {
		journal.order = append(journal.order, "lookup")
		if digest != storedHash {
			return Run{}, false, &Error{code: CodeIdempotencyConflict}
		}
		return stored, true, nil
	}
	got, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request)
	if err != nil || !reflect.DeepEqual(got, stored) || !reflect.DeepEqual(journal.order, []string{"admission", "authorize", "lookup"}) {
		t.Fatalf("replay replaced historical metadata or skipped admission: %+v %v %v", got, err, journal.order)
	}
	request.ModelProfileID = "local"
	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); CodeOf(err) != CodeIdempotencyConflict {
		t.Fatalf("same key with another profile did not conflict: %v", err)
	}
	if toolLoopRequestHash(text, "", "") != requestHash(text, AnswerModeToolLoop, "") {
		t.Fatal("legacy replay identity changed")
	}
}

func TestModelProfileMetadataRoundTripsWithoutCurrentRegistry(t *testing.T) {
	record := &ToolLoopRecord{ModelProfile: &ModelProfile{ID: "historical", Label: "Old label", Location: ProcessingModeExternal}}
	raw, err := marshalStructuredAnswer("qrun_1", "hash", nil, nil, nil, record)
	if err != nil {
		t.Fatal(err)
	}
	var restored structuredAnswer
	if err := json.Unmarshal(raw, &restored); err != nil || restored.ToolLoop == nil || !reflect.DeepEqual(restored.ToolLoop.ModelProfile, record.ModelProfile) {
		t.Fatalf("encrypted artifact payload lost actual selection: %v", err)
	}
	// Decode older artifacts into a fresh value: no current default may be invented.
	var old structuredAnswer
	if err := json.Unmarshal([]byte(`{"tool_loop":{"profile":{},"model":"old"}}`), &old); err != nil || old.ToolLoop.ModelProfile != nil {
		t.Fatal("old trace acquired a fabricated model selection")
	}
}
