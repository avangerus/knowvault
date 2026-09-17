package workspaceapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

type modelProfileQuestionService struct {
	*fakeQuestionService
	catalog      map[string][]question.ModelProfileOption
	catalogCalls []string
	onCatalog    func(string)
	defaultMode  string
}

func (service *modelProfileQuestionService) ModelProfiles(workspaceID string) []question.ModelProfileOption {
	service.catalogCalls = append(service.catalogCalls, workspaceID)
	if service.onCatalog != nil {
		service.onCatalog(workspaceID)
	}
	return service.catalog[workspaceID]
}

func (service *modelProfileQuestionService) DefaultAnswerMode(string) string {
	if service.defaultMode != "" {
		return service.defaultMode
	}
	return questionModeExtractive
}

func postModelProfileQuestion(t *testing.T, harness *testHarness, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", body)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

func TestModelProfilesSnapshotUsesAuthorizedWorkspaceCatalogue(t *testing.T) {
	local := question.ModelProfileOption{
		ModelProfile: question.ModelProfile{ID: "local-qwen", Label: "Qwen", Location: "INTERNAL"}, IsDefault: true,
	}
	cloud := question.ModelProfileOption{
		ModelProfile: question.ModelProfile{ID: "deepseek-law", Label: "DeepSeek", Location: "EXTERNAL"},
	}
	catalog := map[string][]question.ModelProfileOption{
		"ws_alpha": {local, cloud},
		"ws_beta":  {local},
		"ws_empty": {},
	}
	for workspaceID, want := range catalog {
		t.Run(workspaceID, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.service.snapshot.ID = workspaceID
			service := &modelProfileQuestionService{fakeQuestionService: harness.questions, catalog: catalog}
			service.onCatalog = func(id string) {
				if id != workspaceID || harness.service.call != "get" || harness.auth.authenticateCalls != 1 {
					t.Fatalf("catalogue read before workspace authorization: id=%q call=%q auth=%d", id, harness.service.call, harness.auth.authenticateCalls)
				}
			}
			harness.handler.questions = service
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/"+workspaceID, ""))
			if response.Code != http.StatusOK || !reflect.DeepEqual(service.catalogCalls, []string{workspaceID}) {
				t.Fatalf("status=%d catalogue scopes=%v", response.Code, service.catalogCalls)
			}
			var snapshot struct {
				ID            string                        `json:"id"`
				ModelProfiles []question.ModelProfileOption `json:"model_profiles"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.ID != workspaceID || !reflect.DeepEqual(snapshot.ModelProfiles, want) {
				t.Fatalf("workspace catalogue=%#v, want=%#v", snapshot, want)
			}
			// This is a disclosure boundary: only display identity and default
			// choice belong in the catalogue, never registry endpoints or secrets.
			var projection struct {
				ModelProfiles []map[string]json.RawMessage `json:"model_profiles"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &projection); err != nil {
				t.Fatal(err)
			}
			for _, profile := range projection.ModelProfiles {
				if len(profile) != 4 {
					t.Fatalf("unexpected model metadata disclosed: %v", profile)
				}
				for _, field := range []string{"id", "label", "location", "is_default"} {
					if _, present := profile[field]; !present {
						t.Fatalf("model catalogue field %q missing", field)
					}
				}
			}
		})
	}
}

func TestModelProfilesCatalogueIsNotReadWhenWorkspaceAccessFails(t *testing.T) {
	for _, tc := range []struct {
		name       string
		authErr    error
		serviceErr error
		status     int
	}{
		{"session rejected", errors.New("session rejected"), nil, http.StatusUnauthorized},
		{"workspace denied", nil, workspacerepository.NewError(workspacerepository.CodeDenied, nil), http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.auth.authenticateErr = tc.authErr
			harness.service.err = tc.serviceErr
			service := &modelProfileQuestionService{fakeQuestionService: harness.questions}
			harness.handler.questions = service
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha", ""))
			if response.Code != tc.status || len(service.catalogCalls) != 0 {
				t.Fatalf("status=%d catalogue scopes=%v", response.Code, service.catalogCalls)
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if _, exposed := body["model_profiles"]; exposed {
				t.Fatal("denied workspace exposed its model catalogue")
			}
		})
	}
}

func TestModelProfilesSnapshotWithoutOptionalCapabilityReturnsEmptyCatalogue(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha", ""))
	var snapshot struct {
		ModelProfiles []question.ModelProfileOption `json:"model_profiles"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || snapshot.ModelProfiles == nil || len(snapshot.ModelProfiles) != 0 {
		t.Fatalf("legacy capability catalogue: status=%d profiles=%#v", response.Code, snapshot.ModelProfiles)
	}
}

func TestModelProfilesCatalogueRequiresAskPermissionNotOnlyReadableMetadata(t *testing.T) {
	option := question.ModelProfileOption{
		ModelProfile: question.ModelProfile{ID: "local-qwen", Label: "Qwen", Location: "INTERNAL"}, IsDefault: true,
	}
	for _, tc := range []struct {
		name    string
		role    workspace.Role
		status  workspace.Status
		allowed bool
	}{
		{"active owner", workspace.RoleOwner, workspace.StatusActive, true},
		{"active manager", workspace.RoleManager, workspace.StatusActive, true},
		{"active member", workspace.RoleMember, workspace.StatusActive, true},
		{"viewer", workspace.RoleViewer, workspace.StatusActive, false},
		{"auditor", workspace.RoleAuditor, workspace.StatusActive, false},
		{"read only owner", workspace.RoleOwner, workspace.StatusReadOnly, false},
		{"archived owner", workspace.RoleOwner, workspace.StatusArchived, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			harness := newTestHarness(t)
			snapshot := harness.service.snapshot
			snapshot.Status = tc.status
			if tc.role != workspace.RoleOwner {
				snapshot.OwnerPrincipalID = "usr_other_owner"
				snapshot.Members = []workspace.Member{
					{PrincipalID: "usr_other_owner", Role: workspace.RoleOwner},
					{PrincipalID: "usr_alice", Role: tc.role},
				}
			}
			var err error
			harness.service.snapshot, err = workspace.Normalize(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			service := &modelProfileQuestionService{
				fakeQuestionService: harness.questions,
				catalog:             map[string][]question.ModelProfileOption{"ws_alpha": {option}},
			}
			harness.handler.questions = service
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha", ""))
			var result struct {
				ID            string                        `json:"id"`
				ModelProfiles []question.ModelProfileOption `json:"model_profiles"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || result.ID != "ws_alpha" || result.ModelProfiles == nil {
				t.Fatalf("readable metadata disappeared: status=%d snapshot=%#v", response.Code, result)
			}
			want := []question.ModelProfileOption{}
			if tc.allowed {
				want = append(want, option)
			}
			if !reflect.DeepEqual(result.ModelProfiles, want) {
				t.Fatalf("model availability does not follow ask permission: role=%s status=%s profiles=%#v", tc.role, tc.status, result.ModelProfiles)
			}
			if !tc.allowed && len(service.catalogCalls) != 0 {
				t.Fatalf("catalogue read without ask permission: role=%s status=%s scopes=%v", tc.role, tc.status, service.catalogCalls)
			}
		})
	}
}

func TestModelProfileIDInvalidValuesNeverReachQuestionAuthority(t *testing.T) {
	for name, value := range map[string]string{
		"null": "null", "empty": `""`, "blank": `" "`,
		"leading space": `" local-qwen"`, "trailing space": `"local-qwen "`,
		"leading punctuation": `"_qwen"`, "path": `"models/qwen"`, "colon": `"model:qwen"`,
		"non ASCII": "\"\u043c\u043e\u0434\u0435\u043b\u044c\"", "control character": `"qwen\n"`,
		"too long": `"` + strings.Repeat("a", 65) + `"`,
		"number":   "7", "boolean": "true", "object": `{}`, "array": `[]`,
		"malformed string": `"unterminated`,
	} {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			response := postModelProfileQuestion(t, harness, `{"question":"Overview?","model_profile_id":`+value+`}`)
			if response.Code != http.StatusBadRequest || harness.questions.call != "" {
				t.Fatalf("invalid profile reached authority: status=%d call=%q", response.Code, harness.questions.call)
			}
		})
	}
}

func TestModelProfileIDSelectsToolLoopAndForwardsExactIdentity(t *testing.T) {
	for _, profileID := range []string{"q", "DeepSeek-law.v2", strings.Repeat("x", 64)} {
		for _, explicitMode := range []bool{false, true} {
			name := profileID + "/inferred"
			modeField := ""
			if explicitMode {
				name, modeField = profileID+"/explicit", `,"answer_mode":"TOOL_LOOP"`
			}
			t.Run(name, func(t *testing.T) {
				harness := newTestHarness(t)
				response := postModelProfileQuestion(t, harness, `{"question":"Overview?","model_profile_id":"`+profileID+`"`+modeField+`}`)
				request := harness.questions.request
				if response.Code != http.StatusOK || harness.questions.call != "create" || request.ModelProfileID != profileID || request.AnswerMode != question.AnswerModeToolLoop {
					t.Fatalf("selection was not forwarded: status=%d call=%q request=%#v", response.Code, harness.questions.call, request)
				}
				if request.WorkspaceID != "ws_alpha" || request.Question != "Overview?" || request.IdempotencyKey != harness.idempotencyKey || harness.questions.access.PrincipalID != "usr_alice" {
					t.Fatalf("selection changed authenticated request context: %#v %#v", request, harness.questions.access)
				}
			})
		}
	}
}

func TestModelProfileIDRejectsIncompatibleExplicitModes(t *testing.T) {
	for _, mode := range []string{questionModeExtractive, questionModeGenerative} {
		t.Run(mode, func(t *testing.T) {
			harness := newTestHarness(t)
			response := postModelProfileQuestion(t, harness, `{"question":"Overview?","model_profile_id":"local-qwen","answer_mode":"`+mode+`"}`)
			if response.Code != http.StatusBadRequest || harness.questions.call != "" {
				t.Fatalf("incompatible profile/mode reached authority: status=%d call=%q", response.Code, harness.questions.call)
			}
		})
	}
}

func TestAbsentModelProfileIDPreservesLegacyModeDispatch(t *testing.T) {
	for _, tc := range []struct {
		name         string
		modeField    string
		providerMode string
		want         string
	}{
		{"legacy default", "", "", questionModeExtractive},
		{"capability default", "", question.AnswerModeToolLoop, question.AnswerModeToolLoop},
		{"explicit extractive", `,"answer_mode":"EXTRACTIVE"`, question.AnswerModeToolLoop, questionModeExtractive},
		{"explicit generative", `,"answer_mode":"GENERATIVE"`, "", questionModeGenerative},
		{"explicit tool loop", `,"answer_mode":"TOOL_LOOP"`, "", question.AnswerModeToolLoop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			harness := newTestHarness(t)
			if tc.providerMode != "" {
				harness.handler.questions = &modelProfileQuestionService{fakeQuestionService: harness.questions, defaultMode: tc.providerMode}
			}
			response := postModelProfileQuestion(t, harness, `{"question":"Overview?"`+tc.modeField+`}`)
			if response.Code != http.StatusOK || harness.questions.call != "create" || harness.questions.request.ModelProfileID != "" || harness.questions.request.AnswerMode != tc.want {
				t.Fatalf("legacy dispatch changed: status=%d call=%q request=%#v", response.Code, harness.questions.call, harness.questions.request)
			}
		})
	}
}

func TestQuestionResponsePreservesStoredModelProfileInsteadOfCurrentCatalogue(t *testing.T) {
	stored := question.ModelProfile{ID: "shared-model", Label: "Original provider", Location: "EXTERNAL"}
	current := question.ModelProfileOption{
		ModelProfile: question.ModelProfile{ID: stored.ID, Label: "Renamed provider", Location: "INTERNAL"}, IsDefault: true,
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.questions.run.ModelProfile = &stored
			service := &modelProfileQuestionService{
				fakeQuestionService: harness.questions,
				catalog:             map[string][]question.ModelProfileOption{"ws_alpha": {current}},
			}
			harness.handler.questions = service
			var response *httptest.ResponseRecorder
			if method == http.MethodPost {
				response = postModelProfileQuestion(t, harness, `{"question":"Overview?","model_profile_id":"shared-model"}`)
			} else {
				response = httptest.NewRecorder()
				harness.handler.ServeHTTP(response, harness.request(method, workspacesPath+"/ws_alpha/questions/"+harness.questions.run.ID, ""))
			}
			var result struct {
				ModelProfile *question.ModelProfile `json:"model_profile"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || result.ModelProfile == nil || *result.ModelProfile != stored || len(service.catalogCalls) != 0 {
				t.Fatalf("stored answer identity replaced by catalogue: status=%d profile=%#v catalogue calls=%v", response.Code, result.ModelProfile, service.catalogCalls)
			}
		})
	}
}
