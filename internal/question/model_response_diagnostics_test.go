package question

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestModelGatewayReasonCodesAreClosedSortedAndContentFree(t *testing.T) {
	attempt := modelgateway.AttemptResult{ResponseStage: modelgateway.ResponseStageJSON, ResponseDiagnostic: modelgateway.ResponseArgumentsJSONInvalid}
	want := []string{"MODEL_RESPONSE_ARGUMENTS_JSON_INVALID", "MODEL_RESPONSE_STAGE_JSON", "MODEL_RUNTIME_EXTERNAL_WORKSPACE_SCOPED"}
	if got := modelGatewayReasonCodes(attempt, modelgateway.RuntimeScopeExternalWorkspaceScoped); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit reason codes=%v, want %v", got, want)
	}
	for _, diagnostic := range []modelgateway.ResponseDiagnostic{"PRIVATE_PROVIDER_BODY", "MODEL_RESPONSE_JSON_INVALID\nPRIVATE_PROVIDER_BODY"} {
		attempt.ResponseDiagnostic = diagnostic
		got := modelGatewayReasonCodes(attempt, modelgateway.RuntimeScopeLocalLab)
		encoded, err := json.Marshal(map[string]any{"reason_codes": got})
		if err != nil || strings.Contains(string(encoded), "PRIVATE") || len(got) != 2 {
			t.Fatal("untrusted diagnostic entered audit metadata")
		}
	}
	legacy := modelGatewayReasonCodes(modelgateway.AttemptResult{ResponseStage: modelgateway.ResponseStageJSON}, modelgateway.RuntimeScopeLocalLab)
	if !reflect.DeepEqual(legacy, []string{"MODEL_RESPONSE_STAGE_JSON", "MODEL_RUNTIME_LOCAL_LAB"}) {
		t.Fatalf("legacy reason codes changed: %v", legacy)
	}
}

func TestToolLoopFailureKeepsExistingTerminalVocabularyAndDeadlinePriority(t *testing.T) {
	for _, example := range []struct {
		diagnostic modelgateway.ResponseDiagnostic
		want       string
	}{
		{modelgateway.ResponseOutputLimit, "OUTPUT_LIMIT"},
		{modelgateway.ResponseArgumentsJSONInvalid, "MODEL_UNAVAILABLE"},
		{modelgateway.ResponseProviderResource, "MODEL_UNAVAILABLE"},
		{modelgateway.ResponseProviderFiltered, "MODEL_UNAVAILABLE"},
		{modelgateway.ResponseProviderAborted, "MODEL_UNAVAILABLE"},
		{"", "MODEL_UNAVAILABLE"},
		{"PRIVATE_PROVIDER_BODY", "MODEL_UNAVAILABLE"},
	} {
		attempt := modelgateway.AttemptResult{ResponseDiagnostic: example.diagnostic}
		if got := toolLoopModelFailureStopReason(context.Background(), attempt); got != example.want {
			t.Fatalf("diagnostic %q gives %q, want %q", example.diagnostic, got, example.want)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := toolLoopModelFailureStopReason(ctx, attempt); got != "TIME_LIMIT" {
			t.Fatalf("cancelled run changed to %q", got)
		}
	}
}
