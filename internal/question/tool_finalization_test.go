package question

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

type finalizationRuntime struct {
	catalog func(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error)
}

func (runtime finalizationRuntime) Catalog(ctx context.Context, scope workspacetools.Scope) ([]workspacetools.Definition, error) {
	return runtime.catalog(ctx, scope)
}

func (finalizationRuntime) Invoke(context.Context, workspacetools.Scope, string, json.RawMessage) (workspacetools.Result, error) {
	panic("finalization admission must not read data")
}

func TestFinalizationChecksLiveScopeWithOriginalContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scope := workspacetools.Scope{Access: database.AccessContext{OrganizationID: "org", PrincipalID: "person", RequestID: "request"}, WorkspaceID: "workspace", Revision: 17}
	called := 0
	runtime := finalizationRuntime{catalog: func(received context.Context, actual workspacetools.Scope) ([]workspacetools.Definition, error) {
		called++
		if received != ctx || !reflect.DeepEqual(actual, scope) {
			t.Fatal("finalization replaced the run context or captured authority")
		}
		return []workspacetools.Definition{{Name: "knowvault_read"}}, nil
	}}
	definitions, err := toolFinalizationDefinitions(ctx, runtime, scope)
	if err != nil || called != 1 || len(definitions) != 1 || definitions[0].Function.Name != submitAnswerToolName {
		t.Fatalf("finalization did not admit a submit-only provider request: %v %+v", err, definitions)
	}
}

func TestFinalizationFailsClosedBeforeProvider(t *testing.T) {
	for _, example := range []struct {
		name    string
		before  bool
		during  bool
		failure error
		want    error
	}{
		{"cancelled-before-admission", true, false, nil, context.Canceled},
		{"cancelled-during-admission", false, true, nil, context.Canceled},
		{"scope-revoked", false, false, workspacetools.ErrScopeChanged, workspacetools.ErrScopeChanged},
		{"authority-unavailable", false, false, workspacetools.ErrUnavailable, workspacetools.ErrUnavailable},
	} {
		t.Run(example.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if example.before {
				cancel()
			}
			calls := 0
			runtime := finalizationRuntime{catalog: func(context.Context, workspacetools.Scope) ([]workspacetools.Definition, error) {
				calls++
				if example.during {
					cancel()
				}
				return []workspacetools.Definition{{Name: "knowvault_read"}}, example.failure
			}}
			definitions, err := toolFinalizationDefinitions(ctx, runtime, workspacetools.Scope{})
			if !errors.Is(err, example.want) || len(definitions) != 0 || (example.before && calls != 0) || (!example.before && calls != 1) {
				t.Fatalf("unsafe finalization admission: error=%v definitions=%v calls=%d", err, definitions, calls)
			}
		})
	}
}
