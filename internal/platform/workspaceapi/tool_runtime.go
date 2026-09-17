package workspaceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"knowvault.local/verified-workspace/internal/platform/database"
	"net/http"
	"strings"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

var _ workspacetools.Runtime = (*Handler)(nil)

// The chat context has a bounded per-tool result budget. The ordinary MCP
// search/grep default (20 hits) can exceed it before the model sees any hit.
// Keep the model's omitted-limit page small; explicit paging remains available.
const chatRetrievalDefaultLimit = 3

func chatUsesSmallRetrievalPage(kind workspacetools.Kind) bool {
	return kind == workspacetools.KindSearch || kind == workspacetools.KindGrep
}

func (handler *Handler) defaultQuestionMode(workspaceID string) string {
	if provider, ok := handler.questions.(interface{ DefaultAnswerMode(string) string }); ok {
		return provider.DefaultAnswerMode(workspaceID)
	}
	return questionModeExtractive
}

func (handler *Handler) validateToolScope(ctx context.Context, scope workspacetools.Scope) error {
	if handler == nil || handler.service == nil || ctx == nil || scope.Access.Validate() != nil || scope.WorkspaceID == "" || scope.Revision < 1 {
		return workspacetools.ErrUnavailable
	}
	snapshot, err := handler.service.Get(ctx, scope.Access, scope.WorkspaceID)
	if err != nil {
		return workspacetools.ErrUnavailable
	}
	if snapshot.Revision != scope.Revision {
		return workspacetools.ErrScopeChanged
	}
	return nil
}

func (handler *Handler) Catalog(ctx context.Context, scope workspacetools.Scope) ([]workspacetools.Definition, error) {
	if err := handler.validateToolScope(ctx, scope); err != nil {
		return nil, err
	}
	definitions := make([]workspacetools.Definition, 0)
	for _, entry := range handler.mcpTools(scope.Access) {
		projection, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, _ := projection["name"].(string)
		tool, registered := workspacetools.KnowledgeTools().Lookup(name)
		if !registered || name != tool.Name {
			continue
		}
		// The run has already selected its workspace. Do not ask the model to
		// invent authority parameters; Invoke still rejects a foreign override.
		input := projection["inputSchema"].(map[string]any)
		properties := input["properties"].(map[string]any)
		delete(properties, "workspace_id")
		if chatUsesSmallRetrievalPage(tool.Kind) {
			limit := properties["limit"].(map[string]any)
			limit["default"] = chatRetrievalDefaultLimit
			limit["description"] = "Number of matches per page; defaults to 3 in chat. Use next_offset to continue. A page is not an exhaustive answer or a limit on the evidence needed."
		} else if tool.Kind == workspacetools.KindListObjects {
			limit := properties["limit"].(map[string]any)
			limit["description"] = "For an overview, request one small explicit page of 3 objects, then read selected documents. Use next_offset only if the page does not provide suitable choices; has_more alone does not require a full inventory scan. The unchanged omitted-limit default is 100."
		}
		required := make([]string, 0)
		for _, key := range input["required"].([]string) {
			if key != "workspace_id" {
				required = append(required, key)
			}
		}
		input["required"] = required
		schema, err := json.Marshal(input)
		if err != nil {
			return nil, workspacetools.ErrUnavailable
		}
		description, _ := projection["description"].(string)
		switch tool.Kind {
		case workspacetools.KindSearch, workspacetools.KindGrep:
			description += " Matches select evidence to read; the first page does not establish completeness. For broad questions, examine relevant sections and continuations, and disclose the scope actually checked."
		case workspacetools.KindRead:
			description += " Read the relevant content before forming claims. Continue when needed for the requested scope; later automatic citation validation cannot assess omitted context."
		case workspacetools.KindListObjects:
			description += " This is document metadata for navigation, not evidence of its subject matter. For an overview, move from the first small inventory page to reading different relevant documents and state the scope actually checked. An explicitly requested exhaustive list or total still requires checking the full relevant scope."
		case workspacetools.KindSources:
			description += " This reports connection and synchronization state, not the knowledge contained in documents. Use these technical fields in an answer only when the user asks about source or connection state."
		}
		definitions = append(definitions, workspacetools.Definition{Name: name, Description: description, Schema: schema})
	}
	return definitions, nil
}

func (handler *Handler) Invoke(ctx context.Context, scope workspacetools.Scope, name string, arguments json.RawMessage) (workspacetools.Result, error) {
	tool, registered := workspacetools.KnowledgeTools().Lookup(name)
	if !registered || (scope.Access.EffectiveActorKind() == database.ActorKindService && !tool.Service) {
		return workspacetools.Result{}, workspacetools.ErrArguments
	}
	var args map[string]json.RawMessage
	if len(arguments) > 16*1024 || jsonv2.Unmarshal(arguments, &args, jsontext.AllowDuplicateNames(false)) != nil || args == nil {
		return workspacetools.Result{}, workspacetools.ErrArguments
	}
	if supplied, present := args["workspace_id"]; present {
		var workspaceID string
		if json.Unmarshal(supplied, &workspaceID) != nil || workspaceID != scope.WorkspaceID {
			return workspacetools.Result{}, workspacetools.ErrArguments
		}
	}
	args["workspace_id"], _ = json.Marshal(scope.WorkspaceID)
	if chatUsesSmallRetrievalPage(tool.Kind) {
		if _, present := args["limit"]; !present {
			args["limit"], _ = json.Marshal(chatRetrievalDefaultLimit)
		}
	}
	bound, err := json.Marshal(args)
	if err != nil {
		return workspacetools.Result{}, workspacetools.ErrArguments
	}
	if err := handler.validateToolScope(ctx, scope); err != nil {
		return workspacetools.Result{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/mcp", nil)
	if err != nil {
		return workspacetools.Result{}, workspacetools.ErrUnavailable
	}
	writer := &toolCapture{header: make(http.Header)}
	handler.mcpKnowledgeToolCall(writer, request, scope.Access, mcpRequest{JSONRPC: "2.0", ID: jsontext.Value(`"question-tool"`)},
		mcpToolCallParams{Name: name, Arguments: jsontext.Value(bound)}, tool)
	if err := handler.validateToolScope(ctx, scope); err != nil {
		return workspacetools.Result{}, err
	}
	var response struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			Structured json.RawMessage `json:"structuredContent"`
			IsError    bool            `json:"isError"`
		} `json:"result"`
		Error json.RawMessage `json:"error"`
	}
	if writer.overflow || json.Unmarshal(writer.body.Bytes(), &response) != nil {
		return workspacetools.Result{}, workspacetools.ErrUnavailable
	}
	if len(response.Error) > 0 && string(response.Error) != "null" {
		return workspacetools.Result{IsError: true, Text: string(response.Error)}, nil
	}
	parts := make([]string, 0, len(response.Result.Content))
	for _, part := range response.Result.Content {
		if part.Type == "text" {
			parts = append(parts, part.Text)
		}
	}
	return workspacetools.Result{Text: strings.Join(parts, "\n"), Structured: response.Result.Structured, IsError: response.Result.IsError}, nil
}

type toolCapture struct {
	header   http.Header
	body     bytes.Buffer
	overflow bool
}

func (writer *toolCapture) Header() http.Header { return writer.header }
func (writer *toolCapture) WriteHeader(int)     {}
func (writer *toolCapture) Write(value []byte) (int, error) {
	if writer.body.Len()+len(value) > 8*1024*1024 {
		writer.overflow = true
		return 0, io.ErrShortBuffer
	}
	return writer.body.Write(value)
}
