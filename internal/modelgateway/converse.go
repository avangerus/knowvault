package modelgateway

// Converse is the tool-calling sibling of Generate. Its mount, transport and
// workspace allow-list are the same; the evidence-bound ClaimPlan API is unchanged.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strings"
)

type ToolLoopProfile struct {
	ID                  string              `json:"id"`
	ThinkingMode        ThinkingMode        `json:"thinking_mode,omitempty"`
	ModelArtifactSHA256 string              `json:"model_artifact_sha256,omitempty"`
	MaxTurns            int                 `json:"max_turns"`
	MaxToolCalls        int                 `json:"max_tool_calls"`
	MaxInputBytes       int                 `json:"max_input_bytes"`
	MaxToolResultBytes  int                 `json:"max_tool_result_bytes"`
	MaxOutputTokens     int                 `json:"max_output_tokens"`
	TimeoutSeconds      int                 `json:"timeout_seconds"`
	Sampling            *SamplingParameters `json:"sampling,omitempty"`
}

// Explicit sampling is part of the recorded profile. Nil preserves the
// historical greedy request and the provider's other defaults.
type SamplingParameters struct {
	Temperature     float64 `json:"temperature"`
	TopP            float64 `json:"top_p"`
	TopK            int     `json:"top_k"`
	MinP            float64 `json:"min_p"`
	PresencePenalty float64 `json:"presence_penalty"`
	RepeatPenalty   float64 `json:"repeat_penalty"`
	Seed            int64   `json:"seed"`
}

func (sampling SamplingParameters) valid() bool {
	for _, value := range []float64{sampling.Temperature, sampling.TopP, sampling.MinP, sampling.PresencePenalty, sampling.RepeatPenalty} {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	return sampling.Temperature >= 0 && sampling.Temperature <= 2 &&
		sampling.TopP > 0 && sampling.TopP <= 1 && sampling.TopK >= 1 && sampling.TopK <= 200 &&
		sampling.MinP >= 0 && sampling.MinP <= 1 && sampling.PresencePenalty >= 0 && sampling.PresencePenalty <= 2 &&
		sampling.RepeatPenalty > 0 && sampling.RepeatPenalty <= 2 && sampling.Seed >= 0 && sampling.Seed <= math.MaxInt32
}

func (profile ToolLoopProfile) clone() ToolLoopProfile {
	if profile.Sampling != nil {
		copied := *profile.Sampling
		profile.Sampling = &copied
	}
	return profile
}

func (profile ToolLoopProfile) Validate() error {
	if profile.ThinkingMode != "" && !profile.ThinkingMode.valid() {
		return &Error{code: CodeProfile}
	}
	if profile.Sampling != nil && !profile.Sampling.valid() {
		return &Error{code: CodeProfile}
	}
	if !validOpaque(profile.ID) || profile.MaxTurns < 2 || profile.MaxTurns > 20 ||
		profile.MaxToolCalls < 2 || profile.MaxToolCalls > 40 ||
		profile.MaxInputBytes < 8192 || profile.MaxInputBytes > 512*1024 ||
		profile.MaxToolResultBytes < 1024 || profile.MaxToolResultBytes > profile.MaxInputBytes/2 ||
		profile.MaxOutputTokens < 256 || profile.MaxOutputTokens > 16384 ||
		profile.TimeoutSeconds < 10 || profile.TimeoutSeconds > 300 {
		return &Error{code: CodeProfile}
	}
	if profile.ModelArtifactSHA256 != "" {
		digest, err := hex.DecodeString(profile.ModelArtifactSHA256)
		if err != nil || len(digest) != 32 || strings.ToLower(profile.ModelArtifactSHA256) != profile.ModelArtifactSHA256 {
			return &Error{code: CodeProfile}
		}
	}
	return nil
}

type ToolDefinition struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Message deliberately has no reasoning field. Provider reasoning_content and
// reasoning_details are ignored at decoding and cannot enter a stored message.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type TokenUsage struct {
	Input  int `json:"prompt_tokens"`
	Output int `json:"completion_tokens"`
	Total  int `json:"total_tokens"`
}

type ConverseResult struct {
	Message      Message    `json:"message"`
	FinishReason string     `json:"finish_reason"`
	Usage        TokenUsage `json:"usage"`
}

func (adapter *LabAdapter) ToolLoopProfile() (ToolLoopProfile, bool) {
	if adapter == nil || adapter.config.ToolLoop == nil {
		return ToolLoopProfile{}, false
	}
	profile := adapter.config.ToolLoop.clone()
	profile.ThinkingMode = adapter.config.ThinkingMode
	if profile.ThinkingMode == "" {
		profile.ThinkingMode = ThinkingModeDisabled
	}
	return profile, true
}

// Converse makes exactly one attempt. The caller records its outcome and owns
// any repair turn; transport failures never become fabricated model answers.
func (adapter *LabAdapter) Converse(ctx context.Context, workspaceID string, messages []Message, tools []ToolDefinition) (ConverseResult, AttemptResult, error) {
	attempt := AttemptResult{FailureCode: CodeInvalid}
	profile, configured := adapter.ToolLoopProfile()
	if !configured || ctx == nil || !adapter.AllowsWorkspace(workspaceID) || len(messages) < 2 || len(messages) > 128 || len(tools) == 0 || len(tools) > 32 {
		return ConverseResult{}, attempt, &Error{code: CodeInvalid}
	}
	attempt.ModelID = adapter.config.ModelID
	for _, message := range messages {
		if message.Role != "system" && message.Role != "user" && message.Role != "assistant" && message.Role != "tool" {
			return ConverseResult{}, attempt, &Error{code: CodeInvalid}
		}
	}
	for _, tool := range tools {
		if tool.Type != "function" || !validOpaque(tool.Function.Name) || !json.Valid(tool.Function.Parameters) {
			return ConverseResult{}, attempt, &Error{code: CodeInvalid}
		}
	}
	payload := struct {
		Model           string           `json:"model"`
		Messages        []Message        `json:"messages"`
		Tools           []ToolDefinition `json:"tools"`
		ToolChoice      string           `json:"tool_choice"`
		Temperature     float64          `json:"temperature"`
		TopP            *float64         `json:"top_p,omitempty"`
		TopK            *int             `json:"top_k,omitempty"`
		MinP            *float64         `json:"min_p,omitempty"`
		PresencePenalty *float64         `json:"presence_penalty,omitempty"`
		RepeatPenalty   *float64         `json:"repeat_penalty,omitempty"`
		Seed            *int64           `json:"seed,omitempty"`
		MaxTokens       int              `json:"max_tokens"`
		Stream          bool             `json:"stream"`
		Thinking        map[string]any   `json:"thinking"`
		TemplateArgs    map[string]any   `json:"chat_template_kwargs"`
	}{Model: adapter.config.ModelID, Messages: messages, Tools: tools, ToolChoice: "auto", MaxTokens: profile.MaxOutputTokens,
		Thinking: map[string]any{"type": profile.ThinkingMode}, TemplateArgs: map[string]any{"enable_thinking": profile.ThinkingMode == ThinkingModeEnabled}}
	if sampling := profile.Sampling; sampling != nil {
		payload.Temperature = sampling.Temperature
		payload.TopP, payload.TopK, payload.MinP = &sampling.TopP, &sampling.TopK, &sampling.MinP
		payload.PresencePenalty, payload.RepeatPenalty, payload.Seed = &sampling.PresencePenalty, &sampling.RepeatPenalty, &sampling.Seed
	}
	body, err := json.Marshal(payload)
	if err != nil || len(body) > profile.MaxInputBytes {
		return ConverseResult{}, attempt, &Error{code: CodeInvalid}
	}
	attempt.RequestBytes = len(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(adapter.config.Endpoint, "/")+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ConverseResult{}, attempt, &Error{code: CodeInvalid}
	}
	request.Header.Set("Content-Type", "application/json")
	if adapter.config.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+adapter.config.APIKey)
	}
	attempt.ResponseStage = ResponseStageWire
	response, err := adapter.http.Do(request)
	if err != nil {
		attempt.FailureCode = CodeUnavailable
		return ConverseResult{}, attempt, &Error{code: CodeUnavailable}
	}
	defer response.Body.Close()
	attempt.StatusCode = response.StatusCode
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(labMaxResponseBytes)+1))
	attempt.ResponseBytes = len(raw)
	if err != nil || len(raw) > labMaxResponseBytes || response.StatusCode != http.StatusOK {
		attempt.FailureCode = CodeUnavailable
		return ConverseResult{}, attempt, &Error{code: CodeUnavailable}
	}
	attempt.ResponseStage = ResponseStageJSON
	reject := func(diagnostic ResponseDiagnostic) (ConverseResult, AttemptResult, error) {
		attempt.ResponseDiagnostic = diagnostic
		return ConverseResult{}, attempt, &Error{code: CodeInvalid}
	}
	var decoded struct {
		Model   string           `json:"model"`
		Choices []ConverseResult `json:"choices"`
		Usage   TokenUsage       `json:"usage"`
	}
	if json.Unmarshal(raw, &decoded) != nil {
		return reject(ResponseJSONInvalid)
	}
	if decoded.Model != adapter.config.ModelID {
		return reject(ResponseModelMismatch)
	}
	if len(decoded.Choices) != 1 {
		return reject(ResponseChoiceCountInvalid)
	}
	result := decoded.Choices[0]
	result.Usage = decoded.Usage
	if result.Message.Role != "assistant" {
		return reject(ResponseRoleInvalid)
	}
	switch result.FinishReason {
	case "stop", "tool_calls", "length":
	case "insufficient_system_resource":
		return reject(ResponseProviderResource)
	case "aborted":
		return reject(ResponseProviderAborted)
	case "content_filter":
		return reject(ResponseProviderFiltered)
	default:
		return reject(ResponseFinishInvalid)
	}
	if len(result.Message.ToolCalls) > 16 {
		return reject(ResponseToolCountExceeded)
	}
	seen := map[string]bool{}
	for _, call := range result.Message.ToolCalls {
		if !validOpaque(call.ID) {
			return reject(ResponseToolIDInvalid)
		}
		if seen[call.ID] {
			return reject(ResponseToolIDDuplicate)
		}
		if call.Type != "function" {
			return reject(ResponseToolTypeInvalid)
		}
		if !validOpaque(call.Function.Name) {
			return reject(ResponseToolNameInvalid)
		}
		if len(call.Function.Arguments) > 16384 {
			return reject(ResponseArgumentsTooLarge)
		}
		seen[call.ID] = true
	}
	// A length stop is never an executable tool call or a completed answer.
	// Keep identity, shape and byte limits above; do not parse or retain partial
	// arguments merely to discover that the provider exhausted its output.
	if result.FinishReason == "length" {
		return reject(ResponseOutputLimit)
	}
	for _, call := range result.Message.ToolCalls {
		if !json.Valid([]byte(call.Function.Arguments)) {
			return reject(ResponseArgumentsJSONInvalid)
		}
	}
	result.Message.Content = discardHiddenReasoning(result.Message.Content)
	attempt.Succeeded, attempt.FailureCode = true, ""
	return result, attempt, nil
}

func discardHiddenReasoning(content string) string {
	for {
		start := strings.Index(content, "<think>")
		end := strings.Index(content, "</think>")
		if start < 0 {
			if end >= 0 {
				content = content[end+len("</think>"):]
				continue
			}
			return strings.TrimSpace(content)
		}
		if end < start {
			return strings.TrimSpace(content[:start])
		}
		content = content[:start] + content[end+len("</think>"):]
	}
}
