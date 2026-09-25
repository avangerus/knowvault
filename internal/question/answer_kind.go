package question

// ADR-0099 amendment 1, decision 4: the kind of a question is recognised by
// meaning in a dedicated short model call that returns only the kind from a
// closed list. The answering call does not recognise kinds.
//
// This file owns the closed list, the one recognition prompt and the one model
// call. It contains no list of words or patterns matched against the user's
// question: the question text is passed to the model unchanged and only the
// model's own answer is parsed. A failed call, a refusal, an answer with no
// listed kind, or a question that is in doubt all resolve to full, the default
// the amendment fixes.
//
// What still decides the *answer route* in this card is the pre-existing
// deterministic classifier (tool_loop_overview.go); moving routes onto the
// recognised kind is the next step of the amendment and is deliberately not
// done here. The recognised kind is recorded with the run (ToolLoopRecord) and
// measured by the command under tests/e2e/questions/kindmeasure.

import (
	"context"
	"encoding/json"
	"strings"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

// AnswerKind is the closed list of question kinds (card D-15). The empty value
// is not a kind; every caller resolves it through Resolved, which yields full.
type AnswerKind string

const (
	// AnswerKindFull is the default: reading a specific document or record,
	// querying data, counting, listing or comparing. A question about the
	// content of a named document or record is always full.
	AnswerKindFull AnswerKind = "full"
	// AnswerKindChange asks whether a document or material changed, was
	// updated or is still current.
	AnswerKindChange AnswerKind = "change"
	// AnswerKindHypothetical asks what the workspace's data would show if the
	// business were different.
	AnswerKindHypothetical AnswerKind = "hypothetical"
	// AnswerKindPlainOverview asks, in plain words and in general, what kind
	// of information the workspace holds about a topic -- not the content of a
	// named document or record.
	AnswerKindPlainOverview AnswerKind = "plain_overview"
	// AnswerKindWorkspaceOverview asks what the assistant knows or what is
	// available here in general.
	AnswerKindWorkspaceOverview AnswerKind = "workspace_overview"
	// AnswerKindSourcesOverview asks which sources are connected.
	AnswerKindSourcesOverview AnswerKind = "sources_overview"
	// AnswerKindGreeting is a greeting or thanks with no question.
	AnswerKindGreeting AnswerKind = "greeting"
	// AnswerKindOffTopic is a question unrelated to the workspace's subject.
	AnswerKindOffTopic AnswerKind = "off_topic"
	// AnswerKindVague is a request too unclear to act on.
	AnswerKindVague AnswerKind = "vague"
)

// answerKinds is the closed list in the order the recognition prompt presents
// it. It is a kind list, never a word list: nothing here is matched against a
// question.
var answerKinds = []AnswerKind{
	AnswerKindFull,
	AnswerKindChange,
	AnswerKindHypothetical,
	AnswerKindPlainOverview,
	AnswerKindWorkspaceOverview,
	AnswerKindSourcesOverview,
	AnswerKindGreeting,
	AnswerKindOffTopic,
	AnswerKindVague,
}

// AnswerKinds returns a copy of the closed kind list. It exists so the
// measurement command, its input file format and the tests share exactly one
// list with the recognition step.
func AnswerKinds() []AnswerKind {
	return append([]AnswerKind(nil), answerKinds...)
}

// Valid reports whether the value is one of the closed list's kinds.
func (kind AnswerKind) Valid() bool {
	for _, candidate := range answerKinds {
		if kind == candidate {
			return true
		}
	}
	return false
}

// ParseAnswerKind maps one exact token to a listed kind.
func ParseAnswerKind(value string) (AnswerKind, bool) {
	kind := AnswerKind(strings.ToLower(strings.TrimSpace(value)))
	if kind.Valid() {
		return kind, true
	}
	return "", false
}

// kindRecognitionToolName is the one tool the recognition call offers. The
// model submits the kind through it; a plain-content answer is also accepted
// because the provider may answer without calling the tool.
const kindRecognitionToolName = "submit_question_kind"

// kindRecognitionInstructions is the whole recognition prompt. The kind
// definitions are the card's own definitions, worded independently of any
// particular question. Nothing here is matched against the question in code;
// the model reads this and the question's meaning.
const kindRecognitionInstructions = `You name the kind of one question about a workspace. The question is in the next message. Do not answer the question; only name its kind.

Choose exactly one kind from this closed list:
- full: the request needs reading a specific document or record, or querying, counting, listing or comparing data. It is always full when it names or refers to a document, record, table, field, dataset or subject, or asks for a count, total, list, comparison, or the contents, parts or clauses of something, whatever its grammatical mood, including a short command to bring or list them.
- change: the question asks whether a document or material changed, was updated, or is still current.
- hypothetical: the question asks what the workspace's data would show if the business were different.
- plain_overview: the question asks to describe, in plain, simple or business words, what kind of information the workspace holds, about a subject or about the data as a whole. A request to explain the subject matter of the data belongs here even when it names the database or the workspace in general, and it is not about the content of one named document or record.
- workspace_overview: the question is about you or about this place as a whole: what you know, what you can do, or what is available here in general. A question about what can be looked at or found here belongs here.
- sources_overview: the question asks which sources are connected.
- greeting: a greeting or thanks with no question.
- off_topic: a question unrelated to the workspace's subject.
- vague: a request too unclear to act on: it asks nothing answerable and names nothing to work on, no document, record, table, field, subject, count, list or comparison. It applies only to a bare request to show or output something that names none of these, or that names only the data in general without saying which part. A request that names a document or a subject, or asks for a list or for the contents of something, is full, not vague.

Answer with exactly one kind from the list. If the question could be several kinds, or you are in doubt, answer full.`

// KindRecognition is the outcome of one recognition step. Usage is always the
// cost of the call that ran, Valid is true only when the model named a listed
// kind, and Kind is meaningful only then.
type KindRecognition struct {
	Kind  AnswerKind
	Usage modelgateway.TokenUsage
	Valid bool
}

// Resolved is the kind this recognition outcome contributes: the recognised
// kind when the step succeeded with a listed kind, and full otherwise. This is
// the single place the card's "on doubt or error the kind is full" rule is
// applied.
func (recognition KindRecognition) Resolved() AnswerKind {
	if recognition.Valid && recognition.Kind.Valid() {
		return recognition.Kind
	}
	return AnswerKindFull
}

// KindRecogniser recognises the kind of one question by meaning. A model-backed
// implementation is the production one (NewModelKindRecogniser); composition or
// a test may install another through Service.EnableAnswerKindRecogniser.
type KindRecogniser interface {
	Recognise(ctx context.Context, question string) KindRecognition
}

// modelKindRecogniser is the production KindRecogniser: one short Converse
// call on the run's own model adapter, with only the recognition tool mounted.
type modelKindRecogniser struct {
	adapter     *modelgateway.LabAdapter
	workspaceID string
}

// NewModelKindRecogniser builds the production recognition step over adapter.
// A nil adapter or an invalid workspace identity yields a nil interface, so a
// caller that checks for nil keeps today's behaviour instead of calling a
// half-built recogniser.
func NewModelKindRecogniser(adapter *modelgateway.LabAdapter, workspaceID string) KindRecogniser {
	if adapter == nil || !validOpaque(workspaceID) {
		return nil
	}
	return &modelKindRecogniser{adapter: adapter, workspaceID: workspaceID}
}

// Recognise makes exactly one recognition attempt. It never returns an error:
// every failure is reported as Valid=false, which the caller resolves to full.
func (recogniser *modelKindRecogniser) Recognise(ctx context.Context, question string) KindRecognition {
	if recogniser == nil || recogniser.adapter == nil || ctx == nil || ctx.Err() != nil || strings.TrimSpace(question) == "" {
		return KindRecognition{}
	}
	result, _, err := recogniser.adapter.Converse(ctx, recogniser.workspaceID,
		[]modelgateway.Message{
			{Role: "system", Content: kindRecognitionInstructions},
			{Role: "user", Content: question},
		},
		[]modelgateway.ToolDefinition{kindRecognitionTool()})
	outcome := KindRecognition{Usage: result.Usage}
	if err != nil {
		return outcome
	}
	kind, ok := parseRecognisedAnswerKind(result.Message.Content, result.Message.ToolCalls)
	if !ok {
		return outcome
	}
	outcome.Kind, outcome.Valid = kind, true
	return outcome
}

// kindRecognitionTool is the one tool the recognition call offers. Its enum is
// generated from answerKinds, so the offered choices can never drift from the
// list the server accepts.
func kindRecognitionTool() modelgateway.ToolDefinition {
	enum := make([]string, 0, len(answerKinds))
	for _, kind := range answerKinds {
		enum = append(enum, string(kind))
	}
	parameters, err := json.Marshal(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"kind": map[string]any{
				"type":        "string",
				"enum":        enum,
				"description": "the one kind that matches the question's meaning",
			},
		},
		"required":             []string{"kind"},
		"additionalProperties": false,
	})
	if err != nil {
		// The map is closed and static, so marshaling cannot fail; a defensive
		// empty object keeps the call well-formed if it ever did.
		parameters = []byte(`{"type":"object"}`)
	}
	return modelgateway.ToolDefinition{Type: "function", Function: modelgateway.ToolFunction{
		Name:        kindRecognitionToolName,
		Description: "Submit the one kind that matches the question's meaning.",
		Parameters:  parameters,
	}}
}

// parseRecognisedAnswerKind reads only the model's own answer: the argument of
// the recognition tool when it was called, otherwise the answer content. It
// accepts a JSON object with a kind member, a bare kind token (optionally
// quoted or followed by punctuation), or a short answer that names exactly one
// listed kind. Anything else is not a recognition.
func parseRecognisedAnswerKind(content string, calls []modelgateway.ToolCall) (AnswerKind, bool) {
	for _, call := range calls {
		if call.Function.Name != kindRecognitionToolName {
			continue
		}
		if kind, ok := parseAnswerKindJSON(call.Function.Arguments); ok {
			return kind, true
		}
	}
	if kind, ok := parseAnswerKindJSON(content); ok {
		return kind, true
	}
	return kindNamedOnce(content)
}

// parseAnswerKindJSON accepts the tool argument shape {"kind":"..."} and a bare
// token, tolerating surrounding quotes, backticks and sentence punctuation.
func parseAnswerKindJSON(raw string) (AnswerKind, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	var envelope struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(trimmed), &envelope) == nil {
		if kind, ok := ParseAnswerKind(envelope.Kind); ok {
			return kind, true
		}
	}
	return ParseAnswerKind(trimKindDecoration(trimmed))
}

func trimKindDecoration(value string) string {
	return strings.Trim(value, " \t\r\n\"'`.,;:!?()[]{}«»")
}

// kindNamedOnce accepts a short model answer that names exactly one listed
// kind, for example "full." or "The kind is greeting." Two different kinds in
// one answer are ambiguous and yield no recognition.
func kindNamedOnce(content string) (AnswerKind, bool) {
	fields := strings.FieldsFunc(strings.ToLower(content), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_'
	})
	seen := AnswerKind("")
	for _, field := range fields {
		kind, ok := ParseAnswerKind(field)
		if !ok {
			continue
		}
		if seen != "" && seen != kind {
			return "", false
		}
		seen = kind
	}
	if seen == "" {
		return "", false
	}
	return seen, true
}

// EnableAnswerKindRecognition turns ADR-0099 amendment 1's separate
// recognition step on. It is composition-time only: when it is not called, no
// recognition call is made and no kind is recorded, which keeps every existing
// caller's behaviour and cost unchanged. Composition calls it once a model
// adapter is mounted.
func (service *Service) EnableAnswerKindRecognition() {
	if service != nil {
		service.answerKindRecognition = true
	}
}

// EnableAnswerKindRecogniser installs a caller-supplied recognition step and
// turns recognition on. Tests use it to prove the recorded kind comes from the
// recognition step; a nil recogniser turns the step off again.
func (service *Service) EnableAnswerKindRecogniser(recogniser KindRecogniser) {
	if service == nil {
		return
	}
	service.kindRecogniser = recogniser
	service.answerKindRecognition = recogniser != nil
}

// recogniseAnswerKind runs one recognition step for a run. It returns full
// whenever recognition is off, no recogniser can be built, or the step fails or
// names an unlisted kind. The token usage is returned even for a failed step so
// the cost of the attempt is recorded rather than hidden.
func (service *Service) recogniseAnswerKind(ctx context.Context, adapter *modelgateway.LabAdapter,
	workspaceID, question string) (AnswerKind, modelgateway.TokenUsage) {
	if service == nil || !service.answerKindRecognition {
		return AnswerKindFull, modelgateway.TokenUsage{}
	}
	recogniser := service.kindRecogniser
	if recogniser == nil {
		recogniser = NewModelKindRecogniser(adapter, workspaceID)
	}
	if recogniser == nil {
		return AnswerKindFull, modelgateway.TokenUsage{}
	}
	outcome := recogniser.Recognise(ctx, question)
	return outcome.Resolved(), outcome.Usage
}
