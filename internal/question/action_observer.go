package question

import (
	"context"
	"sync/atomic"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

// ActionEvent is deliberately content-free. Its vocabulary is controlled by
// the question service, not by a model response or a tool result.
type ActionEvent struct {
	Sequence   uint64          `json:"sequence"`
	Type       ActionEventType `json:"type"`
	Label      ActionLabel     `json:"label"`
	Outcome    ActionOutcome   `json:"outcome,omitempty"`
	DurationMS *int64          `json:"duration_ms,omitempty"`
}

type ActionEventType string
type ActionLabel string
type ActionOutcome string

const (
	actionStarted  ActionEventType = "action_started"
	actionFinished ActionEventType = "action_finished"
	actionModel    ActionLabel     = "model"
	actionSearch   ActionLabel     = "document_search"
	actionRead     ActionLabel     = "document_read"
	actionLive     ActionLabel     = "live_data"
	actionCompare  ActionLabel     = "trusted_comparison"
	actionOther    ActionLabel     = "other_tool"
	actionSuccess  ActionOutcome   = "succeeded"
	actionFailed   ActionOutcome   = "failed"
)

type actionObserverKey struct{}

type actionObserver struct {
	next atomic.Uint64
	emit func(ActionEvent)
}

// WithActionObserver installs an optional request-scoped lifecycle sink.
// Callers must keep the sink bounded; it runs synchronously at action boundaries.
func WithActionObserver(ctx context.Context, emit func(ActionEvent)) context.Context {
	if emit == nil {
		return ctx
	}
	return context.WithValue(ctx, actionObserverKey{}, &actionObserver{emit: emit})
}

func emitAction(ctx context.Context, kind ActionEventType, outcome ActionOutcome) {
	observer, _ := ctx.Value(actionObserverKey{}).(*actionObserver)
	if observer == nil {
		return
	}
	observer.emit(ActionEvent{Sequence: observer.next.Add(1), Type: kind, Label: actionModel, Outcome: outcome})
}

func converseWithActionObserver(ctx context.Context, converse func() (modelgateway.ConverseResult, modelgateway.AttemptResult, error)) (modelgateway.ConverseResult, modelgateway.AttemptResult, error) {
	emitAction(ctx, actionStarted, "")
	response, attempt, err := converse()
	outcome := actionSuccess
	if err != nil {
		outcome = actionFailed
	}
	emitAction(ctx, actionFinished, outcome)
	return response, attempt, err
}

func toolActionLabel(name string) ActionLabel {
	switch name {
	case "knowvault_search":
		return actionSearch
	case "knowvault_read", "knowvault_evidence_read":
		return actionRead
	case liveDataToolName, analyticScalarToolName:
		return actionLive
	case trustedMetricToolName:
		return actionCompare
	default:
		return actionOther
	}
}

// beginToolAction emits only an allowlisted category, never a catalog name.
func beginToolAction(ctx context.Context, name string) func(bool) {
	observer, _ := ctx.Value(actionObserverKey{}).(*actionObserver)
	if observer == nil {
		return func(bool) {}
	}
	label := toolActionLabel(name)
	started := time.Now()
	observer.emit(ActionEvent{Sequence: observer.next.Add(1), Type: actionStarted, Label: label})
	return func(succeeded bool) {
		outcome := actionFailed
		if succeeded {
			outcome = actionSuccess
		}
		duration := time.Since(started).Milliseconds()
		observer.emit(ActionEvent{Sequence: observer.next.Add(1), Type: actionFinished, Label: label, Outcome: outcome, DurationMS: &duration})
	}
}
