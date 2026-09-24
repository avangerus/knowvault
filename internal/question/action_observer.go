package question

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// ActionEvent carries only a closed, reviewed vocabulary: the category label
// controls disclosure as before, and Request/Detail add a short, bounded,
// allowlisted-field projection of the request and outcome (see
// action_detail.go). Neither is ever a raw tool argument or result payload;
// an unrecognized tool name yields empty Request/Detail so a future or
// external catalog tool can never leak its own arguments or result through
// this transport.
type ActionEvent struct {
	Sequence   uint64          `json:"sequence"`
	Type       ActionEventType `json:"type"`
	Label      ActionLabel     `json:"label"`
	Request    string          `json:"request,omitempty"`
	Outcome    ActionOutcome   `json:"outcome,omitempty"`
	DurationMS *int64          `json:"duration_ms,omitempty"`
	Detail     string          `json:"detail,omitempty"`
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

// ReportAction publishes a content-free action category to the optional
// request observer. Transport consumers must still validate the closed event
// vocabulary before disclosing it.
func ReportAction(ctx context.Context, event ActionEvent) {
	observer, _ := ctx.Value(actionObserverKey{}).(*actionObserver)
	if observer == nil {
		return
	}
	event.Sequence = observer.next.Add(1)
	observer.emit(event)
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
// args and, later, the call's result are never disclosed directly: Request
// and Detail are short, bounded projections computed by action_detail.go
// from a fixed, reviewed set of fields for a fixed set of known tool names.
func beginToolAction(ctx context.Context, name string, args json.RawMessage) func(succeeded bool, result workspacetools.Result) {
	observer, _ := ctx.Value(actionObserverKey{}).(*actionObserver)
	if observer == nil {
		return func(bool, workspacetools.Result) {}
	}
	label := toolActionLabel(name)
	request := actionRequestText(name, args)
	started := time.Now()
	observer.emit(ActionEvent{Sequence: observer.next.Add(1), Type: actionStarted, Label: label, Request: request})
	return func(succeeded bool, result workspacetools.Result) {
		outcome := actionFailed
		if succeeded {
			outcome = actionSuccess
		}
		duration := time.Since(started).Milliseconds()
		detail := actionResultText(name, succeeded, result)
		observer.emit(ActionEvent{Sequence: observer.next.Add(1), Type: actionFinished, Label: label, Outcome: outcome, DurationMS: &duration, Detail: detail})
	}
}
