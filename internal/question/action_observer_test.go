package question

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

func TestModelActionLifecyclePrecedesBlockedModelAndStaysContentFree(t *testing.T) {
	const secret = "PRIVATE_SQL_AND_DOCUMENT_FIXTURE"
	events := make(chan ActionEvent, 2)
	ctx := WithActionObserver(context.Background(), func(event ActionEvent) { events <- event })
	modelEntered := make(chan struct{})
	releaseModel := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, _, err := converseWithActionObserver(ctx, func() (modelgateway.ConverseResult, modelgateway.AttemptResult, error) {
			close(modelEntered)
			<-releaseModel
			return modelgateway.ConverseResult{}, modelgateway.AttemptResult{}, errors.New(secret)
		})
		done <- err
	}()
	var started ActionEvent
	select {
	case started = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("model start event was not emitted")
	}
	select {
	case <-modelEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("fake model was not invoked")
	}
	if started != (ActionEvent{Sequence: 1, Type: actionStarted, Label: actionModel}) {
		t.Fatalf("start event = %#v", started)
	}
	select {
	case event := <-events:
		t.Fatalf("finish arrived before model returned: %#v", event)
	default:
	}
	close(releaseModel)
	var modelErr error
	select {
	case modelErr = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fake model did not return")
	}
	if modelErr == nil || modelErr.Error() != secret {
		t.Fatalf("model error changed: %v", modelErr)
	}
	finished := <-events
	if finished != (ActionEvent{Sequence: 2, Type: actionFinished, Label: actionModel, Outcome: actionFailed}) {
		t.Fatalf("finish event = %#v", finished)
	}
	encoded, err := json.Marshal([]ActionEvent{started, finished})
	if err != nil || strings.Contains(string(encoded), secret) {
		t.Fatalf("sensitive model content entered events: %q, %v", encoded, err)
	}
}

func TestActionObserverIsOptional(t *testing.T) {
	called := 0
	converse := func() (modelgateway.ConverseResult, modelgateway.AttemptResult, error) {
		called++
		return modelgateway.ConverseResult{}, modelgateway.AttemptResult{}, nil
	}
	if _, _, err := converseWithActionObserver(context.Background(), converse); err != nil || called != 1 {
		t.Fatalf("unobserved model call changed: called=%d err=%v", called, err)
	}
	if WithActionObserver(context.Background(), nil) == nil {
		t.Fatal("nil observer discarded the request context")
	}
}

func TestToolActionLifecycleIsOrderedAndAllowlisted(t *testing.T) {
	const sensitive = "private_table_customer_payload"
	for name, wantLabel := range map[string]ActionLabel{
		"knowvault_search":        actionSearch,
		"knowvault_read":          actionRead,
		"knowvault_evidence_read": actionRead,
		liveDataToolName:          actionLive,
		analyticScalarToolName:    actionLive,
		trustedMetricToolName:     actionCompare,
		sensitive:                 actionOther,
	} {
		if got := toolActionLabel(name); got != wantLabel {
			t.Fatalf("tool %q has action label %q, want %q", name, got, wantLabel)
		}
	}
	events := make(chan ActionEvent, 2)
	ctx := WithActionObserver(context.Background(), func(event ActionEvent) { events <- event })
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		finish := beginToolAction(ctx, sensitive)
		<-release // Fake tool blocks with sensitive arguments and result.
		_ = map[string]string{"sql": sensitive, "result": sensitive}
		finish(false)
		close(done)
	}()
	var started ActionEvent
	select {
	case started = <-events:
	case <-time.After(3 * time.Second):
		t.Fatal("tool start event was not emitted")
	}
	if started.Sequence != 1 || started.Type != actionStarted || started.Label != actionOther || started.Outcome != "" || started.DurationMS != nil {
		t.Fatalf("start event = %#v", started)
	}
	select {
	case event := <-events:
		t.Fatalf("tool finished before its fake call returned: %#v", event)
	default:
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fake tool did not return")
	}
	finished := <-events
	if finished.Sequence != 2 || finished.Type != actionFinished || finished.Label != actionOther || finished.Outcome != actionFailed || finished.DurationMS == nil || *finished.DurationMS < 0 {
		t.Fatalf("finish event = %#v", finished)
	}
	encoded, err := json.Marshal([]ActionEvent{started, finished})
	if err != nil || strings.Contains(string(encoded), sensitive) {
		t.Fatalf("sensitive tool content entered events: %q, %v", encoded, err)
	}
}
