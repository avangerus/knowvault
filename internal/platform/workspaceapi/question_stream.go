package workspaceapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"knowvault.local/verified-workspace/internal/question"
)

const questionStreamContentType = "application/x-ndjson"

// questionEventStream writes only transport-owned lifecycle fields until its
// terminal frame. That frame carries the completed Create response, after the
// question authority's disclosure gate has passed.
type questionEventStream struct {
	mu       sync.Mutex
	writer   http.ResponseWriter
	encoder  *json.Encoder
	finished bool
}

type questionStreamFrame struct {
	Type       string        `json:"type"`
	Sequence   uint64        `json:"sequence,omitempty"`
	Phase      string        `json:"phase,omitempty"`
	Label      string        `json:"label,omitempty"`
	Outcome    string        `json:"outcome,omitempty"`
	DurationMS *int64        `json:"duration_ms,omitempty"`
	Result     *question.Run `json:"result,omitempty"`
	Code       string        `json:"code,omitempty"`
	RequestID  string        `json:"request_id,omitempty"`
}

func newQuestionEventStream(writer http.ResponseWriter) *questionEventStream {
	writer.Header().Set("Content-Type", questionStreamContentType)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Accel-Buffering", "no")
	return &questionEventStream{writer: writer, encoder: json.NewEncoder(writer)}
}

func (stream *questionEventStream) action(event question.ActionEvent) error {
	phase, label, outcome := string(event.Type), string(event.Label), string(event.Outcome)
	if event.Sequence == 0 || (phase != "action_started" && phase != "action_finished") ||
		(label != "model" && label != "document_search" && label != "document_read" && label != "live_data" && label != "trusted_comparison" && label != "other_tool") {
		return errors.New("invalid question action event")
	}
	if phase == "action_started" && (outcome != "" || event.DurationMS != nil) ||
		phase == "action_finished" && (outcome != "succeeded" && outcome != "failed" || event.DurationMS != nil && *event.DurationMS < 0) {
		return errors.New("invalid question action outcome")
	}
	return stream.write(questionStreamFrame{Type: "action", Sequence: event.Sequence, Phase: phase, Label: label, Outcome: outcome, DurationMS: event.DurationMS}, false)
}

func (stream *questionEventStream) result(run question.Run) error {
	if run.ID == "" || run.ResultStatus == "" {
		return errors.New("invalid question stream result")
	}
	return stream.write(questionStreamFrame{Type: "result", Result: &run}, true)
}

func (stream *questionEventStream) failure(requestID string) error {
	return stream.write(questionStreamFrame{Type: "error", Code: "QUESTION_FAILED", RequestID: requestID}, true)
}

func (stream *questionEventStream) write(frame questionStreamFrame, terminal bool) error {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.finished {
		return errors.New("question stream already finished")
	}
	if err := stream.encoder.Encode(frame); err != nil {
		stream.finished = true
		return err
	}
	if terminal {
		stream.finished = true
	}
	if err := http.NewResponseController(stream.writer).Flush(); err != nil {
		stream.finished = true
		return err
	}
	return nil
}
