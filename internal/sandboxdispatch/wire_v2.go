package sandboxdispatch

import (
	"fmt"
	"regexp"
	"time"
)

const (
	ParserRequestVersionV1 = "sandbox-parser-request-v1"
	JobVersionV2           = "sandbox-job-v2"
	LeaseVersionV2         = "sandbox-lease-v2"
	OutcomeVersionV2       = "sandbox-outcome-v2"
	LimitsVersionV2        = "sandbox-limit-confirmation-v2"

	OperationObserveStructure       = "OBSERVE_STRUCTURE"
	OperationObservePDFText         = "OBSERVE_PDF_TEXT"
	OperationRenderPDFPages         = "RENDER_PDF_PAGES"
	OperationObserveOCRTokens       = "OBSERVE_OCR_TOKENS"
	maxJSONSafeInteger        int64 = 9007199254740991
)

var profileRevisionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func validProfileRevision(value string) bool { return profileRevisionRe.MatchString(value) }

// ParserRequestV1 is the complete capability tuple. It intentionally contains no
// tenant, workspace, source-version, artifact, or persistence identity.
type ParserRequestV1 struct {
	SchemaVersion              string `json:"schema_version"`
	ParserType                 string `json:"parser_type"`
	Operation                  string `json:"operation"`
	MediaFamily                string `json:"media_family"`
	SandboxProfileRevision     string `json:"sandbox_profile_revision"`
	ObservationProfileRevision string `json:"observation_profile_revision"`
	RendererProfileRevision    string `json:"renderer_profile_revision,omitempty"`
	OCRProfileRevision         string `json:"ocr_profile_revision,omitempty"`
	MaxInputBytes              int64  `json:"max_input_bytes"`
	MaxOutputBytes             int64  `json:"max_output_bytes"`
	MaxUnits                   int64  `json:"max_units"`
	MaxPages                   int64  `json:"max_pages"`
	MaxDecodedPixels           int64  `json:"max_decoded_pixels"`
	OutputContract             string `json:"output_contract"`
}

func (r ParserRequestV1) Validate() error {
	if r.SchemaVersion != ParserRequestVersionV1 || !validProfileRevision(r.SandboxProfileRevision) || !validProfileRevision(r.ObservationProfileRevision) ||
		r.MaxInputBytes < 1 || r.MaxInputBytes > maxJSONSafeInteger || r.MaxOutputBytes < 1 || r.MaxOutputBytes > maxJSONSafeInteger ||
		r.MaxUnits < 1 || r.MaxUnits > maxJSONSafeInteger || r.MaxPages < 1 || r.MaxPages > maxJSONSafeInteger ||
		r.MaxDecodedPixels < 1 || r.MaxDecodedPixels > maxJSONSafeInteger {
		return fmt.Errorf("%w: parser request shape", ErrJobRejected)
	}
	switch r.ParserType + "/" + r.Operation + "/" + r.MediaFamily + "/" + r.OutputContract {
	case "OFFICE/OBSERVE_STRUCTURE/DOCX/document-parser-result-v1", "OFFICE/OBSERVE_STRUCTURE/PPTX/document-parser-result-v1", "OFFICE/OBSERVE_STRUCTURE/XLSX/document-parser-result-v1", "PDF/OBSERVE_PDF_TEXT/PDF/pdf-parser-result-v1":
		if r.RendererProfileRevision == "" && r.OCRProfileRevision == "" {
			return nil
		}
	case "PDF/RENDER_PDF_PAGES/PDF/pdf-render-result-v1":
		if validProfileRevision(r.RendererProfileRevision) && r.OCRProfileRevision == "" {
			return nil
		}
	case "OCR/OBSERVE_OCR_TOKENS/PNG/ocr-result-v1", "OCR/OBSERVE_OCR_TOKENS/JPEG/ocr-result-v1":
		if validProfileRevision(r.OCRProfileRevision) && r.RendererProfileRevision == "" {
			return nil
		}
	}
	return fmt.Errorf("%w: parser request tuple", ErrJobRejected)
}

type JobV2 struct {
	SchemaVersion        string          `json:"schema_version"`
	JobID                string          `json:"job_id"`
	LeaseID              string          `json:"lease_id"`
	ParserRequest        ParserRequestV1 `json:"parser_request"`
	InputArtifact        InputArtifact   `json:"input_artifact"`
	SubmittedAt          string          `json:"submitted_at"`
	DeadlineAt           string          `json:"deadline_at"`
	WorkerPullOnly       bool            `json:"worker_pull_only"`
	ContainerCreationCap string          `json:"container_creation_capability"`
}

// PayloadHeaderV2 is the transport envelope attached to a v2 worker transfer.
// The dispatcher mints the runtime and execution identities after observing the
// registered socket; neither value is accepted from the submitter or worker as
// authority. A submitter's initial payload may carry only LeaseID, while a
// worker-facing transfer must pass Validate with both identities populated.
type PayloadHeaderV2 struct {
	LeaseID                 string `json:"lease_id"`
	RuntimeProfileHash      string `json:"runtime_profile_hash"`
	ExecutionConfirmationID string `json:"execution_confirmation_id"`
}

func (h PayloadHeaderV2) Validate() error {
	if !validID(h.LeaseID) || !sha256Re.MatchString(h.RuntimeProfileHash) || !sha256Re.MatchString(h.ExecutionConfirmationID) {
		return fmt.Errorf("%w: v2 payload header", ErrWireRejected)
	}
	return nil
}

func (j JobV2) Validate(now time.Time) (time.Time, time.Time, error) {
	if j.SchemaVersion != JobVersionV2 || !validID(j.JobID) || !validID(j.LeaseID) || !j.InputArtifact.validate() || !j.WorkerPullOnly || j.ContainerCreationCap != "FORBIDDEN" {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: v2 job shape", ErrJobRejected)
	}
	if err := j.ParserRequest.Validate(); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if j.InputArtifact.MediaType != mediaTypeFor(j.ParserRequest.MediaFamily) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: media type", ErrJobRejected)
	}
	submitted, err := parseTimestamp(j.SubmittedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: submitted_at", ErrJobRejected)
	}
	deadline, err := parseTimestamp(j.DeadlineAt)
	if err != nil || !deadline.After(submitted) || !deadline.After(now) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: deadline", ErrJobRejected)
	}
	return submitted, deadline, nil
}

func mediaTypeFor(mediaFamily string) string {
	switch mediaFamily {
	case "DOCX":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case "PPTX":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case "XLSX":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "PDF":
		return "application/pdf"
	case "PNG":
		return "image/png"
	case "JPEG":
		return "image/jpeg"
	}
	return ""
}

type LeaseV2 struct {
	SchemaVersion string          `json:"schema_version"`
	LeaseID       string          `json:"lease_id"`
	JobID         string          `json:"job_id"`
	WorkerID      string          `json:"worker_id"`
	ParserRequest ParserRequestV1 `json:"parser_request"`
	IssuedAt      string          `json:"issued_at"`
	ExpiresAt     string          `json:"expires_at"`
	Attempt       int             `json:"attempt"`
	State         LeaseState      `json:"state"`
}

func (l LeaseV2) Validate() error {
	if l.SchemaVersion != LeaseVersionV2 || !validID(l.LeaseID) || !validID(l.JobID) || !validID(l.WorkerID) || l.Attempt < 1 || l.Attempt > 1000 {
		return fmt.Errorf("%w: v2 lease shape", ErrLeaseRejected)
	}
	if err := l.ParserRequest.Validate(); err != nil {
		return err
	}
	issued, err := parseTimestamp(l.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: issued_at", ErrLeaseRejected)
	}
	expires, err := parseTimestamp(l.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return fmt.Errorf("%w: expires_at", ErrLeaseRejected)
	}
	switch l.State {
	case LeaseOffered, LeaseClaimed, LeaseTransferred, LeaseQuarantined, LeaseCompleted, LeaseExpired:
		return nil
	}
	return fmt.Errorf("%w: state", ErrLeaseRejected)
}

type OutcomeV2 struct {
	SchemaVersion           string          `json:"schema_version"`
	LeaseID                 string          `json:"lease_id"`
	JobID                   string          `json:"job_id"`
	WorkerID                *string         `json:"worker_id"`
	ParserRequest           ParserRequestV1 `json:"parser_request"`
	Handoff                 Handoff         `json:"handoff"`
	Status                  string          `json:"status"`
	ReportedAt              string          `json:"reported_at"`
	OutputContract          string          `json:"output_contract"`
	ResultDigest            *string         `json:"result_digest"`
	RuntimeProfileHash      *string         `json:"runtime_profile_hash"`
	ExecutionConfirmationID *string         `json:"execution_confirmation_id"`
}

func (o OutcomeV2) Validate() error {
	if o.SchemaVersion != OutcomeVersionV2 || !validID(o.LeaseID) || !validID(o.JobID) || !validID(o.Handoff.ConfirmationID) {
		return fmt.Errorf("%w: v2 outcome shape", ErrOutcomeRejected)
	}
	if err := o.ParserRequest.Validate(); err != nil {
		return err
	}
	if _, err := parseTimestamp(o.ReportedAt); err != nil {
		return fmt.Errorf("%w: reported_at", ErrOutcomeRejected)
	}
	has := o.ResultDigest != nil && sha256Re.MatchString(*o.ResultDigest)
	postTransfer := o.WorkerID != nil && validID(*o.WorkerID) && o.RuntimeProfileHash != nil && sha256Re.MatchString(*o.RuntimeProfileHash) && o.ExecutionConfirmationID != nil && sha256Re.MatchString(*o.ExecutionConfirmationID)
	if o.OutputContract != o.ParserRequest.OutputContract {
		return fmt.Errorf("%w: output contract", ErrOutcomeRejected)
	}
	switch o.Handoff.TransferState {
	case TransferRetry:
		if o.Status == StatusFailed && o.WorkerID == nil && o.ResultDigest == nil && o.RuntimeProfileHash == nil && o.ExecutionConfirmationID == nil {
			return nil
		}
	case TransferConfirmed:
		if postTransfer && o.Status == StatusSucceeded && has && o.Handoff.ConfirmationID == *o.ExecutionConfirmationID {
			return nil
		}
	case TransferQuarantine:
		if postTransfer && o.Status == StatusQuarantine && o.ResultDigest == nil && o.Handoff.ConfirmationID == *o.ExecutionConfirmationID {
			return nil
		}
	}
	return fmt.Errorf("%w: v2 outcome matrix", ErrOutcomeRejected)
}

type LimitConfirmationV2 struct {
	SchemaVersion           string          `json:"schema_version"`
	LeaseID                 string          `json:"lease_id"`
	JobID                   string          `json:"job_id"`
	WorkerID                string          `json:"worker_id"`
	ObservedAt              string          `json:"observed_at"`
	ObservationMethod       string          `json:"observation_method"`
	ParserRequest           ParserRequestV1 `json:"parser_request"`
	Limits                  Limits          `json:"limits"`
	RuntimeProfileHash      string          `json:"runtime_profile_hash"`
	ExecutionConfirmationID string          `json:"execution_confirmation_id"`
	Confirmed               bool            `json:"confirmed"`
}

func (c LimitConfirmationV2) Validate() error {
	if c.SchemaVersion != LimitsVersionV2 || !validID(c.LeaseID) || !validID(c.JobID) || !validID(c.WorkerID) || c.ObservationMethod != "KERNEL_CGROUP_NAMESPACE" || !c.Confirmed || !c.Limits.valid() {
		return fmt.Errorf("%w: v2 limit confirmation shape", ErrObservationUnavailable)
	}
	if err := c.ParserRequest.Validate(); err != nil {
		return err
	}
	observed, err := parseTimestamp(c.ObservedAt)
	if err != nil {
		return fmt.Errorf("%w: observed_at", ErrObservationUnavailable)
	}
	runtime := RuntimeProfileHash(c.ParserRequest.ParserType, c.ParserRequest.SandboxProfileRevision, c.Limits)
	if c.RuntimeProfileHash != runtime || c.ExecutionConfirmationID != ExecutionConfirmationID(runtime, c.LeaseID, c.JobID, c.WorkerID, observed) {
		return fmt.Errorf("%w: v2 identity", ErrObservationUnavailable)
	}
	return nil
}
