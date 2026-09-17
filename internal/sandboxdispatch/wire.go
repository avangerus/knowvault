// Package sandboxdispatch is the production per-object sandbox broker (ADR-0068):
// the dispatcher binary that hands one leased document to one registered parser
// worker and never creates a container itself. No application component may create
// a container or invoke a container runtime; the dispatcher only owns the pull-based
// lease handoff, the parser-type socket binding, the supervisor-owned deadline and
// the kernel-observed limit confirmation.
//
// The protocol between the submitter (the ingestion worker) and the dispatcher, and
// between the dispatcher and the registered parser worker, is expressed in four
// wire schemas — sandbox-job-v1, sandbox-lease-v1, sandbox-outcome-v1 and
// sandbox-limit-confirmation-v1 — each decoded strictly: an unknown member or a
// duplicate name is rejected, so no smuggled tenant id, database id, secret or
// authority can cross the boundary. Two additional socket-level frames exist below
// the wire schemas: the registration hello, by which a worker binds its parser type
// to exactly one socket, the registration acknowledgment, which confirms that
// binding, and the claim, by which a worker accepts an offered lease. These are
// typed by their frame kind, are accepted only in their protocol position on a
// fresh connection, and carry no business content of their own.
//
// The wire framing is a one-byte frame kind followed by a four-byte big-endian
// length and the body. A payload frame carries a small JSON header (the lease id and
// the extraction identity) followed by the raw document bytes, so a document stays
// opaque to the dispatcher: it is only digested against the job's declared
// content_digest and never parsed or logged.
package sandboxdispatch

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Version constants are the only accepted wire protocol versions. A new protocol
// that changes a wire shape mints a new version, never mutates this one.
const (
	JobVersion       = "sandbox-job-v1"
	LeaseVersion     = "sandbox-lease-v1"
	OutcomeVersion   = "sandbox-outcome-v1"
	LimitsVersion    = "sandbox-limit-confirmation-v1"
	OutputContractV1 = "document-parser-result-v1"
	// RegistrationAcceptedVersion is the exact content-free acknowledgment sent
	// only after the dispatcher has observed the peer and published its socket
	// binding. It is a transport version, not a business wire document.
	RegistrationAcceptedVersion = "sandbox-registration-accepted-v1"
)

// Parser types a registered socket may bind (sandbox-job.schema.json).
const (
	ParserTypeText       = "TEXT"
	ParserTypeStructured = "STRUCTURED"
	ParserTypeHTML       = "HTML"
	ParserTypeEML        = "EML"
	ParserTypeOffice     = "OFFICE"
	ParserTypePDF        = "PDF"
	ParserTypeOCR        = "OCR"
)

// Worker capabilities (sandbox-lease registration.capabilities). A worker that
// cannot pull a job or cannot push an outcome is useless by construction and its
// registration is rejected; any other capability does not exist.
const (
	CapabilityPullJob     = "PULL_JOB"
	CapabilityPushOutcome = "PUSH_OUTCOME"
)

// Handoff transfer states and statuses (sandbox-outcome.schema.json).
const (
	TransferConfirmed  = "CONFIRMED"
	TransferRetry      = "RETRY"
	TransferQuarantine = "QUARANTINED"

	StatusSucceeded  = "SUCCEEDED"
	StatusFailed     = "FAILED"
	StatusQuarantine = "QUARANTINED"
)

// Lease states (sandbox-lease.schema.json).
type LeaseState string

const (
	LeaseOffered     LeaseState = "OFFERED"
	LeaseClaimed     LeaseState = "CLAIMED"
	LeaseTransferred LeaseState = "TRANSFERRED"
	LeaseQuarantined LeaseState = "QUARANTINED"
	LeaseCompleted   LeaseState = "COMPLETED"
	LeaseExpired     LeaseState = "EXPIRED"
)

// Frame kinds of the transport framing. Values 1..17 are the complete closed
// set. The v2 job and lease kinds are deliberately distinct from their v1
// counterparts: a peer cannot silently reinterpret a new wire document as the
// immutable v1 contract.
type frameKind byte

const (
	kindRegister                    frameKind = 1  // worker -> dispatcher: registration hello (first frame only)
	kindJob                         frameKind = 2  // submitter -> dispatcher: sandbox-job-v1
	kindPayload                     frameKind = 3  // submitter -> dispatcher: job payload; dispatcher -> worker: leased payload
	kindClaim                       frameKind = 4  // worker -> dispatcher: lease claim (after an OFFERED lease)
	kindLease                       frameKind = 5  // dispatcher -> worker: sandbox-lease-v1
	kindOutcome                     frameKind = 6  // worker -> dispatcher / dispatcher -> submitter: sandbox-outcome-v1
	kindResult                      frameKind = 7  // worker -> dispatcher / dispatcher -> submitter: raw document-parser-result-v1
	kindLimits                      frameKind = 8  // dispatcher -> submitter: sandbox-limit-confirmation-v1
	kindRegisterAccepted            frameKind = 9  // dispatcher -> worker: exact registration acknowledgment
	kindJobV2                       frameKind = 10 // submitter -> dispatcher: sandbox-job-v2
	kindLeaseV2                     frameKind = 11 // dispatcher -> worker: sandbox-lease-v2
	kindRegisterV2                  frameKind = 12 // v2 worker -> its dedicated registration listener
	kindRegisterV2Accepted          frameKind = 13 // v2 dispatcher -> worker: exact registration acknowledgment
	kindSupervisorHandoffV2         frameKind = 14 // supervisor -> dedicated v2 handoff listener
	kindSupervisorHandoffAcceptedV2 frameKind = 15 // dispatcher -> supervisor: handoff accepted
	kindNativeReadinessV2           frameKind = 16 // submitter -> dispatcher: content-free readiness probe
	kindNativeReadinessResultV2     frameKind = 17 // dispatcher -> submitter: exact readiness acknowledgment
)

// registrationAcceptedBody is deliberately a fixed, content-free body. Keeping
// it as a constant makes the handshake closed: no worker, parser, tenant or
// authority data can be smuggled through the registration acknowledgment.
const registrationAcceptedBody = RegistrationAcceptedVersion

// Content-free sentinels. Every rejection collapses to one of these; no document
// content, worker diagnostic or reason detail escapes the dispatcher boundary.
var (
	ErrWireRejected                 = errors.New("sandboxdispatch: wire frame rejected")
	ErrJobRejected                  = errors.New("sandboxdispatch: job rejected")
	ErrRegistrationRejected         = errors.New("sandboxdispatch: registration rejected")
	ErrLeaseRejected                = errors.New("sandboxdispatch: lease transition rejected")
	ErrOutcomeRejected              = errors.New("sandboxdispatch: outcome rejected")
	ErrObservationUnavailable       = errors.New("sandboxdispatch: kernel observation unavailable")
	ErrKillUnavailable              = errors.New("sandboxdispatch: supervisor kill unavailable")
	ErrDispatchFailed               = errors.New("sandboxdispatch: no registered worker for the job")
	ErrRetryBeforeTransfer          = errors.New("sandboxdispatch: retry before transfer")
	ErrSupervisorHandoffUnavailable = errors.New("sandboxdispatch: supervisor handoff unavailable")
	ErrInvalidConfig                = errors.New("sandboxdispatch: invalid dispatcher configuration")
)

// Field length bounds mirror the wire schemas (minLength/maxLength).
const (
	maxIDLen = 128
)

var (
	sha256Re    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	mediaTypeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,254}(/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,254})?$`)
)

func validParserType(parserType string) bool {
	switch parserType {
	case ParserTypeText, ParserTypeStructured, ParserTypeHTML, ParserTypeEML,
		ParserTypeOffice, ParserTypePDF, ParserTypeOCR:
		return true
	}
	return false
}

func validID(value string) bool { return len(value) >= 1 && len(value) <= maxIDLen }

// decodeStrict is the closed-protocol decode shared by every wire document: an
// unknown member or a duplicate name is rejected. Invalid UTF-8 in a string is
// rejected by the decoder's default.
func decodeStrict(raw []byte, v any) error {
	return jsonv2.Unmarshal(raw, v, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
}

// parseTimestamp accepts only an RFC 3339 timestamp.
func parseTimestamp(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q: %w", raw, err)
	}
	return parsed, nil
}

// InputArtifact is the artifact the job dispatches (sandbox-job.schema.json
// input_artifact). The content digest is the submitter's declaration; the
// dispatcher re-derives it from the payload it receives and refuses the job on a
// mismatch before any handoff.
type InputArtifact struct {
	ArtifactID    string `json:"artifact_id"`
	ContentDigest string `json:"content_digest"`
	MediaType     string `json:"media_type"`
}

func (a InputArtifact) validate() bool {
	return validID(a.ArtifactID) && sha256Re.MatchString(a.ContentDigest) &&
		len(a.MediaType) >= 1 && len(a.MediaType) <= 256 && mediaTypeRe.MatchString(a.MediaType)
}

// Job is the submitter-side dispatch document (sandbox-job-v1).
type Job struct {
	SchemaVersion        string        `json:"schema_version"`
	JobID                string        `json:"job_id"`
	LeaseID              string        `json:"lease_id"`
	ParserType           string        `json:"parser_type"`
	SourceVersionID      string        `json:"source_version_id"`
	InputArtifact        InputArtifact `json:"input_artifact"`
	SubmittedAt          string        `json:"submitted_at"`
	DeadlineAt           string        `json:"deadline_at"`
	WorkerPullOnly       bool          `json:"worker_pull_only"`
	ContainerCreationCap string        `json:"container_creation_capability"`
	OutputContract       string        `json:"output_contract"`
}

// Validate checks the job against every closed member of sandbox-job-v1: the fixed
// schema version, the pull-only direction, the forbidden container-creation
// capability, the fixed output contract, the parser type vocabulary and the
// deadline order. A deadline that does not lie strictly after the submission time
// is rejected (CONTRACT_VALIDATION.md §10 deadline inversion).
func (j Job) Validate(now time.Time) (submittedAt, deadlineAt time.Time, err error) {
	if j.SchemaVersion != JobVersion {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: schema_version", ErrJobRejected)
	}
	if !validID(j.JobID) || !validID(j.LeaseID) || !validID(j.SourceVersionID) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: id shape", ErrJobRejected)
	}
	if !validParserType(j.ParserType) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: parser_type", ErrJobRejected)
	}
	if !j.InputArtifact.validate() {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: input_artifact", ErrJobRejected)
	}
	if !j.WorkerPullOnly || j.ContainerCreationCap != "FORBIDDEN" || j.OutputContract != OutputContractV1 {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: fixed members", ErrJobRejected)
	}
	submittedAt, err = parseTimestamp(j.SubmittedAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: submitted_at", ErrJobRejected)
	}
	deadlineAt, err = parseTimestamp(j.DeadlineAt)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: deadline_at", ErrJobRejected)
	}
	if !deadlineAt.After(submittedAt) || !deadlineAt.After(now) {
		return time.Time{}, time.Time{}, fmt.Errorf("%w: deadline order", ErrJobRejected)
	}
	return submittedAt, deadlineAt, nil
}

// Registration is the socket registration carried inside a lease
// (sandbox-lease.schema.json registration). The dispatcher builds it itself from
// the registration hello and its own socket path, so the lease's parser type always
// equals the registration's by construction (SAN-002).
type Registration struct {
	SocketID     string   `json:"socket_id"`
	ParserType   string   `json:"parser_type"`
	SingleSock   bool     `json:"single_socket"`
	Capabilities []string `json:"capabilities"`
}

// Lease is the dispatcher-side lease document (sandbox-lease-v1). Only the
// dispatcher mints it; the worker receives it and answers with a claim frame.
type Lease struct {
	SchemaVersion string       `json:"schema_version"`
	LeaseID       string       `json:"lease_id"`
	JobID         string       `json:"job_id"`
	WorkerID      string       `json:"worker_id"`
	ParserType    string       `json:"parser_type"`
	Registration  Registration `json:"registration"`
	IssuedAt      string       `json:"issued_at"`
	ExpiresAt     string       `json:"expires_at"`
	Attempt       int          `json:"attempt"`
	State         LeaseState   `json:"state"`
}

// Handoff is the transfer confirmation inside an outcome
// (sandbox-outcome.schema.json handoff).
type Handoff struct {
	TransferState  string `json:"transfer_state"`
	ConfirmationID string `json:"confirmation_id"`
}

// Outcome is the worker-side result document (sandbox-outcome-v1). The dispatcher
// validates the closed transfer/status/identity matrix, the worker identity and the
// extraction identity against its own kernel-observed value; a worker self-report
// that contradicts the dispatcher is quarantined.
type Outcome struct {
	SchemaVersion      string  `json:"schema_version"`
	LeaseID            string  `json:"lease_id"`
	JobID              string  `json:"job_id"`
	WorkerID           string  `json:"worker_id"`
	ParserType         string  `json:"parser_type"`
	Handoff            Handoff `json:"handoff"`
	Status             string  `json:"status"`
	ReportedAt         string  `json:"reported_at"`
	ExtractionIdentity *string `json:"extraction_identity"`
}

// validate checks the closed outcome matrix: CONFIRMED => SUCCEEDED with an exact
// sha256 identity, RETRY => FAILED with a null identity, QUARANTINED => QUARANTINED
// with a null identity (the three allOf branches of sandbox-outcome-v1).
func (o Outcome) validate() (reportedAt time.Time, err error) {
	if o.SchemaVersion != OutcomeVersion {
		return time.Time{}, fmt.Errorf("%w: schema_version", ErrOutcomeRejected)
	}
	if !validID(o.LeaseID) || !validID(o.JobID) || !validID(o.WorkerID) {
		return time.Time{}, fmt.Errorf("%w: id shape", ErrOutcomeRejected)
	}
	if !validParserType(o.ParserType) {
		return time.Time{}, fmt.Errorf("%w: parser_type", ErrOutcomeRejected)
	}
	if !validID(o.Handoff.ConfirmationID) {
		return time.Time{}, fmt.Errorf("%w: confirmation_id", ErrOutcomeRejected)
	}
	reportedAt, err = parseTimestamp(o.ReportedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: reported_at", ErrOutcomeRejected)
	}
	hasIdentity := o.ExtractionIdentity != nil && sha256Re.MatchString(*o.ExtractionIdentity)
	switch o.Handoff.TransferState {
	case TransferConfirmed:
		if o.Status != StatusSucceeded || !hasIdentity {
			return time.Time{}, fmt.Errorf("%w: confirmed matrix", ErrOutcomeRejected)
		}
	case TransferRetry:
		if o.Status != StatusFailed || o.ExtractionIdentity != nil {
			return time.Time{}, fmt.Errorf("%w: retry matrix", ErrOutcomeRejected)
		}
	case TransferQuarantine:
		if o.Status != StatusQuarantine || o.ExtractionIdentity != nil {
			return time.Time{}, fmt.Errorf("%w: quarantined matrix", ErrOutcomeRejected)
		}
	default:
		return time.Time{}, fmt.Errorf("%w: transfer_state", ErrOutcomeRejected)
	}
	return reportedAt, nil
}

// Limits is the kernel-observed resource bound set (sandbox-limit-confirmation-v1
// limits). Every field must be a finite positive integer; an unlimited or missing
// kernel bound is not an observation and is refused.
type Limits struct {
	CPUMillis   int64 `json:"cpu_millis"`
	MemoryBytes int64 `json:"memory_bytes"`
	PIDsMax     int64 `json:"pids_max"`
	WallClockMS int64 `json:"wall_clock_ms"`
}

func (l Limits) valid() bool {
	return l.CPUMillis >= 1 && l.MemoryBytes >= 1 && l.PIDsMax >= 1 && l.WallClockMS >= 1
}

// LimitConfirmation is the dispatcher-side kernel observation document
// (sandbox-limit-confirmation-v1). Only the dispatcher mints it; the observation
// method is the fixed kernel cgroup namespace and confirmed is the fixed true.
type LimitConfirmation struct {
	SchemaVersion      string `json:"schema_version"`
	LeaseID            string `json:"lease_id"`
	JobID              string `json:"job_id"`
	WorkerID           string `json:"worker_id"`
	ObservedAt         string `json:"observed_at"`
	ObservationMethod  string `json:"observation_method"`
	Limits             Limits `json:"limits"`
	ExtractionIdentity string `json:"extraction_identity"`
	Confirmed          bool   `json:"confirmed"`
}

// PayloadHeader is the small JSON header of a payload frame: the lease id and the
// extraction identity the dispatcher derived from its own kernel observation. It is
// a transport envelope, not a wire schema; the worker echoes the identity back in
// its outcome and the dispatcher verifies the echo against the value it computed.
type PayloadHeader struct {
	LeaseID            string `json:"lease_id"`
	ExtractionIdentity string `json:"extraction_identity"`
}

// Claim is the socket-level frame by which a worker accepts an offered lease. It
// carries the lease id and the worker id of the claiming connection and nothing
// else.
type Claim struct {
	LeaseID  string `json:"lease_id"`
	WorkerID string `json:"worker_id"`
}

// RegisterHello is the socket-level registration frame, accepted only as the first
// frame on a fresh connection. The parser type binds to exactly one socket; the
// capabilities must be exactly the closed PULL_JOB/PUSH_OUTCOME pair.
type RegisterHello struct {
	WorkerID     string   `json:"worker_id"`
	ParserType   string   `json:"parser_type"`
	Capabilities []string `json:"capabilities"`
}

func (h RegisterHello) validate() bool {
	if !validID(h.WorkerID) || !validParserType(h.ParserType) {
		return false
	}
	if len(h.Capabilities) != 2 {
		return false
	}
	hasPull, hasPush := false, false
	for _, capability := range h.Capabilities {
		switch capability {
		case CapabilityPullJob:
			hasPull = true
		case CapabilityPushOutcome:
			hasPush = true
		default:
			return false
		}
	}
	return hasPull && hasPush
}
