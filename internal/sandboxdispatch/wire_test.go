package sandboxdispatch

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodeStrictRejectsUnknownMembersAndDuplicates(t *testing.T) {
	t.Parallel()

	lease := `{"schema_version":"sandbox-lease-v1","lease_id":"l1","job_id":"j1","worker_id":"w1","parser_type":"TEXT","registration":{"socket_id":"unix:///run/knowvault/parser.sock","parser_type":"TEXT","single_socket":true,"capabilities":["PULL_JOB","PUSH_OUTCOME"]},"issued_at":"2026-08-14T10:00:00Z","expires_at":"2026-08-14T10:01:00Z","attempt":1,"state":"OFFERED"}`
	var decoded Lease
	if err := decodeStrict([]byte(lease), &decoded); err != nil {
		t.Fatalf("valid lease rejected: %v", err)
	}
	if decoded.State != LeaseOffered || decoded.Registration.SocketID == "" {
		t.Fatalf("decoded lease wrong: %#v", decoded)
	}

	smuggled := `{"schema_version":"sandbox-lease-v1","lease_id":"l1","job_id":"j1","worker_id":"w1","parser_type":"TEXT","registration":{"socket_id":"unix:///run/knowvault/parser.sock","parser_type":"TEXT","single_socket":true,"capabilities":["PULL_JOB","PUSH_OUTCOME"]},"issued_at":"2026-08-14T10:00:00Z","expires_at":"2026-08-14T10:01:00Z","attempt":1,"state":"OFFERED","tenant_id":"org_evil"}`
	if err := decodeStrict([]byte(smuggled), &decoded); err == nil {
		t.Fatalf("smuggled tenant id accepted")
	}
	duplicate := `{"schema_version":"sandbox-lease-v1","lease_id":"l1","lease_id":"l2","job_id":"j1","worker_id":"w1","parser_type":"TEXT","registration":{"socket_id":"unix:///run/knowvault/parser.sock","parser_type":"TEXT","single_socket":true,"capabilities":["PULL_JOB","PUSH_OUTCOME"]},"issued_at":"2026-08-14T10:00:00Z","expires_at":"2026-08-14T10:01:00Z","attempt":1,"state":"OFFERED"}`
	if err := decodeStrict([]byte(duplicate), &decoded); err == nil {
		t.Fatalf("duplicate lease_id accepted")
	}
}

func TestJobValidateClosedMembers(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	base := Job{
		SchemaVersion:        JobVersion,
		JobID:                "j1",
		LeaseID:              "l1",
		ParserType:           ParserTypeText,
		SourceVersionID:      "sv1",
		InputArtifact:        InputArtifact{ArtifactID: "a1", ContentDigest: "sha256:" + strings.Repeat("a", 64), MediaType: "text/plain"},
		SubmittedAt:          "2026-08-14T09:59:00Z",
		DeadlineAt:           "2026-08-14T10:05:00Z",
		WorkerPullOnly:       true,
		ContainerCreationCap: "FORBIDDEN",
		OutputContract:       OutputContractV1,
	}
	if _, _, err := base.Validate(now); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}

	for name, mutate := range map[string]func(*Job){
		"push instead of pull":   func(j *Job) { j.WorkerPullOnly = false },
		"container capability":   func(j *Job) { j.ContainerCreationCap = "ALLOWED" },
		"other output contract":  func(j *Job) { j.OutputContract = "anything-else-v1" },
		"deadline inversion":     func(j *Job) { j.DeadlineAt = j.SubmittedAt },
		"deadline in the past":   func(j *Job) { j.DeadlineAt = "2026-08-14T09:59:59Z" },
		"unknown parser type":    func(j *Job) { j.ParserType = "VECTOR" },
		"bad digest":             func(j *Job) { j.InputArtifact.ContentDigest = "sha256:" + strings.Repeat("A", 64) },
		"empty artifact id":      func(j *Job) { j.InputArtifact.ArtifactID = "" },
		"unknown schema version": func(j *Job) { j.SchemaVersion = "sandbox-job-v0" },
	} {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			job := base
			mutate(&job)
			if _, _, err := job.Validate(now); err == nil {
				t.Fatalf("invalid job accepted: %s", name)
			}
		})
	}
}

func TestOutcomeValidateClosedMatrix(t *testing.T) {
	t.Parallel()

	identity := "sha256:" + strings.Repeat("b", 64)
	make := func(transfer, status string, identityValue *string) Outcome {
		return Outcome{
			SchemaVersion:      OutcomeVersion,
			LeaseID:            "l1",
			JobID:              "j1",
			WorkerID:           "w1",
			ParserType:         ParserTypeText,
			Handoff:            Handoff{TransferState: transfer, ConfirmationID: "c1"},
			Status:             status,
			ReportedAt:         "2026-08-14T10:02:00Z",
			ExtractionIdentity: identityValue,
		}
	}

	if _, err := make(TransferConfirmed, StatusSucceeded, &identity).validate(); err != nil {
		t.Fatalf("valid confirmed outcome rejected: %v", err)
	}
	if _, err := make(TransferRetry, StatusFailed, nil).validate(); err != nil {
		t.Fatalf("valid retry outcome rejected: %v", err)
	}
	if _, err := make(TransferQuarantine, StatusQuarantine, nil).validate(); err != nil {
		t.Fatalf("valid quarantined outcome rejected: %v", err)
	}

	for name, outcome := range map[string]Outcome{
		"confirmed without identity":   make(TransferConfirmed, StatusSucceeded, nil),
		"confirmed with failed status": make(TransferConfirmed, StatusFailed, &identity),
		"retry with identity":          make(TransferRetry, StatusFailed, &identity),
		"retry with success":           make(TransferRetry, StatusSucceeded, nil),
		"quarantined with identity":    make(TransferQuarantine, StatusQuarantine, &identity),
		"unknown transfer state":       make("FORGED", StatusFailed, nil),
		"short identity":               make(TransferConfirmed, StatusSucceeded, stringPtr("sha256:ab")),
		"empty confirmation id":        make(TransferConfirmed, StatusSucceeded, &identity),
	} {
		if name == "empty confirmation id" {
			outcome.Handoff.ConfirmationID = ""
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := outcome.validate(); err == nil {
				t.Fatalf("invalid outcome accepted: %s", name)
			}
		})
	}
}

func TestRegisterHelloValidateClosedCapabilities(t *testing.T) {
	t.Parallel()

	valid := RegisterHello{
		WorkerID:     "w1",
		ParserType:   ParserTypeOffice,
		Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome},
	}
	if !valid.validate() {
		t.Fatalf("valid hello rejected")
	}
	for name, hello := range map[string]RegisterHello{
		"missing pull": {
			WorkerID: "w1", ParserType: ParserTypeOffice, Capabilities: []string{CapabilityPushOutcome},
		},
		"unknown capability": {
			WorkerID: "w1", ParserType: ParserTypeOffice, Capabilities: []string{CapabilityPullJob, "CREATE_CONTAINER"},
		},
		"three capabilities": {
			WorkerID: "w1", ParserType: ParserTypeOffice, Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome, CapabilityPullJob},
		},
		"bad worker id": {
			WorkerID: "", ParserType: ParserTypeOffice, Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome},
		},
		"bad parser type": {
			WorkerID: "w1", ParserType: "VECTOR", Capabilities: []string{CapabilityPullJob, CapabilityPushOutcome},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if hello.validate() {
				t.Fatalf("invalid hello accepted: %s", name)
			}
		})
	}
}

func TestWireDocumentsMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	confirmation := LimitConfirmation{
		SchemaVersion:      LimitsVersion,
		LeaseID:            "l1",
		JobID:              "j1",
		WorkerID:           "w1",
		ObservedAt:         "2026-08-14T10:00:00Z",
		ObservationMethod:  "KERNEL_CGROUP_NAMESPACE",
		Limits:             Limits{CPUMillis: 500, MemoryBytes: 536870912, PIDsMax: 64, WallClockMS: 60000},
		ExtractionIdentity: "sha256:" + strings.Repeat("c", 64),
		Confirmed:          true,
	}
	raw, err := json.Marshal(confirmation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded LimitConfirmation
	if err := decodeStrict(raw, &decoded); err != nil {
		t.Fatalf("confirmation round trip: %v", err)
	}
	if decoded.Limits != confirmation.Limits || !decoded.Confirmed {
		t.Fatalf("confirmation drifted: %#v", decoded)
	}
}

func stringPtr(value string) *string { return &value }
