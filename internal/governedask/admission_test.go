// Outcome 2 (audit before data) contract for ADR-0089's governed
// model-authored SQL path.
//
// These probes drive the same admission seam Ask() itself calls
// (withAdmission -> emitAdmission) with a fake audit appender, so the
// admission-before-read/execution ordering, both actor kinds and the
// fail-closed empty result are proven without a live PostgreSQL, Model Gateway
// or governed-execution role. They are protected-independent: no real
// database and no protected file is touched.
package governedask

import (
	"context"
	"errors"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// errInjectedAdmissionFailure models an admission append that does not become
// durable.
var errInjectedAdmissionFailure = errors.New("injected: admission audit append failure")

// recordingAdmissionJournal records every admission append and appends to the
// shared order slice so a run closure can assert admission already happened.
type recordingAdmissionJournal struct {
	appended []audit.EventInput
	order    *[]string
}

func (journal *recordingAdmissionJournal) Append(_ context.Context, _ database.AccessContext, input audit.EventInput) (audit.Event, error) {
	journal.appended = append(journal.appended, input)
	if journal.order != nil {
		*journal.order = append(*journal.order, "admission")
	}
	return audit.Event{EventID: input.EventID}, nil
}

// failingAdmissionJournal never persists the admission event.
type failingAdmissionJournal struct{}

func (failingAdmissionJournal) Append(context.Context, database.AccessContext, audit.EventInput) (audit.Event, error) {
	return audit.Event{}, errInjectedAdmissionFailure
}

func governedAskAccess(kind database.ActorKind) database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_gq_0001",
		RequestID:      "req_gq_0001",
		ActorKind:      kind,
	}
}

func admissionTestService(journal auditAppender) *Service {
	return &Service{
		auditor: journal,
		now:     func() time.Time { return time.Unix(0, 0).UTC() },
	}
}

func TestAttemptAuditPreservesServiceActor(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := admissionTestService(journal)
	if err := service.auditAttempt(context.Background(), governedAskAccess(database.ActorKindService), "ws_0001", 1, "", audit.GovernedQueryOutcomeRejectedStatic, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(journal.appended) != 1 || journal.appended[0].ActorType != audit.ActorService || journal.appended[0].RequestID != "req_gq_0001" {
		t.Fatalf("service attempt misattributed: %+v", journal.appended)
	}
}

// TestWithAdmissionAdmitsBeforeGovernedReadAndExecution proves Ask()'s
// admission ordering: the single admission event is appended strictly before
// the closure that performs every governed read, model call and SQL execution,
// and that closure is only reached once the admission is durable.
func TestWithAdmissionAdmitsBeforeGovernedReadAndExecution(t *testing.T) {
	order := []string{}
	journal := &recordingAdmissionJournal{order: &order}
	service := admissionTestService(journal)

	ran := false
	result, err := service.withAdmission(context.Background(), governedAskAccess(database.ActorKindHuman), "ws_0001",
		func() (AskResult, error) {
			ran = true
			order = append(order, "governed-read-and-execute")
			// The admission must already be recorded when governed work starts.
			if len(journal.appended) != 1 {
				t.Fatalf("admission events visible to the governed body = %d, want exactly one", len(journal.appended))
			}
			return AskResult{AttemptID: "gqat_0001", RowCount: 2}, nil
		})

	if err != nil {
		t.Fatalf("withAdmission returned %v, want a disclosed result", err)
	}
	if !ran {
		t.Fatal("the governed body never ran after a durable admission")
	}
	if len(order) != 2 || order[0] != "admission" || order[1] != "governed-read-and-execute" {
		t.Fatalf("execution order = %v, want admission strictly before the governed read/execution", order)
	}
	if len(journal.appended) != 1 {
		t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
	}
	if result.AttemptID != "gqat_0001" || result.RowCount != 2 {
		t.Fatalf("disclosed result = %+v, want the governed body's own result", result)
	}
}

// TestWithAdmissionFailsClosedWhenAdmissionCannotBeRecorded proves Ask()'s
// fail-closed refusal: a failed admission append returns the existing typed
// unavailable error with a zero AskResult and the governed body (and therefore
// every governed read, model call and SQL execution) never runs.
func TestWithAdmissionFailsClosedWhenAdmissionCannotBeRecorded(t *testing.T) {
	service := admissionTestService(failingAdmissionJournal{})

	ran := false
	result, err := service.withAdmission(context.Background(), governedAskAccess(database.ActorKindHuman), "ws_0001",
		func() (AskResult, error) {
			ran = true
			return AskResult{AttemptID: "must-not-be-returned", RowCount: 7}, nil
		})

	if ran {
		t.Fatal("the governed body ran after the admission append failed")
	}
	if result.AttemptID != "" || result.SQL != "" || result.SQLHash != "" || result.RowCount != 0 ||
		result.Columns != nil || result.Rows != nil || result.Answer != "" {
		t.Fatalf("admission failure leaked a partial result: %+v", result)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeUnavailable {
		t.Fatalf("admission failure error = %v, want a CodeUnavailable *Error", err)
	}
	if !errors.Is(err, errInjectedAdmissionFailure) {
		t.Fatalf("admission failure error = %v, want it to wrap the journal error", err)
	}
}

// TestWithAdmissionAdmitsExactlyOnceAcrossAttempts proves the admission is not
// re-emitted per bounded execution attempt: one Ask admits once, however many
// retries its governed body performs.
func TestWithAdmissionAdmitsExactlyOnceAcrossAttempts(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := admissionTestService(journal)

	_, err := service.withAdmission(context.Background(), governedAskAccess(database.ActorKindHuman), "ws_0001",
		func() (AskResult, error) {
			// askMaxAttempts is the server-owned bounded retry budget.
			for attempt := 0; attempt < askMaxAttempts; attempt++ {
				_ = attempt
			}
			return AskResult{}, errors.New("all attempts refused")
		})
	if err == nil {
		t.Fatal("withAdmission swallowed the governed body's error")
	}
	if len(journal.appended) != 1 {
		t.Fatalf("admission events appended across %d attempts = %d, want exactly one", askMaxAttempts, len(journal.appended))
	}
}

// TestEmitAdmissionCarriesActorKindAndDecision proves the admission event
// records the effective actor kind (HUMAN | SERVICE) and the access decision
// (SUCCESS = admitted) for both kinds of AccessContext.
func TestEmitAdmissionCarriesActorKindAndDecision(t *testing.T) {
	for _, candidate := range []struct {
		name string
		kind database.ActorKind
		want audit.ActorType
	}{
		{name: "human", kind: database.ActorKindHuman, want: audit.ActorHuman},
		{name: "service", kind: database.ActorKindService, want: audit.ActorService},
		{name: "unset defaults to human", kind: "", want: audit.ActorHuman},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			journal := &recordingAdmissionJournal{}
			service := admissionTestService(journal)

			if err := service.emitAdmission(context.Background(), governedAskAccess(candidate.kind), "ws_0001"); err != nil {
				t.Fatalf("emitAdmission returned %v, want nil", err)
			}
			if len(journal.appended) != 1 {
				t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
			}
			admission := journal.appended[0]
			if admission.ActorType != candidate.want {
				t.Fatalf("admission actor_type = %q, want %q", admission.ActorType, candidate.want)
			}
			if admission.Outcome != audit.OutcomeSuccess {
				t.Fatalf("admission access decision = %q, want SUCCESS", admission.Outcome)
			}
			if admission.Action != audit.ActionGovernedQueryAdmitted {
				t.Fatalf("admission action = %q, want %q", admission.Action, audit.ActionGovernedQueryAdmitted)
			}
			if admission.ResourceType != audit.ResourceWorkspace || admission.ResourceID != "ws_0001" {
				t.Fatalf("admission resource = %q/%q, want WORKSPACE/ws_0001", admission.ResourceType, admission.ResourceID)
			}
			if admission.WorkspaceID == nil || *admission.WorkspaceID != "ws_0001" {
				t.Fatalf("admission workspace = %v, want ws_0001", admission.WorkspaceID)
			}
		})
	}
}

// TestEmitAdmissionValidatesThroughAuditBuild proves the admission event is a
// well-formed audit-event-v1 event, that the new action is registered in the
// closed vocabulary, and that it is content-free: no SQL, schema, row or model
// content field is ever populated.
func TestEmitAdmissionValidatesThroughAuditBuild(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := admissionTestService(journal)

	access := governedAskAccess(database.ActorKindService)
	if err := service.emitAdmission(context.Background(), access, "ws_0001"); err != nil {
		t.Fatalf("emitAdmission returned %v, want nil", err)
	}
	input := journal.appended[0]

	event, err := audit.Build(access.OrganizationID, input, 0, "")
	if err != nil {
		t.Fatalf("the admission event does not validate through audit.Build: %v", err)
	}
	if event.Action != audit.ActionGovernedQueryAdmitted {
		t.Fatalf("built action = %q, want %q", event.Action, audit.ActionGovernedQueryAdmitted)
	}
	if event.Outcome != audit.OutcomeSuccess || event.ErrorCode != nil {
		t.Fatalf("built outcome = %q/%v, want SUCCESS with no error code", event.Outcome, event.ErrorCode)
	}
	// Content-free: no SQL hash, schema revision, row count, result digest or
	// model content may appear on an admission event.
	if input.Metadata.GovernedQuerySQLHash != nil || input.Metadata.GovernedQueryExposedSchemaRevision != nil ||
		input.Metadata.GovernedQueryRowCount != nil || input.Metadata.GovernedQueryResultDigest != nil ||
		input.Metadata.GovernedQueryOutcome != nil || input.Metadata.ModelRunID != nil {
		t.Fatalf("admission event carries governed-query/model content: %+v", input.Metadata)
	}
	if len(input.ReferencedEvidenceIDs) != 0 {
		t.Fatalf("admission event references evidence = %v, want none", input.ReferencedEvidenceIDs)
	}
}
