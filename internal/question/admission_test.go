// Outcome 2 (audit before data) contract for the governed workspace question
// run.
//
// These tests drive Create itself (the real service entry point) through the
// admission journal seam plus the two governed-read seams so the
// admission-before-read ordering and its fail-closed refusal are proven without
// a database. They are protected-independent: no real PostgreSQL and no
// protected file is touched.
package question

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
)

// errInjectedAdmissionFailure models a journal whose admission append does not
// become durable.
var errInjectedAdmissionFailure = errors.New("injected: audit append failure")

// recordingAdmissionJournal records every admission append and the order in
// which the admission and the governed reads execute.
type recordingAdmissionJournal struct {
	appended []audit.EventInput
	order    []string
}

func (journal *recordingAdmissionJournal) Append(_ context.Context, _ database.AccessContext, input audit.EventInput) (audit.Event, error) {
	journal.appended = append(journal.appended, input)
	if input.Action == audit.ActionQuestionRunAdmitted || input.Action == audit.ActionEvidenceReadAdmitted {
		journal.order = append(journal.order, "admission")
	} else {
		journal.order = append(journal.order, "outcome")
	}
	return audit.Event{EventID: input.EventID}, nil
}

// failingAdmissionJournal never persists the admission event.
type failingAdmissionJournal struct{}

func (failingAdmissionJournal) Append(context.Context, database.AccessContext, audit.EventInput) (audit.Event, error) {
	return audit.Event{}, errInjectedAdmissionFailure
}

func questionAccess(kind database.ActorKind) database.AccessContext {
	return database.AccessContext{
		OrganizationID: "org_0001",
		PrincipalID:    "principal_question_0001",
		RequestID:      "req_question_0001",
		ActorKind:      kind,
	}
}

// testQuestionIdempotencyKey is a syntactically valid opaque idempotency key.
var testQuestionIdempotencyKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))

func questionCreateRequest() CreateRequest {
	return CreateRequest{
		WorkspaceID:    "ws_0001",
		Question:       "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?",
		IdempotencyKey: testQuestionIdempotencyKey,
	}
}

// testCreateService wires the non-nil fields Create's entry guard requires. The
// zero *database.Store cannot serve a transaction, which is exactly why every
// test below either returns through the replay seam or stops at the
// admission/read-ordering boundary the test is asserting.
func testCreateService(journal admissionJournal) *Service {
	service := &Service{}
	service.db = &database.Store{}
	service.audit = &audit.Store{}
	service.admission = journal
	service.codec = &artifactcrypto.Codec{}
	service.artifacts = &artifactrepository.Repository{}
	service.retrievalStore = &retrieval.Repository{}
	service.now = func() time.Time { return time.Unix(0, 0).UTC() }
	service.newID = func(prefix string) (string, error) { return prefix + "_0001", nil }
	return service
}

// TestCreateAdmitsBeforeFreshPathIdempotencyLookup proves that Create (not a
// helper) persists the admission event before the fresh-path idempotency
// lookup, which is the first governed read on that path.
func TestCreateAdmitsBeforeFreshPathIdempotencyLookup(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		journal.order = append(journal.order, "lookup")
		return Run{}, false, nil
	}

	// With no idempotency row the request proceeds to the fresh run, where the
	// zero database refuses to serve the write. That typed failure is expected;
	// the ordering assertion below is the contract under test.
	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), questionCreateRequest()); err == nil {
		t.Fatal("Create on a fresh path with an unusable database = nil, want the post-admission transaction error")
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "lookup" {
		t.Fatalf("execution order = %v, want admission strictly before the fresh-path idempotency lookup", journal.order)
	}
	if len(journal.appended) != 1 {
		t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
	}
}

// TestCreateAdmitsBeforeIdempotentReplayReturnsStoredData proves that a replay
// of a completed run emits the admission before the stored answer, citations
// and rows are handed back.
func TestCreateAdmitsBeforeIdempotentReplayReturnsStoredData(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	stored := Run{ID: "qrun_stored", WorkspaceID: "ws_0001", Answer: "stored answer", Citations: []Citation{{Number: 1, Excerpt: "stored"}}}
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		journal.order = append(journal.order, "lookup")
		return stored, true, nil
	}

	got, err := service.Create(context.Background(), questionAccess(database.ActorKindService), questionCreateRequest())
	if err != nil {
		t.Fatalf("Create replay = %v, want nil", err)
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "lookup" {
		t.Fatalf("execution order = %v, want admission strictly before the replay lookup", journal.order)
	}
	if got.ID != stored.ID || got.Answer != stored.Answer || len(got.Citations) != 1 || got.Citations[0].Excerpt != "stored" {
		t.Fatalf("replay result = %#v, want the stored answer/citations %#v", got, stored)
	}
	if len(journal.appended) != 1 {
		t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
	}
}

// TestCreateAdmitsBeforePreviousTurnMemoryRead proves the previous-turn memory
// read of a conversation follow-up also happens only after the durable
// admission.
func TestCreateAdmitsBeforePreviousTurnMemoryRead(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := testCreateService(journal)
	service.previousTurnQuestionFn = func(context.Context, database.AccessContext, string, string) (string, string, error) {
		journal.order = append(journal.order, "previous-turn")
		return "", "", nil
	}
	request := questionCreateRequest()
	request.ConversationID = "conv_0001"
	request.Question = "\u0430 \u0432\u0447\u0435\u0440\u0430?"

	if _, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request); err == nil {
		t.Fatal("Create with an unresolvable follow-up = nil, want a typed error")
	}
	if len(journal.order) < 2 || journal.order[0] != "admission" || journal.order[1] != "previous-turn" {
		t.Fatalf("execution order = %v, want admission strictly before the previous-turn read", journal.order)
	}
}

// TestCreateAdmissionFailureFailsClosedBeforeAnyRead proves that a failed
// admission on Create returns the typed unavailable error and never runs the
// governed reads, so no answer, citation or row can leak.
func TestCreateAdmissionFailureFailsClosedBeforeAnyRead(t *testing.T) {
	service := testCreateService(failingAdmissionJournal{})
	reads := 0
	service.previousTurnQuestionFn = func(context.Context, database.AccessContext, string, string) (string, string, error) {
		reads++
		return "", "", nil
	}
	service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
		reads++
		return Run{ID: "qrun_leak", Answer: "leaked"}, true, nil
	}
	request := questionCreateRequest()
	request.ConversationID = "conv_0001"
	request.Question = "\u0430 \u0432\u0447\u0435\u0440\u0430?"

	got, err := service.Create(context.Background(), questionAccess(database.ActorKindHuman), request)
	if err == nil {
		t.Fatal("Create with a failed admission = nil, want the audit failure")
	}
	if CodeOf(err) != CodeUnavailable {
		t.Fatalf("admission failure code = %q, want %q", CodeOf(err), CodeUnavailable)
	}
	if !errors.Is(err, errInjectedAdmissionFailure) {
		t.Fatalf("admission failure must retain the journal error, got %v", err)
	}
	if reads != 0 {
		t.Fatalf("governed reads ran %d time(s) after the admission append failed", reads)
	}
	if got.ID != "" || got.Answer != "" || len(got.Citations) != 0 || got.FailureCode != "" {
		t.Fatalf("admission failure leaked a partial result: %#v", got)
	}
}

// TestCreateAdmissionRecordsActorKindAndAccessDecision proves the admission
// persisted by Create itself records the effective actor kind (HUMAN |
// SERVICE), the access decision (SUCCESS = admitted), the workspace and the
// run, and is a valid registered audit event.
func TestCreateAdmissionRecordsActorKindAndAccessDecision(t *testing.T) {
	for name, testCase := range map[string]struct {
		kind database.ActorKind
		want audit.ActorType
	}{
		"human":   {database.ActorKindHuman, audit.ActorHuman},
		"service": {database.ActorKindService, audit.ActorService},
		"unset":   {"", audit.ActorHuman},
	} {
		t.Run(name, func(t *testing.T) {
			journal := &recordingAdmissionJournal{}
			service := testCreateService(journal)
			service.lookupIdempotencyFn = func(context.Context, database.AccessContext, string, string, string) (Run, bool, error) {
				return Run{ID: "qrun_0001"}, true, nil
			}
			if _, err := service.Create(context.Background(), questionAccess(testCase.kind), questionCreateRequest()); err != nil {
				t.Fatalf("Create = %v, want nil", err)
			}
			if len(journal.appended) != 1 {
				t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
			}
			admission := journal.appended[0]
			if admission.ActorType != testCase.want {
				t.Fatalf("admission actor_type = %q, want %q", admission.ActorType, testCase.want)
			}
			if admission.Action != audit.ActionQuestionRunAdmitted {
				t.Fatalf("admission action = %q, want %q", admission.Action, audit.ActionQuestionRunAdmitted)
			}
			if admission.ResourceType != audit.ResourceWorkspace || admission.ResourceID != "ws_0001" {
				t.Fatalf("admission resource = %q/%q, want WORKSPACE/ws_0001", admission.ResourceType, admission.ResourceID)
			}
			if admission.Outcome != audit.OutcomeSuccess || admission.ErrorCode != nil {
				t.Fatalf("admission access decision = %q error=%v, want SUCCESS/nil", admission.Outcome, admission.ErrorCode)
			}
			if admission.WorkspaceID == nil || *admission.WorkspaceID != "ws_0001" {
				t.Fatalf("admission workspace = %v, want ws_0001", admission.WorkspaceID)
			}
			if admission.Metadata.QuestionRunID == nil || *admission.Metadata.QuestionRunID != "qrun_0001" {
				t.Fatalf("admission question run metadata = %v, want qrun_0001", admission.Metadata.QuestionRunID)
			}
			if _, err := audit.Build("org_0001", admission, 0, ""); err != nil {
				t.Fatalf("admission event is not a valid registered audit event: %v", err)
			}
		})
	}
}

// failingRecordingAdmissionJournal records every append attempt and always
// fails, so a test can prove that a failed admission appends nothing further,
// never runs the governed read and never leaves an outcome behind.
type failingRecordingAdmissionJournal struct{ appended []audit.EventInput }

func (journal *failingRecordingAdmissionJournal) Append(_ context.Context, _ database.AccessContext, input audit.EventInput) (audit.Event, error) {
	journal.appended = append(journal.appended, input)
	return audit.Event{}, errInjectedAdmissionFailure
}

const (
	testStoredRunWorkspace = "ws_0001"
	testStoredRunID        = "qrun_0001"
)

func storedRunReadService(journal admissionJournal, read func(context.Context, database.AccessContext, string, string) (Run, error)) *Service {
	service := testCreateService(journal)
	service.storedRunReadFn = read
	return service
}

func storedRunBatchReadService(journal admissionJournal, read func(context.Context, database.AccessContext, string, []string) (map[string]Run, error)) *Service {
	service := testCreateService(journal)
	service.storedRunBatchReadFn = read
	return service
}

// TestGetAdmitsBeforeStoredRunRead proves that Get itself persists the
// admission event before the governed stored-run read runs.
func TestGetAdmitsBeforeStoredRunRead(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := storedRunReadService(journal, func(context.Context, database.AccessContext, string, string) (Run, error) {
		journal.order = append(journal.order, "read")
		return Run{ID: testStoredRunID, Answer: "stored answer"}, nil
	})

	got, err := service.Get(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, testStoredRunID)
	if err != nil {
		t.Fatalf("Get = %v, want nil", err)
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "read" {
		t.Fatalf("execution order = %v, want admission strictly before the governed read", journal.order)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("appended = %#v, want exactly one question.run.admitted admission", journal.appended)
	}
	if got.ID != testStoredRunID || got.Answer != "stored answer" {
		t.Fatalf("Get result = %#v, want the stored answer", got)
	}
}

// TestGetAdmissionFailureFailsClosedBeforeAnyRead proves a failed admission
// makes Get fail closed with the typed unavailable error, without running the
// governed read, without returning a partial result and without leaving an
// outcome event behind.
func TestGetAdmissionFailureFailsClosedBeforeAnyRead(t *testing.T) {
	journal := &failingRecordingAdmissionJournal{}
	service := storedRunReadService(journal, func(context.Context, database.AccessContext, string, string) (Run, error) {
		t.Fatal("governed read ran after the admission append failed")
		return Run{}, nil
	})

	got, err := service.Get(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, testStoredRunID)
	if err == nil {
		t.Fatal("Get with a failed admission = nil, want the audit failure")
	}
	if CodeOf(err) != CodeUnavailable {
		t.Fatalf("admission failure code = %q, want %q", CodeOf(err), CodeUnavailable)
	}
	if !errors.Is(err, errInjectedAdmissionFailure) {
		t.Fatalf("admission failure must retain the journal error, got %v", err)
	}
	if got.ID != "" || got.Answer != "" || len(got.Citations) != 0 || got.FailureCode != "" {
		t.Fatalf("admission failure leaked a partial result: %#v", got)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("append attempts = %#v, want only the failed admission and no outcome", journal.appended)
	}
}

// TestGetAdmissionRecordsActorKindAndAccessDecision proves the admission
// persisted by Get itself records the effective actor kind (HUMAN | SERVICE)
// and the access decision (SUCCESS = admitted) for both actor kinds.
func TestGetAdmissionRecordsActorKindAndAccessDecision(t *testing.T) {
	for name, testCase := range map[string]struct {
		kind database.ActorKind
		want audit.ActorType
	}{
		"human":   {database.ActorKindHuman, audit.ActorHuman},
		"service": {database.ActorKindService, audit.ActorService},
	} {
		t.Run(name, func(t *testing.T) {
			journal := &recordingAdmissionJournal{}
			service := storedRunReadService(journal, func(context.Context, database.AccessContext, string, string) (Run, error) {
				return Run{ID: testStoredRunID}, nil
			})
			if _, err := service.Get(context.Background(), questionAccess(testCase.kind), testStoredRunWorkspace, testStoredRunID); err != nil {
				t.Fatalf("Get = %v, want nil", err)
			}
			if len(journal.appended) != 1 {
				t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
			}
			admission := journal.appended[0]
			if admission.ActorType != testCase.want {
				t.Fatalf("admission actor_type = %q, want %q", admission.ActorType, testCase.want)
			}
			if admission.Action != audit.ActionQuestionRunAdmitted || admission.Outcome != audit.OutcomeSuccess || admission.ErrorCode != nil {
				t.Fatalf("admission = %#v, want question.run.admitted SUCCESS with no error", admission)
			}
			if admission.ResourceType != audit.ResourceWorkspace || admission.ResourceID != testStoredRunWorkspace {
				t.Fatalf("admission resource = %q/%q, want WORKSPACE/%s", admission.ResourceType, admission.ResourceID, testStoredRunWorkspace)
			}
			if admission.Metadata.QuestionRunID == nil || *admission.Metadata.QuestionRunID != testStoredRunID {
				t.Fatalf("admission question run metadata = %v, want %s", admission.Metadata.QuestionRunID, testStoredRunID)
			}
			if _, err := audit.Build("org_0001", admission, 0, ""); err != nil {
				t.Fatalf("admission event is not a valid registered audit event: %v", err)
			}
		})
	}
}

// TestGetReadFailureAfterAdmissionLeavesFailureOutcome proves a stored-run read
// failure after admission leaves the admission plus a matching failure outcome,
// never the admission alone, and no partial result.
func TestGetReadFailureAfterAdmissionLeavesFailureOutcome(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := storedRunReadService(journal, func(context.Context, database.AccessContext, string, string) (Run, error) {
		journal.order = append(journal.order, "read")
		return Run{ID: testStoredRunID, Answer: "must not leak"}, &Error{code: CodeUnavailable, cause: errors.New("injected: read failed")}
	})

	got, err := service.Get(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, testStoredRunID)
	if err == nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("Get after a read failure = %v, want the typed unavailable error", err)
	}
	if got.ID != "" || got.Answer != "" || len(got.Citations) != 0 {
		t.Fatalf("read failure leaked a partial result: %#v", got)
	}
	if len(journal.order) != 3 || journal.order[0] != "admission" || journal.order[1] != "read" || journal.order[2] != "outcome" {
		t.Fatalf("execution order = %v, want admission, read, then the failure outcome", journal.order)
	}
	if len(journal.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(journal.appended))
	}
	if journal.appended[0].Action != audit.ActionQuestionRunAdmitted || journal.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("first event = %#v, want a successful admission", journal.appended[0])
	}
	failure := journal.appended[1]
	if failure.Action != audit.ActionQuestionFailed || failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil {
		t.Fatalf("second event = %#v, want a failed question outcome with an error code", failure)
	}
	if *failure.ErrorCode != "QUESTION_READ_FAILED" {
		t.Fatalf("failure error code = %q, want QUESTION_READ_FAILED", *failure.ErrorCode)
	}
}

// TestGetRevokedAfterAdmissionReturnsNoData is the revoke-race probe: an actor
// whose access is revoked after the admission is committed gets no data from
// the governed read, and the journal keeps the admission plus the matching
// failure outcome.
func TestGetRevokedAfterAdmissionReturnsNoData(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := storedRunReadService(journal, func(context.Context, database.AccessContext, string, string) (Run, error) {
		journal.order = append(journal.order, "read")
		// The revocation committed before the access point: the read itself
		// re-checks readability and refuses to disclose the stored run.
		return Run{}, &Error{code: CodeNotFound}
	})

	got, err := service.Get(context.Background(), questionAccess(database.ActorKindService), testStoredRunWorkspace, testStoredRunID)
	if err == nil || CodeOf(err) != CodeNotFound {
		t.Fatalf("Get after revocation = %v, want the typed not-found refusal", err)
	}
	if got.ID != "" || got.Answer != "" || len(got.Citations) != 0 {
		t.Fatalf("revoked read leaked data: %#v", got)
	}
	if len(journal.order) != 3 || journal.order[0] != "admission" || journal.order[1] != "read" || journal.order[2] != "outcome" {
		t.Fatalf("execution order = %v, want admission, refused read, then the failure outcome", journal.order)
	}
	if len(journal.appended) != 2 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("appended events = %#v, want admission + failure outcome", journal.appended)
	}
	failure := journal.appended[1]
	if failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil || *failure.ErrorCode != "QUESTION_READ_DENIED" {
		t.Fatalf("failure outcome = %#v, want FAILED with QUESTION_READ_DENIED", failure)
	}
}

// TestGetBatchAdmitsBeforeStoredRunRead proves GetBatch itself persists one
// admission event before the batched governed read runs.
func TestGetBatchAdmitsBeforeStoredRunRead(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := storedRunBatchReadService(journal, func(context.Context, database.AccessContext, string, []string) (map[string]Run, error) {
		journal.order = append(journal.order, "read")
		return map[string]Run{testStoredRunID: {ID: testStoredRunID, Answer: "stored answer"}}, nil
	})

	got, err := service.GetBatch(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, []string{testStoredRunID})
	if err != nil {
		t.Fatalf("GetBatch = %v, want nil", err)
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "read" {
		t.Fatalf("execution order = %v, want admission strictly before the batched read", journal.order)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("appended = %#v, want exactly one question.run.admitted admission", journal.appended)
	}
	if got[testStoredRunID].Answer != "stored answer" {
		t.Fatalf("GetBatch result = %#v, want the stored answer", got)
	}
}

// TestGetBatchAdmissionFailureFailsClosedBeforeAnyRead proves a failed
// admission makes GetBatch return no rows at all, without running the batched
// governed read and without leaving an outcome behind.
func TestGetBatchAdmissionFailureFailsClosedBeforeAnyRead(t *testing.T) {
	journal := &failingRecordingAdmissionJournal{}
	service := storedRunBatchReadService(journal, func(context.Context, database.AccessContext, string, []string) (map[string]Run, error) {
		t.Fatal("batched governed read ran after the admission append failed")
		return nil, nil
	})

	got, err := service.GetBatch(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, []string{testStoredRunID})
	if err == nil {
		t.Fatal("GetBatch with a failed admission = nil, want the audit failure")
	}
	if CodeOf(err) != CodeUnavailable || !errors.Is(err, errInjectedAdmissionFailure) {
		t.Fatalf("admission failure = %v, want the typed unavailable error wrapping the journal error", err)
	}
	if len(got) != 0 {
		t.Fatalf("admission failure returned rows: %#v", got)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("append attempts = %#v, want only the failed admission and no outcome", journal.appended)
	}
}

// TestGetBatchReadFailureAfterAdmissionLeavesFailureOutcome proves a batched
// read failure after admission leaves the admission plus a matching failure
// outcome, never the admission alone.
func TestGetBatchReadFailureAfterAdmissionLeavesFailureOutcome(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := storedRunBatchReadService(journal, func(context.Context, database.AccessContext, string, []string) (map[string]Run, error) {
		journal.order = append(journal.order, "read")
		return map[string]Run{testStoredRunID: {ID: testStoredRunID, Answer: "must not leak"}}, &Error{code: CodeUnavailable, cause: errors.New("injected: batched read failed")}
	})

	got, err := service.GetBatch(context.Background(), questionAccess(database.ActorKindHuman), testStoredRunWorkspace, []string{testStoredRunID})
	if err == nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("GetBatch after a read failure = %v, want the typed unavailable error", err)
	}
	if len(got) != 0 {
		t.Fatalf("read failure leaked rows: %#v", got)
	}
	if len(journal.order) != 3 || journal.order[0] != "admission" || journal.order[1] != "read" || journal.order[2] != "outcome" {
		t.Fatalf("execution order = %v, want admission, read, then the failure outcome", journal.order)
	}
	if len(journal.appended) != 2 || journal.appended[0].Action != audit.ActionQuestionRunAdmitted {
		t.Fatalf("appended events = %#v, want admission + failure outcome", journal.appended)
	}
	if failure := journal.appended[1]; failure.Action != audit.ActionQuestionFailed || failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil {
		t.Fatalf("failure outcome = %#v, want a failed question outcome", failure)
	}
}

const (
	testRowsetWorkspace = "ws_0001"
	testRowsetFragment  = "frag_0001"
)

// structuredRowsetReadService replaces StructuredRowset's governed read with
// the supplied seam so StructuredRowset itself can be driven without a
// database, exactly as storedRunReadService drives Get.
func structuredRowsetReadService(journal admissionJournal, read func(context.Context, database.AccessContext, string, string, string) (*RowsetEvidence, error)) *Service {
	service := testCreateService(journal)
	service.structuredRowsetReadFn = read
	return service
}

// TestStructuredRowsetAdmitsBeforeGovernedRead proves that StructuredRowset
// itself persists the admission event before its first governed read runs, and
// that the successful read result is returned unchanged.
func TestStructuredRowsetAdmitsBeforeGovernedRead(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	want := &RowsetEvidence{Columns: []string{"note"}, Rows: []map[string]string{{"note": "target-note"}}, Total: 1, FilterLabel: "note = target-note"}
	service := structuredRowsetReadService(journal, func(context.Context, database.AccessContext, string, string, string) (*RowsetEvidence, error) {
		journal.order = append(journal.order, "read")
		return want, nil
	})

	got, err := service.StructuredRowset(context.Background(), questionAccess(database.ActorKindHuman), testRowsetWorkspace, testRowsetFragment, "")
	if err != nil {
		t.Fatalf("StructuredRowset = %v, want nil", err)
	}
	if len(journal.order) != 2 || journal.order[0] != "admission" || journal.order[1] != "read" {
		t.Fatalf("execution order = %v, want admission strictly before the governed read", journal.order)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionEvidenceReadAdmitted || journal.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("appended = %#v, want exactly one evidence.read.admitted SUCCESS admission", journal.appended)
	}
	if got == nil || got.Total != want.Total || got.Columns[0] != "note" || got.Rows[0]["note"] != "target-note" {
		t.Fatalf("rowset = %#v, want the read result %#v", got, want)
	}
}

// TestStructuredRowsetAdmissionFailureFailsClosedBeforeAnyRead proves a failed
// admission makes StructuredRowset fail closed with the typed unavailable error
// wrapping the journal error, without running the governed read, without
// returning any rowset or row, and without leaving an outcome behind.
func TestStructuredRowsetAdmissionFailureFailsClosedBeforeAnyRead(t *testing.T) {
	journal := &failingRecordingAdmissionJournal{}
	service := structuredRowsetReadService(journal, func(context.Context, database.AccessContext, string, string, string) (*RowsetEvidence, error) {
		t.Fatal("governed rowset read ran after the admission append failed")
		return nil, nil
	})

	got, err := service.StructuredRowset(context.Background(), questionAccess(database.ActorKindHuman), testRowsetWorkspace, testRowsetFragment, "")
	if err == nil {
		t.Fatal("StructuredRowset with a failed admission = nil, want the audit failure")
	}
	if CodeOf(err) != CodeUnavailable || !errors.Is(err, errInjectedAdmissionFailure) {
		t.Fatalf("admission failure = %v, want the typed unavailable error wrapping the journal error", err)
	}
	if got != nil {
		t.Fatalf("admission failure returned a rowset: %#v", got)
	}
	if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionEvidenceReadAdmitted {
		t.Fatalf("append attempts = %#v, want only the failed admission and no outcome", journal.appended)
	}
}

// TestStructuredRowsetAdmissionRecordsActorKindAndAccessDecision proves the
// admission persisted by StructuredRowset itself records the effective actor
// kind (HUMAN | SERVICE) and the access decision (SUCCESS = admitted), names
// the workspace and the cited evidence fragment, and is a valid registered
// audit event.
func TestStructuredRowsetAdmissionRecordsActorKindAndAccessDecision(t *testing.T) {
	for name, testCase := range map[string]struct {
		kind database.ActorKind
		want audit.ActorType
	}{
		"human":   {database.ActorKindHuman, audit.ActorHuman},
		"service": {database.ActorKindService, audit.ActorService},
	} {
		t.Run(name, func(t *testing.T) {
			journal := &recordingAdmissionJournal{}
			service := structuredRowsetReadService(journal, func(context.Context, database.AccessContext, string, string, string) (*RowsetEvidence, error) {
				return &RowsetEvidence{Total: 1}, nil
			})
			if _, err := service.StructuredRowset(context.Background(), questionAccess(testCase.kind), testRowsetWorkspace, testRowsetFragment, ""); err != nil {
				t.Fatalf("StructuredRowset = %v, want nil", err)
			}
			if len(journal.appended) != 1 {
				t.Fatalf("admission events appended = %d, want exactly one", len(journal.appended))
			}
			admission := journal.appended[0]
			if admission.ActorType != testCase.want {
				t.Fatalf("admission actor_type = %q, want %q", admission.ActorType, testCase.want)
			}
			if admission.Action != audit.ActionEvidenceReadAdmitted || admission.Outcome != audit.OutcomeSuccess || admission.ErrorCode != nil {
				t.Fatalf("admission = %#v, want evidence.read.admitted SUCCESS with no error", admission)
			}
			if admission.ResourceType != audit.ResourceCitation || admission.ResourceID != testRowsetFragment {
				t.Fatalf("admission resource = %q/%q, want CITATION/%s", admission.ResourceType, admission.ResourceID, testRowsetFragment)
			}
			if admission.WorkspaceID == nil || *admission.WorkspaceID != testRowsetWorkspace {
				t.Fatalf("admission workspace = %v, want %s", admission.WorkspaceID, testRowsetWorkspace)
			}
			if len(admission.ReferencedEvidenceIDs) != 1 || admission.ReferencedEvidenceIDs[0] != testRowsetFragment {
				t.Fatalf("admission referenced evidence = %#v, want [%s]", admission.ReferencedEvidenceIDs, testRowsetFragment)
			}
			if _, err := audit.Build("org_0001", admission, 0, ""); err != nil {
				t.Fatalf("admission event is not a valid registered audit event: %v", err)
			}
		})
	}
}

// TestStructuredRowsetReadFailureAfterAdmissionLeavesFailureOutcome proves a
// governed rowset read failure after admission leaves the admission plus a
// matching failure outcome, never the admission alone, and no partial rowset.
func TestStructuredRowsetReadFailureAfterAdmissionLeavesFailureOutcome(t *testing.T) {
	journal := &recordingAdmissionJournal{}
	service := structuredRowsetReadService(journal, func(context.Context, database.AccessContext, string, string, string) (*RowsetEvidence, error) {
		journal.order = append(journal.order, "read")
		return &RowsetEvidence{Total: 3}, &Error{code: CodeUnavailable, cause: errors.New("injected: rowset read failed")}
	})

	got, err := service.StructuredRowset(context.Background(), questionAccess(database.ActorKindHuman), testRowsetWorkspace, testRowsetFragment, "")
	if err == nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("StructuredRowset after a read failure = %v, want the typed unavailable error", err)
	}
	if got != nil {
		t.Fatalf("read failure leaked a rowset: %#v", got)
	}
	if len(journal.order) != 3 || journal.order[0] != "admission" || journal.order[1] != "read" || journal.order[2] != "outcome" {
		t.Fatalf("execution order = %v, want admission, read, then the failure outcome", journal.order)
	}
	if len(journal.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(journal.appended))
	}
	if journal.appended[0].Action != audit.ActionEvidenceReadAdmitted || journal.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("first event = %#v, want a successful admission", journal.appended[0])
	}
	failure := journal.appended[1]
	if failure.Action != audit.ActionEvidenceReadFailed || failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil {
		t.Fatalf("second event = %#v, want a failed evidence-read outcome with an error code", failure)
	}
	if *failure.ErrorCode != rowsetReadFailureCode {
		t.Fatalf("failure error code = %q, want %q", *failure.ErrorCode, rowsetReadFailureCode)
	}
}

// TestReadStructuredRowsetDistinguishesReadFailureFromMissingCell drives the
// real readStructuredRowset (not the structuredRowsetReadFn seam) and proves
// F1: a genuine governed-read/transaction failure -- the fragment cell lookup
// itself or loadStructuredSnapshot -- is returned as a non-nil error so
// StructuredRowset leaves the admission plus its matching failure outcome,
// while only a missing structured cell (the question-local
// errStructuredCellAbsent sentinel) yields an empty rowset with no failure
// outcome.
func TestReadStructuredRowsetDistinguishesReadFailureFromMissingCell(t *testing.T) {
	// A zero *database.Store has no pool, so its governed Read fails with the
	// typed transaction error: a real db.Read failure reached through the
	// production read path.
	run := func(t *testing.T, cell func(context.Context, database.AccessContext, string, string) (string, error)) (*RowsetEvidence, error, *recordingAdmissionJournal) {
		t.Helper()
		journal := &recordingAdmissionJournal{}
		service := testCreateService(journal)
		service.structuredRowsetCellFn = cell
		got, err := service.StructuredRowset(context.Background(), questionAccess(database.ActorKindHuman), testRowsetWorkspace, testRowsetFragment, "")
		return got, err, journal
	}

	t.Run("injected governed read failure", func(t *testing.T) {
		injected := errors.New("injected: governed rowset cell read failed")
		got, err, journal := run(t, func(context.Context, database.AccessContext, string, string) (string, error) {
			return "", injected
		})
		if err == nil || !errors.Is(err, injected) {
			t.Fatalf("StructuredRowset after an injected governed read failure = %v, want the injected error", err)
		}
		if got != nil {
			t.Fatalf("injected read failure leaked a rowset: %#v", got)
		}
		assertRowsetAdmissionThenFailure(t, journal)
	})

	t.Run("governed cell read failure", func(t *testing.T) {
		got, err, journal := run(t, nil)
		if err == nil {
			t.Fatal("StructuredRowset after a governed cell-read failure = nil, want the read error")
		}
		if got != nil {
			t.Fatalf("read failure leaked a rowset: %#v", got)
		}
		assertRowsetAdmissionThenFailure(t, journal)
	})

	t.Run("snapshot load failure after cell resolution", func(t *testing.T) {
		got, err, journal := run(t, func(context.Context, database.AccessContext, string, string) (string, error) {
			return "sv_0001", nil
		})
		if err == nil {
			t.Fatal("StructuredRowset after a loadStructuredSnapshot failure = nil, want the read error")
		}
		if got != nil {
			t.Fatalf("load failure leaked a rowset: %#v", got)
		}
		assertRowsetAdmissionThenFailure(t, journal)
	})

	t.Run("missing structured cell", func(t *testing.T) {
		got, err, journal := run(t, func(context.Context, database.AccessContext, string, string) (string, error) {
			return "", errStructuredCellAbsent
		})
		if err != nil {
			t.Fatalf("missing structured cell = %v, want nil", err)
		}
		if got != nil {
			t.Fatalf("missing structured cell returned a rowset: %#v", got)
		}
		if len(journal.order) != 1 || journal.order[0] != "admission" {
			t.Fatalf("execution order = %v, want only the admission", journal.order)
		}
		if len(journal.appended) != 1 || journal.appended[0].Action != audit.ActionEvidenceReadAdmitted || journal.appended[0].Outcome != audit.OutcomeSuccess {
			t.Fatalf("appended = %#v, want exactly the admission and no failure outcome", journal.appended)
		}
	})
}

// assertRowsetAdmissionThenFailure asserts the journal holds exactly the
// admission followed by one matching content-free failure outcome.
func assertRowsetAdmissionThenFailure(t *testing.T, journal *recordingAdmissionJournal) {
	t.Helper()
	if len(journal.appended) != 2 {
		t.Fatalf("appended events = %d, want admission + failure outcome", len(journal.appended))
	}
	if journal.appended[0].Action != audit.ActionEvidenceReadAdmitted || journal.appended[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("first event = %#v, want a successful admission", journal.appended[0])
	}
	failure := journal.appended[1]
	if failure.Action != audit.ActionEvidenceReadFailed || failure.Outcome != audit.OutcomeFailed || failure.ErrorCode == nil {
		t.Fatalf("second event = %#v, want a failed evidence-read outcome with an error code", failure)
	}
	if *failure.ErrorCode != rowsetReadFailureCode {
		t.Fatalf("failure error code = %q, want %q", *failure.ErrorCode, rowsetReadFailureCode)
	}
}
