// Package question owns the live, deterministic Question Run authority.
//
// The first production slice is intentionally extractive: it selects
// authorized Evidence fragments, projects exact sentence bytes and persists
// every question/answer/citation payload through the encrypted-artifact owner
// boundary. No model, arbitrary SQL or client-selected source filter is
// accepted here. HTTP and MCP adapters call this package rather than
// implementing a second answer path; conversation ids are opaque bindings,
// never a prompt-memory channel.
package question

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	maxQuestionBytes = 32 << 10
	maxCandidates    = 64
	maxCitations     = 8
	// A grouped aggregate may need one metric Evidence per row plus one group
	// witness per bucket. Keep the ordinary extractive answer budget small, but
	// let the typed reducer disclose every Evidence reference required to prove
	// a bounded aggregate instead of failing after the tool has succeeded.
	maxAggregateCitations         = maxCandidates
	maxSignalItems                = 32
	maxSignalEvidence             = 256
	maxSafeGeneration             = int64(9007199254740991)
	questionFailureCleanupTimeout = 5 * time.Second
	// Keep the whole GENERATIVE request below the external 180-second proxy
	// ceiling while retaining the existing detached failure cleanup window.
	// This service-owned bound is independent of the adapter's per-attempt
	// timeout and retry count.
	generativeQuestionRunBudget = 170 * time.Second
	// Model-attempt persistence gets one short context per callback. It keeps
	// content-free attempt provenance durable when the 170-second run context
	// expires while leaving the request budget unchanged.
	modelAttemptPersistenceTimeout = 5 * time.Second
	answerMode                     = "EXTRACTIVE"
	verification                   = "BYTE_EXACT_CITATION"

	// GEN-1 (ADR-0088): a bounded, capability-gated interim GENERATIVE mode.
	// It is accepted only when a Model Gateway adapter and claim verifier are
	// explicitly wired (Service.EnableGeneration); otherwise CodeUnsupportedMode
	// is returned before any run is created, exactly like a missing embedding
	// mount keeps hybrid retrieval an explicit partial rather than a silent
	// downgrade.
	answerModeGenerative         = "GENERATIVE"
	verificationSemanticVerifier = "SEMANTIC_VERIFIER"
	// generationMaxOutputTokens is calibrated against the acc stand's real
	// GEN-2 endpoint (deepseek-v4-flash, a reasoning model whose hidden
	// chain-of-thought consumes output tokens before any answer content is
	// emitted): a live multi-Evidence-fragment attempt needed anywhere from
	// ~130 to over 4,000 completion tokens end-to-end depending on question
	// ambiguity to reach finish_reason "stop", and a 1,024- or 4,096-token
	// budget measurably truncated mid-reasoning (finish_reason "length",
	// empty answer content) on realistic prompts. 32,768 matches the
	// adapter's own independent labMaxOutputTokens ceiling
	// (internal/modelgateway/lab_adapter.go), the most headroom this interim
	// path currently allows.
	// maxGenerativeAttempts bounds one GENERATIVE run's total model attempts,
	// matching db/migrations/000060's attempt_number CHECK (1..2).
	maxGenerativeAttempts     = 2
	generationMaxOutputTokens = 32768
	generationFallbackAnswer  = "Model answer generation is unavailable for this request. Repeat the question in EXTRACTIVE mode."
	// The interim generator emits only Evidence-backed FACT claims. Keeping one
	// claim variant removes nullable UNKNOWN and claim-graph combinations that
	// the external JSON-object endpoint does not enforce itself. The semantic
	// verifier still approves every claim before disclosure; unsupported text
	// therefore fails closed instead of becoming an uncited answer.
	generationSystemInstructions = "Answer the user's question using only the text of the supplied Evidence fragments. " +
		"Create only claims with kind=FACT. Each claim must have a nonempty text string, unknown_reason exactly null, " +
		"evidence_ids as a nonempty array of exact evidence_id values from the input Evidence array, and supporting_claim_ids exactly []. " +
		"Each claim must belong to exactly one section through ordered_claim_ids. Do not create INFERENCE or UNKNOWN claims. " +
		"Do not use any information outside the supplied fragments. " +
		"Keep each claim's text concise: one or two sentences on one line, without line breaks, tabs, or control characters. " +
		"Represent each separate step as a separate claim. Do not include headings, citation numbers, or document markup inside text. " +
		"Compare the conditions under which claims from different fragments apply. If sources give different values for the same action " +
		"under the same conditions, explicitly describe the discrepancy as a fact about the source contents, state both values, and include the evidence_ids of both fragments. " +
		"Do not prioritize a source without explicit support in Evidence, and do not combine incompatible requirements into one instruction. " +
		"Different actions, reference periods, or conditions do not by themselves constitute a contradiction. " +
		"The response must be strictly a ClaimPlan JSON object with no other text."
	generationOutputSchema = `{"type":"object","required":["schema_version","claims","sections"],"properties":{` +
		`"schema_version":{"const":"1.4"},` +
		`"claims":{"type":"array","minItems":1,"maxItems":40,"items":{"type":"object","required":["claim_id","text","kind","unknown_reason","evidence_ids","supporting_claim_ids"],` +
		`"additionalProperties":false,"properties":{"claim_id":{"type":"string","pattern":"^C[1-9][0-9]*$"},"text":{"type":"string","minLength":1,"pattern":"^[^\\x00-\\x1f\\x7f-\\x9f]+$"},"kind":{"const":"FACT"},` +
		`"unknown_reason":{"type":"null"},"evidence_ids":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"string"}},` +
		`"supporting_claim_ids":{"type":"array","maxItems":0}}}},` +
		`"sections":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"object","required":["section_id","title","ordered_claim_ids"],` +
		`"additionalProperties":false,"properties":{"section_id":{"type":"string","pattern":"^S[1-9][0-9]*$"},"title":{"type":["string","null"]},` +
		`"ordered_claim_ids":{"type":"array","minItems":1,"items":{"type":"string"}}}}}},"additionalProperties":false}`
)

// ErrorCode is the stable content-free vocabulary exposed to transport code.
type ErrorCode string

const (
	CodeInvalid             ErrorCode = "QUESTION_REQUEST_INVALID"
	CodeDenied              ErrorCode = "QUESTION_DENIED"
	CodeNotFound            ErrorCode = "QUESTION_NOT_FOUND"
	CodeIdempotencyConflict ErrorCode = "QUESTION_IDEMPOTENCY_CONFLICT"
	CodeUnsupportedMode     ErrorCode = "QUESTION_MODE_UNSUPPORTED"
	CodeUnavailable         ErrorCode = "QUESTION_UNAVAILABLE"
)

// Error never includes question text, source content, a locator or a database
// error. The cause is retained only for trusted in-process diagnostics.
type Error struct {
	code  ErrorCode
	cause error
	// clarification is R2 Outcome 2's server-owned, content-free text for a
	// typed refusal whose reason is safe to show a human (for example a
	// structured-execution capability that is not mounted). It is never
	// persisted and never carries model, source or definition content; a
	// QueryIntent validator refusal instead travels as the wrapped cause, so
	// queryintent.ClarificationOf can read the package's closed dictionary.
	clarification string
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// Clarification is the server-owned clarification text carried by this
// refusal, or "" when it carries none. A queryintent refusal is exposed through
// package-level ClarificationOf instead.
func (e *Error) Clarification() string { return e.clarification }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// CreateRequest is the server-owned Question Run command. The idempotency key
// is already validated by the transport but is checked again here because the
// authority must remain safe for non-HTTP adapters.
type CreateRequest struct {
	WorkspaceID string
	// ConversationID is optional for the first turn. When omitted, the
	// authority creates a new conversation and binds its first turn to the
	// Question Run in the same transaction. FIX-1 #4: the ONLY memory this
	// authority ever derives from it is a bare period follow-up ("and yesterday?")
	// spliced onto the immediately preceding turn's own literal question
	// text (planner.PeriodFollowUp/SpliceFollowUpPeriod in Create) -- never
	// a free-form recollection of prior model output, and every hop still
	// re-verifies current access before reusing anything.
	ConversationID string
	Question       string
	AnswerMode     string
	ModelProfileID string
	IdempotencyKey string
}

// Citation is the disclosed, current-access-checked citation card.
type Citation struct {
	Address          string `json:"address,omitempty"`
	Number           int64  `json:"number"`
	CitationID       string `json:"citation_id"`
	EvidenceFragment string `json:"evidence_fragment_id"`
	Excerpt          string `json:"excerpt"`
	Anchor           string `json:"anchor"`
	DeepLink         string `json:"deep_link"`
	SourceVersionID  string `json:"source_version_id"`
	ExtractionID     string `json:"extraction_id"`
	SourceObjectID   string `json:"source_object_id"`
	EvidenceTextHash string `json:"evidence_text_hash"`
	ExcerptHash      string `json:"excerpt_hash"`
	// R1 grounding projection. SourceQuote is present only when the excerpt is
	// an exact span of the stored extraction; GroundingStatus is the closed
	// CONFIRMED_BY_FRAGMENT|UNCONFIRMED vocabulary and defaults to UNCONFIRMED.
	// Both are additive: a citation from a run written before R1 decodes with a
	// nil quote and is reported unbound.
	SourceQuote     *SourceQuote    `json:"source_quote,omitempty"`
	GroundingStatus GroundingStatus `json:"grounding_status"`
}

// Uncertainty is a server-owned explanation for why a Question Run is not a
// complete, fully supported conclusion. It contains only stable reason codes
// and the Evidence IDs that informed the bounded decision; it never carries
// source text, SQL or model output.
type Uncertainty struct {
	Code        string   `json:"code"`
	EvidenceIDs []string `json:"evidence_ids"`
	// Message is a server-owned, closed-vocabulary Russian sentence derived
	// solely from Code (FIX-2 #6, uncertaintyMessage). It is never persisted
	// and never carries source text; it is recomputed on every read so the
	// dictionary can be extended without a migration.
	Message string `json:"message,omitempty"`
}

// Conflict is the transport-neutral shape for a contradiction detected by a
// future source/entity authority. Requiring concrete Evidence IDs prevents a
// client or model from publishing an ungrounded disagreement claim.
type Conflict struct {
	Code        string   `json:"code"`
	EvidenceIDs []string `json:"evidence_ids"`
	// Message mirrors Uncertainty.Message (FIX-2 #6, conflictMessage).
	Message string `json:"message,omitempty"`
}

// CorpusFreshness is the immutable freshness snapshot used by a Question Run.
// It describes the source state at the moment the run captured its corpus;
// callers can separately inspect the live source-status endpoint for a newer
// operational view. Timestamps are optional because an empty/never-synced
// source has no trustworthy successful-sync time.
type CorpusFreshness struct {
	State                string     `json:"state"`
	CapturedAt           *time.Time `json:"captured_at,omitempty"`
	LastSuccessfulSyncAt *time.Time `json:"last_successful_sync_at,omitempty"`
}

// Run is the transport-neutral persisted projection. Answer and question are
// present only after the current disclosure gate has passed. GroundingStatus is
// the R1 answer-level state exposed identically by REST and by MCP
// structuredContent (CONFIRMED_BY_FRAGMENT only when every claim is bound to a
// SOURCE_QUOTE, otherwise UNCONFIRMED); it is recomputed on read from the
// persisted per-citation states and never consults similarity.
type Run struct {
	ToolLoop           *ToolLoopRecord `json:"tool_loop,omitempty"`
	ModelProfile       *ModelProfile   `json:"model_profile,omitempty"`
	ID                 string          `json:"question_run_id"`
	WorkspaceID        string          `json:"workspace_id"`
	WorkspaceRevision  int64           `json:"workspace_revision"`
	ConversationID     string          `json:"conversation_id,omitempty"`
	ConversationTurnID string          `json:"conversation_turn_id,omitempty"`
	Question           string          `json:"question,omitempty"`
	AnswerMode         string          `json:"answer_mode"`
	VerificationMethod string          `json:"verification_method"`
	GroundingStatus    GroundingStatus `json:"grounding_status"`
	ResultStatus       string          `json:"status"`
	CorpusStatus       string          `json:"corpus_status"`
	Freshness          CorpusFreshness `json:"freshness"`
	StartedAt          time.Time       `json:"started_at"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	Answer             string          `json:"answer,omitempty"`
	AnswerHash         string          `json:"answer_hash,omitempty"`
	ContextPackHash    string          `json:"context_pack_hash,omitempty"`
	ManifestHash       string          `json:"manifest_hash,omitempty"`
	ManifestStatus     string          `json:"manifest_status"`
	Citations          []Citation      `json:"citations"`
	FailureCode        string          `json:"failure_code,omitempty"`
	PlanningStatus     string          `json:"planning_status"`
	PlanningOperation  string          `json:"planning_operation"`
	PlanningConfidence string          `json:"planning_confidence"`
	PlanHash           string          `json:"plan_hash,omitempty"`
	Clarification      string          `json:"clarification,omitempty"`
	Uncertainties      []Uncertainty   `json:"uncertainties"`
	Conflicts          []Conflict      `json:"conflicts"`
	// AnswerResult is FIX-2 #1's structured counterpart of an AGGREGATE/LIST
	// answer (populated only by answerStructuredAggregate); absent for every
	// other operation.
	AnswerResult *AnswerResult `json:"answer_result,omitempty"`
	// Understood is FIX-2 #2's account of a resolved bare period follow-up
	// ("Interpreted as"); absent unless Create actually spliced one.
	Understood *Understood `json:"understood,omitempty"`
	// Searched is FIX-2 #6's "where searched" list, populated only when this run
	// carries an INSUFFICIENT_EVIDENCE uncertainty.
	Searched []SearchedSource `json:"searched,omitempty"`
}

const (
	UncertaintyPlannerUnknown       = "PLANNER_UNKNOWN"
	UncertaintyPlannerClarification = "PLANNER_CLARIFICATION_REQUIRED"
	UncertaintyCorpusPartial        = "CORPUS_PARTIAL"
	UncertaintyInsufficientEvidence = "INSUFFICIENT_EVIDENCE"
	// UncertaintyAmbiguousStructuredSource is FIX-4 #1's third scope-
	// resolution outcome: more than one enabled structured source could
	// answer the plan and neither retrieval nor the declared name/column
	// tie-break resolved it. See snapshot_aggregate.go's
	// persistAmbiguousStructuredSourceRefusal for the answer text, which
	// names every candidate source (this code alone never does).
	UncertaintyAmbiguousStructuredSource = "AMBIGUOUS_STRUCTURED_SOURCE"
)

const (
	freshnessFresh    = "FRESH"
	freshnessStale    = "STALE"
	freshnessFailed   = "FAILED"
	freshnessUnknown  = "UNKNOWN"
	freshnessDisabled = "DISABLED"
)

// corpusFreshnessState reduces the immutable per-source health values to one
// conservative run-level state. Any untrusted/failed source dominates a
// healthy source so a response can never imply that the complete corpus was
// fresh when one of its inputs was not.
func corpusFreshnessState(snapshotCount int64, hasFailed, hasUnknown, hasStale, hasDisabled bool) string {
	if snapshotCount < 1 {
		return freshnessUnknown
	}
	if hasFailed {
		return freshnessFailed
	}
	if hasUnknown {
		return freshnessUnknown
	}
	if hasStale {
		return freshnessStale
	}
	if hasDisabled {
		return freshnessDisabled
	}
	return freshnessFresh
}

var signalCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

func (item Uncertainty) validate() error {
	if !signalCodePattern.MatchString(item.Code) || len(item.EvidenceIDs) > maxSignalEvidence {
		return errors.New("invalid question uncertainty")
	}
	seen := make(map[string]struct{}, len(item.EvidenceIDs))
	for _, id := range item.EvidenceIDs {
		if !validOpaque(id) {
			return errors.New("invalid uncertainty evidence id")
		}
		if _, exists := seen[id]; exists {
			return errors.New("duplicate uncertainty evidence id")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func (item Conflict) validate() error {
	if !signalCodePattern.MatchString(item.Code) || len(item.EvidenceIDs) < 2 || len(item.EvidenceIDs) > maxSignalEvidence {
		return errors.New("invalid question conflict")
	}
	seen := make(map[string]struct{}, len(item.EvidenceIDs))
	for _, id := range item.EvidenceIDs {
		if !validOpaque(id) {
			return errors.New("invalid conflict evidence id")
		}
		if _, exists := seen[id]; exists {
			return errors.New("duplicate conflict evidence id")
		}
		seen[id] = struct{}{}
	}
	return nil
}

func normalizeSignals(uncertainties []Uncertainty, conflicts []Conflict) ([]Uncertainty, []Conflict, error) {
	if len(uncertainties) > maxSignalItems || len(conflicts) > maxSignalItems {
		return nil, nil, errors.New("too many question signals")
	}
	copyUncertainties := make([]Uncertainty, len(uncertainties))
	for index, item := range uncertainties {
		if err := item.validate(); err != nil {
			return nil, nil, err
		}
		copyUncertainties[index] = Uncertainty{Code: item.Code, EvidenceIDs: append([]string(nil), item.EvidenceIDs...)}
		sort.Strings(copyUncertainties[index].EvidenceIDs)
	}
	copyConflicts := make([]Conflict, len(conflicts))
	for index, item := range conflicts {
		if err := item.validate(); err != nil {
			return nil, nil, err
		}
		copyConflicts[index] = Conflict{Code: item.Code, EvidenceIDs: append([]string(nil), item.EvidenceIDs...)}
		sort.Strings(copyConflicts[index].EvidenceIDs)
	}
	sort.Slice(copyUncertainties, func(i, j int) bool {
		if copyUncertainties[i].Code != copyUncertainties[j].Code {
			return copyUncertainties[i].Code < copyUncertainties[j].Code
		}
		return strings.Join(copyUncertainties[i].EvidenceIDs, "\x00") < strings.Join(copyUncertainties[j].EvidenceIDs, "\x00")
	})
	sort.Slice(copyConflicts, func(i, j int) bool {
		if copyConflicts[i].Code != copyConflicts[j].Code {
			return copyConflicts[i].Code < copyConflicts[j].Code
		}
		return strings.Join(copyConflicts[i].EvidenceIDs, "\x00") < strings.Join(copyConflicts[j].EvidenceIDs, "\x00")
	})
	return copyUncertainties, copyConflicts, nil
}

func signalEvidenceIDs(selected []candidate) []string {
	seen := make(map[string]struct{}, len(selected))
	for _, item := range selected {
		if validOpaque(item.ID) {
			seen[item.ID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > maxSignalEvidence {
		ids = ids[:maxSignalEvidence]
	}
	return ids
}

func deriveSignals(planned planner.Plan, selected []candidate, citations []Citation, partial bool) ([]Uncertainty, []Conflict, error) {
	uncertainties := make([]Uncertainty, 0, 3)
	switch planned.Status {
	case planner.UnknownStatus:
		uncertainties = append(uncertainties, Uncertainty{Code: UncertaintyPlannerUnknown})
	case planner.ClarifyStatus:
		uncertainties = append(uncertainties, Uncertainty{Code: UncertaintyPlannerClarification})
	}
	if partial && planned.Status == planner.Ready {
		// A partial corpus is the authoritative caveat carried beside a ready
		// answer (POKA_YOKE QRY-002). Keep one signal for the selected Evidence
		// set: the database contract forbids reusing an Evidence ID across two
		// uncertainty records, and emitting both CORPUS_PARTIAL and
		// INSUFFICIENT_EVIDENCE would otherwise make every mixed-corpus run fail
		// its terminal JSON check.
		uncertainties = append(uncertainties, Uncertainty{Code: UncertaintyCorpusPartial, EvidenceIDs: signalEvidenceIDs(selected)})
	} else if planned.Status == planner.Ready && len(citations) == 0 {
		uncertainties = append(uncertainties, Uncertainty{Code: UncertaintyInsufficientEvidence, EvidenceIDs: signalEvidenceIDs(selected)})
	}
	conflicts := make([]Conflict, 0)
	if planned.Operation == planner.Compare {
		conflicts = append(conflicts, compareConflicts(selected)...)
	}
	if planned.Operation == planner.Explain {
		conflicts = append(conflicts, explainConflicts(planned, selected)...)
	}
	if planned.Operation == planner.CodeTrace {
		conflicts = append(conflicts, codeTraceConflicts(planned, selected)...)
	}
	if planned.Operation == planner.Audit {
		conflicts = append(conflicts, auditConflicts(planned, selected)...)
	}
	return normalizeSignals(uncertainties, conflicts)
}

func marshalSignals(uncertainties []Uncertainty, conflicts []Conflict) ([]byte, []byte, error) {
	uncertainties, conflicts, err := normalizeSignals(uncertainties, conflicts)
	if err != nil {
		return nil, nil, err
	}
	uncertaintyJSON, err := jsonv2.Marshal(uncertainties)
	if err != nil {
		return nil, nil, err
	}
	conflictJSON, err := jsonv2.Marshal(conflicts)
	if err != nil {
		return nil, nil, err
	}
	return uncertaintyJSON, conflictJSON, nil
}

func unmarshalSignals(uncertaintyJSON, conflictJSON []byte) ([]Uncertainty, []Conflict, error) {
	uncertainties := []Uncertainty{}
	conflicts := []Conflict{}
	if len(uncertaintyJSON) > 0 {
		if err := jsonv2.Unmarshal(uncertaintyJSON, &uncertainties, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
			return nil, nil, err
		}
	}
	if len(conflictJSON) > 0 {
		if err := jsonv2.Unmarshal(conflictJSON, &conflicts, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
			return nil, nil, err
		}
	}
	return normalizeSignals(uncertainties, conflicts)
}

// authorizationMemo is GetBatch's opt-in fast path for the per-artifact
// authorize closures below (runAuthorize/citationAuthorize). It never
// replaces the underlying app.question_run_readable check: GetBatch installs
// it into ctx only AFTER it has already run that exact check, in the SAME
// transaction/MVCC snapshot, for every run in readableRuns -- a cache HIT
// here is therefore not a weaker check, it is the identical deterministic
// result of a check GetBatch already paid for moments earlier. Any owning
// row absent from the maps (every caller other than GetBatch, since nothing
// else installs this into ctx) falls straight through to the original query,
// byte-for-byte unchanged. citationRuns maps a citation id to the run id
// GetBatch already resolved it to via its own citation-metadata query, so
// citationAuthorize never needs a fresh join to find that mapping.
type authorizationMemo struct {
	readableRuns map[string]bool
	citationRuns map[string]string
}

type authorizationMemoKey struct{}

func contextWithAuthorizationMemo(ctx context.Context, memo *authorizationMemo) context.Context {
	return context.WithValue(ctx, authorizationMemoKey{}, memo)
}

func authorizationMemoFrom(ctx context.Context) *authorizationMemo {
	memo, _ := ctx.Value(authorizationMemoKey{}).(*authorizationMemo)
	return memo
}

// GovernedAsk is the narrow, optional live-data capability available to the
// Question tool loop. Composition installs it only when ad hoc governed asks
// are mounted and enabled.
type GovernedAsk interface {
	AskWorkspace(ctx context.Context, access database.AccessContext, workspaceID, question string) (governedask.AskResult, error)
}

// Service is the single Question Run authority used by all adapters.
type Service struct {
	tools          workspacetools.Runtime
	db             *database.Store
	audit          *audit.Store
	admission      admissionJournal
	codec          *artifactcrypto.Codec
	evidence       *evidence.Viewer
	retrieval      *retrieval.Executor
	retrievalStore *retrieval.Repository
	planner        *planner.Planner
	artifacts      *artifactrepository.Repository
	now            func() time.Time
	newID          func(string) (string, error)

	// lookupIdempotencyFn and previousTurnQuestionFn are the two governed read
	// steps of Create. They are nil in production (where the real methods run)
	// and exist so the protected-independent unit tests can drive Create itself
	// and prove that the admission event is durable before any of these reads
	// execute, and that a failed admission fails closed without touching them.
	// They never widen scope: the real methods keep their own readability gate
	// at the access point.
	lookupIdempotencyFn    func(ctx context.Context, access database.AccessContext, key, requestHash, workspaceID string) (Run, bool, error)
	previousTurnQuestionFn func(ctx context.Context, access database.AccessContext, workspaceID, conversationID string) (string, string, error)
	// The named-model path proves workspace.ask before inspecting its mounted
	// catalogue. The test seam records admission/authorization order only.
	authorizeModelSelectionFn func(context.Context, database.AccessContext, string) error

	// storedRunReadFn and storedRunBatchReadFn are the governed read bodies of
	// Get and GetBatch. They are nil in production (where the real
	// readStoredRun/readStoredRunBatch methods run) and exist so the
	// protected-independent unit tests can drive Get/GetBatch themselves and
	// prove that the admission event is durable before any protected content is
	// fetched, that a failed admission fails closed with no rows, and that a
	// read which fails after admission leaves the matching failure outcome.
	// They never widen scope: the real methods keep their own readability gate
	// at the access point.
	storedRunReadFn      func(ctx context.Context, access database.AccessContext, workspaceID, runID string) (Run, error)
	storedRunBatchReadFn func(ctx context.Context, access database.AccessContext, workspaceID string, runIDs []string) (map[string]Run, error)

	// structuredRowsetReadFn is StructuredRowset's governed read body. It is
	// nil in production (where readStructuredRowset runs) and exists so the
	// protected-independent unit tests can drive StructuredRowset itself and
	// prove that the admission event is durable before any protected
	// structured cell, snapshot row or source-version content is fetched, that
	// a failed admission fails closed with no rowset, and that a read which
	// fails after admission leaves the matching failure outcome. It never
	// widens scope: readStructuredRowset keeps its own readability gates
	// (app.evidence_fragment_readable / app.question_run_readable) at every
	// access point.
	structuredRowsetReadFn func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, scope string) (*RowsetEvidence, error)

	// structuredRowsetCellFn is readStructuredRowset's first governed read (the
	// fragment's structured-snapshot cell lookup, which returns pgx.ErrNoRows
	// when the fragment has no such cell). It is nil in production (where the
	// real query runs) and exists so the protected-independent tests can drive
	// the real readStructuredRowset itself -- not just structuredRowsetReadFn
	// -- and prove that a genuine governed-read/transaction failure is returned
	// as an error while a missing cell is not. It never widens scope:
	// readStructuredRowsetCell keeps its own app.evidence_fragment_readable gate
	// at the access point.
	structuredRowsetCellFn func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (string, error)

	// generation and verifier back the GEN-1 (ADR-0088) interim GENERATIVE
	// mode. Both are nil unless EnableGeneration was called by composition
	// after a real capability mount was loaded; a nil pair keeps GENERATIVE
	// unsupported, never silently downgraded.
	generation         *modelgateway.LabAdapter
	verifier           *modelgateway.Verifier
	generationProfiles *modelgateway.ProfileRegistry

	// R2 Outcome 2: the server-validated QueryIntent gate. All three are nil
	// until composition calls EnableQueryIntents (intent_gate.go). Production
	// composition mounts a real, access-re-checked MetricDefinition catalog
	// plus the in-tree proposer (NewPlannerIntentProposer) and sealed-intent
	// executor (NewServiceIntentExecutor); a nil catalog leaves every
	// workspace on today's path verbatim, and a wired catalog with a nil
	// proposer or executor still fails closed for workspaces that have
	// APPROVED definitions rather than falling back to free-text planning.
	intentDefinitions MetricDefinitionLister
	intentProposer    QueryIntentProposer
	intentExecutor    QueryIntentExecutor

	// datasetProfileCatalog is the trusted, immutable analytic
	// DatasetProfile snapshot loaded by composition at startup
	// (internal/platform/analyticcatalog), and analyticSourceResolver is the
	// resolver bound to that exact snapshot and to the same concrete workspace
	// repository store (internal/analyticsource). Both are the zero value until
	// the single EnableDatasetProfileCatalog install sets them together; R1.1
	// stores them for the Question tool loop's optional analytic capability.
	//
	// analyticScalarExecutor is the one-shot executor that
	// installAnalyticScalarExecutor builds from that installed resolver and one
	// concrete authorized reader. It stays nil until that install succeeds.
	datasetProfileCatalog   analytic.DatasetProfileCatalog
	analyticSourceResolver  *analyticsource.Resolver
	analyticScalarExecutor  *analyticsource.ScalarExecutor
	liveDataAsk             GovernedAsk
	trustedMetricComparison TrustedMetricComparison
}

// EnableTrustedMetricComparison installs the optional approved comparison
// capability once. Its catalog is resolved for each authorized workspace run.
func (service *Service) EnableTrustedMetricComparison(compare TrustedMetricComparison) error {
	if service == nil || compare == nil || service.trustedMetricComparison != nil {
		return &Error{code: CodeInvalid}
	}
	value := reflect.ValueOf(compare)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return &Error{code: CodeInvalid}
	}
	service.trustedMetricComparison = compare
	return nil
}

// EnableGovernedAsk installs the optional connection-free live-data capability
// once, after composition has mounted and enabled ad hoc governed asks. A
// missing mount leaves the Question tool loop unchanged.
func (service *Service) EnableGovernedAsk(ask GovernedAsk) error {
	if service == nil || ask == nil || service.liveDataAsk != nil {
		return &Error{code: CodeInvalid}
	}
	value := reflect.ValueOf(ask)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return &Error{code: CodeInvalid}
	}
	service.liveDataAsk = ask
	return nil
}

// EnableDatasetProfileCatalog installs the startup-loaded, immutable analytic
// DatasetProfile catalog together with the resolver that re-reads current
// workspace authority and governed exposure for that exact catalog. It is a
// one-shot install: a nil Service, an invalid/zero catalog, a nil concrete
// store, a retained catalog slot that is not the exact Go zero value, a
// non-nil retained resolver, a non-nil retained scalar executor, or a resolver
// construction refusal returns a content-free CodeInvalid refusal, and a
// refused call leaves every slot exactly as it was.
func (service *Service) EnableDatasetProfileCatalog(catalog analytic.DatasetProfileCatalog, store *workspacerepository.Store) error {
	// The retained catalog carries a sealed entry slice, so it is not
	// Go-comparable: its emptiness is an explicit comparison against the zero
	// value. Valid() cannot stand in for that comparison because it is also
	// false for a non-zero invalid value, which must stay an occupied slot
	// instead of being overwritten.
	if service == nil || !catalog.Valid() || store == nil ||
		!reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) ||
		service.analyticSourceResolver != nil ||
		service.analyticScalarExecutor != nil {
		return &Error{code: CodeInvalid}
	}
	resolver, err := analyticsource.NewResolver(store, catalog)
	if err != nil {
		return &Error{code: CodeInvalid}
	}
	service.datasetProfileCatalog = catalog
	service.analyticSourceResolver = resolver
	return nil
}

// EnableGeneration wires the GEN-1 interim Model Gateway adapter and claim
// verifier. It is a no-op on a nil Service. Composition calls it only after
// modelgateway.LoadLabMountedConfig succeeded and a real embedding-backed
// Verifier was constructed; absent that, GENERATIVE stays unsupported.
func (service *Service) EnableGeneration(adapter *modelgateway.LabAdapter, verifier *modelgateway.Verifier) {
	if service == nil {
		return
	}
	service.generation = adapter
	service.verifier = verifier
}

// New constructs the authority and activates only the seven Question Run and
// citation owner branches installed by migration 000024.
func New(db *database.Store, auditStore *audit.Store, codec *artifactcrypto.Codec, viewer *evidence.Viewer) (*Service, error) {
	return NewWithRetrieval(db, auditStore, codec, viewer, nil)
}

// NewWithRetrieval composes the Question authority with the production
// OpenSearch-to-PostgreSQL post-authorization executor. A nil executor keeps
// the database-only qualification path available; production composition must
// pass a real executor after its startup gates.
func NewWithRetrieval(db *database.Store, auditStore *audit.Store, codec *artifactcrypto.Codec, viewer *evidence.Viewer, executor *retrieval.Executor) (*Service, error) {
	if db == nil || auditStore == nil || codec == nil || viewer == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	runAuthorize := func(ctx context.Context, tx database.Transaction, _ database.AccessContext, runID string) error {
		if memo := authorizationMemoFrom(ctx); memo != nil {
			if readable, known := memo.readableRuns[runID]; known {
				if readable {
					return nil
				}
				return errors.New("question run is not readable")
			}
		}
		var readable bool
		if err := tx.QueryRow(ctx, `
			SELECT app.question_run_readable(id, workspace_id)
			FROM public.question_run
			WHERE organization_id = app.current_organization_id() AND id = $1
		`, runID).Scan(&readable); err != nil || !readable {
			return errors.New("question run is not readable")
		}
		return nil
	}
	citationAuthorize := func(ctx context.Context, tx database.Transaction, _ database.AccessContext, citationID string) error {
		if memo := authorizationMemoFrom(ctx); memo != nil {
			if runID, known := memo.citationRuns[citationID]; known {
				if readable, runKnown := memo.readableRuns[runID]; runKnown {
					if readable {
						return nil
					}
					return errors.New("citation is not readable")
				}
			}
		}
		var readable bool
		if err := tx.QueryRow(ctx, `
			SELECT app.question_run_readable(run.id, run.workspace_id)
			FROM public.question_citation citation
			JOIN public.question_run run
			  ON run.organization_id = citation.organization_id AND run.id = citation.question_run_id
			WHERE citation.organization_id = app.current_organization_id() AND citation.id = $1
		`, citationID).Scan(&readable); err != nil || !readable {
			return errors.New("citation is not readable")
		}
		return nil
	}
	branches := []struct {
		field artifactcrypto.OwnerField
		bind  string
		read  string
		check artifactrepository.AuthorizeFunc
	}{
		{artifactcrypto.QuestionText, "app.question_run_bind_question_text", "app.question_run_read_question_text", runAuthorize},
		{artifactcrypto.AnswerMarkdown, "app.question_run_bind_answer_markdown", "app.question_run_read_answer_markdown", runAuthorize},
		{artifactcrypto.AnswerStructured, "app.question_run_bind_answer_structured", "app.question_run_read_answer_structured", runAuthorize},
		{artifactcrypto.QuestionManifestContent, "app.question_run_bind_manifest_content", "app.question_run_read_manifest_content", runAuthorize},
		{artifactcrypto.CitationCitedExcerpt, "app.question_citation_bind_cited_excerpt", "app.question_citation_read_cited_excerpt", citationAuthorize},
		{artifactcrypto.CitationAnchor, "app.question_citation_bind_anchor", "app.question_citation_read_anchor", citationAuthorize},
		{artifactcrypto.CitationDeepLink, "app.question_citation_bind_deep_link", "app.question_citation_read_deep_link", citationAuthorize},
	}
	bindings := make([]artifactrepository.Binding, 0, len(branches))
	for _, branch := range branches {
		binding, err := artifactrepository.NewBinding(branch.field, branch.bind, branch.read, branch.check)
		if err != nil {
			return nil, &Error{code: CodeUnavailable, cause: err}
		}
		bindings = append(bindings, binding)
	}
	repository, err := artifactrepository.New(bindings...)
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	retrievalStore, err := retrieval.NewRepository()
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	return &Service{db: db, audit: auditStore, admission: auditStore, codec: codec, evidence: viewer, retrieval: executor,
		retrievalStore: retrievalStore, planner: planner.New(), artifacts: repository, now: time.Now, newID: ids.New}, nil
}

// Create starts and completes one synchronous question run. The initial row
// and question artifact are committed before retrieval, so a process crash
// leaves a real RUNNING row that can be inspected/reconciled rather than a
// fabricated client-side progress state.
func (service *Service) Create(ctx context.Context, access database.AccessContext, request CreateRequest) (Run, error) {
	if service == nil || service.db == nil || service.audit == nil || service.codec == nil || service.artifacts == nil || service.retrievalStore == nil ||
		service.now == nil || service.newID == nil || access.Validate() != nil || !validOpaque(request.WorkspaceID) ||
		(request.ConversationID != "" && !validOpaque(request.ConversationID)) ||
		(request.ModelProfileID != "" && !ValidModelProfileID(request.ModelProfileID)) ||
		!validIdempotencyKey(request.IdempotencyKey) ||
		(request.AnswerMode != "" && request.AnswerMode != answerMode && request.AnswerMode != answerModeGenerative && request.AnswerMode != AnswerModeToolLoop) {
		return Run{}, &Error{code: CodeInvalid}
	}
	requestedMode := request.AnswerMode
	if request.ModelProfileID != "" {
		if requestedMode != "" && requestedMode != AnswerModeToolLoop {
			return Run{}, &Error{code: CodeInvalid}
		}
		requestedMode = AnswerModeToolLoop
	}
	if requestedMode == "" {
		requestedMode = service.DefaultAnswerMode(request.WorkspaceID)
	}
	var selectedGeneration generationSelection
	if requestedMode == AnswerModeToolLoop && request.ModelProfileID == "" {
		var selectionErr error
		selectedGeneration, selectionErr = service.selectGeneration(request.WorkspaceID, request.ModelProfileID)
		if selectionErr != nil {
			return Run{}, selectionErr
		}
	}
	if requestedMode == answerModeGenerative &&
		(service.generation == nil || service.verifier == nil || !service.generation.AllowsWorkspace(request.WorkspaceID)) {
		// GENERATIVE is a real, addressable capability, but it is off unless
		// composition wired a qualified mount. This is a clean typed rejection
		// before any run/idempotency row exists, matching ADR-0080 §2.5/§2.7
		// ("an unconfigured candidate has no readiness effect"). A workspace not
		// on the adapter's explicit external-runtime allow-list (GEN-2) gets the
		// exact same typed rejection as a fully absent mount — never a silent
		// downgrade to a different mode.
		return Run{}, &Error{code: CodeUnsupportedMode}
	}
	request.AnswerMode = requestedMode
	runCtx, cancel := questionRunContext(ctx, requestedMode)
	defer cancel()
	questionText, err := canonicalQuestion(request.Question)
	if err != nil {
		return Run{}, &Error{code: CodeInvalid}
	}
	// Outcome 2 (audit before data): allocate the run identity and persist the
	// single admission event before ANY governed read on this Create path. The
	// previous-turn memory read below, the idempotency replay lookup and its
	// governed run read, and the fresh-run start/execute/read-back all execute
	// only after this admission is durable -- including on the idempotent
	// replay fast path. The run-id metadata names the run identity allocated
	// for this admitted request; the stored run of a replay is resolved only
	// after admission. If the admission cannot be recorded the request fails
	// closed with the typed unavailable error and no answer, citation or row is
	// read or disclosed; the existing question.created / completed / failed
	// outcome events below are unchanged.
	runID, err := service.newID("qrun")
	if err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	conversationID := request.ConversationID
	if conversationID == "" {
		conversationID, err = service.newID("conv")
		if err != nil {
			return Run{}, &Error{code: CodeUnavailable, cause: err}
		}
	}
	conversationTurnID, err := service.newID("turn")
	if err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	if request.ModelProfileID != "" {
		var selectionErr error
		selectedGeneration, selectionErr = service.admitModelSelection(runCtx, access, request.WorkspaceID, runID, request.ModelProfileID)
		if selectionErr != nil {
			return Run{}, selectionErr
		}
	} else if err := service.emitAdmission(runCtx, access, request.WorkspaceID, runID); err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	if requestedMode == AnswerModeToolLoop {
		return service.createToolLoopRun(runCtx, access, request, questionText, runID, conversationID, conversationTurnID, selectedGeneration)
	}
	// FIX-1 #4: minimal topic memory. A bare period follow-up ("and yesterday?",
	// "and for the week?") carries no subject of its own to plan; splice it onto
	// the immediately preceding turn's own literal question (re-checking
	// current access to that turn -- never trusting the old binding) so the
	// combined question re-plans exactly like a fresh one that named its
	// period explicitly. Any failure to resolve a base question (no prior
	// turn, it is no longer readable, or its own period is already fixed)
	// leaves questionText untouched: ordinary planning/refusal applies, never
	// a guess.
	// FIX-6 #3: a meta-question about the conversation itself ("you said 3 but
	// showed 23", "why are the numbers different?") is never planned or executed like
	// an ordinary question -- it has no corpus to search, only this
	// authority's own last turns to compare. Detected before any follow-up
	// splice so it can never be mistaken for one.
	isMetaDialogueQuestion := request.ConversationID != "" && metaDialogueQuestionPattern.MatchString(questionText)
	if request.ConversationID != "" && !isMetaDialogueQuestion {
		if followUpFilter, isFollowUp := planner.PeriodFollowUp(questionText); isFollowUp {
			if baseQuestion, baseRunID, baseErr := service.previousTurnQuestionText(runCtx, access, request.WorkspaceID, request.ConversationID); baseErr == nil && baseQuestion != "" {
				if combined, spliced := planner.SpliceFollowUpPeriod(baseQuestion, followUpFilter); spliced {
					if canonicalCombined, canonErr := canonicalQuestion(combined); canonErr == nil {
						questionText = canonicalCombined
						// FIX-2 #2: report exactly what this splice resolved --
						// never more than SpliceFollowUpPeriod itself proved.
						if understood := service.buildUnderstood(runCtx, access, baseRunID, baseQuestion, followUpFilter.Name, followUpFilter.Value); understood != nil {
							runCtx = contextWithUnderstood(runCtx, understood)
						}
					}
				}
			}
		} else if function, isOpFollowUp := planner.AggregateFunctionFollowUp(questionText); isOpFollowUp {
			// FIX-6 #1: a bare operation-only follow-up ("which ones?" after "how many
			// vehicles are at work today?") inherits every condition (period,
			// filters, entity key) of the immediately preceding turn's own
			// question and changes only the requested reduction. The combined
			// plan is validated below (same Operation/Function requested) before
			// it is ever adopted -- any surprise from the splice leaves
			// questionText untouched, exactly like the period path above.
			if baseQuestion, baseRunID, baseErr := service.previousTurnQuestionText(runCtx, access, request.WorkspaceID, request.ConversationID); baseErr == nil && baseQuestion != "" {
				if combined, spliced := planner.SpliceFollowUpFunction(baseQuestion, function); spliced {
					if canonicalCombined, canonErr := canonicalQuestion(combined); canonErr == nil {
						if candidatePlan, candidateErr := service.planQuestion(canonicalCombined); candidateErr == nil &&
							candidatePlan.Operation == planner.Aggregate && candidatePlan.Aggregate != nil && candidatePlan.Aggregate.Function == function {
							questionText = canonicalCombined
							if understood := service.buildUnderstoodFollowUp(runCtx, access, baseRunID, candidatePlan); understood != nil {
								runCtx = contextWithUnderstood(runCtx, understood)
							}
						}
					}
				}
			}
		}
	}
	// R2 Outcome 2: a workspace with at least one APPROVED MetricDefinition
	// answers through the server-validated QueryIntent gate. The model only
	// proposes an intent; validateStructuredIntent either seals it with
	// queryintent.Validator -- after which it is the sole input to execution --
	// or returns a typed refusal carrying a clarification. A workspace with no
	// APPROVED definition short-circuits here and keeps today's planning path
	// verbatim. A meta-question about prior turns is never a workspace-data
	// question and keeps its own path.
	if !isMetaDialogueQuestion {
		intent, hasIntent, gateErr := service.validateStructuredIntent(runCtx, access, request.WorkspaceID, questionText)
		if gateErr != nil {
			return Run{}, gateErr
		}
		if hasIntent {
			return service.executeStructuredIntent(runCtx, access, request, runID, conversationID, conversationTurnID, intent)
		}
	}
	planned, planErr := service.planQuestion(questionText)
	if planErr != nil {
		return Run{}, &Error{code: CodeInvalid, cause: planErr}
	}
	requestHash := requestHash(questionText, requestedMode, request.ConversationID)
	// A replay is resolved before any new aggregate is minted. This is also the
	// fast path once a completed run is repeatedly opened by a UI, and it is
	// reachable only after the admission above is durable.
	if replay, found, replayErr := service.lookupIdempotency(runCtx, access, request.IdempotencyKey, requestHash, request.WorkspaceID); replayErr != nil {
		return Run{}, replayErr
	} else if found {
		return replay, nil
	}

	started, createErr := service.start(runCtx, access, request, questionText, planned, requestHash, runID, conversationID, conversationTurnID)
	if createErr != nil {
		// A concurrent first request can win the unique idempotency race. Resolve
		// that exact replay rather than exposing a database conflict.
		if database.SQLStateCode(createErr) == "23505" {
			if replay, found, replayErr := service.lookupIdempotency(runCtx, access, request.IdempotencyKey, requestHash, request.WorkspaceID); replayErr != nil {
				return Run{}, replayErr
			} else if found {
				return replay, nil
			}
		}
		return Run{}, createErr
	}
	_ = started
	if isMetaDialogueQuestion {
		// FIX-6 #3: answer from this authority's own last turns, never from
		// the corpus -- a meta-question about prior answers has nothing to
		// retrieve and must never fall through to INSUFFICIENT_EVIDENCE.
		if completeErr := service.completeMetaDialogue(runCtx, access, runID, request.WorkspaceID, conversationID, conversationTurnID); completeErr != nil {
			slog.Warn("question meta-dialogue completion failed", "error_code", CodeOf(completeErr), "error_type", fmt.Sprintf("%T", completeErr))
			service.reportFailureCleanup(ctx, access, runID, request.WorkspaceID, completeErr)
			return Run{}, completeErr
		}
		return service.Get(runCtx, access, request.WorkspaceID, runID)
	}
	if execErr := service.execute(runCtx, access, runID, request.WorkspaceID, questionText, started.CorpusStatus, started.AnswerMode); execErr != nil {
		// A durable failed status is preferable to losing the request. If the
		// failure itself is a persistence error, retain the original typed error
		// and let the status route expose only the safe terminal code.
		slog.Warn("question execution failed", "error_code", CodeOf(execErr), "error_type", fmt.Sprintf("%T", execErr), "cause_type", fmt.Sprintf("%T", errors.Unwrap(execErr)), "error_class", retrieval.DiagnosticClass(execErr), "sqlstate", database.SQLStateCode(execErr), "constraint", database.SQLConstraintName(execErr))
		service.reportFailureCleanup(ctx, access, runID, request.WorkspaceID, execErr)
		return Run{}, execErr
	}
	return service.Get(runCtx, access, request.WorkspaceID, runID)
}

func questionRunContext(parent context.Context, mode string) (context.Context, context.CancelFunc) {
	if mode != answerModeGenerative {
		return parent, func() {}
	}
	return context.WithTimeout(parent, generativeQuestionRunBudget)
}

func questionContextError(ctx context.Context, cause error) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return nil
}

func modelAttemptPersistenceContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	// Access/audit values are request-scoped and remain available, but caller
	// cancellation and the GENERATIVE run deadline must not cancel this one
	// bounded append. A fresh context is created for every attempt callback.
	return context.WithTimeout(context.WithoutCancel(parent), modelAttemptPersistenceTimeout)
}

// metaDialogueQuestionPattern is FIX-6 #3's closed, content-free recognizer
// for a question ABOUT the conversation itself rather than about workspace
// data: "you said 3 but showed 23", "why are the numbers different?". It is
// deliberately narrow (a fixed Russian phrase dictionary, not free-form
// intent detection) so it never mistakes an ordinary data question for one
// -- matching this pattern is the ONLY thing that routes a run away from the
// normal plan/retrieve/answer path.
var metaDialogueQuestionPattern = regexp.MustCompile("(?i)\u0442\u044b\\s+(\u0441\u043a\u0430\u0437\u0430\u043b|\u0433\u043e\u0432\u043e\u0440\u0438\u043b|\u043e\u0442\u0432\u0435\u0447\u0430\u043b|\u043f\u0438\u0441\u0430\u043b)|\u0432\u044b\\s+(\u0441\u043a\u0430\u0437\u0430\u043b\u0438|\u0433\u043e\u0432\u043e\u0440\u0438\u043b\u0438|\u043e\u0442\u0432\u0435\u0447\u0430\u043b\u0438|\u043f\u0438\u0441\u0430\u043b\u0438)|\u043f\u043e\u0447\u0435\u043c\u0443\\s+(\u0440\u0430\u0437\u043d\u044b\u0435|\u043d\u0435\\s+\u0441\u043e\u0432\u043f\u0430\u0434\u0430\\p{L}*|\u0442\u0430\u043a\u043e\u0435\\s+\u0440\u0430\u0441\u0445\u043e\u0436\u0434\\p{L}*|\u043f\u0440\u043e\u0442\u0438\u0432\u043e\u0440\u0435\u0447\u0438\\p{L}*)|\u0440\u0430\u0437\u043d\u044b\u0435\\s+(\u0447\u0438\u0441\u043b\u0430|\u043e\u0442\u0432\u0435\u0442\u044b|\u0440\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442\u044b)|(\u043d\u0435\\s+\u0441\u043e\u0432\u043f\u0430\u0434\u0430\\p{L}*|\u0440\u0430\u0441\u0445\u043e\u0434\u044f\u0442\u0441\u044f|\u0440\u0430\u0441\u0445\u043e\u0434\u0438\u0442\u0441\u044f)\\s+\u0441\\s+(\u0442\u0435\u043c|\u043f\u0440\u0435\u0434\u044b\u0434\u0443\u0449\\p{L}*|\u043f\u0440\u043e\u0448\u043b\\p{L}*)")

// metaTurnSnapshot is FIX-6 #3's read-only account of one prior turn used
// only to answer a meta-question about the conversation -- never re-used as
// evidence about workspace data.
type metaTurnSnapshot struct {
	runID     string
	question  string
	operation string
	result    *AnswerResult
}

// recentTurnRuns loads up to limit turns immediately preceding
// excludeTurnID in this conversation (most recent first), re-checking
// CURRENT read access to each one exactly like Get already does. A turn
// this principal can no longer read is silently dropped rather than
// guessed at -- the caller reports honestly on however many it recovered.
func (service *Service) recentTurnRuns(ctx context.Context, access database.AccessContext, workspaceID, conversationID, excludeTurnID string, limit int) ([]metaTurnSnapshot, error) {
	var runIDs []string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, queryErr := tx.Query(txCtx, `
			SELECT question_run_id FROM public.conversation_turn
			 WHERE organization_id = $1 AND conversation_id = $2 AND workspace_id = $3 AND id <> $4
			 ORDER BY turn_index DESC LIMIT $5
		`, access.OrganizationID, conversationID, workspaceID, excludeTurnID, limit)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if scanErr := rows.Scan(&id); scanErr != nil {
				return scanErr
			}
			runIDs = append(runIDs, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	snapshots := make([]metaTurnSnapshot, 0, len(runIDs))
	for _, id := range runIDs {
		run, getErr := service.Get(ctx, access, workspaceID, id)
		if getErr != nil {
			// No longer readable, or gone: report honestly on the turns that
			// remain rather than guessing at this one's content.
			continue
		}
		snapshots = append(snapshots, metaTurnSnapshot{runID: run.ID, question: run.Question, operation: run.PlanningOperation, result: run.AnswerResult})
	}
	return snapshots, nil
}

// describeTurnConditions renders one turn's own conditions for the meta
// comparison below: its literal question, and -- when it answered a
// structured AGGREGATE/LIST question -- the exact operation, period and
// filters that produced its number, in the same closed vocabulary
// renderSnapshotAnswer already prints. It never invents a condition a turn
// did not actually carry.
func describeTurnConditions(turn metaTurnSnapshot) string {
	var line strings.Builder
	line.WriteString("«")
	line.WriteString(turn.question)
	line.WriteString("»")
	if turn.result == nil {
		return line.String()
	}
	line.WriteString(" (operation ")
	line.WriteString(turn.result.Operation)
	if turn.result.Value != "" {
		line.WriteString(", answer ")
		line.WriteString(turn.result.Value)
	}
	if turn.result.Period != nil {
		line.WriteString(", period ")
		if turn.result.Period.Label != "" {
			line.WriteString(turn.result.Period.Label)
		} else {
			line.WriteString(turn.result.Period.From)
			line.WriteString(" — ")
			line.WriteString(turn.result.Period.To)
		}
	}
	for _, filter := range turn.result.Filters {
		line.WriteString(", ")
		line.WriteString(filter.Name)
		line.WriteString(" = ")
		line.WriteString(filter.Value)
	}
	line.WriteString(")")
	return line.String()
}

// renderMetaDialogueAnswer composes FIX-6 #3's human answer to a
// meta-question: a comparison of the immediately preceding turns' own
// conditions (never a guess, never a corpus search). recent is ordered most
// recent first (recentTurnRuns' own order).
func renderMetaDialogueAnswer(recent []metaTurnSnapshot) string {
	var answer strings.Builder
	answer.WriteString("This question concerns my previous answers in this conversation. I am comparing their conditions rather than searching the source data.\n\n")
	switch len(recent) {
	case 0:
		answer.WriteString("No previous turns in this conversation are currently available for comparison.")
	case 1:
		answer.WriteString("Only one previous turn is available: ")
		answer.WriteString(describeTurnConditions(recent[0]))
		answer.WriteString(". A second turn for comparison is unavailable or was not found.")
	default:
		// recent[0] is the more recent of the two (the "which ones?" turn),
		// recent[1] the one before it (the original "how many?" turn) --
		// present them in the order they actually happened.
		earlier, later := recent[1], recent[0]
		answer.WriteString("Earlier turn: ")
		answer.WriteString(describeTurnConditions(earlier))
		answer.WriteString(".\nLater turn: ")
		answer.WriteString(describeTurnConditions(later))
		answer.WriteString(".\n\n")
		if earlier.result != nil && later.result != nil {
			var differences []string
			if earlier.result.Operation != later.result.Operation {
				differences = append(differences, "operation ("+earlier.result.Operation+" → "+later.result.Operation+")")
			}
			earlierPeriod := ""
			if earlier.result.Period != nil {
				earlierPeriod = earlier.result.Period.Label
			}
			laterPeriod := ""
			if later.result.Period != nil {
				laterPeriod = later.result.Period.Label
			}
			if earlierPeriod != laterPeriod {
				differences = append(differences, "period (\""+earlierPeriod+"\" → \""+laterPeriod+"\")")
			}
			if !equalAnswerFilters(earlier.result.Filters, later.result.Filters) {
				differences = append(differences, "filters")
			}
			if len(differences) > 0 {
				answer.WriteString("Difference: " + strings.Join(differences, ", ") + " — the numbers differ because the questions used different conditions, not because the answer is contradictory.")
			} else {
				answer.WriteString("Both turns use the same conditions; differing conditions do not explain the numbers. Please ask again.")
			}
		} else {
			answer.WriteString("One of these turns was not a structured aggregate, so its conditions are unavailable for an exact comparison.")
		}
	}
	return answer.String()
}

func equalAnswerFilters(left, right []AnswerFilter) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]string, len(left))
	for _, filter := range left {
		seen[filter.Name] = filter.Value
	}
	for _, filter := range right {
		if value, ok := seen[filter.Name]; !ok || value != filter.Value {
			return false
		}
	}
	return true
}

// completeMetaDialogue persists FIX-6 #3's meta-dialogue answer as an
// ordinary COMPLETED run: no citations, no INSUFFICIENT_EVIDENCE, since this
// run never searched the corpus and has nothing to disclose beside its own
// account of the last turns' conditions.
func (service *Service) completeMetaDialogue(ctx context.Context, access database.AccessContext, runID, workspaceID, conversationID, currentTurnID string) error {
	recent, err := service.recentTurnRuns(ctx, access, workspaceID, conversationID, currentTurnID, 2)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	answer := renderMetaDialogueAnswer(recent)
	return service.persistTerminalRun(ctx, access, runID, workspaceID, answer, nil, nil, "COMPLETED", false, []Uncertainty{}, []Conflict{}, nil)
}

func (service *Service) planQuestion(questionText string) (planner.Plan, error) {
	var (
		planned planner.Plan
		err     error
	)
	if service != nil && service.planner != nil {
		planned, err = service.planner.Plan(questionText)
	} else {
		planned, err = planner.Default().Plan(questionText)
	}
	if err != nil {
		return planner.Plan{}, err
	}
	if err := planned.Validate(); err != nil {
		return planner.Plan{}, err
	}
	return planned, nil
}

func loadCorpusFreshness(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID, runID string) (CorpusFreshness, error) {
	if ctx == nil || !tx.Valid() || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(runID) {
		return CorpusFreshness{State: freshnessUnknown}, &Error{code: CodeInvalid}
	}
	var (
		snapshotCount, capturedCount                 int64
		hasFailed, hasUnknown, hasStale, hasDisabled bool
		capturedAt, lastSuccessfulSyncAt             *time.Time
	)
	if err := tx.QueryRow(ctx, `
		SELECT count(*),
		       COALESCE(bool_or(snapshot.health = 'FAILED'), false),
		       COALESCE(bool_or(snapshot.health = 'UNKNOWN'), false),
		       COALESCE(bool_or(snapshot.health = 'STALE'), false),
		       COALESCE(bool_or(snapshot.health = 'DISABLED'), false),
		       count(snapshot.captured_at), max(snapshot.captured_at), max(snapshot.last_successful_sync)
		  FROM public.question_corpus_snapshot AS snapshot
		  JOIN public.question_run AS run
		    ON run.organization_id = snapshot.organization_id
		   AND run.id = snapshot.question_run_id
		 WHERE snapshot.organization_id = $1
		   AND snapshot.question_run_id = $2
		   AND run.workspace_id = $3
	`, access.OrganizationID, runID, workspaceID).Scan(
		&snapshotCount, &hasFailed, &hasUnknown, &hasStale, &hasDisabled,
		&capturedCount, &capturedAt, &lastSuccessfulSyncAt,
	); err != nil {
		return CorpusFreshness{State: freshnessUnknown}, err
	}
	// A non-null captured timestamp is expected for every snapshot. Keep the
	// response conservative if a legacy/partial row violates that invariant.
	if snapshotCount > 0 && capturedCount != snapshotCount {
		hasUnknown = true
	}
	return CorpusFreshness{
		State:                corpusFreshnessState(snapshotCount, hasFailed, hasUnknown, hasStale, hasDisabled),
		CapturedAt:           capturedAt,
		LastSuccessfulSyncAt: lastSuccessfulSyncAt,
	}, nil
}

// loadSearchedSources is FIX-2 #6's "where searched" projection: every source
// bound and captured for this run (public.question_corpus_snapshot, the
// same per-source rows loadCorpusFreshness aggregates into one state) with a
// closed, content-free classification of why it did not produce a citation.
// A run-level partial corpus (the retrieval budget did not cover the whole
// corpus) is reported as NOT_COVERED for every source rather than guessed
// per source; otherwise an unhealthy source is UNAVAILABLE and a healthy one
// that still produced no citation is NO_MATCHES.
func loadSearchedSources(ctx context.Context, tx database.Transaction, access database.AccessContext, runID string, partial bool) ([]SearchedSource, error) {
	rows, err := tx.Query(ctx, `
		SELECT connection.name, snapshot.health
		  FROM public.question_corpus_snapshot AS snapshot
		  JOIN public.source_scope AS scope
		    ON scope.organization_id = snapshot.organization_id AND scope.id = snapshot.source_scope_id
		  JOIN public.source_connection AS connection
		    ON connection.organization_id = scope.organization_id AND connection.id = scope.connection_id
		 WHERE snapshot.organization_id = $1 AND snapshot.question_run_id = $2
		 ORDER BY connection.name
	`, access.OrganizationID, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	searched := make([]SearchedSource, 0)
	for rows.Next() {
		var name, health string
		if scanErr := rows.Scan(&name, &health); scanErr != nil {
			return nil, scanErr
		}
		result := SearchedNoMatches
		switch {
		case partial:
			result = SearchedNotCovered
		case health == "FAILED" || health == "UNKNOWN" || health == "DISABLED":
			result = SearchedUnavailable
		}
		searched = append(searched, SearchedSource{Source: name, Result: result, Message: searchedMessages[result]})
	}
	return searched, rows.Err()
}

// emitStoredRunBatchAdmission persists the one mandatory admission event for a
// batched stored-run read. The admission names the workspace access (the
// resource the actor was admitted to) and carries no question, answer, citation
// or run content. It mirrors the per-run question.run.admitted admission that
// Get reuses; the run-level identity is intentionally absent because one batch
// spans a caller-supplied set of runs and a single admission must not claim
// only one of them.
func (service *Service) emitStoredRunBatchAdmission(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if service == nil || service.newID == nil || service.now == nil {
		return errors.New("question: admission requires the service")
	}
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	if journal == nil {
		return errors.New("question: admission requires the audit journal")
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	_, err = journal.Append(ctx, access, audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionQuestionRunAdmitted,
		ResourceType:          audit.ResourceWorkspace,
		ResourceID:            workspaceID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{},
		OccurredAt:            service.now().UTC(),
	})
	return err
}

// recordStoredRunReadFailure appends the content-free failure outcome that
// matches the admission event Get/GetBatch persisted before their governed
// read. It runs only on the error path, so the journal never holds an admission
// without its outcome for a failed access. runID is empty for a batched read.
// The append is best-effort: the governed read already failed and its error is
// returned unchanged, exactly as the evidence read keeps its refusal.
func (service *Service) recordStoredRunReadFailure(ctx context.Context, access database.AccessContext, workspaceID, runID string, cause error) {
	if service == nil || service.newID == nil || service.now == nil {
		return
	}
	journal := service.admission
	if journal == nil {
		journal = service.audit
	}
	if journal == nil {
		return
	}
	eventID, err := service.newID("aud")
	if err != nil {
		return
	}
	code := storedRunReadFailureCode(cause)
	principal := access.PrincipalID
	input := audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionQuestionFailed,
		ResourceType:          audit.ResourceWorkspace,
		ResourceID:            workspaceID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeFailed,
		ErrorCode:             &code,
		ReferencedEvidenceIDs: []string{},
		OccurredAt:            service.now().UTC(),
	}
	if runID != "" {
		qrunID := runID
		input.Metadata = audit.Metadata{QuestionRunID: &qrunID}
	}
	// The governed read already failed; persist the matching outcome on a short
	// detached window so a cancelled request cannot leave the admission alone.
	cleanupCtx, cancel := questionFailureCleanupContext(ctx)
	defer cancel()
	if _, appendErr := journal.Append(cleanupCtx, access, input); appendErr != nil {
		slog.Warn("question read failure outcome persistence failed", "error_code", CodeOf(appendErr))
	}
}

// storedRunReadFailureCode maps a governed stored-run read failure to the
// closed, content-free error code carried by the matching failure outcome. A
// run that is not readable (revoked, or a revocation raced at an artifact
// access point) is reported as denied; any other failure is a read failure.
func storedRunReadFailureCode(cause error) string {
	if CodeOf(cause) == CodeNotFound || artifactrepository.CodeOf(cause) == artifactrepository.CodeDenied || artifactrepository.CodeOf(cause) == artifactrepository.CodeNotFound {
		return "QUESTION_READ_DENIED"
	}
	return "QUESTION_READ_FAILED"
}

// Get returns a current-access-checked run. A historical run is deliberately
// hidden when any cited Evidence fragment is no longer readable.
func (service *Service) Get(ctx context.Context, access database.AccessContext, workspaceID, runID string) (Run, error) {
	if service == nil || service.db == nil || service.codec == nil || service.artifacts == nil || access.Validate() != nil ||
		!validOpaque(workspaceID) || !validOpaque(runID) {
		return Run{}, &Error{code: CodeInvalid}
	}
	// Outcome 2 (audit before data): persist the admission event before the
	// governed stored-run read fetches any protected question-run, answer or
	// citation content. It records the effective actor kind (HUMAN | SERVICE)
	// and the access decision (OutcomeSuccess = admitted). A failed admission
	// fails closed with the existing typed unavailable error; no row is fetched
	// or returned. The existing outcome events are unchanged.
	if err := service.emitAdmission(ctx, access, workspaceID, runID); err != nil {
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	read := service.storedRunReadFn
	if read == nil {
		read = service.readStoredRun
	}
	result, err := read(ctx, access, workspaceID, runID)
	if err != nil {
		// A governed read that fails after admission leaves the admission event
		// plus its matching failure outcome, never the admission alone.
		service.recordStoredRunReadFailure(ctx, access, workspaceID, runID, err)
		return Run{}, err
	}
	return result, nil
}

// readStoredRun is Get's governed read: the current-access check and the
// question-run/answer/citation projection inside one read transaction. It runs
// only after Get's admission event is durable. A revocation committed before
// the read (or raced at an artifact access point) closes the read and returns
// no content.
func (service *Service) readStoredRun(ctx context.Context, access database.AccessContext, workspaceID, runID string) (Run, error) {
	var result Run
	// retainedAnalyticScalarPair is the one private copy of the decoded scalar
	// observation and its opaque dependency. It stays a local of this method
	// (never a Run field, context value, Service state or transport field) and
	// is assigned inside the artifact transaction only so the authorization
	// gate can run after that transaction has ended and released its connection.
	var retainedAnalyticScalarPair *analyticScalarPair
	// retainedGovernedQueryDependencies keeps the opaque live-query references
	// method-local until the same post-transaction disclosure point. They are
	// never projected onto Run or retained by Service.
	var retainedGovernedQueryDependencies []governedQueryDependency
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var readable bool
		if err := tx.QueryRow(txCtx, `SELECT app.question_run_readable($1, $2)`, runID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return &Error{code: CodeNotFound}
		}
		var (
			questionArtifact, answerArtifact, structuredArtifact                                sql.NullString
			conversationID, conversationTurnID                                                  sql.NullString
			questionHash, scopeHash, policyRevision                                             string
			answerHash, contextHash, manifestHash, failureCode, planHash, planningClarification sql.NullString
			uncertaintiesJSON, conflictsJSON                                                    []byte
			status, corpus, mode, verify, planningStatus, planningOperation, planningConfidence string
			workspaceRevision                                                                   int64
			startedAt                                                                           time.Time
			completedAt                                                                         *time.Time
		)
		if err := tx.QueryRow(txCtx, `
			SELECT workspace_revision, conversation_id, conversation_turn_id,
			       question_text_artifact_id, question_hash,
			       answer_mode, verification_method, result_status, corpus_status,
			       started_at, completed_at, answer_markdown_artifact_id,
			       answer_structured_artifact_id, answer_hash, workspace_scope_hash,
			       context_pack_hash, manifest_hash, policy_revision, failure_code,
			       planner_status, planner_operation, planner_confidence, planner_plan_hash, planner_clarification,
			       uncertainties_json, conflicts_json
			FROM public.question_run
			WHERE organization_id = $1 AND id = $2 AND workspace_id = $3
		`, access.OrganizationID, runID, workspaceID).Scan(
			&workspaceRevision, &conversationID, &conversationTurnID, &questionArtifact, &questionHash, &mode, &verify,
			&status, &corpus, &startedAt, &completedAt, &answerArtifact,
			&structuredArtifact, &answerHash, &scopeHash, &contextHash,
			&manifestHash, &policyRevision, &failureCode,
			&planningStatus, &planningOperation, &planningConfidence, &planHash, &planningClarification,
			&uncertaintiesJSON, &conflictsJSON,
		); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeNotFound}
			}
			return err
		}
		uncertainties, conflicts, signalErr := unmarshalSignals(uncertaintiesJSON, conflictsJSON)
		if signalErr != nil {
			return &Error{code: CodeUnavailable, cause: signalErr}
		}
		result = Run{
			ID: runID, WorkspaceID: workspaceID, WorkspaceRevision: workspaceRevision,
			ConversationID: conversationID.String, ConversationTurnID: conversationTurnID.String,
			AnswerMode: mode, VerificationMethod: verify, ResultStatus: status,
			CorpusStatus: corpus, StartedAt: startedAt, CompletedAt: completedAt,
			Freshness:  CorpusFreshness{State: freshnessUnknown},
			AnswerHash: answerHash.String, ContextPackHash: contextHash.String, ManifestHash: manifestHash.String,
			ManifestStatus: "NOT_PUBLISHED", FailureCode: failureCode.String, Citations: []Citation{},
			GroundingStatus: GroundingUnconfirmed,
			PlanningStatus:  planningStatus, PlanningOperation: planningOperation,
			PlanningConfidence: planningConfidence, PlanHash: planHash.String, Clarification: planningClarification.String,
			Uncertainties: attachUncertaintyMessages(uncertainties), Conflicts: attachConflictMessages(conflicts),
		}
		freshness, freshnessErr := loadCorpusFreshness(txCtx, tx, access, workspaceID, runID)
		if freshnessErr != nil {
			return freshnessErr
		}
		result.Freshness = freshness
		// FIX-2 #6: "where searched" is server-owned and content-free (source
		// name plus a closed result code), populated only when this run
		// actually reports INSUFFICIENT_EVIDENCE.
		if containsUncertaintyCode(result.Uncertainties, UncertaintyInsufficientEvidence) {
			if searched, searchedErr := loadSearchedSources(txCtx, tx, access, runID, corpus == "PARTIAL"); searchedErr == nil {
				result.Searched = searched
			} else {
				slog.Warn("question searched-sources projection failed", "error", searchedErr)
			}
		}
		if questionArtifact.Valid {
			owner, envelope, fetchErr := service.artifacts.Fetch(txCtx, tx, access, artifactcrypto.QuestionText, runID)
			if fetchErr != nil {
				return fetchErr
			}
			plain, openErr := service.codec.Open(owner, envelope)
			if openErr != nil {
				return openErr
			}
			result.Question = string(plain)
			clear(plain)
		}
		if answerArtifact.Valid {
			owner, envelope, fetchErr := service.artifacts.Fetch(txCtx, tx, access, artifactcrypto.AnswerMarkdown, runID)
			if fetchErr != nil {
				return fetchErr
			}
			plain, openErr := service.codec.Open(owner, envelope)
			if openErr != nil {
				return openErr
			}
			result.Answer = string(plain)
			clear(plain)
		}
		// The structured answer artifact is server-owned (only
		// marshalStructuredAnswer ever writes it): decoding its
		// answer_result/understood fields onto the wire projection (FIX-2
		// #1/#2) is not "trusting client JSON", it is the same disclosure
		// this artifact's citations already go through. Everything else in
		// the decoded document (claims, its own citations copy) is still
		// deliberately NOT projected verbatim -- the stable wire shape stays
		// the existing answer/citations/answer_result/understood fields, never
		// an unbounded pass-through of the artifact. R1 reads back only the
		// additive SOURCE_QUOTE/grounding_status fields from that copy.
		var structuredCitations []Citation
		if structuredArtifact.Valid {
			owner, envelope, fetchErr := service.artifacts.Fetch(txCtx, tx, access, artifactcrypto.AnswerStructured, runID)
			if fetchErr != nil {
				return fetchErr
			}
			plain, openErr := service.codec.Open(owner, envelope)
			if openErr != nil {
				return openErr
			}
			structured, decodeErr := decodeStructuredAnswerCleared(runID, plain)
			if decodeErr != nil {
				// A present structured artifact that fails its strict decode
				// closes the whole read before any decrypted question, answer or
				// citation is returned; the plaintext was already cleared by the
				// decode boundary and the error stays the content-free
				// CodeUnavailable.
				return &Error{code: CodeUnavailable}
			}
			if !storedTypedMetricAnswerMatches(result.Answer, result.AnswerHash, structured) {
				return &Error{code: CodeUnavailable}
			}
			if !validateToolLoopClaimEvidence(runID, result.Answer, structured.ToolLoop, structured.governedQueryDependencies, structured.Citations) {
				return &Error{code: CodeUnavailable}
			}
			if !governedQueryAnswerResultsAllowedForStatus(status, structured.governedQueryDependencies, structured.AnswerResult, structured.ToolLoop) {
				return &Error{code: CodeUnavailable}
			}
			result.AnswerResult = structured.AnswerResult
			result.Understood = structured.Understood
			result.ToolLoop = structured.ToolLoop
			if structured.ToolLoop != nil {
				result.ModelProfile = copyModelProfile(structured.ToolLoop.ModelProfile)
			}
			// R1: only the grounding projection (SOURCE_QUOTE + state) is
			// recovered from the sealed server-written artifact; the wire
			// excerpt/anchor/deep link keep coming from their own gated
			// citation artifacts below.
			structuredCitations = structured.Citations
			// Retain the decoded private pair in this method's local, outside
			// the transaction, so the disclosure gate can reauthorize it after
			// the read transaction has committed/rolled back and released its
			// connection. It is never projected onto the Run.
			retainedAnalyticScalarPair = structured.analyticScalarPair
			retainedGovernedQueryDependencies = structured.governedQueryDependencies
		}
		structuredByCitationID := make(map[string]Citation, len(structuredCitations))
		for _, citation := range structuredCitations {
			if citation.CitationID != "" {
				structuredByCitationID[citation.CitationID] = citation
			}
		}
		if result.AnswerResult != nil {
			result.AnswerResult.Snapshot.CapturedAt = result.Freshness.CapturedAt
		}
		rows, queryErr := tx.Query(txCtx, `
			SELECT id, citation_number, source_object_id, source_version_id,
			       extraction_id, evidence_fragment_id, cited_excerpt_artifact_id,
			       anchor_artifact_id, deep_link_artifact_id, evidence_text_hash,
			       cited_excerpt_hash
			FROM public.question_citation
			WHERE organization_id = $1 AND question_run_id = $2
			ORDER BY citation_number
		`, access.OrganizationID, runID)
		if queryErr != nil {
			return queryErr
		}
		type pendingCitation struct {
			citation                        Citation
			excerptArtifact, anchorArtifact string
			linkArtifact                    string
		}
		pending := make([]pendingCitation, 0)
		for rows.Next() {
			var pendingItem pendingCitation
			var excerptArtifact, anchorArtifact, linkArtifact string
			if err := rows.Scan(&pendingItem.citation.CitationID, &pendingItem.citation.Number, &pendingItem.citation.SourceObjectID, &pendingItem.citation.SourceVersionID,
				&pendingItem.citation.ExtractionID, &pendingItem.citation.EvidenceFragment, &excerptArtifact, &anchorArtifact, &linkArtifact,
				&pendingItem.citation.EvidenceTextHash, &pendingItem.citation.ExcerptHash); err != nil {
				return err
			}
			pendingItem.excerptArtifact, pendingItem.anchorArtifact, pendingItem.linkArtifact = excerptArtifact, anchorArtifact, linkArtifact
			pending = append(pending, pendingItem)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// Drain and close the metadata cursor before fetching citation artifacts.
		// pgx does not permit a second statement on the same transaction while a
		// Rows value is still active; doing this in two phases also makes the
		// disclosure gate explicit.
		rows.Close()
		for _, pendingItem := range pending {
			citation := pendingItem.citation
			for _, item := range []struct {
				field   artifactcrypto.OwnerField
				present string
				set     func(string)
			}{
				{artifactcrypto.CitationCitedExcerpt, pendingItem.excerptArtifact, func(value string) { citation.Excerpt = value }},
				{artifactcrypto.CitationAnchor, pendingItem.anchorArtifact, func(value string) { citation.Anchor = value }},
				{artifactcrypto.CitationDeepLink, pendingItem.linkArtifact, func(value string) { citation.DeepLink = value }},
			} {
				if item.present == "" {
					return &Error{code: CodeUnavailable}
				}
				owner, envelope, fetchErr := service.artifacts.Fetch(txCtx, tx, access, item.field, citation.CitationID)
				if fetchErr != nil {
					return fetchErr
				}
				plain, openErr := service.codec.Open(owner, envelope)
				if openErr != nil {
					return openErr
				}
				item.set(string(plain))
				clear(plain)
			}
			result.Citations = append(result.Citations, citation)
		}
		if !typedMetricCitationsMatchGated(result.ToolLoop, structuredCitations, result.Citations) {
			return &Error{code: CodeUnavailable}
		}
		// R1: project the sealed grounding fields onto the rebuilt citations and
		// derive the answer-level state. A run written before R1 has no
		// structured copy for a citation, so it stays UNCONFIRMED.
		for index := range result.Citations {
			if structured, ok := structuredByCitationID[result.Citations[index].CitationID]; ok {
				applyStructuredGrounding(&result.Citations[index], structured)
				result.Citations[index].Address = structured.Address
			} else {
				normalizeCitationGrounding(&result.Citations[index])
			}
		}
		result.GroundingStatus = answerGroundingStatus(result.Citations)
		if result.ToolLoop != nil && !result.ToolLoop.AllClaimsBound {
			result.GroundingStatus = GroundingUnconfirmed
		}
		return toolLoopDisclosure(txCtx, tx, access, result)
	})
	if err != nil {
		if CodeOf(err) == CodeNotFound || artifactrepository.CodeOf(err) == artifactrepository.CodeDenied || artifactrepository.CodeOf(err) == artifactrepository.CodeNotFound {
			return Run{}, &Error{code: CodeNotFound, cause: err}
		}
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	// The artifact transaction above has finished and released its connection:
	// the current-access scalar disclosure gate runs now, after all error
	// mapping and immediately before the Run is returned. A nil pair is the
	// legacy absence and returns nil with no resolver call. Any refusal returns
	// the exact zero Run plus the gate's content-free CodeNotFound/CodeUnavailable
	// unchanged, so a revoked dependency can never yield a populated Run.
	if err := service.authorizeAnalyticScalarDisclosure(ctx, access, workspaceID, runID, retainedAnalyticScalarPair); err != nil {
		return Run{}, err
	}
	if err := service.authorizeGovernedQueryDisclosures(ctx, access, workspaceID, runID, retainedGovernedQueryDependencies); err != nil {
		return Run{}, err
	}
	return result, nil
}

// GetBatch is FIX-5 #2's batched counterpart to Get: it resolves every run in
// runIDs inside ONE transaction (one connection acquisition, one BEGIN/
// COMMIT) with the main-row, freshness and citation-metadata queries each
// issued once for the WHOLE set instead of once per run. It exists because
// GET /conversations (and the MCP conversation tools) used to call Get once
// PER TURN across every returned conversation -- for a page of up to
// maxConversations conversations with several turns each, that was one new
// transaction, and several further round trips inside it, per turn. This is
// the same fix loadTurnsBatch already applied to conversation_turn, carried
// one layer up to the Question Run projection.
//
// It still calls the SAME per-artifact SECURITY DEFINER Fetch Get uses for
// every disclosed field (internal/artifact/repository is never bypassed or
// batched at the SQL level -- that boundary is deliberate), so this does not
// reduce how many artifact reads a run with N citations costs, only where
// they run: inside this one shared transaction instead of Get's own
// transaction (and, before FIX-5, one connection-pool acquisition) per turn.
// It also decrypts strictly fewer artifacts than N calls to Get() would:
// DeepLink is never a stored secret in practice -- every write site
// (complete, completeGenerative, renderNumericAggregate, ...) derives it as
// exactly "/api/v1/workspaces/<id>/evidence/<fragment id>" -- so this batched
// projection reconstructs it from the already-plaintext EvidenceFragment
// column instead of opening its encrypted artifact. That is "decrypt
// artifacts only for the fields the list view needs" without dropping the
// field from the wire response: every Run this returns still carries a
// DeepLink identical to what Get() would have decrypted.
//
// A run absent from runIDs, not belonging to workspaceID, or not currently
// readable (app.question_run_readable) is simply absent from the returned
// map -- the same "drop this turn" outcome projectConversation's per-turn
// loop got from a NotFound/Denied Get() error. A raced revocation caught only
// once an artifact Fetch is attempted (CodeDenied/CodeNotFound from
// internal/artifact/repository) drops just that one run from the map rather
// than failing the whole batch, which is strictly more precise than the
// single-run Get() callers this replaces: there, the same race aborted the
// entire GET /conversations response instead of one turn.
func (service *Service) GetBatch(ctx context.Context, access database.AccessContext, workspaceID string, runIDs []string) (map[string]Run, error) {
	if service == nil || service.db == nil || service.codec == nil || service.artifacts == nil ||
		access.Validate() != nil || !validOpaque(workspaceID) {
		return nil, &Error{code: CodeInvalid}
	}
	result := make(map[string]Run, len(runIDs))
	if len(runIDs) == 0 {
		return result, nil
	}
	for _, runID := range runIDs {
		if !validOpaque(runID) {
			return nil, &Error{code: CodeInvalid}
		}
	}
	// Outcome 2 (audit before data): persist the admission event before the
	// batched governed read fetches any protected question-run, answer or
	// citation content. One admission names the workspace access that spans the
	// whole batch; it records the effective actor kind (HUMAN | SERVICE) and the
	// access decision (OutcomeSuccess = admitted). A failed admission fails
	// closed with the existing typed unavailable error and no run is returned.
	if err := service.emitStoredRunBatchAdmission(ctx, access, workspaceID); err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	read := service.storedRunBatchReadFn
	if read == nil {
		read = service.readStoredRunBatch
	}
	result, err := read(ctx, access, workspaceID, runIDs)
	if err != nil {
		// A batched governed read that fails after admission leaves the
		// admission event plus its matching failure outcome, never the
		// admission alone.
		service.recordStoredRunReadFailure(ctx, access, workspaceID, "", err)
		return nil, err
	}
	return result, nil
}

// readStoredRunBatch is GetBatch's governed read: every run in runIDs is
// resolved inside ONE read transaction. It runs only after GetBatch's
// admission event is durable.
func (service *Service) readStoredRunBatch(ctx context.Context, access database.AccessContext, workspaceID string, runIDs []string) (map[string]Run, error) {
	result := make(map[string]Run, len(runIDs))
	type artifactRefs struct {
		questionArtifact, answerArtifact, structuredArtifact sql.NullString
	}
	// retainedAnalyticScalarPairs is the one private copy of every decoded scalar
	// pair keyed by its trusted Question Run id. It stays a local of this method
	// (never a Run field, context value, Service state or transport field) and is
	// populated inside the artifact transaction only so the batch disclosure gate
	// can reauthorize every surviving pair after that transaction has ended and
	// released its connection.
	var retainedAnalyticScalarPairs map[string]*analyticScalarPair = make(map[string]*analyticScalarPair, len(runIDs))
	// retainedGovernedQueryDependencies holds the decoded opaque reference lists
	// only for this method, keyed by trusted run ids, until after the artifact
	// transaction and scalar disclosure gate have completed.
	retainedGovernedQueryDependencies := make(map[string][]governedQueryDependency, len(runIDs))
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, err := tx.Query(txCtx, `
			SELECT id, workspace_revision, conversation_id, conversation_turn_id,
			       question_text_artifact_id, question_hash,
			       answer_mode, verification_method, result_status, corpus_status,
			       started_at, completed_at, answer_markdown_artifact_id,
			       answer_structured_artifact_id, answer_hash, workspace_scope_hash,
			       context_pack_hash, manifest_hash, policy_revision, failure_code,
			       planner_status, planner_operation, planner_confidence, planner_plan_hash, planner_clarification,
			       uncertainties_json, conflicts_json
			  FROM public.question_run
			 WHERE organization_id = $1 AND workspace_id = $2 AND id = ANY($3)
			   AND app.question_run_readable(id, workspace_id)
		`, access.OrganizationID, workspaceID, runIDs)
		if err != nil {
			return err
		}
		refsByRun := make(map[string]artifactRefs, len(runIDs))
		order := make([]string, 0, len(runIDs))
		for rows.Next() {
			var (
				runID                                                                               string
				refs                                                                                artifactRefs
				conversationID, conversationTurnID                                                  sql.NullString
				questionHash, scopeHash, policyRevision                                             string
				answerHash, contextHash, manifestHash, failureCode, planHash, planningClarification sql.NullString
				uncertaintiesJSON, conflictsJSON                                                    []byte
				status, corpus, mode, verify, planningStatus, planningOperation, planningConfidence string
				workspaceRevision                                                                   int64
				startedAt                                                                           time.Time
				completedAt                                                                         *time.Time
			)
			if err := rows.Scan(&runID, &workspaceRevision, &conversationID, &conversationTurnID,
				&refs.questionArtifact, &questionHash, &mode, &verify, &status, &corpus, &startedAt, &completedAt,
				&refs.answerArtifact, &refs.structuredArtifact, &answerHash, &scopeHash, &contextHash,
				&manifestHash, &policyRevision, &failureCode,
				&planningStatus, &planningOperation, &planningConfidence, &planHash, &planningClarification,
				&uncertaintiesJSON, &conflictsJSON,
			); err != nil {
				rows.Close()
				return err
			}
			uncertainties, conflicts, signalErr := unmarshalSignals(uncertaintiesJSON, conflictsJSON)
			if signalErr != nil {
				rows.Close()
				return &Error{code: CodeUnavailable, cause: signalErr}
			}
			result[runID] = Run{
				ID: runID, WorkspaceID: workspaceID, WorkspaceRevision: workspaceRevision,
				ConversationID: conversationID.String, ConversationTurnID: conversationTurnID.String,
				AnswerMode: mode, VerificationMethod: verify, ResultStatus: status,
				CorpusStatus: corpus, StartedAt: startedAt, CompletedAt: completedAt,
				Freshness:  CorpusFreshness{State: freshnessUnknown},
				AnswerHash: answerHash.String, ContextPackHash: contextHash.String, ManifestHash: manifestHash.String,
				ManifestStatus: "NOT_PUBLISHED", FailureCode: failureCode.String, Citations: []Citation{},
				GroundingStatus: GroundingUnconfirmed,
				PlanningStatus:  planningStatus, PlanningOperation: planningOperation,
				PlanningConfidence: planningConfidence, PlanHash: planHash.String, Clarification: planningClarification.String,
				Uncertainties: attachUncertaintyMessages(uncertainties), Conflicts: attachConflictMessages(conflicts),
			}
			refsByRun[runID] = refs
			order = append(order, runID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(order) == 0 {
			return nil
		}

		// Every run in `order` just proved app.question_run_readable true in
		// the query above, in this same transaction/MVCC snapshot. Installing
		// that result into ctx lets runAuthorize/citationAuthorize below skip
		// re-querying it once per artifact -- see authorizationMemo's own doc
		// comment for why this is a cache of an already-paid-for check, not a
		// weaker one. citationRuns is filled in once the citation-metadata
		// query below resolves each citation to the run it belongs to.
		readableRuns := make(map[string]bool, len(order))
		for _, runID := range order {
			readableRuns[runID] = true
		}
		memo := &authorizationMemo{readableRuns: readableRuns, citationRuns: make(map[string]string)}
		txCtx = contextWithAuthorizationMemo(txCtx, memo)

		freshnessByRun, err := loadCorpusFreshnessBatch(txCtx, tx, access, workspaceID, order)
		if err != nil {
			return err
		}
		insufficientRuns := make([]string, 0)
		partialByRun := make(map[string]bool, len(order))
		for _, runID := range order {
			run := result[runID]
			if freshness, ok := freshnessByRun[runID]; ok {
				run.Freshness = freshness
			}
			partialByRun[runID] = run.CorpusStatus == "PARTIAL"
			result[runID] = run
			if containsUncertaintyCode(run.Uncertainties, UncertaintyInsufficientEvidence) {
				insufficientRuns = append(insufficientRuns, runID)
			}
		}
		if len(insufficientRuns) > 0 {
			searchedByRun, searchedErr := loadSearchedSourcesBatch(txCtx, tx, access, insufficientRuns, partialByRun)
			if searchedErr != nil {
				slog.Warn("question searched-sources batch projection failed", "error", searchedErr)
			} else {
				for runID, searched := range searchedByRun {
					run := result[runID]
					run.Searched = searched
					result[runID] = run
				}
			}
		}

		structuredCitationsByRun := make(map[string][]Citation, len(order))
		for _, runID := range order {
			refs, ok := refsByRun[runID]
			if !ok {
				continue
			}
			run := result[runID]
			if refs.questionArtifact.Valid {
				plain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.QuestionText, runID)
				if fetchErr != nil {
					if isDroppableRunError(fetchErr) {
						delete(result, runID)
						continue
					}
					return fetchErr
				}
				run.Question = string(plain)
				clear(plain)
			}
			if refs.answerArtifact.Valid {
				plain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.AnswerMarkdown, runID)
				if fetchErr != nil {
					if isDroppableRunError(fetchErr) {
						delete(result, runID)
						continue
					}
					return fetchErr
				}
				run.Answer = string(plain)
				clear(plain)
			}
			if refs.structuredArtifact.Valid {
				plain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.AnswerStructured, runID)
				if fetchErr != nil {
					if isDroppableRunError(fetchErr) {
						delete(result, runID)
						continue
					}
					return fetchErr
				}
				structured, decodeErr := decodeStructuredAnswerCleared(runID, plain)
				if decodeErr != nil {
					// A present structured artifact that fails its strict decode
					// fails the whole batched read closed: the plaintext was
					// already cleared by the decode boundary and no partially
					// projected Question Run, answer or citation is returned.
					return &Error{code: CodeUnavailable}
				}
				if !storedTypedMetricAnswerMatches(run.Answer, run.AnswerHash, structured) {
					return &Error{code: CodeUnavailable}
				}
				if !validateToolLoopClaimEvidence(runID, run.Answer, structured.ToolLoop, structured.governedQueryDependencies, structured.Citations) {
					return &Error{code: CodeUnavailable}
				}
				if !governedQueryAnswerResultsAllowedForStatus(run.ResultStatus, structured.governedQueryDependencies, structured.AnswerResult, structured.ToolLoop) {
					return &Error{code: CodeUnavailable}
				}
				run.AnswerResult = structured.AnswerResult
				run.Understood = structured.Understood
				run.ToolLoop = structured.ToolLoop
				if structured.ToolLoop != nil {
					run.ModelProfile = copyModelProfile(structured.ToolLoop.ModelProfile)
				}
				structuredCitationsByRun[runID] = structured.Citations
				// Retain the decoded private pair in this method's local outside
				// the transaction, so the batch disclosure gate can reauthorize
				// it after the read transaction has committed/rolled back and
				// released its connection. It is never projected onto the Run.
				if structured.analyticScalarPair != nil {
					retainedAnalyticScalarPairs[runID] = structured.analyticScalarPair
				}
				retainedGovernedQueryDependencies[runID] = structured.governedQueryDependencies
			}
			if run.AnswerResult != nil {
				run.AnswerResult.Snapshot.CapturedAt = run.Freshness.CapturedAt
			}
			result[runID] = run
		}

		survivingIDs := make([]string, 0, len(result))
		for runID := range result {
			survivingIDs = append(survivingIDs, runID)
		}
		if len(survivingIDs) == 0 {
			return nil
		}
		citationRows, err := tx.Query(txCtx, `
			SELECT question_run_id, id, citation_number, source_object_id, source_version_id,
			       extraction_id, evidence_fragment_id, cited_excerpt_artifact_id,
			       anchor_artifact_id, evidence_text_hash, cited_excerpt_hash
			  FROM public.question_citation
			 WHERE organization_id = $1 AND question_run_id = ANY($2)
			 ORDER BY question_run_id, citation_number
		`, access.OrganizationID, survivingIDs)
		if err != nil {
			return err
		}
		type pendingCitation struct {
			runID                           string
			citation                        Citation
			excerptArtifact, anchorArtifact string
		}
		pending := make([]pendingCitation, 0)
		for citationRows.Next() {
			var pendingItem pendingCitation
			if err := citationRows.Scan(&pendingItem.runID, &pendingItem.citation.CitationID, &pendingItem.citation.Number,
				&pendingItem.citation.SourceObjectID, &pendingItem.citation.SourceVersionID,
				&pendingItem.citation.ExtractionID, &pendingItem.citation.EvidenceFragment,
				&pendingItem.excerptArtifact, &pendingItem.anchorArtifact,
				&pendingItem.citation.EvidenceTextHash, &pendingItem.citation.ExcerptHash); err != nil {
				citationRows.Close()
				return err
			}
			pending = append(pending, pendingItem)
		}
		if err := citationRows.Err(); err != nil {
			citationRows.Close()
			return err
		}
		citationRows.Close()

		for _, pendingItem := range pending {
			memo.citationRuns[pendingItem.citation.CitationID] = pendingItem.runID
		}

		for _, pendingItem := range pending {
			run, ok := result[pendingItem.runID]
			if !ok {
				continue // this run was already dropped above.
			}
			citation := pendingItem.citation
			if pendingItem.excerptArtifact == "" || pendingItem.anchorArtifact == "" {
				return &Error{code: CodeUnavailable}
			}
			excerptPlain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.CitationCitedExcerpt, citation.CitationID)
			if fetchErr != nil {
				if isDroppableRunError(fetchErr) {
					delete(result, pendingItem.runID)
					continue
				}
				return fetchErr
			}
			citation.Excerpt = string(excerptPlain)
			clear(excerptPlain)
			anchorPlain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.CitationAnchor, citation.CitationID)
			if fetchErr != nil {
				if isDroppableRunError(fetchErr) {
					delete(result, pendingItem.runID)
					continue
				}
				return fetchErr
			}
			citation.Anchor = string(anchorPlain)
			clear(anchorPlain)
			citation.DeepLink = "/api/v1/workspaces/" + workspaceID + "/evidence/" + citation.EvidenceFragment
			run.Citations = append(run.Citations, citation)
			result[pendingItem.runID] = run
		}
		for _, runID := range order {
			run, ok := result[runID]
			if !ok {
				continue
			}
			if !typedMetricCitationsMatchGated(run.ToolLoop, structuredCitationsByRun[runID], run.Citations) {
				return &Error{code: CodeUnavailable}
			}
		}
		// R1: project the sealed grounding fields and derive the answer-level
		// state for every surviving run, exactly like Get.
		for _, runID := range order {
			run, ok := result[runID]
			if !ok {
				continue
			}
			structuredByCitationID := make(map[string]Citation, len(structuredCitationsByRun[runID]))
			for _, citation := range structuredCitationsByRun[runID] {
				if citation.CitationID != "" {
					structuredByCitationID[citation.CitationID] = citation
				}
			}
			for index := range run.Citations {
				if structured, present := structuredByCitationID[run.Citations[index].CitationID]; present {
					applyStructuredGrounding(&run.Citations[index], structured)
					run.Citations[index].Address = structured.Address
				} else {
					normalizeCitationGrounding(&run.Citations[index])
				}
			}
			run.GroundingStatus = answerGroundingStatus(run.Citations)
			if run.ToolLoop != nil && !run.ToolLoop.AllClaimsBound {
				run.GroundingStatus = GroundingUnconfirmed
			}
			if err := toolLoopDisclosure(txCtx, tx, access, run); err != nil {
				if CodeOf(err) == CodeNotFound {
					delete(result, runID)
					continue
				}
				return err
			}
			result[runID] = run
		}
		return nil
	})
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	// The artifact transaction above has finished and released its connection:
	// the batch current-access scalar disclosure gate runs now, after all error
	// mapping and immediately before the surviving runs are returned. Candidate
	// ids are derived only from the final surviving result map, so a run dropped
	// earlier in this read is never a candidate and its retained pair is never
	// checked; the deterministic helper sorts and dedups the ids itself.
	candidateRunIDs := make([]string, 0, len(result))
	for runID := range result {
		candidateRunIDs = append(candidateRunIDs, runID)
	}
	denied, err := service.authorizeAnalyticScalarDisclosureBatch(ctx, access, workspaceID, candidateRunIDs, retainedAnalyticScalarPairs)
	if err != nil {
		// A fatal gate error returns no partial map and the exact bare error,
		// before any denied run is deleted or audited.
		return nil, err
	}
	for _, runID := range denied {
		delete(result, runID)
		// One content-free denied read outcome per removed whole run, using a
		// fresh bare CodeNotFound cause: the run's scalar pair is unreadable now
		// even though its content was already projected in this read.
		service.recordStoredRunReadFailure(ctx, access, workspaceID, runID, &Error{code: CodeNotFound})
	}
	governedCandidateRunIDs := make([]string, 0, len(result))
	for runID := range result {
		governedCandidateRunIDs = append(governedCandidateRunIDs, runID)
	}
	governedDenied, err := service.authorizeGovernedQueryDisclosureBatchMany(
		ctx, access, workspaceID, governedCandidateRunIDs, retainedGovernedQueryDependencies,
	)
	if err != nil {
		// A fatal governed disclosure error returns no partial map and the exact
		// content-free gate error before any governed-denied run is audited.
		return nil, err
	}
	for _, runID := range governedDenied {
		delete(result, runID)
		service.recordStoredRunReadFailure(ctx, access, workspaceID, runID, &Error{code: CodeNotFound})
	}
	return result, nil
}

// fetchAndOpenArtifact fetches one encrypted artifact through the activated
// owner branch and decrypts it. It is the same two-step Get() performs
// inline for each of its own artifact fields, factored out so GetBatch can
// call it once per artifact without duplicating the Fetch+Open pairing.
func fetchAndOpenArtifact(ctx context.Context, tx database.Transaction, service *Service, access database.AccessContext, field artifactcrypto.OwnerField, owningRowID string) ([]byte, error) {
	owner, envelope, fetchErr := service.artifacts.Fetch(ctx, tx, access, field, owningRowID)
	if fetchErr != nil {
		return nil, fetchErr
	}
	plain, openErr := service.codec.Open(owner, envelope)
	if openErr != nil {
		return nil, openErr
	}
	return plain, nil
}

// isDroppableRunError mirrors the condition Get()'s own final error mapping
// already uses to turn an artifact-repository race into CodeNotFound: a
// raced revocation or purge caught only once a specific artifact Fetch runs.
// GetBatch uses it to drop just the one affected run instead of aborting the
// whole batch.
func isDroppableRunError(err error) bool {
	return artifactrepository.CodeOf(err) == artifactrepository.CodeDenied || artifactrepository.CodeOf(err) == artifactrepository.CodeNotFound
}

// loadCorpusFreshnessBatch is loadCorpusFreshness's grouped counterpart: one
// query for every run in runIDs instead of one query per run. A run with no
// corpus snapshot rows is simply absent from the returned map; its zero value
// is the same freshnessUnknown default GetBatch's Run values already start
// with (corpusFreshnessState(0, ...) always returns freshnessUnknown, exactly
// what an absent map entry leaves unspoiled).
func loadCorpusFreshnessBatch(ctx context.Context, tx database.Transaction, access database.AccessContext, workspaceID string, runIDs []string) (map[string]CorpusFreshness, error) {
	rows, err := tx.Query(ctx, `
		SELECT run.id,
		       count(*),
		       COALESCE(bool_or(snapshot.health = 'FAILED'), false),
		       COALESCE(bool_or(snapshot.health = 'UNKNOWN'), false),
		       COALESCE(bool_or(snapshot.health = 'STALE'), false),
		       COALESCE(bool_or(snapshot.health = 'DISABLED'), false),
		       count(snapshot.captured_at), max(snapshot.captured_at), max(snapshot.last_successful_sync)
		  FROM public.question_run AS run
		  JOIN public.question_corpus_snapshot AS snapshot
		    ON run.organization_id = snapshot.organization_id AND run.id = snapshot.question_run_id
		 WHERE run.organization_id = $1 AND run.workspace_id = $2 AND run.id = ANY($3)
		 GROUP BY run.id
	`, access.OrganizationID, workspaceID, runIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]CorpusFreshness, len(runIDs))
	for rows.Next() {
		var (
			runID                                        string
			snapshotCount, capturedCount                 int64
			hasFailed, hasUnknown, hasStale, hasDisabled bool
			capturedAt, lastSuccessfulSyncAt             *time.Time
		)
		if err := rows.Scan(&runID, &snapshotCount, &hasFailed, &hasUnknown, &hasStale, &hasDisabled,
			&capturedCount, &capturedAt, &lastSuccessfulSyncAt); err != nil {
			return nil, err
		}
		if snapshotCount > 0 && capturedCount != snapshotCount {
			hasUnknown = true
		}
		result[runID] = CorpusFreshness{
			State:                corpusFreshnessState(snapshotCount, hasFailed, hasUnknown, hasStale, hasDisabled),
			CapturedAt:           capturedAt,
			LastSuccessfulSyncAt: lastSuccessfulSyncAt,
		}
	}
	return result, rows.Err()
}

// loadSearchedSourcesBatch is loadSearchedSources' grouped counterpart: one
// query for every run in runIDs instead of one query per run.
// partialByRun mirrors each call site's own `corpus == "PARTIAL"` argument to
// the single-run loadSearchedSources.
func loadSearchedSourcesBatch(ctx context.Context, tx database.Transaction, access database.AccessContext, runIDs []string, partialByRun map[string]bool) (map[string][]SearchedSource, error) {
	rows, err := tx.Query(ctx, `
		SELECT snapshot.question_run_id, connection.name, snapshot.health
		  FROM public.question_corpus_snapshot AS snapshot
		  JOIN public.source_scope AS scope
		    ON scope.organization_id = snapshot.organization_id AND scope.id = snapshot.source_scope_id
		  JOIN public.source_connection AS connection
		    ON connection.organization_id = scope.organization_id AND connection.id = scope.connection_id
		 WHERE snapshot.organization_id = $1 AND snapshot.question_run_id = ANY($2)
		 ORDER BY snapshot.question_run_id, connection.name
	`, access.OrganizationID, runIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]SearchedSource, len(runIDs))
	for rows.Next() {
		var runID, name, health string
		if err := rows.Scan(&runID, &name, &health); err != nil {
			return nil, err
		}
		outcome := SearchedNoMatches
		switch {
		case partialByRun[runID]:
			outcome = SearchedNotCovered
		case health == "FAILED" || health == "UNKNOWN" || health == "DISABLED":
			outcome = SearchedUnavailable
		}
		result[runID] = append(result[runID], SearchedSource{Source: name, Result: outcome, Message: searchedMessages[outcome]})
	}
	return result, rows.Err()
}

type candidate struct {
	ID, SourceObjectID, SourceVersionID, ExtractionID  string
	ObjectType, CanonicalFormat, ParserProfileRevision string
	TextHash, AnchorHash, ContentHash                  string
	Ordinal                                            int64
	Text                                               []byte
	Anchor                                             []byte
}

type authorizedCandidateDescriptor struct {
	Ordinal                int64  `json:"ordinal"`
	EvidenceFragmentID     string `json:"evidence_fragment_id"`
	SourceVersionID        string `json:"source_version_id"`
	ExtractionID           string `json:"extraction_id"`
	EvidenceTextHash       string `json:"evidence_text_hash"`
	ExactContextHash       string `json:"exact_context_hash"`
	AuthorizationGrantHash string `json:"authorization_grant_hash"`
}

type scopeBinding struct {
	ScopeID    string `json:"source_scope_id"`
	Revision   int64  `json:"source_scope_revision"`
	AccessMode string `json:"access_mode"`
	ConfigHash string `json:"scope_config_hash"`
	Enabled    bool   `json:"enabled"`
}

func (service *Service) start(ctx context.Context, access database.AccessContext, request CreateRequest, questionText string, planned planner.Plan, requestHash, runID, conversationID, conversationTurnID string) (Run, error) {
	var started Run
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var (
			organizationStatus, workspaceStatus, principalStatus, role string
			policyRevisionID                                           string
			workspaceRevision, policyRevision                          int64
			configurationHash                                          string
			principalRevision                                          int64
		)
		if err := tx.QueryRow(txCtx, `
			SELECT organization.status, workspace.status, workspace.current_revision,
			       revision.configuration_hash, principal.status, principal.session_revision,
			       organization.policy_revision, policy.policy_revision_id, COALESCE(member.role, '')
			FROM public.organization
			JOIN public.workspace
		  ON workspace.organization_id = organization.id AND workspace.id = $2
			JOIN public.workspace_revision revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id AND revision.revision = workspace.current_revision
			JOIN public.principal ON principal.organization_id = organization.id AND principal.id = $3
			JOIN public.organization_policy_revision policy
		  ON policy.organization_id = organization.id AND policy.revision = organization.policy_revision
			LEFT JOIN public.workspace_member member
		  ON member.organization_id = workspace.organization_id AND member.workspace_id = workspace.id
		 AND member.principal_id = principal.id AND member.removed_at IS NULL
			WHERE organization.id = $1
			FOR SHARE OF workspace
		`, access.OrganizationID, request.WorkspaceID, access.PrincipalID).Scan(
			&organizationStatus, &workspaceStatus, &workspaceRevision, &configurationHash,
			&principalStatus, &principalRevision, &policyRevision, &policyRevisionID, &role,
		); err != nil {
			if database.IsNotFound(err) {
				return &Error{code: CodeDenied}
			}
			return err
		}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceAsk,
			Subject: policy.Subject{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
				Status: policy.PrincipalStatus(principalStatus), SessionRevision: principalRevision},
			Workspace:  policy.Workspace{OrganizationID: access.OrganizationID, ID: request.WorkspaceID, Status: policy.WorkspaceStatus(workspaceStatus)},
			Membership: policy.Membership{Present: role != "", Role: policy.WorkspaceRole(role)},
		})
		if organizationStatus != "ACTIVE" || !decision.Allowed {
			return &Error{code: CodeDenied}
		}
		createConversation := request.ConversationID == ""
		turnIndex := int64(1)
		if !createConversation {
			// Lock the conversation row while assigning the next append-only
			// turn.
			//
			// FIX-2 #5: this used to also require boundRevision ==
			// workspaceRevision -- an UNRELATED workspace mutation (a
			// membership change, an access code, a different source's
			// confirmation) advances workspace.current_revision and made
			// every existing conversation's next turn fail this equality,
			// even though rights are independently re-checked below and by
			// every RLS policy on every hop. Migration 000080 (mirroring
			// 000076/000077's identical fix for the aggregate/evidence
			// gates) coordinates the FK and RLS policies on
			// conversation/conversation_turn/conversation_retention to stop
			// requiring that equality too, so this check now verifies only
			// what actually bounds a continuation: the same workspace, and
			// not archived. The new turn's own workspace_revision (below)
			// is still exactly the CURRENT revision -- "a snapshot of the
			// current revision", never a stale or wider one.
			var boundWorkspace string
			var archivedAt *time.Time
			if err := tx.QueryRow(txCtx, `
				SELECT workspace_id, archived_at
				  FROM public.conversation
				 WHERE organization_id = $1 AND id = $2
			`, access.OrganizationID, conversationID).Scan(&boundWorkspace, &archivedAt); err != nil {
				if database.IsNotFound(err) {
					return &Error{code: CodeNotFound}
				}
				return err
			}
			if boundWorkspace != request.WorkspaceID || archivedAt != nil {
				return &Error{code: CodeDenied}
			}
			// The active-row UPDATE policy permits a lock only while the
			// conversation is still appendable. Re-checking under FOR UPDATE
			// serializes concurrent turn-index allocation and maps a raced
			// archive to the same content-free denial.
			var lockedConversationID string
			if err := tx.QueryRow(txCtx, `
				SELECT id
				  FROM public.conversation
				 WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL
				 FOR UPDATE
			`, access.OrganizationID, conversationID).Scan(&lockedConversationID); err != nil {
				if database.IsNotFound(err) {
					return &Error{code: CodeDenied}
				}
				return err
			}
			var retentionState string
			var disclosureAllowed bool
			if err := tx.QueryRow(txCtx, `
				SELECT state, disclosure_allowed
				  FROM public.conversation_retention
				 WHERE organization_id = $1 AND conversation_id = $2
			`, access.OrganizationID, conversationID).Scan(&retentionState, &disclosureAllowed); err != nil {
				if database.IsNotFound(err) {
					return &Error{code: CodeNotFound}
				}
				return err
			}
			if retentionState != "ACTIVE" || !disclosureAllowed {
				return &Error{code: CodeDenied}
			}
			if err := tx.QueryRow(txCtx, `
				SELECT COALESCE(MAX(turn_index), 0) + 1
				  FROM public.conversation_turn
				 WHERE organization_id = $1 AND conversation_id = $2
			`, access.OrganizationID, conversationID).Scan(&turnIndex); err != nil {
				return err
			}
			if turnIndex < 1 || turnIndex > maxSafeGeneration {
				return &Error{code: CodeUnavailable}
			}
		}
		bindings, err := service.loadScopeBindings(txCtx, tx, access.OrganizationID, request.WorkspaceID, workspaceRevision)
		if err != nil {
			return err
		}
		scopeHash, err := hashCanonical(bindings)
		if err != nil {
			return err
		}
		mode, verify := answerMode, verification
		if request.AnswerMode == answerModeGenerative {
			mode, verify = answerModeGenerative, verificationSemanticVerifier
		}
		if request.AnswerMode == AnswerModeToolLoop {
			mode, verify = AnswerModeToolLoop, verificationAddress
		}
		var startedAt time.Time
		if err := tx.QueryRow(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id,
				question_hash, answer_mode, verification_method, result_status,
				corpus_status, workspace_scope_hash, policy_revision,
				planner_status, planner_operation, planner_confidence, planner_plan_hash, planner_clarification
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'RUNNING','COMPLETE',$11,$12,$13,$14,$15,$16,$17)
			RETURNING started_at
		`, access.OrganizationID, runID, request.WorkspaceID, workspaceRevision, access.PrincipalID,
			conversationID, conversationTurnID, requestHash, mode, verify, scopeHash, policyRevisionID, planned.Status,
			planned.Operation, planned.Confidence, planned.PlanHash, planned.Clarification).Scan(&startedAt); err != nil {
			return err
		}
		if _, err := service.retrievalStore.CaptureAccessProvenance(txCtx, tx, access, runID, startedAt); err != nil {
			return err
		}
		corpusComplete, err := service.persistCorpusSnapshots(txCtx, tx, access, runID, request.WorkspaceID,
			workspaceRevision, bindings, startedAt)
		if err != nil {
			return err
		}
		if !corpusComplete {
			if _, err := tx.Exec(txCtx, `UPDATE public.question_run SET corpus_status='PARTIAL' WHERE organization_id=$1 AND id=$2`, access.OrganizationID, runID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id, question_run_id)
			VALUES ($1,$2)
		`, access.OrganizationID, runID); err != nil {
			return err
		}
		if createConversation {
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation (
					organization_id, id, workspace_id, workspace_revision, created_by
				) VALUES ($1,$2,$3,$4,$5)
			`, access.OrganizationID, conversationID, request.WorkspaceID, workspaceRevision, access.PrincipalID); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation_retention (
					organization_id, conversation_id, workspace_id, workspace_revision
				) VALUES ($1,$2,$3,$4)
			`, access.OrganizationID, conversationID, request.WorkspaceID, workspaceRevision); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (
				organization_id, id, conversation_id, workspace_id, workspace_revision,
				turn_index, question_run_id
			) VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, access.OrganizationID, conversationTurnID, conversationID, request.WorkspaceID, workspaceRevision, turnIndex, runID); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_idempotency (organization_id, actor_principal_id, idempotency_key, canonical_request_hash, workspace_id, question_run_id)
			VALUES ($1,$2,$3,$4,$5,$6)
		`, access.OrganizationID, access.PrincipalID, request.IdempotencyKey, requestHash, request.WorkspaceID, runID); err != nil {
			return err
		}
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, access.OrganizationID, runID)
		if err != nil {
			return err
		}
		envelope, err := service.codec.Seal(owner, []byte(questionText))
		if err != nil {
			return err
		}
		artifactID, err := service.newID("art")
		if err != nil {
			return err
		}
		if err := service.artifacts.Store(txCtx, tx, access, artifactcrypto.QuestionText, runID, artifactID, envelope); err != nil {
			return err
		}
		eventID, err := service.newID("aud")
		if err != nil {
			return err
		}
		qrunID := runID
		if _, err := service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &request.WorkspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionQuestionCreated,
			ResourceType: audit.ResourceQuestionRun, ResourceID: runID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, ReferencedEvidenceIDs: []string{},
			Metadata: audit.Metadata{QuestionRunID: &qrunID}, OccurredAt: service.now().UTC(),
		}); err != nil {
			return err
		}
		corpusStatus := "COMPLETE"
		if !corpusComplete {
			corpusStatus = "PARTIAL"
		}
		started = Run{ID: runID, WorkspaceID: request.WorkspaceID, WorkspaceRevision: workspaceRevision,
			ConversationID: conversationID, ConversationTurnID: conversationTurnID,
			AnswerMode: mode, VerificationMethod: verify, ResultStatus: "RUNNING", CorpusStatus: "COMPLETE",
			Freshness: CorpusFreshness{State: freshnessUnknown},
			StartedAt: service.now().UTC(), ManifestStatus: "NOT_PUBLISHED", Citations: []Citation{},
			GroundingStatus: GroundingUnconfirmed,
			Uncertainties:   []Uncertainty{}, Conflicts: []Conflict{},
			PlanningStatus: string(planned.Status), PlanningOperation: string(planned.Operation),
			PlanningConfidence: planned.Confidence, PlanHash: planned.PlanHash, Clarification: planned.Clarification}
		started.CorpusStatus = corpusStatus
		_ = configurationHash
		return nil
	})
	if err != nil {
		if code := CodeOf(err); code == CodeDenied || code == CodeNotFound {
			return Run{}, err
		}
		return Run{}, &Error{code: CodeUnavailable, cause: err}
	}
	return started, nil
}

func (service *Service) execute(ctx context.Context, access database.AccessContext, runID, workspaceID, questionText string, corpusStatus string, mode string) error {
	var candidates []candidate
	var bindings []scopeBinding
	// The run's own persisted corpus_status is the sole source of the partial
	// flag; an absent/unreadable status is not treated as whole.
	partial := corpusStatus == "PARTIAL"
	planned, planErr := service.planQuestion(questionText)
	if planErr != nil {
		return &Error{code: CodeInvalid, cause: planErr}
	}
	if planned.Status != planner.Ready {
		// UNKNOWN and CLARIFICATION_REQUIRED are terminal safe outcomes. No
		// retrieval or tool call is allowed until a user supplies a resolvable
		// task; this is the planner's anti-fabrication boundary.
		return service.complete(ctx, access, runID, workspaceID, questionText, planned, nil, nil, true, mode)
	}
	// AGG-1: an analytic question about a structured source is answered by
	// reducing that source's whole current snapshot (snapshot_aggregate.go),
	// before retrieval and in both answer modes. Retrieval is budgeted, so a
	// count taken over its window would be "how many rows the search engine
	// returned"; and the model is never asked to restate a number, because a
	// restated number is a number that can be misread. When the reduction
	// cannot be resolved exactly this returns false and the ordinary retrieval
	// path below runs unchanged — including its own fail-closed refusal.
	if planned.Operation == planner.Aggregate {
		// The producing run's persisted corpus_status rides into the reducer so
		// AnswerResult.completeness is derived (COMPLETE|PARTIAL), never the
		// reducer's historical hardcoded COMPLETE.
		answered, snapshotErr := service.answerStructuredAggregate(ctx, access, runID, workspaceID, questionText, planned,
			answerResultIdentityForRunStatus(answerResultIdentity{}, corpusStatus))
		if snapshotErr != nil {
			return snapshotErr
		}
		if answered {
			return nil
		}
	}
	if service.retrieval != nil {
		// Bind the run's immutable workspace scope before touching the search
		// dependency. The executor then re-authorizes every returned Evidence
		// fragment against the same request context and workspace.
		err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
			var revision int64
			if err := tx.QueryRow(txCtx, `SELECT workspace_revision FROM public.question_run WHERE organization_id = $1 AND id = $2 AND workspace_id = $3`, access.OrganizationID, runID, workspaceID).Scan(&revision); err != nil {
				return err
			}
			var err error
			bindings, err = service.loadScopeBindings(txCtx, tx, access.OrganizationID, workspaceID, revision)
			return err
		})
		if err != nil {
			return &Error{code: CodeUnavailable, cause: err}
		}
		var retrieved retrieval.Result
		var retrievalErr error
		if service.retrieval.HybridReady() {
			// A composed production executor runs the server-owned lexical and
			// graph channels through explicit fusion. Missing vector qualification
			// remains a partial result and is therefore fail-closed in complete().
			retrieved, retrievalErr = service.retrieval.RetrievePlanWithQuestion(ctx, access, workspaceID, runID, questionText, planned)
		} else {
			retrieved, retrievalErr = service.retrieval.Retrieve(ctx, access, workspaceID, questionText)
		}
		if retrievalErr != nil {
			return &Error{code: CodeUnavailable, cause: retrievalErr}
		}
		partial = retrieved.Partial
		candidates = make([]candidate, 0, len(retrieved.Candidates))
		for _, item := range retrieved.Candidates {
			candidates = append(candidates, candidate{
				ID: item.ID, SourceObjectID: item.SourceObjectID, SourceVersionID: item.SourceVersionID,
				ExtractionID: item.ExtractionID, TextHash: item.TextHash, AnchorHash: item.AnchorHash,
				ObjectType: item.ObjectType, CanonicalFormat: item.CanonicalFormat,
				ParserProfileRevision: item.ParserProfileRevision,
				ContentHash:           item.ContentHash, Ordinal: item.Ordinal,
				Text: append([]byte(nil), item.Text...), Anchor: append([]byte(nil), item.Anchor...),
			})
			clear(item.Text)
			clear(item.Anchor)
		}
		selected := selectCandidatesAtPlan(candidates, planned, service.now())
		return service.complete(ctx, access, runID, workspaceID, questionText, planned, bindings, selected, partial, mode)
	}
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var revision int64
		if err := tx.QueryRow(txCtx, `SELECT workspace_revision FROM public.question_run WHERE organization_id = $1 AND id = $2 AND workspace_id = $3`, access.OrganizationID, runID, workspaceID).Scan(&revision); err != nil {
			return err
		}
		var err error
		bindings, err = service.loadScopeBindings(txCtx, tx, access.OrganizationID, workspaceID, revision)
		if err != nil {
			return err
		}
		rows, err := tx.Query(txCtx, `
			SELECT f.id, v.source_object_id, f.source_version_id, f.extraction_id,
			       o.object_type, e.canonical_format, e.parser_profile_revision,
			       f.text_hash, f.anchor_hash, v.content_hash, f.ordinal
			FROM public.evidence_fragment f
			JOIN public.source_version v
			  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
			JOIN public.source_object o
			  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
			JOIN public.source_extraction e
			  ON e.organization_id = f.organization_id AND e.id = f.extraction_id
			WHERE f.organization_id = $1
			  AND app.evidence_fragment_readable(f.id, $2)
			ORDER BY f.created_at DESC, f.id ASC
			LIMIT $3
		`, access.OrganizationID, workspaceID, maxCandidates+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item candidate
			if err := rows.Scan(&item.ID, &item.SourceObjectID, &item.SourceVersionID, &item.ExtractionID,
				&item.ObjectType, &item.CanonicalFormat, &item.ParserProfileRevision,
				&item.TextHash, &item.AnchorHash, &item.ContentHash, &item.Ordinal); err != nil {
				return err
			}
			candidates = append(candidates, item)
		}
		return rows.Err()
	})
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	// The reader is deliberately bounded, but a bounded reader must never turn
	// an unseen authorized tail into a COMPLETE corpus. Fetch one sentinel row,
	// retain only the deterministic window, and fail closed at completion when
	// the sentinel proves that the corpus was truncated.
	if len(candidates) > maxCandidates {
		partial = true
		candidates = candidates[:maxCandidates]
	}
	for index := range candidates {
		fragment, readErr := service.evidence.Read(ctx, access, workspaceID, candidates[index].ID)
		if readErr != nil {
			// A metadata row without readable evidence is an incomplete corpus,
			// not a valid negative retrieval result.
			partial = true
			continue
		}
		candidates[index].Text = append([]byte(nil), fragment.Text...)
		candidates[index].Anchor = append([]byte(nil), fragment.Anchor...)
		candidates[index].ObjectType = fragment.ObjectType
		candidates[index].CanonicalFormat = fragment.CanonicalFormat
		candidates[index].ParserProfileRevision = fragment.ParserProfileRevision
	}
	selected := selectCandidatesAtPlan(candidates, planned, service.now())
	return service.complete(ctx, access, runID, workspaceID, questionText, planned, bindings, selected, partial, mode)
}

func (service *Service) persistRetrievalSnapshot(ctx context.Context, access database.AccessContext, runID string,
	planned planner.Plan, selected []candidate, partial bool) ([]candidate, error) {
	if service == nil || service.db == nil || service.retrievalStore == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	authorized := make([]candidate, 0, len(selected))
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var startedAt time.Time
		if err := tx.QueryRow(txCtx, `SELECT started_at FROM public.question_run WHERE organization_id=$1 AND id=$2 AND result_status IN ('QUEUED','RUNNING')`, access.OrganizationID, runID).Scan(&startedAt); err != nil {
			return err
		}
		authorizedAt := service.now().UTC()
		if authorizedAt.Before(startedAt.UTC()) {
			authorizedAt = startedAt.UTC()
		}
		descriptors := make([]authorizedCandidateDescriptor, 0, len(selected))
		for index, item := range selected {
			if !validOpaque(item.ID) || len(item.Text) == 0 || len(item.Anchor) == 0 {
				return &Error{code: CodeDenied}
			}
			trusted, contextEntry, resolveErr := service.retrievalStore.ResolveEvidence(txCtx, tx, access, runID, item.ID, int64(index+1), authorizedAt)
			if resolveErr != nil {
				return resolveErr
			}
			if trusted.EvidenceFragmentID != item.ID || trusted.SourceVersionID != item.SourceVersionID ||
				trusted.ExtractionID != item.ExtractionID || trusted.EvidenceTextHash != item.TextHash ||
				contextEntry.AnchorHash != item.AnchorHash || contextEntry.SourceVersionContentHash != item.ContentHash ||
				contextEntry.SourceObjectID != item.SourceObjectID {
				return &Error{code: CodeDenied}
			}
			snapshotCandidate := trusted
			snapshotCandidate.Ordinal = int64(index + 1)
			if err := service.retrievalStore.AddCandidate(txCtx, tx, access, snapshotCandidate); err != nil {
				return err
			}
			if err := service.retrievalStore.AddContextEntry(txCtx, tx, access, contextEntry); err != nil {
				return err
			}
			authorizedItem := item
			authorizedItem.ID = trusted.EvidenceFragmentID
			authorizedItem.SourceObjectID = contextEntry.SourceObjectID
			authorizedItem.SourceVersionID = trusted.SourceVersionID
			authorizedItem.ExtractionID = trusted.ExtractionID
			authorizedItem.TextHash = trusted.EvidenceTextHash
			authorizedItem.AnchorHash = contextEntry.AnchorHash
			authorizedItem.ContentHash = contextEntry.SourceVersionContentHash
			authorized = append(authorized, authorizedItem)
			descriptors = append(descriptors, authorizedCandidateDescriptor{
				Ordinal: int64(index + 1), EvidenceFragmentID: trusted.EvidenceFragmentID,
				SourceVersionID: trusted.SourceVersionID, ExtractionID: trusted.ExtractionID,
				EvidenceTextHash: trusted.EvidenceTextHash, ExactContextHash: trusted.ExactContextHash,
				AuthorizationGrantHash: trusted.AuthorizationGrantHash,
			})
		}
		candidateBytes, err := canon.CanonicalJSON(struct {
			SchemaVersion string                          `json:"schema_version"`
			QuestionRunID string                          `json:"question_run_id"`
			Candidates    []authorizedCandidateDescriptor `json:"candidates"`
		}{"authorized-candidate-set-v1", runID, descriptors})
		if err != nil {
			return err
		}
		candidateSetHash := canon.Hash(candidateBytes)
		if err := service.retrievalStore.CreateCandidateSet(txCtx, tx, access, retrieval.CandidateSet{
			OrganizationID: access.OrganizationID, QuestionRunID: runID,
			CandidateCount: int64(len(descriptors)), CandidateSetHash: candidateSetHash,
			CanonicalBytes: candidateBytes,
		}); err != nil {
			return err
		}
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.AuthorizedCandidateSet, access.OrganizationID, runID)
		if err != nil {
			return err
		}
		envelope, err := service.codec.Seal(owner, candidateBytes)
		if err != nil {
			return err
		}
		artifactID, err := service.newID("art")
		if err != nil {
			return err
		}
		if err := service.retrievalStore.BindCandidateSetArtifact(txCtx, tx, access, runID, artifactID, envelope); err != nil {
			return err
		}
		pipelineProfileHash := canon.Hash([]byte("question-retrieval-authority-v1"))
		truncationReason := ""
		errorCodes := []string{}
		if partial {
			truncationReason = "CORPUS_PARTIAL"
			errorCodes = append(errorCodes, "CORPUS_PARTIAL")
		}
		planHash := planned.PlanHash
		if !strings.HasPrefix(planHash, "sha256:") {
			planHash = ""
		}
		authorizationBytes, err := canon.CanonicalJSON(struct {
			SchemaVersion              string    `json:"schema_version"`
			QuestionRunID              string    `json:"question_run_id"`
			AuthorizedCandidateSetHash string    `json:"authorized_candidate_set_hash"`
			AuthorizedCandidateCount   int64     `json:"authorized_candidate_count"`
			ContextCount               int64     `json:"context_count"`
			Truncated                  bool      `json:"truncated"`
			TruncationReason           string    `json:"truncation_reason,omitempty"`
			PipelineProfileHash        string    `json:"pipeline_profile_hash"`
			ModelExecutionPlanHash     string    `json:"model_execution_plan_hash,omitempty"`
			CapturedAt                 time.Time `json:"captured_at"`
		}{"retrieval-authorization-snapshot-v1", runID, candidateSetHash, int64(len(descriptors)), int64(len(descriptors)), partial, truncationReason, pipelineProfileHash, planHash, authorizedAt})
		if err != nil {
			return err
		}
		return service.retrievalStore.CreateAuthorizationSnapshot(txCtx, tx, access, retrieval.AuthorizationSnapshot{
			OrganizationID: access.OrganizationID, QuestionRunID: runID, CapturedAt: authorizedAt,
			PipelineVersion: "question-retrieval-authority-v1", PipelineProfileHash: pipelineProfileHash,
			ModelExecutionPlanHash: planHash, AuthorizedCandidateSetHash: candidateSetHash,
			AuthorizedCandidateCount: int64(len(descriptors)), ContextCount: int64(len(descriptors)),
			Truncated: partial, TruncationReason: truncationReason, ErrorCodes: errorCodes,
			CanonicalBytes: authorizationBytes, SnapshotHash: canon.Hash(authorizationBytes),
		})
	})
	if err != nil {
		return nil, err
	}
	return authorized, nil
}

func (service *Service) complete(ctx context.Context, access database.AccessContext, runID, workspaceID, questionText string, planned planner.Plan, bindings []scopeBinding, selected []candidate, partial bool, mode string) error {
	authorizedSelected, snapshotErr := service.persistRetrievalSnapshot(ctx, access, runID, planned, selected, partial)
	if snapshotErr != nil {
		return &Error{code: CodeUnavailable, cause: snapshotErr}
	}
	selected = authorizedSelected
	// QRY-002 / SRCH-004, review remark Z1: a PARTIAL corpus is a corpus this
	// run did NOT see all of — retrieval truncated at the candidate budget, or
	// a source binding failed. Prose degrades gracefully under that (an
	// excerpt is still a true excerpt), but an aggregate does not: SUM/COUNT
	// over the visible window is not "an approximate total", it is a different
	// question's exact answer, and it was published as COMPLETED with a
	// precise number and no marking. A number that can be misread is worse
	// than no number, so the aggregate is withheld here and the run reaches
	// its ordinary insufficient-evidence terminal state with corpus_status
	// PARTIAL and the CORPUS_PARTIAL uncertainty intact.
	//
	// This does not touch AGG-1: answerStructuredAggregate reduces the WHOLE
	// current snapshot before retrieval and completes the run itself with
	// partial=false, so an exact aggregate over a structured source is
	// unaffected and is never labelled PARTIAL by this path.
	if aggregateWithheldOnPartialCorpus(planned, partial) {
		selected = nil
	}
	if mode == answerModeGenerative {
		// GEN-1 (ADR-0088): a distinct completion path. It never falls back to
		// rendering an EXTRACTIVE answer under a GENERATIVE-labelled run — the
		// answer_mode/verification_method pair is immutable once inserted by
		// start() (db/migrations/000024's question_run_guard trigger) — so an
		// unverifiable attempt completes this run as its own terminal
		// INSUFFICIENT_EVIDENCE state instead.
		return service.completeGenerative(ctx, access, runID, workspaceID, questionText, planned, selected, partial)
	}
	completedAt := service.now().UTC()
	answer, citations, toolReceipt := renderAnswerPlanAtWithReceiptContext(ctx, workspaceID, questionText, planned, selected, service.now())
	uncertainties, conflicts, signalErr := deriveSignals(planned, selected, citations, partial)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	if len(citations) == 0 {
		// No citation means no answer: the stable, transport-identical sentence
		// used for ordinary insufficient evidence, so nothing about retrieval
		// leaks. A PARTIAL corpus by itself is NOT that case. POKA_YOKE
		// SRCH-004 requires truncation to degrade the corpus status, and
		// QRY-002 requires that status to be carried "separately from answer
		// prose" and shown ABOVE the answer — not to erase the answer. The
		// budget is finite by construction (maximumSearchHits), so any corpus
		// with more matches than that window is permanently partial; erasing
		// the answer there meant a workspace stopped answering at all the
		// moment a second, larger source was connected. corpus_status=PARTIAL
		// and the CORPUS_PARTIAL uncertainty below carry that fact intact.
		answer = "Insufficient evidence in the connected sources."
		citations = nil
	}
	// R1: bind each disclosed citation to an exact span of its authorized
	// candidate's stored normalized text before anything is persisted. A
	// paraphrase or any other non-span excerpt stays UNCONFIRMED.
	bindCitationGrounding(citations, selected)
	var (
		toolRunID        string
		toolEvidenceJSON []byte
		err              error
	)
	if toolReceipt != nil {
		toolRunID, err = service.newID("toolrun")
		if err != nil {
			return &Error{code: CodeUnavailable, cause: err}
		}
		toolEvidenceJSON, err = jsonv2.Marshal(toolReceipt.EvidenceIDs)
		if err != nil {
			return &Error{code: CodeUnavailable, cause: err}
		}
	}
	contextDescriptors := make([]map[string]any, 0, len(citations))
	for _, citation := range citations {
		contextDescriptors = append(contextDescriptors, map[string]any{
			"citation_number": citation.Number, "evidence_fragment_id": citation.EvidenceFragment,
			"excerpt_hash": citation.ExcerptHash, "evidence_text_hash": citation.EvidenceTextHash,
		})
	}
	contextHash, err := hashCanonical(contextDescriptors)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	uncertaintyJSON, conflictJSON, err := marshalSignals(uncertainties, conflicts)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	answerHash := canon.Hash([]byte(answer))
	return service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var readable bool
		if err := tx.QueryRow(txCtx, `SELECT app.question_run_readable($1, $2)`, runID, workspaceID).Scan(&readable); err != nil || !readable {
			return &Error{code: CodeDenied}
		}
		if toolReceipt != nil {
			var resultHash, failureCode any
			if toolReceipt.ResultHash != "" {
				resultHash = toolReceipt.ResultHash
			}
			if toolReceipt.FailureCode != "" {
				failureCode = toolReceipt.FailureCode
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.question_tool_run (
					organization_id, id, question_run_id, workspace_id, tool_id,
					binding_hash, plan_hash, result_hash, evidence_ids_json,
					row_count, cell_count, bucket_count, status, failure_code,
					started_at, completed_at, receipt_hash
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
			`, access.OrganizationID, toolRunID, runID, workspaceID, toolReceipt.ToolID,
				toolReceipt.BindingHash, toolReceipt.PlanHash, resultHash, toolEvidenceJSON,
				toolReceipt.Rows, toolReceipt.Cells, toolReceipt.Buckets, toolReceipt.Status, failureCode,
				toolReceipt.StartedAt, toolReceipt.CompletedAt, toolReceipt.ReceiptHash); err != nil {
				return err
			}
		}
		for index, citation := range citations {
			item, found := candidateForCitation(selected, citation.EvidenceFragment)
			if !found {
				// A renderer is allowed to project a deterministic subset (for
				// example, numeric aggregate cells) from the full selected
				// context.  Positional coupling would bind that citation to an
				// unrelated lexical/context candidate and break evidence
				// lineage.  Missing lineage is a terminal persistence failure.
				return &Error{code: CodeUnavailable}
			}
			citationID, err := service.newID("cit")
			if err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.question_citation (
					organization_id, id, question_run_id, citation_number, source_object_id,
					source_version_id, extraction_id, evidence_fragment_id,
					source_version_content_hash, evidence_text_hash, cited_excerpt_hash
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			`, access.OrganizationID, citationID, runID, citation.Number, item.SourceObjectID,
				item.SourceVersionID, item.ExtractionID, item.ID, item.ContentHash, citation.EvidenceTextHash, citation.ExcerptHash); err != nil {
				return err
			}
			if err := service.storeCitationArtifacts(txCtx, tx, access, citationID, citation, item.Anchor); err != nil {
				return err
			}
			citations[index].CitationID = citationID
		}
		structuredBytes, err := marshalStructuredAnswer(runID, answerHash, citations, nil, understoodFromContext(ctx))
		if err != nil {
			return &Error{code: CodeUnavailable, cause: err}
		}
		for _, payload := range []struct {
			field artifactcrypto.OwnerField
			value []byte
		}{
			{artifactcrypto.AnswerMarkdown, []byte(answer)},
			{artifactcrypto.AnswerStructured, structuredBytes},
		} {
			owner, err := artifactcrypto.NewOwnerIdentity(payload.field, access.OrganizationID, runID)
			if err != nil {
				return err
			}
			envelope, err := service.codec.Seal(owner, payload.value)
			if err != nil {
				return err
			}
			artifactID, err := service.newID("art")
			if err != nil {
				return err
			}
			if err := service.artifacts.Store(txCtx, tx, access, payload.field, runID, artifactID, envelope); err != nil {
				return err
			}
		}
		status := "COMPLETED"
		corpusStatus := "COMPLETE"
		if partial {
			corpusStatus = "PARTIAL"
		}
		if len(citations) == 0 {
			status = "INSUFFICIENT_EVIDENCE"
		}
		if _, err := tx.Exec(txCtx, `
			UPDATE public.question_run
			SET result_status = $3, completed_at = $4, answer_hash = $5,
			    context_pack_hash = $6, corpus_status = $7,
			    uncertainties_json = $8::jsonb, conflicts_json = $9::jsonb
			WHERE organization_id = $1 AND id = $2 AND result_status = 'RUNNING'
		`, access.OrganizationID, runID, status, completedAt, answerHash, contextHash, corpusStatus, string(uncertaintyJSON), string(conflictJSON)); err != nil {
			return err
		}
		if eventID, err := service.newID("aud"); err != nil {
			return err
		} else {
			qrunID := runID
			evidenceIDs := make([]string, 0, len(citations))
			for _, citation := range citations {
				// Audit requires lexicographic order, independently of citation number.
				evidenceIDs = append(evidenceIDs, citation.EvidenceFragment)
			}
			sort.Strings(evidenceIDs)
			evidenceIDs = slices.Compact(evidenceIDs)
			if _, err := service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
				EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
				ActorPrincipalID: &access.PrincipalID, Action: audit.ActionQuestionCompleted,
				ResourceType: audit.ResourceQuestionRun, ResourceID: runID, RequestID: access.RequestID,
				Outcome: audit.OutcomeSuccess, ReferencedEvidenceIDs: evidenceIDs,
				Metadata: audit.Metadata{QuestionRunID: &qrunID}, OccurredAt: completedAt,
			}); err != nil {
				return err
			}
		}
		_ = bindings
		return nil
	})
}

// completeGenerative is the GEN-1 (ADR-0088) completion path for a run whose
// answer_mode was inserted as GENERATIVE by start(). It never falls back to
// an EXTRACTIVE-shaped answer: an unverifiable attempt completes this same
// run as its own terminal INSUFFICIENT_EVIDENCE state with a fixed,
// server-owned, non-empty sentence and no citations.
func (service *Service) completeGenerative(ctx context.Context, access database.AccessContext, runID, workspaceID, questionText string, planned planner.Plan, selected []candidate, partial bool) error {
	if err := questionContextError(ctx, nil); err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	// A partial corpus is a status carried beside the answer (POKA_YOKE
	// QRY-002 / SRCH-004), not a reason to skip generation: the retrieval
	// budget makes every corpus larger than maximumSearchHits permanently
	// partial, so refusing here meant the GENERATIVE mode silently stopped
	// calling the model at all — every run answered the fixed fallback
	// sentence in milliseconds with no gateway attempt to audit. The
	// verification gate below is unchanged: an unverifiable or citation-free
	// plan still completes as INSUFFICIENT_EVIDENCE.
	if len(selected) == 0 || service.generation == nil || service.verifier == nil {
		return service.completeGenerativeInsufficient(ctx, access, runID, workspaceID, planned, selected, partial)
	}

	evidence := make([]modelgateway.Evidence, 0, len(selected))
	texts := make(map[string]string, len(selected))
	for _, item := range selected {
		evidence = append(evidence, modelgateway.Evidence{
			ID: item.ID, SourceObjectID: item.SourceObjectID, SourceVersionID: item.SourceVersionID,
			ExtractionID: item.ExtractionID, TextHash: item.TextHash, AnchorHash: item.AnchorHash,
			Text: string(item.Text),
		})
		texts[item.ID] = string(item.Text)
	}
	evidenceSetHash, hashErr := hashCanonical(modelgateway.EvidenceIDs(evidence))
	if hashErr != nil {
		return &Error{code: CodeUnavailable, cause: hashErr}
	}

	runtimeScope := service.generation.RuntimeScope()
	attemptNumber := 0
	persistAttempt := func(result modelgateway.AttemptResult, startedAt time.Time) {
		attemptNumber++
		persistCtx, cancelPersist := modelAttemptPersistenceContext(ctx)
		defer cancelPersist()
		if persistErr := service.persistGatewayAttempt(persistCtx, access, runID, workspaceID, attemptNumber, evidenceSetHash, result, runtimeScope, startedAt, service.now().UTC()); persistErr != nil {
			slog.Warn("model gateway attempt persistence failed", "error_code", CodeOf(persistErr))
		}
	}
	// ADR-0088's bounded budget is "an invalid model answer costs at most two
	// attempts, then the run is terminally INSUFFICIENT_EVIDENCE". A plan the
	// verifier refuses IS an invalid model answer — the model sampled claims it
	// cannot ground in the Evidence it was given — and it was the only invalid
	// answer that never got the second attempt: one unlucky sample ended the
	// run, which is why the same question answered on one call and refused on
	// the next seconds later. Retry generation, not verification: every attempt
	// is generated afresh, validated in full and persisted as its own audited
	// row, and the verifier's verdict is still the only thing that can publish
	// an answer. maxGenerativeAttempts matches the persisted attempt_number
	// bound in db/migrations/000060.
	for attemptNumber < maxGenerativeAttempts {
		attemptStarted := service.now().UTC()
		plan, attempt, genErr := service.generation.Generate(ctx, questionText, generationSystemInstructions,
			[]byte(generationOutputSchema), evidence, generationMaxOutputTokens)
		persistAttempt(attempt, attemptStarted)
		if genErr != nil {
			if contextErr := questionContextError(ctx, genErr); contextErr != nil {
				return &Error{code: CodeUnavailable, cause: contextErr}
			}
			code := modelgateway.CodeOf(genErr)
			if attemptNumber < maxGenerativeAttempts && (code == modelgateway.CodeUnavailable || code == modelgateway.CodeResponse) {
				continue
			}
			break
		}
		answer, citations, ok, verifyErr := service.buildVerifiedGenerativeAnswer(ctx, runID, plan, selected, texts, workspaceID)
		if verifyErr == nil && ok && answer != "" && len(citations) > 0 {
			return service.persistGenerativeCompletion(ctx, access, runID, workspaceID, planned, selected, citations, answer, partial)
		}
		if contextErr := questionContextError(ctx, verifyErr); contextErr != nil {
			return &Error{code: CodeUnavailable, cause: contextErr}
		}
		if verifyErr != nil || attemptNumber >= maxGenerativeAttempts {
			break
		}
	}
	return service.completeGenerativeInsufficient(ctx, access, runID, workspaceID, planned, selected, partial)
}

// buildVerifiedGenerativeAnswer resolves each disclosed claim's Evidence (a
// FACT claim directly, an INFERENCE claim transitively through its
// SupportingClaimIDs DAG, already proven acyclic by ClaimPlan.Validate),
// requires every disclosed claim to pass the interim semantic verifier, and
// renders the final answer text and citation list. It fails closed (false)
// rather than disclosing a partially-verified plan.
func (service *Service) buildVerifiedGenerativeAnswer(ctx context.Context, runID string, plan modelgateway.ClaimPlan, selected []candidate, texts map[string]string, workspaceID string) (string, []Citation, bool, error) {
	claimByID := make(map[string]modelgateway.Claim, len(plan.Claims))
	for _, claim := range plan.Claims {
		claimByID[claim.ID] = claim
	}
	resolved := make(map[string][]string, len(plan.Claims))
	var resolve func(id string) ([]string, bool)
	resolve = func(id string) ([]string, bool) {
		if cached, ok := resolved[id]; ok {
			return cached, true
		}
		claim, ok := claimByID[id]
		if !ok {
			return nil, false
		}
		switch claim.Kind {
		case "FACT":
			resolved[id] = append([]string(nil), claim.EvidenceIDs...)
		case "INFERENCE":
			seen := make(map[string]struct{})
			all := make([]string, 0, 4)
			for _, supportingID := range claim.SupportingClaimIDs {
				ids, ok := resolve(supportingID)
				if !ok {
					return nil, false
				}
				for _, evidenceID := range ids {
					if _, dup := seen[evidenceID]; !dup {
						seen[evidenceID] = struct{}{}
						all = append(all, evidenceID)
					}
				}
			}
			resolved[id] = all
		default:
			resolved[id] = nil
		}
		return resolved[id], true
	}

	referenced := make(map[string]struct{})
	for _, claim := range plan.Claims {
		if claim.Kind == "UNKNOWN" || claim.Text == nil {
			continue
		}
		evidenceIDs, ok := resolve(claim.ID)
		if !ok || len(evidenceIDs) == 0 {
			return "", nil, false, nil
		}
		evidenceTexts := make([]string, 0, len(evidenceIDs))
		for _, evidenceID := range evidenceIDs {
			text, ok := texts[evidenceID]
			if !ok {
				return "", nil, false, nil
			}
			evidenceTexts = append(evidenceTexts, text)
			referenced[evidenceID] = struct{}{}
		}
		verified, err := service.verifier.VerifyClaim(ctx, workspaceID, runID+":"+claim.ID, *claim.Text, evidenceTexts)
		if err != nil {
			return "", nil, false, err
		}
		if !verified {
			return "", nil, false, nil
		}
	}
	if len(referenced) == 0 {
		return "", nil, false, nil
	}
	ids := make([]string, 0, len(referenced))
	for id := range referenced {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	citationNumber := make(map[string]int64, len(ids))
	citations := make([]Citation, 0, len(ids))
	for index, id := range ids {
		item, found := candidateForCitation(selected, id)
		if !found {
			return "", nil, false, nil
		}
		text := texts[id]
		citationNumber[id] = int64(index + 1)
		citations = append(citations, Citation{
			Number: int64(index + 1), EvidenceFragment: item.ID, Excerpt: text, Anchor: string(item.Anchor),
			DeepLink:        "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID,
			SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID, SourceObjectID: item.SourceObjectID,
			EvidenceTextHash: item.TextHash, ExcerptHash: canon.Hash([]byte(text)),
		})
	}

	var builder strings.Builder
	for _, section := range plan.Sections {
		if section.Title != nil && *section.Title != "" {
			builder.WriteString(*section.Title)
			builder.WriteString("\n")
		}
		for _, claimID := range section.OrderedClaimIDs {
			claim, ok := claimByID[claimID]
			if !ok || claim.Text == nil {
				continue
			}
			builder.WriteString(*claim.Text)
			numbers := make([]int64, 0, len(resolved[claimID]))
			for _, id := range resolved[claimID] {
				if number, ok := citationNumber[id]; ok {
					numbers = append(numbers, number)
				}
			}
			sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
			for _, number := range numbers {
				builder.WriteString(" [")
				builder.WriteString(strconv.FormatInt(number, 10))
				builder.WriteString("]")
			}
			builder.WriteString("\n")
		}
	}
	return strings.TrimSpace(builder.String()), citations, true, nil
}

func (service *Service) completeGenerativeInsufficient(ctx context.Context, access database.AccessContext, runID, workspaceID string, planned planner.Plan, selected []candidate, partial bool) error {
	if err := questionContextError(ctx, nil); err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	uncertainties, conflicts, signalErr := deriveSignals(planned, selected, nil, partial)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	// deriveSignals(..., nil, ...) reports the selected Evidence set is
	// undisclosed via CORPUS_PARTIAL or INSUFFICIENT_EVIDENCE (whichever
	// applies) exactly as the EXTRACTIVE path does. A GENERATIVE run that
	// reaches this function had real Evidence and a corpus that was otherwise
	// Ready: GENERATION_UNAVAILABLE below is the specific reason (the bounded
	// generation/verification attempt itself failed), not "no Evidence was
	// found" — and it is bound to the exact same Evidence IDs, which
	// app.question_run_uncertainties_valid forbids appearing in two
	// uncertainty records. Drop the generic evidence-linked code here rather
	// than double-report the same Evidence set under two reasons.
	filtered := uncertainties[:0]
	for _, item := range uncertainties {
		if item.Code != UncertaintyCorpusPartial && item.Code != UncertaintyInsufficientEvidence {
			filtered = append(filtered, item)
		}
	}
	uncertainties, conflicts, signalErr = normalizeSignals(append(filtered, Uncertainty{Code: "GENERATION_UNAVAILABLE", EvidenceIDs: signalEvidenceIDs(selected)}), conflicts)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	return service.persistTerminalRun(ctx, access, runID, workspaceID, generationFallbackAnswer, nil, selected, "INSUFFICIENT_EVIDENCE", partial, uncertainties, conflicts, nil)
}

func (service *Service) persistGenerativeCompletion(ctx context.Context, access database.AccessContext, runID, workspaceID string, planned planner.Plan, selected []candidate, citations []Citation, answer string, partial bool) error {
	uncertainties, conflicts, signalErr := deriveSignals(planned, selected, citations, partial)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	return service.persistTerminalRun(ctx, access, runID, workspaceID, answer, citations, selected, "COMPLETED", partial, uncertainties, conflicts, nil)
}

// persistTerminalRun is the GENERATIVE-mode persistence tail. It intentionally
// mirrors complete()'s extractive tail (same citation/artifact/audit shape)
// rather than sharing code with it, so a future change to one rendering path
// cannot silently change the other's disclosure behaviour. answerResult is
// FIX-2 #1's structured AGGREGATE/LIST projection: nil for every caller
// except answerStructuredAggregate. It preserves its existing signature and
// delegates with no analytic scalar.
func (service *Service) persistTerminalRun(ctx context.Context, access database.AccessContext, runID, workspaceID, answer string, citations []Citation, selected []candidate, status string, partial bool, uncertainties []Uncertainty, conflicts []Conflict, answerResult *AnswerResult) error {
	return service.persistTerminalRunWithAnalyticScalarPair(ctx, access, runID, workspaceID, answer, citations, selected, status, partial, uncertainties, conflicts, answerResult, nil)
}

// persistTerminalRunWithAnalyticScalarPair carries the one inseparable trusted
// scalar pair from a future analytic producer into the existing encrypted
// structured artifact. A non-nil pair whose observation is invalid is refused
// content-free before the database write begins; every other behaviour is
// identical to persistTerminalRun, including the single transaction, the single
// AnswerStructured artifact and rollback on any failure.
func (service *Service) persistTerminalRunWithAnalyticScalarPair(ctx context.Context, access database.AccessContext, runID, workspaceID, answer string, citations []Citation, selected []candidate, status string, partial bool, uncertainties []Uncertainty, conflicts []Conflict, answerResult *AnswerResult, analyticScalarPair *analyticScalarPair) error {
	return service.persistTerminalRunWithStructuredDependencies(ctx, access, runID, workspaceID, answer, citations, selected, status, partial, uncertainties, conflicts, answerResult, analyticScalarPair, nil)
}

func (service *Service) persistTerminalRunWithStructuredDependencies(ctx context.Context, access database.AccessContext, runID, workspaceID, answer string, citations []Citation, selected []candidate, status string, partial bool, uncertainties []Uncertainty, conflicts []Conflict, answerResult *AnswerResult, analyticScalarPair *analyticScalarPair, dependency *governedQueryDependency) error {
	var dependencies []governedQueryDependency
	if dependency != nil {
		dependencies = []governedQueryDependency{*dependency}
	}
	return service.persistTerminalRunWithStructuredDependencyList(ctx, access, runID, workspaceID, answer, citations, selected, status, partial, uncertainties, conflicts, answerResult, analyticScalarPair, dependencies)
}

func (service *Service) persistTerminalRunWithStructuredDependencyList(ctx context.Context, access database.AccessContext, runID, workspaceID, answer string, citations []Citation, selected []candidate, status string, partial bool, uncertainties []Uncertainty, conflicts []Conflict, answerResult *AnswerResult, analyticScalarPair *analyticScalarPair, governedQueryDependencies []governedQueryDependency) error {
	if analyticScalarPair != nil && !analyticScalarPair.observation.valid() {
		return &Error{code: CodeInvalid}
	}
	if len(governedQueryDependencies) > liveDataMaxSuccessfulCalls {
		return &Error{code: CodeInvalid}
	}
	for _, dependency := range governedQueryDependencies {
		if !dependency.validForRun(runID) {
			return &Error{code: CodeInvalid}
		}
	}
	if !governedQueryAnswerResultsAllowedForStatus(status, governedQueryDependencies, answerResult, toolLoopFromContext(ctx)) {
		return &Error{code: CodeInvalid}
	}
	// R1: bind the citation grounding projection from the same authorized
	// candidates this run persists. A GENERATIVE claim paraphrase never matches
	// a stored span and therefore stays UNCONFIRMED.
	bindCitationGrounding(citations, selected)
	completedAt := service.now().UTC()
	contextDescriptors := make([]map[string]any, 0, len(citations))
	for _, citation := range citations {
		contextDescriptors = append(contextDescriptors, map[string]any{
			"citation_number": citation.Number, "evidence_fragment_id": citation.EvidenceFragment,
			"excerpt_hash": citation.ExcerptHash, "evidence_text_hash": citation.EvidenceTextHash,
		})
	}
	contextHash, err := hashCanonical(contextDescriptors)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	uncertaintyJSON, conflictJSON, err := marshalSignals(uncertainties, conflicts)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	answerHash := canon.Hash([]byte(answer))
	corpusStatus := "COMPLETE"
	if partial {
		corpusStatus = "PARTIAL"
	}
	return service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var readable bool
		if err := tx.QueryRow(txCtx, `SELECT app.question_run_readable($1, $2)`, runID, workspaceID).Scan(&readable); err != nil || !readable {
			return &Error{code: CodeDenied}
		}
		for index, citation := range citations {
			item, found := candidateForCitation(selected, citation.EvidenceFragment)
			if !found {
				return &Error{code: CodeUnavailable}
			}
			citationID, err := service.newID("cit")
			if err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.question_citation (
					organization_id, id, question_run_id, citation_number, source_object_id,
					source_version_id, extraction_id, evidence_fragment_id,
					source_version_content_hash, evidence_text_hash, cited_excerpt_hash
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			`, access.OrganizationID, citationID, runID, citation.Number, citation.SourceObjectID,
				citation.SourceVersionID, citation.ExtractionID, citation.EvidenceFragment,
				item.ContentHash, citation.EvidenceTextHash, citation.ExcerptHash); err != nil {
				return err
			}
			if err := service.storeCitationArtifacts(txCtx, tx, access, citationID, citation, []byte(citation.Anchor)); err != nil {
				return err
			}
			citations[index].CitationID = citationID
		}
		structuredBytes, err := marshalStructuredAnswerWithDependencyList(runID, answerHash, citations, answerResult, understoodFromContext(ctx), analyticScalarPair, governedQueryDependencies, toolLoopFromContext(ctx))
		if err != nil {
			return &Error{code: CodeUnavailable, cause: err}
		}
		for _, payload := range []struct {
			field artifactcrypto.OwnerField
			value []byte
		}{
			{artifactcrypto.AnswerMarkdown, []byte(answer)},
			{artifactcrypto.AnswerStructured, structuredBytes},
		} {
			owner, err := artifactcrypto.NewOwnerIdentity(payload.field, access.OrganizationID, runID)
			if err != nil {
				return err
			}
			envelope, err := service.codec.Seal(owner, payload.value)
			if err != nil {
				return err
			}
			artifactID, err := service.newID("art")
			if err != nil {
				return err
			}
			if err := service.artifacts.Store(txCtx, tx, access, payload.field, runID, artifactID, envelope); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(txCtx, `
			UPDATE public.question_run
			SET result_status = $3, completed_at = $4, answer_hash = $5,
			    context_pack_hash = $6, corpus_status = $7,
			    uncertainties_json = $8::jsonb, conflicts_json = $9::jsonb
			WHERE organization_id = $1 AND id = $2 AND result_status = 'RUNNING'
		`, access.OrganizationID, runID, status, completedAt, answerHash, contextHash, corpusStatus, string(uncertaintyJSON), string(conflictJSON)); err != nil {
			return err
		}
		eventID, err := service.newID("aud")
		if err != nil {
			return err
		}
		qrunID := runID
		evidenceIDs := make([]string, 0, len(citations))
		for _, citation := range citations {
			evidenceIDs = append(evidenceIDs, citation.EvidenceFragment)
		}
		sort.Strings(evidenceIDs)
		evidenceIDs = slices.Compact(evidenceIDs)
		_, err = service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionQuestionCompleted,
			ResourceType: audit.ResourceQuestionRun, ResourceID: runID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, ReferencedEvidenceIDs: evidenceIDs,
			Metadata: audit.Metadata{QuestionRunID: &qrunID}, OccurredAt: completedAt,
		})
		return err
	})
}

// persistGatewayAttempt records one bounded Model Gateway attempt
// content-free (MOD-007/MOD-008): model id, attempt number, status, byte
// counts, response stage and a hash of the exact Evidence-ID set, never
// question/Evidence text or model output. It runs in its own transaction so
// an attempt is durable before the caller can observe the run's final outcome.
func (service *Service) persistGatewayAttempt(ctx context.Context, access database.AccessContext, runID, workspaceID string, attemptNumber int, evidenceSetHash string, result modelgateway.AttemptResult, runtimeScope string, startedAt, completedAt time.Time) error {
	attemptID, err := service.newID("mgat")
	if err != nil {
		return err
	}
	status := "SUCCEEDED"
	var failureCode any
	if !result.Succeeded {
		status = "FAILED"
		code := string(result.FailureCode)
		if code == "" {
			code = "MODEL_GATEWAY_UNAVAILABLE"
		}
		failureCode = code
	}
	modelID := result.ModelID
	if modelID == "" {
		modelID = "unknown"
	}
	if runtimeScope != modelgateway.RuntimeScopeLocalLab && runtimeScope != modelgateway.RuntimeScopeExternalWorkspaceScoped {
		runtimeScope = modelgateway.RuntimeScopeLocalLab
	}
	return service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_model_gateway_attempt (
				organization_id, id, question_run_id, workspace_id, purpose, attempt_number,
				model_id, evidence_set_hash, request_bytes, response_bytes, status, failure_code,
				runtime_scope, started_at, completed_at
			) VALUES ($1,$2,$3,$4,'GENERATION',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		`, access.OrganizationID, attemptID, runID, workspaceID, attemptNumber, modelID, evidenceSetHash,
			result.RequestBytes, result.ResponseBytes, status, failureCode, runtimeScope, startedAt, completedAt); err != nil {
			return err
		}
		eventID, err := service.newID("aud")
		if err != nil {
			return err
		}
		qrunID := runID
		outcome := audit.OutcomeSuccess
		var errorCode *string
		if !result.Succeeded {
			outcome = audit.OutcomeFailed
			code := string(result.FailureCode)
			if code == "" {
				code = "MODEL_GATEWAY_UNAVAILABLE"
			}
			errorCode = &code
		}
		// Runtime scope and response stage are fixed, closed, content-free
		// vocabulary entries (never question/Evidence/model content). Keeping
		// them and the closed response diagnostic in reason_codes requires no
		// response content, raw provider labels or schema migration.
		reasonCodes := modelGatewayReasonCodes(result, runtimeScope)
		_, err = service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionModelGatewayAttempt,
			ResourceType: audit.ResourceModelRun, ResourceID: attemptID, RequestID: access.RequestID,
			Outcome: outcome, ErrorCode: errorCode, ReferencedEvidenceIDs: []string{},
			Metadata: audit.Metadata{QuestionRunID: &qrunID, ReasonCodes: reasonCodes}, OccurredAt: completedAt,
		})
		return err
	})
}

func modelGatewayReasonCodes(result modelgateway.AttemptResult, runtimeScope string) []string {
	reasonCodes := []string{"MODEL_RUNTIME_" + runtimeScope}
	if stageCode := modelResponseStageReasonCode(result.ResponseStage); stageCode != "" {
		reasonCodes = append(reasonCodes, stageCode)
	}
	if diagnosticCode := result.ResponseDiagnostic.ReasonCode(); diagnosticCode != "" {
		reasonCodes = append(reasonCodes, diagnosticCode)
	}
	sort.Strings(reasonCodes)
	return reasonCodes
}

func modelResponseStageReasonCode(stage modelgateway.ResponseStage) string {
	switch stage {
	case modelgateway.ResponseStageWire, modelgateway.ResponseStageJSON, modelgateway.ResponseStageClaim:
		return "MODEL_RESPONSE_STAGE_" + string(stage)
	default:
		return ""
	}
}

func candidateForCitation(selected []candidate, evidenceFragmentID string) (candidate, bool) {
	if evidenceFragmentID == "" {
		return candidate{}, false
	}
	for _, item := range selected {
		if item.ID == evidenceFragmentID {
			return item, true
		}
	}
	return candidate{}, false
}

func (service *Service) storeCitationArtifacts(ctx context.Context, tx database.Transaction, access database.AccessContext, citationID string, citation Citation, anchor []byte) error {
	deepLink := citation.DeepLink
	for _, payload := range []struct {
		field artifactcrypto.OwnerField
		value []byte
	}{
		{artifactcrypto.CitationCitedExcerpt, []byte(citation.Excerpt)},
		{artifactcrypto.CitationAnchor, append([]byte(nil), anchor...)},
		{artifactcrypto.CitationDeepLink, []byte(deepLink)},
	} {
		owner, err := artifactcrypto.NewOwnerIdentity(payload.field, access.OrganizationID, citationID)
		if err != nil {
			return err
		}
		if len(payload.value) == 0 {
			return &Error{code: CodeUnavailable}
		}
		envelope, err := service.codec.Seal(owner, payload.value)
		if err != nil {
			return err
		}
		artifactID, err := service.newID("art")
		if err != nil {
			return err
		}
		if err := service.artifacts.Store(ctx, tx, access, payload.field, citationID, artifactID, envelope); err != nil {
			return err
		}
	}
	return nil
}

func (service *Service) reportFailureCleanup(ctx context.Context, access database.AccessContext, runID, workspaceID string, cause error) {
	status, code := questionFailureTerminal(ctx, cause)
	if err := service.fail(ctx, access, runID, workspaceID, status, code); err != nil {
		slog.Error("question failure persistence failed", "error_code", CodeOf(err), "error_type", fmt.Sprintf("%T", err), "sqlstate", database.SQLStateCode(err), "constraint", database.SQLConstraintName(err), "cause_code", CodeOf(cause))
	}
}

func questionFailureTerminal(ctx context.Context, cause error) (status, code string) {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) && errors.Is(cause, context.Canceled) {
		return "CANCELLED", "QUESTION_CANCELLED"
	}
	return "FAILED", "QUESTION_EXECUTION_FAILED"
}

func (service *Service) fail(ctx context.Context, access database.AccessContext, runID, workspaceID, status, failureCode string) error {
	cleanupCtx, cancel := questionFailureCleanupContext(ctx)
	defer cancel()
	return service.db.Write(cleanupCtx, access, func(txCtx context.Context, tx database.Transaction) error {
		completedAt := service.now().UTC()
		updated, err := tx.Exec(txCtx, `UPDATE public.question_run SET result_status = $4, completed_at = $5, failure_code = $6 WHERE organization_id = $1 AND id = $2 AND workspace_id = $3 AND result_status IN ('QUEUED','RUNNING')`, access.OrganizationID, runID, workspaceID, status, completedAt, failureCode)
		if err != nil {
			return err
		}
		if updated.RowsAffected() == 0 {
			return nil
		}
		eventID, err := service.newID("aud")
		if err != nil {
			return err
		}
		qrunID := runID
		code := failureCode
		_, err = service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorType(access.EffectiveActorKind()),
			ActorPrincipalID: &access.PrincipalID, Action: audit.ActionQuestionFailed,
			ResourceType: audit.ResourceQuestionRun, ResourceID: runID, RequestID: access.RequestID,
			Outcome: audit.OutcomeFailed, ErrorCode: &code, ReferencedEvidenceIDs: []string{},
			Metadata: audit.Metadata{QuestionRunID: &qrunID}, OccurredAt: completedAt,
		})
		return err
	})
}

func questionFailureCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	// Keep request values for access/audit metadata, but do not let request
	// cancellation remove the bounded opportunity to persist terminal failure.
	return context.WithTimeout(context.WithoutCancel(parent), questionFailureCleanupTimeout)
}

func (service *Service) lookupIdempotency(ctx context.Context, access database.AccessContext, key, requestHash, workspaceID string) (Run, bool, error) {
	if service.lookupIdempotencyFn != nil {
		return service.lookupIdempotencyFn(ctx, access, key, requestHash, workspaceID)
	}
	var runID, storedHash, storedWorkspace string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `SELECT canonical_request_hash, workspace_id, question_run_id FROM public.question_idempotency WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key = $3`, access.OrganizationID, access.PrincipalID, key).Scan(&storedHash, &storedWorkspace, &runID)
	})
	if database.IsNotFound(err) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, &Error{code: CodeUnavailable, cause: err}
	}
	if storedHash != requestHash || storedWorkspace != workspaceID {
		return Run{}, false, &Error{code: CodeIdempotencyConflict}
	}
	result, getErr := service.Get(ctx, access, workspaceID, runID)
	if getErr != nil {
		return Run{}, false, getErr
	}
	return result, true, nil
}

// previousTurnQuestionText loads the literal question text of the
// immediately preceding turn in this conversation, for the minimal topic
// memory splice in Create (FIX-1 #4). It re-checks CURRENT read access to
// that turn exactly as Get does (ACL-007/ACL-010: an old turn's binding is
// never itself an authority) -- rights are re-verified on every hop, not
// inherited from when the turn was created. Any failure -- no prior turn,
// it is no longer readable, or an artifact error -- returns ("", nil): the
// caller must treat that exactly like "no memory available" and plan the
// bare follow-up on its own terms, never as a license to guess.
func (service *Service) previousTurnQuestionText(ctx context.Context, access database.AccessContext, workspaceID, conversationID string) (string, string, error) {
	if service.previousTurnQuestionFn != nil {
		return service.previousTurnQuestionFn(ctx, access, workspaceID, conversationID)
	}
	var runID string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT question_run_id
			  FROM public.conversation_turn
			 WHERE organization_id = $1 AND conversation_id = $2 AND workspace_id = $3
			 ORDER BY turn_index DESC LIMIT 1
		`, access.OrganizationID, conversationID, workspaceID).Scan(&runID)
	})
	if err != nil {
		return "", "", nil
	}
	var questionText string
	err = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var readable bool
		if readErr := tx.QueryRow(txCtx, `SELECT app.question_run_readable($1, $2)`, runID, workspaceID).Scan(&readable); readErr != nil {
			return readErr
		}
		if !readable {
			return errPreviousTurnUnreadable
		}
		owner, envelope, fetchErr := service.artifacts.Fetch(txCtx, tx, access, artifactcrypto.QuestionText, runID)
		if fetchErr != nil {
			return fetchErr
		}
		plain, openErr := service.codec.Open(owner, envelope)
		if openErr != nil {
			return openErr
		}
		questionText = string(plain)
		clear(plain)
		return nil
	})
	if err != nil {
		return "", "", nil
	}
	return questionText, runID, nil
}

// toolLoopConversationTurn is the bounded conversation context made available
// to the tool loop. Its contents are included only after current-access checks
// through GetBatch.
type toolLoopConversationTurn struct {
	Question string
}

// recentToolLoopConversationTurns loads the most recent readable turns before
// excludeTurnID, then returns them in chronological order for model context.
// It deliberately keeps the history small and uses GetBatch's governed,
// audited read path for all question and answer content.
func (service *Service) recentToolLoopConversationTurns(ctx context.Context, access database.AccessContext, workspaceID, conversationID, excludeTurnID string, limit int) ([]toolLoopConversationTurn, error) {
	if limit <= 0 {
		return []toolLoopConversationTurn{}, nil
	}
	if limit > 4 {
		limit = 4
	}

	type turnRef struct {
		turnID string
		runID  string
	}
	var refs []turnRef
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, queryErr := tx.Query(txCtx, `
			SELECT prior.id, prior.question_run_id
			  FROM public.conversation_turn AS current_turn
			  JOIN public.conversation_turn AS prior
			    ON prior.organization_id = current_turn.organization_id
			   AND prior.conversation_id = current_turn.conversation_id
			   AND prior.workspace_id = current_turn.workspace_id
			   AND prior.turn_index < current_turn.turn_index
			  JOIN public.question_run AS prior_run
			    ON prior_run.organization_id = prior.organization_id
			   AND prior_run.id = prior.question_run_id
			   AND prior_run.workspace_id = prior.workspace_id
			 WHERE current_turn.organization_id = $1
			   AND current_turn.conversation_id = $2
			   AND current_turn.workspace_id = $3
			   AND current_turn.id = $4
			   AND prior_run.result_status IN ('COMPLETED', 'INSUFFICIENT_EVIDENCE')
			   AND prior_run.question_text_artifact_id IS NOT NULL
			   AND (prior_run.answer_markdown_artifact_id IS NOT NULL OR NULLIF(prior_run.planner_clarification, '') IS NOT NULL)
			 ORDER BY prior.turn_index DESC
			 LIMIT $5
		`, access.OrganizationID, conversationID, workspaceID, excludeTurnID, limit)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var ref turnRef
			if scanErr := rows.Scan(&ref.turnID, &ref.runID); scanErr != nil {
				return scanErr
			}
			refs = append(refs, ref)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	if len(refs) == 0 {
		return []toolLoopConversationTurn{}, nil
	}

	runIDs := make([]string, 0, len(refs))
	for _, ref := range refs {
		runIDs = append(runIDs, ref.runID)
	}
	runs, err := service.GetBatch(ctx, access, workspaceID, runIDs)
	if err != nil {
		return nil, err
	}
	return toolLoopConversationTurnsFromBatch(runIDs, runs), nil
}

// toolLoopConversationTurnsFromBatch projects only runs that survived the
// governed GetBatch read. In particular, a live-query run denied during
// current-access reauthorization has no map entry and its question cannot be
// supplied as context to the next model call.
func toolLoopConversationTurnsFromBatch(runIDs []string, runs map[string]Run) []toolLoopConversationTurn {
	turns := make([]toolLoopConversationTurn, 0, len(runIDs))
	for i := len(runIDs) - 1; i >= 0; i-- {
		run, ok := runs[runIDs[i]]
		if !ok {
			continue
		}
		turns = append(turns, toolLoopConversationTurn{Question: run.Question})
	}
	return turns
}

var errPreviousTurnUnreadable = errors.New("question: previous turn not currently readable")

func (service *Service) loadScopeBindings(ctx context.Context, tx database.Transaction, organizationID, workspaceID string, revision int64) ([]scopeBinding, error) {
	rows, err := tx.Query(ctx, `SELECT source_scope_id, source_scope_revision, access_mode, scope_config_hash, enabled FROM public.workspace_revision_source WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $3 ORDER BY source_scope_id`, organizationID, workspaceID, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []scopeBinding{}
	for rows.Next() {
		var item scopeBinding
		if err := rows.Scan(&item.ScopeID, &item.Revision, &item.AccessMode, &item.ConfigHash, &item.Enabled); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// Source-binding reads remain at the question service's existing read-only
// projection boundary. History may expose uncited search and metadata results.
// An unrelated workspace mutation must not hide history when the complete
// source tuple set is unchanged. Source changes still close this conservative
// guard; every observed fragment is separately reauthorized at disclosure.
func currentToolLoopScope(ctx context.Context, tx toolLoopDisclosureScanner, access database.AccessContext, run Run) (bool, error) {
	var current bool
	err := tx.ScanRow(ctx, `WITH current_workspace AS (
		SELECT current_revision FROM public.workspace WHERE organization_id=$1 AND id=$2
	), captured_bindings AS (
		SELECT source_scope_id, source_scope_revision, access_mode, scope_config_hash, enabled
		FROM public.workspace_revision_source
		WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=$3
	), current_bindings AS (
		SELECT source_scope_id, source_scope_revision, access_mode, scope_config_hash, enabled
		FROM public.workspace_revision_source
		WHERE organization_id=$1 AND workspace_id=$2
		AND workspace_revision=(SELECT current_revision FROM current_workspace)
	)
	SELECT EXISTS (SELECT 1 FROM current_workspace) AND NOT EXISTS (
		(SELECT * FROM captured_bindings EXCEPT SELECT * FROM current_bindings)
		UNION ALL
		(SELECT * FROM current_bindings EXCEPT SELECT * FROM captured_bindings)
	) AND NOT EXISTS (
		SELECT 1 FROM current_bindings b WHERE b.enabled
		AND NOT EXISTS (SELECT 1 FROM app.question_corpus_source_status($2,b.source_scope_id,b.source_scope_revision) s WHERE s.trust_verified)
	)`, []any{access.OrganizationID, run.WorkspaceID, run.WorkspaceRevision}, &current)
	return current, err
}

func (service *Service) persistCorpusSnapshots(ctx context.Context, tx database.Transaction, access database.AccessContext,
	runID, workspaceID string, workspaceRevision int64, bindings []scopeBinding, capturedAt time.Time) (bool, error) {
	if service == nil || service.retrievalStore == nil || len(bindings) == 0 {
		return false, nil
	}
	complete := true
	enabledCount := 0
	for _, binding := range bindings {
		if !binding.Enabled {
			continue
		}
		enabledCount++
		var (
			connectorType, connectorVersion string
			health                          string
			watermark                       int64
			contentFreshnessSLA             *int64
			lastSuccessfulSync              any
			trustVerified                   bool
		)
		if err := tx.QueryRow(ctx, `
			SELECT connector_type, connector_version, health, content_watermark,
			       last_successful_sync, trust_verified
			  FROM app.question_corpus_source_status($1,$2,$3)`, workspaceID,
			binding.ScopeID, binding.Revision).Scan(&connectorType, &connectorVersion, &health,
			&watermark, &lastSuccessfulSync, &trustVerified); err != nil {
			return false, fmt.Errorf("corpus status lookup scope=%s revision=%d: %w", binding.ScopeID, binding.Revision, err)
		}
		if err := tx.QueryRow(ctx, `
			SELECT app.question_corpus_content_freshness_sla($1,$2,$3)`,
			workspaceID, binding.ScopeID, binding.Revision).Scan(&contentFreshnessSLA); err != nil {
			return false, fmt.Errorf("freshness SLA lookup scope=%s revision=%d: %w", binding.ScopeID, binding.Revision, err)
		}
		var successfulSync *time.Time
		if value, ok := lastSuccessfulSync.(time.Time); ok {
			value = value.UTC()
			successfulSync = &value
		} else if lastSuccessfulSync != nil {
			return false, fmt.Errorf("corpus status returned unsupported sync timestamp type %T", lastSuccessfulSync)
		}
		slaSeconds := int64(0)
		if contentFreshnessSLA != nil {
			slaSeconds = *contentFreshnessSLA
		}
		contentFresh := contentFreshWithinSLA(capturedAt, successfulSync, slaSeconds)
		health = effectiveCorpusHealth(health, contentFresh)
		if !trustVerified || health != "HEALTHY" || binding.AccessMode == "SOURCE_ENFORCED" ||
			!contentFresh {
			complete = false
		}
		snapshotID, err := service.newID("corp")
		if err != nil {
			return false, err
		}
		if err := service.retrievalStore.CreateCorpusSnapshot(ctx, tx, access, retrieval.CorpusSnapshot{
			ID: snapshotID, OrganizationID: access.OrganizationID, QuestionRunID: runID,
			SourceScopeID: binding.ScopeID, SourceScopeRevision: binding.Revision,
			AccessMode: binding.AccessMode, ScopeConfigHash: binding.ConfigHash,
			ConnectorType: connectorType, ConnectorVersion: connectorVersion,
			Health: health, ContentWatermark: watermark, LastSuccessfulSync: successfulSync,
			CapturedAt: capturedAt,
		}); err != nil {
			return false, err
		}
	}
	if enabledCount == 0 {
		complete = false
	}
	_ = workspaceRevision
	return complete, nil
}

// contentFreshWithinSLA is the server-owned freshness decision used before a
// Question Run can be marked COMPLETE. A successful status alone is not enough:
// absent, future-dated or over-SLA sync timestamps fail closed. The pointer is
// used because PostgreSQL reports no successful sync as NULL.
func contentFreshWithinSLA(capturedAt time.Time, lastSuccessfulSync *time.Time, slaSeconds int64) bool {
	if capturedAt.IsZero() || lastSuccessfulSync == nil || lastSuccessfulSync.IsZero() || slaSeconds < 1 {
		return false
	}
	capturedAt = capturedAt.UTC()
	last := lastSuccessfulSync.UTC()
	if last.After(capturedAt) {
		return false
	}
	return capturedAt.Sub(last) <= time.Duration(slaSeconds)*time.Second
}

func effectiveCorpusHealth(health string, contentFresh bool) string {
	if health == "HEALTHY" && !contentFresh {
		// Persist the same effective state used for the PARTIAL decision. A
		// source cannot be reported as HEALTHY to monitoring/audit consumers
		// when its successful sync is absent, future-dated or outside its SLA.
		return "STALE"
	}
	return health
}

// selectCandidates keeps lexical retrieval deliberately conservative.  A
// structured aggregate may expand that lexical hit only to sibling cells of
// the same immutable source row/version, and only when the row carries an
// explicit date evidence cell for a date-scoped question.  This prevents a
// Russian/English business label from accidentally summing unrelated rows or
// historical values just because they happen to be numeric.
func selectCandidates(candidates []candidate, questionText string) []candidate {
	return selectCandidatesAt(candidates, questionText, time.Now())
}

func selectCandidatesAt(candidates []candidate, questionText string, now time.Time) []candidate {
	planned, err := planner.Default().Plan(questionText)
	if err != nil {
		return nil
	}
	return selectCandidatesAtPlan(candidates, planned, now)
}

func selectCandidatesAtPlan(candidates []candidate, planned planner.Plan, now time.Time) []candidate {
	if planned.Validate() != nil || planned.Status != planner.Ready {
		return nil
	}
	terms := retrievalTerms(planned.SubjectTerms)
	// A question with no searchable terms cannot establish a relationship to
	// any Evidence fragment.  Returning the corpus in that case would turn a
	// malformed/underspecified request into an answer assembled from unrelated
	// data, so the authority fails closed and lets complete() persist an
	// explicit INSUFFICIENT_EVIDENCE result.
	if len(terms) == 0 {
		return nil
	}
	// Date filters are server-owned authorization constraints for every
	// non-aggregate operation. Aggregate keeps its row-level expansion path
	// below, but lookup/explain/compare/audit/code-trace must not let lexical
	// retrieval disclose an undated or out-of-period fragment. A source row or
	// document is authorized only when a sibling Evidence fragment proves a
	// date in the bounded scope; otherwise selection fails closed.
	var temporalRows map[string]struct{}
	if planned.Operation != planner.Aggregate && hasTemporalPlanFilter(planned.Filters) {
		start, end, scoped := aggregateDateRange(planned, now)
		if !scoped {
			return nil
		}
		temporalRows = collectTemporalEvidenceRows(candidates, start, end)
	}
	var equalityRows map[string]map[string]struct{}
	if hasEqualityPlanFilter(planned.Filters) {
		equalityRows = collectEqualityEvidenceRows(candidates, planned.Filters)
	}
	var aggregateRows map[string]struct{}
	if planned.Operation == planner.Aggregate {
		if planned.Aggregate != nil && planned.Aggregate.Function == "SUM" && planned.Aggregate.Metric == "" && !candidatesHaveNumericEvidence(candidates) {
			// Source-neutral fallback (V1-A): the planner's lexical default for
			// an unmarked aggregate question is SUM, but nothing in the
			// retrieved Evidence for this plan carries a numeric cell at all —
			// e.g. "how many vehicles are on a trip today" over row cards with no
			// numeric EVIDENCE column. Summation is structurally impossible
			// here, so counting matching rows is the only aggregate this data
			// admits. This never fires when a numeric cell exists but is
			// merely ambiguous or unresolved; that stays the existing
			// CodeIncomplete failure in the reducer.
			planned.Aggregate.Function = "COUNT"
		}
		aggregateRows = eligibleAggregateRows(candidates, planned, now)
	}
	type scored struct {
		item  candidate
		score int
	}
	scoredItems := make([]scored, 0, len(candidates))
	for _, item := range candidates {
		if len(item.Text) == 0 {
			continue
		}
		if planned.Operation == planner.Aggregate {
			anchor, ok := parsePostgresCellAnchor(item.Anchor)
			if !ok {
				// The current analytic adapter consumes structured PostgreSQL
				// business-object cells only. Other source kinds remain valid
				// retrieval inputs for LOOKUP/COMPARE/AUDIT but cannot be
				// silently coerced into a numeric aggregate.
				continue
			}
			if _, ok := aggregateRows[aggregateRowKey(item, anchor)]; !ok {
				continue
			}
		}
		textTerms := tokenize(string(item.Text))
		counts := make(map[string]int, len(textTerms))
		for _, term := range textTerms {
			counts[term]++
		}
		score := 0
		for _, term := range terms {
			score += counts[term]
		}
		// Compare/audit/code-trace are explicit-fact authorities. Prefer an
		// Evidence line whose source-owned key resolves to a term in the
		// immutable plan (for example `payload[/status]` for the natural term
		// `status`). Without this bounded key signal, frequent source prose can
		// outrank the actual fact cells in a MatchAny lexical page and make a
		// valid generic comparison look unsupported. The boost changes ranking
		// only; the Evidence gate and renderer still require the exact line,
		// lineage and citation.
		if planned.Operation == planner.Compare || planned.Operation == planner.Audit || planned.Operation == planner.CodeTrace {
			score += explicitFactKeyBoost(item, terms)
		}
		if score > 0 && candidateMatchesPlanFilters(item, planned, now, temporalRows, equalityRows) {
			scoredItems = append(scoredItems, scored{item: item, score: score})
		}
	}
	sort.SliceStable(scoredItems, func(i, j int) bool {
		if scoredItems[i].score != scoredItems[j].score {
			return scoredItems[i].score > scoredItems[j].score
		}
		if scoredItems[i].item.Ordinal != scoredItems[j].item.Ordinal {
			return scoredItems[i].item.Ordinal < scoredItems[j].item.Ordinal
		}
		return scoredItems[i].item.ID < scoredItems[j].item.ID
	})
	selectionLimit := maxCitations
	if planned.Operation == planner.Aggregate {
		// Aggregates need complete authorized rows before the renderer applies
		// its citation budget. Truncating lexical hits at the output citation
		// limit can drop a second group dimension and turn a valid result into a
		// misleading partial total.
		selectionLimit = maxCandidates
	}
	if len(scoredItems) > selectionLimit {
		scoredItems = scoredItems[:selectionLimit]
	}
	result := make([]candidate, len(scoredItems))
	for i, value := range scoredItems {
		result[i] = value.item
	}
	return expandAggregateCandidates(candidates, result, planned, now)
}

const explicitFactKeyRankBoost = 1000

// explicitFactKeyBoost is deliberately narrow and source-agnostic. It only
// observes an explicit equality line already present in an authorized
// candidate and gives it a deterministic ranking preference when its field
// leaf exactly matches a planner subject term. It never resolves aliases,
// guesses values or broadens a workspace scope; ambiguous or absent fields
// therefore continue to fail closed in the renderer.
func explicitFactKeyBoost(item candidate, terms []string) int {
	if len(terms) == 0 {
		return 0
	}
	facts := extractExplicitFacts([]candidate{item})
	if len(facts) == 0 {
		return 0
	}
	requested := make(map[string]struct{}, len(terms))
	for _, term := range terms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term != "" {
			requested[term] = struct{}{}
		}
	}
	for _, fact := range facts {
		leaf := factKeyLeaf(fact.normalKey)
		if _, ok := requested[leaf]; ok {
			return explicitFactKeyRankBoost
		}
	}
	return 0
}

// eligibleAggregateRows narrows a generic aggregate to complete structured
// source rows that actually carry the declared metric/group dimensions. A
// lexical query may return date/context cells from other business objects;
// admitting those rows would make the reducer report an ambiguous metric or
// count unrelated domains. The row key is derived solely from immutable
// source/version/lineage anchors, never from a question noun.
func eligibleAggregateRows(candidates []candidate, planned planner.Plan, now time.Time) map[string]struct{} {
	rows := make(map[string]struct {
		columns map[string]struct{}
		numeric map[string]struct{}
		date    bool
	})
	spec := planned.Aggregate
	if spec == nil {
		return nil
	}
	dateStart, dateEnd, dateScoped := aggregateDateRange(planned, now)
	for _, item := range candidates {
		anchor, ok := parsePostgresCellAnchor(item.Anchor)
		if !ok {
			continue
		}
		key := aggregateRowKey(item, anchor)
		if key == "" {
			continue
		}
		state := rows[key]
		if state.columns == nil {
			state.columns = make(map[string]struct{})
			state.numeric = make(map[string]struct{})
		}
		column := aggregateTermIdentity(aggregateColumn(anchor))
		state.columns[column] = struct{}{}
		if label, _, numeric := decimalEvidence(item.Text); numeric && aggregateTermsEqual(label, aggregateColumn(anchor)) {
			state.numeric[column] = struct{}{}
		}
		if dateScoped && dateEvidenceInRange(item.Text, dateStart, dateEnd) {
			state.date = true
		}
		rows[key] = state
	}
	eligible := make(map[string]struct{}, len(rows))
	for key, state := range rows {
		if dateScoped && !state.date {
			continue
		}
		if spec.Function != "COUNT" {
			if spec.Metric != "" {
				if _, ok := state.numeric[aggregateTermIdentity(spec.Metric)]; !ok && len(state.numeric) != 1 {
					continue
				}
			} else if len(state.numeric) != 1 {
				continue
			}
		}
		validGroups := true
		for _, group := range spec.GroupBy {
			if _, ok := state.columns[aggregateTermIdentity(group)]; !ok {
				validGroups = false
				break
			}
		}
		if validGroups {
			eligible[key] = struct{}{}
		}
	}
	return eligible
}

func hasTemporalPlanFilter(filters []planner.Filter) bool {
	for _, filter := range filters {
		switch filter.Name {
		case "time_range", "time_window", "time_period":
			return true
		}
	}
	return false
}

func hasEqualityPlanFilter(filters []planner.Filter) bool {
	for _, filter := range filters {
		if strings.HasPrefix(filter.Name, "equals:") {
			return true
		}
	}
	return false
}

func candidateScopeKey(item candidate) string {
	if len(item.Anchor) > 0 {
		var kindOnly struct {
			Kind string `json:"kind"`
		}
		if jsonv2.Unmarshal(item.Anchor, &kindOnly) == nil && kindOnly.Kind == "POSTGRESQL_QUERY_CELL" {
			// An explicitly PG-typed anchor is not allowed to broaden into a
			// document-level key when any required row identity is malformed.
			// Otherwise a sibling date/equality witness could authorize a forged
			// fragment before the durable Evidence gate has a chance to reject it.
			anchor, ok := parsePostgresCellAnchor(item.Anchor)
			if !ok {
				return ""
			}
			if key := aggregateRowKey(item, anchor); key != "" {
				return "pg\x00" + key
			}
			return ""
		}
	}
	if anchor, ok := parsePostgresCellAnchor(item.Anchor); ok {
		if key := aggregateRowKey(item, anchor); key != "" {
			return "pg\x00" + key
		}
	}
	if item.SourceObjectID != "" || item.SourceVersionID != "" {
		return "source\x00" + item.SourceObjectID + "\x00" + item.SourceVersionID
	}
	return ""
}

func candidateTemporalKey(item candidate) string { return candidateScopeKey(item) }

func collectTemporalEvidenceRows(candidates []candidate, start, end time.Time) map[string]struct{} {
	rows := make(map[string]struct{})
	for _, item := range candidates {
		if !dateEvidenceInRange(item.Text, start, end) {
			continue
		}
		if key := candidateTemporalKey(item); key != "" {
			rows[key] = struct{}{}
		}
	}
	return rows
}

func equalityWitnessKey(filter planner.Filter) string {
	return strings.ToLower(strings.TrimSpace(filter.Name)) + "\x00" + strings.ToLower(strings.TrimSpace(filter.Value))
}

func evidenceMatchesEqualityFilter(item candidate, filter planner.Filter) bool {
	anchor, ok := parsePostgresCellAnchor(item.Anchor)
	return ok && aggregateTermsEqual(aggregateColumn(anchor), strings.TrimPrefix(filter.Name, "equals:")) &&
		strings.EqualFold(aggregateCellValue(item.Text, anchor), filter.Value)
}

func collectEqualityEvidenceRows(candidates []candidate, filters []planner.Filter) map[string]map[string]struct{} {
	rows := make(map[string]map[string]struct{})
	for _, item := range candidates {
		key := candidateScopeKey(item)
		if key == "" {
			continue
		}
		for _, filter := range filters {
			if !strings.HasPrefix(filter.Name, "equals:") || !evidenceMatchesEqualityFilter(item, filter) {
				continue
			}
			witnesses := rows[key]
			if witnesses == nil {
				witnesses = make(map[string]struct{})
				rows[key] = witnesses
			}
			witnesses[equalityWitnessKey(filter)] = struct{}{}
		}
	}
	return rows
}

func candidateMatchesPlanFilters(item candidate, planned planner.Plan, now time.Time, temporalRows map[string]struct{}, equalityRows map[string]map[string]struct{}) bool {
	if planned.Operation != planner.Aggregate && hasTemporalPlanFilter(planned.Filters) {
		start, end, scoped := aggregateDateRange(planned, now)
		if !scoped {
			return false
		}
		// A natural-language document can carry the requested temporal fact in
		// its own text (for example, "Removed today ...") without a
		// PostgreSQL date-cell anchor. Keep that direct Evidence usable for
		// lookup/explain while retaining the strict sibling-row rule for
		// structured business objects. A mere mention never broadens a PG row
		// and never turns an unrelated undated fragment into a match.
		directMention := !isPostgreSQLCandidate(item) && temporalMention(item.Text, planned.Filters)
		if !directMention {
			if key := candidateTemporalKey(item); key != "" {
				if _, ok := temporalRows[key]; !ok {
					return false
				}
			} else if !dateEvidenceInRange(item.Text, start, end) {
				return false
			}
		}
	}
	for _, filter := range planned.Filters {
		if !strings.HasPrefix(filter.Name, "equals:") {
			continue
		}
		if key := candidateScopeKey(item); key != "" {
			witnesses, ok := equalityRows[key]
			if !ok {
				return false
			}
			if _, ok := witnesses[equalityWitnessKey(filter)]; !ok {
				return false
			}
			continue
		}
		if !evidenceMatchesEqualityFilter(item, filter) {
			return false
		}
	}
	return true
}

func isPostgreSQLCandidate(item candidate) bool {
	if len(item.Anchor) == 0 {
		return false
	}
	var kindOnly struct {
		Kind string `json:"kind"`
	}
	return jsonv2.Unmarshal(item.Anchor, &kindOnly) == nil && kindOnly.Kind == "POSTGRESQL_QUERY_CELL"
}

// temporalMention recognizes only the planner's server-owned period values.
// It is intentionally lexical and local to one Evidence fragment; ranges and
// relative windows still require a structured date witness because a free-form
// sentence cannot safely establish their exact boundaries.
func temporalMention(text []byte, filters []planner.Filter) bool {
	tokens := tokenize(string(text))
	if len(tokens) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		seen[token] = struct{}{}
	}
	for _, filter := range filters {
		if filter.Name != "time_period" {
			continue
		}
		period := strings.ToLower(strings.TrimSpace(filter.Value))
		if period != "" {
			if _, ok := seen[period]; ok {
				return true
			}
		}
	}
	return false
}

// retrievalTerms keeps planner terms canonical while making lexical matching
// tolerant of compound words such as "compliance-controls" and structured
// identifiers such as "control_c17". The planner's
// immutable plan/hash is unchanged; this is only a source-language token
// normalization step before post-authorized Evidence scoring.
func retrievalTerms(terms []string) []string {
	result := make([]string, 0, len(terms)*2)
	seen := make(map[string]struct{}, len(terms)*2)
	for _, term := range terms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term == "" {
			continue
		}
		parts := append([]string{term}, strings.FieldsFunc(term, func(r rune) bool {
			return r == '_' || r == '-' || r == '\u2010' || r == '\u2011' || r == '\u2012' || r == '\u2013' || r == '\u2014'
		})...)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" || len([]rune(part)) < 2 {
				continue
			}
			if _, exists := seen[part]; exists {
				continue
			}
			seen[part] = struct{}{}
			result = append(result, part)
		}
	}
	return result
}

type postgresCellAnchor struct {
	Kind                string `json:"kind"`
	ProjectionLineageID string `json:"projection_lineage_id"`
	RowVersionHash      string `json:"row_version_hash"`
	ColumnName          string `json:"column_name"`
	JSONPath            string `json:"json_path"`
}

func parsePostgresCellAnchor(raw []byte) (postgresCellAnchor, bool) {
	var anchor postgresCellAnchor
	if len(raw) == 0 || jsonv2.Unmarshal(raw, &anchor) != nil || anchor.Kind != "POSTGRESQL_QUERY_CELL" ||
		anchor.ProjectionLineageID == "" || anchor.RowVersionHash == "" || anchor.ColumnName == "" {
		return postgresCellAnchor{}, false
	}
	if anchor.JSONPath != "" && !validJSONPointer(anchor.JSONPath) {
		return postgresCellAnchor{}, false
	}
	return anchor, true
}

// aggregateColumn is the source-neutral field identity presented to the
// analytic reducer. Scalar columns retain their historical name; a JSON leaf
// is qualified with its exact RFC-6901 path so two numeric fields in one
// payload cannot be silently merged.
func aggregateColumn(anchor postgresCellAnchor) string {
	if anchor.JSONPath == "" {
		return anchor.ColumnName
	}
	return anchor.ColumnName + "[" + anchor.JSONPath + "]"
}

// aggregateTermIdentity treats SQL column names case-insensitively while
// retaining the exact JSON Pointer suffix. RFC-6901 object member names are
// case-sensitive; strings.EqualFold over the whole term would merge distinct
// Evidence paths such as payload[/Region] and payload[/region].
func aggregateTermIdentity(value string) string {
	value = strings.TrimSpace(value)
	if open := strings.IndexByte(value, '['); open >= 0 {
		return strings.ToLower(value[:open]) + value[open:]
	}
	return strings.ToLower(value)
}

func aggregateTermsEqual(left, right string) bool {
	return aggregateTermIdentity(left) == aggregateTermIdentity(right)
}

func validJSONPointer(path string) bool {
	if path == "" || len(path) > 4096 || path[0] != '/' || !utf8.ValidString(path) {
		return path == ""
	}
	for index := 0; index < len(path); {
		r, size := utf8.DecodeRuneInString(path[index:])
		if r == utf8.RuneError && size == 1 || r < 0x20 || r >= 0x7f && r <= 0x9f {
			return false
		}
		if r == '~' {
			if index+1 >= len(path) || path[index+1] != '0' && path[index+1] != '1' {
				return false
			}
			index += 2
			continue
		}
		index += size
	}
	return true
}

func aggregateRowKey(item candidate, anchor postgresCellAnchor) string {
	if item.SourceObjectID == "" || item.SourceVersionID == "" || anchor.ProjectionLineageID == "" || anchor.RowVersionHash == "" {
		return ""
	}
	return item.SourceObjectID + "\x00" + item.SourceVersionID + "\x00" + anchor.ProjectionLineageID + "\x00" + anchor.RowVersionHash
}

func aggregateDateRange(planned planner.Plan, now time.Time) (start, end time.Time, scoped bool) {
	now = now.UTC()
	day := func(value time.Time) time.Time {
		return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
	}
	for _, filter := range planned.Filters {
		if filter.Name == "time_range" {
			parts := strings.Split(filter.Value, "/")
			if len(parts) != 2 {
				return time.Time{}, time.Time{}, false
			}
			parsedStart, startErr := time.ParseInLocation("2006-01-02", parts[0], time.UTC)
			parsedEnd, endErr := time.ParseInLocation("2006-01-02", parts[1], time.UTC)
			if startErr != nil || endErr != nil || !parsedStart.Before(parsedEnd) {
				return time.Time{}, time.Time{}, false
			}
			return parsedStart, parsedEnd, true
		}
		if filter.Name == "time_window" && strings.HasPrefix(filter.Value, "last_days:") {
			countText := strings.TrimPrefix(filter.Value, "last_days:")
			count, parseErr := strconv.Atoi(countText)
			if parseErr != nil || count < 1 || count > 366 {
				return time.Time{}, time.Time{}, false
			}
			start = day(now).AddDate(0, 0, -(count - 1))
			return start, day(now).AddDate(0, 0, 1), true
		}
		switch strings.ToLower(filter.Value) {
		case "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today":
			start = day(now)
			return start, start.AddDate(0, 0, 1), true
		case "\u0432\u0447\u0435\u0440\u0430", "yesterday":
			start = day(now).AddDate(0, 0, -1)
			return start, start.AddDate(0, 0, 1), true
		case "\u043c\u0435\u0441\u044f\u0446", "month":
			start = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
			return start, start.AddDate(0, 1, 0), true
		case "\u043d\u0435\u0434\u0435\u043b\u044f", "week":
			start = day(now)
			// ISO weeks begin on Monday. Go's Sunday=0 is normalized without
			// consulting locale or process-global state.
			weekday := int(start.Weekday())
			mondayOffset := (weekday + 6) % 7
			start = start.AddDate(0, 0, -mondayOffset)
			return start, start.AddDate(0, 0, 7), true
		case "\u0433\u043e\u0434", "year":
			start = time.Date(now.Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
			return start, start.AddDate(1, 0, 0), true
		}
	}
	return time.Time{}, time.Time{}, false
}

func evidenceDate(text []byte) (time.Time, bool) {
	value := strings.TrimSpace(string(text))
	// PostgreSQL DATE/TIMESTAMPTZ cells are rendered as `column = value`.
	// Comparing only the canonical ISO date prefix avoids accepting a date
	// fragment assembled from separate citations.
	if len(value) < 14 {
		return time.Time{}, false
	}
	equals := strings.Index(value, " = ")
	if equals < 0 || equals+3+10 > len(value) {
		return time.Time{}, false
	}
	if !temporalColumn(strings.TrimSpace(value[:equals])) {
		return time.Time{}, false
	}
	dateText := value[equals+3 : equals+13]
	parsed, err := time.Parse("2006-01-02", dateText)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func dateEvidenceInRange(text []byte, start, end time.Time) bool {
	parsed, ok := evidenceDate(text)
	if !ok || start.IsZero() || end.IsZero() || !start.Before(end) {
		return false
	}
	return !parsed.Before(start.UTC()) && parsed.Before(end.UTC())
}

func dateEvidenceMatches(text []byte, target time.Time) bool {
	start := time.Date(target.UTC().Year(), target.UTC().Month(), target.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return dateEvidenceInRange(text, start, start.AddDate(0, 0, 1))
}

func expandAggregateCandidates(all, selected []candidate, planned planner.Plan, now time.Time) []candidate {
	if planned.Operation != planner.Aggregate || len(selected) == 0 || len(selected) >= maxCandidates {
		return selected
	}
	dateStart, dateEnd, dateScoped := aggregateDateRange(planned, now)
	type row struct {
		key       string
		items     []candidate
		anchors   []postgresCellAnchor
		selected  bool
		dateMatch bool
	}
	rows := make(map[string]*row)
	orderedKeys := make([]string, 0)
	for _, item := range all {
		anchor, ok := parsePostgresCellAnchor(item.Anchor)
		if !ok {
			continue
		}
		key := aggregateRowKey(item, anchor)
		if key == "" {
			continue
		}
		entry := rows[key]
		if entry == nil {
			entry = &row{key: key}
			rows[key] = entry
			orderedKeys = append(orderedKeys, key)
		}
		entry.items = append(entry.items, item)
		entry.anchors = append(entry.anchors, anchor)
		if dateScoped && dateEvidenceInRange(item.Text, dateStart, dateEnd) {
			entry.dateMatch = true
		}
	}
	selectedIDs := make(map[string]struct{}, len(selected))
	matchedSelectedRows := 0
	for _, item := range selected {
		selectedIDs[item.ID] = struct{}{}
		anchor, ok := parsePostgresCellAnchor(item.Anchor)
		if !ok {
			continue
		}
		if entry := rows[aggregateRowKey(item, anchor)]; entry != nil {
			entry.selected = true
			if dateScoped && entry.dateMatch {
				matchedSelectedRows++
			}
		}
	}
	if dateScoped && matchedSelectedRows > 0 {
		filtered := make([]candidate, 0, len(selected))
		for _, item := range selected {
			anchor, ok := parsePostgresCellAnchor(item.Anchor)
			if !ok {
				filtered = append(filtered, item)
				continue
			}
			entry := rows[aggregateRowKey(item, anchor)]
			if entry != nil && !entry.dateMatch {
				continue
			}
			filtered = append(filtered, item)
		}
		selected = filtered
	}
	add := make([]candidate, 0)
	for _, key := range orderedKeys {
		entry := rows[key]
		if entry == nil || !entry.selected || dateScoped && !entry.dateMatch {
			continue
		}
		// A row with an already lexically selected numeric cell names the only
		// safe aggregate column. Otherwise, expansion is allowed only when the
		// row has exactly one numeric column; multiple metrics require the
		// user to name the column explicitly.
		columns := make(map[string]struct{})
		for index, item := range entry.items {
			if label, _, ok := decimalEvidence(item.Text); ok && aggregateTermsEqual(label, aggregateColumn(entry.anchors[index])) {
				columns[aggregateColumn(entry.anchors[index])] = struct{}{}
			}
		}
		if len(columns) != 1 {
			continue
		}
		if dateScoped {
			// Carry one matching date cell with each expanded row. It remains
			// context (never a numeric input), but lets the authority prove the
			// temporal boundary instead of aggregating a row selected only by a
			// lexical metric term.
			dateItems := make([]candidate, 0, 1)
			for _, item := range entry.items {
				if dateEvidenceInRange(item.Text, dateStart, dateEnd) {
					dateItems = append(dateItems, item)
				}
			}
			sort.Slice(dateItems, func(i, j int) bool { return dateItems[i].ID < dateItems[j].ID })
			if len(dateItems) > 0 {
				if _, exists := selectedIDs[dateItems[0].ID]; !exists {
					add = append(add, dateItems[0])
				}
			}
		}
		for index, item := range entry.items {
			if _, exists := selectedIDs[item.ID]; exists {
				continue
			}
			if label, _, ok := decimalEvidence(item.Text); !ok || !aggregateTermsEqual(label, aggregateColumn(entry.anchors[index])) {
				continue
			}
			add = append(add, item)
		}
	}
	if len(add) == 0 || len(selected)+len(add) > maxCandidates {
		return selected
	}
	result := append(append([]candidate(nil), selected...), add...)
	return result
}

type structuredClaim struct {
	Number             int64  `json:"citation_number"`
	Text               string `json:"text"`
	EvidenceFragmentID string `json:"evidence_fragment_id"`
}

type structuredAnswer struct {
	ToolLoop           *ToolLoopRecord   `json:"tool_loop,omitempty"`
	SchemaVersion      string            `json:"schema_version"`
	QuestionRunID      string            `json:"question_run_id"`
	AnswerMode         string            `json:"answer_mode"`
	VerificationMethod string            `json:"verification_method"`
	AnswerHash         string            `json:"answer_hash"`
	Claims             []structuredClaim `json:"claims"`
	Citations          []Citation        `json:"citations"`
	// AnswerResult and Understood are FIX-2 #1/#2's additive projections.
	// Both are optional and were absent from every structured artifact
	// written before this change; decoding an older artifact simply leaves
	// them nil, never an error.
	AnswerResult *AnswerResult `json:"answer_result,omitempty"`
	Understood   *Understood   `json:"understood,omitempty"`

	AnalyticScalar *analyticScalarObservation `json:"analytic_scalar,omitempty"`
	// AnalyticScalarDependency is the opaque, sealed partner of
	// AnalyticScalar. It is artifact-only: it is written into this one
	// encrypted document and is never copied into Run, REST, MCP, model
	// context, logs or audit metadata, and its bytes are never echoed in
	// failure output.
	AnalyticScalarDependency jsontext.Value `json:"analytic_scalar_dependency,omitempty"`
	// GovernedQueryDependency is the opaque sealed dependency for a complete
	// live-table result in ToolLoop. It is private artifact content and never a
	// public Run, REST, MCP, service-state, log or audit projection.
	GovernedQueryDependency jsontext.Value `json:"governed_query_dependency,omitempty"`

	// These private copies are retained only for the later source reader gate;
	// they are never marshaled or projected.
	analyticScalarPair        *analyticScalarPair
	governedQueryDependencies []governedQueryDependency
}

// A versioned presentation is three copies of one exact answer digest: the sealed
// presentation envelope, the sealed structured answer, and question_run. A
// missing or changed markdown artifact must close both governed read paths
// before either path projects answer or evidence. Legacy records have no
// presentation envelope and retain their original read behavior.
func storedTypedMetricAnswerMatches(answer, runAnswerHash string, structured structuredAnswer) bool {
	loop := structured.ToolLoop
	if loop == nil || (loop.PresentationVersion == nil && loop.PresentationLanguage == nil && loop.PresentationAnswerHash == nil) {
		return true
	}
	if loop.PresentationVersion == nil || !supportedMetricPresentation(*loop.PresentationVersion) ||
		loop.PresentationLanguage == nil || loop.PresentationAnswerHash == nil || answer == "" {
		return false
	}
	answerHash := canon.Hash([]byte(answer))
	return answerHash == *loop.PresentationAnswerHash && answerHash == structured.AnswerHash && answerHash == runAnswerHash
}

// A versioned answer may quote a sealed structured citation. Before either governed
// read discloses it, bind that copy to the separately gated citation row and
// CitedExcerpt artifact. Legacy runs retain their existing citation behavior.
func typedMetricCitationsMatchGated(loop *ToolLoopRecord, structured, gated []Citation) bool {
	if loop == nil || loop.PresentationVersion == nil {
		return true
	}
	if !supportedMetricPresentation(*loop.PresentationVersion) || len(structured) != len(gated) {
		return false
	}
	byID := make(map[string]Citation, len(gated))
	numbers := make(map[int64]struct{}, len(gated))
	for _, citation := range gated {
		if citation.CitationID == "" || citation.Number < 1 ||
			canon.Hash([]byte(citation.Excerpt)) != citation.ExcerptHash {
			return false
		}
		if _, duplicate := byID[citation.CitationID]; duplicate {
			return false
		}
		if _, duplicate := numbers[citation.Number]; duplicate {
			return false
		}
		byID[citation.CitationID] = citation
		numbers[citation.Number] = struct{}{}
	}
	for _, citation := range structured {
		independent, found := byID[citation.CitationID]
		if !found || citation.Number != independent.Number ||
			citation.Excerpt != independent.Excerpt || citation.ExcerptHash != independent.ExcerptHash {
			return false
		}
		delete(byID, citation.CitationID)
	}
	return len(byID) == 0
}

func marshalStructuredAnswer(runID, answerHash string, citations []Citation, answerResult *AnswerResult, understood *Understood, toolLoops ...*ToolLoopRecord) ([]byte, error) {
	return marshalStructuredAnswerWithAnalyticScalarPair(runID, answerHash, citations, answerResult, understood, nil, toolLoops...)
}

// marshalStructuredAnswerWithAnalyticScalarPair is marshalStructuredAnswer plus
// the one inseparable trusted scalar pair. A present pair is encoded exactly
// once through encodeAnalyticScalarPair; both returned members are written into
// the same structured answer before the single JSON marshal, so a scalar can
// never be persisted without its exact dependency or vice versa. Any pair
// refusal returns the content-free CodeInvalid and no artifact bytes.
func marshalStructuredAnswerWithAnalyticScalarPair(runID, answerHash string, citations []Citation, answerResult *AnswerResult, understood *Understood, pair *analyticScalarPair, toolLoops ...*ToolLoopRecord) ([]byte, error) {
	return marshalStructuredAnswerWithDependencies(runID, answerHash, citations, answerResult, understood, pair, nil, toolLoops...)
}

func marshalStructuredAnswerWithDependencies(runID, answerHash string, citations []Citation, answerResult *AnswerResult, understood *Understood, pair *analyticScalarPair, dependency *governedQueryDependency, toolLoops ...*ToolLoopRecord) ([]byte, error) {
	var dependencies []governedQueryDependency
	if dependency != nil {
		dependencies = []governedQueryDependency{*dependency}
	}
	return marshalStructuredAnswerWithDependencyList(runID, answerHash, citations, answerResult, understood, pair, dependencies, toolLoops...)
}

func marshalStructuredAnswerWithDependencyList(runID, answerHash string, citations []Citation, answerResult *AnswerResult, understood *Understood, pair *analyticScalarPair, dependencies []governedQueryDependency, toolLoops ...*ToolLoopRecord) ([]byte, error) {
	if !validOpaque(runID) || len(toolLoops) > 1 {
		return nil, &Error{code: CodeInvalid}
	}
	structured := structuredAnswer{
		SchemaVersion: "extractive-answer-v1", QuestionRunID: runID, AnswerMode: answerMode,
		VerificationMethod: verification, AnswerHash: answerHash, Claims: make([]structuredClaim, 0, len(citations)),
		Citations: citations, AnswerResult: answerResult, Understood: understood,
	}
	if pair != nil {
		observation, dependency, err := encodeAnalyticScalarPair(runID, *pair)
		if err != nil {
			return nil, &Error{code: CodeInvalid}
		}
		structured.AnalyticScalar = &observation
		structured.AnalyticScalarDependency = dependency
	}
	var toolLoop *ToolLoopRecord
	if len(toolLoops) > 0 && toolLoops[0] != nil {
		toolLoop = toolLoops[0]
		structured.ToolLoop = toolLoop
		structured.AnswerMode, structured.VerificationMethod = AnswerModeToolLoop, verificationAddress
	}
	if !validateGovernedQueryAnswerResults(runID, dependencies, toolLoop, answerResult) {
		return nil, &Error{code: CodeInvalid}
	}
	if !validateToolLoopClaimEvidence(runID, "", toolLoop, dependencies, citations) {
		return nil, &Error{code: CodeInvalid}
	}
	if len(dependencies) > 0 {
		encoded, err := encodeGovernedQueryDependencies(runID, dependencies)
		if err != nil {
			return nil, &Error{code: CodeInvalid}
		}
		structured.GovernedQueryDependency = encoded
	}
	for _, citation := range citations {
		structured.Claims = append(structured.Claims, structuredClaim{
			Number: citation.Number, Text: citation.Excerpt, EvidenceFragmentID: citation.EvidenceFragment,
		})
	}
	return jsonv2.Marshal(structured)
}

// structuredAnswerDependencyPresence distinguishes an absent dependency from
// an explicit JSON null. structuredAnswer itself cannot tell them apart because
// both decode to an empty jsontext.Value. This shadow keeps the raw member value
// long enough to apply the legacy-absence rule; it is decode-only and never
// marshaled.
type structuredAnswerDependencyPresence struct {
	AnalyticScalar           jsontext.Value `json:"analytic_scalar"`
	AnalyticScalarDependency jsontext.Value `json:"analytic_scalar_dependency"`
	GovernedQueryDependency  jsontext.Value `json:"governed_query_dependency"`
}

// analyticScalarNull reports whether either scalar member name was present as
// the JSON null literal. The strict structuredAnswer decode has already refused
// unknown and duplicate names before this runs, so the presence decode only has
// to recover which members the document named and with which raw kind.
func (presence structuredAnswerDependencyPresence) analyticScalarNull() bool {
	return presence.AnalyticScalar.Kind() == jsontext.KindNull ||
		presence.AnalyticScalarDependency.Kind() == jsontext.KindNull
}

func (presence structuredAnswerDependencyPresence) governedQueryNull() bool {
	return presence.GovernedQueryDependency.Kind() == jsontext.KindNull
}

// decodeStructuredAnswer is the single strict read back of the server-written
// structured answer artifact: the supplied trusted Question Run must be a valid
// opaque identity and must equal the artifact's own QuestionRunID byte for byte,
// unknown members and duplicate names are refused, and each optional source
// dependency must match its own sealed result. Any run or dependency failure
// returns the exact zero structured answer plus a content-free CodeUnavailable.
// Both halves of the scalar pair absent and the governed dependency absent are
// legacy-compatible; explicit null or an unmatched successful live call is
// refused. Valid dependencies are retained privately for the later reader gate.
func decodeStructuredAnswer(expectedRunID string, raw []byte) (structuredAnswer, error) {
	if !validOpaque(expectedRunID) {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	var structured structuredAnswer
	if err := jsonv2.Unmarshal(raw, &structured, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	if !validPresentationFieldPresence(raw) {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	if structured.QuestionRunID != expectedRunID {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	var presence structuredAnswerDependencyPresence
	if err := jsonv2.Unmarshal(raw, &presence, jsontext.AllowDuplicateNames(false)); err != nil {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	pair, pairErr := decodeAnalyticScalarPair(expectedRunID, structured.AnalyticScalar, structured.AnalyticScalarDependency)
	if presence.analyticScalarNull() || pairErr != nil {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	governedDependencies, governedErr := decodeGovernedQueryDependencies(expectedRunID, structured.GovernedQueryDependency)
	if presence.governedQueryNull() || governedErr != nil || !validateGovernedQueryAnswerResults(expectedRunID, governedDependencies, structured.ToolLoop, structured.AnswerResult) ||
		!validateToolLoopClaimEvidence(expectedRunID, "", structured.ToolLoop, governedDependencies, structured.Citations) {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	if pair != nil {
		structured.AnalyticScalar = &pair.observation
		structured.analyticScalarPair = pair
	}
	structured.governedQueryDependencies = governedDependencies
	return structured, nil
}

// Pointer fields cannot distinguish absence from an explicit JSON null. A
// null presentation member would otherwise erase the v2 marker and let the
// artifact be interpreted under the older v1 answer rules.
func validPresentationFieldPresence(raw []byte) bool {
	var outer struct {
		ToolLoop jsontext.Value `json:"tool_loop"`
	}
	if err := jsonv2.Unmarshal(raw, &outer, jsontext.AllowDuplicateNames(false)); err != nil {
		return false
	}
	if outer.ToolLoop.Kind() != jsontext.KindBeginObject {
		return true
	}
	var members map[string]jsontext.Value
	if err := jsonv2.Unmarshal(outer.ToolLoop, &members, jsontext.AllowDuplicateNames(false)); err != nil {
		return false
	}
	count := 0
	for _, name := range []string{"presentation_version", "presentation_language", "presentation_answer_hash"} {
		if value, present := members[name]; present {
			if value.Kind() == jsontext.KindNull {
				return false
			}
			count++
		}
	}
	return count == 0 || count == 3
}

// decodeStructuredAnswerCleared is the governed-reader boundary around
// decodeStructuredAnswer. It always clears the decrypted structured-answer
// plaintext before returning, on both the accepted and the refused path, and
// every strict refusal becomes the exact zero structured answer plus the
// content-free CodeUnavailable. Both readStoredRun and readStoredRunBatch use
// it, so a present artifact that fails decode can never leave its plaintext
// live in a caller's buffer next to a partially projected Run.
func decodeStructuredAnswerCleared(expectedRunID string, plain []byte) (structuredAnswer, error) {
	structured, err := decodeStructuredAnswer(expectedRunID, plain)
	clear(plain)
	if err != nil {
		return structuredAnswer{}, &Error{code: CodeUnavailable}
	}
	return structured, nil
}

func renderAnswer(workspaceID, questionText string, selected []candidate) (string, []Citation) {
	planned, err := planner.Default().Plan(questionText)
	if err != nil {
		return "", []Citation{}
	}
	return renderAnswerPlanAt(workspaceID, questionText, planned, selected, time.Now())
}

func renderAnswerPlan(workspaceID, questionText string, planned planner.Plan, selected []candidate) (string, []Citation) {
	return renderAnswerPlanAt(workspaceID, questionText, planned, selected, time.Now())
}

func renderAnswerPlanAt(workspaceID, questionText string, planned planner.Plan, selected []candidate, now time.Time) (string, []Citation) {
	answer, citations, _ := renderAnswerPlanAtWithReceipt(workspaceID, questionText, planned, selected, now)
	return answer, citations
}

// aggregateWithheldOnPartialCorpus is the QRY-002 / SRCH-004 decision named
// once so it can be proved directly: an exact aggregate is never published
// over a corpus this run did not see all of. See the call site in complete()
// for why prose and numbers degrade differently under truncation.
func aggregateWithheldOnPartialCorpus(planned planner.Plan, partial bool) bool {
	return partial && planned.Status == planner.Ready && planned.Operation == planner.Aggregate
}

func renderAnswerPlanAtWithReceipt(workspaceID, questionText string, planned planner.Plan, selected []candidate, now time.Time) (string, []Citation, *analytic.Receipt) {
	return renderAnswerPlanAtWithReceiptContext(context.Background(), workspaceID, questionText, planned, selected, now)
}

// renderAnswerPlanAtWithReceiptContext is the request-scoped rendering path
// used by Question Service.  The compatibility wrapper above is retained for
// deterministic in-process callers, but production requests must carry their
// cancellation/deadline into the typed analytic registry.
func renderAnswerPlanAtWithReceiptContext(ctx context.Context, workspaceID, questionText string, planned planner.Plan, selected []candidate, now time.Time) (string, []Citation, *analytic.Receipt) {
	if ctx == nil || ctx.Err() != nil {
		return "", []Citation{}, nil
	}
	if planned.Validate() != nil || len(selected) == 0 {
		return "", []Citation{}, nil
	}
	citations := make([]Citation, 0, len(selected))
	var toolReceipt *analytic.Receipt
	if planned.Operation == planner.Aggregate {
		// Every aggregate, including an ungrouped SUM, goes through the same
		// typed Evidence adapter. There is intentionally no legacy regex
		// shortcut: the adapter emits a sealed receipt and the caller persists
		// the exact generic plan/tool provenance for every analytic result.
		if aggregate, ok := renderAnalyticAggregateContext(ctx, workspaceID, planned, selected, &citations, &toolReceipt); ok {
			return aggregate, citations, toolReceipt
		}
		// A ready aggregate is a typed analytic request, not permission to fall
		// back to prose snippets when its metric/group contract is unresolved.
		// The caller will persist the bounded insufficient-evidence terminal
		// state.
		return "", []Citation{}, toolReceipt
	}
	if planned.Operation == planner.Compare {
		answer, citations := renderCompareFacts(workspaceID, planned, selected)
		return answer, citations, toolReceipt
	}
	if planned.Operation == planner.Explain {
		if answer, definitionCitations := renderExplainDefinitions(workspaceID, planned, selected); answer != "" {
			return answer, definitionCitations, toolReceipt
		}
	}
	if planned.Operation == planner.CodeTrace {
		if answer, traceCitations := renderCodeTrace(workspaceID, planned, selected); answer != "" {
			return answer, traceCitations, toolReceipt
		}
	}
	if planned.Operation == planner.Audit {
		if answer, auditCitations := renderAuditControls(workspaceID, planned, selected); answer != "" {
			return answer, auditCitations, toolReceipt
		}
	}
	// Audit, Compare and CodeTrace have dedicated conservative explicit-fact
	// authorities above. Keep LOOKUP/EXPLAIN on the extractive foundation; an
	// unsupported ready operation must not fall back to an arbitrary snippet.
	if planned.Operation != planner.Lookup && planned.Operation != planner.Explain {
		return "", []Citation{}, toolReceipt
	}
	var answer strings.Builder
	questionTerms := tokenize(questionText)
	for _, item := range selected {
		excerpt := bestSentence(item.Text, questionTerms)
		if excerpt == "" {
			continue
		}
		if answer.Len() > 0 {
			answer.WriteString("\n\n")
		}
		answer.WriteString(excerpt)
		citationNumber := int64(len(citations) + 1)
		answer.WriteString(fmt.Sprintf(" [%d]", citationNumber))
		citations = append(citations, Citation{
			Number: citationNumber, EvidenceFragment: item.ID, Excerpt: excerpt,
			Anchor: string(item.Anchor), DeepLink: "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID,
			SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID, SourceObjectID: item.SourceObjectID,
			// EvidenceTextHash is the trusted organization-keyed projection
			// captured with the authorized candidate. Re-hashing plaintext here
			// would produce a public SHA equality oracle and would fail the
			// question_citation binding constraint.
			EvidenceTextHash: item.TextHash, ExcerptHash: canon.Hash([]byte(excerpt)),
		})
	}
	return answer.String(), citations, toolReceipt
}

var decimalEvidencePattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_$]{0,62}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n]*\])?) = (-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?)$`)

func decimalEvidence(text []byte) (label, value string, ok bool) {
	match := decimalEvidencePattern.FindStringSubmatch(strings.TrimSpace(string(text)))
	if len(match) != 3 {
		return "", "", false
	}
	return match[1], match[2], true
}

// candidatesHaveNumericEvidence reports whether any retrieved candidate
// carries a numeric "column = value" Evidence line. It is the source-neutral
// signal selectCandidatesAtPlan uses to decide whether an unmarked SUM
// default can be honoured at all for this plan's actual Evidence.
func candidatesHaveNumericEvidence(candidates []candidate) bool {
	for _, item := range candidates {
		if _, _, numeric := decimalEvidence(item.Text); numeric {
			return true
		}
	}
	return false
}

func renderNumericAggregate(workspaceID string, planned planner.Plan, selected []candidate, citations *[]Citation, receiptOut **analytic.Receipt, now time.Time) (string, bool) {
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Aggregate || len(selected) == 0 || len(selected) > maxCandidates {
		return "", false
	}
	if dateStart, dateEnd, scoped := aggregateDateRange(planned, now); scoped {
		dateEvidenceFound := false
		for _, item := range selected {
			if dateEvidenceInRange(item.Text, dateStart, dateEnd) {
				dateEvidenceFound = true
				break
			}
		}
		if !dateEvidenceFound {
			return "", false
		}
	}
	if planned.Aggregate != nil && (len(planned.Aggregate.GroupBy) > 0 || planned.Aggregate.Order != "" || planned.Aggregate.Function != "SUM") {
		// The typed Evidence adapter is the authority for group-by/rank and
		// non-sum operations. If the row/column contract cannot be resolved,
		// return false so renderAnswer emits bounded evidence snippets instead
		// of silently collapsing the request to a total.
		return renderAnalyticAggregate(workspaceID, planned, selected, citations, receiptOut)
	}
	total := new(big.Rat)
	maxScale := 0
	columnName := ""
	numericItems := make([]candidate, 0, len(selected))
	for _, item := range selected {
		if (analytic.Evidence{
			ID: item.ID, SourceObjectID: item.SourceObjectID, SourceVersionID: item.SourceVersionID,
			ExtractionID: item.ExtractionID, TextHash: item.TextHash, AnchorHash: item.AnchorHash,
			ContentHash: item.ContentHash,
		}).Validate() != nil {
			return "", false
		}
		anchor, fullAnchor := parsePostgresCellAnchor(item.Anchor)
		if !fullAnchor {
			var kindOnly struct {
				Kind string `json:"kind"`
			}
			if jsonv2.Unmarshal(item.Anchor, &kindOnly) != nil || kindOnly.Kind != "POSTGRESQL_QUERY_CELL" {
				return "", false
			}
		}
		label, rawValue, numeric := decimalEvidence(item.Text)
		if !numeric || !aggregateTermsEqual(label, aggregateColumn(anchor)) {
			// Aggregate expansion may carry one or more lexical context cells
			// from the same immutable row. Context is never included in the
			// numeric total or citation list below.
			continue
		}
		// A sum is meaningful only within one declared projection column. The
		// anchor is checked by the Evidence viewer before it reaches this
		// renderer; matching the canonical `column = value` text here prevents a
		// mixed-column selection from being turned into a fabricated total.
		if columnName == "" {
			columnName = label
		} else if columnName != label {
			return "", false
		}
		value, ok := new(big.Rat).SetString(rawValue)
		if !ok {
			return "", false
		}
		total.Add(total, value)
		if dot := strings.IndexByte(rawValue, '.'); dot >= 0 && len(rawValue)-dot-1 > maxScale {
			maxScale = len(rawValue) - dot - 1
		}
		numericItems = append(numericItems, item)
	}
	if len(numericItems) == 0 {
		return "", false
	}
	if len(numericItems) > maxAggregateCitations {
		return "", false
	}
	// Every context cell must share the exact object/version/row tuple with
	// every numeric cell. This check keeps the renderer safe for direct callers
	// and prevents a lexical hit from another row becoming aggregate authority.
	numericKeys := make(map[string]struct{}, len(numericItems))
	for _, numeric := range numericItems {
		numericAnchor, ok := parsePostgresCellAnchor(numeric.Anchor)
		if !ok {
			continue
		}
		key := aggregateRowKey(numeric, numericAnchor)
		if key == "" {
			return "", false
		}
		numericKeys[key] = struct{}{}
	}
	contextKeys := make(map[string]struct{})
	for _, context := range selected {
		if _, _, numeric := decimalEvidence(context.Text); numeric {
			continue
		}
		contextAnchor, ok := parsePostgresCellAnchor(context.Anchor)
		if !ok {
			return "", false
		}
		contextKey := aggregateRowKey(context, contextAnchor)
		if contextKey == "" {
			return "", false
		}
		if _, ok := numericKeys[contextKey]; !ok {
			return "", false
		}
		contextKeys[contextKey] = struct{}{}
	}
	if len(contextKeys) != 0 {
		for key := range numericKeys {
			if _, ok := contextKeys[key]; !ok {
				return "", false
			}
		}
	}
	aggregateCitations := make([]Citation, 0, len(numericItems))
	for index, item := range numericItems {
		excerpt := strings.TrimSpace(string(item.Text))
		aggregateCitations = append(aggregateCitations, Citation{Number: int64(index + 1), EvidenceFragment: item.ID, Excerpt: excerpt, Anchor: string(item.Anchor), DeepLink: "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID, SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID, SourceObjectID: item.SourceObjectID, EvidenceTextHash: item.TextHash, ExcerptHash: canon.Hash([]byte(excerpt))})
	}
	if maxScale == 0 {
		maxScale = 0
	}
	*citations = append(*citations, aggregateCitations...)
	return "Total: " + total.FloatString(maxScale), true
}

// renderAnalyticAggregate binds planner output to the source-neutral analytic
// adapter.  The adapter receives only post-authorized cells; it cannot see SQL
// text, choose evidence, or manufacture a citation.  Citation material is
// assembled locally and committed only after the complete result validates.
func renderAnalyticAggregate(workspaceID string, planned planner.Plan, selected []candidate, citations *[]Citation, receiptOut **analytic.Receipt) (string, bool) {
	return renderAnalyticAggregateContext(context.Background(), workspaceID, planned, selected, citations, receiptOut)
}

func renderAnalyticAggregateContext(ctx context.Context, workspaceID string, planned planner.Plan, selected []candidate, citations *[]Citation, receiptOut **analytic.Receipt) (string, bool) {
	if ctx == nil || ctx.Err() != nil {
		return "", false
	}
	if planned.Aggregate == nil || planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Aggregate || len(selected) == 0 {
		return "", false
	}
	cells := make([]analytic.Cell, 0, len(selected))
	byID := make(map[string]candidate, len(selected))
	for _, item := range selected {
		anchor, ok := parsePostgresCellAnchor(item.Anchor)
		if !ok {
			return "", false
		}
		rawRowKey := aggregateRowKey(item, anchor)
		if rawRowKey == "" {
			return "", false
		}
		rowKey := canon.Hash([]byte(rawRowKey))
		valueText := strings.TrimSpace(string(item.Text))
		label, rawValue, numeric := decimalEvidence([]byte(valueText))
		if numeric && !aggregateTermsEqual(label, aggregateColumn(anchor)) {
			return "", false
		}
		cell := analytic.Cell{
			Evidence: analytic.Evidence{
				ID: item.ID, SourceObjectID: item.SourceObjectID, SourceVersionID: item.SourceVersionID,
				ExtractionID: item.ExtractionID, TextHash: item.TextHash, AnchorHash: item.AnchorHash, ContentHash: item.ContentHash,
			},
			RowKey: rowKey, Column: aggregateColumn(anchor),
		}
		if numeric && aggregateTermsEqual(label, aggregateColumn(anchor)) {
			cell.Numeric = true
			cell.Value = rawValue
		} else {
			cell.Value = aggregateCellValue(item.Text, anchor)
		}
		cells = append(cells, cell)
		byID[item.ID] = item
	}
	// The Question authority reaches the reducer only through the server-owned
	// allowlist.  The registry validates the full immutable planner output and
	// returns a sealed tool receipt; no renderer path can select an adapter or
	// pass SQL text directly.
	result, receipt, err := analytic.DefaultRegistry().Invoke(ctx, analytic.Invocation{
		WorkspaceID: workspaceID, ToolID: analytic.EvidenceReducerTool, Plan: planned, Cells: cells,
	})
	if err != nil || len(result.Buckets) == 0 {
		return "", false
	}
	if receiptOut != nil {
		*receiptOut = &receipt
	}
	localCitations := make([]Citation, 0, len(selected))
	citationIDs := make(map[string]struct{}, len(selected))
	appendCitation := func(ref analytic.EvidenceRef) bool {
		if _, exists := citationIDs[ref.ID]; exists {
			return true
		}
		item, ok := byID[ref.ID]
		if !ok || len(localCitations) >= maxAggregateCitations {
			return false
		}
		excerpt := strings.TrimSpace(string(item.Text))
		if excerpt == "" {
			return false
		}
		number := int64(len(localCitations) + 1)
		localCitations = append(localCitations, Citation{
			Number: number, EvidenceFragment: item.ID, Excerpt: excerpt, Anchor: string(item.Anchor),
			DeepLink:        "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID,
			SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID, SourceObjectID: item.SourceObjectID,
			EvidenceTextHash: item.TextHash, ExcerptHash: canon.Hash([]byte(excerpt)),
		})
		citationIDs[ref.ID] = struct{}{}
		return true
	}
	var answer strings.Builder
	// Preserve the compact total form for an ungrouped aggregate while still
	// persisting every citation in the structured response. Grouped/ranked
	// output keeps inline markers because each bucket/label is independently
	// disclosed and linked.
	inlineCitations := len(result.GroupBy) > 0
	for index, bucket := range result.Buckets {
		if index > 0 {
			answer.WriteString("\n")
		}
		if len(result.GroupBy) == 0 {
			answer.WriteString(aggregateLabel(result.Function) + ": " + bucket.Value)
		} else {
			answer.WriteString(fmt.Sprintf("%d. %s: %s", index+1, bucket.Key, bucket.Value))
		}
		for _, ref := range bucket.Evidence {
			if !appendCitation(ref) {
				return "", false
			}
			if inlineCitations {
				answer.WriteString(fmt.Sprintf(" [%d]", len(localCitations)))
			}
		}
		for _, ref := range bucket.FilterEvidence {
			before := len(localCitations)
			if !appendCitation(ref) {
				return "", false
			}
			if inlineCitations && len(localCitations) > before {
				answer.WriteString(fmt.Sprintf(" [%d]", len(localCitations)))
			}
		}
		for _, ref := range bucket.GroupEvidence {
			if !appendCitation(ref) {
				return "", false
			}
			if inlineCitations {
				answer.WriteString(fmt.Sprintf(" [%d]", len(localCitations)))
			}
		}
	}
	if answer.Len() == 0 {
		return "", false
	}
	*citations = append(*citations, localCitations...)
	return answer.String(), true
}

type aggregateBucket struct {
	Key         string
	Value       *big.Rat
	Count       int
	Scale       int
	GroupValues []string
	GroupItems  []candidate
	Numbers     []candidate
}

func renderStructuredAggregate(workspaceID string, planned planner.Plan, selected []candidate, citations *[]Citation) (string, bool) {
	spec := planned.Aggregate
	if spec == nil || len(selected) == 0 {
		return "", false
	}
	type cell struct {
		item    candidate
		anchor  postgresCellAnchor
		value   *big.Rat
		scale   int
		numeric bool
	}
	rows := make(map[string][]cell)
	orderedRows := make([]string, 0)
	numericColumns := make(map[string]struct{})
	for _, item := range selected {
		anchor, ok := parsePostgresCellAnchor(item.Anchor)
		if !ok {
			return "", false
		}
		key := aggregateRowKey(item, anchor)
		if key == "" {
			return "", false
		}
		if _, exists := rows[key]; !exists {
			orderedRows = append(orderedRows, key)
		}
		valueText := strings.TrimSpace(string(item.Text))
		label, rawValue, numeric := decimalEvidence([]byte(valueText))
		entry := cell{item: item, anchor: anchor}
		if numeric {
			if !aggregateTermsEqual(label, aggregateColumn(anchor)) {
				return "", false
			}
			value, valid := new(big.Rat).SetString(rawValue)
			if !valid {
				return "", false
			}
			entry.numeric = true
			entry.value = value
			if dot := strings.IndexByte(rawValue, '.'); dot >= 0 {
				entry.scale = len(rawValue) - dot - 1
			}
			numericColumns[aggregateTermIdentity(aggregateColumn(anchor))] = struct{}{}
		}
		rows[key] = append(rows[key], entry)
	}
	metricColumn := ""
	if len(numericColumns) == 1 {
		for column := range numericColumns {
			metricColumn = column
		}
	} else if spec.Metric != "" {
		for column := range numericColumns {
			if aggregateTermsEqual(column, spec.Metric) {
				metricColumn = column
			}
		}
	}
	if metricColumn == "" {
		return "", false
	}
	availableGroupColumns := make(map[string]struct{})
	for _, cells := range rows {
		for _, entry := range cells {
			if !entry.numeric {
				availableGroupColumns[aggregateTermIdentity(aggregateColumn(entry.anchor))] = struct{}{}
			}
		}
	}
	groupColumns := resolveAggregateGroupColumns(spec.GroupBy, availableGroupColumns)
	if len(spec.GroupBy) > 0 && len(groupColumns) != len(spec.GroupBy) {
		return "", false
	}

	buckets := make(map[string]*aggregateBucket)
	orderedBuckets := make([]string, 0)
	for _, rowKey := range orderedRows {
		cells := rows[rowKey]
		groupValues := make([]string, len(groupColumns))
		groupItems := make([]candidate, len(groupColumns))
		groupFound := make([]bool, len(groupColumns))
		var numberCells []cell
		for _, entry := range cells {
			if entry.numeric && aggregateTermsEqual(aggregateColumn(entry.anchor), metricColumn) {
				numberCells = append(numberCells, entry)
			}
			if !entry.numeric {
				for index, groupColumn := range groupColumns {
					if !aggregateTermsEqual(aggregateColumn(entry.anchor), groupColumn) {
						continue
					}
					value := aggregateCellValue(entry.item.Text, entry.anchor)
					if groupFound[index] && groupValues[index] != value {
						return "", false
					}
					groupFound[index] = true
					groupValues[index] = value
					groupItems[index] = entry.item
				}
			}
		}
		if len(numberCells) == 0 {
			return "", false
		}
		for index := range groupColumns {
			if !groupFound[index] || groupValues[index] == "" {
				return "", false
			}
		}
		bucketKey := "__all__"
		if len(groupColumns) > 0 {
			bucketKey = aggregateCompositeGroupKey(groupValues)
		}
		bucket := buckets[bucketKey]
		if bucket == nil {
			bucket = &aggregateBucket{Key: aggregateCompositeGroupLabel(groupValues), Value: new(big.Rat), GroupValues: append([]string(nil), groupValues...), GroupItems: append([]candidate(nil), groupItems...)}
			buckets[bucketKey] = bucket
			orderedBuckets = append(orderedBuckets, bucketKey)
		}
		for _, entry := range numberCells {
			bucket.Value.Add(bucket.Value, entry.value)
			bucket.Count++
			if entry.scale > bucket.Scale {
				bucket.Scale = entry.scale
			}
			bucket.Numbers = append(bucket.Numbers, entry.item)
		}
	}
	if len(buckets) == 0 {
		return "", false
	}
	for _, key := range orderedBuckets {
		bucket := buckets[key]
		if spec.Function == "AVG" && bucket.Count > 0 {
			bucket.Value.Quo(bucket.Value, big.NewRat(int64(bucket.Count), 1))
		} else if spec.Function == "COUNT" {
			bucket.Value.SetInt64(int64(bucket.Count))
			bucket.Scale = 0
		} else if spec.Function != "SUM" && spec.Function != "AVG" {
			// MIN/MAX need the individual values; re-read them deterministically.
			var chosen *big.Rat
			for _, item := range bucket.Numbers {
				_, rawValue, numeric := decimalEvidence(item.Text)
				if !numeric {
					return "", false
				}
				value, ok := new(big.Rat).SetString(rawValue)
				if !ok {
					return "", false
				}
				if chosen == nil || spec.Function == "MIN" && value.Cmp(chosen) < 0 || spec.Function == "MAX" && value.Cmp(chosen) > 0 {
					chosen = value
				}
			}
			if chosen == nil {
				return "", false
			}
			bucket.Value = chosen
		}
	}
	if spec.Order != "" {
		sort.SliceStable(orderedBuckets, func(i, j int) bool {
			cmp := buckets[orderedBuckets[i]].Value.Cmp(buckets[orderedBuckets[j]].Value)
			if spec.Order == "ASC" {
				return cmp < 0
			}
			return cmp > 0
		})
	}
	limit := len(orderedBuckets)
	if spec.Limit > 0 && spec.Limit < limit {
		limit = spec.Limit
	}
	var answer strings.Builder
	citationNumber := int64(0)
	for index := 0; index < limit; index++ {
		bucket := buckets[orderedBuckets[index]]
		value := bucket.Value.FloatString(bucket.Scale)
		if len(groupColumns) == 0 {
			answer.WriteString(aggregateLabel(spec.Function) + ": " + value)
		} else {
			answer.WriteString(fmt.Sprintf("%d. %s: %s", index+1, bucket.Key, value))
		}
		for _, item := range bucket.Numbers {
			citationNumber++
			if citationNumber > maxAggregateCitations {
				return "", false
			}
			excerpt := strings.TrimSpace(string(item.Text))
			answer.WriteString(fmt.Sprintf(" [%d]", citationNumber))
			*citations = append(*citations, Citation{Number: citationNumber, EvidenceFragment: item.ID, Excerpt: excerpt, Anchor: string(item.Anchor), DeepLink: "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID, SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID, SourceObjectID: item.SourceObjectID, EvidenceTextHash: item.TextHash, ExcerptHash: canon.Hash([]byte(excerpt))})
		}
		for _, groupItem := range bucket.GroupItems {
			if groupItem.ID == "" {
				return "", false
			}
			// Every group label is evidence; append each dimension's citation
			// after the numeric cells so the composite label is independently
			// traceable.
			citationNumber++
			if citationNumber > maxAggregateCitations {
				return "", false
			}
			excerpt := strings.TrimSpace(string(groupItem.Text))
			answer.WriteString(fmt.Sprintf(" [%d]", citationNumber))
			*citations = append(*citations, Citation{Number: citationNumber, EvidenceFragment: groupItem.ID, Excerpt: excerpt, Anchor: string(groupItem.Anchor), DeepLink: "/api/v1/workspaces/" + workspaceID + "/evidence/" + groupItem.ID, SourceVersionID: groupItem.SourceVersionID, ExtractionID: groupItem.ExtractionID, SourceObjectID: groupItem.SourceObjectID, EvidenceTextHash: groupItem.TextHash, ExcerptHash: canon.Hash([]byte(excerpt))})
		}
		if index+1 < limit {
			answer.WriteString("\n")
		}
	}
	return answer.String(), true
}

func resolveAggregateGroupColumns(requested []string, available map[string]struct{}) []string {
	if len(requested) == 0 {
		return nil
	}
	// This helper is intentionally kept source-neutral: callers provide the
	// already-authorized parsed cells. Exact matches preserve the requested
	// order; only a single unresolved semantic term may use one unambiguous
	// non-temporal fallback. Multi-dimensional requests never guess.
	resolved := make([]string, 0, len(requested))
	for _, term := range requested {
		term = aggregateTermIdentity(term)
		if _, ok := available[term]; ok {
			resolved = append(resolved, term)
			continue
		}
		if len(requested) != 1 {
			return nil
		}
		fallback := ""
		for column := range available {
			if temporalColumn(column) {
				continue
			}
			if fallback != "" {
				return nil
			}
			fallback = column
		}
		if fallback == "" {
			return nil
		}
		resolved = append(resolved, fallback)
	}
	return resolved
}

func aggregateCompositeGroupKey(values []string) string {
	var builder strings.Builder
	for _, value := range values {
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
		builder.WriteByte('|')
	}
	return builder.String()
}

func aggregateCompositeGroupLabel(values []string) string {
	if len(values) == 0 {
		return "__all__"
	}
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values, " / ")
}

func cellValue(text []byte) string {
	value := strings.TrimSpace(string(text))
	if equals := strings.Index(value, " = "); equals >= 0 {
		return strings.TrimSpace(value[equals+3:])
	}
	return value
}

func aggregateCellValue(text []byte, anchor postgresCellAnchor) string {
	value := cellValue(text)
	if anchor.JSONPath == "" {
		return value
	}
	// JSON leaf renderings use canonical JSON scalars. Decode a JSON string so
	// grouped labels remain the business value (North), while numbers, bools
	// and objects retain their canonical scalar text. Invalid JSON is left
	// untouched and will fail closed at the typed reducer boundary.
	var decoded string
	if jsonv2.Unmarshal([]byte(value), &decoded) == nil {
		return decoded
	}
	return value
}

func temporalColumn(column string) bool {
	lower := strings.ToLower(column)
	return strings.Contains(lower, "date") || strings.Contains(lower, "time") ||
		strings.Contains(lower, "timestamp") || strings.Contains(lower, "\u0434\u0430\u0442\u0430") || strings.Contains(lower, "\u0432\u0440\u0435\u043c\u044f") ||
		strings.HasSuffix(lower, "_at") || strings.HasSuffix(lower, "_on")
}

func aggregateLabel(function string) string {
	switch function {
	case "COUNT":
		return "Count"
	case "AVG":
		return "Average"
	case "MIN":
		return "Minimum"
	case "MAX":
		return "Maximum"
	default:
		return "Total"
	}
}

func exactSentence(text []byte) string {
	value := strings.TrimSpace(string(text))
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '!' || r == '?' || r == '\n' })
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return value
}

func bestSentence(text []byte, terms []string) string {
	value := strings.TrimSpace(string(text))
	if value == "" {
		return ""
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '.' || r == '!' || r == '?' || r == '\n' })
	best := ""
	bestScore := -1
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		counts := make(map[string]struct{}, len(tokenize(part)))
		for _, token := range tokenize(part) {
			counts[token] = struct{}{}
		}
		score := 0
		for _, term := range terms {
			if _, ok := counts[term]; ok {
				score++
			}
		}
		if score > bestScore {
			best, bestScore = part, score
		}
	}
	if best != "" {
		return best
	}
	return exactSentence(text)
}

func tokenize(value string) []string {
	value = strings.ToLower(value)
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			builder.WriteRune(r)
		} else {
			builder.WriteByte(' ')
		}
	}
	parts := strings.Fields(builder.String())
	result := parts[:0]
	for _, part := range parts {
		if len([]byte(part)) >= 3 {
			result = append(result, part)
		}
	}
	return result
}

func canonicalQuestion(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len([]byte(value)) > maxQuestionBytes || !utf8.ValidString(value) {
		return "", errors.New("invalid question")
	}
	canonical, err := canon.Canonicalize([]byte(value))
	if err != nil || len(canonical) == 0 {
		return "", errors.New("invalid question")
	}
	return string(canonical), nil
}

func requestHash(questionText, mode, conversationID string) string {
	return canon.Hash([]byte("question-request-v2\x00" + mode + "\x00" + conversationID + "\x00" + questionText))
}

func hashCanonical(value any) (string, error) {
	raw, err := jsonv2.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return "", err
	}
	return canon.Hash([]byte(canonical)), nil
}

func validIdempotencyKey(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(value) != value {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_-.:", r) {
			continue
		}
		return false
	}
	return true
}
