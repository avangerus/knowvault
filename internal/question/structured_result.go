package question

// FIX-2: structured, machine-readable projections that sit BESIDE the
// existing rendered prose (renderSnapshotAnswer, complete()'s markdown) --
// never a replacement for it. The server still renders text; these types let
// a client stop re-parsing that text to recover the rule/period/snapshot a
// human already reads in the answer paragraph. Every value here is data the
// server already computed for the rendered answer: nothing is invented for
// the wire shape alone.

import (
	"context"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	// ProcessingModeInternal, ProcessingModeExternal and
	// ProcessingModeInternalUnavailable are FIX-2 #4's closed processing_mode
	// vocabulary, derived from the SAME GENERATIVE-mode capability gate
	// Create already enforces (service.generation, EnableGeneration):
	// unconfigured generation reports Unavailable rather than defaulting to
	// Internal, exactly like an unconfigured candidate has no readiness
	// effect elsewhere in this authority.
	ProcessingModeInternal            = "INTERNAL"
	ProcessingModeExternal            = "EXTERNAL"
	ProcessingModeInternalUnavailable = "INTERNAL_UNAVAILABLE"
)

// ProcessingMode reports FIX-2 #4's workspace-scoped processing mode: whether
// a question over workspaceID could run its (optional) generative step on
// the operator's own bounded runtime (INTERNAL) or on an explicit,
// workspace-scoped external runtime (EXTERNAL, GEN-2's
// ExternalRuntimeWorkspaceIDs), and the provider name from that SAME mounted
// configuration. No configuration mounted, or this workspace not on the
// external allow-list, reports INTERNAL_UNAVAILABLE with no provider name --
// never a silent default to INTERNAL for a workspace that cannot actually
// reach it.
func (service *Service) ProcessingMode(workspaceID string) (string, string) {
	if service == nil || service.generation == nil || !service.generation.AllowsWorkspace(workspaceID) {
		return ProcessingModeInternalUnavailable, ""
	}
	provider := service.generation.ProviderName()
	if service.generation.RuntimeScope() == modelgateway.RuntimeScopeExternalWorkspaceScoped {
		return ProcessingModeExternal, provider
	}
	return ProcessingModeInternal, provider
}

// AnswerResult is the structured counterpart of a server-owned snapshot
// calculation or governed live-table result. It is populated only when the
// terminal answer has a validated structured result; other runs leave it
// absent, like answer_hash and manifest_hash before completion.
type AnswerResult struct {
	Kind         string         `json:"kind"`
	Value        string         `json:"value,omitempty"`
	Unit         string         `json:"unit,omitempty"`
	Operation    string         `json:"operation"`
	Rule         string         `json:"rule"`
	Filters      []AnswerFilter `json:"filters,omitempty"`
	Period       *AnswerPeriod  `json:"period,omitempty"`
	Timezone     string         `json:"timezone,omitempty"`
	Snapshot     AnswerSnapshot `json:"snapshot"`
	Keys         []AnswerKey    `json:"keys,omitempty"`
	Completeness string         `json:"completeness"`
	// R2 Outcome 3 unified fields, additive beside every R1 field above.
	// Every one is optional and every one is populated only from data this
	// same run already computed; a genuinely absent value stays empty so the
	// UI renders "no data" rather than an invented value. run_id is the
	// run this answer belongs to. Snapshot-calculation digests use the stable
	// snapshot/execution identity; LIVE_TABLE carries the exact digest of its
	// complete governed text-table result.
	RunID         string           `json:"run_id,omitempty"`
	Intent        *AnswerIntent    `json:"intent,omitempty"`
	RowsetRef     string           `json:"rowset_ref,omitempty"`
	MetricVersion string           `json:"metric_version,omitempty"`
	SnapshotID    string           `json:"snapshot_id,omitempty"`
	ExecutionID   string           `json:"execution_id,omitempty"`
	ResultDigest  string           `json:"result_digest,omitempty"`
	Freshness     *CorpusFreshness `json:"freshness,omitempty"`
	EvidenceRefs  []string         `json:"evidence_refs,omitempty"`
	AuditReceipt  []string         `json:"audit_receipt,omitempty"`
	// Governed live read receipt fields (additive; absent for legacy answers).
	ObservationWindow *AnswerObservationWindow `json:"observation_window,omitempty"`
	ReceiptDigest     string                   `json:"receipt_digest,omitempty"`
}

// AnswerObservationWindow is the server-observed wall-clock window around a
// bounded live governed read. It is provenance for the read call, not a source
// modification timestamp and not a client-supplied freshness claim.
type AnswerObservationWindow struct {
	Basis       string `json:"basis,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// AnswerIntent is R2 Outcome 3's read-only projection of the QueryIntent the
// server validated against an APPROVED MetricDefinition before this run
// executed. It is populated only by the outcome-2 question path; a run that
// never carried an intent simply omits the whole object, exactly like an older
// answer artifact, and the UI shows "no data".
type AnswerIntent struct {
	MetricID string         `json:"metric_id,omitempty"`
	Version  int64          `json:"version,omitempty"`
	Period   *AnswerPeriod  `json:"period,omitempty"`
	Filters  []AnswerFilter `json:"filters,omitempty"`
	Output   string         `json:"output,omitempty"`
	AsOf     string         `json:"as_of,omitempty"`
}

// AnswerFilter is one equality condition the reducer actually applied,
// server-recognized against a real snapshot column (reduceStructuredSnapshot
// declines a filter naming an unknown column rather than silently dropping
// it).
type AnswerFilter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AnswerPeriod is the half-open calendar window (snapshotWindow), reported
// closed/inclusive on the wire the same way renderSnapshotAnswer already
// prints it in prose.
type AnswerPeriod struct {
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Label string `json:"label,omitempty"`
}

// AnswerSnapshot identifies which structured source scope's current snapshot
// was reduced (ID = the bound, enabled source_scope_id the rows were grouped
// under; see snapshotRow.sourceScopeID) and how large it was. CapturedAt is
// filled by Get from the same corpus-freshness projection the run's own
// Freshness field already uses -- it is not persisted inside the structured
// artifact, so it always reflects the freshest read available for this run.
type AnswerSnapshot struct {
	ID         string     `json:"id,omitempty"`
	CapturedAt *time.Time `json:"captured_at,omitempty"`
	RowCount   int        `json:"row_count"`
}

// AnswerKey is one LIST entry: the distinct declared-TITLE value plus up to
// two other columns from a row that carried it, so a client can show more
// than a bare name without a second round trip. Fields preserves display
// values verbatim (never normalized), keyed by the snapshot's own column
// name.
type AnswerKey struct {
	Key    string            `json:"key"`
	Fields map[string]string `json:"fields,omitempty"`
}

// canonicalResultDigest returns the snapshot-calculation digest: the SHA-256
// of the canonical (RFC 8785/JCS) projection of the answer content plus its
// stable snapshot/execution identity and metric version. LIVE_TABLE uses the
// governedquery text-table digest instead, since its rows are sealed in the
// tool trace and are intentionally absent from AnswerResult.
func canonicalResultDigest(answer *AnswerResult) string {
	if answer == nil {
		return ""
	}
	projection := struct {
		Kind          string         `json:"kind"`
		Operation     string         `json:"operation"`
		Value         string         `json:"value"`
		Unit          string         `json:"unit"`
		Rule          string         `json:"rule"`
		Filters       []AnswerFilter `json:"filters"`
		Period        *AnswerPeriod  `json:"period"`
		Completeness  string         `json:"completeness"`
		Keys          []AnswerKey    `json:"keys"`
		Intent        *AnswerIntent  `json:"intent"`
		MetricVersion string         `json:"metric_version"`
		SnapshotID    string         `json:"snapshot_id"`
		ExecutionID   string         `json:"execution_id"`
	}{
		Kind: answer.Kind, Operation: answer.Operation, Value: answer.Value,
		Unit: answer.Unit, Rule: answer.Rule, Filters: answer.Filters,
		Period: answer.Period, Completeness: answer.Completeness, Keys: answer.Keys,
		Intent: answer.Intent, MetricVersion: answer.MetricVersion,
		SnapshotID: answer.SnapshotID, ExecutionID: answer.ExecutionID,
	}
	raw, err := canon.CanonicalJSON(projection)
	if err != nil {
		return ""
	}
	return canon.Hash(raw)
}

// CanonicalDigest returns this result's server-owned digest. Snapshot
// calculations are canonicalized here; LIVE_TABLE returns its independently
// verified exact table digest, whose rows remain sealed in ToolLoop.
func (answer *AnswerResult) CanonicalDigest() string {
	if answer != nil && answer.Kind == "LIVE_TABLE" {
		return answer.ResultDigest
	}
	return canonicalResultDigest(answer)
}

// Understood is the server-owned account of what a bare period follow-up
// ("and yesterday?") was resolved against (FIX-1 #4's splice), so a client can show
// "Understood as: ..." without guessing. It is populated only when Create
// actually spliced a follow-up filter onto a prior turn's own question text;
// every field is data this run already used (SpliceFollowUpPeriod's period,
// the resolved base run's own citations/plan), never inferred.
type Understood struct {
	Period            *AnswerPeriod `json:"period,omitempty"`
	Source            string        `json:"source,omitempty"`
	InheritedFromTurn string        `json:"inherited_from_turn_id,omitempty"`
	OtherConditions   []string      `json:"other_conditions,omitempty"`
}

// RowsetScopeMatched (the default, when the caller passes no scope or an
// empty one) and RowsetScopeFull are FIX-7 #1's closed vocabulary for
// StructuredRowset's scope parameter: matched returns only the rows that
// actually produced the citing answer (the reducer's own matched/witness
// set -- for an answer of "3 vehicles" exactly 3 rows); full is the explicit
// escape hatch to the source scope's entire current snapshot. A caller must
// ask for full by name; it is never the default.
const (
	RowsetScopeMatched = "matched"
	RowsetScopeFull    = "full"
)

// RowsetEvidence is the tabular counterpart of a text Evidence fragment: by
// default (RowsetScopeMatched) the current, re-authorized rows that fragment's
// own citing question run actually matched -- not the whole source scope,
// see FIX-7 #1 -- or, on explicit request (RowsetScopeFull), that structured
// source scope's entire current snapshot. StructuredRowset returns nil for a
// fragment that is not part of a structured snapshot (a document fragment
// keeps its existing text-only basis). Total is the row count of exactly the
// scope returned here (before the 50-row display cap); Snapshot.RowCount
// stays the full source scope's own size either way, matching AnswerResult's
// existing convention.
type RowsetEvidence struct {
	Columns     []string            `json:"columns"`
	Rows        []map[string]string `json:"rows"`
	Total       int                 `json:"total"`
	FilterLabel string              `json:"filter_label,omitempty"`
	Snapshot    AnswerSnapshot      `json:"snapshot"`
}

// SearchedSource is one entry of "where we searched" for a run that ended
// INSUFFICIENT_EVIDENCE: which bound source was consulted and why it did not
// produce a citation, in the same closed, content-free vocabulary the rest
// of the disclosure gate uses (no fragment, filename or query is disclosed).
type SearchedSource struct {
	Source  string `json:"source"`
	Result  string `json:"result"`
	Message string `json:"message"`
}

const (
	SearchedNotCovered  = "NOT_COVERED"
	SearchedNoMatches   = "NO_MATCHES"
	SearchedUnavailable = "UNAVAILABLE"
)

var searchedMessages = map[string]string{
	SearchedNotCovered:  "The source is connected, but the search budget did not cover all of its data in this request.",
	SearchedNoMatches:   "The source was accessible and checked; no matches were found.",
	SearchedUnavailable: "The source was unavailable at request time (not synchronized or disabled).",
}

// uncertaintyMessages / conflictMessages are the closed, human-readable
// Russian dictionary for FIX-2 #6: every code the deriveSignals/GENERATIVE
// paths actually emit (UncertaintyPlannerUnknown..GENERATION_UNAVAILABLE,
// the four typed Conflict codes). A code outside this table still gets a
// safe, content-free fallback rather than an empty string.
var uncertaintyMessages = map[string]string{
	UncertaintyPlannerUnknown:            "The question could not be interpreted as a specific task. Please make it more precise.",
	UncertaintyPlannerClarification:      "The question has more than one interpretation and needs clarification.",
	UncertaintyCorpusPartial:             "The source corpus is incomplete: the answer does not cover all data available in the workspace.",
	UncertaintyInsufficientEvidence:      "Relevant evidence was not found or is unavailable for display.",
	UncertaintyAmbiguousStructuredSource: "The question could not be unambiguously matched to one enabled structured source.",
	"GENERATION_UNAVAILABLE":             "Model-generated answers are unavailable for this request; try EXTRACTIVE mode.",
}

var conflictMessages = map[string]string{
	"CONFLICT_CODE_TRACE_VALUE":     "Sources describe the code value differently; review the evidence.",
	"CONFLICT_FACT_VALUE":           "Sources disagree on the value of the same fact.",
	"CONFLICT_AUDIT_CONTROL_STATUS": "Sources disagree on the control status; review the evidence.",
	"CONFLICT_DEFINITION_VALUE":     "Sources define the same term differently.",
}

func uncertaintyMessage(code string) string {
	if text, ok := uncertaintyMessages[code]; ok {
		return text
	}
	return "Uncertainty with an undocumented code: " + code + "."
}

func conflictMessage(code string) string {
	if text, ok := conflictMessages[code]; ok {
		return text
	}
	return "Source conflict with an undocumented code: " + code + "."
}

func attachUncertaintyMessages(items []Uncertainty) []Uncertainty {
	for index := range items {
		items[index].Message = uncertaintyMessage(items[index].Code)
	}
	return items
}

func attachConflictMessages(items []Conflict) []Conflict {
	for index := range items {
		items[index].Message = conflictMessage(items[index].Code)
	}
	return items
}

func containsUncertaintyCode(items []Uncertainty, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}

// understoodContextKey threads a splice's Understood value from Create,
// where the splice happens and the base turn is resolved, down to whichever
// terminal-persistence function this run ends up on (complete's extractive
// tail or persistTerminalRun's GENERATIVE/AGG-1 tail) without adding an
// Understood parameter to every function on that call path. It carries
// nothing but this run's own already-verified data.
type understoodContextKey struct{}

func contextWithUnderstood(ctx context.Context, understood *Understood) context.Context {
	if understood == nil {
		return ctx
	}
	return context.WithValue(ctx, understoodContextKey{}, understood)
}

func understoodFromContext(ctx context.Context) *Understood {
	if ctx == nil {
		return nil
	}
	understood, _ := ctx.Value(understoodContextKey{}).(*Understood)
	return understood
}

// reportingCalendar reads the tenant's reporting "today" and time zone,
// factored out of loadStructuredSnapshot so a splice's Understood.Period can
// use the exact same calendar the reducer itself would use, without loading
// a whole snapshot just to compute a date window.
func (service *Service) reportingCalendar(ctx context.Context, access database.AccessContext) (time.Time, string, error) {
	var today time.Time
	var zone string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT (now() AT TIME ZONE app.organization_reporting_time_zone())::date,
			       app.organization_reporting_time_zone()
		`).Scan(&today, &zone)
	})
	if err != nil {
		return time.Time{}, "", err
	}
	return today, zone, nil
}

// sourceNameForRun reports the connection name of the structured/document
// source the given run's FIRST citation belongs to, or "" if the run has no
// readable citation (a follow-up must not invent a source it cannot prove).
func (service *Service) sourceNameForRun(ctx context.Context, access database.AccessContext, runID string) string {
	var name string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT connection.name
			  FROM public.question_citation AS citation
			  JOIN public.source_object AS object
			    ON object.organization_id = citation.organization_id AND object.id = citation.source_object_id
			  JOIN public.source_connection AS connection
			    ON connection.organization_id = object.organization_id AND connection.id = object.connection_id
			 WHERE citation.organization_id = $1 AND citation.question_run_id = $2
			 ORDER BY citation.citation_number
			 LIMIT 1
		`, access.OrganizationID, runID).Scan(&name)
	})
	if err != nil {
		return ""
	}
	return name
}

// buildUnderstood assembles FIX-2 #2's "Understood as" projection for a
// successful period splice (FIX-1 #4). It never guesses: a follow-up filter
// that does not resolve to a real calendar window, or a base run this
// principal can no longer read, yields a nil Understood and the caller falls
// back to reporting nothing rather than an invented condition.
func (service *Service) buildUnderstood(ctx context.Context, access database.AccessContext, baseRunID, baseQuestion, followUpName, followUpValue string) *Understood {
	today, zone, err := service.reportingCalendar(ctx, access)
	if err != nil {
		return nil
	}
	start, end, scoped, ok := snapshotWindow([]planner.Filter{{Name: followUpName, Value: followUpValue}}, today)
	if !ok || !scoped {
		return nil
	}
	understood := &Understood{
		InheritedFromTurn: baseRunID,
		Period: &AnswerPeriod{
			From:  start.Format("2006-01-02"),
			To:    end.AddDate(0, 0, -1).Format("2006-01-02"),
			Label: followUpValue,
		},
	}
	_ = zone
	if basePlan, planErr := service.planQuestion(baseQuestion); planErr == nil {
		for _, filter := range basePlan.Filters {
			if strings.HasPrefix(filter.Name, "equals:") {
				understood.OtherConditions = append(understood.OtherConditions,
					strings.TrimPrefix(filter.Name, "equals:")+" = "+filter.Value)
			}
		}
	}
	if source := service.sourceNameForRun(ctx, access, baseRunID); source != "" {
		understood.Source = source
	}
	return understood
}

// buildUnderstoodFollowUp assembles FIX-6 #1's "Understood as" projection for a
// bare operation-only follow-up ("which ones?" after "how many vehicles are
// working today?"): unlike buildUnderstood (which reports a NEWLY spliced period),
// every condition here -- period, equality filters -- is inherited
// unchanged from the base turn, and combinedPlan is the already-validated
// re-plan of the spliced question (Create only calls this once that
// validation passed), so it is read directly rather than re-derived.
func (service *Service) buildUnderstoodFollowUp(ctx context.Context, access database.AccessContext, baseRunID string, combinedPlan planner.Plan) *Understood {
	today, _, err := service.reportingCalendar(ctx, access)
	if err != nil {
		return nil
	}
	understood := &Understood{InheritedFromTurn: baseRunID}
	if start, end, scoped, ok := snapshotWindow(combinedPlan.Filters, today); ok && scoped {
		label := ""
		for _, filter := range combinedPlan.Filters {
			if filter.Name == "time_period" || filter.Name == "time_window" {
				label = filter.Value
				break
			}
		}
		understood.Period = &AnswerPeriod{
			From:  start.Format("2006-01-02"),
			To:    end.AddDate(0, 0, -1).Format("2006-01-02"),
			Label: label,
		}
	}
	for _, filter := range combinedPlan.Filters {
		if strings.HasPrefix(filter.Name, "equals:") {
			understood.OtherConditions = append(understood.OtherConditions,
				strings.TrimPrefix(filter.Name, "equals:")+" = "+filter.Value)
		}
	}
	if source := service.sourceNameForRun(ctx, access, baseRunID); source != "" {
		understood.Source = source
	}
	return understood
}
