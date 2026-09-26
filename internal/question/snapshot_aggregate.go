package question

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// AGG-1 — exact answers over a structured source's CURRENT snapshot.
//
// knowvault-DECISIONS.md 5 makes "how many X today" and "which vehicles were on
// a route yesterday" over an operational SQL projection the product's main job.
// Two properties make that job unlike an extractive answer:
//
//   - The number has to be right, which means it has to be reduced from the
//     WHOLE snapshot. Retrieval is budgeted (maximumSearchHits), so any corpus
//     bigger than the budget is permanently PARTIAL, and a count taken over
//     that window silently reports "how many matching rows the search engine
//     returned" instead of "how many rows there are". That is not a smaller
//     answer, it is a wrong one.
//   - The comparison has to be typed. "started_at = 2026-09-07T01:00:00Z" is a
//     display string; deciding whether it falls on today is calendar
//     arithmetic in someone's time zone, not a prefix match.
//
// So this file reduces db/migrations/000073's typed cells — the same values
// that are already published Evidence fragments of the same snapshot, each one
// re-authorized here through app.evidence_fragment_readable — and lets the
// model do nothing but read the sentence back. When the reduction cannot be
// resolved exactly (no structured snapshot, an unresolvable filter, a metric
// that is not a real column), this path either persists a typed
// insufficient-evidence outcome when the loaded snapshot proves an unresolved
// metric, or declines to the ordinary retrieval answer, which fails closed on
// its own terms. It never
// narrows a request it did not fully understand and calls the result exact.
const (
	// A snapshot larger than this is not silently truncated into an "exact"
	// number: the reducer declines, because a partial snapshot cannot produce
	// one (review-opus-v1-stabilisation.md finding Z1).
	maxSnapshotCells = 400000
	maxSnapshotRows  = 50000
)

type snapshotCell struct {
	fragmentID  string
	ordinal     int
	column      string
	logicalType string
	title       bool
	// period is the owner's declared PERIOD role on this column (FIX-3 #1):
	// which temporal column "today"/"yesterday"/"for the week" scope by, when a
	// snapshot has more than one. Never set on a non-temporal cell (the
	// contract only accepts PERIOD on a DATE/TIMESTAMP/TIMESTAMPTZ column).
	period bool
	// status is the owner's declared STATUS role on this column (SEED-3 #1):
	// which column carries the row's lifecycle status, read by the
	// "overdue"/overdue condition to tell a genuinely overdue row from one
	// whose PERIOD date passed but is already closed.
	status  bool
	value   string
	numeric string
	// calendarDate is the cell's date in the tenant's reporting time zone,
	// computed by PostgreSQL from the typed value. Nil for non-temporal cells.
	calendarDate *time.Time
	// instant is the cell's precise point in time (a real timestamptz, never
	// truncated to a calendar day), used only by SEED-3 #1's "overdue"
	// condition: "the due date has passed" is a comparison against the
	// current instant, not against today's date -- a deadline earlier TODAY
	// (verified live: two of demo_ops.citizen_requests_v's real overdue rows
	// have today's date but an earlier time of day) is still overdue, and
	// snapshotRowInWindow's day-granularity comparison would silently miss
	// it. Nil for non-temporal cells.
	instant *time.Time
}

type snapshotRow struct {
	versionID string
	// sourceScopeID is the structured source scope this row's SourceObject
	// currently, actively belongs to (public.source_object_scope) AND that is
	// bound and enabled in THIS workspace at its current revision
	// (public.workspace_revision_source). Two structured sources ever bound to
	// the same workspace publish rows into the same
	// public.structured_snapshot_cell table with no other column that tells
	// them apart; grouping by this field before reducing is what keeps AGG-1
	// from mixing COUNT/LIST rows across sources (review backlog item, FIN-1),
	// and requiring the workspace binding to be enabled is what keeps a
	// disabled-in-this-workspace source from contributing a group at all
	// (AGG-2). loadStructuredSnapshot never returns a row with an empty
	// sourceScopeID: a row whose owning SourceObject has no live, enabled
	// binding in this workspace is dropped before it reaches Go.
	sourceScopeID string
	cells         []snapshotCell
}

type snapshotAggregateRefusal uint8

const (
	snapshotAggregateRefusalNone snapshotAggregateRefusal = iota
	snapshotAggregateRefusalUnresolvedMetric
)

type snapshotAggregate struct {
	refusal        snapshotAggregateRefusal
	function       string
	rowsInSnapshot int
	rowsMatched    int
	count          int
	values         []string
	valueColumn    string
	numericTotal   string
	metricColumn   string
	temporalColumn string
	windowStart    time.Time
	windowEnd      time.Time
	windowScoped   bool
	// periodLabel is the raw filter value ("today", "yesterday", ...) behind
	// windowStart/windowEnd, kept only for the FIX-2 #1 wire projection
	// (AnswerPeriod.Label); renderSnapshotAnswer never uses it.
	periodLabel string
	timeZone    string
	// overdueCondition, overdueStatusApplied and overdueAsOf are SEED-3 #1's
	// "overdue" condition: overdueCondition is set when the plan asked for
	// it and the reducer resolved it (declared exactly one PERIOD column);
	// overdueStatusApplied says whether a declared STATUS column narrowed the
	// match to non-closed rows, or whether the projection declared none, in
	// which case the condition is date-only and says so ("as obtained").
	overdueCondition     bool
	overdueStatusApplied bool
	overdueAsOf          time.Time
	equality             []planner.Filter
	witnesses            []string
	// sourceScopeID is the bound, enabled structured source scope this
	// reduction's rows were grouped under (snapshotRow.sourceScopeID of every
	// row in the reduced group). FIX-2 #1's AnswerResult.Snapshot.ID.
	sourceScopeID string
	// keys is FIX-2 #1's LIST projection: distinct declared-TITLE values plus
	// up to two other columns from a row that carried them. Populated only
	// for function == "LIST".
	keys []AnswerKey
	// language is the language of the run's own question (questionLanguage) for
	// the answer, explanation and label text the product composes here; empty
	// keeps the historical English spelling for callers that carry no question.
	language string
}

// structuredSnapshotRows is the small part of pgx.Rows used by the snapshot
// loader. Keeping the scanner behind this local interface lets the full
// workspace loader and the rowset's scoped loader share exactly the same
// decoding/limit logic while using different, deliberately constant SQL.
type structuredSnapshotRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

// loadStructuredSnapshot reads every typed cell of the workspace's structured
// sources that this principal may read, at the current workspace revision. The
// authorization predicate is the same one the Evidence viewer uses, applied per
// fragment: this path discloses nothing a citation could not already disclose.
//
// AGG-2: disabling a source in a workspace (RemoveSource / DELETE binding)
// never changes public.source_object_scope.membership_state -- that field is
// catalog reconciliation ("is this object still discoverable by the
// connector"), not workspace binding, and it correctly stays ACTIVE for a
// source a workspace has merely stopped using. The scope-resolution LATERAL
// below used to key group membership on membership_state alone, so a
// structured source that was ever bound to this workspace kept contributing
// a candidate group forever, regardless of whether it is bound and enabled
// in THIS workspace right now: selectStructuredSnapshotGroup would see it,
// try to qualify it, and either mis-split a single answerable source into a
// false ambiguity or (worse) never see the still-enabled source's rows
// grouped correctly beside it. The join now requires the exact same
// bound-and-enabled-at-the-current-revision tuple
// app.evidence_fragment_readable already requires for the fragment itself
// (public.workspace_revision_source at workspace.current_revision, matched
// by source_scope_id AND source_scope_revision, wrs.enabled) so a disabled
// source is invisible to aggregation two ways over: its cells are already
// unreadable, and now it can never anchor a scope group either. A cell
// belonging to no such live, enabled binding is dropped from the result
// entirely (scope.source_scope_id IS NOT NULL below) rather than merged into
// an unlabelled group.
func (service *Service) loadStructuredSnapshot(ctx context.Context, access database.AccessContext, workspaceID string) ([]snapshotRow, time.Time, string, error) {
	return service.loadStructuredSnapshotFiltered(ctx, access, workspaceID, "", "")
}

// loadStructuredSnapshotForSourceVersion is the rowset-only fast path. The
// caller has already found this source_version_id through the authorized
// fragment-cell lookup. Its SQL re-authorizes the exact fragment again in the
// same transaction, resolves that version's live, enabled scope, and fences
// candidates to ACTIVE source objects' current versions before invoking
// app.evidence_fragment_readable. It therefore preserves the per-cell gate
// while avoiding a whole-workspace snapshot scan for every evidence cell.
//
// The planner keeps using loadStructuredSnapshot unchanged; this narrower
// path is intentionally not a cache and has no effect on aggregate
// multi-source ambiguity or reduction semantics.
func (service *Service) loadStructuredSnapshotForSourceVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, sourceVersionID string) ([]snapshotRow, time.Time, string, error) {
	if sourceVersionID == "" {
		return nil, time.Time{}, "", errors.New("structured snapshot source version is empty")
	}
	if fragmentID == "" {
		return nil, time.Time{}, "", errors.New("structured snapshot fragment is empty")
	}
	return service.loadStructuredSnapshotFiltered(ctx, access, workspaceID, fragmentID, sourceVersionID)
}

func (service *Service) loadStructuredSnapshotFiltered(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, sourceVersionID string) ([]snapshotRow, time.Time, string, error) {
	var rows []snapshotRow
	var today time.Time
	var zone string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		// today is now the tenant's precise current instant, not a
		// date-truncated value: snapshotWindow truncates it itself for the
		// existing calendar-window filters, and SEED-3 #1's overdue
		// condition needs the untruncated instant to compare against each
		// row's own precise due-date instant below.
		if err := tx.QueryRow(txCtx, `
			SELECT (now() AT TIME ZONE app.organization_reporting_time_zone()),
			       app.organization_reporting_time_zone()
		`).Scan(&today, &zone); err != nil {
			return err
		}
		var cursor structuredSnapshotRows
		var err error
		if sourceVersionID == "" {
			// Keep the planner's full-workspace query and its semantics intact.
			cursor, err = tx.Query(txCtx, `
				SELECT cell.source_version_id, cell.evidence_fragment_id, cell.column_ordinal,
				       cell.column_name, cell.logical_type, cell.title_role, cell.period_role, cell.status_role,
				       COALESCE(cell.text_value, cell.numeric_value::text,
				                to_char(cell.instant_value AT TIME ZONE app.organization_reporting_time_zone(),
				                        'YYYY-MM-DD"T"HH24:MI:SS'),
				                cell.naive_value::text, cell.date_value::text, cell.bool_value::text) AS display_value,
				       cell.numeric_value::text,
				       CASE cell.logical_type
				           WHEN 'TIMESTAMPTZ' THEN (cell.instant_value AT TIME ZONE app.organization_reporting_time_zone())::date
				           WHEN 'TIMESTAMP' THEN cell.naive_value::date
				           WHEN 'DATE' THEN cell.date_value
				       END AS calendar_date,
				       CASE cell.logical_type
				           WHEN 'TIMESTAMPTZ' THEN cell.instant_value
				           WHEN 'TIMESTAMP' THEN (cell.naive_value AT TIME ZONE app.organization_reporting_time_zone())
				           WHEN 'DATE' THEN (cell.date_value::timestamp AT TIME ZONE app.organization_reporting_time_zone())
				       END AS instant,
				       scope.source_scope_id
				  FROM public.structured_snapshot_cell cell
				  LEFT JOIN LATERAL (
				      SELECT membership.source_scope_id
				        FROM public.source_version AS version
				        JOIN public.source_object_scope AS membership
				          ON membership.organization_id = version.organization_id
				         AND membership.source_object_id = version.source_object_id
				         AND membership.membership_state = 'ACTIVE'
				        JOIN public.workspace AS scope_workspace
				          ON scope_workspace.organization_id = version.organization_id
				         AND scope_workspace.id = $2
				        JOIN public.workspace_revision_source AS scope_binding
				          ON scope_binding.organization_id = scope_workspace.organization_id
				         AND scope_binding.workspace_id = scope_workspace.id
				         AND scope_binding.workspace_revision = scope_workspace.current_revision
				         AND scope_binding.source_scope_id = membership.source_scope_id
				         AND scope_binding.source_scope_revision = membership.source_scope_revision
				         AND scope_binding.enabled
				       WHERE version.organization_id = cell.organization_id
				         AND version.id = cell.source_version_id
				       ORDER BY membership.source_scope_id
				       LIMIT 1
				  ) AS scope ON true
				 WHERE cell.organization_id = $1
				   AND scope.source_scope_id IS NOT NULL
				   AND app.evidence_fragment_readable(cell.evidence_fragment_id, $2)
				 ORDER BY cell.source_version_id, cell.column_ordinal
				 LIMIT $3
			`, access.OrganizationID, workspaceID, maxSnapshotCells+1)
		} else {
			// The rowset path first resolves the exact live scope of the
			// authorized anchor version, then joins cells through candidate
			// versions in that scope. The readability predicate remains on
			// every returned fragment; this is only an early candidate bound.
			cursor, err = tx.Query(txCtx, `
				WITH anchor_scope AS (
				    SELECT membership.source_scope_id,
				           membership.source_scope_revision
				      FROM public.source_version AS anchor_version
				      JOIN public.source_object AS anchor_object
				        ON anchor_object.organization_id = anchor_version.organization_id
				       AND anchor_object.id = anchor_version.source_object_id
				       AND anchor_object.lifecycle_state = 'ACTIVE'
				       AND anchor_object.current_version_id = anchor_version.id
				      JOIN public.source_object_scope AS membership
				        ON membership.organization_id = anchor_version.organization_id
				       AND membership.source_object_id = anchor_version.source_object_id
				       AND membership.membership_state = 'ACTIVE'
				      JOIN public.workspace AS scope_workspace
				        ON scope_workspace.organization_id = anchor_version.organization_id
				       AND scope_workspace.id = $2
				      JOIN public.workspace_revision_source AS scope_binding
				        ON scope_binding.organization_id = scope_workspace.organization_id
				       AND scope_binding.workspace_id = scope_workspace.id
				       AND scope_binding.workspace_revision = scope_workspace.current_revision
				       AND scope_binding.source_scope_id = membership.source_scope_id
				       AND scope_binding.source_scope_revision = membership.source_scope_revision
				       AND scope_binding.enabled
				      JOIN public.evidence_fragment AS anchor_fragment
				        ON anchor_fragment.organization_id = anchor_version.organization_id
				       AND anchor_fragment.id = $4
				       AND anchor_fragment.source_version_id = anchor_version.id
				     WHERE anchor_version.organization_id = $1
				       AND anchor_version.id = $3
				       AND anchor_version.state = 'CURRENT'
				       AND app.evidence_fragment_readable($4, $2)
				     ORDER BY membership.source_scope_id
				     LIMIT 1
				), candidate_versions AS (
				    SELECT DISTINCT version.id AS source_version_id,
				           anchor.source_scope_id
				      FROM anchor_scope AS anchor
				      JOIN public.source_version AS version
				        ON version.organization_id = $1
				       AND version.state = 'CURRENT'
				      JOIN public.source_object AS object
				        ON object.organization_id = version.organization_id
				       AND object.id = version.source_object_id
				       AND object.lifecycle_state = 'ACTIVE'
				       AND object.current_version_id = version.id
				      JOIN public.source_object_scope AS membership
				        ON membership.organization_id = version.organization_id
				       AND membership.source_object_id = version.source_object_id
				       AND membership.source_scope_id = anchor.source_scope_id
				       AND membership.source_scope_revision = anchor.source_scope_revision
				       AND membership.membership_state = 'ACTIVE'
				      JOIN public.workspace AS scope_workspace
				        ON scope_workspace.organization_id = version.organization_id
				       AND scope_workspace.id = $2
				      JOIN public.workspace_revision_source AS scope_binding
				        ON scope_binding.organization_id = scope_workspace.organization_id
				       AND scope_binding.workspace_id = scope_workspace.id
				       AND scope_binding.workspace_revision = scope_workspace.current_revision
				       AND scope_binding.source_scope_id = membership.source_scope_id
				       AND scope_binding.source_scope_revision = membership.source_scope_revision
				       AND scope_binding.enabled
				)
				SELECT cell.source_version_id, cell.evidence_fragment_id, cell.column_ordinal,
				       cell.column_name, cell.logical_type, cell.title_role, cell.period_role, cell.status_role,
				       COALESCE(cell.text_value, cell.numeric_value::text,
				                to_char(cell.instant_value AT TIME ZONE app.organization_reporting_time_zone(),
				                        'YYYY-MM-DD"T"HH24:MI:SS'),
				                cell.naive_value::text, cell.date_value::text, cell.bool_value::text) AS display_value,
				       cell.numeric_value::text,
				       CASE cell.logical_type
				           WHEN 'TIMESTAMPTZ' THEN (cell.instant_value AT TIME ZONE app.organization_reporting_time_zone())::date
				           WHEN 'TIMESTAMP' THEN cell.naive_value::date
				           WHEN 'DATE' THEN cell.date_value
				       END AS calendar_date,
				       CASE cell.logical_type
				           WHEN 'TIMESTAMPTZ' THEN cell.instant_value
				           WHEN 'TIMESTAMP' THEN (cell.naive_value AT TIME ZONE app.organization_reporting_time_zone())
				           WHEN 'DATE' THEN (cell.date_value::timestamp AT TIME ZONE app.organization_reporting_time_zone())
				       END AS instant,
				       candidates.source_scope_id
				  FROM candidate_versions AS candidates
				  JOIN public.structured_snapshot_cell AS cell
				    ON cell.organization_id = $1
				   AND cell.source_version_id = candidates.source_version_id
				 WHERE app.evidence_fragment_readable(cell.evidence_fragment_id, $2)
				 ORDER BY cell.source_version_id, cell.column_ordinal
				 LIMIT $5
			`, access.OrganizationID, workspaceID, sourceVersionID, fragmentID, maxSnapshotCells+1)
		}
		if err != nil {
			return err
		}
		defer cursor.Close()
		total := 0
		for cursor.Next() {
			var (
				versionID string
				cell      snapshotCell
				display   *string
				numeric   *string
				calendar  *time.Time
				instant   *time.Time
				scopeID   *string
			)
			if err := cursor.Scan(&versionID, &cell.fragmentID, &cell.ordinal, &cell.column,
				&cell.logicalType, &cell.title, &cell.period, &cell.status, &display, &numeric, &calendar, &instant, &scopeID); err != nil {
				return err
			}
			if display != nil {
				cell.value = *display
			}
			if numeric != nil {
				cell.numeric = *numeric
			}
			cell.instant = instant
			cell.calendarDate = calendar
			total++
			if total > maxSnapshotCells {
				// Deliberately not truncated: an incomplete snapshot must not
				// become an exact number.
				rows = nil
				return nil
			}
			if len(rows) == 0 || rows[len(rows)-1].versionID != versionID {
				if len(rows) >= maxSnapshotRows {
					rows = nil
					return nil
				}
				newRow := snapshotRow{versionID: versionID}
				if scopeID != nil {
					newRow.sourceScopeID = *scopeID
				}
				rows = append(rows, newRow)
			}
			rows[len(rows)-1].cells = append(rows[len(rows)-1].cells, cell)
		}
		return cursor.Err()
	})
	if err != nil {
		return nil, time.Time{}, "", err
	}
	return rows, today, zone, nil
}

// snapshotWindow turns the plan's temporal filter into a half-open calendar
// range in the tenant's own zone. Every branch is end-exclusive so a day
// boundary is expressed once, in one place.
func snapshotWindow(filters []planner.Filter, today time.Time) (start, end time.Time, scoped, ok bool) {
	// Defensive: callers may now pass a precise current instant (SEED-3 #1's
	// overdue condition needs one), not only a tenant-midnight value the way
	// every caller used to. A calendar window is a whole-day concept
	// regardless of what time of day "now" happens to be, so truncate here
	// once rather than depend on every caller doing it -- an already-midnight
	// value truncates to itself, so this changes nothing for the existing
	// today/yesterday/week/month/year callers.
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())
	for _, filter := range filters {
		switch filter.Name {
		case "time_period":
			switch strings.ToLower(filter.Value) {
			case "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today":
				return today, today.AddDate(0, 0, 1), true, true
			case "\u0432\u0447\u0435\u0440\u0430", "yesterday":
				return today.AddDate(0, 0, -1), today, true, true
			case "\u043d\u0435\u0434\u0435\u043b\u044f", "week":
				return today.AddDate(0, 0, -6), today.AddDate(0, 0, 1), true, true
			case "\u043c\u0435\u0441\u044f\u0446", "month":
				return today.AddDate(0, 0, -29), today.AddDate(0, 0, 1), true, true
			case "\u0433\u043e\u0434", "year":
				return today.AddDate(0, 0, -364), today.AddDate(0, 0, 1), true, true
			}
			return time.Time{}, time.Time{}, false, false
		case "time_window":
			days := strings.TrimPrefix(filter.Value, "last_days:")
			count := 0
			for _, digit := range days {
				if digit < '0' || digit > '9' {
					return time.Time{}, time.Time{}, false, false
				}
				count = count*10 + int(digit-'0')
			}
			if count < 1 || count > 366 {
				return time.Time{}, time.Time{}, false, false
			}
			// "the last N days" includes today: N calendar days ending today.
			return today.AddDate(0, 0, -(count - 1)), today.AddDate(0, 0, 1), true, true
		case "time_range":
			parts := strings.Split(filter.Value, "/")
			if len(parts) != 2 {
				return time.Time{}, time.Time{}, false, false
			}
			from, fromErr := time.Parse("2006-01-02", parts[0])
			to, toErr := time.Parse("2006-01-02", parts[1])
			if fromErr != nil || toErr != nil || !from.Before(to) {
				return time.Time{}, time.Time{}, false, false
			}
			return from, to, true, true
		}
	}
	return time.Time{}, time.Time{}, false, true
}

func snapshotColumnIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// selectStructuredSnapshotGroup is the schema-only fallback half of scope
// resolution (see resolveStructuredSnapshotGroup for the retrieval-hinted
// half that runs first when more than one structured source is active).
// loadStructuredSnapshot loads every row this principal may read across
// EVERY active structured source bound to the workspace: with a single
// active structured source that is exactly the source's own snapshot, but
// with two or more active at once reduceStructuredSnapshot previously ran
// over the UNION of every source's rows, so COUNT/LIST silently mixed rows
// from whichever source happened to sort first.
//
// The rows are grouped by the SourceObject's own live scope membership
// (public.source_object_scope, joined in loadStructuredSnapshot), then each
// group is reduced independently by the unchanged, source-agnostic
// reduceStructuredSnapshot. A group "belongs" to the question when the plan's
// aggregate resolves against it (its declared TITLE/numeric/temporal columns
// and every named equality field are present). Exactly one qualifying group
// is required: zero means no bound source matches the question, more than
// one is a genuine ambiguity column shape alone cannot resolve -- both
// decline (ok=false) rather than guess, exactly like every other refusal
// branch in this file. This is a pure function so it stays directly
// unit-testable without a retrieval dependency.
func selectStructuredSnapshotGroup(rows []snapshotRow, planned planner.Plan, today time.Time, zone string) (snapshotAggregate, bool) {
	distinctScopes := make(map[string]struct{})
	for _, row := range rows {
		distinctScopes[row.sourceScopeID] = struct{}{}
	}
	if len(distinctScopes) <= 1 {
		// Single structured source bound (the common case, and every existing
		// test fixture): behaviour is byte-for-byte the pre-existing one.
		return reduceStructuredSnapshot(rows, planned, today, zone)
	}
	qualifying, order := qualifyingStructuredSnapshotGroups(rows, planned, today, zone)
	if len(order) != 1 {
		return snapshotAggregate{}, false
	}
	return qualifying[order[0]], true
}

// qualifyingStructuredSnapshotGroups groups rows by their sourceScopeID and
// reduces each group independently, reporting every group whose reduction
// resolves the plan (ok=true from reduceStructuredSnapshot), keyed by scope
// ID, alongside their scope IDs in a stable sorted order. Zero qualifying
// groups means no bound source answers this question; more than one is
// FIX-4 #1's real ambiguity -- resolveStructuredSnapshotGroup is the only
// caller that acts on that middle case (name/column tie-break, then a named
// clarifying refusal); selectStructuredSnapshotGroup's own pre-existing
// callers only ever wanted "exactly one or decline".
func qualifyingStructuredSnapshotGroups(rows []snapshotRow, planned planner.Plan, today time.Time, zone string) (map[string]snapshotAggregate, []string) {
	groups := make(map[string][]snapshotRow)
	order := make([]string, 0, 1)
	for _, row := range rows {
		if _, seen := groups[row.sourceScopeID]; !seen {
			order = append(order, row.sourceScopeID)
		}
		groups[row.sourceScopeID] = append(groups[row.sourceScopeID], row)
	}
	sort.Strings(order)
	qualifying := make(map[string]snapshotAggregate, len(order))
	qualifiedOrder := make([]string, 0, len(order))
	for _, scopeID := range order {
		result, ok := reduceStructuredSnapshot(groups[scopeID], planned, today, zone)
		if !ok {
			continue
		}
		qualifying[scopeID] = result
		qualifiedOrder = append(qualifiedOrder, scopeID)
	}
	return qualifying, qualifiedOrder
}

// structuredSnapshotReductionRefusal preserves the typed refusal from a
// loaded source group after the qualifying-group resolver has discarded all
// non-answerable groups. It is consulted only when no group can answer the
// plan, so a different group that resolves the metric still wins normally.
func structuredSnapshotReductionRefusal(rows []snapshotRow, planned planner.Plan, today time.Time, zone string) snapshotAggregateRefusal {
	groups := make(map[string][]snapshotRow)
	for _, row := range rows {
		groups[row.sourceScopeID] = append(groups[row.sourceScopeID], row)
	}
	for _, group := range groups {
		result, ok := reduceStructuredSnapshot(group, planned, today, zone)
		if !ok && result.refusal != snapshotAggregateRefusalNone {
			return result.refusal
		}
	}
	return snapshotAggregateRefusalNone
}

// structuredScopeNameStem is FIX-4 #1's cheap, dependency-free stemmer for
// the name/column tie-break: a shared 4-rune prefix survives the ordinary
// case/number endings a Russian question and a source's own declared name
// independently inflect ("on a trip" question vs "Garbage truck trips" source name;
// "requests" question vs "Citizen requests" source name) without pulling
// in a real morphology dependency. A term shorter than 4 runes compares in
// full -- shortening a short word risks a spurious match no inflection could
// have caused.
func structuredScopeNameStem(term string) string {
	runes := []rune(term)
	if len(runes) > 4 {
		runes = runes[:4]
	}
	return string(runes)
}

// structuredScopeNameTerms splits free text into lowercased word stems,
// dropping anything shorter than 3 runes (prepositions/conjunctions too
// short to carry disambiguating meaning either way).
func structuredScopeNameTerms(value string) []string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		if len([]rune(field)) < 3 {
			continue
		}
		terms = append(terms, structuredScopeNameStem(field))
	}
	return terms
}

// disambiguateStructuredScopeByName is FIX-4 #1's second disambiguation
// signal, tried only when retrieval gave resolveStructuredSnapshotGroup no
// confident hint and column shape alone (qualifyingStructuredSnapshotGroups)
// still leaves more than one bound structured source able to answer the
// plan: score every qualifying source by how many distinct question-word
// stems match a stem of its declared name (names, source_connection.name)
// or one of its own column names. Exactly one highest-scoring, non-zero
// source resolves the tie; a source that scores zero, or two that tie for
// the highest score, are both left for the caller's named clarifying
// refusal -- this never guesses either.
func disambiguateStructuredScopeByName(rows []snapshotRow, order []string, questionText string, names map[string]string) (string, bool) {
	questionTerms := make(map[string]struct{})
	for _, term := range structuredScopeNameTerms(questionText) {
		questionTerms[term] = struct{}{}
	}
	if len(questionTerms) == 0 {
		return "", false
	}
	columnsByScope := make(map[string]map[string]struct{}, len(order))
	for _, row := range rows {
		set, ok := columnsByScope[row.sourceScopeID]
		if !ok {
			set = make(map[string]struct{})
			columnsByScope[row.sourceScopeID] = set
		}
		for _, cell := range row.cells {
			set[cell.column] = struct{}{}
		}
	}
	bestScope, bestScore, tie := "", 0, false
	for _, scopeID := range order {
		matched := make(map[string]struct{})
		collect := func(text string) {
			for _, term := range structuredScopeNameTerms(text) {
				if _, hit := questionTerms[term]; hit {
					matched[term] = struct{}{}
				}
			}
		}
		collect(names[scopeID])
		for column := range columnsByScope[scopeID] {
			collect(column)
		}
		switch score := len(matched); {
		case score == 0:
			continue
		case score > bestScore:
			bestScope, bestScore, tie = scopeID, score, false
		case score == bestScore:
			tie = true
		}
	}
	if bestScope == "" || tie {
		return "", false
	}
	return bestScope, true
}

// ambiguousStructuredSource is FIX-4 #1's third outcome of scope resolution:
// more than one bound structured source can resolve this plan, retrieval
// gave no confident hint, and the declared name/column tie-break
// (disambiguateStructuredScopeByName) could not pick one either. The caller
// (answerStructuredAggregate) renders this as an explicit clarifying refusal
// naming every candidate source, rather than silently falling through into
// the ordinary corpus-wide INSUFFICIENT_EVIDENCE path, which never names a
// structured source at all -- "do not mix; refuse with source names", never mix.
type ambiguousStructuredSource struct {
	names []string
}

// resolveStructuredSnapshotGroup is scope resolution's entry point. With a
// single active structured source it is exactly the pre-existing behaviour
// (selectStructuredSnapshotGroup's own fast path). With two or more, it asks
// retrieval -- the same lexical/hybrid search that already resolves a
// question in one language to cards of the right source in the ordinary,
// single-source case -- which source's cards this question actually matched
// ("from the retrieved cards"), before ever falling back to schema shape
// alone. Neither signal is trusted blindly: the retrieval-hinted group still
// has to resolve through the ordinary reducer (a hint pointing at a source
// whose columns cannot answer the plan is not used), and if retrieval gives
// no usable hint at all, schema-only resolution's own fail-closed decline
// applies exactly as it would without retrieval.
func (service *Service) resolveStructuredSnapshotGroup(
	ctx context.Context, access database.AccessContext, runID, workspaceID, questionText string,
	rows []snapshotRow, planned planner.Plan, today time.Time, zone string,
) (snapshotAggregate, bool, *ambiguousStructuredSource) {
	if _, group, hinted := service.retrievalStructuredScopeHint(ctx, access, runID, workspaceID, questionText, planned, rows); hinted {
		result, ok := reduceStructuredSnapshot(group, planned, today, zone)
		if ok {
			return result, true, nil
		}
	}
	qualifying, order := qualifyingStructuredSnapshotGroups(rows, planned, today, zone)
	if len(order) == 0 {
		if refusal := structuredSnapshotReductionRefusal(rows, planned, today, zone); refusal != snapshotAggregateRefusalNone {
			return snapshotAggregate{refusal: refusal}, false, nil
		}
		return snapshotAggregate{}, false, nil
	}
	if len(order) == 1 {
		return qualifying[order[0]], true, nil
	}
	// FIX-4 #1: retrieval gave no confident hint (or none at all) and more
	// than one bound source's own column shape can resolve the plan. Try the
	// declared name/column tie-break before ever refusing.
	names := service.structuredScopeNames(ctx, access, workspaceID, order)
	if scopeID, ok := disambiguateStructuredScopeByName(rows, order, questionText, names); ok {
		return qualifying[scopeID], true, nil
	}
	labels := make([]string, 0, len(order))
	for _, scopeID := range order {
		if name := strings.TrimSpace(names[scopeID]); name != "" {
			labels = append(labels, name)
		}
	}
	if len(labels) < 2 {
		// Could not name at least two distinct candidates (most likely a
		// names lookup failure): decline exactly like the pre-existing
		// schema-only path rather than surface an unnamed "ambiguous" the
		// caller could not render usefully.
		return snapshotAggregate{}, false, nil
	}
	return snapshotAggregate{}, false, &ambiguousStructuredSource{names: labels}
}

// structuredScopeNames resolves each given structured source scope ID to its
// owner-declared display name (source_connection.name, the same name the
// "Sources" UI shows) for FIX-4 #1's clarifying refusal and name
// tie-break. It goes through migration 000083's app.structured_source_
// scope_names, a narrow read-only SECURITY DEFINER getter, rather than
// selecting source_scope_revision/source_connection directly here:
// check-architecture.go's source-scope guard reserves direct access to
// those tables for the accepted command/audit gate (ADR-0053), and this
// file is a read path, not that gate. It is best-effort: any read failure
// reports an empty map rather than an error, so a names lookup outage
// degrades resolveStructuredSnapshotGroup to its pre-existing schema-only
// decline instead of failing the whole run.
func (service *Service) structuredScopeNames(ctx context.Context, access database.AccessContext, workspaceID string, scopeIDs []string) map[string]string {
	names := make(map[string]string, len(scopeIDs))
	if service == nil || service.db == nil || len(scopeIDs) == 0 {
		return names
	}
	_ = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		cursor, err := tx.Query(txCtx, `
			SELECT source_scope_id, name FROM app.structured_source_scope_names($1, $2)
		`, workspaceID, scopeIDs)
		if err != nil {
			return err
		}
		defer cursor.Close()
		for cursor.Next() {
			var scopeID, name string
			if err := cursor.Scan(&scopeID, &name); err != nil {
				return err
			}
			names[scopeID] = name
		}
		return cursor.Err()
	})
	return names
}

// retrievalStructuredScopeHint runs retrieval purely as a scope-selection
// hint (never as the source of citations or of the reduced rows themselves —
// the aggregate is still reduced from the WHOLE snapshot of the picked
// scope, never retrieval's budgeted window) and reports the highest-ranked
// candidate's structured source scope, if that candidate's SourceVersionID
// belongs to one of the loaded snapshot rows. It never errors: any failure
// (no retrieval dependency, the search call itself failing, no candidate
// mapping to a loaded row) simply reports hinted=false so the caller falls
// back to schema-only resolution.
func (service *Service) retrievalStructuredScopeHint(
	ctx context.Context, access database.AccessContext, runID, workspaceID, questionText string,
	planned planner.Plan, rows []snapshotRow,
) (string, []snapshotRow, bool) {
	if service == nil || service.retrieval == nil {
		return "", nil, false
	}
	versionToScope := make(map[string]string, len(rows))
	groups := make(map[string][]snapshotRow)
	distinctScopes := make(map[string]struct{})
	for _, row := range rows {
		versionToScope[row.versionID] = row.sourceScopeID
		groups[row.sourceScopeID] = append(groups[row.sourceScopeID], row)
		distinctScopes[row.sourceScopeID] = struct{}{}
	}
	if len(distinctScopes) <= 1 {
		// Nothing to disambiguate; let the caller take its unchanged fast path.
		return "", nil, false
	}
	var retrieved retrieval.Result
	var err error
	if service.retrieval.HybridReady() {
		retrieved, err = service.retrieval.RetrievePlanWithQuestion(ctx, access, workspaceID, runID, questionText, planned)
	} else {
		retrieved, err = service.retrieval.Retrieve(ctx, access, workspaceID, questionText)
	}
	if err != nil {
		return "", nil, false
	}
	candidates := append([]retrieval.AuthorizedCandidate(nil), retrieved.Candidates...)
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	// FIX-4 #1: a hint is only as good as its top score being unambiguous.
	// Collecting every scope that shares the single best score (rather than
	// just returning the first sorted candidate's scope) means a genuine tie
	// between two structured sources' cards is reported as "no hint" instead
	// of an arbitrary pick that happened to sort first -- the caller then
	// tries the declared name/column tie-break before ever refusing.
	bestScore := 0.0
	haveBest := false
	bestScopes := make(map[string]struct{}, 1)
	for _, candidate := range candidates {
		scopeID, known := versionToScope[candidate.SourceVersionID]
		if !known || scopeID == "" {
			continue
		}
		if !haveBest {
			bestScore, haveBest = candidate.Score, true
		}
		if candidate.Score < bestScore {
			break // candidates are sorted by descending score.
		}
		bestScopes[scopeID] = struct{}{}
	}
	if len(bestScopes) != 1 {
		return "", nil, false
	}
	for scopeID := range bestScopes {
		return scopeID, groups[scopeID], true
	}
	return "", nil, false
}

// reduceStructuredSnapshot is the deterministic reducer. It returns ok=false
// for every request it cannot resolve exactly; the caller then declines rather
// than publishing a number it cannot defend.
func reduceStructuredSnapshot(rows []snapshotRow, planned planner.Plan, today time.Time, zone string) (snapshotAggregate, bool) {
	if len(rows) == 0 || planned.Aggregate == nil || planned.Status != planner.Ready ||
		planned.Operation != planner.Aggregate {
		return snapshotAggregate{}, false
	}
	if len(planned.Aggregate.GroupBy) > 0 || planned.Aggregate.Order != "" || planned.Aggregate.Limit > 0 {
		// A grouped or ranked aggregate keeps its existing typed Evidence
		// adapter. This slice owns the snapshot-complete scalar and set
		// reductions only, and declines the rest instead of half-answering.
		return snapshotAggregate{}, false
	}
	result := snapshotAggregate{rowsInSnapshot: len(rows), timeZone: zone}
	// selectStructuredSnapshotGroup/resolveStructuredSnapshotGroup always pass
	// one already-picked group here, so every row shares one sourceScopeID.
	if len(rows) > 0 {
		result.sourceScopeID = rows[0].sourceScopeID
	}
	for _, filter := range planned.Filters {
		if filter.Name == "time_period" || filter.Name == "time_window" || filter.Name == "time_range" {
			result.periodLabel = filter.Value
			break
		}
	}

	temporalOrdinal := 0
	numericColumns := make(map[string]struct{})
	titleColumns := make(map[string]struct{})
	allColumns := make(map[string]struct{})
	temporalColumns := make(map[string]struct{})
	periodColumns := make(map[string]struct{})
	periodColumnName := ""
	statusColumns := make(map[string]struct{})
	for _, row := range rows {
		for _, cell := range row.cells {
			identity := snapshotColumnIdentity(cell.column)
			allColumns[identity] = struct{}{}
			if cell.status {
				statusColumns[identity] = struct{}{}
			}
			if cell.calendarDate != nil {
				temporalColumns[identity] = struct{}{}
				if temporalOrdinal == 0 || cell.ordinal < temporalOrdinal {
					temporalOrdinal = cell.ordinal
					result.temporalColumn = cell.column
				}
				if cell.period {
					periodColumns[identity] = struct{}{}
					periodColumnName = cell.column
				}
			}
			if cell.numeric != "" {
				numericColumns[identity] = struct{}{}
			}
			if cell.title {
				titleColumns[identity] = struct{}{}
				result.valueColumn = cell.column
			}
		}
	}

	// SEED-3 #1: "overdue" names the row's own declared due date, never
	// whichever temporal column happens to sort first or whichever one an
	// unrelated period filter would have picked. Without exactly one declared
	// PERIOD column the condition has nothing authoritative to compare "now"
	// against, so it declines rather than guessing -- the same "decline, don't
	// guess" rule FIX-1 #3/FIX-3 #1 already apply to the ordinary time window.
	overdue := overdueConditionRequested(planned.Filters)
	if overdue {
		if len(periodColumns) != 1 {
			return snapshotAggregate{}, false
		}
		result.temporalColumn = periodColumnName
	}

	start, end, scoped, ok := snapshotWindow(planned.Filters, today)
	if !ok {
		return snapshotAggregate{}, false
	}
	if scoped && result.temporalColumn == "" {
		// The question is scoped to a period and this snapshot has no date to
		// scope it by. Counting everything would answer a different question.
		return snapshotAggregate{}, false
	}
	if scoped && len(temporalColumns) > 1 && !overdue {
		// FIX-3 #1: the owner may have declared exactly one of these temporal
		// columns PERIOD at registration -- that declaration, not column
		// order, says which date "when this row counts" means (e.g. a
		// created-at next to a due/deadline date). Use it when present.
		if len(periodColumns) == 1 {
			result.temporalColumn = periodColumnName
		} else {
			// FIX-1 #3: no declared PERIOD resolves the ambiguity (none, or
			// more than one somehow marked). Silently picking the
			// lowest-ordinal one made the answer depend on column order
			// instead of the question -- a guess, not a resolved condition.
			// Decline rather than guess; the caller falls back to the
			// ordinary retrieval answer, which can ask a clarifying question.
			return snapshotAggregate{}, false
		}
	}
	result.windowStart, result.windowEnd, result.windowScoped = start, end, scoped
	if overdue {
		result.overdueCondition = true
		result.overdueStatusApplied = len(statusColumns) == 1
		result.overdueAsOf = today
	}

	equality := make([]planner.Filter, 0, len(planned.Filters))
	for _, filter := range planned.Filters {
		if !strings.HasPrefix(filter.Name, "equals:") {
			continue
		}
		field := snapshotColumnIdentity(strings.TrimPrefix(filter.Name, "equals:"))
		if _, known := allColumns[field]; !known {
			// An explicit predicate naming a column this snapshot does not have
			// is not a predicate to ignore; ignoring it would widen the answer.
			return snapshotAggregate{}, false
		}
		equality = append(equality, planner.Filter{Name: field, Value: filter.Value})
	}
	result.equality = equality

	matched := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		if scoped && !snapshotRowInWindow(row, result.temporalColumn, start, end) {
			continue
		}
		if overdue && !snapshotRowOverdue(row, result.temporalColumn, today, result.overdueStatusApplied) {
			continue
		}
		if !snapshotRowMatchesEquality(row, equality) {
			continue
		}
		matched = append(matched, row)
	}
	result.rowsMatched = len(matched)

	function := planned.Aggregate.Function
	metric := snapshotColumnIdentity(planned.Aggregate.Metric)
	_, metricIsNumeric := numericColumns[metric]
	switch function {
	case "LIST":
		if len(titleColumns) != 1 {
			// Enumerating needs the operator's own declared TITLE column. Zero
			// (nothing declared) or several (ambiguous) is a refusal, not a pick.
			return snapshotAggregate{}, false
		}
	case "COUNT":
	case "SUM":
		if metricIsNumeric {
			break
		}
		// An unresolved SUM metric may fall back to COUNT only when the
		// snapshot has no numeric column. Choosing among numeric columns would
		// otherwise guess which value the question names.
		if len(numericColumns) == 0 {
			function = "COUNT"
			break
		}
		return snapshotAggregate{refusal: snapshotAggregateRefusalUnresolvedMetric}, false
	default:
		return snapshotAggregate{}, false
	}
	result.function = function

	switch function {
	case "COUNT":
		if len(titleColumns) == 1 {
			// FIX-1 #3: count the same distinct declared entities LIST would
			// enumerate, not raw matched rows. A snapshot can hold more than
			// one row per entity (history/detail rows for the same address,
			// say), so a bare row count silently answers "how many rows",
			// not "how many X" -- and disagreed with LIST's own count of the
			// same matched set.
			result.count = len(distinctTitleValues(matched))
		} else {
			result.count = len(matched)
		}
	case "SUM":
		result.metricColumn = metric
		total, sumOK := snapshotSum(matched, metric)
		if !sumOK {
			return snapshotAggregate{}, false
		}
		result.numericTotal = total
	case "LIST":
		values := distinctTitleValues(matched)
		if len(values) == 0 && len(matched) > 0 {
			return snapshotAggregate{}, false
		}
		result.values = values
		result.count = len(values)
		result.keys = listKeys(matched)
	}

	result.witnesses = snapshotWitnesses(matched, result.temporalColumn)
	return result, true
}

// overdueConditionRequested reports whether the plan carries SEED-3 #1's
// declared "overdue" condition filter (planner.go's overdueConditionPattern).
func overdueConditionRequested(filters []planner.Filter) bool {
	for _, filter := range filters {
		if filter.Name == "condition" && filter.Value == "overdue" {
			return true
		}
	}
	return false
}

// closedStatusMarkers is the product's own dictionary of status values that
// mean "this row is no longer open" -- the "marker vocabulary" half of SEED-3
// #1's contract, paired with the owner's per-projection declaration of WHICH
// column carries status (RoleStatus). It is deliberately closed and
// case/whitespace-insensitive (matched the same way an equality filter
// already is, snapshotRowMatchesEquality) rather than a per-tenant
// configuration: extending it is a product change, not a silent runtime one.
var closedStatusMarkers = map[string]struct{}{
	"closed": {}, "done": {}, "resolved": {}, "completed": {}, "complete": {},
	"rejected": {}, "cancelled": {}, "canceled": {}, "declined": {},
	"\u0437\u0430\u043a\u0440\u044b\u0442\u043e": {}, "\u0437\u0430\u043a\u0440\u044b\u0442\u0430": {}, "\u0437\u0430\u043a\u0440\u044b\u0442": {}, "\u0437\u0430\u043a\u0440\u044b\u0442\u044b": {},
	"\u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u043e": {}, "\u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d\u0430": {}, "\u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d": {},
	"\u0440\u0435\u0448\u0435\u043d\u043e": {}, "\u0440\u0435\u0448\u0435\u043d\u0430": {}, "\u0440\u0435\u0448\u0451\u043d": {},
	"\u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u043e": {}, "\u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u0430": {}, "\u043e\u0442\u043c\u0435\u043d\u0435\u043d\u043e": {}, "\u043e\u0442\u043c\u0435\u043d\u0435\u043d\u0430": {},
}

func closedStatusValue(value string) bool {
	_, closed := closedStatusMarkers[strings.ToLower(strings.TrimSpace(value))]
	return closed
}

// snapshotRowOverdue is SEED-3 #1's actual comparison: row's declared PERIOD
// cell (periodColumn, already resolved to the operator's own due-date
// declaration) falls strictly before the tenant's current instant ("now",
// not merely "today's date" -- a due date earlier the same calendar day is
// still overdue, verified live against demo_ops.citizen_requests_v's own
// real rows), AND -- only when the projection also declares exactly one
// STATUS column (statusDeclared) -- that cell's value is not one of
// closedStatusMarkers. Without a declared STATUS column the condition is
// date-only, exactly as the contract requires ("without a declared status column,
// use the due date only"); renderSnapshotAnswer/buildAnswerResult
// disclose which of the two this run actually applied, never silently the
// stronger one.
func snapshotRowOverdue(row snapshotRow, periodColumn string, now time.Time, statusDeclared bool) bool {
	identity := snapshotColumnIdentity(periodColumn)
	pastDue := false
	for _, cell := range row.cells {
		if cell.instant == nil || snapshotColumnIdentity(cell.column) != identity {
			continue
		}
		pastDue = cell.instant.Before(now)
		break
	}
	if !pastDue {
		return false
	}
	if !statusDeclared {
		return true
	}
	for _, cell := range row.cells {
		if cell.status && closedStatusValue(cell.value) {
			return false
		}
	}
	return true
}

func snapshotRowInWindow(row snapshotRow, column string, start, end time.Time) bool {
	identity := snapshotColumnIdentity(column)
	for _, cell := range row.cells {
		if cell.calendarDate == nil || snapshotColumnIdentity(cell.column) != identity {
			continue
		}
		date := cell.calendarDate.UTC()
		day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC)
		return !day.Before(start) && day.Before(end)
	}
	return false
}

// normalizedEntityKey is the dedup key for one declared-TITLE cell value:
// case- and surrounding-whitespace-insensitive, matching the exact scalar
// equality snapshotRowMatchesEquality already applies via strings.EqualFold.
// Before this, LIST deduped on the raw string, so two rows naming the same
// entity with only a casing or trailing-space difference (a common artefact
// of the kind of import that produced 11 rows over 3 real addresses) counted
// as two distinct values instead of one (FIX-1 #3).
func normalizedEntityKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// distinctTitleValues returns the unique declared-TITLE display values named
// by the matched rows, in the same normalized-equality grain as
// snapshotRowMatchesEquality. COUNT and LIST both call this so they report
// the same number of entities for the same matched set (FIX-1 #3): a
// snapshot's row grain is not always its entity grain (more than one row can
// carry the same address, say), and COUNT and LIST must not silently
// disagree about what "how many" and "which ones" count.
func distinctTitleValues(matched []snapshotRow) []string {
	seen := make(map[string]struct{})
	values := make([]string, 0, len(matched))
	for _, row := range matched {
		for _, cell := range row.cells {
			if !cell.title || strings.TrimSpace(cell.value) == "" {
				continue
			}
			key := normalizedEntityKey(cell.value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			values = append(values, strings.TrimSpace(cell.value))
		}
	}
	sort.Strings(values)
	return values
}

// listKeys builds FIX-2 #1's per-entity LIST projection: one AnswerKey per
// distinct declared-TITLE value (same normalized-equality grain as
// distinctTitleValues/snapshotRowMatchesEquality), carrying up to two other
// columns from the first matched row that named it. Field values are the
// original display text, never normalized.
func listKeys(matched []snapshotRow) []AnswerKey {
	type keyAggregate struct {
		display string
		fields  map[string]string
		order   []string
	}
	aggregates := make(map[string]*keyAggregate)
	for _, row := range matched {
		title := ""
		for _, cell := range row.cells {
			if cell.title && strings.TrimSpace(cell.value) != "" {
				title = strings.TrimSpace(cell.value)
				break
			}
		}
		if title == "" {
			continue
		}
		normalized := normalizedEntityKey(title)
		aggregate, ok := aggregates[normalized]
		if !ok {
			aggregate = &keyAggregate{display: title, fields: map[string]string{}}
			aggregates[normalized] = aggregate
		}
		for _, cell := range row.cells {
			if cell.title || strings.TrimSpace(cell.value) == "" {
				continue
			}
			if _, exists := aggregate.fields[cell.column]; exists || len(aggregate.order) >= 2 {
				continue
			}
			aggregate.fields[cell.column] = cell.value
			aggregate.order = append(aggregate.order, cell.column)
		}
	}
	keys := make([]AnswerKey, 0, len(aggregates))
	for _, aggregate := range aggregates {
		var fields map[string]string
		if len(aggregate.order) > 0 {
			fields = make(map[string]string, len(aggregate.order))
			for _, column := range aggregate.order {
				fields[column] = aggregate.fields[column]
			}
		}
		keys = append(keys, AnswerKey{Key: aggregate.display, Fields: fields})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Key < keys[j].Key })
	return keys
}

// answerResultIdentity carries the run-scoped identity the aggregate answer
// path already holds when it projects the structured answer. Every member is
// data this run already computed; an empty member is left absent on the wire
// (the UI then shows «no data») rather than invented. run_id is NOT part of
// the result digest -- see canonicalResultDigest.
type answerResultIdentity struct {
	RunID         string
	Intent        *AnswerIntent
	MetricVersion string
	SnapshotID    string
	ExecutionID   string
	Freshness     *CorpusFreshness
	EvidenceRefs  []string
	AuditReceipt  []string
	// CorpusStatus is the producing run's own persisted
	// question_run.corpus_status, carried verbatim from the run so the
	// completeness AnswerResult publishes is derived, never asserted. It is
	// mapped through answerResultCompleteness below: only the closed
	// COMPLETE|PARTIAL vocabulary yields a value, and an absent/unreadable
	// status stays empty (the UI's «no data») rather than an invented
	// COMPLETE.
	CorpusStatus string
}

// answerResultCompleteness maps a producing run's persisted corpus_status into
// AnswerResult.completeness. It is a closed projection, not a default: only the
// COMPLETE and PARTIAL statuses this authority actually persists map through,
// and anything else (absent, unreadable, an unknown future value) yields "" so
// the UI renders «no data» instead of inferring a full result.
func answerResultCompleteness(corpusStatus string) string {
	switch corpusStatus {
	case "COMPLETE", "PARTIAL":
		return corpusStatus
	default:
		return ""
	}
}

// answerResultIdentityForRunStatus folds a producing run's own persisted
// corpus_status into the identity the aggregate reducer projects, so the
// caller never has to hand a completeness to the reducer: it carries the run's
// status and buildAnswerResult derives the closed value. This is the one seam
// both the ordinary structured path (execute -> answerStructuredAggregate) and
// the validated-intent path (executeValidatedIntent) use.
func answerResultIdentityForRunStatus(base answerResultIdentity, corpusStatus string) answerResultIdentity {
	base.CorpusStatus = corpusStatus
	return base
}

// carryAnswerResultIdentity folds the run-scoped identity a caller already
// holds -- for the validated-intent path, the sealed QueryIntent and the
// re-checked APPROVED definition version -- into the base identity the
// aggregate reducer builds from the run itself. The base run/snapshot/evidence
// identity always wins for the fields it owns; the carried identity supplies
// only the members it actually has, so a caller that carried no intent leaves
// every unified field absent rather than inventing one.
func carryAnswerResultIdentity(base, carried answerResultIdentity) answerResultIdentity {
	if carried.Intent != nil {
		base.Intent = carried.Intent
	}
	if carried.MetricVersion != "" {
		base.MetricVersion = carried.MetricVersion
	}
	if carried.ExecutionID != "" {
		base.ExecutionID = carried.ExecutionID
	}
	if carried.Freshness != nil {
		freshness := *carried.Freshness
		base.Freshness = &freshness
	}
	if len(carried.AuditReceipt) > 0 {
		base.AuditReceipt = append([]string(nil), carried.AuditReceipt...)
	}
	if carried.CorpusStatus != "" {
		// The producing run's persisted corpus_status wins over any value the
		// base identity carried, and is never rewritten by the merge.
		base.CorpusStatus = carried.CorpusStatus
	}
	return base
}

// buildAnswerResult projects a resolved snapshotAggregate into FIX-2 #1's
// wire shape plus R2 Outcome 3's unified fields. Snapshot.CapturedAt is left
// nil here -- Get fills it (and Freshness) from the run's own corpus-freshness
// read, always the freshest value available for that read rather than a value
// frozen at persist time. The optional identity argument carries the
// run-scoped identity the caller already holds; when it is omitted (or any of
// its members is empty) the matching unified field stays empty, never
// invented. result_digest is always the deterministic canonical hash of the
// projected result content.
func buildAnswerResult(result snapshotAggregate, identity ...answerResultIdentity) *AnswerResult {
	answerResult := &AnswerResult{
		Kind: "CALCULATION", Operation: result.function, Timezone: result.timeZone,
		Snapshot: AnswerSnapshot{ID: result.sourceScopeID, RowCount: result.rowsInSnapshot},
	}
	language := result.language
	switch result.function {
	case "LIST":
		answerResult.Value = strconv.Itoa(result.count)
		answerResult.Keys = result.keys
		if result.valueColumn != "" {
			answerResult.Rule = localizedText(language, "\u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u043a\u043e\u043b\u043e\u043d\u043a\u0438 \u00ab", "distinct values in column \u00ab") +
				result.valueColumn + "\u00bb"
		} else {
			answerResult.Rule = localizedText(language, "\u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u0435 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f \u0432 \u0441\u043d\u0438\u043c\u043a\u0435", "distinct values in the snapshot")
		}
	case "SUM":
		answerResult.Value = result.numericTotal
		if result.metricColumn != "" {
			answerResult.Rule = localizedText(language, "\u0441\u0443\u043c\u043c\u0430 \u043a\u043e\u043b\u043e\u043d\u043a\u0438 \u00ab", "sum of column \u00ab") +
				result.metricColumn + "\u00bb"
		} else {
			answerResult.Rule = localizedText(language, "\u0441\u0443\u043c\u043c\u0430 \u043f\u043e \u0441\u043d\u0438\u043c\u043a\u0443", "sum over the snapshot")
		}
	default: // COUNT
		answerResult.Value = strconv.Itoa(result.count)
		if result.valueColumn != "" {
			answerResult.Rule = localizedText(language, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0440\u0430\u0437\u043b\u0438\u0447\u043d\u044b\u0445 \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u0439 \u0432 \u043a\u043e\u043b\u043e\u043d\u043a\u0435 \u00ab", "count of distinct values in column \u00ab") +
				result.valueColumn + "\u00bb"
		} else {
			answerResult.Rule = localizedText(language, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a \u0441\u043d\u0438\u043c\u043a\u0430, \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u044f\u044e\u0449\u0438\u0445 \u0443\u0441\u043b\u043e\u0432\u0438\u044e", "count of snapshot rows satisfying the condition")
		}
	}
	for _, filter := range result.equality {
		answerResult.Filters = append(answerResult.Filters, AnswerFilter{Name: filter.Name, Value: filter.Value})
	}
	if result.overdueCondition {
		answerResult.Filters = append(answerResult.Filters, AnswerFilter{Name: "condition", Value: "overdue"})
		if result.overdueStatusApplied {
			answerResult.Rule += localizedText(language,
				"; \u0443\u0441\u043b\u043e\u0432\u0438\u0435 \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u043a\u0438: \u043a\u043e\u043b\u043e\u043d\u043a\u0430 \u00ab"+result.temporalColumn+"\u00bb \u0440\u0430\u043d\u044c\u0448\u0435 \u0442\u0435\u043a\u0443\u0449\u0435\u0439 \u0434\u0430\u0442\u044b \u0438 \u0441\u0442\u0430\u0442\u0443\u0441 \u043d\u0435 \u0437\u0430\u043a\u0440\u044b\u0442",
				"; overdue condition: column \u00ab"+result.temporalColumn+"\u00bb is before the current date and the status is not closed")
		} else {
			answerResult.Rule += localizedText(language,
				"; \u0443\u0441\u043b\u043e\u0432\u0438\u0435 \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u043a\u0438: \u0442\u043e\u043b\u044c\u043a\u043e \u0441\u0440\u043e\u043a (\u043a\u043e\u043b\u043e\u043d\u043a\u0430 \u00ab"+result.temporalColumn+"\u00bb); \u043a\u043e\u043b\u043e\u043d\u043a\u0430 \u0441\u0442\u0430\u0442\u0443\u0441\u0430 \u043d\u0435 \u043e\u0431\u044a\u044f\u0432\u043b\u0435\u043d\u0430, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u0441\u0442\u0430\u0442\u0443\u0441 \u043d\u0435 \u0443\u0447\u0438\u0442\u044b\u0432\u0430\u0435\u0442\u0441\u044f",
				"; overdue condition: due date only (column \u00ab"+result.temporalColumn+"\u00bb); no status column is declared, so status is not considered")
		}
	}
	if result.windowScoped {
		answerResult.Period = &AnswerPeriod{
			From:  result.windowStart.Format("2006-01-02"),
			To:    result.windowEnd.AddDate(0, 0, -1).Format("2006-01-02"),
			Label: result.periodLabel,
		}
	}
	// R2 Outcome 3: fill the unified fields from the identity the caller
	// already holds, then bind the canonical result digest to content +
	// stable snapshot/execution identity + metric version.
	if len(identity) > 0 {
		run := identity[0]
		answerResult.RunID = run.RunID
		answerResult.MetricVersion = run.MetricVersion
		answerResult.SnapshotID = run.SnapshotID
		answerResult.ExecutionID = run.ExecutionID
		answerResult.Intent = run.Intent
		// The run's own persisted corpus_status is the only source of
		// completeness; an absent/unreadable status stays empty (the UI's
		// «no data»), never COMPLETE.
		answerResult.Completeness = answerResultCompleteness(run.CorpusStatus)
		if run.Freshness != nil {
			freshness := *run.Freshness
			answerResult.Freshness = &freshness
		}
		if len(run.EvidenceRefs) > 0 {
			answerResult.EvidenceRefs = append([]string(nil), run.EvidenceRefs...)
		}
		if len(run.AuditReceipt) > 0 {
			answerResult.AuditReceipt = append([]string(nil), run.AuditReceipt...)
		}
	}
	answerResult.ResultDigest = canonicalResultDigest(answerResult)
	return answerResult
}

func snapshotRowMatchesEquality(row snapshotRow, filters []planner.Filter) bool {
	for _, filter := range filters {
		matched := false
		for _, cell := range row.cells {
			if snapshotColumnIdentity(cell.column) == filter.Name && strings.EqualFold(cell.value, filter.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// snapshotSum adds one declared numeric column across the matched rows using
// exact decimal arithmetic; a row missing that column makes the total
// undefined rather than smaller.
func snapshotSum(rows []snapshotRow, metric string) (string, bool) {
	total := new(big.Rat)
	scale := 0
	for _, row := range rows {
		found := false
		for _, cell := range row.cells {
			if cell.numeric == "" || snapshotColumnIdentity(cell.column) != metric {
				continue
			}
			value, parsed := new(big.Rat).SetString(cell.numeric)
			if !parsed {
				return "", false
			}
			total.Add(total, value)
			if dot := strings.IndexByte(cell.numeric, '.'); dot >= 0 && len(cell.numeric)-dot-1 > scale {
				scale = len(cell.numeric) - dot - 1
			}
			found = true
			break
		}
		if !found {
			return "", false
		}
	}
	return total.FloatString(scale), true
}

// snapshotWitnesses picks one deterministic Evidence fragment per matched row —
// the row's declared TITLE cell, else its temporal cell, else its first cell —
// so every disclosed citation proves a row that was actually counted.
func snapshotWitnesses(rows []snapshotRow, temporalColumn string) []string {
	temporal := snapshotColumnIdentity(temporalColumn)
	witnesses := make([]string, 0, len(rows))
	// FIX-6: LIST/COUNT dedupe matched rows onto distinct declared-TITLE
	// entities (distinctTitleValues/normalizedEntityKey) -- a snapshot can
	// carry more than one matched row for the same entity (several trips for
	// one vehicle today, say). Without this dedup here, a second row for an
	// already-witnessed entity contributed a second citation naming the SAME
	// entity again, so the basis panel's citation count and content silently
	// disagreed with the distinct keys the answer text actually named. Keep
	// exactly one witness row per distinct entity -- the first matched row
	// that named it, in the caller's own row order -- so citation k always
	// names the k-th distinct key, never a repeat.
	seenEntities := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		chosen := ""
		entityKey := ""
		hasTitle := false
		for _, cell := range row.cells {
			if cell.title {
				chosen = cell.fragmentID
				hasTitle = true
				if strings.TrimSpace(cell.value) != "" {
					entityKey = normalizedEntityKey(cell.value)
				}
				break
			}
		}
		if hasTitle && entityKey != "" {
			if _, duplicate := seenEntities[entityKey]; duplicate {
				continue
			}
			seenEntities[entityKey] = struct{}{}
		}
		if chosen == "" {
			for _, cell := range row.cells {
				if snapshotColumnIdentity(cell.column) == temporal {
					chosen = cell.fragmentID
					break
				}
			}
		}
		if chosen == "" && len(row.cells) > 0 {
			chosen = row.cells[0].fragmentID
		}
		if chosen != "" {
			witnesses = append(witnesses, chosen)
		}
	}
	sort.Strings(witnesses)
	if len(witnesses) > maxCitations {
		witnesses = witnesses[:maxCitations]
	}
	return witnesses
}

// renderSnapshotAnswer states the exact result and, beside it, exactly how it
// was obtained: which snapshot, how many rows it holds, which of them matched
// and under what calendar. A reader can disagree with the question's reading
// without having to guess what the number counted.
func renderSnapshotAnswer(result snapshotAggregate, citations []Citation) string {
	language := result.language
	var answer strings.Builder
	switch result.function {
	case "LIST":
		if len(result.values) == 0 {
			answer.WriteString(localizedText(language,
				"\u041e\u0442\u0432\u0435\u0442: \u043f\u043e\u0434\u0445\u043e\u0434\u044f\u0449\u0438\u0445 \u0437\u0430\u043f\u0438\u0441\u0435\u0439 \u0432 \u0441\u043d\u0438\u043c\u043a\u0435 \u043d\u0435\u0442 (0).",
				"Answer: no matching records in the snapshot (0)."))
		} else {
			answer.WriteString(localizedText(language, "\u041e\u0442\u0432\u0435\u0442: ", "Answer: "))
			answer.WriteString(strings.Join(result.values, ", "))
			answer.WriteString(localizedText(language, " \u2014 \u0432\u0441\u0435\u0433\u043e ", " \u2014 total "))
			answer.WriteString(strconv.Itoa(len(result.values)))
			answer.WriteString(".")
		}
	case "SUM":
		answer.WriteString(localizedText(language, "\u041e\u0442\u0432\u0435\u0442: ", "Answer: "))
		answer.WriteString(result.numericTotal)
		answer.WriteString(".")
	default:
		answer.WriteString(localizedText(language, "\u041e\u0442\u0432\u0435\u0442: ", "Answer: "))
		answer.WriteString(strconv.Itoa(result.count))
		answer.WriteString(".")
	}
	answer.WriteString(localizedText(language,
		"\n\n\u0420\u0430\u0441\u0447\u0451\u0442 \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d \u0434\u0435\u0442\u0435\u0440\u043c\u0438\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u043e \u043f\u043e \u043f\u043e\u043b\u043d\u043e\u043c\u0443 \u0442\u0435\u043a\u0443\u0449\u0435\u043c\u0443 \u0441\u043d\u0438\u043c\u043a\u0443 \u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u043d\u043e\u0433\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430: \u0441\u0442\u0440\u043e\u043a \u0432 \u0441\u043d\u0438\u043c\u043a\u0435 \u2014 ",
		"\n\nCalculated deterministically from the complete current structured-source snapshot: rows in snapshot \u2014 "))
	answer.WriteString(strconv.Itoa(result.rowsInSnapshot))
	answer.WriteString(localizedText(language,
		", \u043f\u043e\u0434\u0445\u043e\u0434\u044f\u0449\u0438\u0445 \u043f\u043e\u0434 \u0443\u0441\u043b\u043e\u0432\u0438\u0435 \u2014 ",
		", matching the condition \u2014 "))
	answer.WriteString(strconv.Itoa(result.rowsMatched))
	answer.WriteString(".")
	if result.windowScoped {
		answer.WriteString(localizedText(language, " \u041f\u0435\u0440\u0438\u043e\u0434 \u043f\u043e \u043a\u043e\u043b\u043e\u043d\u043a\u0435 ", " Period by column "))
		answer.WriteString(result.temporalColumn)
		answer.WriteString(localizedText(language, ": \u0441 ", ": from "))
		answer.WriteString(result.windowStart.Format("2006-01-02"))
		answer.WriteString(localizedText(language, " \u043f\u043e ", " through "))
		answer.WriteString(result.windowEnd.AddDate(0, 0, -1).Format("2006-01-02"))
		answer.WriteString(localizedText(language, " \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435\u043b\u044c\u043d\u043e, \u0447\u0430\u0441\u043e\u0432\u043e\u0439 \u043f\u043e\u044f\u0441 ", " inclusive, tenant time zone "))
		answer.WriteString(result.timeZone)
		answer.WriteString(".")
	}
	for _, filter := range result.equality {
		answer.WriteString(localizedText(language, " \u041e\u0442\u0431\u043e\u0440: ", " Selection: "))
		answer.WriteString(filter.Name)
		answer.WriteString(" = ")
		answer.WriteString(filter.Value)
		answer.WriteString(".")
	}
	if result.overdueCondition {
		answer.WriteString(localizedText(language, " \u041e\u0442\u0431\u043e\u0440: \u043f\u0440\u043e\u0441\u0440\u043e\u0447\u0435\u043d\u043e \u2014 \u043a\u043e\u043b\u043e\u043d\u043a\u0430 ", " Selection: overdue \u2014 column "))
		answer.WriteString(result.temporalColumn)
		answer.WriteString(localizedText(language, " \u0440\u0430\u043d\u044c\u0448\u0435 ", " before "))
		answer.WriteString(result.overdueAsOf.Format("2006-01-02"))
		answer.WriteString(".")
		if result.overdueStatusApplied {
			answer.WriteString(localizedText(language,
				" \u0421\u0442\u0430\u0442\u0443\u0441 \u0443\u0447\u0442\u0451\u043d: \u0437\u0430\u043a\u0440\u044b\u0442\u044b\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u044b \u0438\u0441\u043a\u043b\u044e\u0447\u0435\u043d\u044b.",
				" Status considered: closed statuses excluded."))
		} else {
			answer.WriteString(localizedText(language,
				" \u0421\u0442\u0430\u0442\u0443\u0441 \u043d\u0435 \u0443\u0447\u0442\u0451\u043d: \u043a\u043e\u043b\u043e\u043d\u043a\u0430 \u0441\u0442\u0430\u0442\u0443\u0441\u0430 \u043d\u0435 \u043e\u0431\u044a\u044f\u0432\u043b\u0435\u043d\u0430 (\u043a\u0430\u043a \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u043e \u2014 \u0442\u043e\u043b\u044c\u043a\u043e \u0441\u0440\u043e\u043a).",
				" Status not considered: no status column is declared (as received \u2014 due date only)."))
		}
	}
	if len(citations) > 0 {
		answer.WriteString(localizedText(language, " \u041a\u0430\u0440\u0442\u043e\u0447\u043a\u0438 \u0441\u0442\u0440\u043e\u043a:", " Row cards:"))
		for _, citation := range citations {
			answer.WriteString(" [")
			answer.WriteString(strconv.Itoa(int(citation.Number)))
			answer.WriteString("]")
		}
		if len(citations) < result.rowsMatched {
			answer.WriteString(localizedText(language, " (\u043f\u043e\u043a\u0430\u0437\u0430\u043d\u044b \u043f\u0435\u0440\u0432\u044b\u0435 ", " (showing the first "))
			answer.WriteString(strconv.Itoa(len(citations)))
			answer.WriteString(localizedText(language, " \u0438\u0437 ", " of "))
			answer.WriteString(strconv.Itoa(result.rowsMatched))
			answer.WriteString(").")
		}
	}
	return answer.String()
}

// persistAmbiguousStructuredSourceRefusal is FIX-4 #1's named clarifying
// refusal: this run failed closed because more than one bound structured
// source could resolve the plan and neither retrieval nor the declared
// name/column tie-break could pick one. It persists an INSUFFICIENT_EVIDENCE
// run -- fail-closed exactly like every other decline in this file -- but
// whose answer text says WHY and names every candidate source, because a
// caller cannot act on a generic "no evidence" here the way they could on a
// genuine coverage gap.
func (service *Service) persistAmbiguousStructuredSourceRefusal(ctx context.Context, access database.AccessContext, runID, workspaceID string, ambiguous *ambiguousStructuredSource, language string) error {
	answer := ambiguousStructuredSourceAnswer(language, ambiguous.names)
	uncertainties, conflicts, signalErr := normalizeSignals([]Uncertainty{{Code: UncertaintyAmbiguousStructuredSource}}, nil)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	return service.persistTerminalRun(ctx, access, runID, workspaceID, answer, nil, nil, "INSUFFICIENT_EVIDENCE", false, uncertainties, conflicts, nil)
}

// persistUnresolvedStructuredMetricRefusal is the terminal typed refusal for a
// snapshot that cannot resolve the question's SUM metric to one of its own
// declared numeric columns. It fails closed rather than publish a number the
// reducer refused to prove, and it is never deferred to the ordinary retrieval
// fallback: that fallback sums whatever numeric cell the retrieval window
// happened to return, which is a different question's exact answer whenever the
// source's own text columns carry the words of the question.
func (service *Service) persistUnresolvedStructuredMetricRefusal(ctx context.Context, access database.AccessContext, runID, workspaceID string, partial bool, language string) error {
	uncertainties, conflicts, signalErr := normalizeSignals([]Uncertainty{{Code: UncertaintyInsufficientEvidence}}, nil)
	if signalErr != nil {
		return &Error{code: CodeUnavailable, cause: signalErr}
	}
	return service.persistTerminalRun(ctx, access, runID, workspaceID,
		insufficientEvidenceAnswer(language), nil, nil,
		"INSUFFICIENT_EVIDENCE", partial, uncertainties, conflicts, nil)
}

// answerStructuredAggregate is the whole AGG-1 path for one run: reduce the
// snapshot, re-read and re-authorize the witness fragments, persist the answer
// with its citations. A snapshot that cannot resolve the requested metric is a
// terminal typed refusal; a plan more than one source could resolve gets the
// named clarifying refusal. Every other non-answerable plan leaves the caller's
// ordinary retrieval path untouched.
func (service *Service) answerStructuredAggregate(ctx context.Context, access database.AccessContext,
	runID, workspaceID, questionText string, planned planner.Plan, identity ...answerResultIdentity) (bool, error) {
	if service == nil || service.db == nil || service.evidence == nil || service.retrievalStore == nil {
		return false, nil
	}
	if planned.Validate() != nil || planned.Status != planner.Ready || planned.Operation != planner.Aggregate {
		return false, nil
	}
	language := questionLanguage(questionText)
	// The producing run's persisted corpus_status is the single source of this
	// structured run's partiality; it is carried on the identity the callers
	// pass, never inferred from the reduction (which only refuses a snapshot it
	// cannot reduce exactly). An absent/unreadable status is not treated as
	// whole here either.
	structuredPartial := len(identity) > 0 && identity[0].CorpusStatus == "PARTIAL"
	rows, today, zone, err := service.loadStructuredSnapshot(ctx, access, workspaceID)
	if err != nil || len(rows) == 0 {
		return false, nil
	}
	result, ok, ambiguous := service.resolveStructuredSnapshotGroup(ctx, access, runID, workspaceID, questionText, rows, planned, today, zone)
	if !ok {
		// A snapshot whose SUM metric cannot be resolved to one of its own
		// declared numeric columns is not answered by guessing which column the
		// question meant, and it is not answered by the ordinary retrieval
		// fallback either: that path sums whatever numeric cell the retrieval
		// window returned, so a source whose text columns carry the words of the
		// question would publish a total for a metric the reducer refused to
		// prove. The typed refusal is terminal, exactly as it is for a caller
		// that carried a sealed validated intent.
		if result.refusal == snapshotAggregateRefusalUnresolvedMetric {
			if err := service.persistUnresolvedStructuredMetricRefusal(ctx, access, runID, workspaceID, structuredPartial, language); err != nil {
				return false, err
			}
			return true, nil
		}
		if ambiguous != nil {
			if err := service.persistAmbiguousStructuredSourceRefusal(ctx, access, runID, workspaceID, ambiguous, language); err != nil {
				return false, err
			}
			return true, nil
		}
		return false, nil
	}
	result.language = language
	selected := make([]candidate, 0, len(result.witnesses))
	for _, fragmentID := range result.witnesses {
		fragment, readErr := service.evidence.Read(ctx, access, workspaceID, fragmentID)
		if readErr != nil {
			// A witness that is no longer readable means the snapshot moved
			// under this run; do not publish a number it cannot prove.
			return false, nil
		}
		selected = append(selected, candidate{
			ID: fragment.FragmentID, SourceObjectID: fragment.SourceObjectID,
			SourceVersionID: fragment.SourceVersionID, ExtractionID: fragment.ExtractionID,
			TextHash: fragment.EvidenceTextHash, AnchorHash: fragment.AnchorHash,
			ObjectType: fragment.ObjectType, CanonicalFormat: fragment.CanonicalFormat,
			ParserProfileRevision: fragment.ParserProfileRevision, ContentHash: fragment.ContentHash,
			Ordinal: fragment.Ordinal,
			Text:    append([]byte(nil), fragment.Text...), Anchor: append([]byte(nil), fragment.Anchor...),
		})
	}
	if len(selected) == 0 {
		return false, nil
	}
	authorized, snapshotErr := service.persistRetrievalSnapshot(ctx, access, runID, planned, selected, false)
	if snapshotErr != nil {
		return false, snapshotErr
	}
	citations := make([]Citation, 0, len(authorized))
	for index, item := range authorized {
		excerpt := strings.TrimSpace(string(item.Text))
		citations = append(citations, Citation{
			Number: int64(index + 1), EvidenceFragment: item.ID, Excerpt: excerpt,
			Anchor: string(item.Anchor), DeepLink: "/api/v1/workspaces/" + workspaceID + "/evidence/" + item.ID,
			SourceVersionID: item.SourceVersionID, ExtractionID: item.ExtractionID,
			SourceObjectID: item.SourceObjectID, EvidenceTextHash: item.TextHash,
			ExcerptHash: canon.Hash([]byte(excerpt)),
		})
	}
	answer := renderSnapshotAnswer(result, citations)
	uncertainties, conflicts, signalErr := deriveSignals(planned, authorized, citations, structuredPartial)
	if signalErr != nil {
		return false, &Error{code: CodeUnavailable, cause: signalErr}
	}
	// FIX-2 #1: the same reduction that already produced the rendered prose
	// above also carries every field a structured client needs -- project it
	// once, here, rather than asking a client to re-parse renderSnapshotAnswer's
	// Russian sentence.
	answerIdentity := answerResultIdentity{
		RunID:        runID,
		SnapshotID:   result.sourceScopeID,
		EvidenceRefs: append([]string(nil), result.witnesses...),
	}
	if len(identity) > 0 {
		// R2 Outcome 3: the validated-intent caller carries the run's own
		// sealed intent and APPROVED metric version; a caller that carries
		// none keeps the legacy R1 shape.
		answerIdentity = carryAnswerResultIdentity(answerIdentity, identity[0])
	}
	answerResult := buildAnswerResult(result, answerIdentity)
	// The run's terminal corpus_status is the same persisted partiality the
	// AnswerResult.completeness is derived from, so REST/MCP/UI never read a
	// PARTIAL answer beside a COMPLETE run.
	if err := service.persistTerminalRun(ctx, access, runID, workspaceID, answer, citations, authorized,
		"COMPLETED", structuredPartial, uncertainties, conflicts, answerResult); err != nil {
		return false, err
	}
	return true, nil
}

// StructuredRowset is FIX-2 #3's tabular evidence, corrected by FIX-7 #1: for
// an Evidence fragment that carries a structured snapshot cell, the current,
// re-authorized rows this citation's basis panel should show (bounded to
// 50) -- by default (scope=="" or RowsetScopeMatched) only the rows that
// fragment's own most recent readable citing question run actually matched
// (an answer of "3 vehicles" gets exactly 3 rows here, never the whole
// source), or, only when the caller explicitly asks for RowsetScopeFull,
// that source scope's entire current snapshot. It reports (nil, nil) -- not
// an error -- for a fragment that is not part of a structured snapshot (an
// ordinary document fragment keeps its existing text-only basis) or one this
// principal may no longer read; it reports (nil, &Error{CodeInvalid}) for any
// scope value outside the closed {"", matched, full} vocabulary.
func (service *Service) StructuredRowset(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, scope string) (*RowsetEvidence, error) {
	if service == nil || service.db == nil || access.Validate() != nil || !validOpaque(workspaceID) || !validOpaque(fragmentID) {
		return nil, &Error{code: CodeInvalid}
	}
	if scope == "" {
		scope = RowsetScopeMatched
	}
	if scope != RowsetScopeMatched && scope != RowsetScopeFull {
		return nil, &Error{code: CodeInvalid}
	}
	// Outcome 2 (audit before data): persist the admission event before the
	// first governed read fetches any structured cell, snapshot row or source
	// version content. It records the effective actor kind (HUMAN | SERVICE),
	// the access decision (OutcomeSuccess = admitted) and the cited evidence
	// fragment as the admission resource. A failed admission fails closed with
	// the existing typed unavailable error; no db.Read runs and no rowset or
	// row is returned. The existing outcome events stay unchanged.
	if err := service.emitRowsetAdmission(ctx, access, workspaceID, fragmentID); err != nil {
		return nil, &Error{code: CodeUnavailable, cause: err}
	}
	read := service.structuredRowsetReadFn
	if read == nil {
		read = service.readStructuredRowset
	}
	rowset, err := read(ctx, access, workspaceID, fragmentID, scope)
	if err != nil {
		// A governed read that fails after admission leaves the admission event
		// plus its matching failure outcome, never the admission alone.
		service.recordRowsetReadFailure(ctx, access, workspaceID, fragmentID, err)
		return nil, err
	}
	return rowset, nil
}

// errStructuredCellAbsent is readStructuredRowsetCell's question-local
// sentinel for "this fragment has no readable structured-snapshot cell". It is
// what readStructuredRowset treats as the single legitimate "not a rowset
// citation" result; every other error, including a transaction failure, stays
// non-nil so the caller records the matching failure outcome. Keeping the
// sentinel in this package means internal/question no longer names a
// PostgreSQL driver error to distinguish absence from failure.
var errStructuredCellAbsent = errors.New("structured snapshot cell absent")

// readStructuredRowsetCell is readStructuredRowset's first governed read: the
// source_version_id of the structured-snapshot cell that publishes this
// fragment, resolved only while app.evidence_fragment_readable still admits it.
// A database.IsNotFound result is translated into the question-local
// errStructuredCellAbsent sentinel (the one result that means "not a rowset
// citation"); every other error -- including a database.Transaction failure --
// is returned unchanged and non-nil, so the caller can tell an absent cell from
// a failed read. structuredRowsetCellFn is nil in production (where the real
// query runs) and exists so the protected-independent tests can drive
// readStructuredRowset itself both ways.
func (service *Service) readStructuredRowsetCell(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (string, error) {
	if fn := service.structuredRowsetCellFn; fn != nil {
		value, err := fn(ctx, access, workspaceID, fragmentID)
		if err != nil {
			return "", translateStructuredCellAbsence(err)
		}
		return value, nil
	}
	var sourceVersionID string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT cell.source_version_id
			  FROM public.structured_snapshot_cell AS cell
			 WHERE cell.organization_id = $1 AND cell.evidence_fragment_id = $2
			   AND app.evidence_fragment_readable(cell.evidence_fragment_id, $3)
			 LIMIT 1
		`, access.OrganizationID, fragmentID, workspaceID).Scan(&sourceVersionID)
	})
	if err != nil {
		return "", translateStructuredCellAbsence(err)
	}
	return sourceVersionID, nil
}

// translateStructuredCellAbsence maps a database "not found" result onto the
// package-local errStructuredCellAbsent sentinel and passes every other error
// through unchanged, so absence stays distinguishable from a genuine failure
// without importing a driver type here.
func translateStructuredCellAbsence(err error) error {
	if database.IsNotFound(err) {
		return errStructuredCellAbsent
	}
	return err
}

// readStructuredRowset is StructuredRowset's governed read: it starts only
// after StructuredRowset's admission event is durable.
//
// F1: only a fragment that carries no structured cell is a legitimate
// "not a rowset citation" result and returns (nil, nil). Any genuine governed
// read or transaction failure -- the cell lookup itself, or
// loadStructuredSnapshot -- is returned as a non-nil error so StructuredRowset
// records the matching failure outcome beside the admission instead of
// swallowing the failure into an empty rowset.
func (service *Service) readStructuredRowset(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, scope string) (*RowsetEvidence, error) {
	sourceVersionID, err := service.readStructuredRowsetCell(ctx, access, workspaceID, fragmentID)
	if err != nil {
		if errors.Is(err, errStructuredCellAbsent) {
			// No structured cell for this fragment (or it is not currently
			// readable): not a rowset citation, not an error.
			return nil, nil
		}
		return nil, err
	}
	rows, _, _, loadErr := service.loadStructuredSnapshotForSourceVersion(ctx, access, workspaceID, fragmentID, sourceVersionID)
	if loadErr != nil {
		return nil, loadErr
	}
	if len(rows) == 0 {
		return nil, nil
	}
	scopeID := ""
	for _, row := range rows {
		if row.versionID == sourceVersionID {
			scopeID = row.sourceScopeID
			break
		}
	}
	if scopeID == "" {
		return nil, nil
	}
	group := make([]snapshotRow, 0, len(rows))
	for _, row := range rows {
		if row.sourceScopeID == scopeID {
			group = append(group, row)
		}
	}
	if len(group) == 0 {
		return nil, nil
	}

	selected := group
	filterLabel := "entire source snapshot"
	if scope == RowsetScopeMatched {
		if matched, label := service.matchedStructuredRowset(ctx, access, workspaceID, fragmentID, group); len(matched) > 0 {
			selected, filterLabel = matched, label
		} else {
			// No readable citing run named this fragment (never answered
			// through the aggregate reducer, or its citations purged): fall
			// back to the fragment's own single row rather than the whole
			// snapshot -- never the wide default this fix removes.
			for _, row := range group {
				if row.versionID == sourceVersionID {
					selected = []snapshotRow{row}
					break
				}
			}
			filterLabel = "no question-run data: showing only this row"
		}
	}

	displayed := snapshotRowsetDisplayRows(selected)
	columnOrder, tableRows := snapshotRowsetTable(displayed)
	versionIDs := make([]string, 0, len(displayed))
	for _, row := range displayed {
		versionIDs = append(versionIDs, row.versionID)
	}
	var capturedAt *time.Time
	_ = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT max(observed_at) FROM public.source_version
			 WHERE organization_id = $1 AND id = ANY($2)
		`, access.OrganizationID, versionIDs).Scan(&capturedAt)
	})
	return &RowsetEvidence{
		Columns: columnOrder, Rows: tableRows, Total: len(selected),
		FilterLabel: filterLabel,
		Snapshot:    AnswerSnapshot{ID: scopeID, RowCount: len(group), CapturedAt: capturedAt},
	}, nil
}

// rowsetDisplayRowLimit caps how many already-authorized rows
// readStructuredRowset renders as RowsetEvidence.Rows. It is display-only:
// Total still counts every selected row, and Columns may only name columns
// carried by rows actually rendered under this cap.
const rowsetDisplayRowLimit = 50

// snapshotRowsetDisplayRows returns the prefix of selected that
// readStructuredRowset renders: all of it when within rowsetDisplayRowLimit,
// otherwise the first rowsetDisplayRowLimit rows. It never widens the
// already-authorized selection.
func snapshotRowsetDisplayRows(selected []snapshotRow) []snapshotRow {
	if len(selected) > rowsetDisplayRowLimit {
		return selected[:rowsetDisplayRowLimit]
	}
	return selected
}

// snapshotRowsetTable assembles headers and values from the displayed rows.
func snapshotRowsetTable(displayed []snapshotRow) ([]string, []map[string]string) {
	columns := snapshotRowsetColumns(displayed)
	rows := make([]map[string]string, 0, len(displayed))
	for _, row := range displayed {
		values := make(map[string]string, len(row.cells))
		for _, cell := range row.cells {
			values[cell.column] = cell.value
		}
		rows = append(rows, values)
	}
	return columns, rows
}

// snapshotRowsetColumns derives RowsetEvidence.Columns from every rendered row,
// never from displayed[0] alone: a column whose value is absent (NULL or empty)
// on the first rendered row but present on a later one must still appear.
//
// Each column name maps to the ordinal of its first-encountered cell; names are
// appended in first-seen order, then stably sorted ascending by that ordinal, so
// header order follows the owner's declared column order while first-seen order
// breaks ordinal ties. A name seen again keeps its first ordinal and is emitted
// once. Empty input yields a non-nil empty slice.
func snapshotRowsetColumns(displayed []snapshotRow) []string {
	ordinals := make(map[string]int, len(displayed))
	order := make([]string, 0)
	for _, row := range displayed {
		for _, cell := range row.cells {
			if _, seen := ordinals[cell.column]; seen {
				continue
			}
			ordinals[cell.column] = cell.ordinal
			order = append(order, cell.column)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return ordinals[order[i]] < ordinals[order[j]]
	})
	return order
}

// matchedStructuredRowset is FIX-7 #1's core: it finds fragmentID's own most
// recently created, currently readable citation, gathers every fragment ID
// that SAME question run cited (the reducer's whole matched/witness set --
// one representative row per matched entity, FIX-6's own dedup), and returns
// the subset of group's rows those citations name, in citation order, plus a
// human-readable label built from that run's own already-disclosed
// AnswerResult (period/filters/condition) -- content this same authorized
// viewer could already read via GET on the run itself, never new disclosure.
// It returns (nil, "") when no readable citing run names this fragment.
func (service *Service) matchedStructuredRowset(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string, group []snapshotRow) ([]snapshotRow, string) {
	var runID string
	err := service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT qc.question_run_id
			  FROM public.question_citation AS qc
			  JOIN public.question_run AS qr
			    ON qr.organization_id = qc.organization_id AND qr.id = qc.question_run_id
			 WHERE qc.organization_id = $1
			   AND qc.evidence_fragment_id = $2
			   AND qr.workspace_id = $3
			   AND app.question_run_readable(qr.id, qr.workspace_id)
			 ORDER BY qc.created_at DESC
			 LIMIT 1
		`, access.OrganizationID, fragmentID, workspaceID).Scan(&runID)
	})
	if err != nil || runID == "" {
		return nil, ""
	}
	var citedFragments []string
	err = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		cursor, queryErr := tx.Query(txCtx, `
			SELECT evidence_fragment_id
			  FROM public.question_citation
			 WHERE organization_id = $1 AND question_run_id = $2
			 ORDER BY citation_number
		`, access.OrganizationID, runID)
		if queryErr != nil {
			return queryErr
		}
		defer cursor.Close()
		for cursor.Next() {
			var fragment string
			if scanErr := cursor.Scan(&fragment); scanErr != nil {
				return scanErr
			}
			citedFragments = append(citedFragments, fragment)
		}
		return cursor.Err()
	})
	if err != nil || len(citedFragments) == 0 {
		return nil, ""
	}
	rowByFragment := make(map[string]snapshotRow, len(group))
	for _, row := range group {
		for _, cell := range row.cells {
			if _, exists := rowByFragment[cell.fragmentID]; !exists {
				rowByFragment[cell.fragmentID] = row
			}
		}
	}
	matched := make([]snapshotRow, 0, len(citedFragments))
	for _, fragment := range citedFragments {
		if row, ok := rowByFragment[fragment]; ok {
			matched = append(matched, row)
		}
	}
	if len(matched) == 0 {
		return nil, ""
	}
	return matched, service.structuredRowsetFilterLabel(ctx, access, runID)
}

// structuredRowsetFilterLabel renders FIX-7 #1's human-readable filter
// caption from a run's own AnswerResult (the SAME structured artifact GET
// /questions/{run_id} already decodes and discloses to this principal). A run
// with no decodable AnswerResult (an older artifact schema, or a run that was
// not answered through the aggregate reducer) gets the same conservative
// "whole snapshot" caption the pre-FIX-7 behavior always showed.
func (service *Service) structuredRowsetFilterLabel(ctx context.Context, access database.AccessContext, runID string) string {
	var answer *AnswerResult
	_ = service.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		plain, fetchErr := fetchAndOpenArtifact(txCtx, tx, service, access, artifactcrypto.AnswerStructured, runID)
		if fetchErr != nil {
			return fetchErr
		}
		defer clear(plain)
		var structured structuredAnswer
		if decodeErr := jsonv2.Unmarshal(plain, &structured, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); decodeErr != nil {
			return decodeErr
		}
		answer = structured.AnswerResult
		return nil
	})
	if answer == nil {
		return "entire source snapshot"
	}
	parts := make([]string, 0, len(answer.Filters)+1)
	if answer.Period != nil {
		switch {
		case answer.Period.Label != "":
			parts = append(parts, "period: "+answer.Period.Label)
		case answer.Period.From != "":
			parts = append(parts, "period: from "+answer.Period.From+" through "+answer.Period.To)
		}
	}
	for _, filter := range answer.Filters {
		if filter.Name == "condition" && filter.Value == "overdue" {
			parts = append(parts, "overdue")
			continue
		}
		parts = append(parts, filter.Name+" = "+filter.Value)
	}
	if len(parts) == 0 {
		return "unfiltered: entire current source snapshot"
	}
	return "Selection: " + strings.Join(parts, "; ")
}
