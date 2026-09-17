//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// syncRunState is the content-free projection of one sync_run row: status and
// the typed counters, nothing else. The harness never inspects content
// through the admin role.
type syncRunState struct {
	ID                string
	Status            string
	ObjectsSeen       int64
	ObjectsIngested   int64
	VersionsCreated   int64
	EvidencePublished int64
	Quarantined       int64
}

// jobQueueDump is the content-free projection of the tenant job queue for
// failure diagnostics: identity, status and lease bookkeeping, never payload
// contents.
func jobQueueDump(ctx context.Context, admin *pgxpool.Pool, cfg config) string {
	rows, err := admin.Query(ctx, `
		SELECT id, type, status, attempt_count, max_attempts, coalesce(lease_owner, ''),
		       available_at <= transaction_timestamp() AS available
		FROM public.job
		WHERE organization_id = $1
		ORDER BY created_at, id`, cfg.organizationID)
	if err != nil {
		return fmt.Sprintf("job queue read: %v", err)
	}
	defer rows.Close()
	var line strings.Builder
	fmt.Fprintf(&line, "job queue (organization %s):", cfg.organizationID)
	count := 0
	for rows.Next() {
		var id, jobType, status, leaseOwner string
		var attempts, maxAttempts int
		var available bool
		if err := rows.Scan(&id, &jobType, &status, &attempts, &maxAttempts, &leaseOwner, &available); err != nil {
			fmt.Fprintf(&line, "\n  (scan: %v)", err)
			continue
		}
		count++
		fmt.Fprintf(&line, "\n  %s type=%s status=%s attempts=%d/%d lease=%q available=%v",
			id, jobType, status, attempts, maxAttempts, leaseOwner, available)
	}
	if count == 0 {
		fmt.Fprint(&line, "\n  (no rows)")
	}
	return line.String()
}

// errSyncRunNotFound marks a scope that has no sync run at all yet. It is not
// a failure: the durable job places the RUNNING row milliseconds after its
// claim, so a poll that lands before the first claim must keep waiting, not
// fail the window.
var errSyncRunNotFound = errors.New("sync run not started yet")

// latestSyncRun reads the newest sync_run row of the scope. A scope without
// any sync run yields errSyncRunNotFound.
func latestSyncRun(ctx context.Context, admin *pgxpool.Pool, cfg config, sourceScopeID string) (syncRunState, error) {
	var state syncRunState
	err := admin.QueryRow(ctx, `
		SELECT id, status, objects_seen, objects_ingested, versions_created, evidence_published, quarantined
		FROM public.sync_run
		WHERE organization_id = $1 AND source_scope_id = $2
		ORDER BY started_at DESC, id DESC
		LIMIT 1`, cfg.organizationID, sourceScopeID).Scan(
		&state.ID, &state.Status, &state.ObjectsSeen, &state.ObjectsIngested,
		&state.VersionsCreated, &state.EvidencePublished, &state.Quarantined)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return syncRunState{}, errSyncRunNotFound
		}
		return syncRunState{}, fmt.Errorf("read sync run: %w", err)
	}
	return state, nil
}

// waitForSyncRun polls until the newest sync run of the scope reports the
// wanted status. A FAILED run is a hard error; polling past the deadline
// reports the last observed state.
func waitForSyncRun(ctx context.Context, admin *pgxpool.Pool, cfg config, sourceScopeID, wanted string, timeout time.Duration) (syncRunState, error) {
	deadline := time.Now().Add(timeout)
	var last syncRunState
	lastStatus := "NOT_STARTED"
	for time.Now().Before(deadline) {
		state, err := latestSyncRun(ctx, admin, cfg, sourceScopeID)
		if err != nil {
			if !errors.Is(err, errSyncRunNotFound) {
				return syncRunState{}, err
			}
		} else {
			last = state
			lastStatus = state.Status
			if state.Status == wanted {
				return state, nil
			}
			if state.Status == "FAILED" {
				return state, fmt.Errorf("sync run %s failed", state.ID)
			}
		}
		select {
		case <-ctx.Done():
			return syncRunState{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return last, fmt.Errorf("sync run did not reach %s within %v (last status %s)", wanted, timeout, lastStatus)
}

// waitJournal accumulates the distinct database-activity snapshots observed
// while waitForSyncRunJournaled waits, so a window that ends without the wanted
// status reports what the worker was actually doing in the database the whole
// time instead of a single end-state snapshot.
type waitJournal struct {
	keep    int
	start   time.Time
	last    string
	entries []string
}

func newWaitJournal(keep int) *waitJournal {
	return &waitJournal{keep: keep, start: time.Now()}
}

func (journal *waitJournal) capture(ctx context.Context, admin *pgxpool.Pool) {
	snapshot := workerWaitSnapshot(ctx, admin)
	if snapshot == journal.last {
		return
	}
	journal.last = snapshot
	journal.entries = append(journal.entries,
		fmt.Sprintf("t=%.1fs\n%s", time.Since(journal.start).Seconds(), snapshot))
	if len(journal.entries) > journal.keep {
		journal.entries = journal.entries[len(journal.entries)-journal.keep:]
	}
}

func (journal *waitJournal) String() string {
	if len(journal.entries) == 0 {
		return "(no worker database activity observed)"
	}
	return strings.Join(journal.entries, "\n")
}

// workerWaitSnapshot captures the worker's database sessions, every active
// session and the ungranted lock waits in one content-free picture. It is the
// discriminator between a worker that keeps polling and seeing nothing, a
// worker wedged on a lock, and a worker that never reaches the database.
func workerWaitSnapshot(ctx context.Context, admin *pgxpool.Pool) string {
	var line strings.Builder
	appendRows := func(title, sql string, scan func(pgx.Rows) error) {
		rows, err := admin.Query(ctx, sql)
		if err != nil {
			fmt.Fprintf(&line, "%s: (query: %v)\n", title, err)
			return
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			if err := scan(rows); err != nil {
				fmt.Fprintf(&line, "%s: (scan: %v)\n", title, err)
				return
			}
			count++
		}
		if count == 0 {
			fmt.Fprintf(&line, "%s: (none)\n", title)
		}
	}
	appendRows("worker sessions", `
		SELECT pid, state, coalesce(wait_event_type, ''), coalesce(wait_event, ''),
		       coalesce(left(query, 80), ''), coalesce(xact_start::text, '')
		FROM pg_stat_activity
		WHERE usename = 'knowvault_worker'
		ORDER BY pid`, func(rows pgx.Rows) error {
		var pid int
		var state, waitType, waitEvent, query, xactStart string
		if err := rows.Scan(&pid, &state, &waitType, &waitEvent, &query, &xactStart); err != nil {
			return err
		}
		fmt.Fprintf(&line, "  pid=%d state=%s wait=%s/%s query=%q xact=%s\n",
			pid, state, waitType, waitEvent, query, xactStart)
		return nil
	})
	appendRows("active", `
		SELECT pid, coalesce(usename, ''), state, coalesce(wait_event_type, ''),
		       coalesce(wait_event, ''), coalesce(left(query, 80), '')
		FROM pg_stat_activity
		WHERE state = 'active' AND pid <> pg_backend_pid()
		ORDER BY pid`, func(rows pgx.Rows) error {
		var pid int
		var user, state, waitType, waitEvent, query string
		if err := rows.Scan(&pid, &user, &state, &waitType, &waitEvent, &query); err != nil {
			return err
		}
		fmt.Fprintf(&line, "  pid=%d user=%s wait=%s/%s query=%q\n",
			pid, user, waitType, waitEvent, query)
		return nil
	})
	appendRows("ungranted locks", `
		SELECT l.pid, l.mode, coalesce(l.relation::regclass::text, ''),
		       coalesce(l.transactionid::text, '')
		FROM pg_locks AS l
		WHERE NOT l.granted
		ORDER BY l.pid, l.mode`, func(rows pgx.Rows) error {
		var pid int
		var mode, relation, transaction string
		if err := rows.Scan(&pid, &mode, &relation, &transaction); err != nil {
			return err
		}
		fmt.Fprintf(&line, "  pid=%d mode=%s relation=%q xid=%s\n", pid, mode, relation, transaction)
		return nil
	})
	return line.String()
}

// waitForSyncRunJournaled is waitForSyncRun plus a 500ms activity journal of
// the worker's database sessions, active sessions and lock waits, so a failed
// window explains itself.
func waitForSyncRunJournaled(ctx context.Context, admin *pgxpool.Pool, cfg config, sourceScopeID, wanted string, timeout time.Duration) (syncRunState, error) {
	deadline := time.Now().Add(timeout)
	var last syncRunState
	lastStatus := "NOT_STARTED"
	journal := newWaitJournal(12)
	ticks := 0
	for time.Now().Before(deadline) {
		state, err := latestSyncRun(ctx, admin, cfg, sourceScopeID)
		if err != nil {
			if !errors.Is(err, errSyncRunNotFound) {
				return syncRunState{}, err
			}
		} else {
			last = state
			lastStatus = state.Status
			if state.Status == wanted {
				return state, nil
			}
			if state.Status == "FAILED" {
				return state, fmt.Errorf("sync run %s failed\nworker wait journal:\n%s", state.ID, journal.String())
			}
		}
		ticks++
		if ticks%10 == 0 {
			journal.capture(ctx, admin)
		}
		select {
		case <-ctx.Done():
			return syncRunState{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return last, fmt.Errorf("sync run did not reach %s within %v (last status %s)\nworker wait journal:\n%s",
		wanted, timeout, lastStatus, journal.String())
}

// scopeCatalogTotals counts the rows the scope actually materialized: versions
// through the object membership chain and evidence fragments through the
// extraction chain. Each object commits atomically (membership, version,
// extraction, fragments in one transaction), so the catalog is the
// deterministic record of what the scope holds — unlike sync_run counters,
// which the product writes only in the terminal SUCCEEDED update and which a
// SIGKILLed run therefore never records even for the objects it committed.
func scopeCatalogTotals(ctx context.Context, admin *pgxpool.Pool, cfg config, sourceScopeID string) (versions, evidence int64, err error) {
	err = admin.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM public.source_version AS version
			 JOIN public.source_object_scope AS member
			   ON member.organization_id = version.organization_id
			  AND member.source_object_id = version.source_object_id
			 WHERE version.organization_id = $1 AND member.source_scope_id = $2
			   AND member.membership_state = 'ACTIVE'),
			(SELECT count(*) FROM public.evidence_fragment AS fragment
			 JOIN public.source_version AS version
			   ON version.organization_id = fragment.organization_id
			  AND version.id = fragment.source_version_id
			 JOIN public.source_object_scope AS member
			   ON member.organization_id = fragment.organization_id
			  AND member.source_object_id = version.source_object_id
			 WHERE fragment.organization_id = $1 AND member.source_scope_id = $2
			   AND member.membership_state = 'ACTIVE')`,
		cfg.organizationID, sourceScopeID).Scan(&versions, &evidence)
	if err != nil {
		return 0, 0, fmt.Errorf("aggregate scope catalog totals: %w", err)
	}
	return versions, evidence, nil
}

// catalogCounts returns the tenant-wide row counts of the three catalog
// relations the duplicate-detection charter clause aggregates.
func catalogCounts(ctx context.Context, admin *pgxpool.Pool, cfg config) (objects, memberships, versions int64, err error) {
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id = $1`, cfg.organizationID).Scan(&objects); err != nil {
		return 0, 0, 0, fmt.Errorf("count source objects: %w", err)
	}
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope WHERE organization_id = $1`, cfg.organizationID).Scan(&memberships); err != nil {
		return 0, 0, 0, fmt.Errorf("count source object memberships: %w", err)
	}
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version WHERE organization_id = $1`, cfg.organizationID).Scan(&versions); err != nil {
		return 0, 0, 0, fmt.Errorf("count source versions: %w", err)
	}
	return objects, memberships, versions, nil
}

// firstFragmentID returns one evidence fragment of the scope, resolved through
// the extraction → version → membership chain so the viewer route check reads
// a fragment that genuinely belongs to the synchronized scope.
func firstFragmentID(ctx context.Context, admin *pgxpool.Pool, cfg config, sourceScopeID string) (string, error) {
	var id string
	err := admin.QueryRow(ctx, `
		SELECT fragment.id
		FROM public.evidence_fragment AS fragment
		JOIN public.source_version AS version
		  ON version.organization_id = fragment.organization_id AND version.id = fragment.source_version_id
		JOIN public.source_object_scope AS member
		  ON member.organization_id = fragment.organization_id AND member.source_object_id = version.source_object_id
		WHERE fragment.organization_id = $1 AND member.source_scope_id = $2 AND member.membership_state = 'ACTIVE'
		ORDER BY fragment.created_at, fragment.id
		LIMIT 1`, cfg.organizationID, sourceScopeID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("read first evidence fragment: %w", err)
	}
	return id, nil
}

// jobCount returns how many rows the durable job has in the tenant; the
// idempotent-activation clause requires exactly one for the activation key.
func jobCount(ctx context.Context, admin *pgxpool.Pool, cfg config, jobID string) (int64, error) {
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE organization_id = $1 AND id = $2`,
		cfg.organizationID, jobID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count job rows: %w", err)
	}
	return count, nil
}
