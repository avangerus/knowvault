package composition

// source_sql_limit.go is S3 card 2c's server-owned load limit for ADR-0097's
// agent-authored SQL tool (review finding F3). The limits are properties of the
// production server, not of a request:
//
//   - at most 2 executions may be in flight for one source at a time;
//   - at most 20 executions may start in any rolling minute for one principal.
//
// Every transport (MCP, REST and the chat runtime) reaches the customer
// database through the one sourceSQLExecutor, so the shared limiter is the one
// place the limits are enforced and the three surfaces cannot diverge. A call
// over either limit is refused with a closed code before any credential is
// resolved and before any external connection is opened, so it never touches
// the customer database. The refusal is still audited: authorization already
// passed, and the audit is content-free.

import (
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

const (
	// sourceSQLMaxConcurrentPerSource is the card's per-source concurrency
	// bound: at most two executions may be in flight at once.
	sourceSQLMaxConcurrentPerSource = 2
	// sourceSQLMaxExecutionsPerMinute is the card's per-principal rate bound.
	sourceSQLMaxExecutionsPerMinute = 20
	// sourceSQLRateWindow is the rolling window the rate bound is measured over.
	sourceSQLRateWindow = time.Minute
)

// sourceSQLLimiter is the in-process, server-owned admission control. It is
// deliberately per-instance: the card's limits are load shedding, not a
// durable quota, and the database role plus the transaction pins remain the
// security and resource boundary. A nil limiter admits nothing, so a
// miscomposed executor fails closed instead of running unlimited.
type sourceSQLLimiter struct {
	mu         sync.Mutex
	inFlight   map[string]int
	executions map[string][]time.Time
	now        func() time.Time
}

func newSourceSQLLimiter() *sourceSQLLimiter {
	return &sourceSQLLimiter{
		inFlight:   make(map[string]int),
		executions: make(map[string][]time.Time),
		now:        time.Now,
	}
}

// acquire admits one execution for the (source, principal) pair. It returns the
// release function the caller must invoke when the execution finishes and the
// empty string on admission, or a closed refusal code when the call exceeds the
// concurrency or the rate bound. Admission is non-blocking: an over-limit call
// is refused, never queued, so the caller cannot be held by the limiter.
func (limiter *sourceSQLLimiter) acquire(sourceID, principalID string) (func(), string) {
	if limiter == nil {
		return func() {}, string(governedquery.CodeSourceSQLConcurrencyLimited)
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.now == nil {
		limiter.now = time.Now
	}
	if limiter.inFlight == nil {
		limiter.inFlight = make(map[string]int)
	}
	if limiter.executions == nil {
		limiter.executions = make(map[string][]time.Time)
	}
	if limiter.inFlight[sourceID] >= sourceSQLMaxConcurrentPerSource {
		return func() {}, string(governedquery.CodeSourceSQLConcurrencyLimited)
	}
	cutoff := limiter.now().Add(-sourceSQLRateWindow)
	recent := limiter.executions[principalID][:0]
	for _, started := range limiter.executions[principalID] {
		if started.After(cutoff) {
			recent = append(recent, started)
		}
	}
	if len(recent) >= sourceSQLMaxExecutionsPerMinute {
		limiter.executions[principalID] = recent
		return func() {}, string(governedquery.CodeSourceSQLRateLimited)
	}
	limiter.executions[principalID] = append(recent, limiter.now())
	limiter.inFlight[sourceID]++
	released := false
	return func() {
		limiter.mu.Lock()
		defer limiter.mu.Unlock()
		if released {
			return
		}
		released = true
		if limiter.inFlight[sourceID] > 0 {
			limiter.inFlight[sourceID]--
		}
	}, ""
}
