package question

import (
	"testing"
	"time"
)

func TestContentFreshWithinSLAFailClosed(t *testing.T) {
	captured := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	valid := captured.Add(-5 * time.Minute)
	future := captured.Add(time.Minute)
	stale := captured.Add(-11 * time.Minute)

	for _, tc := range []struct {
		name string
		last *time.Time
		sla  int64
		want bool
	}{
		{name: "within", last: &valid, sla: 600, want: true},
		{name: "boundary", last: func() *time.Time { value := captured.Add(-10 * time.Minute); return &value }(), sla: 600, want: true},
		{name: "stale", last: &stale, sla: 600, want: false},
		{name: "future", last: &future, sla: 600, want: false},
		{name: "missing", last: nil, sla: 600, want: false},
		{name: "invalid_sla", last: &valid, sla: 0, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentFreshWithinSLA(captured, tc.last, tc.sla); got != tc.want {
				t.Fatalf("freshness=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestEffectiveCorpusHealthCannotReportStaleSourceHealthy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		health string
		fresh  bool
		want   string
	}{
		{name: "healthy_fresh", health: "HEALTHY", fresh: true, want: "HEALTHY"},
		{name: "healthy_stale", health: "HEALTHY", fresh: false, want: "STALE"},
		{name: "failed", health: "FAILED", fresh: false, want: "FAILED"},
		{name: "unknown", health: "UNKNOWN", fresh: false, want: "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveCorpusHealth(tc.health, tc.fresh); got != tc.want {
				t.Fatalf("health=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestCorpusFreshnessStateFailsClosedAcrossSources(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		count                            int64
		failed, unknown, stale, disabled bool
		want                             string
	}{
		{name: "no snapshot", want: freshnessUnknown},
		{name: "all healthy", count: 2, want: freshnessFresh},
		{name: "disabled source", count: 2, disabled: true, want: freshnessDisabled},
		{name: "stale dominates healthy", count: 2, stale: true, want: freshnessStale},
		{name: "unknown dominates stale", count: 2, unknown: true, stale: true, want: freshnessUnknown},
		{name: "failed dominates every state", count: 2, failed: true, unknown: true, stale: true, want: freshnessFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := corpusFreshnessState(tc.count, tc.failed, tc.unknown, tc.stale, tc.disabled); got != tc.want {
				t.Fatalf("state=%q want=%q", got, tc.want)
			}
		})
	}
}
