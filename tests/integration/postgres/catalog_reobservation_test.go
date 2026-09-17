package postgres_test

import (
	"fmt"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

func TestFolderReobservationPreservesHistoryAndRepeat(t *testing.T) {
	first, second := "original document\n", "edited document\n"
	f := newExactEvidenceFixture(t, first)
	type retained struct{ version, fragment, text string }
	history := []retained{}
	var previous string
	for i, text := range []string{first, first, second, first, first, second, first} {
		writeS1dFile(t, f.target, text)
		runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), fmt.Sprintf("reobserve-%d", i))
		_, version, extraction := s1dActiveEvidence(t, f.ctx, f.admin)
		fragment := s1dFragments(t, f.ctx, f.admin, extraction)[0].id
		whole, err := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, fragment)
		if err != nil || string(whole.Text) != text {
			t.Fatalf("step %d current bytes=%q err=%v, want %q", i, whole.Text, err, text)
		}
		if text != previous {
			for _, old := range history {
				if version == old.version {
					t.Fatalf("step %d revived historical version %s", i, version)
				}
			}
			history = append(history, retained{version, fragment, text})
		} else if version != history[len(history)-1].version {
			t.Fatalf("step %d repeat created a new version", i)
		}
		for _, old := range history {
			read, err := f.viewer.ReadObjectExactVersion(f.ctx, f.access, s1dWorkspace, old.fragment, old.version)
			if err != nil || string(read.Text) != old.text {
				t.Fatalf("step %d historical bytes changed: %q err=%v", i, read.Text, err)
			}
			var state string
			if err := f.admin.QueryRow(f.ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`, s1dOrg, old.version).Scan(&state); err != nil {
				t.Fatal(err)
			}
			want := "SUPERSEDED"
			if old.version == version {
				want = "CURRENT"
			}
			if state != want {
				t.Fatalf("version %s state=%s want=%s", old.version, state, want)
			}
		}
		if got := s1dCounts(t, f.ctx, f.admin).versions; got != len(history) {
			t.Fatalf("versions=%d want=%d", got, len(history))
		}
		previous = text
	}
}

func TestFolderReobservationCannotBypassHistoricalPurge(t *testing.T) {
	f := newExactEvidenceFixture(t, "original\n")
	_, old, _ := s1dActiveEvidence(t, f.ctx, f.admin)
	writeS1dFile(t, f.target, "replacement\n")
	runSync(t, f.ctx, f.handler, f.queue, workerAccess(t, s1dOrg), "reobserve-before-purge")
	_, current, _ := s1dActiveEvidence(t, f.ctx, f.admin)
	purger, err := purge.NewPurger(openStore(t, f.ctx, purgerRole, "knowvault_purger"), time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(f.ctx, purgerAccess(), old, "OPERATOR_REQUEST"); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, f.target, "original\n")
	access := workerAccess(t, s1dOrg)
	if _, err := f.queue.Enqueue(f.ctx, access, jobs.Spec{JobID: mustID(t, "job"), Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "reobserve-purged", Priority: 100, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := f.queue.Claim(f.ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: %v %v", err, ok)
	}
	if err := f.handler.Handle(f.ctx, access, claimed); err == nil {
		t.Fatal("historical purge bypassed by a new observation")
	} else if ingestion.CodeOf(err) == "" {
		t.Fatal(err)
	}
	_, after, _ := s1dActiveEvidence(t, f.ctx, f.admin)
	if after != current || s1dCounts(t, f.ctx, f.admin).versions != 2 {
		t.Fatal("refused observation changed versions")
	}
}
