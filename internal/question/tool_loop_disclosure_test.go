package question

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/platform/database"
)

type toolLoopDisclosureBoolRow struct {
	value bool
	err   error
}

func (row toolLoopDisclosureBoolRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != 1 {
		return fmt.Errorf("tool-loop disclosure test row: got %d destinations, want 1", len(dest))
	}
	target, ok := dest[0].(*bool)
	if !ok {
		return fmt.Errorf("tool-loop disclosure test row: destination is %T, want *bool", dest[0])
	}
	*target = row.value
	return nil
}

type toolLoopDisclosureFakeQueryer struct {
	rows  []bool
	calls int
}

func (queryer *toolLoopDisclosureFakeQueryer) QueryRow(context.Context, string, ...any) pgx.Row {
	queryer.calls++
	if queryer.calls > len(queryer.rows) {
		return toolLoopDisclosureBoolRow{err: fmt.Errorf("tool-loop disclosure test: unexpected query %d", queryer.calls)}
	}
	return toolLoopDisclosureBoolRow{value: queryer.rows[queryer.calls-1]}
}

func TestToolLoopDisclosureReauthorizesScopeAndEvidence(t *testing.T) {
	text := "evidence text"
	run := Run{
		WorkspaceID:       "ws_0001",
		WorkspaceRevision: 1,
		AnswerMode:        AnswerModeToolLoop,
		ToolLoop: &ToolLoopRecord{Calls: []ToolCallRecord{
			testReadCall(t, "read-1", testReadAddress(t, "v1", text), text),
		}},
	}
	cases := []struct {
		name      string
		rows      []bool
		wantError bool
		wantCalls int
	}{
		{name: "stale scope stops before evidence query", rows: []bool{false}, wantError: true, wantCalls: 1},
		{name: "unreadable evidence denies disclosure", rows: []bool{true, false}, wantError: true, wantCalls: 2},
		{name: "current readable footprint is disclosed", rows: []bool{true, true}, wantCalls: 2},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			queryer := &toolLoopDisclosureFakeQueryer{rows: testCase.rows}
			err := toolLoopDisclosure(context.Background(), queryer,
				questionAccess(database.ActorKindHuman), run)
			if testCase.wantError {
				if CodeOf(err) != CodeNotFound {
					t.Fatalf("toolLoopDisclosure error = %v code=%q, want %q", err, CodeOf(err), CodeNotFound)
				}
			} else if err != nil {
				t.Fatalf("toolLoopDisclosure = %v, want nil", err)
			}
			if queryer.calls != testCase.wantCalls {
				t.Fatalf("queries = %d, want %d", queryer.calls, testCase.wantCalls)
			}
		})
	}
}
