package question

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	toolLoopDisclosureScopeMarker    = "current_workspace"
	toolLoopDisclosureEvidenceMarker = "evidence_fragment_readable"
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
	// scopeResults and evidenceResults are consumed one per classified
	// query; running out of either makes the returned row's Scan fail.
	scopeResults    []bool
	evidenceResults []bool
	scopeCalls      int
	evidenceCalls   int
	// sequence records the classified call order, for exact assertions.
	sequence []string
	// unexpected is set when an unknown SQL statement is observed.
	unexpected string
}

func (queryer *toolLoopDisclosureFakeQueryer) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, toolLoopDisclosureScopeMarker):
		queryer.scopeCalls++
		queryer.sequence = append(queryer.sequence, "scope")
		if queryer.scopeCalls > len(queryer.scopeResults) {
			return toolLoopDisclosureBoolRow{err: fmt.Errorf(
				"tool-loop disclosure test: unexpected scope query %d", queryer.scopeCalls)}
		}
		return toolLoopDisclosureBoolRow{value: queryer.scopeResults[queryer.scopeCalls-1]}
	case strings.Contains(sql, toolLoopDisclosureEvidenceMarker):
		queryer.evidenceCalls++
		queryer.sequence = append(queryer.sequence, "evidence")
		if err := validateToolLoopDisclosureEvidenceArgs(args); err != nil {
			return toolLoopDisclosureBoolRow{err: err}
		}
		if queryer.evidenceCalls > len(queryer.evidenceResults) {
			return toolLoopDisclosureBoolRow{err: fmt.Errorf(
				"tool-loop disclosure test: unexpected evidence query %d", queryer.evidenceCalls)}
		}
		return toolLoopDisclosureBoolRow{value: queryer.evidenceResults[queryer.evidenceCalls-1]}
	default:
		queryer.sequence = append(queryer.sequence, "unknown")
		queryer.unexpected = sql
		return toolLoopDisclosureBoolRow{err: fmt.Errorf(
			"tool-loop disclosure test: unrecognized query %q", sql)}
	}
}

// validateToolLoopDisclosureEvidenceArgs proves the evidence query observes the
// exact footprint: two arguments, the object set, and the workspace id.
func validateToolLoopDisclosureEvidenceArgs(args []any) error {
	if len(args) != 2 {
		return fmt.Errorf("tool-loop disclosure test: evidence args = %d, want 2", len(args))
	}
	footprint, ok := args[0].([]string)
	if !ok {
		return fmt.Errorf("tool-loop disclosure test: evidence arg 0 is %T, want []string", args[0])
	}
	if !reflect.DeepEqual(footprint, []string{"demo-object"}) {
		return fmt.Errorf("tool-loop disclosure test: evidence footprint = %#v, want []string{\"demo-object\"}", footprint)
	}
	workspace, ok := args[1].(string)
	if !ok {
		return fmt.Errorf("tool-loop disclosure test: evidence arg 1 is %T, want string", args[1])
	}
	if workspace != "ws_0001" {
		return fmt.Errorf("tool-loop disclosure test: evidence workspace = %q, want %q", workspace, "ws_0001")
	}
	return nil
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
		name            string
		scopeResults    []bool
		evidenceResults []bool
		wantError       bool
		wantSequence    []string
	}{
		{
			name:         "stale scope stops before evidence query",
			scopeResults: []bool{false},
			wantError:    true,
			wantSequence: []string{"scope"},
		},
		{
			name:            "unreadable evidence denies disclosure",
			scopeResults:    []bool{true},
			evidenceResults: []bool{false},
			wantError:       true,
			wantSequence:    []string{"scope", "evidence"},
		},
		{
			name:            "current readable footprint is disclosed",
			scopeResults:    []bool{true},
			evidenceResults: []bool{true},
			wantSequence:    []string{"scope", "evidence"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			queryer := &toolLoopDisclosureFakeQueryer{
				scopeResults:    testCase.scopeResults,
				evidenceResults: testCase.evidenceResults,
			}
			err := toolLoopDisclosure(context.Background(), queryer,
				questionAccess(database.ActorKindHuman), run)
			if testCase.wantError {
				if CodeOf(err) != CodeNotFound {
					t.Fatalf("toolLoopDisclosure error = %v code=%q, want %q", err, CodeOf(err), CodeNotFound)
				}
			} else if err != nil {
				t.Fatalf("toolLoopDisclosure = %v, want nil", err)
			}
			if queryer.unexpected != "" {
				t.Fatalf("toolLoopDisclosure issued unrecognized query %q", queryer.unexpected)
			}
			// An unknown classification yields a failing Scan and
			// therefore a non-NotFound error; prove that never
			// masqueraded as a valid denial.
			if got := CodeOf(err); err != nil && got != CodeNotFound {
				t.Fatalf("toolLoopDisclosure error = %v code=%q, want code %q", err, got, CodeNotFound)
			}
			if !reflect.DeepEqual(queryer.sequence, testCase.wantSequence) {
				t.Fatalf("classified call sequence = %#v, want %#v", queryer.sequence, testCase.wantSequence)
			}
			if queryer.scopeCalls != 1 {
				t.Fatalf("scope queries = %d, want 1", queryer.scopeCalls)
			}
		})
	}
}
