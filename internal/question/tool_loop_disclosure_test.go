package question

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	toolLoopDisclosureScopeMarker    = "current_workspace"
	toolLoopDisclosureEvidenceMarker = "evidence_fragment_readable"
)

type toolLoopDisclosureFakeScanner struct {
	// scopeResults and evidenceResults are consumed one per classified
	// query; running out of either makes the returned Scan fail.
	scopeResults    []bool
	evidenceResults []bool
	scopeCalls      int
	evidenceCalls   int
	// sequence records the classified call order, for exact assertions.
	sequence []string
	// unexpected is set when an unknown SQL statement is observed.
	unexpected string
}

// ScanRow mirrors the database platform seam: it classifies the statement,
// writes the supplied boolean into the single *bool destination, and returns
// strict errors directly.
func (scanner *toolLoopDisclosureFakeScanner) ScanRow(_ context.Context, sql string, args []any, destinations ...any) error {
	switch {
	case strings.Contains(sql, toolLoopDisclosureScopeMarker):
		scanner.scopeCalls++
		scanner.sequence = append(scanner.sequence, "scope")
		if scanner.scopeCalls > len(scanner.scopeResults) {
			return fmt.Errorf("tool-loop disclosure test: unexpected scope query %d", scanner.scopeCalls)
		}
		return scanToolLoopDisclosureBool(destinations, scanner.scopeResults[scanner.scopeCalls-1])
	case strings.Contains(sql, toolLoopDisclosureEvidenceMarker):
		scanner.evidenceCalls++
		scanner.sequence = append(scanner.sequence, "evidence")
		if err := validateToolLoopDisclosureEvidenceArgs(args); err != nil {
			return err
		}
		if scanner.evidenceCalls > len(scanner.evidenceResults) {
			return fmt.Errorf("tool-loop disclosure test: unexpected evidence query %d", scanner.evidenceCalls)
		}
		return scanToolLoopDisclosureBool(destinations, scanner.evidenceResults[scanner.evidenceCalls-1])
	default:
		scanner.sequence = append(scanner.sequence, "unknown")
		scanner.unexpected = sql
		return fmt.Errorf("tool-loop disclosure test: unrecognized query %q", sql)
	}
}

// scanToolLoopDisclosureBool writes value into the single *bool destination.
func scanToolLoopDisclosureBool(destinations []any, value bool) error {
	if len(destinations) != 1 {
		return fmt.Errorf("tool-loop disclosure test: got %d destinations, want 1", len(destinations))
	}
	target, ok := destinations[0].(*bool)
	if !ok {
		return fmt.Errorf("tool-loop disclosure test: destination is %T, want *bool", destinations[0])
	}
	*target = value
	return nil
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
			scanner := &toolLoopDisclosureFakeScanner{
				scopeResults:    testCase.scopeResults,
				evidenceResults: testCase.evidenceResults,
			}
			err := toolLoopDisclosure(context.Background(), scanner,
				questionAccess(database.ActorKindHuman), run)
			if testCase.wantError {
				if CodeOf(err) != CodeNotFound {
					t.Fatalf("toolLoopDisclosure error = %v code=%q, want %q", err, CodeOf(err), CodeNotFound)
				}
			} else if err != nil {
				t.Fatalf("toolLoopDisclosure = %v, want nil", err)
			}
			if scanner.unexpected != "" {
				t.Fatalf("toolLoopDisclosure issued unrecognized query %q", scanner.unexpected)
			}
			// An unknown classification yields a failing Scan and
			// therefore a non-NotFound error; prove that never
			// masqueraded as a valid denial.
			if got := CodeOf(err); err != nil && got != CodeNotFound {
				t.Fatalf("toolLoopDisclosure error = %v code=%q, want code %q", err, got, CodeNotFound)
			}
			if !reflect.DeepEqual(scanner.sequence, testCase.wantSequence) {
				t.Fatalf("classified call sequence = %#v, want %#v", scanner.sequence, testCase.wantSequence)
			}
			if scanner.scopeCalls != 1 {
				t.Fatalf("scope queries = %d, want 1", scanner.scopeCalls)
			}
		})
	}
}
