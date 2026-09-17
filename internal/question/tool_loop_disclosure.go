package question

import (
	"context"
	"sort"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// A trace contains every retrieved result, including evidence not cited in
// the final answer. The legacy citation gate alone cannot authorize it.
// Recheck the full footprint in the same transaction as run disclosure.
func toolLoopDisclosure(ctx context.Context, tx database.Transaction, access database.AccessContext, run Run) error {
	if run.AnswerMode != AnswerModeToolLoop {
		return nil
	}
	if run.ToolLoop == nil {
		if run.ResultStatus == "RUNNING" || run.ResultStatus == "FAILED" || run.ResultStatus == "CANCELLED" {
			return nil
		}
		return &Error{code: CodeNotFound}
	}
	scopeCurrent, err := currentToolLoopScope(ctx, tx, access, run)
	if err != nil {
		return err
	}
	if !scopeCurrent {
		return &Error{code: CodeNotFound}
	}
	observed := make(map[string]bool)
	for _, call := range run.ToolLoop.Calls {
		if call.Outcome == "SUCCEEDED" {
			collectToolAddresses(call.Result.Structured, observed)
		}
	}
	set := make(map[string]bool)
	for value := range observed {
		selector, err := address.Parse(value)
		if err != nil {
			return &Error{code: CodeNotFound}
		}
		set[selector.Object] = true
	}
	fragments := make([]string, 0, len(set))
	for id := range set {
		fragments = append(fragments, id)
	}
	sort.Strings(fragments)
	var readable bool
	if err := tx.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM unnest($1::text[]) id WHERE NOT app.evidence_fragment_readable(id,$2)
	)`, fragments, run.WorkspaceID).Scan(&readable); err != nil {
		return err
	}
	if !readable {
		return &Error{code: CodeNotFound}
	}
	return nil
}
