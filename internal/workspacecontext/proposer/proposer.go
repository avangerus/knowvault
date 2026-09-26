// Package proposer is S2 card E's deterministic workspace-context proposer
// (ADR-0098 decision 4, S2-MODEL-CONTEXT-DESIGN.md "Proposer"): a
// heuristic-v1 detector that runs after a completed question run and turns
// three closed signals (SYNONYM, DEFINITION_CORRECTION, NEW_TERM) into
// PROPOSED workspace_context_proposal rows, plus a Store that implements
// workspacecontext's RunObserver and ProposalService interfaces
// (internal/workspacecontext/interfaces.go, card A0) against migration
// 000113 (workspace_context_proposal, workspace_context_proposal_evidence,
// workspace_context_term_sighting).
//
// The detector (detector.go) is a pure function of one
// workspacecontext.RunEvent: no model call, no database read, no network
// call, entirely table-testable. The store (store.go) is the only part of
// this package that opens a transaction; it depends on
// internal/platform/database directly (a stable, card-independent platform
// package, not one of S2's parallel cards) and on workspacecontext's own A0
// interfaces only for anything that crosses into another card's territory.
// Two seams this package cannot close by itself — minting a new context
// version atomically with an accepted proposal (card A's not-yet-existing
// store), and resolving an evidence run to a viewer-authorized excerpt (card
// B's question.Service) — are exposed as this package's own narrow
// interfaces (VersionMinter, RunExcerptReader) for the lead to wire in
// composition/runtime.go; see their doc comments for the exact contract.
//
// A proposal is never evidence and never changes the tool catalog, read-only
// transactions or authorization (ADR-0098 decision 3); it only records a
// candidate glossary edit that takes effect exclusively through an explicit,
// audited OWNER/MANAGER decision. This package never writes an audit event
// itself (architecture/guardrails.yaml's audit_writer package boundary
// allows only internal/audit to do that) — see the same doc comments for
// what the lead must audit around calls into this package.
package proposer
