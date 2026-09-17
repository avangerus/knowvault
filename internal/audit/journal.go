// Journal read projections for the bounded audit-journal surface. Every value
// is a server-persisted audit-event-v1 field; the canonical body bytes and any
// other internal chain material are deliberately absent. Journal itself is a
// data-transfer value, not the wire shape: workspaceapi projects it into
// auditJournalResponse, which owns the JSON tags and field filtering.
package audit

import "time"

// Journal is one workspace-scoped page of the audit stream (including closed
// content-read denials whose resource ID names that workspace) plus the
// organization chain head. The head belongs to the organization, not to the
// workspace, and is included so a reader can verify event linkage against the
// authoritative append state. WorkspaceID is the server-resolved workspace
// the page was read from, not a transport value echoed back.
type Journal struct {
	WorkspaceID  string
	HeadSequence int64
	HeadHash     string
	Events       []JournalEntry
	// Truncated is true when the workspace stream held more than one page, so
	// this page ends above the stream's oldest event. The repository computes
	// it from the page boundary; the surface projects it verbatim.
	Truncated bool
	// NextBeforeSequence is the keyset cursor for the next older page. It is
	// set only when Truncated is true and always equals the sequence of the
	// last entry actually returned, so a continuation read can pass it back as
	// before_sequence. It stays nil on an empty tail or a complete page: an
	// absent cursor is the only signal a client needs to stop asking. The
	// cursor is an int64 in the domain layer and is projected to a decimal
	// string on the wire so it never loses precision as a JS Number.
	NextBeforeSequence *int64
}

// JournalEntry is the content-free surface projection of one persisted event.
// Actor, resource, request and evidence identifiers are server-owned opaque
// IDs; metadata carries only the closed allowlisted keys enforced by the
// audit_metadata_is_allowed schema constraint.
type JournalEntry struct {
	EventID               string       `json:"event_id"`
	Sequence              int64        `json:"sequence"`
	Action                Action       `json:"action"`
	ResourceType          ResourceType `json:"resource_type"`
	ResourceID            string       `json:"resource_id"`
	ActorType             ActorType    `json:"actor_type"`
	ActorPrincipalID      *string      `json:"actor_principal_id,omitempty"`
	OnBehalfOfPrincipalID *string      `json:"on_behalf_of_principal_id,omitempty"`
	RequestID             string       `json:"request_id"`
	PolicyDecisionID      *string      `json:"policy_decision_id,omitempty"`
	Outcome               Outcome      `json:"outcome"`
	ErrorCode             *string      `json:"error_code,omitempty"`
	ReferencedEvidenceIDs []string     `json:"referenced_evidence_ids"`
	Metadata              Metadata     `json:"metadata"`
	PreviousEventHash     string       `json:"previous_event_hash"`
	EventHash             string       `json:"event_hash"`
	OccurredAt            time.Time    `json:"occurred_at"`
}
