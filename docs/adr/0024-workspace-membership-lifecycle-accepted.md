# ADR-0024: Workspace membership lifecycle

Status: accepted.

Workspace role changes and removals are immutable revision commands. A role
change closes the active `workspace_member` interval by setting
`valid_to_revision` to revision `n+1` and
inserts a replacement row beginning at the same revision. Removal closes the
interval without inserting a replacement. Neither operation updates or deletes
historical membership rows.

The current OWNER cannot be removed, assigned another role or replaced through
the ordinary member commands. Ownership transfer is an explicit owner-only
command: a MANAGER may maintain non-owner memberships but cannot seize the
workspace. The target must already be an ACTIVE principal and an active member
of the same workspace.

Transfer locks the canonical current snapshot, closes both the previous owner
and target membership intervals, inserts the previous owner as MANAGER and the
target as OWNER, advances `owner_principal_id`, writes revision `n+1` and
appends `workspace.role_changed`. All changes share one `database.Write`
transaction. The deferred sole-owner database constraint is the final gate
against a torn or ambiguous owner state.

The PostgreSQL acceptance test verifies every membership interval, exactly one
active OWNER, manager denial for ownership transfer, current revision and the
denied audit event. The pure workspace tests independently reject owner removal,
owner role mutation and transfer to an absent member.
