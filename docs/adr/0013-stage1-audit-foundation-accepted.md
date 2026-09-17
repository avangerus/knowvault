# ADR-0013: Stage 1 audit foundation

Status: accepted.

The first audit slice is a tenant-scoped, append-only event chain in
PostgreSQL. It is deliberately smaller than the Stage 6 checkpoint system:
there are no signing keys, external sinks, checkpoint jobs or content-bearing
payloads in this slice.

- `audit_event` stores only the strict `audit-event-v1` projection: identity,
  action, resource, outcome, safe metadata and hashes; it has no prompt,
  answer, source text, credential, path or free-text field;
- every event is derived by `internal/audit` from typed input. The application
  cannot supply an event hash, a sequence or a previous hash;
- JSON is canonicalized with the accepted Go `jsontext` JCS implementation and
  event hash is SHA-256 of the exact canonical body without `event_hash`;
- PostgreSQL serializes the per-organization chain, checks the expected
  `(sequence, previous_event_hash)`, and rejects `UPDATE` and `DELETE` at both
  privilege and trigger layers;
- a transient chain race returns serialization failure. A bounded transaction retry
  replays the whole tenant-scoped transaction at most three times; it
  never retries an arbitrary database failure.

The runtime `knowvault_app` role may insert audit events but cannot update or
delete them. It has a narrow trigger-mediated grant on `audit_chain_head` only
because the database must update that head atomically with each event. A direct
mutation is rejected by the trigger.

This foundation is not proof against a privileged database operator. Stage 6
adds signed contiguous checkpoints and an external append-only receipt before
production audit readiness can be claimed.
