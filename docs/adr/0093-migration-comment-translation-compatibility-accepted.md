# ADR-0093: Exact checksum compatibility for translated migration comments

Status: accepted by the owner on 2026-09-16 for the English publication.
Deployment status and release scope remain in [PLAN.md](../release/PLAN.md).

## Context

Six previously applied migrations contain source-language comments. Publishing
English comments changes the file checksums even though the SQL is identical.
The migration ledger normally rejects any checksum change. The owner approved
this limited exception after being offered an unchanged-migration alternative.

Original source bytes and the original Git history are retained in a private
archive outside the published repository. This decision does not grant general
permission to edit applied migrations.

## Decision

The operator accepts ordinary checksum equality. It also accepts exactly six
directional triples: the migration filename, its recorded legacy SHA-256, and
the SHA-256 of its reviewed English-comment revision. The complete triples are
fixed in [migration_checksum.go](../../internal/operator/migration_checksum.go).

The allowed files are:

- `000077_stage2_evidence_fragment_readable_per_scope.sql`
- `000078_stage3_governed_query_workspace_binding.sql`
- `000080_stage3_conversation_continuation_revision_tolerant.sql`
- `000082_stage3_structured_snapshot_status_role.sql`
- `000083_stage3_structured_source_scope_names.sql`
- `000094_stage3_metric_definitions.sql`

All non-comment bytes are unchanged. Both migration application and readiness
use the same predicate. An existing ledger retains its checksum and application
timestamp. The operator does not replay SQL or rewrite the ledger. A fresh
installation records the checksum of the current file as usual.

An unknown filename, a reversed pair, hashes taken from different entries, or
any further file edit is rejected. Compatibility is not based on stripping
comments or normalizing SQL at runtime. Future changes require a new additive
migration; this list must not grow as a workaround for checksum failures.

## Verification

Unit tests exercise the six accepted pairs, normal equality, and negative
cases. An isolated PostgreSQL test applies a fresh schema, checks current
checksums, models an existing legacy ledger, reruns the operator, verifies
unchanged ledger values and readiness, and rejects SQL tampering.

The publication verification also compares every non-comment byte with the
archived originals. This compatibility does not change schema permissions,
tenant isolation, source data, or migration SQL.

## Operational consequence

Use the updated operator when checking the English migration directory against
an existing installation. An older operator still rejects the translated files;
the exception does not retroactively alter old binaries. Preserve the matching
operator and migration directory together in deployment and rollback artifacts.
