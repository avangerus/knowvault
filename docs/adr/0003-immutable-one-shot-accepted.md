# ADR-0003: Independent immutable Question Run

Status: `ACCEPTED`

## Solution

Each submission creates a new Question Run. It does not receive the context of previous runs. After terminal status, the question, answer, claims, citations, and manifest are logically immutable for the application role: they cannot be corrected or rewritten as a new version of the same result.

Immutability does not mean indefinite retention or right to disclosure. The accepted retention purge from `IMM-004` is executed only by a separate privileged role, irreversibly removes content-bearing fields and canonical manifest content, leaves a tombstone, hashes/signature metadata, and full audit. Purge is not an UPDATE to the answer and cannot restore or replace its content.

Results are displayed under a single search surface; there is no separate chat model or "Answers" section.

## Why

- clear access area and reproducibility;
- absence of hidden memory;
- safe display of the state of old sources;
- a single entity for user result and machine manifest.

## Consequences

`Run again` creates a new ID. Changing the source only changes the computed freshness state of old citations. Retention purge changes the disclosure state to `PURGED` and never creates new text.
