# ADR-0007: Canonical contracts and a safe renderer

Status: `ACCEPTED`

## Solution

Offsets are measured in bytes of canonical UTF-8 text and use half-open ranges. JSON hashes/signatures use RFC 8785 JCS and two-stage envelopes, where the signature covers the hash, key metadata, time, and replay nonce. Generator output contains only claims/sections without self-declared terminal status, verifier output has a separate strict schema, and the final status and document are built by deterministic server validators/renderer via their own AST without parsing model text as Markdown/HTML.

Full NFC normalization `text-v1` is performed by the fixed `golang.org/x/text/unicode/norm`; a partial table of known combining sequences is not an acceptable implementation.

SourceObject is linked to overlapping scopes via M:N membership and does not duplicate evidence/vectors.

## Why

Without a single canonization, quotes and hashes diverge between Go, browser, Windows, and Linux. Free model prose after verification allows adding an unverified fact. Scope ownership within SourceObject duplicates one object when scopes intersect.

## Consequences

Contracts are accompanied by Unicode, overlap, verifier-TOCTOU, tamper, and rendering negative fixtures. ClaimVerification binds the exact claim text/evidence/support input with the canonical verifier output and selected ModelRun; after verifier claim cannot be replaced by the same ID. Go implementation uses the standard experimental `encoding/json/jsontext.Value.Canonicalize` from pinned Go 1.26.5; all builds pin `GOEXPERIMENT=jsonv2`, no separate JCS dependency is added. The exact toolchain makes bytes reproducible, and upgrade/refusal of experiment requires ADR and full golden regression. Duplicate names, invalid UTF-8, and numbers outside I-JSON safe range are rejected. Changing normalization version or offset unit requires a new ADR and re-index plan.
