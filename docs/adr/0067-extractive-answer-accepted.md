# ADR-0067: Extractive answer contract (R-1 through R-6)

Status: accepted.

This ADR applies the owner's extractive-answer decision to the answer-manifest
and contract boundaries. It prepares the Question Run contract; it does not
activate the Question Run, search, a model runtime, or a user-facing answer
surface at the current coordinate.

## 1. Decision

1. Retrieval remains the hybrid pipeline already specified by the architecture.
   The answer contract does not replace authorization, candidate-set binding,
   or the retrieval snapshot with a text search shortcut.
2. Generator and semantic-verifier components remain mechanically forbidden in
   `EXTRACTIVE` mode. Their profiles and model runs are permitted only in the
   separately gated `GENERATIVE` mode, which is not active in the pilot.
3. An extractive claim is a deterministic projection of one signed,
   organization-scoped, authorized context snapshot. The server, not a model,
   selects the claim and its citation.
4. A published extractive claim's UTF-8 bytes are byte-equal to the UTF-8 bytes
   of exactly one cited sentence. Canonical text normalization is applied before
   the comparison; no paraphrase is accepted.
5. `answer_mode` is a signed top-level manifest property. `EXTRACTIVE` requires
   `BYTE_EXACT_CITATION`; `GENERATIVE` requires `SEMANTIC_VERIFIER`.
6. The citation unit is one sentence, contains no line break, and is at most
   2000 UTF-8 bytes. A future extraction profile may raise the operational
   limit, but no profile may weaken the schema's bound.

## 2. Mechanical contract

`architecture/contracts/answer-manifest.schema.json` is version `2.0` and
requires both `answer_mode` and `verification_method`. Conditional schema rules
require generation and verification profiles for `GENERATIVE` and reject those
profiles, runs, and claim-verification records in `EXTRACTIVE` mode.

The executable contract layer owns the same distinction: it validates the signed
mode/method pair, derives extractive claims only from the authorized context
projection, requires one symmetric citation per factual claim, and compares
claim and citation bytes. The existing numeric, anchor, encryption, renderer,
source, parser, and trust contracts remain unchanged.

## 3. Consequences

The manifest can no longer describe a generative-looking answer while claiming
an extractive proof method. A future generative implementation must pass its
own model/AIBOM/license and phase gates; this ADR is not an activation flag.
The contract fixtures exercise both the positive mode binding and the negative
generator/verifier boundary.

## 4. Acceptance evidence

- the versioned manifest schema and its strict schema suite;
- canonicalization and contract-validation rules for mode-scoped verification;
- `EXA-*` critical guardrails and their registered negative cases;
- the independent review required by the delivery protocol.
