# Contract fixture suite

This directory is the executable acceptance input for the four normative JSON
schemas and for the cross-field rules in `docs/CONTRACT_VALIDATION.md`.

The fixtures are split by intent:

- `fixtures/valid` contains direct schema instances or valid state-machine scenarios;
- `fixtures/invalid` contains one intentional fault per file;
- `fixtures/golden` contains canonical UTF-8/JCS vectors and deterministic Ed25519 signature vectors.

`fixtures/golden/answer-renderer-v1.json` is byte-exact: its Markdown, UTF-8
length, UTF-8 hex, claim byte spans and SHA-256 must all match. The claim spans
cover escaped claim text only; they exclude server prefixes and citation
markers. `answer-renderer-v1-metacharacters.json` additionally proves that
model-supplied Markdown-like text is accepted but rendered inert; metacharacters
are not a model validation error.

`fixture-cases.json` is the source of truth for the expected result. A runner
must assert the exact `expected_error_code`; checking only that validation
failed is insufficient.

## Validation order

1. Strict I-JSON decoding. Duplicate member names, invalid UTF-8 and non-finite
   numbers are rejected before schema validation; a parser that silently keeps
   the last duplicate member is not sufficient.
2. JSON Schema, with Draft 2020-12 formats enabled and all `$ref` documents
   pre-registered locally.
3. Canonicalization and hash calculation.
4. Signature verification and replay protection where applicable.
5. Semantic validation.
6. Data-model/state-machine validation for multi-object scenarios.

`signature-envelope-ed25519.json` fixes the exact signing boundaries and verifies
real deterministic Ed25519 signatures. A
manifest hashes `JCS(manifest minus manifest_hash and signature)` and signs only
the four-field manifest envelope shown there. A connector event hashes
`JCS(event minus integrity)` and signs only the ten-field connector envelope.
Neither signature is computed directly over the original content object.

The test clock is supplied by each case that depends on expiry. Tests must not
read the wall clock for those cases.

## Error-code ownership

The codes in `fixture-cases.json` form part of the contract-test surface. If an
implementation needs a different code, the fixture and the implementation are
changed together only after architectural review; silently accepting a broad
generic error is not compliant.
