# ADR-0004: Derived data without persistent source binaries

Status: `ACCEPTED`

## Solution

The original binaries are not stored in the product's persistent storage. They can be read in the ephemeral processing area and are deleted after extraction.

The system stores derived normalized fragments, search chunks, embeddings, metadata, anchors, hashes, and cited excerpts.

## Why

Without derivative text, hybrid retrieval, generation, and citation verification are impossible. Storing the full source binary as a proprietary archive is not required for the product.

## Consequences

- the administrator is honestly shown the composition of derived data;
- ephemeral storage is excluded from backup;
- rebuild may require re-reading the source;
- legal retention cited excerpt is determined by a separate policy.

