# ADR-0100 — Files stay in the company's folder; KnowVault keeps only encrypted search text

**Status:** proposed

**Date:** 2026-09-26

**Owners:** product owner (decision), lead engineer

**Related:** backlog R1.S10.s1.T3; ADR-0002 (storage), ADR-0062 (parser sandbox); `internal/ingestion/pipeline.go`; migrations 000005, 000014, 000027, 000043, 000046

## Context

The owner's rule for the first release (26.09): users never upload files to
KnowVault and never download files from it. A workspace is connected to a
working folder the company already uses; KnowVault follows that folder and
answers in chat. It should keep only what search and evidence need, not the
files. The open question was whether evidence could even be "dynamic", read
from the folder at answer time, with no stored text at all.

What ingestion stores today (verified in code):

- no original file bytes and no whole converted document;
- per fragment, sealed in `encrypted_artifact` (AES-256-GCM, per-row key):
  normalized text, anchor, metadata (`pipeline.go` around 1096–1104);
- per object: title, canonical locator, external id, also sealed (483–489);
- a lexical search projection (`search_chunk`) and optional embeddings;
  tables hold only artifact ids and hashes, never plaintext.

## Decision (recommended)

1. KnowVault never stores an original file or a whole converted document.
   The unit of storage is the evidence fragment: a section-sized piece of
   the converted markdown, sealed as today.
2. The fragment text is kept, encrypted, because three things need it:
   lexical search (numbers, contract codes, names that vectors miss), the
   exact quote shown next to a citation, and the check that a cited quote
   really is in the source.
3. A file's outline (its section headings) and its short index (the first
   line of each section) are derived when they are read, from the fragments
   already stored, with no model call and no new stored record. They feed the
   workspace data map. If a model-written summary is added later, it uses the
   same model channel as answers, so on the test stand the text goes to the
   cloud model, which is acceptable for test data only.
4. The folder stays the source of truth. A file changed in the folder gets a
   new version at the next scheduled ingest; a file removed from the folder has
   its fragments, outline, index, search chunks and embeddings purged at that
   ingest. Every answer states the ingest date of the data it used.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Dynamic evidence: store nothing, read the folder at answer time | Search still needs an index built from the text, so the text's sensitivity does not go away. Every answer would need live folder access and full re-parsing, which is slow for big office files. A quote could disappear or change between search and display, breaking citations. |
| Vectors only, no text | No exact search for numbers and codes, no quotable evidence, no citation check. Embeddings can be partly inverted, so the data is not actually kept out. |
| Store original files | The owner ruled it out, and it adds a copy of company files with no benefit over encrypted fragments. |

## Consequences

### Positive

- Matches the owner's rule without losing exact search or checkable citations.
- No schema change. The outline and index are derived at read time; the only
  new obligation is purging a removed file's data.

### Negative / trade-offs

- Encrypted fragment text is still a copy of the content, bounded by what
  was converted, and it goes when the file leaves the folder.
- Freshness depends on the ingest schedule, so answers must show the date.

### Security and failure semantics

- Keys and artifact sealing stay exactly as today. The outline and index are
  served through the same authorized, audited whole-document read as the text.
- If the folder is unreachable at ingest, the previous version stays and
  answers keep its date. If a file cannot be parsed, it is quarantined as
  today, and nothing partial is published.
- Before acceptance, purge-on-removal must be proven by an integration test:
  remove a file, ingest, and confirm no fragment, chunk or embedding of it
  remains readable.
