# Pilot acceptance

The pilot lets an external MCP agent find and read permitted documents and
prepared PostgreSQL records, with retained source addresses and an audit trail.
Use this checklist with an agreed dataset and control questions before a customer
evaluation. Current release capabilities and measured limits are in
[Pilot status](PILOT-STATUS.md).

## Functional checks

| ID | Workflow | Acceptance condition |
| --- | --- | --- |
| F1 | Documents | Connect an approved folder, synchronize supported readable files, find relevant passages, and read the complete retained text. Unsupported or failed inputs appear as visible skips; they are not silently counted as successfully ingested. |
| F2 | SQL records | Connect a prepared PostgreSQL view with stable entity identity, source version, modification time and typed payload. Find and read known records, compare values with the source, and inspect their provenance and field addresses. |
| F3 | External MCP | Use an independent MCP client for document and SQL questions. Include ordinary wording, typos, ambiguous questions and unsupported premises. Answers must have relevant supporting sources; a returned address alone does not establish correctness. |
| F4 | Versions and updates | After synchronization, changed data is discoverable and its address identifies the new version. A retained older address still identifies the original bytes when current access and retention allow reading them. Unchanged synchronization creates no duplicate versions. |
| F5 | Access and audit | An authorized user or service can read its data. Another workspace or revoked credential cannot read the same known address. Successful and denied actions are attributable in the authorized audit view; an unauthorized user cannot read that journal. |
| F6 | Web search | A user can submit an independent question, inspect sources, open a separate evidence page and return to results. Search and reading work without a model answer. Configured model selection is honored; built-in answers remain preliminary. |
| F7 | Delivery | Record the tested source revision, component identities, prerequisites and startup steps. A new client can follow the connection instructions. Report remaining installation and operational limitations explicitly. |

## Source lifecycle checks

Exercise documents and SQL entities separately:

1. Synchronize content A, change it to B, then restore A. Verify the current
   result and the retained addresses after each observation.
2. Remove a known entity during a complete, authoritative observation. Confirm
   that its previous address is no longer readable while the entity is absent.
3. Restore the permitted entity and check its content, version metadata and
   successful repeated synchronization. Restoration must not bypass revoked
   access, retention restrictions or final deletion.
4. Cause an incomplete scan or malformed update. Inspect freshness and skips;
   a successful task status alone must not imply that retained data is fresh.
5. Search for a retained older version and read it back. Preserve any partial
   coverage indicator; one historical hit does not prove exhaustive retrieval.

## Record the result

Freeze the questions, expected facts, source versions and evaluation rules
before running the comparison. Separate retrieval/read correctness from the
agent's interpretation. Include dates, numbers, units, null values, exact
citations and negative authorization cases. Never derive a total from only the
top search results or ingest the expected-answer oracle as source material.

Keep failed runs and evaluation corrections. Rescoring saved answers is not a
new live run. A result does not establish acceptance for another dataset or
later build. Store source-bearing logs and deployment receipts privately.

OCR/VLM, Excel analysis, arbitrary SQL analytics, a broad connector catalog,
long-running chat, a turnkey offline installer and company-wide scale are outside
this pilot's guarantee. This checklist preserves the pilot boundary; it does not
introduce a full production-readiness claim.

Start with [Getting started](GETTING_STARTED.md), [SQL snapshots](SQL-SNAPSHOTS.md)
and the [MCP client guide](MCP-CLIENT-GUIDE.md). The
[synthetic company-month fixture](../tools/seeds/company-month/README.md) can
support repeatable checks without using customer data.
