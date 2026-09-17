# Pilot status

Status: **MCP pilot; built-in model answers are preliminary.**
This public snapshot is dated September 16, 2026.
The [pilot release](https://github.com/avangerus/knowvault/releases/tag/v0.1.0-pilot.1)
describes the initial release scope.

KnowVault is an open-source enterprise knowledge platform for AI agents. The
pilot helps an employee use their preferred agent to find and read company
documents and prepared PostgreSQL data, with workspace permissions, source
addresses, and audit. Its web application, identity integration, access controls,
and connectors are implemented. Deployment is operator-assisted.

## Available workflows

| Area | Current scope |
| --- | --- |
| Documents | Approved server folders; Markdown/plain text and supported DOCX/text-PDF extraction without OCR. |
| PostgreSQL | Prepared views become versioned entity snapshots with typed values, timestamps, and provenance. |
| External agents | Workspace-scoped HTTP MCP, expiring and revocable service access codes, search, inventory, and complete paginated reads. |
| Evidence | Retained version addresses, readable source pages, byte-level evidence metadata, and authorization checks at read time. |
| Source lifecycle | Synchronization status, visible skips, and recovery when an observed file or SQL entity disappears and returns. |
| Identity and access | Keycloak/OIDC sign-in, organizations and workspace membership, service identities, and revocable agent credentials. |
| Audit | Attribution to users or service identities on data-access paths, plus administrative actions and a web audit journal. |
| Web interface | Independent search questions, source inspection, and optional answers from configured available models. |

Keyword and semantic retrieval are implemented. Their presence does not establish
retrieval quality for every domain or completeness of a broad result set.
Workspace authorization is implemented; automatic inheritance of permissions
from every upstream enterprise application is not a pilot claim. The pilot
connector scope is folders and prepared PostgreSQL views, rather than a broad
catalog of packaged enterprise integrations.

## What has been measured

Controlled tests have exercised file and SQL-entity disappearance and return,
unchanged-content synchronization, historical source reads, authorization
denials, service-code revocation, and audit attribution.

Recent live lifecycle checks included:

- A SQL source with **40 → 39 → 40** entities: the missing entity's old address
  was inaccessible during absence, and restoration returned the same retained
  version and bytes. A repeat synchronization created no extra versions.
- An exact older document version found through REST and MCP and read back as
  **139 matching bytes**. The historical result reported partial coverage;
  this proves the retained hit, not exhaustive historical retrieval.
- A malformed document update marked the still-readable older data as stale.
  Restoring the original document returned the source to fresh status without
  creating a duplicate version.

These are bounded checks against synthetic data. They do not verify every
document format, source policy, or customer dataset, and they are not a full
acceptance rerun on every later server revision.

## Known limitations

- **Answer quality:** a recent broad-list model answer returned readable citations
  but omitted material conditions. Citation validity does not prove that an
  answer is complete or correct. Check important claims against the source.
- **Coverage:** partial search results and the end of a result page do not prove
  that no other relevant records exist. Full historical-search coverage remains
  unproven.
- **SQL lookup:** business identifiers should also be included in the payload.
  Exact lookup by the service identity field is not a separate pilot tool.
- **Installation:** the development bootstrap is not yet a qualified turnkey
  distribution of the deployed pilot. A complete host-reboot recovery test and
  a production offline bundle are not claimed.
- **Scale:** company-wide performance at millions of files has not been
  established by the pilot checks.

OCR/VLM, Excel analysis, arbitrary SQL analytics, long-running conversations,
and general-purpose knowledge graphs are outside the current pilot scope.
Existing code or design documents for those directions do not make them release
commitments.

## Evaluate it on your work

Connect a small approved document collection and a prepared SQL view. Try actual
employee questions, including typos and ambiguous wording. Read the citations,
change a source record, and test a user or agent without permission. Record
retrieval failures separately from a model's interpretation errors.

Start with [Getting started](GETTING_STARTED.md),
[SQL snapshots](SQL-SNAPSHOTS.md), and [MCP access codes](MCP_ACCESS_CODE.md).
Report reproducible issues through the
[issue templates](https://github.com/avangerus/knowvault/issues/new/choose).
