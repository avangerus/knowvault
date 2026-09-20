# Product north star and release path

## Product north star

**An authorized employee asks a simple or complex question about the company in
a chat or through MCP and receives a concise, complete and verifiable answer
from all current connected company data they are allowed to use. KnowVault
discovers the relevant sources, builds and executes a bounded multi-step plan,
reconciles the facts, explains uncertainty and attaches inspectable evidence without giving a
model or caller unrestricted access to the underlying systems.**

Every part of that statement is a product contract:

| Term | Required product behavior |
| --- | --- |
| Authorized employee | Identity, workspace membership and source ACLs are enforced at every retrieval and tool call, including follow-up turns. |
| Asks | The primary input is ordinary language. Users describe the business outcome; they do not select SQL, tables or a fixed report. |
| Chat | A session keeps useful context, supports follow-up questions and clarification, and shows tool progress without forcing the user to understand the implementation. The same capability is available to external agents through MCP. |
| Simple or complex | The system handles direct lookup as well as decomposition, time comparison, aggregation, joins, reconciliation, anomaly analysis and multi-source questions. |
| Question about the company | The vocabulary is the organization's vocabulary: contracts, customers, operations, incidents, routes, vehicles, documents and other governed entities, rather than database identifiers. |
| All current company data | Documents and structured systems participate through connectors and typed source profiles. Freshness and observed time are explicit; unavailable or stale sources are never silently treated as current. |
| Allowed to use | Retrieval, computation and answer synthesis preserve source permissions. Hidden data cannot influence an answer, citation, count or suggested follow-up. |
| Concise, complete answer | The response leads with the business conclusion, includes the decisive facts and calculations, and expands when the question requires detail. A raw result table is evidence, not the answer. |
| Verifiable | Every material claim maps to a document fragment, source record or signed execution receipt with source identity, observation time and reproducible inputs. |
| Multi-step plan | KnowVault may inspect metadata, search, read, aggregate, compare and re-query. The plan is bounded, observable and interruptible. |
| Bounded access | Models propose typed intents over administrator-approved semantic profiles. Server code validates and compiles them to parameterized reads. Models and callers never receive a general SQL execution surface. |
| Explains uncertainty | Ambiguity, missing coverage, stale data, conflicts and failed tools are stated in the answer. Clarification is requested only when it materially changes the result. |

The interaction reference is [Gordon in Docker Desktop](https://docs.docker.com/ai/gordon/):
an assistant embedded in the product, aware of the user's current context, able
to select and use tools, maintain a conversation, and explain actions and
failures.
KnowVault applies that interaction model to governed company knowledge. Its
additional contract is claim-level evidence, inherited enterprise permissions,
durable audit and fully local operation when required.

The business outcome is measured as time from a real employee question to a
correct, decision-ready answer with usable evidence. Connector count, indexed
chunk count, preset count, model benchmark scores and generated SQL are
supporting measures; none is the product result.

## Read-only product boundary

The current product is strictly read-only. KnowVault may discover metadata,
search, read, aggregate, compare and explain data. It must not create, update or
delete source records; run customer business commands; trigger workflows;
approve transactions; or modify files, databases, tickets, messages or source
permissions. This boundary applies to the browser, API, MCP, models, internal
tools and administrator-configured connectors. User confirmation does not make
a write operation admissible.

Every structured connector uses a dedicated read-only identity and a
read-only transaction. Every document connector ingests through a read-only
source capability. Tool schemas expose no mutation operation. Acceptance must
prove that unsupported write requests are refused before reaching a source and
that the refusal is attributable in the audit journal. Any future write-back
capability requires a separate owner decision, threat model, product contract
and release plan; it is not an extension of the current chat session.

## Release path to the north star

| Milestone | User-visible truth | Acceptance |
| --- | --- | --- |
| R0 — Controlled access baseline | The deployed system can securely search documents and execute reviewed live database reads with rights, audit and receipts. | Existing document and Cicada D0-D4 evidence. This is a diagnostic baseline, not the north-star product. |
| R1 — First real data conversation | In chat, a user asks varied natural-language questions over one approved structured domain, including follow-ups, periods, grouping, comparisons and anomaly questions. KnowVault plans the read, returns a written answer and exposes its calculation and receipt. No question is matched to a fixed SQL preset. | A domain-independent stress suite with paraphrases, informal questions, ambiguity, inaccessible fields, stale data and adversarial inputs; answers checked against direct controls. |
| R2 — Cross-source reasoning | One conversation can combine structured data and documents, follow links between entities and answer a question that requires more than one retrieval or calculation step. | Claim-level source coverage, rights tests for every step, replayable plan and failure/partial-answer behavior. |
| R3 — Enterprise pilot | Administrators can connect and profile the customer's required sources; users receive the same behavior through the web chat and MCP. | Customer question set, permission matrix, audit review, freshness SLOs, scale and operational handoff. |

R1 is governed by [ADR-0096](../adr/0096-read-only-conversational-analytics-authority-accepted.md).
Each follow-up is a new authorized Question Run, typed analytics replaces
model-authored SQL, browser and MCP share one server authority, and all source
operations remain strictly read-only.

### R1 nested delivery cycles

Only the first incomplete capability is active. Every capability is delivered
as small DSH cards, normally one concern, no more than three production files,
focused tests and an explicit stop condition. The release lead accepts a card
only from its diff and measured behavior; a completed model turn is not
acceptance. Luna maintains dependency order and acceptance evidence. Astra is
the independent critic for architecture, authorization, evidence and any branch
scored 9/10 or 10/10 in complexity.

| Cycle | User-visible truth | Acceptance gate | Status |
| --- | --- | --- | --- |
| R1.0 — One authority | Browser and MCP enter the same admitted, authorized Question Run and see the same terminal semantics. | Durable admission before reads; equivalent identity/scope tests; revocation before disclosure; no second execution path. | Active after ADR-0096 |
| R1.1 — Trusted profile | One approved dataset exposes human terms, grain, keys, types, units, NULL/time semantics, allowed operations and an immutable revision/hash. | Invalid, drifting or retired profiles fail closed; counts and duplicate policy match direct controls. | Queued |
| R1.2 — Closed intent | Varied ordinary-language questions become a typed lookup/filter/group/aggregate intent without SQL. | Closed schemas; unknown fields/operators/relations refused; plan binds exact profile and catalog hashes. | Queued |
| R1.3 — Deterministic read | Server compiles the intent to a bounded parameterized read and returns a typed numeric or row result. | Read-only transaction; identifier allowlist; row/byte/time budgets; decimals, NULLs, periods, truncation and errors verified. | Queued |
| R1.4 — Verifiable answer | The user receives a concise answer whose numbers cannot differ from the deterministic result and whose limits are visible. | Completeness gates totals/absence; receipt binds inputs, coverage and digest; retained evidence and live observation are labelled separately. | Queued |
| R1.5 — Bounded follow-up | A user can refine period, entity or grouping without repeating context, while every turn remains independently authorized. | Context/depth budget; inherited references resolved into the new plan; previous answers are not evidence; revocation tests pass. | Queued |
| R1.6 — Unseen GM demo | Unseen direct, aggregate, comparison, anomaly, informal and unsupported GM questions work through browser and MCP. | Owner-reviewed 24-question suite, at least 90% correct answerable cases, 100% correct refuse/clarify and zero unauthorized disclosure. | Queued |

Promotion is one-way only after its gate passes. A failed card is split before a
second implementation attempt. Two failed revisions, an unplanned branch over
four hours, or a 9/10–10/10 complexity estimate returns the decision to the
release lead and owner rather than widening the implementation.

R1 starts with the accessible GM contract/container and KPI projections because
they provide real data and direct controls. Vehicle, route and raw removal
questions enter acceptance only after read-only semantic projections for those
entities are available. Adding fixed question-to-SQL bindings does not advance
R1. Existing presets remain release diagnostics and break-glass controls.

R1 uses two complementary evidence paths. Versioned entity snapshots support
exact source pages, relationships and record-level drill-down. Typed analytics
support bounded counts, trends, grouping and comparisons that cannot be made
reliable by retrieving a sample of rows. A model chooses only profile, measure,
dimensions, typed filters and period; server code validates that intent and
compiles a parameterized read from registry-owned identifiers. The written
answer cites snapshot evidence where available and always links the immutable
analytic run receipt for calculated claims.

The first R1 acceptance set contains 24 owner-reviewed questions: 14 factual or
synthesis questions including informal wording and typos, four questions that
require both structured data and documents, three follow-up turns and three
ambiguous or unsupported questions. At least 90% of answerable cases must be
correct, every material claim must carry readable evidence, all unsupported
cases must clarify or refuse correctly, and unauthorized identities must learn
zero facts or metadata. At least six cases must complete two or more knowledge
tool calls without operator intervention. Browser and MCP must agree on facts
and sources; every question, model call, tool call and read is attributable in
the audit journal. Initial performance targets are visible activity within two
seconds, median completion within 30 seconds and p95 within 90 seconds on the
qualified pilot hardware.

## Current proven baseline

KnowVault's current release is an **operator-assisted MCP pilot**. It connects
approved document folders and prepared PostgreSQL views to authorized search,
complete source reads and inspectable evidence pages.

### Cicada controlled-query demonstration

The immediate release outcome is a complete demonstration in the customer
pilot environment: an authorized owner opens KnowVault in a browser, chooses
or enters one of four approved ordinary-language questions from the preset
catalogue, receives a short inspectable result over the approved live views,
and can see when and where the data was read. An external MCP agent can obtain
the same live fact. The run is attributable in the audit journal, while another
workspace, a revoked credential and any caller-supplied SQL receive no data.

This outcome, rather than component count or test count, controls the critical
path. Work is delivered through the following gates in order:

| Gate | User-visible result | Acceptance evidence | Owner |
| --- | --- | --- | --- |
| D0 — Connected | The pilot environment runs the recorded KnowVault image and can read the two approved views through the dedicated role. | Image revision, TLS `verify-full`, read-only grants, row-count controls and rollback receipt. | Release lead |
| D1 — Reviewed facts | Four accepted business questions execute once through the governed model path, are reviewed against frozen direct control queries, and become versioned reviewed preset bindings. | First-attempt strict model qualification; exact columns, nulls, decimal text and every returned value checked at the reported execution time; attempt, SQL and schema hashes. | DSH implementation; release lead acceptance |
| D2 — Closed MCP demo | An external agent lists and runs the four presets. Ad-hoc and caller-supplied SQL are absent in `PRESET_ONLY`. | All [governed SQL preset checks](../PILOT-ACCEPTANCE.md#governed-sql-preset-checks) 1–5, including human and SERVICE parity, live receipts, pre-service input denial, authorization and configuration denials, hash mismatch and authorized audit. | DSH implementation; independent security review; release lead acceptance |
| D3 — Browser demo | The same four approved questions can be selected or matched by exact phrase in the web interface and show a compact live result with source identity, freshness and execution receipt. | Browser walkthrough in the pilot environment, reload/back behavior, empty/error states and audit attribution. | DSH implementation; UI review; release lead acceptance and deployment |
| D4 — Handoff | A second operator can start, verify, demonstrate and roll back the recorded release. | GitHub required checks, deployment runbook, demo script, component identities and rollback drill. | Release lead; second-operator acceptance |

Current gate status and forecast, measured from an approved D1 start:

| Gate | Status on 19 September 2026 | Remaining work | Forecast |
| --- | --- | --- | --- |
| D0 | Complete | Preserve the recorded image and private deployment receipt. | Done |
| D1 | Complete | Exact configured local Qwen profile passed first-attempt 4/4 and repeated 20/20 strict structured-output qualification. | Done |
| D2 | Complete | Four reviewed bindings active in `PRESET_ONLY`; human/SERVICE MCP 8/8, denials 6/6, revoked credential 401, authorization/audit verified. | Done |
| D3 | Complete | Browser ran all four live checks with source identity, execution window and receipt; refresh did not rerun, evidence back preserved results, implicit catalogue discovery 4/4 and explicit mismatch denied. | Done |
| D4 | Acceptance complete; green release-head checks required | GitHub branch protection verifies the exact release head. | Automated gate |

Only one gate-changing implementation slice is active at a time. DSH receives
small contracts covering configuration, adapter behavior, qualification,
preset activation and UI in that order. Each slice must produce its focused
test evidence before the release lead accepts it and opens the next slice.
Independent reviewers inspect security or UI boundaries after implementation;
documentation, CI and runbook preparation may proceed in parallel, but no
parallel product path is created. A failed qualification closes the gate and
returns the decision to the release lead instead of weakening the parser,
evidence contract or access controls.

The work model is explicit. The release lead owns architecture, scope, task
contracts, acceptance and deployment. DSH (`deepseek-flash`) is the primary
implementation worker and receives bounded changes with focused tests. Small
independent agents inspect code paths and review security, UI and CI; they do
not duplicate the implementation worker. Heavy builds and test workloads run
on the remote build worker. The pilot environment receives only a committed,
reviewed image and is used for live acceptance, not development.

The explicit, mounted structured-output capability on the exact configured
Qwen profile was accepted and measured as described in the status table above:
first-attempt 4/4 followed by repeated 20/20 strict structured-output
qualification, with no implicit fallback and unchanged strict ClaimPlan and SQL
validation. Prompt shortening and manual insertion of governed attempts were
not release paths.

D2 delivered the external MCP demonstration with four reviewed live checks. D3
delivered a thin browser surface over the same preset contract through the
existing MCP endpoint; it did not create a second REST or SQL path or a chat
system. Free-form SQL generation, parameters and data write-back remain outside
this release.

## Pilot outcomes

- Connect supported text documents and prepared SQL entity snapshots.
- Let an external MCP agent discover and run administrator-approved live SQL
  presets by id, with no SQL input surface and with a versioned execution receipt.
- Let an external MCP client search and read within its workspace permissions.
- Open a citation at its saved source version and inspect its metadata.
- Track source updates, disappearance and return without silently replacing evidence.
- Attribute access to users or service identities and support credential revocation.
- Provide a simple web search interface with optional preliminary model answers.
- Rerank authorized search candidates with a separately identified neural model
  before pagination, preserving source addresses and reporting any degradation.

See [pilot status](../PILOT-STATUS.md) for available workflows and measured
limitations, and [pilot acceptance](../PILOT-ACCEPTANCE.md) for evaluation steps.
The [published release](https://github.com/avangerus/knowvault/releases/tag/v0.1.0-pilot.1)
identifies the initial English pilot source snapshot.

## Future direction

The [connector and format roadmap](../CONNECTOR-ROADMAP.md) describes target
coverage across enterprise systems, event streams and multimodal data.
Retrieval quality, operational scale and a qualified offline distribution
remain development directions. Their scope and sequence follow customer
evidence and explicit release decisions; this document does not promise dates
or make them part of the current pilot guarantee.

## Compatibility

Applied database migrations remain immutable. The narrowly bounded legacy
comment-checksum exception is recorded in [ADR-0093](../adr/0093-migration-comment-translation-compatibility-accepted.md).
Source-publication provenance is recorded in [ADR-0094](../adr/0094-english-source-publication-accepted.md).
Product authorization, audit and evidence-integrity contracts remain in force.

## Current authorized extension: governed SQL presets

The owner authorized this F2/F3/F5 extension on 19.09.2026. A preset is a
versioned reference to an already executed and reviewed governed-query attempt,
not SQL text in UI, API, MCP or the operator mount. The accepted first slice met
those boundaries: an external MCP client could list and run a preset, an unknown
field or SQL field was refused before the service, workspace access and
live-query opt-in were rechecked, the dedicated database role remained read-only
and bounded, and the result carried live-state timestamps plus attempt, preset,
SQL and result hashes.

This does not add arbitrary SQL analytics, parameters, schedules, automatic
write-back, or a retained `kv1:` evidence address for live rows. Those remain
outside the pilot unless separately approved.
