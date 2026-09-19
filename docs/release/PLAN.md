# Release scope and direction

KnowVault's current release is an **operator-assisted MCP pilot**. It connects
approved document folders and prepared PostgreSQL views to authorized search,
complete source reads and inspectable evidence pages.

## North star: customer demonstration release

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
| D4 | In progress | Freeze exact release identity, publish operator runbook/demo script, and obtain second-operator acceptance. | 2–4 hours |

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

The fastest useful milestone is D2: an external MCP demonstration with four
reviewed live checks. D3 adds a thin browser surface over the same preset
contract through the existing MCP endpoint; it does not create a second REST
or SQL path or a chat system. Free-form SQL generation, parameters and data
write-back remain outside this release.

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
not SQL text in UI, API, MCP or the operator mount. The first slice is complete
when an external MCP client can list and run a preset, an unknown field or SQL
field is refused before the service, workspace access and live-query opt-in are
rechecked, the dedicated database role remains read-only and bounded, and the
result carries live-state timestamps plus attempt, preset, SQL and result hashes.

This does not add arbitrary SQL analytics, parameters, schedules, automatic
write-back, or a retained `kv1:` evidence address for live rows. Those remain
outside the pilot unless separately approved.
