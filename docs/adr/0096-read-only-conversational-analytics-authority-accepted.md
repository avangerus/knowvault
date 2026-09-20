# ADR-0096 — Read-only conversational analytics authority

**Status:** accepted by the owner on 2026-09-20

**Owner decision:** The owner defined the product north star as a chat that
answers complex questions over company data, required read-only operation, and
authorized an evolutionary implementation through small DSH work packages with
independent architecture review. This ADR records the governing boundary before
runtime wiring begins.

**Supersedes or narrows:** ADR-0082 sections that restrict MCP to one extractive
tool; ADR-0085 statements that models cannot select a tool; the ADR-0089
model-authored SQL path; ADR-0095 treatment of reviewed presets as a product
question surface. Those documents remain immutable history. Their authorization,
audit, evidence and read-only requirements remain in force unless this decision
states a narrower replacement.

## Context

The controlled Cicada demonstration proved document retrieval, prepared SQL
reads, rights, audit and execution receipts. It did not prove the product north
star: an employee asking varied ordinary-language questions and receiving a
complete, concise and verifiable answer from the data they may use. Fixed
question-to-query presets are useful controls, but do not generalize to new
questions, periods, filters, groupings or follow-ups.

The repository also contained conflicting authorities. The constitution
forbade chat chains, ADR-0085 allowed only the server planner to choose a tool,
ADR-0089 allowed model-authored SQL, and ADR-0095 exposed presets as MCP tools.
Runtime work cannot safely proceed while those paths compete.

## Decision

### Conversation and Question Runs

A conversation may retain bounded context and accept follow-up questions. Every
turn creates a new immutable Question Run with its own idempotency key, plan,
authorization snapshot, audit trail and terminal result. The server limits turn
depth and total inherited context. It rechecks current access to every item
reused from earlier turns. A previous answer is context, not evidence; every
published claim is bound again to evidence or a deterministic result available
to the current run. Inherited references and filters are resolved into the
current run's standalone plan. No hidden long-term model memory is authoritative.

### Model and tool authority

The model may propose only typed intents and tool calls from a closed catalog
whose revision and hash are frozen for the Question Run. The catalog grants no
authority. Server code validates arguments, resolves registry references,
authorizes the current actor, applies budgets, compiles the operation and invokes
the adapter. The model receives no credentials, network capability, arbitrary
tool runtime or direct source access. Revocation applies immediately, including
after an earlier tool call and before disclosure.

Browser, versioned API and MCP use the same server-side admission, authorization,
planning, tool and disclosure authority. With equivalent identity, workspace,
catalog revision and inputs, the allowed data, computation, evidence and
terminal semantics are equivalent. Surface-specific wording may differ.

### Typed analytics and SQL

Typed analytics is the R1 structured-read authority. The model or caller may
select only an immutable dataset profile, measures, dimensions, typed filters,
period, grouping, aggregate and ordering admitted by that profile. They cannot
provide SQL, expressions, joins, executable identifiers or source credentials.
A server-owned compiler may emit a parameterized read from a closed AST and
registry-owned identifiers. The ADR-0089 model-authored SQL path is excluded
from R1 activation and cannot remain reachable through another endpoint.

An immutable dataset profile revision and hash define source identity, grain,
keys, field types, units, NULL meaning, time zone and period semantics, allowed
operators, and explicitly declared relations and cardinality. Execution binds
to that exact revision and hash. Cross-source or cross-profile joins are
unsupported until a relation is explicitly declared and accepted.

Reviewed presets remain diagnostics, regression fixtures and break-glass
controls. They do not restrict the questions the product accepts and do not
count as evidence that natural-language planning generalizes.

### Read-only boundary

All company-source access is strictly read-only. No conversational, API, MCP,
model or internal analytic tool may create, update or delete source records,
files, messages, tickets, permissions, configuration or workflows. User
confirmation does not admit a write. Dedicated read-only source identities,
read-only transactions and mutation-free tool schemas are required. KnowVault
may durably append its own Question Runs, plans, receipts and audit events.

### Completeness, derived rights and evidence

Completeness is a typed statement about an explicit authorized population and
observation period. Exact totals, rankings, absence and invariant satisfaction
require a completed scan or query with known coverage and no unreported
truncation. Unknown coverage, stale data, failed tools and inconsistent source
times are disclosed and cannot be converted into a complete claim. The system
does not imply a shared temporal snapshot across sources.

A derived result inherits the restrictions of every source row, field,
fragment, profile and relation that influenced it, including dependencies not
shown in the final answer. Rights are checked before reading, before disclosure
and when a saved result is reopened. Loss of access to any dependency closes
the corresponding disclosure; checking only visible citations is insufficient.

A live receipt binds the operation, frozen profile and catalog, authorized
input population, parameters, observation window, coverage state and result
digest. It proves what was executed, but is not retained source evidence and
does not alone guarantee later reconstruction of values. The interface labels
live observations separately from retained versioned evidence. Numeric claims
come from deterministic typed results; text generation may explain them but
cannot replace or alter their values. Hash integrity does not establish semantic
correctness.

### Bounded execution

Every Question Run has server-owned limits for model turns, tool calls, rows,
bytes, execution time and total wall time. Catalog definitions are frozen once
per run. Unsupported joins, missing profiles, ambiguous terms or exhausted
budgets return typed clarification, partial or insufficient-evidence outcomes;
there is no fallback to arbitrary SQL or unrestricted tools.

## Alternatives

1. Expand hardcoded presets. Rejected because each new question requires a new
   implementation and users still cannot ask about their data naturally.
2. Let a model generate and execute SQL. Rejected for R1 because identifiers,
   joins, permissions, cardinality and completeness cannot be closed reliably at
   that boundary.
3. Build a universal knowledge graph and orchestration engine first. Deferred:
   it is a high-complexity branch without the smallest demonstrable business
   result.
4. Use one bounded tool loop, typed profiles and a closed compiler. Accepted as
   the shortest path that generalizes while preserving rights and evidence.

No new dependency or license is introduced by this architecture decision.

## Required acceptance before activation

- versioned schemas for intent, profile, result and receipt reject unknown
  fields and unknown enum values;
- unseen direct, aggregate, comparison, negative and informal questions match
  frozen direct controls, including NULL, decimal, duplicate and time-zone cases;
- incomplete or truncated populations cannot produce exact totals or absence;
- profile/catalog hash drift, retired profiles and undeclared relations fail
  closed;
- malicious prompts cannot reach SQL text, credentials, unregistered tools or
  write operations;
- revocation between admission, execution and disclosure prevents output and
  removes undisclosed derived content;
- browser and MCP pass through the same authority and return equivalent facts,
  calculations, evidence and terminal outcomes;
- every admission, model call, tool call, denial, result and disclosure is
  attributable without placing protected content in the audit journal;
- live qualification on Cicada uses customer-visible questions and direct
  controls before deployment is accepted.

Universal cross-source joins, a universal ontology, long-term conversation
memory, write-back, additional connectors and cost optimization remain outside
R1. Unsupported cases must say so explicitly.
