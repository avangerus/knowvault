# ADR-0085 — Enterprise knowledge graph and generic question planner

Status: Accepted by product owner request (2026-08-29)  
Supersedes: conflicting product-scope clauses in the earlier 1.0 constitution  
Owner: KnowVault product/architecture

## Context

The previous 1.0 delivery boundary treated the extractive Question Run and a
small set of source paths as the product. That boundary cannot answer arbitrary
cross-source questions or keep SQL business objects, code, mail and documents
linked inside isolated workspaces. A list of hardcoded question branches would
also make correctness and authorization impossible to audit.

## Decision

KnowVault is an on-prem corporate knowledge base / corporate ChatGPT over
isolated workspaces. Documents, mail, Git/code and SQL business objects use one
source-agnostic ingestion contract and produce canonical entities, relations,
immutable versions and provenance. A workspace-scoped semantic catalog stores
terms, aliases, synonyms and context with evidence-backed revisions.

Every question enters one server-owned generic planner. Its operation vocabulary
is `LOOKUP`, `EXPLAIN`, `COMPARE`, `AGGREGATE`, `AUDIT` and `CODE_TRACE`;
aggregate plans carry `group_by`, an aggregate function and optional ranking.
The planner never emits SQL, facts, URLs or Evidence IDs. SQL is a typed,
allowlisted, bounded analytic adapter selected by the plan; it is not the
system's data model or authority.

Lexical, vector and entity/relationship retrieval may be fused, but every result
is re-authorized against the current workspace graph. Models are untrusted
bounded components: they cannot choose tools, invent SQL or citations, and may
publish only strict claims whose support and hashes are verified. Every output
claim is linked to concrete Evidence IDs, source/version provenance and current
access. Unknown, unsupported, stale, conflicting or ambiguous input produces
`UNKNOWN`, clarification or typed insufficient evidence.

UI, versioned HTTP API and authenticated MCP are adapters over the same
Question/Planner authority. Workspace/RBAC, freshness, retention and revocation
apply to entities, relations, catalog entries, vectors, snapshots, tool results
and citations. Provider/model activation remains gated by exact live
qualification; no mock or fixture is a production fallback.

## Consequences

The existing Evidence viewer, OpenSearch transport, deterministic numeric
renderer and Question Run persistence remain foundations/adapters. They must be
refactored behind the generic contracts and cannot be used as proof that the
enterprise product is complete. Provider-specific Git/mail implementations,
vector/reranker/generator artifacts and full graph reconciliation are deferred
until their contracts, live dependencies and security evidence are qualified.

The first implementation loop is the audit plus a real planner vertical slice;
its status and remaining gaps are recorded in
`docs/PRODUCT_DEFINITION_AUDIT.md`.

## Acceptance requirements

* canonical entity/relation/version and source-adapter schemas with positive,
  deny and mutation tests;
* generic planner plans are canonical, hashed and persisted with Question Runs;
* unseen aggregate questions demonstrate `group_by + aggregate + rank` without
  entity-specific branches;
* hybrid retrieval and graph-wide authorization pass live tenant/revocation,
  freshness, retention and race/security tests;
* UI/API/MCP parity, typed analytic tool audit, UNKNOWN/clarification behavior
  and model non-authority are proven by real integration evidence;
* release is blocked until all deferred dependencies have exact pins and live
  qualification evidence.
