# KnowVault Enterprise product constitution

Normative product boundaries. Changes to those boundaries require an explicit owner decision and an ADR. The [pilot status](docs/PILOT-STATUS.md) identifies available workflows and limitations; the source and format catalog below is a design scope, not a claim that every integration is released.

## 1. Promise

The user creates a protected workspace, connects selected sources, poses an arbitrary question, and receives an answer where each output is linked to Evidence IDs, versions, and sources; uncertainty and conflicts are displayed explicitly.

```text
Workspace
  + authorized Source Scopes
  + canonical entities/relations and semantic catalog
  + generic planner + bounded analytic tools
  + Evidence IDs with provenance and a current access gate
  = a verifiable immutable result
```

## 2. Main User Scenario

1. Log in via corporate OIDC SSO.
2. Open or create a workspace.
3. Connect limited source areas.
4. View synchronization readiness and errors.
5. Search in the web application, call the REST API, or ask an external AI agent connected through MCP.
6. Receive a planner operation, an answer with inline Evidence links,
   uncertainty/conflicts, or UNKNOWN/clarification.
7. Open the authenticated KnowVault evidence page with the retained passage, version and metadata; follow an original-source locator when available and permitted.
8. Inspect available context and recorded source relationships; broader cross-system coverage follows the connector roadmap.
9. Ask a bounded follow-up when more detail or a changed period is needed; every
   turn is persisted and authorized as a new Question Run.

## 3. Objects 1.0

- `Organization` — isolation boundary.
- `Workspace` — logical boundary of data, access, search, and results.
- `SourceConnection` — technical read-only connection.
- `SourceScope` — explicitly selected portion of the connection.
- `SourceObject` and `SourceVersion` — source object and its immutable version.
- `SourceExtraction` — immutable result of processing a specific SourceVersion with a fixed parser/OCR profile.
- `EvidenceFragment` — addressable fragment of a specific Extraction with a precise anchor.
- `CanonicalEntity` and `EntityRelation` — versioned cross-source knowledge graph nodes/edges with provenance and workspace authorization.
- `SemanticTerm` — workspace-scoped ontology term/alias/context revision.
- `PlannerPlan` and `AnalyticToolRun` — immutable task/tool provenance; tool output is not an independent source of fact.
- `Conversation` — bounded user-visible context linking Question Runs; it is not
  an evidence source or an authorization boundary.
- `QuestionRun` — one independently authorized turn, retrieval snapshot, plan,
  tool history and answer.
- `Claim`/`Citation` — linkage of each answer output to specific Evidence IDs.
- `AuditEvent` — append-only action record, not a user result.

## 4. Interface Surfaces

The workspace web UI, versioned HTTP API and authenticated MCP share authorization and evidence services. External agents and built-in questions use the same bounded Question/Planner authority. A model may propose typed operations from a frozen closed catalog; the server alone validates, authorizes, compiles and executes them. The UI contains sections:

```text
Search · Sources · Access · Activity log · Settings
```

Settings holds the workspace model context of ADR-0098.

The latest Question Runs are displayed under Search. There is no separate "Answers" section. The Activity Log is intended for security and investigations and does not replace search results.

## 5. Source and format boundaries

The pilot covers mounted folders and prepared PostgreSQL views, including supported DOCX and text-PDF extraction when the native profile is provisioned. The wider product design includes:

- folders and file storage;
- Git repository + branch + path scope;
- mailbox + folder/label scope;
- selected website area;
- external PostgreSQL database as selected tables or DBA-managed views through
  first-class source type `POSTGRESQL_QUERY`.

`POSTGRESQL_QUERY` adheres to the accepted ADR-0078 boundary as amended by ADR-0097: immutable structured projections over selected base tables with a primary key or pre-created DBA views, a separate read-only role, TLS `verify-full`, bounded transaction-consistent full snapshots, and `WORKSPACE_MANAGED`. Product/UI/operator/user-facing API fields do not accept or create SQL text. The agent source tools of ADR-0097 (`knowvault_source_schema`, `knowvault_source_sql`) are the only SQL input: one read-only statement per call against one enabled source, bounded by a separate query role, a read-only transaction, a plan scope check, limits and audit. The sole exception is the source owner `internal/source/postgresqlquery` who builds one fixed parameterless `SELECT` solely from trusted structured identifiers and quoted declared columns per ADR-0078; joins and business logic remain in the reviewed source-owned view. The pilot implements this prepared-view snapshot boundary. Separate experimental governed-query code does not broaden the pilot into arbitrary SQL execution.

The broader parser design covers PDF, DOCX, PPTX, XLSX, CSV, TXT, Markdown, HTML, JSON, XML, EML, source code, PNG/JPEG and scanned PDFs. Format code and contracts are distinct from pilot qualification: see [Native ingestion](docs/NATIVE-INGEST.md), [parser contracts](docs/PARSER_CONTRACTS.md) and the [connector/format roadmap](docs/CONNECTOR-ROADMAP.md).

## 6. Non-revisable properties

1. A conversation is a bounded sequence of independently authorized Question
   Runs. There is no hidden authoritative thread memory; prior answers are
   context rather than evidence and current rights are checked on every turn.
2. This is not an autonomous agent: the model has no arbitrary tools,
   credentials, or network access. It may propose only typed calls from the
   frozen catalog; server policy validates and invokes every bounded adapter.
3. External sources remain the source of truth.
4. Original binary documents do not become the product's permanent storage.
5. Derived text fragments are stored because without them, search, answering, and citation verification are impossible.
6. In the `SOURCE_ENFORCED` mode, the workspace never expands source rights. The `WORKSPACE_MANAGED` mode is a separate explicit owner scope grant, not a simulation of source ACL; it requires warning, confirmation, and audit.
7. A new question uses only current active versions.
8. A completed Question Run, planner plan, answer, claims, citations, and manifest are logically immutable. Privileged retention purge may physically remove content, leaving tombstones, hashes, and audit metadata.
9. Re-running with a new `Idempotency-Key` always creates a new Question Run. Text question matching is not deduplication.
10. No exact anchor — no citation.
11. No valid citation — the actual phrase is not published.
12. An incomplete corpus is always visible to the user.
13. Deletion or access revocation immediately prohibits new data disclosure.
14. The model and provider are replaceable and do not belong to the domain model.
15. Web UI and internal API use a single policy layer.

## 7. What is forbidden in 1.0

- unbounded message chains, hidden long-term model memory, or treating an earlier
  answer as evidence; bounded follow-ups governed by ADR-0096 are allowed; the
  explicit, audited workspace model context of ADR-0098 is configuration, not
  memory, and never evidence;
- arbitrary MCP/tool runtime and unauthenticated public API; only versioned HTTP API and authenticated MCP from ADR-0082 via the common Question/Planner authority are allowed, without SQL input, credentials, or write actions;
- autonomous actions or writes to external source systems; read-only access by authenticated external MCP agents remains part of the product;
- reports, timelines, decision log, and commitments;
- watch, notifications, and automatic recalculation of answers;
- cross-workspace search;
- SQL authorship/input on product UI, operator and user-facing API surfaces, and
  any database connector outside the `POSTGRESQL_QUERY` boundary of ADR-0078 as
  amended by ADR-0097; agent-written read-only SQL is allowed only through the
  ADR-0097 source tools. The typed analytics compiler from ADR-0096
  may emit a parameterized read only from a closed AST and registry-owned
  identifiers; this does not create a SQL input surface;
- treating planned Slack, Teams, SharePoint, Jira, Notion or CRM integrations as released capabilities; each requires an approved connector and access contract;
- search in the open internet;
- fine-tuning on client data;
- saving original binaries to persistent object storage;
- public links to results.

## 8. Technological Line

- user interface: TypeScript + React, static build via pinned esbuild;
- main backend, ingestion, and connector agent: Go;
- metadata and durable jobs: PostgreSQL;
- full-text and vector search: OpenSearch;
- complex-document parsing: isolated, version-pinned parser workers; current Office/text-PDF implementation uses Apache POI/PDFBox;
- OCR: a separately qualified isolated processing capability, outside the pilot guarantee;
- embeddings, reranking, and generation: isolated model runtimes via Model Gateway;
- production UI — static assets served by Go. Node.js is not needed in production.

In 1.0, Redis, a separate message broker, Temporal, MinIO, Vault, Grafana, or a second vector store are not added without a new ADR.

## 9. Rule of Change

Contributors implement the accepted design. Any change to product boundaries, language, storage, access model, immutable semantics, or runtime composition requires:

1. ADR with status `PROPOSED`;
2. description of alternatives and impact on licenses;
3. new acceptance tests;
4. explicit confirmation by the architecture owner;
5. only after this, code changes.
