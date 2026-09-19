# KnowVault documentation

Find and read permitted company data, open its evidence, and audit access.
The [pilot status](PILOT-STATUS.md) describes what is currently supported.

## Use and evaluate

| Guide | Purpose |
| --- | --- |
| [Getting started](GETTING_STARTED.md) | Connect to a deployment and use the first workspace. |
| [MCP access](MCP_ACCESS_CODE.md) | Issue a scoped agent credential and configure a client. |
| [Agent guide](MCP-CLIENT-GUIDE.md) | Read evidence, preserve source links and handle partial results. |
| [MCP tools](MCP-TOOLS.md) | Tool inputs, addresses, permissions and pagination. |
| [SQL snapshots](SQL-SNAPSHOTS.md) | Prepare versioned, searchable PostgreSQL entity records. |
| [Governed SQL presets](GOVERNED-SQL-PRESETS.md) | Run reviewed live database checks through MCP without a SQL input surface. |
| [Pilot acceptance](PILOT-ACCEPTANCE.md) | Evaluate retrieval, evidence, access and source updates. |
| [Connector roadmap](CONNECTOR-ROADMAP.md) | Current integrations and future source/format coverage. |

## Deploy and operate

- [Deployment](DEPLOYMENT.md) and [Compose](../deploy/compose/README.md): runtime
  components and development bootstrap prerequisites.
- [Model profiles](MODEL-PROFILES.md): configure available built-in answer models.
- [Native document ingestion](NATIVE-INGEST.md): Office/PDF parser requirements.
- [Worker operations](WORKER_OPERATIONS.md): jobs, leases, retries and readiness.
- [Database guide](../db/README.md) and [operator artifact](OPERATOR_ARTIFACT.md):
  database setup, migration compatibility and operator responsibilities.
- [Images](../deploy/images/README.md): component boundaries and pinned builds.
- [Security](../SECURITY.md): report vulnerabilities privately.

## Develop and integrate

- [OpenAPI](../api/openapi.yaml): REST API contracts.
- [HLD](HLD.md): how web search, an external AI client and the API reach retained evidence.
- [Architecture](../ARCHITECTURE.md): component responsibilities and technical invariants.
- [LLD](LLD.md): package ownership, request paths and implementation locations.
- [Data model](DATA_MODEL.md), [source contracts](SOURCE_CONTRACTS.md),
  [parser contracts](PARSER_CONTRACTS.md) and [canonicalization](CANONICALIZATION.md).
- [Trust boundary](TRUST_BOUNDARY.md) and [encryption](ENCRYPTION.md).
- [Architecture decisions](adr/README.md), [version lock](../architecture/versions.json)
  and [license policy](../architecture/licenses.yaml).
- [Contributing](../CONTRIBUTING.md) and [testing](TESTING.md).

## Source-of-truth hierarchy

Use [Pilot status](PILOT-STATUS.md) and the [release plan](release/PLAN.md) for current support, and [Pilot acceptance](PILOT-ACCEPTANCE.md) for evaluation. The [connector roadmap](CONNECTOR-ROADMAP.md) identifies future coverage separately. Design contracts do not turn planned capabilities into release commitments.

Resolve technical contract discrepancies using:

1. [Product constitution](../PRODUCT_CONSTITUTION.md): boundaries and invariants.
2. Accepted [ADRs](adr/README.md) and machine guardrails in `architecture/`.
3. Normative schemas, API contracts, source contracts and parser contracts.
4. Subject-specific data, security, deployment and operational documents.
5. HLD and LLD: explanatory maps of the implementation and its boundaries.

A design or historical check is not proof that a capability is available.
Behavior changes require the corresponding contract or decision update before
the implementation; explanatory wording cannot override an invariant.

KnowVault is licensed under [Apache-2.0](../LICENSE); third-party components and
model artifacts retain their own licenses. Original accepted-decision hashes
and their reviewed English equivalents are retained in the
[translation provenance record](release/ENGLISH-ADR-REVIEW.json).
