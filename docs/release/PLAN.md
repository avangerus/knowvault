# Release scope and direction

KnowVault's current release is an **operator-assisted MCP pilot**. It connects
approved document folders and prepared PostgreSQL views to authorized search,
complete source reads and inspectable evidence pages.

## Pilot outcomes

- Connect supported text documents and prepared SQL entity snapshots.
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
