# ADR-0094: English source publication under Apache-2.0

Status: accepted by the owner on 2026-09-16.

## Context

The owner requested publication of KnowVault at `avangerus/knowvault`, selected
Apache-2.0, and required English throughout the published repository, including
internal documentation. Original documents must remain available privately.
The agreed MCP pilot scope and existing security and evidence contracts remain
in force; publication is not acceptance of the full enterprise roadmap.

## Decision

The repository's human-facing documentation, interface, operational messages,
developer comments, public examples and repository presentation use English.
Original documents, evaluation corpora, screenshots and Git history are retained
in a private archive outside the public source publication.

Known multilingual inputs, matching rules, byte-level fixtures, and fixed
historical renderer contracts retain their decoded values. Where necessary,
source notation uses standard Unicode escapes. This is a representation change,
not a restriction on the languages of connected company data. Documentation
explains escape notation wherever a reader needs it to interpret a canonical
example. New English synthetic examples have a distinct dataset revision.

The owner-approved publication is a one-time translation of existing accepted
ADR documents, with original and translated hashes retained in the publication
review record. Freeze the reviewed English bytes in the accepted-ADR registry.
This does not authorize future rewriting of accepted decisions or routine
rebaselining to suppress a failed check. A changed decision still requires a
new ADR. The original requirements, qualifications and historical status remain
part of each translated record.

Applied SQL migrations have the separate, narrower runtime exception in
[ADR-0093](0093-migration-comment-translation-compatibility-accepted.md).
No general SQL normalization or checksum bypass is introduced.

The project is distributed under [Apache License 2.0](../../LICENSE).
[NOTICE](../../NOTICE) identifies the project and distinguishes dependency,
model and dataset licenses. Third-party source corpora are excluded from the
published tree; connecting data does not relicense it.

The verified repository owner, `@avangerus`, replaces placeholder identities
in CODEOWNERS. Every protected path remains explicitly covered, and negative
checks still reject a removed rule, commented rule or missing required owner.
CODEOWNERS does not by itself establish independent reviewers or a GitHub
branch-protection policy.

## Verification and consequences

Translate API descriptions without changing runtime behavior. The sole API
schema correction adds `FOLDER` to the autonomous recurring source-type enum,
alongside `POSTGRESQL_QUERY`, matching the already implemented connector catalog.
The contract drift test rejects both a missing supported type and an unsupported
type. All other non-documentation API values remain unchanged.
Compare decoded language-fixture values and source structure, then run relevant
tests, builds and architecture controls on the test host. Align source-text
mutation anchors to the reviewed representation; preserve their positive and
negative outcomes. Review owner requirements directly rather than relying only
on character counts or automated translation checks.

Scan the final public candidate for source-language prose, private source data
and credentials, check documentation links, and verify the built interface.
Preserve original GitHub refs and metadata before replacing published history.
Do not claim that translation tests establish new retrieval or answer-quality
results. Current delivery and remaining work are in [PLAN.md](../release/PLAN.md).
