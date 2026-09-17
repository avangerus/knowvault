# ADR-0055: Encrypted artifact key-wrapping backend and runtime boundary

Status: accepted.

Amends ADR-0041 and ADR-0035. ADR-0041 recorded three non-convertible
mounted-secret capabilities; ADR-0035 recorded a three-key manifest. Those ADRs
remain unedited historical records. This ADR is the current authority: it adds a
fourth deliberately non-convertible mounted-secret capability, `ArtifactWrapKey`,
and one `artifact_kek` manifest entry, without weakening the non-convertibility
guarantee. Editing a prior accepted ADR is forbidden; the accepted-ADR
immutability gate freezes their content so a history change cannot pass as a
routine protected-hash update.

Migration `000005` (ADR-0046) installed the `encrypted_artifact` envelope store,
its closed 26-branch owner inventory and its immutable mutation guard. This ADR
authorizes the runtime that owns that table and the database containment that
makes the runtime safe. It does not authorize ingestion, jobs/lease, connector,
extraction or Evidence.

## Tenant-bound key-wrapping provider

Key wrapping is a replaceable capability behind a narrow provider interface. The
provider is bound at construction to the exact organization from trusted
composition; a provider or codec for organization A can neither seal nor open an
owner of organization B, even when the caller supplies a formally valid owner
identity. The provider never exports the key-encryption key, and no application
code receives generic KEK bytes.

`WrapDEK` returns one atomic result carrying the wrapped bytes, the wrap scheme
and the exact key reference and version together; the caller never separately
re-reads mutable current-key metadata, so the persisted key reference/version
cannot drift from the bytes they authenticate. The wrapped-DEK format is
versioned and scheme-tagged so a future external-KMS blob is distinguishable and
the mounted backend fails closed on any scheme it does not own. Its wrap AAD
binds the schema version, key reference, key version and the full owner tuple
(organization, owner table/column, resource type, resource id, field), so a
wrapped DEK moved to another artifact, column, tenant, key reference or key
version fails wrap authentication. The clear DEK is never persisted, logged,
audited or placed in a job payload.

The on-edge 1.0 reference backend is a purpose-typed mounted-secret KEK loaded
from the same root-owned, `O_NOFOLLOW`, `fstat`-validated mount as the other
keys, with a distinct reference and fingerprint. A future external-KMS adapter
implements the same interface without changing the artifact crypto or repository
contract.

## Key lifecycle and readiness

The mounted backend holds exactly one key reference/version. Open permits only
the exact stored key version and fails closed on a tenant mismatch, an unknown
version or a foreign scheme. This ADR does not build a rotation framework: a
readiness preflight fails closed when the database still holds active artifacts
under a key reference/version the current backend cannot provide, so composition
of the artifact runtime remains mechanically forbidden until that preflight is
wired.

## Database containment and semantic ownership

The runtime role has no raw `SELECT` or `INSERT` on `encrypted_artifact`; the
string `encrypted_artifact` is only an anti-drift signal, never the security
boundary. Direct or dynamically assembled SQL from a sibling package meets a
PostgreSQL privilege denial, not merely a checker. Every artifact write and read
flows through a per-activated-branch `SECURITY DEFINER` function that, in one
transaction, proves the exact owning row, the tenant, the single permitted
operation and the transactional binding of owning row and artifact. A committed
artifact without its exact owning relation is therefore technically impossible,
and no orphan can survive.

The read owner identity is derived by the database from the trusted owning row
after domain authorization; it is never assembled by the caller. The 26-branch
crypto registry proves only the accepted AAD form: a branch stays inert until it
is activated together with its owning-row binding, its authorization resolver and
its negative tests. Until at least one branch is activated, artifact persistence
is inert. The generic low-level seal/open and persist/load are not exposed to
application code as a standalone capability; only activated branch bindings are.

One parity gate proves the owner inventory is set-equal across the AAD schema,
the SQL owner-validation function, the typed Go registry and the documentation,
eliminating the owner-count drift class. This ADR introduces no generic blob
store, no full KMS/rotation framework and no new third-party dependency.
