# ADR-0090 — Runtime components of the one-compose install

**Status:** proposed

**Date:** 2026-09-07

**Owners:** KnowVault delivery (curator on behalf of the owner)

**Related:** `deploy/compose/compose.yaml`, `deploy/compose/README.md`,
`architecture/versions.json`, `architecture/licenses.yaml`, POKA_YOKE ARC-005
("a new runtime component requires an ADR and license record"), owner decision 9
("simple software, not a monster: one compose, one bootstrap"), ADR-0080 §2.4 and
ADR-0088 GEN-2 addendum (embedding runtime), ADR-0086 (agents as principals).

## Context

The owner requires installation in one `docker compose` and one `bootstrap.sh`
(solution 9). For this to be true, the stack must include not only the product code (`server`, `worker`, `operator`) and its mandatory dependencies (`postgres`, `opensearch`), but also two components that would be considered "foreign" in another delivery:

- **`proxy` (reverse proxy, nginx)** — public TLS gateway for installation and mTLS terminator for the embedding channel. Without it, installation requires the customer to provide their own load balancer and manually issue certificates, meaning it no longer remains "install and works."
- **`keycloak` (built-in IdP)** — default OIDC provider. KnowVault does not have and should not have its own password database: identity is an external boundary (ADR-0001). But without a provider "out of the box," the first installation is impossible without an external IdP.

Both are already present in `deploy/compose/compose.yaml` and recorded in `architecture/versions.json` with digest and license. What was missing was a solution explaining why they are included in the delivery, and which version-record references: ARC-005 requires that a new runtime component have both an ADR and a license record, but these two records lacked references to the ADR.

Out of scope: quality/qualification of the embedding model (ADR-0080 §3), selection of the customer's external OIDC (supported by changing `KNOWVAULT_PROVIDER_ID`), HA/DR topology, and any expansion of the component set.

## Decision

1. KnowVault installation by default provides **exactly two infrastructure components beyond the product and its storage**: `reverse_proxy` and `built_in_idp`. Each of them:
   - is pinned in `architecture/versions.json` with a **tag** and digest, along with a license and `adr` field pointing to this document;
   - does not own application state: the product does not store data in them and does not treat them as the source of truth;
   - can be replaced without changing product code — reverse proxy replaced by an external load balancer, built-in IdP replaced by the customer's OIDC (switched via `KNOWVAULT_PROVIDER_ID` and followed by a new `provider-register`).
2. **Built-in IdP does not extend product trust.** It remains a regular external OIDC provider: the same issuer/audience/signature checks apply as for any other external provider. There is no separate "trusted" path for it.
3. **Reverse proxy is not an authorization boundary.** It terminates TLS and mTLS; every access decision is made anew by the server. A request coming from "inside" receives no privileges.
4. **Adding a third component requires a new ADR.** Doubt is interpreted as "do not add" (owner decision 9). This ADR is the upper limit of the set, not permission to expand it.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Require the customer to provide a reverse proxy and OIDC | Violates owner decision 9: installation is no longer "one compose, one bootstrap"; the first installation becomes an implementation project |
| Embed TLS termination in the server | The product would own certificates and rotation — a new responsibility and failure surface to save one container |
| A custom user database instead of an IdP | Explicitly prohibited: identity is an external boundary; this would introduce a password surface that the product does not have |
| Use tags without pinning digests | Violates the `runtime_latest_tags: false` policy in `architecture/versions.json` |

## Consequences

### Positive

- "Install and connect" is verified by the same script as acceptance.
- The set of installation components is closed and named; each new one requires a decision.
- The version-record of both components now satisfies ARC-005 in entirety
  (ADR + license + digest).

### Negative / trade-offs

- Installation pulls two images, which some customers replace with their own.
- Updating these images is a separate operational task with digest correction.

### Security and failure semantics

- built-in IdP unavailable → login impossible; this is an authentication failure, not a bypass: fail-closed behavior is preserved, no "local" account appears.
- Compromised reverse proxy → it cannot grant access: authorization is performed by the server based on the OIDC session or access code, not based on the fact of passing through the proxy.
- Replaced with external OIDC → the path is the same as for built-in: the product does not distinguish between "own" and "external" provider.
- Re-running `bootstrap.sh` is idempotent and does not recreate secrets.

## Implementation and evidence

- Code/configuration: `deploy/compose/compose.yaml` (`proxy`, `keycloak`),
  `deploy/compose/bootstrap.sh`, `deploy/compose/proxy/`,
  `deploy/compose/keycloak/`.
- Contracts/schemas: `architecture/versions.json` → `runtime_components.reverse_proxy`,
  `runtime_components.built_in_idp` (tag + digest + license + `adr`).
- Negative/mutation tests: `scripts/check-architecture.go` (digest-mandatory, prohibition of latest tags); `docker compose config` on `deploy/compose` with `.env.example` — dry run of installation.
- Guardrails/versions/licenses/protected hashes: `architecture/guardrails.yaml` holds `deploy/compose` and `architecture/*` under protected-hash.

## Delivery status

`current`: both components are delivered and verified by the acceptance test deployment.
`target`: replacing the built-in IdP with the customer's OIDC in S6 — same attack surface.
`reserved`: nothing. `deferred`: HA/DR topology of the installation.

## Supersedes / superseded by

Not replaced and not replaced.
