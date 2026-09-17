# ADR-0072: Industrial on-prem perimeter for 1.0 (D2-5 through D2-11)

Status: proposed.

Extends ADR-0069 (deployment/operations boundary) and records the owner
perimeter decisions D2-5…D2-11 into the normative carrier. ADR-0069 fixed the
deployment/operations boundary; the industrial perimeter — production IdP,
transport security, metrics, backup, SIEM, offline delivery and topology — is
not covered there and is recorded by this ADR. The criteria D2-5…D2-11 originate
in the owner prototype package outside this repository (PROTOTYPE-DOD.md,
DOD-2); this ADR carries their wording into the tree, so the tree is
self-contained after acceptance. It creates no operator command, deploys no
topology and closes no R2 criterion while the current coordinate remains
P2/R1; the same reservation ADR-0069 states for deployment tooling applies
here.

## 1. Decision

1. **Industrial IdP (D2-5).** The production identity provider is Keycloak
   on-prem, pinned by exact image digest with a license-reviewed SBOM/AIBOM
   (LIC-008); the test IdP exists only in CI. A production configuration whose
   provider is not the pinned Keycloak, or that names the test IdP, is rejected
   with a typed failure. The existing normative SSO scope is unchanged: OIDC
   Authorization Code flow only, no SAML in 1.0; other Keycloak protocol
   surfaces are not activated.

2. **TLS everywhere (D2-6).** TLS is mandatory on every external boundary,
   terminated by a reverse proxy that is itself a digest-pinned component of
   the loop using corporate-CA certificates. Plain-HTTP access to protected
   endpoints must be refused or redirected; this is proven by a test, not by
   configuration prose.

3. **On-prem metrics (D2-7).** Prometheus runs inside the loop and scrapes
   server, worker and PostgreSQL metrics. Metric and log content is bounded by
   the ARCHITECTURE.md §14 allowlist — IDs, durations, counts, error codes
   only, no source text, prompt body, tokens, embeddings or cited excerpts —
   and a gate scans logs and metrics for source content bytes; the scan must
   find none. A separate Grafana or collector is not part of the 1.0 delivery.

4. **In-loop backup (D2-8).** Backup is encrypted basebackup plus WAL archive,
   inside the loop. The restore drill is a mandatory procedure step (per
   ADR-0070 §5, whose negative checks apply), and the NFR-B1 window (≤15 min of
   lost updates) and NFR-B2 window (≤2 h restore) are normative acceptance
   thresholds (D8-10), not observations. Backup semantics stay bounded by
   ADR-0069 §1.2: keys are mounted secrets and never stored in the backup
   artifact.

5. **SIEM export (D2-9).** The audit journal is exported to the customer SIEM
   over syslog RFC 5424, content-free. A test proves events reach a receiver;
   a gate proves the stream carries no source, prompt, token or excerpt
   content. This composes with the existing requirement that audit checkpoints
   close into a verified customer append-only sink.

6. **Offline bundle (D2-10).** Delivery is a signed offline bundle — images,
   migrations, SBOM/AIBOM — installable without any external network. An
   "install offline" job proves a network-free machine reaches a working loop.
   Model and container delivery remains offline by the existing deployment
   contract.

7. **Single-node topology (D2-11).** One instance serves exactly one
   organization on a single node with the NFR-R4 resource limits. A
   configuration naming more than one organization is rejected with a typed
   failure; the measured resource profile is recorded in the Phase Acceptance
   Record.

## 2. Acceptance binding

Each decision above carries the proof form from DOD-2 (D2-5…D2-11): CI smoke on
Keycloak (login → session → protected endpoint), the plain-HTTP refusal test,
the content-free log/metric scan, the restore drill measured against NFR-B1/B2,
the syslog delivery and content scan, the offline install job, and the
multi-organization configuration refusal. Until the deployment implementation
result lands, Keycloak, the reverse proxy and Prometheus shall be registered as
stage-blocking deferred components with exact-artifact, license, offline-
availability and smoke/negative-test obligations (the ADR-0069 pattern); no
such entries exist in `architecture/versions.json` yet, and this ADR does not
add them. This ADR is normative preparation, not a claim that perimeter
tooling exists.

## 3. Consequences

The perimeter norms D2-5…D2-11 are now recorded where the deployment result
will be checked against them, with one owner per concern (ADR-0069): the
operator binary owns bootstrap and configuration; the perimeter components are
pinned, license-reviewed loop components, never runtime downloads. Any future
deviation — a non-Keycloak production IdP, a metrics exporter carrying content,
a backup without drill proof — is an architecture violation with a typed
refusal, not a documentation drift. On acceptance, ARCHITECTURE.md is
reconciled: its statement that Prometheus is not part of the 1.0 delivery is
replaced by this ADR's on-prem Prometheus decision, its reference deployment
image list gains the pinned reverse proxy at implementation time, and the
`architecture/licenses.yaml` Prometheus entry ("no Prometheus binary or
library is shipped in 1.0") is revised to the on-prem Prometheus decision.
