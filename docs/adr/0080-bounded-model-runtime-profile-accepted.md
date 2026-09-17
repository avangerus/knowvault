# ADR-0080: Bounded production model-runtime profile

Status: accepted.

Acceptance scope: design authorization only; model/runtime capability remains
inert and `DEFERRED`.

Date: 2026-08-27.

Owners: product architect, model-runtime owner, search owner, security owner,
operations owner.

Decision scope: accepted owner design contract only. It selects no executable
artifact and authorizes no implementation, dependency import, production
composition, runtime start, delivery-coordinate advance or release claim.

Owner decision: accepted on 2026-08-27 after blind design review `PASS`, under
explicit product-owner authority.
This decision accepts the bounded model-runtime boundary below, not model or
runtime qualification, activation, delivery or a release verdict.

Related: `PRODUCT_CONSTITUTION.md`, `docs/IMPLEMENTATION_PLAN.md` Stages 3, 4
and 6, `docs/LIVE_SYSTEM_DOD.md`, `architecture/versions.json`,
`architecture/contracts/answer-manifest.schema.json`, and model invariants
`MOD-001`, `MOD-008` through `MOD-012`, `CIT-003`, `CIT-006` through
`CIT-009`, `SRCH-010`, `EXA-001` through `EXA-004`, `OPS-010` and `OPS-011`.
ADR-0079 is referenced only to restate the current prohibition and the inert
conditional future note in §2.9; it is not a dependency or an authorization for
this ADR.

> **Acceptance boundary (normative).** This ADR accepts the bounded design for
> exact local pinned runtimes and, subject to the same qualification gates, an
> exact customer-owned/customer-operated on-prem inference peer inside the
> customer deployment perimeter. The peer is reached solely through the KnowVault
> Model Gateway and is not a third-party or external SaaS service; a private or
> RFC1918 address alone never qualifies it. Acceptance does not select an
> executable artifact, qualify or activate a model/runtime, change
> `architecture/versions.json`, advance delivery, or imply `GENERATIVE` PASS.
> All model/runtime locks remain `DEFERRED` and the capability remains inert
> until a later atomic qualification, implementation and delivery package passes
> every required gate. `PRODUCT_CONSTITUTION.md` §7 still forbids MCP and a
> public developer API; ADR-0079 is an accepted design, but its acceptance alone
> does not authorize MCP. §2.9 remains conditional and inert until a separate
> phase amendment and protected baseline changes pass every required gate.

## 1. Evidence status at design acceptance time

The labels in this section are normative: an **Observed** fact is a bounded
probe result, an **Unknown** is a release blocker, and a **Design** statement is
an accepted choice that has no runtime authority until the gates in this ADR are
closed.

### Observed

- A read-only host probe identified the available local GPU as an NVIDIA
  GeForce RTX 4070 with `12282 MiB` total memory. At the probe instant it
  reported `8932 MiB` used and `3079 MiB` free. This is a volatile snapshot,
  not a capacity reservation or performance result. It also corrects the
  unverified RTX 4090 assumption for this candidate host.
- The local inventory exposed llama.cpp-served discovery labels for a Qwen VL
  4B-class artifact and a Gemma E4B-class artifact. These are discovery labels,
  not exact model identities, revisions, aliases or qualified profiles.
- A private-network candidate endpoint exposed a self-reported model discovery
  label. Reachability and a self-reported label do not establish
  TLS, authentication, runtime identity, weights, tokenizer, context behavior,
  license, retention policy or fitness.
- `mxbai-embed-large-v1` and `bge-small-en` are candidate embedding inventory
  labels. No qualified reranker artifact was found by the bounded probe.
- `architecture/versions.json` currently keeps `model.embedding`,
  `model.reranker`, `model.generator`, `model.verifier` and `oci.vllm` in
  `DEFERRED`. Consequently none of the observed candidates may appear in an
  executable production configuration or start in any environment under the
  current accepted lock.
- The current Answer Manifest contract requires exact model revision, artifact
  hash, profile revision/hash and purpose-specific fields, requires generation
  and verification profiles for `GENERATIVE`, and permits only 1024-dimensional
  embeddings. It forbids generator/verifier runs in `EXTRACTIVE`.

### Unknown and therefore blocking

- Exact weight files and hashes, source revision, tokenizer, chat template,
  prompt template, quantization, runtime/build/image identity, decoding
  settings, output-schema implementation and complete transitive AIBOM are
  unknown for every discovery label.
- Artifact provenance, redistribution and production-use licenses, NOTICE/source
  obligations, vulnerability posture, offline availability and reproducible
  installation are not yet proven.
- The remote service's TLS server identity, client authentication, authorization,
  API contract, logging/retention/training behavior, network containment,
  operator ownership, runtime/image digest and model residency are unknown.
- Actual context-window support, correct behavior at the bounded 24,000-token
  Evidence boundary, peak VRAM/RAM, TTFT, throughput, tail latency, structured
  output reliability, Russian/English quality and citation support are unknown.
- The exact dimensionality and RU/EN retrieval fitness of the embedding
  candidate have not been accepted against the current 1024-dimensional
  manifest/index contract. The reranker identity, placement and fitness are
  wholly unknown.

No Unknown in this inventory may be converted into an alias, default or
operator warning. It must be closed by immutable evidence or the affected
capability remains unavailable.

## 2. Decision

### 2.1 One gateway and exact profiles

All embedding, reranking, generation and verification calls enter one KnowVault
Model Gateway authority. Application, retrieval, Question Run, UI and API
adapters cannot call a model runtime directly. Models receive no tools, source
credentials, network capability, policy decisions, raw SQL, whole source rows,
prior Question Runs or caller-selected endpoints.

Every callable profile is immutable and purpose-specific. Its canonical hash
binds at least the exact weights and all shards, tokenizer and normalization,
runtime binary/image and configuration, quantization, chat/prompt template,
input and output schemas, context allocation, stop rules and decoding
parameters. The server creates the append-only execution plan before the first
call and persists every bounded attempt and exact input/output binding as
required by the existing Answer Manifest and guardrails. A discovery label such
as `qwen3.8-27b`, `Qwen VL 4B`, `Gemma E4B` or `mxbai-embed-large-v1` can never
be a production alias.

Exact manifests, digests, licenses and platform locks belong in
`architecture/versions.json`, release candidate manifests, AIBOM/SBOM and
offline-bundle inventories. This ADR deliberately does not duplicate or invent
them. Activation requires an accepted atomic lock change from `DEFERRED` to an
exact qualified state, followed by `ACTIVE` only with the working end-to-end
path and evidence required by the existing lifecycle policy. Runtime downloads,
mutable tags, model auto-pull and unrecorded cache population are forbidden.

### 2.2 Generation placement and bounded request

The probed remote Qwen placement remains a candidate only. It is not a
production generator and is not eligible merely because it is reachable on
RFC1918/private address space, on the same LAN, or inside a customer-named
network. Any future production use requires a customer-owned and
customer-operated on-prem inference peer inside the exact customer deployment
perimeter, with the owner, site/cluster, host and serving process recorded in a
signed inventory. The literal probed address and self-reported label are never
production configuration. Acceptance of this design does not qualify or
activate the peer: the generator must still be an exact qualified local runtime
or that exact customer-controlled peer, and `GENERATIVE` is unavailable until
all applicable gates pass. This candidate cannot be a fallback.

Remote production eligibility is conjunctive and must be proved before a
qualification call. The immutable inventory must exact-match, at minimum:

- the customer deployment/perimeter ID, site or cluster, host/VM/node identity,
  ownership/operator authority, OS/kernel, network namespace, listening socket
  and effective firewall/egress-policy digest, independently checked against
  customer control-plane/host attestation and topology; provider-hosted shared
  tenancy, “private” or “on-prem” without these identities is insufficient;
- the serving runtime binary or OCI image digest, build/driver/runtime
  revisions, launch arguments and configuration/profile hash, process or
  container identity and endpoint protocol;
- the model source/revision, every weight/shard digest, tokenizer and
  normalization, chat/prompt template, quantization, context allocation,
  output schema, AIBOM, license/NOTICE records and the resulting exact model
  profile hash. `qwen3.8-27b` remains only a discovery label until all of these
  values are independently recomputed and locked.

The sole ingress to that peer is the KnowVault Model Gateway over mutually
authenticated TLS. The peer accepts no other client or adapter, and no
application, retrieval, Question Run, UI or API component has a direct route,
socket or protocol to it. The gateway and peer both verify the exact opposite
identity and purpose scope; cleartext HTTP, certificate bypass, an IP/name
mismatch, caller-supplied bearer credentials, endpoint discovery, public-network
failover and any direct adapter are denied. The model CA and gateway client
identity are separate customer-supplied mounts at exactly
`/run/knowvault/trust/model-ca.pem`,
`/run/knowvault/identity/model-client-cert.pem` and
`/run/knowvault/identity/model-client-key.pem`, with exact path, ownership,
mode, byte-fingerprint and revision checks. The CA mount is used by both TLS
verifiers, the client key is mounted only in the gateway process, and the
peer's server certificate/key are separately exact-inventoried. Verification
uses only that dedicated model CA and exact hostname/SAN or pinned peer
identity; the system trust pool, proxy/environment CA, arbitrary path and
fallback identity are not allowed.

The inference host has deny-all outbound-new-connection policy, including DNS.
Response packets on the established mTLS session initiated by the exact Model
Gateway are stateful return traffic, not an outbound destination; the only new
outbound flows permitted are explicitly enumerated, digest/version-pinned local
dependencies. No other outbound destination is permitted. DNS, HTTP(S),
telemetry, training, log-forwarding and arbitrary proxy canaries must be
rejected. Effective routes, firewall/policy counters and packet capture are
recorded as evidence; a customer or service-provider documentary assertion is
not evidence of containment.

One generation attempt receives at most 24,000 tokens of selected,
post-authorized Evidence according to the profile's exact tokenizer. The
Question Run owner constructs a deterministic context pack and accounts for
system instructions, question, schema and output separately; total input must
also fit the smaller of the qualified model context limit and its immutable
profile limit. Output is capped at 2,048 tokens and the strict structured
answer schema's byte/item/depth limits. Cap+1 is rejected before the model call;
the gateway never silently truncates a claim, citation identifier or structured
value. Context selection/truncation is persisted in retrieval provenance and
cannot be controlled by the model.

The initial production generation admission limit is one in-flight remote
attempt for the deployment. Each organization and workspace has a bounded,
fair queue; no tenant can reserve the only slot indefinitely. Initial hard
bounds are: 30 seconds maximum queue residence, 5 seconds for DNS/TCP/TLS/auth,
20 seconds to first response token, and 90 seconds wall-clock for one attempt.
There are at most two recorded attempts, and a retry is allowed only for a
typed transient transport failure before any accepted output bytes. Schema
rejection, authentication/authorization failure, TLS failure, identity/profile
mismatch, timeout after output begins and deterministic validation failure are
not retried under another model.

The generation circuit opens after five consecutive typed dependency failures
or at least 50% failures in the last 20 admitted calls, whichever occurs first.
It remains open for 60 seconds, admits one half-open probe, and reopens on probe
failure. Circuit state is per exact endpoint/profile and cannot route to another
profile. These are safety bounds, not proof of the Stage 6 p95 SLO; the accepted
candidate must still demonstrate `GENERATIVE` p95 at or below 30 seconds on the
frozen reference workload.

### 2.3 Local verifier and the GPU coexistence contract

The accepted design requires a qualified, text-only Gemma-family profile,
different from the Qwen-family generator. Different family is a minimum
independence boundary, not evidence of verification quality. The discovered
Gemma E4B-class artifact is only a candidate until its exact text weights,
tokenizer, runtime, license, AIBOM, schema behavior and verification benchmark
pass. It cannot be activated merely because it is present on disk.

KnowVault may account for at most 6144 MiB of local GPU memory across all of its
processes. Local GPU concurrency is globally one, including verifier and any
future GPU-qualified embedding or reranking work. Admission requires an
operator-created reservation and a preflight proving both that the KnowVault
6144 MiB ceiling will not be exceeded and that the device currently has the
qualified profile's measured peak plus its frozen safety margin free. The
observed `3079 MiB` free snapshot therefore does not admit a profile requiring a
larger reservation.

KnowVault never kills, pauses, evicts or reconfigures another development
workload; never auto-starts or auto-loads a local model when headroom is
insufficient; and never relies on another process being auto-evicted. The job
remains queued only within its bound or fails with a typed capacity error.
Unexpected allocation beyond the declared profile peak immediately makes that
runtime unready, stops new admission and fails the affected attempt closed. It
does not trigger a smaller quantization, CPU spill or different model.

Qwen VL and any other multimodal artifact may be qualified only as text-only
for this workload. Vision projectors, image encoders, image input fields,
automatic modality detection and projector auto-load are forbidden in the
generation and verification profile. A text profile must prove from process
arguments, loaded-file inventory and negative image-input tests that no vision
projector is loaded. The present Qwen VL 4B-class candidate is not the primary
generator and is not a fallback.

### 2.4 Embedding and reranking

Embedding placement is CPU-first. `mxbai-embed-large-v1` remains only a
candidate until an exact offline artifact/runtime/profile is locked and it
passes the frozen Russian/English retrieval benchmark, license/AIBOM review,
resource limits and the current 1024-dimensional manifest/index contract. If
its exact output dimension is not 1024, KnowVault must select another qualified
artifact or accept an explicit versioned schema/index/profile migration; padding,
truncation or an undocumented projection is forbidden.

`bge-small-en` cannot be the sole production embedding profile for a bilingual
Russian/English corpus. It may be rejected or separately qualified for a
narrow, explicitly English-only future scope, but no language heuristic may
silently create mixed vector spaces. Query and corpus vectors always exact-match
one active immutable embedding profile; staged full re-embedding and atomic
alias activation remain mandatory.

No reranker is selected by this ADR. The implementation must acquire and
qualify a real offline-capable reranker against the same RU/EN candidate corpus,
then record its exact artifact/runtime/profile, license and AIBOM in the Stage 3
locks before the first integration call. No placeholder, lexical score renamed
as reranking, generator reuse, invented model ID or no-op pass-through is
allowed. Its CPU/GPU placement is decided from qualification evidence; if GPU
is selected, it shares the 6144 MiB ceiling and global concurrency-one gate.

### 2.5 Failure semantics and mode availability

There is no silent fallback between exact profiles, endpoints, runtimes,
quantizations or devices. A missing/unready embedding or reranker makes the
hybrid retrieval capability unready and rejects new dependent runs. A missing
generator or verifier makes `GENERATIVE` unavailable. A failed verifier cannot
publish generator output. Exhausted bounds produce a typed terminal failure or
`INSUFFICIENT_EVIDENCE` only where the existing Question Run contract permits;
no partial or unverified factual answer is saved as completed.

`EXTRACTIVE` remains a separate deterministic product mode only after its own
Stage 4 gate is green. It is available while generator/verifier runtimes are
down only if retrieval and every extractive dependency are independently ready
and the caller selected `EXTRACTIVE` before run creation. A `GENERATIVE` run is
never changed, retried or rendered as `EXTRACTIVE`; the user or integration may
submit a new one-shot run with a new idempotency key and explicit mode. The UI
and API surfaces must expose the same current per-mode availability without
claiming a degraded mode is the requested mode.

### 2.6 Workspace isolation and model data boundary

The gateway accepts only a server-owned capability exact-bound to organization,
workspace, Question Run, purpose, retrieval snapshot, context-pack hash and
model profile. It rechecks that binding before dispatch and before accepting an
output. Queue entries, caches, prefix/KV caches, batch construction, persisted
artifacts and retry state cannot mix organizations or workspaces. Cross-tenant
dynamic batching and shared prompt-prefix/KV caching are disabled unless a
later ADR proves cryptographic and process isolation; this profile assumes they
are absent. Model input/output artifacts use the existing organization-bound
encryption and retention owners.

Only the current question, fixed server instructions, strict output schema and
selected post-authorized Evidence fragments may cross the model boundary. Raw
documents, raw SQL rows, source credentials, identity tokens, ACLs, denied hit
counts, hidden metadata and prior questions do not. Evidence instructions,
URLs, tool syntax, SQL and prompt delimiters are untrusted text; runtimes have no
tools and no general egress.

The remote candidate is not a generic private data-egress boundary. Its exact
customer-owned/customer-operated peer may be activated only after technical
configuration and live tests prove all of the following: request/response
logging is disabled at the peer; no prompt/output retention, disk spool,
checkpoint, backup or crash dump is enabled; training/fine-tuning and provider
forwarding are disabled; and prefix/KV, dynamic-batch and other cross-tenant
caches are disabled. This profile has no cache exception. Process arguments,
mounted configuration, open-file
and storage inspection, restart/purge probes and canaries must prove these
properties. A privacy policy, operator statement or other documentary claim
alone never qualifies the peer. The gateway still stores only the existing
organization-bound encrypted artifacts with their approved retention owner;
the remote peer receives no durable copy.

Evidence artifacts remain envelope-encrypted under the customer data boundary
until the trusted Model Gateway has authenticated the caller, rechecked the
server-owned capability and completed post-authorization. The gateway decrypts
only the bounded context needed for that attempt. Its onward mTLS request may
contain only that bounded prompt; plaintext context is held in memory-only
buffers, never written to a file, swap, page dump, trace or log, and is zeroed
on completion, cancellation and failure on a best-effort basis. The peer's
response is handled under the same bounded memory and content-free telemetry
rules. The local verifier, embedder and reranker run with deny-by-default
network egress. A health or license check cannot fetch from the Internet at
runtime, and no direct adapter may contact the remote peer.

### 2.7 Admission, startup and readiness

Admission is server-side and occurs before queue allocation. It verifies exact
profile activation, organization/workspace authority, corpus snapshot, token and
byte budgets, queue quota, global concurrency, deadline feasibility and resource
reservation. Queue limits are fixed in an immutable runtime profile and cover
items, bytes and residence time. Scheduling is round-robin across active
organizations, then workspaces, with per-principal and per-workspace limits;
operator/admin traffic has no content-processing bypass. A cap+1 request receives
a typed refusal and allocates no model-sized buffer.

CPU embedding has separate bounded workers, RAM, batch, token and deadline
budgets. GPU work is serialized by a lease whose holder, profile, measured
memory and deadline are kernel/NVML-observed, not worker self-report. A crashed
holder loses the lease; a replacement rechecks actual free memory and does not
assume driver cleanup. Remote generation has its own single-slot lease and
bounded queue. Retries re-enter neither queue nor quota invisibly: every attempt
is preplanned and accounted.

On startup, the gateway refuses to activate a profile unless all exact artifacts
are present offline, hashes/signatures and profile hash recompute, lock/AIBOM/
license entries are `ACTIVE`, runtime/image identity matches, no unexpected file
or projector is loaded, secret/trust mounts are valid, egress policy is active,
and a purpose-specific bounded schema probe succeeds. Startup never downloads,
warms an unqualified model or starts a local GPU runtime without reservation.

Readiness is capability-specific and dependency-aware:

- retrieval is ready only when the exact active embedder and reranker, vector
  profile/index alias and terminal post-authorization dependencies are ready;
- `EXTRACTIVE` is ready only when retrieval and deterministic validation/signing
  dependencies are ready;
- `GENERATIVE` is ready only when retrieval, either the exact pinned local
  generator or the authenticated TLS customer-controlled on-prem peer,
  reserved text-only verifier, validators and signing dependencies are ready;
- an unconfigured candidate has no readiness effect, while any advertised or
  required active profile that is unknown, mismatched, circuit-open or outside
  resource reservation makes that capability red.

Liveness reports only process health and cannot substitute for readiness.
Operator/API/UI views must not show global green while the selected mode is red.
Existing in-flight work may finish only within its immutable deadline and
current authorization; no dependency outage permits stale-result disclosure.

### 2.8 Content-free operations telemetry

Allowed metrics are bounded operational values: queue depth and wait, admitted/
rejected/timeout counts by closed reason code and purpose, attempt latency,
TTFT, generated token count, tokens/second, input/output token counts, circuit
state, CPU/RAM, KnowVault GPU memory, reservation headroom and readiness. Labels
come from a closed low-cardinality inventory; raw organization, workspace,
principal, question, Evidence or run identifiers are not metric labels.

Question text, Evidence, prompt, output, embeddings, tokens, source paths/URLs,
SQL, row values, credentials and model input/output bytes are forbidden in
metrics, logs, traces, readiness bodies, errors, audit and dead letters. Audit
records the authorized actor/workspace/run operation and content-free typed
outcome under the existing audit contract. Debug mode cannot weaken this rule.

### 2.9 Conditional future MCP note — inert under the current baseline

This note is conditional only. `PRODUCT_CONSTITUTION.md` §7 forbids MCP.
ADR-0079 is an accepted design, but neither its acceptance nor this ADR changes
that prohibition or authorizes MCP. Acceptance of ADR-0079 or ADR-0080 alone
must not add an MCP dependency, route, contract, configuration entry, binary,
capability or runtime process. Until a separate owner-approved phase amendment
and protected baseline changes amend the Constitution,
`architecture/guardrails.yaml`, the affected contracts and P2–P6, every MCP
path and call is absent and denied; this note is inert and creates no
implementation or test obligation.

If and only if that separate amendment is accepted, a later MCP adapter may be
added under its own delivery package, and it must use the same application
authority, Model Gateway, exact profile, current mode-readiness result,
workspace binding, bounded request and content-free telemetry rules as every
other admitted surface. It may never call a peer runtime directly or weaken
any requirement in this ADR. That future conditional does not qualify or
activate any model today.

## 3. Qualification and acceptance proof

The delivery owner freezes the exact commit, hardware/driver/runtime/image and
model artifacts, profile hashes, trust/auth configuration, corpus and workload
manifest, scorer versions, limits and thresholds before viewing candidate
results. Tests run through production images, real PostgreSQL/OpenSearch,
production Model Gateway and real model runtimes. Recorded/replayed responses,
fake endpoints, no-op models, synthetic performance substitutions and skipped
GPU/model checks do not count as live evidence. Non-sensitive adversarial
fixtures may supplement, but never replace, the real end-to-end corpus.

### 3.1 Resource and performance matrix

1. Measure cold and warm peak GPU memory for every local profile at minimum,
   median and cap input/output, including the exact 24,000-token Evidence case
   where applicable. Sampling includes allocation spikes and driver-reported
   process memory. Peak plus the frozen safety margin must fit 6144 MiB; a
   6145-MiB mutation and the observed-style insufficient-headroom condition must
   reject before load without disturbing other GPU processes.
2. Run contention with an unrelated development workload consuming GPU memory.
   Prove global local-model concurrency one, fair bounded queueing, no eviction,
   no auto-start, no CPU/model fallback, correct crash lease recovery and stable
   memory accounting.
3. At exactly 24,000 Evidence tokens and the output cap, record p50/p95/p99
   end-to-end latency, TTFT, tokens/second, queue time, input/output tokens,
   CPU/RAM/GPU and error distribution. `GENERATIVE` still must meet the existing
   p95 <= 30 seconds release SLO on the frozen production query mix; separate
   TTFT and throughput thresholds are owner-signed before candidate execution.
4. Run the complete Stage 6 reference load and an eight-hour soak with real
   ingestion, retrieval, generation, verification, revocation, reindex and
   backup activity. Memory may not grow beyond the existing DoD bound; no lost
   job, dead letter, cross-workspace cache entry or unaccounted model attempt is
   permitted.

### 3.2 Quality and contract matrix

1. A versioned bilingual RU/EN retrieval set with immutable query, expected
   Evidence and workspace-grant manifests measures embedding recall and
   reranker nDCG/recall separately and together. Thresholds are accepted before
   candidate scoring. Language slices, numeric/date/unit questions, zero-hit and
   revoked Evidence are reported; aggregate quality cannot hide a failed slice.
2. A versioned RU/EN Question Run set measures citation-support precision and
   recall, unsupported-claim rate, verifier false-accept/false-reject rates and
   deterministic numeric/date/unit validation. Every material claim opens its
   exact current Evidence chain. Existing release thresholds and Answer Manifest
   semantic rules remain authoritative.
3. Structured-output tests exercise the exact generation and verification
   schemas at maximum counts/depth/bytes and every cap+1, missing, duplicate,
   unknown, malformed Unicode, bidi, Markdown/HTML/URL and invented Evidence-ID
   mutation. Only strict schema output proceeds; repair by free-form model call
   or renderer interpretation is forbidden.
4. Prompt-injection content is placed in real documents, mail, Git and
   PostgreSQL business-object Evidence in both languages. It cannot alter
   profile, mode, policy, context selection, schema, citation, network or tool
   inventory.
5. Multi-workspace tests interleave identical and distinct questions, Evidence
   and prefixes under overlapping and disjoint principals. Candidate/result
   bytes, queues, caches, metrics and timing classes reveal no forbidden tenant
   data; revocation before dispatch, during generation, during verification and
   before disclosure fails current-access checks.

### 3.3 Failure and supply-chain matrix

1. Kill/restart the gateway and each runtime before dispatch, after dispatch,
   before first byte, mid-output and before terminal commit. Disconnect and slow
   consumer tests prove bounded cancellation, durable attempt records and no
   partial answer publication. The same sequence is run against the
   customer-operated peer to prove no prompt/output survives a restart, crash,
   cancellation or reconnect.
2. Against the real production images and a real customer-deployed peer, run
   `acceptance.model.remote-unauthorized-client` with no client certificate,
   an untrusted/revoked/expired client certificate, a wrong client identity and
   a wrong purpose/audience. Run
   `acceptance.model.remote-wrong-ca-hostname` with a wrong model CA, wrong
   hostname/SAN, IP/name mismatch, rotated CA and a system-trust-only setup.
   Run `acceptance.model.remote-runtime-model-digest` with missing and
   substituted host, runtime/image, model/shard, tokenizer and profile
   digests. Every variant fails closed before any prompt bytes are accepted,
   uses the typed reason, and never retries through a downgrade or alternate
   route.
3. Run `acceptance.model.remote-gateway-bypass` from every application,
   worker, UI/API and inference-host namespace against the peer's direct HTTP,
   TLS, alternate-port and discovered-address paths. Static route/import scans,
   socket policy, peer listener ACLs and packet capture must show that only the
   Model Gateway's mutually authenticated TLS ingress is reachable; no direct
   adapter or peer-to-peer path survives.
4. Run `acceptance.model.remote-egress-deny` on the inference host with unique
   canaries for DNS, HTTP/HTTPS, telemetry, training and log-forwarding sinks.
   The host's effective policy must deny every new outbound flow except
   explicitly pinned local dependencies; the stateful reply leg of the exact
   inbound gateway session is the sole permitted return traffic. Packet capture
   and policy counters must prove zero canary delivery. Removing or changing a
   local dependency pin must make startup red; a proxy, default route, resolver
   or system trust pool may not provide an escape.
5. Run `acceptance.model.remote-data-boundary` and
   `acceptance.model.remote-retention-restart` with unique prompt, selected
   Evidence and output canaries. Inspect peer configuration, process
   arguments, open files, volumes, temp paths, swap/page dumps, crash dumps,
   backups, logs, traces, metrics and outbound connections after success,
   failure, cancellation, kill and restart. Technical configuration and these
   inspections must prove no request/response logging, retention, disk spool,
   checkpoint, backup, training/fine-tuning or forwarding; a privacy policy or
   operator declaration without the test result is not evidence.
6. Run `acceptance.model.remote-cache-workspace` by interleaving identical and
   distinct prompts, Evidence, prefixes and organizations/workspaces. The
   peer must have cross-tenant dynamic batching and prefix/KV caches disabled;
   cache, batch, timing, logs, storage and output canaries must reveal no
   cross-workspace bytes. Purge and restart must leave no retained prompt or
   output.
7. Run `acceptance.model.remote-encrypted-memory-boundary` with a packet
   capture before the trusted gateway and on the onward mTLS leg. Evidence is
   envelope-encrypted until the gateway's authorization/decryption point; no
   pre-gateway cleartext appears in transport, logs or artifacts. Heap/core/
   swap/temp-path and cancellation probes prove that the decrypted bounded
   context exists only in memory and is zeroed on completion/failure on a
   best-effort basis.
8. Remove or mutate one weight shard, tokenizer, template, quantization/runtime
   setting, image layer, AIBOM/license entry, offline-bundle blob, trust mount,
   egress policy or protected-baseline amendment. Startup or
   architecture/release checks must turn red before a model call. Prove a clean
   offline installation performs zero runtime downloads.
9. Deny remote prompt-retention evidence, packet-capture/egress evidence, exact
   identity evidence, customer-perimeter ownership evidence, the required GPU
   reservation, exact model/profile lock or any required delivery evidence.
   `GENERATIVE` remains unready for the remote candidate. Demonstrate that an
   independently green `EXTRACTIVE` path remains honestly selectable and that
   an existing generative run is never relabeled or downgraded.

Raw benchmark, telemetry, scanner and packet-capture evidence follows the
customer-controlled evidence-vault and signed/sanitized release-verdict rules in
`docs/LIVE_SYSTEM_DOD.md`. The release bundle receives exact digests and signed
verdicts, not prompts or customer content.

## 4. Accepted design invariant and proof inventory

These identifiers are reserved by this accepted design. They become
guardrail/test identifiers only in a later accepted atomic delivery package;
their presence here is not a delivery claim.

| Accepted design invariant | Required proof IDs |
| --- | --- |
| `MRP-001` every model call enters one exact-profile Model Gateway authority | `architecture.model.single-gateway`, `mutation.model.direct-runtime-call` |
| `MRP-002` discovery labels never activate models and all executable artifacts exact-match locks/AIBOM | `architecture.model.deferred-candidate`, `mutation.model.mutable-alias`, `acceptance.model.offline-hash-recompute` |
| `MRP-003` local KnowVault GPU use is <=6144 MiB with global concurrency one and explicit headroom | `acceptance.model.gpu-peak`, `acceptance.model.gpu-contention`, `mutation.model.gpu-cap-plus-one` |
| `MRP-004` no auto-eviction, auto-start, spill or silent model/device fallback occurs | `acceptance.model.insufficient-headroom`, `mutation.model.fallback-route`, `acceptance.model.foreign-process-preserved` |
| `MRP-005` generation uses one exact local pinned or customer-controlled on-prem profile; remote use is authenticated TLS with bounded 24k Evidence input/output/attempts | `acceptance.model.remote-trust-auth`, `acceptance.model.context-cap-plus-one`, `mutation.model.remote-downgrade` |
| `MRP-006` semantic verifier is a separately qualified text-only different-family profile | `architecture.model.generator-verifier-independence`, `acceptance.model.projector-absent`, `mutation.model.verifier-generator-reuse` |
| `MRP-007` active embedding/reranker profiles pass frozen RU/EN quality and vector-space contracts | `acceptance.search.bilingual-recall-ndcg`, `mutation.search.embedding-dimension-adapter`, `architecture.model.reranker-real-artifact` |
| `MRP-008` model failure never publishes unverified output or relabels GENERATIVE as EXTRACTIVE | `acceptance.model.verifier-outage`, `mutation.model.mode-downgrade`, `contract.manifest.unverified-completed` |
| `MRP-009` model input, queues and caches are exact organization/workspace/run bound | `acceptance.model.multiworkspace-isolation`, `mutation.model.cross-tenant-batch`, `acceptance.model.revocation-race` |
| `MRP-010` configured capability readiness includes trust, artifact, resource and dependency state | `operator.model.capability-readiness`, `mutation.model.liveness-as-readiness`, `acceptance.model.circuit-readiness` |
| `MRP-011` model observability is content-free and low-cardinality | `acceptance.model.telemetry-canary`, `mutation.model.prompt-logging`, `contract.model.metric-labels` |
| `MRP-012` scheduling and retries are bounded, fair, preplanned and durably attributable | `acceptance.model.queue-fairness`, `mutation.model.hidden-retry`, `acceptance.model.crash-attempt-reconcile` |
| `MRP-013` the remote Qwen candidate is eligible only as an exact customer-owned/customer-operated on-prem peer inside the declared deployment perimeter, reached solely by Model Gateway mTLS with dedicated model trust/identity mounts and no direct adapter | `architecture.model.remote-customer-perimeter`, `acceptance.model.remote-unauthorized-client`, `acceptance.model.remote-wrong-ca-hostname`, `acceptance.model.remote-runtime-model-digest`, `acceptance.model.remote-gateway-bypass` |
| `MRP-014` the remote inference host has deny-all new outbound egress, including DNS, and cannot deliver telemetry, training or log-forwarding canaries outside explicitly pinned local dependencies | `acceptance.model.remote-egress-deny`, `mutation.model.remote-egress-policy`, `acceptance.model.remote-canary-sinks` |
| `MRP-015` remote model data is encrypted until the trusted gateway, decrypted bounded prompts are memory-only and best-effort zeroed, and the peer has no technical logging, retention, forwarding, training or cross-tenant cache path | `acceptance.model.remote-encrypted-memory-boundary`, `acceptance.model.remote-data-boundary`, `acceptance.model.remote-retention-restart`, `acceptance.model.remote-cache-workspace`, `mutation.model.remote-prompt-retention` |

## 5. Explicit non-goals

- No mock, fake, stub, replay, heuristic answerer or no-op reranker counts as a
  production path or live acceptance proof.
- No natural-language-to-SQL, model tool, source access, arbitrary URL fetch,
  Internet search, agent loop, conversation memory or fine-tuning on customer
  data is introduced.
- No model is selected because it is already installed, fits a marketing
  context length or responds to an unauthenticated discovery request.
- No local Qwen candidate is a standby for the remote generator; no generator
  is a standby for the verifier; no English-only embedder is a bilingual
  default.
- No vision workload/projector, speculative multi-model race, autoscaling that
  assumes another GPU, or cross-tenant continuous batching is authorized.
- This ADR does not choose the exact remote serving protocol, llama.cpp/vLLM
  build, model revision, quantization, reranker, driver/container mechanism or
  benchmark thresholds not already fixed by an accepted contract. Those become
  exact only in the reviewed qualification and version-lock package.

## 6. Alternatives considered

| Alternative | Why not selected |
| --- | --- |
| Run the primary generator on the shared local GPU | The observed RTX 4070 has only 3079 MiB free at the probe instant; competing with development violates the coexistence and 6144 MiB ceiling. |
| Automatically unload development models for KnowVault | KnowVault has no authority to disrupt other work, and eviction makes capacity and latency nondeterministic. |
| Fall back from remote generation to local Qwen/Gemma | Changes the signed model profile, quality and security boundary and can publish an answer that was never qualified. |
| Use the same Qwen family for generation and verification | Correlated failure weakens semantic verification; the selected design requires an independently qualified different family. |
| Use Qwen VL with its projector for text | It consumes unnecessary resources and expands the input/decoder attack surface without a product requirement. |
| Use `bge-small-en` for all embeddings | An English-oriented discovery candidate has no accepted evidence for the required RU/EN corpus. |
| Omit reranking until a model is found | The accepted Stage 3 design and manifest require a real reranking profile; a pass-through would be a prohibited stub. |
| On model outage silently return an extractive answer | It changes immutable run semantics and misrepresents the requested and signed answer mode. |

## 7. Governance and delivery status

Governance has four separate decisions. First, owner acceptance authorizes this
bounded design and its protected HLD/Trust Boundary/DoD amendments; it does not
select an executable artifact, qualify a model/runtime, activate a capability,
or advance delivery. Second, a later qualification package must freeze the
exact artifacts, runtime/image, licenses, AIBOM, profiles, hardware/reference
workload, customer perimeter and peer trust/egress configuration and add them
atomically to the protected locks/contracts. If a selected embedding is not
1024-dimensional, an explicit accepted schema/index migration precedes
activation. Third, the implementation and delivery package must provide the
Model Gateway, scheduling, admission, encrypted artifacts, readiness,
content-free telemetry and all real tests without changing the Stage 3 → Stage
4 → Stage 6 order or bypassing any R/P gate in `docs/IMPLEMENTATION_PLAN.md` and
`docs/DELIVERY_STATE.md`. Fourth, only an owner-recorded activation after the
exact candidate passes `docs/LIVE_SYSTEM_DOD.md` and every applicable remote-peer
gate may advertise a model capability or advance delivery state. Merge, service
reachability and a green unit test are not activation.

## 8. Delivery status

This is an accepted design only. Model/runtime capabilities remain
**`DEFERRED`**, inert, not implemented, not qualified and not active; the
observed GPU snapshot, discovered labels and private-network candidate are
inventory evidence only. `architecture/versions.json` and `DELIVERY_STATE.md`
remain unchanged. No stage or gate is complete because of this ADR, and no
qualification, activation, delivery or release PASS is implied.
