# Reranking

KnowVault separates three model roles and never lets one stand in for another:

- the **answering model** reads addresses and decides what they mean;
- the **embedding model** serves the vector channel of hybrid search;
- the **ranking (reranking) model** re-orders an already-authorized candidate set.

The reranker **does** receive the original query and the authorized candidate
text, and returns **scores** — never an answer. It re-orders only what the
product is already allowed to return.

## Pipeline

1. **Lexical + semantic fusion.** A lexical channel and a vector channel each
   apply the workspace, the rights-bearing scope and the current-version state
   *inside* their own query, then fuse by reciprocal-rank fusion (`rrf`, `k`).
2. **Live authorization.** Every fused survivor is re-authorized against the
   live rights context before candidate selection. Rights can be revoked at any
   time, including during the final readback, so a page may shrink.
3. **Bounded neural rerank.** Authorized candidates are re-scored by the
   mounted reranker, within a fixed work budget.
4. **Pagination.** The reranked order is paged; scores remain the original
   channel/fusion scores, and copy deferral is deterministic.
5. **Evidence.** Each hit returns an immutable address, excerpt and score, plus
   the profile that actually ran. The answer is built from addresses, not
   definitions the product invented.

## Budgets and representation

- At most **32** units are reranked before pagination. The remaining candidates
  keep their baseline order; equal scores keep the previous order.
- The **512** figure is the combined grouped-evidence read budget: probes,
  full-member ranking preparation and the final readback — not a budget spread
  across all lexical, vector and term channels.
- The reranker scores a **SQL-joined, ordered, authorized** field projection,
  subject to a **client 8 KiB per-text** limit and a model truncate of **8192
  tokens**. This is not full-corpus completeness and not unconditional full
  text.

## Profile metadata

Every result carries the retrieval profile so a measurement run never assumes
which algorithm produced a score:

- `reranker` — true only after an actual successful inference.
- `reranker_model_id`, `reranker_profile_hash`, `reranker_candidates`,
  `reranker_representation` — the exact configured identity; present when a
  reranker is configured and also retained after a runtime failure.
- `degraded` / `reranker_degraded` — visible fallback: a mounted reranker that
  could not answer reports `reranker=false`, `degraded=true`,
  `reranker_degraded=true` rather than reading as a reranked answer.

The projection is metadata only: no candidate text, no endpoints, no
credentials. Exhaustive totals are never produced.

## Operator mount

- Fixed mount root `/run/knowvault/reranking`, directory `0750`, gid `65532`;
  files `0440`.
- Served over **mTLS**; the profile is **immutable** at runtime.
- An **optional** reranker that is absent is a valid configuration; a reranker
  that is present but **malformed** is a **startup failure**.

Server wiring is accepted without a reindex for a reranker change.

## Qualification status

- `compose.reranking.yaml` is a **candidate** overlay with qualification limits
  until the runtime is qualified; it is not a supported default.
- The candidate model is **BAAI/bge-reranker-v2-m3** (Apache-2.0) served by
  **TEI** on CPU 1.6 with an **8192**-token context — not 512.
- A bounded CPU probe used two CPUs and a 4 GiB container limit. Three
  32-candidate requests took about **3 seconds** each; peak memory was
  **2.62 GiB**. This is a synthetic probe, not a customer SLA or concurrency
  qualification.
- Russian and English relevance probes selected the expected first result.
  A SQL-like hard-negative case did **not**: an example outranked the requested
  active contract. Reranking does not enforce business predicates, establish
  authoritative records, or prove an exhaustive count. Read and compare the
  returned evidence before answering those questions.

See the [model card](https://huggingface.co/BAAI/bge-reranker-v2-m3) for the
upstream model and license. The pinned revision and file hashes are recorded
in `deploy/compose/reranking-profile.json` and `reranking-runtime.json`.
