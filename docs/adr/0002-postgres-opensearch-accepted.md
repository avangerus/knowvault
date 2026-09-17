# ADR-0002: PostgreSQL + OpenSearch

Status: `ACCEPTED`

## Solution

PostgreSQL stores control data, evidence metadata/text, immutable Question Runs, jobs, outbox, and audit. OpenSearch is the sole lexical/vector index and stores active Evidence/Search Chunks with embeddings of dimension 1024.

Workspace is a server-built filter over the organization index, not a separate physical index or copy of vectors.

## Why

- one engine for BM25, vector search, and metadata filters;
- PostgreSQL provides transactions, constraints, and RLS;
- no second vector store is needed;
- deletion and ACL can be handled in PostgreSQL prior to eventual OpenSearch cleanup.

## Consequences

OpenSearch never makes the final access decision. Every retrieval hit undergoes PostgreSQL post-authorization.

