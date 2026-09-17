# Native document ingestion

The pilot can extract readable text from supported DOCX documents and PDFs with
a text layer. Markdown and plain text remain the simplest source formats.
Scanned pages, OCR/VLM and Excel analysis are outside the pilot guarantee.
Conversion support must be checked on representative documents; a parser's
presence does not establish fidelity for every input.

## Runtime boundary

The ingestion worker submits document bytes through the existing dispatcher.
Apache POI and PDFBox run in isolated parser processes. The application worker
does not receive a container runtime, registration sockets or supervisor state,
and it has no in-process parser fallback.

The external Linux supervisor owns parser startup and the operating-system
resources. The dispatcher retains admission, deadline, resource-limit and
verified-exit authority. A successful process exit alone cannot authorize an
extraction result or removal of a sandbox's state. Runtime identity and limits
are pinned in the repository's deployment and supply-chain contracts.

Native extraction requires an explicitly provisioned host service and the
matching parser artifact. It is not enabled merely by starting the base Compose
stack. See the [supervisor installation contract](../deploy/supervisor/README.md),
[parser contracts](PARSER_CONTRACTS.md) and
[dependency lock](../architecture/versions.json).

## Operator activation

1. Prepare the reviewed parser artifact and verified root filesystem on a host
   satisfying the supervisor's Linux, systemd, pidfd and cgroup requirements.
   Install the matching supervisor and dispatcher configuration. Artifact,
   profile, identity or ownership mismatches must stop activation.
2. Verify the host service and both OFFICE and text-PDF registrations before
   enabling the worker. Keep parser processes isolated from source mounts,
   application secrets and network access.
3. Apply the [native-ingest overlay](../deploy/compose/native-ingest.yaml) with
   the corresponding deployment. It selects
   `KNOWVAULT_WORKER_NATIVE_PROFILE=document-parser-sandbox-v3` and mounts only
   the read-only submit directory into the worker. The default remains disabled.
4. Run `/knowvault-worker native-readiness` inside the configured worker
   environment. This content-free probe does not open the database, source
   documents or secret mounts. It requires both registered parser roles with
   the expected identity and unused capacity. Busy, missing, stopped, mismatched
   or rejected peers do not report ready.
5. Synchronize a small approved document collection. Inspect extraction status,
   visible skips, complete retained text and the returned version addresses
   before expanding the source scope.

Readiness is a point-in-time capacity check, not a reservation or a substitute
for per-job admission. Without the configured extractors, native formats are
reported as skipped. Enabling this profile does not enable OCR or rendering.

## Verify extraction and recovery

Use the [synthetic native fixture generator](../tools/native-ingest-fixture-seed.mjs)
or authored documents with known text. Compare the complete returned text,
paragraph/table boundaries and supported source locators, not only a search
snippet. Keep expected answers separate from all ingestible source roots.

Exercise malformed input, timeout, denied caller identity and service
interruption in an isolated environment. A failed or interrupted parse must not
publish a successful result. Check freshness and skips when an update cannot be
extracted. Follow the supervisor's incident procedure for retained runtime state;
do not delete that state merely to make startup succeed.

Host restart, recovery packaging and format fidelity need deployment-specific
verification. See [Worker operations](WORKER_OPERATIONS.md),
[Pilot acceptance](PILOT-ACCEPTANCE.md) and [Pilot status](PILOT-STATUS.md).
