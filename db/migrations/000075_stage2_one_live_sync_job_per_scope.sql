-- Review remark Z5: "one live activation job per scope" was enforced only by
-- a SELECT of a live job taken immediately before the enqueue
-- (internal/source/registration.Service.Activate / Sync / autoSyncOne). Under
-- READ COMMITTED two concurrent :activate calls both read "no live job" and
-- both enqueue, so a scope could hold two live sync jobs and be published
-- twice concurrently. A predicate read is not a uniqueness guarantee; only the
-- database can be.
--
-- The guarantee is scoped to the operator-facing activation authority, which
-- is what the remark is about and the only writer that promises it. That
-- service now marks every scope-sync job it queues with the existing closed
-- payload key operation = 'ACTIVATE' (000013's job_payload_is_safe already
-- admits exactly this value, so no payload vocabulary changes), and the
-- partial unique index below admits at most one live such job per
-- (organization, source scope).
--
-- The queue keeps its own contract unchanged: worker-internal recovery --
-- crash resume and stale-lease fencing -- legitimately queues fresh work for a
-- scope whose previous unit of work is still live, and those enqueues carry no
-- operation marker, so they stay outside the predicate. Constraining them
-- would turn crash recovery into a permanent refusal, a strictly worse failure
-- than the race being closed here.

BEGIN;

CREATE UNIQUE INDEX job_one_live_activation_per_scope
    ON public.job (organization_id, (payload_json ->> 'source_scope_id'))
    WHERE payload_json ->> 'operation' = 'ACTIVATE'
      AND payload_json ? 'source_scope_id'
      AND status IN ('PENDING', 'RUNNING');

COMMIT;
