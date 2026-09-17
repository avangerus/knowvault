-- 000102: resolve active source objects from a workspace-bound source scope
-- before scanning their current structured snapshot cells. The existing
-- source_object_scope primary key is object-first; this additive partial
-- lookup follows the scoped rowset query's tenant/scope/revision fence.
--
-- This index changes only lookup order. RLS, workspace binding checks,
-- source-object current-version checks, evidence readability, audit admission
-- and rowset matched/full semantics remain enforced by the caller/query.

BEGIN;

CREATE INDEX source_object_scope_active_scope_lookup
    ON public.source_object_scope
        (organization_id, source_scope_id, source_scope_revision, source_object_id)
    WHERE membership_state = 'ACTIVE';

COMMIT;
