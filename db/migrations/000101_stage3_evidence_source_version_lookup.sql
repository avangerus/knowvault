-- 000101: inventory and authorization aggregate evidence fragments by the
-- tenant-scoped source_version_id.  The existing primary key and extraction
-- ordinal index do not support that predicate, so each page row can otherwise
-- rescan the complete evidence_fragment table.
--
-- This is an additive lookup index only.  It does not change RLS, grants,
-- artifact authorization, audit admission, pagination, or the evidence read
-- contract.  The leading organization_id preserves the tenant fence in the
-- same index lookup.

BEGIN;

CREATE INDEX evidence_fragment_source_version_lookup
    ON public.evidence_fragment (organization_id, source_version_id);

COMMIT;
