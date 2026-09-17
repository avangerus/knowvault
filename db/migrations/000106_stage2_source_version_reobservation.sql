-- Internal observation identities distinguish A -> B -> A without reviving a
-- SUPERSEDED version or changing any immutable content/provenance. Connector
-- input validators continue to accept only native/hash keys. The final token
-- identifies the previous CURRENT version, not a fabricated upstream version.
BEGIN;

CREATE OR REPLACE FUNCTION app.source_external_version_key_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value IS NOT NULL
       AND (value ~ '^native:[^[:cntrl:]]{1,248}$'
            OR value ~ '^hash:sha256:[0-9a-f]{64}$'
            OR value ~ '^observation:sha256:[0-9a-f]{64}:version_[0-9A-HJKMNP-TV-Z]{26}$');
$$;

COMMIT;
