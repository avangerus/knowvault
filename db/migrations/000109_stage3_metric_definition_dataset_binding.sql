-- R1-C2.6b-2a: additive nullable DatasetBinding storage.
BEGIN;
ALTER TABLE public.metric_definition_version
    ADD COLUMN dataset_id text,
    ADD COLUMN profile_version bigint,
    ADD COLUMN profile_hash text,
    ADD COLUMN measure_id text,
    ADD COLUMN execution_mode text;

-- Strict binding label validator. Unlike the historical app.stage2_opaque_id_is_valid
-- (char_length + ASCII btrim + POSIX cntrl), this proves the exact Go metricdef.validLabel
-- contract: non-empty, at most 256 octets, Go strings.TrimSpace == value, and no C0/C1
-- control code points anywhere. PostgreSQL UTF8 text already supplies valid UTF-8, so the
-- remaining Go clauses are octet length, an explicit two-sided trim set, and controls.
-- Immutable and STRICT so it can be used in a CHECK constraint. The historical helper is
-- deliberately left untouched. U& literals hold the exact Go TrimSpace code point set.
CREATE FUNCTION app.metric_definition_binding_label_is_valid(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT value <> ''
       AND octet_length(value) <= 256
       AND value = btrim(value, U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')
       AND value !~ U&'[\0001-\001F\007F-\009F]';
$$;

ALTER TABLE public.metric_definition_version
    ADD CONSTRAINT metric_definition_version_dataset_binding_shape CHECK (
        (dataset_id IS NULL AND profile_version IS NULL AND profile_hash IS NULL
         AND measure_id IS NULL AND execution_mode IS NULL)
        OR
        (dataset_id IS NOT NULL
         AND profile_version IS NOT NULL
         AND profile_hash IS NOT NULL
         AND measure_id IS NOT NULL
         AND execution_mode IS NOT NULL
         AND app.metric_definition_binding_label_is_valid(dataset_id)
         AND profile_version BETWEEN 1 AND 9007199254740991
         AND app.stage2_sha256_is_valid(profile_hash)
         AND app.metric_definition_binding_label_is_valid(measure_id)
         AND execution_mode = 'LIVE')
    );
COMMIT;
