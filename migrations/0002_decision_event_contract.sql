ALTER TABLE scientific_event
  DROP CONSTRAINT scientific_event_aggregate_version_check,
  ALTER COLUMN aggregate_version TYPE numeric
    USING aggregate_version::numeric,
  ALTER COLUMN payload_sha256 TYPE text
    USING btrim(payload_sha256),
  ADD CONSTRAINT scientific_event_aggregate_version_u64_check
    CHECK (
      aggregate_version >= 1
      AND aggregate_version <= 18446744073709551615
      AND aggregate_version = trunc(aggregate_version)
    ),
  ADD CONSTRAINT scientific_event_tenant_id_check
    CHECK (
      tenant_id <> ''
      AND tenant_id = btrim(
        tenant_id,
        U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'
      )
    ),
  ADD CONSTRAINT scientific_event_payload_sha256_check
    CHECK ((payload_sha256 COLLATE "C") ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT scientific_event_signature_check
    CHECK (
      jsonb_typeof(signature) = 'object'
      AND signature <> '{}'::jsonb
    );

CREATE FUNCTION reject_scientific_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'scientific_event is append-only'
    USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER scientific_event_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON scientific_event
FOR EACH STATEMENT
EXECUTE FUNCTION reject_scientific_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON scientific_event FROM PUBLIC;
