SET LOCAL search_path = pg_catalog;

ALTER TABLE public.scientific_event
  ADD CONSTRAINT scientific_event_tenant_id_bytes_check
    CHECK (octet_length(tenant_id) <= 128) NOT VALID,
  ADD CONSTRAINT scientific_event_event_type_envelope_check
    CHECK (char_length(event_type) <= 200 AND octet_length(event_type) <= 800) NOT VALID,
  ADD CONSTRAINT scientific_event_schema_version_envelope_check
    CHECK (char_length(schema_version) <= 200 AND octet_length(schema_version) <= 800) NOT VALID,
  ADD CONSTRAINT scientific_event_aggregate_type_envelope_check
    CHECK (char_length(aggregate_type) <= 200 AND octet_length(aggregate_type) <= 800) NOT VALID,
  ADD CONSTRAINT scientific_event_aggregate_id_envelope_check
    CHECK (char_length(aggregate_id) <= 200 AND octet_length(aggregate_id) <= 800) NOT VALID,
  ADD CONSTRAINT scientific_event_payload_bytes_check
    CHECK (octet_length(payload::text) <= 524288) NOT VALID,
  ADD CONSTRAINT scientific_event_signature_bytes_check
    CHECK (octet_length(signature::text) <= 20480) NOT VALID;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_tenant_id_bytes_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_event_type_envelope_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_schema_version_envelope_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_aggregate_type_envelope_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_aggregate_id_envelope_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_payload_bytes_check;

ALTER TABLE public.scientific_event
  VALIDATE CONSTRAINT scientific_event_signature_bytes_check;
