\set ON_ERROR_STOP on

INSERT INTO scientific_event (
  event_id,
  event_type,
  schema_version,
  aggregate_type,
  aggregate_id,
  aggregate_version,
  occurred_at,
  ingested_at,
  tenant_id,
  payload,
  payload_sha256,
  signature
)
VALUES (
  '00000000-0000-4000-8000-000000000001',
  'decision.recorded',
  '2',
  'decision',
  'fixture-decision',
  42,
  '2026-01-02 03:04:05+00',
  '2026-01-02 03:04:06+00',
  'tenant-fixture',
  '{"decision_id":"fixture-decision","status":"approved"}'::jsonb,
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  '{"alg":"Ed25519","key_id":"fixture-key","value":"fixture-signature"}'::jsonb
);
