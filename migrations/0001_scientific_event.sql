CREATE TABLE scientific_event (
  event_id uuid PRIMARY KEY,
  event_type text NOT NULL,
  schema_version text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_id text NOT NULL,
  aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
  occurred_at timestamptz NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  tenant_id text NOT NULL,
  payload jsonb NOT NULL,
  payload_sha256 char(64) NOT NULL,
  signature jsonb NOT NULL,
  UNIQUE (tenant_id, aggregate_type, aggregate_id, aggregate_version)
);

REVOKE UPDATE, DELETE ON scientific_event FROM PUBLIC;
