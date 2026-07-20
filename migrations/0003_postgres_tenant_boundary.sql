SET LOCAL search_path = pg_catalog;

-- bioworld.tenant_id is trusted transaction context. A principal allowed
-- arbitrary SQL can choose it and is outside this database access boundary.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON TABLE public.scientific_event FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reject_scientific_event_mutation() FROM PUBLIC;

ALTER FUNCTION public.reject_scientific_event_mutation()
  SET search_path = pg_catalog;

ALTER TABLE public.scientific_event
  DROP CONSTRAINT scientific_event_pkey,
  ADD CONSTRAINT scientific_event_pkey PRIMARY KEY (tenant_id, event_id);

ALTER TABLE public.scientific_event
  RENAME CONSTRAINT scientific_event_tenant_id_aggregate_type_aggregate_id_aggr_key
  TO scientific_event_stream_version_key;

ALTER TABLE public.scientific_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scientific_event FORCE ROW LEVEL SECURITY;

CREATE POLICY scientific_event_tenant_fence
ON public.scientific_event
AS RESTRICTIVE
FOR ALL
TO PUBLIC
USING (
  tenant_id = NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  )
)
WITH CHECK (
  tenant_id = NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  )
);

CREATE POLICY scientific_event_tenant_select
ON public.scientific_event
AS PERMISSIVE
FOR SELECT
TO PUBLIC
USING (
  tenant_id = NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  )
);

CREATE POLICY scientific_event_tenant_insert
ON public.scientific_event
AS PERMISSIVE
FOR INSERT
TO PUBLIC
WITH CHECK (
  tenant_id = NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  )
);
