SET TIME ZONE 'UTC';
SET statement_timeout = '60s';
SET lock_timeout = '10s';
SET idle_in_transaction_session_timeout = '60s';

DO $migrator_contract$
BEGIN
  IF current_user <> 'bioworld_migrator'
    OR session_user <> 'bioworld_migrator'
  THEN
    RAISE EXCEPTION 'owner checks must start as bioworld_migrator';
  END IF;

  IF pg_catalog.pg_has_role(
    current_user,
    'bioworld_owner',
    'USAGE'
  ) OR NOT pg_catalog.pg_has_role(
    current_user,
    'bioworld_owner',
    'SET'
  ) THEN
    RAISE EXCEPTION 'migrator role transition differs from contract';
  END IF;
END
$migrator_contract$;

SET ROLE bioworld_owner;
SET search_path = pg_catalog;

DO $forced_rls_contract$
DECLARE
  visible_rows bigint;
BEGIN
  IF current_user <> 'bioworld_owner'
    OR session_user <> 'bioworld_migrator'
  THEN
    RAISE EXCEPTION 'migrator did not enter the owner role';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'forced RLS did not filter the table owner';
  END IF;

  BEGIN
    INSERT INTO public.scientific_event (
      event_id,
      event_type,
      schema_version,
      aggregate_type,
      aggregate_id,
      aggregate_version,
      occurred_at,
      tenant_id,
      payload,
      payload_sha256,
      signature
    )
    VALUES (
      '00000000-0000-4000-8000-000000000120',
      'decision.recorded',
      '2',
      'decision',
      'owner-missing-tenant',
      1,
      '2026-01-02 03:04:05+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'owner inserted without tenant context';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;
END
$forced_rls_contract$;

BEGIN;

DO $owner_mutation_contract$
DECLARE
  visible_rows bigint;
BEGIN
  PERFORM pg_catalog.set_config(
    'bioworld.tenant_id',
    'tenant-fixture',
    true
  );

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event
  WHERE event_id = '00000000-0000-4000-8000-000000000001';

  IF visible_rows <> 1 THEN
    RAISE EXCEPTION 'owner cannot read the selected tenant';
  END IF;

  BEGIN
    UPDATE public.scientific_event
    SET event_type = 'decision.changed'
    WHERE event_id = '00000000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'owner UPDATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;

  BEGIN
    DELETE FROM public.scientific_event
    WHERE event_id = '00000000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'owner DELETE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;

  BEGIN
    TRUNCATE TABLE public.scientific_event;
    RAISE EXCEPTION 'owner TRUNCATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;
END
$owner_mutation_contract$;

ROLLBACK;

DO $owner_reset_contract$
DECLARE
  visible_rows bigint;
BEGIN
  IF NULLIF(current_setting('bioworld.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'owner tenant context survived rollback';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'owner tenant context leaked after rollback';
  END IF;
END
$owner_reset_contract$;

SELECT 'bioworld_owner_boundary_ready';
