SET TIME ZONE 'UTC';
SET statement_timeout = '60s';
SET lock_timeout = '10s';
SET idle_in_transaction_session_timeout = '60s';

\set ON_ERROR_STOP off
SET ROLE bioworld_owner;
\set owner_role_sqlstate :SQLSTATE
SET ROLE bioworld_migrator;
\set migrator_role_sqlstate :SQLSTATE
\set ON_ERROR_STOP on

SELECT
  :'owner_role_sqlstate' = '42501'
  AND :'migrator_role_sqlstate' = '42501'
  AS role_transition_denied
\gset

\if :role_transition_denied
\else
\quit 3
\endif

DO $session_contract$
DECLARE
  visible_rows bigint;
BEGIN
  IF current_user <> 'bioworld_writer' OR session_user <> 'bioworld_writer' THEN
    RAISE EXCEPTION 'tenant checks must run as bioworld_writer';
  END IF;

  IF current_setting('search_path') <> 'pg_catalog' THEN
    RAISE EXCEPTION 'writer search_path is not hardened';
  END IF;

  IF NOT has_schema_privilege(current_user, 'public', 'USAGE')
    OR has_schema_privilege(current_user, 'public', 'CREATE')
  THEN
    RAISE EXCEPTION 'writer schema privileges differ from contract';
  END IF;

  IF NOT has_table_privilege(current_user, 'public.scientific_event', 'SELECT')
    OR NOT has_table_privilege(current_user, 'public.scientific_event', 'INSERT')
  THEN
    RAISE EXCEPTION 'writer read or insert privilege is missing';
  END IF;

  IF has_table_privilege(current_user, 'public.scientific_event', 'UPDATE')
    OR has_table_privilege(current_user, 'public.scientific_event', 'DELETE')
    OR has_table_privilege(current_user, 'public.scientific_event', 'TRUNCATE')
    OR has_table_privilege(current_user, 'public.scientific_event', 'REFERENCES')
    OR has_table_privilege(current_user, 'public.scientific_event', 'TRIGGER')
    OR has_table_privilege(current_user, 'public.scientific_event', 'MAINTAIN')
  THEN
    RAISE EXCEPTION 'writer mutation privileges exceed contract';
  END IF;

  IF NULLIF(current_setting('bioworld.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'fresh writer session retained tenant context';
  END IF;

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event;

  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'writer without tenant context can read rows';
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
      '00000000-0000-4000-8000-000000000100',
      'decision.recorded',
      '2',
      'decision',
      'missing-tenant-context',
      1,
      '2026-01-02 03:04:05+00',
      'tenant-a',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'writer inserted without tenant context';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    EXECUTE 'CREATE SCHEMA writer_escape';
    RAISE EXCEPTION 'writer CREATE SCHEMA was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    EXECUTE 'CREATE TEMP TABLE writer_escape (value integer)';
    RAISE EXCEPTION 'writer CREATE TEMP TABLE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    EXECUTE
      'ALTER TABLE public.scientific_event ADD COLUMN writer_escape integer';
    RAISE EXCEPTION 'writer ALTER TABLE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;
END
$session_contract$;

BEGIN;

DO $tenant_a_insert$
BEGIN
  PERFORM pg_catalog.set_config('bioworld.tenant_id', 'tenant-a', true);

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
    '00000000-0000-4000-8000-000000000110',
    'decision.recorded',
    '2',
    'decision',
    'tenant-a-event',
    1,
    '2026-01-02 03:04:05+00',
    'tenant-a',
    '{"status":"approved"}'::jsonb,
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '{"alg":"Ed25519"}'::jsonb
  );
END
$tenant_a_insert$;

COMMIT;

DO $commit_reset$
DECLARE
  visible_rows bigint;
BEGIN
  IF NULLIF(current_setting('bioworld.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'tenant context survived commit';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'committed tenant context leaked into pooled session';
  END IF;
END
$commit_reset$;

BEGIN;

DO $tenant_b_insert$
DECLARE
  visible_rows bigint;
BEGIN
  PERFORM pg_catalog.set_config('bioworld.tenant_id', 'tenant-b', true);

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
    '00000000-0000-4000-8000-000000000110',
    'decision.recorded',
    '2',
    'decision',
    'tenant-b-event',
    1,
    '2026-01-02 03:04:05+00',
    'tenant-b',
    '{"status":"approved"}'::jsonb,
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '{"alg":"Ed25519"}'::jsonb
  );

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-b'
    AND event_id = '00000000-0000-4000-8000-000000000110';

  IF visible_rows <> 1 THEN
    RAISE EXCEPTION 'tenant B row is not visible';
  END IF;

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-a';

  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'tenant B can read tenant A rows';
  END IF;
END
$tenant_b_insert$;

COMMIT;

BEGIN;

DO $tenant_a_isolation$
DECLARE
  visible_rows bigint;
BEGIN
  PERFORM pg_catalog.set_config('bioworld.tenant_id', 'tenant-a', true);

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-a'
    AND event_id = '00000000-0000-4000-8000-000000000110';

  IF visible_rows <> 1 THEN
    RAISE EXCEPTION 'tenant A row is not visible';
  END IF;

  SELECT count(*)
  INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-b';

  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'tenant A can read tenant B rows';
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
      '00000000-0000-4000-8000-000000000111',
      'decision.recorded',
      '2',
      'decision',
      'cross-tenant-write',
      1,
      '2026-01-02 03:04:05+00',
      'tenant-b',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'tenant A inserted a tenant B row';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

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
      '00000000-0000-4000-8000-000000000110',
      'decision.recorded',
      '2',
      'decision',
      'tenant-a-duplicate-event-id',
      2,
      '2026-01-02 03:04:05+00',
      'tenant-a',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'same-tenant duplicate event ID was accepted';
  EXCEPTION
    WHEN SQLSTATE '23505' THEN NULL;
  END;

  BEGIN
    UPDATE public.scientific_event
    SET event_type = 'decision.changed'
    WHERE tenant_id = 'tenant-a';
    RAISE EXCEPTION 'writer UPDATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    DELETE FROM public.scientific_event
    WHERE tenant_id = 'tenant-a';
    RAISE EXCEPTION 'writer DELETE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    TRUNCATE TABLE public.scientific_event;
    RAISE EXCEPTION 'writer TRUNCATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;
END
$tenant_a_isolation$;

ROLLBACK;

DO $rollback_reset$
DECLARE
  visible_rows bigint;
BEGIN
  IF NULLIF(current_setting('bioworld.tenant_id', true), '') IS NOT NULL THEN
    RAISE EXCEPTION 'tenant context survived rollback';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'rolled-back tenant context leaked into pooled session';
  END IF;
END
$rollback_reset$;

SELECT 'bioworld_tenant_access_ready';
