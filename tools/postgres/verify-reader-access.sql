SET TIME ZONE 'UTC';
SET statement_timeout = '60s';
SET lock_timeout = '10s';
SET idle_in_transaction_session_timeout = '60s';

\set ON_ERROR_STOP off
SET ROLE bioworld_owner;
\set owner_role_sqlstate :SQLSTATE
SET ROLE bioworld_migrator;
\set migrator_role_sqlstate :SQLSTATE
SET ROLE bioworld_writer;
\set writer_role_sqlstate :SQLSTATE
\set ON_ERROR_STOP on

SELECT
  :'owner_role_sqlstate' = '42501'
  AND :'migrator_role_sqlstate' = '42501'
  AND :'writer_role_sqlstate' = '42501'
  AS role_transition_denied
\gset

\if :role_transition_denied
\else
\quit 3
\endif

DO $reader_contract$
DECLARE
  event_table oid := pg_catalog.to_regclass('public.scientific_event');
  object_count bigint;
  reader_id oid;
  visible_rows bigint;
BEGIN
  IF current_user <> 'bioworld_reader'
    OR session_user <> 'bioworld_reader'
  THEN
    RAISE EXCEPTION 'reader checks must run as bioworld_reader';
  END IF;

  SELECT oid INTO reader_id
  FROM pg_catalog.pg_roles
  WHERE rolname = 'bioworld_reader'
    AND rolcanlogin
    AND NOT rolsuper
    AND NOT rolcreatedb
    AND NOT rolcreaterole
    AND NOT rolinherit
    AND NOT rolreplication
    AND NOT rolbypassrls;

  IF reader_id IS NULL THEN
    RAISE EXCEPTION 'reader role attributes differ from contract';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members
    WHERE member = reader_id OR roleid = reader_id
  ) THEN
    RAISE EXCEPTION 'reader role must have no memberships';
  END IF;

  IF pg_catalog.current_setting('search_path') <> 'pg_catalog' THEN
    RAISE EXCEPTION 'reader search_path is not hardened';
  END IF;

  IF NOT pg_catalog.has_database_privilege(
    current_user,
    current_database(),
    'CONNECT'
  ) OR pg_catalog.has_database_privilege(
    current_user,
    current_database(),
    'CREATE'
  ) OR pg_catalog.has_database_privilege(
    current_user,
    current_database(),
    'TEMP'
  ) THEN
    RAISE EXCEPTION 'reader database privileges differ from contract';
  END IF;

  IF NOT pg_catalog.has_schema_privilege(current_user, 'public', 'USAGE')
    OR pg_catalog.has_schema_privilege(current_user, 'public', 'CREATE')
  THEN
    RAISE EXCEPTION 'reader schema privileges differ from contract';
  END IF;

  IF NOT pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'SELECT'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'INSERT'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'UPDATE'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'DELETE'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'TRUNCATE'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'REFERENCES'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'TRIGGER'
  ) OR pg_catalog.has_table_privilege(
    current_user,
    'public.scientific_event',
    'MAINTAIN'
  ) THEN
    RAISE EXCEPTION 'reader table privileges differ from contract';
  END IF;

  SELECT count(*) INTO object_count
  FROM pg_catalog.pg_class AS relation
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    COALESCE(
      relation.relacl,
      pg_catalog.acldefault('r', relation.relowner)
    )
  ) AS privilege
  WHERE relation.oid = event_table
    AND privilege.grantee = reader_id
    AND privilege.privilege_type = 'SELECT';

  IF object_count <> 1 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class AS relation
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        relation.relacl,
        pg_catalog.acldefault('r', relation.relowner)
      )
    ) AS privilege
    WHERE relation.oid = event_table
      AND privilege.grantee = reader_id
      AND privilege.privilege_type <> 'SELECT'
  ) THEN
    RAISE EXCEPTION 'reader direct table grants differ from contract';
  END IF;

  IF pg_catalog.has_function_privilege(
    current_user,
    'public.reject_scientific_event_mutation()',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'reader can execute mutation trigger function';
  END IF;

  IF event_table IS NULL OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_class
    WHERE oid = event_table
      AND relrowsecurity
      AND relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'reader table RLS is not enabled and forced';
  END IF;

  IF NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'fresh reader session retained tenant context';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'reader without tenant context can read rows';
  END IF;

  BEGIN
    EXECUTE 'CREATE SCHEMA reader_escape';
    RAISE EXCEPTION 'reader CREATE SCHEMA was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    EXECUTE 'CREATE TEMP TABLE reader_escape (value integer)';
    RAISE EXCEPTION 'reader CREATE TEMP TABLE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    EXECUTE
      'ALTER TABLE public.scientific_event ADD COLUMN reader_escape integer';
    RAISE EXCEPTION 'reader ALTER TABLE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;
END
$reader_contract$;

BEGIN;

DO $tenant_read_contract$
DECLARE
  visible_rows bigint;
BEGIN
  PERFORM pg_catalog.set_config(
    'bioworld.tenant_id',
    'tenant-fixture',
    true
  );

  SELECT count(*) INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-fixture'
    AND event_id = '00000000-0000-4000-8000-000000000001';

  IF visible_rows <> 1 THEN
    RAISE EXCEPTION 'reader cannot read its selected tenant';
  END IF;

  PERFORM pg_catalog.set_config(
    'bioworld.tenant_id',
    'tenant-reader-hidden',
    true
  );

  SELECT count(*) INTO visible_rows
  FROM public.scientific_event
  WHERE tenant_id = 'tenant-fixture';

  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'reader can read another tenant';
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
      '00000000-0000-4000-8000-000000000130',
      'decision.recorded',
      '2',
      'decision',
      'reader-write',
      1,
      '2026-01-02 03:04:05+00',
      'tenant-reader-hidden',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'reader INSERT was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    UPDATE public.scientific_event
    SET event_type = 'decision.changed';
    RAISE EXCEPTION 'reader UPDATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    DELETE FROM public.scientific_event;
    RAISE EXCEPTION 'reader DELETE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;

  BEGIN
    TRUNCATE TABLE public.scientific_event;
    RAISE EXCEPTION 'reader TRUNCATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '42501' THEN NULL;
  END;
END
$tenant_read_contract$;

COMMIT;

DO $commit_reset$
DECLARE
  visible_rows bigint;
BEGIN
  IF NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'reader tenant context survived commit';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'reader tenant context leaked after commit';
  END IF;
END
$commit_reset$;

BEGIN;

DO $rollback_context$
BEGIN
  PERFORM pg_catalog.set_config(
    'bioworld.tenant_id',
    'tenant-fixture',
    true
  );
END
$rollback_context$;

ROLLBACK;

DO $rollback_reset$
DECLARE
  visible_rows bigint;
BEGIN
  IF NULLIF(
    pg_catalog.current_setting('bioworld.tenant_id', true),
    ''
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'reader tenant context survived rollback';
  END IF;

  SELECT count(*) INTO visible_rows FROM public.scientific_event;
  IF visible_rows <> 0 THEN
    RAISE EXCEPTION 'reader tenant context leaked after rollback';
  END IF;
END
$rollback_reset$;

SELECT 'bioworld_reader_access_ready';
