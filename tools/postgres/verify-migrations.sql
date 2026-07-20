SET TIME ZONE 'UTC';
SET statement_timeout = '60s';
SET lock_timeout = '10s';
SET idle_in_transaction_session_timeout = '60s';

DO $catalog_checks$
DECLARE
  actual_types jsonb;
  expected_constraint text;
  object_count bigint;
BEGIN
  IF current_setting('server_version_num')::integer <> 180004 THEN
    RAISE EXCEPTION 'expected PostgreSQL server_version_num 180004, got %',
      current_setting('server_version_num');
  END IF;

  IF to_regclass('public.scientific_event') IS NULL THEN
    RAISE EXCEPTION 'public.scientific_event does not exist';
  END IF;

  SELECT jsonb_object_agg(attribute.attname, format_type(attribute.atttypid, attribute.atttypmod))
  INTO actual_types
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid = 'public.scientific_event'::regclass
    AND attribute.attnum > 0
    AND NOT attribute.attisdropped;

  IF actual_types IS DISTINCT FROM jsonb_build_object(
    'event_id', 'uuid',
    'event_type', 'text',
    'schema_version', 'text',
    'aggregate_type', 'text',
    'aggregate_id', 'text',
    'aggregate_version', 'numeric',
    'occurred_at', 'timestamp with time zone',
    'ingested_at', 'timestamp with time zone',
    'tenant_id', 'text',
    'payload', 'jsonb',
    'payload_sha256', 'text',
    'signature', 'jsonb'
  ) THEN
    RAISE EXCEPTION 'unexpected scientific_event column types: %', actual_types;
  END IF;

  FOREACH expected_constraint IN ARRAY ARRAY[
    'scientific_event_aggregate_version_u64_check',
    'scientific_event_tenant_id_check',
    'scientific_event_payload_sha256_check',
    'scientific_event_signature_check'
  ]
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_constraint AS constraint_definition
      WHERE constraint_definition.conrelid = 'public.scientific_event'::regclass
        AND constraint_definition.conname = expected_constraint
        AND constraint_definition.contype = 'c'
        AND constraint_definition.convalidated
    ) THEN
      RAISE EXCEPTION 'missing or unvalidated constraint: %', expected_constraint;
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_constraint AS constraint_definition
    WHERE constraint_definition.conrelid = 'public.scientific_event'::regclass
      AND constraint_definition.conname = 'scientific_event_aggregate_version_check'
  ) THEN
    RAISE EXCEPTION 'obsolete aggregate version constraint still exists';
  END IF;

  SELECT count(*)
  INTO object_count
  FROM pg_proc AS function_definition
  JOIN pg_namespace AS function_namespace
    ON function_namespace.oid = function_definition.pronamespace
  JOIN pg_language AS function_language
    ON function_language.oid = function_definition.prolang
  WHERE function_namespace.nspname = 'public'
    AND function_definition.proname = 'reject_scientific_event_mutation'
    AND pg_get_function_identity_arguments(function_definition.oid) = ''
    AND function_definition.prorettype = 'trigger'::regtype
    AND function_language.lanname = 'plpgsql';

  IF object_count <> 1 THEN
    RAISE EXCEPTION 'append-only trigger function is missing or invalid';
  END IF;

  SELECT count(*)
  INTO object_count
  FROM pg_trigger AS trigger_definition
  WHERE trigger_definition.tgrelid = 'public.scientific_event'::regclass
    AND trigger_definition.tgname = 'scientific_event_append_only'
    AND NOT trigger_definition.tgisinternal
    AND trigger_definition.tgenabled = 'O'
    AND trigger_definition.tgtype = 58
    AND trigger_definition.tgfoid =
      'public.reject_scientific_event_mutation()'::regprocedure;

  IF object_count <> 1 THEN
    RAISE EXCEPTION 'append-only trigger is missing or invalid';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(
      COALESCE(relation.relacl, acldefault('r', relation.relowner))
    ) AS privilege
    WHERE relation.oid = 'public.scientific_event'::regclass
      AND privilege.grantee = 0
      AND privilege.privilege_type IN ('UPDATE', 'DELETE', 'TRUNCATE')
  ) THEN
    RAISE EXCEPTION 'PUBLIC retains scientific_event mutation privileges';
  END IF;

  SELECT count(*)
  INTO object_count
  FROM scientific_event
  WHERE event_id = '00000000-0000-4000-8000-000000000001'
    AND event_type = 'decision.recorded'
    AND schema_version = '2'
    AND aggregate_type = 'decision'
    AND aggregate_id = 'fixture-decision'
    AND aggregate_version = 42
    AND occurred_at = '2026-01-02 03:04:05+00'::timestamptz
    AND ingested_at = '2026-01-02 03:04:06+00'::timestamptz
    AND tenant_id = 'tenant-fixture'
    AND payload = '{"decision_id":"fixture-decision","status":"approved"}'::jsonb
    AND payload_sha256 =
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    AND signature =
      '{"alg":"Ed25519","key_id":"fixture-key","value":"fixture-signature"}'::jsonb;

  IF object_count <> 1 THEN
    RAISE EXCEPTION 'migration 0001 fixture was not preserved by the upgrade';
  END IF;
END
$catalog_checks$;

DO $tenant_catalog_checks$
DECLARE
  event_table oid := to_regclass('public.scientific_event');
  expected_tenant_expression text :=
    '(tenant_id = NULLIF(current_setting(''bioworld.tenant_id''::text, true), ''''::text))';
  object_count bigint;
  primary_key_columns text[];
  stream_key_columns text[];
  owner_id oid;
  migrator_id oid;
  writer_id oid;
BEGIN
  SELECT oid INTO owner_id
  FROM pg_authid
  WHERE rolname = 'bioworld_owner'
    AND NOT rolcanlogin
    AND NOT rolsuper
    AND NOT rolcreatedb
    AND NOT rolcreaterole
    AND NOT rolinherit
    AND NOT rolreplication
    AND NOT rolbypassrls;

  SELECT oid INTO migrator_id
  FROM pg_authid
  WHERE rolname = 'bioworld_migrator'
    AND rolcanlogin
    AND NOT rolsuper
    AND NOT rolcreatedb
    AND NOT rolcreaterole
    AND NOT rolinherit
    AND NOT rolreplication
    AND NOT rolbypassrls;

  SELECT oid INTO writer_id
  FROM pg_authid
  WHERE rolname = 'bioworld_writer'
    AND rolcanlogin
    AND NOT rolsuper
    AND NOT rolcreatedb
    AND NOT rolcreaterole
    AND NOT rolinherit
    AND NOT rolreplication
    AND NOT rolbypassrls;

  IF owner_id IS NULL OR migrator_id IS NULL OR writer_id IS NULL THEN
    RAISE EXCEPTION 'database roles differ from contract';
  END IF;

  SELECT count(*) INTO object_count
  FROM pg_auth_members
  WHERE roleid = owner_id
    AND member = migrator_id
    AND NOT admin_option
    AND NOT inherit_option
    AND set_option;

  IF (object_count <> 1 OR EXISTS (
    SELECT 1
    FROM pg_auth_members
    WHERE member = writer_id
      AND roleid IN (owner_id, migrator_id)
  ) OR pg_has_role(writer_id, owner_id, 'SET')
    OR pg_has_role(writer_id, owner_id, 'USAGE')
    OR pg_has_role(writer_id, migrator_id, 'SET')
    OR pg_has_role(writer_id, migrator_id, 'USAGE')
  ) THEN
    RAISE EXCEPTION 'database role membership differs from contract';
  END IF;

  IF (
    SELECT datdba
    FROM pg_database
    WHERE datname = current_database()
  ) <> owner_id OR (
    SELECT nspowner
    FROM pg_namespace
    WHERE nspname = 'public'
  ) <> owner_id OR (
    SELECT relowner
    FROM pg_class
    WHERE oid = event_table
  ) <> owner_id OR (
    SELECT proowner
    FROM pg_proc
    WHERE oid = to_regprocedure('public.reject_scientific_event_mutation()')
  ) <> owner_id THEN
    RAISE EXCEPTION 'database object ownership differs from contract';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_class
    WHERE oid = event_table
      AND relrowsecurity
      AND relforcerowsecurity
  ) THEN
    RAISE EXCEPTION 'scientific_event RLS is not enabled and forced';
  END IF;

  SELECT array_agg(attribute.attname ORDER BY key_column.ordinality)
  INTO primary_key_columns
  FROM pg_constraint AS constraint_definition
  CROSS JOIN LATERAL unnest(constraint_definition.conkey)
    WITH ORDINALITY AS key_column(attnum, ordinality)
  JOIN pg_attribute AS attribute
    ON attribute.attrelid = constraint_definition.conrelid
    AND attribute.attnum = key_column.attnum
  WHERE constraint_definition.conrelid = event_table
    AND constraint_definition.conname = 'scientific_event_pkey'
    AND constraint_definition.contype = 'p'
    AND constraint_definition.convalidated;

  IF primary_key_columns IS DISTINCT FROM ARRAY['tenant_id', 'event_id']::text[] THEN
    RAISE EXCEPTION 'scientific_event primary key differs from contract: %',
      primary_key_columns;
  END IF;

  SELECT array_agg(attribute.attname ORDER BY key_column.ordinality)
  INTO stream_key_columns
  FROM pg_constraint AS constraint_definition
  CROSS JOIN LATERAL unnest(constraint_definition.conkey)
    WITH ORDINALITY AS key_column(attnum, ordinality)
  JOIN pg_attribute AS attribute
    ON attribute.attrelid = constraint_definition.conrelid
    AND attribute.attnum = key_column.attnum
  WHERE constraint_definition.conrelid = event_table
    AND constraint_definition.conname = 'scientific_event_stream_version_key'
    AND constraint_definition.contype = 'u'
    AND constraint_definition.convalidated;

  IF stream_key_columns IS DISTINCT FROM ARRAY[
    'tenant_id',
    'aggregate_type',
    'aggregate_id',
    'aggregate_version'
  ]::text[] THEN
    RAISE EXCEPTION 'scientific_event stream key differs from contract: %',
      stream_key_columns;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_index AS index_definition
    JOIN pg_attribute AS tenant_attribute
      ON tenant_attribute.attrelid = index_definition.indrelid
      AND tenant_attribute.attname = 'tenant_id'
    WHERE index_definition.indrelid = event_table
      AND index_definition.indisunique
      AND index_definition.indisvalid
      AND index_definition.indisready
      AND NOT EXISTS (
        SELECT 1
        FROM unnest(index_definition.indkey::smallint[])
          WITH ORDINALITY AS key_column(attnum, ordinality)
        WHERE key_column.ordinality <= index_definition.indnkeyatts
          AND key_column.attnum = tenant_attribute.attnum
      )
  ) THEN
    RAISE EXCEPTION 'a global unique index can leak cross-tenant existence';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conrelid = event_table
      AND conname =
        'scientific_event_tenant_id_aggregate_type_aggregate_id_aggr_key'
  ) THEN
    RAISE EXCEPTION 'generated stream constraint name still exists';
  END IF;

  IF (
    SELECT count(*)
    FROM pg_policy
    WHERE polrelid = event_table
  ) <> 3 THEN
    RAISE EXCEPTION 'scientific_event policy count differs from contract';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_policy
    WHERE polrelid = event_table
      AND polname = 'scientific_event_tenant_fence'
      AND polcmd = '*'
      AND NOT polpermissive
      AND polroles = ARRAY[0::oid]
      AND pg_get_expr(polqual, polrelid) = expected_tenant_expression
      AND pg_get_expr(polwithcheck, polrelid) = expected_tenant_expression
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy
    WHERE polrelid = event_table
      AND polname = 'scientific_event_tenant_select'
      AND polcmd = 'r'
      AND polpermissive
      AND polroles = ARRAY[0::oid]
      AND pg_get_expr(polqual, polrelid) = expected_tenant_expression
      AND polwithcheck IS NULL
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy
    WHERE polrelid = event_table
      AND polname = 'scientific_event_tenant_insert'
      AND polcmd = 'a'
      AND polpermissive
      AND polroles = ARRAY[0::oid]
      AND polqual IS NULL
      AND pg_get_expr(polwithcheck, polrelid) = expected_tenant_expression
  ) THEN
    RAISE EXCEPTION 'scientific_event policies differ from contract';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_proc
    WHERE oid = to_regprocedure('public.reject_scientific_event_mutation()')
      AND proconfig @> ARRAY['search_path=pg_catalog']::text[]
      AND NOT prosecdef
  ) THEN
    RAISE EXCEPTION 'mutation trigger function search_path is unsafe';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_database AS database_definition
    CROSS JOIN LATERAL aclexplode(
      COALESCE(
        database_definition.datacl,
        acldefault('d', database_definition.datdba)
      )
    ) AS privilege
    WHERE database_definition.datname = current_database()
      AND privilege.grantee = 0
  ) OR EXISTS (
    SELECT 1
    FROM pg_namespace AS namespace
    CROSS JOIN LATERAL aclexplode(
      COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))
    ) AS privilege
    WHERE namespace.nspname = 'public'
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'CREATE'
  ) OR EXISTS (
    SELECT 1
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(
      COALESCE(relation.relacl, acldefault('r', relation.relowner))
    ) AS privilege
    WHERE relation.oid = event_table
      AND privilege.grantee = 0
  ) OR EXISTS (
    SELECT 1
    FROM pg_proc AS function_definition
    CROSS JOIN LATERAL aclexplode(
      COALESCE(
        function_definition.proacl,
        acldefault('f', function_definition.proowner)
      )
    ) AS privilege
    WHERE function_definition.oid =
      to_regprocedure('public.reject_scientific_event_mutation()')
      AND privilege.grantee = 0
      AND privilege.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC privileges exceed contract';
  END IF;

  IF NOT has_database_privilege(
    'bioworld_writer',
    current_database(),
    'CONNECT'
  ) OR has_database_privilege(
    'bioworld_writer',
    current_database(),
    'CREATE'
  ) OR has_database_privilege(
    'bioworld_writer',
    current_database(),
    'TEMP'
  ) OR NOT has_schema_privilege(
    'bioworld_writer',
    'public',
    'USAGE'
  ) OR has_schema_privilege(
    'bioworld_writer',
    'public',
    'CREATE'
  ) OR has_function_privilege(
    'bioworld_writer',
    'public.reject_scientific_event_mutation()',
    'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'writer database, schema, or function privileges differ from contract';
  END IF;

  SELECT count(*) INTO object_count
  FROM pg_class AS relation
  CROSS JOIN LATERAL aclexplode(
    COALESCE(relation.relacl, acldefault('r', relation.relowner))
  ) AS privilege
  WHERE relation.oid = event_table
    AND privilege.grantee = writer_id
    AND privilege.privilege_type IN ('SELECT', 'INSERT');

  IF object_count <> 2 OR EXISTS (
    SELECT 1
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(
      COALESCE(relation.relacl, acldefault('r', relation.relowner))
    ) AS privilege
    WHERE relation.oid = event_table
      AND privilege.grantee = writer_id
      AND privilege.privilege_type NOT IN ('SELECT', 'INSERT')
  ) OR EXISTS (
    SELECT 1
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(
      COALESCE(relation.relacl, acldefault('r', relation.relowner))
    ) AS privilege
    WHERE relation.oid = event_table
      AND privilege.grantee = migrator_id
  ) THEN
    RAISE EXCEPTION 'writer table privileges differ from contract';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_db_role_setting
    WHERE setdatabase = (
      SELECT oid FROM pg_database WHERE datname = current_database()
    )
      AND setrole = writer_id
      AND setconfig @> ARRAY['search_path=pg_catalog']::text[]
  ) THEN
    RAISE EXCEPTION 'writer default search_path differs from contract';
  END IF;
END
$tenant_catalog_checks$;

BEGIN;

DO $behavior_checks$
BEGIN
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
    '00000000-0000-4000-8000-000000000002',
    'decision.recorded',
    '2',
    'decision',
    'u64-maximum',
    18446744073709551615,
    '2026-01-02 03:04:05+00',
    '2026-01-02 03:04:06+00',
    'tenant-fixture',
    '{"status":"approved"}'::jsonb,
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '{"alg":"Ed25519"}'::jsonb
  );

  IF NOT EXISTS (
    SELECT 1
    FROM scientific_event
    WHERE event_id = '00000000-0000-4000-8000-000000000002'
      AND aggregate_version = 18446744073709551615
  ) THEN
    RAISE EXCEPTION 'valid u64 maximum aggregate version was not preserved';
  END IF;

  INSERT INTO public.scientific_event (
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
    'same-event-id-other-tenant',
    1,
    '2026-01-02 03:04:05+00',
    '2026-01-02 03:04:06+00',
    'tenant-secondary',
    '{"status":"approved"}'::jsonb,
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    '{"alg":"Ed25519"}'::jsonb
  );

  BEGIN
    INSERT INTO public.scientific_event (
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
      'same-event-id-same-tenant',
      1,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'same-tenant duplicate event ID was accepted';
  EXCEPTION
    WHEN SQLSTATE '23505' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000003',
      'decision.recorded',
      '2',
      'decision',
      'version-zero',
      0,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'aggregate version zero was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000004',
      'decision.recorded',
      '2',
      'decision',
      'version-out-of-range',
      18446744073709551616,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'out-of-range aggregate version was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000005',
      'decision.recorded',
      '2',
      'decision',
      'version-fractional',
      1.5,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'fractional aggregate version was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000006',
      'decision.recorded',
      '2',
      'decision',
      'blank-tenant',
      1,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      '',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'blank tenant was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000007',
      'decision.recorded',
      '2',
      'decision',
      'padded-tenant',
      1,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      ' tenant-fixture ',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'padded tenant was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000008',
      'decision.recorded',
      '2',
      'decision',
      'invalid-digest',
      1,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      'not-a-sha256',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'invalid payload digest was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000009',
      'decision.recorded',
      '2',
      'decision',
      'empty-signature',
      1,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{}'::jsonb
    );
    RAISE EXCEPTION 'empty signature was accepted';
  EXCEPTION
    WHEN SQLSTATE '23514' THEN NULL;
  END;

  BEGIN
    INSERT INTO scientific_event VALUES (
      '00000000-0000-4000-8000-000000000010',
      'decision.recorded',
      '2',
      'decision',
      'fixture-decision',
      42,
      '2026-01-02 03:04:05+00',
      '2026-01-02 03:04:06+00',
      'tenant-fixture',
      '{"status":"approved"}'::jsonb,
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      '{"alg":"Ed25519"}'::jsonb
    );
    RAISE EXCEPTION 'duplicate aggregate version was accepted';
  EXCEPTION
    WHEN SQLSTATE '23505' THEN NULL;
  END;

  BEGIN
    UPDATE scientific_event
    SET event_type = 'decision.changed'
    WHERE event_id = '00000000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'scientific_event UPDATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;

  BEGIN
    DELETE FROM scientific_event
    WHERE event_id = '00000000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'scientific_event DELETE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;

  BEGIN
    TRUNCATE TABLE scientific_event;
    RAISE EXCEPTION 'scientific_event TRUNCATE was accepted';
  EXCEPTION
    WHEN SQLSTATE '55000' THEN NULL;
  END;
END
$behavior_checks$;

ROLLBACK;

SELECT 'bioworld_migrations_ready';
