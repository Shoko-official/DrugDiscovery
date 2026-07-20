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
