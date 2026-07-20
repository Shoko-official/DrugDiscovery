\set ON_ERROR_STOP on
\getenv migrator_password BIOWORLD_MIGRATOR_PASSWORD
\getenv writer_password BIOWORLD_WRITER_PASSWORD
\getenv reader_password BIOWORLD_READER_PASSWORD

CREATE ROLE bioworld_owner
  NOLOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS;

CREATE ROLE bioworld_migrator
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD :'migrator_password';

CREATE ROLE bioworld_writer
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD :'writer_password';

CREATE ROLE bioworld_reader
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOINHERIT
  NOREPLICATION
  NOBYPASSRLS
  PASSWORD :'reader_password';

GRANT bioworld_owner TO bioworld_migrator
  WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

DO $legacy_ownership$
BEGIN
  IF pg_catalog.to_regclass('public.scientific_event') IS NOT NULL THEN
    ALTER TABLE public.scientific_event OWNER TO bioworld_owner;
  END IF;

  IF pg_catalog.to_regprocedure(
    'public.reject_scientific_event_mutation()'
  ) IS NOT NULL THEN
    ALTER FUNCTION public.reject_scientific_event_mutation()
      OWNER TO bioworld_owner;
  END IF;
END
$legacy_ownership$;

ALTER DATABASE bioworld_migrations OWNER TO bioworld_owner;
ALTER SCHEMA public OWNER TO bioworld_owner;

REVOKE ALL ON DATABASE bioworld_migrations FROM PUBLIC;
GRANT CONNECT ON DATABASE bioworld_migrations
  TO bioworld_migrator, bioworld_writer, bioworld_reader;

REVOKE ALL ON SCHEMA public FROM PUBLIC;

ALTER ROLE bioworld_writer IN DATABASE bioworld_migrations
  SET search_path = pg_catalog;

ALTER ROLE bioworld_reader IN DATABASE bioworld_migrations
  SET search_path = pg_catalog;
