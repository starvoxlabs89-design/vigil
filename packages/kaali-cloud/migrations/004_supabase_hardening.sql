-- 004_supabase_hardening.sql
--
-- Kaali Cloud talks to Postgres DIRECTLY (the `pg` client in src/db.js), so it
-- does NOT use Supabase's auto-generated PostgREST/REST API. On Supabase that
-- REST API is served to the `anon` (unauthenticated) and `authenticated` roles
-- using the project's public anon key — which means the userbase (password
-- hashes, tokens, OAuth links) could be readable by anyone with that key unless
-- those roles are explicitly denied. This migration slams that door shut.
--
-- Guarded by a role-existence check, so it is a harmless no-op on a plain local
-- Postgres where the `anon`/`authenticated` roles don't exist. Idempotent.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    -- Existing objects
    EXECUTE 'REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon, authenticated';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated';
    EXECUTE 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM anon, authenticated';
    -- Future objects created by this role (migrations run as the connection role)
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES    FROM anon, authenticated';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon, authenticated';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM anon, authenticated';
    RAISE NOTICE 'Supabase hardening applied: anon/authenticated denied on schema public.';
  END IF;
END$$;
