-- Munaxa Identity staging — the database roles and the privilege baseline that
-- `prisma migrate deploy` is applied on top of.
--
-- Applied to the Identity Supabase project before any application object exists. It creates no
-- table, no type and no function: `public` stays empty so the Prisma baseline runs against a
-- clean database and `_prisma_migrations` records it exactly once, at release time, as
-- identity_mig.
--
-- Neither role is given a password. A migration must never write a credential — one that does
-- puts it in the migration history for ever. The deployment sets them out of band.
--
-- Run as the project's admin connection (Supabase `postgres`). Idempotent.

-- ---------------------------------------------------------------------------------------------
-- The two roles.
-- ---------------------------------------------------------------------------------------------
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'identity_mig') then
    create role identity_mig login nosuperuser nobypassrls nocreatedb nocreaterole noreplication;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'identity_app') then
    create role identity_app login nosuperuser nobypassrls nocreatedb nocreaterole noreplication;
  end if;
end
$$;

-- identity_mig creates and therefore owns every application object. Object ownership, not schema
-- ownership, is what FORCE ROW LEVEL SECURITY binds to — and identity_mig is NOBYPASSRLS, so the
-- owner is subject to the tenant policies exactly as the runtime role is.
grant usage, create on schema public to identity_mig;
grant usage on schema public to identity_app;

-- Supabase creates roles with set_option = false, so the admin connection cannot SET ROLE into
-- identity_mig and therefore cannot record default privileges on its behalf. postgres already
-- holds ADMIN OPTION on both roles, so this grants nothing it could not grant itself; INHERIT
-- stays false so the admin connection does not silently acquire identity_mig's rights.
grant identity_mig to postgres with set true, inherit false;
grant identity_app to postgres with set true, inherit false;

-- ---------------------------------------------------------------------------------------------
-- Default privileges keyed to identity_mig.
--
-- Deliberately no blanket table grant to identity_app. The Prisma baseline grants per table, and
-- identity_audit_event is granted SELECT and INSERT only; a default of `arwd on tables` would
-- hand back the UPDATE and DELETE that make the audit trail append-only by privilege rather than
-- by promise.
--
-- PostgreSQL checks ALTER DEFAULT PRIVILEGES against the *inherited* privileges of the role, so
-- these are recorded as identity_mig itself rather than with FOR ROLE.
-- ---------------------------------------------------------------------------------------------
set role identity_mig;
alter default privileges in schema public grant execute on routines to identity_app;
alter default privileges in schema public grant usage on types to identity_app;
reset role;

-- ---------------------------------------------------------------------------------------------
-- Close PostgREST.
--
-- Supabase exposes `public` through PostgREST as anon and authenticated. Identity does not use
-- PostgREST at all, so the whole schema is taken away from those roles rather than trusted to
-- hold nothing worth reading. Schema USAGE is the gate: without it no object inside can be
-- named, whatever its own ACL says — which is what closes the residual PUBLIC EXECUTE described
-- in 02-post-migration-hardening.sql.
-- ---------------------------------------------------------------------------------------------
revoke all on schema public from anon, authenticated, service_role;
revoke all on schema public from public;

-- Supabase's own default privileges, keyed to postgres, grant anon/authenticated/service_role
-- full CRUD on anything postgres creates in `public`. Identity creates nothing as postgres, but
-- one statement run as postgres by an operator should not be able to open a table to an anon key.
-- ROUTINES rather than FUNCTIONS, so procedures are covered too.
alter default privileges for role postgres in schema public
  revoke all on tables from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all on sequences from anon, authenticated, service_role;
alter default privileges for role postgres in schema public
  revoke all on routines from anon, authenticated, service_role;
