-- Munaxa Identity staging — run this immediately after `prisma migrate deploy`, as identity_mig.
--
-- Why this exists rather than being folded into the default privileges.
--
-- PostgreSQL's built-in default grants EXECUTE on every new routine to PUBLIC and USAGE on every
-- new type to PUBLIC. `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON ROUTINES FROM PUBLIC` does
-- not remove it: measured on this project's PostgreSQL 17.6, the revoke records nothing and a
-- routine created afterwards still carries `=X`. So the removal has to happen after the objects
-- exist.
--
-- ALL ROUTINES, never ALL FUNCTIONS. `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA ... FROM PUBLIC`
-- was measured on this project to leave both procedures in the schema with PUBLIC EXECUTE intact;
-- only ALL ROUTINES clears functions and procedures alike. Identity ships no procedure today, so
-- this is a guard against the next migration that adds one, not a fix for a present hole.
--
-- Nothing here is load-bearing on its own: anon and authenticated hold no USAGE on `public`
-- (01-roles-and-privileges.sql), so they cannot name a routine to execute it whatever its ACL
-- says. This is the second lock on the same door.

revoke execute on all routines in schema public from public;

do $$
declare t record;
begin
  for t in select typname from pg_type ty join pg_namespace n on n.oid = ty.typnamespace
           where n.nspname = 'public' and ty.typtype = 'e'
  loop
    execute format('revoke usage on type public.%I from public', t.typname);
  end loop;
end
$$;

-- ---------------------------------------------------------------------------------------------
-- Verification. Every row must read as stated; a row that does not is a release blocker.
-- ---------------------------------------------------------------------------------------------

-- 1. No table, routine or type in `public` is reachable by PostgREST's roles or by PUBLIC.
select 'exposed objects (must be 0)' as check, count(*) as value
from (
  select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind in ('r','v','m','p','f','S')
     and exists (select 1 from aclexplode(c.relacl) a
                 where a.grantee = 0
                    or a.grantee in (select oid from pg_roles
                                     where rolname in ('anon','authenticated','service_role')))
  union all
  select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public'
     and exists (select 1 from aclexplode(p.proacl) a
                 where a.grantee = 0
                    or a.grantee in (select oid from pg_roles
                                     where rolname in ('anon','authenticated','service_role')))
  union all
  select 1 from pg_type ty join pg_namespace n on n.oid = ty.typnamespace
   where n.nspname = 'public' and ty.typtype = 'e'
     and exists (select 1 from aclexplode(ty.typacl) a
                 where a.grantee = 0
                    or a.grantee in (select oid from pg_roles
                                     where rolname in ('anon','authenticated','service_role')))
) exposed;

-- 2. Every tenant-scoped table has RLS enabled AND forced, owned by identity_mig.
select 'tables missing FORCE RLS (must be 0)' as check, count(*) as value
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
  and c.relname <> 'identity_tenant' and c.relname <> '_prisma_migrations'
  and (not c.relrowsecurity or not c.relforcerowsecurity
       or pg_get_userbyid(c.relowner) <> 'identity_mig');

-- 3. The audit trail is append-only by privilege: identity_app holds SELECT and INSERT, nothing else.
select 'audit trail privileges (must be {INSERT,SELECT})' as check,
       (select array_agg(a.privilege_type order by a.privilege_type)
        from pg_class c join pg_namespace n on n.oid = c.relnamespace,
             aclexplode(c.relacl) a
        where n.nspname = 'public' and c.relname = 'identity_audit_event'
          and a.grantee = (select oid from pg_roles where rolname = 'identity_app'))::text as value;

-- 4. The runtime role can neither bypass RLS nor administer anything.
select 'identity_app role attributes' as check,
       format('superuser=%s bypassrls=%s createdb=%s createrole=%s',
              rolsuper, rolbypassrls, rolcreatedb, rolcreaterole) as value
from pg_roles where rolname = 'identity_app';
