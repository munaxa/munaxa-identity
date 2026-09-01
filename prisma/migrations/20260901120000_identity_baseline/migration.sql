-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "account_status" AS ENUM ('active', 'disabled', 'locked', 'pending_verification');

-- CreateEnum
CREATE TYPE "identity_source" AS ENUM ('local', 'federated');

-- CreateTable
CREATE TABLE "identity_tenant" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "identity_tenant_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_account" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "identifier" TEXT NOT NULL,
    "identifier_normalized" TEXT NOT NULL,
    "password_hash" TEXT,
    "password_algorithm" TEXT,
    "password_updated_at" TIMESTAMPTZ(6),
    "status" "account_status" NOT NULL DEFAULT 'pending_verification',
    "token_version" INTEGER NOT NULL DEFAULT 1,
    "mfa_enrolled" BOOLEAN NOT NULL DEFAULT false,
    "must_change_password" BOOLEAN NOT NULL DEFAULT false,
    "identity_source" "identity_source" NOT NULL DEFAULT 'local',
    "external_id" TEXT,
    "identity_provider_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_by" TEXT,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,
    "updated_by" TEXT,
    "disabled_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "identity_account_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_session" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL,
    "idle_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "device_id" TEXT,
    "ip_address" TEXT,
    "user_agent" TEXT,
    "auth_methods" TEXT[],
    "mfa_satisfied" BOOLEAN NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "revocation_reason" TEXT,
    "token_version" INTEGER NOT NULL,
    "attributes" JSONB,

    CONSTRAINT "identity_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_refresh_token" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "family_id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "session_id" TEXT,
    "device_id" TEXT,
    "rotated_at" TIMESTAMPTZ(6),
    "replaced_by" TEXT,
    "revoked_at" TIMESTAMPTZ(6),
    "revocation_reason" TEXT,
    "token_version" INTEGER NOT NULL,

    CONSTRAINT "identity_refresh_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_role" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "permissions" TEXT[],
    "inherits" TEXT[],
    "system" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "identity_role_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_role_assignment" (
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "role_id" UUID NOT NULL,
    "scope" TEXT NOT NULL DEFAULT '',
    "assigned_at" TIMESTAMPTZ(6) NOT NULL,
    "assigned_by" TEXT,
    "expires_at" TIMESTAMPTZ(6),

    CONSTRAINT "identity_role_assignment_pkey" PRIMARY KEY ("tenant_id","account_id","role_id","scope")
);

-- CreateTable
CREATE TABLE "identity_reset_token" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "token_hash" TEXT NOT NULL,
    "issued_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "password_hash_fingerprint" TEXT NOT NULL,
    "request_ip" TEXT,

    CONSTRAINT "identity_reset_token_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "identity_audit_event" (
    "tenant_id" TEXT NOT NULL,
    "sequence" BIGINT NOT NULL,
    "id" TEXT NOT NULL,
    "event" JSONB NOT NULL,
    "event_name" TEXT NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL,
    "recorded_at" TIMESTAMPTZ(6) NOT NULL,
    "previous_hash" TEXT,
    "hash" TEXT NOT NULL,
    "format_version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "identity_audit_event_pkey" PRIMARY KEY ("tenant_id","sequence")
);

-- CreateIndex
CREATE UNIQUE INDEX "identity_tenant_key_key" ON "identity_tenant"("key");

-- CreateIndex
CREATE INDEX "ix_identity_account_status" ON "identity_account"("tenant_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_account_identifier" ON "identity_account"("tenant_id", "identifier_normalized");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_account_external" ON "identity_account"("tenant_id", "identity_provider_id", "external_id");

-- CreateIndex
CREATE INDEX "ix_identity_session_live" ON "identity_session"("tenant_id", "account_id", "revoked_at", "idle_expires_at", "absolute_expires_at");

-- CreateIndex
CREATE INDEX "ix_identity_refresh_token_family" ON "identity_refresh_token"("tenant_id", "family_id");

-- CreateIndex
CREATE INDEX "ix_identity_refresh_token_account" ON "identity_refresh_token"("tenant_id", "account_id");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_refresh_token_hash" ON "identity_refresh_token"("tenant_id", "token_hash");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_role_key" ON "identity_role"("tenant_id", "key");

-- CreateIndex
CREATE INDEX "ix_identity_role_assignment_account" ON "identity_role_assignment"("tenant_id", "account_id");

-- CreateIndex
CREATE INDEX "ix_identity_reset_token_account" ON "identity_reset_token"("tenant_id", "account_id");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_reset_token_hash" ON "identity_reset_token"("tenant_id", "token_hash");

-- CreateIndex
CREATE INDEX "ix_identity_audit_occurred" ON "identity_audit_event"("tenant_id", "occurred_at");

-- CreateIndex
CREATE INDEX "ix_identity_audit_event" ON "identity_audit_event"("tenant_id", "event_name");

-- AddForeignKey
ALTER TABLE "identity_account" ADD CONSTRAINT "identity_account_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "identity_tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_role" ADD CONSTRAINT "identity_role_tenant_id_fkey" FOREIGN KEY ("tenant_id") REFERENCES "identity_tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_role_assignment" ADD CONSTRAINT "identity_role_assignment_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "identity_account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_role_assignment" ADD CONSTRAINT "identity_role_assignment_role_id_fkey" FOREIGN KEY ("role_id") REFERENCES "identity_role"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- ============================================================================
-- Row-level security, the runtime role, and the grants that make "append-only"
-- a privilege rather than a promise.
--
-- Two roles, as in every Munaxa product: the migration owner (this connection) creates and owns
-- the tables; `identity_app` is what the service connects as at runtime and holds no privilege
-- it does not use. `identity_app` is NOBYPASSRLS, and every policy below is written so that a
-- query with no tenant context matches nothing rather than everything.
--
-- FORCE is applied because it applies row-level security to the table owner as well. Without it
-- an application misconfigured to connect as the owner would silently read every organisation's
-- accounts, and nothing would fail.
--
-- Deliberately absent: any SECURITY DEFINER function and any resolver role. Munaxa Work needs
-- both because it must answer "which tenants may this person act in?" before a tenant exists
-- (Work ADR-0033/0077). Identity never has that problem — every Platform port method takes a
-- tenant as its first argument, and a login resolves its organisation from `identity_tenant`
-- before it touches an account. Adding one here by analogy would be adding a hole to solve a
-- problem this schema does not have.
-- ============================================================================

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'identity_app') then
    -- NOLOGIN here; the deployment sets a password out of band. A migration must never write a
    -- credential, and one that does puts it in the migration history for ever.
    create role identity_app nologin nosuperuser nobypassrls nocreatedb nocreaterole noreplication;
  end if;
end
$$;

grant usage on schema public to identity_app;

-- `identity_tenant` carries no personal data and is what a tenant context is resolved *from*, so
-- it is readable without one. It is not writable at runtime: organisations are provisioned.
grant select on identity_tenant to identity_app;

grant select, insert, update, delete on
  identity_account, identity_session, identity_refresh_token,
  identity_role, identity_role_assignment, identity_reset_token
to identity_app;

-- Append-only, enforced by the absence of UPDATE and DELETE rather than by a policy the
-- application is trusted to respect.
grant select, insert on identity_audit_event to identity_app;

-- The tenant a statement is acting for. Set transaction-locally by the unit of work; a
-- session-level setting would outlive the connection checkout and apply to whatever ran next.
create or replace function identity_current_tenant() returns text
language sql stable as $$
  select nullif(current_setting('identity.tenant_id', true), '')
$$;

comment on function identity_current_tenant() is
  'The organisation this transaction is acting for, or null. Null matches no row in any policy.';

do $$
declare
  t text;
begin
  foreach t in array array[
    'identity_account', 'identity_session', 'identity_refresh_token',
    'identity_role', 'identity_role_assignment', 'identity_reset_token',
    'identity_audit_event'
  ]
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format(
      'create policy tenant_isolation on %I using (tenant_id = identity_current_tenant()) '
      'with check (tenant_id = identity_current_tenant())', t);
  end loop;
end
$$;
