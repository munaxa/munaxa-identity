-- Company sign-in (OpenID Connect with Microsoft Entra ID or Google Workspace), per organisation.
--
-- Two directory tables and two constraints on `identity_account`. Nothing existing changes shape:
-- the account columns this uses (`identity_source`, `identity_provider_id`, `external_id`) have
-- been in the baseline since the first migration so that this would not be a backfill.

-- ============================================================================
-- identity_sso_connection: one company directory an organisation signs in through.
--
-- `directory_id` is the Microsoft Entra tenant id (a GUID) or the Google Workspace primary domain.
-- No client secret lives here: Munaxa holds one application registration per provider, configured
-- on the service, and a company's administrator consents to it in their own directory.
-- ============================================================================
CREATE TABLE "identity_sso_connection" (
    "id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "directory_id" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "trust_provider_mfa" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_by" TEXT,
    "updated_by" TEXT,

    CONSTRAINT "identity_sso_connection_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "ck_identity_sso_connection_provider" CHECK ("provider" IN ('microsoft', 'google')),
    -- A Microsoft tenant id is a GUID; a Google directory is a lower-case DNS name. Anything else
    -- is a typo that would otherwise only show up as a sign-in nobody can complete.
    CONSTRAINT "ck_identity_sso_connection_directory" CHECK (
        ("provider" = 'microsoft' AND "directory_id" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        OR ("provider" = 'google' AND "directory_id" ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
    )
);

CREATE UNIQUE INDEX "uq_identity_sso_connection_directory"
    ON "identity_sso_connection"("tenant_id", "provider", "directory_id");
CREATE INDEX "ix_identity_sso_connection_tenant" ON "identity_sso_connection"("tenant_id");
-- Target of the domain table's composite key below.
CREATE UNIQUE INDEX "uq_identity_sso_connection_tenant" ON "identity_sso_connection"("id", "tenant_id");

ALTER TABLE "identity_sso_connection" ADD CONSTRAINT "identity_sso_connection_tenant_id_fkey"
    FOREIGN KEY ("tenant_id") REFERENCES "identity_tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ============================================================================
-- identity_sso_domain: which email domain signs in through which connection.
--
-- The primary key makes a domain belong to exactly one connection across every organisation: two
-- organisations both claiming `acme.com` would let either one's directory decide who `@acme.com`
-- people are, and the second claim is refused instead.
-- ============================================================================
CREATE TABLE "identity_sso_domain" (
    "domain" TEXT NOT NULL,
    "connection_id" UUID NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "identity_sso_domain_pkey" PRIMARY KEY ("domain"),
    CONSTRAINT "ck_identity_sso_domain_shape" CHECK (
        "domain" ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    )
);

CREATE INDEX "ix_identity_sso_domain_connection" ON "identity_sso_domain"("connection_id");

-- Composite, so a domain row can never name one organisation and point at another's connection.
ALTER TABLE "identity_sso_domain" ADD CONSTRAINT "identity_sso_domain_connection_id_tenant_id_fkey"
    FOREIGN KEY ("connection_id", "tenant_id") REFERENCES "identity_sso_connection"("id", "tenant_id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "identity_sso_domain" ADD CONSTRAINT "identity_sso_domain_tenant_id_fkey"
    FOREIGN KEY ("tenant_id") REFERENCES "identity_tenant"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ============================================================================
-- The account side.
--
-- A federated account has no password and names its connection; a local account names none. Both
-- directions are constraints rather than conventions because each failure is a security defect:
-- a federated account with a password could be signed into around the company's directory, and a
-- local account bound to a connection could be claimed by whoever the directory says it is.
-- Every existing row is `local` with no provider, so both hold already.
-- ============================================================================
ALTER TABLE "identity_account" ADD CONSTRAINT "ck_identity_account_source" CHECK (
    ("identity_source" = 'local' AND "identity_provider_id" IS NULL AND "external_id" IS NULL)
    OR ("identity_source" = 'federated' AND "identity_provider_id" IS NOT NULL AND "password_hash" IS NULL)
);

-- Composite, so an account can only ever name a connection of its own organisation. A local account
-- (provider null) is not checked, as MATCH SIMPLE intends.
ALTER TABLE "identity_account" ADD CONSTRAINT "identity_account_identity_provider_id_tenant_id_fkey"
    FOREIGN KEY ("identity_provider_id", "tenant_id") REFERENCES "identity_sso_connection"("id", "tenant_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ============================================================================
-- Row-level security.
--
-- `identity_sso_connection` is an ordinary tenant table: the `tenant_isolation` policy every tenant
-- table has. Its trust settings (enabled, trust_provider_mfa) can only be read or changed inside the
-- organisation's own context.
--
-- `identity_sso_domain` is where a company sign-in starts: from an email address, before any
-- organisation is known. Reading it therefore needs no context (the same reason `identity_tenant`
-- has no policy), and it holds no personal data or credential, only which organisation an email
-- domain belongs to. Writing it still needs the organisation's context, so one organisation can
-- never add or remove another's domain. Forced, like every tenant table, so the owner is bound too.
-- ============================================================================
ALTER TABLE "identity_sso_connection" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "identity_sso_connection" FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON "identity_sso_connection"
    USING (tenant_id = identity_current_tenant())
    WITH CHECK (tenant_id = identity_current_tenant());

ALTER TABLE "identity_sso_domain" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "identity_sso_domain" FORCE ROW LEVEL SECURITY;
CREATE POLICY domain_lookup ON "identity_sso_domain" FOR SELECT USING (true);
CREATE POLICY tenant_insert ON "identity_sso_domain" FOR INSERT
    WITH CHECK (tenant_id = identity_current_tenant());
CREATE POLICY tenant_delete ON "identity_sso_domain" FOR DELETE
    USING (tenant_id = identity_current_tenant());

-- ============================================================================
-- Grants.
--
-- Writable by `identity_app` because the operator commands that configure them run as the service
-- (ADR-0006), never as a superuser, and always inside the organisation's context.
-- No DELETE on connections: one is disabled, never removed, so the accounts bound to it keep a
-- referent and the audit trail keeps a meaning.
-- ============================================================================
grant select, insert, update on identity_sso_connection to identity_app;
grant select, insert, delete on identity_sso_domain to identity_app;
