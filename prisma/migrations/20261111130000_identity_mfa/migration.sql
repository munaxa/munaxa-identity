-- Munaxa Identity: TOTP multi-factor authentication.
--
-- Two tables, both tenant-bearing, both under FORCE ROW LEVEL SECURITY with the same
-- `tenant_isolation` policy every other tenant table carries. Nothing here is readable without a
-- tenant context, and nothing here holds a secret in the clear: the TOTP secret is an AES-256-GCM
-- envelope sealed by the application under a dedicated key ring, and a recovery code is stored only
-- as a keyed hash. See docs/adr/0005-totp-mfa.md and docs/runbooks/mfa.md.
--
-- Additive only: no existing table, column or policy is altered, so the migration is safe to apply
-- ahead of the release that uses it.

-- CreateTable
CREATE TABLE "identity_mfa_enrollment" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "secret_ciphertext" TEXT NOT NULL,
    "key_id" TEXT NOT NULL,
    "label" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL,
    "confirmed_at" TIMESTAMPTZ(6),
    "last_used_at" TIMESTAMPTZ(6),

    CONSTRAINT "identity_mfa_enrollment_pkey" PRIMARY KEY ("id"),
    -- The method vocabulary is Platform's; only the methods it defines can be stored.
    CONSTRAINT "ck_identity_mfa_enrollment_method"
      CHECK ("method" IN ('totp', 'email-otp', 'sms-otp', 'webauthn', 'passkey')),
    CONSTRAINT "ck_identity_mfa_enrollment_state" CHECK ("state" IN ('pending', 'active')),
    -- An active factor is, by definition, one that was confirmed. A row claiming otherwise is a
    -- factor nobody proved they hold.
    CONSTRAINT "ck_identity_mfa_enrollment_confirmed"
      CHECK (("state" = 'active') = ("confirmed_at" IS NOT NULL)),
    -- The application only ever writes a `v1.` envelope. A plaintext base32 secret cannot match.
    CONSTRAINT "ck_identity_mfa_enrollment_sealed" CHECK ("secret_ciphertext" LIKE 'v1.%.%.%.%')
);

-- CreateTable
CREATE TABLE "identity_mfa_recovery_code" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "account_id" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "key_id" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),

    CONSTRAINT "identity_mfa_recovery_code_pkey" PRIMARY KEY ("id"),
    -- A keyed SHA-256 in hex. Anything else is not a hash this code wrote.
    CONSTRAINT "ck_identity_mfa_recovery_code_hash" CHECK ("code_hash" ~ '^[0-9a-f]{64}$')
);

-- CreateIndex
CREATE INDEX "ix_identity_mfa_enrollment_key" ON "identity_mfa_enrollment"("tenant_id", "key_id");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_mfa_enrollment_state" ON "identity_mfa_enrollment"("tenant_id", "account_id", "method", "state");

-- CreateIndex
CREATE INDEX "ix_identity_mfa_recovery_code_account" ON "identity_mfa_recovery_code"("tenant_id", "account_id");

-- CreateIndex
CREATE UNIQUE INDEX "uq_identity_mfa_recovery_code" ON "identity_mfa_recovery_code"("tenant_id", "account_id", "key_id", "code_hash");

-- AddForeignKey
ALTER TABLE "identity_mfa_enrollment" ADD CONSTRAINT "identity_mfa_enrollment_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "identity_account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "identity_mfa_recovery_code" ADD CONSTRAINT "identity_mfa_recovery_code_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "identity_account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- ============================================================================
-- Grants and row-level security, exactly as the baseline does it for every tenant table.
-- ============================================================================

-- The runtime role needs to enrol, confirm, replace and remove factors, and to mark recovery codes
-- consumed. It needs nothing else, and in particular no TRUNCATE.
grant select, insert, update, delete on identity_mfa_enrollment, identity_mfa_recovery_code
  to identity_app;

do $$
declare
  t text;
begin
  foreach t in array array['identity_mfa_enrollment', 'identity_mfa_recovery_code']
  loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format(
      'create policy tenant_isolation on %I using (tenant_id = identity_current_tenant()) '
      'with check (tenant_id = identity_current_tenant())', t);
  end loop;
end
$$;
