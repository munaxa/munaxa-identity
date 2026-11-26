-- Whether an account's email address was shown to belong to the person (ADR-0008 follow-up).
-- Additive and nullable: every existing account starts unchecked, and the id token says so.
ALTER TABLE "identity_account" ADD COLUMN "email_verified_at" TIMESTAMPTZ(6);
