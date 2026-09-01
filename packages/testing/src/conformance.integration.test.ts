import { randomUUID } from 'node:crypto';

import {
  runRefreshTokenConformance,
  runResetTokenConformance,
  runSessionConformance,
} from '@munaxa/conformance';
import type { RefreshTokenRecord, ResetTokenRecord, SessionRecord } from '@munaxa/interfaces';
import type { TenantId, UserId } from '@munaxa/types';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';

import { OWNER_URL, createOrganisation, truncateAll } from './index.js';
import { PrismaRefreshTokenStore } from '../../../apps/api/src/persistence/refresh-token-store.adapter.js';
import { PrismaResetTokenStore } from '../../../apps/api/src/persistence/reset-token-store.adapter.js';
import { PrismaSessionStore } from '../../../apps/api/src/persistence/session-store.adapter.js';
import { PrismaService } from '../../../apps/api/src/persistence/prisma.service.js';

/**
 * Platform's executable specification, run against the adapters this repository ships.
 *
 * These suites are deliberately hostile: they force interleaving with jitter rather than hoping for
 * it, because an adapter that is only atomic when nothing yields is one that passes in CI and fails
 * in production. They are why `markRotated` is a single conditional write and `createWithinLimit`
 * takes its count `for update` — properties that reading the code cannot establish and a sequential
 * test cannot see.
 *
 * The suites run as the migration owner, which `force row level security` applies to exactly as it
 * applies to the application role; the tenant context comes from the adapters themselves.
 */

/**
 * A fresh organisation per store, and why.
 *
 * The suites call `createStore()` once per test and then build records with fixed ids — `'used'`,
 * `'live'` — because they were written for a store that begins each test empty. A database-backed
 * store does not, so `revokeForUser` would count rows an earlier test left behind and the suite
 * would fail on residue rather than on behaviour. Advancing the tenant with each store gives every
 * test the isolation the suite assumes, using the isolation mechanism the product already has.
 */
let currentTenant = randomUUID() as TenantId;
const nextTenant = (): TenantId => {
  currentTenant = randomUUID() as TenantId;
  return currentTenant;
};
const TENANT = (): TenantId => currentTenant;
const ACCOUNT = randomUUID() as UserId;

const ACCOUNT_TENANT = randomUUID();

let prisma: PrismaService;
let ownerPool: pg.Pool;
let owner: pg.PoolClient;

beforeAll(async () => {
  ownerPool = new pg.Pool({ connectionString: OWNER_URL, max: 1 });
  owner = await ownerPool.connect();
  await truncateAll(owner);
  await createOrganisation(owner, 'conformance', ACCOUNT_TENANT);

  // Every foreign key in these tables points at an account, so one has to exist for the records
  // the suites invent to be storable at all.
  await owner.query('select set_config($1, $2, false)', ['identity.tenant_id', ACCOUNT_TENANT]);
  await owner.query(
    `insert into identity_account
       (id, tenant_id, identifier, identifier_normalized, status, token_version, mfa_enrolled,
        must_change_password, identity_source, created_at, updated_at, version)
     values ($1, $2, 'conformance@example', 'conformance@example', 'active', 1, false, false,
             'local', now(), now(), 1)`,
    [ACCOUNT, ACCOUNT_TENANT],
  );

  // The datasource is supplied explicitly, exactly as the application supplies it. Relying on an
  // ambient `DATABASE_URL` is the defect this constructor exists to prevent, and a test that
  // relied on one would be reintroducing it.
  prisma = new PrismaService({ DATABASE_URL: OWNER_URL } as never);
  await prisma.$connect();
});

afterAll(async () => {
  await prisma.$disconnect();
  await truncateAll(owner);
  owner.release();
  await ownerPool.end();
});

const harness = { describe, it, expect };
const now = Date.now();

const session = (overrides: Partial<SessionRecord> = {}): SessionRecord => ({
  id: `sess_${randomUUID()}` as SessionRecord['id'],
  tenantId: TENANT(),
  userId: ACCOUNT,
  createdAt: now,
  lastSeenAt: now,
  idleExpiresAt: now + 900_000,
  absoluteExpiresAt: now + 43_200_000,
  authMethods: ['password'],
  mfaSatisfied: false,
  tokenVersion: 1,
  ...overrides,
});

const refreshToken = (overrides: Partial<RefreshTokenRecord> = {}): RefreshTokenRecord => ({
  id: `rt_${randomUUID()}`,
  tenantId: TENANT(),
  userId: ACCOUNT,
  familyId: `fam_${randomUUID()}` as RefreshTokenRecord['familyId'],
  tokenHash: randomUUID(),
  issuedAt: now,
  expiresAt: now + 2_592_000_000,
  tokenVersion: 1,
  ...overrides,
});

const resetToken = (overrides: Partial<ResetTokenRecord> = {}): ResetTokenRecord => ({
  id: `rst_${randomUUID()}`,
  tenantId: TENANT(),
  userId: ACCOUNT,
  tokenHash: randomUUID(),
  issuedAt: now,
  expiresAt: now + 3_600_000,
  passwordHashFingerprint: 'a-fingerprint',
  ...overrides,
});

describe('the session store', () => {
  runSessionConformance(harness, {
    createStore: () => {
      nextTenant();
      return new PrismaSessionStore(prisma);
    },
    makeSession: session,
  });
});

describe('the refresh-token store', () => {
  runRefreshTokenConformance(harness, {
    createStore: () => {
      nextTenant();
      return new PrismaRefreshTokenStore(prisma);
    },
    makeRecord: refreshToken,
  });
});

describe('the reset-token store', () => {
  runResetTokenConformance(harness, {
    createStore: () => {
      nextTenant();
      return new PrismaResetTokenStore(prisma);
    },
    makeRecord: resetToken,
  });
});
