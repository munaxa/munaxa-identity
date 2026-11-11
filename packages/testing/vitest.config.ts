import { defineConfig } from 'vitest/config';

/**
 * One file at a time.
 *
 * Several suites share one PostgreSQL and call `truncateAll` in their hooks. Run in parallel, one
 * suite's truncate lands in the middle of another's test and the failure looks like a defect in
 * whatever was being tested — a revoked session that "came back", a row that "was never written".
 * The suites are small; serialising them costs seconds and buys results that mean something.
 */
export default defineConfig({
  test: { hookTimeout: 30_000, testTimeout: 30_000, fileParallelism: false },
});
