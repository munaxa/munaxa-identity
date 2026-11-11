import { defineConfig } from 'vitest/config';

// One file at a time. Every suite empties the shared test database in `beforeAll`, so two files
// running at once truncate each other's rows mid-test and fail on residue rather than behaviour.
export default defineConfig({
  test: { hookTimeout: 30_000, testTimeout: 30_000, fileParallelism: false },
});
