import type { SqlClient } from '../src/migrations/migration-runner.js';

/**
 * Just enough of PostgreSQL to prove the runner's decisions without one.
 *
 * It models what the runner relies on and nothing else: who the session is, the advisory lock, the
 * ledger, which tables exist, and — the part that matters — that a ledger row written inside a
 * transaction exists only if that transaction commits. Every other statement is treated as a
 * migration's SQL and recorded as executed, or made to fail on request.
 *
 * Real PostgreSQL behaviour (DDL, roles, RLS) is proved separately, against a real server, by
 * `packages/testing/src/migration-runner.integration.test.ts`.
 */
export interface LedgerRow {
  readonly name: string;
  readonly checksum: string;
  readonly mode: 'applied' | 'adopted';
}

export class FakeDatabase implements SqlClient {
  public role = { role: 'identity_mig', superuser: false, bypass: false };
  public ledgerExists = false;
  public ledger: LedgerRow[] = [];
  public tables: string[] = [];
  /** Migration SQL that ran, in order. */
  public readonly executed: string[] = [];
  public readonly statements: string[] = [];
  public locked = false;
  public lockAcquisitions = 0;
  /** A migration SQL text that should fail when executed. */
  public failOn: string | undefined;
  /** Tables a successfully executed migration "creates". */
  public createsTables: readonly string[] = [];

  private inTransaction = false;
  private pendingRows: LedgerRow[] = [];

  public query(
    text: string,
    values: readonly unknown[] = [],
  ): Promise<{ rows: Record<string, unknown>[] }> {
    this.statements.push(text);
    const statement = text.trim().replace(/\s+/g, ' ').toLowerCase();
    const result = (rows: Record<string, unknown>[] = []) => Promise.resolve({ rows });

    if (statement.startsWith('select current_user')) return result([{ ...this.role }]);
    if (statement.startsWith('select pg_advisory_lock')) {
      this.locked = true;
      this.lockAcquisitions += 1;
      return result();
    }
    if (statement.startsWith('select pg_advisory_unlock')) {
      this.locked = false;
      return result();
    }
    if (statement.startsWith('create schema if not exists identity_migration')) return result();
    if (statement.startsWith('create table if not exists identity_migration.applied')) {
      this.ledgerExists = true;
      return result();
    }
    if (statement.startsWith('select name, checksum from identity_migration.applied')) {
      return result(
        [...this.ledger].sort((a, b) => (a.name < b.name ? -1 : 1)).map((row) => ({ ...row })),
      );
    }
    if (statement.includes('from information_schema.tables')) {
      return result(this.tables.map((table_name) => ({ table_name })));
    }
    if (statement === 'begin') {
      this.inTransaction = true;
      this.pendingRows = [];
      return result();
    }
    if (statement === 'commit') {
      this.ledger.push(...this.pendingRows);
      this.inTransaction = false;
      this.pendingRows = [];
      return result();
    }
    if (statement === 'rollback') {
      this.inTransaction = false;
      this.pendingRows = [];
      return result();
    }
    if (statement.startsWith('insert into identity_migration.applied')) {
      const row: LedgerRow = {
        name: String(values[0]),
        checksum: String(values[1]),
        mode: statement.includes("'adopted'") ? 'adopted' : 'applied',
      };
      if (this.inTransaction) this.pendingRows.push(row);
      else this.ledger.push(row);
      return result();
    }

    // Anything else is a migration's own SQL.
    if (text === this.failOn) return Promise.reject(new Error('syntax error at or near "oops"'));
    this.executed.push(text);
    this.tables = [...new Set([...this.tables, ...this.createsTables])];
    return result();
  }

  public end(): Promise<void> {
    return Promise.resolve();
  }
}
