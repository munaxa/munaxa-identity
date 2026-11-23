/**
 * Whether a connection string reaches a database the Testing personas may be written to.
 *
 * Read with **pg's own parser** (`pg-connection-string`, loaded through `pg` so it is the copy the
 * seed script's client uses), never with `new URL()`. The two disagree exactly where it matters:
 * pg takes `?host=` over the authority, reads `%2F…` and `socket:` as a Unix socket, falls back to
 * `PGHOST` and `PGDATABASE` when the string leaves them out, and parses `not a url` as host `base`.
 * A check that reads the string differently from the client that connects checks nothing.
 *
 * Production's names come from munaxa-platform `infra/aws/stack`: the RDS instance is
 * `munaxa-<environment>-pg` (`data.tf`, prefix from `network.tf`), so production's endpoint starts
 * `munaxa-prod-pg.`; the private namespace is `<environment>.munaxa.internal` (`services.tf`).
 * Anything under the `munaxa-prod` prefix counts.
 */
import { createRequire } from 'node:module';
import { isIP } from 'node:net';

const fromPg = createRequire(createRequire(import.meta.url).resolve('pg'));
const { parse } = fromPg('pg-connection-string');

/** The environment variables pg reads when a connection string leaves a part out. */
const PG_FALLBACKS = ['PGHOST', 'PGHOSTADDR', 'PGDATABASE'];

const REFUSED = 'Testing personas are refused there.';

/** Lower case, no IPv6 brackets, no trailing dot (`db.prod.munaxa.internal.` is the same host). */
const normalised = (host) =>
  host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.+$/, '');

const isLoopback = (address) =>
  isIP(address) === 4 ? address.startsWith('127.') : address === '::1';

const isProductionHost = (host) =>
  (host.split('.')[0] ?? '').startsWith('munaxa-prod') ||
  host === 'prod.munaxa.internal' ||
  host.endsWith('.prod.munaxa.internal');

/** `prod` or `production` as a word of the database name (`identity_prod`, not `nonprod`). */
const isProductionName = (name) => /(^|[^a-z])prod(uction)?([^a-z]|$)/i.test(name);

/** Why the connection string names a host that cannot be confirmed as non-production. */
const hostRefusal = (rawHost) => {
  if (typeof rawHost !== 'string' || rawHost.trim() === '')
    return `The database URL names no host, so pg would use PGHOST or a default. ${REFUSED}`;
  if (rawHost.startsWith('/'))
    return `The database URL names a Unix socket (${rawHost}), whose server cannot be confirmed as non-production. ${REFUSED}`;
  const host = normalised(rawHost);
  if (host.includes(',')) return `The database URL names several hosts. ${REFUSED}`;
  if (isIP(host) !== 0 && !isLoopback(host))
    return `The database host ${host} is a raw address, which cannot be confirmed as non-production. Use its name. ${REFUSED}`;
  if (isProductionHost(host))
    return `The database host ${host} is production's (munaxa-prod). ${REFUSED}`;
  return undefined;
};

/** Query parameters that choose the server instead of the authority. */
const overridesHost = (connection) => {
  const query = connection.indexOf('?');
  if (query === -1) return false;
  const parameters = new URLSearchParams(connection.slice(query + 1));
  return parameters.has('host') || parameters.has('hostaddr');
};

/**
 * Why the database `connection` reaches must not receive the Testing personas, or `undefined`.
 *
 * `undefined` for an absent connection string: the seed script then refuses to run for want of one.
 * `env` is the environment the client would read its fallbacks from.
 */
export const databaseRefusal = (connection, env = process.env) => {
  if (connection === undefined || connection.trim() === '') return undefined;

  const fallbacks = PG_FALLBACKS.filter((name) => (env[name] ?? '').trim() !== '');
  if (fallbacks.length > 0)
    return `${fallbacks.join(', ')} ${fallbacks.length === 1 ? 'is' : 'are'} set, and pg would read the target from it. Unset it. ${REFUSED}`;

  if (!/^postgres(ql)?:\/\//i.test(connection.trim()))
    return `The database URL is not a postgres:// or postgresql:// URL, so its target cannot be confirmed as non-production. ${REFUSED}`;
  if (overridesHost(connection))
    return `The database URL chooses its server with a host or hostaddr parameter. Name the host in the URL itself. ${REFUSED}`;

  let parsed;
  try {
    parsed = parse(connection.trim());
  } catch {
    return `The database URL cannot be read. ${REFUSED}`;
  }

  const refusal = hostRefusal(parsed.host);
  if (refusal !== undefined) return refusal;

  const name = typeof parsed.database === 'string' ? parsed.database.trim() : '';
  if (name === '')
    return `The database URL names no database, so pg would use PGDATABASE or the user name. ${REFUSED}`;
  if (isProductionName(name)) return `The database ${name} is named for production. ${REFUSED}`;
  return undefined;
};
