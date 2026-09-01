import pino, { type Logger } from 'pino';
import type { IdentityEnvironment } from '@identity/config';

/**
 * Structured logs, with redaction that is a property of the logger rather than of every call site.
 *
 * The redaction list is the point. An authentication service handles exactly the values that must
 * never reach a log aggregator — a bearer token, a session cookie, a password in a form body — and
 * "remember not to log it" is not a control, because the leak is never the line somebody thought
 * about. It is a request logger printing `req.headers` wholesale, or an error handler serialising
 * the object it was handed. Both are covered here by path, so a future call site that logs a whole
 * request cannot leak one.
 *
 * `censor` rather than `remove`: a log line saying `authorization: [redacted]` tells an incident
 * responder the header was present, which is often the fact they need. A silently dropped field
 * tells them nothing and looks like the header was absent.
 */
export const REDACTED_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["set-cookie"]',
  'res.headers["set-cookie"]',
  'req.body.password',
  'req.body.identifier',
  'password',
  'accessToken',
  'refreshToken',
  'token',
  'privateKey',
  'passwordHash',
  '*.password',
  '*.accessToken',
  '*.refreshToken',
  '*.privateKey',
] as const;

export const createLogger = (environment: IdentityEnvironment): Logger =>
  pino({
    level: environment.MUNAXA_LOG_LEVEL,
    redact: { paths: [...REDACTED_PATHS], censor: '[redacted]' },
    base: {
      service: environment.APP_NAME,
      version: environment.APP_VERSION,
      build: environment.BUILD_SHA,
    },
    // JSON in production, unconditionally. A pretty transport is a development affordance, and the
    // configuration refuses `LOG_PRETTY` there rather than leaving it to a deployment to remember.
    ...(environment.LOG_PRETTY
      ? { transport: { target: 'pino-pretty', options: { singleLine: true } } }
      : {}),
  });
