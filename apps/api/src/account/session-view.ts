import type { SessionRecord } from '@munaxa/interfaces';
import type { SessionId } from '@munaxa/types';

/**
 * What a person is shown about one of their sessions.
 *
 * An allow-list, built field by field. The record it is built from also carries the token version,
 * the auth-method list, free-form `attributes` and the full client address, and spreading the
 * record — or filtering out the known-sensitive keys — would publish whatever field somebody adds
 * to it next. So nothing reaches the response unless it is named here.
 *
 * The `id` is returned because it is what "sign out this device" names. It is not a credential:
 * every route that accepts one also requires the caller's own verified access token, and matches
 * the id against the caller's own account in the same statement.
 */
export interface SessionView {
  readonly id: SessionId;
  readonly current: boolean;
  readonly createdAt: string;
  readonly lastActiveAt: string;
  /** The earlier of the idle and absolute deadlines: when this session ends if nothing happens. */
  readonly expiresAt: string;
  /** Present only when the deployment's policy permits it, and then only as a network prefix. */
  readonly ipPrefix?: string;
  /** A coarse description such as "Firefox on Linux", never the raw header. */
  readonly device: string;
}

export type SessionIpPolicy = 'hidden' | 'prefix';

export const toSessionView = (
  session: SessionRecord,
  current: SessionId,
  ipPolicy: SessionIpPolicy,
): SessionView => {
  const ipPrefix =
    ipPolicy === 'prefix' && session.ipAddress !== undefined
      ? maskIp(session.ipAddress)
      : undefined;
  return {
    id: session.id,
    current: session.id === current,
    createdAt: new Date(session.createdAt).toISOString(),
    lastActiveAt: new Date(session.lastSeenAt).toISOString(),
    expiresAt: new Date(Math.min(session.idleExpiresAt, session.absoluteExpiresAt)).toISOString(),
    ...(ipPrefix === undefined ? {} : { ipPrefix }),
    device: describeUserAgent(session.userAgent),
  };
};

/**
 * The network a session came from, without the host.
 *
 * The full address is personal data and is not needed to recognise a session; the prefix is
 * enough for "that was me, at home". Anything that does not parse as an address yields nothing
 * rather than an echo of whatever string was stored.
 */
export const maskIp = (address: string): string | undefined => {
  const value = address.trim().replace(/^::ffff:/i, '');
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (v4 !== null) {
    const octets = v4.slice(1, 4).map(Number);
    if (octets.some((octet) => octet > 255) || Number(v4[4]) > 255) return undefined;
    return `${octets.join('.')}.0/24`;
  }
  if (/^[0-9a-f:]+$/i.test(value) && value.includes(':')) {
    const groups = expandIpv6(value);
    return groups === undefined ? undefined : `${groups.slice(0, 3).join(':')}::/48`;
  }
  return undefined;
};

const expandIpv6 = (value: string): string[] | undefined => {
  const halves = value.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] === '' ? [] : (halves[0] ?? '').split(':');
  const tail = halves.length === 2 && halves[1] !== '' ? (halves[1] ?? '').split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return undefined;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) return undefined;
  return groups.map((group) => group.toLowerCase().replace(/^0+(?=.)/, ''));
};

const BROWSERS: readonly (readonly [RegExp, string])[] = [
  [/\bEdg(?:e|A|iOS)?\//, 'Edge'],
  [/\b(?:OPR|Opera)\//, 'Opera'],
  [/\bSamsungBrowser\//, 'Samsung Internet'],
  [/\b(?:Firefox|FxiOS)\//, 'Firefox'],
  [/\b(?:Chrome|CriOS|Chromium)\//, 'Chrome'],
  [/\bVersion\/[\d.]+.*\bSafari\//, 'Safari'],
  [/\bcurl\//i, 'curl'],
];

const SYSTEMS: readonly (readonly [RegExp, string])[] = [
  [/\b(?:iPhone|iPad|iPod)\b/, 'iOS'],
  [/\bAndroid\b/, 'Android'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bWindows\b/, 'Windows'],
  [/\bMac OS X\b|\bMacintosh\b/, 'macOS'],
  [/\bLinux\b/, 'Linux'],
];

/**
 * A user-agent reduced to a fixed vocabulary.
 *
 * The output is built only from the labels above, so a header carrying markup, a script, a
 * newline or a tracking identifier cannot reach a page that renders this field: whatever the client
 * sent, what comes back is one of a few dozen known strings.
 */
export const describeUserAgent = (userAgent: string | undefined): string => {
  if (userAgent === undefined || userAgent.trim() === '') return 'Unknown device';
  const header = userAgent.slice(0, 512);
  const browser = BROWSERS.find(([pattern]) => pattern.test(header))?.[1];
  const system = SYSTEMS.find(([pattern]) => pattern.test(header))?.[1];
  if (browser !== undefined && system !== undefined) return `${browser} on ${system}`;
  return browser ?? system ?? 'Unknown device';
};
