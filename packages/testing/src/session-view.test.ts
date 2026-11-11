import { describe, expect, it } from 'vitest';

import { describeUserAgent, maskIp } from '../../../apps/api/src/account/session-view.js';

/**
 * The two fields of a session view that are derived from client-supplied strings.
 *
 * Both are reduced to a fixed shape — a network prefix, a label from a fixed vocabulary — so
 * nothing a client sent can reach a page that renders them, and a full address never leaves.
 */
describe('maskIp', () => {
  it('keeps the /24 of an IPv4 address and drops the host', () => {
    expect(maskIp('203.0.113.77')).toBe('203.0.113.0/24');
    expect(maskIp('::ffff:198.51.100.9')).toBe('198.51.100.0/24');
  });

  it('keeps the /48 of an IPv6 address, including compressed forms', () => {
    expect(maskIp('2001:db8:abcd:12::1')).toBe('2001:db8:abcd::/48');
    expect(maskIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe('2001:db8:0::/48');
    expect(maskIp('::1')).toBe('0:0:0::/48');
  });

  it('returns nothing for anything that is not an address, rather than echoing it', () => {
    for (const value of [
      '',
      'unknown',
      '999.1.1.1',
      '1.2.3',
      '<script>',
      '1:2:3:4:5:6:7:8:9',
      'a::b::c',
    ]) {
      expect([value, maskIp(value)]).toEqual([value, undefined]);
    }
  });
});

describe('describeUserAgent', () => {
  it('names common browsers and systems', () => {
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 Edg/130.0',
      ),
    ).toBe('Edge on Windows');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
      ),
    ).toBe('Safari on macOS');
    expect(
      describeUserAgent(
        'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36',
      ),
    ).toBe('Chrome on Android');
  });

  it('never returns any part of the header it was given', () => {
    const hostile = 'Evil/1.0 <img src=x onerror=alert(1)> \r\nSet-Cookie: x=y tracking-id-12345';
    const described = describeUserAgent(hostile);
    expect(described).toBe('Unknown device');
    expect(describeUserAgent(undefined)).toBe('Unknown device');
    expect(describeUserAgent('   ')).toBe('Unknown device');
  });

  it('reads only a bounded prefix of a very long header', () => {
    expect(describeUserAgent(`${'x'.repeat(10_000)} Firefox/131.0`)).toBe('Unknown device');
  });
});
