import { describe, expect, it } from 'vitest';

import { safeReturnTo } from '../../../apps/api/src/auth/auth.controller.js';

/**
 * Where a browser is sent after signing in, or after a second factor. Only a path on the shared
 * origin is honoured; everything a browser would resolve to another host falls back to `/`.
 */
describe('safeReturnTo', () => {
  it('keeps a path on this origin', () => {
    expect(safeReturnTo('/')).toBe('/');
    expect(safeReturnTo('/work/assets?page=2#top')).toBe('/work/assets?page=2#top');
  });

  it('falls back to / for nothing, an absolute URL or a scheme-relative URL', () => {
    expect(safeReturnTo(undefined)).toBe('/');
    expect(safeReturnTo('')).toBe('/');
    expect(safeReturnTo('https://evil.example/')).toBe('/');
    expect(safeReturnTo('//evil.example/')).toBe('/');
    expect(safeReturnTo('javascript:alert(1)')).toBe('/');
  });

  it('refuses a backslash, which browsers read as a slash', () => {
    // `new URL('/\\evil.example', base)` resolves to https://evil.example/.
    expect(new URL('/\\evil.example/x', 'https://id.example.test/').host).toBe('evil.example');
    expect(safeReturnTo('/\\evil.example/x')).toBe('/');
    expect(safeReturnTo('/\\/evil.example')).toBe('/');
    expect(safeReturnTo('/work\\..\\x')).toBe('/');
  });

  it('refuses control characters, which browsers strip before parsing', () => {
    expect(new URL('/\t/evil.example', 'https://id.example.test/').host).toBe('evil.example');
    expect(safeReturnTo('/\t/evil.example')).toBe('/');
    expect(safeReturnTo('/\n/evil.example')).toBe('/');
    expect(safeReturnTo('/\r\n/evil.example')).toBe('/');
    expect(safeReturnTo('/work\u0000')).toBe('/');
  });
});
