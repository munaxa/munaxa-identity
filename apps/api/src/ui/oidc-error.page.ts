/**
 * The page for an authorization request that cannot be answered with a redirect: an unknown
 * client, or a redirect URI that client never registered. Sending the browser anywhere would be the
 * open redirect, so the person is told, in both languages, and nothing else happens.
 */

import { escapeHtml as escape, frame } from './layout.js';

export const oidcErrorPage = (): string =>
  frame({
    language: 'en',
    title: 'This sign-in link is not valid',
    body: `    <header>
      <h1>${escape('This sign-in link is not valid')}</h1>
      <p class="lead">${escape('The application that sent you here is not set up to sign in with Munaxa. Go back to it and try again, or contact your administrator.')}</p>
      <p class="lead" lang="ar" dir="rtl">${escape('رابط تسجيل الدخول هذا غير صالح. ارجع إلى التطبيق وحاول مرة أخرى، أو تواصل مع المسؤول.')}</p>
    </header>`,
  });
