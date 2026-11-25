/**
 * The sign-in page, rendered as HTML by the service that owns the credential.
 *
 * **Why not a Next.js application.** The page has one form, no state, no client data fetching and
 * nothing to hydrate. A second deployable unit for it would mean a second container, a second route
 * through the front door and a second place the credential passes through — for a form. Serving it
 * from the service that already owns the password is fewer moving parts *and* a shorter path for
 * the one value that matters.
 *
 * **Why it works without JavaScript.** A plain form post is the most robust thing a login page can
 * be: no script to fail, no fetch to mis-handle, no token ever touched by client code. The endpoint
 * accepts `application/x-www-form-urlencoded` alongside JSON and answers a form post with a
 * redirect, so the browser does what browsers have always done here.
 *
 * There is no password in `localStorage`, no token read by script, and no cookie readable by
 * script — the session is `httpOnly` and the response body carries nothing.
 *
 * It is drawn in the shared Identity frame (`layout.ts`): the Munaxa Docs sign-in layout in the
 * Munaxa Group colours.
 */

import { alert, escapeHtml as escape, field, frame } from './layout.js';

export interface SignInPageOptions {
  readonly language: 'en' | 'ar';
  readonly returnTo: string;
  /** Present only after a failed attempt. Every credential failure produces the same one. */
  readonly error?: 'invalid' | 'locked' | 'mfa' | 'password-policy' | 'unavailable' | undefined;
  readonly organisationRequired: boolean;
}

const COPY = {
  en: {
    title: 'Sign in to Munaxa',
    lead: 'Use your Munaxa account to continue. Only Munaxa Identity sees your password.',
    identifier: 'Email address',
    password: 'Password',
    organisation: 'Organisation',
    submit: 'Sign in',
    invalid: 'Those details were not accepted. Check them and try again.',
    locked: 'Too many attempts. Wait a few minutes before trying again.',
    mfa: 'This account needs a second factor, which is unavailable on this deployment right now.',
    policy: 'This password must be changed before the account can be used.',
    // Deliberately says nothing about which part is unwell, and deliberately does not blame the
    // person's details — this is the one message on the page that is not about their credentials.
    unavailable: 'Sign-in is temporarily unavailable. Please try again in a moment.',
  },
  ar: {
    title: 'تسجيل الدخول إلى مُناخة',
    lead: 'استخدم حساب مُناخة للمتابعة. هوية مُناخة وحدها ترى كلمة المرور.',
    identifier: 'البريد الإلكتروني',
    password: 'كلمة المرور',
    organisation: 'المؤسسة',
    submit: 'تسجيل الدخول',
    invalid: 'لم تُقبل هذه البيانات. تحقّق منها وحاول مرة أخرى.',
    locked: 'محاولات كثيرة. انتظر بضع دقائق قبل المحاولة مجددًا.',
    mfa: 'يحتاج هذا الحساب إلى عامل ثانٍ غير متاح على هذا النشر حاليًا.',
    policy: 'يجب تغيير كلمة المرور قبل استخدام هذا الحساب.',
    unavailable: 'تسجيل الدخول غير متاح مؤقتًا. يرجى المحاولة بعد قليل.',
  },
} as const;

type Copy = (typeof COPY)[keyof typeof COPY];

const messageFor = (error: SignInPageOptions['error'], copy: Copy): string | undefined => {
  switch (error) {
    // A wrong password, an unknown address and a disabled account all arrive here as `invalid`,
    // and all render the same sentence. Any difference would tell somebody enumerating addresses
    // which ones are real.
    case 'invalid':
      return copy.invalid;
    case 'locked':
      return copy.locked;
    case 'mfa':
      return copy.mfa;
    case 'password-policy':
      return copy.policy;
    case 'unavailable':
      return copy.unavailable;
    default:
      return undefined;
  }
};

export const signInPage = (options: SignInPageOptions): string => {
  const copy = COPY[options.language];
  const other = options.language === 'en' ? 'ar' : 'en';

  return frame({
    language: options.language,
    title: copy.title,
    // `returnTo` reaches this from the query string: escaped where it is an attribute, encoded
    // where it is part of a URL.
    languageSwitch: { href: `?lang=${other}&amp;returnTo=${encodeURIComponent(options.returnTo)}` },
    body: `    <header>
      <h1>${escape(copy.title)}</h1>
      <p class="lead">${escape(copy.lead)}</p>
    </header>
    ${alert('danger', 'alert', messageFor(options.error, copy))}
    <form method="post" action="/api/auth/login">
    <input type="hidden" name="returnTo" value="${escape(options.returnTo)}">
    <input type="hidden" name="lang" value="${options.language}">
    ${field(
      'identifier',
      copy.identifier,
      '<input id="identifier" name="identifier" type="email" autocomplete="username" required autofocus>',
      true,
    )}
    ${field(
      'password',
      copy.password,
      '<input id="password" name="password" type="password" autocomplete="current-password" required>',
      true,
    )}
    ${
      options.organisationRequired
        ? field(
            'organisation',
            copy.organisation,
            '<input id="organisation" name="organisation" autocomplete="organization" spellcheck="false" required>',
            true,
          )
        : ''
    }
    <button type="submit">${escape(copy.submit)}</button>
    </form>`,
  });
};
