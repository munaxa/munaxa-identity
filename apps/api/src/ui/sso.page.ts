/**
 * "Sign in with Microsoft or Google": one field, the work email address.
 *
 * The address decides the directory (its domain belongs to one company connection), so the person
 * never chooses a provider and never types an organisation. Posting it starts the redirect; nothing
 * is shown about which organisation the domain belongs to.
 *
 * No password field on this page, deliberately: a company sign-in never sends a Munaxa password
 * anywhere, and a page that asked for one would teach people to type it where it does not belong.
 */

import { alert, escapeHtml as escape, field, frame } from './layout.js';

export interface SsoPageOptions {
  readonly language: 'en' | 'ar';
  readonly returnTo: string;
  /** `not-offered`: no company sign-in for this address. `unavailable`: try again shortly. */
  readonly error?: 'not-offered' | 'unavailable' | undefined;
}

const COPY = {
  en: {
    title: 'Sign in with your company account',
    lead: 'Enter your work email address. You will continue at Microsoft or Google, where your company signs you in.',
    email: 'Work email address',
    submit: 'Continue',
    back: 'Sign in with a Munaxa password instead',
    notOffered:
      'Company sign-in is not set up for this email address. Sign in with your Munaxa password, or ask your administrator.',
    unavailable: 'Sign-in is temporarily unavailable. Please try again in a moment.',
  },
  ar: {
    title: 'تسجيل الدخول بحساب مؤسستك',
    lead: 'أدخل بريد العمل الإلكتروني. ستتابع لدى Microsoft أو Google حيث تسجّل مؤسستك دخولك.',
    email: 'بريد العمل الإلكتروني',
    submit: 'متابعة',
    back: 'تسجيل الدخول بكلمة مرور مُناخة بدلًا من ذلك',
    notOffered:
      'تسجيل الدخول بحساب المؤسسة غير مفعّل لهذا البريد. سجّل الدخول بكلمة مرور مُناخة أو تواصل مع المسؤول.',
    unavailable: 'تسجيل الدخول غير متاح مؤقتًا. يرجى المحاولة بعد قليل.',
  },
} as const;

export const ssoPage = (options: SsoPageOptions): string => {
  const copy = COPY[options.language];
  const other = options.language === 'en' ? 'ar' : 'en';
  const returnTo = encodeURIComponent(options.returnTo);
  const message =
    options.error === 'not-offered'
      ? copy.notOffered
      : options.error === 'unavailable'
        ? copy.unavailable
        : undefined;

  return frame({
    language: options.language,
    title: copy.title,
    languageSwitch: { href: `?lang=${other}&amp;returnTo=${returnTo}` },
    body: `    <header>
      <h1>${escape(copy.title)}</h1>
      <p class="lead">${escape(copy.lead)}</p>
    </header>
    ${alert(options.error === 'not-offered' ? 'info' : 'danger', 'alert', message)}
    <form method="post" action="/api/auth/sso/start">
    <input type="hidden" name="returnTo" value="${escape(options.returnTo)}">
    <input type="hidden" name="lang" value="${options.language}">
    ${field(
      'identifier',
      copy.email,
      '<input id="identifier" name="identifier" type="email" autocomplete="username" required autofocus>',
      true,
    )}
    <button type="submit">${escape(copy.submit)}</button>
    </form>
    <div class="links"><a class="link" href="/api/auth/login?lang=${options.language}&amp;returnTo=${returnTo}">${escape(copy.back)}</a></div>`,
  });
};
