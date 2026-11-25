/**
 * The password-recovery pages: ask for a link, choose a new password, and the outcomes.
 *
 * Plain forms, no script, the same as the sign-in page and for the same reasons. Two properties
 * matter more here than anywhere else:
 *
 * - **The reset page never consumes the link.** It is a GET, and mail scanners, link previewers and
 *   antivirus gateways fetch every link in a message before the person does. The page only renders
 *   a form; the token is spent by the POST that form makes.
 * - **The token leaves the URL as soon as it can.** It arrives in the link's query string because
 *   an email link has nowhere else to carry it, and from there it goes into a hidden form field, so
 *   the POST that uses it carries it in a body. Every response is `no-store` and `same-origin` referrers (the
 *   edge sets both), so the page is neither cached nor named in a `Referer` to anything it links.
 *
 * They are drawn in the shared Identity frame (`layout.ts`), the same card as the sign-in page.
 */

import { type Language, alert, escapeHtml as escape, field, frame } from './layout.js';

export type { Language };

const COPY = {
  en: {
    forgotTitle: 'Reset your password',
    forgotLead:
      'Enter the email address you sign in with. If it belongs to an account, we will send a link to choose a new password.',
    identifier: 'Email address',
    organisation: 'Organisation',
    send: 'Send reset link',
    // The same sentence whether or not the address has an account — that is the whole point.
    sent: 'If that address belongs to an account, a reset link is on its way. It works once and expires soon.',
    limited: 'Too many requests. Wait a while before asking again.',
    unavailable: 'Password reset is temporarily unavailable. Please try again later.',
    resetTitle: 'Choose a new password',
    password: 'New password',
    confirm: 'Confirm new password',
    save: 'Set new password',
    mismatch: 'The two passwords do not match.',
    invalidLink: 'This reset link is invalid, already used or expired. Ask for a new one.',
    newLink: 'Ask for a new link',
    policy: 'That password does not meet the requirements. Choose a longer, less common password.',
    breached: 'That password has appeared in a data breach. Choose a different one.',
    signIn: 'Back to sign in',
    doneTitle: 'Password changed',
    done: 'Your password has been changed and every device has been signed out. Sign in with your new password.',
    signInNow: 'Sign in',
  },
  ar: {
    forgotTitle: 'إعادة تعيين كلمة المرور',
    forgotLead:
      'أدخل البريد الإلكتروني الذي تسجّل به الدخول. إن كان مرتبطًا بحساب فسنرسل رابطًا لاختيار كلمة مرور جديدة.',
    identifier: 'البريد الإلكتروني',
    organisation: 'المؤسسة',
    send: 'إرسال رابط إعادة التعيين',
    sent: 'إن كان هذا البريد مرتبطًا بحساب فقد أُرسل رابط إعادة التعيين. يعمل مرة واحدة وتنتهي صلاحيته قريبًا.',
    limited: 'طلبات كثيرة. انتظر قليلًا قبل الطلب مجددًا.',
    unavailable: 'إعادة تعيين كلمة المرور غير متاحة مؤقتًا. يرجى المحاولة لاحقًا.',
    resetTitle: 'اختر كلمة مرور جديدة',
    password: 'كلمة المرور الجديدة',
    confirm: 'تأكيد كلمة المرور الجديدة',
    save: 'تعيين كلمة المرور',
    mismatch: 'كلمتا المرور غير متطابقتين.',
    invalidLink: 'رابط إعادة التعيين غير صالح أو مستخدم أو منتهي الصلاحية. اطلب رابطًا جديدًا.',
    newLink: 'طلب رابط جديد',
    policy: 'كلمة المرور لا تستوفي المتطلبات. اختر كلمة أطول وأقل شيوعًا.',
    breached: 'ظهرت كلمة المرور هذه في تسريب بيانات. اختر كلمة أخرى.',
    signIn: 'العودة إلى تسجيل الدخول',
    doneTitle: 'تم تغيير كلمة المرور',
    done: 'تم تغيير كلمة المرور وتسجيل الخروج من جميع الأجهزة. سجّل الدخول بكلمة المرور الجديدة.',
    signInNow: 'تسجيل الدخول',
  },
} as const;

type Copy = (typeof COPY)[Language];

/** The page's card, inside the shared frame; the body brings its own heading. */
const shell = (language: Language, title: string, body: string): string =>
  frame({ language, title, body });

const note = (text: string | undefined): string => alert('info', 'status', text);

export type ForgotNotice = 'sent' | 'limited' | 'unavailable' | undefined;

export const forgotPage = (options: {
  readonly language: Language;
  readonly organisationRequired: boolean;
  readonly notice?: ForgotNotice;
}): string => {
  const copy: Copy = COPY[options.language];
  const text =
    options.notice === 'sent'
      ? copy.sent
      : options.notice === 'limited'
        ? copy.limited
        : options.notice === 'unavailable'
          ? copy.unavailable
          : undefined;
  return shell(
    options.language,
    copy.forgotTitle,
    `  <header>
    <h1>${escape(copy.forgotTitle)}</h1>
    <p class="lead">${escape(copy.forgotLead)}</p>
  </header>
  ${note(text)}
  <form method="post" action="/api/auth/password/forgot">
    <input type="hidden" name="lang" value="${options.language}">
    ${field('identifier', copy.identifier, '<input id="identifier" name="identifier" type="email" autocomplete="username" required autofocus>', true)}
    ${
      options.organisationRequired
        ? field(
            'organisation',
            copy.organisation,
            '<input id="organisation" name="organisation" autocomplete="organization" required>',
            true,
          )
        : ''
    }
    <button type="submit">${escape(copy.send)}</button>
  </form>
  <a class="link" href="/api/auth/login?lang=${options.language}">${escape(copy.signIn)}</a>`,
  );
};

export type ResetError = 'mismatch' | 'policy' | 'breached' | 'unavailable' | undefined;

export const resetPage = (options: {
  readonly language: Language;
  readonly organisation: string;
  readonly token: string;
  readonly error?: ResetError;
}): string => {
  const copy: Copy = COPY[options.language];
  const text =
    options.error === 'mismatch'
      ? copy.mismatch
      : options.error === 'policy'
        ? copy.policy
        : options.error === 'breached'
          ? copy.breached
          : options.error === 'unavailable'
            ? copy.unavailable
            : undefined;
  return shell(
    options.language,
    copy.resetTitle,
    `  <h1>${escape(copy.resetTitle)}</h1>
  ${note(text)}
  <form method="post" action="/api/auth/password/reset" autocomplete="off">
    <input type="hidden" name="lang" value="${options.language}">
    <input type="hidden" name="organisation" value="${escape(options.organisation)}">
    <input type="hidden" name="token" value="${escape(options.token)}">
    ${field('password', copy.password, '<input id="password" name="password" type="password" autocomplete="new-password" required autofocus>', true)}
    ${field('confirm', copy.confirm, '<input id="confirm" name="confirm" type="password" autocomplete="new-password" required>', true)}
    <button type="submit">${escape(copy.save)}</button>
  </form>`,
  );
};

export const invalidLinkPage = (language: Language): string => {
  const copy: Copy = COPY[language];
  return shell(
    language,
    copy.resetTitle,
    `  <h1>${escape(copy.resetTitle)}</h1>
  ${note(copy.invalidLink)}
  <a class="link" href="/api/auth/password/forgot?lang=${language}">${escape(copy.newLink)}</a>`,
  );
};

export const unavailablePage = (language: Language): string => {
  const copy: Copy = COPY[language];
  return shell(
    language,
    copy.forgotTitle,
    `  <h1>${escape(copy.forgotTitle)}</h1>
  ${note(copy.unavailable)}
  <a class="link" href="/api/auth/login?lang=${language}">${escape(copy.signIn)}</a>`,
  );
};

export const donePage = (language: Language): string => {
  const copy: Copy = COPY[language];
  return shell(
    language,
    copy.doneTitle,
    `  <h1>${escape(copy.doneTitle)}</h1>
  ${note(copy.done)}
  <a class="link" href="/api/auth/login?lang=${language}">${escape(copy.signInNow)}</a>`,
  );
};
