/**
 * The second-factor pages, in the same no-JavaScript form-post style as the sign-in page.
 *
 * Four states: asking for a code at sign-in, starting an enrollment, confirming it (the only page
 * that ever shows the secret), and showing the recovery codes (the only page that ever shows them,
 * once). Every response carrying one of these is `no-store` with `Referrer-Policy: same-origin`, set
 * by the controller.
 *
 * They are drawn in the shared Identity frame (`layout.ts`), the same card as the sign-in page.
 */

import { alert, escapeHtml as escape, field, frame } from './layout.js';

export type MfaPageState =
  | { readonly kind: 'verify' }
  | { readonly kind: 'enroll-start' }
  | { readonly kind: 'enroll-confirm'; readonly secret: string; readonly uri: string }
  | { readonly kind: 'recovery-codes'; readonly codes: readonly string[]; readonly next: string };

export interface MfaPageOptions {
  readonly language: 'en' | 'ar';
  readonly returnTo: string;
  readonly state: MfaPageState;
  readonly error?: 'invalid' | 'expired' | 'locked' | 'unavailable' | undefined;
}

const COPY = {
  en: {
    verifyTitle: 'Two-step verification',
    verifyLead: 'Enter the six-digit code from your authenticator app.',
    code: 'Authentication code',
    recovery: 'Or a recovery code',
    verify: 'Verify',
    enrollTitle: 'Set up two-step verification',
    enrollLead:
      'This account must use an authenticator app. Start setup, add the key to your app, then enter the code it shows.',
    start: 'Start setup',
    key: 'Setup key (enter it in your authenticator app)',
    link: 'Or open this link on the device with the app',
    confirm: 'Confirm',
    codesTitle: 'Save your recovery codes',
    codesLead:
      'Each code works once if you lose your device. They are shown only now. Store them somewhere safe.',
    continue: 'Continue',
    invalid: 'That code was not accepted. Try again.',
    expired: 'This sign-in has expired. Sign in again.',
    locked: 'Too many attempts. Wait a few minutes, then sign in again.',
    unavailable: 'Two-step verification is temporarily unavailable. Please try again shortly.',
    signIn: 'Back to sign-in',
  },
  ar: {
    verifyTitle: 'التحقق بخطوتين',
    verifyLead: 'أدخل الرمز المكوّن من ستة أرقام من تطبيق المصادقة.',
    code: 'رمز المصادقة',
    recovery: 'أو رمز استرداد',
    verify: 'تحقّق',
    enrollTitle: 'إعداد التحقق بخطوتين',
    enrollLead:
      'يجب أن يستخدم هذا الحساب تطبيق مصادقة. ابدأ الإعداد وأضف المفتاح إلى التطبيق ثم أدخل الرمز الذي يظهر.',
    start: 'بدء الإعداد',
    key: 'مفتاح الإعداد (أدخله في تطبيق المصادقة)',
    link: 'أو افتح هذا الرابط على الجهاز الذي فيه التطبيق',
    confirm: 'تأكيد',
    codesTitle: 'احفظ رموز الاسترداد',
    codesLead: 'كل رمز يعمل مرة واحدة إذا فقدت جهازك. تُعرض الآن فقط. احفظها في مكان آمن.',
    continue: 'متابعة',
    invalid: 'لم يُقبل هذا الرمز. حاول مرة أخرى.',
    expired: 'انتهت صلاحية تسجيل الدخول هذا. سجّل الدخول مجددًا.',
    locked: 'محاولات كثيرة. انتظر بضع دقائق ثم سجّل الدخول مجددًا.',
    unavailable: 'التحقق بخطوتين غير متاح مؤقتًا. يرجى المحاولة بعد قليل.',
    signIn: 'العودة إلى تسجيل الدخول',
  },
} as const;

export const mfaPage = (options: MfaPageOptions): string => {
  const copy = COPY[options.language];
  const hidden = `<input type="hidden" name="returnTo" value="${escape(options.returnTo)}">
    <input type="hidden" name="lang" value="${options.language}">`;
  const message = options.error === undefined ? undefined : copy[options.error];
  const terminal = options.error === 'expired' || options.error === 'locked';
  const signInLink = `<p><a class="link" href="/api/auth/login?lang=${options.language}&amp;returnTo=${encodeURIComponent(options.returnTo)}">${escape(copy.signIn)}</a></p>`;

  let title: string;
  let body: string;
  let lead: string | undefined;
  switch (options.state.kind) {
    case 'verify':
      title = copy.verifyTitle;
      body = terminal
        ? signInLink
        : `<form method="post" action="/api/auth/mfa/verify">
    ${hidden}
    ${field('code', copy.code, '<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" autofocus>', false)}
    ${field('recoveryCode', copy.recovery, '<input id="recoveryCode" name="recoveryCode" autocomplete="off" spellcheck="false">', false)}
    <button type="submit">${escape(copy.verify)}</button>
  </form>`;
      lead = terminal ? undefined : copy.verifyLead;
      break;
    case 'enroll-start':
      title = copy.enrollTitle;
      body = terminal
        ? signInLink
        : `<form method="post" action="/api/auth/mfa/enrollment">
    ${hidden}
    <button type="submit">${escape(copy.start)}</button>
  </form>`;
      lead = terminal ? undefined : copy.enrollLead;
      break;
    case 'enroll-confirm':
      title = copy.enrollTitle;
      lead = copy.enrollLead;
      body = `<div class="field">
    <p class="lead">${escape(copy.key)}</p>
    <p class="secret"><code>${escape(options.state.secret.replaceAll(/(.{4})/g, '$1 ').trim())}</code></p>
    <p><a class="link" href="${escape(options.state.uri)}">${escape(copy.link)}</a></p>
  </div>
  <form method="post" action="/api/auth/mfa/enrollment/confirm">
    ${hidden}
    ${field('code', copy.code, '<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>', true)}
    <button type="submit">${escape(copy.confirm)}</button>
  </form>`;
      break;
    case 'recovery-codes':
      title = copy.codesTitle;
      lead = copy.codesLead;
      body = `<ul class="codes">${options.state.codes.map((code) => `<li><code>${escape(code)}</code></li>`).join('')}</ul>
  <a class="button" href="${escape(options.state.next)}">${escape(copy.continue)}</a>`;
      break;
  }

  return frame({
    language: options.language,
    title,
    body: `    <header>
      <h1>${escape(title)}</h1>
      ${lead === undefined ? '' : `<p class="lead">${escape(lead)}</p>`}
    </header>
    ${alert('danger', 'alert', message)}
  ${body}`,
  });
};
