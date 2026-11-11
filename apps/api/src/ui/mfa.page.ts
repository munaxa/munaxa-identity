/**
 * The second-factor pages, in the same no-JavaScript form-post style as the sign-in page.
 *
 * Four states: asking for a code at sign-in, starting an enrollment, confirming it (the only page
 * that ever shows the secret), and showing the recovery codes (the only page that ever shows them,
 * once). Every response carrying one of these is `no-store` with `Referrer-Policy: no-referrer`, set
 * by the controller.
 */

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
    dir: 'ltr',
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
    dir: 'rtl',
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

const escape = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#x27;');

export const mfaPage = (options: MfaPageOptions): string => {
  const copy = COPY[options.language];
  const hidden = `<input type="hidden" name="returnTo" value="${escape(options.returnTo)}">
    <input type="hidden" name="lang" value="${options.language}">`;
  const message = options.error === undefined ? undefined : copy[options.error];
  const terminal = options.error === 'expired' || options.error === 'locked';
  const signInLink = `<p><a href="/api/auth/login?lang=${options.language}&amp;returnTo=${encodeURIComponent(options.returnTo)}">${escape(copy.signIn)}</a></p>`;

  let title: string;
  let body: string;
  switch (options.state.kind) {
    case 'verify':
      title = copy.verifyTitle;
      body = terminal
        ? signInLink
        : `<p class="lead">${escape(copy.verifyLead)}</p>
  <form method="post" action="/api/auth/mfa/verify">
    ${hidden}
    <label for="code">${escape(copy.code)}</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" autofocus>
    <label for="recoveryCode">${escape(copy.recovery)}</label>
    <input id="recoveryCode" name="recoveryCode" autocomplete="off" spellcheck="false">
    <button type="submit">${escape(copy.verify)}</button>
  </form>`;
      break;
    case 'enroll-start':
      title = copy.enrollTitle;
      body = terminal
        ? signInLink
        : `<p class="lead">${escape(copy.enrollLead)}</p>
  <form method="post" action="/api/auth/mfa/enrollment">
    ${hidden}
    <button type="submit">${escape(copy.start)}</button>
  </form>`;
      break;
    case 'enroll-confirm':
      title = copy.enrollTitle;
      body = `<p class="lead">${escape(copy.enrollLead)}</p>
  <p>${escape(copy.key)}</p>
  <p class="secret"><code>${escape(options.state.secret.replaceAll(/(.{4})/g, '$1 ').trim())}</code></p>
  <p><a href="${escape(options.state.uri)}">${escape(copy.link)}</a></p>
  <form method="post" action="/api/auth/mfa/enrollment/confirm">
    ${hidden}
    <label for="code">${escape(copy.code)}</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus>
    <button type="submit">${escape(copy.confirm)}</button>
  </form>`;
      break;
    case 'recovery-codes':
      title = copy.codesTitle;
      body = `<p class="lead">${escape(copy.codesLead)}</p>
  <ul class="codes">${options.state.codes.map((code) => `<li><code>${escape(code)}</code></li>`).join('')}</ul>
  <p><a class="button" href="${escape(options.state.next)}">${escape(copy.continue)}</a></p>`;
      break;
  }

  return `<!doctype html>
<html lang="${options.language}" dir="${copy.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escape(title)}</title>
<style>
  :root { color-scheme: light dark; --line: color-mix(in srgb, currentColor 20%, transparent); }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Tahoma, sans-serif; padding: 1.5rem; }
  main { width: 100%; max-width: 24rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  p.lead { margin: 0 0 1.5rem; opacity: .75; font-size: .875rem; }
  label { display: block; font-size: .875rem; margin: 0 0 .25rem; }
  input { width: 100%; padding: .625rem .75rem; margin: 0 0 1rem; font: inherit;
          border: 1px solid var(--line); border-radius: .375rem; background: transparent; color: inherit; }
  button, a.button { display: block; text-align: center; width: 100%; padding: .625rem; font: inherit;
           font-weight: 600; cursor: pointer; border: 1px solid var(--line); border-radius: .375rem;
           background: transparent; color: inherit; text-decoration: none; }
  .error { padding: .75rem; margin: 0 0 1rem; font-size: .875rem; border-radius: .375rem;
           border: 1px solid var(--line); }
  .secret code, .codes code { font-size: 1.05rem; letter-spacing: .05em; word-break: break-all; direction: ltr; }
  .codes { columns: 2; padding-inline-start: 1.25rem; }
</style>
</head>
<body>
<main>
  <h1>${escape(title)}</h1>
  ${message === undefined ? '' : `<p class="error" role="alert">${escape(message)}</p>`}
  ${body}
</main>
</body>
</html>`;
};
