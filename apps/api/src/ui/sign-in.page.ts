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
 */

export interface SignInPageOptions {
  readonly language: 'en' | 'ar';
  readonly returnTo: string;
  /** Present only after a failed attempt. Every credential failure produces the same one. */
  readonly error?: 'invalid' | 'locked' | 'mfa' | 'password-policy' | undefined;
  readonly organisationRequired: boolean;
}

const COPY = {
  en: {
    dir: 'ltr',
    title: 'Sign in to Munaxa',
    lead: 'Munaxa Identity signs you in. Munaxa Work never sees your password.',
    identifier: 'Email address',
    password: 'Password',
    organisation: 'Organisation',
    submit: 'Sign in',
    invalid: 'Those details were not accepted. Check them and try again.',
    locked: 'Too many attempts. Wait a few minutes before trying again.',
    mfa: 'This account needs a second factor, which this deployment cannot yet ask for.',
    policy: 'This password must be changed before the account can be used.',
  },
  ar: {
    dir: 'rtl',
    title: 'تسجيل الدخول إلى مُناخة',
    lead: 'هوية مُناخة هي التي تسجّل دخولك. لا يرى تطبيق العمل كلمة المرور إطلاقًا.',
    identifier: 'البريد الإلكتروني',
    password: 'كلمة المرور',
    organisation: 'المؤسسة',
    submit: 'تسجيل الدخول',
    invalid: 'لم تُقبل هذه البيانات. تحقّق منها وحاول مرة أخرى.',
    locked: 'محاولات كثيرة. انتظر بضع دقائق قبل المحاولة مجددًا.',
    mfa: 'يحتاج هذا الحساب إلى عامل ثانٍ لا يستطيع هذا النشر طلبه بعد.',
    policy: 'يجب تغيير كلمة المرور قبل استخدام هذا الحساب.',
  },
} as const;

/** Escaped everywhere it is interpolated: `returnTo` reaches this from the query string. */
const escape = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#x27;');

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
    default:
      return undefined;
  }
};

export const signInPage = (options: SignInPageOptions): string => {
  const copy = COPY[options.language];
  const message = messageFor(options.error, copy);
  const other = options.language === 'en' ? 'ar' : 'en';

  return `<!doctype html>
<html lang="${options.language}" dir="${copy.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(copy.title)}</title>
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
  button { width: 100%; padding: .625rem; font: inherit; font-weight: 600; cursor: pointer;
           border: 1px solid var(--line); border-radius: .375rem; background: transparent; color: inherit; }
  .error { padding: .75rem; margin: 0 0 1rem; font-size: .875rem; border-radius: .375rem;
           border: 1px solid var(--line); }
  .lang { display: block; margin-top: 1.5rem; font-size: .8125rem; opacity: .7; }
</style>
</head>
<body>
<main>
  <h1>${escape(copy.title)}</h1>
  <p class="lead">${escape(copy.lead)}</p>
  ${message === undefined ? '' : `<p class="error" role="alert">${escape(message)}</p>`}
  <form method="post" action="/api/auth/login">
    <input type="hidden" name="returnTo" value="${escape(options.returnTo)}">
    <input type="hidden" name="lang" value="${options.language}">
    <label for="identifier">${escape(copy.identifier)}</label>
    <input id="identifier" name="identifier" type="email" autocomplete="username" required autofocus>
    <label for="password">${escape(copy.password)}</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    ${
      options.organisationRequired
        ? `<label for="organisation">${escape(copy.organisation)}</label>
    <input id="organisation" name="organisation" autocomplete="organization" required>`
        : ''
    }
    <button type="submit">${escape(copy.submit)}</button>
  </form>
  <a class="lang" href="?lang=${other}&amp;returnTo=${encodeURIComponent(options.returnTo)}">${
    other === 'ar' ? 'العربية' : 'English'
  }</a>
</main>
</body>
</html>`;
};
