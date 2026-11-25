/**
 * The one frame every Identity page is drawn in: sign-in, second factor and password recovery.
 *
 * **Why it looks like Munaxa Docs.** Docs v2 has the approved sign-in layout: a muted page, one
 * card in the middle with the brand at its head, the controls a reader may need *before* signing
 * in at the top of the page, and a line under the card saying that access is audited. These pages
 * are the front door of every other product (Munaxa Control's operator console, Munaxa Work), so
 * they take the same layout. The colours are the Munaxa Group palette, not a product's: the front
 * door belongs to the company. Every value below is copied from `@munaxa/platform`
 * `themes/group/palette.css` and `themes/base/base.css`; change them there first.
 *
 * **Why still no script and no external file.** The page is served by the service that owns the
 * credential and must work with no JavaScript and nothing else to load. The styles are inline,
 * there is no web font (the system face), and the mark is a 1.2 KB data URI: the corporate
 * symbol from `assets/group/logos/symbol.png`, cropped to its artwork and reduced to 91x60 px.
 * The corporate identity has no lockup, so the wordmark is set as text beside it, which is what
 * the platform's own brand module tells corporate surfaces to do.
 *
 * **No theme toggle.** Docs has one because it has a script; here the colour scheme follows the
 * device (`prefers-color-scheme`), which needs none.
 */

export type Language = 'en' | 'ar';

export const escapeHtml = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#x27;');

/** The Munaxa Group symbol, 91x60 px, 32-colour PNG. sha256 of the bytes: c974f894…f8ed033. */
const SYMBOL =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFsAAAA8CAMAAAA+GTZJAAAAYFBMVEVFUHWXmqYjI3xpcYxMV3ldZoRxd5Hd19MJb28AAP9QWnsbNj86R257gZeKj6MA//9bY4RXX3t9gpi5ucIjMl8+SnF/f/8qOWYAAAA3RG9VVVX///1VVap/f39IVHdNWHqiKmfQAAAAIHRSTlPwIgNdmpUsDwIBdgTXUUYB2BcxHf+vAv4A/AMDAwLMr4Qed5QAAAPmSURBVHjanZjrdqwoEIU3qK2edHeSk5kRRPH933K42a1Sha74K1nVbD+LugEU88xKiWqxGkvVhv+OVlM1FrCNNxtSAoz0qNoGevCPRmUO4rNTttqbtXZmRhyc9N+4Nqp/iZ34rISzvs1LS4qDccjtvTSKy/dqqcR92D56MdNV7VkK7BejcZ+Snn5s7bB/dKOmi9qTqvV+MXB7rZaqOVidXWTbTWs7d2aLh2UF/1Q3ZGYHLi9pS1Vn0gNM2i+pqvzNgzWXfOK8TSzWIjlFmmUgzFUOjiveDtx1dIpRLWH14Be0R8rbPknW7bpR0h58OtWe1EIuHtYw/Ka1beYU5Ng3TWvHOPtUh9h/pUAGnmsb0NJrnEljaXsGjiz+KgbbgYeyIdUf5t3iAH7U7oxltWOcGXqvfVV51wVK+6OAPQz3tu9DajHit734XruXbUE6gc/Mbm7qAqXtfFnUdh7vmZqQPD5y2jzREfySx3FapPYeD5k9FsBnWpvlycGZ/NL1NgyxS0lf9DV0EXyO4PocHLsi9eVngmdVncX4f+zGbMG32nPz9Ux/i4VTt8njDf0D/LzBsfX2w+/nJCa/msuhs1DZNLetv12xuE1i9t1pZhPUxVn0+MKkgPApkMfgd6opcymNdOj4PPifFzh2M55qxVO0KmTAh7Lcdo0FcBcqvTlqT8o8FgBuzhFpbPsd+KsrYxOB6/SI2EJYsqUMjjaB4yVdYW267vEz2MSSXQTH6pD9D5199GT6d+BxTEraxyaoren9C1HoXuMZOJguGewdU+90cwk8aBvZIv9u6RZ/ay5BpsK4kcChmOrg3l2od4v7psKY5AbTPmqTO46nEgWyUEtZMwI4greJeHDf1fnV/9KL40GBjSS0UXsiy1LUntSDHjxRBg8eRxh3+J7dkVXFJfBaVWq2zBt4bNDbEZPqiV96vIORdAYsKXE7phymtstGkgMHMzfoR2p8E9skhE+QEjjovNbLq8Kz4LF7dVyMW+dv8ps250UOXMfM5qvlA/QnbY+Ls6JHinTCkRx4DRq77bYHoAeY5iZVAdwC+vTMNdIedw7/UAWPA3fykDvvT26kx91+f0Qz6dd/gAvzPweetLnxV+N+Ov6z4OskwoAvsCdDdAoV4vv035WB9LiukBeT+ojNgL9P8CS4FvjBOTZ5YN0Gk1SUGdlJtKauh3Lw3dmG+C5rOoxmnz1WdJ/kxVudF+jthhwm07twNbZXoj67eEqBtl29iP213bgXtze//+4njjzdMuqGkw4zzCuHdXO8jfQn6rXsOJnWOxZhpBf++tOddYRipcMcU/lB1/3ux991HG8C3uYk8z/xKNfsHzHiDgAAAABJRU5ErkJggg==';

const FRAME_COPY = {
  en: { dir: 'ltr', audited: 'Access is logged to the audit trail.', brand: 'Munaxa' },
  ar: { dir: 'rtl', audited: 'يُسجَّل كل دخول في سجل التدقيق.', brand: 'مُناخة' },
} as const;

/** Group palette (light), base geometry, and the dark scheme. */
const STYLES = `
  :root { color-scheme: light;
    --background: #f2f4f7; --foreground: #101828; --card: #ffffff;
    --primary: #2b3a67; --primary-hover: #3c4e85; --primary-foreground: #ffffff;
    --muted-foreground: #667085; --border: #e4e7ec; --input: #d0d5dd; --ring: #2b3a67;
    --accent: #f4f7fe; --accent-foreground: #2b3a67;
    --destructive: #ef4444; --destructive-strong: #c70f22; --info: #0ea5e9;
    --shadow-tint: 31 43 77; --symbol-ground: transparent; --symbol-pad: 0; }
  @media (prefers-color-scheme: dark) {
    :root { color-scheme: dark;
      --background: #0a0f1a; --foreground: #fafbfc; --card: #101828;
      --primary: #7e93c9; --primary-hover: #9babd5; --primary-foreground: #101828;
      --muted-foreground: #98a2b3; --border: rgb(255 255 255 / .12); --input: rgb(255 255 255 / .16);
      --ring: #7e93c9; --accent: #1d2939; --accent-foreground: #fafbfc;
      --destructive-strong: #ff5f5b; --shadow-tint: 0 0 0; --symbol-ground: #ffffff; --symbol-pad: 3px 4px; }
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body { min-height: 100vh; min-height: 100dvh; display: flex; flex-direction: column;
         background: var(--background); color: var(--foreground);
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Tahoma, "Noto Sans Arabic", sans-serif;
         -webkit-font-smoothing: antialiased; }
  .top { display: flex; justify-content: flex-end; gap: .375rem; padding: 1rem 1.25rem; min-height: 4rem; }
  .chip { display: inline-flex; align-items: center; height: 2rem; padding: 0 .75rem; border-radius: .375rem;
          border: 1px solid var(--border); background: var(--card); color: var(--foreground);
          font-size: .875rem; font-weight: 500; text-decoration: none; }
  .chip:hover { background: var(--accent); color: var(--accent-foreground); }
  main { flex: 1; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
  .card { width: 100%; max-width: 380px; display: flex; flex-direction: column; gap: 1.5rem; padding: 2rem;
          background: var(--card); border: 1px solid var(--border); border-radius: 14px;
          box-shadow: 0 24px 50px -30px rgb(var(--shadow-tint) / .25), 0 0 0 1px var(--border) inset; }
  .brand { display: flex; align-items: center; gap: .625rem; height: 30px; }
  .brand img { box-sizing: content-box; height: 26px; width: auto; display: block; padding: var(--symbol-pad); border-radius: 6px;
               background: var(--symbol-ground); }
  .brand span { font-size: 1.625rem; font-weight: 800; letter-spacing: -.03em; line-height: 1; direction: ltr; }
  .brand b { color: var(--primary); }
  header { display: flex; flex-direction: column; gap: .25rem; }
  h1 { font-size: 1.5rem; line-height: 2rem; font-weight: 600; margin: 0; }
  p { margin: 0; }
  .lead { color: var(--muted-foreground); font-size: .875rem; }
  form { display: flex; flex-direction: column; gap: 1.5rem; margin: 0; }
  .field { display: flex; flex-direction: column; gap: .375rem; }
  label { font: 500 .75rem/1rem ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          text-transform: uppercase; letter-spacing: .025em; color: var(--muted-foreground); }
  [dir="rtl"] label { font-family: inherit; letter-spacing: 0; font-size: .8125rem; }
  label .req { color: var(--destructive); margin-inline-start: .125rem; }
  input { width: 100%; height: 2.25rem; padding: 0 .75rem; font: inherit; font-size: .875rem;
          color: var(--foreground); background: transparent; border: 1px solid var(--input); border-radius: .375rem;
          box-shadow: 0 1px 2px 0 rgb(16 24 40 / .05); }
  input:focus-visible, .button:focus-visible, button:focus-visible, a:focus-visible {
          outline: 2px solid var(--ring); outline-offset: 2px; }
  button, .button { display: inline-flex; align-items: center; justify-content: center; width: 100%; height: 2.25rem;
          padding: 0 1rem; font: inherit; font-size: .875rem; font-weight: 500; cursor: pointer; text-decoration: none;
          border: 0; border-radius: .375rem; background: var(--primary); color: var(--primary-foreground); }
  button:hover, .button:hover { background: var(--primary-hover); }
  .alert { padding: 1rem; font-size: .875rem; border-radius: .5rem; border: 1px solid; }
  .alert.danger { border-color: rgb(239 68 68 / .3); background: rgb(239 68 68 / .1); }
  .alert.info { border-color: rgb(14 165 233 / .3); background: rgb(14 165 233 / .1); }
  .link { font-size: .875rem; color: var(--primary); text-underline-offset: 3px; }
  .links { display: flex; flex-direction: column; gap: .5rem; }
  .secret code, .codes code { font-size: 1.05rem; letter-spacing: .05em; word-break: break-all; direction: ltr; }
  .secret { padding: .75rem; border-radius: .5rem; background: var(--background); }
  .codes { columns: 2; margin: 0; padding-inline-start: 1.25rem; }
  .audited { margin: 0 0 1.25rem; text-align: center; font-size: .75rem; color: var(--muted-foreground); }
  @media (max-width: 420px) { main { padding: 1rem; } .card { padding: 1.5rem; } }
`;

export interface FrameOptions {
  readonly language: Language;
  readonly title: string;
  /** The card's contents below the brand: heading, message, form, links. Already escaped. */
  readonly body: string;
  /** The other language's version of this same page, when the page has one. */
  readonly languageSwitch?: { readonly href: string } | undefined;
}

/** One labelled field, the label above the control as in the platform's `Field`. */
export const field = (id: string, label: string, control: string, required: boolean): string =>
  `<div class="field">
      <label for="${id}">${escapeHtml(label)}${required ? '<span class="req" aria-hidden="true">*</span>' : ''}</label>
      ${control}
    </div>`;

/** A bordered message with a tone, as the platform's `Alert`. */
export const alert = (
  tone: 'danger' | 'info',
  role: 'alert' | 'status',
  text: string | undefined,
): string =>
  text === undefined ? '' : `<p class="alert ${tone}" role="${role}">${escapeHtml(text)}</p>`;

export const frame = (options: FrameOptions): string => {
  const copy = FRAME_COPY[options.language];
  const other = options.language === 'en' ? 'ar' : 'en';
  const switchLink =
    options.languageSwitch === undefined
      ? ''
      : `<a class="chip" href="${options.languageSwitch.href}" lang="${other}" hreflang="${other}">${
          other === 'ar' ? 'العربية' : 'English'
        }</a>`;

  return `<!doctype html>
<html lang="${options.language}" dir="${copy.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(options.title)}</title>
<style>${STYLES}</style>
</head>
<body>
<div class="top">${switchLink}</div>
<main>
  <div class="card">
    <div class="brand" role="img" aria-label="${escapeHtml(copy.brand)}"><img src="${SYMBOL}" width="39" height="26" alt=""><span aria-hidden="true">munaxa<b>.</b></span></div>
${options.body}
  </div>
</main>
<p class="audited">${escapeHtml(copy.audited)}</p>
</body>
</html>`;
};
