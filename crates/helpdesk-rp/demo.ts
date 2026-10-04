import type { Locale } from './i18n';

const messages = {
  ja: {
    title: 'mikaki 連携デモ',
    skip: '本文へ移動',
    navigation: 'デモのメニュー',
    overview: 'デモのトップ',
    official: 'mikakiの公式サイト',
    start: 'サインインして、接続を確かめる',
    steps: 'このデモで試すこと',
    stepLogin: 'mikakiでサインインし、このデモに戻ります。',
    stepCheck: 'ログイン状態を開き、セッションを再確認します。',
    stepLogout: 'このデモからログアウトし、保護された画面が開けなくなることを確認します。',
    privacyTitle: 'このデモで扱う情報',
    opLogoutDetails: 'mikaki全体からのログアウトについて',
    opLogoutWarning:
      'mikakiのSSOを終了すると、他の接続アプリにも影響します。次の確認画面で対象を確かめてから操作してください。',
    home: '公開IdPへの接続を試す',
    intro:
      'mikakiでサインインし、このアプリのログイン状態を確認できます。mikakiの登録済みパスキーが必要です。',
    session: 'ログイン状態',
    login: 'mikakiでサインイン',
    active: 'サインイン済み',
    loginRequired: 'このデモのログイン状態を見るには、サインインしてください。',
    sessionBody:
      'このアプリには、有効な確認期間内のログイン状態があります。「セッションを再確認」でmikakiに現在の状態を問い合わせます。',
    check: 'セッションを再確認',
    logout: 'このデモからログアウト',
    logoutBody:
      'このデモだけのログイン状態を削除します。mikakiのSSOや他のアプリのログインは終了しません。',
    opLogout: 'mikaki側のログアウト確認画面',
    expires: 'このデモのセッション上限（UTC）',
    lease: '次のセッション確認期限（UTC）',
    privacy:
      'このデモは名前・メール・Vaultの内容を要求しません。ログインに必要なアプリ別の識別子とセッション情報を専用DBに一時保存します。アプリのセッション上限は1時間です。',
    invitation: '招待・登録について',
    guide: '連携手順を読む',
    rateLimited: '短時間に操作が集中しています。少し待ってから、もう一度お試しください。',
  },
  en: {
    title: 'mikaki integration demo',
    skip: 'Skip to content',
    navigation: 'Demo navigation',
    overview: 'Demo home',
    official: 'mikaki official website',
    start: 'Sign in to check the connection',
    steps: 'What you can try',
    stepLogin: 'Sign in with mikaki and return to this demo.',
    stepCheck: 'Open the login state and check the session again.',
    stepLogout:
      'Sign out of this demo and confirm that its protected page is no longer accessible.',
    privacyTitle: 'Information this demo uses',
    opLogoutDetails: 'About signing out of mikaki itself',
    opLogoutWarning:
      'Ending mikaki’s SSO can affect other connected applications. Review the affected sessions on the next confirmation screen before acting.',
    home: 'Try the public identity provider',
    intro:
      'Sign in with mikaki and check this application’s login state. You need a passkey registered with mikaki.',
    session: 'Login state',
    login: 'Sign in with mikaki',
    active: 'Signed in',
    loginRequired: 'Sign in to view this demo’s login state.',
    sessionBody:
      'This application has a login state within its confirmation period. “Check session again” asks mikaki for the current state.',
    check: 'Check session again',
    logout: 'Sign out of this demo',
    logoutBody:
      'This removes only the demo’s login state. It does not end mikaki SSO or sign you out of other applications.',
    opLogout: 'Open mikaki’s sign-out confirmation',
    expires: 'This demo’s session limit (UTC)',
    lease: 'Next session check due (UTC)',
    privacy:
      'This demo does not request your name, email or Vault contents. It temporarily stores the application-specific identifier and session information needed for login in a separate database. The application session is limited to one hour.',
    invitation: 'Invitations and registration',
    guide: 'Read the integration guide',
    rateLimited: 'Too many operations in a short time. Please wait a little and try again.',
  },
};
export const demoMessages = (locale: Locale) => messages[locale];
const safe = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );
export const formatDemoTime = (seconds: number, locale: Locale) =>
  new Intl.DateTimeFormat(locale, {
    dateStyle: 'medium',
    timeStyle: 'medium',
    timeZone: 'UTC',
  }).format(new Date(seconds * 1000));
export function demoDocument(locale: Locale, content: string, languageUrl: string, path: string) {
  const t = demoMessages(locale);
  return `<!doctype html><html lang="${locale}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safe(t.title)}</title><style>${demoStyle}</style></head><body><a class="skip-link" href="#main-content">${safe(t.skip)}</a><header class="demo-header"><div class="demo-header-inner"><a class="demo-brand" href="/">mikaki <span>${locale === 'ja' ? '連携デモ' : 'integration demo'}</span></a><nav aria-label="${safe(t.navigation)}"><a href="/"${path === '/' ? ' aria-current="page"' : ''}>${safe(t.overview)}</a><a href="/session"${path === '/session' ? ' aria-current="page"' : ''}>${safe(t.session)}</a></nav><a class="language" href="${safe(languageUrl)}" lang="${locale === 'ja' ? 'en' : 'ja'}">${locale === 'ja' ? 'English' : '日本語'}</a></div></header><main id="main-content" class="demo-main" tabindex="-1">${content}</main><footer class="demo-footer"><span>demo.mikaki.org</span><a href="https://mikaki.org${locale === 'en' ? '/en/' : '/'}">${safe(t.official)}</a></footer></body></html>`;
}
const demoStyle = `
:root{font-family:Inter,'Helvetica Neue',Arial,'Hiragino Kaku Gothic ProN',Meiryo,sans-serif;color:#223c32;background:#f6f7f2;color-scheme:light;font-synthesis:none}
*{box-sizing:border-box}body{margin:0;font-size:17px;line-height:1.8}a{color:#285441;text-underline-offset:.2em;overflow-wrap:anywhere}button{font:inherit;cursor:pointer}button,a{touch-action:manipulation}:focus-visible{outline:3px solid #a34016;outline-offset:4px}main:focus{outline:none}
.skip-link{position:fixed;top:-100px;left:16px;z-index:10;background:white;border:2px solid #285441;padding:12px 20px}.skip-link:focus{top:12px}
.demo-header{background:white;border-bottom:1px solid #d6ded4}.demo-header-inner{max-width:1160px;padding:20px 40px;margin:auto;display:flex;align-items:center;gap:32px}.demo-brand{font-size:25px;font-weight:650;text-decoration:none;color:#223c32;white-space:nowrap}.demo-brand span{display:block;font-size:12px;font-weight:500;letter-spacing:.05em;color:#52645b}.demo-header nav{display:flex;gap:8px;margin-left:auto}.demo-header nav a,.language{display:inline-flex;align-items:center;min-height:44px;padding:8px 12px;font-size:14px}.demo-header nav a{text-decoration:none;border-radius:6px}.demo-header [aria-current='page']{background:#e8eee3;font-weight:650}
.demo-main{max-width:880px;margin:auto;padding:48px 40px 56px}.eyebrow{font-size:13px;font-weight:650;letter-spacing:.05em;color:#52645b;margin:0 0 12px}h1{font-size:clamp(28px,4vw,38px);line-height:1.5;letter-spacing:-.025em;margin:0 0 20px}h2{font-size:21px;line-height:1.6;margin:0 0 14px}p{margin:12px 0}.demo-intro{margin-bottom:28px}.demo-intro p:last-child{max-width:66ch;color:#52645b}.task-panel{background:white;border:1px solid #d6ded4;border-radius:10px;padding:28px 32px}.task-panel form{margin:20px 0 0}.task-panel .status{display:inline-block;color:#173d2c;background:#e6efdf;border-radius:5px;padding:6px 12px;font-size:18px}
button,.button{display:inline-flex;justify-content:center;align-items:center;min-height:48px;padding:12px 22px;background:#285441;color:white;border:1px solid #285441;border-radius:6px;font-size:15px;font-weight:600;text-decoration:none;line-height:1.5}button:hover,.button:hover{background:#193e2e}.secondary{background:white;color:#285441}.secondary:hover{background:#eaf0e8}
.demo-steps{margin:32px 0}.demo-steps ol{padding-left:1.5em}.demo-steps li{padding-left:6px;margin:10px 0}.privacy-note{padding:24px 28px;border-radius:8px;background:#eaf0e5;color:#36513f}.privacy-note h2{font-size:18px}.privacy-note p{font-size:15px}.privacy-note a{display:inline-block;min-height:44px;padding:8px 0;margin-right:20px}
.session-times{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:24px 0;padding:22px 0;border-block:1px solid #d6ded4}.session-times dt{font-size:14px;font-weight:650;color:#52645b}.session-times dd{margin:8px 0 0;font-size:16px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.session-actions{display:flex;flex-wrap:wrap;gap:14px}.session-actions form{margin:0}.logout-note{font-size:15px;color:#52645b;margin-top:18px}.op-logout{margin-top:24px;border:1px solid #d6ded4;border-radius:8px;padding:16px 20px}.op-logout summary{min-height:32px;cursor:pointer;font-size:15px;font-weight:600}.op-logout p{font-size:15px}.demo-footer{max-width:800px;margin:auto;padding:22px 0 32px;border-top:1px solid #d6ded4;display:flex;justify-content:space-between;gap:20px;color:#52645b;font-size:14px}
@media(max-width:600px){body{font-size:16px}.demo-header-inner{padding:16px 20px;gap:12px;flex-wrap:wrap}.demo-header nav{order:3;width:100%;margin-left:0}.language{margin-left:auto}.demo-header nav a{flex:1}.demo-main{padding:32px 20px 40px}.task-panel{padding:24px 20px}.session-times{grid-template-columns:1fr;gap:18px}.session-actions{flex-direction:column}.session-actions button{width:100%}.privacy-note{padding:22px}.demo-footer{margin:0 20px;padding:20px 0;flex-wrap:wrap}.task-panel>form button{width:100%}}
@media(forced-colors:active){button,.button,.task-panel,.privacy-note{border:1px solid ButtonText}:focus-visible{outline-color:Highlight}}
`;
