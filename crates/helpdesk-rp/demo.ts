import type { Locale } from './i18n';

const messages = {
  ja: {
    title: 'mikaki 連携デモ',
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
    logoutBody: 'このデモのログアウトは、mikakiや他のアプリからのログアウトとは別の操作です。',
    opLogout: 'mikaki側のログアウト確認画面',
    expires: 'このデモのセッション上限（UTC）',
    lease: 'mikakiの確認が有効な時刻（UTC）',
    privacy:
      'このデモは名前・メール・Vaultの内容を要求しません。ログインに必要なアプリ別の識別子とセッション情報を専用DBに一時保存します。アプリのセッション上限は1時間です。',
    invitation: '招待・登録について',
    guide: '連携手順を読む',
    rateLimited: '短時間に操作が集中しています。少し待ってから、もう一度お試しください。',
  },
  en: {
    title: 'mikaki integration demo',
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
      'Signing out of this demo is separate from signing out of mikaki or other applications.',
    opLogout: 'Open mikaki’s sign-out confirmation',
    expires: 'This demo’s session limit (UTC)',
    lease: 'mikaki confirmation valid until (UTC)',
    privacy:
      'This demo does not request your name, email or Vault contents. It temporarily stores the application-specific identifier and session information needed for login in a separate database. The application session is limited to one hour.',
    invitation: 'Invitations and registration',
    guide: 'Read the integration guide',
    rateLimited: 'Too many operations in a short time. Please wait a little and try again.',
  },
};
export const demoMessages = (locale: Locale) => messages[locale];
export const demoStyle = `body{color:#27362b;background:#f5f4ea;max-width:760px}nav{border-bottom:1px solid #a5b29f;padding-bottom:1rem}main{padding:1rem 0}button{background:#3c573f;color:white;border:1px solid #314934;border-radius:6px;padding:.7rem 1rem;cursor:pointer}a{color:#344f3b}dl{padding:1rem;border:1px solid #a5b29f;border-radius:8px}dt{font-weight:600}dd{margin:.25rem 0 1rem;overflow-wrap:anywhere}form{margin:1rem 0}h1{font-size:2rem}`;
