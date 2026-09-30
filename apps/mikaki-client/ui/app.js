const $ = (selector) => document.querySelector(selector);
const invoke = window.__TAURI__?.core?.invoke;
const screens = [...document.querySelectorAll('.screen')];
const login = $('#login');
const cancel = $('#cancel-login');
const navigation = $('#navigation');
const dialog = $('#logout-dialog');
const theme = $('#theme');
let platform;
let available = false;
let signedIn = false;
let pending = null;
let starting = false;
let cancelling = false;
let diagnosticBusy = false;
let grantAvailable = false;
let epoch = 0;
let readSequence = 0;
let timer;
let themeChoice = 'system';

function notice(message = '') {
  $('#status').textContent = message;
  $('#status').hidden = !message;
}
function diagnostic(error) {
  $('#diagnostic-error').textContent = String(error).slice(0, 500);
  $('#error-details').hidden = false;
}
function friendly(error) {
  const value = String(error);
  if (/timed out|expired/i.test(value))
    return '本人確認が時間切れになりました。もう一度ログインしてください。';
  if (/cancelled|denied/i.test(value))
    return '本人確認が取り消されました。もう一度試すことができます。';
  return 'ログインを完了できませんでした。接続を確認して、もう一度試してください。';
}
function route() {
  const requested = location.hash.slice(1);
  const allowed = signedIn
    ? ['home', 'account', 'settings', 'diagnostics']
    : ['welcome', 'settings', 'diagnostics'];
  return allowed.includes(requested) ? requested : signedIn ? 'home' : 'welcome';
}
function navigate(view, replace = false) {
  if (pending) return;
  const depth = replace ? 0 : (history.state?.mikakiDepth ?? 0) + 1;
  if (replace || location.hash !== '#' + view) {
    history[replace ? 'replaceState' : 'pushState']({ mikakiDepth: depth }, '', '#' + view);
  }
  render(true);
}
function render(focus = false) {
  const view = pending ? 'waiting' : route();
  for (const screen of screens) screen.hidden = screen.id !== view;
  navigation.hidden = !signedIn || !!pending;
  $('#open-settings').disabled = !!pending;
  $('#session-settings').hidden = !signedIn;
  $('#open-logout').disabled = diagnosticBusy || !!pending;
  login.disabled = !available || !!pending;
  cancel.disabled = cancelling;
  cancel.textContent = cancelling ? '終了しています…' : 'キャンセルして戻る';
  $('#diagnostic-session').textContent = signedIn ? 'ログイン済み' : 'ログインしていません';
  $('#diagnostic-platform').textContent =
    platform === 'mobile'
      ? 'スマートフォン'
      : platform === 'desktop'
        ? 'デスクトップ'
        : '利用できません';
  $('#vault-key').disabled = !available || diagnosticBusy || !!pending;
  $('#vault-consent').disabled = !available || !signedIn || diagnosticBusy || !!pending;
  $('#vault-read').disabled = !available || !grantAvailable || diagnosticBusy || !!pending;
  for (const tab of navigation.querySelectorAll('a')) {
    const selected =
      tab.dataset.nav ===
      (view === 'account' ? 'home' : view === 'diagnostics' ? 'settings' : view);
    if (selected) tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  }
  if (focus) {
    window.scrollTo(0, 0);
    // Focus the heading for keyboard/screen-reader navigation without keeping it in tab order.
    const heading = $('#' + view).querySelector('h1');
    heading.setAttribute('tabindex', '-1');
    heading.focus({ preventScroll: true });
    heading.addEventListener('blur', () => heading.removeAttribute('tabindex'), { once: true });
  }
}
function schedule() {
  clearTimeout(timer);
  if (!pending || document.hidden || starting || cancelling) return;
  timer = setTimeout(() => void refreshNative(), 1000);
}
function showWaiting(kind) {
  $('#waiting-title').innerHTML =
    kind === 'vault'
      ? 'ブラウザで<br />読取を承認してください'
      : 'ブラウザで<br />本人確認してください';
  $('#waiting-description').textContent = '完了すると、このアプリに戻ります。';
  $('#waiting-phase').textContent = 'ブラウザを開いています';
  $('#check-auth').hidden = true;
  notice();
  render(true);
}
function applyMobile(result) {
  const wasPending = pending;
  signedIn = typeof result.subject === 'string' && result.subject.length > 0;
  $('#vault').hidden = !result.vault_preview_available;
  grantAvailable = result.vault_attribute === 'owner_note';
  if (result.phase === 'pending' || result.phase === 'exchanging') {
    pending ||= 'login';
    $('#waiting-phase').textContent =
      result.phase === 'exchanging' ? 'ログインを確認しています' : 'ブラウザでの完了を待っています';
    render();
    schedule();
    return;
  }
  pending = null;
  clearTimeout(timer);
  if (wasPending) {
    if (result.phase === 'vault_complete') {
      $('#vault-status').textContent = 'Vault読取が承認されました。暗号文を取得できます。';
      navigate('diagnostics', true);
    } else if (result.phase === 'complete' && signedIn) {
      navigate('home', true);
      notice('ログインしました。');
    } else {
      navigate(wasPending === 'vault' ? 'diagnostics' : signedIn ? 'home' : 'welcome', true);
      const messages = {
        denied: '本人確認が取り消されました。もう一度試すことができます。',
        failed: 'ログインを完了できませんでした。もう一度試してください。',
        expired: '本人確認が時間切れになりました。もう一度試してください。',
        idle: '本人確認を終了しました。',
      };
      notice(messages[result.phase] ?? 'ログインを完了できませんでした。もう一度試してください。');
    }
  } else render();
}
async function refreshNative() {
  if (!available || starting || cancelling) return;
  const generation = epoch;
  const sequence = ++readSequence;
  try {
    const result = await invoke(platform === 'mobile' ? 'mobile_auth_status' : 'native_session');
    if (generation !== epoch || sequence !== readSequence) return;
    $('#check-auth').hidden = true;
    if (platform === 'mobile') applyMobile(result);
    else {
      signedIn = !!result;
      render();
    }
  } catch (error) {
    if (generation !== epoch || sequence !== readSequence) return;
    diagnostic(error);
    notice('ログイン状態を確認できませんでした。もう一度確認してください。');
    $('#check-auth').hidden = !pending;
    schedule();
  }
}
async function bootstrap() {
  if (!invoke) {
    notice('この環境ではログインを利用できません。');
    render();
    return;
  }
  const generation = ++epoch;
  clearTimeout(timer);
  try {
    platform = await invoke('native_platform');
    const session = await invoke('native_session');
    const mobile = platform === 'mobile' ? await invoke('mobile_auth_status') : null;
    if (generation !== epoch) return;
    available = true;
    signedIn = !!session;
    notice();
    $('#retry-init').hidden = true;
    if (mobile) {
      if (mobile.phase === 'pending' || mobile.phase === 'exchanging') {
        pending = 'login';
        showWaiting(pending);
      }
      applyMobile(mobile);
    }
    if (!pending) navigate(signedIn ? 'home' : 'welcome', true);
    render();
  } catch (error) {
    if (generation !== epoch) return;
    available = false;
    diagnostic(error);
    notice('接続を確認できませんでした。もう一度確認してください。');
    $('#retry-init').hidden = false;
    render();
  }
}
async function start(kind = 'login') {
  if (!available || pending || diagnosticBusy) return;
  const generation = ++epoch;
  pending = kind;
  starting = true;
  showWaiting(kind);
  try {
    if (kind === 'vault') {
      await invoke('start_mobile_vault_read', { attribute: 'owner_note' });
    } else if (platform === 'mobile') {
      await invoke('start_mobile_login');
    } else {
      const session = await invoke('start_desktop_login');
      if (generation !== epoch) return;
      signedIn = !!session;
      pending = null;
      starting = false;
      navigate(signedIn ? 'home' : 'welcome', true);
      notice(signedIn ? 'ログインしました。' : 'ログインを完了できませんでした。');
      return;
    }
    if (generation !== epoch) return;
    starting = false;
    await refreshNative();
  } catch (error) {
    if (generation !== epoch) return;
    starting = false;
    pending = null;
    diagnostic(error);
    await refreshNative();
    if (generation !== epoch) return;
    if (!pending) {
      navigate(kind === 'vault' ? 'diagnostics' : signedIn ? 'home' : 'welcome', true);
      notice(friendly(error));
    }
  }
}
login.addEventListener('click', () => void start());
$('#vault-consent').addEventListener('click', () => void start('vault'));
$('#retry-init').addEventListener('click', () => void bootstrap());
$('#check-auth').addEventListener('click', () => void refreshNative());
cancel.addEventListener('click', async () => {
  if (!pending || cancelling) return;
  const kind = pending;
  const generation = ++epoch;
  clearTimeout(timer);
  cancelling = true;
  render();
  try {
    await invoke('cancel_native_login');
    if (generation !== epoch) return;
    pending = null;
    starting = false;
    cancelling = false;
    await refreshNative();
    if (generation !== epoch) return;
    navigate(kind === 'vault' ? 'diagnostics' : signedIn ? 'home' : 'welcome', true);
    notice('本人確認を終了しました。');
  } catch (error) {
    if (generation !== epoch) return;
    cancelling = false;
    starting = false;
    diagnostic(error);
    notice('本人確認を終了できませんでした。もう一度試してください。');
    schedule();
    render();
  }
});
$('#open-settings').addEventListener('click', () => navigate('settings'));
document.addEventListener('click', (event) => {
  const anchor = event.target.closest('a[href^="#"]');
  if (!anchor) return;
  event.preventDefault();
  if (pending) return;
  notice();
  navigate(anchor.hash.slice(1));
});
document.querySelectorAll('[data-back]').forEach((button) => {
  button.addEventListener('click', () => {
    notice();
    if ((history.state?.mikakiDepth ?? 0) > 0) history.back();
    else navigate(route() === 'diagnostics' ? 'settings' : signedIn ? 'home' : 'welcome', true);
  });
});
window.addEventListener('popstate', () => {
  if (dialog.open) dialog.close();
  if (!pending && location.hash !== '#' + route()) {
    history.replaceState({ mikakiDepth: 0 }, '', '#' + route());
  }
  notice();
  render(true);
});
$('#open-logout').addEventListener('click', () => {
  if (!signedIn || pending || diagnosticBusy) return;
  $('#logout-error').hidden = true;
  dialog.showModal();
});
$('#keep-session').addEventListener('click', () => dialog.close());
$('#clear').addEventListener('click', async () => {
  if (!dialog.open || !signedIn || $('#clear').disabled) return;
  $('#clear').disabled = true;
  $('#keep-session').disabled = true;
  const generation = ++epoch;
  clearTimeout(timer);
  try {
    await invoke('clear_native_session');
    if (generation !== epoch) return;
    epoch++;
    signedIn = false;
    pending = null;
    grantAvailable = false;
    $('#vault-status').textContent = '';
    dialog.close();
    navigate('welcome', true);
    notice('この端末からログアウトしました。');
  } catch (error) {
    diagnostic(error);
    $('#logout-error').textContent = 'ログアウトできませんでした。もう一度試してください。';
    $('#logout-error').hidden = false;
  } finally {
    $('#clear').disabled = false;
    $('#keep-session').disabled = false;
    render();
  }
});
dialog.addEventListener('cancel', (event) => {
  if ($('#clear').disabled) event.preventDefault();
});
async function runDiagnostic(command) {
  if (!available || pending || diagnosticBusy) return;
  diagnosticBusy = true;
  render();
  $('#vault-status').textContent =
    command === 'check_mobile_vault_key'
      ? '端末の鍵を確認しています。'
      : '暗号文を取得しています。';
  const generation = epoch;
  try {
    const result = await invoke(command);
    if (generation !== epoch) return;
    $('#vault-status').textContent =
      command === 'check_mobile_vault_key'
        ? '端末の署名鍵を利用できます。'
        : '暗号文を取得しました。revision ' +
          result.revision +
          '、形式 ' +
          result.format_version +
          '。';
  } catch (error) {
    if (generation !== epoch) return;
    diagnostic(error);
    $('#vault-status').textContent =
      '操作を完了できませんでした。接続と承認状態を確認してください。';
  } finally {
    diagnosticBusy = false;
    render();
    void refreshNative();
  }
}
$('#vault-key').addEventListener('click', () => void runDiagnostic('check_mobile_vault_key'));
$('#vault-read').addEventListener('click', () => {
  if (grantAvailable) void runDiagnostic('read_mobile_vault_ciphertext');
});
const systemTheme = matchMedia('(prefers-color-scheme: dark)');
function applyTheme() {
  const resolved =
    themeChoice === 'system' ? (systemTheme.matches ? 'dark' : 'light') : themeChoice;
  document.documentElement.dataset.theme = resolved;
  window.MikakiSystemBars?.postMessage(resolved);
  theme.value = themeChoice;
  const setTheme = window.__TAURI__?.app?.setTheme;
  if (setTheme) void setTheme(themeChoice === 'system' ? null : themeChoice).catch(diagnostic);
}
try {
  const stored = localStorage.getItem('mikaki-appearance');
  if (['system', 'light', 'dark'].includes(stored)) themeChoice = stored;
} catch {
  /* Appearance storage is optional; authentication stays in Rust. */
}
theme.addEventListener('change', () => {
  themeChoice = theme.value;
  try {
    localStorage.setItem('mikaki-appearance', themeChoice);
  } catch {
    /* Use the current appearance for this launch. */
  }
  applyTheme();
});
systemTheme.addEventListener('change', () => {
  if (themeChoice === 'system') applyTheme();
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) clearTimeout(timer);
  else void refreshNative();
});
window.addEventListener('focus', () => void refreshNative());
window.addEventListener('pagehide', () => clearTimeout(timer));
const getVersion = window.__TAURI__?.app?.getVersion;
if (getVersion)
  void getVersion()
    .then((version) => {
      $('#app-version').textContent = version;
    })
    .catch(() => {});
history.replaceState({ mikakiDepth: 0 }, '', '#welcome');
applyTheme();
render();
void bootstrap();
