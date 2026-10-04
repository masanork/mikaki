let proximityGeneration = 0;
let proximitySession = null;
let proximityReview = null;
let proximityActive = false;
let proximityTimer = null;
let presentationGeneration = 0;
let presentationReview = null;
let presentationInFlight = false;
let invocationChecking = false;
let issuanceBusy = false;
let issuanceGeneration = 0;
let walletAvailable = false;
let walletActive = false;
let walletGeneration = 0;
let walletChecking = false;
let walletTimer;
let walletPhase = 'idle';
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
let epoch = 0;
let readSequence = 0;
let timer;
let themeChoice = 'system';
let cardSupported = false;
let cardBusy = false;
let cardGeneration = 0;

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
  renderIdentityReader(view);
  renderWalletIssuance(view);
  for (const screen of screens) screen.hidden = screen.id !== view;
  navigation.hidden = !signedIn || !!pending;
  $('#open-settings').disabled = !!pending;
  $('#session-settings').hidden = !signedIn;
  $('#open-logout').disabled = cardBusy || !!pending;
  login.disabled = !available || cardBusy || !!pending;
  cancel.disabled = cancelling;
  cancel.textContent = cancelling ? '終了しています…' : 'キャンセルして戻る';
  $('#diagnostic-session').textContent = signedIn ? 'ログイン済み' : 'ログインしていません';
  $('#diagnostic-platform').textContent =
    platform === 'mobile'
      ? 'スマートフォン'
      : platform === 'desktop'
        ? 'デスクトップ'
        : '利用できません';
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
function showWaiting() {
  $('#waiting-title').innerHTML = 'ブラウザで<br />本人確認してください';
  $('#waiting-description').textContent = '完了すると、このアプリに戻ります。';
  $('#waiting-phase').textContent = 'ブラウザを開いています';
  $('#check-auth').hidden = true;
  notice();
  render(true);
}
function applyMobile(result) {
  const wasPending = pending;
  signedIn = typeof result.subject === 'string' && result.subject.length > 0;
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
    if (result.phase === 'complete' && signedIn) {
      navigate('home', true);
      notice('ログインしました。');
    } else {
      navigate(signedIn ? 'home' : 'welcome', true);
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
    void consumeIdentityInvocation();
    void refreshWalletIssuance();
  } catch (error) {
    if (generation !== epoch) return;
    available = false;
    diagnostic(error);
    notice('接続を確認できませんでした。もう一度確認してください。');
    $('#retry-init').hidden = false;
    render();
  }
}
async function start() {
  if (!available || pending || cardBusy) return;
  const generation = ++epoch;
  pending = 'login';
  starting = true;
  showWaiting();
  try {
    if (platform === 'mobile') {
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
      navigate(signedIn ? 'home' : 'welcome', true);
      notice(friendly(error));
    }
  }
}
login.addEventListener('click', () => void start());
$('#retry-init').addEventListener('click', () => void bootstrap());
$('#check-auth').addEventListener('click', () => void refreshNative());
cancel.addEventListener('click', async () => {
  if (!pending || cancelling) return;
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
    navigate(signedIn ? 'home' : 'welcome', true);
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
  if (!signedIn || pending) return;
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
function clearIdentityPreview() {
  $('#identity-pin').value = '';
  $('#identity-pin2').value = '';
  $('#identity-preview').hidden = true;
  for (const id of ['name', 'address', 'birth-date', 'gender', 'expiry-date'])
    $('#identity-' + id).textContent = '';
}
function cancelIdentityRead() {
  clearProximity();
  clearPresentationReview();
  cardGeneration++;
  clearIdentityPreview();
  $('#identity-status').textContent = '';
  if (cardBusy && invoke) void invoke('cancel_identity_card').catch(() => {});
  if (invoke) void invoke('clear_identity_evidence').catch(() => {});
}
function renderIdentityReader(view) {
  $('#identity-reader').hidden = !cardSupported;
  if (view !== 'diagnostics') {
    clearProximity();
    clearPresentationReview();
    if (cardBusy || !$('#identity-preview').hidden || $('#identity-pin').value)
      cancelIdentityRead();
  }
  $('#identity-read').disabled =
    cardBusy || issuanceBusy || !!pending || walletActive;
  $('#identity-pin').disabled = cardBusy;
  $('#identity-pin2').disabled = cardBusy;
  $('#identity-type').disabled = cardBusy;
  $('#identity-cancel').hidden = !cardBusy;
}
$('#identity-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!invoke || !cardSupported || cardBusy || issuanceBusy || pending) return;
  let pin = $('#identity-pin').value;
  let pin2 = $('#identity-pin2').value;
  const documentType = $('#identity-type').value;
  if (documentType === 'driving_license' && pin2 && !/^[0-9]{4}$/.test(pin2)) return;
  if (!/^[0-9]{4}$/.test(pin)) return;
  clearIdentityPreview();
  const generation = ++cardGeneration;
  cardBusy = true;
  render();
  $('#identity-status').textContent = 'カードをスマートフォンに近づけてください。';
  try {
    const reading = invoke('read_identity_card', {
      pin,
      documentType,
      pin2: documentType === 'driving_license' && pin2 ? pin2 : null,
    });
    pin = '';
    pin2 = '';
    const result = await reading;
    if (generation !== cardGeneration || route() !== 'diagnostics' || document.hidden) return;
    if (result.verification !== 'unverified') throw { code: 'invalid_response' };
    $('#identity-name').textContent = result.name;
    $('#identity-address').textContent = result.address;
    $('#identity-birth-date').textContent = result.birth_date;
    $('#identity-gender').textContent =
      { 1: '男性', 2: '女性', 9: '記載なし' }[result.gender] ?? '';
    $('#identity-expiry-date').textContent = result.expiry_date ?? '';
    $('#identity-link').disabled = documentType === 'driving_license' && !result.backend_verifiable;
    $('#identity-preview').hidden = false;
    $('#identity-status').textContent = '読み取りが完了しました。';
  } catch (error) {
    if (generation !== cardGeneration) return;
    const messages = {
      pin_failed: '暗証番号が違います。番号を確認してから再操作してください。',
      pin_blocked: '暗証番号がロックされています。カードの窓口で解除してください。',
      nfc_unavailable: 'この端末ではNFCを利用できません。',
      nfc_disabled: '端末の設定でNFCを有効にしてください。',
      read_timeout: '読み取りが時間切れになりました。',
      cancelled: '読み取りを取り消しました。',
      card_removed: 'カードとの接続が切れました。',
      reader_busy: '前の読み取りが終了するまでお待ちください。',
      unsupported_card: 'このカードの読み取りには対応していません。',
    };
    $('#identity-status').textContent = messages[error?.code] ?? 'カードを読み取れませんでした。';
    if (error?.code === 'pin_failed' && Number.isInteger(error.remaining_retries)) {
      $('#identity-status').textContent += ' 残り' + error.remaining_retries + '回です。';
    }
  } finally {
    pin = '';
    pin2 = '';
    cardBusy = false;
    render();
  }
});
$('#identity-cancel').addEventListener('click', () => {
  cancelIdentityRead();
  $('#identity-status').textContent = '読み取りを終了しています。';
});
$('#identity-clear').addEventListener('click', () => {
  clearIdentityPreview();
  if (invoke) void invoke('clear_identity_evidence').catch(() => {});
  $('#identity-status').textContent = '';
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) cancelIdentityRead();
});
window.addEventListener('pagehide', cancelIdentityRead);
if (invoke)
  void invoke('identity_reader_supported')
    .then((supported) => {
      cardSupported = supported === true;
      render();
    })
    .catch(() => {});
applyTheme();
render();
void bootstrap();

$('#identity-type').addEventListener('change', () => {
  const license = $('#identity-type').value === 'driving_license';
  $('#identity-pin-label').textContent = license
    ? '暗証番号1（数字4桁）'
    : '券面事項入力補助用の暗証番号（数字4桁）';
  $('#identity-pin2-field').hidden = !license;
  clearIdentityPreview();
  if (invoke) void invoke('clear_identity_evidence').catch(() => {});
});
function issuanceError(error) {
  return (
    {
      document_verification_failed:
        '発行者の署名を検証できませんでした。対応する発行者鍵が必要です。',
      issuer_unavailable: 'サーバーの身分証検証・発行機能はまだ有効になっていません。',
      not_found: 'サーバーの身分証検証・発行機能はまだ有効になっていません。',
      access_denied: '紐付けと発行が拒否されました。',
      wallet_attestation_unavailable:
        '端末の鍵を確認できませんでした。この端末での発行設定を確認してください。',
      wallet_transaction_unavailable: '受取操作の有効期限が切れました。もう一度始めてください。',
      wallet_not_configured: 'このアプリでは証明書の受取がまだ有効になっていません。',
      wallet_inventory_full:
        '保存件数の上限に達しました。期限切れまで待つか、保存した証明書を消去してください。',
      credential_already_saved: 'この証明書はすでに保存されています。',
      invalid_metadata: '発行者の設定を確認できませんでした。この形式での受取は完了していません。',
      network_error: '通信できませんでした。受取を取り消してから、もう一度始めてください。',
      read_required: '身分証を読み取り直してください。',
      slow_down: 'しばらく待ってから読み取り直してください。',
      transaction_unavailable:
        'この端末への発行権限がありません。属性のみ紐付けた場合は利用するwalletから受領を開始し、それ以外の場合は読み取り直してください。',
    }[error instanceof Error ? error.message : String(error)] ??
    '操作を完了できませんでした。身分証を読み取り直してください。'
  );
}
$('#identity-link').addEventListener('click', async () => {
  if (!invoke || issuanceBusy || cardBusy || walletActive) return;
  const generation = ++issuanceGeneration;
  issuanceBusy = true;
  render();
  $('#identity-link').disabled = true;
  $('#identity-issuance').hidden = false;
  $('#identity-issuance-status').textContent = '署名を検証しています。';
  try {
    const result = await invoke('start_identity_link', {
      configuration: $('#identity-credential-format').value,
    });
    if (generation !== issuanceGeneration) return;
    clearIdentityPreview();
    $('#identity-holder').textContent = '端末鍵の識別子: ' + result.holder_thumbprint;
    $('#identity-issuance-status').textContent =
      'ブラウザで属性とアカウントを確認し、紐付けを承認してください。';
    $('#identity-receive').hidden = false;
  } catch (error) {
    if (generation === issuanceGeneration) {
      $('#identity-issuance-status').textContent = issuanceError(error);
      $('#identity-receive').hidden = true;
    }
  } finally {
    issuanceBusy = false;
    render();
  }
});
function renderWalletIssuance(view) {
  clearTimeout(walletTimer);
  if (walletActive && !document.hidden)
    walletTimer = setTimeout(() => void refreshWalletIssuance(), 5000);
  $('#identity-wallet-issuance').hidden = !walletAvailable;
  $('#identity-wallet-start').disabled =
    walletActive || issuanceBusy || cardBusy || !!pending;
  $('#identity-wallet-format').disabled = walletActive || issuanceBusy;
  $('#identity-wallet-receive').hidden =
    !walletActive || !['pending', 'ready'].includes(walletPhase);
  $('#identity-wallet-receive').disabled = issuanceBusy || cardBusy;
  $('#identity-wallet-cancel').hidden = !walletActive;
  $('#identity-wallet-cancel').disabled = walletPhase === 'cancelling';
  if (
    view !== 'diagnostics' &&
    walletActive &&
    !['cancelling', 'cancellation_failed'].includes(walletPhase)
  )
    cancelWalletIssuance();
}
function cancelWalletIssuance() {
  if (walletPhase === 'cancelling') return;
  const generation = ++walletGeneration;
  walletActive = true;
  walletPhase = 'cancelling';
  $('#identity-wallet-status').textContent = '受取を取り消しています。';
  if (invoke)
    void invoke('cancel_identity_wallet_issuance')
      .then(() => {
        if (generation !== walletGeneration) return;
        walletActive = false;
        walletPhase = 'cancelled';
        $('#identity-wallet-status').textContent = '証明書の受取を取り消しました。';
        render();
      })
      .catch(() => {
        if (generation !== walletGeneration) return;
        walletPhase = 'cancellation_failed';
        $('#identity-wallet-status').textContent =
          '受取を取り消せませんでした。もう一度取り消してください。';
        render();
      });
  $('#identity-wallet-receive').hidden = true;
  $('#identity-wallet-cancel').hidden = true;
}
async function refreshWalletIssuance() {
  if (
    !invoke ||
    !available ||
    walletChecking ||
    issuanceBusy ||
    ['cancelling', 'cancellation_failed'].includes(walletPhase)
  )
    return;
  walletChecking = true;
  const generation = walletGeneration;
  try {
    const status = await invoke('identity_wallet_issuance_status');
    if (generation !== walletGeneration) return;
    walletAvailable = status?.available === true;
    walletPhase = status?.phase ?? 'idle';
    walletActive = ['starting', 'pending', 'ready', 'receiving'].includes(walletPhase);
    const message = {
      pending: 'ブラウザでアカウントと属性を確認し、この端末への発行を承認してください。',
      ready: '発行が承認されました。「承認を確認して受け取る」を選んでください。',
      denied: '発行が拒否されました。証明書は受け取っていません。',
      expired: '受取操作の有効期限が切れました。もう一度始めてください。',
      failed: '受取を完了できませんでした。もう一度始めてください。',
      cancelled: '証明書の受取を取り消しました。',
    }[walletPhase];
    if (message) $('#identity-wallet-status').textContent = message;
    if (walletActive && route() !== 'diagnostics') navigate('diagnostics', true);
    else render();
  } catch {
    /* The feature remains hidden in builds without a configured native wallet. */
  } finally {
    walletChecking = false;
  }
}
$('#identity-wallet-start').addEventListener('click', async () => {
  if (!invoke || !walletAvailable || walletActive || issuanceBusy || cardBusy) return;
  const generation = ++walletGeneration;
  walletActive = true;
  walletPhase = 'starting';
  issuanceBusy = true;
  $('#identity-wallet-status').textContent = '端末の鍵と発行者を確認しています。';
  render();
  try {
    const result = await invoke('start_identity_wallet_issuance', {
      configuration: $('#identity-wallet-format').value,
    });
    if (generation !== walletGeneration) return;
    if (result.phase !== 'pending') throw Error('invalid_response');
    walletPhase = 'pending';
    $('#identity-wallet-status').textContent =
      'ブラウザでアカウントと属性を確認し、この端末への発行を承認してください。';
  } catch (error) {
    if (generation === walletGeneration) {
      walletActive = false;
      walletPhase = 'failed';
      $('#identity-wallet-status').textContent = issuanceError(error);
    }
  } finally {
    issuanceBusy = false;
    render();
  }
});
$('#identity-wallet-receive').addEventListener('click', async () => {
  if (!invoke || !walletActive || issuanceBusy || cardBusy) return;
  const generation = walletGeneration;
  issuanceBusy = true;
  $('#identity-wallet-status').textContent = '発行の承認と証明書を確認しています。';
  render();
  try {
    const result = await invoke('receive_identity_wallet_credential');
    if (generation !== walletGeneration) return;
    if (result.state === 'pending') {
      $('#identity-wallet-status').textContent =
        'まだ承認されていません。ブラウザでの操作を完了してください。';
    } else if (result.state === 'received' && ['dc+sd-jwt', 'mso_mdoc'].includes(result.format)) {
      walletActive = false;
      walletPhase = 'received';
      $('#identity-wallet-status').textContent =
        (result.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT') +
        '属性証明書を受け取り、署名を確認しました。有効期限: ' +
        new Date(result.expires_at * 1000).toLocaleTimeString();
    } else throw Error('invalid_response');
  } catch (error) {
    if (generation === walletGeneration) {
      walletActive = false;
      walletPhase = 'failed';
      $('#identity-wallet-status').textContent = issuanceError(error);
    }
  } finally {
    issuanceBusy = false;
    render();
  }
});
$('#identity-wallet-cancel').addEventListener('click', () => {
  cancelWalletIssuance();
  render();
});
window.addEventListener('focus', () => void refreshWalletIssuance());
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) void refreshWalletIssuance();
});
$('#identity-receive').addEventListener('click', async () => {
  if (!invoke || issuanceBusy || walletActive) return;
  const generation = issuanceGeneration;
  issuanceBusy = true;
  render();
  $('#identity-receive').disabled = true;
  try {
    const result = await invoke('receive_identity_credential');
    if (generation !== issuanceGeneration) return;
    if (result.state === 'pending') {
      $('#identity-issuance-status').textContent =
        'まだ承認されていません。ブラウザでの操作を完了してください。';
    } else if (result.state === 'received' && ['dc+sd-jwt', 'mso_mdoc'].includes(result.format)) {
      $('#identity-issuance-status').textContent =
        (result.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT') +
        '属性証明書を受け取り、署名を確認しました。有効期限: ' +
        new Date(result.expires_at * 1000).toLocaleTimeString();
      $('#identity-receive').hidden = true;
    } else throw 'invalid_response';
  } catch (error) {
    if (generation === issuanceGeneration) {
      $('#identity-issuance-status').textContent = issuanceError(error);
      $('#identity-receive').hidden = true;
    }
  } finally {
    issuanceBusy = false;
    $('#identity-receive').disabled = false;
    render();
  }
});
$('#identity-credential-clear').addEventListener('click', () => {
  cancelWalletIssuance();
  cancelIdentityRead();
  issuanceGeneration++;
  clearPresentationReview();
  if (invoke)
    void invoke('clear_identity_credential').catch(() => {
      $('#identity-vp-status').textContent =
        '端末の証明書を消去できませんでした。もう一度消去してください。';
    });
  $('#identity-issuance').hidden = true;
  $('#identity-holder').textContent = '';
  $('#identity-issuance-status').textContent = '';
});

$('#identity-manage').addEventListener('click', () => {
  if (invoke)
    void invoke('open_identity_management').catch((error) => {
      $('#identity-status').textContent = issuanceError(error);
    });
});

function clearPresentationReview() {
  presentationGeneration++;
  if (presentationInFlight && invoke) {
    presentationInFlight = false;
    void invoke('cancel_identity_presentation').catch(() => {});
  }
  const id = presentationReview;
  presentationReview = null;
  $('#identity-vp-request').value = '';
  $('#identity-vp-consent').hidden = true;
  $('#identity-vp-target').textContent = '';
  $('#identity-vp-values').replaceChildren();
  $('#identity-vp-status').textContent = '';
  if (id && invoke)
    void invoke('confirm_identity_presentation', { reviewId: id, approve: false }).catch(() => {});
}
function presentationError(error) {
  const code = error instanceof Error ? error.message : String(error);
  return (
    {
      verifier_not_configured: 'このアプリには提示先がまだ登録されていません。',
      untrusted_verifier: '登録済みの提示先と一致しません。',
      credential_required: '有効な証明書を受け取ってください。',
      credential_query_unsatisfied: '提示に必要な証明書が揃っていません。',
      credential_changed: '同意した証明書を確認できませんでした。新しい要求でやり直してください。',
      credential_expired: '証明書の有効期限が切れました。受け取り直してください。',
      request_expired: '提示要求の有効期限が切れました。新しい要求を受け取ってください。',
      credential_does_not_match: '要求された属性が証明書にありません。',
      request_consumed: '使用済みの要求です。新しい要求を受け取ってください。',
      certificate_revoked: '提示先の証明書は失効しています。属性を送信しませんでした。',
      certificate_status_unknown:
        '提示先の証明書の失効状態を確認できません。属性を送信しませんでした。',
      crl_expired: '提示先の失効情報は期限切れです。属性を送信しませんでした。',
      crl_stale: '提示先の失効情報が古いため、属性を送信しませんでした。',
      crl_not_yet_valid: '提示先の失効情報の日時を確認できません。属性を送信しませんでした。',
      invalid_crl: '提示先の失効情報を検証できません。属性を送信しませんでした。',
    }[code] ?? '提示できませんでした。有効な証明書と新しい署名付き要求を確認してください。'
  );
}
$('#identity-wallet-restore').addEventListener('click', async () => {
  if (!invoke || issuanceBusy || cardBusy) return;
  const generation = issuanceGeneration;
  issuanceBusy = true;
  render();
  try {
    const result = await invoke('identity_credential_status');
    if (generation !== issuanceGeneration) return;
    $('#identity-issuance').hidden = false;
    $('#identity-receive').hidden = true;
    $('#identity-issuance-status').textContent =
      result.state === 'received'
        ? (result.credential_count > 1
            ? `保存した証明書${result.credential_count}件を確認しました。最後に受け取った`
            : '保存した') +
          (result.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT') +
          '属性証明書を確認しました。有効期限: ' +
          new Date(result.expires_at * 1000).toLocaleTimeString()
        : '有効な保存済み証明書はありません。';
  } catch (error) {
    if (generation === issuanceGeneration)
      $('#identity-vp-status').textContent = presentationError(error);
  } finally {
    issuanceBusy = false;
    render();
  }
});
async function reviewPresentation(command, args) {
  if (!invoke || issuanceBusy || cardBusy) return;
  clearPresentationReview();
  const generation = presentationGeneration;
  issuanceBusy = true;
  presentationInFlight = command === 'review_identity_invocation';
  render();
  try {
    const review = await invoke(command, args);
    if (generation !== presentationGeneration) {
      void invoke('confirm_identity_presentation', {
        reviewId: review.review_id,
        approve: false,
      }).catch(() => {});
      return;
    }
    presentationReview = review.review_id;
    $('#identity-vp-target').textContent = review.verifier_name + ' — ' + review.response_uri;
    const labels = {
      name: '氏名',
      address: '住所',
      birthdate: '生年月日',
      gender: '性別（カード上の符号）',
      document_expiry_date: '身分証の有効期限',
    };
    const credentials = review.credentials?.length
      ? review.credentials
      : [{ values: review.values, retained_fields: review.retained_fields }];
    const appendValues = (target, credential) => {
      for (const [key, value] of Object.entries(credential.values)) {
        const term = document.createElement('dt');
        term.textContent =
          (labels[key] ?? key) +
          (credential.retained_fields?.includes(key) ? '（提示先が保存予定）' : '');
        const description = document.createElement('dd');
        description.textContent =
          typeof value === 'object' && value !== null
            ? (value.formatted ?? JSON.stringify(value))
            : String(value);
        target.append(term, description);
      }
    };
    for (const [index, credential] of credentials.entries()) {
      if (review.credentials?.length) {
        const group = document.createElement('div');
        const title = document.createElement('dt');
        title.textContent = `証明書 ${index + 1}（${credential.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT'}）`;
        const details = document.createElement('dd');
        const fields = document.createElement('dl');
        appendValues(fields, credential);
        if (!Object.keys(credential.values).length)
          details.textContent = '選択開示する属性はありません。証明情報を送信します。';
        details.append(fields);
        group.append(title, details);
        $('#identity-vp-values').append(group);
      } else appendValues($('#identity-vp-values'), credential);
    }
    $('#identity-vp-consent').hidden = false;
    $('#identity-vp-status').textContent =
      (credentials.some((credential) => Object.keys(credential.values).length)
        ? '表示されたすべての証明書の属性と証明情報を提示先へ送信します。有効期限: '
        : '選択開示する属性はありません。発行者・証明書の型・所持証明などの証明情報を提示先へ送信します。有効期限: ') +
      new Date(review.expires_at * 1000).toLocaleTimeString();
  } catch (error) {
    if (generation === presentationGeneration)
      $('#identity-vp-status').textContent = presentationError(error);
  } finally {
    presentationInFlight = false;
    issuanceBusy = false;
    render();
    void consumeIdentityInvocation();
  }
}

$('#identity-vp-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void reviewPresentation('review_identity_presentation', {
    request: $('#identity-vp-request').value.trim(),
  });
});
async function consumeIdentityInvocation() {
  if (
    !invoke ||
    !available ||
    invocationChecking ||
    issuanceBusy ||
    cardBusy ||
    pending ||
    proximityActive
  )
    return;
  invocationChecking = true;
  let reviewed = false;
  try {
    const id = await invoke('pending_identity_invocation');
    if (!id || issuanceBusy || cardBusy || pending || proximityActive) return;
    navigate('diagnostics');
    reviewed = true;
    await reviewPresentation('review_identity_invocation', { invocationId: id });
  } catch (_) {
    // No pending native invocation or this platform does not support it.
  } finally {
    invocationChecking = false;
    if (reviewed) void consumeIdentityInvocation();
  }
}
$('#identity-vp-deny').addEventListener('click', clearPresentationReview);
$('#identity-vp-approve').addEventListener('click', async () => {
  if (!invoke || issuanceBusy || !presentationReview) return;
  const reviewId = presentationReview;
  const generation = presentationGeneration;
  presentationReview = null;
  $('#identity-vp-consent').hidden = true;
  $('#identity-vp-values').replaceChildren();
  $('#identity-vp-target').textContent = '';
  issuanceBusy = true;
  presentationInFlight = true;
  render();
  try {
    const result = await invoke('confirm_identity_presentation', { reviewId, approve: true });
    if (generation === presentationGeneration) {
      const messages = {
        opened: '選択した属性を提示し、提示先の画面を開きました。',
        rejected:
          '属性は送信済みです。提示先への復帰URLを確認できないため、画面を開きませんでした。',
        invalid_response:
          '属性は送信済みです。提示先の応答を確認できませんでした。再送せず、提示先で結果を確認してください。',
        browser_unavailable:
          '属性は送信済みです。提示先の画面を開けませんでした。提示先で結果を確認してください。',
        cancelled: '属性は送信済みです。提示先の画面への移動は取り消しました。',
      };
      $('#identity-vp-status').textContent =
        messages[result.completion] ?? '選択した属性を提示しました。';
    }
  } catch (error) {
    if (generation === presentationGeneration)
      $('#identity-vp-status').textContent = presentationError(error);
  } finally {
    presentationInFlight = false;
    issuanceBusy = false;
    render();
  }
});

function clearProximity() {
  if (!proximityActive) return;
  proximityGeneration++;
  clearTimeout(proximityTimer);
  proximityTimer = null;
  proximityActive = false;
  const id = proximitySession;
  proximitySession = proximityReview = null;
  $('#identity-proximity-panel').hidden = true;
  $('#identity-proximity-qr').replaceChildren();
  $('#identity-proximity-values').replaceChildren();
  $('#identity-proximity-target').textContent = '';
  $('#identity-proximity-consent').hidden = true;
  if (invoke) void invoke('cancel_identity_proximity', { sessionId: id }).catch(() => {});
}
function proximityError(error) {
  const code = error instanceof Error ? error.message : String(error);
  return (
    {
      reader_not_configured: '近接提示の読み手がまだ登録されていません。',
      mdoc_required: 'mdoc形式の属性証明書を受け取ってください。',
      proximity_unsupported: 'この端末では近接提示を利用できません。',
      credential_required: '有効なmdoc属性証明書を受け取ってください。',
      untrusted_reader: '登録済みの読み手を確認できませんでした。',
      certificate_revoked: '読み手の証明書は失効しています。属性を送信しませんでした。',
      certificate_status_unknown:
        '読み手の証明書の失効状態を確認できません。属性を送信しませんでした。',
      crl_expired: '読み手の失効情報は期限切れです。属性を送信しませんでした。',
      crl_stale: '読み手の失効情報が古いため、属性を送信しませんでした。',
      crl_not_yet_valid: '読み手の失効情報の日時を確認できません。属性を送信しませんでした。',
      invalid_crl: '読み手の失効情報を検証できません。属性を送信しませんでした。',
      reader_authentication_expired:
        '読み手の確認期限が切れました。新しい接続からやり直してください。',
    }[code] ?? '近接提示を終了しました。接続方法と証明書の有効期限を確認してください。'
  );
}
function renderProximityQr(modules) {
  if (
    !Array.isArray(modules) ||
    modules.length < 21 ||
    modules.length > 177 ||
    modules.some(
      (row) =>
        !Array.isArray(row) ||
        row.length !== modules.length ||
        row.some((v) => typeof v !== 'boolean'),
    )
  )
    throw new Error('invalid_qr');
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const size = modules.length + 8;
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('width', '256');
  svg.setAttribute('height', '256');
  svg.style.maxWidth = '100%';
  svg.setAttribute('shape-rendering', 'crispEdges');
  const background = document.createElementNS(svg.namespaceURI, 'rect');
  background.setAttribute('width', String(size));
  background.setAttribute('height', String(size));
  background.setAttribute('fill', 'white');
  svg.append(background);
  const path = document.createElementNS(svg.namespaceURI, 'path');
  path.setAttribute('fill', 'black');
  path.setAttribute(
    'd',
    modules
      .flatMap((row, y) => row.flatMap((v, x) => (v ? [`M${x + 4} ${y + 4}h1v1h-1z`] : [])))
      .join(''),
  );
  svg.append(path);
  $('#identity-proximity-qr').replaceChildren(svg);
}
$('#identity-proximity-start').addEventListener('click', async () => {
  if (!invoke || cardBusy || issuanceBusy || proximityActive) return;
  clearPresentationReview();
  proximityActive = true;
  const generation = ++proximityGeneration;
  $('#identity-proximity-panel').hidden = false;
  $('#identity-proximity-status').textContent = 'Bluetoothで接続する準備をしています。';
  issuanceBusy = true;
  render();
  try {
    const engagement = $('#identity-proximity-engagement').value;
    const session = await invoke('start_identity_proximity', { engagement });
    if (generation !== proximityGeneration) {
      void invoke('cancel_identity_proximity', { sessionId: session.session_id }).catch(() => {});
      return;
    }
    proximitySession = session.session_id;
    proximityTimer = setTimeout(
      clearProximity,
      Math.max(0, Math.min(120000, session.expires_at * 1000 - Date.now())),
    );
    if (session.engagement !== engagement) throw new Error('engagement_mismatch');
    if (
      engagement !== 'nfc' &&
      engagement !== 'nfc_negotiated' &&
      engagement !== 'nfc_negotiated_data'
    )
      renderProximityQr(session.qr_modules);
    $('#identity-proximity-status').textContent =
      engagement === 'qr_nfc' || engagement === 'nfc_negotiated_data'
        ? engagement === 'nfc_negotiated_data'
          ? '読み手に端末をかざし、そのまま属性を確認・承認してください。'
          : '読み手にQRを見せ、その後は端末をかざしたまま属性を確認・承認してください。'
        : engagement === 'nfc' || engagement === 'nfc_negotiated'
          ? '読み手に端末をかざしてください。接続後は端末を離して属性を確認できます。'
          : '読み手にQRコードを見せてください。属性は確認後に送信します。';
    const review = await invoke('review_identity_proximity', { sessionId: session.session_id });
    if (generation !== proximityGeneration) return;
    proximityReview = review.review_id;
    $('#identity-proximity-qr').replaceChildren();
    $('#identity-proximity-target').textContent = review.reader_name;
    const labels = {
      name: '氏名',
      address: '住所',
      birthdate: '生年月日',
      gender: '性別（カード上の符号）',
      document_expiry_date: '身分証の有効期限',
    };
    for (const [key, value] of Object.entries(review.values)) {
      const term = document.createElement('dt');
      term.textContent =
        (labels[key] ?? key) +
        (review.retained_fields?.includes(key) ? '（読み手が保存予定）' : '');
      const description = document.createElement('dd');
      description.textContent =
        typeof value === 'object' && value !== null
          ? (value.formatted ?? JSON.stringify(value))
          : String(value);
      $('#identity-proximity-values').append(term, description);
    }
    $('#identity-proximity-consent').hidden = false;
    $('#identity-proximity-status').textContent =
      (engagement === 'qr_nfc' || engagement === 'nfc_negotiated_data'
        ? '端末をかざしたまま、表示された属性の提示を承認してください。有効期限: '
        : '表示された属性を提示します。有効期限: ') +
      new Date(review.expires_at * 1000).toLocaleTimeString();
  } catch (error) {
    if (generation === proximityGeneration) {
      clearProximity();
      $('#identity-proximity-panel').hidden = false;
      $('#identity-proximity-status').textContent = proximityError(error);
    }
  } finally {
    issuanceBusy = false;
    render();
  }
});
$('#identity-proximity-cancel').addEventListener('click', clearProximity);
$('#identity-proximity-approve').addEventListener('click', async () => {
  if (!invoke || issuanceBusy || !proximityReview || !proximitySession) return;
  const generation = proximityGeneration,
    sessionId = proximitySession,
    reviewId = proximityReview;
  proximityReview = null;
  $('#identity-proximity-consent').hidden = true;
  $('#identity-proximity-values').replaceChildren();
  $('#identity-proximity-target').textContent = '';
  issuanceBusy = true;
  render();
  try {
    await invoke('confirm_identity_proximity', { sessionId, reviewId, approve: true });
    if (generation === proximityGeneration) {
      clearProximity();
      $('#identity-proximity-panel').hidden = false;
      $('#identity-proximity-status').textContent = '選択した属性を近くの読み手に提示しました。';
    }
  } catch (error) {
    if (generation === proximityGeneration) {
      clearProximity();
      $('#identity-proximity-panel').hidden = false;
      $('#identity-proximity-status').textContent = proximityError(error);
    }
  } finally {
    issuanceBusy = false;
    render();
  }
});

if (invoke && window.__TAURI__?.core?.Channel) {
  const updates = new window.__TAURI__.core.Channel();
  updates.onmessage = ({ event, id }) => {
    if (event === 'identity-proximity-ended') {
      if (proximityActive && proximitySession === id) {
        clearProximity();
        $('#identity-proximity-panel').hidden = false;
        $('#identity-proximity-status').textContent =
          '接続が終了しました。新しい接続からやり直してください。';
      }
    } else if (event === 'identity-presentation-ready') {
      void consumeIdentityInvocation();
    } else if (event === 'identity-issuance-updated') {
      void refreshWalletIssuance();
    }
  };
  void invoke('subscribe_identity_updates', { onEvent: updates })
    .then(() => consumeIdentityInvocation())
    .catch(() => {});
}
window.addEventListener('focus', () => void consumeIdentityInvocation());
