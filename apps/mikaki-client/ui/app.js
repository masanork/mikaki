import { walletDocument, walletCredential, passportAuthenticationNote } from './wallet-model.js';
let selectedDocument = null;
let selectedDocumentType = null;
let walletDetailTrigger = null;
let walletDetailGeneration = 0;
let selectedPassportSaved = false;
let passportPrefilling = false;
let hideWalletNames = false;
let savingDocument = false;
let selectedPassportEligible = false;
let passportAvailable = false;
let passportCapabilityEpoch = -1;
let passportReviewId = null;
let passportReviewBusy = false;
let passportReviewGeneration = 0;
let passportReviewTimer;
let passportReviewTrigger = null;
let walletExpiryTimer;
let passportPreviewTimer;
let walletInventoryGeneration = 0;
let walletInventoryLoaded = false;
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
const navigation = $('#navigation');
const theme = $('#theme');
let platform;
let signedIn = false;
let walletSubject = null;
let epoch = 0;
let pending = false;
let walletAccountBusy = false;
let walletAccountTimer;
let walletAccountRead = 0;
let available = false;
let webOpening = false;
let themeChoice = 'system';
let cardSupported = false;
let cardBusy = false;
let cardGeneration = 0;
let sharedSession = false;
let authPhase = 'idle';
let loginReturnView = null;
let workspaceKey = '';
let workspaceQueue = Promise.resolve();
let workspacePage = 'chat';
let workspaceFailed = false;

function authenticationMessage(phase) {
  return (
    {
      configuration_required:
        'ログイン機能の更新が必要です。アプリと接続先の更新後に再試行してください。',
      workspace_unavailable:
        'この端末のPasskey画面を開けませんでした。Android System WebViewを更新して再試行してください。',
      connection_failed: '接続できませんでした。ネットワークを確認して、もう一度お試しください。',
      secure_connection_failed:
        '安全な接続を確認できませんでした。ネットワークを確認してください。',
      expired: 'ログインの有効期限が切れました。もう一度Passkeyでログインしてください。',
      denied: 'ログインを取り消しました。',
      failed: '認証後の確認を完了できませんでした。もう一度お試しください。',
    }[phase] ?? ''
  );
}
function syncWorkspace() {
  if (!sharedSession || !invoke) return;
  const visible = route() === 'chat' && (signedIn || pending) && !workspaceFailed;
  const args = {
    visible,
    page: workspacePage,
    top: Math.max(0, Math.min(250, $('.app-header').getBoundingClientRect().bottom)),
    bottom: Math.max(48, Math.min(300, innerHeight - navigation.getBoundingClientRect().top)),
    viewportWidth: innerWidth,
  };
  const key = JSON.stringify(args);
  if (workspaceKey === key) return;
  workspaceKey = key;
  workspaceQueue = workspaceQueue
    .catch(() => {})
    .then(async () => {
      try {
        await invoke('set_app_workspace', args);
      } catch (error) {
        if (workspaceKey !== key) return;
        workspaceKey = '';
        if (String(error).includes('draft_kept')) navigate('chat', true);
        else {
          workspaceFailed = true;
          if (!signedIn) {
            await invoke('cancel_native_login').catch(() => {});
            loginReturnView = null;
          }
          pending = false;
          authPhase = 'workspace_unavailable';
          notice(authenticationMessage(authPhase));
          if (args.visible) render();
        }
      }
    });
}

function notice(message = '') {
  $('#status').textContent = message;
  $('#status').hidden = !message;
}
function diagnostic(error) {
  $('#diagnostic-error').textContent = String(error).slice(0, 500);
  $('#error-details').hidden = false;
}
function route() {
  const requested = location.hash.slice(1);
  return ['wallet', 'chat', 'settings', 'diagnostics', 'connection'].includes(requested)
    ? requested
    : 'wallet';
}
function navigate(view, replace = false) {
  const depth = replace ? 0 : (history.state?.mikakiDepth ?? 0) + 1;
  if (replace || location.hash !== '#' + view)
    history[replace ? 'replaceState' : 'pushState']({ mikakiDepth: depth }, '', '#' + view);
  render(true);
}
function render(focus = false) {
  const view = route();
  $('#wallet-login').hidden = signedIn || pending;
  $('#wallet-logout').hidden = !signedIn || pending;
  $('#wallet-login-cancel').hidden = !pending;
  $('#wallet-login').disabled = !available || walletAccountBusy;
  $('#wallet-logout').disabled =
    walletAccountBusy || cardBusy || issuanceBusy || savingDocument || walletActive;
  $('#wallet-account-status').textContent = pending
    ? sharedSession
      ? 'Passkeyでログインしています。'
      : 'ブラウザでログインを完了してください。'
    : signedIn
      ? sharedSession
        ? 'ログイン済み · Wallet / Chat'
        : 'アカウントに接続済み'
      : authenticationMessage(authPhase) ||
        'Passkeyでログインすると、あなたの身分証とChatを開けます。';
  $('#wallet-login').textContent = 'Passkeyでログイン';
  $('#chat-login').hidden = !sharedSession || (!workspaceFailed && (signedIn || pending));
  $('#chat-login').textContent = signedIn ? 'もう一度開く' : 'Passkeyでログイン';
  $('#chat').inert = sharedSession && view === 'chat' && (signedIn || pending) && !workspaceFailed;
  $('#open-chat').hidden = sharedSession;
  $('#chat-help').textContent = sharedSession
    ? workspaceFailed
      ? authenticationMessage('workspace_unavailable')
      : pending
        ? 'Passkeyの選択画面で本人確認してください。'
        : signedIn
          ? 'Chatを開いています…'
          : 'Walletと共通のアカウントでログインします。'
    : 'ログインと会話は、このアプリ内のWeb画面で行います。';
  renderIdentityReader(view);
  renderWalletIssuance(view);
  if (view === 'wallet' && signedIn && passportCapabilityEpoch !== epoch)
    void refreshPassportAvailability();
  if (view !== 'wallet') clearPassportIssuanceReview();
  if (view !== 'wallet') {
    walletInventoryGeneration++;
    walletInventoryLoaded = false;
    clearTimeout(walletExpiryTimer);
    clearWalletView();
  } else if (!walletInventoryLoaded) {
    walletInventoryLoaded = true;
    void refreshWalletInventory();
  }
  for (const screen of screens) screen.hidden = screen.id !== view;
  navigation.hidden = false;
  for (const button of document.querySelectorAll('[data-web-destination]'))
    button.disabled = !invoke || webOpening || cardBusy || issuanceBusy;
  $('#diagnostic-platform').textContent =
    platform === 'mobile'
      ? 'スマートフォン'
      : platform === 'desktop'
        ? 'デスクトップ'
        : '確認できません';
  for (const tab of navigation.querySelectorAll('a')) {
    if (tab.dataset.nav === (view === 'diagnostics' ? 'settings' : view))
      tab.setAttribute('aria-current', 'page');
    else tab.removeAttribute('aria-current');
  }
  syncWorkspace();
  if (focus) {
    window.scrollTo(0, 0);
    const heading = $('#' + view).querySelector('h1');
    heading.setAttribute('tabindex', '-1');
    heading.focus({ preventScroll: true });
    heading.addEventListener('blur', () => heading.removeAttribute('tabindex'), { once: true });
  }
}

async function refreshWalletAccount() {
  if (!available || walletAccountBusy) return;
  const read = ++walletAccountRead;
  const generation = epoch;
  try {
    const result = await invoke(platform === 'mobile' ? 'mobile_auth_status' : 'native_session');
    if (read !== walletAccountRead || generation !== epoch) return;
    const subject = result?.subject ?? null;
    sharedSession = result?.shared_session === true;
    authPhase = result?.phase ?? 'idle';
    pending = platform === 'mobile' && ['pending', 'exchanging'].includes(result?.phase);
    updateWalletSubject(subject);
    if (!pending && loginReturnView && signedIn) {
      const target = loginReturnView;
      loginReturnView = null;
      navigate(target, true);
    } else render();
    if (!pending && authenticationMessage(authPhase)) notice(authenticationMessage(authPhase));
  } catch {
    if (read !== walletAccountRead || generation !== epoch) return;
    updateWalletSubject(null);
    pending = false;
    authPhase = 'connection_failed';
    render();
  } finally {
    clearTimeout(walletAccountTimer);
    if ((pending || sharedSession) && !document.hidden)
      walletAccountTimer = setTimeout(() => void refreshWalletAccount(), pending ? 1000 : 10000);
  }
}
function updateWalletSubject(subject) {
  if (subject === walletSubject) return;
  if (sharedSession && walletSubject !== null) {
    workspaceKey = '';
    // Session loss/replacement discards the old remote document immediately;
    // a draft confirmation must not retain another/unchecked owner's keys.
    workspaceQueue = workspaceQueue.catch(() => {}).then(() => invoke('reset_app_workspace'));
  }
  walletSubject = subject;
  signedIn = typeof subject === 'string' && subject.length > 0;
  epoch++;
  walletInventoryGeneration++;
  walletInventoryLoaded = false;
  passportCapabilityEpoch = -1;
  cancelIdentityRead();
  clearPassportIssuanceReview();
  clearPresentationReview();
  clearWalletView();
}
async function login(returnView) {
  if (!available || walletAccountBusy || pending) return;
  walletAccountBusy = true;
  workspaceFailed = false;
  pending = true;
  render();
  try {
    await invoke(platform === 'mobile' ? 'start_mobile_login' : 'start_desktop_login');
    if (sharedSession) {
      workspacePage = 'chat';
      loginReturnView = returnView;
      workspaceKey = '';
      navigate('chat');
    }
  } catch (error) {
    pending = false;
    authPhase = String(error).includes('client ID')
      ? 'configuration_required'
      : 'connection_failed';
    notice(authenticationMessage(authPhase));
  } finally {
    walletAccountBusy = false;
    await refreshWalletAccount();
  }
}
$('#wallet-login').addEventListener('click', () => void login('wallet'));
$('#chat-login').addEventListener('click', () => {
  if (signedIn) {
    workspaceFailed = false;
    workspaceKey = '';
    render();
  } else void login('chat');
});
$('#wallet-login-cancel').addEventListener('click', async () => {
  if (walletAccountBusy) return;
  epoch++;
  await invoke('cancel_native_login').catch(() => {});
  pending = false;
  loginReturnView = null;
  if (sharedSession) navigate('wallet');
  await refreshWalletAccount();
});
$('#wallet-logout').addEventListener('click', async () => {
  if (walletAccountBusy || cardBusy || issuanceBusy || savingDocument || walletActive) return;
  walletAccountBusy = true;
  epoch++;
  try {
    await invoke('clear_native_session');
    workspaceKey = '';
    notice(
      'このWalletからログアウトしました。保存した読取記録は、同じアカウントでログインすると復元できます。',
    );
  } catch {
    notice('ログアウトできませんでした。もう一度お試しください。');
  } finally {
    walletAccountBusy = false;
    await refreshWalletAccount();
  }
});

async function bootstrap() {
  if (!invoke) {
    notice('この環境ではアプリの機能を利用できません。');
    render();
    return;
  }
  try {
    platform = await invoke('native_platform');
    available = true;
    await refreshWalletAccount();
    render();
    void consumeIdentityInvocation();
    void refreshWalletIssuance();
    void refreshWalletInventory();
  } catch (error) {
    diagnostic(error);
    notice('端末の状態を確認できませんでした。アプリを開き直してください。');
  }
}
for (const button of document.querySelectorAll('[data-web-destination]')) {
  button.addEventListener('click', async () => {
    if (!invoke || webOpening || cardBusy || issuanceBusy) return;
    if (sharedSession) {
      workspacePage = button.dataset.webDestination === 'signin' ? 'account' : 'chat';
      if (!signedIn) await login(button.dataset.webDestination === 'chat' ? 'chat' : 'wallet');
      else navigate('chat');
      return;
    }
    webOpening = true;
    cancelIdentityRead();
    render();
    try {
      await invoke('open_mikaki_web', { destination: button.dataset.webDestination });
      notice('アプリ内でWeb画面を開いています。');
    } catch (error) {
      diagnostic(error);
      notice('Web画面を開けませんでした。もう一度試してください。');
    } finally {
      webOpening = false;
      render();
    }
  });
}
window.addEventListener('resize', syncWorkspace);
$('#open-settings').addEventListener('click', () => navigate('settings'));
document.addEventListener('click', (event) => {
  const anchor = event.target.closest('a[href^="#"]');
  if (!anchor) return;
  event.preventDefault();
  notice();
  if (anchor.dataset.nav === 'chat') workspacePage = 'chat';
  navigate(anchor.hash.slice(1));
});
document.querySelectorAll('[data-back]').forEach((button) => {
  button.addEventListener('click', () => {
    notice();
    if ((history.state?.mikakiDepth ?? 0) > 0) history.back();
    else navigate(route() === 'diagnostics' ? 'settings' : 'wallet', true);
  });
});
window.addEventListener('popstate', () => {
  notice();
  render(true);
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
const getVersion = window.__TAURI__?.app?.getVersion;
if (getVersion)
  void getVersion()
    .then((version) => {
      $('#app-version').textContent = version;
    })
    .catch(() => {});
history.replaceState({ mikakiDepth: 0 }, '', '#' + route());
const identityAccessFields = [
  'identity-pin',
  'identity-pin2',
  'identity-passport-number',
  'identity-passport-birth',
  'identity-passport-expiry',
];

function clearIdentityPreview() {
  clearTimeout(passportPreviewTimer);
  for (const id of identityAccessFields) $('#' + id).value = '';
  $('#identity-preview').hidden = true;
  $('#identity-save-status').textContent = '';
  $('#identity-save-document').textContent = 'このWalletに保存';
  $('#identity-save-document').disabled = false;
  for (const id of ['name', 'address', 'birth-date', 'gender', 'expiry-date'])
    $('#identity-' + id).textContent = '';
}
function renderPassportPreviewAuthentication(report) {
  clearTimeout(passportPreviewTimer);
  $('#identity-preview-note').textContent =
    passportAuthenticationNote(report) +
    ' 日付の西暦年は入力した値を使い、月日・下2桁の年をICチップと照合しています。この記録から本人確認・証明書発行・VP提示はできません。';
  if (Number.isSafeInteger(report?.valid_until) && report.valid_until * 1000 > Date.now())
    passportPreviewTimer = setTimeout(
      () => renderPassportPreviewAuthentication(report),
      Math.min(2147483647, Math.max(100, report.valid_until * 1000 - Date.now() + 50)),
    );
}
function cancelIdentityRead() {
  passportPrefilling = false;
  clearProximity();
  clearPresentationReview();
  cardGeneration++;
  clearIdentityPreview();
  $('#identity-status').textContent = '';
  if (cardBusy && invoke) void invoke('cancel_identity_card').catch(() => {});
  if (invoke) void invoke('clear_identity_evidence').catch(() => {});
}
function renderIdentityReader(view) {
  $('#identity-reader').hidden = !cardSupported || !signedIn;
  if (!$('#wallet-card-detail').hidden) {
    const blocked = cardBusy || issuanceBusy || savingDocument || walletActive || !!pending;
    $('#wallet-document-reread').disabled = !cardSupported || blocked;
    $('#wallet-document-receive').hidden =
      !selectedDocument || !walletAvailable || selectedDocumentType === 'passport';
    for (const id of [
      'wallet-document-receive',
      'wallet-passport-issue',
      'wallet-credential-present',
      'wallet-credential-proximity',
    ])
      $('#' + id).disabled = blocked;
  }
  for (const option of document.querySelectorAll('[data-document-type]'))
    option.disabled = !signedIn || !cardSupported || cardBusy || issuanceBusy || walletActive;
  $('#wallet-add-button').disabled = $('#wallet-empty-add').disabled =
    !signedIn || !cardSupported || !!pending;
  $('#wallet-reader-support').textContent = cardSupported
    ? '読み取った情報は、保存・紐付けを選ぶまで端末内で一時的に扱います。'
    : '身分証の読み取りと保存には、NFC対応のAndroid版Mikakiをお使いください。';
  if (view !== 'wallet') {
    clearProximity();
    clearPresentationReview();
    if (
      cardBusy ||
      passportPrefilling ||
      !$('#identity-preview').hidden ||
      identityAccessFields.some((id) => $('#' + id).value)
    )
      cancelIdentityRead();
  }
  $('#identity-read').disabled =
    cardBusy || issuanceBusy || savingDocument || !!pending || walletActive;
  const passport = $('#identity-type').value === 'passport';
  $('#identity-pin').disabled = cardBusy || passport;
  $('#identity-pin2').disabled = cardBusy;
  for (const id of identityAccessFields.slice(2)) $('#' + id).disabled = cardBusy || !passport;
  $('#identity-type').disabled = cardBusy;
  $('#identity-cancel').hidden = !cardBusy;
}
$('#identity-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!invoke || !cardSupported || cardBusy || issuanceBusy || savingDocument || pending) return;
  let pin = $('#identity-pin').value;
  let pin2 = $('#identity-pin2').value;
  const documentType = $('#identity-type').value;
  const passport = documentType === 'passport';
  let passportAccess = passport
    ? {
        documentNumber: $('#identity-passport-number').value,
        birthDate: $('#identity-passport-birth').value,
        expiryDate: $('#identity-passport-expiry').value,
      }
    : null;
  if (
    passport &&
    (!/^[A-Z0-9]{1,9}$/.test(passportAccess.documentNumber) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(passportAccess.birthDate) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(passportAccess.expiryDate) ||
      passportAccess.birthDate >= passportAccess.expiryDate)
  )
    return;
  if (documentType === 'driving_license' && pin2 && !/^[0-9]{4}$/.test(pin2)) return;
  if (!passport && !/^[0-9]{4}$/.test(pin)) return;
  clearIdentityPreview();
  const generation = ++cardGeneration;
  cardBusy = true;
  render();
  $('#identity-status').textContent = passport
    ? '旅券を開いたまま、ICチップをスマートフォンに近づけてください。'
    : 'カードをスマートフォンに近づけてください。';
  try {
    const reading = passport
      ? invoke('read_identity_passport', passportAccess)
      : invoke('read_identity_card', {
          pin,
          documentType,
          pin2: documentType === 'driving_license' && pin2 ? pin2 : null,
        });
    pin = '';
    pin2 = '';
    passportAccess = null;
    const result = await reading;
    if (generation !== cardGeneration || route() !== 'wallet' || document.hidden) return;
    if (
      result.verification !== 'unverified' ||
      result.document_type !== documentType ||
      (passport && result.backend_verifiable)
    )
      throw { code: 'invalid_response' };
    $('#identity-name').textContent = result.name;
    $('#identity-address').textContent = result.address;
    $('#identity-birth-date').textContent = result.birth_date;
    $('#identity-gender').textContent =
      { 1: '男性', 2: '女性', 9: '記載なし' }[result.gender] ?? '';
    $('#identity-expiry-date').textContent = result.expiry_date ?? '';
    $('#identity-link').disabled = !result.backend_verifiable;
    $('#identity-link-field').hidden = passport;
    if (passport) renderPassportPreviewAuthentication(result.passport_authentication);
    else
      $('#identity-preview-note').textContent =
        '読取結果です。本人確認とアカウントへの紐付けはまだ行っていません。';
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
      invalid_passport_access: '旅券番号と西暦の日付を確認してください。',
      passport_authentication_failed:
        '旅券との認証に失敗しました。番号・日付とBAC対応を確認してから再操作してください。',
      passport_integrity_failed: '旅券の通信内容を検証できませんでした。読み取りを中止しました。',
      invalid_data:
        '読取データを確認できませんでした。入力と対応する旅券の形式を確認してください。',
    };
    $('#identity-status').textContent = messages[error?.code] ?? 'カードを読み取れませんでした。';
    if (error?.code === 'pin_failed' && Number.isInteger(error.remaining_retries)) {
      $('#identity-status').textContent += ' 残り' + error.remaining_retries + '回です。';
    }
  } finally {
    pin = '';
    pin2 = '';
    passportAccess = null;
    cardBusy = false;
    render();
  }
});
$('#identity-cancel').addEventListener('click', () => {
  cancelIdentityRead();
  $('#identity-status').textContent = '読み取りを終了しています。';
});
$('#identity-clear').addEventListener('click', () => {
  cancelIdentityRead();
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
  cardGeneration++;
  const license = $('#identity-type').value === 'driving_license';
  const passport = $('#identity-type').value === 'passport';
  $('#identity-pin-field').hidden = passport;
  $('#identity-pin').required = !passport;
  $('#identity-passport-fields').hidden = !passport;
  $('#identity-link-field').hidden = passport;
  for (const id of identityAccessFields.slice(2)) $('#' + id).required = passport;
  $('#identity-read').textContent = passport ? 'パスポートを読み取る' : 'カードを読み取る';
  $('#identity-pin-label').textContent = license
    ? '暗証番号1（数字4桁）'
    : '券面事項入力補助用の暗証番号（数字4桁）';
  $('#identity-pin2-field').hidden = !license;
  clearIdentityPreview();
  render();
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
      age_pool_unavailable:
        '年齢専用の複数件受取は、この発行者では有効になっていません。1件を選んでください。',
      invalid_age_pool:
        '年齢専用の受取件数や属性を確認できませんでした。承認を取り直してください。',
      age_batch_unavailable:
        '年齢専用の複数件発行は、この発行者では有効になっていません。1件を選んでください。',
      invalid_age_batch: '年齢専用の発行件数や鍵を確認できませんでした。読み取り直してください。',
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
  if (!invoke || issuanceBusy || cardBusy || savingDocument || walletActive) return;
  const generation = ++issuanceGeneration;
  issuanceBusy = true;
  render();
  $('#identity-link').disabled = true;
  $('#identity-issuance').hidden = false;
  $('#identity-issuance-status').textContent = '署名を検証しています。';
  try {
    const count = Number($('#identity-credential-count').value);
    const result = await invoke('start_identity_link', {
      configuration: $('#identity-credential-format').value,
      ...(count > 1 ? { credentialCount: count } : {}),
    });
    if (generation !== issuanceGeneration) return;
    clearIdentityPreview();
    $('#identity-holder').textContent =
      `${result.credential_count ?? 1}件の端末鍵の識別子: ` +
      (result.holder_thumbprints ?? [result.holder_thumbprint]).join(', ');
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
  if (walletActive) $('#identity-wallet-issuance').open = true;
  $('#identity-wallet-start').disabled = walletActive || issuanceBusy || cardBusy;
  $('#identity-wallet-format').disabled = walletActive || issuanceBusy;
  $('#identity-wallet-count').disabled = walletActive || issuanceBusy;
  $('#identity-wallet-receive').hidden =
    !walletActive || !['pending', 'ready'].includes(walletPhase);
  $('#identity-wallet-receive').disabled = issuanceBusy || cardBusy;
  $('#identity-wallet-cancel').hidden = !walletActive;
  $('#identity-wallet-cancel').disabled = walletPhase === 'cancelling';
  if (
    view !== 'wallet' &&
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
    if (walletActive && route() !== 'wallet') navigate('wallet', true);
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
      ...(Number($('#identity-wallet-count').value) > 1
        ? { credentialCount: Number($('#identity-wallet-count').value) }
        : {}),
    });
    if (generation !== walletGeneration) return;
    if (result.phase !== 'pending') throw new Error('invalid_response');
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
        `属性証明書を${result.credential_count ?? 1}件受け取り、全件の署名を確認しました。有効期限: ` +
        new Date(result.expires_at * 1000).toLocaleTimeString();
    } else throw new Error('invalid_response');
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
        `属性証明書を${result.credential_count ?? 1}件受け取り、全件の署名を確認しました。有効期限: ` +
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

function walletElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}
function walletIcon(name, className = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `icon ${className}`);
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(svg.namespaceURI, 'use');
  use.setAttribute('href', `#${name}`);
  svg.append(use);
  return svg;
}
async function refreshPassportAvailability() {
  const generation = epoch;
  passportCapabilityEpoch = generation;
  passportAvailable = false;
  try {
    const supported = await invoke('passport_issuance_available');
    if (generation === epoch) {
      passportAvailable = supported === true;
      $('#wallet-passport-issue').hidden = !passportAvailable || !selectedPassportEligible;
    }
  } catch {
    /* Feature unavailable. */
  }
}
function clearPassportIssuanceReview(restoreFocus = false) {
  const trigger = passportReviewTrigger;
  passportReviewTrigger = null;
  const active = passportReviewId !== null || passportReviewBusy;
  passportReviewGeneration++;
  passportReviewId = null;
  passportReviewBusy = false;
  clearTimeout(passportReviewTimer);
  $('#passport-issuance-review').hidden = true;
  $('#passport-review-values').replaceChildren();
  $('#passport-review-holder').textContent = '';
  if (active && invoke) void invoke('cancel_passport_issuance_review').catch(() => {});
  if (restoreFocus && trigger?.isConnected) trigger.focus({ preventScroll: true });
}
$('#wallet-passport-issue').addEventListener('click', async () => {
  if (
    !invoke ||
    !signedIn ||
    !passportAvailable ||
    !selectedPassportSaved ||
    selectedDocumentType !== 'passport' ||
    issuanceBusy ||
    cardBusy
  )
    return;
  const trigger = walletDetailTrigger;
  closeWalletDetail();
  passportReviewTrigger = trigger;
  passportReviewBusy = true;
  const generation = ++passportReviewGeneration,
    session = epoch;
  $('#wallet-document-status').textContent = '旅券の署名と送信する項目を確認しています。';
  try {
    const review = await invoke('review_passport_issuance');
    if (
      generation !== passportReviewGeneration ||
      session !== epoch ||
      route() !== 'wallet' ||
      document.hidden
    ) {
      void invoke('cancel_passport_issuance_review').catch(() => {});
      return;
    }
    if (
      typeof review.review_id !== 'string' ||
      review.issuer !== 'https://auth.mikaki.org/identity/issuer' ||
      !Number.isSafeInteger(review.expires_at) ||
      review.expires_at * 1000 <= Date.now()
    )
      throw new Error('invalid_review');
    const labels = {
      name_mrz: '氏名（MRZ表記）',
      issuing_state: '発行国コード',
      nationality: '国籍コード',
      birth_date_mrz: '生年月日（YYMMDD）',
      expiry_date_mrz: '旅券期限（YYMMDD）',
      sex_mrz: '性別（MRZ表記）',
    };
    for (const [field, label] of Object.entries(labels)) {
      const value = review.claims?.[field];
      if (typeof value !== 'string' || value.length > 80) throw new Error('invalid_review');
      $('#passport-review-values').append(
        walletElement('dt', '', label),
        walletElement('dd', '', value),
      );
    }
    passportReviewId = review.review_id;
    $('#passport-review-holder').textContent = 'Wallet連携鍵: ' + review.holder_thumbprint;
    $('#passport-issuance-review').hidden = false;
    $('#passport-issuance-review').focus();
    $('#wallet-document-status').textContent = '';
    passportReviewTimer = setTimeout(
      clearPassportIssuanceReview,
      Math.max(0, review.expires_at * 1000 - Date.now()),
    );
  } catch (error) {
    if (generation !== passportReviewGeneration) return;
    clearPassportIssuanceReview(true);
    const code = String(error);
    $('#wallet-document-status').textContent = /passport_issuer_unavailable/.test(code)
      ? '旅券証明書の発行サービスは現在利用できません。'
      : /network_error/.test(code)
        ? '通信できませんでした。接続を確認して再試行してください。'
        : /wallet_not_configured|wallet_configuration_invalid|wallet_attestation_unavailable/.test(
              code,
            )
          ? 'このアプリのWallet認証設定を確認できません。対応版への更新が必要です。'
          : /document_login_required/.test(code)
            ? '旅券を保存したアカウントでログインし直してください。'
            : '保存した旅券の署名・失効情報を検証できませんでした。失効情報を更新したアプリで再確認してください。';
  } finally {
    if (generation === passportReviewGeneration) passportReviewBusy = false;
  }
});
$('#passport-review-cancel').addEventListener('click', () => clearPassportIssuanceReview(true));
$('#passport-review-confirm').addEventListener('click', async () => {
  if (!invoke || !passportReviewId || issuanceBusy) return;
  const id = passportReviewId;
  passportReviewTrigger = null;
  passportReviewId = null;
  clearTimeout(passportReviewTimer);
  $('#passport-issuance-review').hidden = true;
  $('#passport-review-values').replaceChildren();
  $('#passport-review-holder').textContent = '';
  const generation = ++issuanceGeneration;
  issuanceBusy = true;
  render();
  $('#identity-reader').open = true;
  $('#identity-issuance').hidden = false;
  $('#identity-issuance-status').textContent = '原本を送信して検証しています。';
  try {
    const result = await invoke('confirm_passport_issuance', { reviewId: id, approve: true });
    if (generation !== issuanceGeneration || !signedIn) return;
    if (!result) throw new Error('cancelled');
    $('#identity-holder').textContent = 'Wallet連携鍵: ' + result.holder_thumbprint;
    const message = 'ブラウザで6項目とWallet連携鍵を確認して発行を承認してください。';
    $('#identity-issuance-status').textContent = message;
    $('#identity-receive').hidden = result.haip === true;
    if (result.haip === true) {
      walletGeneration++;
      walletAvailable = true;
      walletActive = true;
      walletPhase = 'pending';
      $('#identity-wallet-issuance').open = true;
      $('#identity-wallet-status').textContent = message;
    }
  } catch {
    if (generation === issuanceGeneration)
      $('#identity-issuance-status').textContent =
        '旅券証明書の発行を開始できませんでした。署名情報とログイン状態を確認してください。';
  } finally {
    issuanceBusy = false;
    render();
  }
});

function clearWalletView() {
  $('#wallet-documents').replaceChildren();
  $('#wallet-document-count').textContent = '0';
  $('#wallet-document-status').textContent = '';
  $('#wallet-empty').hidden = true;
  $('#wallet-inventory').replaceChildren();
  closeWalletDetail();
}
function closeWalletDetail(restoreFocus = false) {
  clearPassportIssuanceReview();
  walletDetailGeneration++;
  selectedPassportSaved = false;
  selectedPassportEligible = false;
  hidePassportDetails();
  $('#wallet-passport-section').hidden = true;
  const trigger = walletDetailTrigger;
  walletDetailTrigger = null;
  selectedDocument = null;
  selectedDocumentType = null;
  $('#wallet-card-detail').hidden = true;
  for (const id of [
    'wallet-card-title',
    'wallet-card-issuer',
    'wallet-card-kind',
    'wallet-card-note',
  ])
    $('#' + id).textContent = '';
  $('#wallet-card-values').replaceChildren();
  $('#wallet-document-remove').hidden = true;
  for (const id of [
    'wallet-document-reread',
    'wallet-document-receive',
    'wallet-passport-issue',
    'wallet-credential-present',
    'wallet-credential-proximity',
  ])
    $('#' + id).hidden = true;
  if (restoreFocus && trigger?.isConnected) trigger.focus({ preventScroll: true });
}
function showWalletDetail(card, trigger) {
  closeWalletDetail();
  if (card.source === 'issued_credential' && card.expires_at * 1000 <= Date.now()) {
    void refreshWalletInventory();
    return;
  }
  walletDetailTrigger = trigger;
  selectedDocumentType = card.source === 'card_read' ? card.documentType : null;
  selectedDocument = card.source === 'card_read' ? card.id : null;
  selectedPassportSaved = card.source === 'card_read' && card.passportSaved;
  $('#wallet-passport-section').hidden = !selectedPassportSaved;
  $('#wallet-card-title').textContent = card.title;
  $('#wallet-card-kind').textContent =
    card.source === 'card_read' ? '身分証の読取記録' : '発行された証明書';
  $('#wallet-card-issuer').textContent =
    card.source === 'card_read'
      ? '保存日 ' + new Date(card.savedAt * 1000).toLocaleString('ja-JP')
      : '発行者: ' + card.issuer;
  const names = {
    name_mrz: '氏名（MRZ表記）',
    issuing_state: '発行国コード',
    nationality: '国籍コード',
    birth_date_mrz: '生年月日（YYMMDD）',
    expiry_date_mrz: '旅券期限（YYMMDD）',
    sex_mrz: '性別（MRZ表記）',
    name: '氏名',
    address: '住所',
    birthdate: '生年月日',
    gender: '性別',
    document_expiry_date: '書類の有効期限',
  };
  for (const [key, value] of Object.entries(card.fields)) {
    if (value === null || value === undefined || value === '') continue;
    const term = walletElement('dt', '', names[key] ?? key);
    let display = typeof value === 'object' ? (value?.formatted ?? '') : String(value);
    if (key === 'gender') display = { 1: '男性', 2: '女性', 9: '記載なし' }[display] ?? display;
    $('#wallet-card-values').append(term, walletElement('dd', '', display));
  }
  if (card.source === 'issued_credential') {
    $('#wallet-card-values').append(
      walletElement('dt', '', '証明書の有効期限'),
      walletElement('dd', '', new Date(card.expires_at * 1000).toLocaleString('ja-JP')),
    );
  }
  $('#wallet-card-note').textContent =
    card.source === 'card_read' && card.documentType === 'passport'
      ? passportAuthenticationNote(card.passportAuthentication) +
        ' BAC通信で読み取った内容の控えです。日付の西暦年には入力した値を使っています。公的な身分証の代わりには使えません。この記録から証明書発行・VP提示はできません。'
      : card.source === 'card_read'
        ? 'この端末で読み取った内容の控えです。公的な身分証の代わりには使えません。オンライン・対面で提示するには、発行者の署名付き証明書を受け取ります。'
        : '提示先と送る項目は、提示要求を開いてから確認します。カードを開くだけでは送信しません。';
  $('#wallet-document-remove').hidden = card.source !== 'card_read';
  $('#wallet-document-reread').hidden = card.source !== 'card_read';
  $('#wallet-document-reread').textContent =
    card.documentType === 'passport' ? 'パスポートを読み取り直す' : '再読取して本人確認する';
  $('#wallet-document-reread').disabled = !cardSupported;
  $('#wallet-document-receive').hidden =
    card.source !== 'card_read' || !walletAvailable || card.documentType === 'passport';
  selectedPassportEligible =
    card.passportSaved &&
    card.passportAuthentication?.issuer_trust === 'csca_verified' &&
    card.passportAuthentication?.revocation === 'good' &&
    card.passportAuthentication?.valid_until * 1000 > Date.now();
  $('#wallet-passport-issue').hidden = !passportAvailable || !selectedPassportEligible;
  $('#wallet-credential-present').hidden = card.source !== 'issued_credential';
  $('#wallet-credential-proximity').hidden =
    card.source !== 'issued_credential' || card.format !== 'mso_mdoc' || !cardSupported;
  $('#wallet-card-detail').hidden = false;
  $('#wallet-card-detail').focus({ preventScroll: true });
  $('#wallet-card-detail').scrollIntoView({ behavior: 'instant', block: 'nearest' });
}
function createWalletCard(card) {
  const read = card.source === 'card_read';
  const row = walletElement(
    'button',
    `identity-card ${card.theme} ${read ? 'document-card' : 'wallet-card'}`,
  );
  row.type = 'button';
  row.append(walletElement('span', 'card-pattern'));
  const top = walletElement('span', 'card-top');
  top.append(walletElement('span', 'card-overline', card.subtitle), walletIcon(card.icon));
  row.append(top, walletElement('strong', 'card-title', card.title));
  const person = walletElement('span', 'card-person');
  person.append(
    walletIcon('i-user'),
    walletElement(
      'span',
      'card-holder',
      hideWalletNames ? '•••• ••••' : card.displayName || '氏名の記載なし',
    ),
  );
  // Only the actual display name is kept in this button's closure. Nothing is persisted in DOM data attributes.
  person.lastChild.dataset.walletName = '';
  row.append(person);
  const bottom = walletElement('span', 'card-bottom');
  bottom.append(walletElement('span', 'card-badge', read ? card.status : '署名確認済み'));
  const expiry = read
    ? card.expiry
      ? `有効期限 ${card.expiry}`
      : '有効期限の情報なし'
    : card.format === 'mso_mdoc'
      ? 'mdoc'
      : 'SD-JWT';
  bottom.append(
    walletElement('span', 'card-expiry', expiry),
    walletElement('span', 'card-open', '↗'),
  );
  row.append(bottom);
  row.addEventListener('click', () => showWalletDetail(card, row));
  row.addEventListener('wallet-privacy', () => {
    person.lastChild.textContent = hideWalletNames
      ? '•••• ••••'
      : card.displayName || '氏名の記載なし';
  });
  return row;
}
function openWalletAdd() {
  $('#wallet-add').open = true;
  $('#wallet-add').scrollIntoView({ behavior: 'instant', block: 'nearest' });
  $('#wallet-add summary').focus();
}
$('#wallet-add-button').addEventListener('click', openWalletAdd);
$('#wallet-empty-add').addEventListener('click', openWalletAdd);
$('#wallet-add').addEventListener('toggle', () =>
  $('#wallet-add-button').setAttribute('aria-expanded', String($('#wallet-add').open)),
);
function openDocumentReader(type) {
  if (!['my_number_card', 'driving_license', 'passport'].includes(type)) return false;
  if (
    !cardSupported ||
    cardBusy ||
    issuanceBusy ||
    savingDocument ||
    walletActive ||
    route() !== 'wallet' ||
    document.hidden
  )
    return false;
  closeWalletDetail();
  $('#identity-type').value = type;
  $('#identity-type').dispatchEvent(new Event('change'));
  $('#identity-reader').open = true;
  $('#wallet-add').open = false;
  $('#identity-reader').scrollIntoView({ behavior: 'instant', block: 'start' });
  $(type === 'passport' ? '#identity-passport-number' : '#identity-pin').focus({
    preventScroll: true,
  });
  return true;
}
for (const option of document.querySelectorAll('[data-document-type]')) {
  option.addEventListener('click', () => openDocumentReader(option.dataset.documentType));
}
$('#wallet-document-reread').addEventListener('click', async () => {
  const saved = selectedPassportSaved;
  if (!openDocumentReader(selectedDocumentType) || !saved) return;
  const generation = cardGeneration,
    session = epoch;
  passportPrefilling = true;
  try {
    const access = await invoke('identity_passport_details');
    if (
      generation !== cardGeneration ||
      session !== epoch ||
      !signedIn ||
      route() !== 'wallet' ||
      document.hidden ||
      $('#identity-type').value !== 'passport' ||
      cardBusy
    )
      return;
    $('#identity-passport-number').value = access.document_number;
    $('#identity-passport-birth').value = access.birth_date;
    $('#identity-passport-expiry').value = access.expiry_date;
    $('#identity-status').textContent =
      '保存した旅券情報を入力しました。内容を確認してから読み取ってください。';
  } catch {
    if (generation === cardGeneration && session === epoch && route() === 'wallet')
      $('#identity-status').textContent =
        '保存した旅券情報を取得できませんでした。旅券番号と日付を入力してください。';
  } finally {
    if (generation === cardGeneration) passportPrefilling = false;
  }
});
for (const id of identityAccessFields.slice(2))
  $('#' + id).addEventListener('input', () => {
    if (passportPrefilling) {
      cardGeneration++;
      passportPrefilling = false;
    }
  });
function hidePassportDetails() {
  $('#wallet-passport-values').replaceChildren();
  $('#wallet-passport-values').hidden = true;
  $('#wallet-passport-status').textContent = '';
  $('#wallet-passport-reveal').textContent = '旅券番号・MRZを表示';
  $('#wallet-passport-reveal').setAttribute('aria-expanded', 'false');
  $('#wallet-passport-reveal').disabled = false;
}
$('#wallet-passport-reveal').addEventListener('click', async () => {
  if (!invoke || !selectedPassportSaved || selectedDocumentType !== 'passport') return;
  if (!$('#wallet-passport-values').hidden) {
    walletDetailGeneration++;
    hidePassportDetails();
    return;
  }
  const generation = walletDetailGeneration,
    session = epoch;
  $('#wallet-passport-reveal').disabled = true;
  try {
    const details = await invoke('identity_passport_details');
    if (
      generation !== walletDetailGeneration ||
      session !== epoch ||
      !signedIn ||
      route() !== 'wallet' ||
      document.hidden ||
      selectedDocumentType !== 'passport'
    )
      return;
    if (!/^[A-Z0-9]{1,9}$/.test(details.document_number) || !/^[A-Z0-9<]{88}$/.test(details.mrz))
      throw new Error('invalid_passport_details');
    const values = $('#wallet-passport-values');
    values.append(
      walletElement('dt', '', '旅券番号'),
      walletElement('dd', '', details.document_number),
      walletElement('dt', '', 'MRZ（ICチップから読取）'),
      walletElement('dd', 'passport-mrz', details.mrz.slice(0, 44) + '\n' + details.mrz.slice(44)),
    );
    values.hidden = false;
    $('#wallet-passport-reveal').textContent = '旅券番号・MRZを隠す';
    $('#wallet-passport-reveal').setAttribute('aria-expanded', 'true');
  } catch {
    if (generation === walletDetailGeneration && session === epoch)
      $('#wallet-passport-status').textContent = '保存した旅券情報を取得できませんでした。';
  } finally {
    if (generation === walletDetailGeneration && session === epoch)
      $('#wallet-passport-reveal').disabled = false;
  }
});
$('#wallet-document-receive').addEventListener('click', () => {
  if (!walletAvailable || walletActive || issuanceBusy || cardBusy || savingDocument) return;
  closeWalletDetail();
  $('#identity-wallet-issuance').open = true;
  $('#identity-wallet-format').focus();
  $('#identity-wallet-issuance').scrollIntoView({ behavior: 'instant', block: 'start' });
});
function openPresentationPreparation(nearby) {
  if (
    issuanceBusy ||
    cardBusy ||
    savingDocument ||
    walletActive ||
    route() !== 'wallet' ||
    document.hidden
  )
    return;
  closeWalletDetail();
  $('#wallet-present').open = true;
  const input = nearby ? $('#identity-proximity-engagement') : $('#identity-vp-request');
  input.focus();
  input.scrollIntoView({ behavior: 'instant', block: 'center' });
}
$('#wallet-credential-present').addEventListener('click', () => openPresentationPreparation(false));
$('#wallet-credential-proximity').addEventListener('click', () =>
  openPresentationPreparation(true),
);
$('#wallet-privacy').addEventListener('click', () => {
  hideWalletNames = !hideWalletNames;
  $('#wallet-privacy').setAttribute('aria-pressed', String(hideWalletNames));
  $('#wallet-privacy span').textContent = hideWalletNames ? '氏名を表示' : '氏名を隠す';
  closeWalletDetail();
  for (const card of document.querySelectorAll('.identity-card'))
    card.dispatchEvent(new Event('wallet-privacy'));
});
$('#wallet-detail-close').addEventListener('click', () => closeWalletDetail(true));
$('#wallet-document-remove').addEventListener('click', async () => {
  const id = selectedDocument;
  if (!id || !confirm('この端末に保存した読取記録を削除しますか？')) return;
  $('#wallet-document-remove').disabled = true;
  try {
    await invoke('remove_identity_document', { documentId: id });
    closeWalletDetail();
    await refreshWalletInventory();
  } catch {
    $('#wallet-card-note').textContent = '削除できませんでした。もう一度試してください。';
  } finally {
    $('#wallet-document-remove').disabled = false;
  }
});
$('#identity-save-document').addEventListener('click', async () => {
  if (!invoke || savingDocument || cardBusy) return;
  savingDocument = true;
  render();
  const generation = cardGeneration;
  $('#identity-save-document').disabled = true;
  try {
    await invoke('save_identity_document');
    if (generation !== cardGeneration || route() !== 'wallet' || document.hidden) return;
    $('#identity-save-status').textContent = 'この端末のWalletに保存しました。';
    $('#identity-save-document').textContent = 'Walletに保存済み';
    await refreshWalletInventory();
  } catch (error) {
    if (generation !== cardGeneration) return;
    $('#identity-save-status').textContent = String(error).includes('read_required')
      ? '読取結果の有効期限が切れました。もう一度読み取ってください。'
      : '保存できませんでした。もう一度試してください。';
    $('#identity-save-document').disabled = false;
  } finally {
    savingDocument = false;
    render();
  }
});

async function refreshWalletInventory() {
  if (!invoke || route() !== 'wallet' || document.hidden) return;
  const generation = ++walletInventoryGeneration;
  $('#wallet-status').textContent = '証明書を確認しています。';
  $('#wallet-document-status').textContent = '身分証を確認しています。';
  const [documents, credentials] = await Promise.allSettled([
    signedIn ? invoke('identity_document_inventory') : Promise.resolve({ documents: [] }),
    invoke('identity_wallet_inventory'),
  ]);
  if (generation !== walletInventoryGeneration || route() !== 'wallet' || document.hidden) return;
  clearTimeout(walletExpiryTimer);
  clearWalletView();
  const deadlines = [];
  if (documents.status === 'fulfilled' && Array.isArray(documents.value?.documents)) {
    try {
      const records = documents.value.documents.map((record) => walletDocument(record));
      for (const card of records) {
        $('#wallet-documents').append(createWalletCard(card));
        const until = card.passportAuthentication?.valid_until;
        if (Number.isSafeInteger(until) && until * 1000 > Date.now()) deadlines.push(until * 1000);
      }
      $('#wallet-document-count').textContent = String(records.length);
      $('#wallet-empty').hidden = records.length > 0;
      $('#wallet-document-status').textContent = records.length ? 'この端末に保存した読取記録' : '';
    } catch {
      $('#wallet-document-status').textContent =
        '身分証の保存内容を確認できませんでした。一覧を更新してください。';
    }
  } else
    $('#wallet-document-status').textContent =
      '身分証を確認できませんでした。一覧を更新してください。';
  if (credentials.status === 'fulfilled' && Array.isArray(credentials.value)) {
    try {
      const cards = credentials.value
        .filter((card) => card.expires_at * 1000 > Date.now())
        .map(walletCredential);
      for (const card of cards) $('#wallet-inventory').append(createWalletCard(card));
      $('#wallet-status').textContent = cards.length
        ? `証明書 ${cards.length}件 · 提示する項目は毎回確認します。`
        : '証明書はまだありません。本人確認後に受け取ると、ここに表示されます。';
      deadlines.push(...cards.map((c) => c.expires_at * 1000));
    } catch {
      $('#wallet-status').textContent = '証明書を確認できませんでした。一覧を更新してください。';
    }
  } else $('#wallet-status').textContent = presentationError(credentials.reason);
  if (deadlines.length)
    walletExpiryTimer = setTimeout(
      () => {
        // Remove old success labels before waiting for a possibly slow native refresh.
        clearWalletView();
        void refreshWalletInventory();
      },
      Math.min(2147483647, Math.max(100, Math.min(...deadlines) - Date.now() + 50)),
    );
}
$('#identity-wallet-restore').addEventListener('click', () => void refreshWalletInventory());
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
      wallet_storage_unavailable: '証明書の使用状態を保存できないため、送信しませんでした。',
      wallet_key_unavailable: '証明書の鍵を確認できません。新しい証明書を受け取ってください。',
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
function appendPredicateSource(target, credential) {
  if (credential.source?.single_use === true) {
    const usage = document.createElement('dt');
    usage.textContent = '1回限りの年齢証明';
    const notice = document.createElement('dd');
    notice.textContent =
      '提示を承認すると、この証明書は送信前に使用済みになります。送信に失敗しても再利用できません。次の提示には新しい証明書が必要です。';
    target.append(usage, notice);
  }
  if (!Object.keys(credential.values).some((key) => key === 'age_over_18' || key === 'age_over_20'))
    return;
  const term = document.createElement('dt');
  term.textContent = '確認結果の根拠';
  const description = document.createElement('dd');
  const documentType = credential.source?.document_type;
  const label =
    documentType === 'my_number_card'
      ? 'マイナンバーカード（券面入力補助AP）'
      : documentType === 'driving_license'
        ? 'IC運転免許証'
        : '紐付けた文書';
  const disclosure = Object.hasOwn(credential.values, 'birthdate')
    ? '生年月日の値も上記のとおり送信します。'
    : '生年月日の値は送信しません。';
  description.textContent = `${label}の署名済み生年月日から発行時に計算。${disclosure}カードの現在の所持は確認していません。`;
  target.append(term, description);
}
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
      name_mrz: '氏名（MRZ表記）',
      issuing_state: '発行国コード',
      nationality: '国籍コード',
      birth_date_mrz: '生年月日（YYMMDD）',
      expiry_date_mrz: '旅券期限（YYMMDD）',
      sex_mrz: '性別（MRZ表記）',
      name: '氏名',
      address: '住所',
      birthdate: '生年月日',
      age_over_18: '18歳以上である',
      age_over_20: '20歳以上である',
      gender: '性別（カード上の符号）',
      document_expiry_date: '身分証の有効期限',
    };
    const credentials = review.credentials?.length
      ? review.credentials
      : [{ values: review.values, source: review.source, retained_fields: review.retained_fields }];
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
            : typeof value === 'boolean'
              ? value
                ? 'はい'
                : 'いいえ'
              : String(value);
        target.append(term, description);
      }
      appendPredicateSource(target, credential);
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
  if (!invoke || !available || invocationChecking || issuanceBusy || cardBusy || proximityActive)
    return;
  invocationChecking = true;
  let reviewed = false;
  try {
    const id = await invoke('pending_identity_invocation');
    if (!id || issuanceBusy || cardBusy || proximityActive) return;
    navigate('wallet');
    $('#wallet-present').open = true;
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
      name_mrz: '氏名（MRZ表記）',
      issuing_state: '発行国コード',
      nationality: '国籍コード',
      birth_date_mrz: '生年月日（YYMMDD）',
      expiry_date_mrz: '旅券期限（YYMMDD）',
      sex_mrz: '性別（MRZ表記）',
      name: '氏名',
      address: '住所',
      birthdate: '生年月日',
      age_over_18: '18歳以上である',
      age_over_20: '20歳以上である',
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
          : typeof value === 'boolean'
            ? value
              ? 'はい'
              : 'いいえ'
            : String(value);
      $('#identity-proximity-values').append(term, description);
    }
    appendPredicateSource($('#identity-proximity-values'), review);
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
    } else if (event === 'product-wallet-ready') {
      navigate('wallet');
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

document.addEventListener('visibilitychange', () => {
  clearTimeout(walletAccountTimer);
  if (document.hidden) {
    walletInventoryGeneration++;
    walletInventoryLoaded = false;
    clearTimeout(walletExpiryTimer);
    clearWalletView();
    clearPassportIssuanceReview();
    cancelIdentityRead();
  } else {
    passportCapabilityEpoch = -1;
    void refreshWalletAccount();
  }
});
window.addEventListener('focus', () => void refreshWalletAccount());
