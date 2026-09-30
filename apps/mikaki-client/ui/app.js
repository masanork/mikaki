const button = document.querySelector('#login');
const clear = document.querySelector('#clear');
const status = document.querySelector('#status');
const vaultSection = document.querySelector('#vault');
const vaultConsent = document.querySelector('#vault-consent');
const vaultKey = document.querySelector('#vault-key');
const vaultRead = document.querySelector('#vault-read');
const vaultStatus = document.querySelector('#vault-status');
const invoke = window.__TAURI__?.core?.invoke;
let platform;
let pollGeneration = 0;

button.disabled = true;
clear.disabled = true;

if (!invoke) {
  status.textContent = 'この端末のネイティブログインはまだ利用できません。';
} else {
  try {
    platform = await invoke('native_platform');
    const session = await invoke('native_session');
    button.disabled = false;
    clear.disabled = false;
    if (session) status.textContent = 'ログイン済みです。';
    if (platform === 'mobile') {
      const mobile = await invoke('mobile_auth_status');
      vaultSection.hidden = !mobile.vault_preview_available;
      vaultRead.disabled = mobile.vault_attribute !== 'owner_note';
      if (mobile.phase === 'pending' || mobile.phase === 'exchanging') {
        button.disabled = true;
        status.textContent = 'システムブラウザで認証してください。';
        pollMobile(++pollGeneration);
      }
    }
  } catch {
    status.textContent = 'この端末のネイティブログインはまだ利用できません。';
  }

  button.addEventListener('click', async () => {
    button.disabled = true;
    status.textContent = 'システムブラウザで認証してください。';
    try {
      if (platform === 'mobile') {
        await invoke('start_mobile_login');
        pollMobile(++pollGeneration);
      } else {
        await invoke('start_desktop_login');
        status.textContent = 'ログインしました。';
        button.disabled = false;
      }
    } catch (error) {
      status.textContent = String(error);
      button.disabled = false;
    }
  });

  clear.addEventListener('click', async () => {
    pollGeneration++;
    try {
      await invoke('clear_native_session');
      status.textContent = 'この端末のセッションを消去しました。';
      vaultRead.disabled = true;
      vaultConsent.disabled = false;
      vaultStatus.textContent = '';
      button.disabled = false;
    } catch (error) {
      status.textContent = String(error);
    }
  });

  vaultConsent.addEventListener('click', async () => {
    vaultConsent.disabled = true;
    vaultRead.disabled = true;
    vaultStatus.textContent = 'システムブラウザでVault読取を承認してください。';
    try {
      await invoke('start_mobile_vault_read', { attribute: 'owner_note' });
      button.disabled = true;
      pollMobile(++pollGeneration);
    } catch (error) {
      vaultStatus.textContent = String(error);
      vaultConsent.disabled = false;
    }
  });

  vaultKey.addEventListener('click', async () => {
    vaultKey.disabled = true;
    vaultStatus.textContent = '端末の署名鍵を確認しています。';
    try {
      await invoke('check_mobile_vault_key');
      vaultStatus.textContent = '端末の署名鍵を利用できます。';
    } catch (error) {
      vaultStatus.textContent = String(error);
    } finally {
      vaultKey.disabled = false;
    }
  });

  vaultRead.addEventListener('click', async () => {
    vaultRead.disabled = true;
    vaultStatus.textContent = '暗号文を取得しています。';
    try {
      const snapshot = await invoke('read_mobile_vault_ciphertext');
      vaultStatus.textContent = `暗号文を取得しました。revision ${snapshot.revision}、形式 ${snapshot.format_version}。`;
      vaultRead.disabled = false;
    } catch (error) {
      vaultStatus.textContent = String(error);
    }
  });
}

async function pollMobile(generation) {
  if (generation !== pollGeneration) return;
  try {
    const result = await invoke('mobile_auth_status');
    if (generation !== pollGeneration) return;
    if (result.phase === 'pending' || result.phase === 'exchanging') {
      setTimeout(() => pollMobile(generation), 1000);
      return;
    }
    if (result.phase === 'vault_complete') {
      vaultStatus.textContent = 'Vault読取が承認されました。暗号文を取得できます。';
      vaultRead.disabled = result.vault_attribute !== 'owner_note';
      vaultConsent.disabled = false;
      button.disabled = false;
      return;
    }
    const messages = {
      complete: 'ログインしました。',
      denied: '認証が取り消されました。',
      failed: 'ログインを完了できませんでした。',
      expired: 'ログインが時間切れになりました。',
    };
    status.textContent = messages[result.phase] ?? 'ログインを完了できませんでした。';
    if (vaultConsent.disabled) {
      vaultStatus.textContent = messages[result.phase] ?? 'Vault読取を開始できませんでした。';
    }
    vaultConsent.disabled = false;
  } catch {
    status.textContent = 'ログイン状態を確認できませんでした。';
  }
  button.disabled = false;
}
