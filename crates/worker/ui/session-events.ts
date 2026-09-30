const CHANNEL = 'mikaki-vault-lifecycle-v1';
const STORAGE = 'mikaki-vault-lock-v1';
export function publishVaultLock(): void {
  // The notification is a lock hint, never proof of revocation. No identity or secret is sent.
  try {
    const channel = new BroadcastChannel(CHANNEL);
    channel.postMessage('lock');
    channel.close();
  } catch {
    /* Storage and resume verification remain available. */
  }
  try {
    localStorage.setItem(STORAGE, `${Date.now()}:${crypto.randomUUID()}`);
  } catch {
    /* Best effort; access is still checked on resume. */
  }
}
export function subscribeVaultLock(lock: () => void): () => void {
  let channel: BroadcastChannel | null = null;
  try {
    channel = new BroadcastChannel(CHANNEL);
    channel.onmessage = (event) => {
      if (event.data === 'lock') lock();
    };
  } catch {
    /* Storage fallback. */
  }
  const storage = (event: StorageEvent) => {
    if (event.key === STORAGE && event.newValue) lock();
  };
  window.addEventListener('storage', storage);
  return () => {
    channel?.close();
    window.removeEventListener('storage', storage);
  };
}
