/** Lazy product entry. The owner lease comes from the already unlocked Vault. */
import init, * as wasm from 'mikaki-chat-crypto';
import type { OwnerVaultController } from '../vault-owner-controller.ts';
import { VaultMlsDevice, type EnrollmentModule } from './vault-device.ts';
import { MlsChatView } from './chat-view.ts';
import type { MessagingOptions } from '../messaging-module.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
type Profile = { device: string; phase: 'enrolling' | 'active' };
type Configuration = {
  enabled: true;
  issuer: string;
  public_key: string;
  registered_device_id: string | null;
};
async function config(owner: OwnerVaultController): Promise<Configuration> {
  const response = await owner.scope.request('/vault/messaging-config', { cache: 'no-store' });
  const value: unknown = await response.json();
  if (!response.ok || !value || typeof value !== 'object') throw new Error('messaging_unavailable');
  const v = value as Configuration;
  if (
    Object.keys(v).length !== 4 ||
    !['enabled', 'issuer', 'public_key', 'registered_device_id'].every((key) =>
      Object.hasOwn(v, key),
    ) ||
    v.enabled !== true ||
    v.issuer !== location.origin ||
    typeof v.public_key !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(v.public_key) ||
    (v.registered_device_id !== null &&
      (typeof v.registered_device_id !== 'string' || !UUID.test(v.registered_device_id)))
  )
    throw new Error('messaging_unavailable');
  return v;
}
async function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('mikaki-chat-profile-v1', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('profiles');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('profile_unavailable'));
  });
}
function checkedProfile(value: unknown): Profile | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid_profile');
  const { device, phase } = value as Record<string, unknown>;
  if (
    Object.keys(value).length !== 2 ||
    !Object.hasOwn(value, 'device') ||
    !Object.hasOwn(value, 'phase') ||
    typeof device !== 'string' ||
    !UUID.test(device) ||
    (phase !== 'enrolling' && phase !== 'active')
  )
    throw new Error('invalid_profile');
  return { device, phase };
}
async function profile(id: string, next?: Profile): Promise<Profile | undefined> {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('profiles', next ? 'readwrite' : 'readonly');
      const request = next
        ? tx.objectStore('profiles').put(next, id)
        : tx.objectStore('profiles').get(id);
      let value: unknown;
      request.onsuccess = () => {
        value = next ?? request.result;
      };
      tx.oncomplete = () => {
        try {
          resolve(checkedProfile(value));
        } catch (error) {
          reject(error);
        }
      };
      tx.onerror = tx.onabort = () => reject(new Error('profile_unavailable'));
    });
  } finally {
    db.close();
  }
}
const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '') => {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
};
export async function mount(
  owner: OwnerVaultController,
  root: HTMLElement,
  options?: MessagingOptions,
): Promise<{ dispose(): void }> {
  const token = owner.checkpoint();
  const context = owner.lease().stored.context;
  const id = Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(JSON.stringify(['mikaki-chat-profile-v1', context])),
      ),
    ),
    (b) => b.toString(16).padStart(2, '0'),
  ).join('');
  owner.assertCurrent(token);
  const settings = await config(owner);
  await init({ module_or_path: new URL('/messaging/crypto.wasm', location.origin) });
  owner.assertCurrent(token);
  if (!document.querySelector('link[data-messaging-style]')) {
    const style = document.createElement('link');
    style.rel = 'stylesheet';
    style.href = '/messaging/chat.css';
    style.dataset['messagingStyle'] = 'true';
    document.head.append(style);
  }
  let device: VaultMlsDevice | undefined,
    chat: MlsChatView | undefined,
    closed = false;
  const dispose = () => {
    if (closed) return;
    closed = true;
    chat?.dispose();
    device?.close();
    unsubscribe();
    root.replaceChildren();
  };
  const unsubscribe = owner.onLeaseInvalidated(dispose);
  const assert = () => {
    owner.assertCurrent(token);
    if (closed) throw new Error('messaging_closed');
  };
  const blocked = (message: string) => {
    if (!closed) {
      root.replaceChildren(node('p', message));
      root.firstElementChild?.setAttribute('role', 'alert');
    }
  };
  const connect = async (entry: Profile, create: boolean) => {
    assert();
    device = new VaultMlsDevice(
      owner,
      // The separately built native module implements the pinned custody ABI.
      wasm as unknown as EnrollmentModule,
      JSON.stringify([{ issuer: settings.issuer, public_key: settings.public_key }]),
      entry.device,
    );
    if (create) await device.create();
    else await device.open();
    assert();
    await profile(id, { device: entry.device, phase: 'active' });
    assert();
    chat = new MlsChatView(root, device, undefined, true, options?.onDraft, true);
    await chat.open();
    assert();
  };
  try {
    if (!navigator.locks) throw new Error('web_locks_required');
    await navigator.locks.request(
      `mikaki-chat-profile:${id}`,
      { signal: owner.scope.signal },
      async () => {
        assert();
        const saved = await profile(id);
        assert();
        if (saved) {
          if (settings.registered_device_id && settings.registered_device_id !== saved.device)
            throw new Error('profile_mismatch');
          await connect(saved, false);
        } else if (settings.registered_device_id) {
          throw new Error('local_profile_missing');
        } else {
          const section = node('section');
          section.append(
            node(
              'p',
              'このブラウザーをチャット端末として登録します。秘密鍵と本文は、この端末のVaultで暗号化して保存します。保存データを削除すると、過去の会話には戻れません。',
            ),
          );
          const button = node('button', 'この端末でチャットを有効にする');
          button.type = 'button';
          button.addEventListener('click', () => {
            if (button.disabled || closed) return;
            button.disabled = true;
            void navigator.locks
              .request(`mikaki-chat-profile:${id}`, { signal: owner.scope.signal }, async () => {
                assert();
                const previous = await profile(id);
                const current = await config(owner);
                assert();
                if (previous || current.registered_device_id)
                  throw new Error('profile_already_exists');
                const next: Profile = { device: crypto.randomUUID(), phase: 'enrolling' };
                await profile(id, next);
                assert();
                await connect(next, true);
              })
              .catch(() =>
                blocked(
                  '端末登録を完了できませんでした。Vaultを開き直して保存済みの登録を確認してください。端末や鍵は自動で作り直しません。',
                ),
              );
          });
          section.append(button);
          root.replaceChildren(section);
        }
      },
    );
  } catch {
    device?.close();
    blocked(
      'このブラウザーのチャット保存データを確認できないため停止しています。鍵や会話を自動で作り直すことはできません。',
    );
  }
  return { dispose };
}
