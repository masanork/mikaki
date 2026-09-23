import {
  decodeBase64Url,
  encodeBase64Url,
  newPrfInput,
  openAttribute,
  parseOwnerEnvelope,
  sealAttribute,
  type SealedAttribute,
} from './vault-crypto.js';

type RecordResponse = SealedAttribute & { revision: number };
type Pending = {
  method: 'PUT' | 'DELETE';
  revision: number;
  value: string;
  id: string;
  body: string | undefined;
};

const inputElement = document.getElementById('name');
const unlockElement = document.getElementById('unlock');
const saveElement = document.getElementById('save');
const removeElement = document.getElementById('delete');
const statusElement = document.getElementById('status');
if (
  !(inputElement instanceof HTMLInputElement) ||
  !(unlockElement instanceof HTMLButtonElement) ||
  !(saveElement instanceof HTMLButtonElement) ||
  !(removeElement instanceof HTMLButtonElement) ||
  !(statusElement instanceof HTMLElement)
)
  throw new Error('Invalid Vault page');
const input = inputElement;
const unlock = unlockElement;
const save = saveElement;
const remove = removeElement;
const status = statusElement;

const attribute = 'name';
const endpoint = `/vault/attributes/${attribute}`;
const origin = location.origin;
let current: RecordResponse | null = null;
let currentRevision = 0;
let sessionCredential: Uint8Array<ArrayBuffer> | null = null;
let opened = false;
let pending: Pending | null = null;

function message(value: string): void {
  status.textContent = value;
}

function controls(): void {
  input.disabled = !opened;
  save.disabled = !opened;
  remove.disabled = !opened || current === null;
  unlock.disabled = opened;
}

function record(value: unknown): value is RecordResponse {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Partial<RecordResponse>;
  return (
    item.format_version === 1 &&
    Number.isSafeInteger(item.revision) &&
    typeof item.revision === 'number' &&
    item.revision > 0 &&
    typeof item.ciphertext === 'string' &&
    typeof item.owner_envelope === 'string'
  );
}

async function prf(
  credentialId: Uint8Array<ArrayBuffer>,
  prfInput: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!window.PublicKeyCredential || !navigator.credentials)
    throw new Error('このブラウザはPasskeyに対応していません。');
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: prfInput } } },
    },
  });
  if (
    !(credential instanceof PublicKeyCredential) ||
    encodeBase64Url(new Uint8Array(credential.rawId)) !== encodeBase64Url(credentialId)
  ) {
    throw new Error('指定したPasskeyでの確認が必要です。');
  }
  const output = credential.getClientExtensionResults().prf?.results?.first;
  if (!(output instanceof ArrayBuffer) || output.byteLength !== 32) {
    throw new Error('このPasskeyはPRFに対応していません。別の対応Passkeyが必要です。');
  }
  return new Uint8Array(output);
}

async function load(): Promise<void> {
  opened = false;
  current = null;
  currentRevision = 0;
  pending = null;
  input.value = '';
  controls();
  const session = await fetch('/vault/session', { cache: 'no-store' });
  if (!session.ok) throw new Error('ログインの有効期限が切れました。');
  const sessionBody: unknown = await session.json();
  if (
    typeof sessionBody !== 'object' ||
    sessionBody === null ||
    !('credential_id' in sessionBody) ||
    typeof sessionBody.credential_id !== 'string'
  ) {
    throw new Error('Passkey情報を読み込めません。');
  }
  sessionCredential = decodeBase64Url(sessionBody.credential_id);
  const response = await fetch(endpoint, { cache: 'no-store' });
  if (response.status === 404) {
    const etag = response.headers.get('ETag');
    if (etag !== null) {
      const match = /^"([1-9][0-9]*)"$/.exec(etag);
      if (!match) throw new Error('保存データの版を確認できません。');
      currentRevision = Number(match[1]);
      if (!Number.isSafeInteger(currentRevision))
        throw new Error('保存データの版を確認できません。');
    }
    message('表示名は未登録です。Passkeyで開いて登録できます。');
    return;
  }
  if (!response.ok) throw new Error('表示名を読み込めません。');
  const body: unknown = await response.json();
  if (!record(body)) throw new Error('保存データの形式を確認できません。');
  current = body;
  currentRevision = body.revision;
  message('Passkeyで開いて表示名を確認してください。');
}

unlock.addEventListener('click', async () => {
  try {
    if (current) {
      const envelope = parseOwnerEnvelope(current.owner_envelope);
      const output = await prf(envelope.credentialId, envelope.prfInput);
      const plaintext = await openAttribute(
        current,
        output,
        envelope.credentialId,
        origin,
        attribute,
        current.revision,
      );
      input.value = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    } else {
      if (!sessionCredential) throw new Error('Passkey情報を読み込めません。');
      const output = await prf(sessionCredential, newPrfInput());
      output.fill(0);
    }
    opened = true;
    controls();
    message('表示名を編集できます。保存時にもう一度Passkeyを使います。');
  } catch (error) {
    message(error instanceof Error ? error.message : 'Passkeyで開けませんでした。');
  }
});

async function mutate(method: 'PUT' | 'DELETE'): Promise<void> {
  if (!opened) return;
  try {
    const revision = currentRevision;
    const value = input.value;
    if (method === 'PUT' && (value.length === 0 || value.length > 256)) {
      throw new Error('表示名を1〜256文字で入力してください。');
    }
    if (method === 'DELETE' && !current) return;
    if (
      pending &&
      (pending.method !== method || pending.revision !== revision || pending.value !== value)
    ) {
      throw new Error('前の保存結果を確認できません。ページを再読み込みしてください。');
    }
    if (!pending) {
      let body: string | undefined;
      if (method === 'PUT') {
        const envelope = current ? parseOwnerEnvelope(current.owner_envelope) : null;
        const credentialId = envelope?.credentialId ?? sessionCredential;
        if (!credentialId) throw new Error('Passkey情報を読み込めません。');
        const prfInput = envelope?.prfInput ?? newPrfInput();
        const output = await prf(credentialId, prfInput);
        const sealed = await sealAttribute(
          new TextEncoder().encode(value),
          output,
          credentialId,
          prfInput,
          origin,
          attribute,
          revision + 1,
        );
        output.fill(0);
        body = JSON.stringify(sealed);
      }
      pending = {
        method,
        revision,
        value,
        id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
        body,
      };
    }
    const operation = pending;
    if (!operation) throw new Error('保存操作を準備できません。');
    const headers: Record<string, string> = {
      'X-Operation-ID': operation.id,
      [revision === 0 ? 'If-None-Match' : 'If-Match']: revision === 0 ? '*' : `"${revision}"`,
    };
    if (method === 'PUT') headers['Content-Type'] = 'application/json';
    const response = await fetch(endpoint, { method, headers, body: operation.body ?? null });
    if (response.status === 409)
      throw new Error('別の更新と競合しました。再読み込みして確認してください。');
    if (!response.ok) throw new Error('保存できませんでした。同じ内容で再試行できます。');
    pending = null;
    await load();
    message(
      method === 'PUT' ? '保存しました。Passkeyで再度開いて確認できます。' : '削除しました。',
    );
  } catch (error) {
    message(error instanceof Error ? error.message : '操作に失敗しました。');
  }
}

save.addEventListener('click', () => {
  void mutate('PUT');
});
remove.addEventListener('click', () => {
  void mutate('DELETE');
});
void load().catch((error: unknown) => {
  message(error instanceof Error ? error.message : '読み込みに失敗しました。');
});
