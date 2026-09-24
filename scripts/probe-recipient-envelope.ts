import { randomBytes, randomUUID } from 'node:crypto';
import { getPlatformProxy } from 'wrangler';
import { sealUserInfoDataKey } from '../crates/worker/ui/vault-recipient-envelope.ts';
import { encodeBase64Url } from '../crates/worker/ui/vault-crypto.ts';
import type { UserInfoRecipient } from '../crates/worker/ui/recipient-directory.ts';

// Read-only production probe: use the active public key and internal service
// binding with synthetic ciphertext. No Vault record or Grant is created.
const CONFIG = 'crates/worker/wrangler.recipient-admin.jsonc';
const ORIGIN = 'https://mikaki.tossa.app';

function contentAad(revision: number): Uint8Array<ArrayBuffer> {
  const fields = ['mikaki-vault-attribute-content', '1', ORIGIN, 'name', String(revision)];
  const encoded = fields.map((field) => new TextEncoder().encode(field));
  const output = new Uint8Array(encoded.reduce((length, field) => length + 2 + field.length, 0));
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const field of encoded) {
    view.setUint16(offset, field.length);
    output.set(field, offset + 2);
    offset += field.length + 2;
  }
  return output;
}

function publicKeyBytes(value: unknown): Uint8Array<ArrayBuffer> {
  if (
    !Array.isArray(value) ||
    value.length !== 1184 ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    throw new Error('unexpected D1 public key');
  }
  return Uint8Array.from(value);
}

async function main(): Promise<void> {
  const platform = await getPlatformProxy({ configPath: CONFIG, remoteBindings: true });
  try {
    const db = platform.env.DB as {
      prepare(query: string): { first<T>(): Promise<T | null> };
    };
    const claims = platform.env.USERINFO_CLAIMS as { fetch: typeof fetch };
    const row = await db
      .prepare(
        "SELECT key_id,public_key,generation,revision FROM vault_recipient_key WHERE service_id='userinfo' AND state='active'",
      )
      .first<{ key_id: string; public_key: unknown; generation: number; revision: number }>();
    if (!row || !claims?.fetch) throw new Error('active recipient unavailable');
    const recipient: UserInfoRecipient = {
      service_id: 'userinfo',
      algorithm: 'ML-KEM-768',
      envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',
      key_id: row.key_id,
      public_key: encodeBase64Url(publicKeyBytes(row.public_key)),
      generation: row.generation,
      revision: row.revision,
    };
    const accountId = `probe-${randomUUID()}`;
    const revision = 1;
    const dataKey = new Uint8Array(randomBytes(32));
    try {
      const nonce = new Uint8Array(randomBytes(12));
      const key = await crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, ['encrypt']);
      const encrypted = new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: nonce, additionalData: contentAad(revision) },
          key,
          new TextEncoder().encode('Synthetic probe name'),
        ),
      );
      const ciphertext = new Uint8Array(1 + nonce.length + encrypted.length);
      ciphertext[0] = 1;
      ciphertext.set(nonce, 1);
      ciphertext.set(encrypted, 1 + nonce.length);
      const frame = await sealUserInfoDataKey(dataKey, recipient, {
        origin: ORIGIN,
        accountId,
        revision,
        ciphertext,
      });
      const endpoint = `https://userinfo.internal/internal/recipient-keys/${recipient.key_id}/validate-envelope`;
      const input = {
        origin: ORIGIN,
        account_id: accountId,
        revision,
        ciphertext: encodeBase64Url(ciphertext),
        frame: encodeBase64Url(frame),
      };
      const call = (body: typeof input) =>
        claims.fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      const positive = await call(input);
      const wrongOwner = await call({ ...input, account_id: `probe-${randomUUID()}` });
      const wrongCiphertext = new Uint8Array(ciphertext);
      wrongCiphertext[wrongCiphertext.length - 1] ^= 1;
      const wrongContent = await call({ ...input, ciphertext: encodeBase64Url(wrongCiphertext) });
      if (positive.status !== 204 || wrongOwner.status !== 503 || wrongContent.status !== 503) {
        throw new Error(
          `recipient validation mismatch: ${positive.status}/${wrongOwner.status}/${wrongContent.status}`,
        );
      }
      console.log(
        JSON.stringify({
          key_id: recipient.key_id,
          generation: recipient.generation,
          positive: positive.status,
          wrong_owner: wrongOwner.status,
          wrong_ciphertext: wrongContent.status,
        }),
      );
    } finally {
      dataKey.fill(0);
    }
  } finally {
    await platform.dispose();
  }
}

await main();
