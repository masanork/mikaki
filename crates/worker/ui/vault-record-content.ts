// Independent recipient-side v2 content reader. It accepts no owner envelope or parent key.
import { decodeBase64Url } from './vault-crypto.ts';
import {
  parseVaultRecordSource,
  vaultCiphertextDigest,
  type VaultRecordSource,
} from './vault-record-source.ts';

type Bytes = Uint8Array<ArrayBuffer>;
export async function openOwnerRecordContentKey(
  ciphertext: string,
  raw: Bytes,
  selected: VaultRecordSource,
): Promise<Bytes> {
  const source = parseVaultRecordSource(selected),
    keyBytes = raw.slice();
  try {
    if (
      keyBytes.length !== 32 ||
      (await vaultCiphertextDigest(ciphertext)) !== source.ciphertext_sha256
    )
      throw new Error('Invalid candidate content key or digest');
    const body = decodeBase64Url(ciphertext);
    if (body.length < 29 || body.length > 24576 || body[0] !== 2)
      throw new Error('Wrong record version or size');
    const parts = [
      'mikaki-vault-record-content',
      '2',
      source.origin,
      source.owner_id,
      source.vault_id,
      source.collection_id,
      source.record_id,
      source.kind,
      String(source.revision),
    ].map((part) => new TextEncoder().encode(part));
    const aad = new Uint8Array(parts.reduce((length, part) => length + 2 + part.length, 0));
    let offset = 0;
    for (const part of parts) {
      if (part.length > 65535) throw new Error('Invalid record context');
      new DataView(aad.buffer).setUint16(offset, part.length);
      offset += 2;
      aad.set(part, offset);
      offset += part.length;
    }
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: body.slice(1, 13), additionalData: aad },
        key,
        body.slice(13),
      ),
    );
  } finally {
    keyBytes.fill(0);
  }
}
