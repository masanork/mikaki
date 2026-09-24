import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

const require = createRequire(import.meta.url);
const rust = require('./pkg/mikaki_pqc_probe.js');

test('product sender envelope opens in independent RustCrypto receiver', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-envelope-'));
  try {
    const outfile = join(directory, 'envelope.mjs');
    await build({
      entryPoints: [
        new URL('../../../crates/worker/ui/vault-recipient-envelope.ts', import.meta.url).pathname,
      ],
      outfile,
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'es2022',
    });
    const { sealUserInfoDataKey } = await import(pathToFileURL(outfile).href);
    const keys = ml_kem768.keygen(new Uint8Array(64).fill(0x71));
    const keyId = createHash('sha256').update(keys.publicKey).digest('base64url');
    const frame = await sealUserInfoDataKey(
      new Uint8Array(32).fill(0x51),
      {
        service_id: 'userinfo',
        algorithm: 'ML-KEM-768',
        envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',
        key_id: keyId,
        public_key: Buffer.from(keys.publicKey).toString('base64url'),
        generation: 1,
        revision: 1,
      },
      {
        origin: 'https://mikaki.example',
        accountId: 'test-account-1',
        revision: 9,
        ciphertext: new TextEncoder().encode('test-vault-ciphertext'),
      },
    );
    assert.equal(frame.length, 1187);
    assert.equal(rust.fixture_vault_envelope_opens(frame), true);
    const changed = frame.slice();
    changed[4] ^= 1;
    assert.equal(rust.fixture_vault_envelope_opens(changed), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
