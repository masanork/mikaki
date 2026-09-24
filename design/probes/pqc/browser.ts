import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const wasmModule = fileURLToPath(new URL('./pkg-web/mikaki_pqc_probe.js', import.meta.url));
const wasmBinary = fileURLToPath(new URL('./pkg-web/mikaki_pqc_probe_bg.wasm', import.meta.url));
const fixtureFile = fileURLToPath(new URL('./hpke-envelope-fixture.json', import.meta.url));
const nobleRoot = resolve(fileURLToPath(new URL('../node_modules/@noble/', import.meta.url)));
const server = createServer(async (request, response) => {
  if (request.url === '/') {
    response
      .writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      .end(
        `<script type="importmap">{"imports":{"@noble/post-quantum/":"/node_modules/@noble/post-quantum/","@noble/hashes/":"/node_modules/@noble/hashes/","@noble/curves/":"/node_modules/@noble/curves/"}}</script>`,
      );
    return;
  }
  const files = new Map([
    ['/pkg-web/mikaki_pqc_probe.js', [wasmModule, 'text/javascript']],
    ['/pkg-web/mikaki_pqc_probe_bg.wasm', [wasmBinary, 'application/wasm']],
    ['/hpke-envelope-fixture.json', [fixtureFile, 'application/json']],
  ]);
  let requested = files.get(request.url ?? '');
  if (request.url?.startsWith('/node_modules/@noble/') && request.url.endsWith('.js')) {
    const path = resolve(nobleRoot, request.url.slice('/node_modules/@noble/'.length));
    if (path.startsWith(nobleRoot + sep)) requested = [path, 'text/javascript'];
  }
  if (!requested) {
    response.writeHead(404).end();
    return;
  }
  try {
    response.writeHead(200, { 'Content-Type': requested[1] }).end(await readFile(requested[0]));
  } catch {
    response.writeHead(500).end();
  }
});

await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${(server.address() as import('node:net').AddressInfo).port}/`);
  const passed = await page.evaluate(async () => {
    const probe = await import(/* @vite-ignore */ '/pkg-web/mikaki_pqc_probe.js' as string);
    await probe.default();
    return probe.self_test();
  });
  assert.equal(passed, true);
  const envelopePassed = await page.evaluate(async () => {
    const { ml_kem768 } = await import(
      /* @vite-ignore */ '@noble/post-quantum/ml-kem.js' as string
    );
    const probe = await import(/* @vite-ignore */ '/pkg-web/mikaki_pqc_probe.js' as string);
    await probe.default();
    const fixture = await (await fetch('/hpke-envelope-fixture.json')).json();
    const decode = (value: string) =>
      Uint8Array.from(
        atob(
          value.replaceAll('-', '+').replaceAll('_', '/') +
            '='.repeat((4 - (value.length % 4)) % 4),
        ),
        (character) => character.charCodeAt(0),
      );
    const concat = (...parts: Uint8Array[]) => {
      const result = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
      let offset = 0;
      for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
      }
      return result;
    };
    const equal = (left: Uint8Array, right: Uint8Array) =>
      left.length === right.length && left.every((byte, index) => byte === right[index]);
    const utf8 = (value: string) => new TextEncoder().encode(value);
    const u64 = (value: bigint) => {
      const result = new Uint8Array(8);
      new DataView(result.buffer).setBigUint64(0, value);
      return result;
    };
    const context = (...parts: Uint8Array[]) =>
      concat(
        ...parts.flatMap((part) => {
          if (part.length > 65535) throw Error('context part too large');
          const length = new Uint8Array(2);
          new DataView(length.buffer).setUint16(0, part.length);
          return [length, part];
        }),
      );
    const sha256 = async (value: Uint8Array) =>
      new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(value)));
    const seed = decode(fixture.seed);
    const keys = ml_kem768.keygen(seed);
    const keyId = await sha256(keys.publicKey);
    const suite = Uint8Array.from([0, 0x41, 0, 1, 0, 2]);
    const version = Uint8Array.from([1]);
    const generation = u64(1n);
    const info = context(
      utf8('mikaki-vault-recipient-envelope-v1-draft04'),
      version,
      suite,
      utf8('userinfo'),
      keyId,
      generation,
    );
    const aad = context(
      utf8('https://mikaki.example'),
      utf8('test-account-1'),
      utf8('name'),
      u64(9n),
      utf8('userinfo'),
      utf8('oidc.userinfo.name'),
      await sha256(utf8('test-vault-ciphertext')),
    );
    const hpkeSuite = concat(utf8('HPKE'), suite);
    const hmac = async (key: Uint8Array, message: Uint8Array) => {
      const imported = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(key),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
      );
      return new Uint8Array(await crypto.subtle.sign('HMAC', imported, new Uint8Array(message)));
    };
    const extract = (salt: Uint8Array, ikm: Uint8Array) =>
      hmac(salt.length ? salt : new Uint8Array(32), ikm);
    const expand = async (prk: Uint8Array, label: Uint8Array, size: number) => {
      let previous = new Uint8Array(0);
      const chunks: Uint8Array[] = [];
      for (let counter = 1; chunks.length * 32 < size; counter++) {
        if (counter > 255) throw Error('HKDF length exceeded');
        previous = await hmac(prk, concat(previous, label, Uint8Array.from([counter])));
        chunks.push(previous);
      }
      return concat(...chunks).subarray(0, size);
    };
    const labeledExtract = (salt: Uint8Array, label: string, ikm: Uint8Array) =>
      extract(salt, concat(utf8('HPKE-v1'), hpkeSuite, utf8(label), ikm));
    const labeledExpand = (prk: Uint8Array, label: string, value: Uint8Array, size: number) => {
      const length = new Uint8Array(2);
      new DataView(length.buffer).setUint16(0, size);
      return expand(prk, concat(length, utf8('HPKE-v1'), hpkeSuite, utf8(label), value), size);
    };
    const schedule = async (sharedSecret: Uint8Array) => {
      const empty = new Uint8Array(0);
      const scheduleContext = concat(
        Uint8Array.from([0]),
        await labeledExtract(empty, 'psk_id_hash', empty),
        await labeledExtract(empty, 'info_hash', info),
      );
      const secret = await labeledExtract(sharedSecret, 'secret', empty);
      return {
        key: await labeledExpand(secret, 'key', scheduleContext, 32),
        nonce: await labeledExpand(secret, 'base_nonce', scheduleContext, 12),
      };
    };
    const open = async (sharedSecret: Uint8Array, ciphertext: Uint8Array, additionalData = aad) => {
      const { key, nonce } = await schedule(sharedSecret);
      const imported = await crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [
        'decrypt',
      ]);
      return new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: new Uint8Array(nonce),
            additionalData: new Uint8Array(additionalData),
          },
          imported,
          new Uint8Array(ciphertext),
        ),
      );
    };
    const seal = async (sharedSecret: Uint8Array, plaintext: Uint8Array) => {
      const { key, nonce } = await schedule(sharedSecret);
      const imported = await crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, [
        'encrypt',
      ]);
      return new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: new Uint8Array(nonce), additionalData: new Uint8Array(aad) },
          imported,
          new Uint8Array(plaintext),
        ),
      );
    };
    const frame = (enc: Uint8Array, ciphertext: Uint8Array) =>
      concat(utf8('MKVE'), version, suite, keyId, generation, enc, ciphertext);
    const dataKey = new Uint8Array(32).fill(0x51);
    const checkedIn = decode(fixture.frame);
    const rustFrame = probe.fixture_vault_envelope_frame();
    if (!equal(checkedIn.subarray(0, 51), frame(new Uint8Array(0), new Uint8Array(0)))) {
      throw Error('fixture header mismatch');
    }
    for (const value of [checkedIn, rustFrame]) {
      if (value.length !== 1187) throw Error('fixture length mismatch');
      const shared = ml_kem768.decapsulate(value.subarray(51, 1139), keys.secretKey);
      if (!equal(await open(shared, value.subarray(1139)), dataKey)) {
        throw Error('browser could not open envelope');
      }
      let rejected = false;
      try {
        await open(shared, value.subarray(1139), context(utf8('wrong-purpose')));
      } catch {
        rejected = true;
      }
      if (!rejected) throw Error('changed AAD was accepted');
    }
    const browserKem = ml_kem768.encapsulate(keys.publicKey, new Uint8Array(32).fill(0x42));
    const browserFrame = frame(browserKem.cipherText, await seal(browserKem.sharedSecret, dataKey));
    if (!equal(browserFrame, checkedIn) || !probe.fixture_vault_envelope_opens(browserFrame)) {
      throw Error('browser envelope differs from fixture or fails Rust receiver');
    }
    return true;
  });
  assert.equal(envelopePassed, true);
  console.log('PQC browser Wasm and Vault HPKE noble/Web Crypto fixture passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
