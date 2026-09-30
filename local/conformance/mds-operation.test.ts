import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import init, * as wasm from '../../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
import { MdsStore, download } from '../mds.ts';
import type { Config, Input, Verifier } from '../mds.ts';
await init({
  module_or_path: readFileSync(
    new URL('../../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm', import.meta.url),
  ),
});
const cases: { name: string; ok: boolean; input: Input }[] = JSON.parse(
  readFileSync(
    new URL('../../crates/webauthn/testdata/mds-operations.json', import.meta.url),
    'utf8',
  ),
);
const verifier: Verifier = {
  verify: (i) => JSON.parse(wasm.verify_mds(JSON.stringify(i))),
  crlUrls: (jwt, p) => JSON.parse(wasm.mds_crl_urls_with_profile(jwt, p)),
};
function fixture(name: string) {
  return structuredClone(cases.find((c) => c.name === name)!.input);
}
function config(input: Input): Config {
  return {
    url: 'https://mds.example/blob',
    profile: input.profile,
    anchor_spki: input.anchor_spki,
    allowed_hosts: ['mds.example'],
    max_age_seconds: 86400,
  };
}
test('atomic durable snapshot, concurrent serial checks, restart, equivocation, profile and trust isolation', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mikaki-mds-'));
  const path = join(dir, 'state.sqlite');
  const first = fixture('RS256 number 1');
  const cfg = config(first);
  let a = new MdsStore(path, cfg, verifier);
  let b = new MdsStore(path, cfg, verifier);
  try {
    a.accept(first);
    assert.equal(a.forRegistration(first.now).number, 1);
    b.accept(fixture('RS256 number 3'));
    assert.throws(() => a.accept(fixture('RS256 number 2')), /mds_rollback/);
    assert.equal(a.forRegistration(first.now).number, 3);
    a.close();
    a = new MdsStore(path, cfg, verifier);
    assert.equal(a.forRegistration(first.now).number, 3);
    assert.throws(
      () => new MdsStore(path, { ...cfg, profile: 'mds3.0' }, verifier),
      /mds_channel_changed/,
    );
    assert.throws(
      () => new MdsStore(path, { ...cfg, anchor_spki: 'wrong' }, verifier),
      /mds_channel_changed/,
    );
    const tampered = fixture('RS256 number 3');
    tampered.jwt = tampered.jwt.slice(0, -5) + 'AAAAA';
    assert.throws(() => a.accept(tampered));
    assert.equal(a.forRegistration(first.now).number, 3);
  } finally {
    a.close();
    b.close();
    rmSync(dir, { recursive: true });
  }
  const store = new MdsStore(':memory:', cfg, verifier);
  try {
    store.accept(fixture('RS256 number 2'));
    assert.throws(
      () => store.accept(fixture('RS256 same number different content')),
      /mds_rollback/,
    );
    assert.equal(store.status(first.now).number, 2);
  } finally {
    store.close();
  }
});
test('failing download retains snapshot; same serial cannot extend its lifetime; expired CRL fails closed', async () => {
  const input = fixture('ES256 number 1');
  const cfg = config(input);
  const store = new MdsStore(':memory:', cfg, verifier);
  try {
    store.accept(input);
    await assert.rejects(
      store.refresh(input.now + 1, async () => new Response('', { status: 503 })),
      /mds_http_503/,
    );
    assert.equal(store.status(input.now + 1).number, 1);
    assert.equal(store.status(input.now + 1).failure, 'mds_http_503');
    store.accept({ ...input, now: input.now + 3600 });
    assert.equal(store.status(input.now + 3600).first_seen, input.now);
    assert.throws(() => store.forRegistration(input.now + 86401), /mds_stale/);
    assert.throws(() => store.accept({ ...input, now: input.now - 301 }), /mds_stale/);
    assert.throws(() => store.forRegistration(2000000000));
  } finally {
    store.close();
  }
  const legacy = fixture('RS256 legacy');
  const old = new MdsStore(':memory:', config(legacy), verifier);
  try {
    old.accept(legacy);
    assert.throws(() => old.accept({ ...legacy, now: legacy.now + 86401 }), /mds_stale/);
  } finally {
    old.close();
  }
});
test('real signed feed and CRL refresh; rejected signature preserves whole previous snapshot', async () => {
  const input = fixture('RS256 number 1');
  const store = new MdsStore(':memory:', config(input), verifier);
  let jwt = input.jwt;
  const fake: typeof fetch = async (url) =>
    new Response(String(url).endsWith('root.crl') ? Buffer.from(input.crls[0], 'base64url') : jwt);
  try {
    await store.refresh(input.now, fake);
    assert.equal(store.forRegistration(input.now).number, 1);
    jwt = fixture('RS256 number 2').jwt;
    await store.refresh(input.now + 1, fake);
    assert.equal(store.forRegistration(input.now + 1).number, 2);
    jwt = jwt.slice(0, -5) + 'AAAAA';
    await assert.rejects(store.refresh(input.now + 2, fake));
    assert.equal(store.status(input.now + 2).number, 2);
    assert.equal(store.status(input.now + 2).entries, 1);
    assert.equal(store.status(input.now + 2).usable, true);
  } finally {
    store.close();
  }
});
test('transport rejects redirects, credentials, ports, schemes, oversized bodies before publication', async () => {
  const hosts = ['mds.example'];
  let requests = 0;
  const redirect: typeof fetch = async () => {
    requests++;
    return new Response('', { status: 302, headers: { location: 'https://evil.example/crl' } });
  };
  await assert.rejects(
    download('https://mds.example/blob', hosts, 1024, redirect),
    /mds_destination/,
  );
  assert.equal(requests, 1);
  for (const url of [
    'http://mds.example/blob',
    'https://user:pass@mds.example/blob',
    'https://mds.example:444/blob',
    'https://evil.example/blob',
  ])
    await assert.rejects(download(url, hosts, 1024, redirect), /mds_destination/);
  await assert.rejects(
    download('https://mds.example/blob', hosts, 4, async () => new Response('12345')),
    /mds_size/,
  );
  await assert.rejects(
    download(
      'https://mds.example/blob',
      hosts,
      1024,
      async () => new Response('', { status: 302, headers: { location: '/blob' } }),
    ),
    /mds_redirect_limit/,
  );
});
