import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { initSync, verify_mds } from '../../crates/browser-wasm/pkg/sakimori_browser_wasm.js';

initSync({
  module: await readFile(
    new URL('../../crates/browser-wasm/pkg/sakimori_browser_wasm_bg.wasm', import.meta.url),
  ),
});

const fixtures = JSON.parse(
  await readFile(
    new URL('../../crates/webauthn/testdata/attestations.json', import.meta.url),
    'utf8',
  ),
);

test('verified MDS snapshot metadata survives the Wasm JSON boundary', () => {
  for (const name of ['valid MDS', 'valid U2F metadata', 'missing nextUpdate is accepted']) {
    const fixture = fixtures.mds.find((item) => item.name === name);
    const verified = JSON.parse(verify_mds(JSON.stringify(fixture.input)));
    assert.equal(verified.number, 1);
    assert.equal(verified.issued_at, fixture.input.now);
    assert.equal(verified.entries.length, 1);
    assert.equal(verified.next_update == null, name === 'missing nextUpdate is accepted');
    if (name === 'valid MDS') {
      assert.equal(verified.entries[0].status_reports[0].status, 'FIDO_CERTIFIED');
      assert.equal(verified.entries[0].status_reports[0].authenticatorVersion, 1);
    }
    if (name === 'valid U2F metadata') {
      assert.equal(verified.entries[0].aaguid, '');
      assert.equal(verified.entries[0].key_ids.length, 1);
    }
  }
});
