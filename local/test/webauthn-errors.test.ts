import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initSync, register } from '../../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
import { webauthnDiagnostic } from '../webauthn-errors.ts';

initSync({
  module: await readFile(
    new URL('../../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm', import.meta.url),
  ),
});

test('Node-generated registration fixtures verify through the Wasm boundary', async () => {
  const fixtures = JSON.parse(
    await readFile(
      new URL('../../crates/webauthn/testdata/interop-node.json', import.meta.url),
      'utf8',
    ),
  ) as {
    registrations: {
      name: string;
      ok: boolean;
      kind?: string;
      context: Record<string, unknown>;
      response: Record<string, unknown>;
    }[];
  };
  for (const fixture of fixtures.registrations) {
    const input = {
      ceremony: {
        purpose: 'register',
        browser_hash: 'browser',
        expires_at: 100,
        failures: 0,
        consumed: false,
        context: fixture.context,
      },
      browser_hash: 'browser',
      now: 1,
      max_failures: 5,
      response: fixture.response,
    };
    if (fixture.ok) {
      assert.equal(JSON.parse(register(JSON.stringify(input))).attestation.kind, fixture.kind);
    } else {
      assert.throws(
        () => register(JSON.stringify(input)),
        () => true,
        fixture.name,
      );
    }
  }
});

test('Wasm rejection carries only a reason code and stage across the JS boundary', async () => {
  const fixtures = JSON.parse(
    await readFile(
      new URL('../../crates/webauthn/testdata/attestations.json', import.meta.url),
      'utf8',
    ),
  );
  const fixture = fixtures.registrations.find(
    (v: { name: string }) => v.name === 'expired certificate',
  );
  const input = {
    ceremony: {
      purpose: 'register',
      browser_hash: 'private-browser',
      expires_at: 100,
      failures: 0,
      consumed: false,
      context: fixture.context,
    },
    browser_hash: 'private-browser',
    now: 1,
    max_failures: 5,
    response: fixture.response,
  };
  const rejects = (value: string, code: string, stage: string) =>
    assert.throws(
      () => register(value),
      (error) => {
        assert.deepEqual(JSON.parse(String(error)), { code, stage });
        assert.deepEqual(webauthnDiagnostic(error), { code, stage });
        return true;
      },
    );
  rejects(JSON.stringify(input), 'certificate_time', 'certificate');
  input.ceremony.purpose = 'authenticate';
  rejects(JSON.stringify(input), 'ceremony_purpose', 'ceremony');
  input.ceremony.purpose = 'register';
  input.ceremony.context.algorithms = [];
  rejects(JSON.stringify(input), 'configuration', 'configuration');
  rejects('invalid private request', 'input', 'input');
});

test('diagnostic logging drops arbitrary text, unknown codes and mismatched stages', () => {
  const fallback = { code: 'credential', stage: 'credential' };
  for (const error of [
    new Error('private credential'),
    null,
    '{}',
    'null',
    'secret',
    'x'.repeat(129),
    JSON.stringify({ code: 'private credential', stage: 'credential' }),
    JSON.stringify({ code: 'challenge', stage: 'secret' }),
  ])
    assert.deepEqual(webauthnDiagnostic(error), fallback);
  assert.deepEqual(
    webauthnDiagnostic(
      JSON.stringify({ code: 'challenge', stage: 'client_data', response: 'secret' }),
    ),
    { code: 'challenge', stage: 'client_data' },
  );
});

test('Wasm registration exposes trusted attestation evidence only after verification', async () => {
  const fixtures = JSON.parse(
    await readFile(
      new URL('../../crates/webauthn/testdata/attestations.json', import.meta.url),
      'utf8',
    ),
  );
  const fixture = fixtures.registrations.find((v: { name: string }) => v.name === 'packed chain');
  const input = {
    ceremony: {
      purpose: 'register',
      browser_hash: 'browser',
      expires_at: 100,
      failures: 0,
      consumed: false,
      context: fixture.context,
    },
    browser_hash: 'browser',
    now: 1,
    max_failures: 5,
    response: fixture.response,
  };
  const optional = JSON.parse(register(JSON.stringify(input)));
  input.ceremony.context.attestation_policy = 'required_trusted';
  const required = JSON.parse(register(JSON.stringify(input)));
  assert.deepEqual(required, optional);
  assert.equal(required.attestation.format, 'packed');
  assert.equal(required.attestation.kind, 'trusted');
  assert.equal(
    required.attestation.trust.metadata_key,
    fixture.context.attestation.entries[0].aaguid,
  );
  assert.equal(required.attestation.trust.verified_at, fixture.context.attestation.now);
  assert.match(required.attestation.trust.anchor_sha256, /^[A-Za-z0-9_-]{43}$/);
  input.ceremony.context.attestation = null;
  assert.throws(
    () => register(JSON.stringify(input)),
    (error) => {
      assert.deepEqual(JSON.parse(String(error)), { code: 'trust', stage: 'attestation' });
      return true;
    },
  );
  input.ceremony.context.attestation_policy = 'unknown';
  assert.throws(
    () => register(JSON.stringify(input)),
    (error) => {
      assert.deepEqual(JSON.parse(String(error)), { code: 'input', stage: 'input' });
      return true;
    },
  );
});
