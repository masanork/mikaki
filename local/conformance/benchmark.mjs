// Offline, sequential measurements. No HTTP, DB bypass, or cached verification results.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { fileURLToPath } from 'node:url';
import init, * as wasm from '../../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
const root = new URL('../../', import.meta.url);
const path = (p) => fileURLToPath(new URL(p, root));
await init({ module_or_path: readFileSync(path('crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm')) });
const cases = JSON.parse(execFileSync(path('target/release/examples/benchmark'), ['--export']));
const measure = (name, operation, iterations = 100) => {
  for (let i = 0; i < 5; i++) operation();
  const samples = [];
  for (let sample = 0; sample < 7; sample++) {
    const start = performance.now();
    for (let i = 0; i < iterations; i++) operation();
    samples.push(((performance.now() - start) * 1000) / iterations);
  }
  samples.sort((a, b) => a - b);
  return {
    name,
    iterations_per_sample: iterations,
    samples: 7,
    median_us: samples[3],
    min_us: samples[0],
    max_us: samples[6],
  };
};
const report = {
  recorded_at: new Date().toISOString(),
  node: process.version,
  cpu: cpus()[0].model,
  rust: execFileSync('rustc', ['--version'], { encoding: 'utf8' }).trim(),
  native: [],
  wasm_json_boundary: [],
  native_process_json_boundary: [],
  metadata_lookup: [],
};
// No builds or concurrent benchmarks while timing these operations.
for (const profile of ['debug', 'release']) {
  report.native.push({
    profile,
    ...JSON.parse(
      execFileSync(path(`target/${profile}/examples/benchmark`), [
        profile === 'debug' ? '20' : '100',
      ]),
    ),
  });
}
for (const c of cases) {
  const now = c.context.attestation?.now ?? 1790035200;
  const input = {
    ceremony: {
      purpose: c.credential ? 'authenticate' : 'register',
      browser_hash: 'benchmark',
      expires_at: now + 120,
      failures: 0,
      consumed: false,
      context: c.context,
    },
    browser_hash: 'benchmark',
    now,
    max_failures: 5,
    response: c.response,
  };
  const encoded = JSON.stringify(input);
  const stored = JSON.stringify(c.credential);
  report.wasm_json_boundary.push(
    measure(c.name, () => {
      let accepted;
      try {
        const proof = c.credential ? wasm.authenticate(encoded, stored) : wasm.register(encoded);
        accepted = JSON.parse(proof).id === c.response.id || JSON.parse(proof).counter === 1;
      } catch {
        accepted = false;
      }
      assert.equal(accepted, c.ok);
    }),
  );
  for (const profile of ['debug', 'release']) {
    const request = JSON.stringify({ ...input, credential: c.credential });
    report.native_process_json_boundary.push({
      profile,
      ...measure(
        c.name,
        () => {
          const proof = JSON.parse(
            execFileSync(path(`target/${profile}/examples/conformance`), {
              input: request,
              encoding: 'utf8',
              timeout: 10000,
            }),
          );
          assert.equal(proof !== null, c.ok);
        },
        5,
      ),
    });
  }
}
const entries = readdirSync(path('target/fido-metadata'))
  .filter((n) => n.endsWith('.json'))
  .map((n) => {
    const m = JSON.parse(readFileSync(path(`target/fido-metadata/${n}`)));
    return {
      aaguid: m.aaguid
        ? Buffer.from(m.aaguid.replaceAll('-', ''), 'hex').toString('base64url')
        : '',
      key_ids: m.attestationCertificateKeyIdentifiers ?? [],
    };
  });
for (const file of readdirSync(path('target/fido-mds')).filter((n) => n.endsWith('.json'))) {
  const input = JSON.parse(readFileSync(path(`target/fido-mds/${file}`)));
  input.now = Math.floor(Date.now() / 1000);
  try {
    entries.push(...JSON.parse(wasm.verify_mds(JSON.stringify(input))).entries);
  } catch {
    /* Invalid test BLOB is excluded. */
  }
}
report.metadata_entries = entries.length;
for (const c of cases.filter((c) => !c.credential)) {
  const attestation = c.response.attestation;
  const repeated = () =>
    entries.filter((e) => {
      const hint = wasm.attestation_hint(attestation);
      return e.aaguid === hint || e.key_ids.includes(hint);
    });
  const once = () => {
    const hint = wasm.attestation_hint(attestation);
    return entries.filter((e) => e.aaguid === hint || e.key_ids.includes(hint));
  };
  assert.deepEqual(repeated(), once());
  report.metadata_lookup.push({
    case: c.name,
    before: measure('decode per metadata entry', repeated, 20),
    after: measure('decode once per response', once, 100),
  });
}
mkdirSync(path('artifacts'), { recursive: true });
writeFileSync(path('artifacts/webauthn-performance.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
