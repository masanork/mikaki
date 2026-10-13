// Opt-in, synthetic cross-verifier probe against a caller-selected clean civ commit.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
assert.equal(args.length, 4, 'usage: --civ-checkout <clean checkout> --civ-commit <full commit>');
assert.equal(args[0], '--civ-checkout');
assert.equal(args[2], '--civ-commit');
const checkout = resolve(args[1]);
const commit = args[3];
assert.match(commit, /^[a-f0-9]{40}$/);
const git = (...args: string[]) =>
  execFileSync('git', ['-C', checkout, ...args], { encoding: 'utf8' }).trim();
assert.equal(git('rev-parse', 'HEAD'), commit);
assert.equal(
  git('status', '--porcelain', '--untracked-files=all'),
  '',
  'civ checkout must be clean',
);
const directory = await mkdtemp(join(tmpdir(), 'mikaki-civ-interop-'));
try {
  await mkdir(join(directory, 'src'));
  await writeFile(
    join(directory, 'src', 'main.rs'),
    await readFile(new URL('../design/probes/civ-kenmen-interop/main.rs', import.meta.url)),
  );
  const identity = fileURLToPath(new URL('../crates/identity', import.meta.url));
  await writeFile(
    join(directory, 'Cargo.toml'),
    `[package]
name = "mikaki-civ-interop-probe"
version = "0.1.0"
edition = "2024"
[dependencies]
mikaki-identity = { path = ${JSON.stringify(identity)} }
civ-kenmen = { path = ${JSON.stringify(join(checkout, 'crates', 'civ-kenmen'))} }
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.151"
[workspace]
`,
  );
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const now = Math.floor(Date.now() / 1000);
  const trust = [
    {
      id: 'synthetic-interop',
      document_type: 'my_number_card',
      n: jwk.n!,
      e: jwk.e!,
      subject_key_identifier: null,
      not_before: now - 60,
      not_after: now + 600,
    },
  ];
  function fixture(date = '19900228') {
    const fields: [number, string][] = [
      [0x22, 'Synthetic Person'],
      [0x23, 'Synthetic Address'],
      [0x24, date],
      [0x25, '1'],
    ];
    const attributes = Buffer.concat(
      fields.map(([tag, text]) =>
        Buffer.concat([Buffer.from([0xdf, tag, Buffer.byteLength(text)]), Buffer.from(text)]),
      ),
    );
    const msg = Buffer.concat([
      Buffer.from([0xdf, 0x31, 32]),
      Buffer.alloc(32, 11),
      Buffer.from([0xdf, 0x32, 32]),
      createHash('sha256').update(attributes).digest(),
    ]);
    const inner = Buffer.concat([
      msg,
      Buffer.from([0xdf, 0x33, 0x82, 1, 0]),
      sign('sha256', msg, keys.privateKey),
    ]);
    return {
      document_type: 'my_number_card',
      attributes: [...attributes],
      signature: [
        ...Buffer.concat([
          Buffer.from([0xff, 0x30, 0x82, inner.length >> 8, inner.length & 255]),
          inner,
        ]),
      ],
      domicile: [],
      photo: [],
    };
  }
  const cases: {
    name: string;
    evidence: ReturnType<typeof fixture>;
    trust: typeof trust;
    now: number;
  }[] = [];
  const add = (name: string, evidence = fixture(), policy = trust) =>
    cases.push({ name, evidence, trust: policy, now });
  add('valid Gregorian');
  add('valid era', fixture('4020228'));
  let e = fixture();
  e.attributes[3] ^= 1;
  add('attribute tamper', e);
  e = fixture();
  e.signature[e.signature.length - 1] ^= 1;
  add('signature tamper', e);
  e = fixture();
  e.signature[8] ^= 1;
  add('DF31 value tamper', e);
  e = fixture();
  e.attributes.push(...e.attributes);
  add('duplicate attributes', e);
  add('untrusted issuer', fixture(), []);
  add(
    'expired issuer',
    fixture(),
    trust.map((k) => ({ ...k, not_after: now })),
  );
  e = fixture();
  e.signature.pop();
  add('truncated EF0003', e);
  add('signed invalid Gregorian', fixture('19900230'));
  add('signed invalid era boundary', fixture('4010101'));
  add('signed future birthday', fixture('30000101'));
  add(
    'wrong document-type trust',
    fixture(),
    trust.map((k) => ({ ...k, document_type: 'driving_license' })),
  );
  const result: { case: string; civ: string; mikaki: string; age_available: boolean | null }[] =
    JSON.parse(
      execFileSync(
        'cargo',
        ['run', '--quiet', '--offline', '--manifest-path', join(directory, 'Cargo.toml')],
        {
          encoding: 'utf8',
          input: JSON.stringify(cases),
          maxBuffer: 100000,
        },
      ),
    );
  assert.equal(result.length, cases.length);
  for (const r of result) {
    if (r.case.startsWith('valid '))
      assert.equal(r.civ === 'verified' && r.mikaki === 'verified', true, r.case);
    else if (r.case.startsWith('signed invalid'))
      assert.equal(r.civ === 'verified' && r.mikaki === 'InvalidEvidence', true, r.case);
    else if (r.case === 'wrong document-type trust')
      assert.equal(r.civ === 'verified' && r.mikaki === 'UntrustedIssuer', true, r.case);
    else if (r.case === 'signed future birthday')
      assert.equal(
        r.civ === 'verified' && r.mikaki === 'verified' && r.age_available === false,
        true,
        r.case,
      );
    else assert.equal(r.civ !== 'verified' && r.mikaki !== 'verified', true, r.case);
  }
  assert.equal(git('rev-parse', 'HEAD'), commit, 'civ commit changed while probing');
  assert.equal(
    git('status', '--porcelain', '--untracked-files=all'),
    '',
    'civ input changed while probing',
  );
  console.log(
    JSON.stringify(
      { civ_commit: commit, scope: 'synthetic host verification only', cases: result },
      null,
      2,
    ),
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
