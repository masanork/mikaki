import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('independent OpenSSL CRL verification confirms clean and revoked whole chains', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mikaki-reader-crl-'));
  const fixture = (name: string) => readFileSync('crates/identity/tests/fixtures/trust/' + name);
  const pemCrl = (name: string) =>
    '-----BEGIN X509 CRL-----\n' +
    fixture(name + '.crl')
      .toString('base64')
      .match(/.{1,64}/g)!
      .join('\n') +
    '\n-----END X509 CRL-----\n';
  try {
    for (const name of ['root', 'intermediate', 'leaf'])
      writeFileSync(
        join(dir, name + '.pem'),
        new X509Certificate(fixture(name + '.der')).toString(),
      );
    for (const [leaf, ca, expected] of [
      ['clean-intermediate', 'clean-root', true],
      ['revoked-leaf', 'clean-root', false],
      ['clean-intermediate', 'revoked-intermediate', false],
    ] as const) {
      writeFileSync(join(dir, 'crls.pem'), pemCrl(leaf) + pemCrl(ca));
      const result = spawnSync(
        'openssl',
        [
          'verify',
          '-purpose',
          'any',
          '-attime',
          '1790899200',
          '-crl_check_all',
          '-CAfile',
          join(dir, 'root.pem'),
          '-untrusted',
          join(dir, 'intermediate.pem'),
          '-CRLfile',
          join(dir, 'crls.pem'),
          join(dir, 'leaf.pem'),
        ],
        { encoding: 'utf8', timeout: 10000 },
      );
      assert.equal(result.error, undefined);
      const output = result.stdout + result.stderr;
      // LibreSSL may return zero while reporting certificate validation errors.
      if (expected) assert.match(output, /: OK/);
      else assert.match(output, /certificate revoked/i);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
