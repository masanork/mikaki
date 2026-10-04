// Independent OpenSSL extension reader for synthetic interoperability fixtures.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import type { X509Certificate } from 'node:crypto';
export function certificateKeyIdentifier(
  certificate: X509Certificate,
  type: 'Subject' | 'Authority',
) {
  const text = execFileSync('openssl', ['x509', '-inform', 'DER', '-text', '-noout'], {
    input: certificate.raw,
    encoding: 'utf8',
    maxBuffer: 100_000,
  });
  const value = text.match(
    new RegExp(
      `X509v3 ${type} Key Identifier:\\s*\\n\\s*(?:keyid:)?([0-9A-F]+(?::[0-9A-F]+)*)`,
      'i',
    ),
  )?.[1];
  assert.ok(value, `${type} key identifier must exist in fixture`);
  return Buffer.from(value.replaceAll(':', ''), 'hex').toString('base64url');
}
