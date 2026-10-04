// Disposable reader CA/leaf for the host x509_hash peer; no production trust.
import { execFile } from 'node:child_process';
import { createPrivateKey, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { exportJWK, generateKeyPair, type JWK } from 'jose';

export async function readerPki(signer: JWK) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-reader-pki-'));
  const path = (name: string) => join(directory, name);
  const run = promisify(execFile);
  const key = async (name: string, jwk: JWK) =>
    writeFile(
      path(name),
      createPrivateKey({ key: jwk, format: 'jwk' }).export({
        format: 'pem',
        type: 'pkcs8',
      }),
      { mode: 0o600 },
    );
  try {
    await key('reader.key', signer);
    await key(
      'ca.key',
      await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey),
    );
    await run('openssl', [
      'req',
      '-new',
      '-x509',
      '-sha256',
      '-key',
      path('ca.key'),
      '-days',
      '365',
      '-set_serial',
      `0x${randomBytes(16).toString('hex')}`,
      '-subj',
      '/CN=Disposable presentation reader CA',
      '-addext',
      'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-addext',
      'subjectKeyIdentifier=hash',
      '-out',
      path('ca.pem'),
    ]);
    await run('openssl', [
      'req',
      '-new',
      '-sha256',
      '-key',
      path('reader.key'),
      '-subj',
      '/CN=Disposable presentation reader',
      '-out',
      path('reader.csr'),
    ]);
    await writeFile(
      path('reader.ext'),
      [
        'basicConstraints=critical,CA:FALSE',
        'keyUsage=critical,digitalSignature',
        'extendedKeyUsage=critical,1.0.18013.5.1.6',
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid:always',
      ].join('\n') + '\n',
      { mode: 0o600 },
    );
    await run('openssl', [
      'x509',
      '-req',
      '-sha256',
      '-in',
      path('reader.csr'),
      '-CA',
      path('ca.pem'),
      '-CAkey',
      path('ca.key'),
      '-set_serial',
      `0x${randomBytes(16).toString('hex')}`,
      '-days',
      '30',
      '-extfile',
      path('reader.ext'),
      '-outform',
      'DER',
      '-out',
      path('reader.der'),
    ]);
    await run('openssl', [
      'x509',
      '-in',
      path('ca.pem'),
      '-outform',
      'DER',
      '-out',
      path('ca.der'),
    ]);
    return {
      chain: [(await readFile(path('reader.der'))).toString('base64')],
      trust_anchors: [(await readFile(path('ca.der'))).toString('base64')],
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
