// Disposable P-256 credential PKI, separate from wallet attestation trust.
import { createPrivateKey, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { exportJWK, generateKeyPair, type JWK } from 'jose';

export async function credentialPki(
  directory: URL,
  signer: JWK,
  fixtureCa?: JWK,
  options: { criticalLeafBasicConstraints?: boolean } = {},
) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const run = promisify(execFile);
  const path = (name: string) => new URL(name, directory).pathname;
  await writeFile(
    path('signer.key'),
    createPrivateKey({ key: signer, format: 'jwk' }).export({ format: 'pem', type: 'pkcs8' }),
    { mode: 0o600 },
  );
  const certificates: Record<string, { chain: string[]; trust_anchors: string[] }> = {};
  const anchors: Record<string, string> = {};
  for (const [format, prefix] of [
    ['sd_jwt', 'sd'],
    ['mdoc', 'mdoc'],
  ] as const) {
    const ca =
      fixtureCa ??
      (await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey));
    await writeFile(
      path(`${prefix}-ca.key`),
      createPrivateKey({ key: ca, format: 'jwk' }).export({ format: 'pem', type: 'pkcs8' }),
      { mode: 0o600 },
    );
    await run('openssl', [
      'req',
      '-new',
      '-x509',
      '-sha256',
      '-key',
      path(`${prefix}-ca.key`),
      '-days',
      '3650',
      '-set_serial',
      `0x${randomBytes(16).toString('hex')}`,
      '-subj',
      `/C=JP/CN=Disposable ${prefix} credential CA`,
      '-addext',
      'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-addext',
      'subjectKeyIdentifier=hash',
      '-addext',
      'issuerAltName=URI:https://disposable-credential.example/contact',
      '-out',
      path(`${prefix}-ca.pem`),
    ]);
    await run('openssl', [
      'req',
      '-new',
      '-sha256',
      '-key',
      path('signer.key'),
      '-subj',
      `/C=JP/CN=Disposable ${prefix} credential signer`,
      '-out',
      path(`${prefix}.csr`),
    ]);
    await writeFile(
      path(`${prefix}.ext`),
      [
        options.criticalLeafBasicConstraints
          ? 'basicConstraints=critical,CA:FALSE'
          : 'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature',
        'subjectKeyIdentifier=hash',
        'authorityKeyIdentifier=keyid:always',
        'issuerAltName=URI:https://disposable-credential.example/contact',
        ...(format === 'mdoc'
          ? [
              'extendedKeyUsage=critical,1.0.18013.5.1.2',
              'crlDistributionPoints=URI:https://disposable-credential.example/iaca.crl',
            ]
          : []),
      ].join('\n') + '\n',
      { mode: 0o600 },
    );
    await run('openssl', [
      'x509',
      '-req',
      '-sha256',
      '-in',
      path(`${prefix}.csr`),
      '-CA',
      path(`${prefix}-ca.pem`),
      '-CAkey',
      path(`${prefix}-ca.key`),
      '-set_serial',
      `0x${randomBytes(16).toString('hex')}`,
      '-days',
      '365',
      '-extfile',
      path(`${prefix}.ext`),
      '-outform',
      'DER',
      '-out',
      path(`${prefix}-signer.der`),
    ]);
    await run('openssl', [
      'x509',
      '-in',
      path(`${prefix}-ca.pem`),
      '-outform',
      'DER',
      '-out',
      path(`${prefix}-ca.der`),
    ]);
    anchors[format] = await readFile(path(`${prefix}-ca.pem`), 'utf8');
    certificates[format] = {
      chain: [(await readFile(path(`${prefix}-signer.der`))).toString('base64')],
      trust_anchors: [(await readFile(path(`${prefix}-ca.der`))).toString('base64')],
    };
  }
  return { certificates, anchors };
}
