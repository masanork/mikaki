/** Prepare dedicated LabPKI CA/CSR material; never deploy or enable an Identity profile. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  X509Certificate,
  type JsonWebKeyInput,
  type KeyObject,
} from 'node:crypto';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const publicJwk = (key: KeyObject) => {
  const { kty, crv, x, y } = createPublicKey(key).export({ format: 'jwk' });
  assert.equal(kty, 'EC');
  assert.equal(crv, 'P-256');
  return { kty, crv, x, y };
};
const freshKey = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
const secretJwk = (key: KeyObject, purpose: string) => ({
  ...key.export({ format: 'jwk' }),
  kid: `mikaki-haip-lab-${purpose}-${randomUUID()}`,
});
const certificate = (path: string) =>
  new X509Certificate(readFileSync(path)).raw.toString('base64');

export function prepareIdentityLabPki(
  labpkiBinary: string,
  issuerKeyFile: string,
  output: string,
  caOutput: string,
  baseUrl = 'http://localhost:8080',
) {
  assert.equal(statSync(issuerKeyFile).mode & 0o077, 0, 'Issuer key must remain private');
  const issuerJwk = JSON.parse(readFileSync(issuerKeyFile, 'utf8')) as JsonWebKeyInput['key'] & {
    kid: string;
    [key: string]: unknown;
  };
  const issuer = createPrivateKey({ key: issuerJwk, format: 'jwk' });
  const issuerPublic = publicJwk(issuer);
  assert.ok(typeof issuerJwk.kid === 'string' && issuerJwk.kid.length > 0);
  for (const [field, value] of Object.entries(issuerPublic)) assert.equal(issuerJwk[field], value);
  const appDir = resolve(output);
  const caDir = resolve(caOutput);
  assert.ok(
    appDir !== caDir && !appDir.startsWith(`${caDir}/`) && !caDir.startsWith(`${appDir}/`),
    'Application and CA custody must use separate directories',
  );
  mkdirSync(dirname(appDir), { recursive: true, mode: 0o700 });
  mkdirSync(appDir, { mode: 0o700 }); // Never replace an existing preparation or key.
  const save = (name: string, data: unknown) => {
    const path = join(appDir, name);
    writeFileSync(path, `${JSON.stringify(data)}\n`, { mode: 0o600, flag: 'wx' });
    return path;
  };
  const runCa = (...args: string[]) =>
    execFileSync(resolve(labpkiBinary), args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  runCa('haip-init', '-out', caDir, '-base-url', baseUrl);
  const csr = (name: string, key: KeyObject) => {
    const path = join(appDir, `${name}.csr`);
    // OpenSSL receives the key through stdin, never argv or a temporary key file.
    execFileSync(
      'openssl',
      [
        'req',
        '-new',
        '-sha256',
        '-key',
        '/dev/stdin',
        '-subj',
        `/C=JP/CN=Mikaki HAIP Lab ${name}`,
        '-out',
        path,
      ],
      { input: key.export({ format: 'pem', type: 'pkcs8' }), stdio: ['pipe', 'ignore', 'pipe'] },
    );
    return path;
  };
  const issue = (profile: string, request: string, name: string) => {
    const result = JSON.parse(
      runCa('haip-issue', '-out', caDir, '-profile', profile, '-csr', request, '-cn', name),
    ) as { certificate: string; trust_anchor: string; crl: string; serial: string };
    return {
      result,
      chain: [certificate(result.certificate)],
      trust_anchors: [certificate(result.trust_anchor)],
    };
  };
  const attester = freshKey();
  const encryption = freshKey();
  const issuerCsr = csr('issuer', issuer);
  const sd = issue('sd-jwt', issuerCsr, 'Mikaki Lab SD-JWT signer');
  const mdoc = issue('mdoc', issuerCsr, 'Mikaki Lab mdoc Document Signer');
  const at = issue('attester', csr('attester', attester), 'Mikaki Lab Wallet and Key Attester');
  const revoked = issue('sd-jwt', issuerCsr, 'Mikaki Lab revoked validation probe');
  runCa('revoke', '-out', caDir, '-serial', revoked.result.serial, '-reason', '1');
  const trust = (issued: typeof sd) => ({
    chain: issued.chain,
    trust_anchors: issued.trust_anchors,
    revocation: {
      crls: [readFileSync(issued.result.crl).toString('base64')],
      max_age_seconds: 604800,
    },
  });
  const clientId = 'mikaki-android-wallet';
  const attesterTrust = {
    issuer: 'https://auth.mikaki.org/identity/attester',
    trust_anchors: at.trust_anchors,
  };
  const keyTrust = {
    trust_anchors: at.trust_anchors,
    key_storage: null,
    user_authentication: null,
  };
  const sdTrust = trust(sd);
  const mdocTrust = trust(mdoc);
  const walletConfiguration = {
    client_id: clientId,
    client_trust: [attesterTrust],
    key_trust: keyTrust,
    credential_trust: {
      sd_jwt: { trust_anchors: sdTrust.trust_anchors, revocation: sdTrust.revocation },
      mdoc: { trust_anchors: mdocTrust.trust_anchors, revocation: mdocTrust.revocation },
    },
  };
  save('attester-signing.secret.json', {
    jwk: JSON.stringify(secretJwk(attester, 'attester')),
    chain: at.chain,
    trust_anchors: at.trust_anchors,
  });
  save('credential-encryption.secret.jwk.json', {
    ...secretJwk(encryption, 'encryption'),
    alg: 'ECDH-ES',
    use: 'enc',
  });
  const credentialCertificates = { sd_jwt: sdTrust, mdoc: mdocTrust };
  save('issuer-public-settings.json', {
    IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(credentialCertificates),
    IDENTITY_WALLET_ATTESTERS: JSON.stringify([attesterTrust]),
    IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify(keyTrust),
    IDENTITY_WALLET_CLIENTS: JSON.stringify([
      {
        client_id: clientId,
        name: 'Mikaki Android Lab Wallet',
        redirect_uri: 'https://app.mikaki.org/identity/issuance/callback',
        attesters: [attesterTrust.issuer],
      },
    ]),
    MIKAKI_DPOP_NONCE_MODE: 'required',
  });
  save('MIKAKI_HAIP_WALLET.json', walletConfiguration);
  const bundle = save('public-pki-bundle.json', {
    format: 'mikaki-haip-labpki-v1',
    issuer_jwk: issuerPublic,
    attester_jwk: publicJwk(attester),
    credential_certificates: credentialCertificates,
    attester: { chain: at.chain, trust_anchors: at.trust_anchors },
    wallet_configuration: walletConfiguration,
    revoked_sd_jwt: trust(revoked),
  });
  return {
    format: 'mikaki-haip-labpki-preparation-v1',
    public_bundle: bundle,
    ca_directory: caDir,
    bundle_sha256: createHash('sha256').update(readFileSync(bundle)).digest('hex'),
    development_trust: true,
    runtime_activation: 'not_performed',
    android_verifier_policy_and_service: 'not_provisioned',
    attester_certificate_revocation: 'not_checked_by_current_attester_validator',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [binary, issuerKey, output, caOutput, baseUrl, ...extra] = process.argv.slice(2);
    assert.ok(
      binary && issuerKey && output && caOutput && extra.length === 0,
      'Usage: node scripts/prepare-identity-labpki.ts LABPKI_BINARY ISSUER_JWK OUTPUT_DIR CA_DIR [BASE_URL]',
    );
    console.log(
      JSON.stringify(prepareIdentityLabPki(binary, issuerKey, output, caOutput, baseUrl)),
    );
  } catch {
    console.error(
      'LabPKI preparation failed; no key or certificate contents were logged. Use new directories when retrying.',
    );
    process.exitCode = 1;
  }
}
