// Opt-in independent verifier for the native Rust mixed-inventory confirmation test.
// Synthetic fixture input over stdin only; no network, credential files or private holder keys.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { compactDecrypt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { verifyNativeWithMultipaz } from './multipaz-presentation.ts';
import {
  decodeCbor,
  embedded,
  encodeCbor,
  field,
  verifyMdocIssuer,
  type Cbor,
} from './mdoc-test.ts';
const timeout = setTimeout(
  () => process.exit(1),
  process.env.MIKAKI_MULTIPAZ_PRESENTATION_CHECKOUT ? 15 * 60 * 1000 : 15000,
);
let bytes = '';
for await (const chunk of process.stdin) {
  bytes += String(chunk);
  assert.ok(Buffer.byteLength(bytes) <= 96 * 1024);
}
const input = JSON.parse(bytes);
const at = new Date(input.at * 1000);
const namespace = 'app.tossa.mikaki.linked_document.1';
const key = await importJWK(input.recipient, 'ECDH-ES');
const { plaintext, protectedHeader } = await compactDecrypt(input.response, key, {
  keyManagementAlgorithms: ['ECDH-ES'],
  contentEncryptionAlgorithms: ['A256GCM'],
});
assert.equal(protectedHeader.kid, 'recipient');
assert.equal(protectedHeader.apu, undefined);
assert.ok(typeof protectedHeader.apv === 'string');
assert.equal(Buffer.from(protectedHeader.apv, 'base64url').toString(), input.nonce);
const response = JSON.parse(Buffer.from(plaintext).toString());
assert.deepEqual(Object.keys(response).sort(), ['state', 'vp_token']);
assert.equal(response.state, 'S'.repeat(43));
assert.deepEqual(Object.keys(response.vp_token).sort(), ['birth', 'name']);
assert.equal(response.vp_token.name.length, 1);
assert.equal(response.vp_token.birth.length, 1);
async function checkCertificate(leaf: X509Certificate, purpose: 'sd' | 'mdoc') {
  const root = new X509Certificate(
    await readFile(
      new URL(
        `../../../crates/identity/tests/fixtures/credential/${purpose}-ca.der`,
        import.meta.url,
      ),
    ),
  );
  assert.equal(leaf.verify(root.publicKey), true);
  assert.equal(root.ca, true);
  assert.equal(leaf.ca, false);
  for (const cert of [leaf, root]) {
    assert.ok(Date.parse(cert.validFrom) <= at.getTime());
    assert.ok(at.getTime() < Date.parse(cert.validTo));
  }
  assert.deepEqual(
    leaf.publicKey.export({ format: 'der', type: 'spki' }),
    createPublicKey({ key: input.issuer_key, format: 'jwk' }).export({
      format: 'der',
      type: 'spki',
    }),
  );
}
const sd = String(response.vp_token.name[0]);
const parts = sd.split('~');
assert.equal(parts.length, 3);
const issuerHeader = decodeProtectedHeader(parts[0]);
assert.equal(issuerHeader.typ, 'dc+sd-jwt');
assert.equal(issuerHeader.alg, 'ES256');
assert.equal(issuerHeader.kid, 'issuer');
assert.equal(issuerHeader.x5c!.length, 1);
await checkCertificate(new X509Certificate(Buffer.from(issuerHeader.x5c![0], 'base64')), 'sd');
const issuerKey = await importJWK(input.issuer_key, 'ES256');
const { payload: claims } = await jwtVerify(parts[0], issuerKey, {
  issuer: input.issuer,
  currentDate: at,
  algorithms: ['ES256'],
});
assert.equal(claims.vct, `${input.issuer}/types/linked-document`);
assert.deepEqual((claims.cnf as any).jwk, input.holder_sd);
assert.equal(claims._sd_alg, 'sha-256');
const disclosure = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
assert.equal(disclosure.length, 3);
assert.equal(disclosure[1], 'name');
assert.equal(disclosure[2], 'Fixture');
assert.ok(
  (claims._sd as string[]).includes(createHash('sha256').update(parts[1]).digest('base64url')),
);
const holderSd = await importJWK(input.holder_sd, 'ES256');
const { payload: kb, protectedHeader: kbHeader } = await jwtVerify(parts[2], holderSd, {
  audience: 'fixture',
  currentDate: at,
  algorithms: ['ES256'],
});
assert.equal(kbHeader.typ, 'kb+jwt');
assert.equal(kb.nonce, input.nonce);
assert.equal(
  kb.sd_hash,
  createHash('sha256').update(`${parts[0]}~${parts[1]}~`).digest('base64url'),
);
await assert.rejects(
  jwtVerify(parts[2], await importJWK(input.holder_mdoc, 'ES256'), { currentDate: at }),
);
const decoded = decodeCbor(Buffer.from(response.vp_token.birth[0], 'base64url'));
assert.equal(field(decoded, 'version'), '1.0');
assert.equal(field(decoded, 'status'), 0);
const docs = field(decoded, 'documents') as Cbor[];
assert.equal(docs.length, 1);
const doc = docs[0];
assert.equal(field(doc, 'docType'), namespace);
const partial = verifyMdocIssuer(
  encodeCbor(field(doc, 'issuerSigned')).toString('base64url'),
  input.holder_mdoc,
  input.issuer_key,
);
assert.deepEqual(partial.values, { birthdate: '1990-02-28' });
const issuerAuth = field(partial.signed, 'issuerAuth') as Cbor[];
await checkCertificate(new X509Certificate(field(issuerAuth[1], 33) as Buffer), 'mdoc');
const validity = field(partial.mso, 'validityInfo') as Map<string, { tag: number; value: string }>;
assert.ok(Date.parse(validity.get('validFrom')!.value) <= at.getTime());
assert.ok(at.getTime() < Date.parse(validity.get('validUntil')!.value));
const device = field(doc, 'deviceSigned');
const ns = field(device, 'nameSpaces');
assert.deepEqual(embedded(ns), new Map());
const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
assert.equal(signature[2], null);
assert.deepEqual(decodeCbor(signature[0] as Buffer), new Map([[1, -7]]));
const { crv, kty, x, y } = input.recipient;
const thumbprint = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest();
const signatureValid = (holder: object, nonce: string) => {
  const hash = createHash('sha256')
    .update(encodeCbor(['fixture', nonce, thumbprint, 'https://verifier.example/response']))
    .digest();
  const payload = encodeCbor({
    tag: 24,
    value: encodeCbor([
      'DeviceAuthentication',
      [null, null, ['OpenID4VPHandover', hash]],
      namespace,
      ns,
    ]),
  });
  return verify(
    'sha256',
    encodeCbor(['Signature1', signature[0], Buffer.alloc(0), payload]),
    { key: createPublicKey({ key: holder, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    signature[3] as Buffer,
  );
};
assert.equal(signatureValid(input.holder_mdoc, input.nonce), true);
assert.equal(signatureValid(input.holder_sd, input.nonce), false);
assert.equal(signatureValid(input.holder_mdoc, 'wrong-nonce'), false);
await verifyNativeWithMultipaz({
  sd,
  mdoc: response.vp_token.birth[0],
  nonce: input.nonce,
  at: input.at,
  issuer: input.issuer,
  issuer_key: input.issuer_key,
  holder_sd: input.holder_sd,
  holder_mdoc: input.holder_mdoc,
  recipient_thumbprint: thumbprint.toString('base64url'),
});
clearTimeout(timeout);
process.stdout.write('native inventory peer passed\n');
