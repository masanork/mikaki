// Independent host verifier for presentations produced by the unchanged Multipaz SDK.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { importJWK, jwtVerify, type JWK } from 'jose';
import {
  decodeCbor,
  embedded,
  encodeCbor,
  field,
  verifyMdocIssuer,
  type Cbor,
} from './mdoc-test.ts';

export type MultipazChallenge = {
  nonce: string;
  audience: string;
  response_uri: string;
  recipient_thumbprint: string;
};
export async function verifyMultipazIssuedPresentation(
  configuration: string,
  token: string,
  issuer: string,
  issuerKey: JWK,
  holder: JWK,
  challenge: MultipazChallenge,
  expected: Record<string, unknown>,
) {
  assert.ok(Buffer.byteLength(token) <= 64 * 1024);
  const now = Math.floor(Date.now() / 1000);
  const namespace = 'app.tossa.mikaki.linked_document.1';
  let values: Record<string, unknown>;
  if (configuration === 'linked_document') {
    const parts = token.split('~');
    assert.equal(parts.length, 4, 'exactly two disclosed attributes and one key binding');
    const { payload } = await jwtVerify(parts[0], await importJWK(issuerKey, 'ES256'), {
      algorithms: ['ES256'],
      typ: 'dc+sd-jwt',
      issuer,
    });
    assert.deepEqual((payload.cnf as { jwk: JWK }).jwk, holder);
    assert.equal(payload.vct, `${issuer}/types/linked-document`);
    assert.equal(payload._sd_alg, 'sha-256');
    assert.ok(Number.isInteger(payload.exp) && payload.exp! > now);
    values = {};
    for (const disclosure of parts.slice(1, -1)) {
      assert.ok(
        (payload._sd as string[]).includes(
          createHash('sha256').update(disclosure).digest('base64url'),
        ),
      );
      const item = JSON.parse(Buffer.from(disclosure, 'base64url').toString());
      assert.equal(item.length, 3);
      const [, name, value] = item;
      assert.ok(['name', 'birthdate'].includes(name));
      assert.equal(Object.hasOwn(values, name), false);
      values[name] = value;
    }
    const kb = parts.at(-1)!;
    const { payload: binding } = await jwtVerify(kb, await importJWK(holder, 'ES256'), {
      algorithms: ['ES256'],
      typ: 'kb+jwt',
      audience: challenge.audience,
    });
    assert.equal(binding.nonce, challenge.nonce);
    assert.ok(
      Number.isInteger(binding.iat) && now - 60 <= binding.iat! && binding.iat! <= now + 30,
    );
    assert.equal(
      binding.sd_hash,
      createHash('sha256').update(token.slice(0, -kb.length)).digest('base64url'),
    );
  } else {
    assert.equal(configuration, 'linked_document_mdoc');
    const response = decodeCbor(Buffer.from(token, 'base64url'));
    assert.equal(field(response, 'version'), '1.0');
    assert.equal(field(response, 'status'), 0);
    const docs = field(response, 'documents') as Cbor[];
    assert.equal(docs.length, 1);
    const doc = docs[0];
    assert.equal(field(doc, 'docType'), namespace);
    const partial = verifyMdocIssuer(
      encodeCbor(field(doc, 'issuerSigned')).toString('base64url'),
      holder,
      issuerKey,
    );
    const validity = field(partial.mso, 'validityInfo');
    const date = (name: string) => {
      const tagged = field(validity, name) as { tag: number; value: string };
      assert.equal(tagged.tag, 0);
      return Date.parse(tagged.value) / 1000;
    };
    assert.ok(date('validFrom') <= now && now < date('validUntil'));
    values = partial.values;
    const device = field(doc, 'deviceSigned');
    const namespaces = field(device, 'nameSpaces');
    assert.deepEqual(embedded(namespaces), new Map());
    const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
    assert.equal(signature.length, 4);
    assert.equal(signature[2], null);
    assert.deepEqual(decodeCbor(signature[0] as Buffer), new Map([[1, -7]]));
    const transcriptHash = createHash('sha256')
      .update(
        encodeCbor([
          challenge.audience,
          challenge.nonce,
          Buffer.from(challenge.recipient_thumbprint, 'base64url'),
          challenge.response_uri,
        ]),
      )
      .digest();
    const authentication = encodeCbor({
      tag: 24,
      value: encodeCbor([
        'DeviceAuthentication',
        [null, null, ['OpenID4VPHandover', transcriptHash]],
        namespace,
        namespaces,
      ]),
    });
    assert.equal(
      verify(
        'sha256',
        encodeCbor(['Signature1', signature[0], Buffer.alloc(0), authentication]),
        {
          key: createPublicKey({ key: holder, format: 'jwk' }),
          dsaEncoding: 'ieee-p1363',
        },
        signature[3] as Buffer,
      ),
      true,
    );
  }
  assert.deepEqual(Object.keys(values).sort(), ['birthdate', 'name']);
  assert.deepEqual(values, expected);
}
