import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { importJWK, jwtVerify } from 'jose';
import type { Cbor } from './support/mdoc-test.ts';

test('independent JOSE verifies Rust OID4VP request, SD-JWT issuer and holder binding', async () => {
  const fixture = JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'presentation_fixture',
        '--offline',
        '--locked',
      ],
      { encoding: 'utf8', maxBuffer: 100_000 },
    ),
  );
  const verifier = await importJWK(fixture.registry.jwk, 'ES256');
  const request = await jwtVerify(fixture.request, verifier, {
    algorithms: ['ES256'],
    typ: 'oauth-authz-req+jwt',
    audience: 'https://self-issued.me/v2',
    issuer: fixture.registry.client_id,
  });
  assert.equal(request.payload.response_uri, fixture.registry.response_uri);
  const parts: string[] = fixture.presentation.split('~');
  const issuerJwt = parts.shift()!;
  const kbJwt = parts.pop()!;
  const issuer = await importJWK(fixture.issuer_jwk, 'ES256');
  const issued = await jwtVerify(issuerJwt, issuer, {
    algorithms: ['ES256'],
    typ: 'dc+sd-jwt',
    issuer: fixture.issuer,
  });
  assert.deepEqual(issued.payload.cnf, { jwk: fixture.holder_jwk });
  const disclosed: Record<string, unknown> = {};
  for (const disclosure of parts) {
    const digest = createHash('sha256').update(disclosure).digest('base64url');
    assert.ok((issued.payload._sd as string[]).includes(digest));
    const [, name, value] = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8'));
    disclosed[name] = value;
  }
  assert.deepEqual(disclosed, { name: 'Fixture Person', birthdate: '1990-02-28' });
  assert.equal(Object.hasOwn(disclosed, 'address'), false);
  assert.equal(Object.hasOwn(disclosed, 'gender'), false);
  const holder = await importJWK(fixture.holder_jwk, 'ES256');
  const binding = await jwtVerify(kbJwt, holder, {
    algorithms: ['ES256'],
    typ: 'kb+jwt',
    audience: fixture.registry.client_id,
  });
  assert.equal(binding.payload.nonce, request.payload.nonce);
  const selected = fixture.presentation.slice(0, -kbJwt.length);
  assert.equal(binding.payload.sd_hash, createHash('sha256').update(selected).digest('base64url'));
  assert.notEqual(
    binding.payload.sd_hash,
    createHash('sha256').update(fixture.credential).digest('base64url'),
  );
  await assert.rejects(jwtVerify(kbJwt, verifier, { algorithms: ['ES256'] }));
  await assert.rejects(
    jwtVerify(kbJwt, holder, { algorithms: ['ES256'], audience: 'different-verifier' }),
  );
  assert.deepEqual(fixture.response, { identity: [fixture.presentation] });
});

test('independent Node crypto verifies mdoc issuer, selective disclosure and Final transcript binding', async () => {
  const { decodeCbor, encodeCbor, field, embedded, verifyMdocIssuer } =
    await import('./support/mdoc-test.ts');
  const { createPublicKey, verify } = await import('node:crypto');
  const f = JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'presentation_fixture',
        '--offline',
        '--locked',
      ],
      { encoding: 'utf8', maxBuffer: 100_000 },
    ),
  );
  const complete = verifyMdocIssuer(f.mdoc_credential, f.holder_jwk, f.issuer_jwk);
  assert.equal(complete.values.address, 'Private fixture address');
  const response = decodeCbor(Buffer.from(f.mdoc_response, 'base64url'));
  assert.equal(field(response, 'version'), '1.0');
  assert.equal(field(response, 'status'), 0);
  const docs = field(response, 'documents');
  assert.ok(Array.isArray(docs) && docs.length === 1);
  const doc = docs[0];
  const partial = verifyMdocIssuer(
    encodeCbor(field(doc, 'issuerSigned')).toString('base64url'),
    f.holder_jwk,
    f.issuer_jwk,
  );
  assert.deepEqual(partial.values, { name: 'Fixture Person', birthdate: '1990-02-28' });
  const info = encodeCbor([
    f.registry.client_id,
    f.request_claims.nonce,
    null,
    f.registry.response_uri,
  ]);
  const transcript = encodeCbor([
    null,
    null,
    ['OpenID4VPHandover', createHash('sha256').update(info).digest()],
  ]);
  assert.equal(transcript.toString('base64url'), f.mdoc_transcript);
  const device = field(doc, 'deviceSigned');
  const ns = field(device, 'nameSpaces');
  assert.deepEqual(embedded(ns), new Map());
  const payload = encodeCbor({
    tag: 24,
    value: encodeCbor([
      'DeviceAuthentication',
      decodeCbor(transcript),
      'app.tossa.mikaki.linked_document.1',
      ns,
    ]),
  });
  assert.equal(payload.toString('base64url'), f.mdoc_authentication);
  const auth = field(field(device, 'deviceAuth'), 'deviceSignature');
  assert.ok(Array.isArray(auth) && auth.length === 4);
  assert.equal(auth[2], null);
  const input = encodeCbor(['Signature1', auth[0], Buffer.alloc(0), payload]);
  const key = createPublicKey({ key: f.holder_jwk, format: 'jwk' });
  assert.equal(
    verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, auth[3] as Buffer),
    true,
  );
  const changed = Buffer.from(input);
  changed[changed.length - 1] ^= 1;
  assert.equal(
    verify('sha256', changed, { key, dsaEncoding: 'ieee-p1363' }, auth[3] as Buffer),
    false,
  );
});

test('independent JOSE decrypts SD-JWT and mdoc responses bound to the pinned recipient key', async () => {
  const { compactDecrypt } = await import('jose');
  const { createPublicKey, verify } = await import('node:crypto');
  const { decodeCbor: dec, encodeCbor: enc, field } = await import('./support/mdoc-test.ts');
  const f = JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'presentation_fixture',
        '--offline',
        '--locked',
      ],
      { encoding: 'utf8', maxBuffer: 100_000 },
    ),
  );
  const encryption = f.encryption_registry.response_encryption;
  const recipient = await importJWK(
    { ...encryption.jwk, d: Buffer.alloc(32, 6).toString('base64url') },
    'ECDH-ES',
  );
  const signingKey = await importJWK(f.encryption_registry.jwk, 'ES256');
  const request = await jwtVerify(f.encrypted_request, signingKey, {
    algorithms: ['ES256'],
    typ: 'oauth-authz-req+jwt',
  });
  assert.equal(request.payload.response_mode, 'direct_post.jwt');
  const decrypt = async (jwe: string) => {
    const result = await compactDecrypt(jwe, recipient, {
      keyManagementAlgorithms: ['ECDH-ES'],
      contentEncryptionAlgorithms: ['A256GCM'],
    });
    assert.equal(result.protectedHeader.kid, encryption.kid);
    assert.equal(
      result.protectedHeader.apv,
      Buffer.from(String(request.payload.nonce)).toString('base64url'),
    );
    assert.equal(result.protectedHeader.apu, undefined);
    assert.equal(jwe.split('.')[1], '');
    assert.equal(jwe.split('.').length, 5);
    return JSON.parse(Buffer.from(result.plaintext).toString());
  };
  const sd = await decrypt(f.encrypted_sd);
  assert.equal(sd.state, request.payload.state);
  assert.deepEqual(sd.vp_token, { identity: [f.presentation] });
  const result = await decrypt(f.encrypted_mdoc);
  assert.equal(result.state, request.payload.state);
  const response = dec(Buffer.from(result.vp_token.identity[0], 'base64url'));
  const device = field((field(response, 'documents') as Cbor[])[0], 'deviceSigned');
  const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
  const { crv, kty, x, y } = encryption.jwk;
  const thumbprint = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest();
  const handoverHash = createHash('sha256')
    .update(
      enc([
        f.registry.client_id,
        request.payload.nonce as string,
        thumbprint,
        f.registry.response_uri,
      ]),
    )
    .digest();
  const transcript = [null, null, ['OpenID4VPHandover', handoverHash]];
  const payload = enc({
    tag: 24,
    value: enc([
      'DeviceAuthentication',
      transcript,
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  });
  const options = {
    key: createPublicKey({ key: f.holder_jwk, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363' as const,
  };
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), payload]),
      options,
      signature[3] as Buffer,
    ),
    true,
  );
  const wrongHash = createHash('sha256')
    .update(
      enc([f.registry.client_id, request.payload.nonce as string, null, f.registry.response_uri]),
    )
    .digest();
  const wrong = enc({
    tag: 24,
    value: enc([
      'DeviceAuthentication',
      [null, null, ['OpenID4VPHandover', wrongHash]],
      'app.tossa.mikaki.linked_document.1',
      field(device, 'nameSpaces'),
    ]),
  });
  assert.equal(
    verify(
      'sha256',
      enc(['Signature1', signature[0], Buffer.alloc(0), wrong]),
      options,
      signature[3] as Buffer,
    ),
    false,
  );
  assert.notEqual(f.encrypted_mdoc, f.encrypted_mdoc_again);
  const second = await decrypt(f.encrypted_mdoc_again);
  assert.deepEqual(second, result);
  const wrongKey = await importJWK(
    { ...f.registry.jwk, d: Buffer.alloc(32, 5).toString('base64url') },
    'ECDH-ES',
  );
  await assert.rejects(compactDecrypt(f.encrypted_mdoc, wrongKey));
  const parts = f.encrypted_mdoc.split('.');
  const tampered = Buffer.from(parts[3], 'base64url');
  tampered[0] ^= 1;
  parts[3] = tampered.toString('base64url');
  await assert.rejects(compactDecrypt(parts.join('.'), recipient));
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  header.apv = Buffer.from('wrong nonce').toString('base64url');
  parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
  parts[3] = f.encrypted_mdoc.split('.')[3];
  await assert.rejects(compactDecrypt(parts.join('.'), recipient));
});

test('Draft 18 mdoc response uses PE submission and the same generated nonce in apu and legacy transcript', async () => {
  const { compactDecrypt } = await import('jose');
  const { createPublicKey, verify } = await import('node:crypto');
  const {
    decodeCbor: dec,
    encodeCbor: enc,
    field,
    embedded,
  } = await import('./support/mdoc-test.ts');
  const fixture = () =>
    JSON.parse(
      execFileSync(
        'cargo',
        [
          'run',
          '-q',
          '-p',
          'mikaki-identity',
          '--example',
          'presentation_fixture',
          '--offline',
          '--locked',
        ],
        { encoding: 'utf8', maxBuffer: 100_000 },
      ),
    );
  const f = fixture();
  const e = f.encryption_registry.response_encryption;
  const recipient = await importJWK(
    { ...e.jwk, d: Buffer.alloc(32, 6).toString('base64url') },
    'ECDH-ES',
  );
  const signed = await jwtVerify(f.legacy_request, await importJWK(f.registry.jwk, 'ES256'), {
    algorithms: ['ES256'],
    typ: 'oauth-authz-req+jwt',
  });
  const clear = await compactDecrypt(f.legacy_response, recipient, {
    keyManagementAlgorithms: ['ECDH-ES'],
    contentEncryptionAlgorithms: ['A256GCM'],
  });
  const nonce = Buffer.from(String(clear.protectedHeader.apu), 'base64url').toString();
  assert.equal(nonce.length, 43);
  assert.equal(Buffer.from(nonce, 'base64url').length, 32);
  assert.equal(
    clear.protectedHeader.apv,
    Buffer.from(String(signed.payload.nonce)).toString('base64url'),
  );
  const response = JSON.parse(Buffer.from(clear.plaintext).toString());
  assert.equal(typeof response.vp_token, 'string');
  assert.equal(response.state, signed.payload.state);
  assert.deepEqual(response.presentation_submission, {
    id: nonce,
    definition_id: 'legacy-definition',
    descriptor_map: [{ id: 'app.tossa.mikaki.linked_document.1', format: 'mso_mdoc', path: '$' }],
  });
  const doc = (field(dec(Buffer.from(response.vp_token, 'base64url')), 'documents') as Cbor[])[0];
  const disclosed = field(field(doc, 'issuerSigned'), 'nameSpaces') as Map<Cbor, Cbor>;
  const items = disclosed.get('app.tossa.mikaki.linked_document.1') as Cbor[];
  assert.deepEqual(
    items.map((i) => field(embedded(i), 'elementIdentifier')),
    ['name'],
  );
  const hash = (v: Cbor) => createHash('sha256').update(enc(v)).digest();
  const transcript = [
    null,
    null,
    [
      hash([f.registry.client_id, nonce]),
      hash([f.registry.response_uri, nonce]),
      signed.payload.nonce as string,
    ],
  ];
  const device = field(doc, 'deviceSigned');
  const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
  const input = (transcript: Cbor) =>
    enc([
      'Signature1',
      signature[0],
      Buffer.alloc(0),
      enc({
        tag: 24,
        value: enc([
          'DeviceAuthentication',
          transcript,
          'app.tossa.mikaki.linked_document.1',
          field(device, 'nameSpaces'),
        ]),
      }),
    ]);
  const key = {
    key: createPublicKey({ key: f.holder_jwk, format: 'jwk' }),
    dsaEncoding: 'ieee-p1363' as const,
  };
  assert.equal(verify('sha256', input(transcript), key, signature[3] as Buffer), true);
  const final = [
    null,
    null,
    [
      'OpenID4VPHandover',
      hash([f.registry.client_id, signed.payload.nonce as string, null, f.registry.response_uri]),
    ],
  ];
  assert.equal(verify('sha256', input(final), key, signature[3] as Buffer), false);
  const wrong = [
    null,
    null,
    [
      hash([f.registry.client_id, 'wrong']),
      hash([f.registry.response_uri, nonce]),
      signed.payload.nonce as string,
    ],
  ];
  assert.equal(verify('sha256', input(wrong), key, signature[3] as Buffer), false);
  const parts = f.legacy_response.split('.');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  header.apu = Buffer.from('different generated nonce').toString('base64url');
  parts[0] = Buffer.from(JSON.stringify(header)).toString('base64url');
  await assert.rejects(compactDecrypt(parts.join('.'), recipient));
  const second = fixture();
  const secondHeader = JSON.parse(
    Buffer.from(second.legacy_response.split('.')[0], 'base64url').toString(),
  );
  assert.notEqual(secondHeader.apu, clear.protectedHeader.apu);
});

test('independent X509 and JOSE verify the certificate-required Rust request', async () => {
  const f = JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'presentation_fixture',
        '--offline',
        '--locked',
      ],
      { encoding: 'utf8', maxBuffer: 100_000 },
    ),
  );
  const [leaf, intermediate] = f.certificate_chain.map(
    (s: string) => new X509Certificate(Buffer.from(s, 'base64')),
  );
  const root = new X509Certificate(Buffer.from(f.certificate_root, 'base64'));
  assert.equal(leaf.verify(intermediate.publicKey), true);
  assert.equal(intermediate.verify(root.publicKey), true);
  assert.equal(root.verify(root.publicKey), true);
  assert.equal(leaf.checkHost('verifier.example', { wildcards: false }), 'verifier.example');
  assert.equal(leaf.checkHost('evil.example'), undefined);
  const key = await importJWK(f.certificate_registry.jwk, 'ES256');
  const request = await jwtVerify(f.certificate_request, key, {
    algorithms: ['ES256'],
    typ: 'oauth-authz-req+jwt',
    audience: 'https://self-issued.me/v2',
    currentDate: new Date(f.now * 1000),
  });
  assert.deepEqual(request.protectedHeader.x5c, f.certificate_chain);
  assert.deepEqual(leaf.publicKey.export({ format: 'jwk' }), f.certificate_registry.jwk);
  assert.equal(request.payload.client_id, f.certificate_registry.client_id);
  assert.deepEqual(f.certificate_registry.certificate_trust.trust_anchors, [f.certificate_root]);
});
