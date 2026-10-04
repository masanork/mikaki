// Independent verifier for the credential actually issued to the live Rust wallet.
// This is a host protocol peer, not a third-party Wallet or a production Verifier.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, randomBytes, verify, X509Certificate } from 'node:crypto';
import { compactDecrypt, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import type { JWK, JWTPayload } from 'jose';
import { decodeCbor, embedded, encodeCbor, field, verifyMdocIssuer } from './mdoc-test.ts';
import type { Cbor } from './mdoc-test.ts';
import { readerPki } from './reader-pki.ts';
import { certificateKeyIdentifier } from './certificate-key-identifier.ts';

const namespace = 'app.tossa.mikaki.linked_document.1';
const secret = () => randomBytes(32).toString('base64url');
export async function issuedWalletVerifier(
  format: string,
  issuer: string,
  issuerJwk: JWK,
  root: string,
  responseUri = 'https://verifier.example/issued-wallet',
) {
  const signing = await generateKeyPair('ES256', { extractable: true });
  const reader = await readerPki(await exportJWK(signing.privateKey));
  const leaf = new X509Certificate(Buffer.from(reader.chain[0], 'base64'));
  const readerCa = new X509Certificate(Buffer.from(reader.trust_anchors[0], 'base64'));
  assert.equal(leaf.checkIssued(readerCa), true);
  assert.equal(leaf.verify(readerCa.publicKey), true);
  assert.equal(leaf.ca, false);
  assert.notEqual(leaf.subject, leaf.issuer);
  const otherRecipient = await generateKeyPair('ECDH-ES');
  const registry = {
    client_id: `x509_hash:${createHash('sha256').update(leaf.raw).digest('base64url')}`,
    name: 'Independent host verifier',
    response_uri: responseUri,
    kid: 'issued-wallet-verifier-signing',
    jwk: await exportJWK(signing.publicKey),
    profile: 'oid4vp_final_x509_hash',
    certificate_trust: { trust_anchors: reader.trust_anchors },
  };
  const recipients = new Map<
    string,
    {
      privateKey: CryptoKey;
      jwk: JWK;
      kid: string;
    }
  >();
  const ca = new X509Certificate(Buffer.from(root, 'base64'));
  const issuerAuthority = certificateKeyIdentifier(ca, 'Subject');
  const request = async (
    authorities = [{ type: 'aki', values: [issuerAuthority] }],
    options: {
      omitState?: boolean;
      omitTimestamps?: boolean;
      walletNonce?: string;
      multiQuery?: boolean;
      wrongSecondAuthority?: boolean;
    } = {},
  ) => {
    const encryption = await generateKeyPair('ECDH-ES', { extractable: true });
    const recipient = {
      privateKey: encryption.privateKey,
      jwk: await exportJWK(encryption.publicKey),
      kid: secret(),
    };
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      aud: 'https://self-issued.me/v2',
      ...(options.walletNonce ? { wallet_nonce: options.walletNonce } : {}),
      client_id: registry.client_id,
      response_type: 'vp_token',
      response_mode: 'direct_post.jwt',
      response_uri: registry.response_uri,
      nonce: randomBytes(16).toString('base64url'),
      ...(!options.omitState ? { state: `opaque: &=+?${secret()}` } : {}),
      ...(!options.omitTimestamps ? { iat: now, exp: now + 120 } : {}),
      client_metadata: {
        jwks: { keys: [{ ...recipient.jwk, kid: recipient.kid, alg: 'ECDH-ES', use: 'enc' }] },
        encrypted_response_enc_values_supported: ['A128GCM', 'A256GCM'],
        vp_formats_supported: {
          'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
          mso_mdoc: { issuerauth_alg_values: [-9], deviceauth_alg_values: [-9] },
        },
      },
      dcql_query: {
        credentials: [
          {
            id: 'identity',
            format,
            trusted_authorities: authorities,
            meta:
              format === 'dc+sd-jwt'
                ? { vct_values: [`${issuer}/types/linked-document`] }
                : { doctype_value: namespace },
            claims: ['name', 'birthdate'].map((name) => ({
              path: format === 'dc+sd-jwt' ? [name] : [namespace, name],
            })),
          },
        ],
      },
    };
    if (options.multiQuery) {
      const base = claims.dcql_query.credentials[0];
      const claim = (name: string) => ({
        path: format === 'dc+sd-jwt' ? [name] : [namespace, name],
      });
      base.claims = [claim('name')];
      claims.dcql_query.credentials.push(
        {
          ...base,
          id: 'birth',
          claims: [claim('birthdate')],
          trusted_authorities: options.wrongSecondAuthority
            ? [{ type: 'aki', values: [secret()] }]
            : authorities,
        },
        { ...base, id: 'private_optional', claims: [claim('address')] },
      );
      Object.assign(claims.dcql_query, {
        credential_sets: [
          { options: [['identity', 'birth']] },
          { options: [['birth']] },
          { options: [['private_optional']], required: false },
        ],
      });
    }
    recipients.set(claims.nonce, recipient);
    return {
      claims,
      jwt: await new SignJWT(claims)
        .setProtectedHeader({ typ: 'oauth-authz-req+jwt', alg: 'ES256', x5c: reader.chain })
        .sign(signing.privateKey),
    };
  };
  const checkCertificate = (leaf: X509Certificate, claims: JWTPayload) => {
    const requested = (claims.dcql_query as any).credentials[0].trusted_authorities;
    const aki = certificateKeyIdentifier(leaf, 'Authority');
    assert.ok(
      requested.some(
        (a: { type: string; values: string[] }) => a.type === 'aki' && a.values.includes(aki),
      ),
    );
    assert.equal(aki, issuerAuthority);
    assert.equal(leaf.ca, false);
    assert.equal(ca.ca, true);
    assert.equal(leaf.checkIssued(ca), true);
    assert.equal(leaf.verify(ca.publicKey), true);
    assert.notDeepEqual(leaf.raw, ca.raw);
    assert.deepEqual(leaf.publicKey.export({ format: 'jwk' }), issuerJwk);
    const now = Date.now();
    for (const cert of [leaf, ca]) {
      assert.ok(Date.parse(cert.validFrom) <= now && now < Date.parse(cert.validTo));
    }
  };
  const accept = async (response: string, claims: JWTPayload, holder: JWK) => {
    await assert.rejects(compactDecrypt(response, otherRecipient.privateKey));
    const recipient = recipients.get(String(claims.nonce));
    assert.ok(recipient, 'response must match a request');
    for (const [nonce, previous] of recipients) {
      if (nonce !== claims.nonce) {
        await assert.rejects(compactDecrypt(response, previous.privateKey));
      }
    }
    const result = await compactDecrypt(response, recipient.privateKey, {
      keyManagementAlgorithms: ['ECDH-ES'],
      contentEncryptionAlgorithms: ['A128GCM', 'A256GCM'],
    });
    assert.equal(result.protectedHeader.kid, recipient.kid);
    // Final does not require apv. When supplied, keep the native nonce convention strict.
    if (result.protectedHeader.apv !== undefined)
      assert.equal(
        result.protectedHeader.apv,
        Buffer.from(String(claims.nonce)).toString('base64url'),
      );
    assert.equal(result.protectedHeader.apu, undefined);
    const body = JSON.parse(Buffer.from(result.plaintext).toString());
    assert.equal(body.state, claims.state);
    assert.equal(Object.hasOwn(body, 'state'), Object.hasOwn(claims, 'state'));
    const multi = (claims.dcql_query as any).credentials.length > 1;
    assert.deepEqual(
      Object.keys(body.vp_token).sort(),
      multi ? ['birth', 'identity'] : ['identity'],
    );
    if (multi) assert.deepEqual(body.vp_token.birth, body.vp_token.identity);
    assert.equal(body.vp_token.identity.length, 1);
    const token: string = body.vp_token.identity[0];
    let values: Record<string, unknown>;
    if (format === 'dc+sd-jwt') {
      const parts = token.split('~');
      const issued = await jwtVerify(parts.shift()!, await importJWK(issuerJwk, 'ES256'), {
        typ: 'dc+sd-jwt',
        algorithms: ['ES256'],
        issuer,
      });
      assert.deepEqual((issued.payload.cnf as any).jwk, holder);
      assert.equal(issued.protectedHeader.x5c!.length, 1);
      checkCertificate(
        new X509Certificate(Buffer.from(issued.protectedHeader.x5c![0], 'base64')),
        claims,
      );
      const kb = parts.pop()!;
      const binding = await jwtVerify(kb, await importJWK(holder, 'ES256'), {
        typ: 'kb+jwt',
        algorithms: ['ES256'],
        audience: registry.client_id,
      });
      assert.equal(binding.payload.nonce, claims.nonce);
      assert.equal(
        binding.payload.sd_hash,
        createHash('sha256').update(token.slice(0, -kb.length)).digest('base64url'),
      );
      values = {};
      for (const disclosure of parts) {
        assert.ok(
          (issued.payload._sd as string[]).includes(
            createHash('sha256').update(disclosure).digest('base64url'),
          ),
        );
        const [, name, value] = JSON.parse(Buffer.from(disclosure, 'base64url').toString());
        assert.equal(Object.hasOwn(values, name), false);
        values[name] = value;
      }
      await assert.rejects(
        jwtVerify(kb, await importJWK(holder, 'ES256'), { audience: 'another-verifier' }),
      );
    } else {
      const decoded = decodeCbor(Buffer.from(token, 'base64url'));
      assert.equal(field(decoded, 'version'), '1.0');
      assert.equal(field(decoded, 'status'), 0);
      const docs = field(decoded, 'documents') as Cbor[];
      assert.equal(docs.length, 1);
      const doc = docs[0];
      assert.equal(field(doc, 'docType'), namespace);
      const partial = verifyMdocIssuer(
        encodeCbor(field(doc, 'issuerSigned')).toString('base64url'),
        holder,
        issuerJwk,
      );
      const issuerAuth = field(partial.signed, 'issuerAuth') as Cbor[];
      checkCertificate(new X509Certificate(field(issuerAuth[1], 33) as Buffer), claims);
      values = partial.values;
      const device = field(doc, 'deviceSigned');
      const ns = field(device, 'nameSpaces');
      assert.deepEqual(embedded(ns), new Map());
      const signature = field(field(device, 'deviceAuth'), 'deviceSignature') as Cbor[];
      assert.equal(signature[2], null);
      assert.deepEqual(decodeCbor(signature[0] as Buffer), new Map([[1, -7]]));
      const { crv, kty, x, y } = recipient.jwk;
      const thumbprint = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest();
      const signatureValid = (nonce: string, recipient: Buffer | null, uri: string) => {
        const hash = createHash('sha256')
          .update(encodeCbor([registry.client_id, nonce, recipient, uri]))
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
      assert.equal(signatureValid(String(claims.nonce), thumbprint, registry.response_uri), true);
      assert.equal(signatureValid(secret(), thumbprint, registry.response_uri), false);
      assert.equal(signatureValid(String(claims.nonce), null, registry.response_uri), false);
      assert.equal(
        signatureValid(String(claims.nonce), thumbprint, 'https://other.example/response'),
        false,
      );
    }
    assert.deepEqual(Object.keys(values).sort(), ['birthdate', 'name']);
    assert.equal(typeof values.name, 'string');
    // External mdoc generators may encode the fixture date as RFC 8943 full-date.
    // Normalize only after validating the original signed item digest and DeviceSignature.
    if (format === 'mso_mdoc' && typeof values.birthdate === 'object') {
      assert.deepEqual(values.birthdate, { tag: 1004, value: '1990-02-28' });
      values = { ...values, birthdate: '1990-02-28' };
    }
    assert.equal(values.birthdate, '1990-02-28');
    return values;
  };
  const requestForWallet = async (
    form: [string, string][],
    substituteNonce = false,
    multiQuery = false,
    wrongSecondAuthority = false,
  ) => {
    assert.deepEqual(form.map(([key]) => key).sort(), ['wallet_metadata', 'wallet_nonce']);
    const fields = Object.fromEntries(form);
    const metadata = JSON.parse(fields.wallet_metadata);
    assert.deepEqual(metadata.client_id_prefixes_supported, ['x509_hash']);
    assert.deepEqual(metadata.request_object_signing_alg_values_supported, ['ES256']);
    assert.deepEqual(metadata.authorization_encryption_alg_values_supported, ['ECDH-ES']);
    assert.deepEqual(metadata.authorization_encryption_enc_values_supported, ['A256GCM']);
    assert.ok(metadata.vp_formats_supported[format]);
    assert.equal(Object.hasOwn(metadata, 'credentials'), false);
    assert.match(fields.wallet_nonce, /^[A-Za-z0-9_-]{43}$/);
    return request(undefined, {
      omitState: true,
      omitTimestamps: true,
      walletNonce: substituteNonce ? secret() : fields.wallet_nonce,
      multiQuery,
      wrongSecondAuthority,
    });
  };
  return { registry, request, requestForWallet, accept };
}
